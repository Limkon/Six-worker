/**
 * 文件名: src/protocols/mandala.js
 * 修改内容: 
 * 1. [新增] 密码长度限制：在计算哈希前，将密码截断为最大 128 字符。
 * 2. [保留] 虚位密码逻辑：支持在解密数据中搜索 SHA224 哈希，并动态调整读取游标。
 */
import { CONSTANTS } from '../constants.js';
import { textDecoder, sha224Hash } from '../utils/helpers.js';
import { parseAddressAndPort } from './utils.js';

export async function parseMandalaHeader(mandalaBuffer, password) {
    // 1. 基础长度检查 (Salt(4) + Hash(56) + PadLen(1) + Cmd(1) + Atyp(1) + Port(2) + CRLF(2) = 67字节)
    if (mandalaBuffer.byteLength < 67) {
        return { hasError: true, message: 'Mandala buffer too short' };
    }

    const buffer = mandalaBuffer instanceof Uint8Array ? mandalaBuffer : new Uint8Array(mandalaBuffer);

    // 2. 提取随机盐 (前4字节)
    const salt = buffer.slice(0, 4);

    // 3. 异或解密 (XOR)
    const decrypted = new Uint8Array(buffer.length - 4);
    for (let i = 0; i < decrypted.length; i++) {
        decrypted[i] = buffer[i + 4] ^ salt[i % 4];
    }

    // 4. 验证哈希 (支持虚位密码 + 长度限制)
    
    // [新增] 密码长度限制
    // 限制密码不超过 128 位（字符/字节），超过部分直接舍弃
    // 例如：如果密码是 200 位的字符串，只取前 128 位参与哈希计算
    const safePassword = String(password).slice(0, 128);

    // 计算标准 SHA224 哈希 (基于截断后的密码)
    const expectedHash = sha224Hash(safePassword);
    
    // 将解密后的缓冲区转为字符串进行搜索
    let decryptedString;
    try {
        decryptedString = textDecoder.decode(decrypted);
    } catch (e) {
        return { hasError: true, message: 'Mandala decode failed' };
    }

    // [搜索哈希位置]
    const hashIndex = decryptedString.indexOf(expectedHash);

    if (hashIndex === -1) {
        return { hasError: true, message: 'Invalid Mandala Auth' };
    }

    // [动态调整游标]
    // 哈希长度固定为 56 字节
    const hashEnd = hashIndex + 56;

    // 5. 跳过随机混淆填充 (PadLen 位于 Hash 之后 1 字节)
    if (hashEnd >= decrypted.length) {
        return { hasError: true, message: 'Buffer too short for PadLen' };
    }
    
    const padLen = decrypted[hashEnd]; // 获取填充长度
    let cursor = hashEnd + 1 + padLen; // 动态调整游标

    if (cursor >= decrypted.length) return { hasError: true, message: 'Buffer too short after padding' };

    // 6. 解析指令 (CMD)
    const cmd = decrypted[cursor];
    if (cmd !== 1) return { hasError: true, message: 'Unsupported Mandala CMD: ' + cmd };
    cursor++;

    // 7. 解析地址 (ATYP + Addr)
    const atyp = decrypted[cursor];
    const addrResult = parseAddressAndPort(decrypted.buffer, cursor + 1, atyp);
    
    if (addrResult.hasError) return addrResult;
    
    // 8. 解析端口
    const dataOffset = addrResult.dataOffset;
    if (dataOffset + 2 > decrypted.byteLength) return { hasError: true, message: 'Buffer short for port' };
    
    const view = new DataView(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);
    const port = view.getUint16(dataOffset, false);
    
    // 9. 验证 CRLF (作为头部结束标志)
    const headerEnd = dataOffset + 2;
    if (decrypted[headerEnd] !== 0x0D || decrypted[headerEnd + 1] !== 0x0A) {
        return { hasError: true, message: 'Missing CRLF' };
    }

    // 10. 还原目标地址字符串
    let addressRemote = "";
    switch (atyp) {
        case CONSTANTS.ADDRESS_TYPE_IPV4:
            addressRemote = addrResult.targetAddrBytes.join('.');
            break;
        case CONSTANTS.ATYP_SS_DOMAIN: // Domain
            addressRemote = textDecoder.decode(addrResult.targetAddrBytes);
            break;
        case CONSTANTS.ATYP_SS_IPV6: // IPv6
            const ipv6 = [];
            const v6View = new DataView(addrResult.targetAddrBytes.buffer, addrResult.targetAddrBytes.byteOffset, addrResult.targetAddrBytes.byteLength);
            for (let i = 0; i < 8; i++) ipv6.push(v6View.getUint16(i * 2, false).toString(16));
            addressRemote = '[' + ipv6.join(':') + ']';
            break;
        default:
            return { hasError: true, message: 'Unknown ATYP' };
    }

    return {
        hasError: false,
        addressRemote,
        portRemote: port,
        addressType: atyp,
        isUDP: false,
        rawClientData: decrypted.slice(headerEnd + 2),
        protocol: 'mandala'
    };
}
