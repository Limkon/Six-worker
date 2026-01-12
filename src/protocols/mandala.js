/**
 * 文件名: src/protocols/mandala.js
 * 修改内容: 
 * 1. [修改] 验证逻辑：在解密数据中搜索 expectedHash (SHA224)，支持前后存在垃圾数据的虚位验证。
 * 2. [新增] 动态指针：根据 Hash 实际出现的位置，动态调整后续 PadLen、CMD、Address 的读取偏移量，防止解析错位。
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

    // 4. 验证哈希 (支持虚位密码)
    // 计算标准 SHA224 哈希 (56字符 hex 字符串)
    const expectedHash = sha224Hash(String(password));
    
    // 将解密后的缓冲区转为字符串进行搜索
    let decryptedString;
    try {
        decryptedString = textDecoder.decode(decrypted);
    } catch (e) {
        return { hasError: true, message: 'Mandala decode failed' };
    }

    // [核心修改] 搜索哈希位置
    // indexOf 返回 -1 表示未找到，否则返回哈希起始索引
    const hashIndex = decryptedString.indexOf(expectedHash);

    if (hashIndex === -1) {
        return { hasError: true, message: 'Invalid Mandala Auth' };
    }

    // [关键] 重新计算数据偏移量
    // 标准情况下 hashIndex 应为 0。如果是虚位密码，hashIndex > 0。
    // 哈希长度固定为 56 字节。
    const hashEnd = hashIndex + 56;

    // 5. 跳过随机混淆填充 (PadLen 位于 Hash 之后 1 字节)
    if (hashEnd >= decrypted.length) {
        return { hasError: true, message: 'Buffer too short for PadLen' };
    }
    
    const padLen = decrypted[hashEnd]; // 获取填充长度
    let cursor = hashEnd + 1 + padLen; // 动态调整游标：Hash结束位置 + 1(PadLen字节) + PadLen长度

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
        // 原始客户端数据 = 解密后去掉头部的剩余部分
        rawClientData: decrypted.slice(headerEnd + 2),
        protocol: 'mandala'
    };
}
