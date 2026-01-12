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

    // 3. 异或解密 (XOR) - 仅解密头部潜在的最大范围，避免性能损耗
    // 这里我们解密整个 chunk，因为 payload 也可能包含在内
    const decrypted = new Uint8Array(buffer.length - 4);
    for (let i = 0; i < decrypted.length; i++) {
        decrypted[i] = buffer[i + 4] ^ salt[i % 4];
    }

    // 4. 验证哈希 (Offset 0-56)
    // 使用与 Trojan 相同的 SHA224 逻辑
    const expectedHash = sha224Hash(String(password));
    let receivedHash;
    try {
        receivedHash = textDecoder.decode(decrypted.slice(0, 56));
    } catch (e) {
        return { hasError: true, message: 'Mandala hash decode failed' };
    }

    if (receivedHash !== expectedHash) {
        return { hasError: true, message: 'Invalid Mandala Auth' };
    }

    // 5. 跳过随机混淆填充
    const padLen = decrypted[56]; // 获取填充长度
    let cursor = 57 + padLen;     //以此跳过垃圾数据

    if (cursor >= decrypted.length) return { hasError: true, message: 'Buffer too short after padding' };

    // 6. 解析指令 (CMD)
    const cmd = decrypted[cursor];
    if (cmd !== 1) return { hasError: true, message: 'Unsupported Mandala CMD: ' + cmd };
    cursor++;

    // 7. 解析地址 (ATYP + Addr)
    const atyp = decrypted[cursor];
    // parseAddressAndPort 需要传入 buffer, offset (指向ATYP的下一位), atyp
    // 注意：我们要传 decrypted buffer
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

    // 10. 还原目标地址字符串 (用于日志和连接)
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
        // 注意：Mandala 仅对 WebSocket 第一帧 (握手帧) 进行了 XOR 混淆
        // 后续数据流是否混淆取决于客户端实现，这里假设仅混淆头部
        rawClientData: decrypted.slice(headerEnd + 2),
        protocol: 'mandala'
    };
}
