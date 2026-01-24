// src/protocols/mandala.js
import { CONSTANTS } from '../constants.js';
import { textDecoder, sha224Hash } from '../utils/helpers.js';
import { parseAddressAndPort } from './utils.js';

// [优化] 缓存 Password Hash
const passwordHashCache = new Map();
const MAX_CACHE_SIZE = 100;

export async function parseMandalaHeader(mandalaBuffer, password) {
    // 1. 基础长度检查 (Salt(4) + Hash(56) + PadLen(1) + Cmd(1) + Atyp(1) + Port(2) + CRLF(2) = 67字节)
    if (mandalaBuffer.byteLength < 67) {
        return { hasError: true, message: 'Mandala buffer too short' };
    }

    // [优化] 避免不必要的包装
    const buffer = mandalaBuffer instanceof Uint8Array ? mandalaBuffer : new Uint8Array(mandalaBuffer);

    // 2. 提取随机盐 (前4字节)
    const salt = buffer.subarray(0, 4);

    // 3. 异或解密 (XOR)
    const decrypted = new Uint8Array(buffer.length - 4);
    for (let i = 0; i < decrypted.length; i++) {
        decrypted[i] = buffer[i + 4] ^ salt[i & 3];
    }

    // 4. 验证哈希 (Offset 0-56)
    let expectedHash = passwordHashCache.get(password);
    
    if (expectedHash) {
        passwordHashCache.delete(password);
        passwordHashCache.set(password, expectedHash);
    } else {
        expectedHash = sha224Hash(String(password));
        if (passwordHashCache.size >= MAX_CACHE_SIZE) {
            const oldestKey = passwordHashCache.keys().next().value;
            passwordHashCache.delete(oldestKey);
        }
        passwordHashCache.set(password, expectedHash);
    }

    let receivedHash;
    try {
        receivedHash = textDecoder.decode(decrypted.subarray(0, 56));
    } catch (e) {
        return { hasError: true, message: 'Mandala hash decode failed' };
    }

    if (receivedHash !== expectedHash) {
        return { hasError: true, message: 'Invalid Mandala Auth' };
    }

    // 5. 跳过随机混淆填充
    const padLen = decrypted[56]; 
    let cursor = 57 + padLen;     

    if (cursor >= decrypted.length) return { hasError: true, message: 'Buffer too short after padding' };

    // 6. 解析指令 (CMD)
    // [修改] 支持 TCP(1) 和 UDP(3)
    const cmd = decrypted[cursor];
    const isUDP = (cmd === 3);

    if (cmd !== 1 && !isUDP) {
        return { hasError: true, message: 'Unsupported Mandala CMD: ' + cmd };
    }
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
        case CONSTANTS.ATYP_SS_DOMAIN: 
            addressRemote = textDecoder.decode(addrResult.targetAddrBytes);
            break;
        case CONSTANTS.ATYP_SS_IPV6: 
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
        isUDP: isUDP, // [修改] 传递 UDP 状态
        rawClientData: decrypted.subarray(headerEnd + 2),
        protocol: 'mandala'
    };
}
