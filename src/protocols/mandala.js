// src/protocols/mandala.js
import { CONSTANTS } from '../constants.js';
import { textDecoder, textEncoder, sha224Hash } from '../utils/helpers.js';

// Password Hash Cache
const passwordHashCache = new Map();
const MAX_CACHE_SIZE = 100;

function constantTimeEqual(a, b) {
    if (a.byteLength !== b.byteLength) return false;
    let mismatch = 0;
    for (let i = 0; i < a.byteLength; i++) {
        mismatch |= a[i] ^ b[i];
    }
    return mismatch === 0;
}

export async function parseMandalaHeader(mandalaBuffer, password) {
    // 基础长度检查 (Salt(4) + Hash(56) + PadLen(1) + Cmd(1) + Atyp(1) + Port(2) + CRLF(2) = 67字节)
    if (mandalaBuffer.byteLength < 67) {
        return { hasError: true, message: 'Mandala buffer too short' };
    }

    const buffer = mandalaBuffer instanceof Uint8Array ? mandalaBuffer : new Uint8Array(mandalaBuffer);

    // 1. 异或解密 (必须分配新内存)
    const salt = buffer.subarray(0, 4);
    const decrypted = new Uint8Array(buffer.byteLength - 4);
    
    // 简单的循环更有利于 V8 优化
    const len = decrypted.length;
    for (let i = 0; i < len; i++) {
        decrypted[i] = buffer[i + 4] ^ salt[i & 3];
    }

    // 2. 验证哈希 (Offset 0-56)
    let expectedHashBytes = passwordHashCache.get(password);
    if (!expectedHashBytes) {
        const hashHex = sha224Hash(String(password));
        expectedHashBytes = textEncoder.encode(hashHex);
        if (passwordHashCache.size >= MAX_CACHE_SIZE) {
            const firstKey = passwordHashCache.keys().next().value;
            passwordHashCache.delete(firstKey);
        }
        passwordHashCache.set(password, expectedHashBytes);
    }

    if (!constantTimeEqual(decrypted.subarray(0, 56), expectedHashBytes)) {
        return { hasError: true, message: 'Invalid Mandala Auth' };
    }

    // 3. 解析剩余头部
    // [Optimization] 使用 DataView 操作 decrypted buffer
    const view = new DataView(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);
    
    const padLen = decrypted[56]; 
    let cursor = 57 + padLen;     

    if (cursor >= decrypted.length) return { hasError: true, message: 'Buffer too short after padding' };

    const cmd = decrypted[cursor];
    const isUDP = (cmd === 3);

    if (cmd !== 1 && !isUDP) {
        return { hasError: true, message: 'Unsupported Mandala CMD: ' + cmd };
    }
    cursor++;

    const atyp = decrypted[cursor];
    cursor++;
    
    let addressRemote = "";
    let portRemote = 0;
    let headerEnd = 0;

    try {
        switch (atyp) {
            case CONSTANTS.ADDRESS_TYPE_IPV4:
                // 4 bytes IPv4
                addressRemote = decrypted.subarray(cursor, cursor + 4).join('.');
                cursor += 4;
                break;
            case CONSTANTS.ATYP_SS_DOMAIN: 
                const domainLen = decrypted[cursor];
                cursor++; // skip len byte
                addressRemote = textDecoder.decode(decrypted.subarray(cursor, cursor + domainLen));
                cursor += domainLen;
                break;
            case CONSTANTS.ATYP_SS_IPV6: 
                const ipv6 = [];
                for (let i = 0; i < 8; i++) {
                    ipv6.push(view.getUint16(cursor + i * 2, false).toString(16));
                }
                addressRemote = '[' + ipv6.join(':') + ']';
                cursor += 16;
                break;
            default:
                return { hasError: true, message: 'Unknown ATYP: ' + atyp };
        }
        
        // Port
        portRemote = view.getUint16(cursor, false);
        cursor += 2;
        headerEnd = cursor;

    } catch (e) {
        return { hasError: true, message: 'Address parse failed' };
    }
    
    // 4. 验证 CRLF
    if (headerEnd + 2 > decrypted.byteLength) return { hasError: true, message: 'Missing CRLF data' };
    if (decrypted[headerEnd] !== 0x0D || decrypted[headerEnd + 1] !== 0x0A) {
        return { hasError: true, message: 'Missing CRLF' };
    }

    return {
        hasError: false,
        addressRemote,
        portRemote,
        addressType: atyp,
        isUDP: isUDP, 
        // [Optimization] Zero-copy return
        rawClientData: decrypted.subarray(headerEnd + 2),
        protocol: 'mandala'
    };
}
