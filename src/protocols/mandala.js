// src/protocols/mandala.js
import { CONSTANTS } from '../constants.js';
import { textDecoder, textEncoder, sha224Hash, StreamCipher } from '../utils/helpers.js';

// Cache System
const passwordHashCache = new Map();
const passwordBytesCache = new Map();
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

    // 1. 获取输入视图
    const buffer = mandalaBuffer instanceof Uint8Array ? mandalaBuffer : new Uint8Array(mandalaBuffer);

    // 2. 读取 Salt (明文，前4字节)
    const salt = buffer.subarray(0, 4);
    
    // 3. 准备解密 
    // ciphertext 是原始数据的引用（包含 [加密头部] + [明文Body]）
    const ciphertext = buffer.subarray(4);
    
    // 创建一个副本用于解密，避免修改原始 buffer 导致 Body 被破坏
    const decrypted = new Uint8Array(ciphertext); 
    
    // 4. 获取密码 Bytes (带缓存)
    let passwordBytes = passwordBytesCache.get(password);
    if (!passwordBytes) {
        passwordBytes = textEncoder.encode(password);
        if (passwordBytesCache.size >= MAX_CACHE_SIZE) {
            const first = passwordBytesCache.keys().next().value;
            passwordBytesCache.delete(first);
        }
        passwordBytesCache.set(password, passwordBytes);
    }

    // 5. 初始化流加密并执行解密
    // 注意：这里会解密整个缓冲区。头部被正确解密，但后面的 Body (原文本就是明文) 会被错误地异或。
    const cipher = new StreamCipher(passwordBytes, salt);
    cipher.process(decrypted); 

    // 6. 验证哈希 (Offset 0-56 in decrypted buffer)
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

    // 7. 解析剩余头部 (使用 DataView 操作 decrypted buffer)
    // 我们需要在 decrypted 中找到头部的结束位置
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
                addressRemote = decrypted.subarray(cursor, cursor + 4).join('.');
                cursor += 4;
                break;
            case CONSTANTS.ATYP_SS_DOMAIN: 
                const domainLen = decrypted[cursor];
                cursor++; 
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
    
    // 8. 验证 CRLF
    if (headerEnd + 2 > decrypted.byteLength) return { hasError: true, message: 'Missing CRLF data' };
    if (decrypted[headerEnd] !== 0x0D || decrypted[headerEnd + 1] !== 0x0A) {
        return { hasError: true, message: 'Missing CRLF' };
    }

    // 9. 返回结果 (关键修复)
    // [Fix] 必须从原始的 ciphertext 中截取 Body，而不是从 decrypted 中截取。
    // 因为客户端只加密了 Header，后面的 Body 是明文发送的。
    // decrypted 中的 Body 是被我们错误异或过的乱码，而 ciphertext 中的 Body 是原始明文。
    return {
        hasError: false,
        addressRemote,
        portRemote,
        addressType: atyp,
        isUDP: isUDP, 
        // ❌ 错误写法: rawClientData: decrypted.subarray(headerEnd + 2)
        // ✅ 正确写法: 从原始数据中提取后续明文流
        rawClientData: ciphertext.subarray(headerEnd + 2),
        protocol: 'mandala'
    };
}
