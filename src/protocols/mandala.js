// src/protocols/mandala.js
import { CONSTANTS } from '../constants.js';
import { textDecoder, textEncoder, sha224Hash, StreamCipher } from '../utils/helpers.js';

// Cache System
const passwordHashCache = new Map();
const passwordBytesCache = new Map();
const MAX_CACHE_SIZE = 100;

/**
 * 恒定时间比较两个 Uint8Array 是否相等，防止时序攻击
 */
function constantTimeEqual(a, b) {
    if (a.byteLength !== b.byteLength) return false;
    let mismatch = 0;
    for (let i = 0; i < a.byteLength; i++) {
        mismatch |= a[i] ^ b[i];
    }
    return mismatch === 0;
}

/**
 * 获取或缓存密码的 Hash 字节 (SHA-224 Hex String -> Bytes)
 */
function getCachedPasswordHashBytes(password) {
    let expectedHashBytes = passwordHashCache.get(password);
    if (!expectedHashBytes) {
        // 注意：协议设计为将 SHA224 的 Hex 字符串转换为 Bytes 传输
        const hashHex = sha224Hash(String(password));
        expectedHashBytes = textEncoder.encode(hashHex);
        
        if (passwordHashCache.size >= MAX_CACHE_SIZE) {
            const firstKey = passwordHashCache.keys().next().value;
            passwordHashCache.delete(firstKey);
        }
        passwordHashCache.set(password, expectedHashBytes);
    }
    return expectedHashBytes;
}

/**
 * 获取或缓存密码的原始字节
 */
function getCachedPasswordBytes(password) {
    let passwordBytes = passwordBytesCache.get(password);
    if (!passwordBytes) {
        passwordBytes = textEncoder.encode(password);
        
        if (passwordBytesCache.size >= MAX_CACHE_SIZE) {
            const first = passwordBytesCache.keys().next().value;
            passwordBytesCache.delete(first);
        }
        passwordBytesCache.set(password, passwordBytes);
    }
    return passwordBytes;
}

export async function parseMandalaHeader(mandalaBuffer, password) {
    if (!password) {
        return { hasError: true, message: 'Password is required' };
    }

    // 基础长度检查 (Salt(4) + Hash(56) + PadLen(1) + Cmd(1) + Atyp(1) + Port(2) + CRLF(2) = 67字节)
    if (mandalaBuffer.byteLength < 67) {
        return { hasError: true, message: 'Mandala buffer too short' };
    }

    // 1. 获取输入视图 (确保是 Uint8Array)
    const buffer = mandalaBuffer instanceof Uint8Array ? mandalaBuffer : new Uint8Array(mandalaBuffer);

    // 2. 读取 Salt (明文，前4字节)
    const salt = buffer.subarray(0, 4);
    
    // 3. 准备解密 
    // ciphertext 是原始数据的引用（包含 [加密头部] + [明文Body]）
    const ciphertext = buffer.subarray(4);
    
    // 创建一个副本用于解密，避免修改原始 buffer。
    // 重要：Mandala 协议只加密了头部，Body 是明文。
    // StreamCipher 会解密整个流，导致副本中的 Body 变成乱码，但这不影响我们稍后从 ciphertext 中提取正确的 Body。
    const decrypted = new Uint8Array(ciphertext); 
    
    // 4. 获取密码 Bytes
    const passwordBytes = getCachedPasswordBytes(password);

    // 5. 初始化流加密并执行解密
    const cipher = new StreamCipher(passwordBytes, salt);
    cipher.process(decrypted); 

    // 6. 验证哈希 (Offset 0-56 in decrypted buffer)
    const expectedHashBytes = getCachedPasswordHashBytes(password);

    if (!constantTimeEqual(decrypted.subarray(0, 56), expectedHashBytes)) {
        return { hasError: true, message: 'Invalid Mandala Auth' };
    }

    // 7. 解析剩余头部
    const view = new DataView(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);
    
    const padLen = decrypted[56]; 
    let cursor = 57 + padLen;     

    // 确保 Padding 后还有数据 (Cmd, Atyp, Port 等)
    if (cursor >= decrypted.length) {
        return { hasError: true, message: 'Buffer too short after padding' };
    }

    const cmd = decrypted[cursor];
    const isUDP = (cmd === 3);

    // 仅支持 TCP(1) 和 UDP(3)
    if (cmd !== 1 && !isUDP) {
        return { hasError: true, message: 'Unsupported Mandala CMD: ' + cmd };
    }
    cursor++;

    // 检查 cursor 是否越界 (需要读取 atyp)
    if (cursor >= decrypted.length) return { hasError: true, message: 'Buffer ended unexpectedly' };

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
                // IPv6 长度 16 字节，每组 2 字节
                for (let i = 0; i < 8; i++) {
                    ipv6.push(view.getUint16(cursor + i * 2, false).toString(16)); // false = Big Endian
                }
                addressRemote = '[' + ipv6.join(':') + ']';
                cursor += 16;
                break;
            default:
                return { hasError: true, message: 'Unknown ATYP: ' + atyp };
        }
        
        // 读取 Port (2字节, Big Endian)
        portRemote = view.getUint16(cursor, false);
        cursor += 2;
        headerEnd = cursor;

    } catch (e) {
        return { hasError: true, message: 'Address parse failed: ' + e.message };
    }
    
    // 8. 验证 CRLF (协议尾部标记)
    if (headerEnd + 2 > decrypted.byteLength) {
        return { hasError: true, message: 'Missing CRLF data' };
    }
    if (decrypted[headerEnd] !== 0x0D || decrypted[headerEnd + 1] !== 0x0A) {
        return { hasError: true, message: 'Missing CRLF' };
    }

    // 9. 返回结果
    // 这里的关键是从原始 ciphertext 中提取 Body，因为 Body 是明文传输的。
    // headerEnd 是头部结束位置（不含 CRLF），CRLF 占2字节，所以数据从 headerEnd + 2 开始。
    const rawClientData = ciphertext.subarray(headerEnd + 2);

    return {
        hasError: false,
        addressRemote,
        portRemote,
        addressType: atyp,
        isUDP: isUDP, 
        rawClientData: rawClientData,
        protocol: 'mandala'
    };
}
