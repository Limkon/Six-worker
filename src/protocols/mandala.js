// src/protocols/mandala.js
import { CONSTANTS } from '../constants.js';
import { textDecoder, textEncoder, sha224Hash, StreamCipher } from '../utils/helpers.js';

// Cache System
const passwordHashCache = new Map();
// [Optimization] 增加 Bytes 缓存，避免每次 new StreamCipher 都进行 TextEncode
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
    
    // 3. 准备解密 (复制剩余数据，避免修改原始 buffer 导致影响其他协议探测)
    // 密文部分从第 4 字节开始
    const ciphertext = buffer.subarray(4);
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
    // 使用 Password + Salt 初始化状态机
    const cipher = new StreamCipher(passwordBytes, salt);
    cipher.process(decrypted); // 原地解密 decrypted 数组

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

    // [Security] 必须验证解密后的数据是否符合签名
    if (!constantTimeEqual(decrypted.subarray(0, 56), expectedHashBytes)) {
        return { hasError: true, message: 'Invalid Mandala Auth' };
    }

    // 7. 解析剩余头部 (使用 DataView 操作 decrypted buffer)
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
    
    // 8. 验证 CRLF
    if (headerEnd + 2 > decrypted.byteLength) return { hasError: true, message: 'Missing CRLF data' };
    if (decrypted[headerEnd] !== 0x0D || decrypted[headerEnd + 1] !== 0x0A) {
        return { hasError: true, message: 'Missing CRLF' };
    }

    // 9. 返回结果
    // 注意: rawClientData 是解密后的数据，意味着后续处理管道将传输明文。
    // 这符合 Header-Only Obfuscation 的设计。
    return {
        hasError: false,
        addressRemote,
        portRemote,
        addressType: atyp,
        isUDP: isUDP, 
        rawClientData: decrypted.subarray(headerEnd + 2),
        protocol: 'mandala'
    };
}
