// src/protocols/mandala.js
/**
 * 文件名: src/protocols/mandala.js
 * 修改说明:
 * 1. [Performance] 深度优化：引入“二级哈希”机制。
 * - 基础密钥使用 sha224Hash(password)，直接命中全局 LRU 缓存 (与 Trojan 共享)。
 * - 完整性校验使用 SHA256(CachedKey + Header)，既利用了缓存，又保证了动态头部的完整性。
 * 2. [Security] 保持 HMAC 思想，防止比特翻转攻击。
 */
import { CONSTANTS } from '../constants.js';
// [Optimization] 引入 sha224Hash 以利用全局缓存
import { textDecoder, textEncoder, StreamCipher, sha224Hash } from '../utils/helpers.js';

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

export async function parseMandalaHeader(mandalaBuffer, password) {
    if (!password) {
        return { hasError: true, message: 'Password is required' };
    }

    // 基础长度检查
    if (mandalaBuffer.byteLength < 40) {
        return { hasError: true, message: 'Mandala buffer too short' };
    }

    // 1. 获取输入视图
    const buffer = mandalaBuffer instanceof Uint8Array ? mandalaBuffer : new Uint8Array(mandalaBuffer);

    // 2. 读取 Salt
    const salt = buffer.subarray(0, 4);
    const ciphertext = buffer.subarray(4);
    
    // [Probing] 预读前 2KB
    const PROBE_LIMIT = 2048;
    const decodeLen = Math.min(ciphertext.byteLength, PROBE_LIMIT);
    const decrypted = new Uint8Array(ciphertext.subarray(0, decodeLen)); 
    
    // 3. 解密 (StreamCipher 依然使用原始密码，因其初始化开销极低且无缓存机制)
    // 注意：如果想进一步压榨性能，CipherKey 也可以改用 CachedHash，但会破坏更多兼容性，暂保持原样。
    const passwordBytes = textEncoder.encode(password);
    const cipher = new StreamCipher(passwordBytes, salt);
    cipher.process(decrypted); 

    // 4. [Optimization] 获取缓存的 Auth Key
    // 这里直接调用 sha224Hash，它会从 src/utils/helpers.js 的全局缓存中立即返回结果
    // 这一步消耗为近似 0 (O(1) Map Lookup)
    const cachedAuthKeyHex = sha224Hash(String(password));
    const cachedAuthKeyBytes = textEncoder.encode(cachedAuthKeyHex); // 56 bytes

    // 5. 投机性解析
    const HASH_SIZE = 32; // SHA-256
    if (decrypted.byteLength < HASH_SIZE + 1) return { hasError: true, message: 'Data too short' };

    const padLen = decrypted[HASH_SIZE]; 
    let cursor = HASH_SIZE + 1 + padLen;     

    if (cursor >= decrypted.length) return { hasError: true, message: 'Padding overflow' };

    const cmd = decrypted[cursor];
    const isUDP = (cmd === 3);

    if (cmd !== 1 && !isUDP) return { hasError: true, message: 'Unsupported Mandala CMD: ' + cmd };
    cursor++;

    if (cursor >= decrypted.length) return { hasError: true, message: 'Buffer ended unexpectedly' };

    const atyp = decrypted[cursor];
    cursor++;
    
    let addressRemote = "";
    let portRemote = 0;
    const view = new DataView(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);

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
                for (let i = 0; i < 8; i++) ipv6.push(view.getUint16(cursor + i * 2, false).toString(16)); 
                addressRemote = '[' + ipv6.join(':') + ']';
                cursor += 16;
                break;
            default:
                return { hasError: true, message: 'Unknown ATYP: ' + atyp };
        }
        portRemote = view.getUint16(cursor, false);
        cursor += 2;
    } catch (e) {
        return { hasError: true, message: 'Header parse failed' };
    }
    
    const headerEnd = cursor;
    
    if (headerEnd + 2 > decrypted.byteLength) return { hasError: true, message: 'Missing CRLF' };
    if (decrypted[headerEnd] !== 0x0D || decrypted[headerEnd + 1] !== 0x0A) {
        return { hasError: true, message: 'Invalid Footer' };
    }
    const fullHeaderLen = headerEnd + 2;

    // =========================================================
    // 6. [Core] 基于缓存密钥的完整性校验
    // =========================================================
    // Hash = SHA256( CachedAuthKeyBytes + HeaderData )
    
    const receivedHash = decrypted.subarray(0, HASH_SIZE);
    const headerData = decrypted.subarray(HASH_SIZE, fullHeaderLen);
    
    // 拼接：[Cached_56_Bytes] + [Dynamic_Header]
    const verifyBuffer = new Uint8Array(cachedAuthKeyBytes.length + headerData.length);
    verifyBuffer.set(cachedAuthKeyBytes);
    verifyBuffer.set(headerData, cachedAuthKeyBytes.length);
    
    // 原生 SHA-256 计算 (非常快)
    const computedHashBuffer = await crypto.subtle.digest('SHA-256', verifyBuffer);
    const computedHash = new Uint8Array(computedHashBuffer);

    if (!constantTimeEqual(receivedHash, computedHash)) {
        return { hasError: true, message: 'Mandala Integrity Check Failed' };
    }

    const rawClientData = ciphertext.subarray(fullHeaderLen);

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
