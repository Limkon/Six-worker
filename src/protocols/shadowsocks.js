// src/protocols/shadowsocks.js
import { CONSTANTS } from '../constants.js';
import { textDecoder, textEncoder } from '../utils/helpers.js';
import { parseAddressAndPort } from './utils.js';

// Shadowsocks AEAD Ciphers
const AEAD_METHODS = {
    'aes-256-gcm': { keyLen: 32, saltLen: 32, nonceLen: 12, tagLen: 16 },
    'aes-128-gcm': { keyLen: 16, saltLen: 16, nonceLen: 12, tagLen: 16 },
    'chacha20-poly1305': { keyLen: 32, saltLen: 32, nonceLen: 12, tagLen: 16 },
};

// 缓存派生的主密钥 (Master Key)
const masterKeyCache = new Map();

/**
 * OpenSSL EVP_BytesToKey (MD5) 实现
 * 将密码转换为固定长度的 Master Key
 */
async function evpBytesToKey(password, keyLen) {
    const passBytes = textEncoder.encode(password);
    let key = new Uint8Array(0);
    let prevHash = new Uint8Array(0);

    while (key.length < keyLen) {
        const data = new Uint8Array(prevHash.length + passBytes.length);
        data.set(prevHash, 0);
        data.set(passBytes, prevHash.length);

        const hashBuffer = await crypto.subtle.digest('MD5', data);
        const hash = new Uint8Array(hashBuffer);
        
        const newKey = new Uint8Array(key.length + hash.length);
        newKey.set(key, 0);
        newKey.set(hash, key.length);
        
        key = newKey;
        prevHash = hash;
    }
    return key.slice(0, keyLen);
}

/**
 * HKDF-SHA1 实现 (Shadowsocks 标准)
 * 修复了 Salt/Key 顺序和 Info 拼接问题
 */
async function hkdfSha1(salt, ikm, info, length) {
    // 1. HKDF-Extract(salt, IKM) -> PRK
    // RFC 5869: PRK = HMAC-Hash(salt, IKM)
    // 重要: salt 是 HMAC 的 Key, IKM 是 Data
    const key = await crypto.subtle.importKey('raw', salt, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const prk = await crypto.subtle.sign('HMAC', key, ikm);
    
    // 2. HKDF-Expand(PRK, info, L)
    // T = HMAC-Hash(PRK, info | 0x01)
    const infoBuffer = new Uint8Array(info.length + 1);
    infoBuffer.set(info, 0);
    infoBuffer[info.length] = 0x01; // 正确拼接计数器
    
    const prkKey = await crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const t1 = await crypto.subtle.sign('HMAC', prkKey, infoBuffer);
    
    return t1.slice(0, length);
}

/**
 * 解析 Shadowsocks 头部
 * 支持 'aes-256-gcm', 'aes-128-gcm', 'chacha20-poly1305' (取决于运行时支持) 和 'none'
 */
export async function parseShadowsocksHeader(ssBuffer, password, method = 'none') {
    const buffer = ssBuffer instanceof Uint8Array ? ssBuffer : new Uint8Array(ssBuffer);

    // --- 1. 明文模式 ---
    if (method === 'none' || !method) {
        if (buffer.byteLength < 4) return { hasError: true, message: 'SS buffer too short' };
        
        const addrType = buffer[0];
        const addressInfo = parseAddressAndPort(buffer, 1, addrType);
        if (addressInfo.hasError) return addressInfo;
        
        if (addressInfo.dataOffset + 2 > buffer.byteLength) return { hasError: true, message: 'SS buffer too short for port' };
        
        const dataView = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
        const port = dataView.getUint16(addressInfo.dataOffset, false);
        const addressRemote = resolveAddressString(addrType, addressInfo.targetAddrBytes);
        
        return { 
            hasError: false, 
            addressRemote, 
            addressType: addrType, 
            portRemote: port, 
            rawClientData: buffer.subarray(addressInfo.dataOffset + 2), 
            isUDP: false 
        };
    }

    // --- 2. AEAD 加密模式 ---
    const cipher = AEAD_METHODS[method];
    if (!cipher) {
        return { hasError: true, message: `Unsupported cipher: ${method}` };
    }

    if (buffer.byteLength < cipher.saltLen) {
        return { hasError: true, message: 'SS buffer too short for Salt' };
    }

    // 提取 Salt
    const salt = buffer.subarray(0, cipher.saltLen);
    
    // 准备 Master Key
    let masterKeyBytes = masterKeyCache.get(password);
    if (!masterKeyBytes) {
        masterKeyBytes = await evpBytesToKey(password, cipher.keyLen);
        masterKeyCache.set(password, masterKeyBytes);
    }

    // 派生 Session Subkey
    const info = textEncoder.encode('ss-subkey');
    const subKeyBytes = await hkdfSha1(salt, masterKeyBytes, info, cipher.keyLen);
    
    const algoName = method.includes('aes') ? 'AES-GCM' : 'ChaCha20-Poly1305';
    let subKey;
    try {
        subKey = await crypto.subtle.importKey(
            'raw', 
            subKeyBytes, 
            { name: algoName }, 
            false, 
            ['decrypt']
        );
    } catch (e) {
        return { hasError: true, message: `Import key failed: ${e.message}` };
    }

    // --- 解密 Chunk 0 (头部长度) ---
    // [Encrypted Length (2)] + [Tag (16)]
    const chunk0Len = 2 + cipher.tagLen;
    const offset1 = cipher.saltLen + chunk0Len;
    if (buffer.byteLength < offset1) return { hasError: true, message: 'SS buffer too short for Chunk 0' };

    const chunk0Enc = buffer.subarray(cipher.saltLen, offset1);
    const nonce0 = new Uint8Array(cipher.nonceLen); // 全 0 Nonce

    let decryptedLenBytes;
    try {
        decryptedLenBytes = await crypto.subtle.decrypt(
            { name: algoName, iv: nonce0 },
            subKey,
            chunk0Enc
        );
    } catch (e) {
        return { hasError: true, message: 'SS Decrypt Chunk 0 failed (Bad Password?)' };
    }

    // Shadowsocks 长度是大端序 (Big-Endian)
    const payloadLen = new DataView(decryptedLenBytes).getUint16(0, false) & 0x3FFF;

    // --- 解密 Chunk 1 (目标地址 Payload) ---
    // [Encrypted Payload (payloadLen)] + [Tag (16)]
    const chunk1TotalLen = payloadLen + cipher.tagLen;
    const offset2 = offset1 + chunk1TotalLen;
    
    if (buffer.byteLength < offset2) return { hasError: true, message: 'SS buffer too short for Header Payload' };

    const chunk1Enc = buffer.subarray(offset1, offset2);
    
    // Nonce 递增 (Little-Endian)
    const nonce1 = new Uint8Array(cipher.nonceLen);
    nonce1[0] = 1; 

    let decryptedHeader;
    try {
        decryptedHeader = await crypto.subtle.decrypt(
            { name: algoName, iv: nonce1 },
            subKey,
            chunk1Enc
        );
    } catch (e) {
        return { hasError: true, message: 'SS Decrypt Header Payload failed' };
    }

    const headerBuffer = new Uint8Array(decryptedHeader);
    
    // 解析明文头部
    const addrType = headerBuffer[0];
    const addressInfo = parseAddressAndPort(headerBuffer, 1, addrType);
    if (addressInfo.hasError) return addressInfo;

    const portIndex = addressInfo.dataOffset;
    const port = new DataView(headerBuffer.buffer, headerBuffer.byteOffset, headerBuffer.byteLength).getUint16(portIndex, false);
    const addressRemote = resolveAddressString(addrType, addressInfo.targetAddrBytes);

    return {
        hasError: false,
        addressRemote,
        addressType: addrType,
        portRemote: port,
        // 返回后续的加密数据，供协议栈处理（如果 Outbound 不支持流式解密，这里的数据实际上是不可用的）
        rawClientData: buffer.subarray(offset2),
        isUDP: false,
        cryptoState: {
            method,
            subKey,
            nonceValue: 2
        }
    };
}

function resolveAddressString(addrType, targetAddrBytes) {
    switch (addrType) {
        case CONSTANTS.ATYP_SS_IPV4:
            return targetAddrBytes.join('.');
        case CONSTANTS.ATYP_SS_DOMAIN:
            return textDecoder.decode(targetAddrBytes);
        case CONSTANTS.ATYP_SS_IPV6:
            const ipv6 = [];
            const v6View = new DataView(targetAddrBytes.buffer, targetAddrBytes.byteOffset, targetAddrBytes.byteLength);
            for (let i = 0; i < 8; i++) ipv6.push(v6View.getUint16(i * 2, false).toString(16));
            return '[' + ipv6.join(':') + ']';
        default:
            return '';
    }
}
