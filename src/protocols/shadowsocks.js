// src/protocols/shadowsocks.js
import { CONSTANTS } from '../constants.js';
import { textDecoder, textEncoder } from '../utils/helpers.js';
import { parseAddressAndPort } from './utils.js';

// Shadowsocks AEAD 常量
const AEAD_METHODS = {
    'aes-256-gcm': { keyLen: 32, saltLen: 32, nonceLen: 12, tagLen: 16 },
    'aes-128-gcm': { keyLen: 16, saltLen: 16, nonceLen: 12, tagLen: 16 },
    'chacha20-poly1305': { keyLen: 32, saltLen: 32, nonceLen: 12, tagLen: 16 },
};

// 缓存派生的主密钥 (Master Key)，避免重复计算
const masterKeyCache = new Map();

/**
 * OpenSSL EVP_BytesToKey 实现 (MD5)
 * 用于将字符串密码转换为符合 Shadowsocks 标准的 Master Key
 */
async function evpBytesToKey(password, keyLen) {
    const passBytes = textEncoder.encode(password);
    let key = new Uint8Array(0);
    let prevHash = new Uint8Array(0);

    // 循环计算 MD5 直到密钥长度满足要求
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
 */
async function hkdfSha1(salt, ikm, info, length) {
    const key = await crypto.subtle.importKey('raw', ikm, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const prk = await crypto.subtle.sign('HMAC', key, salt);
    
    const infoBuffer = new Uint8Array(info.length + 1 + 1);
    infoBuffer.set(info, 0);
    infoBuffer[info.length + 1] = 1; // Counter
    
    const prkKey = await crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    // Shadowsocks 只用第一块 (T1)
    const t1 = await crypto.subtle.sign('HMAC', prkKey, infoBuffer.slice(0, info.length + 1));
    return t1.slice(0, length);
}

/**
 * 解析 Shadowsocks 头部 (支持 aes-256-gcm 和 none)
 * @param {Uint8Array} ssBuffer - 输入数据
 * @param {string} password - 密码
 * @param {string} method - 加密方式 (默认 'none', 支持 'aes-256-gcm')
 */
export async function parseShadowsocksHeader(ssBuffer, password, method = 'none') {
    // [优化] 避免不必要的 Uint8Array 包装
    const buffer = ssBuffer instanceof Uint8Array ? ssBuffer : new Uint8Array(ssBuffer);

    // --- 1. 处理 "none" (明文) ---
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
            isUDP: false, 
            rawDataIndex: 0 
        };
    }

    // --- 2. 处理 AEAD 加密 (如 aes-256-gcm) ---
    const cipher = AEAD_METHODS[method];
    if (!cipher) {
        return { hasError: true, message: `Unsupported cipher: ${method}` };
    }

    // 检查 Salt 长度
    if (buffer.byteLength < cipher.saltLen) {
        return { hasError: true, message: 'SS buffer too short for Salt' };
    }

    const salt = buffer.subarray(0, cipher.saltLen);
    
    // 获取 Master Key
    let masterKeyBytes = masterKeyCache.get(password);
    if (!masterKeyBytes) {
        // [修复] 使用 EVP_BytesToKey 生成兼容标准客户端的 Key
        masterKeyBytes = await evpBytesToKey(password, cipher.keyLen);
        masterKeyCache.set(password, masterKeyBytes);
    }

    // 密钥派生 (HKDF)
    const info = textEncoder.encode('ss-subkey');
    const subKeyBytes = await hkdfSha1(salt, masterKeyBytes, info, cipher.keyLen);
    
    // 导入为 CryptoKey
    // 注意: ChaCha20-Poly1305 在原生 Web Crypto 中可能不受支持，这里主要针对 AES-GCM
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
    // AEAD 结构: [Encrypted Length (2bytes)] + [Tag (16bytes)]
    const chunk0Len = 2 + cipher.tagLen;
    const offset1 = cipher.saltLen + chunk0Len;
    if (buffer.byteLength < offset1) return { hasError: true, message: 'SS buffer too short for Chunk 0' };

    const chunk0Enc = buffer.subarray(cipher.saltLen, offset1);
    
    // Nonce 0 (12 bytes, all zeros)
    const nonce0 = new Uint8Array(cipher.nonceLen); 

    let decryptedLenBytes;
    try {
        decryptedLenBytes = await crypto.subtle.decrypt(
            { name: algoName, iv: nonce0 },
            subKey,
            chunk0Enc
        );
    } catch (e) {
        // 解密失败通常意味着密码错误或加密方式不匹配
        return { hasError: true, message: 'SS Decrypt Chunk 0 failed (Invalid Password?)' };
    }

    const payloadLen = new DataView(decryptedLenBytes).getUint16(0, false) & 0x3FFF; // Max 16KB

    // --- 解密 Chunk 1 (头部 Payload: Address + Port) ---
    // 结构: [Encrypted Payload (payloadLen)] + [Tag (16bytes)]
    const chunk1TotalLen = payloadLen + cipher.tagLen;
    const offset2 = offset1 + chunk1TotalLen;
    if (buffer.byteLength < offset2) return { hasError: true, message: 'SS buffer too short for Header Payload' };

    const chunk1Enc = buffer.subarray(offset1, offset2);
    
    // Nonce 1 (Little-Endian increment)
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
    
    // 解析解密后的头部 (ATYP + Addr + Port)
    // 这里的 headerBuffer 已经是明文数据，结构同 'none' 模式
    const addrType = headerBuffer[0];
    const addressInfo = parseAddressAndPort(headerBuffer, 1, addrType);
    if (addressInfo.hasError) return addressInfo;

    const portIndex = addressInfo.dataOffset;
    if (portIndex + 2 > headerBuffer.byteLength) return { hasError: true, message: 'SS Header too short' };

    const port = new DataView(headerBuffer.buffer, headerBuffer.byteOffset, headerBuffer.byteLength).getUint16(portIndex, false);
    const addressRemote = resolveAddressString(addrType, addressInfo.targetAddrBytes);

    // 返回结果
    // 注意：rawClientData 返回的是剩余的 **加密数据**。
    // 如果 Worker 不具备全流解密转发能力，这部分数据直接转发给目标服务器是没有意义的。
    // 但作为协议探测/头部解析，这是正确的返回。
    
    return {
        hasError: false,
        addressRemote,
        addressType: addrType,
        portRemote: port,
        rawClientData: buffer.subarray(offset2), 
        isUDP: false, 
        cryptoState: {
            method,
            subKey,
            nonceValue: 2 // 下一个 nonce
        }
    };
}

// 辅助函数：还原地址字符串
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
