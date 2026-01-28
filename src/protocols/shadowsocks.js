// src/protocols/shadowsocks.js
import { CONSTANTS } from '../constants.js';
import { textDecoder, textEncoder } from '../utils/helpers.js';
import { parseAddressAndPort } from './utils.js';

// Shadowsocks AEAD 常量
const AEAD_METHODS = {
    'aes-256-gcm': { keyLen: 32, saltLen: 32, nonceLen: 12, tagLen: 16 },
    'aes-128-gcm': { keyLen: 16, saltLen: 16, nonceLen: 12, tagLen: 16 },
    // chacha20-poly1305 在 Cloudflare 某些运行时可能不支持，建议优先用 aes-256-gcm
};

// 缓存派生的主密钥 (Master Key)，避免重复 PBKDF2/Hash 计算
const masterKeyCache = new Map();

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
    // Shadowsocks 只用第一块 (T1)，足够生成 32字节 Subkey
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
    
    // 密钥派生 (HKDF)
    // 注意: 标准 SS 使用 "ss-subkey" 字符串作为 Info
    const info = textEncoder.encode('ss-subkey');
    
    // 获取 Master Key (这里简化处理，假设 password 已经是 32字节 key 或者通过某种方式预处理过)
    // 在生产环境中，通常需要对 password 进行 MD5/EVP_BytesToKey 处理得到 MasterKey
    // 这里为了演示，假设 password 经过处理或直接作为 key 种子
    // 如果 password 是普通字符串，建议先做一次 SHA-256
    let masterKeyBytes = masterKeyCache.get(password);
    if (!masterKeyBytes) {
        const passBuf = textEncoder.encode(password);
        // 使用 SHA-256 将任意长度密码规整为 32 字节 (对于 aes-256-gcm)
        const hash = await crypto.subtle.digest('SHA-256', passBuf);
        masterKeyBytes = new Uint8Array(hash);
        masterKeyCache.set(password, masterKeyBytes);
    }

    // 派生会话子密钥 (Subkey)
    const subKeyBytes = await hkdfSha1(salt, masterKeyBytes, info, cipher.keyLen);
    
    // 导入为 CryptoKey
    const subKey = await crypto.subtle.importKey(
        'raw', 
        subKeyBytes, 
        { name: 'AES-GCM' }, 
        false, 
        ['decrypt']
    );

    // --- 解密 Chunk 0 (头部长度) ---
    // AEAD 结构: [Encrypted Length (2bytes)] + [Tag (16bytes)]
    const chunk0Len = 2 + cipher.tagLen;
    const offset1 = cipher.saltLen + chunk0Len;
    if (buffer.byteLength < offset1) return { hasError: true, message: 'SS buffer too short for Chunk 0' };

    const chunk0Enc = buffer.subarray(cipher.saltLen, offset1);
    
    // 构造 Nonce (全0, 只有 increment 0)
    // 每次解密都需要独立的 Nonce，这里是第一个 Payload，Nonce 通常是 0
    const nonce0 = new Uint8Array(cipher.nonceLen); // filled with 0

    let decryptedLenBytes;
    try {
        decryptedLenBytes = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce0 },
            subKey,
            chunk0Enc
        );
    } catch (e) {
        return { hasError: true, message: 'SS Decrypt Chunk 0 failed' };
    }

    const payloadLen = new DataView(decryptedLenBytes).getUint16(0, false) & 0x3FFF; // Max 16KB

    // --- 解密 Chunk 1 (头部 Payload: Address + Port) ---
    // 结构: [Encrypted Payload (payloadLen)] + [Tag (16bytes)]
    const chunk1TotalLen = payloadLen + cipher.tagLen;
    const offset2 = offset1 + chunk1TotalLen;
    if (buffer.byteLength < offset2) return { hasError: true, message: 'SS buffer too short for Header Payload' };

    const chunk1Enc = buffer.subarray(offset1, offset2);
    
    // Nonce 递增
    const nonce1 = new Uint8Array(cipher.nonceLen);
    nonce1[0] = 1; // increment for next chunk

    let decryptedHeader;
    try {
        decryptedHeader = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce1 },
            subKey,
            chunk1Enc
        );
    } catch (e) {
        return { hasError: true, message: 'SS Decrypt Header Payload failed' };
    }

    const headerBuffer = new Uint8Array(decryptedHeader);
    
    // 解析解密后的头部 (ATYP + Addr + Port)
    const addrType = headerBuffer[0];
    const addressInfo = parseAddressAndPort(headerBuffer, 1, addrType);
    if (addressInfo.hasError) return addressInfo;

    const portIndex = addressInfo.dataOffset;
    if (portIndex + 2 > headerBuffer.byteLength) return { hasError: true, message: 'SS Header too short' };

    const port = new DataView(headerBuffer.buffer).getUint16(portIndex, false);
    const addressRemote = resolveAddressString(addrType, addressInfo.targetAddrBytes);

    // 返回结果
    // 注意: rawClientData 应该是解密后的剩余数据，或者是原始的剩余加密数据？
    // 如果 Worker 不做全流解密代理，这里返回 剩余的加密数据 (buffer.subarray(offset2)) 是没有意义的，因为 Outbound 无法处理。
    // 但为了保持接口一致性，我们返回剩余的 Buffer。
    // **重要**: 这里的 rawClientData 仍然是加密的。如果下游没有解密能力，连接会失败。
    
    return {
        hasError: false,
        addressRemote,
        addressType: addrType,
        portRemote: port,
        rawClientData: buffer.subarray(offset2), // 剩余的 Encrypted Chunks
        isUDP: false, // SS TCP
        // 可以返回 key/nonce 状态供后续解密使用
        cryptoState: {
            method,
            subKey,
            nonceValue: 2 // 下一个 nonce 是 2
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
