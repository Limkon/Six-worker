// src/protocols/trojan.js
import { CONSTANTS } from '../constants.js';
import { textDecoder, textEncoder, sha224Hash } from '../utils/helpers.js';

// Trojan 密码哈希缓存 (存储 Uint8Array 以优化性能)
const trojanHashCache = new Map();
const MAX_CACHE_SIZE = 100;

/**
 * [安全] 常量时间比较函数
 * 防止通过比对耗时推测哈希内容的侧信道攻击
 * @param {Uint8Array} a 
 * @param {Uint8Array} b 
 * @returns {boolean}
 */
function constantTimeEqual(a, b) {
    if (a.byteLength !== b.byteLength) return false;
    let mismatch = 0;
    for (let i = 0; i < a.byteLength; i++) {
        mismatch |= a[i] ^ b[i];
    }
    return mismatch === 0;
}

export async function parseTrojanHeader(trojanBuffer, password) {
    // 58 = Hash(56) + CR(1) + LF(1)
    if (trojanBuffer.byteLength < 58) return { hasError: true, message: 'Trojan buffer too short.' };
    
    // [优化] 避免不必要的包装
    const buffer = trojanBuffer instanceof Uint8Array ? trojanBuffer : new Uint8Array(trojanBuffer);
    
    // 1. 验证哈希 (Offset 0-56)
    // [优化] 直接操作 Bytes，避免将网络数据解码为 String
    let expectedHashBytes = trojanHashCache.get(password);
    
    if (expectedHashBytes) {
        trojanHashCache.delete(password);
        trojanHashCache.set(password, expectedHashBytes);
    } else {
        // 计算 SHA224 并转换为 Bytes 缓存
        const hashHex = sha224Hash(String(password));
        expectedHashBytes = textEncoder.encode(hashHex);
        
        if (trojanHashCache.size >= MAX_CACHE_SIZE) {
            const oldestKey = trojanHashCache.keys().next().value;
            trojanHashCache.delete(oldestKey);
        }
        trojanHashCache.set(password, expectedHashBytes);
    }

    const receivedHashBytes = buffer.subarray(0, 56);
    
    // [安全] 使用常量时间比对
    if (!constantTimeEqual(receivedHashBytes, expectedHashBytes)) {
        return { hasError: true, message: 'Invalid Trojan password.' };
    }

    // 2. 验证 CRLF
    if (buffer[56] !== 0x0D || buffer[57] !== 0x0A) {
        return { hasError: true, message: 'Invalid Trojan header (Missing CRLF)' };
    }
    
    // 3. 解析请求 (Cmd + Atyp + Addr + Port + CRLF + Payload)
    const requestData = buffer.subarray(58);
    if (requestData.byteLength < 4) return { hasError: true, message: 'Trojan request too short.' };
    
    // [优化] 统一 DataView
    const requestView = new DataView(requestData.buffer, requestData.byteOffset, requestData.byteLength);
    const command = requestData[0]; // 这是一个字节，直接读取即可，不需要 DataView
    
    // [Fix] 允许 CONNECT(1) 和 UDP(3)
    const isUDP = (command === 3);
    
    if (command !== 1 && !isUDP) {
        return { hasError: true, message: 'Unsupported Trojan cmd: ' + command };
    }
    
    const atyp = requestData[1];
    let host, port, addressEndIndex = 0;
    
    // 解析地址
    try {
        switch (atyp) {
            case CONSTANTS.ADDRESS_TYPE_IPV4: 
                addressEndIndex = 2 + 4; 
                // [优化] subarray join
                host = requestData.subarray(2, addressEndIndex).join('.'); 
                break;
            case CONSTANTS.ATYP_TROJAN_DOMAIN: 
                const domainLen = requestData[2]; 
                addressEndIndex = 3 + domainLen; 
                host = textDecoder.decode(requestData.subarray(3, addressEndIndex)); 
                break;
            case CONSTANTS.ATYP_TROJAN_IPV6: 
                addressEndIndex = 2 + 16; 
                const ipv6 = []; 
                for (let i = 0; i < 8; i++) ipv6.push(requestView.getUint16(2 + i * 2, false).toString(16));
                host = '[' + ipv6.join(':') + ']'; 
                break;
            default: return { hasError: true, message: 'Invalid Trojan ATYP: ' + atyp };
        }
    } catch (e) {
        return { hasError: true, message: 'Address decode failed' };
    }
    
    // 验证端口数据长度
    if (addressEndIndex + 2 > requestData.byteLength) return { hasError: true, message: 'Buffer too short for port' };

    port = requestView.getUint16(addressEndIndex, false);
    const payloadStartIndex = addressEndIndex + 2;
    
    // 验证 Payload 前的 CRLF
    if (requestData.byteLength < payloadStartIndex + 2) return { hasError: true, message: 'Trojan missing payload CRLF' };
    if (requestData[payloadStartIndex] !== 0x0D || requestData[payloadStartIndex + 1] !== 0x0A) {
        return { hasError: true, message: 'Trojan missing payload CRLF' };
    }
    
    // 返回 Payload 视图 (对于 UDP，这里通常是 Encapsulated Payload)
    // [优化] Zero-copy 视图
    const rawClientData = requestData.subarray(payloadStartIndex + 2);
    
    return { 
        hasError: false, 
        addressRemote: host, 
        addressType: atyp, 
        portRemote: port, 
        rawClientData, 
        isUDP: isUDP, 
        rawDataIndex: 0 
    };
}
