// src/protocols/mandala.js
/**
 * 文件名: src/protocols/mandala.js
 * 修改说明:
 * 1. [Refactor] 移除本地缓存逻辑，直接依赖 src/utils/helpers.js 的全局 sha224Hash 缓存。
 * 2. [Cleanup] 简化哈希比对流程。
 */
import { CONSTANTS } from '../constants.js';
import { textDecoder, textEncoder, sha224Hash } from '../utils/helpers.js';

/**
 * [安全] 常量时间比较函数
 * 防止侧信道攻击
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
    // Mandala 协议头结构与 Trojan 非常相似
    // 58 = Hash(56) + CR(1) + LF(1)
    if (mandalaBuffer.byteLength < 58) return { hasError: true, message: 'Mandala buffer too short.' };
    
    // [Optimization] 确保 buffer 是 Uint8Array
    const buffer = mandalaBuffer instanceof Uint8Array ? mandalaBuffer : new Uint8Array(mandalaBuffer);
    
    // 1. 验证哈希 (Offset 0-56)
    // [Refactor] 直接调用带缓存的 sha224Hash 函数
    // 底层 helpers.js 会自动处理 LRU 缓存，这里只需要转换编码
    const hashHex = sha224Hash(String(password));
    const expectedHashBytes = textEncoder.encode(hashHex);

    const receivedHashBytes = buffer.subarray(0, 56);
    
    // [安全] 常量时间比对
    if (!constantTimeEqual(receivedHashBytes, expectedHashBytes)) {
        return { hasError: true, message: 'Invalid Mandala password.' };
    }

    // 2. 验证 CRLF
    if (buffer[56] !== 0x0D || buffer[57] !== 0x0A) {
        return { hasError: true, message: 'Invalid Mandala header (Missing CRLF)' };
    }
    
    // 3. 解析请求 (Cmd + Atyp + Addr + Port + CRLF + Payload)
    const requestOffset = 58;
    const requestData = buffer.subarray(requestOffset);
    
    if (requestData.byteLength < 4) return { hasError: true, message: 'Mandala request too short.' };
    
    const view = new DataView(buffer.buffer, buffer.byteOffset + requestOffset, requestData.byteLength);
    
    const command = buffer[requestOffset];
    const isUDP = (command === 3);
    
    if (command !== 1 && !isUDP) {
        return { hasError: true, message: 'Unsupported Mandala cmd: ' + command };
    }
    
    const atyp = buffer[requestOffset + 1];
    let host = "";
    let port = 0;
    let payloadIndex = 0;
    
    // 解析地址
    try {
        switch (atyp) {
            case CONSTANTS.ADDRESS_TYPE_IPV4: // 1
                host = buffer.subarray(requestOffset + 2, requestOffset + 6).join('.'); 
                port = view.getUint16(6, false);
                payloadIndex = 8;
                break;
                
            case CONSTANTS.ATYP_TROJAN_DOMAIN: // 3
                const domainLen = buffer[requestOffset + 2];
                host = textDecoder.decode(buffer.subarray(requestOffset + 3, requestOffset + 3 + domainLen)); 
                port = view.getUint16(3 + domainLen, false);
                payloadIndex = 3 + domainLen + 2;
                break;
                
            case CONSTANTS.ATYP_TROJAN_IPV6: // 4
                const ipv6 = []; 
                for (let i = 0; i < 8; i++) {
                    ipv6.push(view.getUint16(2 + i * 2, false).toString(16));
                }
                host = '[' + ipv6.join(':') + ']'; 
                port = view.getUint16(18, false);
                payloadIndex = 20;
                break;
                
            default: 
                return { hasError: true, message: 'Invalid Mandala ATYP: ' + atyp };
        }
    } catch (e) {
        return { hasError: true, message: 'Address decode failed' };
    }
    
    const crlfIndex = requestOffset + payloadIndex;
    
    if (buffer.byteLength < crlfIndex + 2) {
        return { hasError: true, message: 'Mandala buffer too short for payload CRLF' };
    }

    if (buffer[crlfIndex] !== 0x0D || buffer[crlfIndex + 1] !== 0x0A) {
        return { hasError: true, message: 'Mandala missing payload CRLF' };
    }
    
    const rawClientData = buffer.subarray(crlfIndex + 2);
    
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
