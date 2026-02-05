// src/protocols/trojan.js
/**
 * 文件名: src/protocols/trojan.js
 * 修改说明:
 * 1. [Refactor] 移除本地 trojanHashCache，直接依赖 sha224Hash 的底层缓存。
 * 2. [Cleanup] 代码逻辑简化。
 */
import { CONSTANTS } from '../constants.js';
import { textDecoder, textEncoder, sha224Hash } from '../utils/helpers.js';

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
    
    // [Optimization] 确保 buffer 是 Uint8Array，避免不必要的包装
    const buffer = trojanBuffer instanceof Uint8Array ? trojanBuffer : new Uint8Array(trojanBuffer);
    
    // 1. 验证哈希 (Offset 0-56)
    // [Refactor] 直接调用带缓存的 sha224Hash 函数
    // 底层 helpers.js 会处理 LRU 缓存，此处只需将 Hex 转为 Bytes 即可
    const hashHex = sha224Hash(String(password));
    const expectedHashBytes = textEncoder.encode(hashHex);

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
    const requestOffset = 58;
    const requestData = buffer.subarray(requestOffset);
    
    if (requestData.byteLength < 4) return { hasError: true, message: 'Trojan request too short.' };
    
    // [Optimization] 使用 DataView 读取后续字段，注意需要累加 byteOffset
    const view = new DataView(buffer.buffer, buffer.byteOffset + requestOffset, requestData.byteLength);
    
    const command = buffer[requestOffset]; // 直接读取字节
    const isUDP = (command === 3);
    
    // [Fix] 允许 CONNECT(1) 和 UDP(3)
    if (command !== 1 && !isUDP) {
        return { hasError: true, message: 'Unsupported Trojan cmd: ' + command };
    }
    
    const atyp = buffer[requestOffset + 1];
    let host = "";
    let port = 0;
    let payloadIndex = 0; // 相对于 requestOffset 的偏移
    
    // 解析地址
    try {
        switch (atyp) {
            case CONSTANTS.ADDRESS_TYPE_IPV4: // 1
                // 2(Cmd+Atyp) + 4(IPv4) + 2(Port)
                // [Optimization] 使用 subarray.join，避免创建新数组
                host = buffer.subarray(requestOffset + 2, requestOffset + 6).join('.'); 
                port = view.getUint16(6, false); // Offset 6 relative to request start
                payloadIndex = 8;
                break;
                
            case CONSTANTS.ATYP_TROJAN_DOMAIN: // 3
                const domainLen = buffer[requestOffset + 2];
                // 2(Cmd+Atyp) + 1(Len) + Domain + 2(Port)
                host = textDecoder.decode(buffer.subarray(requestOffset + 3, requestOffset + 3 + domainLen)); 
                port = view.getUint16(3 + domainLen, false);
                payloadIndex = 3 + domainLen + 2;
                break;
                
            case CONSTANTS.ATYP_TROJAN_IPV6: // 4
                // 2(Cmd+Atyp) + 16(IPv6) + 2(Port)
                const ipv6 = []; 
                for (let i = 0; i < 8; i++) {
                    ipv6.push(view.getUint16(2 + i * 2, false).toString(16));
                }
                host = '[' + ipv6.join(':') + ']'; 
                port = view.getUint16(18, false);
                payloadIndex = 20;
                break;
                
            default: 
                return { hasError: true, message: 'Invalid Trojan ATYP: ' + atyp };
        }
    } catch (e) {
        return { hasError: true, message: 'Address decode failed' };
    }
    
    // 验证 Payload 前的 CRLF
    // crlfIndex 是 Payload 之前的两个字节
    const crlfIndex = requestOffset + payloadIndex;
    
    if (buffer.byteLength < crlfIndex + 2) {
        return { hasError: true, message: 'Trojan buffer too short for payload CRLF' };
    }

    if (buffer[crlfIndex] !== 0x0D || buffer[crlfIndex + 1] !== 0x0A) {
        return { hasError: true, message: 'Trojan missing payload CRLF' };
    }
    
    // 返回 Payload 视图 (对于 UDP，这里通常是 Encapsulated Payload)
    // [Optimization] Zero-copy 视图，直接返回剩余数据的引用
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
