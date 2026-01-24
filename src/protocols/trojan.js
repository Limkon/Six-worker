// src/protocols/trojan.js
import { CONSTANTS } from '../constants.js';
import { textDecoder, sha224Hash } from '../utils/helpers.js';

// [优化] 缓存 Trojan 密码哈希
const trojanHashCache = new Map();
const MAX_CACHE_SIZE = 100;

export async function parseTrojanHeader(trojanBuffer, password) {
    if (trojanBuffer.byteLength < 58) return { hasError: true, message: 'Trojan buffer too short.' };
    
    // [优化] 避免不必要的 new Uint8Array 包装 (如果已经是 Uint8Array)
    const buffer = trojanBuffer instanceof Uint8Array ? trojanBuffer : new Uint8Array(trojanBuffer);
    const trojanView = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    
    // [优化] LRU 缓存策略，消除定期清空带来的抖动
    let expectedHash = trojanHashCache.get(password);
    
    if (expectedHash) {
        // [LRU] 命中：移动到末尾（最新）
        trojanHashCache.delete(password);
        trojanHashCache.set(password, expectedHash);
    } else {
        // 未命中：计算并插入
        expectedHash = sha224Hash(String(password));
        
        // [LRU] 溢出：移除头部（最旧）
        if (trojanHashCache.size >= MAX_CACHE_SIZE) {
            const oldestKey = trojanHashCache.keys().next().value;
            trojanHashCache.delete(oldestKey);
        }
        trojanHashCache.set(password, expectedHash);
    }

    let receivedHash;
    try { 
        // [优化] 使用 subarray (视图) 而非 slice (内存复制)，减少 GC 压力
        receivedHash = textDecoder.decode(buffer.subarray(0, 56)); 
    } 
    catch (e) { return { hasError: true, message: 'Failed to decode client hash.'}; }
    
    if (receivedHash !== expectedHash) return { hasError: true, message: 'Invalid Trojan password.' };
    if (trojanView.getUint16(56) !== 0x0D0A) return { hasError: true, message: 'Invalid Trojan header' };
    
    // [优化] 使用 subarray
    const requestData = buffer.subarray(58);
    if (requestData.byteLength < 4) return { hasError: true, message: 'Trojan request too short.' };
    
    const requestView = new DataView(requestData.buffer, requestData.byteOffset, requestData.byteLength);
    const command = requestView.getUint8(0);
    
    // [修改] 允许 CONNECT(1) 和 UDP(3)
    const isUDP = (command === 3);
    
    if (command !== 1 && !isUDP) {
        return { hasError: true, message: 'Unsupported Trojan cmd: ' + command };
    }
    
    const atyp = requestView.getUint8(1);
    let host, port, addressEndIndex = 0;
    
    switch (atyp) {
        case CONSTANTS.ADDRESS_TYPE_IPV4: 
            addressEndIndex = 2 + 4; 
            // IPv4 比较短，join 消耗不大，subarray 也可以
            host = requestData.subarray(2, addressEndIndex).join('.'); 
            break;
        case CONSTANTS.ATYP_TROJAN_DOMAIN: 
            const domainLen = requestView.getUint8(2); 
            addressEndIndex = 3 + domainLen; 
            // [优化] 使用 subarray
            host = textDecoder.decode(requestData.subarray(3, addressEndIndex)); 
            break;
        case CONSTANTS.ATYP_TROJAN_IPV6: 
            addressEndIndex = 2 + 16; 
            const ipv6 = []; 
            // 保持原有逻辑，DataView 读取无需由 slice 产生新 buffer
            for (let i = 0; i < 8; i++) ipv6.push(requestView.getUint16(2 + i * 2, false).toString(16));
            host = '[' + ipv6.join(':') + ']'; 
            break;
        default: return { hasError: true, message: 'Invalid Trojan ATYP: ' + atyp };
    }
    
    // 边界检查
    if (addressEndIndex + 2 > requestData.byteLength) return { hasError: true, message: 'Buffer too short for port' };

    port = requestView.getUint16(addressEndIndex, false);
    const payloadStartIndex = addressEndIndex + 2;
    
    if (requestData.byteLength < payloadStartIndex + 2 || requestView.getUint16(payloadStartIndex) !== 0x0D0A) {
        return { hasError: true, message: 'Trojan missing CRLF' };
    }
    
    // [优化] 返回剩余数据的视图
    const rawClientData = requestData.subarray(payloadStartIndex + 2);
    
    return { 
        hasError: false, 
        addressRemote: host, 
        addressType: atyp, 
        portRemote: port, 
        rawClientData, 
        isUDP: isUDP, // [修改] 返回正确的 UDP 状态
        rawDataIndex: 0 
    };
}
