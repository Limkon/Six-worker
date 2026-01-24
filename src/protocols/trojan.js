// src/protocols/trojan.js
import { CONSTANTS } from '../constants.js';
import { textDecoder, sha224Hash } from '../utils/helpers.js';

// Trojan 密码哈希缓存
const trojanHashCache = new Map();
const MAX_CACHE_SIZE = 100;

export async function parseTrojanHeader(trojanBuffer, password) {
    if (trojanBuffer.byteLength < 58) return { hasError: true, message: 'Trojan buffer too short.' };
    
    const buffer = trojanBuffer instanceof Uint8Array ? trojanBuffer : new Uint8Array(trojanBuffer);
    const trojanView = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    
    // Hash 缓存检查
    let expectedHash = trojanHashCache.get(password);
    if (expectedHash) {
        trojanHashCache.delete(password);
        trojanHashCache.set(password, expectedHash);
    } else {
        expectedHash = sha224Hash(String(password));
        if (trojanHashCache.size >= MAX_CACHE_SIZE) {
            const oldestKey = trojanHashCache.keys().next().value;
            trojanHashCache.delete(oldestKey);
        }
        trojanHashCache.set(password, expectedHash);
    }

    let receivedHash;
    try { 
        receivedHash = textDecoder.decode(buffer.subarray(0, 56)); 
    } 
    catch (e) { return { hasError: true, message: 'Failed to decode client hash.'}; }
    
    if (receivedHash !== expectedHash) return { hasError: true, message: 'Invalid Trojan password.' };
    if (trojanView.getUint16(56) !== 0x0D0A) return { hasError: true, message: 'Invalid Trojan header' };
    
    const requestData = buffer.subarray(58);
    if (requestData.byteLength < 4) return { hasError: true, message: 'Trojan request too short.' };
    
    const requestView = new DataView(requestData.buffer, requestData.byteOffset, requestData.byteLength);
    const command = requestView.getUint8(0);
    
    // [Fix] 允许 CONNECT(1) 和 UDP(3)
    const isUDP = (command === 3);
    
    if (command !== 1 && !isUDP) {
        return { hasError: true, message: 'Unsupported Trojan cmd: ' + command };
    }
    
    const atyp = requestView.getUint8(1);
    let host, port, addressEndIndex = 0;
    
    switch (atyp) {
        case CONSTANTS.ADDRESS_TYPE_IPV4: 
            addressEndIndex = 2 + 4; 
            host = requestData.subarray(2, addressEndIndex).join('.'); 
            break;
        case CONSTANTS.ATYP_TROJAN_DOMAIN: 
            const domainLen = requestView.getUint8(2); 
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
    
    if (addressEndIndex + 2 > requestData.byteLength) return { hasError: true, message: 'Buffer too short for port' };

    port = requestView.getUint16(addressEndIndex, false);
    const payloadStartIndex = addressEndIndex + 2;
    
    if (requestData.byteLength < payloadStartIndex + 2 || requestView.getUint16(payloadStartIndex) !== 0x0D0A) {
        return { hasError: true, message: 'Trojan missing CRLF' };
    }
    
    // 返回 Payload 视图 (对于 UDP，这里通常是 Encapsulated Payload)
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
