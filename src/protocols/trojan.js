import { CONSTANTS } from '../constants.js';
import { textDecoder, sha224Hash } from '../utils/helpers.js';

export async function parseTrojanHeader(trojanBuffer, password) {
    if (trojanBuffer.byteLength < 58) return { hasError: true, message: 'Trojan buffer too short.' };
    
    // [修复] 防止崩溃
    const buffer = trojanBuffer instanceof Uint8Array ? trojanBuffer : new Uint8Array(trojanBuffer);
    const trojanView = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    
    const expectedHash = sha224Hash(String(password));
    let receivedHash;
    try { receivedHash = textDecoder.decode(buffer.slice(0, 56)); } 
    catch (e) { return { hasError: true, message: 'Failed to decode client hash.'}; }
    
    if (receivedHash !== expectedHash) return { hasError: true, message: 'Invalid Trojan password.' };
    if (trojanView.getUint16(56) !== 0x0D0A) return { hasError: true, message: 'Invalid Trojan header' };
    
    const requestData = buffer.slice(58);
    if (requestData.byteLength < 4) return { hasError: true, message: 'Trojan request too short.' };
    
    const requestView = new DataView(requestData.buffer, requestData.byteOffset, requestData.byteLength);
    const command = requestView.getUint8(0);
    if (command !== 1) return { hasError: true, message: 'Unsupported Trojan cmd: ' + command };
    
    const atyp = requestView.getUint8(1);
    let host, port, addressEndIndex = 0;
    
    switch (atyp) {
        case CONSTANTS.ADDRESS_TYPE_IPV4: 
            addressEndIndex = 2 + 4; 
            host = requestData.slice(2, addressEndIndex).join('.'); 
            break;
        case CONSTANTS.ATYP_TROJAN_DOMAIN: 
            const domainLen = requestView.getUint8(2); 
            addressEndIndex = 3 + domainLen; 
            host = textDecoder.decode(requestData.slice(3, addressEndIndex)); 
            break;
        case CONSTANTS.ATYP_TROJAN_IPV6: 
            addressEndIndex = 2 + 16; 
            const ipv6 = []; for (let i = 0; i < 8; i++) ipv6.push(requestView.getUint16(2 + i * 2, false).toString(16));
            host = '[' + ipv6.join(':') + ']'; 
            break;
        default: return { hasError: true, message: 'Invalid Trojan ATYP: ' + atyp };
    }
    
    port = requestView.getUint16(addressEndIndex, false);
    const payloadStartIndex = addressEndIndex + 2;
    if (requestData.byteLength < payloadStartIndex + 2 || requestView.getUint16(payloadStartIndex) !== 0x0D0A) {
        return { hasError: true, message: 'Trojan missing CRLF' };
    }
    const rawClientData = requestData.slice(payloadStartIndex + 2);
    
    return { hasError: false, addressRemote: host, addressType: atyp, portRemote: port, rawClientData, isUDP: false, rawDataIndex: 0 };
}
