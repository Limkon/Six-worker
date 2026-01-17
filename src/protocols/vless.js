import { CONSTANTS } from '../constants.js';
import { textDecoder, stringifyUUID } from '../utils/helpers.js';

export async function processVlessHeader(vlessBuffer, expectedUserIDs) {
    if (vlessBuffer.byteLength < 24) return { hasError: true, message: "Buffer too short" };
    
    const buffer = vlessBuffer instanceof Uint8Array ? vlessBuffer : new Uint8Array(vlessBuffer);
    
    const version = buffer[0];
    if (version !== 0) return { hasError: true, message: "Invalid VLESS version" };
    
    // [优化] slice -> subarray
    const uuid = stringifyUUID(buffer.subarray(1, 17));
    if (!expectedUserIDs.map(id => id.toLowerCase()).includes(uuid)) {
        return { hasError: true, message: "Invalid VLESS user" };
    }
    
    const optLength = buffer[17];
    const command = buffer[18 + optLength];
    
    let isUDP = command === 2;
    if (command !== 1 && command !== 2) return { hasError: true, message: 'Unsupported VLESS command: ' + command};
    
    const portIndex = 19 + optLength;
    if (buffer.byteLength < portIndex + 2) return { hasError: true, message: "Buffer too short" };

    const portRemote = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength).getUint16(portIndex, false);
    
    let addressIndex = portIndex + 2;
    const addressType = buffer[addressIndex];
    addressIndex++;
    
    let addressRemote = "";
    let addressLength = 0;
    
    switch (addressType) {
        case CONSTANTS.ADDRESS_TYPE_IPV4: 
            addressLength = 4; 
            addressRemote = buffer.subarray(addressIndex, addressIndex + 4).join('.'); 
            break;
        case CONSTANTS.ADDRESS_TYPE_URL: 
            addressLength = buffer[addressIndex]; 
            addressIndex++; 
            addressRemote = textDecoder.decode(buffer.subarray(addressIndex, addressIndex + addressLength)); 
            break;
        case CONSTANTS.ADDRESS_TYPE_IPV6: 
            addressLength = 16;
            const ipv6View = new DataView(buffer.buffer, buffer.byteOffset + addressIndex, 16);
            const ipv6 = [];
            for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2, false).toString(16));
            addressRemote = '[' + ipv6.join(':') + ']';
            break;
        default: 
            return { hasError: true, message: 'Invalid VLESS addressType: ' + addressType };
    }
    
    if (!addressRemote) return { hasError: true, message: "VLESS address is empty" };
    
    // cloudflareVersion 仅 2 字节，创建一个新的 Uint8Array 开销很小，可以保留
    return { hasError: false, addressRemote, addressType, portRemote, isUDP, rawDataIndex: addressIndex + addressLength, cloudflareVersion: new Uint8Array([version]) };
}
