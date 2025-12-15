import { CONSTANTS } from '../constants.js';
import { textDecoder } from '../utils/helpers.js';
import { parseAddressAndPort } from './utils.js';

export async function parseShadowsocksHeader(ssBuffer) {
    const buffer = ssBuffer instanceof Uint8Array ? ssBuffer : new Uint8Array(ssBuffer);
    
    if (buffer.byteLength < 4) return { hasError: true, message: 'SS buffer too short' };
    
    const addrType = buffer[0];
    let offset = 1;
    
    const addressInfo = parseAddressAndPort(buffer, offset, addrType);
    if (addressInfo.hasError) return addressInfo;
    
    if (addressInfo.dataOffset + 2 > buffer.byteLength) return { hasError: true, message: 'SS buffer too short for port' };
    
    // [修复] 使用 buffer.buffer
    const dataView = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const port = dataView.getUint16(addressInfo.dataOffset, false);
    
    let addressRemote = "";
    switch (addrType) {
        case CONSTANTS.ATYP_SS_IPV4: addressRemote = addressInfo.targetAddrBytes.join('.'); break;
        case CONSTANTS.ATYP_SS_DOMAIN: addressRemote = textDecoder.decode(addressInfo.targetAddrBytes); break;
        case CONSTANTS.ATYP_SS_IPV6:
            const ipv6 = [];
            const addrBytesView = new DataView(addressInfo.targetAddrBytes.buffer, addressInfo.targetAddrBytes.byteOffset, addressInfo.targetAddrBytes.byteLength);
            for (let i = 0; i < 8; i++) ipv6.push(addrBytesView.getUint16(i * 2, false).toString(16));
            addressRemote = '[' + ipv6.join(':') + ']';
            break;
        default: return { hasError: true, message: 'Invalid SS ATYP: ' + addrType };
    }
    
    return { hasError: false, addressRemote, addressType: addrType, portRemote: port, rawClientData: buffer.slice(addressInfo.dataOffset + 2), isUDP: false, rawDataIndex: 0 };
}
