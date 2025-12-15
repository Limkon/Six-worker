import { CONSTANTS } from '../constants.js';
import { textDecoder } from '../utils/helpers.js';
import { parseAddressAndPort } from './utils.js';

export async function parseSocks5Header(socksBuffer, offset = 0) {
    const buffer = socksBuffer instanceof Uint8Array ? socksBuffer : new Uint8Array(socksBuffer);
    const originalLength = buffer.length;
    if (!offset) offset = 0; // [修复] 处理 offset 为空的情况

    if (offset + 4 > originalLength) return { hasError: true, message: 'SOCKS buffer too short.' };
    
    const socksVersion = buffer[offset];
    if (socksVersion !== CONSTANTS.SOCKS_VERSION) return { hasError: true, message: 'Invalid SOCKS version.' };
    
    const cmd = buffer[offset + 1];
    if (cmd !== CONSTANTS.SOCKS_CMD_CONNECT) return { hasError: true, message: 'Unsupported SOCKS command: ' + cmd };
    
    if (buffer[offset + 2] !== 0x00) return { hasError: true, message: 'Invalid SOCKS RSV.' };
    
    const addrType = buffer[offset + 3];
    let addressOffset = offset + 4;
    
    const addressInfo = parseAddressAndPort(buffer, addressOffset, addrType);
    if (addressInfo.hasError) return addressInfo;
    
    if (addressInfo.dataOffset + 2 > originalLength) return { hasError: true, message: 'SOCKS buffer too short for port' };
    
    // [修复] 使用 buffer.buffer
    const dataView = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const port = dataView.getUint16(addressInfo.dataOffset, false);
    
    let addressRemote = "";
    switch (addrType) {
        case CONSTANTS.ADDRESS_TYPE_IPV4: addressRemote = addressInfo.targetAddrBytes.join('.'); break;
        case CONSTANTS.ATYP_TROJAN_DOMAIN: addressRemote = textDecoder.decode(addressInfo.targetAddrBytes); break;
        case CONSTANTS.ATYP_TROJAN_IPV6:
            const ipv6 = [];
            const addrBytesView = new DataView(addressInfo.targetAddrBytes.buffer, addressInfo.targetAddrBytes.byteOffset, addressInfo.targetAddrBytes.byteLength);
            for (let i = 0; i < 8; i++) ipv6.push(addrBytesView.getUint16(i * 2, false).toString(16));
            addressRemote = '[' + ipv6.join(':') + ']';
            break;
        default: return { hasError: true, message: 'Invalid SOCKS ATYP: ' + addrType };
    }
    
    return { hasError: false, addressRemote, addressType: addrType, portRemote: port, rawClientData: buffer.slice(addressInfo.dataOffset + 2), isUDP: false, rawDataIndex: 0, isSocks5: true };
}
