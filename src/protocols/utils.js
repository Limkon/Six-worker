import { CONSTANTS } from '../constants.js';
import { textDecoder } from '../utils/helpers.js';

export const parseAddressAndPort = (buffer, offset, addrType) => {
    // [优化] 如果 buffer 已经是 Uint8Array，直接使用，避免复制
    const bufferView = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let addressLength;
    
    if (addrType === CONSTANTS.ATYP_SS_DOMAIN) { // Domain
        if (offset >= bufferView.length) return { hasError: true, message: "Buffer too short for domain length" };
        addressLength = bufferView[offset];
        offset += 1;
    } else if (addrType === CONSTANTS.ATYP_SS_IPV4) { // IPv4
        addressLength = 4;
    } else if (addrType === CONSTANTS.ATYP_SS_IPV6) { // IPv6
        addressLength = 16;
    } else {
        return { hasError: true, message: 'Invalid ATYP: ' + addrType };
    }
    
    const newOffset = offset + addressLength;
    if (newOffset > bufferView.length) {
        return { hasError: true, message: 'Buffer too short for address' };
    }
    
    // [优化] 使用 subarray 返回视图，避免内存复制
    const targetAddrBytes = bufferView.subarray(offset, newOffset);
    return { hasError: false, targetAddrBytes, dataOffset: newOffset };
};
