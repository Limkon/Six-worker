import { CONSTANTS } from '../constants.js';
import { textDecoder } from '../utils/helpers.js';
import { parseAddressAndPort } from './utils.js';

export async function parseShadowsocksHeader(ssBuffer) {
    // [优化] 避免不必要的 Uint8Array 包装
    const buffer = ssBuffer instanceof Uint8Array ? ssBuffer : new Uint8Array(ssBuffer);
    
    if (buffer.byteLength < 4) return { hasError: true, message: 'SS buffer too short' };
    
    const addrType = buffer[0];
    let offset = 1;
    
    const addressInfo = parseAddressAndPort(buffer, offset, addrType);
    if (addressInfo.hasError) return addressInfo;
    
    if (addressInfo.dataOffset + 2 > buffer.byteLength) return { hasError: true, message: 'SS buffer too short for port' };
    
    // [优化] 确保 DataView 使用正确的 offset (支持 buffer 为 subarray 的情况)
    const dataView = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const port = dataView.getUint16(addressInfo.dataOffset, false);
    
    let addressRemote = "";
    switch (addrType) {
        case CONSTANTS.ATYP_SS_IPV4: 
            addressRemote = addressInfo.targetAddrBytes.join('.'); 
            break;
        case CONSTANTS.ATYP_SS_DOMAIN: 
            addressRemote = textDecoder.decode(addressInfo.targetAddrBytes); 
            break;
        case CONSTANTS.ATYP_SS_IPV6:
            const ipv6 = [];
            // [优化] 直接基于 targetAddrBytes 的 buffer 创建视图
            const addrBytesView = new DataView(addressInfo.targetAddrBytes.buffer, addressInfo.targetAddrBytes.byteOffset, addressInfo.targetAddrBytes.byteLength);
            for (let i = 0; i < 8; i++) ipv6.push(addrBytesView.getUint16(i * 2, false).toString(16));
            addressRemote = '[' + ipv6.join(':') + ']';
            break;
        default: return { hasError: true, message: 'Invalid SS ATYP: ' + addrType };
    }
    
    return { 
        hasError: false, 
        addressRemote, 
        addressType: addrType, 
        portRemote: port, 
        // [优化] 使用 subarray 返回剩余数据视图，极大减少内存复制开销
        rawClientData: buffer.subarray(addressInfo.dataOffset + 2), 
        isUDP: false, 
        rawDataIndex: 0 
    };
}
