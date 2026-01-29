// src/protocols/socks5.js
import { CONSTANTS } from '../constants.js';
import { textDecoder } from '../utils/helpers.js';

export async function parseSocks5Header(socksBuffer) {
    // [Optimization] Zero-copy buffer wrap
    const buffer = socksBuffer instanceof Uint8Array ? socksBuffer : new Uint8Array(socksBuffer);
    
    // 最小长度: Ver(1) + Cmd(1) + Rsv(1) + Atyp(1) = 4 bytes
    if (buffer.byteLength < 4) return { hasError: true, message: 'SOCKS buffer too short.' };
    
    const socksVersion = buffer[0];
    if (socksVersion !== CONSTANTS.SOCKS_VERSION) return { hasError: true, message: 'Invalid SOCKS version.' };
    
    const cmd = buffer[1];
    const isUDP = (cmd === 3);
    
    // [Fix] 允许 CONNECT (1) 和 UDP ASSOCIATE (3)
    if (cmd !== CONSTANTS.SOCKS_CMD_CONNECT && !isUDP) {
        return { hasError: true, message: 'Unsupported SOCKS command: ' + cmd };
    }
    
    if (buffer[2] !== 0x00) return { hasError: true, message: 'Invalid SOCKS RSV.' };
    
    const addrType = buffer[3];
    
    // [Optimization] 使用 DataView 读取后续数据
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    
    let addressRemote = "";
    let portRemote = 0;
    let payloadStartIndex = 0;
    
    try {
        // 内联地址解析 (Offset 从 4 开始)
        switch (addrType) {
            case CONSTANTS.ADDRESS_TYPE_IPV4: {
                if (buffer.byteLength < 10) return { hasError: true, message: 'SOCKS buffer too short for IPv4' };
                // 4(Head) + 4(IPv4) + 2(Port) = 10
                addressRemote = buffer.subarray(4, 8).join('.'); 
                portRemote = view.getUint16(8, false);
                payloadStartIndex = 10;
                break;
            }
            case CONSTANTS.ATYP_TROJAN_DOMAIN: {
                if (buffer.byteLength < 5) return { hasError: true, message: 'SOCKS buffer too short for Domain len' };
                const domainLen = buffer[4];
                const boundary = 5 + domainLen + 2;
                if (buffer.byteLength < boundary) return { hasError: true, message: 'SOCKS buffer too short for Domain' };
                
                addressRemote = textDecoder.decode(buffer.subarray(5, 5 + domainLen)); 
                portRemote = view.getUint16(5 + domainLen, false);
                payloadStartIndex = boundary;
                break;
            }
            case CONSTANTS.ATYP_TROJAN_IPV6: {
                if (buffer.byteLength < 22) return { hasError: true, message: 'SOCKS buffer too short for IPv6' };
                // 4(Head) + 16(IPv6) + 2(Port) = 22
                const ipv6 = [];
                for (let i = 0; i < 8; i++) ipv6.push(view.getUint16(4 + i * 2, false).toString(16));
                addressRemote = '[' + ipv6.join(':') + ']';
                portRemote = view.getUint16(20, false);
                payloadStartIndex = 22;
                break;
            }
            default: 
                return { hasError: true, message: 'Invalid SOCKS ATYP: ' + addrType };
        }
    } catch (e) {
        return { hasError: true, message: 'Address parse failed' };
    }
    
    return { 
        hasError: false, 
        addressRemote, 
        addressType: addrType, 
        portRemote, 
        // [Optimization] 返回剩余数据的引用 (Zero-copy)
        rawClientData: buffer.subarray(payloadStartIndex), 
        isUDP: isUDP, 
        rawDataIndex: payloadStartIndex, 
        isSocks5: true 
    };
}
