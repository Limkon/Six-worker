// src/protocols/shadowsocks.js
import { CONSTANTS } from '../constants.js';
import { textDecoder } from '../utils/helpers.js';

export async function parseShadowsocksHeader(ssBuffer) {
    // [Optimization] 避免不必要的 Uint8Array 包装 (Zero-copy check)
    const buffer = ssBuffer instanceof Uint8Array ? ssBuffer : new Uint8Array(ssBuffer);
    
    // 最小长度检查: ATYP(1) + ADDR(min 1) + PORT(2) = 4 bytes
    if (buffer.byteLength < 4) return { hasError: true, message: 'SS buffer too short' };
    
    const addrType = buffer[0];
    let addressRemote = '';
    let portRemote = 0;
    let headersLength = 0;

    try {
        // [Optimization] 使用 DataView 进行大端序读取，避免手动位移操作
        const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

        switch (addrType) {
            case CONSTANTS.ATYP_SS_IPV4: {
                // IPv4: 1(ATYP) + 4(IPv4) + 2(Port) = 7 bytes
                if (buffer.byteLength < 7) return { hasError: true, message: 'SS buffer too short for IPv4' };
                // [Optimization] 使用 subarray.join 避免内存分配
                addressRemote = buffer.subarray(1, 5).join('.');
                portRemote = view.getUint16(5, false); // Big-Endian
                headersLength = 7;
                break;
            }
            case CONSTANTS.ATYP_SS_DOMAIN: {
                // Domain: 1(ATYP) + 1(Len) + Domain + 2(Port)
                const domainLen = buffer[1];
                headersLength = 1 + 1 + domainLen + 2;
                if (buffer.byteLength < headersLength) return { hasError: true, message: 'SS buffer too short for Domain' };
                // [Optimization] Zero-copy decode
                addressRemote = textDecoder.decode(buffer.subarray(2, 2 + domainLen));
                portRemote = view.getUint16(2 + domainLen, false);
                break;
            }
            case CONSTANTS.ATYP_SS_IPV6: {
                // IPv6: 1(ATYP) + 16(IPv6) + 2(Port) = 19 bytes
                if (buffer.byteLength < 19) return { hasError: true, message: 'SS buffer too short for IPv6' };
                const ipv6 = [];
                // [Optimization] 使用 DataView 读取 8 个 16位整数
                for (let i = 0; i < 8; i++) {
                    ipv6.push(view.getUint16(1 + i * 2, false).toString(16));
                }
                addressRemote = '[' + ipv6.join(':') + ']';
                portRemote = view.getUint16(17, false);
                headersLength = 19;
                break;
            }
            default:
                return { hasError: true, message: `Invalid SS ATYP: ${addrType}` };
        }
    } catch (e) {
        return { hasError: true, message: 'SS parse failed: ' + e.message };
    }

    return { 
        hasError: false, 
        addressRemote, 
        addressType: addrType, 
        portRemote, 
        // [Optimization] 返回剩余数据的引用，完全零拷贝
        rawClientData: buffer.subarray(headersLength), 
        isUDP: false, 
        rawDataIndex: headersLength 
    };
}
