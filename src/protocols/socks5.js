/**
 * 文件名: src/protocols/socks5.js
 * 说明: 解析 SOCKS5 请求帧 (VER CMD RSV ATYP DST.ADDR DST.PORT)
 */
import { CONSTANTS } from '../constants.js';

export async function parseSocks5Header(buffer) {
    if (buffer.byteLength < 6) return { hasError: true, message: 'SOCKS5 request too short' };
    
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    
    // 校验版本和保留字段
    if (view.getUint8(0) !== 0x05) return { hasError: true, message: 'Invalid SOCKS5 version' };
    if (view.getUint8(2) !== 0x00) return { hasError: true, message: 'Invalid SOCKS5 RSV' };
    
    const cmd = view.getUint8(1);
    // 支持 CONNECT(1) 和 UDP ASSOCIATE(3)
    const isUDP = (cmd === 0x03);
    if (cmd !== 0x01 && cmd !== 0x03) {
        return { hasError: true, message: 'Unsupported SOCKS5 CMD: ' + cmd };
    }

    const atyp = view.getUint8(3);
    let addressRemote = '';
    let portIndex = 0;
    let rawDataIndex = 0;

    try {
        if (atyp === 0x01) { // IPv4
            if (buffer.byteLength < 10) return { hasError: true, message: 'Buffer too short for IPv4' };
            addressRemote = new Uint8Array(buffer.slice(4, 8)).join('.');
            portIndex = 8;
        } else if (atyp === 0x03) { // Domain
            const domainLen = view.getUint8(4);
            if (buffer.byteLength < 5 + domainLen + 2) return { hasError: true, message: 'Buffer too short for Domain' };
            addressRemote = new TextDecoder().decode(buffer.slice(5, 5 + domainLen));
            portIndex = 5 + domainLen;
        } else if (atyp === 0x04) { // IPv6
            if (buffer.byteLength < 22) return { hasError: true, message: 'Buffer too short for IPv6' };
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(view.getUint16(4 + i * 2, false).toString(16));
            }
            addressRemote = '[' + ipv6.join(':') + ']';
            portIndex = 20;
        } else {
            return { hasError: true, message: 'Invalid SOCKS5 ATYP: ' + atyp };
        }

        const portRemote = view.getUint16(portIndex, false);
        rawDataIndex = portIndex + 2;

        return {
            hasError: false,
            addressRemote,
            portRemote,
            addressType: atyp,
            isUDP,
            rawClientData: buffer.slice(rawDataIndex), // SOCKS5 请求后的数据即为 Payload
            rawDataIndex
        };
    } catch (e) {
        return { hasError: true, message: `Socks5 parse error: ${e.message}` };
    }
}
