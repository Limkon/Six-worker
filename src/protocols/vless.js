/**
 * 文件名: src/protocols/vless.js
 * 修改说明:
 * 1. [性能优化] 移除了 expectedUserIDs.map(...) 逻辑。
 * 原因：在 src/config.js 的 initializeContext 中已预处理好小写 ID 列表，此处直接使用 includes 即可。
 * 2. [保留] 维持原有的零拷贝 subarray 视图逻辑和地址解析功能。
 */
import { CONSTANTS } from '../constants.js';
import { textDecoder, stringifyUUID } from '../utils/helpers.js';

export async function processVlessHeader(vlessBuffer, expectedUserIDs) {
    if (vlessBuffer.byteLength < 24) return { hasError: true, message: "Buffer too short" };
    
    // [优化] 避免不必要的 new Uint8Array 包装
    const buffer = vlessBuffer instanceof Uint8Array ? vlessBuffer : new Uint8Array(vlessBuffer);
    
    const version = buffer[0];
    if (version !== 0) return { hasError: true, message: "Invalid VLESS version" };
    
    // [优化] 使用 subarray 替代 slice，避免内存复制
    const uuid = stringifyUUID(buffer.subarray(1, 17));

    // [性能优化] 直接使用预处理好的 expectedUserIDs，避免高频调用 map 和 toLowerCase
    if (!expectedUserIDs.includes(uuid)) {
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
            // [优化] subarray
            addressRemote = buffer.subarray(addressIndex, addressIndex + 4).join('.'); 
            break;
        case CONSTANTS.ADDRESS_TYPE_URL: 
            addressLength = buffer[addressIndex]; 
            addressIndex++; 
            // [优化] subarray
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
    
    return { hasError: false, addressRemote, addressType, portRemote, isUDP, rawDataIndex: addressIndex + addressLength, cloudflareVersion: new Uint8Array([version]) };
}
