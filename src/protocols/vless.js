// src/protocols/vless.js
/**
 * 文件名: src/protocols/vless.js
 * 核心功能: 解析 VLESS 协议头部 (Version, UUID, Command, Port, Address)。
 * 审计优化:
 * 1. [Performance] IPv6 解析优化: 移除 DataView 分配，改用位运算直接提取，减少 GC 压力。
 * 2. [Stability] 保持了之前对 Buffer 长度和 UUID 校验的健壮性检查。
 */
import { CONSTANTS } from '../constants.js';
import { textDecoder, stringifyUUID } from '../utils/helpers.js';

/**
 * 解析 VLESS 协议头部
 * @param {Uint8Array|ArrayBuffer} vlessBuffer 
 * @param {string[]} expectedUserIDs - 预处理好的小写 UUID 列表
 */
export async function processVlessHeader(vlessBuffer, expectedUserIDs) {
    // 基础长度检查: Version(1) + UUID(16) + OptLen(1) + Cmd(1) + Port(2) + Atyp(1) = 22 bytes minimum
    // 考虑到后续地址字段，24 字节是一个合理的最小安全长度
    if (vlessBuffer.byteLength < 24) return { hasError: true, message: "Buffer too short" };
    
    // [优化] 避免不必要的 new Uint8Array 包装
    const buffer = vlessBuffer instanceof Uint8Array ? vlessBuffer : new Uint8Array(vlessBuffer);
    
    const version = buffer[0];
    if (version !== 0) return { hasError: true, message: "Invalid VLESS version" };
    
    // [优化] 使用 subarray 提取 UUID 字节，避免复制
    // stringifyUUID 内部负责将 16 字节转换为标准 UUID 字符串
    const uuid = stringifyUUID(buffer.subarray(1, 17));

    // [性能优化] 直接使用预处理好的 expectedUserIDs
    if (!expectedUserIDs.includes(uuid)) {
        return { hasError: true, message: "Invalid VLESS user" };
    }
    
    const optLength = buffer[17];
    // Cmd 在 OptLen 之后
    // Offset: 1(Ver) + 16(UUID) + 1(OptLen) + optLength
    const commandIndex = 18 + optLength;
    
    if (commandIndex >= buffer.byteLength) return { hasError: true, message: "Buffer too short for command" };
    const command = buffer[commandIndex];
    
    // [Fix] 允许 CONNECT(1) 和 UDP(2)
    const isUDP = command === 2;
    if (command !== 1 && command !== 2) {
        return { hasError: true, message: 'Unsupported VLESS command: ' + command };
    }
    
    const portIndex = commandIndex + 1;
    if (buffer.byteLength < portIndex + 2) return { hasError: true, message: "Buffer too short for port" };

    // 解析端口
    // 确保 DataView 使用正确的 buffer 和 byteOffset
    // 注意: 这里保留 DataView 是因为只创建一次且读取一次，开销尚可接受，
    // 若追求极致也可改为 ((buffer[portIndex] << 8) | buffer[portIndex + 1])
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const portRemote = view.getUint16(portIndex, false);
    
    let addressIndex = portIndex + 2;
    const addressType = buffer[addressIndex];
    addressIndex++;
    
    let addressRemote = "";
    let addressLength = 0;
    
    // 解析目标地址
    try {
        switch (addressType) {
            case CONSTANTS.ADDRESS_TYPE_IPV4: 
                addressLength = 4; 
                // [优化] 使用 subarray 并 join，避免额外内存分配
                addressRemote = buffer.subarray(addressIndex, addressIndex + 4).join('.'); 
                break;
            case CONSTANTS.ADDRESS_TYPE_URL: 
                addressLength = buffer[addressIndex]; 
                addressIndex++; // 跳过长度字节
                // [优化] 零拷贝解码
                addressRemote = textDecoder.decode(buffer.subarray(addressIndex, addressIndex + addressLength)); 
                break;
            case CONSTANTS.ADDRESS_TYPE_IPV6: 
                addressLength = 16;
                // [Optimization] IPv6 解析优化: 移除 DataView，使用位运算
                // 直接读取 16 字节，每 2 字节合并为一个 Hex 片段
                const ipv6 = [];
                for (let i = 0; i < 8; i++) {
                    const idx = addressIndex + (i * 2);
                    const high = buffer[idx];
                    const low = buffer[idx + 1];
                    // (High << 8) | Low 组合成 16 位整数，然后转 16 进制字符串
                    ipv6.push(((high << 8) | low).toString(16));
                }
                addressRemote = '[' + ipv6.join(':') + ']';
                break;
            default: 
                return { hasError: true, message: 'Invalid VLESS addressType: ' + addressType };
        }
    } catch (e) {
        return { hasError: true, message: 'Address parse failed' };
    }
    
    if (!addressRemote) return { hasError: true, message: "VLESS address is empty" };
    
    const rawDataIndex = addressIndex + addressLength;
    
    return { 
        hasError: false, 
        addressRemote, 
        addressType, 
        portRemote, 
        isUDP, 
        rawDataIndex, 
        cloudflareVersion: new Uint8Array([version]) 
    };
}
