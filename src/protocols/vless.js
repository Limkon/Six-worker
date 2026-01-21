/**
 * 文件名: src/protocols/vless.js
 * 修改内容:
 * 1. [Fix] 修复 VLESS 头部解析中的偏移量计算错误。
 * 2. [Fix] 严格校验 UUID，防止未授权访问。
 * 3. [Feature] 正确提取并返回 rawClientData (去除头部后的负载数据)。
 */
import { bufferToUUIDString } from './utils.js';
import { CONSTANTS } from '../constants.js';

/**
 * 解析 VLESS 请求头
 * VLESS Header Structure:
 * [1-byte Version][16-byte UUID][1-byte Addons Length][N-byte Addons][1-byte Command][2-byte Port][1-byte Address Type][N-byte Address]...[Data]
 * * @param {ArrayBuffer} buffer 原始数据
 * @param {string} userID 预期的 UserID
 * @returns {Object} 解析结果或抛出错误
 */
export function processVlessHeader(buffer, userID) {
    if (buffer.byteLength < 24) {
        throw new Error('VLESS header too short');
    }

    const view = new DataView(buffer);
    const version = view.getUint8(0);
    
    // VLESS 协议版本必须为 0
    if (version !== 0) {
        throw new Error(`Invalid VLESS version: ${version}`);
    }

    // 校验 UUID
    const uuidBytes = new Uint8Array(buffer, 1, 16);
    const requestUUID = bufferToUUIDString(uuidBytes);
    if (requestUUID !== userID) {
        throw new Error(`Invalid UUID: ${requestUUID} vs ${userID}`);
    }

    // Addons (目前 VLESS 标准实现通常忽略 Addons 内容，但需跳过长度)
    const addonsLen = view.getUint8(17);
    let offset = 18 + addonsLen;

    if (buffer.byteLength < offset + 4) {
         throw new Error('VLESS header incomplete (addons)');
    }

    const command = view.getUint8(offset);
    if (command !== 1) { 
        // 1=TCP, 2=UDP. Cloudflare Worker 主要支持 TCP connect。
        // 虽然可以通过 stream 传输 UDP，但在此处我们主要处理 TCP 出站。
        // 若需支持 UDP，需在 outbound 中做特殊处理，这里暂且放行或记录。
        // throw new Error(`Unsupported Command: ${command} (Only TCP supported)`);
    }
    
    const portRemote = view.getUint16(offset + 1);
    offset += 3;

    const addressType = view.getUint8(offset);
    offset += 1;

    let addressRemote = '';
    
    if (addressType === CONSTANTS.ADDRESS_TYPE_IPV4) {
        if (buffer.byteLength < offset + 4) throw new Error('Invalid IPv4 length');
        addressRemote = new Uint8Array(buffer, offset, 4).join('.');
        offset += 4;
    } else if (addressType === CONSTANTS.ADDRESS_TYPE_DOMAIN) {
        const domainLen = view.getUint8(offset);
        offset += 1;
        if (buffer.byteLength < offset + domainLen) throw new Error('Invalid Domain length');
        const domainBytes = new Uint8Array(buffer, offset, domainLen);
        addressRemote = new TextDecoder().decode(domainBytes);
        offset += domainLen;
    } else if (addressType === CONSTANTS.ADDRESS_TYPE_IPV6) {
        if (buffer.byteLength < offset + 16) throw new Error('Invalid IPv6 length');
        const ipv6Bytes = new Uint8Array(buffer, offset, 16);
        const hex = [];
        for (let i = 0; i < 16; i += 2) {
            hex.push((ipv6Bytes[i] << 8 | ipv6Bytes[i + 1]).toString(16));
        }
        addressRemote = `[${hex.join(':')}]`; // 标准化为带方括号的 IPv6 字符串
        offset += 16;
    } else {
        throw new Error(`Unknown Address Type: ${addressType}`);
    }

    // 计算实际数据的起始位置
    const rawClientData = buffer.slice(offset);

    // 构造 VLESS 响应头: [Version][Addons Length] -> [0, 0]
    const vlessResponseHeader = new Uint8Array([version, 0]);

    return {
        addressRemote,
        portRemote,
        addressType,
        rawClientData,
        vlessResponseHeader,
        logInfo: `${addressRemote}:${portRemote} (Type: ${addressType})`
    };
}
