/**
 * 文件名: src/protocols/utils.js
 * 修改内容:
 * 1. [New] 增加 UUID 与 Buffer 互转的高效辅助函数。
 * 2. [Optimization] 提供强类型的 UUID 校验工具。
 */

/**
 * 验证字符串是否为有效的 UUID 格式
 * @param {string} uuid 
 * @returns {boolean}
 */
export function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

/**
 * 将 UUID 字符串转换为 Uint8Array (16字节)
 * @param {string} uuid 
 * @returns {Uint8Array}
 */
export function uuidStringToBuffer(uuid) {
    if (!isValidUUID(uuid)) {
        return new Uint8Array(16);
    }
    const hex = uuid.replace(/-/g, '');
    const buffer = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        buffer[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return buffer;
}

/**
 * 将 Uint8Array (16字节) 转换为 UUID 字符串
 * @param {Uint8Array} buffer 
 * @returns {string}
 */
export function bufferToUUIDString(buffer) {
    const hex = [];
    for (let i = 0; i < buffer.length; i++) {
        hex.push((buffer[i] < 16 ? '0' : '') + buffer[i].toString(16));
    }
    const s = hex.join('');
    return `${s.substr(0, 8)}-${s.substr(8, 4)}-${s.substr(12, 4)}-${s.substr(16, 4)}-${s.substr(20, 12)}`;
}

/**
 * 安全地合并两个 Uint8Array
 */
export function joinUint8Array(arr1, arr2) {
    const combined = new Uint8Array(arr1.length + arr2.length);
    combined.set(arr1);
    combined.set(arr2, arr1.length);
    return combined;
}

/**
 * 简单的 Hex Dump 用于调试 (仅在开发模式使用)
 */
export function toHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join(" ");
}
