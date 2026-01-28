// src/protocols/mandala.js
import { CONSTANTS } from '../constants.js';
import { textDecoder, textEncoder, sha224Hash } from '../utils/helpers.js';
import { parseAddressAndPort } from './utils.js';

// [优化] 缓存 Password Hash (存储 Buffer 格式以减少运行时转换)
const passwordHashCache = new Map();
const MAX_CACHE_SIZE = 100;

/**
 * [安全] 常量时间比较函数
 * 防止通过比对耗时推测哈希内容的侧信道攻击
 * @param {Uint8Array} a 
 * @param {Uint8Array} b 
 * @returns {boolean}
 */
function constantTimeEqual(a, b) {
    if (a.byteLength !== b.byteLength) return false;
    let mismatch = 0;
    for (let i = 0; i < a.byteLength; i++) {
        mismatch |= a[i] ^ b[i];
    }
    return mismatch === 0;
}

export async function parseMandalaHeader(mandalaBuffer, password) {
    // 1. 基础长度检查 (Salt(4) + Hash(56) + PadLen(1) + Cmd(1) + Atyp(1) + Port(2) + CRLF(2) = 67字节)
    if (mandalaBuffer.byteLength < 67) {
        return { hasError: true, message: 'Mandala buffer too short' };
    }

    // [优化] 避免不必要的包装
    const buffer = mandalaBuffer instanceof Uint8Array ? mandalaBuffer : new Uint8Array(mandalaBuffer);

    // 2. 提取随机盐 (前4字节)
    const salt = buffer.subarray(0, 4);

    // 3. 异或解密 (XOR)
    // 必须创建新内存，因为要写入解密数据，且避免修改原输入buffer可能带来的副作用
    const decrypted = new Uint8Array(buffer.byteLength - 4);
    
    // [优化] 简单的循环结构更有利于 V8 引擎优化
    const len = decrypted.length;
    for (let i = 0; i < len; i++) {
        decrypted[i] = buffer[i + 4] ^ salt[i & 3];
    }

    // 4. 验证哈希 (Offset 0-56)
    // [优化] 使用二进制 Bytes 直接比对，避免 textDecoder 解码成字符串的开销
    let expectedHashBytes = passwordHashCache.get(password);
    
    if (expectedHashBytes) {
        // 更新 LRU 位置
        passwordHashCache.delete(password);
        passwordHashCache.set(password, expectedHashBytes);
    } else {
        // 计算哈希并转换为 Bytes 缓存
        const hashHex = sha224Hash(String(password));
        expectedHashBytes = textEncoder.encode(hashHex);
        
        if (passwordHashCache.size >= MAX_CACHE_SIZE) {
            const oldestKey = passwordHashCache.keys().next().value;
            passwordHashCache.delete(oldestKey);
        }
        passwordHashCache.set(password, expectedHashBytes);
    }

    // 提取接收到的哈希部分
    const receivedHashBytes = decrypted.subarray(0, 56);

    // [安全] 使用常量时间比较进行认证
    if (!constantTimeEqual(receivedHashBytes, expectedHashBytes)) {
        return { hasError: true, message: 'Invalid Mandala Auth' };
    }

    // 5. 跳过随机混淆填充
    const padLen = decrypted[56]; 
    let cursor = 57 + padLen;     

    if (cursor >= decrypted.length) return { hasError: true, message: 'Buffer too short after padding' };

    // 6. 解析指令 (CMD)
    const cmd = decrypted[cursor];
    
    // [Fix] 允许 TCP(1) 和 UDP(3)
    const isUDP = (cmd === 3);

    if (cmd !== 1 && !isUDP) {
        return { hasError: true, message: 'Unsupported Mandala CMD: ' + cmd };
    }
    cursor++;

    // 7. 解析地址 (ATYP + Addr)
    const atyp = decrypted[cursor];
    // 直接传递 decrypted 视图，parseAddressAndPort 内部已优化
    const addrResult = parseAddressAndPort(decrypted, cursor + 1, atyp);
    
    if (addrResult.hasError) return addrResult;
    
    // 8. 解析端口
    const dataOffset = addrResult.dataOffset;
    // 检查是否有足够的字节读取端口(2) + CRLF(2)
    if (dataOffset + 2 > decrypted.byteLength) return { hasError: true, message: 'Buffer short for port' };
    
    const view = new DataView(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);
    const port = view.getUint16(dataOffset, false);
    
    // 9. 验证 CRLF (作为头部结束标志)
    const headerEnd = dataOffset + 2;
    
    // [安全] 严格边界检查，防止 headerEnd + 1 越界
    if (headerEnd + 2 > decrypted.byteLength) {
        return { hasError: true, message: 'Missing CRLF data' };
    }

    if (decrypted[headerEnd] !== 0x0D || decrypted[headerEnd + 1] !== 0x0A) {
        return { hasError: true, message: 'Missing CRLF' };
    }

    // 10. 还原目标地址字符串
    let addressRemote = "";
    try {
        switch (atyp) {
            case CONSTANTS.ADDRESS_TYPE_IPV4:
                addressRemote = addrResult.targetAddrBytes.join('.');
                break;
            case CONSTANTS.ATYP_SS_DOMAIN: 
                addressRemote = textDecoder.decode(addrResult.targetAddrBytes);
                break;
            case CONSTANTS.ATYP_SS_IPV6: 
                const ipv6 = [];
                // 确保使用正确偏移量的 DataView
                const v6View = new DataView(addrResult.targetAddrBytes.buffer, addrResult.targetAddrBytes.byteOffset, addrResult.targetAddrBytes.byteLength);
                for (let i = 0; i < 8; i++) ipv6.push(v6View.getUint16(i * 2, false).toString(16));
                addressRemote = '[' + ipv6.join(':') + ']';
                break;
            default:
                return { hasError: true, message: 'Unknown ATYP' };
        }
    } catch (e) {
        return { hasError: true, message: 'Address decode failed' };
    }

    return {
        hasError: false,
        addressRemote,
        portRemote: port,
        addressType: atyp,
        isUDP: isUDP, 
        // [优化] 返回解密后剩余数据的视图 (Zero-copy)
        rawClientData: decrypted.subarray(headerEnd + 2),
        protocol: 'mandala'
    };
}
