// src/protocols/mandala.js
/**
 * 文件名: src/protocols/mandala.js
 * 修改说明:
 * 1. [Optimization] 引入头部预读机制 (Header Probing)：仅复制并解密前 2KB 数据用于解析头部，
 * 避免在大流量场景下对 Payload 进行无效的内存复制和异或运算，显著降低 CPU 和内存开销。
 * 2. [Refactor] 保持与 helpers.js 全局缓存的对接。
 */
import { CONSTANTS } from '../constants.js';
import { textDecoder, textEncoder, sha224Hash, StreamCipher } from '../utils/helpers.js';

/**
 * 恒定时间比较两个 Uint8Array 是否相等，防止时序攻击
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
    if (!password) {
        return { hasError: true, message: 'Password is required' };
    }

    // 基础长度检查 (Salt(4) + Hash(56) + PadLen(1) + Cmd(1) + Atyp(1) + Port(2) + CRLF(2) = 67字节)
    if (mandalaBuffer.byteLength < 67) {
        return { hasError: true, message: 'Mandala buffer too short' };
    }

    // 1. 获取输入视图
    const buffer = mandalaBuffer instanceof Uint8Array ? mandalaBuffer : new Uint8Array(mandalaBuffer);

    // 2. 读取 Salt (明文，前4字节)
    const salt = buffer.subarray(0, 4);
    
    // 3. 准备解密区域
    // ciphertext 指向 Salt 之后的所有数据 (含 加密头部 + 明文Body)
    const ciphertext = buffer.subarray(4);
    
    // [Optimization] 性能优化关键点：
    // Mandala 协议只加密了头部。为了避免处理 Payload (可能很大) 带来的内存复制和异或计算开销，
    // 我们只截取前 2048 字节进行解密和解析。这足够覆盖任何合法的 Mandala 头部。
    const PROBE_LIMIT = 2048;
    const decodeLen = Math.min(ciphertext.byteLength, PROBE_LIMIT);
    
    // 创建一个较小的缓冲区用于解密头部
    const decrypted = new Uint8Array(ciphertext.subarray(0, decodeLen)); 
    
    // 4. 获取密码 Bytes (直接转换，开销极低)
    const passwordBytes = textEncoder.encode(password);

    // 5. 初始化流加密并执行解密 (仅针对头部区域)
    const cipher = new StreamCipher(passwordBytes, salt);
    cipher.process(decrypted); 

    // 6. 验证哈希 (Offset 0-56 in decrypted buffer)
    // 直接调用 sha224Hash，利用 helpers.js 的全局 LRU 缓存
    const hashHex = sha224Hash(String(password));
    const expectedHashBytes = textEncoder.encode(hashHex);

    if (!constantTimeEqual(decrypted.subarray(0, 56), expectedHashBytes)) {
        return { hasError: true, message: 'Invalid Mandala Auth' };
    }

    // 7. 解析剩余头部
    const view = new DataView(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);
    
    const padLen = decrypted[56]; 
    let cursor = 57 + padLen;     

    // 确保 Padding 后还有数据 (Cmd, Atyp, Port 等)
    if (cursor >= decrypted.length) {
        // 如果头部甚至超出了我们的探测范围 (2KB)，说明数据异常或遭到了攻击
        return { hasError: true, message: 'Buffer too short or Padding too long' };
    }

    const cmd = decrypted[cursor];
    const isUDP = (cmd === 3);

    // 仅支持 TCP(1) 和 UDP(3)
    if (cmd !== 1 && !isUDP) {
        return { hasError: true, message: 'Unsupported Mandala CMD: ' + cmd };
    }
    cursor++;

    if (cursor >= decrypted.length) return { hasError: true, message: 'Buffer ended unexpectedly' };

    const atyp = decrypted[cursor];
    cursor++;
    
    let addressRemote = "";
    let portRemote = 0;
    let headerEnd = 0;

    try {
        switch (atyp) {
            case CONSTANTS.ADDRESS_TYPE_IPV4:
                addressRemote = decrypted.subarray(cursor, cursor + 4).join('.');
                cursor += 4;
                break;
            case CONSTANTS.ATYP_SS_DOMAIN: 
                const domainLen = decrypted[cursor];
                cursor++; 
                if (cursor + domainLen > decrypted.length) throw new Error('Domain length overflow');
                addressRemote = textDecoder.decode(decrypted.subarray(cursor, cursor + domainLen));
                cursor += domainLen;
                break;
            case CONSTANTS.ATYP_SS_IPV6: 
                const ipv6 = [];
                for (let i = 0; i < 8; i++) {
                    ipv6.push(view.getUint16(cursor + i * 2, false).toString(16)); 
                }
                addressRemote = '[' + ipv6.join(':') + ']';
                cursor += 16;
                break;
            default:
                return { hasError: true, message: 'Unknown ATYP: ' + atyp };
        }
        
        if (cursor + 2 > decrypted.length) throw new Error('Port overflow');
        
        // 读取 Port (2字节, Big Endian)
        portRemote = view.getUint16(cursor, false);
        cursor += 2;
        headerEnd = cursor;

    } catch (e) {
        return { hasError: true, message: 'Address parse failed: ' + e.message };
    }
    
    // 8. 验证 CRLF (协议尾部标记)
    // headerEnd 指向 Port 之后的位置，CRLF 紧随其后
    if (headerEnd + 2 > decrypted.byteLength) {
        return { hasError: true, message: 'Missing CRLF data' };
    }
    if (decrypted[headerEnd] !== 0x0D || decrypted[headerEnd + 1] !== 0x0A) {
        return { hasError: true, message: 'Missing CRLF' };
    }

    // 9. 返回结果
    // 这里的关键是从原始 ciphertext 中提取 Body。
    // decrypted 只是头部的一个拷贝，且只解密了前部分。
    // 真实的 Payload (Body) 位于原始 ciphertext 的 (headerEnd + 2) 之后。
    const rawClientData = ciphertext.subarray(headerEnd + 2);

    return {
        hasError: false,
        addressRemote,
        portRemote,
        addressType: atyp,
        isUDP: isUDP, 
        rawClientData: rawClientData, // Zero-copy view from original buffer
        protocol: 'mandala'
    };
}
