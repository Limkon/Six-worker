import { CONSTANTS } from '../constants.js';

// --- 配置常量 ---
const ALGORITHM = 'AES-GCM';
const KEY_LENGTH = 256;
const SALT_STRING = 'mandala-protocol-salt-v1'; 
const IV_LENGTH = 12;
const ITERATIONS = 1000; // 遵循您的指令：1000次迭代

// --- 全局缓存 (优化性能) ---
let GLOBAL_CACHED_KEY = null;
let GLOBAL_PASSWORD_HASH = null;

// --- 内部辅助函数：初始化密钥 ---
async function _getDerivedKey(password) {
    if (!password) password = 'default-mandala-secret';

    // 1. 命中全局缓存
    if (GLOBAL_CACHED_KEY && GLOBAL_PASSWORD_HASH === password) {
        return GLOBAL_CACHED_KEY;
    }

    // 2. 计算新密钥
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    const derivedKey = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: enc.encode(SALT_STRING),
            iterations: ITERATIONS,
            hash: 'SHA-256',
        },
        keyMaterial,
        { name: ALGORITHM, length: KEY_LENGTH },
        false,
        ['encrypt', 'decrypt']
    );

    // 3. 更新缓存
    GLOBAL_CACHED_KEY = derivedKey;
    GLOBAL_PASSWORD_HASH = password;
    return derivedKey;
}

/**
 * 核心处理函数：解析 Mandala 协议头 (重构为支持 AES-GCM)
 * 保持了原有的参数签名，确保兼容性。
 */
export async function parseMandalaHeader(mandalaBuffer, password) {
    if (!password) {
        return { hasError: true, message: 'Password is required' };
    }

    // 转换为 Uint8Array
    const buffer = mandalaBuffer instanceof Uint8Array ? mandalaBuffer : new Uint8Array(mandalaBuffer);

    // 长度检查 (IV + Tag 至少 28 字节)
    if (buffer.byteLength < IV_LENGTH + 16) {
        return { hasError: true, message: 'Mandala buffer too short (Invalid)' };
    }

    try {
        // 1. 获取密钥
        const key = await _getDerivedKey(password);

        // 2. 提取 IV 和 密文
        const iv = buffer.subarray(0, IV_LENGTH);
        const ciphertext = buffer.subarray(IV_LENGTH);

        // 3. 执行 AES-GCM 解密 (这一步同时验证了完整性，替代了原来的 Hash 校验)
        // 注意：这里解密的是整个包（Payload），不再只是头部
        const decryptedBuffer = await crypto.subtle.decrypt(
            {
                name: ALGORITHM,
                iv: iv,
            },
            key,
            ciphertext
        );

        const decrypted = new Uint8Array(decryptedBuffer);
        const view = new DataView(decrypted.buffer);
        let cursor = 0;

        // 4. 解析 Payload 结构
        // 新协议结构建议: [CMD(1)] [ATYP(1)] [ADDR_VAR] [PORT(2)] [DATA...]
        // 不需要 Padding 和 CRLF，因为 AES-GCM 已经界定了边界

        if (cursor >= decrypted.length) return { hasError: true, message: 'Empty payload' };

        const cmd = decrypted[cursor];
        cursor++;
        
        const isUDP = (cmd === 3); // 保留 UDP 判断逻辑
        if (cmd !== 1 && !isUDP) {
             // 兼容性尝试：如果解密出的第一个字节不是 1 或 3，可能是旧协议数据或干扰
            return { hasError: true, message: 'Unsupported CMD: ' + cmd };
        }

        const atyp = decrypted[cursor];
        cursor++;

        let addressRemote = "";
        let portRemote = 0;

        // 解析地址 (逻辑与原版保持一致)
        switch (atyp) {
            case CONSTANTS.ADDRESS_TYPE_IPV4:
                addressRemote = decrypted.subarray(cursor, cursor + 4).join('.');
                cursor += 4;
                break;
            case CONSTANTS.ATYP_SS_DOMAIN:
                const domainLen = decrypted[cursor];
                cursor++;
                // 使用 TextDecoder 替代 helpers 中的 textDecoder，避免依赖
                addressRemote = new TextDecoder().decode(decrypted.subarray(cursor, cursor + domainLen));
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

        // 解析端口
        portRemote = view.getUint16(cursor, false); // Big Endian
        cursor += 2;

        // 5. 提取剩余数据作为 rawClientData
        // 此时 decrypted 已经是明文，直接截取剩余部分
        const rawClientData = decrypted.subarray(cursor);

        return {
            hasError: false,
            addressRemote,
            portRemote,
            addressType: atyp,
            isUDP: isUDP,
            rawClientData: rawClientData, // 这是解密后的 Body
            protocol: 'mandala'
        };

    } catch (e) {
        // AES-GCM 解密失败会抛出错误（如密码错误或数据篡改）
        console.error('Mandala Decrypt Error:', e);
        return { hasError: true, message: 'Decryption failed (Invalid Password or Tampered Data)' };
    }
}
