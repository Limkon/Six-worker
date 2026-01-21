/**
 * 文件名: src/utils/dns.js
 * 修改内容:
 * 1. [Optimization] 增加 DNS 内存缓存机制，减少 DoH 请求延迟。
 * 2. [Fix] 重写 parseIPv6，支持 :: 压缩和 IPv4 映射格式，增强鲁棒性。
 * 3. [Fix] 增强 resolveToIPv6 的错误处理和超时控制。
 */

// 简单的内存缓存，用于存储 DNS 解析结果
// Key: hostname, Value: { ip: string, expires: number }
const DNS_CACHE = new Map();
const CACHE_TTL = 60 * 1000; // 缓存有效期 60 秒

/**
 * 解析 IPv6 字符串为 8 个 16 位整数的数组
 * 用于 SOCKS5 协议中的地址处理
 * @param {string} ip IPv6 地址字符串
 * @returns {number[]|null} 8个整数组成的数组，如果解析失败返回 null
 */
export function parseIPv6(ip) {
    if (!ip) return null;
    let addr = ip.trim();

    // 处理 IPv4 映射 IPv6 地址 (::ffff:1.2.3.4)
    if (addr.includes('.')) {
        const lastColon = addr.lastIndexOf(':');
        const v4Str = addr.substring(lastColon + 1);
        const v6Prefix = addr.substring(0, lastColon + 1);
        
        const v4Parts = v4Str.split('.').map(Number);
        if (v4Parts.length !== 4 || v4Parts.some(p => isNaN(p) || p < 0 || p > 255)) {
            return null;
        }
        
        // 将 IPv4 转为 2 个 16 位整数
        const p7 = (v4Parts[0] << 8) | v4Parts[1];
        const p8 = (v4Parts[2] << 8) | v4Parts[3];
        
        // 递归解析前缀部分，并将 IPv4 部分追加到末尾
        // 通常前缀是 ::ffff: 或 ::
        // 这里构造一个临时 IPv6 字符串来复用逻辑，或者手动处理
        // 为简化，我们假设前缀是压缩格式或标准格式
        let hexParts = [];
        if (v6Prefix === '::' || v6Prefix === '::ffff:') {
            // 标准 IPv4 映射前缀
            hexParts = [0, 0, 0, 0, 0, 0xffff];
            if (v6Prefix === '::') hexParts[5] = 0; // 兼容 ::1.2.3.4 (IPv4-compatible)
        } else {
            // 尝试解析前缀部分，预期得到前6段
            // 这种情况较少见，简单处理：
            return null; 
        }
        return [...hexParts, p7, p8];
    }

    // 处理标准 IPv6
    // 1. 处理双冒号 ::
    if (addr.indexOf('::') !== -1) {
        const parts = addr.split('::');
        if (parts.length > 2) return null; // 只能有一个 ::
        
        const left = parts[0] ? parts[0].split(':') : [];
        const right = parts[1] ? parts[1].split(':') : [];
        
        const missing = 8 - (left.length + right.length);
        if (missing < 0) return null;
        
        const zeros = new Array(missing).fill('0');
        addr = [...left, ...zeros, ...right].join(':');
    }
    
    const hexParts = addr.split(':');
    if (hexParts.length !== 8) return null;
    
    const result = [];
    for (const part of hexParts) {
        if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return null;
        result.push(parseInt(part, 16));
    }
    
    return result;
}

/**
 * 使用 DoH (DNS over HTTPS) 解析域名的 AAAA (IPv6) 记录
 * @param {string} host 域名
 * @param {string} dnsServer DoH 服务器地址 (例如 https://1.1.1.1/dns-query)
 * @returns {Promise<string|null>} 解析到的 IPv6 地址或 null
 */
export async function resolveToIPv6(host, dnsServer) {
    if (!host || !dnsServer) return null;

    // 1. 检查缓存
    const cacheKey = `aaaa:${host}`;
    const cached = DNS_CACHE.get(cacheKey);
    if (cached && cached.expires > Date.now()) {
        return cached.ip;
    }

    // 2. 构造 DoH 请求 URL (使用 JSON 格式)
    // 许多 DoH 提供商 (Cloudflare, Google) 支持 'application/dns-json'
    // 格式通常为: https://provider/dns-query?name=example.com&type=AAAA
    
    // 简单的 URL 构造，处理 dnsServer 是否已有 query param
    const separator = dnsServer.includes('?') ? '&' : '?';
    const url = `${dnsServer}${separator}name=${encodeURIComponent(host)}&type=AAAA`;

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3000); // 3秒超时

        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'application/dns-json'
            },
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            // console.error(`DNS query failed: ${response.status}`);
            return null;
        }

        const data = await response.json();
        
        // 验证响应
        // Status 0 表示 NOERROR
        if (data.Status !== 0 || !data.Answer || !Array.isArray(data.Answer)) {
            return null;
        }

        // 查找 Type 28 (AAAA) 的记录
        const aaaaRecord = data.Answer.find(r => r.type === 28);
        
        if (aaaaRecord && aaaaRecord.data) {
            const ip = aaaaRecord.data;
            
            // 简单验证是否为有效 IPv6 字符串（排除空值）
            if (ip && ip.includes(':')) {
                // 写入缓存
                DNS_CACHE.set(cacheKey, {
                    ip: ip,
                    expires: Date.now() + CACHE_TTL
                });
                
                // 清理旧缓存 (简单维护，避免内存无限增长)
                if (DNS_CACHE.size > 100) {
                    const keys = DNS_CACHE.keys();
                    DNS_CACHE.delete(keys.next().value);
                }
                
                return ip;
            }
        }
    } catch (error) {
        // console.error(`DoH request failed for ${host}:`, error);
        return null;
    }

    return null;
}
