// src/utils/dns.js
/**
 * 文件名: src/utils/dns.js
 * 修复说明:
 * 1. [Performance] resolveToIPv6: 增加 ctx 参数，使用 ctx.waitUntil 实现 Cache API 非阻塞写入。
 * 消除了之前 await cache.put 导致的 DNS 解析延迟。
 * 2. [Reliability] 保留了 Cache API 写入的错误捕获，防止后台任务失败影响主流程。
 */
import { CONSTANTS } from '../constants.js';

// DNS 缓存 Map (存储结果 - L1 内存缓存)
const dnsCache = new Map();

// 正在进行的 DNS 请求 (存储 Promise，用于去重并发请求)
const inflightRequests = new Map();

/**
 * 解析 IPv6 字符串为 8 个 16 位整数的数组
 * 支持 :: 压缩格式和 IPv4 嵌入格式 (::ffff:1.2.3.4)
 */
export function parseIPv6(ip) {
    if (!ip) return null;
    ip = ip.replace(/[\[\]]/g, '');
    
    // 处理 IPv4 嵌入格式 (例如 64:ff9b::192.0.0.170)
    if (ip.includes('.')) {
        const lastColon = ip.lastIndexOf(':');
        const v4Str = ip.substring(lastColon + 1);
        const v6Prefix = ip.substring(0, lastColon);
        const v4Parts = v4Str.split('.').map(Number);
        
        if (v4Parts.length !== 4) return null;
        
        // 将 IPv4 转为 2 个 16 位整数
        const p1 = (v4Parts[0] << 8) | v4Parts[1];
        const p2 = (v4Parts[2] << 8) | v4Parts[3];
        
        // 递归解析前缀部分，并补全最后两位
        const prefixParts = parseIPv6(v6Prefix + ':0:0'); 
        if (!prefixParts) return null;
        
        prefixParts[6] = p1;
        prefixParts[7] = p2;
        return prefixParts;
    }
    
    // 处理标准 Hex 格式
    const parts = ip.split(':');
    let res = [];
    const emptyIndex = parts.indexOf('');
    
    if (emptyIndex !== -1) {
        // 处理双冒号 :: 压缩
        const head = parts.slice(0, emptyIndex).filter(p => p !== '').map(p => parseInt(p, 16) || 0);
        const tail = parts.slice(emptyIndex + 1).filter(p => p !== '').map(p => parseInt(p, 16) || 0);
        // 补全中间的 0
        const middle = new Array(8 - head.length - tail.length).fill(0);
        res = [...head, ...middle, ...tail];
    } else {
        res = parts.map(p => parseInt(p, 16) || 0);
    }
    
    return res.slice(0, 8);
}

/**
 * 自动探测 DNS 服务器的 NAT64 前缀
 * 基于 RFC 7050，查询 ipv4only.arpa
 */
export async function detectNat64Prefix(dnsServer) {
    try {
        const dohUrl = new URL(dnsServer);
        dohUrl.searchParams.set('name', 'ipv4only.arpa');
        dohUrl.searchParams.set('type', 'AAAA');

        const response = await fetch(dohUrl.toString(), {
            method: 'GET',
            headers: { 'Accept': 'application/dns-json' }
        });

        if (!response.ok) return null;
        const data = await response.json();

        if (data && data.Status === 0 && Array.isArray(data.Answer)) {
            for (const rec of data.Answer) {
                if (rec.type === 28 && rec.data) { // Type 28 is AAAA
                    const ip = rec.data;
                    const parts = parseIPv6(ip);
                    
                    if (parts && parts.length === 8) {
                        const p6 = parts[6];
                        const p7 = parts[7];

                        // 严格数值匹配，不依赖字符串格式
                        if (p6 === 0xC000 && (p7 === 0x00AA || p7 === 0x00AB)) {
                            // 提取前 96 位 (前 6 段) 作为前缀
                            const prefixParts = parts.slice(0, 6);
                            
                            // 优化输出格式：检测是否为知名 Well-Known Prefix (64:ff9b::)
                            if (prefixParts[0] === 0x64 && prefixParts[1] === 0xff9b && 
                                prefixParts[2] === 0 && prefixParts[3] === 0 && 
                                prefixParts[4] === 0 && prefixParts[5] === 0) {
                                return "64:ff9b::";
                            }
                            
                            // 其他情况直接返回完整段，以确保数据完整性
                            return prefixParts.map(x => x.toString(16)).join(':') + ':';
                        }
                    }
                }
            }
        }
    } catch (e) {
        console.error(`[NAT64] Detection failed:`, e);
    }
    return null;
}

/**
 * [Internal] 执行实际的 DNS 解析逻辑 (无缓存副作用)
 */
async function performResolve(domain, dnsServer) {
    let isDoH = false;
    try {
        const u = new URL(dnsServer);
        if (u.protocol === 'http:' || u.protocol === 'https:') {
            isDoH = true;
        }
    } catch (e) {}

    // 模式 A: DoH 解析模式
    if (isDoH) {
        try {
            const url = new URL(dnsServer);
            url.searchParams.set('name', domain);
            url.searchParams.set('type', 'AAAA'); 
            
            const response = await fetch(url.toString(), {
                method: 'GET',
                headers: { 'Accept': 'application/dns-json' }
            });

            if (!response.ok) return null;

            let data;
            try { data = await response.json(); } catch (e) { return null; }
            
            if (data && data.Status === 0 && Array.isArray(data.Answer)) {
                for (const rec of data.Answer) {
                    if (rec.type === 28 && rec.data) {
                        return rec.data; // 直接返回 IP，由外层处理缓存
                    }
                }
            }
        } catch (e) {
            console.error(`[DNS] DoH Query failed for ${domain}:`, e);
        }
        return null;
    }

    // 模式 B: Prefix 合成模式
    // 假设 dnsServer 字符串本身就是前缀 (e.g. "64:ff9b::")
    let prefix = dnsServer.split('/')[0].trim();
    
    // 简单的格式校验
    if (!prefix.includes(':')) return null;

    let ipv4 = domain;
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    
    // 如果 domain 不是 IPv4，先解析 A 记录
    if (!ipv4Regex.test(domain)) {
        try {
            const dohUrl = 'https://cloudflare-dns.com/dns-query';
            const url = new URL(dohUrl);
            url.searchParams.set('name', domain);
            url.searchParams.set('type', 'A');
            
            const res = await fetch(url, { headers: { 'Accept': 'application/dns-json' } });
            const data = await res.json();
            
            if (data && data.Status === 0 && Array.isArray(data.Answer)) {
                const rec = data.Answer.find(r => r.type === 1);
                if (rec && rec.data) {
                    ipv4 = rec.data;
                } else {
                    return null;
                }
            } else {
                return null;
            }
        } catch (e) {
            return null;
        }
    }

    // [Fix] NAT64 合成算法：将 IPv4 转换为 Hex 形式，避免简单字符串拼接
    // 例如 192.0.2.1 -> c000:0201
    const parts = ipv4.split('.').map(Number);
    if (parts.length === 4) {
        // 确保前缀以 : 结尾以便拼接
        if (!prefix.endsWith(':')) prefix += ':';
        
        // 计算两个 16 位 Hex 块
        const part1 = ((parts[0] << 8) | parts[1]).toString(16).padStart(4, '0'); // c000
        const part2 = ((parts[2] << 8) | parts[3]).toString(16).padStart(4, '0'); // 0201
        
        const synthesizedIP = `${prefix}${part1}:${part2}`;
        return synthesizedIP;
    }
    
    return null;
}

/**
 * 核心解析函数：集成 L1/L2 缓存与并发合并
 * [Change] 增加 ctx 参数，用于利用 waitUntil 进行非阻塞缓存写入
 */
export async function resolveToIPv6(domain, dnsServer, ctx) {
    if (!dnsServer) return null;

    // [Original Keep] 缓存容量保护：防止 Worker 内存溢出
    if (dnsCache.size > 1000) {
        dnsCache.clear();
    }

    const cacheKey = `${domain}|${dnsServer}`;
    // 为 Cache API 构造一个合法的虚拟 URL 作为 Key
    const cacheUrl = new URL(`http://dns-cache.local/${encodeURIComponent(cacheKey)}`);
    const cache = caches.default;

    // 1. 查 L1 结果缓存 (内存)
    const cached = dnsCache.get(cacheKey);
    if (cached && Date.now() < cached.expires) {
        return cached.ip;
    }

    // 2. 查 L2 持久化缓存 (Cloudflare Cache API)
    try {
        const response = await cache.match(cacheUrl);
        if (response) {
            const ip = await response.text();
            // 同步到 L1
            dnsCache.set(cacheKey, { ip, expires: Date.now() + 60000 });
            return ip;
        }
    } catch (e) {
        console.error(`[DNS] Cache API match failed:`, e);
    }

    // 3. 查请求合并缓存 (Request Coalescing)
    if (inflightRequests.has(cacheKey)) {
        return await inflightRequests.get(cacheKey);
    }

    // 4. 发起新请求
    const promise = performResolve(domain, dnsServer).finally(() => {
        inflightRequests.delete(cacheKey);
    });

    inflightRequests.set(cacheKey, promise);

    try {
        const ip = await promise;
        // 5. 存入缓存 (仅成功时)
        if (ip) {
            // 存入 L1
            dnsCache.set(cacheKey, { ip, expires: Date.now() + 60000 });
            
            // 存入 L2 (Cache API)
            // [Fix] 关键优化：使用 ctx.waitUntil 实现非阻塞写入
            // 之前使用 await cache.put 会阻塞 DNS 返回，增加延迟
            const putCache = async () => {
                try {
                    const cacheResponse = new Response(ip, {
                        headers: { 
                            'Cache-Control': 'max-age=60', // 边缘缓存 60 秒
                            'Content-Type': 'text/plain' 
                        }
                    });
                    await cache.put(cacheUrl, cacheResponse);
                } catch (cacheError) {
                    console.warn(`[DNS] Cache put bg error:`, cacheError);
                }
            };

            if (ctx && typeof ctx.waitUntil === 'function') {
                ctx.waitUntil(putCache());
            } else {
                // 如果没有提供 ctx，则回退到 Fire-and-forget 模式 (不 await，也不阻塞)
                // 注意：在 Worker 结束前这可能无法完成，但总比阻塞好
                putCache().catch(e => {}); 
            }
        }
        return ip;
    } catch (e) {
        console.error(`[DNS] Resolve error:`, e);
        return null;
    }
}
