/**
 * 文件名: src/utils/dns.js
 * 优化内容: 
 * 1. [性能] 增加 DNS 内存缓存 (TTL 60秒)，消除重复 DoH 请求延迟。
 * 2. [稳定性] 增强 parseIPv6 的容错性。
 */
import { CONSTANTS } from '../constants.js';

// [优化] DNS 缓存 Map: { domain: { ip: string, expires: number } }
const dnsCache = new Map();

export function parseIPv6(ip) {
    // 简单的 IPv6 展开逻辑，确保返回标准格式
    if (!ip) return null;
    ip = ip.replace(/[\[\]]/g, '');
    
    // 如果是标准格式，尝试直接解析
    if (ip.includes('.')) return null; // 不处理 IPv4 映射
    
    // 简易展开 (仅用于 hex 转换，不作为严格校验)
    const parts = ip.split(':');
    const res = [];
    for (const part of parts) {
        if (part === '') {
            // 处理 :: 缩写
            const missing = 8 - (parts.length - 1);
            for (let i = 0; i < missing; i++) res.push(0);
        } else {
            res.push(parseInt(part, 16));
        }
    }
    // 补齐末尾
    while (res.length < 8) res.push(0);
    return res.slice(0, 8);
}

export async function resolveToIPv6(domain, dnsServer) {
    if (!dnsServer) return null;

    // [优化] 1. 检查缓存
    const cacheKey = `${domain}|${dnsServer}`;
    const cached = dnsCache.get(cacheKey);
    if (cached && Date.now() < cached.expires) {
        return cached.ip;
    }

    // 2. 发起 DoH 请求
    try {
        const url = new URL(dnsServer);
        url.searchParams.set('name', domain);
        url.searchParams.set('type', 'AAAA'); // 请求 IPv6
        
        const response = await fetch(url.toString(), {
            method: 'GET',
            headers: { 'Accept': 'application/dns-json' }
        });

        if (!response.ok) return null;

        const data = await response.json();
        
        // 提取 Answer
        if (data.Status === 0 && data.Answer) {
            for (const rec of data.Answer) {
                if (rec.type === 28 && rec.data) { // Type 28 is AAAA
                    const ip = rec.data;
                    // [优化] 3. 写入缓存 (TTL 60秒)
                    dnsCache.set(cacheKey, { ip, expires: Date.now() + 60000 });
                    
                    // 简单的缓存清理 (防止内存无限增长)
                    if (dnsCache.size > 1000) dnsCache.clear();
                    
                    return ip;
                }
            }
        }
    } catch (e) {
        console.error(`DNS Query failed for ${domain}:`, e);
    }
    
    return null;
}
