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
    if (!ip) return null;
    ip = ip.replace(/[\[\]]/g, '');
    
    // 如果包含点号，可能是 IPv4 映射地址，本项目暂不处理
    if (ip.includes('.')) return null; 
    
    const parts = ip.split(':');
    let res = [];
    const emptyIndex = parts.indexOf('');
    
    if (emptyIndex !== -1) {
        // 处理 :: 缩写情况
        // head: :: 之前的段
        const head = parts.slice(0, emptyIndex).filter(p => p !== '').map(p => parseInt(p, 16) || 0);
        // tail: :: 之后的段
        const tail = parts.slice(emptyIndex + 1).filter(p => p !== '').map(p => parseInt(p, 16) || 0);
        // middle: 需要补齐的 0
        const middle = new Array(8 - head.length - tail.length).fill(0);
        res = [...head, ...middle, ...tail];
    } else {
        res = parts.map(p => parseInt(p, 16) || 0);
    }

    // 确保返回 8 个 16 位整数
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
