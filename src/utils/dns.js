/**
 * 文件名: src/utils/dns.js
 * 修改说明: 
 * 1. [安全性] 增强 JSON 解析的健壮性，防止非标准响应导致崩溃。
 * 2. [稳定性] 增加对 Answer 字段的类型检查。
 * 3. [兼容性] 增加对 IPv4 映射地址 (::ffff:1.2.3.4) 的解析支持。
 */
import { CONSTANTS } from '../constants.js';

// DNS 缓存 Map: { domain: { ip: string, expires: number } }
const dnsCache = new Map();

export function parseIPv6(ip) {
    if (!ip) return null;
    ip = ip.replace(/[\[\]]/g, '');
    
    // [修改] 处理 IPv4 映射地址 (例如 ::ffff:192.168.1.1)
    if (ip.includes('.')) {
        const lastColon = ip.lastIndexOf(':');
        const v4Str = ip.substring(lastColon + 1);
        const v6Prefix = ip.substring(0, lastColon);
        
        // 解析 IPv4 部分
        const v4Parts = v4Str.split('.').map(Number);
        if (v4Parts.length !== 4) return null;
        
        // 将 IPv4 转为 2个 16位整数
        const p1 = (v4Parts[0] << 8) | v4Parts[1];
        const p2 = (v4Parts[2] << 8) | v4Parts[3];
        
        // 递归解析前缀部分，补齐最后两段占位
        // 注意：如果是 ::ffff:1.2.3.4 -> 前缀 ::ffff -> 构造 ::ffff:0:0 解析
        const prefixParts = parseIPv6(v6Prefix + ':0:0'); 
        if (!prefixParts) return null;
        
        // 替换最后两个为 IPv4 转换来的值
        prefixParts[6] = p1;
        prefixParts[7] = p2;
        return prefixParts;
    }
    
    const parts = ip.split(':');
    let res = [];
    const emptyIndex = parts.indexOf('');
    
    if (emptyIndex !== -1) {
        // 处理 :: 缩写情况
        const head = parts.slice(0, emptyIndex).filter(p => p !== '').map(p => parseInt(p, 16) || 0);
        const tail = parts.slice(emptyIndex + 1).filter(p => p !== '').map(p => parseInt(p, 16) || 0);
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

    // 1. 检查缓存
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

        // [修复] 增加 JSON 解析的容错处理
        let data;
        try {
            data = await response.json();
        } catch (jsonError) {
            console.warn(`[DNS] Failed to parse JSON from ${dnsServer}:`, jsonError);
            return null;
        }
        
        // [修复] 严格检查数据结构，确保 Answer 存在且为数组
        if (data && data.Status === 0 && Array.isArray(data.Answer)) {
            for (const rec of data.Answer) {
                if (rec.type === 28 && rec.data) { // Type 28 is AAAA
                    const ip = rec.data;
                    // 3. 写入缓存 (TTL 60秒)
                    dnsCache.set(cacheKey, { ip, expires: Date.now() + 60000 });
                    
                    // 简单的缓存清理 (防止内存无限增长)
                    if (dnsCache.size > 1000) dnsCache.clear();
                    
                    return ip;
                }
            }
        }
    } catch (e) {
        console.error(`[DNS] Query failed for ${domain}:`, e);
    }
    
    return null;
}
