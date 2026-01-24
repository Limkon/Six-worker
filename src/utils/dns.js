// src/utils/dns.js
/**
 * 文件名: src/utils/dns.js
 * 修改说明: 
 * 1. [修复] resolveToIPv6 现在兼容 CIDR 格式的 NAT64 前缀 (如 64:ff9b::/96)，不再强制要求 URL。
 * 2. [新增] 针对前缀模式，增加 IPv4 -> IPv6 的合成逻辑。
 * 3. [安全性] 增强 JSON 解析的健壮性。
 */
import { CONSTANTS } from '../constants.js';

// DNS 缓存 Map: { domain: { ip: string, expires: number } }
const dnsCache = new Map();

export function parseIPv6(ip) {
    if (!ip) return null;
    ip = ip.replace(/[\[\]]/g, '');
    
    // 处理 IPv4 映射地址 (例如 ::ffff:192.168.1.1)
    if (ip.includes('.')) {
        const lastColon = ip.lastIndexOf(':');
        const v4Str = ip.substring(lastColon + 1);
        const v6Prefix = ip.substring(0, lastColon);
        
        const v4Parts = v4Str.split('.').map(Number);
        if (v4Parts.length !== 4) return null;
        
        const p1 = (v4Parts[0] << 8) | v4Parts[1];
        const p2 = (v4Parts[2] << 8) | v4Parts[3];
        
        // 递归解析前缀部分，补齐最后两段占位
        const prefixParts = parseIPv6(v6Prefix + ':0:0'); 
        if (!prefixParts) return null;
        
        prefixParts[6] = p1;
        prefixParts[7] = p2;
        return prefixParts;
    }
    
    const parts = ip.split(':');
    let res = [];
    const emptyIndex = parts.indexOf('');
    
    if (emptyIndex !== -1) {
        const head = parts.slice(0, emptyIndex).filter(p => p !== '').map(p => parseInt(p, 16) || 0);
        const tail = parts.slice(emptyIndex + 1).filter(p => p !== '').map(p => parseInt(p, 16) || 0);
        const middle = new Array(8 - head.length - tail.length).fill(0);
        res = [...head, ...middle, ...tail];
    } else {
        res = parts.map(p => parseInt(p, 16) || 0);
    }

    return res.slice(0, 8);
}

export async function resolveToIPv6(domain, dnsServer) {
    if (!dnsServer) return null;

    const cacheKey = `${domain}|${dnsServer}`;
    const cached = dnsCache.get(cacheKey);
    if (cached && Date.now() < cached.expires) {
        return cached.ip;
    }

    // 1. 判断 dnsServer 类型 (URL 还是 Prefix)
    let isDoH = false;
    try {
        const u = new URL(dnsServer);
        if (u.protocol === 'http:' || u.protocol === 'https:') {
            isDoH = true;
        }
    } catch (e) {
        // 不是 URL，假定为 Prefix
    }

    // 2. 模式 A: DoH 解析模式 (原逻辑)
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
                    if (rec.type === 28 && rec.data) { // Type 28 is AAAA
                        const ip = rec.data;
                        dnsCache.set(cacheKey, { ip, expires: Date.now() + 60000 });
                        if (dnsCache.size > 1000) dnsCache.clear();
                        return ip;
                    }
                }
            }
        } catch (e) {
            console.error(`[DNS] DoH Query failed for ${domain}:`, e);
        }
        return null;
    }

    // 3. 模式 B: Prefix 合成模式 (修复逻辑)
    // 假设 dnsServer 是前缀，例如 "64:ff9b::/96" 或 "64:ff9b::"
    let prefix = dnsServer.split('/')[0].trim();
    if (!prefix.includes(':')) return null;

    let ipv4 = domain;

    // 如果域名不是 IPv4 格式，先尝试解析出 A 记录
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Regex.test(domain)) {
        try {
            // 使用 Cloudflare 默认 DNS 解析域名获取 IPv4
            const dohUrl = 'https://cloudflare-dns.com/dns-query';
            const url = new URL(dohUrl);
            url.searchParams.set('name', domain);
            url.searchParams.set('type', 'A');
            
            const res = await fetch(url, { headers: { 'Accept': 'application/dns-json' } });
            const data = await res.json();
            
            if (data && data.Status === 0 && Array.isArray(data.Answer)) {
                const rec = data.Answer.find(r => r.type === 1); // Type 1 is A
                if (rec && rec.data) {
                    ipv4 = rec.data;
                    // 缓存这个中间解析结果? 暂时不缓存，直接走下面的合成并缓存最终结果
                } else {
                    return null; // 无 A 记录，无法合成
                }
            } else {
                return null;
            }
        } catch (e) {
            console.error(`[DNS] A-Record lookup failed for synthesis:`, e);
            return null;
        }
    }

    // 执行合成
    // 确保前缀以 : 结尾 (例如 64:ff9b::)
    // 标准 IPv6 表示法允许结尾是 IPv4 (例如 64:ff9b::1.2.3.4)
    if (!prefix.endsWith(':')) prefix += ':';
    
    // 如果前缀已经是以 :: 结尾，直接拼接即可 (64:ff9b:: + 1.2.3.4)
    // 如果前缀是 2001:db8:1:2::，拼接后 2001:db8:1:2::1.2.3.4 也是合法的
    const synthesizedIP = prefix + ipv4;
    
    dnsCache.set(cacheKey, { ip: synthesizedIP, expires: Date.now() + 60000 });
    return synthesizedIP;
}
