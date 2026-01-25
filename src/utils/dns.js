// src/utils/dns.js
/**
 * 文件名: src/utils/dns.js
 * 修复说明: 
 * 1. [Fix] 重构 detectNat64Prefix: 移除脆弱的字符串匹配，完全依赖 parseIPv6 解析后的数值进行判断。
 * 2. [优化] 增强对不同 DNS 响应格式（Hex/Dotted/Compressed）的兼容性。
 */
import { CONSTANTS } from '../constants.js';

// DNS 缓存 Map
const dnsCache = new Map();

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
                    
                    // 确保解析成功且长度正确
                    if (parts && parts.length === 8) {
                        // ipv4only.arpa 的知名地址数值 (RFC 7050)
                        // 192.0.0.170 => 0xC0, 0x00, 0x00, 0xAA => 0xC000, 0x00AA
                        // 192.0.0.171 => 0xC0, 0x00, 0x00, 0xAB => 0xC000, 0x00AB
                        // 它们位于 IPv6 地址的最后 32 位 (即 parts[6] 和 parts[7])
                        
                        const p6 = parts[6];
                        const p7 = parts[7];

                        // 严格数值匹配，不依赖字符串格式
                        if (p6 === 0xC000 && (p7 === 0x00AA || p7 === 0x00AB)) {
                            // 提取前 96 位 (前 6 段) 作为前缀
                            const prefixParts = parts.slice(0, 6);
                            
                            // 重新组合为标准格式，确保以 :: 结尾
                            // 例如: [0x64, 0xff9b, 0, 0, 0, 0] => "64:ff9b:0:0:0:0::" -> 简写优化可选，这里直接用标准拼装
                            // 为了兼容 resolveToIPv6 的简单的字符串拼接逻辑，我们返回最规范的形式
                            // 过滤掉尾部的连续 0 以生成更短的前缀字符串 (可选，但为了稳健直接拼装即可)
                            const prefixStr = prefixParts.map(p => p.toString(16)).join(':') + ':';
                            
                            // 修正：resolveToIPv6 中期望前缀以 : 结尾，如 "64:ff9b::"
                            // 如果前缀本身包含连续0，toString(16) 会变成 "0"，这里我们手动构造一个带双冒号的格式以防万一
                            // 最简单且兼容性最好的方式：直接返回 hex 串 + ":"，例如 "64:ff9b:0:0:0:0:"
                            // 或者如果是 64:ff9b::，则返回 "64:ff9b::"
                            
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

export async function resolveToIPv6(domain, dnsServer) {
    if (!dnsServer) return null;

    const cacheKey = `${domain}|${dnsServer}`;
    const cached = dnsCache.get(cacheKey);
    if (cached && Date.now() < cached.expires) {
        return cached.ip;
    }

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
                        const ip = rec.data;
                        dnsCache.set(cacheKey, { ip, expires: Date.now() + 60000 });
                        return ip;
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

    // 确保前缀以 : 结尾以便拼接
    if (!prefix.endsWith(':')) prefix += ':';
    
    // 简单的合成逻辑 (适用于 /96 前缀)
    // 如果前缀是 "64:ff9b::"，拼接 ipv4 "1.2.3.4" 变成 "64:ff9b::1.2.3.4"
    // 系统会在 connect 时自动识别这种混合格式
    const synthesizedIP = prefix + ipv4;
    
    dnsCache.set(cacheKey, { ip: synthesizedIP, expires: Date.now() + 60000 });
    return synthesizedIP;
}
