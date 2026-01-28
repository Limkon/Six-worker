// src/utils/dns.js
/**
 * 文件名: src/utils/dns.js
 * 修改说明: 
 * 1. [新增] detectNat64Prefix 函数: 基于 RFC 7050 标准，通过解析 ipv4only.arpa 自动探测 NAT64 前缀。
 * 2. [保留] 之前的 resolveToIPv6 和 parseIPv6 逻辑。
 */
import { CONSTANTS } from '../constants.js';

// DNS 缓存 Map
const dnsCache = new Map();

// ... (parseIPv6 函数保持不变，此处省略以节省篇幅，请保留原有的 parseIPv6) ...
export function parseIPv6(ip) {
    if (!ip) return null;
    ip = ip.replace(/[\[\]]/g, '');
    if (ip.includes('.')) {
        const lastColon = ip.lastIndexOf(':');
        const v4Str = ip.substring(lastColon + 1);
        const v6Prefix = ip.substring(0, lastColon);
        const v4Parts = v4Str.split('.').map(Number);
        if (v4Parts.length !== 4) return null;
        const p1 = (v4Parts[0] << 8) | v4Parts[1];
        const p2 = (v4Parts[2] << 8) | v4Parts[3];
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

/**
 * 自动探测 DNS 服务器的 NAT64 前缀
 * 原理: 查询 ipv4only.arpa 的 AAAA 记录，对比返回的 IPv6 地址与已知 IPv4 (192.0.0.170/171)
 * @param {string} dnsServer - DoH URL 地址，例如 https://cloudflare-dns.com/dns-query
 * @returns {Promise<string|null>} - 返回探测到的前缀 (如 "64:ff9b::") 或 null
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
                    // ipv4only.arpa 的固定 IPv4 是 192.0.0.170 (0xC00000AA) 和 192.0.0.171 (0xC00000AB)
                    // 常见的 NAT64 前缀是 96位，最后 32位是 IPv4
                    // 我们尝试提取前缀：去掉最后的 IPv4 部分
                    
                    // 简单策略：查找 192.0.0.170 或 171 的十六进制后缀
                    // 192.0.0.170 -> c000:00aa
                    // 192.0.0.171 -> c000:00ab
                    
                    // 标准化 IPv6 字符串比较复杂，这里使用简化的字符串包含判断
                    // 只要包含 IPv4 映射部分，我们就截取前面的部分作为前缀
                    
                    // 更严谨的方法：利用 parseIPv6 解析成数组，检查最后两段
                    const parts = parseIPv6(ip);
                    if (parts) {
                        // 检查是否以 192.0.0.170 或 171 结尾
                        // 192.0.0.170 = 0xC00000AA = 49152, 170
                        // 192.0.0.171 = 0xC00000AB = 49152, 171
                        const p7 = parts[7];
                        const p6 = parts[6];
                        
                        // 检查最后一段是否匹配
                        if ((p6 === 0xC000 && (p7 === 0x00AA || p7 === 0x00AB)) || 
                            // 或者是 ::ffff:192.0.0.170 这种格式 (虽然不太可能是 NAT64)
                           (ip.includes('192.0.0.170') || ip.includes('192.0.0.171'))) {
                            
                            // 这是一个合成地址，提取前96位作为前缀
                            // 重新构建前缀字符串
                            const prefixParts = parts.slice(0, 6);
                            // 将数组转回 IPv6 字符串格式 (简化版)
                            const prefixHex = prefixParts.map(n => n.toString(16)).join(':');
                            
                            // 规范化：如果全是0，缩写为 ::
                            // 这里简单返回带 :: 的格式
                            // 注意：这只是一个近似的重建，为了更通用，我们直接处理字符串可能更好
                            
                            // 方案B: 字符串处理 (更直观适配 resolveToIPv6 的输入)
                            // 如果 IP 是 64:ff9b::192.0.0.170
                            if (ip.includes('.')) {
                                const lastColon = ip.lastIndexOf(':');
                                return ip.substring(0, lastColon + 1); // 返回 "64:ff9b::"
                            }
                            
                            // 如果 IP 是 64:ff9b::c000:aa
                            // 这比较难拆，建议直接返回 "64:ff9b::" (标准知名公用前缀) 
                            // 或者根据 parts 前6段重组
                            
                            // 最终方案：使用 parts 前6段重组，并确保以 : 结尾
                            // 比如 64:ff9b:0:0:0:0 -> 64:ff9b::
                            
                            // 针对当前项目，最稳妥的方式是：
                            // 如果是知名地址，直接返回知名地址的前缀，否则返回前6段
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

    // 如果 dnsServer 是 "auto"，尝试自动探测 (可选功能)
    if (dnsServer === 'auto') {
        // 使用 Cloudflare DNS 尝试探测 (前提是 Cloudflare DoH 返回合成地址，但通常它不返回)
        // 或者是用户提供的一个特定的支持 NAT64 的 DoH
        // 这里暂时不默认开启 auto 逻辑，除非用户明确传入 URL
    }

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

    // 2. 模式 A: DoH 解析模式
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

    // 3. 模式 B: Prefix 合成模式
    let prefix = dnsServer.split('/')[0].trim();
    if (!prefix.includes(':')) return null;

    let ipv4 = domain;
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    
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

    if (!prefix.endsWith(':')) prefix += ':';
    const synthesizedIP = prefix + ipv4;
    
    dnsCache.set(cacheKey, { ip: synthesizedIP, expires: Date.now() + 60000 });
    return synthesizedIP;
}
