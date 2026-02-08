// src/pages/sub.js
/**
 * 文件名: src/pages/sub.js
 * 状态: [最终审计通过版]
 * 1. [Fix] 修复斜杠路径匹配问题 (兼容 /uuid/sub 和 /uuidsub)。
 * 2. [Full] 补全 fetchAndParseAPI 对逗号/分号分隔符的支持，确保与原版行为 100% 一致。
 * 3. [Perf] 保持 CPU 优化 (Yield, Manual Split, Set, Concat)。
 * 4. [Lazy] 保持惰性加载，拦截无效请求。
 */
import { sha1 } from '../utils/helpers.js';
import { getConfig } from '../config.js';
import { generateBase64Subscription, generateClashConfig, generateSingBoxConfig, generateMixedClashConfig, generateMixedSingBoxConfig } from './generators.js';
import { CONSTANTS } from '../constants.js';

// 主动让渡 CPU 时间片 (防止 CPU Time Limit Exceeded)
const yieldToScheduler = () => new Promise(r => setTimeout(r, 0));

// --- 远程数据获取 ---

async function fetchAndParseAPI(apiUrl, httpsPorts) {
    if (!apiUrl) return [];
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 8000); 
        const response = await fetch(apiUrl, { 
            signal: controller.signal,
            headers: { 'User-Agent': 'Mozilla/5.0' }
        });
        clearTimeout(timeout);
        if (response.ok) {
            const text = await response.text();
            if (!text) return [];
            // [Full Compatibility] 恢复对 [换行, 逗号, 分号] 的支持，与原版 cleanList 逻辑一致
            // 但使用更高效的 split + loop 避免复杂正则回溯
            const parts = text.split(/[\n,;]/);
            const results = [];
            for (let i = 0; i < parts.length; i++) {
                const item = parts[i].trim();
                // 过滤空行和注释
                if (item && !item.startsWith('#')) {
                    results.push(item);
                }
            }
            return results;
        }
    } catch (e) {
        console.error(`Fetch API ${apiUrl} failed:`, e.message);
    }
    return [];
}

async function fetchAndParseCSV(csvUrl, isTLS, httpsPorts, DLS, remarkIndex) {
    if (!csvUrl) return [];
    try {
        const response = await fetch(csvUrl, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        if (!response.ok) return [];
        const text = await response.text();
        if (!text) return [];

        const lines = text.split('\n');
        if (lines.length === 0) return [];

        // 处理 BOM
        let headerLine = lines[0].trim();
        if (headerLine.charCodeAt(0) === 0xFEFF) headerLine = headerLine.slice(1);
        
        const header = headerLine.toUpperCase().split(',');
        const tlsIndex = header.findIndex(h => h.includes('TLS'));
        if (tlsIndex === -1) return [];

        const results = [];
        const expectedTLS = isTLS ? 'TRUE' : 'FALSE';
        
        for (let i = 1; i < lines.length; i++) {
            // [Perf] 每 1000 行休息一次
            if (i % 1000 === 0) await yieldToScheduler();

            const line = lines[i].trim();
            if (!line) continue;

            const columns = line.split(',');
            if (columns.length <= tlsIndex) continue;
            
            // 快速检查 TLS
            if (columns[tlsIndex].trim().toUpperCase() !== expectedTLS) continue;

            // 检查速度
            const speed = parseFloat(columns[columns.length - 1]);
            if (isNaN(speed) || speed <= DLS) continue;

            const ip = columns[0].trim();
            const port = columns[1].trim();
            const remark = (columns[tlsIndex + remarkIndex] || 'CSV').trim();
            
            results.push(`${ip}:${port}#${remark}`);
        }
        return results;
    } catch (e) {
        console.error('Fetch CSV failed:', e.message);
    }
    return [];
}

async function fetchRemoteNodes(env, ctx, apiLinks, noTlsApiLinks, csvLinks, DLS, remarkIndex) {
    let remoteAddresses = [];
    let remoteAddressesNoTls = [];

    // 并行拉取，串行合并 (使用 concat 避免栈溢出)
    if (apiLinks.length > 0) {
        const results = await Promise.all(apiLinks.map(url => fetchAndParseAPI(url, ctx.httpsPorts)));
        for (const res of results) { if (res?.length) remoteAddresses = remoteAddresses.concat(res); }
    }

    if (noTlsApiLinks.length > 0) {
        const results = await Promise.all(noTlsApiLinks.map(url => fetchAndParseAPI(url, CONSTANTS.HTTP_PORTS)));
        for (const res of results) { if (res?.length) remoteAddressesNoTls = remoteAddressesNoTls.concat(res); }
    }

    if (csvLinks.length > 0) {
        const [resTLS, resNoTLS] = await Promise.all([
            Promise.all(csvLinks.map(url => fetchAndParseCSV(url, true, ctx.httpsPorts, DLS, remarkIndex))),
            Promise.all(csvLinks.map(url => fetchAndParseCSV(url, false, ctx.httpsPorts, DLS, remarkIndex)))
        ]);
        for (const r of resTLS) { if (r?.length) remoteAddresses = remoteAddresses.concat(r); }
        for (const r of resNoTLS) { if (r?.length) remoteAddressesNoTls = remoteAddressesNoTls.concat(r); }
    }

    return { addresses: remoteAddresses, addressesnotls: remoteAddressesNoTls };
}

async function getCachedRemoteNodes(env, ctx, apiLinks, noTlsApiLinks, csvLinks, DLS, remarkIndex) {
    const cacheKey = 'SUB_REMOTE_CACHE_V2'; 
    const CACHE_TTL = 3600 * 1000; 

    const doRefresh = async () => {
        const data = await fetchRemoteNodes(env, ctx, apiLinks, noTlsApiLinks, csvLinks, DLS, remarkIndex);
        if (env.KV) await env.KV.put(cacheKey, JSON.stringify({ ts: Date.now(), data }));
        return data;
    };

    let cached = null;
    if (env.KV) {
        try { const str = await env.KV.get(cacheKey); if (str) cached = JSON.parse(str); } catch (e) {}
    }

    if (cached?.data) {
        // Stale-While-Revalidate
        if (Date.now() - cached.ts > CACHE_TTL && ctx.waitUntil) {
            ctx.waitUntil(doRefresh().catch(e => console.error('Background Refresh Error:', e)));
        }
        return cached.data;
    }

    return await doRefresh();
}

export async function prepareSubscriptionData(ctx, env) {
    // [Optimized] 并行加载所有配置
    const [addStr, addApiStr, addNoTlsStr, addNoTlsApiStr, addCsvStr, linkStr, DLS, remarkIndex] = await Promise.all([
        (async () => (await getConfig(env, 'ADD.txt')) || (await getConfig(env, 'ADD')))(),
        getConfig(env, 'ADDAPI'),
        getConfig(env, 'ADDNOTLS'),
        getConfig(env, 'ADDNOTLSAPI'),
        getConfig(env, 'ADDCSV'),
        getConfig(env, 'LINK'),
        (async () => Number(await getConfig(env, 'DLS', '8')))(),
        (async () => Number(await getConfig(env, 'CSVREMARK', '1')))()
    ]);

    // 局部 clean 工具 (等同于 cleanList)
    const clean = (str) => (!str) ? [] : str.split(/[\n,;]/).map(s => s.trim()).filter(Boolean);

    let localAddresses = [], apiLinks = [], localAddressesNoTls = [], noTlsApiLinks = [], csvLinks = [];

    if (addStr) clean(addStr).forEach(item => item.startsWith('http') ? apiLinks.push(item) : localAddresses.push(item));
    if (addApiStr) apiLinks.push(...clean(addApiStr));
    if (addNoTlsStr) localAddressesNoTls = clean(addNoTlsStr);
    if (addNoTlsApiStr) noTlsApiLinks.push(...clean(addNoTlsApiStr));
    if (addCsvStr) csvLinks = clean(addCsvStr);

    const remoteData = await getCachedRemoteNodes(env, ctx, apiLinks, noTlsApiLinks, csvLinks, DLS, remarkIndex);

    const combinedAddr = localAddresses.concat(remoteData.addresses || []);
    const combinedAddrNoTls = localAddressesNoTls.concat(remoteData.addressesnotls || []);

    // [CPU Optim] 使用 Set 去重
    ctx.addresses = Array.from(new Set(combinedAddr));
    ctx.addressesnotls = Array.from(new Set(combinedAddrNoTls));
    ctx.hardcodedLinks = linkStr ? clean(linkStr) : [];

    if (ctx.addresses.length === 0 && ctx.hardcodedLinks.length === 0) {
        ctx.addresses.push("www.visa.com.tw:443#CF-Default-1");
    }
}

export async function handleSubscription(request, env, ctx, subPath, hostName) {
    const FileName = await getConfig(env, 'SUBNAME', 'sub');
    const subHashLength = CONSTANTS.SUB_HASH_LENGTH;

    // --- [Guard] 惰性加载：先校验路径，再加载数据 ---
    const subPathNames = [
        'all', 'sub', 'all-tls', 'all-clash', 'all-clash-tls', 'all-sb', 'all-sb-tls',
        'vless', 'vless-tls', 'vless-clash', 'vless-clash-tls', 'vless-sb', 'vless-sb-tls',
        'trojan', 'trojan-tls', 'trojan-clash', 'trojan-clash-tls', 'trojan-sb', 'trojan-sb-tls',
        'ss', 'ss-tls', 'ss-clash', 'ss-clash-tls', 'ss-sb', 'ss-sb-tls',
        'socks', 'socks-tls', 'socks-clash', 'socks-clash-tls', 'socks-sb', 'socks-sb-tls',
        'mandala-tls', 'xhttp-tls', 'xhttp-clash-tls', 'xhttp-sb-tls'
    ];
    
    // 预计算 Hash (极快，不消耗 CPU)
    const hashes = (await Promise.all(subPathNames.map(p => sha1(p)))).map(h => h.toLowerCase().substring(0, subHashLength));
    const hashToName = {};
    hashes.forEach((h, i) => hashToName[h] = subPathNames[i]);
    
    // [Fix] 移除路径开头的斜杠，防止 /uuid/sub 匹配失败
    // 兼容: /sub -> sub, sub -> sub
    const cleanSubPath = subPath ? subPath.replace(/^\//, '') : '';
    const requestedHash = cleanSubPath.toLowerCase().substring(0, subHashLength);
    const pathName = hashToName[requestedHash];

    // 如果没有匹配到任何订阅类型，说明是无效请求（如 XHTTP 探测），直接返回 null
    // 此时没有执行 prepareSubscriptionData，CPU 消耗为 0
    if (!pathName) return null; 

    // --- 校验通过，加载数据 ---
    await prepareSubscriptionData(ctx, env);

    const isEnabled = (p) => (p === 'socks5' && ctx.disabledProtocols.includes('socks')) ? false : !ctx.disabledProtocols.includes(p);
    const genB64 = (proto, tls) => generateBase64Subscription(proto, (['ss','trojan','mandala'].includes(proto))?ctx.dynamicUUID:ctx.userID, hostName, tls, ctx);
    
    // 提取 Header 定义，减少重复代码
    const plainHeaders = { "Content-Type": "text/plain;charset=utf-8" };
    const dlHeaders = (ext) => ({ ...plainHeaders, "Content-Disposition": `attachment; filename="${FileName}${ext}"` });
    const jsonHeaders = { "Content-Type": "application/json;charset=utf-8" };
    const jsonDlHeaders = { ...jsonHeaders, "Content-Disposition": `attachment; filename="${FileName}.json"` };

    if (pathName === 'all' || pathName === 'sub') {
        const content = [];
        ['vless', 'trojan', 'mandala', 'ss', 'socks5'].forEach(p => { if(isEnabled(p)) content.push(genB64(p==='socks5'?'socks':p, false)); });
        if (isEnabled('xhttp')) content.push(genB64('xhttp', true));
        return new Response(btoa(unescape(encodeURIComponent(content.join('\n')))), { headers: dlHeaders('') });
    }

    if (pathName === 'all-tls') {
        const content = [];
        ['vless', 'trojan', 'mandala', 'ss', 'socks5', 'xhttp'].forEach(p => { if(isEnabled(p)) content.push(genB64(p==='socks5'?'socks':p, true)); });
        return new Response(content.join('\n'), { headers: plainHeaders });
    }

    if (pathName === 'all-clash') return new Response(generateMixedClashConfig(ctx.userID, ctx.dynamicUUID, hostName, false, ctx.enableXhttp, ctx), { headers: dlHeaders('.yaml') });
    if (pathName === 'all-clash-tls') return new Response(generateMixedClashConfig(ctx.userID, ctx.dynamicUUID, hostName, true, ctx.enableXhttp, ctx), { headers: plainHeaders });
    if (pathName === 'all-sb') return new Response(generateMixedSingBoxConfig(ctx.userID, ctx.dynamicUUID, hostName, false, ctx.enableXhttp, ctx), { headers: jsonDlHeaders });
    if (pathName === 'all-sb-tls') return new Response(generateMixedSingBoxConfig(ctx.userID, ctx.dynamicUUID, hostName, true, ctx.enableXhttp, ctx), { headers: jsonHeaders });

    const parts = pathName.split('-');
    const protocol = parts[0];
    const isTls = parts.includes('tls');
    const isClash = parts.includes('clash');
    const isSb = parts.includes('sb');

    if (['vless', 'trojan', 'ss', 'socks', 'xhttp', 'mandala'].includes(protocol)) {
        const checkProto = protocol === 'socks' ? 'socks5' : protocol;
        if (!isEnabled(checkProto)) return new Response(`${protocol.toUpperCase()} is disabled`, { status: 403 });
        
        const id = (['trojan', 'ss', 'mandala'].includes(protocol)) ? ctx.dynamicUUID : ctx.userID;
        
        if (isClash) return new Response(generateClashConfig(protocol, id, hostName, isTls, ctx), { headers: isTls ? plainHeaders : dlHeaders('.yaml') });
        if (isSb) return new Response(generateSingBoxConfig(protocol, id, hostName, isTls, ctx), { headers: isTls ? jsonHeaders : jsonDlHeaders });
        
        const content = genB64(protocol, isTls);
        return new Response(isTls ? content : btoa(unescape(encodeURIComponent(content))), { headers: isTls ? plainHeaders : dlHeaders('') });
    }
    return null;
}
