/**
 * 文件名: src/pages/sub.js
 * 审计确认: 
 * 1. 确认已实现 Stale-While-Revalidate 缓存策略，大幅提升订阅响应速度。
 * 2. 确认去重逻辑使用了 Set，优化了内存占用。
 * 3. 逻辑稳健，当 KV 不可用时会自动降级为实时获取。
 */
import { cleanList, sha1 } from '../utils/helpers.js';
import { getConfig } from '../config.js';
import { generateBase64Subscription, generateClashConfig, generateSingBoxConfig, generateMixedClashConfig, generateMixedSingBoxConfig } from './generators.js';
import { CONSTANTS } from '../constants.js';

// 整理优选列表 (API)
async function fetchAndParseAPI(apiUrl, httpsPorts) {
    if (!apiUrl) return [];
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000); 
        const response = await fetch(apiUrl, { 
            signal: controller.signal,
            headers: { 'User-Agent': 'Mozilla/5.0' }
        });
        clearTimeout(timeout);
        if (response.ok) {
            const text = await response.text();
            return await cleanList(text);
        }
    } catch (e) {
        console.error(`Fetch API ${apiUrl} failed:`, e.message);
    }
    return [];
}

// 整理测速结果 (CSV)
async function fetchAndParseCSV(csvUrl, isTLS, httpsPorts, DLS, remarkIndex) {
    if (!csvUrl) return [];
    try {
        const response = await fetch(csvUrl, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        if (!response.ok) return [];
        const text = await response.text();
        const lines = text.split(/\r?\n/);
        if (lines.length === 0) return [];
        const header = lines[0].split(',');
        const tlsIndex = header.indexOf('TLS');
        if (tlsIndex === -1) return [];
        
        const results = [];
        for (let i = 1; i < lines.length; i++) {
            const columns = lines[i].split(',');
            if (columns.length > tlsIndex && columns[tlsIndex] && columns[tlsIndex].toUpperCase() === (isTLS ? 'TRUE' : 'FALSE')) {
                const speed = parseFloat(columns[columns.length - 1]);
                if (speed > DLS) {
                    const ip = columns[0];
                    const port = columns[1];
                    const remark = columns[tlsIndex + remarkIndex] || 'CSV';
                    results.push(`${ip}:${port}#${remark}`);
                }
            }
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

    if (apiLinks.length > 0) {
        const results = await Promise.all(apiLinks.map(url => fetchAndParseAPI(url, ctx.httpsPorts)));
        results.forEach(res => remoteAddresses.push(...res));
    }

    if (noTlsApiLinks.length > 0) {
        const results = await Promise.all(noTlsApiLinks.map(url => fetchAndParseAPI(url, CONSTANTS.HTTP_PORTS)));
        results.forEach(res => remoteAddressesNoTls.push(...res));
    }

    if (csvLinks.length > 0) {
        const [resTLS, resNoTLS] = await Promise.all([
            Promise.all(csvLinks.map(url => fetchAndParseCSV(url, true, ctx.httpsPorts, DLS, remarkIndex))),
            Promise.all(csvLinks.map(url => fetchAndParseCSV(url, false, ctx.httpsPorts, DLS, remarkIndex)))
        ]);
        resTLS.forEach(r => remoteAddresses.push(...r));
        resNoTLS.forEach(r => remoteAddressesNoTls.push(...r));
    }

    return {
        addresses: remoteAddresses,
        addressesnotls: remoteAddressesNoTls
    };
}

async function getCachedRemoteNodes(env, ctx, apiLinks, noTlsApiLinks, csvLinks, DLS, remarkIndex) {
    const cacheKey = 'SUB_REMOTE_CACHE';
    const CACHE_TTL = 3600 * 1000; 

    const doRefresh = async () => {
        const data = await fetchRemoteNodes(env, ctx, apiLinks, noTlsApiLinks, csvLinks, DLS, remarkIndex);
        const entry = { ts: Date.now(), data };
        if (env.KV) await env.KV.put(cacheKey, JSON.stringify(entry));
        return data;
    };

    let cached = null;
    if (env.KV) {
        try {
            const str = await env.KV.get(cacheKey);
            if (str) cached = JSON.parse(str);
        } catch (e) {
            console.error('KV Cache Read Error:', e);
        }
    }

    if (cached && cached.data) {
        if (Date.now() - cached.ts > CACHE_TTL) {
            // [优化] Stale-While-Revalidate: 后台更新，不阻塞当前请求
            if (ctx.waitUntil) {
                ctx.waitUntil(doRefresh().catch(e => console.error('Background Refresh Error:', e)));
            }
        }
        return cached.data;
    }

    return await doRefresh();
}

export async function prepareSubscriptionData(ctx, env) {
    const addStr = await getConfig(env, 'ADD.txt') || await getConfig(env, 'ADD');
    const addApiStr = await getConfig(env, 'ADDAPI');
    const addNoTlsStr = await getConfig(env, 'ADDNOTLS');
    const addNoTlsApiStr = await getConfig(env, 'ADDNOTLSAPI');
    const addCsvStr = await getConfig(env, 'ADDCSV');
    const linkStr = await getConfig(env, 'LINK');
    
    const DLS = Number(await getConfig(env, 'DLS', '8'));
    const remarkIndex = Number(await getConfig(env, 'CSVREMARK', '1'));

    let localAddresses = [];
    let localAddressesNoTls = [];
    let apiLinks = [];
    let noTlsApiLinks = [];
    let csvLinks = [];

    if (addStr) {
        const list = await cleanList(addStr);
        list.forEach(item => {
            if (item.startsWith('http')) apiLinks.push(item);
            else localAddresses.push(item);
        });
    }

    if (addApiStr) apiLinks.push(...(await cleanList(addApiStr)));
    if (addNoTlsStr) localAddressesNoTls = await cleanList(addNoTlsStr);
    if (addNoTlsApiStr) noTlsApiLinks.push(...(await cleanList(addNoTlsApiStr)));
    if (addCsvStr) csvLinks = await cleanList(addCsvStr);

    const remoteData = await getCachedRemoteNodes(env, ctx, apiLinks, noTlsApiLinks, csvLinks, DLS, remarkIndex);

    let hardcodedLinks = linkStr ? await cleanList(linkStr) : [];

    // [优化] 针对大规模数据的合并去重优化
    ctx.addresses = [...new Set([...localAddresses, ...remoteData.addresses])].filter(Boolean);
    ctx.addressesnotls = [...new Set([...localAddressesNoTls, ...remoteData.addressesnotls])].filter(Boolean);
    ctx.hardcodedLinks = hardcodedLinks;

    if (ctx.addresses.length === 0 && ctx.hardcodedLinks.length === 0) {
        ctx.addresses.push("www.visa.com.tw:443#CF-Default-1");
        ctx.addresses.push("usa.visa.com:8443#CF-Default-2");
    }
}

export async function handleSubscription(request, env, ctx, subPath, hostName) {
    const FileName = await getConfig(env, 'SUBNAME', 'sub');
    await prepareSubscriptionData(ctx, env);

    const subHashLength = CONSTANTS.SUB_HASH_LENGTH;
    const isEnabled = (p) => {
        if (p === 'socks5' && ctx.disabledProtocols.includes('socks')) return false;
        return !ctx.disabledProtocols.includes(p);
    };

    const subPathNames = [
        'all', 'sub', 'all-tls', 'all-clash', 'all-clash-tls', 'all-sb', 'all-sb-tls',
        'vless', 'vless-tls', 'vless-clash', 'vless-clash-tls', 'vless-sb', 'vless-sb-tls',
        'trojan', 'trojan-tls', 'trojan-clash', 'trojan-clash-tls', 'trojan-sb', 'trojan-sb-tls',
        'ss', 'ss-tls', 'ss-clash', 'ss-clash-tls', 'ss-sb', 'ss-sb-tls',
        'socks', 'socks-tls', 'socks-clash', 'socks-clash-tls', 'socks-sb', 'socks-sb-tls',
        'mandala-tls', 'xhttp-tls', 'xhttp-clash-tls', 'xhttp-sb-tls'
    ];
    
    const hashPromises = subPathNames.map(p => sha1(p));
    const hashes = (await Promise.all(hashPromises)).map(h => h.toLowerCase().substring(0, subHashLength));
    
    const hashToName = {};
    hashes.forEach((h, i) => hashToName[h] = subPathNames[i]);
    
    const requestedHash = subPath.toLowerCase().substring(0, subHashLength);
    const pathName = hashToName[requestedHash];
    if (!pathName) return null;

    const plainHeader = { "Content-Type": "text/plain;charset=utf-8" };
    const plainDownloadHeader = { ...plainHeader, "Content-Disposition": `attachment; filename="${FileName}"` };
    const jsonHeader = { "Content-Type": "application/json;charset=utf-8" };
    const jsonDownloadHeader = { ...jsonHeader, "Content-Disposition": `attachment; filename="${FileName}.json"` };

    const genB64 = (proto, tls) => generateBase64Subscription(proto, (['ss','trojan','mandala'].includes(proto))?ctx.dynamicUUID:ctx.userID, hostName, tls, ctx);
    
    if (pathName === 'all' || pathName === 'sub') {
        const content = [];
        ['vless', 'trojan', 'mandala', 'ss', 'socks5'].forEach(p => { if(isEnabled(p)) content.push(genB64(p==='socks5'?'socks':p, false)); });
        if (isEnabled('xhttp')) content.push(genB64('xhttp', true));
        return new Response(btoa(unescape(encodeURIComponent(content.join('\n')))), { headers: plainDownloadHeader });
    }

    if (pathName === 'all-tls') {
        const content = [];
        ['vless', 'trojan', 'mandala', 'ss', 'socks5', 'xhttp'].forEach(p => { if(isEnabled(p)) content.push(genB64(p==='socks5'?'socks':p, true)); });
        return new Response(content.join('\n'), { headers: plainHeader });
    }

    if (pathName === 'all-clash') return new Response(generateMixedClashConfig(ctx.userID, ctx.dynamicUUID, hostName, false, ctx.enableXhttp, ctx), { headers: plainDownloadHeader });
    if (pathName === 'all-clash-tls') return new Response(generateMixedClashConfig(ctx.userID, ctx.dynamicUUID, hostName, true, ctx.enableXhttp, ctx), { headers: plainHeader });
    if (pathName === 'all-sb') return new Response(generateMixedSingBoxConfig(ctx.userID, ctx.dynamicUUID, hostName, false, ctx.enableXhttp, ctx), { headers: jsonDownloadHeader });
    if (pathName === 'all-sb-tls') return new Response(generateMixedSingBoxConfig(ctx.userID, ctx.dynamicUUID, hostName, true, ctx.enableXhttp, ctx), { headers: jsonHeader });

    const parts = pathName.split('-');
    const protocol = parts[0];
    const isTls = parts.includes('tls');
    const isClash = parts.includes('clash');
    const isSb = parts.includes('sb');

    if (['vless', 'trojan', 'ss', 'socks', 'xhttp', 'mandala'].includes(protocol)) {
        const checkProto = protocol === 'socks' ? 'socks5' : protocol;
        if (!isEnabled(checkProto)) return new Response(`${protocol.toUpperCase()} is disabled`, { status: 403 });
        
        const id = (['trojan', 'ss', 'mandala'].includes(protocol)) ? ctx.dynamicUUID : ctx.userID;

        if (isClash) {
            if (protocol === 'mandala') return new Response('Clash not supported for Mandala', { status: 400 });
            return new Response(generateClashConfig(protocol, id, hostName, isTls, ctx), { headers: plainDownloadHeader });
        } else if (isSb) {
            if (protocol === 'mandala') return new Response('SingBox not supported for Mandala', { status: 400 });
            return new Response(generateSingBoxConfig(protocol, id, hostName, isTls, ctx), { headers: jsonDownloadHeader });
        } else {
            const content = genB64(protocol, isTls);
            return isTls ? new Response(content, { headers: plainHeader }) : new Response(btoa(unescape(encodeURIComponent(content))), { headers: plainDownloadHeader });
        }
    }
    return null;
}
