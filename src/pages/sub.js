/**
 * 文件名: src/pages/sub.js
 * 修改内容: 
 * 1. [优化] 引入 KV 缓存机制 (SUB_REMOTE_CACHE) 存储远程节点数据。
 * 2. [优化] 实现 Stale-While-Revalidate 策略，缓存过期时后台异步更新 (ctx.waitUntil)，加速订阅响应。
 * 3. [重构] 将远程资源抓取逻辑提取为 fetchRemoteNodes 函数。
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
        const timeout = setTimeout(() => controller.abort(), 5000); // 适当放宽超时至5秒
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
        const header = lines[0].split(',');
        const tlsIndex = header.indexOf('TLS');
        if (tlsIndex === -1) return [];
        
        const results = [];
        for (let i = 1; i < lines.length; i++) {
            const columns = lines[i].split(',');
            if (columns.length > tlsIndex && columns[tlsIndex] && columns[tlsIndex].toUpperCase() === (isTLS ? 'TRUE' : 'FALSE') && parseFloat(columns[columns.length - 1]) > DLS) {
                const ip = columns[0];
                const port = columns[1];
                const remark = columns[tlsIndex + remarkIndex] || 'CSV';
                results.push(`${ip}:${port}#${remark}`);
            }
        }
        return results;
    } catch (e) {
        console.error('Fetch CSV failed:', e.message);
    }
    return [];
}

// [新增] 执行远程资源抓取的核心逻辑
async function fetchRemoteNodes(env, ctx, apiLinks, noTlsApiLinks, csvLinks, DLS, remarkIndex) {
    let remoteAddresses = [];
    let remoteAddressesNoTls = [];

    // 1. Fetch TLS APIs
    if (apiLinks.length > 0) {
        const promises = apiLinks.map(url => fetchAndParseAPI(url, ctx.httpsPorts));
        const results = await Promise.all(promises);
        results.forEach(res => remoteAddresses = remoteAddresses.concat(res));
    }

    // 2. Fetch NoTLS APIs
    if (noTlsApiLinks.length > 0) {
        const promises = noTlsApiLinks.map(url => fetchAndParseAPI(url, CONSTANTS.HTTP_PORTS));
        const results = await Promise.all(promises);
        results.forEach(res => remoteAddressesNoTls = remoteAddressesNoTls.concat(res));
    }

    // 3. Fetch CSVs
    if (csvLinks.length > 0) {
        const promisesTLS = csvLinks.map(url => fetchAndParseCSV(url, true, ctx.httpsPorts, DLS, remarkIndex));
        const promisesNoTLS = csvLinks.map(url => fetchAndParseCSV(url, false, ctx.httpsPorts, DLS, remarkIndex));
        
        const [resTLS, resNoTLS] = await Promise.all([Promise.all(promisesTLS), Promise.all(promisesNoTLS)]);
        resTLS.forEach(r => remoteAddresses = remoteAddresses.concat(r));
        resNoTLS.forEach(r => remoteAddressesNoTls = remoteAddressesNoTls.concat(r));
    }

    return {
        addresses: remoteAddresses,
        addressesnotls: remoteAddressesNoTls
    };
}

// [新增] 缓存管理函数 (Stale-While-Revalidate)
async function getCachedRemoteNodes(env, ctx, apiLinks, noTlsApiLinks, csvLinks, DLS, remarkIndex) {
    const cacheKey = 'SUB_REMOTE_CACHE';
    const CACHE_TTL = 3600 * 1000; // 1小时缓存失效

    // 内部函数：执行更新并写入 KV
    const doRefresh = async () => {
        // console.log('[Cache] Refreshing remote nodes...');
        const data = await fetchRemoteNodes(env, ctx, apiLinks, noTlsApiLinks, csvLinks, DLS, remarkIndex);
        const entry = { ts: Date.now(), data };
        if (env.KV) await env.KV.put(cacheKey, JSON.stringify(entry));
        return data;
    };

    // 1. 尝试读取缓存
    let cached = null;
    if (env.KV) {
        try {
            const str = await env.KV.get(cacheKey);
            if (str) cached = JSON.parse(str);
        } catch (e) {
            console.error('KV Cache Read Error:', e);
        }
    }

    // 2. 如果有缓存
    if (cached && cached.data) {
        // 检查过期
        if (Date.now() - cached.ts > CACHE_TTL) {
            // 已过期：后台异步更新，立刻返回旧数据 (Stale-While-Revalidate)
            if (ctx.waitUntil) {
                ctx.waitUntil(doRefresh().catch(e => console.error('Background Refresh Error:', e)));
            } else {
                // 如果没有 waitUntil 环境，不阻塞，但也无法后台更新，只能下次再试或忽略
                // 这里选择不阻塞
                doRefresh().catch(() => {});
            }
        }
        return cached.data;
    }

    // 3. 如果没有缓存 (冷启动)，必须等待更新
    return await doRefresh();
}

// 准备订阅数据
export async function prepareSubscriptionData(ctx, env) {
    const addStr = await getConfig(env, 'ADD.txt') || await getConfig(env, 'ADD');
    const addApiStr = await getConfig(env, 'ADDAPI');
    const addNoTlsStr = await getConfig(env, 'ADDNOTLS');
    const addNoTlsApiStr = await getConfig(env, 'ADDNOTLSAPI');
    const addCsvStr = await getConfig(env, 'ADDCSV');
    const linkStr = await getConfig(env, 'LINK');
    
    const DLS = Number(await getConfig(env, 'DLS', '8'));
    const remarkIndex = Number(await getConfig(env, 'CSVREMARK', '1'));

    // 本地静态节点 (Static)
    let localAddresses = [];
    let localAddressesNoTls = [];
    
    // 待抓取的远程链接 (To Fetch)
    let apiLinks = [];
    let noTlsApiLinks = [];
    let csvLinks = [];

    // 1. 解析 ADD/ADD.txt (混合了 IP 和 HTTP 链接)
    if (addStr) {
        const list = await cleanList(addStr);
        list.forEach(item => {
            if (item.startsWith('http')) apiLinks.push(item);
            else localAddresses.push(item);
        });
    }

    // 2. 解析 ADDAPI
    if (addApiStr) {
        const apis = await cleanList(addApiStr);
        apiLinks = apiLinks.concat(apis);
    }
    
    // 3. 解析 ADDNOTLS
    if (addNoTlsStr) {
        localAddressesNoTls = await cleanList(addNoTlsStr);
    }

    // 4. 解析 ADDNOTLSAPI
    if (addNoTlsApiStr) {
        const apis = await cleanList(addNoTlsApiStr);
        noTlsApiLinks = noTlsApiLinks.concat(apis);
    }

    // 5. 解析 ADDCSV
    if (addCsvStr) {
        csvLinks = await cleanList(addCsvStr);
    }

    // 6. 获取远程节点 (优先读取缓存)
    const remoteData = await getCachedRemoteNodes(env, ctx, apiLinks, noTlsApiLinks, csvLinks, DLS, remarkIndex);

    // 7. 合并结果
    let hardcodedLinks = [];
    if (linkStr) {
        hardcodedLinks = await cleanList(linkStr);
    }

    // 合并去重
    ctx.addresses = [...new Set([...localAddresses, ...remoteData.addresses])].filter(Boolean);
    ctx.addressesnotls = [...new Set([...localAddressesNoTls, ...remoteData.addressesnotls])].filter(Boolean);
    ctx.hardcodedLinks = hardcodedLinks;

    // 保底逻辑
    if (ctx.addresses.length === 0 && ctx.hardcodedLinks.length === 0) {
        ctx.addresses.push("www.visa.com.tw:443#CF-Default-1");
        ctx.addresses.push("usa.visa.com:8443#CF-Default-2");
    }
}

// 处理订阅请求
export async function handleSubscription(request, env, ctx, subPath, hostName) {
    const FileName = await getConfig(env, 'SUBNAME', 'sub');
    
    await prepareSubscriptionData(ctx, env);

    const subHashLength = CONSTANTS.SUB_HASH_LENGTH;
    const enableXhttp = ctx.enableXhttp;

    // [新增] 协议启用检查函数
    const isEnabled = (p) => {
        if (p === 'socks5' && ctx.disabledProtocols.includes('socks')) return false;
        return !ctx.disabledProtocols.includes(p);
    };

    // 2. 构造路径映射表 (Path -> Hash)
    const subPathNames = [
        'all', 'sub', 'all-tls', 'all-clash', 'all-clash-tls', 'all-sb', 'all-sb-tls',
        'vless', 'vless-tls', 'vless-clash', 'vless-clash-tls', 'vless-sb', 'vless-sb-tls',
        'trojan', 'trojan-tls', 'trojan-clash', 'trojan-clash-tls', 'trojan-sb', 'trojan-sb-tls',
        'ss', 'ss-tls', 'ss-clash', 'ss-clash-tls', 'ss-sb', 'ss-sb-tls',
        'socks', 'socks-tls', 'socks-clash', 'socks-clash-tls', 'socks-sb', 'socks-sb-tls',
        'mandala-tls',
        'xhttp-tls', 'xhttp-clash-tls', 'xhttp-sb-tls'
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

    const genB64 = (proto, tls) => generateBase64Subscription(proto, (proto==='ss'||proto==='trojan'||proto==='mandala')?ctx.dynamicUUID:ctx.userID, hostName, tls, ctx);
    
    // --- 通用订阅 ---
    if (pathName === 'all' || pathName === 'sub') {
        const content = [];
        if (isEnabled('vless')) content.push(genB64('vless', false));
        if (isEnabled('trojan')) content.push(genB64('trojan', false));
        if (isEnabled('mandala')) content.push(genB64('mandala', false));
        if (isEnabled('ss')) content.push(genB64('ss', false));
        if (isEnabled('socks5')) content.push(genB64('socks', false));
        if (isEnabled('xhttp')) content.push(genB64('xhttp', true));
        
        return new Response(btoa(unescape(encodeURIComponent(content.join('\n')))), { headers: plainDownloadHeader });
    }
    if (pathName === 'all-tls') {
        const content = [];
        if (isEnabled('vless')) content.push(genB64('vless', true));
        if (isEnabled('trojan')) content.push(genB64('trojan', true));
        if (isEnabled('mandala')) content.push(genB64('mandala', true));
        if (isEnabled('ss')) content.push(genB64('ss', true));
        if (isEnabled('socks5')) content.push(genB64('socks', true));
        if (isEnabled('xhttp')) content.push(genB64('xhttp', true));

        return new Response(content.join('\n'), { headers: plainHeader });
    }

    // --- Clash 混合订阅 ---
    if (pathName === 'all-clash') {
        return new Response(generateMixedClashConfig(ctx.userID, ctx.dynamicUUID, hostName, false, enableXhttp, ctx), { headers: plainDownloadHeader });
    }
    if (pathName === 'all-clash-tls') {
        return new Response(generateMixedClashConfig(ctx.userID, ctx.dynamicUUID, hostName, true, enableXhttp, ctx), { headers: plainHeader });
    }

    // --- SingBox 混合订阅 ---
    if (pathName === 'all-sb') {
        return new Response(generateMixedSingBoxConfig(ctx.userID, ctx.dynamicUUID, hostName, false, enableXhttp, ctx), { headers: jsonDownloadHeader });
    }
    if (pathName === 'all-sb-tls') {
        return new Response(generateMixedSingBoxConfig(ctx.userID, ctx.dynamicUUID, hostName, true, enableXhttp, ctx), { headers: jsonHeader });
    }

    // --- 单协议订阅 ---
    const parts = pathName.split('-');
    const protocol = parts[0];
    const isTls = parts.includes('tls');
    const isClash = parts.includes('clash');
    const isSb = parts.includes('sb');

    if (['vless', 'trojan', 'ss', 'socks', 'xhttp', 'mandala'].includes(protocol)) {
        // [修改] 检查协议是否被禁用
        const checkProto = protocol === 'socks' ? 'socks5' : protocol;
        if (!isEnabled(checkProto)) {
            return new Response(`${protocol.toUpperCase()} is disabled by admin`, { status: 403 });
        }
        
        const id = (protocol === 'trojan' || protocol === 'ss' || protocol === 'mandala') ? ctx.dynamicUUID : ctx.userID;

        if (isClash) {
            if (protocol === 'mandala') return new Response('Clash not supported for Mandala', { status: 400 });
            return new Response(generateClashConfig(protocol, id, hostName, isTls, ctx), { headers: plainDownloadHeader });
        } else if (isSb) {
            if (protocol === 'mandala') return new Response('SingBox not supported for Mandala', { status: 400 });
            return new Response(generateSingBoxConfig(protocol, id, hostName, isTls, ctx), { headers: jsonDownloadHeader });
        } else {
            const content = genB64(protocol, isTls);
            if (isTls) return new Response(content, { headers: plainHeader }); 
            else return new Response(btoa(unescape(encodeURIComponent(content))), { headers: plainDownloadHeader });
        }
    }

    return null;
}
