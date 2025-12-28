/**
 * 文件名: src/pages/sub.js
 * 修改内容: 
 * 1. 引入协议禁用检查逻辑 (isEnabled)。
 * 2. 生成 all/all-tls 订阅时过滤被禁用的协议。
 * 3. 单协议订阅请求时，如果协议被禁用则拦截。
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
        const timeout = setTimeout(() => controller.abort(), 2000); // 2秒超时
        const response = await fetch(apiUrl, { signal: controller.signal });
        clearTimeout(timeout);
        if (response.ok) {
            const text = await response.text();
            return await cleanList(text);
        }
    } catch (e) {
        console.error(`Fetch API ${apiUrl} failed:`, e);
    }
    return [];
}

// 整理测速结果 (CSV)
async function fetchAndParseCSV(csvUrl, isTLS, httpsPorts, DLS, remarkIndex) {
    if (!csvUrl) return [];
    try {
        const response = await fetch(csvUrl);
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
        console.error('Fetch CSV failed:', e);
    }
    return [];
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

    let addresses = [];
    let addressesApi = [];
    let addressesNoTls = [];
    let addressesNoTlsApi = [];
    let addressesCsv = [];
    let links = [];

    if (addStr) {
        const list = await cleanList(addStr);
        list.forEach(item => {
            if (item.startsWith('http')) addressesApi.push(item);
            else addresses.push(item);
        });
    }

    if (addApiStr) {
        const apis = await cleanList(addApiStr);
        addressesApi = addressesApi.concat(apis);
    }
    
    if (addressesApi.length > 0) {
        const promises = addressesApi.map(url => fetchAndParseAPI(url, ctx.httpsPorts));
        const results = await Promise.all(promises);
        results.forEach(res => addresses = addresses.concat(res));
    }

    if (addNoTlsStr) addressesNoTls = await cleanList(addNoTlsStr);
    
    if (addNoTlsApiStr) {
        const apis = await cleanList(addNoTlsApiStr);
        const promises = apis.map(url => fetchAndParseAPI(url, CONSTANTS.HTTP_PORTS)); 
        const results = await Promise.all(promises);
        results.forEach(res => addressesNoTls = addressesNoTls.concat(res));
    }

    if (addCsvStr) {
        const csvs = await cleanList(addCsvStr);
        const promisesTLS = csvs.map(url => fetchAndParseCSV(url, true, ctx.httpsPorts, DLS, remarkIndex));
        const promisesNoTLS = csvs.map(url => fetchAndParseCSV(url, false, ctx.httpsPorts, DLS, remarkIndex));
        
        const [resTLS, resNoTLS] = await Promise.all([Promise.all(promisesTLS), Promise.all(promisesNoTLS)]);
        resTLS.forEach(r => addresses = addresses.concat(r));
        resNoTLS.forEach(r => addressesNoTls = addressesNoTls.concat(r));
    }

    if (linkStr) {
        links = await cleanList(linkStr);
    }

    ctx.addresses = [...new Set(addresses)].filter(Boolean);
    ctx.addressesnotls = [...new Set(addressesNoTls)].filter(Boolean);
    ctx.hardcodedLinks = links;

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
    // generators.js 中的 generateMixedClashConfig 已经内置了 disabledProtocols 过滤，直接调用即可
    if (pathName === 'all-clash') {
        return new Response(generateMixedClashConfig(ctx.userID, ctx.dynamicUUID, hostName, false, enableXhttp, ctx), { headers: plainDownloadHeader });
    }
    if (pathName === 'all-clash-tls') {
        return new Response(generateMixedClashConfig(ctx.userID, ctx.dynamicUUID, hostName, true, enableXhttp, ctx), { headers: plainHeader });
    }

    // --- SingBox 混合订阅 ---
    // generators.js 中的 generateMixedSingBoxConfig 已经内置了 disabledProtocols 过滤
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
        // 将 URL 路径中的 'socks' 映射为 'socks5' 进行检查
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
