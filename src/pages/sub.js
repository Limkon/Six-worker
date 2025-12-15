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
            // 简单处理: 如果是反代IP形式 (ip:port#remark)，直接使用
            // 过滤逻辑简化，假设内容是标准的一行一个
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
            // 检查 TLS 列是否匹配，且速度是否达标
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

// 准备订阅数据 (填充 ctx.addresses 和 ctx.addressesnotls)
export async function prepareSubscriptionData(ctx, env) {
    // 1. 获取配置
    const addStr = await getConfig(env, 'ADD.txt') || await getConfig(env, 'ADD');
    const addApiStr = await getConfig(env, 'ADDAPI');
    const addNoTlsStr = await getConfig(env, 'ADDNOTLS');
    const addNoTlsApiStr = await getConfig(env, 'ADDNOTLSAPI');
    const addCsvStr = await getConfig(env, 'ADDCSV');
    const linkStr = await getConfig(env, 'LINK');
    
    // 参数配置
    const DLS = Number(await getConfig(env, 'DLS', '8'));
    const remarkIndex = Number(await getConfig(env, 'CSVREMARK', '1'));

    // 2. 初始化列表
    let addresses = [];
    let addressesApi = [];
    let addressesNoTls = [];
    let addressesNoTlsApi = [];
    let addressesCsv = [];
    let links = [];

    // 3. 处理手动列表 (ADD)
    if (addStr) {
        const list = await cleanList(addStr);
        // 分类 API 和 普通地址
        list.forEach(item => {
            if (item.startsWith('http')) addressesApi.push(item);
            else addresses.push(item);
        });
    }

    // 4. 处理手动 API (ADDAPI)
    if (addApiStr) {
        const apis = await cleanList(addApiStr);
        addressesApi = addressesApi.concat(apis);
    }
    
    // 5. 拉取 API 内容 (并发)
    if (addressesApi.length > 0) {
        const promises = addressesApi.map(url => fetchAndParseAPI(url, ctx.httpsPorts));
        const results = await Promise.all(promises);
        results.forEach(res => addresses = addresses.concat(res));
    }

    // 6. 处理非 TLS (ADDNOTLS)
    if (addNoTlsStr) addressesNoTls = await cleanList(addNoTlsStr);
    
    if (addNoTlsApiStr) {
        const apis = await cleanList(addNoTlsApiStr);
        const promises = apis.map(url => fetchAndParseAPI(url, CONSTANTS.HTTP_PORTS)); // 使用 HTTP 端口
        const results = await Promise.all(promises);
        results.forEach(res => addressesNoTls = addressesNoTls.concat(res));
    }

    // 7. 处理 CSV (ADDCSV)
    if (addCsvStr) {
        const csvs = await cleanList(addCsvStr);
        // 并发拉取 TLS 和 非TLS
        const promisesTLS = csvs.map(url => fetchAndParseCSV(url, true, ctx.httpsPorts, DLS, remarkIndex));
        const promisesNoTLS = csvs.map(url => fetchAndParseCSV(url, false, ctx.httpsPorts, DLS, remarkIndex));
        
        const [resTLS, resNoTLS] = await Promise.all([Promise.all(promisesTLS), Promise.all(promisesNoTLS)]);
        resTLS.forEach(r => addresses = addresses.concat(r));
        resNoTLS.forEach(r => addressesNoTls = addressesNoTls.concat(r));
    }

    // 8. 处理 LINK (硬编码链接)
    if (linkStr) {
        links = await cleanList(linkStr);
    }

    // 9. 去重与兜底
    ctx.addresses = [...new Set(addresses)].filter(Boolean);
    ctx.addressesnotls = [...new Set(addressesNoTls)].filter(Boolean);
    ctx.hardcodedLinks = links;

    // 兜底：如果完全没有节点，添加官方默认
    if (ctx.addresses.length === 0 && ctx.hardcodedLinks.length === 0) {
        ctx.addresses.push("www.visa.com.tw:443#CF-Default-1");
        ctx.addresses.push("usa.visa.com:8443#CF-Default-2");
    }
}

// 处理订阅请求
export async function handleSubscription(request, env, ctx, subPath, hostName) {
    const FileName = await getConfig(env, 'SUBNAME', 'sub');
    
    // 1. 准备数据
    await prepareSubscriptionData(ctx, env);

    const subHashLength = CONSTANTS.SUB_HASH_LENGTH;
    const enableXhttp = ctx.enableXhttp;

    // 2. 构造路径映射表 (Path -> Hash)
    const subPathNames = [
        'all', 'sub', 'all-tls', 'all-clash', 'all-clash-tls', 'all-sb', 'all-sb-tls',
        'vless', 'vless-tls', 'vless-clash', 'vless-clash-tls', 'vless-sb', 'vless-sb-tls',
        'trojan', 'trojan-tls', 'trojan-clash', 'trojan-clash-tls', 'trojan-sb', 'trojan-sb-tls',
        'ss', 'ss-tls', 'ss-clash', 'ss-clash-tls', 'ss-sb', 'ss-sb-tls',
        'socks', 'socks-tls', 'socks-clash', 'socks-clash-tls', 'socks-sb', 'socks-sb-tls',
        'xhttp-tls', 'xhttp-clash-tls', 'xhttp-sb-tls'
    ];
    
    // 计算 Hash
    const hashPromises = subPathNames.map(p => sha1(p));
    const hashes = (await Promise.all(hashPromises)).map(h => h.toLowerCase().substring(0, subHashLength));
    
    const hashToName = {};
    hashes.forEach((h, i) => hashToName[h] = subPathNames[i]);
    
    // 3. 匹配路径
    const requestedHash = subPath.toLowerCase().substring(0, subHashLength);
    const pathName = hashToName[requestedHash];
    
    if (!pathName) return null; // Not a subscription request

    // 4. 生成内容
    const plainHeader = { "Content-Type": "text/plain;charset=utf-8" };
    const plainDownloadHeader = { ...plainHeader, "Content-Disposition": `attachment; filename="${FileName}"` };
    const jsonHeader = { "Content-Type": "application/json;charset=utf-8" };
    const jsonDownloadHeader = { ...jsonHeader, "Content-Disposition": `attachment; filename="${FileName}.json"` };

    // 辅助函数：简化调用
    const genB64 = (proto, tls) => generateBase64Subscription(proto, (proto==='ss'||proto==='trojan')?ctx.dynamicUUID:ctx.userID, hostName, tls, ctx);
    
    // --- 通用订阅 ---
    if (pathName === 'all' || pathName === 'sub') {
        const content = [
            genB64('vless', false),
            genB64('trojan', false),
            genB64('ss', false),
            genB64('socks', false),
            enableXhttp ? genB64('xhttp', true) : ''
        ].join('\n');
        return new Response(btoa(unescape(encodeURIComponent(content))), { headers: plainDownloadHeader });
    }
    if (pathName === 'all-tls') {
        const content = [
            genB64('vless', true),
            genB64('trojan', true),
            genB64('ss', true),
            genB64('socks', true),
            enableXhttp ? genB64('xhttp', true) : ''
        ].join('\n');
        return new Response(content, { headers: plainHeader });
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

    if (['vless', 'trojan', 'ss', 'socks', 'xhttp'].includes(protocol)) {
        if (protocol === 'xhttp' && !enableXhttp) return new Response('XHTTP disabled', { status: 404 });
        
        const id = (protocol === 'trojan' || protocol === 'ss') ? ctx.dynamicUUID : ctx.userID;

        if (isClash) {
            return new Response(generateClashConfig(protocol, id, hostName, isTls, ctx), { headers: plainDownloadHeader });
        } else if (isSb) {
            return new Response(generateSingBoxConfig(protocol, id, hostName, isTls, ctx), { headers: jsonDownloadHeader });
        } else {
            // Base64
            const content = genB64(protocol, isTls);
            if (isTls) return new Response(content, { headers: plainHeader }); // TLS 预览用明文
            else return new Response(btoa(unescape(encodeURIComponent(content))), { headers: plainDownloadHeader });
        }
    }

    return null;
}
