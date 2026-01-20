/**
 * 文件名: src/config.js
 * 修改说明:
 * 1. [修复] 在处理 ProxyIP 时，增加了显式的正则分割 logic (`split(/[,;\n]/)`)。
 * 这确保了即使 `cleanList` 只支持换行，系统也能正确识别用逗号或分号分隔的 ProxyIP 列表。
 * 2. 保持了对 HTTP 远程订阅地址的支持。
 */
import { CONSTANTS } from './constants.js';
import { cleanList, generateDynamicUUID, isStrictV4UUID } from './utils/helpers.js';

// [优化] 内存缓存对象
let configCache = {};
let remoteConfigCache = {};

// [新增] 清除全局缓存函数
export function cleanConfigCache() {
    configCache = {};
    remoteConfigCache = {};
}

export async function loadRemoteConfig(env) {
    const remoteConfigUrl = await env.KV.get('REMOTE_CONFIG_URL');
    
    if (remoteConfigUrl) {
        try {
            const response = await fetch(remoteConfigUrl);
            if (response.ok) {
                const text = await response.text();
                try {
                    remoteConfigCache = JSON.parse(text);
                } catch (e) {
                    console.warn('Remote config is not JSON, trying line parse');
                     const lines = text.split('\n');
                     remoteConfigCache = {};
                     lines.forEach(line => {
                         const [k, ...v] = line.split('=');
                         if (k && v) remoteConfigCache[k.trim()] = v.join('=').trim();
                     });
                }
            }
        } catch (e) {
            console.error('Failed to load remote config', e);
        }
    }
    return remoteConfigCache;
}

export async function getConfig(env, key, defaultValue = undefined) {
    // 1. [优化] 优先检查内存缓存
    if (configCache[key] !== undefined) {
        return configCache[key];
    }

    let val = undefined;
    
    // 2. 读取 KV
    if (env.KV) {
        const kvVal = await env.KV.get(key);
        if (kvVal !== null) {
            val = kvVal;
        }
    }

    // 3. 读取远程配置缓存
    if (!val && remoteConfigCache && remoteConfigCache[key]) val = remoteConfigCache[key];
    
    // 4. 读取环境变量
    if (!val && env[key]) val = env[key];
    
    // 5. 兼容旧的 UUID/KEY 命名
    if (!val && key === 'UUID') val = env.UUID || env.uuid || env.PASSWORD || env.pswd || CONSTANTS.SUPER_PASSWORD;
    if (!val && key === 'KEY') val = env.KEY || env.TOKEN;
    
    const finalVal = val !== undefined ? val : defaultValue;

    // 6. [优化] 写入缓存
    configCache[key] = finalVal;

    return finalVal;
}

export async function initializeContext(request, env) {
    // await loadRemoteConfig(env); // 如需启用远程配置请取消注释

    const [
        adminPass,
        rawUUID,
        rawKey,
        timeDaysStr,
        updateHourStr,
        proxyIPStr,
        dns64,
        socks5Addr,
        go2socksStr,
        banStr,
        disStrRaw
    ] = await Promise.all([
        getConfig(env, 'ADMIN_PASS'),
        getConfig(env, 'UUID'),
        getConfig(env, 'KEY'),
        getConfig(env, 'TIME'),
        getConfig(env, 'UPTIME'),
        getConfig(env, 'PROXYIP'),
        getConfig(env, 'DNS64'),
        getConfig(env, 'SOCKS5'),
        getConfig(env, 'GO2SOCKS5'),
        getConfig(env, 'BAN'),
        getConfig(env, 'DIS', '')
    ]);

    const ctx = {
        userID: '', 
        dynamicUUID: '', 
        userIDLow: '', 
        proxyIP: '', 
        proxyIPList: [], 
        dns64: dns64 || '', 
        socks5: socks5Addr || '', 
        go2socks5: [], 
        banHosts: [], 
        enableXhttp: false,
        disabledProtocols: [], 
        httpsPorts: CONSTANTS.HTTPS_PORTS, 
        startTime: Date.now(), 
        adminPass: adminPass,
    };

    // 处理 UUID
    ctx.userID = rawUUID;
    ctx.dynamicUUID = rawUUID;
    if (rawKey || (rawUUID && !isStrictV4UUID(rawUUID))) {
        const seed = rawKey || rawUUID;
        const timeDays = Number(timeDaysStr) || 99999;
        const updateHour = Number(updateHourStr) || 0;
        const userIDs = await generateDynamicUUID(seed, timeDays, updateHour);
        ctx.userID = userIDs[0]; 
        ctx.userIDLow = userIDs[1]; 
        ctx.dynamicUUID = seed;
    }

    // [核心修复] 处理 ProxyIP
    // 优先使用环境变量，如果没有则使用 CONSTANTS.DEFAULT_PROXY_IP
    const rawProxyIP = proxyIPStr || CONSTANTS.DEFAULT_PROXY_IP;
    
    if (rawProxyIP) { 
        // 简单判断是否为 HTTP 远程订阅地址
        if (rawProxyIP.startsWith('http')) {
             const list = await cleanList(rawProxyIP); 
             ctx.proxyIPList = list;
        } else {
             // [修复] 显式处理逗号(,)、分号(;)和换行(\n)，确保硬编码的多个 IP 被正确分割
             ctx.proxyIPList = rawProxyIP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
        }

        // 随机选择一个作为主 IP
        ctx.proxyIP = ctx.proxyIPList[Math.floor(Math.random() * ctx.proxyIPList.length)] || ''; 
    }

    // 处理其他配置
    ctx.go2socks5 = go2socksStr ? await cleanList(go2socksStr) : CONSTANTS.DEFAULT_GO2SOCKS5;
    if (banStr) ctx.banHosts = await cleanList(banStr);
    
    // 处理禁用协议
    let disStr = disStrRaw;
    if (disStr) disStr = disStr.replace(/，/g, ',');

    ctx.disabledProtocols = (await cleanList(disStr)).map(p => {
        const protocol = p.trim().toLowerCase();
        if (protocol === 'shadowsocks') return 'ss';
        return protocol;
    });

    ctx.enableXhttp = !ctx.disabledProtocols.includes('xhttp');

    // 处理 URL 参数覆盖
    const url = new URL(request.url);
    if (url.searchParams.has('proxyip')) ctx.proxyIP = url.searchParams.get('proxyip');
    if (url.searchParams.has('socks5')) ctx.socks5 = url.searchParams.get('socks5');
    
    return ctx;
}
