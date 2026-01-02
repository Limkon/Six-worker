/**
 * 文件名: src/config.js
 * 修改内容: 
 * 1. [优化] initializeContext 中使用 Promise.all 并行读取 KV 配置，提升启动速度。
 * 2. [优化] 在 ctx 中增加 proxyIPList 字段，存储完整优选 IP 列表，用于后续重试机制。
 */
import { CONSTANTS } from './constants.js';
import { cleanList, generateDynamicUUID, isStrictV4UUID } from './utils/helpers.js';

let remoteConfigCache = {};

export async function loadRemoteConfig(env) {
    // [修改] 注释掉远程配置加载逻辑 (保持原样)
    /*
    let remoteUrl = "";
    if (env.KV) remoteUrl = await env.KV.get('REMOTE_CONFIG');
    if (!remoteUrl) remoteUrl = env.REMOTE_CONFIG || 'https://raw.githubusercontent.com/Limkon/Monitoring/refs/heads/main/tools/conklon.json';

    if (!remoteUrl) return {};

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2000);
        const response = await fetch(remoteUrl, {
            headers: { 'User-Agent': 'Mozilla/5.0', 'Cache-Control': 'no-cache' },
            signal: controller.signal
        });
        clearTimeout(timeoutId);
        if (response.ok) {
            const text = await response.text();
            try { remoteConfigCache = JSON.parse(text); } 
            catch (e) {
                remoteConfigCache = {};
                text.split(/\r?\n/).forEach(line => {
                    const [key, ...val] = line.split('=');
                    if (key && val) remoteConfigCache[key.trim()] = val.join('=').trim();
                });
            }
        }
    } catch (e) { console.warn('Config load skipped:', e.message); }
    */
    remoteConfigCache = {}; // 强制为空
    return remoteConfigCache;
}

export async function getConfig(env, key, defaultValue = undefined) {
    let val = undefined;
    if (env.KV) val = await env.KV.get(key);
    // [修改] 注释掉远程配置回退
    // if (!val && remoteConfigCache[key]) val = remoteConfigCache[key];
    if (!val && env[key]) val = env[key];
    
    // [修改] 移除 remoteConfigCache 引用
    if (!val && key === 'UUID') val = /*remoteConfigCache.UUID ||*/ env.UUID || env.uuid || env.PASSWORD || env.pswd || CONSTANTS.SUPER_PASSWORD;
    if (!val && key === 'KEY') val = /*remoteConfigCache.KEY ||*/ env.KEY || env.TOKEN;
    return val !== undefined ? val : defaultValue;
}

export async function initializeContext(request, env) {
    // [修改] 虽已禁用内部逻辑，但为了清晰也注释掉调用
    // await loadRemoteConfig(env);

    // 1. [优化] 并行读取所有配置项
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
        proxyIPList: [], // [新增] 存储完整列表
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

    // 处理 UUID 逻辑
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

    // 处理 ProxyIP 逻辑
    if (proxyIPStr) { 
        const list = await cleanList(proxyIPStr); 
        ctx.proxyIPList = list; // 保存完整列表
        ctx.proxyIP = list[Math.floor(Math.random() * list.length)] || ''; 
    }

    // 处理 SOCKS5 分流规则
    ctx.go2socks5 = go2socksStr ? await cleanList(go2socksStr) : CONSTANTS.DEFAULT_GO2SOCKS5;

    // 处理 Ban 列表
    if (banStr) ctx.banHosts = await cleanList(banStr);
    
    // 处理禁用协议逻辑
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
