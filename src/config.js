/**
 * 文件名: src/config.js
 * 修改内容: 修复禁用协议列表解析问题（增加 trim 去空格、中文逗号兼容、Shadowsocks 别名映射）。
 */
import { CONSTANTS } from './constants.js';
import { cleanList, generateDynamicUUID, isStrictV4UUID } from './utils/helpers.js';

let remoteConfigCache = {};

export async function loadRemoteConfig(env) {
    // [修改] 注释掉远程配置加载逻辑
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
    const ctx = {
        userID: '', dynamicUUID: '', userIDLow: '', proxyIP: '', dns64: '', socks5: '', go2socks5: [], banHosts: [], 
        enableXhttp: false,
        disabledProtocols: [], // [新增] 禁用协议列表
        httpsPorts: CONSTANTS.HTTPS_PORTS, startTime: Date.now(), adminPass: await getConfig(env, 'ADMIN_PASS'),
    };
    let rawUUID = await getConfig(env, 'UUID');
    let rawKey = await getConfig(env, 'KEY');
    ctx.userID = rawUUID;
    ctx.dynamicUUID = rawUUID;
    if (rawKey || (rawUUID && !isStrictV4UUID(rawUUID))) {
        const seed = rawKey || rawUUID;
        const timeDays = Number(await getConfig(env, 'TIME')) || 99999;
        const updateHour = Number(await getConfig(env, 'UPTIME')) || 0;
        const userIDs = await generateDynamicUUID(seed, timeDays, updateHour);
        ctx.userID = userIDs[0]; ctx.userIDLow = userIDs[1]; ctx.dynamicUUID = seed;
    }
    const proxyIPStr = await getConfig(env, 'PROXYIP');
    if (proxyIPStr) { const list = await cleanList(proxyIPStr); ctx.proxyIP = list[Math.floor(Math.random() * list.length)] || ''; }
    ctx.dns64 = await getConfig(env, 'DNS64');
    let socks5Addr = await getConfig(env, 'SOCKS5');
    if (socks5Addr) ctx.socks5 = socks5Addr;
    const go2socksStr = await getConfig(env, 'GO2SOCKS5');
    ctx.go2socks5 = go2socksStr ? await cleanList(go2socksStr) : CONSTANTS.DEFAULT_GO2SOCKS5;
    const banStr = await getConfig(env, 'BAN');
    if (banStr) ctx.banHosts = await cleanList(banStr);
    
    // [修改] 处理禁用协议逻辑 (取代原 EX 逻辑)
    // 获取禁用列表，默认值为 '' (即默认不禁用任何协议)
    let disStr = await getConfig(env, 'DIS', '');
    
    // 预处理：替换中文逗号，避免 split 失败
    if (disStr) disStr = disStr.replace(/，/g, ',');

    ctx.disabledProtocols = (await cleanList(disStr)).map(p => {
        // 去除空格并转小写
        const protocol = p.trim().toLowerCase();
        // 处理别名：将 shadowsocks 映射为内部使用的 ss
        if (protocol === 'shadowsocks') return 'ss';
        return protocol;
    });

    // 根据禁用列表推导 enableXhttp
    // 只有当 'xhttp' 不在禁用列表中时，才启用 XHTTP
    ctx.enableXhttp = !ctx.disabledProtocols.includes('xhttp');

    const url = new URL(request.url);
    if (url.searchParams.has('proxyip')) ctx.proxyIP = url.searchParams.get('proxyip');
    if (url.searchParams.has('socks5')) ctx.socks5 = url.searchParams.get('socks5');
    return ctx;
}
