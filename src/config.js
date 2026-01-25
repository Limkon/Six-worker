// src/config.js
/**
 * 文件名: src/config.js
 * 修改说明:
 * 1. [修复] 严格执行“单一连接只使用一个ProxyIP”策略。
 * 2. [优化] 从获取到的列表中随机选择 1 个 IP，并强制上下文仅锁定该 IP，防止 outbound 模块轮询。
 */
import { CONSTANTS } from './constants.js';
import { cleanList, generateDynamicUUID, isStrictV4UUID } from './utils/helpers.js';

// 内存缓存对象
let configCache = {};

// 远程配置缓存
let remoteConfigCache = {
    data: {},
    lastFetch: 0
};

// 远程 ProxyIP 缓存
let proxyIPRemoteCache = {
    data: [],
    expires: 0
};

export function cleanConfigCache() {
    configCache = {};
    remoteConfigCache = { data: {}, lastFetch: 0 };
    proxyIPRemoteCache = { data: [], expires: 0 };
}

export async function loadRemoteConfig(env, forceReload = false) {
    const remoteConfigUrl = await env.KV.get('REMOTE_CONFIG_URL');
    
    // 如果不是强制刷新(forceReload为false)，且缓存中有数据，直接返回缓存。
    if (!forceReload && remoteConfigCache.data && Object.keys(remoteConfigCache.data).length > 0) {
        return remoteConfigCache.data;
    }
    
    if (remoteConfigUrl) {
        try {
            // 添加超时控制 (5秒)
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);
            
            const response = await fetch(remoteConfigUrl, {
                signal: controller.signal
            });
            
            clearTimeout(timeoutId); // 请求成功，清除定时器

            if (response.ok) {
                const text = await response.text();
                const now = Date.now();
                try {
                    const newData = JSON.parse(text);
                    remoteConfigCache.data = newData;
                    remoteConfigCache.lastFetch = now;
                    
                    // 远程配置更新后，清空本地 key-value 缓存，确保生效
                    configCache = {}; 
                } catch (e) {
                    console.warn('Remote config is not JSON, trying line parse');
                    const lines = text.split('\n');
                    const newData = {};
                    lines.forEach(line => {
                        const trimmedLine = line.trim();
                        if (!trimmedLine || trimmedLine.startsWith('#') || trimmedLine.startsWith('//')) {
                            return;
                        }
                        const eqIndex = trimmedLine.indexOf('=');
                        if (eqIndex > 0) {
                            const k = trimmedLine.substring(0, eqIndex).trim();
                            const v = trimmedLine.substring(eqIndex + 1).trim();
                            if (k && v) {
                                newData[k] = v;
                            }
                        }
                    });
                    remoteConfigCache.data = newData;
                    remoteConfigCache.lastFetch = now;
                    configCache = {}; 
                }
            }
        } catch (e) {
            console.error('Failed to load remote config', e);
        }
    }
    return remoteConfigCache.data;
}

export async function getConfig(env, key, defaultValue = undefined) {
    if (configCache[key] !== undefined) {
        return configCache[key];
    }

    let val = undefined;
    
    if (env.KV) {
        const kvVal = await env.KV.get(key);
        if (kvVal !== null) {
            val = kvVal;
        }
    }

    if (!val && remoteConfigCache.data && remoteConfigCache.data[key]) {
        val = remoteConfigCache.data[key];
    }
    
    if (!val && env[key]) val = env[key];
    
    if (!val && key === 'UUID') val = env.UUID || env.uuid || env.PASSWORD || env.pswd || env.SUPER_PASSWORD || CONSTANTS.SUPER_PASSWORD;
    if (!val && key === 'KEY') val = env.KEY || env.TOKEN;
    
    const finalVal = val !== undefined ? val : defaultValue;

    configCache[key] = finalVal;

    return finalVal;
}

export async function initializeContext(request, env) {
    // 解析 URL 以检查 flush 参数
    const url = new URL(request ? request.url : 'http://localhost');
    const forceReload = url.searchParams.has('flush'); // 只要 URL 包含 ?flush 即可触发

    const enableRemote = await getConfig(env, 'REMOTE_CONFIG', '0');
    if (enableRemote === '1') {
        await loadRemoteConfig(env, forceReload);
    }

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
        expectedUserIDs: [], 
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

    if (rawUUID) {
        ctx.userID = rawUUID;
        ctx.dynamicUUID = rawUUID;
    }

    if (rawKey || (rawUUID && !isStrictV4UUID(rawUUID))) {
        const seed = rawKey || rawUUID;
        
        if (seed) {
            const timeDays = Number(timeDaysStr) || 0;
            const updateHour = Number(updateHourStr) || 0;
            const userIDs = await generateDynamicUUID(seed, timeDays, updateHour);
            ctx.userID = userIDs[0]; 
            ctx.userIDLow = userIDs[1]; 
            ctx.dynamicUUID = seed;
        }
    }

    if (!ctx.userID) {
        const superPass = await getConfig(env, 'SUPER_PASSWORD') || CONSTANTS.SUPER_PASSWORD;
        
        if (superPass) {
             const timeDays = Number(timeDaysStr) || 0;
             const updateHour = Number(updateHourStr) || 0;
             const userIDs = await generateDynamicUUID(superPass, timeDays, updateHour);
             ctx.userID = userIDs[0]; 
             ctx.userIDLow = userIDs[1]; 
             ctx.dynamicUUID = superPass;
             console.log('[CONFIG] Missing UUID/KEY, generated UUID using SUPER_PASSWORD.');
        } else {
            console.warn('[CONFIG] CRITICAL: No UUID/KEY/SUPER_PASSWORD configured! Generating temporary UUID. Service may be unstable.');
            const tempUUID = crypto.randomUUID();
            ctx.userID = tempUUID;
            ctx.dynamicUUID = tempUUID;
        }
    }

    ctx.expectedUserIDs = [ctx.userID, ctx.userIDLow].filter(Boolean).map(id => id.toLowerCase());

    const rawProxyIP = proxyIPStr || CONSTANTS.DEFAULT_PROXY_IP;
    
    // [逻辑修正] ProxyIP 获取逻辑
    let rawList = [];
    if (rawProxyIP) { 
        if (rawProxyIP.startsWith('http')) {
             if (Date.now() < proxyIPRemoteCache.expires) {
                 rawList = proxyIPRemoteCache.data;
             } else {
                 try {
                     // 添加超时控制 (5秒)
                     const controller = new AbortController();
                     const timeoutId = setTimeout(() => controller.abort(), 5000);

                     const response = await fetch(rawProxyIP, {
                        signal: controller.signal
                     });
                     
                     clearTimeout(timeoutId);

                     if (response.ok) {
                         const text = await response.text();
                         const list = await cleanList(text); 
                         rawList = list;
                         proxyIPRemoteCache.data = list;
                         proxyIPRemoteCache.expires = Date.now() + 600000; // 成功缓存 10 分钟
                     } else {
                         throw new Error(`ProxyIP fetch failed: ${response.status}`);
                     }
                 } catch (e) {
                     console.error('Failed to fetch remote ProxyIP:', e);
                     const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
                     rawList = defParams;
                     // 失败时缓存默认值 1 分钟，避免频繁重试
                     proxyIPRemoteCache.data = defParams;
                     proxyIPRemoteCache.expires = Date.now() + 60000; 
                 }
             }
        } else {
             rawList = rawProxyIP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
        }
    }

    // [关键修复] 严格执行“单一ProxyIP”原则
    // 从列表中随机选择 1 个，并在整个请求生命周期中只使用这一个
    if (rawList && rawList.length > 0) {
        const selectedIP = rawList[Math.floor(Math.random() * rawList.length)];
        ctx.proxyIP = selectedIP;
        // 锁定列表仅包含这一个 IP，防止 Outbound 模块意外使用其他 IP
        ctx.proxyIPList = [selectedIP]; 
    } else {
        ctx.proxyIP = '';
        ctx.proxyIPList = [];
    }

    ctx.go2socks5 = go2socksStr ? await cleanList(go2socksStr) : CONSTANTS.DEFAULT_GO2SOCKS5;
    if (banStr) ctx.banHosts = await cleanList(banStr);
    
    let disStr = disStrRaw;
    if (disStr) disStr = disStr.replace(/，/g, ',');

    ctx.disabledProtocols = (await cleanList(disStr)).map(p => {
        const protocol = p.trim().toLowerCase();
        if (protocol === 'shadowsocks') return 'ss';
        return protocol;
    });

    ctx.enableXhttp = !ctx.disabledProtocols.includes('xhttp');

    if (url.searchParams.has('proxyip')) {
        const manualIP = url.searchParams.get('proxyip');
        ctx.proxyIP = manualIP;
        ctx.proxyIPList = [manualIP]; // 手动指定时同样锁定
    }
    if (url.searchParams.has('socks5')) ctx.socks5 = url.searchParams.get('socks5');
    
    return ctx;
}
