// src/config.js
/**
 * 文件名: src/config.js
 * 修改说明:
 * 1. [Fix] 修复远程配置关闭后 (REMOTE_CONFIG=0) 仍然读取脏缓存的 Bug。
 * 2. [Optimization] 保持并发限制 (5+5+1) 以避免 CPU 超时。
 */
import { CONSTANTS } from './constants.js';
import { cleanList, generateDynamicUUID, isStrictV4UUID, getKV, clearKVCache } from './utils/helpers.js';

// 内存缓存对象 (处理后的配置)
// 注意：此缓存随 Worker 实例存活，修改 KV 后需访问 /?flush=1 才能立即生效
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

/**
 * 清理配置缓存
 * @param {Array<string>} [updatedKeys] - 可选，仅清理指定的键名。
 */
export async function cleanConfigCache(updatedKeys) {
    if (!updatedKeys || !Array.isArray(updatedKeys) || updatedKeys.includes('REMOTE_CONFIG_URL')) {
        configCache = {};
        remoteConfigCache = { data: {}, lastFetch: 0 };
        proxyIPRemoteCache = { data: [], expires: 0 };
        await clearKVCache();
        return;
    }
    for (const key of updatedKeys) {
        delete configCache[key];
    }
    await clearKVCache(updatedKeys);
    if (updatedKeys.includes('PROXYIP')) {
        proxyIPRemoteCache = { data: [], expires: 0 };
    }
}

export async function loadRemoteConfig(env, forceReload = false) {
    const remoteConfigUrl = await getKV(env, 'REMOTE_CONFIG_URL');
    
    if (!forceReload && remoteConfigCache.data && Object.keys(remoteConfigCache.data).length > 0) {
        return remoteConfigCache.data;
    }
    
    if (remoteConfigUrl) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);
            
            const response = await fetch(remoteConfigUrl, {
                signal: controller.signal
            }).finally(() => {
                clearTimeout(timeoutId);
            });

            if (response.ok) {
                const text = await response.text();
                const now = Date.now();
                try {
                    const newData = JSON.parse(text);
                    remoteConfigCache.data = newData;
                    remoteConfigCache.lastFetch = now;
                    configCache = {}; // 远程配置更新，强制让 getConfig 重新计算
                } catch (e) {
                    console.warn('Remote config is not JSON, trying line parse');
                    const lines = text.split('\n');
                    const newData = {};
                    lines.forEach(line => {
                        const trimmedLine = line.trim();
                        if (!trimmedLine || trimmedLine.startsWith('#') || trimmedLine.startsWith('//')) return;
                        const eqIndex = trimmedLine.indexOf('=');
                        if (eqIndex > 0) {
                            const k = trimmedLine.substring(0, eqIndex).trim();
                            const v = trimmedLine.substring(eqIndex + 1).trim();
                            if (k && v) newData[k] = v;
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
        val = await getKV(env, key);
    }

    // 仅当 KV 未定义时才尝试远程配置
    if ((val === null || val === undefined) && remoteConfigCache.data && remoteConfigCache.data[key]) {
        val = remoteConfigCache.data[key];
    }
    
    if ((val === null || val === undefined) && env[key]) {
        val = env[key];
    }
    
    if (!val && key === 'UUID') {
         val = env.UUID || env.uuid || env.PASSWORD || env.pswd || env.SUPER_PASSWORD || CONSTANTS.SUPER_PASSWORD;
    }
    if (!val && key === 'KEY') val = env.KEY || env.TOKEN;
    
    const finalVal = (val !== undefined && val !== null) ? val : defaultValue;
    configCache[key] = finalVal;
    return finalVal;
}

export async function initializeContext(request, env) {
    const url = new URL(request ? request.url : 'http://localhost');
    const forceReload = url.searchParams.get('flush') === '1'; 

    if (forceReload) {
        console.log('[Config] Flush requested via URL parameter. Purging caches...');
        await cleanConfigCache();
    }

    const enableRemote = await getConfig(env, 'REMOTE_CONFIG', '0');
    if (enableRemote === '1') {
        await loadRemoteConfig(env, forceReload);
    } else {
        // [Fix] 关键修复: 如果远程配置被关闭，必须清除内存中可能残留的远程数据
        // 否则 getConfig 在 KV 缺失时会错误地回退到陈旧的远程配置中
        if (remoteConfigCache.data && Object.keys(remoteConfigCache.data).length > 0) {
            console.log('[Config] Remote config disabled, clearing stale cache.');
            remoteConfigCache.data = {};
            remoteConfigCache.lastFetch = 0;
            // 同时清理 configCache，防止已计算的混合配置包含脏数据
            configCache = {}; 
        }
    }

    // [Optimization] 分批执行 (Batch Limit: 5)
    // Batch 1: 核心认证 (5)
    const [adminPass, rawUUID, rawKey, timeDaysStr, updateHourStr] = await Promise.all([
        getConfig(env, 'ADMIN_PASS'),
        getConfig(env, 'UUID'),
        getConfig(env, 'KEY'),
        getConfig(env, 'TIME'),
        getConfig(env, 'UPTIME')
    ]);

    // Batch 2: 网络配置 (5)
    const [proxyIPStr, dns64, socks5Addr, go2socksStr, banStr] = await Promise.all([
        getConfig(env, 'PROXYIP'),
        getConfig(env, 'DNS64'),
        getConfig(env, 'SOCKS5'),
        getConfig(env, 'GO2SOCKS5'),
        getConfig(env, 'BAN')
    ]);

    // Batch 3: 其他 (1)
    const disStrRaw = await getConfig(env, 'DIS', '');

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
            console.warn('[CONFIG] CRITICAL: No UUID/KEY/SUPER_PASSWORD configured!');
            const tempUUID = crypto.randomUUID();
            ctx.userID = tempUUID;
            ctx.dynamicUUID = tempUUID;
        }
    }

    ctx.expectedUserIDs = [ctx.userID, ctx.userIDLow].filter(Boolean).map(id => id.toLowerCase());

    const rawProxyIP = proxyIPStr || CONSTANTS.DEFAULT_PROXY_IP;
    
    let rawList = [];
    if (rawProxyIP) { 
        if (rawProxyIP.startsWith('http')) {
             if (Date.now() < proxyIPRemoteCache.expires) {
                 rawList = proxyIPRemoteCache.data;
             } else {
                 try {
                     const controller = new AbortController();
                     const timeoutId = setTimeout(() => controller.abort(), 5000);

                     const response = await fetch(rawProxyIP, {
                        signal: controller.signal
                     }).finally(() => {
                         clearTimeout(timeoutId);
                     });

                     if (response.ok) {
                         const text = await response.text();
                         const list = await cleanList(text); 
                         rawList = list;
                         proxyIPRemoteCache.data = list;
                         proxyIPRemoteCache.expires = Date.now() + 600000;
                     } else {
                         throw new Error(`ProxyIP fetch failed: ${response.status}`);
                     }
                 } catch (e) {
                     console.error('Failed to fetch remote ProxyIP:', e);
                     const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
                     rawList = defParams;
                     proxyIPRemoteCache.data = defParams;
                     proxyIPRemoteCache.expires = Date.now() + 60000; 
                 }
             }
        } else {
             rawList = rawProxyIP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
        }
    }

    // [Feature] 严格单一 ProxyIP 策略
    if (rawList && rawList.length > 0) {
        const selectedIP = rawList[Math.floor(Math.random() * rawList.length)];
        ctx.proxyIP = selectedIP;
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
        ctx.proxyIPList = [manualIP];
    }
    if (url.searchParams.has('socks5')) ctx.socks5 = url.searchParams.get('socks5');
    
    return ctx;
}
