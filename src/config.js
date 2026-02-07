// src/config.js
/**
 * 文件名: src/config.js
 * 审计优化说明:
 * 1. [Optimization] 增加 parsedListCache: 缓存解析后的数组对象(BAN/PROXYIP等)，避免每次请求重复 split/map。
 */
import { CONSTANTS } from './constants.js';
import { cleanList, generateDynamicUUID, isStrictV4UUID, getKV, clearKVCache } from './utils/helpers.js';

// 内存缓存对象 (处理后的配置)
let configCache = {};
// 配置版本号 (用于并发控制)
let configGeneration = 0;

// [Optimization] 解析后的列表缓存 (避免重复 split/map)
let parsedListCache = {
    proxyIP: null,     // Array
    banHosts: null,    // Array
    disabledProtocols: null, // Array
    go2socks5: null    // Array
};

// 远程配置缓存
const REMOTE_CONFIG_TTL = 360 * 60 * 1000; 
let remoteConfigCache = {
    data: {},
    lastFetch: 0
};

// 远程 ProxyIP 缓存及并发锁
let proxyIPRemoteCache = {
    data: [],
    expires: 0,
    fetchingPromise: null
};

// UUID 计算缓存
let uuidCache = {
    key: null,      
    data: null,     
    lastUpdate: 0   
};
const UUID_CACHE_TTL = 10 * 60 * 1000; 

/**
 * 清理配置缓存
 */
export async function cleanConfigCache(updatedKeys) {
    configGeneration++;

    if (!updatedKeys || !Array.isArray(updatedKeys) || updatedKeys.includes('REMOTE_CONFIG_URL')) {
        configCache = {};
        remoteConfigCache = { data: {}, lastFetch: 0 };
        proxyIPRemoteCache = { data: [], expires: 0, fetchingPromise: null };
        uuidCache = { key: null, data: null, lastUpdate: 0 };
        // [Optimization] 清理列表缓存
        parsedListCache = { proxyIP: null, banHosts: null, disabledProtocols: null, go2socks5: null };
        await clearKVCache();
        return;
    }
    for (const key of updatedKeys) {
        delete configCache[key];
    }
    await clearKVCache(updatedKeys);
    
    // [Optimization] 定向清理列表缓存
    if (updatedKeys.includes('PROXYIP')) {
        proxyIPRemoteCache = { data: [], expires: 0, fetchingPromise: null };
        parsedListCache.proxyIP = null;
    }
    if (updatedKeys.includes('BAN')) parsedListCache.banHosts = null;
    if (updatedKeys.includes('DIS')) parsedListCache.disabledProtocols = null;
    if (updatedKeys.includes('GO2SOCKS5')) parsedListCache.go2socks5 = null;

    if (updatedKeys.some(k => ['UUID', 'KEY', 'TIME', 'UPTIME', 'SUPER_PASSWORD'].includes(k))) {
        uuidCache = { key: null, data: null, lastUpdate: 0 };
    }
}

export async function loadRemoteConfig(env, forceReload = false) {
    const remoteConfigUrl = await getKV(env, 'REMOTE_CONFIG_URL');
    const now = Date.now();
    const isExpired = (now - remoteConfigCache.lastFetch) > REMOTE_CONFIG_TTL;

    if (!forceReload && !isExpired && remoteConfigCache.data && Object.keys(remoteConfigCache.data).length > 0) {
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
                const updateTime = Date.now();
                
                const parseConfig = (txt) => {
                    try {
                        return JSON.parse(txt);
                    } catch (e) {
                        console.warn('Remote config is not JSON, trying line parse');
                        const lines = txt.split('\n');
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
                        return newData;
                    }
                };

                const newData = parseConfig(text);
                remoteConfigCache.data = newData;
                remoteConfigCache.lastFetch = updateTime;
                
                configCache = {}; 
                configGeneration++;
                // [Optimization] 远程配置更新后，也要清理列表缓存，因为可能包含相关配置
                parsedListCache = { proxyIP: null, banHosts: null, disabledProtocols: null, go2socks5: null };
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
    const currentGen = configGeneration;
    let val = undefined;
    
    if (env.KV) val = await getKV(env, key);
    if ((val === null || val === undefined) && remoteConfigCache.data && remoteConfigCache.data[key]) val = remoteConfigCache.data[key];
    if ((val === null || val === undefined) && env[key]) val = env[key];
    
    if (!val && key === 'UUID') val = env.UUID || env.uuid || env.PASSWORD || env.pswd || env.SUPER_PASSWORD || CONSTANTS.SUPER_PASSWORD;
    if (!val && key === 'KEY') val = env.KEY || env.TOKEN;
    
    const finalVal = (val !== undefined && val !== null) ? val : defaultValue;
    
    if (currentGen === configGeneration) {
        configCache[key] = finalVal;
    }
    return finalVal;
}

async function getCachedUUID(seed, timeDays, updateHour) {
    const cacheKey = `${seed}|${timeDays}|${updateHour}`;
    const now = Date.now();
    if (uuidCache.key === cacheKey && uuidCache.data && (now - uuidCache.lastUpdate < UUID_CACHE_TTL)) {
        return uuidCache.data;
    }
    const userIDs = await generateDynamicUUID(seed, timeDays, updateHour);
    uuidCache = { key: cacheKey, data: userIDs, lastUpdate: now };
    return userIDs;
}

export async function initializeContext(request, env) {
    const url = new URL(request ? request.url : 'http://localhost');
    const forceReload = url.searchParams.get('flush') === '1'; 

    if (forceReload) {
        console.log('[Config] Flush requested via URL parameter. Purging caches...');
        configCache = {};
        configGeneration++;
        proxyIPRemoteCache = { data: [], expires: 0, fetchingPromise: null };
        uuidCache = { key: null, data: null, lastUpdate: 0 };
        parsedListCache = { proxyIP: null, banHosts: null, disabledProtocols: null, go2socks5: null };
        await clearKVCache();
    }

    const enableRemote = await getConfig(env, 'REMOTE_CONFIG', '0');
    if (enableRemote === '1') {
        await loadRemoteConfig(env, forceReload);
    } else {
        if (remoteConfigCache.data && Object.keys(remoteConfigCache.data).length > 0) {
            console.log('[Config] Remote config disabled, clearing stale cache.');
            remoteConfigCache.data = {};
            remoteConfigCache.lastFetch = 0;
            configCache = {}; 
            configGeneration++; 
            parsedListCache = { proxyIP: null, banHosts: null, disabledProtocols: null, go2socks5: null };
        }
    }

    const [adminPass, rawUUID, rawKey, timeDaysStr, updateHourStr] = await Promise.all([
        getConfig(env, 'ADMIN_PASS'),
        getConfig(env, 'UUID'),
        getConfig(env, 'KEY'),
        getConfig(env, 'TIME'),
        getConfig(env, 'UPTIME')
    ]);

    const [proxyIPStr, dns64, socks5Addr, go2socksStr, banStr] = await Promise.all([
        getConfig(env, 'PROXYIP'),
        getConfig(env, 'DNS64'),
        getConfig(env, 'SOCKS5'),
        getConfig(env, 'GO2SOCKS5'),
        getConfig(env, 'BAN')
    ]);

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
            const userIDs = await getCachedUUID(seed, timeDays, updateHour);
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
             const userIDs = await getCachedUUID(superPass, timeDays, updateHour);
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
             if (Date.now() < proxyIPRemoteCache.expires && proxyIPRemoteCache.data.length > 0) {
                 rawList = proxyIPRemoteCache.data;
             } else {
                 if (!proxyIPRemoteCache.fetchingPromise) {
                     proxyIPRemoteCache.fetchingPromise = (async () => {
                         try {
                             const controller = new AbortController();
                             const timeoutId = setTimeout(() => controller.abort(), 5000);
                             const response = await fetch(rawProxyIP, { signal: controller.signal }).finally(() => clearTimeout(timeoutId));
                             
                             if (response.ok) {
                                 const text = await response.text();
                                 const list = await cleanList(text);
                                 proxyIPRemoteCache.data = list;
                                 proxyIPRemoteCache.expires = Date.now() + 600000; 
                                 return list;
                             } else {
                                 throw new Error(`ProxyIP fetch failed: ${response.status}`);
                             }
                         } catch (e) {
                             console.error('Failed to fetch remote ProxyIP:', e);
                             const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
                             proxyIPRemoteCache.data = defParams;
                             proxyIPRemoteCache.expires = Date.now() + 60000; 
                             return defParams;
                         } finally {
                             proxyIPRemoteCache.fetchingPromise = null;
                         }
                     })();
                 }
                 rawList = await proxyIPRemoteCache.fetchingPromise;
             }
        } else {
            // [Optimization] 使用静态列表缓存
            if (parsedListCache.proxyIP) {
                rawList = parsedListCache.proxyIP;
            } else {
                rawList = rawProxyIP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
                parsedListCache.proxyIP = rawList;
            }
        }
    }

    if (rawList && rawList.length > 0) {
        const selectedIP = rawList[Math.floor(Math.random() * rawList.length)];
        ctx.proxyIP = selectedIP;
        ctx.proxyIPList = [selectedIP]; 
    } else {
        ctx.proxyIP = '';
        ctx.proxyIPList = [];
    }

    // [Optimization] 使用缓存优化列表解析
    if (parsedListCache.go2socks5) {
        ctx.go2socks5 = parsedListCache.go2socks5;
    } else {
        ctx.go2socks5 = go2socksStr ? await cleanList(go2socksStr) : CONSTANTS.DEFAULT_GO2SOCKS5;
        parsedListCache.go2socks5 = ctx.go2socks5;
    }

    if (parsedListCache.banHosts) {
        ctx.banHosts = parsedListCache.banHosts;
    } else if (banStr) {
        ctx.banHosts = await cleanList(banStr);
        parsedListCache.banHosts = ctx.banHosts;
    }
    
    // [Optimization] 禁用协议缓存
    if (parsedListCache.disabledProtocols) {
        ctx.disabledProtocols = parsedListCache.disabledProtocols;
    } else {
        let disStr = disStrRaw;
        if (disStr) disStr = disStr.replace(/，/g, ',');
        const disList = await cleanList(disStr);
        ctx.disabledProtocols = disList.map(p => {
            const protocol = p.trim().toLowerCase();
            if (protocol === 'shadowsocks') return 'ss';
            return protocol;
        });
        parsedListCache.disabledProtocols = ctx.disabledProtocols;
    }

    ctx.enableXhttp = !ctx.disabledProtocols.includes('xhttp');

    if (url.searchParams.has('proxyip')) {
        const manualIP = url.searchParams.get('proxyip');
        ctx.proxyIP = manualIP;
        ctx.proxyIPList = [manualIP];
    }
    if (url.searchParams.has('socks5')) ctx.socks5 = url.searchParams.get('socks5');
    
    return ctx;
}
