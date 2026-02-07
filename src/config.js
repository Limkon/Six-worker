// src/config.js
/**
 * 文件名: src/config.js
 * 审计优化说明:
 * 1. [Fix] Race Condition Fix: 引入 configGeneration 版本号控制，解决并发写入时的竞争冒险问题。
 * 防止 cleanConfigCache 清理后，旧的 getConfig 请求返回并覆盖写入陈旧数据。
 * 2. [Optimization] ProxyIP 防惊群: 引入 proxyIPFetchingPromise，防止缓存过期瞬间爆发大量重复 fetch 请求。
 * 3. [Feature] Remote Config TTL: 增加远程配置 6 小时自动过期机制。
 * 4. [Optimization] UUID 计算缓存: 增加 uuidCache，避免每次请求都重复进行 SHA-256 计算。
 */
import { CONSTANTS } from './constants.js';
import { cleanList, generateDynamicUUID, isStrictV4UUID, getKV, clearKVCache } from './utils/helpers.js';

// 内存缓存对象 (处理后的配置)
let configCache = {};
// [Fix] 配置版本号 (用于并发控制)
let configGeneration = 0;

// 远程配置缓存
const REMOTE_CONFIG_TTL = 360 * 60 * 1000; // 360分钟自动过期
let remoteConfigCache = {
    data: {},
    lastFetch: 0
};

// 远程 ProxyIP 缓存及并发锁
let proxyIPRemoteCache = {
    data: [],
    expires: 0,
    fetchingPromise: null // [Optimization] 防止惊群效应的 Promise 锁
};

// [Optimization] UUID 计算缓存 (避免每次请求重复计算 SHA-256)
let uuidCache = {
    key: null,      // 缓存键: seed|timeDays|updateHour
    data: null,     // [userID, userIDLow]
    lastUpdate: 0   // 上次更新时间戳
};
const UUID_CACHE_TTL = 10 * 60 * 1000; // 10分钟缓存

/**
 * 清理配置缓存
 */
export async function cleanConfigCache(updatedKeys) {
    // [Fix] 标记当前缓存失效 (递增版本号)
    configGeneration++;

    if (!updatedKeys || !Array.isArray(updatedKeys) || updatedKeys.includes('REMOTE_CONFIG_URL')) {
        configCache = {};
        remoteConfigCache = { data: {}, lastFetch: 0 };
        // 清理 ProxyIP 缓存时，也要重置 fetchingPromise
        proxyIPRemoteCache = { data: [], expires: 0, fetchingPromise: null };
        // [Optimization] 重置 UUID 缓存
        uuidCache = { key: null, data: null, lastUpdate: 0 };
        await clearKVCache();
        return;
    }
    for (const key of updatedKeys) {
        delete configCache[key];
    }
    await clearKVCache(updatedKeys);
    if (updatedKeys.includes('PROXYIP')) {
        proxyIPRemoteCache = { data: [], expires: 0, fetchingPromise: null };
    }
    // 如果更新了 UUID/KEY/TIME/UPTIME，需要清理 UUID 缓存
    if (updatedKeys.some(k => ['UUID', 'KEY', 'TIME', 'UPTIME', 'SUPER_PASSWORD'].includes(k))) {
        uuidCache = { key: null, data: null, lastUpdate: 0 };
    }
}

export async function loadRemoteConfig(env, forceReload = false) {
    const remoteConfigUrl = await getKV(env, 'REMOTE_CONFIG_URL');
    
    // [Feature] 增加 TTL 检查
    const now = Date.now();
    const isExpired = (now - remoteConfigCache.lastFetch) > REMOTE_CONFIG_TTL;

    if (!forceReload && !isExpired && remoteConfigCache.data && Object.keys(remoteConfigCache.data).length > 0) {
        return remoteConfigCache.data;
    }
    
    if (remoteConfigUrl) {
        try {
            // 简单的 fetch 逻辑
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
                
                // 辅助解析函数
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
                
                // [Fix] 更新缓存时清理旧缓存并递增版本号
                configCache = {}; 
                configGeneration++;
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

    // [Fix] 捕获当前操作开始时的配置版本
    const currentGen = configGeneration;

    let val = undefined;
    
    if (env.KV) {
        val = await getKV(env, key);
    }

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
    
    // [Fix] 仅当版本号未发生变化时才写入缓存
    // 这避免了: 请求A开始 -> 请求B清理缓存(Bump Gen) -> 请求A结束并写入陈旧数据
    if (currentGen === configGeneration) {
        configCache[key] = finalVal;
    }
    
    return finalVal;
}

// [Optimization] 封装带缓存的 UUID 生成逻辑
async function getCachedUUID(seed, timeDays, updateHour) {
    const cacheKey = `${seed}|${timeDays}|${updateHour}`;
    const now = Date.now();

    // 检查缓存命中且未过期
    if (uuidCache.key === cacheKey && uuidCache.data && (now - uuidCache.lastUpdate < UUID_CACHE_TTL)) {
        return uuidCache.data;
    }

    // 缓存未命中或过期，执行计算
    const userIDs = await generateDynamicUUID(seed, timeDays, updateHour);
    
    // 更新缓存
    uuidCache = {
        key: cacheKey,
        data: userIDs,
        lastUpdate: now
    };
    return userIDs;
}

export async function initializeContext(request, env) {
    const url = new URL(request ? request.url : 'http://localhost');
    const forceReload = url.searchParams.get('flush') === '1'; 

    if (forceReload) {
        console.log('[Config] Flush requested via URL parameter. Purging caches...');
        // [Fix] 递增版本号
        configCache = {};
        configGeneration++;
        
        // 强制重置 ProxyIP 缓存和锁
        proxyIPRemoteCache = { data: [], expires: 0, fetchingPromise: null };
        // [Optimization] 重置 UUID 缓存
        uuidCache = { key: null, data: null, lastUpdate: 0 };
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
            configGeneration++; // [Fix] Invalidate
        }
    }

    // Batch 1
    const [adminPass, rawUUID, rawKey, timeDaysStr, updateHourStr] = await Promise.all([
        getConfig(env, 'ADMIN_PASS'),
        getConfig(env, 'UUID'),
        getConfig(env, 'KEY'),
        getConfig(env, 'TIME'),
        getConfig(env, 'UPTIME')
    ]);

    // Batch 2
    const [proxyIPStr, dns64, socks5Addr, go2socksStr, banStr] = await Promise.all([
        getConfig(env, 'PROXYIP'),
        getConfig(env, 'DNS64'),
        getConfig(env, 'SOCKS5'),
        getConfig(env, 'GO2SOCKS5'),
        getConfig(env, 'BAN')
    ]);

    // Batch 3
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
            // [Optimization] 使用带缓存的 UUID 生成器
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
             // [Optimization] 使用带缓存的 UUID 生成器
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
                 // [Optimization] 防止惊群效应 (Thundering Herd)
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
                                 proxyIPRemoteCache.expires = Date.now() + 600000; // 10分钟缓存
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
                 
                 // 等待 fetch 结果
                 rawList = await proxyIPRemoteCache.fetchingPromise;
             }
        } else {
             rawList = rawProxyIP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
        }
    }

    if (rawList && rawList.length > 0) {
        const selectedIP = rawList[Math.floor(Math.random() * rawList.length)];
        ctx.proxyIP = selectedIP;
        ctx.proxyIPList = [selectedIP]; // 保持单一 IP 策略
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
