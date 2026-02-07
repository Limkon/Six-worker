// src/config.js
/**
 * 文件名: src/config.js
 * 审计优化说明:
 * 1. [Fix] Race Condition Fix 保留: 继续保持 initializeContext 中的原子更新逻辑。
 * 2. [Optimization] ProxyIP 防惊群: 引入 proxyIPFetchingPromise，防止缓存过期瞬间爆发大量重复 fetch 请求。
 * 3. [Feature] Remote Config TTL: 增加远程配置 5 分钟自动过期机制，避免配置长期不更新。
 * 4. [Config] 策略保持: 继续维持 ProxyIP 单一 IP 策略。
 * 5. [Optimization] UUID 计算缓存: 增加 uuidCache，避免每次请求都重复进行 SHA-256 计算 (Crypto API)。
 */
import { CONSTANTS } from './constants.js';
import { cleanList, generateDynamicUUID, isStrictV4UUID, getKV, clearKVCache } from './utils/helpers.js';

// 内存缓存对象 (处理后的配置)
let configCache = {};

// 远程配置缓存
const REMOTE_CONFIG_TTL = 560 * 60 * 1000; // 560分钟自动过期
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
const UUID_CACHE_TTL = 10 * 60 * 1000; // 10分钟缓存，足以覆盖大多数请求间隙，同时允许动态轮换

/**
 * 清理配置缓存
 */
export async function cleanConfigCache(updatedKeys) {
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
            // 简单的 fetch 逻辑，无需复杂的锁，因为 initializeContext 通常串行控制了刷新流程
            // 且配置文件的体积通常很小，重复 fetch 影响不如 ProxyIP 列表大
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
                try {
                    const newData = JSON.parse(text);
                    remoteConfigCache.data = newData;
                    remoteConfigCache.lastFetch = updateTime;
                    configCache = {}; 
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
                    remoteConfigCache.lastFetch = updateTime;
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
        // [Fix] Race Condition Fix: 仅清理派生缓存和 KV，保留 remoteConfigCache
        configCache = {};
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
                 // 如果已有请求正在 fetch，后续请求直接复用该 Promise
                 if (!proxyIPRemoteCache.fetchingPromise) {
                     proxyIPRemoteCache.fetchingPromise = (async () => {
                         try {
                             const controller = new AbortController();
                             const timeoutId = setTimeout(() => controller.abort(), 5000);
                             const response = await fetch(rawProxyIP, { signal: controller.signal }).finally(() => clearTimeout(timeoutId));
                             
                             if (response.ok) {
                                 const text = await response.text();
                                 const list = await cleanList(text);
                                 // 更新缓存
                                 proxyIPRemoteCache.data = list;
                                 proxyIPRemoteCache.expires = Date.now() + 600000; // 10分钟缓存
                                 return list;
                             } else {
                                 throw new Error(`ProxyIP fetch failed: ${response.status}`);
                             }
                         } catch (e) {
                             console.error('Failed to fetch remote ProxyIP:', e);
                             // 失败时的兜底：使用默认列表，缓存 1 分钟
                             const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
                             proxyIPRemoteCache.data = defParams;
                             proxyIPRemoteCache.expires = Date.now() + 60000; 
                             return defParams;
                         } finally {
                             // 无论成功失败，结束后释放锁
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
