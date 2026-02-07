// src/config.js
/**
 * 文件名: src/config.js
 * 修复版:
 * 1. [Fix] 修复 "Worker code hung" 错误: 
 * - 限制远程配置/ProxyIP 的读取大小 (Max 100KB)，防止解析巨型响应导致 CPU 挂起。
 * - 限制 timeDays 最大值，防止 UUID 生成死循环。
 * 2. [Robust] 增强 ProxyIP 获取的超时控制和错误处理。
 */
import { CONSTANTS } from './constants.js';
import { cleanList, generateDynamicUUID, isStrictV4UUID, getKV, clearKVCache } from './utils/helpers.js';

// 内存缓存对象
let configCache = {};
let configGeneration = 0;

// [Optimization] 解析后的列表缓存
let parsedListCache = {
    proxyIP: null,     
    banHosts: null,    
    disabledProtocols: null, 
    go2socks5: null    
};

// 远程配置缓存
const REMOTE_CONFIG_TTL = 360 * 60 * 1000; 
let remoteConfigCache = {
    data: {},
    lastFetch: 0
};

// 远程 ProxyIP 缓存
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
 * 辅助：安全读取文本，限制长度，防止处理过大数据导致死循环
 */
async function safeReadText(response, maxLength = 1024 * 50) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let result = '';
    let bytesRead = 0;

    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value) {
                result += decoder.decode(value, { stream: true });
                bytesRead += value.byteLength;
                if (bytesRead > maxLength) {
                    console.warn(`[Config] Remote content exceeded ${maxLength} bytes, truncated.`);
                    break; // 超过限制直接截断
                }
            }
        }
        result += decoder.decode(); // flush
    } catch (e) {
        console.error('[Config] Error reading text:', e);
    } finally {
        try { reader.cancel(); } catch (_) {}
    }
    return result;
}

export async function cleanConfigCache(updatedKeys) {
    configGeneration++;

    if (!updatedKeys || !Array.isArray(updatedKeys) || updatedKeys.includes('REMOTE_CONFIG_URL')) {
        configCache = {};
        remoteConfigCache = { data: {}, lastFetch: 0 };
        proxyIPRemoteCache = { data: [], expires: 0, fetchingPromise: null };
        uuidCache = { key: null, data: null, lastUpdate: 0 };
        parsedListCache = { proxyIP: null, banHosts: null, disabledProtocols: null, go2socks5: null };
        await clearKVCache();
        return;
    }
    for (const key of updatedKeys) {
        delete configCache[key];
    }
    await clearKVCache(updatedKeys);
    
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
            const timeoutId = setTimeout(() => controller.abort(), 5000); // 5秒硬超时
            
            const response = await fetch(remoteConfigUrl, {
                signal: controller.signal,
                headers: { 'User-Agent': 'Six-Worker-Config-Fetcher' }
            }).finally(() => clearTimeout(timeoutId));

            if (response.ok) {
                // [Fix] 限制配置大小为 50KB，防止解析超大文件导致 Hang
                const text = await safeReadText(response, 50 * 1024);
                const updateTime = Date.now();
                
                const parseConfig = (txt) => {
                    // 尝试 JSON
                    try {
                        const json = JSON.parse(txt);
                        if (json && typeof json === 'object') return json;
                    } catch (e) {}

                    // 回退到行解析 (防御性编程)
                    // 使用正则匹配每一行，避免 split 大字符串
                    const newData = {};
                    const regex = /^\s*([^#=\s]+)\s*=\s*(.+?)\s*$/gm;
                    let match;
                    // 设置一个最大迭代次数防止 ReDoS
                    let loopCount = 0;
                    while ((match = regex.exec(txt)) !== null && loopCount++ < 1000) {
                        newData[match[1]] = match[2];
                    }
                    return newData;
                };

                const newData = parseConfig(text);
                remoteConfigCache.data = newData;
                remoteConfigCache.lastFetch = updateTime;
                
                configCache = {}; 
                configGeneration++;
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
        await cleanConfigCache(); // 使用无参调用清理所有
    }

    // 处理远程配置
    const enableRemote = await getConfig(env, 'REMOTE_CONFIG', '0');
    if (enableRemote === '1') {
        await loadRemoteConfig(env, forceReload);
    } else if (remoteConfigCache.lastFetch > 0) {
        // 如果远程配置被禁用但缓存还在，清理它
        remoteConfigCache = { data: {}, lastFetch: 0 };
        configCache = {}; 
        configGeneration++; 
        parsedListCache = { proxyIP: null, banHosts: null, disabledProtocols: null, go2socks5: null };
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
            // [Fix] 限制 timeDays 防止死循环
            let timeDays = Number(timeDaysStr) || 0;
            if (timeDays > 36500) timeDays = 36500; // 最大 100 年
            
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
             let timeDays = Number(timeDaysStr) || 0;
             if (timeDays > 36500) timeDays = 36500;

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

    // -------------------------------------------------------------------------
    // ProxyIP Fetch Logic (Optimized & Safer)
    // -------------------------------------------------------------------------
    const rawProxyIP = proxyIPStr || CONSTANTS.DEFAULT_PROXY_IP;
    let rawList = [];

    if (rawProxyIP) { 
        if (rawProxyIP.startsWith('http')) {
             if (Date.now() < proxyIPRemoteCache.expires && proxyIPRemoteCache.data.length > 0) {
                 rawList = proxyIPRemoteCache.data;
             } else {
                 // 使用 Promise 处理并发，防止重复请求
                 if (!proxyIPRemoteCache.fetchingPromise) {
                     proxyIPRemoteCache.fetchingPromise = (async () => {
                         try {
                             const controller = new AbortController();
                             // [Fix] 缩短超时到 3s，防止阻塞过久
                             const timeoutId = setTimeout(() => controller.abort(), 3000);
                             
                             const response = await fetch(rawProxyIP, { 
                                 signal: controller.signal,
                                 headers: { 'User-Agent': 'Six-Worker-ProxyIP-Fetcher' }
                             }).finally(() => clearTimeout(timeoutId));
                             
                             if (response.ok) {
                                 // [Fix] 限制文本大小，防止处理过大数据挂起
                                 const text = await safeReadText(response, 50 * 1024);
                                 const list = await cleanList(text);
                                 proxyIPRemoteCache.data = list;
                                 proxyIPRemoteCache.expires = Date.now() + 600000; 
                                 return list;
                             } else {
                                 throw new Error(`ProxyIP fetch failed: ${response.status}`);
                             }
                         } catch (e) {
                             console.error('Failed to fetch remote ProxyIP:', e.message);
                             const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
                             proxyIPRemoteCache.data = defParams;
                             proxyIPRemoteCache.expires = Date.now() + 60000; // 失败后 1 分钟再试
                             return defParams;
                         } finally {
                             proxyIPRemoteCache.fetchingPromise = null;
                         }
                     })();
                 }
                 // [Fix] 这里的 await 是安全的，即使 Promise 已经 settle
                 rawList = await proxyIPRemoteCache.fetchingPromise;
             }
        } else {
            // 静态列表解析
            if (parsedListCache.proxyIP) {
                rawList = parsedListCache.proxyIP;
            } else {
                // [Fix] 限制长度防止恶意输入导致的 split 性能问题
                const safeStr = rawProxyIP.length > 10000 ? rawProxyIP.substring(0, 10000) : rawProxyIP;
                rawList = safeStr.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
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

    // -------------------------------------------------------------------------

    if (parsedListCache.go2socks5) {
        ctx.go2socks5 = parsedListCache.go2socks5;
    } else {
        // [Fix] 同样限制 go2socks 输入长度
        const safeGoStr = go2socksStr && go2socksStr.length > 5000 ? go2socksStr.substring(0, 5000) : go2socksStr;
        ctx.go2socks5 = safeGoStr ? await cleanList(safeGoStr) : CONSTANTS.DEFAULT_GO2SOCKS5;
        parsedListCache.go2socks5 = ctx.go2socks5;
    }

    if (parsedListCache.banHosts) {
        ctx.banHosts = parsedListCache.banHosts;
    } else if (banStr) {
        const safeBanStr = banStr.length > 10000 ? banStr.substring(0, 10000) : banStr;
        ctx.banHosts = await cleanList(safeBanStr);
        parsedListCache.banHosts = ctx.banHosts;
    }
    
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
