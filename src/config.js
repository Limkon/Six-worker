// src/config.js
/**
 * 文件名: src/config.js
 * 状态: [修复 Worker Hung 问题]
 * 1. [Fix] initializeContext 和 loadRemoteConfig 增加 signal 参数，支持外部取消。
 * 2. [Stability] 解决 execWithRetry 重试时旧任务不释放导致的资源累积。
 * 3. [Ctx] 保持 ctx 参数传递，确保 Cache API 写入可靠。
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

// [Fix] 增加 signal 参数，支持中止
export async function loadRemoteConfig(env, forceReload = false, signal = null) {
    const remoteConfigUrl = await getKV(env, 'REMOTE_CONFIG_URL');
    const now = Date.now();
    const isExpired = (now - remoteConfigCache.lastFetch) > REMOTE_CONFIG_TTL;

    if (!forceReload && !isExpired && remoteConfigCache.data && Object.keys(remoteConfigCache.data).length > 0) {
        return remoteConfigCache.data;
    }
    
    if (remoteConfigUrl) {
        try {
            const controller = new AbortController();
            
            // [Fix] 信号合并：如果外部传入了 signal 且触发了 abort，这里也应该 abort
            if (signal) {
                signal.addEventListener('abort', () => controller.abort());
                if (signal.aborted) controller.abort();
            }

            const timeoutId = setTimeout(() => controller.abort(), 5000); // 5秒硬超时
            
            const response = await fetch(remoteConfigUrl, {
                signal: controller.signal,
                headers: { 'User-Agent': 'Six-Worker-Config-Fetcher' }
            }).finally(() => clearTimeout(timeoutId));

            if (response.ok) {
                const text = await safeReadText(response, 50 * 1024);
                const updateTime = Date.now();
                
                const parseConfig = (txt) => {
                    try {
                        const json = JSON.parse(txt);
                        if (json && typeof json === 'object') return json;
                    } catch (e) {}

                    const newData = {};
                    const regex = /^\s*([^#=\s]+)\s*=\s*(.+?)\s*$/gm;
                    let match;
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
            // 如果是中止错误，不做处理
            if (e.name !== 'AbortError') {
                console.error('Failed to load remote config', e);
            }
        }
    }
    return remoteConfigCache.data;
}

// [Critical Fix] 支持传递 ctx，并智能处理参数
export async function getConfig(env, key, arg3 = undefined, arg4 = null) {
    // 参数归一化: getConfig(env, key, defaultValue, ctx) 或 getConfig(env, key, ctx)
    let defaultValue = undefined;
    let ctx = null;

    if (arg3 && typeof arg3.waitUntil === 'function') {
        // 第三个参数是 ctx
        ctx = arg3;
        defaultValue = undefined;
    } else {
        // 常规调用
        defaultValue = arg3;
        ctx = arg4;
    }

    if (configCache[key] !== undefined) {
        return configCache[key];
    }
    const currentGen = configGeneration;
    let val = undefined;
    
    // [Fix] 传递 ctx 给 getKV
    if (env.KV) val = await getKV(env, key, ctx);

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

// [Critical Fix] initializeContext 接收 signal 参数，防止死任务累积
export async function initializeContext(request, env, ctx = null, signal = null) {
    const url = new URL(request ? request.url : 'http://localhost');
    const forceReload = url.searchParams.get('flush') === '1'; 

    // 如果信号已中止，提前退出
    if (signal && signal.aborted) throw new Error('Init Aborted');

    if (forceReload) {
        console.log('[Config] Flush requested via URL parameter. Purging caches...');
        await cleanConfigCache(); 
    }

    // 处理远程配置
    // [Fix] 传递 ctx 和 signal
    const enableRemote = await getConfig(env, 'REMOTE_CONFIG', '0', ctx);
    if (enableRemote === '1') {
        await loadRemoteConfig(env, forceReload, signal);
    } else if (remoteConfigCache.lastFetch > 0) {
        remoteConfigCache = { data: {}, lastFetch: 0 };
        configCache = {}; 
        configGeneration++; 
        parsedListCache = { proxyIP: null, banHosts: null, disabledProtocols: null, go2socks5: null };
    }

    if (signal && signal.aborted) throw new Error('Init Aborted');

    // [Fix] 传递 ctx 到 getConfig
    const [adminPass, rawUUID, rawKey, timeDaysStr, updateHourStr] = await Promise.all([
        getConfig(env, 'ADMIN_PASS', undefined, ctx),
        getConfig(env, 'UUID', undefined, ctx),
        getConfig(env, 'KEY', undefined, ctx),
        getConfig(env, 'TIME', undefined, ctx),
        getConfig(env, 'UPTIME', undefined, ctx)
    ]);

    const [proxyIPStr, dns64, socks5Addr, go2socksStr, banStr] = await Promise.all([
        getConfig(env, 'PROXYIP', undefined, ctx),
        getConfig(env, 'DNS64', undefined, ctx),
        getConfig(env, 'SOCKS5', undefined, ctx),
        getConfig(env, 'GO2SOCKS5', undefined, ctx),
        getConfig(env, 'BAN', undefined, ctx)
    ]);

    const disStrRaw = await getConfig(env, 'DIS', '', ctx);

    const context = {
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
        context.userID = rawUUID;
        context.dynamicUUID = rawUUID;
    }

    if (rawKey || (rawUUID && !isStrictV4UUID(rawUUID))) {
        const seed = rawKey || rawUUID;
        if (seed) {
            let timeDays = Number(timeDaysStr) || 0;
            if (timeDays > 36500) timeDays = 36500; 
            
            const updateHour = Number(updateHourStr) || 0;
            
            const userIDs = await getCachedUUID(seed, timeDays, updateHour);
            context.userID = userIDs[0]; 
            context.userIDLow = userIDs[1]; 
            context.dynamicUUID = seed;
        }
    }

    if (!context.userID) {
        const superPass = await getConfig(env, 'SUPER_PASSWORD', undefined, ctx) || CONSTANTS.SUPER_PASSWORD;
        if (superPass) {
             let timeDays = Number(timeDaysStr) || 0;
             if (timeDays > 36500) timeDays = 36500;

             const updateHour = Number(updateHourStr) || 0;
             const userIDs = await getCachedUUID(superPass, timeDays, updateHour);
             context.userID = userIDs[0]; 
             context.userIDLow = userIDs[1]; 
             context.dynamicUUID = superPass;
             console.log('[CONFIG] Missing UUID/KEY, generated UUID using SUPER_PASSWORD.');
        } else {
            console.warn('[CONFIG] CRITICAL: No UUID/KEY/SUPER_PASSWORD configured!');
            const tempUUID = crypto.randomUUID();
            context.userID = tempUUID;
            context.dynamicUUID = tempUUID;
        }
    }

    context.expectedUserIDs = [context.userID, context.userIDLow].filter(Boolean).map(id => id.toLowerCase());

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
                 if (!proxyIPRemoteCache.fetchingPromise) {
                     proxyIPRemoteCache.fetchingPromise = (async () => {
                         try {
                             const controller = new AbortController();
                             const timeoutId = setTimeout(() => controller.abort(), 3000); // 3s Timeout
                             
                             const response = await fetch(rawProxyIP, { 
                                 signal: controller.signal,
                                 headers: { 'User-Agent': 'Six-Worker-ProxyIP-Fetcher' }
                             }).finally(() => clearTimeout(timeoutId));
                             
                             if (response.ok) {
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
                             proxyIPRemoteCache.expires = Date.now() + 60000; 
                             return defParams;
                         } finally {
                             proxyIPRemoteCache.fetchingPromise = null;
                         }
                     })();
                 }
                 // 安全等待结果
                 // [Fix] 尊重外部 signal，防止挂起
                 if (signal) {
                     // 如果外部超时，这里 race 会由外部 timeoutPromise 触发 throw，但为了保险我们手动检查
                     if (signal.aborted) throw new Error('Init Aborted (ProxyIP)');
                 }
                 rawList = await proxyIPRemoteCache.fetchingPromise;
             }
        } else {
            if (parsedListCache.proxyIP) {
                rawList = parsedListCache.proxyIP;
            } else {
                const safeStr = rawProxyIP.length > 10000 ? rawProxyIP.substring(0, 10000) : rawProxyIP;
                rawList = safeStr.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
                parsedListCache.proxyIP = rawList;
            }
        }
    }

    if (rawList && rawList.length > 0) {
        const selectedIP = rawList[Math.floor(Math.random() * rawList.length)];
        context.proxyIP = selectedIP;
        context.proxyIPList = [selectedIP]; 
    } else {
        context.proxyIP = '';
        context.proxyIPList = [];
    }

    // -------------------------------------------------------------------------

    if (parsedListCache.go2socks5) {
        context.go2socks5 = parsedListCache.go2socks5;
    } else {
        const safeGoStr = go2socksStr && go2socksStr.length > 5000 ? go2socksStr.substring(0, 5000) : go2socksStr;
        context.go2socks5 = safeGoStr ? await cleanList(safeGoStr) : CONSTANTS.DEFAULT_GO2SOCKS5;
        parsedListCache.go2socks5 = context.go2socks5;
    }

    if (parsedListCache.banHosts) {
        context.banHosts = parsedListCache.banHosts;
    } else if (banStr) {
        const safeBanStr = banStr.length > 10000 ? banStr.substring(0, 10000) : banStr;
        context.banHosts = await cleanList(safeBanStr);
        parsedListCache.banHosts = context.banHosts;
    }
    
    if (parsedListCache.disabledProtocols) {
        context.disabledProtocols = parsedListCache.disabledProtocols;
    } else {
        let disStr = disStrRaw;
        if (disStr) disStr = disStr.replace(/，/g, ',');
        const disList = await cleanList(disStr);
        context.disabledProtocols = disList.map(p => {
            const protocol = p.trim().toLowerCase();
            if (protocol === 'shadowsocks') return 'ss';
            return protocol;
        });
        parsedListCache.disabledProtocols = context.disabledProtocols;
    }

    context.enableXhttp = !context.disabledProtocols.includes('xhttp');

    if (url.searchParams.has('proxyip')) {
        const manualIP = url.searchParams.get('proxyip');
        context.proxyIP = manualIP;
        context.proxyIPList = [manualIP];
    }
    if (url.searchParams.has('socks5')) context.socks5 = url.searchParams.get('socks5');
    
    return context;
}
