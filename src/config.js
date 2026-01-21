/**
 * 文件名: src/config.js
 * 修改说明:
 * 1. [性能/逻辑优化] loadRemoteConfig 增加时间戳缓存 (TTL 60秒)，防止频繁请求。
 * 2. [逻辑优化] 当远程配置更新时，清空 configCache 以确保新配置生效。
 */
import { CONSTANTS } from './constants.js';
import { cleanList, generateDynamicUUID, isStrictV4UUID } from './utils/helpers.js';

// [优化] 内存缓存对象
let configCache = {};

// [修改] 远程配置缓存，包含数据和上次获取时间
let remoteConfigCache = {
    data: {},
    lastFetch: 0
};

// 专门用于存储远程 ProxyIP 列表的缓存
let proxyIPRemoteCache = {
    data: [],
    expires: 0
};

// [新增] 清除全局缓存函数
export function cleanConfigCache() {
    configCache = {};
    remoteConfigCache = { data: {}, lastFetch: 0 };
    proxyIPRemoteCache = { data: [], expires: 0 };
}

export async function loadRemoteConfig(env) {
    const remoteConfigUrl = await env.KV.get('REMOTE_CONFIG_URL');
    const now = Date.now();
    const CACHE_TTL = 60000; // 60秒缓存

    // [新增] 检查 TTL，避免频繁请求
    if (remoteConfigUrl && now - remoteConfigCache.lastFetch < CACHE_TTL) {
        return remoteConfigCache.data;
    }
    
    if (remoteConfigUrl) {
        try {
            const response = await fetch(remoteConfigUrl);
            if (response.ok) {
                const text = await response.text();
                try {
                    const newData = JSON.parse(text);
                    remoteConfigCache.data = newData;
                    remoteConfigCache.lastFetch = now;
                    
                    // [关键] 远程配置更新后，清空本地 configCache，防止旧值覆盖新值
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
                    configCache = {}; // 清空缓存
                }
            }
        } catch (e) {
            console.error('Failed to load remote config', e);
        }
    }
    return remoteConfigCache.data;
}

export async function getConfig(env, key, defaultValue = undefined) {
    // 1. [优化] 优先检查内存缓存
    if (configCache[key] !== undefined) {
        return configCache[key];
    }

    let val = undefined;
    
    // 2. 读取 KV (优先级：KV > 环境变量，允许动态覆盖)
    if (env.KV) {
        const kvVal = await env.KV.get(key);
        if (kvVal !== null) {
            val = kvVal;
        }
    }

    // 3. 读取远程配置缓存
    // [修改] 访问 remoteConfigCache.data
    if (!val && remoteConfigCache.data && remoteConfigCache.data[key]) {
        val = remoteConfigCache.data[key];
    }
    
    // 4. 读取环境变量
    if (!val && env[key]) val = env[key];
    
    // 5. 兼容旧的 UUID/KEY 命名
    if (!val && key === 'UUID') val = env.UUID || env.uuid || env.PASSWORD || env.pswd || env.SUPER_PASSWORD || CONSTANTS.SUPER_PASSWORD;
    if (!val && key === 'KEY') val = env.KEY || env.TOKEN;
    
    const finalVal = val !== undefined ? val : defaultValue;

    // 6. [优化] 写入缓存
    configCache[key] = finalVal;

    return finalVal;
}

export async function initializeContext(request, env) {
    // [新增] 远程配置开关检查
    const enableRemote = await getConfig(env, 'REMOTE_CONFIG', '0');
    if (enableRemote === '1') {
        await loadRemoteConfig(env);
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

    // 处理 UUID
    if (rawUUID) {
        ctx.userID = rawUUID;
        ctx.dynamicUUID = rawUUID;
    }

    if (rawKey || (rawUUID && !isStrictV4UUID(rawUUID))) {
        const seed = rawKey || rawUUID;
        
        if (seed) {
            const timeDays = Number(timeDaysStr) || 99999;
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
             const timeDays = Number(timeDaysStr) || 99999;
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
    
    if (rawProxyIP) { 
        if (rawProxyIP.startsWith('http')) {
             if (Date.now() < proxyIPRemoteCache.expires) {
                 ctx.proxyIPList = proxyIPRemoteCache.data;
             } else {
                 try {
                     const response = await fetch(rawProxyIP);
                     if (response.ok) {
                         const text = await response.text();
                         const list = await cleanList(text); 
                         ctx.proxyIPList = list;
                         proxyIPRemoteCache.data = list;
                         proxyIPRemoteCache.expires = Date.now() + 600000;
                     }
                 } catch (e) {
                     console.error('Failed to fetch remote ProxyIP:', e);
                     const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
                     ctx.proxyIPList = defParams;
                 }
             }
        } else {
             ctx.proxyIPList = rawProxyIP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
        }
        ctx.proxyIP = ctx.proxyIPList[Math.floor(Math.random() * ctx.proxyIPList.length)] || ''; 
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

    const url = new URL(request ? request.url : 'http://localhost');
    if (url.searchParams.has('proxyip')) ctx.proxyIP = url.searchParams.get('proxyip');
    if (url.searchParams.has('socks5')) ctx.socks5 = url.searchParams.get('socks5');
    
    return ctx;
}
