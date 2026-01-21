/**
 * 文件名: src/config.js
 * 修改说明:
 * 1. [新增] 在 getConfig 的 UUID 查找链中加入 env.SUPER_PASSWORD，支持直接从环境变量读取超级密码。
 * 2. [逻辑] 优化 initializeContext 中的兜底逻辑，当 UUID/KEY 缺失时，优先尝试使用 SUPER_PASSWORD 生成确定性 UUID，最后才回退到随机 UUID。
 */
import { CONSTANTS } from './constants.js';
import { cleanList, generateDynamicUUID, isStrictV4UUID } from './utils/helpers.js';

// [优化] 内存缓存对象
let configCache = {};
let remoteConfigCache = {};

// 专门用于存储远程 ProxyIP 列表的缓存
let proxyIPRemoteCache = {
    data: [],
    expires: 0
};

// [新增] 清除全局缓存函数
export function cleanConfigCache() {
    configCache = {};
    remoteConfigCache = {};
    proxyIPRemoteCache = { data: [], expires: 0 };
}

export async function loadRemoteConfig(env) {
    const remoteConfigUrl = await env.KV.get('REMOTE_CONFIG_URL');
    
    if (remoteConfigUrl) {
        try {
            const response = await fetch(remoteConfigUrl);
            if (response.ok) {
                const text = await response.text();
                try {
                    remoteConfigCache = JSON.parse(text);
                } catch (e) {
                    console.warn('Remote config is not JSON, trying line parse');
                    const lines = text.split('\n');
                    remoteConfigCache = {};
                    lines.forEach(line => {
                        const trimmedLine = line.trim();
                        // 过滤空行、以 # 或 // 开头的注释行
                        if (!trimmedLine || trimmedLine.startsWith('#') || trimmedLine.startsWith('//')) {
                            return;
                        }
                        
                        // 使用 indexOf 寻找第一个等号，支持值中包含等号的情况
                        const eqIndex = trimmedLine.indexOf('=');
                        if (eqIndex > 0) {
                            const k = trimmedLine.substring(0, eqIndex).trim();
                            const v = trimmedLine.substring(eqIndex + 1).trim();
                            if (k && v) {
                                remoteConfigCache[k] = v;
                            }
                        }
                    });
                }
            }
        } catch (e) {
            console.error('Failed to load remote config', e);
        }
    }
    return remoteConfigCache;
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
    if (!val && remoteConfigCache && remoteConfigCache[key]) val = remoteConfigCache[key];
    
    // 4. 读取环境变量
    if (!val && env[key]) val = env[key];
    
    // 5. 兼容旧的 UUID/KEY 命名
    // [修改] 增加 env.SUPER_PASSWORD 检查，确保环境变量中的 SUPER_PASSWORD 能被作为 UUID 候补读取
    if (!val && key === 'UUID') val = env.UUID || env.uuid || env.PASSWORD || env.pswd || env.SUPER_PASSWORD || CONSTANTS.SUPER_PASSWORD;
    if (!val && key === 'KEY') val = env.KEY || env.TOKEN;
    
    const finalVal = val !== undefined ? val : defaultValue;

    // 6. [优化] 写入缓存
    configCache[key] = finalVal;

    return finalVal;
}

export async function initializeContext(request, env) {
    // [新增] 远程配置开关检查
    // 默认关闭 (0)，如需开启请在环境变量中设置 REMOTE_CONFIG 为 1
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
    // 优先使用 rawUUID (如果 getConfig('UUID') 读取到了 SUPER_PASSWORD，这里 rawUUID 就是那个密码)
    if (rawUUID) {
        ctx.userID = rawUUID;
        ctx.dynamicUUID = rawUUID;
    }

    // 如果配置了 KEY，或者 UUID 不是标准 V4 格式 (例如是 SUPER_PASSWORD)，启用动态 UUID 逻辑
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

    // [关键修复] 如果此时 userID 仍为空，说明用户未配置 UUID/KEY
    if (!ctx.userID) {
        // [新增] 再次尝试直接获取 SUPER_PASSWORD，作为最后的挽救措施
        // 这一步是为了防止 getConfig('UUID') 没能正确回退到 SUPER_PASSWORD 的情况
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
            // 只有当 SUPER_PASSWORD 也没有时，才生成随机临时 UUID
            console.warn('[CONFIG] CRITICAL: No UUID/KEY/SUPER_PASSWORD configured! Generating temporary UUID. Service may be unstable.');
            const tempUUID = crypto.randomUUID();
            ctx.userID = tempUUID;
            ctx.dynamicUUID = tempUUID;
        }
    }

    // [性能优化] 预生成小写 ID 列表，供各协议模块直接使用
    ctx.expectedUserIDs = [ctx.userID, ctx.userIDLow].filter(Boolean).map(id => id.toLowerCase());

    // [核心修复] 处理 ProxyIP
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

    // 处理其他配置
    ctx.go2socks5 = go2socksStr ? await cleanList(go2socksStr) : CONSTANTS.DEFAULT_GO2SOCKS5;
    if (banStr) ctx.banHosts = await cleanList(banStr);
    
    // 处理禁用协议
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
