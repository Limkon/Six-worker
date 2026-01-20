/**
 * 文件名: src/config.js
 * 修改内容: 
 * 1. [性能优化] 引入 configCache 全局缓存对象，极大减少 KV/Env 读取次数，消除热启动延迟。
 * 2. [代码简化] 重构 initializeContext，移除冗余的手动缓存逻辑，利用 getConfig 自动缓存。
 * 3. [保留修复] 保留 KV.get 返回 null 的判断逻辑。
 * 4. [修改] 处理 ProxyIP 逻辑，支持从 DEFAULT_PROXY_IP 加载多个硬编码 IP。
 */
import { CONSTANTS } from './constants.js';
import { cleanList, generateDynamicUUID, isStrictV4UUID } from './utils/helpers.js';

// [优化] 内存缓存对象
let configCache = {};
let remoteConfigCache = {};

// [新增] 清除全局缓存函数 (供管理面板或清理逻辑调用)
export function cleanConfigCache() {
    configCache = {};
    remoteConfigCache = {};
    // console.log('Global config cache cleaned.');
}

export async function loadRemoteConfig(env) {
    // 优先从缓存读取 URL，避免重复 KV 操作 (如果 getConfig 未被调用过)
    // 注意：这里我们直接用 KV.get 以免循环依赖，或者假设 getConfig 已处理
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
                         const [k, ...v] = line.split('=');
                         if (k && v) remoteConfigCache[k.trim()] = v.join('=').trim();
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
    
    // 2. 读取 KV
    if (env.KV) {
        const kvVal = await env.KV.get(key);
        // [修复] 只有当 KV 返回非 null 值时才赋值，避免 null 覆盖 undefined 导致后续 fallback 逻辑和默认值失效
        if (kvVal !== null) {
            val = kvVal;
        }
    }

    // 3. 读取远程配置缓存
    if (!val && remoteConfigCache && remoteConfigCache[key]) val = remoteConfigCache[key];
    
    // 4. 读取环境变量
    if (!val && env[key]) val = env[key];
    
    // 5. 兼容旧的 UUID/KEY 命名
    if (!val && key === 'UUID') val = env.UUID || env.uuid || env.PASSWORD || env.pswd || CONSTANTS.SUPER_PASSWORD;
    if (!val && key === 'KEY') val = env.KEY || env.TOKEN;
    
    const finalVal = val !== undefined ? val : defaultValue;

    // 6. [优化] 写入缓存 (Worker 实例存活期间有效)
    configCache[key] = finalVal;

    return finalVal;
}

export async function initializeContext(request, env) {
    // [可选] 启用远程配置加载。如果需要启用，取消下行注释。
    // await loadRemoteConfig(env);

    // 1. [优化] 并行读取配置 (getConfig 内部已集成缓存，热启动时瞬间返回)
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

    // 2. 构建上下文
    const ctx = {
        userID: '', 
        dynamicUUID: '', 
        userIDLow: '', 
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

    // 处理 UUID (依赖时间计算，需每次执行)
    ctx.userID = rawUUID;
    ctx.dynamicUUID = rawUUID;
    if (rawKey || (rawUUID && !isStrictV4UUID(rawUUID))) {
        const seed = rawKey || rawUUID;
        const timeDays = Number(timeDaysStr) || 99999;
        const updateHour = Number(updateHourStr) || 0;
        const userIDs = await generateDynamicUUID(seed, timeDays, updateHour);
        ctx.userID = userIDs[0]; 
        ctx.userIDLow = userIDs[1]; 
        ctx.dynamicUUID = seed;
    }

    // [修改] 处理 ProxyIP (支持硬编码默认值的多 IP 负载均衡)
    // 优先使用环境变量，如果没有则使用 CONSTANTS.DEFAULT_PROXY_IP
    const rawProxyIP = proxyIPStr || CONSTANTS.DEFAULT_PROXY_IP;
    
    if (rawProxyIP) { 
        const list = await cleanList(rawProxyIP); 
        ctx.proxyIPList = list; 
        // 随机选择一个作为主 IP
        ctx.proxyIP = list[Math.floor(Math.random() * list.length)] || ''; 
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

    // 处理 URL 参数覆盖 (最高优先级)
    const url = new URL(request.url);
    if (url.searchParams.has('proxyip')) ctx.proxyIP = url.searchParams.get('proxyip');
    if (url.searchParams.has('socks5')) ctx.socks5 = url.searchParams.get('socks5');
    
    return ctx;
}
