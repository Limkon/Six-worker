/**
 * 文件名: src/config.js
 * 修改内容: 
 * 1. [修复] getConfig 中 KV.get 返回 null 导致默认值失效的问题 (解决 "null 配置设置" 显示错误)。
 */
import { CONSTANTS } from './constants.js';
import { cleanList, generateDynamicUUID, isStrictV4UUID } from './utils/helpers.js';

let remoteConfigCache = {};
let globalConfigCache = null; // 全局内存缓存变量

// [新增] 清除全局缓存函数
export function cleanConfigCache() {
    globalConfigCache = null;
    // console.log('Global config cache cleaned.');
}

export async function loadRemoteConfig(env) {
    const remoteConfigUrl = await env.KV.get('REMOTE_CONFIG_URL');
    if (remoteConfigUrl) {
        try {
            const response = await fetch(remoteConfigUrl);
            if (response.ok) {
                const text = await response.text();
                // 尝试解析 JSON，失败则解析 KEY=VALUE
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
    let val = undefined;
    // 优先读取 KV
    if (env.KV) {
        const kvVal = await env.KV.get(key);
        // [修复] 只有当 KV 返回非 null 值时才赋值，避免 null 覆盖 undefined 导致后续 fallback 逻辑和默认值失效
        if (kvVal !== null) {
            val = kvVal;
        }
    }

    // 其次读取远程配置缓存
    if (!val && remoteConfigCache && remoteConfigCache[key]) val = remoteConfigCache[key];
    // 最后读取环境变量
    if (!val && env[key]) val = env[key];
    
    // 兼容旧的 UUID/KEY 命名
    if (!val && key === 'UUID') val = env.UUID || env.uuid || env.PASSWORD || env.pswd || CONSTANTS.SUPER_PASSWORD;
    if (!val && key === 'KEY') val = env.KEY || env.TOKEN;
    return val !== undefined ? val : defaultValue;
}

export async function initializeContext(request, env) {
    // [可选] 启用远程配置加载。如果需要启用，取消下行注释。
    // await loadRemoteConfig(env);

    // 1. [优化] 优先检查全局内存缓存
    let configData = globalConfigCache;

    // 如果没有缓存 (冷启动或被清除)，则执行并行读取
    if (!configData) {
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

        // 将读取结果存入对象
        configData = {
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
        };

        // 写入全局缓存 (Worker 实例存活期间有效)
        globalConfigCache = configData;
    }

    // 2. 从缓存数据中解构配置
    const {
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
    } = configData;

    // 3. 构建上下文
    const ctx = {
        userID: '', 
        dynamicUUID: '', 
        userIDLow: '', 
        proxyIP: '', 
        proxyIPList: [], // [保留] 存储完整列表
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

    // 处理 ProxyIP (保留列表逻辑)
    if (proxyIPStr) { 
        const list = await cleanList(proxyIPStr); 
        ctx.proxyIPList = list; // [保留]
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
