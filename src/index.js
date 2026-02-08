// src/index.js
/**
 * 文件名: src/index.js
 * 架构重构:
 * 1. [Security] 实施 "路由严格分发策略"。
 * 2. [Fix] 针对 Hash 路由 (GET) 增加空路径拦截，彻底阻断 XHTTP 探测流量进入订阅逻辑。
 * 3. [Stability] 保持 Watchdog 机制保护全局上下文加载。
 * 4. [Fix] 修复 Watchdog Promise 泄露: 使用 AbortController 确保超时能中止异步任务。
 * 5. [Optimization] 利用 Cache API 持久化 "域名推送状态"，解决 Worker 实例重启导致 KV 重复读取的问题。
 */
import { initializeContext, getConfig, cleanConfigCache } from './config.js';
import { handleWebSocketRequest } from './handlers/websocket.js';
import { handleXhttpClient } from './handlers/xhttp.js';
import { handleEditConfig, handleBestIP } from './pages/admin.js';
import { handleSubscription } from './pages/sub.js';
import { executeWebDavPush } from './handlers/webdav.js';
import { generateHomePage } from './pages/home.js';
import { sha1 } from './utils/helpers.js';
import { CONSTANTS } from './constants.js';
import { getPasswordSetupHtml, getLoginHtml } from './templates/auth.js';

// --- 全局状态 (L1 内存缓存) ---
// 仅作为最快速的短路检查，不作为持久化依据
let lastSavedDomain = ''; 

// --- 缓存工具 (L2 Cache API) ---
// 使用 Cache API 跨实例记录 "该域名近期已推送过"，减少 KV 读写
async function hasDomainBeenPushedRecently(hostName) {
    if (!hostName) return false;
    // 1. L1 Memory Check (Fastest)
    if (hostName === lastSavedDomain) return true;

    // 2. L2 Cache API Check (Persistent across isolates)
    const cache = caches.default;
    const cacheKey = `http://six-worker.local/domain_pushed/${encodeURIComponent(hostName)}`;
    try {
        const res = await cache.match(cacheKey);
        if (res) {
            // 如果缓存命中，同步回 L1
            lastSavedDomain = hostName;
            return true;
        }
    } catch (e) {
        console.warn('[Cache] Check failed:', e);
    }
    return false;
}

async function markDomainAsPushed(hostName, ctx) {
    if (!hostName) return;
    // Update L1
    lastSavedDomain = hostName;
    
    // Update L2 (Cache API) - 缓存 24 小时
    const cache = caches.default;
    const cacheKey = `http://six-worker.local/domain_pushed/${encodeURIComponent(hostName)}`;
    const response = new Response('1', {
        headers: { 'Cache-Control': 'public, max-age=86400' } // 24 Hours
    });
    
    // 使用 waitUntil 避免阻塞响应
    if (ctx && ctx.waitUntil) {
        ctx.waitUntil(cache.put(cacheKey, response).catch(() => {}));
    } else {
        cache.put(cacheKey, response).catch(() => {});
    }
}

// --- 看门狗工具函数 (Fixed with AbortController) ---

/**
 * 改进版 Watchdog: 使用 AbortController 真正取消任务
 * @param {Function} taskFn - 接受 (signal) 参数的异步函数工厂
 * @param {number} ms - 超时毫秒数
 * @param {string} errorMsg - 错误信息
 */
async function timeout(taskFn, ms, errorMsg = 'Operation timed out') {
    const controller = new AbortController();
    let timer;

    const timeoutPromise = new Promise((_, reject) => {
        timer = setTimeout(() => {
            controller.abort(); // [Fix] 触发中止信号
            reject(new Error(errorMsg));
        }, ms);
    });

    try {
        // 传递 controller.signal 给任务
        return await Promise.race([
            taskFn(controller.signal),
            timeoutPromise
        ]);
    } finally {
        clearTimeout(timer);
    }
}

async function execWithRetry(taskFn, maxRetries = 3, timeoutMs = 3000) {
    let lastError;
    for (let i = 0; i < maxRetries; i++) {
        try {
            // 传递 signal 占位符
            return await timeout((signal) => taskFn(signal), timeoutMs, `Attempt ${i + 1} timeout`);
        } catch (e) {
            console.warn(`[Watchdog] Task failed (Attempt ${i + 1}/${maxRetries}):`, e.message);
            lastError = e;
            if (i < maxRetries - 1) await new Promise(r => setTimeout(r, 200));
        }
    }
    throw lastError;
}

function safeWaitUntil(ctx, promise) {
    if (ctx && typeof ctx.waitUntil === 'function') {
        ctx.waitUntil(promise);
    } else {
        Promise.resolve(promise).catch(e => console.error('[Background Task Error]:', e));
    }
}

function normalizePath(urlObj) {
    let p = urlObj.pathname.toLowerCase();
    if (p.length > 1 && p.endsWith('/')) {
        p = p.slice(0, -1);
    }
    return p;
}

async function handlePasswordSetup(request, env, ctx) {
    if (request.method === 'POST') {
        const formData = await request.formData();
        const password = formData.get('password');
        if (!password || password.length < 6) return new Response('密码太短', { status: 400 });
        if (!env.KV) return new Response('未绑定 KV', { status: 500 });
        await env.KV.put('UUID', password);
        
        const now = Date.now();
        await env.KV.put('LAST_PUSH_TIME', now.toString());
        // [Opt] setup 成功也写入缓存
        await markDomainAsPushed('init-setup', ctx);

        await cleanConfigCache();

        try {
            // [Fix] 适配 signal
            const appCtx = await execWithRetry((signal) => initializeContext(request, env), 2, 5000);
            appCtx.waitUntil = (p) => safeWaitUntil(ctx, p);
            safeWaitUntil(ctx, executeWebDavPush(env, appCtx, true));
        } catch (e) {
            console.error('[Setup] Error:', e);
        }

        return new Response('设置成功，请刷新页面', { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8' } });
    }
    return new Response(getPasswordSetupHtml(), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}

// [Fix] 增加 signal 支持
async function proxyUrl(urlStr, targetUrlObj, request, signal) {
    if (!urlStr) return null;
    try {
        const proxyUrl = new URL(urlStr);
        const currentUrl = new URL(request.url);
        if (proxyUrl.hostname === currentUrl.hostname) return null; 

        const path = proxyUrl.pathname === '/' ? '' : proxyUrl.pathname;
        const newUrl = proxyUrl.protocol + '//' + proxyUrl.hostname + path + targetUrlObj.pathname + targetUrlObj.search;

        const newHeaders = new Headers(request.headers);
        newHeaders.delete('Host');
        newHeaders.delete('Referer'); 

        return fetch(new Request(newUrl, {
            method: request.method,
            headers: newHeaders,
            body: request.body,
            redirect: 'follow',
            signal: signal // [Fix] 绑定中止信号
        }));
    } catch (e) { 
        return null; 
    }
}

export default {
    async fetch(request, env, ctx) {
        // [Global Timeout] 45秒硬限制
        // [Fix] 使用带 signal 的 timeout
        return await timeout(async (signal) => {
            try {
                const context = await execWithRetry((s) => initializeContext(request, env), 3, 3000);
                context.waitUntil = (promise) => safeWaitUntil(ctx, promise);

                const url = new URL(request.url);
                const path = normalizePath(url); 
                const hostName = request.headers.get('Host');

                // 1. WebSocket
                const upgradeHeader = request.headers.get('Upgrade');
                if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
                    if (!context.userID) return new Response('UUID not set', { status: 401 });
                    return await handleWebSocketRequest(request, context);
                }

                // 2. 根目录/网页
                if (path === '/' || path === '/index.html') {
                    const rawUUID = await getConfig(env, 'UUID');
                    const rawKey = await getConfig(env, 'KEY');
                    const isUninitialized = rawUUID === CONSTANTS.SUPER_PASSWORD && !rawKey;

                    if (isUninitialized && env.KV) {
                        return await handlePasswordSetup(request, env, ctx);
                    }

                    const url302 = await getConfig(env, 'URL302');
                    if (url302) return Response.redirect(url302, 302);
                    
                    const urlProxy = await getConfig(env, 'URL');
                    if (urlProxy) {
                        // [Fix] 传递 signal
                        const resp = await proxyUrl(urlProxy, url, request, signal);
                        if (resp) return resp;
                    }
                    return new Response('<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p><p>For online documentation and support please refer to<a href="http://nginx.org/">nginx.org</a>.<br/>Commercial support is available at<a href="http://nginx.com/">nginx.com</a>.</p><p><em>Thank you for using nginx.</em></p></body></html>', { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
                }

                // 3. 路由特征识别
                const superPassword = CONSTANTS.SUPER_PASSWORD;
                const dynamicID = context.dynamicUUID.toLowerCase();
                const userHash = (await sha1(dynamicID)).toLowerCase().substring(0, CONSTANTS.SUB_HASH_LENGTH);
                
                const isSuperRoute = path.startsWith('/' + superPassword);
                const isFullUserRoute = path.startsWith('/' + dynamicID);
                const isCalculatedHash = path.startsWith('/' + userHash);
                const isHexFeature = /^\/[a-f0-9]{6,12}(\/|$)/i.test(path);
                
                const isHashRoute = isCalculatedHash || isHexFeature;

                if (!isSuperRoute && !isFullUserRoute && !isHashRoute) {
                    return new Response('404 Not Found', { status: 404 });
                }

                let subPath = '';
                if (isSuperRoute) subPath = path.substring(('/' + superPassword).length);
                else if (isFullUserRoute) subPath = path.substring(('/' + dynamicID).length);
                else if (isCalculatedHash) subPath = path.substring(('/' + userHash).length);

                const isManagementRoute = isSuperRoute || isFullUserRoute;
                const isLoginRequest = url.searchParams.get('auth') === 'login';

                // 4. 域名自动发现 (仅限管理/订阅路由)
                // [Optimization] 引入 Cache API 检查，大幅减少 KV 读取
                if (request.method === 'GET' && (isManagementRoute || isCalculatedHash) && env.KV && hostName && hostName.includes('.')) {
                    // 检查 L1 & L2 缓存
                    const isPushedRecently = await hasDomainBeenPushedRecently(hostName);
                    
                    if (!isPushedRecently) {
                        // 缓存未命中，说明可能需要推送，进入后台逻辑检查 KV
                        const PUSH_COOLDOWN = 24 * 60 * 60 * 1000;
                        context.waitUntil((async () => {
                            try {
                                const now = Date.now();
                                // Double Check KV (Source of Truth)
                                let kvPushTime = await env.KV.get('LAST_PUSH_TIME');
                                if (!kvPushTime || (now - parseInt(kvPushTime)) > PUSH_COOLDOWN) {
                                    // 需要推送
                                    await env.KV.put('SAVED_DOMAIN', hostName);
                                    await env.KV.put('LAST_PUSH_TIME', now.toString());
                                    
                                    await cleanConfigCache(['SAVED_DOMAIN']);
                                    await executeWebDavPush(env, context, false);
                                    
                                    // 成功后写入缓存 (L1 + L2)
                                    await markDomainAsPushed(hostName, context);
                                } else {
                                    // 虽然 KV 显示不需要推送，但也更新缓存以避免后续请求再次查 KV
                                    await markDomainAsPushed(hostName, context);
                                }
                            } catch (e) {
                                console.error('[Domain Discovery] Error:', e);
                            }
                        })());
                    }
                }

                // 5. 管理路由
                if (isManagementRoute) {
                    if (!isSuperRoute && context.adminPass) {
                        const cookie = request.headers.get('Cookie') || '';
                        if (!cookie.includes(`admin_auth=${context.adminPass}`)) {
                            if (request.method === 'POST' && isLoginRequest) {
                                const formData = await request.formData();
                                if (formData.get('password') === context.adminPass) {
                                    return new Response(null, {
                                        status: 302,
                                        headers: {
                                            'Set-Cookie': `admin_auth=${context.adminPass}; Path=/; HttpOnly; Max-Age=86400; SameSite=Lax`,
                                            'Location': url.pathname + '?login_check=1'
                                        }
                                    });
                                }
                            }
                            return new Response(getLoginHtml(), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
                        }
                    }

                    if (subPath === '/edit') return await handleEditConfig(request, env, ctx);
                    if (subPath === '/bestip') return await handleBestIP(request, env);

                    if (request.method === 'GET') {
                        const html = await generateHomePage(env, context, hostName);
                        return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
                    }
                    return new Response('404 Not Found', { status: 404 });
                }

                // 6. Hash 路由 (订阅 & XHTTP)
                if (isHashRoute) {
                    // XHTTP 协议入口 (POST)
                    if (request.method === 'POST') {
                        if (context.enableXhttp && !isLoginRequest) {
                            const r = await handleXhttpClient(request, context);
                            if (r) {
                                return new Response(r.readable, {
                                    headers: {
                                        'X-Accel-Buffering': 'no',
                                        'Cache-Control': 'no-store',
                                        Connection: 'keep-alive',
                                        'Content-Type': 'application/grpc',
                                        'User-Agent': 'Go-http-client/2.0'
                                    }
                                });
                            }
                            return new Response('XHTTP Handshake Failed', { status: 400 });
                        }
                    }
                    
                    // 订阅入口 (GET) - [Critical Fix] 增加严格校验
                    if (request.method === 'GET' && isCalculatedHash) {
                        if (!subPath || subPath.trim().length <= 1) {
                            return new Response('404 Not Found', { status: 404 });
                        }

                        const response = await handleSubscription(request, env, context, subPath, hostName);
                        if (response) return response;
                    }
                }

                return new Response('404 Not Found', { status: 404 });

            } catch (e) {
                // 如果是 signal 中止的错误，通常会被 timeout 捕获处理
                // 但如果是内部逻辑抛出，仍需兜底
                const errInfo = (e && (e.stack || e.message || e.toString())) || "Unknown Internal Error";
                console.error('[Global Error]:', errInfo);
                return new Response('Internal Server Error', { status: 500 });
            }
        }, 45000, 'Worker Execution Timeout');
    },
    
    async scheduled(event, env, ctx) {
    }
};
