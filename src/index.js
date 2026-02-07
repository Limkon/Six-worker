// src/index.js
/**
 * 文件名: src/index.js
 * 核心机制增强:
 * 1. [Feature] 引入 "看门狗 (Watchdog)" 机制: 针对 initializeContext 进行超时监控与自动重试。
 * 2. [Stability] 全局请求超时控制: 防止 Worker 永久挂起导致 Error 1101。
 * 3. [Fix] 彻底解决 "Worker code had hung" 问题。
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

// --- 全局配置 ---
let lastSavedDomain = ''; 
let lastPushTime = 0;     
const PUSH_COOLDOWN = 24 * 60 * 60 * 1000; 

// --- 看门狗工具函数 (Watchdog Utils) ---

/**
 * 带有超时控制的 Promise 包装器
 * @param {Promise} promise - 原始任务
 * @param {number} ms - 超时时间 (毫秒)
 * @param {string} errorMsg - 超时报错信息
 */
function timeout(promise, ms, errorMsg = 'Operation timed out') {
    let timer;
    const timeoutPromise = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(errorMsg)), ms);
    });
    return Promise.race([
        promise.finally(() => clearTimeout(timer)),
        timeoutPromise
    ]);
}

/**
 * 自动重试机制 (Terminate & Restart)
 * @param {Function} taskFn - 要执行的异步函数工厂 () => Promise
 * @param {number} maxRetries - 最大重试次数
 * @param {number} timeoutMs - 单次尝试的超时时间
 */
async function execWithRetry(taskFn, maxRetries = 3, timeoutMs = 3000) {
    let lastError;
    for (let i = 0; i < maxRetries; i++) {
        try {
            // 尝试执行任务，并加上超时限制
            return await timeout(taskFn(), timeoutMs, `Attempt ${i + 1} timeout`);
        } catch (e) {
            console.warn(`[Watchdog] Task failed (Attempt ${i + 1}/${maxRetries}):`, e.message);
            lastError = e;
            // 失败后稍微等待一下再重试 (指数退避可选，这里简单等待 200ms)
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
        lastPushTime = now;

        await cleanConfigCache();

        try {
            // 设置初始化也使用重试机制
            const appCtx = await execWithRetry(() => initializeContext(request, env), 2, 5000);
            appCtx.waitUntil = (p) => safeWaitUntil(ctx, p);
            safeWaitUntil(ctx, executeWebDavPush(env, appCtx, true));
        } catch (e) {
            console.error('[Setup] Error:', e);
        }

        return new Response('设置成功，请刷新页面', { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8' } });
    }
    return new Response(getPasswordSetupHtml(), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}

async function proxyUrl(urlStr, targetUrlObj, request) {
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
            redirect: 'follow'
        }));
    } catch (e) { 
        return null; 
    }
}

export default {
    async fetch(request, env, ctx) {
        // [Watchdog] 全局软超时控制 (45秒)
        // Cloudflare 硬限制通常是 30s-50s (取决于套餐)，我们在此之前主动返回错误，避免 "Hang" 报错
        return await timeout((async () => {
            try {
                // [Watchdog] 使用重试机制加载上下文
                // 如果远程配置卡死，这里会在 3秒后自动重试，最多试 3 次
                // 这就是您要的 "超时终止并重启" 机制
                const context = await execWithRetry(() => initializeContext(request, env), 3, 3000);
                
                context.waitUntil = (promise) => safeWaitUntil(ctx, promise);

                const url = new URL(request.url);
                const path = normalizePath(url); 
                const hostName = request.headers.get('Host');

                // 1. WebSocket 处理
                const upgradeHeader = request.headers.get('Upgrade');
                if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
                    if (!context.userID) return new Response('UUID not set', { status: 401 });
                    return await handleWebSocketRequest(request, context);
                }

                // 2. 根目录/网页处理
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
                        const resp = await proxyUrl(urlProxy, url, request);
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

                // 4. 域名自动发现
                if (request.method === 'GET' && (isManagementRoute || isCalculatedHash) && env.KV && hostName && hostName.includes('.')) {
                    if (hostName !== lastSavedDomain) {
                        const now = Date.now();
                        if (now - lastPushTime > PUSH_COOLDOWN) {
                            context.waitUntil((async () => {
                                let kvPushTime = await env.KV.get('LAST_PUSH_TIME');
                                if (!kvPushTime || (now - parseInt(kvPushTime)) > PUSH_COOLDOWN) {
                                    await env.KV.put('SAVED_DOMAIN', hostName);
                                    await env.KV.put('LAST_PUSH_TIME', now.toString());
                                    lastSavedDomain = hostName;
                                    lastPushTime = now;
                                    await cleanConfigCache(['SAVED_DOMAIN']);
                                    await executeWebDavPush(env, context, false);
                                }
                            })());
                        }
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

                // 6. Hash 路由
                if (isHashRoute) {
                    if (request.method === 'POST') {
                        if (context.enableXhttp && !isLoginRequest) {
                            const r = await handleXhttpClient(request, context);
                            if (r) {
                                context.waitUntil(r.closed);
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
                    if (request.method === 'GET' && isCalculatedHash) {
                        const response = await handleSubscription(request, env, context, subPath, hostName);
                        if (response) return response;
                    }
                }

                return new Response('404 Not Found', { status: 404 });

            } catch (e) {
                // 捕获所有业务逻辑错误，防止挂起
                const errInfo = (e && (e.stack || e.message || e.toString())) || "Unknown Internal Error";
                console.error('[Global Error]:', errInfo);
                return new Response('Internal Server Error (Watchdog Catch)', { status: 500 });
            }
        })(), 45000, 'Worker Execution Timeout'); // 全局 45秒 硬超时
    },
    
    async scheduled(event, env, ctx) {
    }
};
