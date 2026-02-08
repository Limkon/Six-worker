// src/index.js
/**
 * 文件名: src/index.js
 * 修复说明:
 * 1. [Fix] 将 ctx 传递给 initializeContext，打通 Cache API 的 waitUntil 链路。
 * 2. [Stability] 包含之前的 Watchdog 超时优化和异常捕获逻辑。
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
let lastSavedDomain = ''; 

// --- 缓存工具 (L2 Cache API) ---
async function hasDomainBeenPushedRecently(hostName) {
    if (!hostName) return false;
    if (hostName === lastSavedDomain) return true;

    const cache = caches.default;
    const cacheKey = `http://six-worker.local/domain_pushed/${encodeURIComponent(hostName)}`;
    try {
        const res = await cache.match(cacheKey);
        if (res) {
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
    lastSavedDomain = hostName;
    
    const cache = caches.default;
    const cacheKey = `http://six-worker.local/domain_pushed/${encodeURIComponent(hostName)}`;
    const response = new Response('1', {
        headers: { 'Cache-Control': 'public, max-age=86400' } 
    });
    
    if (ctx && ctx.waitUntil) {
        ctx.waitUntil(cache.put(cacheKey, response).catch(() => {}));
    } else {
        cache.put(cacheKey, response).catch(() => {});
    }
}

// --- 看门狗工具函数 ---
async function timeout(taskFn, ms, errorMsg = 'Operation timed out') {
    const controller = new AbortController();
    let timer;

    const timeoutPromise = new Promise((_, reject) => {
        timer = setTimeout(() => {
            controller.abort(); 
            reject(new Error(errorMsg));
        }, ms);
    });

    try {
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
            return await timeout((signal) => taskFn(signal), timeoutMs, `Attempt ${i + 1} timeout`);
        } catch (e) {
            console.warn(`[Watchdog] Task failed (Attempt ${i + 1}/${maxRetries}):`, e.message || e);
            lastError = e;
            if (i < maxRetries - 1) await new Promise(r => setTimeout(r, 200 * (i + 1)));
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
        await markDomainAsPushed('init-setup', ctx);

        await cleanConfigCache();

        try {
            // [Fix] 传递 ctx
            const appCtx = await execWithRetry((signal) => initializeContext(request, env, ctx), 2, 5000);
            appCtx.waitUntil = (p) => safeWaitUntil(ctx, p);
            safeWaitUntil(ctx, executeWebDavPush(env, appCtx, true));
        } catch (e) {
            console.error('[Setup] Error:', e);
        }

        return new Response('设置成功，请刷新页面', { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8' } });
    }
    return new Response(getPasswordSetupHtml(), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}

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
            signal: signal 
        }));
    } catch (e) { 
        return null; 
    }
}

export default {
    async fetch(request, env, ctx) {
        try {
            return await timeout(async (signal) => {
                try {
                    // [Fix] 传递 ctx 到 initializeContext
                    const context = await execWithRetry((s) => initializeContext(request, env, ctx), 3, 6000);
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
                        // [Fix] 传递 ctx 到 getConfig
                        const rawUUID = await getConfig(env, 'UUID', ctx);
                        const rawKey = await getConfig(env, 'KEY', ctx);
                        const isUninitialized = rawUUID === CONSTANTS.SUPER_PASSWORD && !rawKey;

                        if (isUninitialized && env.KV) {
                            return await handlePasswordSetup(request, env, ctx);
                        }

                        const url302 = await getConfig(env, 'URL302', ctx);
                        if (url302) return Response.redirect(url302, 302);
                        
                        const urlProxy = await getConfig(env, 'URL', ctx);
                        if (urlProxy) {
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

                    // 4. 域名自动发现
                    if (request.method === 'GET' && (isManagementRoute || isCalculatedHash) && env.KV && hostName && hostName.includes('.')) {
                        const isPushedRecently = await hasDomainBeenPushedRecently(hostName);
                        
                        if (!isPushedRecently) {
                            const PUSH_COOLDOWN = 24 * 60 * 60 * 1000;
                            context.waitUntil((async () => {
                                try {
                                    const now = Date.now();
                                    let kvPushTime = await env.KV.get('LAST_PUSH_TIME');
                                    if (!kvPushTime || (now - parseInt(kvPushTime)) > PUSH_COOLDOWN) {
                                        await env.KV.put('SAVED_DOMAIN', hostName);
                                        await env.KV.put('LAST_PUSH_TIME', now.toString());
                                        await cleanConfigCache(['SAVED_DOMAIN']);
                                        await executeWebDavPush(env, context, false);
                                        await markDomainAsPushed(hostName, context);
                                    } else {
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

                    // 6. Hash 路由
                    if (isHashRoute) {
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
                    const errInfo = (e && (e.stack || e.message || e.toString())) || "Unknown Internal Error";
                    console.error('[Fetch Internal Error]:', errInfo);
                    return new Response('Internal Server Error', { status: 500 });
                }
            }, 45000, 'Worker Execution Timeout');
        } catch (fatalError) {
            console.error('[Fatal Worker Error]:', fatalError);
            return new Response('Service Unavailable', { status: 503 });
        }
    },
    
    async scheduled(event, env, ctx) {
    }
};
