// src/index.js
/**
 * 文件名: src/index.js
 * 修复说明:
 * 1. [Fix] 引入正则特征匹配 /^\/[a-f0-9]{6,12}/，只要路径是 6-12 位 Hex 字符，即视为合法 Hash 路径。
 * 解决因长度配置(6位 vs 8位)或计算差异导致的客户端连接失败。
 * 2. [Security] 依然拦截非 Hex 路径 (如 /admin, /login)，防止 CPU 超限。
 * 3. [Stability] 保持 API 鉴权和 Web 功能。
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

// --- 全局内存缓存 ---
let lastSavedDomain = ''; 
let lastPushTime = 0;     
const PUSH_COOLDOWN = 24 * 60 * 60 * 1000; 

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

// 初始密码设置
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
            const appCtx = await initializeContext(request, env);
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
        try {
            const context = await initializeContext(request, env);
            context.waitUntil = (promise) => safeWaitUntil(ctx, promise);

            const url = new URL(request.url);
            const path = normalizePath(url); 
            const hostName = request.headers.get('Host');

            // 1. WebSocket (最高优先级)
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
                    const resp = await proxyUrl(urlProxy, url, request);
                    if (resp) return resp;
                }

                return new Response('<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p><p>For online documentation and support please refer to<a href="http://nginx.org/">nginx.org</a>.<br/>Commercial support is available at<a href="http://nginx.com/">nginx.com</a>.</p><p><em>Thank you for using nginx.</em></p></body></html>', { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
            }

            // ============================================================
            // 3. 路由特征识别 (关键修复)
            // ============================================================
            const superPassword = CONSTANTS.SUPER_PASSWORD;
            const dynamicID = context.dynamicUUID.toLowerCase();
            
            // 计算标准 Hash (供订阅使用)
            const userHash = (await sha1(dynamicID)).toLowerCase().substring(0, CONSTANTS.SUB_HASH_LENGTH);

            // 路径判定
            const isSuperRoute = path.startsWith('/' + superPassword);
            const isFullUserRoute = path.startsWith('/' + dynamicID);
            
            // [Fix] 宽容的 Hash 路径匹配:
            // 1. 匹配计算出的 Hash
            // 2. 或者匹配 "6到12位纯 Hex 字符" (覆盖 /8fee08ee 这种情况)
            // 这确保了只要客户端发的是 UUID 前段，无论长度配置如何，都能命中。
            const isCalculatedHash = path.startsWith('/' + userHash);
            const isHexFeature = /^\/[a-f0-9]{6,12}(\/|$)/i.test(path);
            
            const isHashRoute = isCalculatedHash || isHexFeature;

            // 提前拦截非相关路径 (防止 CPU 耗尽)
            if (!isSuperRoute && !isFullUserRoute && !isHashRoute) {
                return new Response('404 Not Found', { status: 404 });
            }

            let subPath = '';
            if (isSuperRoute) subPath = path.substring(('/' + superPassword).length);
            else if (isFullUserRoute) subPath = path.substring(('/' + dynamicID).length);
            else if (isCalculatedHash) subPath = path.substring(('/' + userHash).length);
            // 对于 Hex 特征路径，我们不需要精确的 subPath 切割来做 API 路由，因为它只用于 XHTTP/Sub

            const isManagementRoute = isSuperRoute || isFullUserRoute;
            const isLoginRequest = url.searchParams.get('auth') === 'login';

            // 4. 自动域名发现 (仅在有效路径访问时触发)
            if (request.method === 'GET' && env.KV && hostName && hostName.includes('.')) {
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

            // 5. 管理路由 (完整 UUID / SuperPass)
            if (isManagementRoute) {
                // 5.1 鉴权逻辑
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

                // 5.2 API 
                if (request.method === 'POST') {
                    if (subPath === '/edit') return await handleEditConfig(request, env, ctx);
                    if (subPath === '/bestip') return await handleBestIP(request, env);
                }
                
                // 5.3 页面
                if (request.method === 'GET') {
                    const html = await generateHomePage(env, context, hostName);
                    return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
                }

                // 完整路径下的 POST 若非 API，也可能是客户端误连，为防 CPU 问题，此处建议 404
                // 除非你也想让完整 UUID 路径支持 XHTTP (根据之前需求，暂不放行，以免混淆)
                return new Response('404 Not Found', { status: 404 });
            }

            // ============================================================
            // 6. Hash 路由 (UUID 前段 / Hex 特征路径)
            // ============================================================
            if (isHashRoute) {
                // 6.1 XHTTP 代理 (POST)
                if (request.method === 'POST') {
                    // 只要是 POST 且符合 Hex 特征，且不是登录，就尝试 XHTTP
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

                // 6.2 订阅内容 (GET)
                // 只有完全匹配计算出的 hash 时才输出订阅，防止通过爆破 Hex 路径获取订阅信息
                if (request.method === 'GET' && isCalculatedHash) {
                    const response = await handleSubscription(request, env, context, subPath, hostName);
                    if (response) return response;
                }
            }

            // 7. 兜底
            return new Response('404 Not Found', { status: 404 });

        } catch (e) {
            const errInfo = (e && (e.stack || e.message || e.toString())) || "Unknown Internal Error";
            console.error(errInfo);
            return new Response(errInfo, { status: 500 });
        }
    },
    
    async scheduled(event, env, ctx) {
    }
};
