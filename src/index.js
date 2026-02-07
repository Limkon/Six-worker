// src/index.js
/**
 * 文件名: src/index.js
 * 状态: 最终审计通过 (Final Verified)
 * 功能对比:
 * 1. [WebSocket] 保留 (最高优先级)
 * 2. [Root] 保留 (设置/302/代理/伪装)
 * 3. [XHTTP] 重构 (仅限 UUID 前段路径触发)
 * 4. [Admin] 保留 (含 API 鉴权 / 登录 / 面板)
 * 5. [Sub] 保留 (订阅下发)
 * 6. [Auto-Discovery] 保留 (支持管理页和订阅触发)
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

// 统一处理路径：去除末尾斜杠 (除非是根路径)
function normalizePath(urlObj) {
    let p = urlObj.pathname.toLowerCase();
    if (p.length > 1 && p.endsWith('/')) {
        p = p.slice(0, -1);
    }
    return p;
}

// 初始密码设置处理
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
            console.log('[Setup] First time setup completed.');
        } catch (e) {
            console.error('[Setup] Error:', e);
        }

        return new Response('设置成功，请刷新页面', { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8' } });
    }
    return new Response(getPasswordSetupHtml(), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}

// 简单网页代理
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

            // ============================================================
            // 1. WebSocket 处理 (最高优先级)
            // ============================================================
            const upgradeHeader = request.headers.get('Upgrade');
            if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
                if (!context.userID) return new Response('UUID not set', { status: 401 });
                return await handleWebSocketRequest(request, context);
            }

            // ============================================================
            // 2. 根目录/网页处理
            // ============================================================
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
            // 3. 路由特征识别 (分流核心)
            // ============================================================
            const superPassword = CONSTANTS.SUPER_PASSWORD;
            const dynamicID = context.dynamicUUID.toLowerCase();
            // 计算 UUID 前段 (Hash)
            const userHash = (await sha1(dynamicID)).toLowerCase().substring(0, CONSTANTS.SUB_HASH_LENGTH);
            
            const isSuperRoute = path.startsWith('/' + superPassword);
            const isFullUserRoute = path.startsWith('/' + dynamicID);
            const isHashRoute = path.startsWith('/' + userHash); // UUID 前段

            // [Critical Fix] 提前拦截非法路径，防止扫描器消耗 CPU
            if (!isSuperRoute && !isFullUserRoute && !isHashRoute) {
                return new Response('404 Not Found', { status: 404 });
            }

            // 计算子路径 (用于 API 等)
            let subPath = '';
            if (isSuperRoute) subPath = path.substring(('/' + superPassword).length);
            else if (isFullUserRoute) subPath = path.substring(('/' + dynamicID).length);
            else if (isHashRoute) subPath = path.substring(('/' + userHash).length);

            const isManagementRoute = isSuperRoute || isFullUserRoute;
            const isLoginRequest = url.searchParams.get('auth') === 'login';

            // ============================================================
            // 4. 域名自动发现 (在任何有效路由的 GET 请求中触发)
            // ============================================================
            if (request.method === 'GET' && env.KV && hostName && hostName.includes('.')) {
                if (hostName !== lastSavedDomain) {
                    const now = Date.now();
                    if (now - lastPushTime > PUSH_COOLDOWN) {
                        context.waitUntil((async () => {
                            // 再次检查 KV 防止并发覆盖
                            let kvPushTimeStr = await env.KV.get('LAST_PUSH_TIME');
                            let kvPushTime = kvPushTimeStr ? (parseInt(kvPushTimeStr) || 0) : 0;
                            
                            if (now - kvPushTime > PUSH_COOLDOWN) {
                                console.log(`[Auto-Discovery] Updating domain to ${hostName}`);
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

            // ============================================================
            // 5. 管理路由 (完整 UUID / SuperPass) -> 网页 / API
            // ============================================================
            if (isManagementRoute) {
                // 5.1 鉴权逻辑
                if (!isSuperRoute && context.adminPass) {
                    const cookie = request.headers.get('Cookie') || '';
                    if (!cookie.includes(`admin_auth=${context.adminPass}`)) {
                         // 登录 POST
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
                         // 未登录且不是 POST API，返回登录页
                         // 注意：如果是 API 请求但未携带 Cookie，也会因为没进入下面的 API 块而最终 404 或在这里被拦截
                         return new Response(getLoginHtml(), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
                    }
                }

                // 5.2 受保护的 API (POST)
                if (request.method === 'POST') {
                    if (subPath === '/edit') return await handleEditConfig(request, env, ctx);
                    if (subPath === '/bestip') return await handleBestIP(request, env);
                }
                
                // 5.3 管理页面 (GET)
                if (request.method === 'GET') {
                    const html = await generateHomePage(env, context, hostName);
                    return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
                }

                // 完整 UUID 路径不处理 XHTTP
                return new Response('404 Not Found', { status: 404 });
            }

            // ============================================================
            // 6. Hash 路由 (UUID 前段) -> XHTTP / 订阅
            // ============================================================
            if (isHashRoute) {
                // 6.1 XHTTP 代理 (仅限 POST 且开启功能)
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

                // 6.2 订阅内容 (仅限 GET)
                if (request.method === 'GET') {
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
