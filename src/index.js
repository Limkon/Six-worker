// src/index.js
/**
 * 文件名: src/index.js
 * 修复说明: 
 * 1. [Fix] 修复 XHTTP 路径匹配问题：自动去除请求路径末尾的 '/'，解决 "/8fee08ee/" 匹配不到 "/8fee08ee" 的 404 错误。
 * 2. [Fix] 修复 XHTTP Content-Type 匹配问题：使用 .includes() 支持 'application/grpc-web' 等变体。
 * 3. [保留] 包含之前的所有安全修复 (waitUntil, proxyUrl 端口修复等)。
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

let lastSavedDomain = '';

// [辅助函数] 安全执行 waitUntil，防止 crash
function safeWaitUntil(ctx, promise) {
    if (ctx && typeof ctx.waitUntil === 'function') {
        ctx.waitUntil(promise);
    } else {
        Promise.resolve(promise).catch(e => console.error('[Background Task Error]:', e));
    }
}

async function handlePasswordSetup(request, env, ctx) {
    if (request.method === 'POST') {
        const formData = await request.formData();
        const password = formData.get('password');
        if (!password || password.length < 6) return new Response('密码太短', { status: 400 });
        if (!env.KV) return new Response('未绑定 KV', { status: 500 });
        await env.KV.put('UUID', password);
        
        cleanConfigCache();

        try {
            const appCtx = await initializeContext(request, env);
            appCtx.waitUntil = (p) => safeWaitUntil(ctx, p);
            safeWaitUntil(ctx, executeWebDavPush(env, appCtx, true));
            console.log('[Setup] First time setup completed, WebDAV push triggered.');
        } catch (e) {
            console.error('[Setup] Failed to trigger WebDAV push:', e);
        }

        return new Response('设置成功，请刷新页面', { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8' } });
    }
    return new Response(getPasswordSetupHtml(), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}

async function proxyUrl(urlStr, targetUrlObj, request) {
    if (!urlStr) return null;
    try {
        const parsedUrl = new URL(urlStr);
        const path = parsedUrl.pathname === '/' ? '' : parsedUrl.pathname;
        const newUrl = parsedUrl.protocol + '//' + parsedUrl.host + path + targetUrlObj.pathname + targetUrlObj.search;
        return fetch(new Request(newUrl, request));
    } catch (e) { return null; }
}

export default {
    async fetch(request, env, ctx) {
        try {
            const context = await initializeContext(request, env);
            context.waitUntil = (promise) => safeWaitUntil(ctx, promise);

            const url = new URL(request.url);
            const path = url.pathname.toLowerCase();
            const hostName = request.headers.get('Host');

            // WebSocket
            const upgradeHeader = request.headers.get('Upgrade');
            if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
                if (!context.userID) return new Response('UUID not set', { status: 401 });
                return await handleWebSocketRequest(request, context);
            }

            // Password Setup
            const rawUUID = await getConfig(env, 'UUID');
            const rawKey = await getConfig(env, 'KEY');
            const isUninitialized = rawUUID === CONSTANTS.SUPER_PASSWORD && !rawKey;

            if (isUninitialized && env.KV && path === '/') {
                return await handlePasswordSetup(request, env, ctx);
            }

            // Route ID
            const superPassword = CONSTANTS.SUPER_PASSWORD;
            const dynamicID = context.dynamicUUID.toLowerCase();
            const userHash = (await sha1(dynamicID)).toLowerCase().substring(0, CONSTANTS.SUB_HASH_LENGTH);
            
            const isSuperRoute = path.startsWith('/' + superPassword);
            const isUserRoute = path.startsWith('/' + dynamicID);
            const isSubRoute = path.startsWith('/' + userHash);
            
            let subPath = '';
            if (isSuperRoute) subPath = path.substring(('/' + superPassword).length);
            else if (isUserRoute) subPath = path.substring(('/' + dynamicID).length);
            else if (isSubRoute) subPath = path.substring(('/' + userHash).length);

            const isManagementRoute = isSuperRoute || isUserRoute;
            const isApiPostPath = isManagementRoute && (subPath === '/edit' || subPath === '/bestip');

            // 域名自动发现
            if ((isManagementRoute || isSubRoute) && env.KV && hostName && hostName.includes('.')) {
                if (hostName !== lastSavedDomain) {
                    lastSavedDomain = hostName; 
                    context.waitUntil(env.KV.put('SAVED_DOMAIN', hostName));
                    context.waitUntil(executeWebDavPush(env, context, false));
                }
            }

            // ================== XHTTP Logic Start ==================
            const xhttpPath = context.userID ? `/${context.userID.substring(0, 8).toLowerCase()}` : null;
            
            // [Fix] Content-Type 模糊匹配 (兼容 application/grpc-web)
            const reqContentType = request.headers.get('Content-Type') || '';
            const isXhttpHeader = reqContentType.includes('application/grpc');
            
            // [Fix] 路径去尾部斜杠匹配 (兼容 /8fee08ee/ 和 /8fee08ee)
            // 如果 path 是 /abcd/，转换成 /abcd 进行比对
            const cleanPath = (path.endsWith('/') && path.length > 1) ? path.slice(0, -1) : path;
            const isXhttpPath = xhttpPath && cleanPath === xhttpPath;

            if (request.method === 'POST' && !isApiPostPath && url.searchParams.get('auth') !== 'login' && path !== '/') {
                if (context.enableXhttp) {
                    // 只要路径匹配 OR 头信息匹配，就尝试处理
                    if (isXhttpPath || isXhttpHeader) {
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
                        return new Response('Internal Server Error', { status: 500 });
                    }
                    
                    if (!isManagementRoute) {
                        const contentType = request.headers.get('content-type') || '';
                        if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
                            return new Response('Error: Detected Form submission on non-auth path.', { status: 400 });
                        }
                    }
                } else if (isXhttpPath || isXhttpHeader) {
                    return new Response('XHTTP protocol is disabled.', { status: 403 });
                }
            }
            // ================== XHTTP Logic End ==================

            // Management Pages
            if (isManagementRoute) {
                if (!path.startsWith('/' + superPassword)) {
                    if (context.adminPass) {
                        const cookie = request.headers.get('Cookie') || '';
                        if (!cookie.includes(`admin_auth=${context.adminPass}`)) {
                            if (request.method === 'POST' && url.searchParams.get('auth') === 'login') {
                                const formData = await request.formData();
                                if (formData.get('password') === context.adminPass) {
                                    return new Response(null, {
                                        status: 302,
                                        headers: {
                                            'Set-Cookie': `admin_auth=${context.adminPass}; Path=/; HttpOnly; Max-Age=86400; SameSite=Lax`,
                                            'Location': url.pathname 
                                        }
                                    });
                                }
                            }
                            return new Response(getLoginHtml(), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
                        }
                    }
                }

                if (subPath === '/edit') return await handleEditConfig(request, env, ctx);
                if (subPath === '/bestip') return await handleBestIP(request, env);
                
                const html = await generateHomePage(env, context, hostName);
                return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
            }

            // Subscriptions
            if (isSubRoute) {
                const response = await handleSubscription(request, env, context, subPath, hostName);
                if (response) return response;
            }

            // Root Path
            if (path === '/') {
                const url302 = await getConfig(env, 'URL302');
                if (url302) return Response.redirect(url302, 302);
                
                const urlProxy = await getConfig(env, 'URL');
                if (urlProxy) {
                    const resp = await proxyUrl(urlProxy, url, request);
                    if (resp) return resp;
                }

                return new Response('<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p><p>For online documentation and support please refer to<a href="http://nginx.org/">nginx.org</a>.<br/>Commercial support is available at<a href="http://nginx.com/">nginx.com</a>.</p><p><em>Thank you for using nginx.</em></p></body></html>', { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
            }

            return new Response('404 Not Found', { status: 404 });

        } catch (e) {
            return new Response(e.stack || e.toString(), { status: 500 });
        }
    },
    
    async scheduled(event, env, ctx) {
        // Scheduled task logic (if any)
    }
};
