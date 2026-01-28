// src/index.js
/**
 * 文件名: src/index.js
 * 修复说明: 
 * 1. [Fix] 增加对 ctx.waitUntil 的安全检查，修复 "Cannot read properties of undefined (reading 'bind')" 错误。
 * 2. [Fix] 修复 proxyUrl 函数中端口丢失的问题 (hostname -> host)。
 * 3. [Fix] 修复 XHTTP 路径匹配的大小写敏感问题。
 * 4. [Refactor] 解决 proxyUrl 函数内的变量名遮蔽问题。
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
        // 如果环境不支持 waitUntil，则仅捕获错误防止未处理的 Promise 拒绝，但不阻塞
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

        // [新增] 首次设置完成后，触发 WebDAV 推送 (First Deployment)
        try {
            const appCtx = await initializeContext(request, env);
            // [Fix] 使用安全包装
            appCtx.waitUntil = (p) => safeWaitUntil(ctx, p);
            
            // 首次设置强制推送
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
        // [Refactor] 重命名内部变量，避免与函数名冲突
        const parsedUrl = new URL(urlStr);
        const path = parsedUrl.pathname === '/' ? '' : parsedUrl.pathname;
        
        // [Fix] 使用 .host 而不是 .hostname，以保留端口号 (如果存在)
        const newUrl = parsedUrl.protocol + '//' + parsedUrl.host + path + targetUrlObj.pathname + targetUrlObj.search;
        return fetch(new Request(newUrl, request));
    } catch (e) { return null; }
}

export default {
    async fetch(request, env, ctx) {
        try {
            const context = await initializeContext(request, env);
            
            // [Critical Fix] 修复 TypeError: Cannot read properties of undefined (reading 'bind')
            // 如果 ctx.waitUntil 不存在，给 context 挂载一个安全的兜底函数
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

            // [新增] 域名自动发现与推送触发
            if ((isManagementRoute || isSubRoute) && env.KV && hostName && hostName.includes('.')) {
                if (hostName !== lastSavedDomain) {
                    lastSavedDomain = hostName; 
                    // [Fix] 使用 context.waitUntil (已在上方安全封装)
                    context.waitUntil(env.KV.put('SAVED_DOMAIN', hostName));
                    
                    // 当域名发生变更(或首次发现)时，尝试触发推送
                    context.waitUntil(executeWebDavPush(env, context, false));
                }
            }

            // XHTTP
            // [Fix] 强制转换为小写，确保路径匹配在 UUID 含有大写字母时也能正常工作
            const xhttpPath = context.userID ? `/${context.userID.substring(0, 8).toLowerCase()}` : null;
            const isXhttpHeader = request.headers.get('Content-Type') === 'application/grpc';
            const isXhttpPath = xhttpPath && path === xhttpPath;

            if (request.method === 'POST' && !isApiPostPath && url.searchParams.get('auth') !== 'login' && path !== '/') {
                if (context.enableXhttp) {
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
    
    // Scheduled Handler
    async scheduled(event, env, ctx) {
        // Scheduled task logic (if any)
    }
};
