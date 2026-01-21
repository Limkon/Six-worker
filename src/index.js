/**
 * 文件名: src/index.js
 * 修改内容: 
 * 1. [修复] 优化 XHTTP 拦截逻辑，通过特征路径 (ID前8位) 和 Header 精准识别，避免拦截普通 POST 请求。
 * 2. [修复] 初始密码设置成功后调用 cleanConfigCache()，确保配置立即生效。
 * 3. [优化] 提升了 POST 请求处理的鲁棒性，非 XHTTP 路径的 POST 请求将正常进入后续路由。
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

async function handlePasswordSetup(request, env) {
    if (request.method === 'POST') {
        const formData = await request.formData();
        const password = formData.get('password');
        if (!password || password.length < 6) return new Response('密码太短', { status: 400 });
        if (!env.KV) return new Response('未绑定 KV', { status: 500 });
        await env.KV.put('UUID', password);
        
        // 清除缓存，使 UUID 立即生效
        cleanConfigCache();

        return new Response('设置成功，请刷新页面', { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8' } });
    }
    return new Response(getPasswordSetupHtml(), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}

async function proxyUrl(urlStr, targetUrlObj, request) {
    if (!urlStr) return null;
    try {
        const proxyUrl = new URL(urlStr);
        const path = proxyUrl.pathname === '/' ? '' : proxyUrl.pathname;
        const newUrl = proxyUrl.protocol + '//' + proxyUrl.hostname + path + targetUrlObj.pathname + targetUrlObj.search;
        return fetch(new Request(newUrl, request));
    } catch (e) { return null; }
}

export default {
    async fetch(request, env, ctx) {
        try {
            // 1. 初始化上下文
            const context = await initializeContext(request, env);
            context.waitUntil = ctx.waitUntil.bind(ctx);

            const url = new URL(request.url);
            const path = url.pathname.toLowerCase();
            const hostName = request.headers.get('Host');

            // 2. WebSocket 核心拦截 (最高优先级)
            const upgradeHeader = request.headers.get('Upgrade');
            if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
                if (!context.userID) return new Response('UUID not set', { status: 401 });
                return await handleWebSocketRequest(request, context);
            }

            // 3. 初始密码设置 (KV 存在但无 UUID)
            const rawUUID = await getConfig(env, 'UUID');
            const rawKey = await getConfig(env, 'KEY');
            const isUninitialized = rawUUID === CONSTANTS.SUPER_PASSWORD && !rawKey;

            if (isUninitialized && env.KV && path === '/') {
                return await handlePasswordSetup(request, env);
            }

            // 4. 路由识别
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

            // 5. XHTTP 协议拦截 (优化后的精准识别逻辑)
            const xhttpPath = context.userID ? `/${context.userID.substring(0, 8)}` : null;
            const isXhttpHeader = request.headers.get('Content-Type') === 'application/grpc';
            const isXhttpPath = xhttpPath && path === xhttpPath;

            if (request.method === 'POST' && !isApiPostPath && url.searchParams.get('auth') !== 'login' && path !== '/') {
                if (context.enableXhttp) {
                    // 仅当符合 XHTTP 特征（路径匹配或 gRPC Header）时才进入处理
                    if (isXhttpPath || isXhttpHeader) {
                        const r = await handleXhttpClient(request, context);
                        if (r) {
                            ctx.waitUntil(r.closed);
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
                        // 如果路径匹配但处理失败，返回 500
                        return new Response('Internal Server Error (XHTTP Handler Failed)', { status: 500 });
                    }
                    
                    // 对于非协议路径的 POST 且非管理路径，检查是否为遗漏 auth 参数的表单提交
                    if (!isManagementRoute) {
                        const contentType = request.headers.get('content-type') || '';
                        if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
                            return new Response('Error: Detected Form submission on non-auth path. Missing "?auth=login" param?', { status: 400 });
                        }
                    }
                } else if (isXhttpPath || isXhttpHeader) {
                    // 协议已明确禁用
                    return new Response('XHTTP protocol is disabled by admin.', { status: 403 });
                }
            }

            // 6. 管理页面鉴权
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

            // 8. 订阅处理
            if (isSubRoute) {
                const response = await handleSubscription(request, env, context, subPath, hostName);
                if (response) return response;
            }

            // 9. 根路径与回落
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
    
    // Scheduled 事件: 处理 WebDAV 推送等定时任务
    async scheduled(event, env, ctx) {
        try {
            // await executeWebDavPush(env, ctx);
        } catch (e) { 
            console.error('Scheduled Event Error:', e); 
        }
    }
};
