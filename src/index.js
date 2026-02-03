// src/index.js
/**
 * 文件名: src/index.js
 * 修改说明:
 * 1. [Feature] 实现 24 小时“冷静期”机制。
 * 2. [Optimization] 重启后增加 KV 值比对，避免伪变更触发推送。
 * 3. [Logic] 仅当距离上次推送超过 24 小时且域名发生真实变化时，才触发同步。
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
let lastSavedDomain = ''; // 上次保存的域名 (内存缓存)
let lastPushTime = 0;     // 上次推送的时间戳 (内存缓存)
const PUSH_COOLDOWN = 24 * 60 * 60 * 1000; // 冷却时间：24小时

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
        
        // 初始设置时，强制更新时间戳，确保立即推送
        const now = Date.now();
        await env.KV.put('LAST_PUSH_TIME', now.toString());
        lastPushTime = now;

        await cleanConfigCache();

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
        const proxyUrl = new URL(urlStr);
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
            const path = url.pathname.toLowerCase();
            const hostName = request.headers.get('Host');

            // 1. WebSocket 处理 (最高优先级)
            const upgradeHeader = request.headers.get('Upgrade');
            if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
                if (!context.userID) return new Response('UUID not set', { status: 401 });
                return await handleWebSocketRequest(request, context);
            }

            // 2. 初始密码设置
            const rawUUID = await getConfig(env, 'UUID');
            const rawKey = await getConfig(env, 'KEY');
            const isUninitialized = rawUUID === CONSTANTS.SUPER_PASSWORD && !rawKey;

            if (isUninitialized && env.KV && path === '/') {
                return await handlePasswordSetup(request, env, ctx);
            }

            // 3. 路由路径计算
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

            // 4. 域名自动发现 (24小时冷静期逻辑)
            if ((isManagementRoute || isSubRoute) && env.KV && hostName && hostName.includes('.')) {
                // 仅当域名变化时才尝试进行后续检查
                if (hostName !== lastSavedDomain) {
                    const now = Date.now();
                    
                    // A. 内存快速检查 (如果内存还在冷却期，跳过)
                    if (now - lastPushTime > PUSH_COOLDOWN) {
                        
                        // B. KV 权威检查 (防止重启后内存丢失导致的误判)
                        // 读取上次推送时间
                        let kvPushTimeStr = await env.KV.get('LAST_PUSH_TIME');
                        let kvPushTime = kvPushTimeStr ? (parseInt(kvPushTimeStr) || 0) : 0;
                        
                        // 更新内存时间戳
                        lastPushTime = kvPushTime;

                        if (now - kvPushTime > PUSH_COOLDOWN) {
                            // [Optimization] 关键修复: 读取 KV 里的真实域名进行比对
                            // 如果 Worker 刚重启，lastSavedDomain 为空，但 KV 可能已经是最新域名
                            // 此时若不比对 KV，会误认为域名变更而触发推送
                            const currentRealDomain = await env.KV.get('SAVED_DOMAIN');
                            
                            if (hostName !== currentRealDomain) {
                                console.log(`[Auto-Discovery] Cooldown passed. Updating domain to ${hostName}`);
                                
                                lastSavedDomain = hostName;
                                lastPushTime = now;
                                
                                // 并发执行
                                context.waitUntil(Promise.all([
                                    env.KV.put('SAVED_DOMAIN', hostName),
                                    env.KV.put('LAST_PUSH_TIME', now.toString()), 
                                    cleanConfigCache(['SAVED_DOMAIN']),
                                    executeWebDavPush(env, context, false)
                                ]));
                            } else {
                                // 域名其实没变，只是内存丢失了。静默更新内存即可。
                                lastSavedDomain = hostName;
                                // console.log(`[Auto-Discovery] Domain matches KV. Syncing memory only.`);
                            }
                        }
                    }
                }
            }

            // 5. XHTTP 协议拦截
            if (request.method === 'POST' && context.enableXhttp && !isApiPostPath && url.searchParams.get('auth') !== 'login' && path !== '/') {
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
                
                if (!isManagementRoute) {
                    const contentType = request.headers.get('content-type') || '';
                    if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
                        return new Response('Error: Detected Form submission on XHTTP path. Missing "?auth=login" param?', { status: 400 });
                    }
                    return new Response('Internal Server Error (XHTTP Handshake Failed)', { status: 500 });
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

            // 7. 订阅处理
            if (isSubRoute) {
                const response = await handleSubscription(request, env, context, subPath, hostName);
                if (response) return response;
            }

            // 8. 根路径与回落
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
    }
};
