// src/index.js
/**
 * 文件名: src/index.js
 * 最终审计修正版:
 * 1. [Fix] 修复 API 路径判定 bug: 兼容带尾部斜杠的请求 (e.g., /edit/)，防止误入 XHTTP 逻辑。
 * 2. [Feat] 根目录增强: 支持 /index.html 映射到主页。
 * 3. [Perf] 极致性能: 确保代理流量 (POST) 在第一层级被拦截，零 CPU 浪费。
 * 4. [Logic] 严格分流: 根目录(Web) vs 非根目录(Proxy/Admin)。
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

// 统一处理路径：去除末尾斜杠 (除非是根路径)
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

async function proxyUrl(urlStr, targetUrlObj, request) {
    if (!urlStr) return null;
    try {
        const proxyUrl = new URL(urlStr);
        const currentUrl = new URL(request.url);
        if (proxyUrl.hostname === currentUrl.hostname) return null; // Prevent loops

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
            // [Fix] 规范化路径，解决 /edit/ 匹配失败的问题
            const path = normalizePath(url); 
            const hostName = request.headers.get('Host');

            // 1. WebSocket 处理 (最高优先级)
            const upgradeHeader = request.headers.get('Upgrade');
            if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
                if (!context.userID) return new Response('UUID not set', { status: 401 });
                return await handleWebSocketRequest(request, context);
            }

            // ============================================================
            // 逻辑分流 A: 根目录处理 (普通网页/设置/重定向)
            // [Fix] 支持 /index.html 别名
            // ============================================================
            if (path === '/' || path === '/index.html') {
                // A.1 初始设置
                const rawUUID = await getConfig(env, 'UUID');
                const rawKey = await getConfig(env, 'KEY');
                const isUninitialized = rawUUID === CONSTANTS.SUPER_PASSWORD && !rawKey;

                if (isUninitialized && env.KV) {
                    return await handlePasswordSetup(request, env, ctx);
                }

                // A.2 网页功能
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
            // 逻辑分流 B: 其他路径处理 (默认优先 XHTTP)
            // ============================================================
            
            // [Critical Fix] 判定是否为 API 请求。使用 endsWith 配合规范化后的 path。
            // 这样 /uuid/edit 和 /uuid/edit/ (已被规范化) 都能正确被识别为 API，不会误入 XHTTP。
            const isApiPostPath = path.endsWith('/edit') || path.endsWith('/bestip');
            const isLoginRequest = url.searchParams.get('auth') === 'login';

            // B.1 XHTTP 协议拦截 
            // 只有 POST 且开启 XHTTP 且 不是已知 API/Login 时，才视为 XHTTP 流量
            if (request.method === 'POST' && context.enableXhttp && !isApiPostPath && !isLoginRequest) {
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
                // 握手失败，直接返回 400，不再消耗 CPU 去计算 SHA1 或查询 KV
                return new Response('XHTTP Handshake Failed', { status: 400 });
            }

            // B.2 路由计算 (仅 GET 请求 或 明确的 API POST 请求才会到达这里)
            const superPassword = CONSTANTS.SUPER_PASSWORD;
            const dynamicID = context.dynamicUUID.toLowerCase();
            
            const isSuperRoute = path.startsWith('/' + superPassword);
            const isUserRoute = path.startsWith('/' + dynamicID);
            
            let userHash = '';
            let isSubRoute = false;

            // 只有当前面不匹配时，才进行 SHA1 计算
            if (!isSuperRoute && !isUserRoute) {
                userHash = (await sha1(dynamicID)).toLowerCase().substring(0, CONSTANTS.SUB_HASH_LENGTH);
                isSubRoute = path.startsWith('/' + userHash);
            }
            
            let subPath = '';
            if (isSuperRoute) subPath = path.substring(('/' + superPassword).length);
            else if (isUserRoute) subPath = path.substring(('/' + dynamicID).length);
            else if (isSubRoute) subPath = path.substring(('/' + userHash).length);

            const isManagementRoute = isSuperRoute || isUserRoute;

            // B.3 域名自动发现 (仅 GET 请求触发)
            if (request.method === 'GET' && (isManagementRoute || isSubRoute) && env.KV && hostName && hostName.includes('.')) {
                if (hostName !== lastSavedDomain) {
                    const now = Date.now();
                    if (now - lastPushTime > PUSH_COOLDOWN) {
                        let kvPushTimeStr = await env.KV.get('LAST_PUSH_TIME');
                        let kvPushTime = kvPushTimeStr ? (parseInt(kvPushTimeStr) || 0) : 0;
                        lastPushTime = kvPushTime;

                        if (now - kvPushTime > PUSH_COOLDOWN) {
                            const currentRealDomain = await env.KV.get('SAVED_DOMAIN');
                            if (hostName !== currentRealDomain) {
                                console.log(`[Auto-Discovery] Updating domain to ${hostName}`);
                                lastSavedDomain = hostName;
                                lastPushTime = now;
                                context.waitUntil(Promise.all([
                                    env.KV.put('SAVED_DOMAIN', hostName),
                                    env.KV.put('LAST_PUSH_TIME', now.toString()), 
                                    cleanConfigCache(['SAVED_DOMAIN']),
                                    executeWebDavPush(env, context, false)
                                ]));
                            } else {
                                lastSavedDomain = hostName;
                            }
                        }
                    }
                }
            }

            // B.4 管理页面与 API
            if (isManagementRoute) {
                // 鉴权逻辑
                if (!path.startsWith('/' + superPassword)) {
                    if (context.adminPass) {
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
                }

                // 处理 API POST 请求
                if (subPath === '/edit') return await handleEditConfig(request, env, ctx);
                if (subPath === '/bestip') return await handleBestIP(request, env);
                
                // 处理 页面 GET 请求
                if (request.method === 'GET') {
                    const html = await generateHomePage(env, context, hostName);
                    return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
                }
            }

            // B.5 订阅处理 (仅 GET)
            if (isSubRoute && request.method === 'GET') {
                const response = await handleSubscription(request, env, context, subPath, hostName);
                if (response) return response;
            }

            // B.6 兜底 (非根路径，非XHTTP，非API，非订阅 -> 404)
            return new Response('404 Not Found', { status: 404 });

        } catch (e) {
            const errInfo = (e && (e.stack || e.message || e.toString())) || "Unknown Internal Error";
            console.error(errInfo);
            return new Response(errInfo, { 
                status: 500, 
                headers: { 
                    'Content-Type': 'text/plain;charset=utf-8',
                    'X-Error-Source': 'Six-Worker-Core'
                } 
            });
        }
    },
    
    async scheduled(event, env, ctx) {
    }
};
