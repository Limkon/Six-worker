/**
 * 文件名: src/index.js
 * 说明: 
 * 1. [关键修复] 修正了初始密码设置的判断逻辑 (直接检查原始配置，防止被动态UUID欺骗)。
 * 2. [关键修复] XHTTP 拦截逻辑排除根路径 ('/')，防止误拦截密码设置和登录表单。
 * 3. 整合了美化后的登录界面。
 * 4. 移除了 WebDAV 自动推送引用。
 */
import { initializeContext, getConfig } from './config.js';
import { handleWebSocketRequest } from './handlers/websocket.js';
import { handleXhttpClient } from './handlers/xhttp.js';
import { handleEditConfig, handleBestIP } from './pages/admin.js';
import { handleSubscription } from './pages/sub.js';
// [修改] 移除 WebDAV 模块引用
// import { executeWebDavPush } from './handlers/webdav.js';
import { generateHomePage } from './pages/home.js';
import { sha1, isStrictV4UUID } from './utils/helpers.js';
import { CONSTANTS } from './constants.js';

// 密码设置页面 HTML
const passwordSetupHtml = `<!DOCTYPE html><html><head><title>初始化设置</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:#f4f4f4}.box{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 0 10px rgba(0,0,0,0.1);width:300px}input,button{width:100%;padding:10px;margin:10px 0;box-sizing:border-box}button{background:#007bff;color:#fff;border:none;cursor:pointer}</style></head><body><div class="box"><h1>设置初始密码</h1><p>请输入UUID或密码作为您的密钥。</p><form method="POST" action="/"><input type="password" name="password" placeholder="输入密码/UUID" required><button type="submit">保存设置</button></form></div></body></html>`;

// 登录页面 HTML (美化版)
const loginHtml = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>后台访问验证</title>
    <style>
        :root {
            --primary-color: #007bff;
            --primary-hover: #0056b3;
            --bg-color: #f0f2f5;
            --card-bg: #ffffff;
            --text-color: #333333;
            --border-color: #dee2e6;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-color: var(--bg-color);
            color: var(--text-color);
        }
        .card {
            background: var(--card-bg);
            padding: 2.5rem;
            border-radius: 16px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.05);
            width: 100%;
            max-width: 380px;
            text-align: center;
            transition: transform 0.3s ease;
        }
        .card:hover {
            transform: translateY(-2px);
        }
        h3 {
            margin-top: 0;
            margin-bottom: 1.5rem;
            font-size: 1.5rem;
            font-weight: 600;
            color: #2c3e50;
        }
        form {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        input {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            font-size: 16px;
            box-sizing: border-box;
            transition: all 0.3s ease;
            outline: none;
        }
        input:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.1);
        }
        button {
            width: 100%;
            padding: 12px;
            background-color: var(--primary-color);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s ease, transform 0.1s ease;
        }
        button:hover {
            background-color: var(--primary-hover);
        }
        button:active {
            transform: scale(0.98);
        }
    </style>
</head>
<body>
    <div class="card">
        <h3>🔒 访问受限</h3>
        <p style="color:#666; margin-bottom: 1.5rem;">当前页面需要管理员权限</p>
        <form method="POST" action="?auth=login">
            <input type="password" name="password" placeholder="请输入访问密码" required autofocus autocomplete="current-password">
            <button type="submit">立即解锁</button>
        </form>
    </div>
</body>
</html>`;

async function handlePasswordSetup(request, env) {
    if (request.method === 'POST') {
        const formData = await request.formData();
        const password = formData.get('password');
        if (!password || password.length < 6) return new Response('密码太短', { status: 400 });
        if (!env.KV) return new Response('未绑定 KV', { status: 500 });
        await env.KV.put('UUID', password);
        return new Response('设置成功，请刷新页面', { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8' } });
    }
    return new Response(passwordSetupHtml, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
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

            // 3. 初始密码设置 (KV存在但无UUID)
            // [修复] 修正判断逻辑：显式检查原始配置，而非依赖 context.userID
            // getConfig 会在无配置时返回默认密码，所以这里比较 rawUUID 是否等于默认密码
            const rawUUID = await getConfig(env, 'UUID');
            const rawKey = await getConfig(env, 'KEY');
            
            // 判断依据：UUID 为默认值 且 没有配置 KEY
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

            // 辅助判断：是否是 API POST 请求 (如果是管理 API，则不作为 XHTTP 处理)
            const isManagementRoute = isSuperRoute || isUserRoute;
            const isApiPostPath = isManagementRoute && (subPath === '/edit' || subPath === '/bestip');

            // 5. XHTTP 协议拦截 (POST请求 + 开启XHTTP + 非管理API + 非登录请求)
            // [修复] 增加 && path !== '/' 判断。
            // 这一步非常关键：根路径 ('/') 的 POST 请求（如初始密码设置、根路径反代）
            // 必须排除在 XHTTP 拦截之外，否则会报错 "Detected Form submission..."
            if (request.method === 'POST' && context.enableXhttp && !isApiPostPath && url.searchParams.get('auth') !== 'login' && path !== '/') {
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
                
                // [优化] XHTTP 握手失败时的错误区分
                if (!isManagementRoute) {
                    const contentType = request.headers.get('content-type') || '';
                    // 如果 Content-Type 表明这是一个表单提交，说明用户可能想登录但被 XHTTP 拦截了
                    if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
                        return new Response('Error: Detected Form submission on XHTTP path. Missing "?auth=login" param?', { status: 400 });
                    }
                    return new Response('Internal Server Error', { status: 500 });
                }
            }

            // 6. 管理页面鉴权 (Admin Pass)
            if (isManagementRoute) {
                // 如果是超级密码路径，跳过鉴权
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
                                            'Set-Cookie': `admin_auth=${context.adminPass}; Path=/; HttpOnly; Max-Age=86400`,
                                            'Location': url.pathname 
                                        }
                                    });
                                }
                            }
                            return new Response(loginHtml, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
                        }
                    }
                }

                // 7. 管理功能分发
                if (subPath === '/edit') return await handleEditConfig(request, env, ctx);
                if (subPath === '/bestip') return await handleBestIP(request, env);
                
                // 默认：显示主页信息 (已移除 WebDAV 自动推送)
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

                return new Response('<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>', { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
            }

            return new Response('404 Not Found', { status: 404 });

        } catch (e) {
            return new Response(e.stack || e.toString(), { status: 500 });
        }
    }
};
