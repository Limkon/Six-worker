// src/templates/auth.js
/**
 * 文件名: src/templates/auth.js
 * 说明: 存放认证相关的 HTML 模板 (登录页、初始化密码页)
 * 修改: [Security] 在登录页增加 Cookie 可用性检测脚本，防止登录死循环。
 */

export function getPasswordSetupHtml() {
    return `<!DOCTYPE html><html><head><title>初始化设置</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:#f4f4f4;margin:0}.box{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 0 10px rgba(0,0,0,0.1);width:300px;display:flex;flex-direction:column;align-items:center;text-align:center}h1{margin-top:0;font-size:1.5rem}p{color:#666;margin-bottom:1rem}form{width:100%}input,button{width:100%;padding:10px;margin:10px 0;box-sizing:border-box;border-radius:4px;border:1px solid #ccc}button{background:#007bff;color:#fff;border:none;cursor:pointer;font-weight:600}button:hover{background:#0056b3}</style></head><body><div class="box"><h1>设置初始密码</h1><p>请输入UUID或密码作为您的密钥。</p><form method="POST" action="/"><input type="password" name="password" placeholder="输入密码/UUID" required><button type="submit">保存设置</button></form></div></body></html>`;
}

export function getLoginHtml() {
    return `
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
            --error-bg: #f8d7da;
            --error-color: #721c24;
            --error-border: #f5c6cb;
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
        .error-box {
            background-color: var(--error-bg);
            color: var(--error-color);
            border: 1px solid var(--error-border);
            padding: 0.75rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
            text-align: left;
            display: none; /* 默认隐藏，由JS触发 */
            line-height: 1.4;
        }
    </style>
</head>
<body>
    <div class="card">
        <h3>🔒 访问受限</h3>
        
        <div id="error-msg" class="error-box"></div>

        <p style="color:#666; margin-bottom: 1.5rem;">当前页面需要管理员权限</p>
        <form method="POST" action="?auth=login">
            <input type="password" name="password" placeholder="请输入访问密码" required autofocus autocomplete="current-password">
            <button type="submit">立即解锁</button>
        </form>
    </div>

    <script>
        (function() {
            var msgDiv = document.getElementById('error-msg');
            
            // 1. 静态检测：浏览器是否完全禁用了 Cookie
            if (!navigator.cookieEnabled) {
                msgDiv.innerHTML = "<strong>⚠️ 浏览器 Cookie 已禁用</strong><br>系统必须依赖 Cookie 保存登录状态。请在浏览器设置中开启 Cookie 后刷新页面重试。";
                msgDiv.style.display = 'block';
                return;
            }

            // 2. 动态检测：是否发生了“登录成功但Cookie丢失”的死循环
            // (配合 index.js 中的 login_check=1 参数)
            var urlParams = new URLSearchParams(window.location.search);
            if (urlParams.has('login_check')) {
                msgDiv.innerHTML = "<strong>⚠️ 无法写入登录状态</strong><br>您的密码正确，但浏览器未保存 Cookie。<br>可能原因：<br>1. 正在使用隐私模式或第三方 Cookie 被拦截<br>2. 访问域名不支持 HttpOnly Cookie<br>3. 请尝试切换 HTTPS 访问";
                msgDiv.style.display = 'block';
                
                // 清理 URL 参数，避免用户刷新时一直看到错误
                try {
                    var newUrl = window.location.pathname;
                    window.history.replaceState({}, document.title, newUrl);
                } catch(e) {}
            }
        })();
    </script>
</body>
</html>`;
}
