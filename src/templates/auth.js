/**
 * 文件名: src/templates/auth.js
 * 说明: 存放认证相关的 HTML 模板 (登录页、初始化密码页)
 */

export function getPasswordSetupHtml() {
    return `<!DOCTYPE html><html><head><title>初始化设置</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:#f4f4f4}.box{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 0 10px rgba(0,0,0,0.1);width:300px}input,button{width:100%;padding:10px;margin:10px 0;box-sizing:border-box}button{background:#007bff;color:#fff;border:none;cursor:pointer}</style></head><body><div class="box"><h1>设置初始密码</h1><p>请输入UUID或密码作为您的密钥。</p><form method="POST" action="/"><input type="password" name="password" placeholder="输入密码/UUID" required><button type="submit">保存设置</button></form></div></body></html>`;
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
}
