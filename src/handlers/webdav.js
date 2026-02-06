/**
 * 文件名: src/handlers/webdav.js
 * 审计与修复: 
 * 1. [Fix] 增加凭据非空检查，防止空配置导致 Fetch 异常。
 * 2. [Optimization] 延长推送超时时间至 10s，适应网络波动。
 * 3. [Security] 限制推送内容最大为 10KB，防止大对象导致的内存溢出风险。
 */
import { handleSubscription } from '../pages/sub.js';
import { sha1 } from '../utils/helpers.js';
import { getConfig } from '../config.js'; 
import { CONSTANTS } from '../constants.js';

export async function executeWebDavPush(env, ctx, force = false) {
    try {
        // WebDAV 功能开关 (默认关闭，除非环境变量设为 1 或强制执行)
        const enableWebdav = await getConfig(env, 'WEBDAV', '0');
        if (enableWebdav !== '1' && !force) {
            return;
        }

        // 1. [配置区] 必须在此处填写您的坚果云/WebDAV 信息
        // 注意：如果不填写，脚本会自动跳过 WebDAV 推送，不会报错
        const rawWebdavUrl = ''; // 示例: https://dav.jianguoyun.com/dav/
        const webdavUser = '';   // 示例: your_email@example.com
        const webdavPass = '';   // 示例: 应用专用密码

        // [Security Fix] 检查凭据是否已配置
        if (!rawWebdavUrl || !webdavUser || !webdavPass) {
            // 仅在显式开启或强制推送时才警告，避免日志噪音
            if (enableWebdav === '1' || force) {
                console.warn('[WebDAV] Credentials missing! Please configure rawWebdavUrl/User/Pass in src/handlers/webdav.js');
            }
            return;
        }

        const webdavUrl = rawWebdavUrl.endsWith('/') ? rawWebdavUrl : `${rawWebdavUrl}/`;
        console.log(`[WebDAV] Starting push to ${webdavUrl}`);

        // 2. 准备请求上下文 (自动域名发现逻辑)
        // 优先读取环境变量 -> 其次读取 KV 自动保存的域名
        let hostName = await getConfig(env, 'WORKER_DOMAIN');
        if (!hostName && env.KV) {
            hostName = await env.KV.get('SAVED_DOMAIN');
            if (hostName) {
                console.log(`[WebDAV] Using auto-detected domain from KV: ${hostName}`);
            }
        }

        if (!hostName) {
            console.warn('[WebDAV] Warning: Domain not found! Please access your Worker url at least once.');
            hostName = 'worker.local';
        }

        // 3. 计算 /all 路径的 hash
        const subHashLength = CONSTANTS.SUB_HASH_LENGTH;
        const allPathHash = (await sha1('all')).toLowerCase().substring(0, subHashLength);

        // 4. 调用 handleSubscription 生成订阅内容
        // 构造模拟请求对象
        const mockRequest = new Request(`https://${hostName}/${ctx.dynamicUUID}/${allPathHash}`);
        const response = await handleSubscription(mockRequest, env, ctx, allPathHash, hostName);

        if (!response || !response.ok) {
            console.error('[WebDAV] Failed to generate subscription content.');
            return;
        }

        // 5. 获取内容并处理 (Base64 解码)
        let content = await response.text();
        try {
            // 尝试将 Base64 订阅内容解码为明文，方便在网盘直接查看
            const decoded = atob(content);
            content = decoded;
        } catch (e) {}

        // 6. 去重与大小限制 (10KB 限制修复)
        const uniqueLines = [...new Set(content.split('\n'))].filter(line => line.trim() !== '');
        
        // [Security Fix] 严格限制推送大小不超过 10KB
        const MAX_BYTES = 10 * 1024; // 10KB
        const encoder = new TextEncoder();
        
        let accumulatedBytes = 0;
        const limitedLines = [];
        
        for (const line of uniqueLines) {
            // 计算当前行加上换行符后的字节大小
            const lineBytes = encoder.encode(line).length + 1; 
            
            if (accumulatedBytes + lineBytes > MAX_BYTES) {
                console.warn(`[WebDAV] Content exceeded 10KB limit. Truncating remaining nodes...`);
                break;
            }
            
            limitedLines.push(line);
            accumulatedBytes += lineBytes;
        }
        
        const finalContent = limitedLines.join('\n');

        // 7. 检查内容 Hash (防重复推送)
        if (env.KV && !force) {
            const currentHash = await sha1(finalContent);
            const lastHash = await env.KV.get('WEBDAV_HASH');
            if (currentHash === lastHash) {
                console.log('[WebDAV] Content unchanged, skipping push.');
                return;
            }
            // 异步更新 Hash
            if (ctx.waitUntil) ctx.waitUntil(env.KV.put('WEBDAV_HASH', currentHash));
        }

        // 8. 生成文件名并推送
        const subName = await getConfig(env, 'SUBNAME', 'sub');
        // 使用 UTC+8 时间戳作为文件名后缀
        const offset = 8 * 60 * 60 * 1000;
        const now = new Date();
        const localDate = new Date(now.getTime() + offset);
        const timestamp = localDate.toISOString().replace(/[-:T.]/g, '').slice(0, 14); // YYYYMMDDHHMMSS
        const fileName = `${subName}_${timestamp}.txt`;
        
        const targetUrl = `${webdavUrl}${fileName}`;
        const auth = btoa(`${webdavUser}:${webdavPass}`);
        
        // 9. 执行推送 (带 10s 超时控制)
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000); // [Opt] 延长至 10s

        const pushRequest = fetch(targetUrl, {
            method: 'PUT',
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'text/plain; charset=utf-8',
                'User-Agent': 'Cloudflare-Worker-Pusher'
            },
            body: finalContent,
            signal: controller.signal
        }).then(res => {
            if (res.ok) console.log(`[WebDAV] Push success: ${fileName}`);
            else console.error(`[WebDAV] Push failed: ${res.status} ${res.statusText}`);
        }).catch(err => {
            console.error(`[WebDAV] Push error: ${err.message}`);
        }).finally(() => {
            clearTimeout(timeoutId);
        });

        if (ctx.waitUntil) ctx.waitUntil(pushRequest);
        else await pushRequest;

    } catch (e) {
        console.error('[WebDAV] Logic Error:', e);
    }
}
