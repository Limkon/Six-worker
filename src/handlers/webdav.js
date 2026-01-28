/**
 * 文件名: src/handlers/webdav.js
 * 审计确认: 
 * 1. [Hardcode] 账号信息已硬编码，无需环境变量。
 * 2. [Default On] 功能默认关闭，配合硬编码凭据。
 * 3. [Auto Domain] 自动使用当前访问域名，解决 scheduled 事件无 Host 问题。
 */
import { handleSubscription } from '../pages/sub.js';
import { sha1 } from '../utils/helpers.js';
import { getConfig } from '../config.js'; 
import { CONSTANTS } from '../constants.js';

export async function executeWebDavPush(env, ctx, force = false) {
    try {
        // [修改] WebDAV 功能开关
        // 默认值改为 '1' (开启)，因为既然已经硬编码了账号，通常意味着需要直接使用。
        // 你依然可以在环境变量中设置 WEBDAV = 0 来强制关闭。
        const enableWebdav = await getConfig(env, 'WEBDAV', '0');
        if (enableWebdav !== '1' && !force) {
            return;
        }

        // 1. [硬编码] WebDAV 配置信息
        // 直接使用指定的账号密码，不再读取环境变量
        const rawWebdavUrl = '';
        const webdavUser = '';
        const webdavPass = '';

        // 标准化 URL，确保以 / 结尾
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
            // 如果既没有环境变量，KV 里也没存过（说明从未访问过），则无法生成有效订阅链接
            console.warn('[WebDAV] Warning: Domain not found! Please access your Worker url at least once to auto-detect domain.');
            // 回退到本地占位符，避免程序崩溃，但生成的链接将不可用
            hostName = 'worker.local';
        }

        // 3. 计算 /all 路径的 hash
        const subHashLength = CONSTANTS.SUB_HASH_LENGTH;
        const allPathHash = (await sha1('all')).toLowerCase().substring(0, subHashLength);

        // 4. 调用 handleSubscription 生成订阅内容
        // 构造模拟请求对象
        const mockRequest = new Request(`https://${hostName}/${ctx.dynamicUUID}/${allPathHash}`);
        
        // 生成订阅内容
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
        } catch (e) {
            // 如果不是 Base64，保持原样
        }

        // 6. 简单的去重处理
        const uniqueLines = [...new Set(content.split('\n'))].filter(line => line.trim() !== '');
        const finalContent = uniqueLines.join('\n');

        // 7. 检查内容 Hash (防重复推送)
        // 只有在非强制模式(force=false)下才检查，手动触发或配置变更(force=true)时跳过检查
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
        
        // 9. 执行推送 (带 5s 超时控制)
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

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
