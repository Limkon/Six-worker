/**
 * 文件名: src/handlers/webdav.js
 * 审计确认: 
 * 1. 修复了 Scheduled 事件中无法获取 Host 的核心问题 (依赖 WORKER_DOMAIN)。
 * 2. 优化了 URL 拼接逻辑，自动处理末尾斜杠。
 * 3. 增加了功能开关，防止未配置时的无效执行。
 */
import { handleSubscription } from '../pages/sub.js';
import { sha1 } from '../utils/helpers.js';
import { getConfig } from '../config.js'; 
import { CONSTANTS } from '../constants.js';

export async function executeWebDavPush(env, ctx, force = false) {
    try {
        // [新增] WebDAV 功能开关检查
        // 默认关闭 (0)，如需开启请在环境变量中设置 WEBDAV 为 1
        // 注意：如果 force 为 true (例如手动触发)，则忽略开关状态
        const enableWebdav = await getConfig(env, 'WEBDAV', '0');
        if (enableWebdav !== '1' && !force) {
            return;
        }

        // 1. 获取 WebDAV 配置
        const rawWebdavUrl = await getConfig(env, 'WEBDAV_URL');
        const webdavUser = await getConfig(env, 'WEBDAV_USER');
        const webdavPass = await getConfig(env, 'WEBDAV_PASS');

        if (!rawWebdavUrl || !webdavUser || !webdavPass) {
            // 静默失败，因为如果用户没配 WebDAV，不需要在日志里一直报错
            return;
        }

        // [修复] 标准化 URL，确保以 / 结尾
        const webdavUrl = rawWebdavUrl.endsWith('/') ? rawWebdavUrl : `${rawWebdavUrl}/`;

        console.log(`[WebDAV] Starting push to ${webdavUrl}`);

        // 2. 准备请求上下文
        // [修复] 尝试获取 Worker 的真实域名。
        // 在 Scheduled 事件中无法通过 Request 获取 Host，必须依赖环境变量 WORKER_DOMAIN
        let hostName = await getConfig(env, 'WORKER_DOMAIN');
        if (!hostName) {
            hostName = 'worker.local';
            console.warn('[WebDAV] Warning: WORKER_DOMAIN not set. Generated links will use "worker.local" and may not work.');
        }

        // 3. 计算 /all 路径的 hash
        const subHashLength = CONSTANTS.SUB_HASH_LENGTH;
        const allPathHash = (await sha1('all')).toLowerCase().substring(0, subHashLength);

        // 4. 调用 handleSubscription 生成内容
        // 构造模拟请求
        const mockRequest = new Request(`https://${hostName}/${ctx.dynamicUUID}/${allPathHash}`);
        
        // 调用订阅处理函数
        const response = await handleSubscription(mockRequest, env, ctx, allPathHash, hostName);

        if (!response || !response.ok) {
            console.error('[WebDAV] Failed to generate subscription content.');
            return;
        }

        // 5. 获取内容并处理 (Base64 解码)
        let content = await response.text();
        try {
            // 尝试将 Base64 订阅内容解码为明文，以便直接查看
            const decoded = atob(content);
            content = decoded;
        } catch (e) {
            console.warn('[WebDAV] Content is not Base64 or decode failed, using original content.');
        }

        // 6. 去重 (按行去重)
        const uniqueLines = [...new Set(content.split('\n'))].filter(line => line.trim() !== '');
        const finalContent = uniqueLines.join('\n');

        // 7. 检查 Hash (防重复推送)
        if (env.KV && !force) {
            const currentHash = await sha1(finalContent);
            const lastHash = await env.KV.get('WEBDAV_HASH');
            if (currentHash === lastHash) {
                console.log('[WebDAV] Content unchanged, skipping.');
                return;
            }
            if (ctx.waitUntil) ctx.waitUntil(env.KV.put('WEBDAV_HASH', currentHash));
        }

        // 8. 生成文件名并推送
        const subName = await getConfig(env, 'SUBNAME', 'sub');
        const now = new Date();
        // 生成时间戳文件名: sub_20231027083000.txt
        const timestamp = now.toISOString().replace(/[-:T.]/g, '').slice(0, 14);
        const fileName = `${subName}_${timestamp}.txt`;
        
        // 使用修正后的 webdavUrl 进行拼接
        const targetUrl = `${webdavUrl}${fileName}`;
        const auth = btoa(`${webdavUser}:${webdavPass}`);
        
        const pushRequest = fetch(targetUrl, {
            method: 'PUT',
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'text/plain; charset=utf-8',
                'User-Agent': 'Cloudflare-Worker-Pusher'
            },
            body: finalContent
        });

        if (ctx.waitUntil) ctx.waitUntil(pushRequest);
        else await pushRequest;
        
        console.log(`[WebDAV] Push triggered successfully: ${fileName}`);

    } catch (e) {
        console.error('[WebDAV] Logic Error:', e);
    }
}
