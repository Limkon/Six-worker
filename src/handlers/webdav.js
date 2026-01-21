/**
 * 文件名: src/handlers/webdav.js
 * 修改说明: 
 * 1. [修复] 尝试读取 WORKER_DOMAIN 配置，解决定时任务生成订阅时节点地址为 'worker.local' 导致无法连接的问题。
 * 2. [稳健性] 增加对 WEBDAV_URL 的存在性检查。
 */
import { handleSubscription } from '../pages/sub.js';
import { sha1 } from '../utils/helpers.js';
import { getConfig } from '../config.js'; 
import { CONSTANTS } from '../constants.js';

export async function executeWebDavPush(env, ctx, force = false) {
    try {
        // 1. 获取 WebDAV 配置
        const webdavUrl = await getConfig(env, 'WEBDAV_URL');
        const webdavUser = await getConfig(env, 'WEBDAV_USER');
        const webdavPass = await getConfig(env, 'WEBDAV_PASS');

        if (!webdavUrl || !webdavUser || !webdavPass) {
            // 静默失败，因为如果用户没配 WebDAV，不需要在日志里一直报错
            return;
        }

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
            content = atob(content);
        } catch (e) {
            console.warn('[WebDAV] Content decode failed, using original.', e);
        }

        // 6. 去重
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
        const timestamp = now.toISOString().replace(/[-:T.]/g, '').slice(0, 14);
        const fileName = `${subName}_${timestamp}.txt`;
        
        const targetUrl = webdavUrl.endsWith('/') ? webdavUrl + fileName : webdavUrl + '/' + fileName;
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
        
        console.log('[WebDAV] Push triggered successfully.');

    } catch (e) {
        console.error('WebDAV Logic Error:', e);
    }
}
