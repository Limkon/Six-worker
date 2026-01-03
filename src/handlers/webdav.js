/**
 * 文件名: src/handlers/webdav.js
 * 修改说明: 
 * 1. [恢复] 去除注释，恢复 WebDAV 推送逻辑。
 * 2. [重构] 作为一个可调用的独立模块，不再包含硬编码的配置（配置应从 env 或 KV 读取，或者作为参数传入）。
 */
import { handleSubscription } from '../pages/sub.js';
import { sha1 } from '../utils/helpers.js';
import { getConfig } from '../config.js'; 
import { CONSTANTS } from '../constants.js';

export async function executeWebDavPush(env, ctx, force = false) {
    try {
        // 1. 获取 WebDAV 配置 (建议存储在 KV 或环境变量中)
        const webdavUrl = await getConfig(env, 'WEBDAV_URL');
        const webdavUser = await getConfig(env, 'WEBDAV_USER');
        const webdavPass = await getConfig(env, 'WEBDAV_PASS');

        if (!webdavUrl || !webdavUser || !webdavPass) {
            console.log('[WebDAV] Configuration missing (WEBDAV_URL/USER/PASS), skipping push.');
            return;
        }

        console.log(`[WebDAV] Starting push to ${webdavUrl}`);

        // 2. 准备请求上下文
        // 模拟一个 hostName，通常使用当前 worker 的域名，或者默认值
        const hostName = 'worker.local'; // 这里可能需要从外部传入真实的 hostName

        // 3. 计算 /all 路径的 hash
        const subHashLength = CONSTANTS.SUB_HASH_LENGTH;
        const allPathHash = (await sha1('all')).toLowerCase().substring(0, subHashLength);

        // 4. 调用 handleSubscription 生成内容
        // 注意：handleSubscription 需要 request 对象，这里我们伪造一个
        const mockRequest = new Request(`https://${hostName}/${ctx.dynamicUUID}/${allPathHash}`);
        
        // 调用订阅处理函数
        // 注意：我们需要确保 handleSubscription 能处理这种内部调用
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
