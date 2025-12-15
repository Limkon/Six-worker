/**
 * 文件名: src/handlers/webdav.js
 * 修复说明:
 * 1. 独立模块：不再手动生成节点，而是直接调用 handleSubscription 获取通用订阅内容。
 * 2. 注入参数：通过 ctx.socksPassword 强制 Socks5 使用 KEY 作为密码。
 * 3. 格式转换：获取 Base64 订阅内容后解码为明文。
 * 4. 自动去重：使用 Set 去除因生成逻辑导致的重复硬编码节点。
 */
import { handleSubscription } from '../pages/sub.js';
import { sha1 } from '../utils/helpers.js';
import { getConfig } from '../config.js'; 
import { CONSTANTS } from '../constants.js';

export async function executeWebDavPush(env, hostName, ctx, force = false) {
    try {
        // ==========================================
        // WebDAV 配置 (请确认此处信息是否正确)
        // 注意：URL 必须以 / 结尾
        const WEBDAV_CONFIG = {
            URL:  'https://wani.teracloud.jp/dav/', 
            USER: 'zoten',
            PASS: 'N6f7pgwoU5QB6noh'
        };
        // ==========================================

        if (!WEBDAV_CONFIG.URL || !WEBDAV_CONFIG.USER || !WEBDAV_CONFIG.PASS) {
            console.error('[WebDAV] Configuration missing.');
            return;
        }

        console.log(`[WebDAV] Starting push to ${WEBDAV_CONFIG.URL}`);

        // 1. 注入 Socks5 密码 (用户要求的 KEY)
        const userKey = await getConfig(env, 'KEY');
        if (userKey) {
            ctx.socksPassword = userKey;
        }

        // 2. 调用通用订阅生成逻辑 (模拟访问 /all)
        const subHashLength = CONSTANTS.SUB_HASH_LENGTH;
        const allPathHash = (await sha1('all')).toLowerCase().substring(0, subHashLength);

        // 直接调用 sub.js 的处理器获取 Response
        // 传入 null 作为 request，因为 handleSubscription 内部主要依赖 env, ctx, subPath
        const response = await handleSubscription(null, env, ctx, allPathHash, hostName);

        if (!response || !response.ok) {
            console.error('[WebDAV] Failed to generate subscription content via handleSubscription');
            return;
        }

        // 3. 获取内容并处理
        let content = await response.text();

        // 要求：推送明文 (Response 默认是 Base64，需要解码)
        try {
            content = atob(content);
        } catch (e) {
            console.warn('[WebDAV] Content decode failed, pushing original content.', e);
        }

        // 要求：解决重复节点 (利用 Set 进行行级去重)
        // 这会自动合并重复的 hardcodedLinks
        const uniqueLines = [...new Set(content.split('\n'))].filter(line => line.trim() !== '');
        const finalContent = uniqueLines.join('\n');

        // 4. 检查 Hash 避免重复推送
        if (env.KV && !force) {
            const currentHash = await sha1(finalContent);
            const lastHash = await env.KV.get('WEBDAV_HASH');
            if (currentHash === lastHash) {
                console.log('[WebDAV] Content unchanged, skipping.');
                return;
            }
            ctx.waitUntil && ctx.waitUntil(env.KV.put('WEBDAV_HASH', currentHash));
        }

        // 5. 生成文件名
        const subName = await getConfig(env, 'SUBNAME', 'sub');
        const now = new Date();
        const timestamp = now.toISOString().replace(/[-:T.]/g, '').slice(0, 14);
        const fileName = `${subName}_${timestamp}.txt`;
        
        // 6. 推送
        const targetUrl = WEBDAV_CONFIG.URL.endsWith('/') ? WEBDAV_CONFIG.URL + fileName : WEBDAV_CONFIG.URL + '/' + fileName;
        const auth = btoa(`${WEBDAV_CONFIG.USER}:${WEBDAV_CONFIG.PASS}`);
        
        const request = fetch(targetUrl, {
            method: 'PUT',
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'text/plain; charset=utf-8',
                'User-Agent': 'Cloudflare-Worker-Pusher'
            },
            body: finalContent
        });

        if (ctx.waitUntil) ctx.waitUntil(request);
        else await request;
        
        console.log('[WebDAV] Push triggered successfully.');

    } catch (e) {
        console.error('WebDAV 推送逻辑错误:', e);
    }
}
