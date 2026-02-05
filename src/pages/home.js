/**
 * 文件名: src/pages/home.js
 * 说明: 
 * 1. [重构] 引入 src/templates/home.js 模板。
 * 2. [逻辑] 保持了节点生成和协议判断逻辑。
 * 3. [Fix] 修复直接读取 env.KV 导致的潜在白屏问题，统一使用 getConfig 走缓存和容错机制。
 */
import { CONSTANTS } from '../constants.js';
import { sha1 } from '../utils/helpers.js';
import { getConfig } from '../config.js'; // [新增] 引入配置获取工具
import { getHomePageHtml, getSectionHtml, getCopyBtnHtml } from '../templates/home.js';

export async function generateHomePage(env, ctx, hostName) {
    // [Fix] 使用 getConfig 替代直接 KV 读取
    // 优势: 1. 利用 L1/L2 缓存提高加载速度 2. 包含 try-catch 防止 KV 故障导致白屏 3. 统一配置管理
    const FileName = await getConfig(env, 'SUBNAME', 'sub');
    
    const isWorkersDev = hostName.includes("workers.dev");
    const httpsPorts = ctx.httpsPorts;
    const path = '/?ed=2560'; // Default VLESS path
    
    // 辅助函数：判断协议是否启用
    const isEnabled = (p) => {
        if (p === 'socks5' && ctx.disabledProtocols.includes('socks')) return false;
        return !ctx.disabledProtocols.includes(p);
    };

    // 计算订阅路径哈希
    const subPathNames = [
        'all', 'all-tls', 'all-clash', 'all-clash-tls', 'all-sb', 'all-sb-tls',
        'vless', 'vless-tls', 'vless-clash', 'vless-clash-tls', 'vless-sb', 'vless-sb-tls',
        'trojan', 'trojan-tls', 'trojan-clash', 'trojan-clash-tls', 'trojan-sb', 'trojan-sb-tls',
        'ss', 'ss-tls', 'ss-clash', 'ss-clash-tls', 'ss-sb', 'ss-sb-tls',
        'socks', 'socks-tls', 'socks-clash', 'socks-clash-tls', 'socks-sb', 'socks-sb-tls',
        'mandala-tls', 
        'xhttp-tls', 'xhttp-clash-tls', 'xhttp-sb-tls'
    ];
    
    // 生成 Hash 映射
    const hashPromises = subPathNames.map(p => sha1(p));
    const hashes = (await Promise.all(hashPromises)).map(h => h.toLowerCase().substring(0, CONSTANTS.SUB_HASH_LENGTH));
    const subs = {};
    
    // 订阅前缀
    const userHash = (await sha1(ctx.dynamicUUID)).toLowerCase().substring(0, CONSTANTS.SUB_HASH_LENGTH);
    const subPathPrefix = `/${userHash}`;

    subPathNames.forEach((name, i) => {
        const key = name.replace(/-/g, '_');
        subs[key] = `https://${hostName}${subPathPrefix}${hashes[i]}`;
    });

    // 动态生成节点详情 HTML
    let nodeDetailsHtml = '';
    const activeProtocols = [];

    // VLESS
    if (isEnabled('vless')) {
        const vless_tls = `vless://${ctx.userID}@${hostName}:${httpsPorts[0]}?encryption=none&security=tls&sni=${hostName}&fp=random&type=ws&host=${hostName}&path=${encodeURIComponent(path)}#${hostName}-VLESS-TLS`;
        nodeDetailsHtml += getSectionHtml('VLESS TLS', getCopyBtnHtml(vless_tls));
        activeProtocols.push('VLESS');
    }

    // Trojan
    if (isEnabled('trojan')) {
        const trojan_tls = `trojan://${ctx.dynamicUUID}@${hostName}:${httpsPorts[0]}?security=tls&sni=${hostName}&fp=random&type=ws&host=${hostName}&path=${encodeURIComponent(path)}#${hostName}-TROJAN-TLS`;
        nodeDetailsHtml += getSectionHtml('Trojan TLS', getCopyBtnHtml(trojan_tls));
        activeProtocols.push('Trojan');
    }

    // Mandala
    if (isEnabled('mandala')) {
        const mandala_tls = `mandala://${ctx.dynamicUUID}@${hostName}:${httpsPorts[0]}?security=tls&sni=${hostName}&type=ws&host=${hostName}&path=${encodeURIComponent(path)}#${hostName}-MANDALA-TLS`;
        nodeDetailsHtml += getSectionHtml('Mandala TLS', getCopyBtnHtml(mandala_tls));
        activeProtocols.push('Mandala');
    }

    // Shadowsocks
    if (isEnabled('ss')) {
        const ss_b64 = btoa(`none:${ctx.dynamicUUID}`);
        const ss_tls = `ss://${ss_b64}@${hostName}:${httpsPorts[0]}/?plugin=${encodeURIComponent(`v2ray-plugin;tls;host=${hostName};sni=${hostName};path=${encodeURIComponent(path)}`)}#${hostName}-SS-TLS`;
        nodeDetailsHtml += getSectionHtml('Shadowsocks TLS', getCopyBtnHtml(ss_tls));
        activeProtocols.push('SS');
    }

    // Socks5
    if (isEnabled('socks5')) {
        const socks_auth = btoa(`${ctx.userID}:${ctx.dynamicUUID}`);
        const socks_tls = `socks://${socks_auth}@${hostName}:${httpsPorts[0]}?transport=ws&security=tls&sni=${hostName}&path=${encodeURIComponent(path)}#${hostName}-SOCKS-TLS`;
        nodeDetailsHtml += getSectionHtml('Socks5 TLS', getCopyBtnHtml(socks_tls));
        activeProtocols.push('Socks5');
    }

    // XHTTP
    if (isEnabled('xhttp')) {
        const xhttp_tls = `vless://${ctx.userID}@${hostName}:${httpsPorts[0]}?encryption=none&security=tls&sni=${hostName}&fp=random&allowInsecure=1&type=xhttp&host=${hostName}&path=${encodeURIComponent('/' + ctx.userID.substring(0, 8))}&mode=stream-one#${hostName}-XHTTP-TLS`;
        // XHTTP 结构比较特殊，手动拼接或复用 getSectionHtml 均可
        const content = `<h3>Vless+xhttp+tls</h3>` +
            `<div class="input-group mb-3"><input type="text" class="form-control" value="${xhttp_tls}" readonly><button class="btn btn-outline-secondary" onclick="copyToClipboard('${xhttp_tls}')">复制</button></div>`;
        nodeDetailsHtml += `<hr><h2 class="mt-4">XHTTP 节点 (VLESS)</h2>` + content;
        activeProtocols.push('XHTTP');
    }

    const mixedTitle = `混合订阅 (${activeProtocols.join('+')})`;
    const managementPath = '/' + ctx.dynamicUUID.toLowerCase();

    // 调用模板函数生成最终 HTML
    return getHomePageHtml(FileName, mixedTitle, isWorkersDev, subs, nodeDetailsHtml, managementPath);
}
