/**
 * 文件名: src/pages/admin.js
 * 说明: 
 * 1. [新增] 引入 executeWebDavPush，实现配置变更后自动触发 WebDAV 推送。
 * 2. [修复] 修复 BestIP 在线优选功能中加载 IPv6 CIDR (如 Cloudflare 官方列表) 失败的问题。
 */
import { getConfig, cleanConfigCache, initializeContext } from '../config.js'; 
import { CONSTANTS } from '../constants.js';
import { cleanList } from '../utils/helpers.js';
import { getAdminConfigHtml, getBestIPHtml } from '../templates/admin.js';
import { executeWebDavPush } from '../handlers/webdav.js';

// 处理 /edit 页面 (配置编辑器)
export async function handleEditConfig(request, env, ctx) {
    const FileName = await getConfig(env, 'SUBNAME', 'sub');
    
    if (!env.KV) {
        return new Response('<p>错误：未绑定KV空间，无法使用在线配置功能。</p>', { status: 404, headers: { "Content-Type": "text/html;charset=utf-8" } });
    }

    // 定义配置项列表
    const configItems = [
        ['ADMIN_PASS', '后台管理访问密码', '设置后，通过 /KEY 路径访问管理页需输入此密码。留空则不开启验证。', '例如: 123456', 'text'],
        ['UUID', 'UUID (用户ID/密码)', 'VLESS的用户ID, 也是Trojan/SS的密码。', '例如: 1234567', 'text'],
        ['KEY', '动态UUID密钥', '用于生成动态UUID, 填写后将覆盖上方静态UUID。', '例如: my-secret-key', 'text'],
        ['TIME', '动态UUID有效时间 (天)', '动态UUID的有效周期, 单位为天。', '例如: 1 (表示1天)', 'number'],
        ['UPTIME', '动态UUID更新时间 (小时)', '动态UUID在周期的第几个小时更新。', '例如: 0 (表示0点)', 'number'],
        ['PROXYIP', '出站代理IP (ProxyIP)', 'Worker访问目标网站时使用的IP, 多个用逗号隔开。', '例如: 1.2.3.4 或 [2606::]', 'text'],
        ['SUBNAME', '订阅文件名 (FileName)', '订阅链接下载时的文件名前缀。', '例如: sub.txt', 'text'],
        ['ADD.txt', '优选IP列表 (ADD.txt)', '订阅节点使用的地址列表, 一行一个。', 'usa.visa.com#备注\n1.2.3.4:8443#备注\n[2606:4700::]:2053#IPv6', 'textarea'],
        ['ADDAPI', '优选IP API (ADDAPI)', '远程优选IP列表(TXT格式)的下载链接。', 'https://example.com/ips.txt', 'text'],
        ['ADDNOTLS', '非TLS节点 (ADDNOTLS)', '手动添加非TLS节点(80端口等)。', 'www.example.com:80#备注', 'textarea'],
        ['ADDNOTLSAPI', '非TLS API (ADDNOTLSAPI)', '远程非TLS节点列表的下载链接。', 'https://example.com/notls.txt', 'text'],
        ['ADDCSV', 'CSV测速文件 (ADDCSV)', 'CloudflareSpeedTest 测速结果 CSV 文件的链接。', 'https://example.com/result.csv', 'text'],
        ['CFPORTS', 'CF端口 (httpsPorts)', 'Cloudflare支持的TLS端口, 逗号隔开。', '443,8443,2053,2083,2087,2096', 'text'],
        ['DIS', '禁用协议', '填入需要关闭的协议(VLESS, Trojan, XHTTP等), 英文逗号分隔, 不区分大小写。默认全部开启，pages不支持XHTTP。', '例如: XHTTP, SOCKS5', 'text'],
        ['DNS64', 'NAT64服务器', '用于将IPv4转为IPv6访问 (如无可留空)。', '例如: 64:ff9b::/96', 'text'],
        ['SOCKS5', 'SOCKS5/HTTP代理', 'Worker出站时使用的前置代理 (如无可留空)。', 'user:pass@host:port 或 http://user:pass@host:port', 'text'],
        ['GO2SOCKS5', 'SOCKS5分流规则', '哪些域名走SOCKS5代理, 逗号隔开。', '*example.net,*example.com,all in', 'text'],
        ['BAN', '禁止访问的域名', '禁止通过Worker代理访问的域名, 逗号隔开。', 'example.com,example.org', 'text'],
        // WebDAV 选项已移除，实现静默处理
        ['URL302', '根路径跳转URL (302)', '访问根路径 / 时跳转到的地址。', 'https://github.com/', 'text'],
        ['URL', '根路径反代URL', '访问根路径 / 时反代的地址 (302优先)。', 'https://github.com/', 'text'],
        ['BESTIP_SOURCES', 'BestIP IP源', '自定义BestIP页面的IP源列表 (格式: 名称 网址，每行一个)。', 
`CF官方 https://www.cloudflare.com/ips-v4/`, 'textarea'],
    ];

    // 处理 POST 保存请求
    if (request.method === 'POST') {
        try {
            const formData = await request.formData();
            const savePromises = [];
            for (const [key] of configItems) {
                const value = formData.get(key);
                if (value !== null) {
                    if (value === '') {
                        savePromises.push(env.KV.delete(key));
                    } else {
                        if (key === 'BESTIP_SOURCES') {
                            const lines = value.split('\n');
                            for (let i = 0; i < lines.length; i++) {
                                const line = lines[i].trim();
                                if (!line) continue;
                                const parts = line.split(/\s+/);
                                if (parts.length < 2) {
                                    return new Response(`保存失败: BestIP IP源 格式错误 (第${i + 1}行)。应为: 名称 网址`, { status: 400 });
                                }
                            }
                        }
                        savePromises.push(env.KV.put(key, value));
                    }
                }
            }
            await Promise.all(savePromises);
            
            cleanConfigCache();

            // [新增] 配置变更后，触发 WebDAV 推送
            // 因为配置变了，订阅内容也会变，所以这里使用 force=true 强制推送
            try {
                const appCtx = await initializeContext(request, env);
                appCtx.waitUntil = ctx.waitUntil.bind(ctx);
                ctx.waitUntil(executeWebDavPush(env, appCtx, true));
                // console.log('[Admin] Config updated, triggered WebDAV push.'); // 静默
            } catch (err) {
                console.error('[Admin] Failed to trigger WebDAV push:', err);
            }

            return new Response('保存成功', { status: 200 });
        } catch (e) {
            return new Response('保存失败: ' + e.message, { status: 500 });
        }
    }
    
    // 处理 GET 渲染页面
    const remoteConfig = {}; 
    const kvPromises = configItems.map(item => env.KV.get(item[0]));
    const kvValues = await Promise.all(kvPromises);
    let formHtml = '';
    
    configItems.forEach(([key, label, desc, placeholder, type], index) => {
        const kvValue = kvValues[index];
        const envValue = env[key];
        let displayValue = kvValue ?? '';
        
        if (kvValue === null) {
             if (key === 'BESTIP_SOURCES') displayValue = placeholder;
        }
        
        let envHint = '';
        if (key !== 'ADD.txt' && key !== 'BESTIP_SOURCES') {
            if (envValue) envHint = `<div class="env-hint">环境变量: <code>${envValue}</code></div>`;
        }
        
        const escapeHtml = (str) => { if (!str) return ''; return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;'); };
        let inputField = '';
        if (type === 'textarea') {
            const rows = (key === 'BESTIP_SOURCES' || key === 'ADD.txt' || key === 'ADDNOTLS') ? 8 : 4;
            inputField = `<textarea class="form-control" id="${key}" name="${key}" rows="${rows}" placeholder="${escapeHtml(placeholder)}">${escapeHtml(displayValue)}</textarea>`;
        } else {
            inputField = `<input type="${type}" class="form-control" id="${key}" name="${key}" value="${escapeHtml(displayValue)}" placeholder="${escapeHtml(placeholder)}">`;
        }
        formHtml += `<div class="mb-3"><label for="${key}" class="form-label">${label}</label>${inputField}<div class="form-text">${desc} (留空则使用环境变量或默认值)</div>${envHint}</div><hr>`;
    });

    return new Response(getAdminConfigHtml(FileName, formHtml), { headers: { "Content-Type": "text/html;charset=utf-8" } });
}

export async function handleBestIP(request, env) {
    const url = new URL(request.url);
    const txt = 'ADD.txt';

    // 1. 处理测试请求 API
    if (url.searchParams.get('action') === 'test') {
        const ip = url.searchParams.get('ip');
        const port = url.searchParams.get('port');
        if (!ip || !port) {
            return new Response(JSON.stringify({ error: 'Missing ip or port' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }
        const testUrl = 'https://cloudflare.com/cdn-cgi/trace';
        const startTime = Date.now();
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 2000);
            const response = await fetch(testUrl, {
                method: "GET",
                headers: { "Accept": "text/plain" },
                signal: controller.signal,
                resolveOverride: ip
            });
            clearTimeout(timeoutId);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const traceText = await response.text();
            const latency = Date.now() - startTime;
            const coloMatch = traceText.match(/colo=([A-Z]{3})/);
            const result = {
                ip: ip,
                port: port,
                latency: latency,
                colo: coloMatch ? coloMatch[1] : "N/A"
            };
            return new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } });
        } catch (e) {
            return new Response(JSON.stringify({
                ip: ip,
                port: port,
                latency: 9999,
                colo: "FAIL"
            }), { headers: { 'Content-Type': 'application/json' } });
        }
    }
    
    // 2. 处理保存请求 API
    if (request.method === "POST") {
        if (!env.KV) return new Response(JSON.stringify({ error: '未绑定KV空间' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        try {
            const data = await request.json();
            const action = url.searchParams.get('action') || 'save';
            if (action === 'append') {
                const existing = await env.KV.get(txt) || '';
                const newContent = [...new Set([...existing.split('\n'), ...data.ips].filter(Boolean))].join('\n');
                await env.KV.put(txt, newContent);
                return new Response(JSON.stringify({ success: true, message: '追加成功' }), { headers: { 'Content-Type': 'application/json' } });
            } else {
                await env.KV.put(txt, data.ips.join('\n'));
                return new Response(JSON.stringify({ success: true, message: '保存成功' }), { headers: { 'Content-Type': 'application/json' } });
            }
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
        }
    }

    // 3. 处理 IP 源加载 API
    const defaultIpSources = [
        {"name": "CF官方", "url": "https://www.cloudflare.com/ips-v4/"}
    ];
    let ipSources = defaultIpSources;
    if (env.KV) {
        const kvData = await env.KV.get('BESTIP_SOURCES');
        const remoteData = await getConfig(env, 'BESTIP_SOURCES'); 
        const sourceData = kvData || remoteData;

        if (sourceData) {
            try {
                if (sourceData.trim().startsWith('[')) {
                     try {
                        const parsed = JSON.parse(sourceData);
                        if (Array.isArray(parsed)) ipSources = parsed;
                     } catch(e) {}
                } else {
                    const lines = sourceData.split('\n');
                    const parsedSources = [];
                    for (const line of lines) {
                        const parts = line.trim().split(/\s+/);
                        if (parts.length >= 2) {
                            const url = parts.pop();
                            const name = parts.join(' ');
                            if (url && name) parsedSources.push({ name, url });
                        }
                    }
                    if (parsedSources.length > 0) ipSources = parsedSources;
                }
            } catch (e) { console.error("解析 BESTIP_SOURCES 失败"); }
        }
    }
    const allIpSources = [...ipSources, {"name": "反代IP列表", "url": "proxyip"}];

    if (url.searchParams.has('loadIPs')) {
        const ipSourceName = url.searchParams.get('loadIPs');
        async function GetCFIPs(sourceName) {
             try {
                let response;
                const source = allIpSources.find(s => s.name === sourceName);
                if (sourceName === '反代IP列表') {
                    response = await fetch('https://raw.githubusercontent.com/cmliu/ACL4SSR/main/baipiao.txt');
                    const text = response.ok ? await response.text() : '';
                    return text.split('\n').map(l => l.trim()).filter(Boolean);
                } else if (source) {
                    response = await fetch(source.url);
                } else {
                    response = await fetch(allIpSources[0].url);
                }
                const text = response.ok ? await response.text() : '';
                const cidrs = text.split('\n').filter(line => line.trim() && !line.startsWith('#'));
                const ips = new Set();
                while (ips.size < 512 && cidrs.length > 0) {
                    for (const cidr of cidrs) {
                        if (ips.size >= 512) break;
                        try {
                            if (!cidr.includes('/')) { ips.add(cidr); continue; }
                            const [network, prefixStr] = cidr.split('/');
                            
                            // [新增] IPv6 兼容逻辑：如果是 IPv6 CIDR，直接添加网络地址部分用于测试
                            if (network.includes(':')) {
                                ips.add(network);
                                continue;
                            }
                            
                            const prefix = parseInt(prefixStr);
                            if (prefix < 12 || prefix > 31) continue;
                            const ipToInt = (ip) => ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
                            const intToIp = (int) => [(int >>> 24) & 255, (int >>> 16) & 255, (int >>> 8) & 255, int & 255].join('.');
                            const networkInt = ipToInt(network);
                            const hostBits = 32 - prefix;
                            const numHosts = 1 << hostBits;
                            if (numHosts > 2) {
                                const randomOffset = Math.floor(Math.random() * (numHosts - 2)) + 1;
                                ips.add(intToIp(networkInt + randomOffset));
                            }
                        } catch (e) {}
                    }
                    if (cidrs.length === 0) break;
                }
                return Array.from(ips);
            } catch (error) { return []; }
        }
        const ips = await GetCFIPs(ipSourceName);
        return new Response(JSON.stringify({ ips }), { headers: { 'Content-Type': 'application/json' } });
    }

    const ipSourceOptions = allIpSources.map(s => `<option value="${s.name}">${s.name}</option>`).join('\n');
    
    return new Response(getBestIPHtml(ipSourceOptions), { headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
}
