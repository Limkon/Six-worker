/**
 * 文件名: src/pages/generators.js
 * 修改内容:
 * 1. 修改混合订阅生成逻辑 (Clash/SingBox)，根据 ctx.disabledProtocols 过滤协议。
 * 2. 修复了 XHTTP 协议的 Headers 和 Path 生成。
 * 3. 保持了 Base64 链接生成的原有逻辑。
 * 4. [本次修复] 移除了 XHTTP 链接中的 allowInsecure=1 参数，强制开启证书验证。
 */
import { CONSTANTS } from '../constants.js';

// 辅助函数：生成 Base64 节点链接
export function generateBase64Subscription(protocol, id, hostName, tlsOnly, ctx, noLinks = false) {
    let finalLinks = [];
    const httpPorts = CONSTANTS.HTTP_PORTS;
    const httpsPorts = ctx.httpsPorts;
    const path = '/?ed=2560';

    const createLink = (addr, useTls) => {
        const portList = useTls ? httpsPorts : httpPorts;
        const match = addr.match(/^(.*?)(?::(\d+))?(?:#(.*))?$/);
        if (!match) return;
        
        const ip = match[1];
        const port = match[2] || portList[0];
        const remark = match[3] || `${hostName}-${protocol.toUpperCase()}`;
        
        if (protocol === 'xhttp') {
             const xhttpPath = '/' + id.substring(0, 8);
             // [修复] 移除 allowInsecure=1，确保安全
             finalLinks.push(`vless://${id}@${ip}:${port}?encryption=none&security=tls&sni=${hostName}&fp=random&type=xhttp&host=${hostName}&path=${encodeURIComponent(xhttpPath)}&mode=stream-one#${encodeURIComponent(remark)}`);
        } else if (protocol === 'vless') {
             const security = useTls ? `&security=tls&sni=${hostName}&fp=random` : '&security=none';
             finalLinks.push(`vless://${id}@${ip}:${port}?encryption=none${security}&type=ws&host=${hostName}&path=${encodeURIComponent(path)}#${encodeURIComponent(remark)}`);
        } else if (protocol === 'trojan') {
             const security = useTls ? `&security=tls&sni=${hostName}&fp=random` : '&security=none';
             finalLinks.push(`trojan://${id}@${ip}:${port}?${security}&type=ws&host=${hostName}&path=${encodeURIComponent(path)}#${encodeURIComponent(remark)}`);
        } else if (protocol === 'mandala') {
             const security = useTls ? `&security=tls&sni=${hostName}` : '';
             finalLinks.push(`mandala://${id}@${ip}:${port}?type=ws&host=${hostName}&path=${encodeURIComponent(path)}${security}#${encodeURIComponent(remark)}`);
        } else if (protocol === 'ss') {
             const ss_method = 'none';
             const ss_b64 = btoa(`${ss_method}:${id}`);
             let plugin_opts = `v2ray-plugin;host=${hostName};path=${encodeURIComponent(path)}`;
             if (useTls) plugin_opts += `;tls;sni=${hostName}`;
             finalLinks.push(`ss://${ss_b64}@${ip}:${port}/?plugin=${encodeURIComponent(plugin_opts)}#${encodeURIComponent(remark)}`);
        } else if (protocol === 'socks') {
             const security = useTls ? `security=tls&sni=${hostName}&path=${encodeURIComponent(path)}` : `path=${encodeURIComponent(path)}`;
             const password = ctx.dynamicUUID || ctx.userID;
             const auth = btoa(`${id}:${password}`);
             finalLinks.push(`socks://${auth}@${ip}:${port}?${security}&transport=ws#${encodeURIComponent(remark)}`);
        }
    };

    if (ctx.addresses) ctx.addresses.forEach(addr => createLink(addr, true));
    if (!tlsOnly && ctx.addressesnotls) ctx.addressesnotls.forEach(addr => createLink(addr, false));

    if (!noLinks && protocol !== 'xhttp' && ctx.hardcodedLinks) {
        finalLinks = finalLinks.concat(ctx.hardcodedLinks);
    }

    return finalLinks.join('\n');
}

// 生成 Clash 配置 (单协议)
export function generateClashConfig(protocol, id, hostName, tlsOnly, ctx) {
    let proxies = [];
    const proxyNames = [];
    const httpPorts = CONSTANTS.HTTP_PORTS;
    const httpsPorts = ctx.httpsPorts;
    const path = '/?ed=2560';
    
    const createProxy = (addr, useTls) => {
        const portList = useTls ? httpsPorts : httpPorts;
        const match = addr.match(/^(.*?)(?::(\d+))?(?:#(.*))?$/);
        if (!match) return;

        const ip = match[1];
        const port = match[2] || portList[0];
        const remark = match[3] || `${hostName}-${protocol.toUpperCase()}`;
        
        let proxy = {
            name: remark,
            type: protocol === 'xhttp' ? 'vless' : (protocol === 'ss' ? 'ss' : (protocol === 'socks' ? 'socks5' : protocol)),
            server: ip,
            port: parseInt(port),
            tls: useTls,
            'skip-cert-verify': true,
            udp: false
        };

        if (protocol === 'vless' || protocol === 'xhttp') {
            proxy.uuid = id;
            proxy.cipher = 'auto';
        } else if (protocol === 'trojan') {
            proxy.password = id;
        } else if (protocol === 'ss') {
            proxy.cipher = 'none';
            proxy.password = id;
            proxy.plugin = 'v2ray-plugin';
            proxy['plugin-opts'] = {
                mode: 'websocket',
                tls: useTls,
                host: hostName,
                path: path
            };
            if (useTls) proxy['plugin-opts'].sni = hostName;
        } else if (protocol === 'socks') {
            proxy.username = id;
            proxy.password = ctx.dynamicUUID || ctx.userID;
        } 

        if (protocol === 'xhttp') {
            proxy.network = 'xhttp';
            proxy['xhttp-opts'] = {
                mode: 'stream-one',
                path: '/' + id.substring(0, 8),
                headers: {
                    'Host': hostName,
                    'Content-Type': 'application/grpc',
                    'User-Agent': 'Go-http-client/2.0'
                }
            };
            proxy.servername = hostName;
        } else if (protocol !== 'ss' && protocol !== 'mandala') { 
            proxy.network = 'ws';
            proxy['ws-opts'] = {
                path: path,
                headers: { Host: hostName }
            };
            if (useTls) proxy.servername = hostName;
        }

        if (protocol !== 'mandala') {
            proxies.push(proxy);
            proxyNames.push(remark);
        }
    };

    if (ctx.addresses) ctx.addresses.forEach(addr => createProxy(addr, true));
    if (!tlsOnly && ctx.addressesnotls) ctx.addressesnotls.forEach(addr => createProxy(addr, false));

    return buildClashYaml(proxies, proxyNames);
}

// 生成混合 Clash 配置 (自动过滤禁用协议)
export function generateMixedClashConfig(vlessId, trojanPass, hostName, tlsOnly, enableXhttp, ctx) {
    let proxies = [];
    const proxyNames = [];
    const httpPorts = CONSTANTS.HTTP_PORTS;
    const httpsPorts = ctx.httpsPorts;
    const path = '/?ed=2560';

    const createMixedProxy = (protocol, addr, useTls) => {
        const portList = useTls ? httpsPorts : httpPorts;
        const match = addr.match(/^(.*?)(?::(\d+))?(?:#(.*))?$/);
        if (!match) return;

        const ip = match[1];
        const port = match[2] || portList[0];
        const remark = match[3] ? `${protocol.toUpperCase()}-${match[3]}` : `${hostName}-${protocol.toUpperCase()}`;
        
        let proxy = {
            name: remark,
            type: protocol === 'xhttp' ? 'vless' : (protocol === 'ss' ? 'ss' : (protocol === 'socks' ? 'socks5' : protocol)),
            server: ip,
            port: parseInt(port),
            tls: useTls,
            'skip-cert-verify': true,
            udp: false
        };

        if (protocol === 'vless' || protocol === 'xhttp') {
            proxy.uuid = vlessId;
            proxy.cipher = 'auto';
        } else if (protocol === 'trojan') {
            proxy.password = trojanPass;
        } else if (protocol === 'ss') {
            proxy.cipher = 'none';
            proxy.password = trojanPass;
            proxy.plugin = 'v2ray-plugin';
            proxy['plugin-opts'] = {
                mode: 'websocket',
                tls: useTls,
                host: hostName,
                path: path
            };
            if (useTls) proxy['plugin-opts'].sni = hostName;
        } else if (protocol === 'socks') {
            proxy.username = vlessId;
            proxy.password = trojanPass;
        }

        if (protocol === 'xhttp') {
            proxy.network = 'xhttp';
            proxy['xhttp-opts'] = {
                mode: 'stream-one',
                path: '/' + vlessId.substring(0, 8),
                headers: {
                    'Host': hostName,
                    'Content-Type': 'application/grpc',
                    'User-Agent': 'Go-http-client/2.0'
                }
            };
            proxy.servername = hostName;
        } else if (protocol !== 'ss') {
            proxy.network = 'ws';
            proxy['ws-opts'] = {
                path: path,
                headers: { Host: hostName }
            };
            if (useTls) proxy.servername = hostName;
        }

        proxies.push(proxy);
        proxyNames.push(remark);
    };

    // [修改] 定义协议列表并过滤禁用的协议
    let protocols = ['vless', 'trojan', 'ss', 'socks', 'xhttp'];
    
    protocols = protocols.filter(p => {
        // 如果 disabledProtocols 包含该协议名，则过滤掉
        // 注意: Socks5 可能被配置为 'socks5' 或 'socks'，这里做宽泛匹配
        if (ctx.disabledProtocols.includes(p)) return false;
        if (p === 'socks' && ctx.disabledProtocols.includes('socks5')) return false;
        return true;
    });

    if (ctx.addresses) {
        ctx.addresses.forEach(addr => {
            protocols.forEach(p => {
                if (p === 'xhttp') createMixedProxy(p, addr, true);
                else createMixedProxy(p, addr, true);
            });
        });
    }
    
    if (!tlsOnly && ctx.addressesnotls) {
        ctx.addressesnotls.forEach(addr => {
            protocols.forEach(p => {
                if (p !== 'xhttp') createMixedProxy(p, addr, false);
            });
        });
    }

    return buildClashYaml(proxies, proxyNames);
}

// 辅助函数: 构建 Clash YAML 字符串
function buildClashYaml(proxies, proxyNames) {
    const yamlProxies = proxies.map(p => {
        let s = `- name: ${p.name}\n  type: ${p.type}\n  server: ${p.server}\n  port: ${p.port}\n  tls: ${p.tls}\n  udp: ${p.udp}\n  skip-cert-verify: true\n`;
        if(p.uuid) s += `  uuid: ${p.uuid}\n`;
        if(p.password) s += `  password: "${p.password}"\n`;
        if(p.username) s += `  username: "${p.username}"\n`;
        if(p.cipher) s += `  cipher: ${p.cipher}\n`;
        if(p.network) s += `  network: ${p.network}\n`;
        if(p.servername) s += `  servername: ${p.servername}\n`;
        if(p['ws-opts']) {
            s += `  ws-opts:\n    path: "${p['ws-opts'].path}"\n    headers:\n      Host: ${p['ws-opts'].headers.Host}\n`;
        }
        if(p['xhttp-opts']) {
            s += `  xhttp-opts:\n    mode: ${p['xhttp-opts'].mode}\n    path: "${p['xhttp-opts'].path}"\n    headers:\n      Host: ${p['xhttp-opts'].headers.Host}\n      Content-Type: ${p['xhttp-opts'].headers['Content-Type']}\n      User-Agent: ${p['xhttp-opts'].headers['User-Agent']}\n`;
        }
        if(p.plugin) {
            s += `  plugin: ${p.plugin}\n  plugin-opts:\n    mode: ${p['plugin-opts'].mode}\n    tls: ${p['plugin-opts'].tls}\n    host: ${p['plugin-opts'].host}\n    path: "${p['plugin-opts'].path}"\n`;
            if (p['plugin-opts'].sni) s += `    sni: ${p['plugin-opts'].sni}\n`;
        }
        return s;
    }).join('');

    return `port: 7890
allow-lan: true
mode: rule
log-level: info
proxies:
${yamlProxies}
proxy-groups:
- name: 节点选择
  type: select
  proxies:
  - 自动选择
  - DIRECT
${proxyNames.map(n => `  - ${n}`).join('\n')}
- name: 自动选择
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
${proxyNames.map(n => `  - ${n}`).join('\n')}
rules:
- MATCH,节点选择`;
}

// 生成 SingBox 配置 (单协议)
export function generateSingBoxConfig(protocol, id, hostName, tlsOnly, ctx) {
    if (protocol === 'mandala') return '{}'; // Mandala 暂不支持 SingBox
    return generateMixedSingBoxConfig(id, ctx.dynamicUUID, hostName, tlsOnly, false, ctx, [protocol]);
}

// 生成混合 SingBox 配置
export function generateMixedSingBoxConfig(vlessId, trojanPass, hostName, tlsOnly, enableXhttp, ctx, protocolsFilter = null) {
    let outbounds = [];
    const httpPorts = CONSTANTS.HTTP_PORTS;
    const httpsPorts = ctx.httpsPorts;
    const path = '/?ed=2560';

    const createMixedOutbound = (protocol, addr, useTls) => {
        const portList = useTls ? httpsPorts : httpPorts;
        const match = addr.match(/^(.*?)(?::(\d+))?(?:#(.*))?$/);
        if (!match) return;

        const ip = match[1];
        const port = match[2] || portList[0];
        const remark = match[3] ? `${protocol.toUpperCase()}-${match[3]}` : `${hostName}-${protocol.toUpperCase()}`;
        
        let outbound = {
            type: protocol === 'xhttp' ? 'vless' : (protocol === 'ss' ? 'shadowsocks' : (protocol === 'socks' ? 'socks5' : protocol)),
            tag: remark,
            server: ip,
            server_port: parseInt(port)
        };

        if (protocol === 'vless' || protocol === 'xhttp') {
            outbound.uuid = vlessId;
            outbound.packet_encoding = "packetaddr";
        } else if (protocol === 'trojan') {
            outbound.password = trojanPass;
        } else if (protocol === 'ss') {
            outbound.method = 'none';
            outbound.password = trojanPass;
        } else if (protocol === 'socks') {
            outbound.username = vlessId;
            outbound.password = trojanPass;
        }

        if (protocol === 'xhttp') {
            outbound.transport = {
                type: 'xhttp',
                mode: 'stream-one',
                path: '/' + vlessId.substring(0, 8),
                headers: { 
                    Host: hostName,
                    "Content-Type": "application/grpc",
                    "User-Agent": "Go-http-client/2.0"
                }
            };
        } else {
             outbound.transport = {
                type: 'ws',
                path: path,
                headers: { Host: hostName }
            };
        }

        if (useTls) {
            outbound.tls = {
                enabled: true,
                server_name: hostName,
                insecure: true,
                utls: { enabled: true, fingerprint: "chrome" }
            };
        }

        outbounds.push(outbound);
    };

    // [修改] 协议过滤逻辑
    let protocols = [];
    if (protocolsFilter) {
        protocols = protocolsFilter;
    } else {
        const all = ['vless', 'trojan', 'ss', 'socks', 'xhttp'];
        protocols = all.filter(p => {
             if (ctx.disabledProtocols.includes(p)) return false;
             if (p === 'socks' && ctx.disabledProtocols.includes('socks5')) return false;
             return true;
        });
    }

    if (ctx.addresses) {
        ctx.addresses.forEach(addr => {
            protocols.forEach(p => {
                if (p === 'xhttp') createMixedOutbound(p, addr, true);
                else createMixedOutbound(p, addr, true);
            });
        });
    }
    
    if (!tlsOnly && ctx.addressesnotls) {
        ctx.addressesnotls.forEach(addr => {
            protocols.forEach(p => {
                if (p !== 'xhttp') createMixedOutbound(p, addr, false);
            });
        });
    }

    const tags = outbounds.map(o => o.tag);

    return JSON.stringify({
        "log": {"level": "info"},
        "inbounds": [{"type": "tun", "tag": "tun-in"}],
        "outbounds": [
            {
                "type": "selector",
                "tag": "select",
                "outbounds": ["auto", "direct", ...tags]
            },
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": tags,
                "url": "http://www.gstatic.com/generate_204"
            },
            { "type": "direct", "tag": "direct" },
            ...outbounds
        ],
        "route": {
            "final": "select",
            "rules": [
                {"protocol": "dns", "outbound": "direct"}
            ]
        }
    }, null, 2);
}
