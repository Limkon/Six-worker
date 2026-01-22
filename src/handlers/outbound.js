// src/handlers/outbound.js

/**
 * 文件名: src/handlers/outbound.js
 * 修复说明:
 * 1. [Strict Mode] 当直连失败回退到 ProxyIP 时，实施严格策略：
 * - 强制端口 443：非 443 端口不使用 ProxyIP。
 * - 禁止轮询：移除 proxyIPList 随机逻辑，仅使用单一 ctx.proxyIP。
 * - 禁止重试：单次尝试失败即终止。
 * 2. [Verified] 保留原有的 IPv6 格式修复和 Socket 安全逻辑。
 */
import { connect } from 'cloudflare:sockets';
import { CONSTANTS } from '../constants.js';
import { resolveToIPv6, parseIPv6 } from '../utils/dns.js';
import { safeCloseWebSocket, isHostBanned } from '../utils/helpers.js';

/**
 * 判断目标是否为 Cloudflare CDN/Worker/Pages 域名
 */
function isCloudflareCDN(host) {
    if (!host) return false;
    const h = host.toLowerCase();
    const cfDomains = [
        'workers.dev', 'pages.dev', 'cloudflare.com', 'cloudflare.net',
        'discord.gg', 'discordapp.com'
    ];
    return cfDomains.some(d => h === d || h.endsWith('.' + d));
}

/**
 * 解析 ProxyIP 字符串，提取 host 和 port
 */
function parseProxyIP(proxyAddr, defaultPort) {
    if (!proxyAddr) return { host: CONSTANTS.DEFAULT_PROXY_IP.split(',')[0].trim(), port: defaultPort };
    
    let host = proxyAddr;
    let port = defaultPort;
    
    // 1. 处理带中括号的 IPv6
    if (host.startsWith('[')) {
        const bracketEnd = host.lastIndexOf(']');
        if (bracketEnd === -1) {
            return { host: host, port: defaultPort };
        }
        
        if (bracketEnd > 0) {
            const remainder = host.substring(bracketEnd + 1);
            if (remainder.startsWith(':')) {
                const portStr = remainder.substring(1);
                if (/^\d+$/.test(portStr)) port = parseInt(portStr, 10);
            }
            host = host.substring(1, bracketEnd);
            return { host, port };
        }
    }
    
    // 2. 处理常规 host:port
    const lastColon = host.lastIndexOf(':');
    if (lastColon > 0 && host.indexOf(':') === lastColon) {
        const portStr = host.substring(lastColon + 1);
        if (/^\d+$/.test(portStr)) {
            port = parseInt(portStr, 10);
            host = host.substring(0, lastColon);
        }
    }
    return { host, port };
}

function shouldUseSocks5(addressRemote, go2socks5) {
    if (!go2socks5 || go2socks5.length === 0) return false;
    if (go2socks5.includes('all in') || go2socks5.includes('*')) return true;
    return go2socks5.some(pattern => {
        let regexPattern = pattern.replace(/\*/g, '.*');
        let regex = new RegExp(`^${regexPattern}$`, 'i');
        return regex.test(addressRemote);
    });
}

function parseSocks5Config(address) {
    if (!address) return null;
    const cleanAddr = address.includes('://') ? address.split('://')[1] : address;
    const lastAtIndex = cleanAddr.lastIndexOf("@");
    let [latter, former] = lastAtIndex === -1 ? [cleanAddr, undefined] : [cleanAddr.substring(lastAtIndex + 1), cleanAddr.substring(0, lastAtIndex)];
    let username, password, hostname, port;
    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) throw new Error('Invalid SOCKS auth format');
        [username, password] = formers;
    }
    const lastColonIndex = latter.lastIndexOf(":");
    if (lastColonIndex === -1) throw new Error('Invalid SOCKS address format, missing port');
    hostname = latter.substring(0, lastColonIndex);
    port = Number(latter.substring(lastColonIndex + 1));
    if (hostname.startsWith('[') && hostname.endsWith(']')) hostname = hostname.slice(1, -1);
    return { username, password, hostname, port };
}

async function socks5Connect(socks5Addr, addressType, addressRemote, portRemote, log) {
    const config = parseSocks5Config(socks5Addr);
    if (!config) throw new Error('Socks5 config missing');
    
    const { username, password, hostname, port } = config;
    const socket = connect({ hostname, port });
    await socket.opened;
    
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    
    // SOCKS5 Hello
    await writer.write(new Uint8Array([5, 1, 2])); 
    let { value: res } = await reader.read();
    
    if (!res || res.length < 2 || res[0] !== 0x05 || res[1] === 0xff) throw new Error('SOCKS5 greeting failed');
    
    // SOCKS5 Auth
    if (res[1] === 0x02) {
        if (!username || !password) throw new Error('SOCKS5 auth required');
        
        const uBytes = encoder.encode(username);
        const pBytes = encoder.encode(password);
        
        const authReq = new Uint8Array([1, uBytes.length, ...uBytes, pBytes.length, ...pBytes]);
        await writer.write(authReq);
        
        const { value: authRes } = await reader.read();
        if (!authRes || authRes.length < 2 || authRes[0] !== 0x01 || authRes[1] !== 0x00) throw new Error('SOCKS5 auth failed');
    }
    
    let DSTADDR;
    switch (addressType) {
        case CONSTANTS.ADDRESS_TYPE_IPV4:
            DSTADDR = new Uint8Array([1, ...addressRemote.split('.').map(Number)]);
            break;
        case CONSTANTS.ADDRESS_TYPE_IPV6:
        case CONSTANTS.ATYP_TROJAN_IPV6:
             const v6Parts = parseIPv6(addressRemote.replace(/[\[\]]/g, ''));
             if (!v6Parts) throw new Error('Invalid IPv6 address');
             const v6Bytes = new Uint8Array(16);
             for (let i = 0; i < 8; i++) {
                 v6Bytes[i * 2] = (v6Parts[i] >> 8) & 0xff;
                 v6Bytes[i * 2 + 1] = v6Parts[i] & 0xff;
             }
             DSTADDR = new Uint8Array([4, ...v6Bytes]);
             break;
        default:
             const domainBytes = encoder.encode(addressRemote);
             DSTADDR = new Uint8Array([3, domainBytes.length, ...domainBytes]);
    }
    
    const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
    await writer.write(socksRequest);
    const { value: connRes } = await reader.read();
    
    if (!connRes || connRes.length < 2 || connRes[0] !== 0x05 || connRes[1] !== 0x00) throw new Error(`SOCKS5 connection failed: ${connRes ? connRes[1] : 'No response'}`);
    
    // 处理 SOCKS5 握手后的早期数据
    let headLen = 0;
    if (connRes.length >= 4) {
        if (connRes[3] === 1) headLen = 10; // IPv4
        else if (connRes[3] === 4) headLen = 22; // IPv6
        else if (connRes[3] === 3) headLen = 7 + connRes[4]; // Domain
    }

    if (headLen > 0 && connRes.length > headLen) {
        socket.initialData = connRes.subarray(headLen);
    }

    writer.releaseLock();
    reader.releaseLock();
    return socket;
}

export async function createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log, fallbackAddress) {
    const useSocks = ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5);
    const STEPPED_TIMEOUTS = [5000, 6000, 7000];
    let attemptCounter = 0;

    // Cloudflare CDN 允许的端口检查（保留，防止 abuse）
    const isCF = isCloudflareCDN(addressRemote);
    if (isCF && portRemote !== 443) {
        throw new Error('Cloudflare CDN allowed only on port 443');
    }

    const connectAndWrite = async (host, port, isSocks) => {
        const currentTimeout = STEPPED_TIMEOUTS[Math.min(attemptCounter, STEPPED_TIMEOUTS.length - 1)];
        attemptCounter++;

        log(`[connect] Target: ${host}:${port} (Socks: ${isSocks}) (Timeout: ${currentTimeout}ms)`);
        
        let isTimedOut = false;
        const timeoutPromise = new Promise((_, reject) => setTimeout(() => {
            isTimedOut = true;
            reject(new Error(`Connect timeout (${currentTimeout}ms)`));
        }, currentTimeout));
        
        let socket;
        try {
            const doConnect = async () => {
                 let s;
                 try {
                     if (isSocks) {
                        s = await socks5Connect(ctx.socks5, addressType, addressRemote, portRemote, log);
                    } else {
                        s = connect({ hostname: host, port: port });
                    }
                 } catch(e) { throw e; }

                 if (isTimedOut) {
                     if (s) {
                         try { s.close(); } catch(e) {}
                         log(`[connect] Late connection to ${host}:${port} closed due to timeout.`);
                     }
                     return null; 
                 }
                 return s;
            };

            socket = await Promise.race([doConnect(), timeoutPromise]);
            
            if (isTimedOut && socket) {
                 try { socket.close(); } catch(e) {}
                 throw new Error(`Connect timeout (${currentTimeout}ms) - closed late socket`);
            }
            if (!socket) throw new Error('Connection failed or timed out');
            if (!isSocks) await Promise.race([socket.opened, timeoutPromise]);
            return socket;
        } catch (err) {
            if (socket) { try { socket.close(); } catch(e) {} }
            throw err;
        }
    };

    // Phase 1: 直连
    try {
        return await connectAndWrite(addressRemote, portRemote, useSocks);
    } catch (err1) {
        log(`[connect] Phase 1 failed: ${err1.message}`);
    }

    // Phase 2: ProxyIP 回退逻辑
    // [Policy] 仅限 443 端口
    if (portRemote === 443) {
        // [Policy] 禁止轮询 / 禁止随机：严格单 IP 模式
        let proxyIP = null;
        if (fallbackAddress) {
            proxyIP = fallbackAddress;
        } else if (ctx.proxyIP) {
            proxyIP = ctx.proxyIP;
        } else {
            // 仅在完全未配置时回退到默认
            const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
            if (defParams.length > 0) proxyIP = defParams[0];
        }

        if (proxyIP) {
            const { host: proxyHost, port: proxyPort } = parseProxyIP(proxyIP, portRemote);
            try {
                // [Policy] 禁止重试：这里只有一次尝试机会
                return await connectAndWrite(proxyHost.toLowerCase(), proxyPort, false);
            } catch (err2) {
                log(`[connect] Phase 2 (ProxyIP: ${proxyHost}) failed: ${err2.message}`);
                // 失败即在此中断，不会再去尝试列表中的其他 IP（因为没有列表了）
            }
        }
    } else {
        log(`[connect] Phase 2 skipped: ProxyIP policy requires port 443 (Target: ${portRemote})`);
    }

    // Phase 3: NAT64 (仅当未使用 Socks5 且 ProxyIP 阶段也失败/跳过时)
    if (!useSocks && ctx.dns64) {
        try {
            log(`[connect] Phase 3: Attempting NAT64...`);
            const v6Address = await resolveToIPv6(addressRemote, ctx.dns64);
            if (v6Address) {
                const nat64IP = v6Address;
                return await connectAndWrite(nat64IP, portRemote, false);
            } else {
                log(`[connect] Phase 3 (NAT64) skipped: DNS resolution failed`);
            }
        } catch (err3) {
            log(`[connect] Phase 3 (NAT64) failed: ${err3.message}`);
        }
    }

    throw new Error(`All connection attempts failed.`);
}

export async function remoteSocketToWS(remoteSocket, webSocket, vlessHeader, retryCallback, log) {
    let hasIncomingData = false;
    let responseHeader = vlessHeader;
    
    if (remoteSocket.initialData && remoteSocket.initialData.byteLength > 0) {
        hasIncomingData = true;
        log(`[Socks5] Flushing ${remoteSocket.initialData.byteLength} bytes of early data`);
        if (responseHeader) {
            const header = responseHeader;
            const data = remoteSocket.initialData;
            const combined = new Uint8Array(header.length + data.length);
            combined.set(header);
            combined.set(data, header.length);
            webSocket.send(combined);
            responseHeader = null;
        } else {
            webSocket.send(remoteSocket.initialData);
        }
        remoteSocket.initialData = null;
    }

    await remoteSocket.readable.pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                hasIncomingData = true;
                if (webSocket.readyState !== 1) { 
                    controller.error(new Error('Client WebSocket closed, stopping remote read'));
                    return;
                }
                if (responseHeader) {
                    const header = responseHeader;
                    const data = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
                    const combined = new Uint8Array(header.length + data.length);
                    combined.set(header);
                    combined.set(data, header.length);
                    webSocket.send(combined);
                    responseHeader = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            close() { log(`Remote socket closed. Data: ${hasIncomingData}`); },
            abort(reason) { console.error('Remote socket aborted', reason); },
        })
    ).catch((error) => {
        if (error.message !== 'webSocket is not open' && error.message !== 'Client WebSocket closed, stopping remote read') {
            console.error('remoteSocketToWS error:', error);
        }
        safeCloseWebSocket(webSocket);
    });
    
    if (!hasIncomingData && retryCallback) {
        log('Retry initiated due to no data');
        try {
            await retryCallback();
        } catch (e) {
            log('Retry failed', e);
            safeCloseWebSocket(webSocket);
        }
    }
}

async function flushBuffer(writer, buffer, log) {
    if (!buffer || buffer.length === 0) return;
    
    log(`Flushing ${buffer.length} buffered chunks`);
    
    while (buffer.length > 0) {
        const batch = [...buffer];
        buffer.length = 0; 
        
        for (const chunk of batch) {
            await writer.write(chunk);
        }
    }
}

export async function handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
    if (isHostBanned(addressRemote, ctx.banHosts)) {
        log(`[Outbound] Host banned: ${addressRemote}`);
        safeCloseWebSocket(webSocket);
        return;
    }

    const prepareRetry = () => {
        remoteSocketWrapper.value = null;
        remoteSocketWrapper.isConnecting = true;
    };
    
    const finalizeConnection = (socket) => {
        remoteSocketWrapper.value = socket;
        remoteSocketWrapper.isConnecting = false;
    };

    const nat64Retry = async () => {
        if (!ctx.dns64) { safeCloseWebSocket(webSocket); return; }
        log('[Retry] Switching to NAT64...');
        prepareRetry(); 
        try {
            const v6Address = await resolveToIPv6(addressRemote, ctx.dns64);
            if (!v6Address) throw new Error('DNS64 resolution failed');
            const nat64IP = v6Address;
            const natSocket = await connect({ hostname: nat64IP, port: portRemote });
            const writer = natSocket.writable.getWriter();
            if (rawClientData && rawClientData.byteLength > 0) {
                await writer.write(rawClientData);
            }
            await flushBuffer(writer, remoteSocketWrapper.buffer, log);
            writer.releaseLock();
            finalizeConnection(natSocket);
            remoteSocketToWS(natSocket, webSocket, vlessResponseHeader, null, log);
        } catch (e) {
            log('[Retry] NAT64 failed: ' + e.message);
            safeCloseWebSocket(webSocket);
        }
    };

    const proxyIPRetry = async () => {
        // [Policy] 强制端口 443
        if (portRemote !== 443) {
            log(`[Retry] ProxyIP skipped: Port ${portRemote} is not 443`);
            // 如果不能用 ProxyIP，看是否可以用 NAT64
            if (ctx.dns64 && !(ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5))) {
                await nat64Retry();
            } else {
                safeCloseWebSocket(webSocket);
            }
            return;
        }

        // CF CDN 域名禁止 Retry (双重保险)
        if (isCloudflareCDN(addressRemote)) {
            log(`[Retry] Cloudflare CDN (${addressRemote}) target - Retry disabled.`);
            safeCloseWebSocket(webSocket);
            return;
        }

        log('[Retry] Switching to ProxyIP...');
        prepareRetry(); 

        // [Policy] 禁止轮询 / 禁止随机：严格单 IP 模式
        let proxyIP = ctx.proxyIP;
        if (!proxyIP) {
             const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
             if (defParams.length > 0) proxyIP = defParams[0];
        }

        if (proxyIP) {
            try {
                const { host: proxyHost, port: proxyPort } = parseProxyIP(proxyIP, portRemote);
                log(`[Retry] Attempting ProxyIP: ${proxyHost}`);
                
                const proxySocket = await connect({ hostname: proxyHost.toLowerCase(), port: proxyPort });
                
                const writer = proxySocket.writable.getWriter();
                if (rawClientData && rawClientData.byteLength > 0) {
                    await writer.write(rawClientData);
                }
                await flushBuffer(writer, remoteSocketWrapper.buffer, log);
                writer.releaseLock();
                
                finalizeConnection(proxySocket);
                
                const useSocks = ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5);
                const nextRetry = (!useSocks && ctx.dns64) ? nat64Retry : null;
                
                remoteSocketToWS(proxySocket, webSocket, vlessResponseHeader, nextRetry, log);
                return; 
            } catch (e) {
                log(`[Retry] ProxyIP failed: ${e.message}`);
                // [Policy] 禁止重试：失败即止，不循环，直接去尝试 NAT64 或断开
            }
        }

        if (ctx.dns64 && !(ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5))) {
            await nat64Retry();
        } else {
            safeCloseWebSocket(webSocket);
        }
    };

    try {
        const socket = await createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log);
        
        const writer = socket.writable.getWriter();
        if (rawClientData && rawClientData.byteLength > 0) {
            await writer.write(rawClientData);
        }
        await flushBuffer(writer, remoteSocketWrapper.buffer, log);
        writer.releaseLock();
        
        finalizeConnection(socket);
        
        remoteSocketToWS(socket, webSocket, vlessResponseHeader, proxyIPRetry, log);
    } catch (error) {
        log('[Outbound] Initial connection failed: ' + error.message);
        safeCloseWebSocket(webSocket);
    }
}
