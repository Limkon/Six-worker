// src/handlers/outbound.js

/**
 * 文件名: src/handlers/outbound.js
 * 修改说明:
 * 1. [架构优化] 明确将 "TCP Socket (ProxyIP)" 确立为第一退回方案 (Phase 2)。
 * 2. [逻辑增强] 在 createUnifiedConnection 中，当直连失败时立即尝试 ProxyIP。
 * 3. [双重保障] 修复 handleTCPOutBound 中的重试回调，确保"连接成功但无数据"(Error 1000特征)时也能触发 ProxyIP 重试。
 */
import { connect } from 'cloudflare:sockets';
import { CONSTANTS } from '../constants.js';
import { resolveToIPv6, parseIPv6 } from '../utils/dns.js';
import { safeCloseWebSocket, isHostBanned } from '../utils/helpers.js';

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
    
    // 处理 SOCKS5 握手后的早期数据 (Early Data)
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
                        // 核心：使用 TCP Socket (connect API)
                        s = connect({ hostname: host, port: port });
                    }
                 } catch(e) { throw e; }

                 if (isTimedOut) {
                     if (s) { try { s.close(); } catch(e) {} }
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

    // Phase 1: Direct Connection (直接连接)
    try {
        return await connectAndWrite(addressRemote, portRemote, useSocks);
    } catch (err1) {
        log(`[connect] Phase 1 (Direct) failed: ${err1.message}`);
    }

    // Phase 2: TCP Socket ProxyIP Fallback (第一退回方案)
    // 这是您请求的"方案一"核心：当直连失败，立即尝试连接 ProxyIP
    let proxyAttempts = [];
    if (fallbackAddress) {
        proxyAttempts.push(fallbackAddress);
    } else {
        if (ctx.proxyIP) {
            proxyAttempts.push(ctx.proxyIP);
        }
        // 确保有默认 ProxyIP 可用
        if (ctx.proxyIPList && ctx.proxyIPList.length > 0) {
            // 随机选 2 个，增加成功率
            for (let i = 0; i < 2; i++) {
                const randomIP = ctx.proxyIPList[Math.floor(Math.random() * ctx.proxyIPList.length)];
                if (randomIP && !proxyAttempts.includes(randomIP)) proxyAttempts.push(randomIP);
            }
        }
        // 兜底默认值
        if (proxyAttempts.length === 0) {
            const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
            if (defParams.length > 0) proxyAttempts.push(defParams[0]);
        }
    }
    
    proxyAttempts = [...new Set(proxyAttempts)].filter(Boolean);

    let proxySocket = null;
    for (const ip of proxyAttempts) {
        const { host: proxyHost, port: proxyPort } = parseProxyIP(ip, portRemote);
        try {
            // 使用 TCP Socket 直连 ProxyIP，但携带目标 SNI (由上层 VLESS/TLS 处理)
            log(`[connect] Phase 2 (ProxyIP): Attempting ${proxyHost}:${proxyPort}`);
            proxySocket = await connectAndWrite(proxyHost.toLowerCase(), proxyPort, false);
            if (proxySocket) {
                log(`[connect] Phase 2 (ProxyIP) Success`);
                break; 
            }
        } catch (err2) {
            log(`[connect] Phase 2 (ProxyIP: ${proxyHost}) failed: ${err2.message}`);
        }
    }
    if (proxySocket) return proxySocket;

    // Phase 3: NAT64 (IPv6 Fallback)
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

    throw new Error(`All connection attempts (Direct, ProxyIP, NAT64) failed.`);
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
                hasIncomingData = true; // 标记收到数据
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
            close() { log(`Remote socket closed. Data received: ${hasIncomingData}`); },
            abort(reason) { console.error('Remote socket aborted', reason); },
        })
    ).catch((error) => {
        if (error.message !== 'webSocket is not open' && error.message !== 'Client WebSocket closed, stopping remote read') {
            console.error('remoteSocketToWS error:', error);
        }
        safeCloseWebSocket(webSocket);
    });
    
    // 核心逻辑：如果没有收到任何数据就结束了 (例如 CF 拦截返回空响应或立即断开)，尝试重试
    if (!hasIncomingData && retryCallback) {
        log('Retry initiated due to no incoming data (Possible Block/Error 1000)');
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
        log('[Retry] Switching to NAT64 (Phase 3)...');
        prepareRetry(); 
        
        try {
            const v6Address = await resolveToIPv6(addressRemote, ctx.dns64);
            if (!v6Address) throw new Error('DNS64 resolution failed');
            const nat64IP = v6Address;
            const natSocket = await connect({ hostname: nat64IP, port: portRemote });
            
            const writer = natSocket.writable.getWriter();
            if (rawClientData && rawClientData.byteLength > 0) await writer.write(rawClientData);
            await flushBuffer(writer, remoteSocketWrapper.buffer, log);
            writer.releaseLock();
            finalizeConnection(natSocket);
            remoteSocketToWS(natSocket, webSocket, vlessResponseHeader, null, log);
        } catch (e) {
            log('[Retry] NAT64 failed: ' + e.message);
            safeCloseWebSocket(webSocket);
        }
    };

    // 这一步就是 "方案一" (TCP Socket + ProxyIP) 的重试逻辑
    const proxyIPRetry = async () => {
        log('[Retry] Switching to ProxyIP (Phase 2)...');
        prepareRetry(); 

        let attempts = [];
        if (ctx.proxyIP) attempts.push(ctx.proxyIP);
        if (ctx.proxyIPList && ctx.proxyIPList.length > 0) {
            // 随机取更多 IP 进行重试，提高成功率
            for (let i = 0; i < 3; i++) {
                const randomIP = ctx.proxyIPList[Math.floor(Math.random() * ctx.proxyIPList.length)];
                if (randomIP && !attempts.includes(randomIP)) attempts.push(randomIP);
            }
        }
        attempts = [...new Set(attempts)].filter(Boolean);
        if (attempts.length === 0) {
            const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
            if (defParams.length > 0) attempts.push(defParams[0]);
        }

        for (const ip of attempts) {
            try {
                const { host: proxyHost, port: proxyPort } = parseProxyIP(ip, portRemote);
                log(`[Retry] Attempting ProxyIP: ${proxyHost}`);
                
                const proxySocket = await connect({ hostname: proxyHost.toLowerCase(), port: proxyPort });
                
                const writer = proxySocket.writable.getWriter();
                if (rawClientData && rawClientData.byteLength > 0) await writer.write(rawClientData);
                await flushBuffer(writer, remoteSocketWrapper.buffer, log);
                writer.releaseLock();
                finalizeConnection(proxySocket);
                
                // 如果这次重试又失败了（无数据），是否还有下一招？
                // 如果禁用了 Socks5 且有 DNS64，则尝试 NAT64。
                const useSocks = ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5);
                const nextRetry = (!useSocks && ctx.dns64) ? nat64Retry : null;
                
                remoteSocketToWS(proxySocket, webSocket, vlessResponseHeader, nextRetry, log);
                return; 
            } catch (e) {
                log(`[Retry] ProxyIP (${ip}) failed: ${e.message}`);
            }
        }

        // 如果所有 ProxyIP 都失败，尝试 NAT64
        if (ctx.dns64 && !(ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5))) {
            await nat64Retry();
        } else {
            safeCloseWebSocket(webSocket);
        }
    };

    try {
        // 尝试建立初始连接 (内部已包含 Phase 1 -> Phase 2 -> Phase 3 的自动 fallback)
        const socket = await createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log);
        
        const writer = socket.writable.getWriter();
        if (rawClientData && rawClientData.byteLength > 0) await writer.write(rawClientData);
        await flushBuffer(writer, remoteSocketWrapper.buffer, log);
        writer.releaseLock();
        
        finalizeConnection(socket);
        
        // 关键：即使 createUnifiedConnection 成功返回了 socket，也有可能因为 CF 拦截而没有任何数据传回
        // 因此这里必须传入 proxyIPRetry 作为回调。
        remoteSocketToWS(socket, webSocket, vlessResponseHeader, proxyIPRetry, log);

    } catch (error) {
        log('[Outbound] Initial connection failed completely: ' + error.message);
        // 这里理论上 createUnifiedConnection 已经试过所有方案了，但为了保险，可以根据错误类型决定是否手动触发一次重试
        // 但通常如果连 createUnifiedConnection 都全抛错，说明网络极差或配置错误，直接关闭即可。
        safeCloseWebSocket(webSocket);
    }
}
