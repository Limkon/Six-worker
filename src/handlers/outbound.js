/**
 * 文件名: src/handlers/outbound.js
 * 修改内容:
 * 1. [Fix] 修复 parseProxyIP 对无方括号 IPv6 地址的误判问题。
 * 2. [Fix] 修复 connectAndWrite 在超时竞态条件下可能导致的 Socket 资源泄漏。
 * 3. [Critical Fix] 保持对 NAT64 连接时 IPv6 地址方括号的去除处理。
 */
import { connect } from 'cloudflare:sockets';
import { CONSTANTS } from '../constants.js';
import { resolveToIPv6, parseIPv6 } from '../utils/dns.js';
import { safeCloseWebSocket, isHostBanned } from '../utils/helpers.js';

/**
 * [重构] 解析 ProxyIP 字符串，提取 host 和 port
 * 支持格式: 
 * - 1.2.3.4
 * - 1.2.3.4:8080
 * - 2001:db8::1 (视为纯 IP)
 * - [2001:db8::1]
 * - [2001:db8::1]:8080
 */
function parseProxyIP(proxyAddr, defaultPort) {
    if (!proxyAddr) return { host: CONSTANTS.DEFAULT_PROXY_IP.split(',')[0].trim(), port: defaultPort };
    
    let str = proxyAddr.trim();
    let port = defaultPort;
    let host = str;

    // 尝试寻找最后一个冒号，但要忽略方括号内的冒号
    const lastColon = str.lastIndexOf(':');
    const lastBracket = str.lastIndexOf(']');
    
    // 如果冒号在右方括号之后（或者没有方括号），则认为是端口分隔符
    if (lastColon > lastBracket && lastColon > 0) {
        const portStr = str.substring(lastColon + 1);
        if (/^\d+$/.test(portStr)) {
            // [Fix] 增强 IPv6 判断：如果无方括号且包含多个冒号，则视为 IPv6 字面量（无端口）
            // 例如: 2001:db8::1 (会被误判为端口 1) -> 修正为 Host: 2001:db8::1, Port: default
            const isIPv6Literal = lastBracket === -1 && str.split(':').length > 2;
            
            if (!isIPv6Literal) {
                port = parseInt(portStr, 10);
                host = str.substring(0, lastColon);
            }
        }
    }
    
    // 清理 Host 两端的方括号
    if (host.startsWith('[') && host.endsWith(']')) {
        host = host.slice(1, -1);
    }
    
    return { host, port };
}

function shouldUseSocks5(addressRemote, go2socks5) {
    if (!go2socks5 || go2socks5.length === 0) return false;
    if (go2socks5.includes('all in') || go2socks5.includes('*')) return true;
    
    return go2socks5.some(pattern => {
        // [Optimization] 优先进行简单的字符串匹配，避免不必要的正则开销
        if (!pattern.includes('*')) {
            return pattern.toLowerCase() === addressRemote.toLowerCase();
        }
        
        // 对于包含通配符的规则，再使用正则
        try {
            let regexPattern = pattern.replace(/\*/g, '.*');
            let regex = new RegExp(`^${regexPattern}$`, 'i');
            return regex.test(addressRemote);
        } catch (e) {
            return false;
        }
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
        
        let hasTimedOut = false;

        // [Fix] 封装连接过程，防止超时后的 Socket 泄漏
        const connectPromise = (async () => {
             try {
                const sock = isSocks 
                    ? await socks5Connect(ctx.socks5, addressType, addressRemote, portRemote, log)
                    : connect({ hostname: host, port: port });
                
                // 如果已超时，说明外层 Promise.race 已拒绝，必须关闭此“迟到”的 Socket
                if (hasTimedOut) {
                    log(`[connect] Closing late connection to ${host}:${port} (after timeout)`);
                    try { sock.close(); } catch(e){}
                    return null;
                }
                
                // 非 Socks 模式下等待连接完全打开
                if (!isSocks) {
                    await sock.opened;
                    // 二次检查，等待 opened 期间可能发生超时
                    if (hasTimedOut) {
                         log(`[connect] Closing late connection to ${host}:${port} (after opened)`);
                         try { sock.close(); } catch(e){}
                         return null;
                    }
                }
                return sock;
             } catch (e) {
                 // 如果已超时，忽略错误；否则抛出供 Promise.race 捕获
                 if (hasTimedOut) return null;
                 throw e;
             }
        })();

        const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => {
                hasTimedOut = true;
                reject(new Error(`Connect timeout (${currentTimeout}ms)`));
            }, currentTimeout);
        });

        return await Promise.race([connectPromise, timeoutPromise]);
    };

    try {
        return await connectAndWrite(addressRemote, portRemote, useSocks);
    } catch (err1) {
        log(`[connect] Phase 1 failed: ${err1.message}`);
    }

    let proxyAttempts = [];
    if (fallbackAddress) {
        proxyAttempts.push(fallbackAddress);
    } else {
        if (ctx.proxyIP) {
            proxyAttempts.push(ctx.proxyIP);
        } else {
            const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
            if (defParams.length > 0) proxyAttempts.push(defParams[0]);
        }

        if (ctx.proxyIPList && ctx.proxyIPList.length > 0) {
            for (let i = 0; i < 2; i++) {
                const randomIP = ctx.proxyIPList[Math.floor(Math.random() * ctx.proxyIPList.length)];
                if (randomIP && !proxyAttempts.includes(randomIP)) {
                    proxyAttempts.push(randomIP);
                }
            }
        }
    }
    
    proxyAttempts = [...new Set(proxyAttempts)].filter(Boolean);

    let proxySocket = null;
    for (const ip of proxyAttempts) {
        const { host: proxyHost, port: proxyPort } = parseProxyIP(ip, portRemote);
        try {
            proxySocket = await connectAndWrite(proxyHost.toLowerCase(), proxyPort, false);
            if (proxySocket) break; 
        } catch (err2) {
            log(`[connect] Phase 2 (ProxyIP: ${proxyHost}) failed: ${err2.message}`);
        }
    }
    if (proxySocket) return proxySocket;

    if (!useSocks && ctx.dns64) {
        try {
            log(`[connect] Phase 3: Attempting NAT64...`);
            const v6Address = await resolveToIPv6(addressRemote, ctx.dns64);
            if (v6Address) {
                // [Critical Fix] 直接使用 pure IPv6，不允许带方括号
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

            // [Critical Fix] 移除多余的方括号，确保使用纯 IPv6 字符串
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
        log('[Retry] Switching to ProxyIP...');
        prepareRetry(); 

        let attempts = [];
        if (ctx.proxyIP) attempts.push(ctx.proxyIP);
        if (ctx.proxyIPList && ctx.proxyIPList.length > 0) {
            for (let i = 0; i < 2; i++) {
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
                log(`[Retry] ProxyIP (${ip}) failed: ${e.message}`);
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
