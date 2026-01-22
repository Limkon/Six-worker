// src/handlers/outbound.js

/**
 * 文件名: src/handlers/outbound.js
 * 修复说明:
 * 1. [关键修改] 移除了 ProxyIP 的轮询机制 (Rotation)。
 * - 在 createUnifiedConnection 和 proxyIPRetry 中删除了随机从 ctx.proxyIPList 获取 IP 的逻辑。
 * - 现在的行为：严格只连接 ctx.proxyIP 指定的那一个 IP，如果该 IP 失败，则根据流程进入 NAT64 或报错，不再尝试其他随机 IP。
 * 2. [功能保留] 完整保留了 SOCKS5 协议栈、NAT64 处理、Socket 超时保护、Early Data 处理等所有原有功能。
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
        
        // [修复] 标记该次尝试是否已超时
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
                 } catch(e) {
                     throw e;
                 }

                 // [修复关键点]：如果连接成功时已经超时，立即关闭 Socket 并返回 null/抛错
                 // 这样可以确保 Promise.race 已经 reject 的情况下，后台建立的连接不会被泄漏
                 if (isTimedOut) {
                     if (s) {
                         try { s.close(); } catch(e) {}
                         log(`[connect] Late connection to ${host}:${port} closed due to timeout.`);
                     }
                     return null; 
                 }
                 return s;
            };

            // 获取 Socket 对象
            socket = await Promise.race([doConnect(), timeoutPromise]);
            
            // 双重检查：理论上 doConnect 如果处理了 isTimedOut 不会返回 socket，但为了稳健性再次检查
            if (isTimedOut && socket) {
                 try { socket.close(); } catch(e) {}
                 throw new Error(`Connect timeout (${currentTimeout}ms) - closed late socket`);
            }

            if (!socket) { 
                throw new Error('Connection failed or timed out');
            }

            if (!isSocks) {
                // 等待连接建立 (Socket.opened)，同时继续监听超时
                await Promise.race([socket.opened, timeoutPromise]);
            }
            return socket;
        } catch (err) {
            // 常规错误处理，确保如果 socket 已经被赋值则关闭
            if (socket) {
                try { socket.close(); } catch(e) {}
            }
            throw err;
        }
    };

    // Phase 1: 尝试直连 (或通过 SOCKS5)
    try {
        return await connectAndWrite(addressRemote, portRemote, useSocks);
    } catch (err1) {
        log(`[connect] Phase 1 failed: ${err1.message}`);
    }

    // Phase 2: 尝试通过 ProxyIP
    // [修改] 取消轮询：只保留 ctx.proxyIP 或 fallbackAddress，不再随机添加其他 IP
    let proxyAttempts = [];
    if (fallbackAddress) {
        proxyAttempts.push(fallbackAddress);
    } else {
        if (ctx.proxyIP) {
            proxyAttempts.push(ctx.proxyIP);
        } else {
            // 如果没有配置 ProxyIP，保留默认回退（作为最后的手段，但通常这符合用户预期）
            const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
            if (defParams.length > 0) proxyAttempts.push(defParams[0]);
        }
        
        // [已删除] 原有的随机补充 IP 逻辑：
        /* if (ctx.proxyIPList && ctx.proxyIPList.length > 0) {
            for (let i = 0; i < 2; i++) { ... }
        }
        */
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

    // Phase 3: NAT64 备选
    if (!useSocks && ctx.dns64) {
        try {
            log(`[connect] Phase 3: Attempting NAT64...`);
            const v6Address = await resolveToIPv6(addressRemote, ctx.dns64);
            if (v6Address) {
                // [修复] 移除方括号，connect API 期望原始 IPv6 字符串
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
    
    // 如果连接关闭但从未收到过数据，触发重试回调（例如切换 IP）
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

            // [修复] 移除方括号，connect API 期望原始 IPv6 字符串
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

        // [修改] 取消轮询：只使用当前配置的单一 IP
        let attempts = [];
        if (ctx.proxyIP) attempts.push(ctx.proxyIP);
        
        // [已删除] 随机补充 IP 逻辑:
        /*
        if (ctx.proxyIPList && ctx.proxyIPList.length > 0) {
             for (let i = 0; i < 2; i++) { ... }
        }
        */
        
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

        // 如果 ProxyIP 重试失败，根据配置决定是否回退到 NAT64
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
