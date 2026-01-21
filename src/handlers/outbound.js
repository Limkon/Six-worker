/**
 * 文件名: src/handlers/outbound.js
 * 修复说明:
 * 1. [Critical Fix] 修复 Stream 锁竞争 Bug。推迟状态更新 (remoteSocketWrapper.value) 直到 writer 锁释放后，
 * 防止 websocket.js 在 buffer 冲刷期间尝试获取锁导致崩溃。
 * 2. [Optimization] 优化 flushBuffer 逻辑，更安全地处理并发写入的数据。
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
    
    if (!res || res[0] !== 0x05 || res[1] === 0xff) throw new Error('SOCKS5 greeting failed');
    
    // SOCKS5 Auth
    if (res[1] === 0x02) {
        if (!username || !password) throw new Error('SOCKS5 auth required');
        
        const uBytes = encoder.encode(username);
        const pBytes = encoder.encode(password);
        
        const authReq = new Uint8Array([1, uBytes.length, ...uBytes, pBytes.length, ...pBytes]);
        await writer.write(authReq);
        
        const { value: authRes } = await reader.read();
        if (!authRes || authRes[0] !== 0x01 || authRes[1] !== 0x00) throw new Error('SOCKS5 auth failed');
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
    
    if (!connRes || connRes[0] !== 0x05 || connRes[1] !== 0x00) throw new Error(`SOCKS5 connection failed: ${connRes ? connRes[1] : 'No response'}`);
    
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
        
        const doConnect = async () => {
             if (isSocks) {
                return await socks5Connect(ctx.socks5, addressType, addressRemote, portRemote, log);
            } else {
                return connect({ hostname: host, port: port });
            }
        };

        const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error(`Connect timeout (${currentTimeout}ms)`)), currentTimeout));
        const socket = await Promise.race([doConnect(), timeoutPromise]);
        
        if (!isSocks) {
            await Promise.race([socket.opened, timeoutPromise]);
        }
        return socket;
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
                const nat64IP = '[' + v6Address + ']';
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
    
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                hasIncomingData = true;
                if (webSocket.readyState !== 1) { 
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
        if (error.message !== 'webSocket is not open') {
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

// [优化] 辅助函数：更健壮的缓冲区冲刷逻辑
async function flushBuffer(writer, buffer, log) {
    if (!buffer || buffer.length === 0) return;
    
    log(`Flushing ${buffer.length} buffered chunks`);
    
    // 使用 while 循环，应对 flush 过程中又有新数据被 push 进来的情况
    // 复制当前 buffer 并清空，避免死循环（虽然 JS 单线程通常不会，但为了逻辑严谨）
    while (buffer.length > 0) {
        const batch = [...buffer];
        buffer.length = 0; // 立即清空，后续进入的数据会在下一次循环或由 websocket.js 处理
        
        for (const chunk of batch) {
            await writer.write(chunk);
        }
    }
}

export async function handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
    // 准备重试环境：设置状态为连接中
    // 注意：这里将 value 设为 null，通知 websocket.js 开始缓冲数据
    const prepareRetry = () => {
        remoteSocketWrapper.value = null;
        remoteSocketWrapper.isConnecting = true;
    };
    
    // 状态更新辅助函数：确保释放锁之后再更新状态
    const finalizeConnection = (socket) => {
        remoteSocketWrapper.value = socket;
        remoteSocketWrapper.isConnecting = false;
        // 此时 websocket.js 才会检测到新 socket 并尝试获取 writer
    };

    const nat64Retry = async () => {
        if (!ctx.dns64) { safeCloseWebSocket(webSocket); return; }
        log('[Retry] Switching to NAT64...');
        prepareRetry(); 
        
        try {
            const v6Address = await resolveToIPv6(addressRemote, ctx.dns64);
            if (!v6Address) throw new Error('DNS64 resolution failed');

            const nat64IP = '[' + v6Address + ']';
            const natSocket = await connect({ hostname: nat64IP, port: portRemote });
            
            // [关键修改] 先获取 writer 并冲刷数据
            const writer = natSocket.writable.getWriter();
            if (rawClientData && rawClientData.byteLength > 0) {
                await writer.write(rawClientData);
            }
            await flushBuffer(writer, remoteSocketWrapper.buffer, log);
            writer.releaseLock();
            
            // [关键修改] 锁释放后再更新状态
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
                
                // [关键修改] 先获取 writer 并冲刷数据
                const writer = proxySocket.writable.getWriter();
                if (rawClientData && rawClientData.byteLength > 0) {
                    await writer.write(rawClientData);
                }
                await flushBuffer(writer, remoteSocketWrapper.buffer, log);
                writer.releaseLock();
                
                // [关键修改] 锁释放后再更新状态
                finalizeConnection(proxySocket);
                
                const useSocks = ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5);
                const nextRetry = (!useSocks && ctx.dns64) ? nat64Retry : null;
                
                remoteSocketToWS(proxySocket, webSocket, vlessResponseHeader, nextRetry, log);
                return; 
            } catch (e) {
                log(`[Retry] ProxyIP (${ip}) failed: ${e.message}`);
            }
        }

        // 如果 ProxyIP 全部失败，尝试 NAT64
        if (ctx.dns64 && !(ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5))) {
            await nat64Retry();
        } else {
            safeCloseWebSocket(webSocket);
        }
    };

    try {
        const socket = await createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log);
        
        // [关键修改] 先获取 writer 并冲刷数据
        const writer = socket.writable.getWriter();
        if (rawClientData && rawClientData.byteLength > 0) {
            await writer.write(rawClientData);
        }
        await flushBuffer(writer, remoteSocketWrapper.buffer, log);
        writer.releaseLock();
        
        // [关键修改] 锁释放后再更新状态，防止 websocket.js 抢占 Locked Stream
        finalizeConnection(socket);
        
        remoteSocketToWS(socket, webSocket, vlessResponseHeader, proxyIPRetry, log);
    } catch (error) {
        log('[Outbound] Initial connection failed: ' + error.message);
        safeCloseWebSocket(webSocket);
    }
}
