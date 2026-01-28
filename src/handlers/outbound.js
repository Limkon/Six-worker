/**
 * 文件名: src/handlers/outbound.js
 * 修正说明:
 * 1. [Fix] 修复 ProxyIP 为数组时的类型错误。
 * 2. [Optimize] 重构 parseProxyIP，完美支持 IPv6 (带括号/不带括号) 及端口解析。
 * 3. [Performance] 直连超时优化为 [1500, 4000]。
 * 4. [Fix] WebSocket 发送增加 safeSend 包装。
 * 5. [Critical Fix] 修复 Socks5 UDP 连接逻辑，透传 isUDP 参数并发送正确的 UDP ASSOCIATE 命令 (0x03)。
 */
import { connect } from 'cloudflare:sockets';
import { CONSTANTS } from '../constants.js';
import { resolveToIPv6, parseIPv6 } from '../utils/dns.js';
import { safeCloseWebSocket, isHostBanned } from '../utils/helpers.js';

// --- 熔断缓存机制 ---
const CACHE_TTL = 10 * 60 * 1000; // 10分钟
const MAX_CACHE_SIZE = 500; 

class DirectFailureCache {
    constructor() {
        this.cache = new Map();
    }

    add(host) {
        if (!host) return;
        if (this.has(host)) return;
        if (this.cache.size >= MAX_CACHE_SIZE) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }
        this.cache.set(host, Date.now() + CACHE_TTL);
    }

    has(host) {
        if (!host) return false;
        const expireTime = this.cache.get(host);
        if (!expireTime) return false;
        if (Date.now() > expireTime) {
            this.cache.delete(host); 
            return false;
        }
        return true;
    }
}

const failureCache = new DirectFailureCache();

export function addToFailureCache(host) {
    if (host) failureCache.add(host);
}

// --- 核心工具函数 ---

// [辅助] 安全获取单个 IP (处理数组或字符串)
function getSingleProxyIP(proxyIP) {
    if (!proxyIP) return null;
    if (Array.isArray(proxyIP)) {
        if (proxyIP.length === 0) return null;
        return proxyIP[Math.floor(Math.random() * proxyIP.length)];
    }
    return proxyIP;
}

// [Optimization] 重构后的 IP 解析函数
function parseProxyIP(proxyAddr, defaultPort) {
    if (!proxyAddr) return { host: CONSTANTS.DEFAULT_PROXY_IP.split(',')[0].trim(), port: defaultPort };
    
    let host = proxyAddr;
    let port = defaultPort;

    // 情况 1: 以 '[' 开头，标准 IPv6 格式 [ipv6]:port 或 [ipv6]
    if (host.startsWith('[')) {
        const bracketEnd = host.indexOf(']');
        if (bracketEnd > 0) {
            const ipPart = host.substring(1, bracketEnd); // 提取括号内的 IP
            const portPart = host.substring(bracketEnd + 1);
            
            // 检查是否有端口
            if (portPart.startsWith(':')) {
                const p = parseInt(portPart.substring(1), 10);
                if (!isNaN(p)) port = p;
            }
            return { host: ipPart, port };
        }
    }

    // 情况 2: 包含多个冒号，且不带括号。视为纯 IPv6 地址，无法携带端口。
    const colonCount = (host.match(/:/g) || []).length;
    if (colonCount > 1) {
        return { host, port };
    }

    // 情况 3: IPv4 或 域名 (可能带端口)
    const lastColon = host.lastIndexOf(':');
    if (lastColon > 0) {
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

// [Fix] 增加 isUDP 参数
async function socks5Connect(socks5Addr, addressType, addressRemote, portRemote, log, isUDP = false) {
    const config = parseSocks5Config(socks5Addr);
    if (!config) throw new Error('Socks5 config missing');
    const { username, password, hostname, port } = config;
    const socket = connect({ hostname, port });
    await socket.opened;
    
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    
    // Handshake
    await writer.write(new Uint8Array([5, 1, 2])); 
    let { value: res } = await reader.read();
    if (!res || res.length < 2 || res[0] !== 0x05 || res[1] === 0xff) throw new Error('SOCKS5 greeting failed');
    
    // Auth
    if (res[1] === 0x02) {
        if (!username || !password) throw new Error('SOCKS5 auth required');
        const uBytes = encoder.encode(username);
        const pBytes = encoder.encode(password);
        const authReq = new Uint8Array([1, uBytes.length, ...uBytes, pBytes.length, ...pBytes]);
        await writer.write(authReq);
        const { value: authRes } = await reader.read();
        if (!authRes || authRes.length < 2 || authRes[0] !== 0x01 || authRes[1] !== 0x00) throw new Error('SOCKS5 auth failed');
    }
    
    // Request Construction
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
    
    // [Fix] 如果 isUDP 为 true，发送 0x03 (UDP ASSOCIATE)，否则发送 0x01 (CONNECT)
    const cmd = isUDP ? 0x03 : 0x01;
    const socksRequest = new Uint8Array([5, cmd, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
    
    await writer.write(socksRequest);
    const { value: connRes } = await reader.read();
    
    if (!connRes || connRes.length < 2 || connRes[0] !== 0x05 || connRes[1] !== 0x00) throw new Error(`SOCKS5 connection failed (CMD: ${cmd})`);
    
    let headLen = 0;
    if (connRes.length >= 4) {
        if (connRes[3] === 1) headLen = 10; 
        else if (connRes[3] === 4) headLen = 22; 
        else if (connRes[3] === 3) headLen = 7 + connRes[4]; 
    }
    if (headLen > 0 && connRes.length > headLen) {
        socket.initialData = connRes.subarray(headLen);
    }
    writer.releaseLock();
    reader.releaseLock();
    return socket;
}

// [Fix] 增加 isUDP 参数并透传
async function connectWithTimeout(host, port, timeoutMs, log, socksConfig = null, addressType = null, addressRemote = null, isUDP = false) {
    let isTimedOut = false;
    let socket = null;

    const timeoutPromise = new Promise((_, reject) => setTimeout(() => {
        isTimedOut = true;
        reject(new Error(`Connect timeout (${timeoutMs}ms)`));
    }, timeoutMs));

    const doConnect = async () => {
        let s;
        try {
            if (socksConfig) {
                // [Fix] 传递 isUDP
                s = await socks5Connect(socksConfig, addressType, addressRemote, port, log, isUDP);
            } else {
                s = connect({ hostname: host, port: port });
            }
            
            if (isTimedOut) {
                if (s) { try { s.close(); } catch(e) {} }
                return null;
            }
            return s;
        } catch (e) {
            throw e;
        }
    };

    try {
        socket = await Promise.race([doConnect(), timeoutPromise]);

        if (isTimedOut) {
            if (socket) { try { socket.close(); } catch(e) {} }
            throw new Error(`Connect timeout (${timeoutMs}ms)`);
        }
        
        if (!socket) throw new Error('Connection failed or aborted');

        if (!socksConfig) {
            await Promise.race([socket.opened, timeoutPromise]);
        }
        
        return socket;
    } catch (err) {
        if (socket) { try { socket.close(); } catch(e) {} }
        throw err;
    }
}

// [Fix] 接收 isUDP 参数并向下传递
export async function createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log, fallbackAddress, isUDP = false) {
    const useSocks = ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5);
    const DIRECT_TIMEOUTS = [1500, 4000]; 
    const PROXY_TIMEOUT = 5000; 

    // --- Phase 1: Direct Connection (带熔断) ---
    if (!failureCache.has(addressRemote)) {
        const currentTimeout = DIRECT_TIMEOUTS[0];
        try {
            const protoLabel = isUDP ? 'UDP' : 'TCP';
            log(`[connect:${protoLabel}] Phase 1: Direct ${addressRemote}:${portRemote} (Timeout: ${currentTimeout}ms)`);
            
            return await connectWithTimeout(
                addressRemote, 
                portRemote, 
                currentTimeout, 
                log, 
                useSocks ? ctx.socks5 : null, 
                addressType, 
                addressRemote,
                isUDP // [Fix] 传递 isUDP
            );
        } catch (err1) {
            log(`[connect] Phase 1 failed: ${err1.message}`);
            if (err1.message.includes('refused') || err1.message.includes('reset') || err1.message.includes('abort')) {
                log(`[Smart] Adding ${addressRemote} to failure cache (Circuit Breaker)`);
                addToFailureCache(addressRemote);
            }
        }
    } else {
        log(`[Smart] Skipping Phase 1 (Direct) for cached failed host: ${addressRemote}`);
    }

    // --- Phase 2: ProxyIP ---
    let proxyIP = getSingleProxyIP(fallbackAddress || ctx.proxyIP);
    
    if (!proxyIP) {
        const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
        if (defParams.length > 0) proxyIP = defParams[0];
    }

    if (proxyIP) {
        const { host: proxyHost, port: proxyPort } = parseProxyIP(proxyIP, portRemote);
        try {
            // ProxyIP 连接通常是 TCP 隧道，暂时不支持 UDP 语义透传（取决于 ProxyIP 节点的实现），
            // 这里我们假设 ProxyIP 节点接受 TCP 连接。如果需要支持 ProxyIP 的 UDP，这里也需要传递 isUDP，
            // 但目前的架构 ProxyIP 主要是 Cloudflare IP 或其他 HTTP/WS 中转，通常仅支持 TCP。
            // 因此此处暂不传递 isUDP，保持 TCP 行为，除非有明确的 UDP Proxy 协议。
            return await connectWithTimeout(proxyHost.toLowerCase(), proxyPort, PROXY_TIMEOUT, log);
        } catch (err2) {
            log(`[connect] Phase 2 (ProxyIP: ${proxyHost}) failed: ${err2.message}`);
        }
    }

    // --- Phase 3: NAT64 ---
    if (!useSocks && ctx.dns64) {
        try {
            log(`[connect] Phase 3: Attempting NAT64...`);
            const v6Address = await resolveToIPv6(addressRemote, ctx.dns64);
            if (v6Address) {
                // NAT64 同样通常是 TCP 映射
                return await connectWithTimeout(v6Address, portRemote, PROXY_TIMEOUT, log);
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

    const safeSend = (data) => {
        try {
            if (webSocket.readyState === 1) {
                webSocket.send(data);
                return true;
            }
        } catch (error) {
            log(`[WS] Send Error: ${error.message}`);
        }
        return false;
    };
    
    if (remoteSocket.initialData && remoteSocket.initialData.byteLength > 0) {
        hasIncomingData = true;
        log(`[Socks5] Flushing ${remoteSocket.initialData.byteLength} bytes of early data`);
        if (responseHeader) {
            const header = responseHeader;
            const data = remoteSocket.initialData;
            const combined = new Uint8Array(header.length + data.length);
            combined.set(header);
            combined.set(data, header.length);
            if (!safeSend(combined)) return; 
            responseHeader = null;
        } else {
            if (!safeSend(remoteSocket.initialData)) return;
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
                    if (!safeSend(combined)) {
                        controller.error(new Error('WebSocket send failed'));
                        return;
                    }
                    responseHeader = null;
                } else {
                    if (!safeSend(chunk)) {
                         controller.error(new Error('WebSocket send failed'));
                         return;
                    }
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

async function safeWrite(writer, chunk) {
    const WRITE_TIMEOUT = 10000; 
    const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Write timeout')), WRITE_TIMEOUT));
    await Promise.race([writer.write(chunk), timeoutPromise]);
}

async function flushBuffer(writer, buffer, log) {
    if (!buffer || buffer.length === 0) return;
    log(`Flushing ${buffer.length} buffered chunks`);
    
    let loops = 0;
    const MAX_FLUSH_LOOPS = 20; 

    while (buffer.length > 0) {
        if (loops >= MAX_FLUSH_LOOPS) {
            log('[Warn] Buffer flush limit reached.');
            break;
        }
        
        const batch = [...buffer];
        buffer.length = 0; 
        
        for (const chunk of batch) {
            try {
                await safeWrite(writer, chunk);
            } catch (e) {
                log(`[Error] Write failed during flush: ${e.message}`);
                throw e; 
            }
        }
        loops++;
    }
}

// ... handleTCPOutBound 保持不变，可以直接引用原文件 ...
// ... handleUDPOutBound 保持不变，可以直接引用原文件 ...
// 为了文件完整性，这里重新列出这两个函数，确保它们调用 createUnifiedConnection 时逻辑一致

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
            // NAT64 retry 不涉及 isUDP
            const natSocket = await connectWithTimeout(v6Address, portRemote, 5000, log);
            
            const writer = natSocket.writable.getWriter();
            if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
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
        log('[Retry] Retrying ProxyIP...');
        prepareRetry(); 

        let ip = getSingleProxyIP(ctx.proxyIP);
        if (!ip) {
            const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
            if (defParams.length > 0) ip = defParams[0];
        }

        if (ip) {
            try {
                const { host: proxyHost, port: proxyPort } = parseProxyIP(ip, portRemote);
                log(`[Retry] Attempting ProxyIP: ${proxyHost}`);
                const proxySocket = await connectWithTimeout(proxyHost.toLowerCase(), proxyPort, 5000, log);
                
                const writer = proxySocket.writable.getWriter();
                if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
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
        // TCP 模式，isUDP = false
        const socket = await createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log, null, false);
        const writer = socket.writable.getWriter();
        if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
        await flushBuffer(writer, remoteSocketWrapper.buffer, log);
        writer.releaseLock();
        finalizeConnection(socket);
        remoteSocketToWS(socket, webSocket, vlessResponseHeader, proxyIPRetry, log);
    } catch (error) {
        log('[Outbound] Initial connection failed: ' + error.message);
        safeCloseWebSocket(webSocket);
    }
}

export async function handleUDPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
    if (isHostBanned(addressRemote, ctx.banHosts)) {
        log(`[Outbound:UDP] Host banned: ${addressRemote}`);
        safeCloseWebSocket(webSocket);
        return;
    }

    log(`[Outbound:UDP] Initiating UDP connection to ${addressRemote}:${portRemote}`);

    const prepareRetry = () => {
        remoteSocketWrapper.value = null;
        remoteSocketWrapper.isConnecting = true;
    };
    
    const finalizeConnection = (socket) => {
        remoteSocketWrapper.value = socket;
        remoteSocketWrapper.isConnecting = false;
    };

    // 重试逻辑与 TCP 类似，但通常 UDP 的重试价值较小，这里保持原样以维持一致性
    const nat64Retry = async () => {
        if (!ctx.dns64) { safeCloseWebSocket(webSocket); return; }
        log('[Retry:UDP] Switching to NAT64...');
        prepareRetry(); 
        try {
            const v6Address = await resolveToIPv6(addressRemote, ctx.dns64);
            if (!v6Address) throw new Error('DNS64 resolution failed');
            const natSocket = await connectWithTimeout(v6Address, portRemote, 5000, log);
            
            const writer = natSocket.writable.getWriter();
            if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
            await flushBuffer(writer, remoteSocketWrapper.buffer, log);
            writer.releaseLock();
            
            finalizeConnection(natSocket);
            remoteSocketToWS(natSocket, webSocket, vlessResponseHeader, null, log);
        } catch (e) {
            log('[Retry:UDP] NAT64 failed: ' + e.message);
            safeCloseWebSocket(webSocket);
        }
    };

    const proxyIPRetry = async () => {
        log('[Retry:UDP] Retrying ProxyIP...');
        prepareRetry(); 

        let ip = getSingleProxyIP(ctx.proxyIP);
        if (!ip) {
            const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
            if (defParams.length > 0) ip = defParams[0];
        }

        if (ip) {
            try {
                const { host: proxyHost, port: proxyPort } = parseProxyIP(ip, portRemote);
                log(`[Retry:UDP] Attempting ProxyIP: ${proxyHost}`);
                const proxySocket = await connectWithTimeout(proxyHost.toLowerCase(), proxyPort, 5000, log);
                
                const writer = proxySocket.writable.getWriter();
                if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
                await flushBuffer(writer, remoteSocketWrapper.buffer, log);
                writer.releaseLock();
                
                finalizeConnection(proxySocket);
                const useSocks = ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5);
                const nextRetry = (!useSocks && ctx.dns64) ? nat64Retry : null;
                remoteSocketToWS(proxySocket, webSocket, vlessResponseHeader, nextRetry, log);
                return; 
            } catch (e) {
                log(`[Retry:UDP] ProxyIP (${ip}) failed: ${e.message}`);
            }
        }

        if (ctx.dns64 && !(ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5))) {
            await nat64Retry();
        } else {
            safeCloseWebSocket(webSocket);
        }
    };

    try {
        // [Critical] 透传 isUDP: true
        const socket = await createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log, null, true);
        const writer = socket.writable.getWriter();
        if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
        await flushBuffer(writer, remoteSocketWrapper.buffer, log);
        writer.releaseLock();
        finalizeConnection(socket);
        remoteSocketToWS(socket, webSocket, vlessResponseHeader, proxyIPRetry, log);
    } catch (error) {
        log('[Outbound:UDP] Connection failed: ' + error.message);
        safeCloseWebSocket(webSocket);
    }
}
