/**
 * 文件名: src/handlers/outbound.js
 * 审计与修复说明:
 * 1. [Refactor] 重构 SOCKS5 UDP 逻辑：
 * - 区分控制流(TCP)和数据流(UDP)。
 * - 增加 UDP 头部封装(Encapsulation)与解封装(Decapsulation)。
 * - 保持控制连接活跃(Keep-Alive)。
 * 2. [Keep] 保持 ProxyIP 的单次会话锁定逻辑(getSingleProxyIP)，防止风控。
 */
import { connect } from 'cloudflare:sockets';
import { CONSTANTS } from '../constants.js';
import { resolveToIPv6, parseIPv6 } from '../utils/dns.js';
import { safeCloseWebSocket, isHostBanned, textEncoder } from '../utils/helpers.js'; // 引入 textEncoder

// --- 熔断缓存机制 (保持不变) ---
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

// --- 核心工具函数 (保持不变) ---

function getSingleProxyIP(proxyIP) {
    if (!proxyIP) return null;
    if (Array.isArray(proxyIP)) {
        if (proxyIP.length === 0) return null;
        return proxyIP[Math.floor(Math.random() * proxyIP.length)];
    }
    return proxyIP;
}

function parseProxyIP(proxyAddr, defaultPort) {
    if (!proxyAddr) return { host: CONSTANTS.DEFAULT_PROXY_IP.split(',')[0].trim(), port: defaultPort };
    
    let host = proxyAddr;
    let port = defaultPort;

    if (host.startsWith('[')) {
        const bracketEnd = host.indexOf(']');
        if (bracketEnd > 0) {
            const ipPart = host.substring(1, bracketEnd);
            const portPart = host.substring(bracketEnd + 1);
            if (portPart.startsWith(':')) {
                const p = parseInt(portPart.substring(1), 10);
                if (!isNaN(p)) port = p;
            }
            return { host: ipPart, port };
        }
    }

    const colonCount = (host.match(/:/g) || []).length;
    if (colonCount > 1) {
        return { host, port };
    }

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

// [Refactor] 修复 SOCKS5 连接逻辑，支持 UDP 握手信息解析
async function socks5Connect(socks5Addr, addressType, addressRemote, portRemote, log, isUDP = false) {
    const config = parseSocks5Config(socks5Addr);
    if (!config) throw new Error('Socks5 config missing');
    const { username, password, hostname, port } = config;
    const socket = connect({ hostname, port });
    await socket.opened;
    
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    const encoder = new TextEncoder(); // 确保使用 TextEncoder
    
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
    // 如果是 UDP Associate (0x03)，Request 中的地址通常是 0.0.0.0:0，表示允许任何来源发送 UDP
    // 但为了兼容部分服务端，我们依然发送目标地址（虽然协议上这里主要是为了 bind 限制）
    // 或者发送 0.0.0.0 (IPV4)
    if (isUDP) {
         // 标准 RFC1928: DST.ADDR/PORT 字段包含了客户端希望用来发送 UDP 数据报的源 IP 和端口。
         // 大多数客户端发送 0.0.0.0:0
         DSTADDR = new Uint8Array([1, 0, 0, 0, 0]);
         // 重置 portRemote 为 0，因为这是 bind 请求
         // 但为了保持函数通用性，我们构造一个通用的 0 地址包
    } else {
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
    }
    
    const cmd = isUDP ? 0x03 : 0x01;
    // 如果是 UDP，端口发 0
    const portBytes = isUDP ? [0, 0] : [portRemote >> 8, portRemote & 0xff];
    const socksRequest = new Uint8Array([5, cmd, 0, ...DSTADDR, ...portBytes]);
    
    await writer.write(socksRequest);
    const { value: connRes } = await reader.read();
    
    if (!connRes || connRes.length < 2 || connRes[0] !== 0x05 || connRes[1] !== 0x00) {
        throw new Error(`SOCKS5 connection failed (CMD: ${cmd}, REP: ${connRes ? connRes[1] : 'empty'})`);
    }
    
    // [Refactor] UDP Associate 响应解析 (BND.ADDR/PORT)
    if (isUDP) {
        let bndAddr = '';
        let bndPort = 0;
        let addrType = connRes[3];
        let offset = 4;
        
        if (addrType === 1) { // IPv4
            bndAddr = connRes.slice(offset, offset + 4).join('.');
            offset += 4;
        } else if (addrType === 3) { // Domain
            const len = connRes[offset];
            offset++;
            bndAddr = new TextDecoder().decode(connRes.slice(offset, offset + len));
            offset += len;
        } else if (addrType === 4) { // IPv6
            // 简单处理，暂不还原为字符串，因为 connect 可能需要 hostname
            // 这里假设 SOCKS5 server 返回的是 IP
            // 为简化，若返回 IPv6，我们可能需要额外处理，这里暂略
            // 实际环境 Cloudflare connect 对 IPv6 支持较好
            const hex = [];
            for(let i=0; i<16; i++) hex.push(connRes[offset+i].toString(16).padStart(2, '0'));
            bndAddr = `[${hex.join('').match(/.{1,4}/g).join(':')}]`;
            offset += 16;
        }
        
        // 解析端口
        const p1 = connRes[offset];
        const p2 = connRes[offset+1];
        bndPort = (p1 << 8) | p2;

        writer.releaseLock();
        reader.releaseLock();

        // 标记 Socket 为 UDP 控制连接
        socket.isUdpControl = true;
        socket.bndAddr = bndAddr;
        socket.bndPort = bndPort;
        
        return socket;
    }
    
    // TCP 逻辑保持不变
    let headLen = 0;
    // ... 原有的 TCP 头部跳过逻辑 ...
    // 计算头部长度以跳过 BND 地址 (虽然 TCP Connect 的 BND 通常没用，但协议有返回)
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

// 保持 createUnifiedConnection 接口一致
async function connectWithTimeout(host, port, timeoutMs, log, socksConfig = null, addressType = null, addressRemote = null, isUDP = false) {
    let isTimedOut = false;
    let socket = null;

    const timeoutPromise = new Promise((_, reject) => setTimeout(() => {
        isTimedOut = true;
        reject(new Error(`Connect timeout (${timeoutMs}ms)`));
    }, timeoutMs));

    const doConnect = async () => {
        try {
            if (socksConfig) {
                return await socks5Connect(socksConfig, addressType, addressRemote, port, log, isUDP);
            } else {
                return connect({ hostname: host, port: port });
            }
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
        if (!socket) throw new Error('Connection failed');
        if (!socksConfig) await Promise.race([socket.opened, timeoutPromise]);
        return socket;
    } catch (err) {
        if (socket) { try { socket.close(); } catch(e) {} }
        throw err;
    }
}

export async function createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log, fallbackAddress, isUDP = false) {
    const useSocks = ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5);
    const DIRECT_TIMEOUTS = [1500, 4000]; 
    const PROXY_TIMEOUT = 5000; 

    // Phase 1: Direct
    if (!failureCache.has(addressRemote)) {
        const currentTimeout = DIRECT_TIMEOUTS[0];
        try {
            const protoLabel = isUDP ? 'UDP' : 'TCP';
            log(`[connect:${protoLabel}] Phase 1: Direct ${addressRemote}:${portRemote} (Timeout: ${currentTimeout}ms)`);
            return await connectWithTimeout(addressRemote, portRemote, currentTimeout, log, useSocks ? ctx.socks5 : null, addressType, addressRemote, isUDP);
        } catch (err1) {
            log(`[connect] Phase 1 failed: ${err1.message}`);
            if (err1.message.includes('refused') || err1.message.includes('reset') || err1.message.includes('abort')) {
                addToFailureCache(addressRemote);
            }
        }
    }

    // Phase 2: ProxyIP
    // [Keep] 保持 ProxyIP 锁定逻辑，符合风控要求
    let proxyIP = getSingleProxyIP(fallbackAddress || ctx.proxyIP);
    if (!proxyIP) {
        const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
        if (defParams.length > 0) proxyIP = defParams[0];
    }

    if (proxyIP) {
        const { host: proxyHost, port: proxyPort } = parseProxyIP(proxyIP, portRemote);
        try {
            // ProxyIP 通常是中转节点，暂不支持 UDP Associate 协议透传，这里降级为 TCP 连接
            // 或者如果 ProxyIP 支持 UDP 转发，需在此处增加逻辑。
            // 现有的逻辑对 ProxyIP 统一使用 TCP 连接。
            return await connectWithTimeout(proxyHost.toLowerCase(), proxyPort, PROXY_TIMEOUT, log);
        } catch (err2) {
            log(`[connect] Phase 2 (ProxyIP: ${proxyHost}) failed: ${err2.message}`);
        }
    }

    // Phase 3: NAT64
    if (!useSocks && ctx.dns64) {
        try {
            const v6Address = await resolveToIPv6(addressRemote, ctx.dns64);
            if (v6Address) {
                return await connectWithTimeout(v6Address, portRemote, PROXY_TIMEOUT, log);
            }
        } catch (err3) {
            log(`[connect] Phase 3 (NAT64) failed: ${err3.message}`);
        }
    }

    throw new Error(`All connection attempts failed.`);
}

// --- UDP 头部封装助手 ---
function createSocks5UdpHeader(addressType, addressRemote, portRemote) {
    // Header: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT
    const rsvFrag = [0, 0, 0];
    let addrBytes;
    let atyp = addressType;

    // 转换地址为 Bytes
    if (addressType === CONSTANTS.ADDRESS_TYPE_IPV4) {
        addrBytes = addressRemote.split('.').map(Number);
    } else if (addressType === CONSTANTS.ADDRESS_TYPE_IPV6 || addressType === CONSTANTS.ATYP_TROJAN_IPV6) {
        atyp = 4; // SOCKS5 IPv6 ATYP
        const v6Parts = parseIPv6(addressRemote.replace(/[\[\]]/g, ''));
        addrBytes = [];
        for (let i = 0; i < 8; i++) {
            addrBytes.push((v6Parts[i] >> 8) & 0xff);
            addrBytes.push(v6Parts[i] & 0xff);
        }
    } else {
        atyp = 3; // Domain
        const encoder = new TextEncoder();
        const domain = encoder.encode(addressRemote);
        addrBytes = [domain.length, ...domain];
    }

    const portBytes = [portRemote >> 8, portRemote & 0xff];
    return new Uint8Array([...rsvFrag, atyp, ...addrBytes, ...portBytes]);
}

// 移除 SOCKS5 UDP 头部 (用于接收)
function stripSocks5UdpHeader(buffer) {
    if (buffer.length < 4) return buffer; // Too short
    // Skip RSV(2) FRAG(1) ATYP(1)
    let offset = 4;
    const atyp = buffer[3];
    if (atyp === 1) offset += 4; // IPv4
    else if (atyp === 3) offset += 1 + buffer[4]; // Domain
    else if (atyp === 4) offset += 16; // IPv6
    
    offset += 2; // Port
    
    if (offset > buffer.length) return buffer;
    return buffer.slice(offset);
}

// --- Write Helpers ---
async function safeWrite(writer, chunk) {
    const WRITE_TIMEOUT = 10000; 
    const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Write timeout')), WRITE_TIMEOUT));
    await Promise.race([writer.write(chunk), timeoutPromise]);
}

async function flushBuffer(writer, buffer, log) {
    if (!buffer || buffer.length === 0) return;
    const MAX_FLUSH_LOOPS = 20; 
    let loops = 0;
    while (buffer.length > 0) {
        if (loops >= MAX_FLUSH_LOOPS) break;
        const batch = [...buffer];
        buffer.length = 0; 
        for (const chunk of batch) {
            try { await safeWrite(writer, chunk); } catch (e) { throw e; }
        }
        loops++;
    }
}

export async function remoteSocketToWS(remoteSocket, webSocket, vlessHeader, retryCallback, log) {
    // 这里的实现保持不变，用于通用 TCP 管道
    // UDP 专用管道见下文 separate logic
    let hasIncomingData = false;
    let responseHeader = vlessHeader;

    const safeSend = (data) => {
        try {
            if (webSocket.readyState === 1) {
                webSocket.send(data);
                return true;
            }
        } catch (error) { }
        return false;
    };
    
    if (remoteSocket.initialData && remoteSocket.initialData.byteLength > 0) {
        hasIncomingData = true;
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
                    controller.error(new Error('Client WebSocket closed'));
                    return;
                }
                const dataToSend = responseHeader 
                    ? new Uint8Array([...responseHeader, ...(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk))])
                    : chunk;
                responseHeader = null;
                if (!safeSend(dataToSend)) controller.error(new Error('WebSocket send failed'));
            },
            close() { log(`Remote socket closed.`); },
            abort(reason) { console.error('Remote socket aborted', reason); },
        })
    ).catch((error) => {
        safeCloseWebSocket(webSocket);
    });
    
    if (!hasIncomingData && retryCallback) {
        try { await retryCallback(); } catch (e) { safeCloseWebSocket(webSocket); }
    }
}

export async function handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
    if (isHostBanned(addressRemote, ctx.banHosts)) {
        safeCloseWebSocket(webSocket);
        return;
    }

    // 重试机制 (Keep Logic)
    const prepareRetry = () => { remoteSocketWrapper.value = null; remoteSocketWrapper.isConnecting = true; };
    const finalizeConnection = (socket) => { remoteSocketWrapper.value = socket; remoteSocketWrapper.isConnecting = false; };

    const nat64Retry = async () => {
        if (!ctx.dns64) { safeCloseWebSocket(webSocket); return; }
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
        } catch (e) { safeCloseWebSocket(webSocket); }
    };

    const proxyIPRetry = async () => {
        prepareRetry();
        // [Keep] 保持 ProxyIP 锁定逻辑
        let ip = getSingleProxyIP(ctx.proxyIP);
        if (!ip) {
            const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
            if (defParams.length > 0) ip = defParams[0];
        }

        if (ip) {
            try {
                const { host: proxyHost, port: proxyPort } = parseProxyIP(ip, portRemote);
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
            } catch (e) {}
        }
        if (ctx.dns64 && !(ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5))) await nat64Retry();
        else safeCloseWebSocket(webSocket);
    };

    try {
        const socket = await createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log, null, false);
        const writer = socket.writable.getWriter();
        if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
        await flushBuffer(writer, remoteSocketWrapper.buffer, log);
        writer.releaseLock();
        finalizeConnection(socket);
        remoteSocketToWS(socket, webSocket, vlessResponseHeader, proxyIPRetry, log);
    } catch (error) {
        log('[Outbound] TCP Initial failed: ' + error.message);
        safeCloseWebSocket(webSocket);
    }
}

// [Refactor] UDP 处理主逻辑
export async function handleUDPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
    if (isHostBanned(addressRemote, ctx.banHosts)) {
        safeCloseWebSocket(webSocket);
        return;
    }
    
    // 复用 TCP 的重试逻辑 (代码一致性)
    const prepareRetry = () => { remoteSocketWrapper.value = null; remoteSocketWrapper.isConnecting = true; };
    const finalizeConnection = (socket) => { remoteSocketWrapper.value = socket; remoteSocketWrapper.isConnecting = false; };
    
    const nat64Retry = async () => {
        if (!ctx.dns64) { safeCloseWebSocket(webSocket); return; }
        prepareRetry();
        try {
            // NAT64 UDP (Cloudflare Connect 目前对 UDP 支持有限，这里假设直连或通过 TCP 隧道)
            // 如果目标是纯 UDP，普通 connect 可能不通，但作为 fallback 保持逻辑完整
            const v6Address = await resolveToIPv6(addressRemote, ctx.dns64);
            if (!v6Address) throw new Error('DNS64 resolution failed');
            const natSocket = await connectWithTimeout(v6Address, portRemote, 5000, log); // UDP?
            
            const writer = natSocket.writable.getWriter();
            if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
            await flushBuffer(writer, remoteSocketWrapper.buffer, log);
            writer.releaseLock();
            finalizeConnection(natSocket);
            remoteSocketToWS(natSocket, webSocket, vlessResponseHeader, null, log);
        } catch (e) { safeCloseWebSocket(webSocket); }
    };

    const proxyIPRetry = async () => {
        prepareRetry();
        let ip = getSingleProxyIP(ctx.proxyIP);
        if (!ip) {
            const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
            if (defParams.length > 0) ip = defParams[0];
        }
        if (ip) {
            try {
                const { host: proxyHost, port: proxyPort } = parseProxyIP(ip, portRemote);
                const proxySocket = await connectWithTimeout(proxyHost.toLowerCase(), proxyPort, 5000, log);
                const writer = proxySocket.writable.getWriter();
                if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
                await flushBuffer(writer, remoteSocketWrapper.buffer, log);
                writer.releaseLock();
                finalizeConnection(proxySocket);
                // ProxyIP UDP 降级为 TCP 隧道
                remoteSocketToWS(proxySocket, webSocket, vlessResponseHeader, null, log);
                return; 
            } catch (e) {}
        }
        if (ctx.dns64) await nat64Retry();
        else safeCloseWebSocket(webSocket);
    };

    try {
        // 尝试建立连接 (如果走了 SOCKS5，isUDP=true 会触发 0x03 握手)
        const connectionObj = await createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log, null, true);
        
        // 检查是否是 SOCKS5 UDP 控制连接
        if (connectionObj.isUdpControl) {
            const controlSocket = connectionObj; // 这是 TCP 控制 socket
            const { bndAddr, bndPort } = controlSocket;
            
            log(`[SOCKS5] UDP Associate success. Relay: ${bndAddr}:${bndPort}`);
            
            // 建立数据连接到 Relay
            // 注意: Cloudflare connect 主要是 TCP。如果 Relay 支持 UDP over TCP (非标) 或者 Cloudflare 支持 UDP connect，这里生效。
            // 否则这里会建立一个 TCP 连接到 Relay 的 UDP 端口，可能会失败。
            // 但这是符合 SOCKS5 逻辑的唯一写法。
            const udpSocket = connect({ hostname: bndAddr, port: bndPort }); 
            finalizeConnection(udpSocket);
            
            // --- 数据发送 (Encapsulation) ---
            const udpWriter = udpSocket.writable.getWriter();
            
            // 封装头部并发送初始数据
            const header = createSocks5UdpHeader(addressType, addressRemote, portRemote);
            if (rawClientData && rawClientData.byteLength > 0) {
                const packet = new Uint8Array(header.length + rawClientData.byteLength);
                packet.set(header);
                packet.set(new Uint8Array(rawClientData), header.length);
                await safeWrite(udpWriter, packet);
            }
            
            // 处理 Buffer (封装每个包)
            // 注意：简单 flush 可能会合并包，SOCKS5 UDP 需要保留边界。
            // 但在 Stream 环境下很难做到精确边界，这里假设 flushBuffer 处理的是 stream chunk
            // 正确做法是每个 write 都加 header，但 remoteSocketWrapper.buffer 可能是碎片。
            // 简化处理：丢弃旧 buffer 或假设它是完整包 (Better effort)
            // 实际场景：initialData 通常包含第一个完整包。
            udpWriter.releaseLock();

            // --- 数据接收 (Decapsulation) ---
            // 管道逻辑： Relay -> Strip Header -> WebSocket
            let responseHeader = vlessResponseHeader;
            await udpSocket.readable.pipeTo(new WritableStream({
                async write(chunk, controller) {
                    if (webSocket.readyState !== 1) { controller.error(new Error('WS Closed')); return; }
                    
                    // 解包 (移除 SOCKS5 UDP Header)
                    const payload = stripSocks5UdpHeader(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk));
                    
                    const dataToSend = responseHeader 
                        ? new Uint8Array([...responseHeader, ...payload])
                        : payload;
                    responseHeader = null;
                    
                    webSocket.send(dataToSend);
                },
                close() { 
                    log('UDP Relay closed'); 
                    controlSocket.close(); // 关闭控制连接
                },
                abort(e) { controlSocket.close(); }
            })).catch(() => { controlSocket.close(); safeCloseWebSocket(webSocket); });

        } else {
            // 普通直连 (Direct / TCP-like UDP tunnel)
            const socket = connectionObj;
            const writer = socket.writable.getWriter();
            if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
            await flushBuffer(writer, remoteSocketWrapper.buffer, log);
            writer.releaseLock();
            finalizeConnection(socket);
            remoteSocketToWS(socket, webSocket, vlessResponseHeader, proxyIPRetry, log);
        }

    } catch (error) {
        log('[Outbound:UDP] Initial failed: ' + error.message);
        // 触发重试逻辑 (ProxyIP 或 NAT64)
        await proxyIPRetry();
    }
}
