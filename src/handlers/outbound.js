/**
 * 文件名: src/handlers/outbound.js
 * 核心功能: 处理出站连接 (TCP/UDP)，支持 Direct, ProxyIP, SOCKS5, NAT64。
 * 包含修复: 
 * 1. SOCKS5 UDP Associate (BND.ADDR 0.0.0.0 Fix).
 * 2. 严格的 Cloudflare 防风控机制 (禁止内网 IP).
 * 3. 增强的正则匹配性能.
 * 4. [Fix] SOCKS5 UDP Buffer: 修复 UDP 分包导致的断流问题。
 */
import { connect } from 'cloudflare:sockets';
import { CONSTANTS } from '../constants.js';
import { resolveToIPv6, parseIPv6 } from '../utils/dns.js';
import { safeCloseWebSocket, isHostBanned, textEncoder } from '../utils/helpers.js';

// --- [Security] 安全检查：私有 IP 阻断 (防止风控核心) ---
// 使用预编译正则提高性能，严格匹配小数点防止误杀公网 IP (如 10.x vs 104.x)
const IPV4_PRIVATE_REGEX = /^(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[0-1])\.|192\.168\.|169\.254\.|0\.0\.0\.0|localhost)/;
const IPV4_CGNAT_REGEX = /^100\.(?:6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./; // 100.64.0.0/10
const IPV6_PRIVATE_REGEX = /^(:?(:|f[cd][0-9a-f]{2}|fe[89ab][0-9a-f])):|^(::1)$/i; // fc00::, fe80::, ::1

function isPrivateIP(address) {
    if (!address) return true; // 空地址视为风险
    
    // 检查 IPv4 私有网段
    if (IPV4_PRIVATE_REGEX.test(address)) return true;
    
    // 检查 Carrier Grade NAT (通常不应通过公网代理访问)
    if (IPV4_CGNAT_REGEX.test(address)) return true;

    // 检查 IPv6 (Unique Local, Link Local, Loopback)
    if (address.includes(':')) {
        if (IPV6_PRIVATE_REGEX.test(address.toLowerCase())) return true;
    }

    return false;
}

// --- 熔断缓存机制 ---
const CACHE_TTL = 10 * 60 * 1000;
const MAX_CACHE_SIZE = 500; 

class DirectFailureCache {
    constructor() { this.cache = new Map(); }
    add(host) {
        if (!host) return;
        if (this.has(host)) return;
        if (this.cache.size >= MAX_CACHE_SIZE) this.cache.delete(this.cache.keys().next().value);
        this.cache.set(host, Date.now() + CACHE_TTL);
    }
    has(host) {
        if (!host) return false;
        const expireTime = this.cache.get(host);
        if (!expireTime) return false;
        if (Date.now() > expireTime) { this.cache.delete(host); return false; }
        return true;
    }
}
const failureCache = new DirectFailureCache();
export function addToFailureCache(host) { if (host) failureCache.add(host); }

// --- 核心工具函数 ---
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
    if (colonCount > 1) return { host, port };
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
    if (typeof address === 'object') return address; // 支持直接传入对象

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

// SOCKS5 连接逻辑 (支持 UDP 握手)
async function socks5Connect(socks5Addr, addressType, addressRemote, portRemote, log, isUDP = false) {
    const config = parseSocks5Config(socks5Addr);
    if (!config) throw new Error('Socks5 config missing');
    const { username, password, hostname, port } = config;
    
    // 建立 TCP 控制连接
    const socket = connect({ hostname, port });
    await socket.opened;
    
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    
    // 1. Handshake
    await writer.write(new Uint8Array([5, 1, 2])); 
    let { value: res } = await reader.read();
    if (!res || res.length < 2 || res[0] !== 0x05 || res[1] === 0xff) throw new Error('SOCKS5 greeting failed');
    
    // 2. Auth
    if (res[1] === 0x02) {
        if (!username || !password) throw new Error('SOCKS5 auth required');
        const uBytes = encoder.encode(username);
        const pBytes = encoder.encode(password);
        const authReq = new Uint8Array([1, uBytes.length, ...uBytes, pBytes.length, ...pBytes]);
        await writer.write(authReq);
        const { value: authRes } = await reader.read();
        if (!authRes || authRes.length < 2 || authRes[0] !== 0x01 || authRes[1] !== 0x00) throw new Error('SOCKS5 auth failed');
    }
    
    // 3. Request (CONNECT or UDP ASSOCIATE)
    let DSTADDR;
    if (isUDP) {
         // UDP Associate 请求：IP/Port 通常设为 0，让服务器决定绑定
         DSTADDR = new Uint8Array([1, 0, 0, 0, 0]);
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
    const portBytes = isUDP ? [0, 0] : [portRemote >> 8, portRemote & 0xff];
    const socksRequest = new Uint8Array([5, cmd, 0, ...DSTADDR, ...portBytes]);
    
    await writer.write(socksRequest);
    const { value: connRes } = await reader.read();
    
    if (!connRes || connRes.length < 2 || connRes[0] !== 0x05 || connRes[1] !== 0x00) {
        throw new Error(`SOCKS5 connection failed (CMD: ${cmd}, REP: ${connRes ? connRes[1] : 'empty'})`);
    }
    
    // 4. Handle Response
    if (isUDP) {
        // 解析 BND.ADDR 和 BND.PORT
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
            const hex = [];
            for(let i=0; i<16; i++) hex.push(connRes[offset+i].toString(16).padStart(2, '0'));
            bndAddr = `[${hex.join('').match(/.{1,4}/g).join(':')}]`;
            offset += 16;
        }
        
        const p1 = connRes[offset];
        const p2 = connRes[offset+1];
        bndPort = (p1 << 8) | p2;

        writer.releaseLock();
        reader.releaseLock();

        // 标记并保存中继信息
        socket.isUdpControl = true;
        socket.bndAddr = bndAddr;
        socket.bndPort = bndPort;
        socket.originalHost = hostname; // 用于 BND.ADDR 0.0.0.0 的 Fallback
        
        return socket;
    }
    
    // TCP: Skip BND info
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

// 统一连接入口
async function connectWithTimeout(host, port, timeoutMs, log, socksConfig = null, addressType = null, addressRemote = null, isUDP = false) {
    let isTimedOut = false;
    let socket = null;
    const timeoutPromise = new Promise((_, reject) => setTimeout(() => {
        isTimedOut = true;
        reject(new Error(`Connect timeout (${timeoutMs}ms)`));
    }, timeoutMs));

    const doConnect = async () => {
        if (socksConfig) {
            return await socks5Connect(socksConfig, addressType, addressRemote, port, log, isUDP);
        } else {
            return connect({ hostname: host, port: port });
        }
    };

    try {
        socket = await Promise.race([doConnect(), timeoutPromise]);
        if (isTimedOut) {
            if (socket) { try { socket.close(); } catch(e) {} }
            throw new Error(`Connect timeout (${timeoutMs}ms)`);
        }
        if (!socket) throw new Error('Connection failed');
        // 非 SOCKS (Direct/Connect) 需要等待 opened，SOCKS 在 socks5Connect 内部已等待
        if (!socksConfig) await Promise.race([socket.opened, timeoutPromise]);
        return socket;
    } catch (err) {
        if (socket) { try { socket.close(); } catch(e) {} }
        throw err;
    }
}

// 创建连接对象 (根据配置选择 直连 / SOCKS5 / NAT64 等)
export async function createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log, fallbackAddress, isUDP = false) {
    const useSocks = ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5);
    const DIRECT_TIMEOUTS = [1500, 4000]; 
    const PROXY_TIMEOUT = 5000; 

    // Phase 1: Direct or Main SOCKS5
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
    let proxyIP = getSingleProxyIP(fallbackAddress || ctx.proxyIP);
    if (!proxyIP) {
        const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
        if (defParams.length > 0) proxyIP = defParams[0];
    }

    if (proxyIP) {
        const { host: proxyHost, port: proxyPort } = parseProxyIP(proxyIP, portRemote);
        try {
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

// --- UDP Helper Functions ---

function concatUint8(a, b) {
    const bArr = b instanceof Uint8Array ? b : new Uint8Array(b);
    const res = new Uint8Array(a.length + bArr.length);
    res.set(a);
    res.set(bArr, a.length);
    return res;
}

// 计算 SOCKS5 UDP 头部长度，如果数据不足则返回 -1
function getSocks5UdpHeaderLength(buffer) {
    if (buffer.length < 4) return -1; // Need at least RSV(2)+FRAG(1)+ATYP(1)
    const atyp = buffer[3];
    if (atyp === 1) return 10; // IPv4: 4+4+2
    if (atyp === 4) return 22; // IPv6: 4+16+2
    if (atyp === 3) {
        if (buffer.length < 5) return -1; // Need Len byte
        const len = buffer[4];
        return 7 + len; // 4 + 1(Len) + Len + 2(Port)
    }
    return 0; // Unknown/Invalid
}

function createSocks5UdpHeader(addressType, addressRemote, portRemote) {
    const rsvFrag = [0, 0, 0];
    let addrBytes;
    let atyp = addressType;
    if (addressType === CONSTANTS.ADDRESS_TYPE_IPV4) {
        addrBytes = addressRemote.split('.').map(Number);
    } else if (addressType === CONSTANTS.ADDRESS_TYPE_IPV6 || addressType === CONSTANTS.ATYP_TROJAN_IPV6) {
        atyp = 4;
        const v6Parts = parseIPv6(addressRemote.replace(/[\[\]]/g, ''));
        addrBytes = [];
        for (let i = 0; i < 8; i++) {
            addrBytes.push((v6Parts[i] >> 8) & 0xff);
            addrBytes.push(v6Parts[i] & 0xff);
        }
    } else {
        atyp = 3; 
        const encoder = new TextEncoder();
        const domain = encoder.encode(addressRemote);
        addrBytes = [domain.length, ...domain];
    }
    const portBytes = [portRemote >> 8, portRemote & 0xff];
    return new Uint8Array([...rsvFrag, atyp, ...addrBytes, ...portBytes]);
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

// TCP Pipe
export async function remoteSocketToWS(remoteSocket, webSocket, vlessHeader, retryCallback, log) {
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
            const combined = new Uint8Array(responseHeader.length + remoteSocket.initialData.length);
            combined.set(responseHeader);
            combined.set(remoteSocket.initialData, responseHeader.length);
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
                if (webSocket.readyState !== 1) { controller.error(new Error('WS Closed')); return; }
                const dataToSend = responseHeader 
                    ? new Uint8Array([...responseHeader, ...(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk))])
                    : chunk;
                responseHeader = null;
                if (!safeSend(dataToSend)) controller.error(new Error('WS send failed'));
            },
            close() { log(`Remote socket closed.`); },
            abort(reason) { console.error('Remote socket aborted', reason); },
        })
    ).catch((error) => { safeCloseWebSocket(webSocket); });
    
    if (!hasIncomingData && retryCallback) {
        try { await retryCallback(); } catch (e) { safeCloseWebSocket(webSocket); }
    }
}

// [Refactor] 提取通用 SOCKS5 UDP 流量处理
async function handleSocks5UDPFlow(controlSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log, finalizeConnectionCallback) {
    const { bndAddr, bndPort, originalHost } = controlSocket;
    
    // [Fix] 处理 BND.ADDR 为 0.0.0.0 或 :: 的情况
    let targetHost = bndAddr;
    const isZeroIP = bndAddr === '0.0.0.0' || bndAddr === '::' || bndAddr.startsWith('0:0:0:0') || bndAddr === '[::]';
    if (isZeroIP && originalHost) {
        targetHost = originalHost;
        log(`[SOCKS5] BND.ADDR is ${bndAddr}, falling back to proxy host: ${targetHost}`);
    }

    log(`[SOCKS5] UDP Associate ready. Relay: ${targetHost}:${bndPort}`);
    
    // Connect to Relay
    const udpSocket = connect({ hostname: targetHost, port: bndPort });
    finalizeConnectionCallback(udpSocket);
    
    const udpWriter = udpSocket.writable.getWriter();
    
    // Encapsulate & Send Initial Data
    const header = createSocks5UdpHeader(addressType, addressRemote, portRemote);
    if (rawClientData && rawClientData.byteLength > 0) {
        const packet = new Uint8Array(header.length + rawClientData.byteLength);
        packet.set(header);
        packet.set(new Uint8Array(rawClientData), header.length);
        await safeWrite(udpWriter, packet);
    }
    udpWriter.releaseLock();

    // Decapsulate & Stream Response
    let responseHeader = vlessResponseHeader;
    let udpBuffer = new Uint8Array(0); // [Fix] Buffer mechanism for fragmentation

    await udpSocket.readable.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (webSocket.readyState !== 1) { controller.error(new Error('WS Closed')); return; }
            
            // 1. Accumulate buffer
            udpBuffer = concatUint8(udpBuffer, chunk);
            
            // Safety: Buffer limit
            if (udpBuffer.length > 4096) {
                // Buffer overflow or bad protocol, reset
                udpBuffer = new Uint8Array(0); 
                return;
            }

            // 2. Check for complete header
            const headerLen = getSocks5UdpHeaderLength(udpBuffer);
            
            if (headerLen > 0) {
                // We have enough data for at least the header
                if (udpBuffer.length >= headerLen) {
                    // Header is complete
                    // Extract Payload (Everything after header)
                    const payload = udpBuffer.subarray(headerLen);
                    
                    const dataToSend = responseHeader 
                        ? new Uint8Array([...responseHeader, ...payload])
                        : payload;
                    responseHeader = null;
                    
                    webSocket.send(dataToSend);
                    
                    // Reset buffer (Assume 1 packet per flow chunk logic or tolerate loss if concatenated)
                    udpBuffer = new Uint8Array(0);
                }
                // Else: Wait for more data
            } else if (headerLen === 0) {
                 // Invalid data, reset
                 udpBuffer = new Uint8Array(0);
            }
            // headerLen == -1: Need more data, keep buffering
        },
        close() { 
            log('UDP Relay closed'); 
            controlSocket.close(); 
        },
        abort(e) { controlSocket.close(); }
    })).catch(() => { controlSocket.close(); safeCloseWebSocket(webSocket); });
}

export async function handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
    // [Security] 强制阻断私有 IP 或 违禁 Host (核心安全修复)
    if (isPrivateIP(addressRemote) || isHostBanned(addressRemote, ctx.banHosts)) { 
        log(`[Block] TCP request blocked: ${addressRemote} is private or banned.`);
        safeCloseWebSocket(webSocket); 
        return; 
    }

    const prepareRetry = () => { remoteSocketWrapper.value = null; remoteSocketWrapper.isConnecting = true; };
    const finalizeConnection = (socket) => { remoteSocketWrapper.value = socket; remoteSocketWrapper.isConnecting = false; };

    const nat64Retry = async () => {
        if (!ctx.dns64) { safeCloseWebSocket(webSocket); return; }
        prepareRetry();
        try {
            const v6Address = await resolveToIPv6(addressRemote, ctx.dns64);
            if (!v6Address) throw new Error('DNS64 failed');
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

export async function handleUDPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
    // [Security] 强制阻断私有 IP 或 违禁 Host
    if (isPrivateIP(addressRemote) || isHostBanned(addressRemote, ctx.banHosts)) { 
        log(`[Block] UDP request blocked: ${addressRemote} is private or banned.`);
        safeCloseWebSocket(webSocket); 
        return; 
    }
    
    const prepareRetry = () => { remoteSocketWrapper.value = null; remoteSocketWrapper.isConnecting = true; };
    const finalizeConnection = (socket) => { remoteSocketWrapper.value = socket; remoteSocketWrapper.isConnecting = false; };
    
    const nat64Retry = async () => {
        if (!ctx.dns64) { safeCloseWebSocket(webSocket); return; }
        prepareRetry();
        try {
            const v6Address = await resolveToIPv6(addressRemote, ctx.dns64);
            if (!v6Address) throw new Error('DNS64 failed');
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
        let ip = getSingleProxyIP(ctx.proxyIP);
        if (!ip) {
            const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
            if (defParams.length > 0) ip = defParams[0];
        }
        
        if (ip) {
            const { host: proxyHost, port: proxyPort } = parseProxyIP(ip, portRemote);
            
            // [Fix] 尝试 ProxyIP UDP Associate
            try {
                const socksConfig = { hostname: proxyHost, port: proxyPort, username: '', password: '' };
                const connectionObj = await socks5Connect(socksConfig, addressType, addressRemote, portRemote, log, true);
                if (connectionObj.isUdpControl) {
                    await handleSocks5UDPFlow(connectionObj, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log, finalizeConnection);
                    return; 
                }
            } catch (socksErr) { }

            // Fallback: TCP Tunnel
            try {
                const proxySocket = await connectWithTimeout(proxyHost.toLowerCase(), proxyPort, 5000, log);
                const writer = proxySocket.writable.getWriter();
                if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
                await flushBuffer(writer, remoteSocketWrapper.buffer, log);
                writer.releaseLock();
                finalizeConnection(proxySocket);
                remoteSocketToWS(proxySocket, webSocket, vlessResponseHeader, null, log);
                return; 
            } catch (e) {}
        }
        
        if (ctx.dns64) await nat64Retry();
        else safeCloseWebSocket(webSocket);
    };

    try {
        const connectionObj = await createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log, null, true);
        
        if (connectionObj.isUdpControl) {
            await handleSocks5UDPFlow(connectionObj, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log, finalizeConnection);
        } else {
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
        await proxyIPRetry();
    }
}
