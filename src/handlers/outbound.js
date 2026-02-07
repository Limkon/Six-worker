/**
 * 文件名: src/handlers/outbound.js
 * 修复说明:
 * 1. [Critical Fix] SOCKS5 握手逻辑修正：
 * - 之前错误地强制发送 [5, 1, 2]，导致无密码的 SOCKS5 代理连接失败。
 * - 现在根据是否有 credential 动态发送 [5, 1, 0] 或 [5, 2, 0, 2]，恢复兼容性。
 * 2. 保留了之前所有的 UDP 粘包修复和安全阻断逻辑。
 */
import { connect } from 'cloudflare:sockets';
import { CONSTANTS } from '../constants.js';
import { resolveToIPv6, parseIPv6 } from '../utils/dns.js';
import { safeCloseWebSocket, isHostBanned, textEncoder } from '../utils/helpers.js';

// --- [Security] 安全检查：私有 IP 阻断 ---
const IPV4_PRIVATE_REGEX = /^(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[0-1])\.|192\.168\.|169\.254\.|198\.1[89]\.|(?:22[4-9]|23\d|24\d|25[0-5])\.|0\.|localhost)/;
const IPV4_CGNAT_REGEX = /^100\.(?:6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./; 
const IPV6_PRIVATE_REGEX = /^(:?(:|f[cd][0-9a-f]{2}|fe[89ab][0-9a-f])):|^(::1)$/i; 

function isPrivateIP(address) {
    if (!address) return true; 
    if (IPV4_PRIVATE_REGEX.test(address)) return true;
    if (IPV4_CGNAT_REGEX.test(address)) return true;
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
    if (typeof address === 'object') return address; 

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
    
    // 1. Handshake (Method Selection)
    // [Fix] 动态构建 Methods 列表
    // 如果有用户名密码，发送 [5, 2, 0, 2] (支持 NoAuth(0) 和 UserPass(2))
    // 如果没有，发送 [5, 1, 0] (只支持 NoAuth)
    const methods = [0];
    if (username && password) methods.push(2);
    const handshakeReq = new Uint8Array([5, methods.length, ...methods]);
    
    await writer.write(handshakeReq); 
    
    let { value: res } = await reader.read();
    if (!res || res.length < 2 || res[0] !== 0x05) throw new Error('SOCKS5 greeting failed');
    
    // 检查服务端选中的 Method
    const selectedMethod = res[1];
    if (selectedMethod === 0xff) throw new Error('SOCKS5 no acceptable methods');
    
    // 2. Auth (如果服务端选中了 0x02)
    if (selectedMethod === 0x02) {
        if (!username || !password) throw new Error('SOCKS5 auth required but credentials missing');
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

        socket.isUdpControl = true;
        socket.bndAddr = bndAddr;
        socket.bndPort = bndPort;
        socket.originalHost = hostname; 
        
        return socket;
    }
    
    // TCP: Skip BND info and keep Initial Data
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
    
    const DIRECT_TIMEOUTS = [4000, 8000]; 
    const PROXY_TIMEOUT = 10000; 

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
            const v6Address = await resolveToIPv6(addressRemote, ctx.dns64, ctx);
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

function getSocks5UdpHeaderLength(buffer) {
    if (buffer.length < 4) return -1; 
    const atyp = buffer[3];
    if (atyp === 1) return 10; 
    if (atyp === 4) return 22; 
    if (atyp === 3) {
        if (buffer.length < 5) return -1; 
        const len = buffer[4];
        return 7 + len; 
    }
    return 0; 
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
    const WRITE_TIMEOUT = 30000; 
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

async function handleSocks5UDPFlow(controlSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log, finalizeConnectionCallback) {
    const { bndAddr, bndPort, originalHost } = controlSocket;
    
    let targetHost = bndAddr;
    const isZeroIP = bndAddr === '0.0.0.0' || bndAddr === '::' || bndAddr.startsWith('0:0:0:0') || bndAddr === '[::]';
    if (isZeroIP && originalHost) {
        targetHost = originalHost;
        log(`[SOCKS5] BND.ADDR is ${bndAddr}, falling back to proxy host: ${targetHost}`);
    }

    log(`[SOCKS5] UDP Associate ready. Relay: ${targetHost}:${bndPort}`);
    
    const udpSocket = connect({ hostname: targetHost, port: bndPort });
    finalizeConnectionCallback(udpSocket);
    
    const udpWriter = udpSocket.writable.getWriter();
    
    const header = createSocks5UdpHeader(addressType, addressRemote, portRemote);
    if (rawClientData && rawClientData.byteLength > 0) {
        const packet = new Uint8Array(header.length + rawClientData.byteLength);
        packet.set(header);
        packet.set(new Uint8Array(rawClientData), header.length);
        await safeWrite(udpWriter, packet);
    }
    udpWriter.releaseLock();

    let responseHeader = vlessResponseHeader;
    let udpBuffer = new Uint8Array(0); 
    let isHeaderComplete = false; 

    const MAX_UDP_BUFFER = 65535; 

    await udpSocket.readable.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (webSocket.readyState !== 1) { controller.error(new Error('WS Closed')); return; }
            
            udpBuffer = concatUint8(udpBuffer, chunk);
            
            if (udpBuffer.length > MAX_UDP_BUFFER) {
                udpBuffer = new Uint8Array(0); 
                return;
            }

            if (!isHeaderComplete) {
                const headerLen = getSocks5UdpHeaderLength(udpBuffer);
                
                if (headerLen > 0) {
                    if (udpBuffer.length >= headerLen) {
                        const payload = udpBuffer.subarray(headerLen);
                        
                        const dataToSend = responseHeader 
                            ? new Uint8Array([...responseHeader, ...payload])
                            : payload;
                        responseHeader = null;
                        
                        if (dataToSend.length > 0) {
                             webSocket.send(dataToSend);
                        }
                        
                        isHeaderComplete = true;
                        udpBuffer = new Uint8Array(0);
                    }
                } else if (headerLen === 0) {
                     udpBuffer = new Uint8Array(0);
                }
            } else {
                if (udpBuffer.length > 0) {
                    const dataToSend = responseHeader 
                        ? new Uint8Array([...responseHeader, ...udpBuffer]) 
                        : udpBuffer;
                    responseHeader = null;
                    
                    webSocket.send(dataToSend);
                    udpBuffer = new Uint8Array(0);
                }
            }
        },
        close() { 
            log('UDP Relay closed'); 
            controlSocket.close(); 
        },
        abort(e) { controlSocket.close(); }
    })).catch(() => { controlSocket.close(); safeCloseWebSocket(webSocket); });
}

export async function handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
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
            const v6Address = await resolveToIPv6(addressRemote, ctx.dns64, ctx);
            if (!v6Address) throw new Error('DNS64 failed');
            const natSocket = await connectWithTimeout(v6Address, portRemote, 10000, log);
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
                const proxySocket = await connectWithTimeout(proxyHost.toLowerCase(), proxyPort, 10000, log);
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
            const natSocket = await connectWithTimeout(v6Address, portRemote, 10000, log);
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
            
            try {
                const socksConfig = { hostname: proxyHost, port: proxyPort, username: '', password: '' };
                const connectionObj = await socks5Connect(socksConfig, addressType, addressRemote, portRemote, log, true);
                if (connectionObj.isUdpControl) {
                    await handleSocks5UDPFlow(connectionObj, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log, finalizeConnection);
                    return; 
                }
            } catch (socksErr) { }

            try {
                const proxySocket = await connectWithTimeout(proxyHost.toLowerCase(), proxyPort, 10000, log);
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
