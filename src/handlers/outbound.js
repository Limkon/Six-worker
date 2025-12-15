/**
 * 文件名: src/handlers/outbound.js
 * 修复说明:
 * 1. [核心] 重构 createUnifiedConnection，将 Phase 2 和 Phase 3 从嵌套结构改为线性结构，确保降级逻辑正确执行。
 * 2. 移除 Phase 2 的 `if (!useSocks)` 判断，确保 Socks5 失败后也能降级到 ProxyIP。
 * 3. 修正 NAT64 的触发条件逻辑。
 */
import { connect } from 'cloudflare:sockets';
import { CONSTANTS } from '../constants.js';
import { resolveToIPv6, parseIPv6 } from '../utils/dns.js';
import { safeCloseWebSocket, isHostBanned } from '../utils/helpers.js';

function parseProxyIP(proxyAddr, defaultPort) {
    if (!proxyAddr) return { host: CONSTANTS.DEFAULT_PROXY_IP, port: defaultPort };
    
    let host = proxyAddr;
    let port = defaultPort;
    
    const bracketIndex = host.lastIndexOf(']:');
    if (host.startsWith('[') && bracketIndex > 0) {
        const portStr = host.substring(bracketIndex + 2);
        if (/^\d+$/.test(portStr)) port = parseInt(portStr, 10);
        host = host.substring(1, bracketIndex);
        return { host, port };
    }
    
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
    const cleanAddr = address.replace(/^https?:\/\//i, '');
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
    
    await writer.write(new Uint8Array([5, 2, 0, 2]));
    let { value: res } = await reader.read();
    
    if (!res || res[0] !== 0x05 || res[1] === 0xff) throw new Error('SOCKS5 greeting failed');
    
    if (res[1] === 0x02) {
        if (!username || !password) throw new Error('SOCKS5 auth required');
        const authReq = new Uint8Array([1, username.length, ...encoder.encode(username), password.length, ...encoder.encode(password)]);
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
             DSTADDR = new Uint8Array([4, ...parseIPv6(addressRemote.replace(/[\[\]]/g, ''))]);
             break;
        default:
             DSTADDR = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]);
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
    const CONNECT_TIMEOUT_MS = 5000;
    const enableHttp = ctx.socks5 && ctx.socks5.toLowerCase().startsWith('http://');
    const useSocks = ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5);

    const connectAndWrite = async (host, port, isSocks) => {
        log(`[connect] Target: ${host}:${port} (Socks: ${isSocks})`);
        const doConnect = async () => {
             if (isSocks) {
                return await socks5Connect(ctx.socks5, addressType, addressRemote, portRemote, log);
            } else {
                return connect({ hostname: host, port: port });
            }
        };
        const remote = doConnect();
        const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Connect timeout')), CONNECT_TIMEOUT_MS));
        const socket = await remote;
        if (!isSocks) await Promise.race([socket.opened, timeoutPromise]);
        return socket;
    };

    // -----------------------------------------------------------
    // Phase 1: Direct / Socks5
    // -----------------------------------------------------------
    try {
        return await connectAndWrite(addressRemote, portRemote, useSocks);
    } catch (err1) {
        log(`[connect] Phase 1 failed: ${err1.message}`);
    }

    // -----------------------------------------------------------
    // Phase 2: ProxyIP Fallback (Unconditional)
    // -----------------------------------------------------------
    const currentProxyIP = fallbackAddress || ctx.proxyIP;
    const { host: proxyHost, port: proxyPort } = parseProxyIP(currentProxyIP, portRemote);
    try {
        return await connectAndWrite(proxyHost.toLowerCase(), proxyPort, false);
    } catch (err2) {
        log(`[connect] Phase 2 (ProxyIP: ${proxyHost}) failed: ${err2.message}`);
    }

    // -----------------------------------------------------------
    // Phase 3: NAT64 Fallback (Only if not using Socks)
    // -----------------------------------------------------------
    if (!useSocks && ctx.dns64) {
        try {
            log(`[connect] Phase 3: Attempting NAT64...`);
            const nat64IP = '[' + (await resolveToIPv6(addressRemote, ctx.dns64)) + ']';
            return await connectAndWrite(nat64IP, portRemote, false);
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
                    controller.error('webSocket is not open');
                }
                if (responseHeader) {
                    webSocket.send(await new Blob([responseHeader, chunk]).arrayBuffer());
                    responseHeader = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            close() { log(`Remote socket closed. Data: ${hasIncomingData}`); },
            abort(reason) { console.error('Remote socket aborted', reason); },
        })
    ).catch((error) => {
        console.error('remoteSocketToWS error:', error);
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

export async function handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
    // 闭包重试逻辑：NAT64
    const nat64Retry = async () => {
        if (!ctx.dns64) { safeCloseWebSocket(webSocket); return; }
        log('[Retry] Switching to NAT64...');
        try {
            const nat64IP = '[' + (await resolveToIPv6(addressRemote, ctx.dns64)) + ']';
            const natSocket = await connect({ hostname: nat64IP, port: portRemote });
            
            remoteSocketWrapper.value = natSocket;
            remoteSocketWrapper.isConnecting = false;
            
            remoteSocketToWS(natSocket, webSocket, vlessResponseHeader, null, log);
        } catch (e) {
            log('[Retry] NAT64 failed: ' + e.message);
            safeCloseWebSocket(webSocket);
        }
    };

    // 闭包重试逻辑：ProxyIP
    const proxyIPRetry = async () => {
        log('[Retry] Switching to ProxyIP...');
        try {
            const { host: proxyHost, port: proxyPort } = parseProxyIP(ctx.proxyIP, portRemote);
            const proxySocket = await connect({ hostname: proxyHost.toLowerCase(), port: proxyPort });
            
            remoteSocketWrapper.value = proxySocket;
            remoteSocketWrapper.isConnecting = false;
            
            // ProxyIP 连接成功后，若无数据，下一个 fallback 是 NAT64 (如果条件允许)
            const useSocks = ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5);
            const nextRetry = (!useSocks && ctx.dns64) ? nat64Retry : null;
            
            remoteSocketToWS(proxySocket, webSocket, vlessResponseHeader, nextRetry, log);
        } catch (e) {
            log('[Retry] ProxyIP failed: ' + e.message);
            // ProxyIP 连接失败，立即尝试 NAT64
            if (ctx.dns64 && !(ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5))) {
                await nat64Retry();
            } else {
                safeCloseWebSocket(webSocket);
            }
        }
    };

    try {
        const socket = await createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log);
        remoteSocketWrapper.value = socket;
        remoteSocketWrapper.isConnecting = false;
        
        const writer = socket.writable.getWriter();
        
        if (rawClientData && rawClientData.byteLength > 0) {
            await writer.write(rawClientData);
        }
        
        if (remoteSocketWrapper.buffer && remoteSocketWrapper.buffer.length > 0) {
            log(`Flushing ${remoteSocketWrapper.buffer.length} buffered chunks`);
            for (const chunk of remoteSocketWrapper.buffer) {
                await writer.write(chunk);
            }
            remoteSocketWrapper.buffer = [];
        }
        writer.releaseLock();
        
        remoteSocketToWS(socket, webSocket, vlessResponseHeader, proxyIPRetry, log);
        
    } catch (error) {
        log('[Outbound] Initial connection failed: ' + error.message);
        safeCloseWebSocket(webSocket);
    }
}
