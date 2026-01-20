/**
 * 文件名: src/handlers/outbound.js
 * 核心优化: 实现了“零配置”穿透 Cloudflare 回环限制。
 * 逻辑变更: 当访问 443 端口失败时，优先尝试连接【目标地址自身】的非标准端口 (2053/2096等)。
 * 优势: 不再依赖 ProxyIP 列表，直接利用目标网站 IP 进行端口绕过，实现免维护。
 */
import { connect } from 'cloudflare:sockets';
import { CONSTANTS } from '../constants.js';
import { resolveToIPv6, parseIPv6 } from '../utils/dns.js';
import { safeCloseWebSocket, isHostBanned } from '../utils/helpers.js';

// Cloudflare 支持的非标准 HTTPS 端口
const CF_FALLBACK_PORTS = [2053, 2096, 8443, 2083, 2087];

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
    
    // SOCKS5 Hello
    await writer.write(new Uint8Array([5, 1, 2])); 
    let { value: res } = await reader.read();
    
    if (!res || res[0] !== 0x05 || res[1] === 0xff) throw new Error('SOCKS5 greeting failed');
    
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
             DSTADDR = new Uint8Array([4, ...parseIPv6(addressRemote.replace(/[\[\]]/g, ''))]);
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

export async function createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log) {
    const useSocks = ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5);
    const STEPPED_TIMEOUTS = [4000, 5000, 6000];
    let attemptCounter = 0;

    const connectAndWrite = async (host, port, isSocks) => {
        const currentTimeout = STEPPED_TIMEOUTS[Math.min(attemptCounter, STEPPED_TIMEOUTS.length - 1)];
        attemptCounter++;

        log(`[connect] Target: ${host}:${port} (Socks: ${isSocks})`);
        
        const doConnect = async () => {
             if (isSocks) {
                return await socks5Connect(ctx.socks5, addressType, addressRemote, portRemote, log);
            } else {
                return connect({ hostname: host, port: port });
            }
        };

        const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error(`Timeout ${currentTimeout}ms`)), currentTimeout));
        const socket = await Promise.race([doConnect(), timeoutPromise]);
        
        if (!isSocks) {
            await Promise.race([socket.opened, timeoutPromise]);
        }
        return socket;
    };

    // -----------------------------------------------------------
    // Phase 1: 尝试直连 (Direct Connection)
    // -----------------------------------------------------------
    try {
        return await connectAndWrite(addressRemote, portRemote, useSocks);
    } catch (err1) {
        log(`[connect] Phase 1 (Direct) failed: ${err1.message}`);

        // -----------------------------------------------------------
        // Phase 1.5: 端口自救 (Self-Port Fallback)
        // 说明: 如果直连 443 失败，很可能是被 CF 阻断。
        // 我们不急着找 ProxyIP，而是直接连【目标地址本身】的 2053 等端口。
        // 这不需要 ProxyIP，因为目标地址本身就是最稳定的 IP。
        // -----------------------------------------------------------
        if (!useSocks && portRemote === 443) {
            log(`[connect] Phase 1.5: Attempting Self-Port Fallback on ${addressRemote}...`);
            for (const fallbackPort of CF_FALLBACK_PORTS) {
                try {
                    // 直接尝试连接原目标域名，但是换端口
                    const fallbackSocket = await connectAndWrite(addressRemote, fallbackPort, false);
                    if (fallbackSocket) {
                        log(`[connect] Phase 1.5 Success: Connected to ${addressRemote}:${fallbackPort}`);
                        return fallbackSocket;
                    }
                } catch (errFallback) {
                    // 忽略单个端口的失败，继续尝试下一个
                }
            }
            log(`[connect] Phase 1.5 (Self-Port Fallback) failed.`);
        }
    }

    // -----------------------------------------------------------
    // Phase 2: ProxyIP (仅当用户显式配置了 ProxyIP 或 默认列表时)
    // -----------------------------------------------------------
    let proxyAttempts = [];
    if (ctx.proxyIP) proxyAttempts.push(ctx.proxyIP);
    if (ctx.proxyIPList && ctx.proxyIPList.length > 0) {
        for (let i = 0; i < 2; i++) {
            const randomIP = ctx.proxyIPList[Math.floor(Math.random() * ctx.proxyIPList.length)];
            if (randomIP && !proxyAttempts.includes(randomIP)) proxyAttempts.push(randomIP);
        }
    }
    // 只有在真的没有办法时，才使用默认硬编码 IP，或者你也可以在这里留空
    if (proxyAttempts.length === 0) proxyAttempts.push(CONSTANTS.DEFAULT_PROXY_IP);
    
    proxyAttempts = [...new Set(proxyAttempts)].filter(Boolean);

    for (const ip of proxyAttempts) {
        const { host: proxyHost, port: proxyPort } = parseProxyIP(ip, portRemote);
        try {
            // 尝试 ProxyIP 的标准端口
            return await connectAndWrite(proxyHost.toLowerCase(), proxyPort, false);
        } catch (err2) {
             // 尝试 ProxyIP 的非标准端口
             if (proxyPort === 443) {
                for (const fallbackPort of CF_FALLBACK_PORTS) {
                    try {
                        return await connectAndWrite(proxyHost.toLowerCase(), fallbackPort, false);
                    } catch (e) {}
                }
             }
        }
    }

    // -----------------------------------------------------------
    // Phase 3: NAT64 Fallback
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
                if (webSocket.readyState !== 1) return;
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
        if (error.message !== 'webSocket is not open') console.error('remoteSocketToWS error:', error);
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
    // 定义重试逻辑：当初始连接成功但无数据返回时触发
    const genericRetry = async () => {
        log('[Retry] Generic retry sequence initiated...');
        
        // 尝试: 目标自身 IP + 非标准端口 (Port Hopping)
        if (portRemote === 443) {
             for (const fallbackPort of CF_FALLBACK_PORTS) {
                 try {
                     log(`[Retry] Attempting Self-Port Hop: ${addressRemote}:${fallbackPort}`);
                     const socket = await connect({ hostname: addressRemote, port: fallbackPort });
                     
                     remoteSocketWrapper.value = socket;
                     remoteSocketWrapper.isConnecting = false;
                     const writer = socket.writable.getWriter();
                     if (rawClientData && rawClientData.byteLength > 0) await writer.write(rawClientData);
                     writer.releaseLock();
                     
                     // 成功则开始转发，不再继续重试
                     remoteSocketToWS(socket, webSocket, vlessResponseHeader, null, log);
                     return; 
                 } catch (e) {
                     // ignore
                 }
             }
        }

        // 如果上面失败，尝试 ProxyIP
        let attempts = [];
        if (ctx.proxyIP) attempts.push(ctx.proxyIP);
        if (ctx.proxyIPList) attempts.push(...ctx.proxyIPList);
        if (attempts.length === 0) attempts.push(CONSTANTS.DEFAULT_PROXY_IP);
        attempts = [...new Set(attempts)].filter(Boolean);

        for (const ip of attempts) {
             const { host, port } = parseProxyIP(ip, portRemote);
             const tryList = port === 443 ? [443, ...CF_FALLBACK_PORTS] : [port];
             
             for (const p of tryList) {
                 try {
                     log(`[Retry] Attempting ProxyIP: ${host}:${p}`);
                     const socket = await connect({ hostname: host.toLowerCase(), port: p });
                     remoteSocketWrapper.value = socket;
                     remoteSocketWrapper.isConnecting = false;
                     const writer = socket.writable.getWriter();
                     if (rawClientData && rawClientData.byteLength > 0) await writer.write(rawClientData);
                     writer.releaseLock();
                     remoteSocketToWS(socket, webSocket, vlessResponseHeader, null, log);
                     return;
                 } catch (e) {}
             }
        }
        
        // 最后尝试 NAT64
        if (ctx.dns64) {
             try {
                const nat64IP = '[' + (await resolveToIPv6(addressRemote, ctx.dns64)) + ']';
                log(`[Retry] Attempting NAT64: ${nat64IP}`);
                const socket = await connect({ hostname: nat64IP, port: portRemote });
                remoteSocketWrapper.value = socket;
                remoteSocketWrapper.isConnecting = false;
                const writer = socket.writable.getWriter();
                if (rawClientData && rawClientData.byteLength > 0) await writer.write(rawClientData);
                writer.releaseLock();
                remoteSocketToWS(socket, webSocket, vlessResponseHeader, null, log);
             } catch(e) {
                 safeCloseWebSocket(webSocket);
             }
        } else {
             safeCloseWebSocket(webSocket);
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
            for (const chunk of remoteSocketWrapper.buffer) {
                await writer.write(chunk);
            }
            remoteSocketWrapper.buffer = [];
        }
        writer.releaseLock();
        
        remoteSocketToWS(socket, webSocket, vlessResponseHeader, genericRetry, log);
        
    } catch (error) {
        log('[Outbound] Initial connection failed: ' + error.message);
        safeCloseWebSocket(webSocket);
    }
}
