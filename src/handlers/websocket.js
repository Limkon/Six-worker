// src/handlers/websocket.js
/**
 * 文件名: src/handlers/websocket.js
 * 审计修复说明:
 * 1. [Fix] 修复 bufferedBytes 计数器同步 Bug: 当底层 Buffer 数组被 outbound.js 清空时，自动重置计数器，防止重试期间误触发熔断。
 * 2. [Optimization] 调整计数器逻辑位置，确保仅在连接成功 accept 后才计数，防止同步错误导致的计数泄漏。
 */
import { ProtocolManager } from '../protocols/manager.js';
import { processVlessHeader } from '../protocols/vless.js';
import { parseTrojanHeader } from '../protocols/trojan.js';
import { parseMandalaHeader } from '../protocols/mandala.js';
import { parseSocks5Header } from '../protocols/socks5.js';
import { parseShadowsocksHeader } from '../protocols/shadowsocks.js';
import { handleTCPOutBound, handleUDPOutBound } from './outbound.js';
import { safeCloseWebSocket, base64ToArrayBuffer, isHostBanned } from '../utils/helpers.js';

// 注册支持的协议解析器
const protocolManager = new ProtocolManager()
    .register('vless', processVlessHeader)
    .register('trojan', parseTrojanHeader)
    .register('mandala', parseMandalaHeader)
    .register('socks5', parseSocks5Header)
    .register('ss', parseShadowsocksHeader);

// [Smart Global State] 全局活跃连接计数器
let activeWebSocketConnections = 0;

function concatUint8(a, b) {
    const bArr = b instanceof Uint8Array ? b : new Uint8Array(b);
    const res = new Uint8Array(a.length + bArr.length);
    res.set(a);
    res.set(bArr, a.length);
    return res;
}

// 动态计算最大缓冲区大小
function getDynamicBufferSize() {
    if (activeWebSocketConnections < 5) return 10 * 1024 * 1024; 
    if (activeWebSocketConnections < 20) return 2 * 1024 * 1024; 
    if (activeWebSocketConnections < 50) return 512 * 1024;      
    return 128 * 1024;                                           
}

export async function handleWebSocketRequest(request, ctx) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    
    // [Optimization] 增加 try-catch 确保 accept 失败时不会导致计数器泄漏
    try {
        webSocket.accept();
    } catch (e) {
        console.error('[WS] Accept failed', e);
        return new Response('WebSocket Accept Failed', { status: 500 });
    }

    // 1. 成功建立连接后，增加计数
    activeWebSocketConnections++;

    let remoteSocketWrapper = { value: null, isConnecting: false, buffer: [], bufferedBytes: 0 };
    let isConnected = false; 
    let socks5State = 0; 
    
    let vlessBuffer = new Uint8Array(0); 
    
    let activeWriter = null;
    let activeSocket = null;
    
    const MAX_HEADER_BUFFER = 2048; 
    const PROBE_THRESHOLD = 1024;   
    const DETECT_TIMEOUT_MS = 10000; 

    const log = (info, event) => console.log(`[WS][Conns:${activeWebSocketConnections}] ${info}`, event || '');

    const timeoutTimer = setTimeout(() => {
        if (!isConnected) {
            log('Timeout: Protocol detection took too long');
            safeCloseWebSocket(webSocket);
        }
    }, DETECT_TIMEOUT_MS);

    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    const streamPromise = readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            const chunkArr = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);

            // --- 阶段二：已连接状态 ---
            if (isConnected) {
                if (activeSocket !== remoteSocketWrapper.value) {
                    if (activeWriter) {
                        try { await activeWriter.ready; activeWriter.releaseLock(); } catch(e) {}
                        activeWriter = null;
                    }
                    activeSocket = remoteSocketWrapper.value;
                    if (activeSocket) {
                        try { activeWriter = activeSocket.writable.getWriter(); } 
                        catch (e) { safeCloseWebSocket(webSocket); return; }
                    }
                }
                
                if (activeWriter) {
                    await activeWriter.write(chunkArr);
                } else if (remoteSocketWrapper.isConnecting) {
                    // [Fix] 关键修复: 同步计数器状态
                    // 如果 outbound.js 已经清空了 buffer 数组，我们需要重置计数器
                    if (remoteSocketWrapper.buffer.length === 0) {
                        remoteSocketWrapper.bufferedBytes = 0;
                    }

                    // [Smart Security] 智能熔断检查
                    const newSize = remoteSocketWrapper.bufferedBytes + chunkArr.byteLength;
                    const dynamicLimit = getDynamicBufferSize(); 
                    
                    if (newSize > dynamicLimit) {
                        clearTimeout(timeoutTimer);
                        throw new Error(`Smart Buffer Limit Exceeded: ${newSize} > ${dynamicLimit} (ActiveConns: ${activeWebSocketConnections})`);
                    }

                    remoteSocketWrapper.buffer.push(chunkArr);
                    remoteSocketWrapper.bufferedBytes = newSize;
                }
                return;
            }

            // --- 阶段一：协议识别 ---
            vlessBuffer = concatUint8(vlessBuffer, chunkArr);

            if (vlessBuffer.length > MAX_HEADER_BUFFER) {
                clearTimeout(timeoutTimer);
                throw new Error(`Header buffer limit exceeded`);
            }

            if (socks5State < 2) {
                const { consumed, newState, error } = tryHandleSocks5Handshake(vlessBuffer, socks5State, webSocket, ctx, log);
                if (error) { clearTimeout(timeoutTimer); throw new Error(error); }
                if (consumed > 0) {
                    vlessBuffer = vlessBuffer.slice(consumed);
                    socks5State = newState;
                    if (socks5State !== 2) return; 
                }
            }

            if (vlessBuffer.length === 0) return;

            try {
                const result = await protocolManager.detect(vlessBuffer, ctx);
                
                if (socks5State === 2 && result.protocol !== 'socks5') {
                    throw new Error('Protocol mismatch after Socks5 handshake');
                }

                const pName = result.protocol; 
                const isSocksDisabled = pName === 'socks5' && ctx.disabledProtocols.includes('socks');
                if (ctx.disabledProtocols.includes(pName) || isSocksDisabled) {
                    throw new Error(`Protocol ${pName} is disabled`);
                }

                const { protocol, addressRemote, portRemote, addressType, rawDataIndex, isUDP } = result;
                
                log(`Detected: ${protocol.toUpperCase()} -> ${addressRemote}:${portRemote}`);
                
                if (isHostBanned(addressRemote, ctx.banHosts)) {
                    throw new Error(`Blocked: ${addressRemote}`);
                }
                
                isConnected = true;
                clearTimeout(timeoutTimer); 
                remoteSocketWrapper.isConnecting = true;

                let clientData = vlessBuffer; 
                let responseHeader = null;

                if (protocol === 'vless') {
                    clientData = vlessBuffer.subarray(rawDataIndex);
                    responseHeader = new Uint8Array([result.cloudflareVersion[0], 0]);
                } else if (protocol === 'trojan' || protocol === 'ss' || protocol === 'mandala') {
                    clientData = result.rawClientData;
                } else if (protocol === 'socks5') {
                    clientData = result.rawClientData;
                    webSocket.send(new Uint8Array([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]));
                    socks5State = 3;
                }

                vlessBuffer = null; 

                if (isUDP) {
                    handleUDPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);
                } else {
                    handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);
                }

            } catch (e) {
                if (vlessBuffer && vlessBuffer.length < PROBE_THRESHOLD && vlessBuffer.length < MAX_HEADER_BUFFER) {
                    return; 
                }
                clearTimeout(timeoutTimer);
                log(`Detection failed: ${e.message}`);
                safeCloseWebSocket(webSocket);
            }
        },
        close() { cleanup(); },
        abort(reason) { cleanup(); safeCloseWebSocket(webSocket); },
    })).catch((err) => {
        clearTimeout(timeoutTimer);
        cleanup();
        safeCloseWebSocket(webSocket);
    });

    function cleanup() {
        if (activeWriter) { try { activeWriter.releaseLock(); } catch(e) {} activeWriter = null; }
        if (remoteSocketWrapper.value) { try { remoteSocketWrapper.value.close(); } catch(e) {} remoteSocketWrapper.value = null; }
    }

    if (ctx.waitUntil) {
        ctx.waitUntil(streamPromise.finally(() => {
            activeWebSocketConnections--;
            if (activeWebSocketConnections < 0) activeWebSocketConnections = 0;
        }));
    } else {
        streamPromise.finally(() => {
            activeWebSocketConnections--;
            if (activeWebSocketConnections < 0) activeWebSocketConnections = 0;
        });
    }

    return new Response(null, { status: 101, webSocket: client });
}

function tryHandleSocks5Handshake(buffer, currentState, webSocket, ctx, log) {
    const res = { consumed: 0, newState: currentState, error: null };
    if (buffer.length === 0) return res;

    if (currentState === 0) {
        if (buffer[0] !== 0x05) return res; 
        if (buffer.length < 2) return res; 
        const nMethods = buffer[1];
        if (buffer.length < 2 + nMethods) return res; 

        const methods = buffer.subarray(2, 2 + nMethods);
        let hasAuth = false;
        for (let m of methods) { if (m === 0x02) hasAuth = true; }

        if (hasAuth) {
            webSocket.send(new Uint8Array([0x05, 0x02])); 
            res.newState = 1;
        } else {
            webSocket.send(new Uint8Array([0x05, 0xFF])); 
            res.error = "Socks5: No supported auth method";
            return res;
        }
        res.consumed = 2 + nMethods;
        return res;
    }

    if (currentState === 1) {
        if (buffer.length < 3) return res;
        if (buffer[0] !== 0x01) { res.error = "Socks5 Auth: Wrong version"; return res; }
        
        let offset = 1;
        const uLen = buffer[offset++];
        if (buffer.length < offset + uLen + 1) return res;
        const user = new TextDecoder().decode(buffer.subarray(offset, offset + uLen));
        offset += uLen;
        const pLen = buffer[offset++];
        if (buffer.length < offset + pLen) return res;
        const pass = new TextDecoder().decode(buffer.subarray(offset, offset + pLen));
        offset += pLen;

        const isValid = (user === ctx.userID || user === ctx.dynamicUUID) && 
                        (pass === ctx.dynamicUUID || pass === ctx.userID);
        
        if (isValid) {
            webSocket.send(new Uint8Array([0x01, 0x00])); 
            res.newState = 2;
            res.consumed = offset;
        } else {
            webSocket.send(new Uint8Array([0x01, 0x01])); 
            res.error = `Socks5 Auth Failed: ${user}`;
        }
        return res;
    }
    return res;
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    let isStreamClosed = false; 

    return new ReadableStream({
        start(controller) {
            const safeEnqueue = (chunk) => {
                if (readableStreamCancel || isStreamClosed) return;
                try { controller.enqueue(chunk); } catch (e) { }
            };
            
            const safeClose = () => {
                if (readableStreamCancel || isStreamClosed) return;
                try { controller.close(); isStreamClosed = true; } catch (e) { }
            };

            const safeError = (e) => {
                if (readableStreamCancel || isStreamClosed) return;
                try { controller.error(e); isStreamClosed = true; } catch (err) { }
            };

            webSocketServer.addEventListener('message', (event) => {
                const data = typeof event.data === 'string' 
                    ? new TextEncoder().encode(event.data) 
                    : event.data;
                safeEnqueue(data);
            });
            
            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                safeClose();
            });
            
            webSocketServer.addEventListener('error', (err) => {
                safeError(err);
            });
            
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) safeError(error);
            else if (earlyData) safeEnqueue(earlyData);
        },
        cancel() { 
            readableStreamCancel = true; 
            safeCloseWebSocket(webSocketServer); 
        }
    });
}
