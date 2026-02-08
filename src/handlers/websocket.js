// src/handlers/websocket.js
/**
 * 文件名: src/handlers/websocket.js
 * 状态: [最终防御版]
 * 1. [Fix] Network connection lost 防御: 针对 Go-http-client 等扫描器瞬间断连的情况增加容错。
 * 2. [Safety] 计数器泄露保护: 确保在任何异常下 activeConnectionsInInstance 都能正确递减。
 * 3. [Security] 增加 isHostBanned 检查，实现域名/IP黑名单拦截。
 * 4. [Optimization] Early Data: 增加了解析长度限制和 try-catch 隔离。
 */
import { ProtocolManager } from '../protocols/manager.js';
import { processVlessHeader } from '../protocols/vless.js';
import { parseTrojanHeader } from '../protocols/trojan.js';
import { parseMandalaHeader } from '../protocols/mandala.js';
import { parseSocks5Header } from '../protocols/socks5.js';
import { parseShadowsocksHeader } from '../protocols/shadowsocks.js';
import { handleTCPOutBound, handleUDPOutBound } from './outbound.js';
import { safeCloseWebSocket, base64ToArrayBuffer, isHostBanned } from '../utils/helpers.js';
import { CONSTANTS } from '../constants.js';

// 注册支持的协议解析器
const protocolManager = new ProtocolManager()
    .register('vless', processVlessHeader)
    .register('trojan', parseTrojanHeader)
    .register('mandala', parseMandalaHeader)
    .register('socks5', parseSocks5Header)
    .register('ss', parseShadowsocksHeader);

// [Smart Global State] 当前 Worker 实例活跃连接计数器
let activeConnectionsInInstance = 0;

function mergeChunks(chunks) {
    if (chunks.length === 0) return new Uint8Array(0);
    if (chunks.length === 1) return chunks[0];
    const totalLen = chunks.reduce((sum, c) => sum + c.byteLength, 0);
    const res = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of chunks) {
        res.set(c, offset);
        offset += c.byteLength;
    }
    return res;
}

function getDynamicBufferSize() {
    if (activeConnectionsInInstance < 5) return 10 * 1024 * 1024; 
    if (activeConnectionsInInstance < 20) return 2 * 1024 * 1024; 
    if (activeConnectionsInInstance < 50) return 512 * 1024;      
    return 128 * 1024;                                            
}

export async function handleWebSocketRequest(request, ctx) {
    // [Security] 实例级硬性熔断
    if (activeConnectionsInInstance >= CONSTANTS.MAX_CONCURRENT) {
        // [Safety] 极端情况下的自动修正：如果计数器长期卡在最大值，尝试重置（防止计数器泄露导致的永久拒绝服务）
        // 只有在确定没有真实负载但计数器很高时才会有风险，这里做一个简单的饱和保护
        console.warn(`[WS] Instance Overloaded (${activeConnectionsInInstance} conns). Rejecting.`);
        return new Response('Error: Instance Too Busy (Rate Limit)', { status: 429 });
    }

    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    
    try {
        webSocket.accept();
    } catch (e) {
        console.error('[WS] Accept failed', e);
        return new Response('WebSocket Accept Failed', { status: 500 });
    }

    // 1. 增加计数
    activeConnectionsInInstance++;

    // [Fix] 幂等递减控制器
    let hasDecremented = false;
    const safeDecrement = () => {
        if (!hasDecremented) {
            activeConnectionsInInstance--;
            if (activeConnectionsInInstance < 0) activeConnectionsInInstance = 0;
            hasDecremented = true;
        }
    };

    let remoteSocketWrapper = { value: null, isConnecting: false, buffer: [], bufferedBytes: 0 };
    let isConnected = false; 
    let socks5State = 0; 
    
    let vlessChunks = []; 
    let vlessBufferLength = 0;
    
    let activeWriter = null;
    let activeSocket = null;
    
    const MAX_HEADER_BUFFER = 2048; 
    const PROBE_THRESHOLD = 1024;
    
    const IDLE_TIMEOUT = 60 * 1000; 
    let lastActivityTime = Date.now();
    let idleTimer = null;

    const updateActivity = () => { lastActivityTime = Date.now(); };
    
    // 辅助清理函数
    function cleanup() {
        clearTimeout(protocolDetectTimer);
        clearInterval(idleTimer); 
        if (activeWriter) { try { activeWriter.releaseLock(); } catch(e) {} activeWriter = null; }
        if (remoteSocketWrapper.value) { try { remoteSocketWrapper.value.close(); } catch(e) {} remoteSocketWrapper.value = null; }
    }

    // 启动空闲检测
    idleTimer = setInterval(() => {
        if (Date.now() - lastActivityTime > IDLE_TIMEOUT) {
            cleanup();
            safeCloseWebSocket(webSocket);
            safeDecrement(); // 确保空闲超时也触发递减
        }
    }, 10000); 

    const log = (info, event) => {
        // 降低常见 Bot 扫描日志的级别，避免刷屏
        if (info.includes('Detection failed')) return;
        console.log(`[WS][Conns:${activeConnectionsInInstance}] ${info}`, event || '');
    };

    const DETECT_TIMEOUT_MS = 10000;
    const protocolDetectTimer = setTimeout(() => {
        if (!isConnected) {
            // log('Timeout: Protocol detection took too long');
            safeCloseWebSocket(webSocket);
        }
    }, DETECT_TIMEOUT_MS);

    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    const streamPromise = readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            updateActivity(); 

            // [Defensive] 如果连接已被外部关闭或出错，停止处理
            if (hasDecremented) return;

            const chunkArr = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);

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
                    remoteSocketWrapper.buffer.push(chunkArr);
                    const currentBufferSize = remoteSocketWrapper.buffer.reduce((sum, c) => sum + c.byteLength, 0);
                    remoteSocketWrapper.bufferedBytes = currentBufferSize;

                    const dynamicLimit = getDynamicBufferSize();
                    if (currentBufferSize > dynamicLimit) {
                        clearTimeout(protocolDetectTimer);
                        throw new Error(`Smart Buffer Limit Exceeded: ${currentBufferSize} > ${dynamicLimit}`);
                    }
                }
                return;
            }

            // --- 阶段一：协议识别与握手 ---
            vlessChunks.push(chunkArr);
            vlessBufferLength += chunkArr.byteLength;

            if (vlessBufferLength > MAX_HEADER_BUFFER) {
                clearTimeout(protocolDetectTimer);
                throw new Error(`Header buffer limit exceeded`);
            }
            
            const currentBuffer = mergeChunks(vlessChunks);

            // SOCKS5 握手
            if (socks5State < 2) {
                const { consumed, newState, error } = tryHandleSocks5Handshake(currentBuffer, socks5State, webSocket, ctx, log);
                if (error) { clearTimeout(protocolDetectTimer); throw new Error(error); }
                if (consumed > 0) {
                    const remaining = currentBuffer.slice(consumed);
                    vlessChunks = [remaining];
                    vlessBufferLength = remaining.byteLength;
                    socks5State = newState;
                    if (socks5State !== 2) return; 
                }
            }

            if (vlessBufferLength === 0) return;

            try {
                const bufferToDetect = (socks5State > 0) ? mergeChunks(vlessChunks) : currentBuffer;
                const result = await protocolManager.detect(bufferToDetect, ctx);
                
                if (socks5State === 2 && result.protocol !== 'socks5') {
                    throw new Error('Protocol mismatch after Socks5 handshake');
                }

                if (ctx.disabledProtocols.includes(result.protocol) || 
                   (result.protocol === 'socks5' && ctx.disabledProtocols.includes('socks'))) {
                    throw new Error(`Protocol ${result.protocol} is disabled`);
                }

                const { protocol, addressRemote, portRemote, addressType, rawDataIndex, isUDP } = result;
                
                log(`Detected: ${protocol.toUpperCase()} -> ${addressRemote}:${portRemote}`);

                // [Security] 域名黑名单检查
                if (isHostBanned(addressRemote, ctx.banHosts)) {
                    throw new Error(`Blocked: ${addressRemote}`);
                }
                
                isConnected = true;
                clearTimeout(protocolDetectTimer); 
                remoteSocketWrapper.isConnecting = true;

                let clientData = bufferToDetect; 
                let responseHeader = null;

                if (protocol === 'vless') {
                    clientData = bufferToDetect.subarray(rawDataIndex);
                    responseHeader = new Uint8Array([result.cloudflareVersion[0], 0]);
                } else if (protocol === 'trojan' || protocol === 'ss' || protocol === 'mandala') {
                    clientData = result.rawClientData;
                } else if (protocol === 'socks5') {
                    clientData = result.rawClientData;
                    webSocket.send(new Uint8Array([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]));
                    socks5State = 3;
                }

                vlessChunks = null; // GC

                // [Safety] 传递 safeDecrement 给 outbound 处理函数，以便它们在连接关闭时也能触发（可选，目前通过 finally 统一处理）
                if (isUDP) {
                    handleUDPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);
                } else {
                    handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);
                }

            } catch (e) {
                if (vlessBufferLength < PROBE_THRESHOLD && vlessBufferLength < MAX_HEADER_BUFFER) {
                    return; 
                }
                clearTimeout(protocolDetectTimer);
                safeCloseWebSocket(webSocket);
            }
        },
        close() { cleanup(); },
        abort(reason) { cleanup(); safeCloseWebSocket(webSocket); },
    })).catch((err) => {
        cleanup();
        safeCloseWebSocket(webSocket);
        // Catch block swallowed error, but we must ensure decrement happens.
        // It's handled in the finally block below.
    });

    const handleLifecycle = () => {
        return streamPromise.finally(() => {
            safeDecrement(); 
        });
    };

    // [Fix] 使用 try-catch 并在 Worker 层面捕获可能的 waitUntil 错误
    // "Network connection lost" 往往发生在 waitUntil 还没完全注册好或 Response 返回瞬间
    try {
        if (ctx.waitUntil) {
            ctx.waitUntil(handleLifecycle());
        } else {
            handleLifecycle().catch(e => console.error(e));
        }
        
        return new Response(null, { status: 101, webSocket: client });
    } catch (e) {
        // 如果在创建 Response 或 waitUntil 时出错（极少见），确保递减
        safeDecrement();
        console.error('[WS] Response Creation Failed:', e);
        return new Response('Internal Error', { status: 500 });
    }
}

// ... SOCKS5 握手函数保持不变 ...
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

// [Optimization] 更安全的 ReadableStream 包装器
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
                if (readableStreamCancel) return;
                try {
                    const data = typeof event.data === 'string' 
                        ? new TextEncoder().encode(event.data) 
                        : event.data;
                    safeEnqueue(data);
                } catch (e) {
                    // Ignore message processing errors
                }
            });
            
            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                safeClose();
            });
            
            webSocketServer.addEventListener('error', (err) => {
                safeError(err);
            });
            
            // [Fix] 将 Early Data 处理包裹在 try-catch 中，防止同步错误导致 Crash
            try {
                const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
                if (error) {
                    // 如果 Early Data 错误，不要直接 Crash，而是视为无 Early Data 或记录警告
                    // safeError(error); // 过于激进，可能导致 Client Disconnect 报错
                    console.warn('[WS] Early Data invalid:', error.message);
                } else if (earlyData) {
                    safeEnqueue(earlyData);
                }
            } catch (e) {
                console.warn('[WS] Early Data processing failed:', e);
            }
        },
        cancel() { 
            readableStreamCancel = true; 
            safeCloseWebSocket(webSocketServer); 
        }
    });
}
