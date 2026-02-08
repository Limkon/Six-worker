// src/handlers/websocket.js
/**
 * 文件名: src/handlers/websocket.js
 * 状态: [Refactored & Optimized & Fixed]
 * 1. [Optimization] 握手阶段内存优化: 使用 vlessChunks 数组代替 concatUint8，降低 GC 压力。
 * 2. [Fix] 集成 Idle Timeout (60s): 强制清理僵尸连接。
 * 3. [Fix] 集成幂等递减 (hasDecremented): 确保计数器准确。
 * 4. [Fix] 集成精确缓冲计算 (reduce): 确保与 outbound.js 状态同步。
 * 5. [Security] 保持硬性熔断和动态 Buffer 限制。
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

// [New Helper] 合并 Chunk 数组 (替代频繁 concatUint8)
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

// [Smart Logic] 动态计算最大缓冲区大小
function getDynamicBufferSize() {
    if (activeConnectionsInInstance < 5) return 10 * 1024 * 1024; // <5 并发: 10MB
    if (activeConnectionsInInstance < 20) return 2 * 1024 * 1024; // <20 并发: 2MB
    if (activeConnectionsInInstance < 50) return 512 * 1024;      // <50 并发: 512KB
    return 128 * 1024;                                            // >50 并发: 128KB
}

export async function handleWebSocketRequest(request, ctx) {
    // [Security] 实例级硬性熔断
    if (activeConnectionsInInstance >= CONSTANTS.MAX_CONCURRENT) {
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

    // [Fix] 幂等递减控制器 (防止多次递减)
    let hasDecremented = false;
    const safeDecrement = () => {
        if (!hasDecremented) {
            activeConnectionsInInstance--;
            if (activeConnectionsInInstance < 0) activeConnectionsInInstance = 0;
            hasDecremented = true;
        }
    };

    // 连接状态包装器
    let remoteSocketWrapper = { value: null, isConnecting: false, buffer: [], bufferedBytes: 0 };
    let isConnected = false; 
    let socks5State = 0; 
    
    // [Optimization] 使用 Chunk Array 替代 buffer 累加
    let vlessChunks = []; 
    let vlessBufferLength = 0;
    
    let activeWriter = null;
    let activeSocket = null;
    
    // 安全配置
    const MAX_HEADER_BUFFER = 2048; 
    const PROBE_THRESHOLD = 1024;
    
    // [Fix] 空闲超时控制 (Idle Timeout)
    const IDLE_TIMEOUT = 60 * 1000; 
    let lastActivityTime = Date.now();
    let idleTimer = null;

    const updateActivity = () => { lastActivityTime = Date.now(); };
    
    // 启动空闲检测
    idleTimer = setInterval(() => {
        if (Date.now() - lastActivityTime > IDLE_TIMEOUT) {
            console.log(`[WS] Connection idle for ${IDLE_TIMEOUT}ms. Closing.`);
            cleanup();
            safeCloseWebSocket(webSocket);
        }
    }, 10000); 

    const log = (info, event) => console.log(`[WS][Conns:${activeConnectionsInInstance}] ${info}`, event || '');

    // 协议检测超时
    const DETECT_TIMEOUT_MS = 10000;
    const protocolDetectTimer = setTimeout(() => {
        if (!isConnected) {
            log('Timeout: Protocol detection took too long');
            safeCloseWebSocket(webSocket);
        }
    }, DETECT_TIMEOUT_MS);

    // 处理 Early Data
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    const streamPromise = readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            updateActivity(); // [Fix] 更新活跃时间

            const chunkArr = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);

            // --- 阶段二：已连接状态 (数据透传) ---
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
                    // [Fix] 实时计算 Buffer 大小 (Reduce)
                    // 确保与 outbound.js 的 buffer 状态同步
                    remoteSocketWrapper.buffer.push(chunkArr);
                    const currentBufferSize = remoteSocketWrapper.buffer.reduce((sum, c) => sum + c.byteLength, 0);
                    remoteSocketWrapper.bufferedBytes = currentBufferSize;

                    // [Smart Security] 智能熔断
                    const dynamicLimit = getDynamicBufferSize();
                    if (currentBufferSize > dynamicLimit) {
                        clearTimeout(protocolDetectTimer);
                        throw new Error(`Smart Buffer Limit Exceeded: ${currentBufferSize} > ${dynamicLimit}`);
                    }
                }
                return;
            }

            // --- 阶段一：协议识别与握手 ---
            // [Optimization] 使用 chunks push 代替 concat
            vlessChunks.push(chunkArr);
            vlessBufferLength += chunkArr.byteLength;

            if (vlessBufferLength > MAX_HEADER_BUFFER) {
                clearTimeout(protocolDetectTimer);
                throw new Error(`Header buffer limit exceeded`);
            }
            
            // 为了进行协议检测，我们需要临时合并当前的 chunks
            // 注意：这里仍然需要合并，因为解析器需要连续的 Buffer，
            // 但通过使用 vlessChunks，我们避免了每次 chunk 到来时对整个历史数据的 reallocation，
            // 只有在试图解析的那一刻才临时分配。
            const currentBuffer = mergeChunks(vlessChunks);

            // SOCKS5 握手
            if (socks5State < 2) {
                const { consumed, newState, error } = tryHandleSocks5Handshake(currentBuffer, socks5State, webSocket, ctx, log);
                if (error) { clearTimeout(protocolDetectTimer); throw new Error(error); }
                if (consumed > 0) {
                    // 消费了部分数据，需要调整 chunks
                    // 简化处理：由于 socks5 握手通常很短，我们直接重置 chunks 为剩余部分
                    const remaining = currentBuffer.slice(consumed);
                    vlessChunks = [remaining];
                    vlessBufferLength = remaining.byteLength;
                    socks5State = newState;
                    if (socks5State !== 2) return; 
                    // 如果进入 stage 2，重新 merge 并继续
                }
            }

            if (vlessBufferLength === 0) return;

            try {
                // 识别协议
                // 再次 merge (如果刚才 socks5 消耗过数据，currentBuffer 需要刷新)
                // 优化：如果 socks5 没消耗数据，可以直接复用 currentBuffer
                const bufferToDetect = (socks5State > 0) ? mergeChunks(vlessChunks) : currentBuffer;

                const result = await protocolManager.detect(bufferToDetect, ctx);
                
                if (socks5State === 2 && result.protocol !== 'socks5') {
                    throw new Error('Protocol mismatch after Socks5 handshake');
                }

                if (ctx.disabledProtocols.includes(result.protocol) || 
                   (result.protocol === 'socks5' && ctx.disabledProtocols.includes('socks'))) {
                    throw new Error(`Protocol ${result.protocol} is disabled`);
                }

                // --- 识别成功 ---
                const { protocol, addressRemote, portRemote, addressType, rawDataIndex, isUDP } = result;
                
                log(`Detected: ${protocol.toUpperCase()} -> ${addressRemote}:${portRemote}`);

                if (isHostBanned(addressRemote, ctx.banHosts)) {
                    throw new Error(`Blocked: ${addressRemote}`);
                }
                
                isConnected = true;
                clearTimeout(protocolDetectTimer); 
                remoteSocketWrapper.isConnecting = true;

                let clientData = bufferToDetect; // Default
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
                // log(`Detection failed: ${e.message}`);
                safeCloseWebSocket(webSocket);
            }
        },
        close() { cleanup(); },
        abort(reason) { cleanup(); safeCloseWebSocket(webSocket); },
    })).catch((err) => {
        cleanup();
        safeCloseWebSocket(webSocket);
    });

    // 辅助清理函数
    function cleanup() {
        clearTimeout(protocolDetectTimer);
        clearInterval(idleTimer); 
        if (activeWriter) { try { activeWriter.releaseLock(); } catch(e) {} activeWriter = null; }
        if (remoteSocketWrapper.value) { try { remoteSocketWrapper.value.close(); } catch(e) {} remoteSocketWrapper.value = null; }
    }

    // 生命周期管理 (使用 safeDecrement)
    const handleLifecycle = () => {
        return streamPromise.finally(() => {
            safeDecrement(); // [Fix] 幂等递减
        });
    };

    if (ctx.waitUntil) {
        ctx.waitUntil(handleLifecycle());
    } else {
        handleLifecycle();
    }

    return new Response(null, { status: 101, webSocket: client });
}

// SOCKS5 握手辅助函数 (保持不变)
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

// ReadableStream 包装器 (保持不变)
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
