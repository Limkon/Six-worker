// src/handlers/websocket.js
/**
 * 文件名: src/handlers/websocket.js
 * 最终修复版:
 * 1. [Fix] 恢复 Idle Timeout (60s) 机制，强制清理僵尸连接.
 * 2. [Fix] 恢复 activeConnectionsInInstance 计数器幂等性保护 (hasDecremented).
 * 3. [Fix] 恢复 bufferedBytes 的 reduce 实时计算逻辑，确保 100% 准确.
 * 4. [Security] 包含实例级硬性熔断 (Max Concurrent) 和 动态 Buffer 限制.
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

// 工具：合并 Uint8Array
function concatUint8(a, b) {
    const bArr = b instanceof Uint8Array ? b : new Uint8Array(b);
    const res = new Uint8Array(a.length + bArr.length);
    res.set(a);
    res.set(bArr, a.length);
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
    
    let vlessBuffer = new Uint8Array(0); 
    
    let activeWriter = null;
    let activeSocket = null;
    
    // 安全配置
    const MAX_HEADER_BUFFER = 2048; 
    const PROBE_THRESHOLD = 1024;
    
    // [Fix] 空闲超时控制 (Idle Timeout)
    // 关键逻辑：防止死连接占用计数器
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
    }, 10000); // 每 10 秒检查一次

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
                    // outbound.js 清空 buffer 数组 (length=0) 时，这里自动重新计算，无需显式重置标志
                    remoteSocketWrapper.buffer.push(chunkArr);
                    
                    // 使用 reduce 确保与 buffer 真实内容 100% 同步
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
            vlessBuffer = concatUint8(vlessBuffer, chunkArr);

            if (vlessBuffer.length > MAX_HEADER_BUFFER) {
                clearTimeout(protocolDetectTimer);
                throw new Error(`Header buffer limit exceeded`);
            }

            // SOCKS5 握手
            if (socks5State < 2) {
                const { consumed, newState, error } = tryHandleSocks5Handshake(vlessBuffer, socks5State, webSocket, ctx, log);
                if (error) { clearTimeout(protocolDetectTimer); throw new Error(error); }
                if (consumed > 0) {
                    vlessBuffer = vlessBuffer.slice(consumed);
                    socks5State = newState;
                    if (socks5State !== 2) return; 
                }
            }

            if (vlessBuffer.length === 0) return;

            try {
                // 识别协议
                const result = await protocolManager.detect(vlessBuffer, ctx);
                
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
        clearInterval(idleTimer); // [Fix] 清理 idleTimer
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
