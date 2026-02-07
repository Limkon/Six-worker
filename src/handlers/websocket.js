// src/handlers/websocket.js
/**
 * 文件名: src/handlers/websocket.js
 * 审计修复说明:
 * 1. [Fix] 语义修正: 将 activeWebSocketConnections 重命名为 activeConnectionsInInstance，明确仅统计当前实例。
 * 2. [Security] 硬性熔断: 引入 CONSTANTS.MAX_CONCURRENT。当单实例连接数超限(默认512)时，直接拒绝新连接(429)，防止 OOM。
 * 3. [Fix] 修复 bufferedBytes 计数器同步 Bug: 当底层 Buffer 数组被 outbound.js 清空时，自动重置计数器。
 * 4. [Optimization] 调整计数器逻辑位置，确保仅在连接成功 accept 后才计数。
 * 5. [Smart Security] 智能熔断机制: 根据并发数动态调整 Buffer 大小 (10MB -> 128KB)。
 */
import { ProtocolManager } from '../protocols/manager.js';
import { processVlessHeader } from '../protocols/vless.js';
import { parseTrojanHeader } from '../protocols/trojan.js';
import { parseMandalaHeader } from '../protocols/mandala.js';
import { parseSocks5Header } from '../protocols/socks5.js';
import { parseShadowsocksHeader } from '../protocols/shadowsocks.js';
import { handleTCPOutBound, handleUDPOutBound } from './outbound.js';
import { safeCloseWebSocket, base64ToArrayBuffer, isHostBanned } from '../utils/helpers.js';
import { CONSTANTS } from '../constants.js'; // [Fix] 确保引入常量

// 注册支持的协议解析器
const protocolManager = new ProtocolManager()
    .register('vless', processVlessHeader)
    .register('trojan', parseTrojanHeader)
    .register('mandala', parseMandalaHeader)
    .register('socks5', parseSocks5Header)
    .register('ss', parseShadowsocksHeader);

// [Smart Global State] 当前 Worker 实例活跃连接计数器
// 注意：Cloudflare Worker 是分布式的，此变量仅统计当前 Isolate (隔离实例) 的连接数。
// 无法用于统计全局总并发，但对于防止单实例 OOM (内存溢出) 至关重要。
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
// 依据: Cloudflare Worker 限制 128MB 内存。
// 策略: 并发越高，单连接允许的 Buffer 越小，防止总内存溢出。
function getDynamicBufferSize() {
    if (activeConnectionsInInstance < 5) return 10 * 1024 * 1024; // <5 并发: 10MB
    if (activeConnectionsInInstance < 20) return 2 * 1024 * 1024; // <20 并发: 2MB (标准)
    if (activeConnectionsInInstance < 50) return 512 * 1024;      // <50 并发: 512KB
    return 128 * 1024;                                            // >50 并发: 128KB (保命模式)
}

export async function handleWebSocketRequest(request, ctx) {
    // [Security Fix] 实例级硬性熔断
    // 如果当前实例已经过载，拒绝新连接。客户端重试时可能会被调度到其他空闲实例。
    if (activeConnectionsInInstance >= CONSTANTS.MAX_CONCURRENT) {
        console.warn(`[WS] Instance Overloaded (${activeConnectionsInInstance} conns). Rejecting new request.`);
        return new Response('Error: Instance Too Busy (Rate Limit)', { status: 429 });
    }

    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    
    // [Optimization] 增加 try-catch 确保 accept 失败时不会导致计数器泄漏
    try {
        webSocket.accept();
    } catch (e) {
        console.error('[WS] Accept failed', e);
        return new Response('WebSocket Accept Failed', { status: 500 });
    }

    // 1. 成功建立连接后，增加计数 (仅限当前实例)
    activeConnectionsInInstance++;

    // 连接状态包装器 (通过对象引用传递给 outbound.js)
    // [Fix] 增加 bufferedBytes 用于追踪当前缓冲区大小
    let remoteSocketWrapper = { value: null, isConnecting: false, buffer: [], bufferedBytes: 0 };
    let isConnected = false; 
    let socks5State = 0; // 0: Method, 1: Auth, 2: Request, 3: Established
    
    // [Buffer] 定义 vlessBuffer 用于处理分包和粘包
    let vlessBuffer = new Uint8Array(0); 
    
    let activeWriter = null;
    let activeSocket = null;
    
    // 安全配置
    const MAX_HEADER_BUFFER = 2048; // 协议头解析缓冲区
    const PROBE_THRESHOLD = 1024;   // 探测阈值
    const DETECT_TIMEOUT_MS = 10000; // 10秒未识别协议则断开

    const log = (info, event) => console.log(`[WS][Conns:${activeConnectionsInInstance}] ${info}`, event || '');

    // 协议检测超时熔断
    const timeoutTimer = setTimeout(() => {
        if (!isConnected) {
            log('Timeout: Protocol detection took too long');
            safeCloseWebSocket(webSocket);
        }
    }, DETECT_TIMEOUT_MS);

    // 处理 Early Data (VLESS over WS 0-RTT)
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    
    // 创建可读流
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    const streamPromise = readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            const chunkArr = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);

            // --- 阶段二：已连接状态 (数据透传) ---
            if (isConnected) {
                // 如果 socket 实例发生变化 (例如重试或建立连接后)，更新 writer
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
                
                // 数据写入逻辑
                if (activeWriter) {
                    await activeWriter.write(chunkArr);
                } else if (remoteSocketWrapper.isConnecting) {
                    // [Fix] 关键修复: 同步计数器状态
                    // 如果 outbound.js 已经清空了 buffer 数组 (例如重试前)，我们需要重置计数器
                    if (remoteSocketWrapper.buffer.length === 0) {
                        remoteSocketWrapper.bufferedBytes = 0;
                    }

                    // [Smart Security] 智能熔断检查
                    const newSize = remoteSocketWrapper.bufferedBytes + chunkArr.byteLength;
                    const dynamicLimit = getDynamicBufferSize(); // 获取动态阈值
                    
                    if (newSize > dynamicLimit) {
                        clearTimeout(timeoutTimer);
                        throw new Error(`Smart Buffer Limit Exceeded: ${newSize} > ${dynamicLimit} (ActiveConns: ${activeConnectionsInInstance})`);
                    }

                    remoteSocketWrapper.buffer.push(chunkArr);
                    remoteSocketWrapper.bufferedBytes = newSize;
                }
                return;
            }

            // --- 阶段一：协议识别与握手 (Active Parsing) ---
            vlessBuffer = concatUint8(vlessBuffer, chunkArr);

            // [Security] 实时检查 Buffer 大小
            if (vlessBuffer.length > MAX_HEADER_BUFFER) {
                clearTimeout(timeoutTimer);
                throw new Error(`Header buffer limit exceeded`);
            }

            // SOCKS5 握手拦截
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
                // 尝试识别协议
                const result = await protocolManager.detect(vlessBuffer, ctx);
                
                // 一致性检查：SOCKS5 握手后必须匹配 SOCKS5 协议
                if (socks5State === 2 && result.protocol !== 'socks5') {
                    throw new Error('Protocol mismatch after Socks5 handshake');
                }

                // 检查协议是否被禁用
                const pName = result.protocol; 
                const isSocksDisabled = pName === 'socks5' && ctx.disabledProtocols.includes('socks');
                if (ctx.disabledProtocols.includes(pName) || isSocksDisabled) {
                    throw new Error(`Protocol ${pName} is disabled`);
                }

                // --- 识别成功 ---
                const { protocol, addressRemote, portRemote, addressType, rawDataIndex, isUDP } = result;
                
                log(`Detected: ${protocol.toUpperCase()} -> ${addressRemote}:${portRemote}`);
                
                // [Security] 内网/黑名单阻断
                if (isHostBanned(addressRemote, ctx.banHosts)) {
                    throw new Error(`Blocked: ${addressRemote}`);
                }
                
                isConnected = true;
                clearTimeout(timeoutTimer); 
                remoteSocketWrapper.isConnecting = true;

                // 准备 payload 和响应头
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

                vlessBuffer = null; // 释放内存

                // 移交出站连接
                if (isUDP) {
                    handleUDPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);
                } else {
                    handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);
                }

            } catch (e) {
                // [Stability] 数据分片处理
                if (vlessBuffer && vlessBuffer.length < PROBE_THRESHOLD && vlessBuffer.length < MAX_HEADER_BUFFER) {
                    return; 
                }
                clearTimeout(timeoutTimer);
                log(`Detection failed: ${e.message}`);
                safeCloseWebSocket(webSocket);
            }
        },
        // 资源清理
        close() { cleanup(); },
        abort(reason) { cleanup(); safeCloseWebSocket(webSocket); },
    })).catch((err) => {
        clearTimeout(timeoutTimer);
        cleanup();
        safeCloseWebSocket(webSocket);
    });

    // 辅助清理函数
    function cleanup() {
        if (activeWriter) { try { activeWriter.releaseLock(); } catch(e) {} activeWriter = null; }
        if (remoteSocketWrapper.value) { try { remoteSocketWrapper.value.close(); } catch(e) {} remoteSocketWrapper.value = null; }
    }

    // 维持 Worker 生命周期并在结束时减少连接计数
    if (ctx.waitUntil) {
        ctx.waitUntil(streamPromise.finally(() => {
            activeConnectionsInInstance--;
            if (activeConnectionsInInstance < 0) activeConnectionsInInstance = 0;
        }));
    } else {
        streamPromise.finally(() => {
            activeConnectionsInInstance--;
            if (activeConnectionsInInstance < 0) activeConnectionsInInstance = 0;
        });
    }

    return new Response(null, { status: 101, webSocket: client });
}

// SOCKS5 握手辅助函数
function tryHandleSocks5Handshake(buffer, currentState, webSocket, ctx, log) {
    const res = { consumed: 0, newState: currentState, error: null };
    if (buffer.length === 0) return res;

    // 阶段 0: Method 协商
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

    // 阶段 1: 认证
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

// 健壮的 ReadableStream 包装器
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
