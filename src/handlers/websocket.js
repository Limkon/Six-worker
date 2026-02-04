// src/handlers/websocket.js
/**
 * 文件名: src/handlers/websocket.js
 * 审计结论: [已修复]
 * 1. 包含内存溢出保护 (Header Buffer Limit)。
 * 2. 包含 SOCKS5 状态机修复。
 * 3. 包含完整的资源锁释放逻辑 (Writer Release Lock)。
 * 4. [Fix] 修复 "This ReadableStream is closed" 竞态报错。
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

// 工具：合并 Uint8Array
function concatUint8(a, b) {
    const bArr = b instanceof Uint8Array ? b : new Uint8Array(b);
    const res = new Uint8Array(a.length + bArr.length);
    res.set(a);
    res.set(bArr, a.length);
    return res;
}

export async function handleWebSocketRequest(request, ctx) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    
    // 连接状态包装器 (通过对象引用传递给 outbound.js)
    let remoteSocketWrapper = { value: null, isConnecting: false, buffer: [] };
    let isConnected = false; 
    let socks5State = 0; // 0: Method, 1: Auth, 2: Request, 3: Established
    let headerBuffer = new Uint8Array(0); 
    
    let activeWriter = null;
    let activeSocket = null;
    
    // 安全配置
    const MAX_HEADER_BUFFER = 4096; // 限制头部最大 4KB，防止内存溢出
    const DETECT_TIMEOUT_MS = 10000; // 10秒未识别协议则断开

    const log = (info, event) => console.log(`[WS] ${info}`, event || '');

    // 协议检测超时熔断
    const timeoutTimer = setTimeout(() => {
        if (!isConnected) {
            log('Timeout: Protocol detection took too long');
            safeCloseWebSocket(webSocket);
        }
    }, DETECT_TIMEOUT_MS);

    // 处理 Early Data (VLESS over WS 0-RTT)
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    
    // [Fix] 使用修复后的流创建函数
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    const streamPromise = readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            const chunkArr = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);

            // --- 阶段二：已连接状态 (数据透传) ---
            if (isConnected) {
                // 如果 socket 实例发生变化 (例如重试或建立连接后)，更新 writer
                if (activeSocket !== remoteSocketWrapper.value) {
                    if (activeWriter) {
                        try {
                            await activeWriter.ready;
                            activeWriter.releaseLock(); 
                        } catch(e) {}
                        activeWriter = null;
                    }
                    activeSocket = remoteSocketWrapper.value;
                    if (activeSocket) {
                        try {
                            activeWriter = activeSocket.writable.getWriter();
                        } catch (e) {
                            safeCloseWebSocket(webSocket);
                            return;
                        }
                    }
                }
                
                // 数据写入逻辑
                if (activeWriter) {
                    await activeWriter.write(chunkArr);
                } else if (remoteSocketWrapper.isConnecting) {
                    // 连接正在建立中，暂存数据到缓冲区
                    remoteSocketWrapper.buffer.push(chunkArr);
                }
                return;
            }

            // --- 阶段一：协议识别与握手 ---
            headerBuffer = concatUint8(headerBuffer, chunkArr);

            // [Security] 实时检查 Buffer 大小
            if (headerBuffer.length > MAX_HEADER_BUFFER) {
                clearTimeout(timeoutTimer);
                throw new Error(`Header buffer limit exceeded`);
            }

            // SOCKS5 握手拦截 (在进入通用识别前处理)
            if (socks5State < 2) {
                const { consumed, newState, error } = tryHandleSocks5Handshake(headerBuffer, socks5State, webSocket, ctx, log);
                if (error) {
                    clearTimeout(timeoutTimer); 
                    throw new Error(error);
                }
                if (consumed > 0) {
                    headerBuffer = headerBuffer.slice(consumed);
                    socks5State = newState;
                    // 如果还未完成握手 (例如刚完成 Method 协商)，返回等待更多数据
                    if (socks5State !== 2) return; 
                }
            }

            if (headerBuffer.length === 0) return;

            try {
                // 尝试识别协议
                const result = await protocolManager.detect(headerBuffer, ctx);
                
                // 一致性检查：如果之前进行了 SOCKS5 握手，后续协议必须是 SOCKS5
                if (socks5State === 2 && result.protocol !== 'socks5') {
                    throw new Error('Protocol mismatch after Socks5 handshake');
                }

                // 禁用协议检查
                const pName = result.protocol; 
                const isSocksDisabled = pName === 'socks5' && ctx.disabledProtocols.includes('socks');
                if (ctx.disabledProtocols.includes(pName) || isSocksDisabled) {
                    throw new Error(`Protocol ${pName} is disabled`);
                }

                // --- 识别成功 ---
                const { protocol, addressRemote, portRemote, addressType, rawDataIndex, isUDP } = result;
                
                log(`Detected: ${protocol.toUpperCase()} -> ${addressRemote}:${portRemote}`);
                
                // [Security] 内网 IP / 黑名单阻断
                if (isHostBanned(addressRemote, ctx.banHosts)) {
                    throw new Error(`Blocked: ${addressRemote}`);
                }
                
                // 标记状态为已连接
                isConnected = true;
                clearTimeout(timeoutTimer); 
                remoteSocketWrapper.isConnecting = true;

                // 准备 payload 和响应头
                let clientData = headerBuffer; 
                let responseHeader = null;

                if (protocol === 'vless') {
                    // VLESS 需要剥离头部，并返回版本号响应
                    clientData = headerBuffer.subarray(rawDataIndex);
                    responseHeader = new Uint8Array([result.cloudflareVersion[0], 0]);
                } else if (protocol === 'trojan' || protocol === 'ss' || protocol === 'mandala') {
                    // Trojan/SS 使用解析后的净荷 (去除了头部)
                    clientData = result.rawClientData;
                } else if (protocol === 'socks5') {
                    // SOCKS5 使用解析后的净荷，并发送握手成功响应
                    clientData = result.rawClientData;
                    webSocket.send(new Uint8Array([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]));
                    socks5State = 3;
                }

                headerBuffer = null; // 释放内存

                // 移交出站连接 (调用 outbound.js)
                if (isUDP) {
                    handleUDPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);
                } else {
                    handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);
                }

            } catch (e) {
                // [Robustness] 如果是数据分片导致解析失败（长度不够），允许等待后续数据
                if (headerBuffer && headerBuffer.length < 512 && headerBuffer.length < MAX_HEADER_BUFFER) {
                    return; 
                }
                // 否则视为非法协议或错误
                clearTimeout(timeoutTimer);
                log(`Detection failed: ${e.message}`);
                safeCloseWebSocket(webSocket);
            }
        },
        // [Fix] 确保流关闭时释放锁和资源
        close() { 
            if (activeWriter) { try { activeWriter.releaseLock(); } catch(e) {} }
            if (remoteSocketWrapper.value) { try { remoteSocketWrapper.value.close(); } catch(e) {} }
        },
        abort(reason) { 
            if (activeWriter) { try { activeWriter.releaseLock(); } catch(e) {} }
            if (remoteSocketWrapper.value) { try { remoteSocketWrapper.value.close(); } catch(e) {} }
            safeCloseWebSocket(webSocket); 
        },
    })).catch((err) => {
        // [Fix] 异常捕获时的兜底清理
        clearTimeout(timeoutTimer);
        if (activeWriter) { try { activeWriter.releaseLock(); } catch(e) {} }
        if (remoteSocketWrapper.value) { try { remoteSocketWrapper.value.close(); } catch(e) {} }
        safeCloseWebSocket(webSocket);
    });

    // 维持 Worker 生命周期
    if (ctx.waitUntil) ctx.waitUntil(streamPromise);

    return new Response(null, { status: 101, webSocket: client });
}

// SOCKS5 握手辅助函数
function tryHandleSocks5Handshake(buffer, currentState, webSocket, ctx, log) {
    const res = { consumed: 0, newState: currentState, error: null };
    if (buffer.length === 0) return res;

    // 阶段 0: Method 协商
    if (currentState === 0) {
        if (buffer[0] !== 0x05) return res; // 不是 SOCKS5
        if (buffer.length < 2) return res; 
        const nMethods = buffer[1];
        if (buffer.length < 2 + nMethods) return res; 

        const methods = buffer.subarray(2, 2 + nMethods);
        let hasAuth = false;
        for (let m of methods) { if (m === 0x02) hasAuth = true; }

        if (hasAuth) {
            webSocket.send(new Uint8Array([0x05, 0x02])); // 接受 Auth
            res.newState = 1;
        } else {
            webSocket.send(new Uint8Array([0x05, 0xFF])); // 拒绝
            res.error = "Socks5: No supported auth method";
            return res;
        }
        res.consumed = 2 + nMethods;
        return res;
    }

    // 阶段 1: 用户名密码认证
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
            webSocket.send(new Uint8Array([0x01, 0x00])); // Auth Success
            res.newState = 2;
            res.consumed = offset;
        } else {
            webSocket.send(new Uint8Array([0x01, 0x01])); // Auth Fail
            res.error = `Socks5 Auth Failed: ${user}`;
        }
        return res;
    }
    return res;
}

// [Fix] 健壮的 ReadableStream 包装器，防止 "closed" 报错
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    let isStreamClosed = false; // [Fix] 新增内部状态，追踪流是否已关闭

    return new ReadableStream({
        start(controller) {
            // [Fix] 包装 enqueue，防止向已关闭流写入
            const safeEnqueue = (chunk) => {
                if (readableStreamCancel || isStreamClosed) return;
                try {
                    controller.enqueue(chunk);
                } catch (e) {
                    // 忽略 "closed" 错误，但这通常不应该发生，因为我们有 isStreamClosed 检查
                }
            };
            
            // [Fix] 包装 close
            const safeClose = () => {
                if (readableStreamCancel || isStreamClosed) return;
                try {
                    controller.close();
                    isStreamClosed = true;
                } catch (e) { }
            };

             // [Fix] 包装 error
            const safeError = (e) => {
                if (readableStreamCancel || isStreamClosed) return;
                try {
                    controller.error(e);
                    isStreamClosed = true;
                } catch (err) { }
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
