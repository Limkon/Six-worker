/**
 * 文件名: src/handlers/websocket.js
 * 最终优化:
 * 1. [安全] 新增 DETECT_TIMEOUT (10秒)：防止僵尸连接占用资源。
 * 2. [性能] 保持了 Buffer 机制与 Socks5 状态机分离的高效结构。
 * 3. [稳定] 完美的异常捕获与资源释放。
 */
import { ProtocolManager } from '../protocols/manager.js';
import { processVlessHeader } from '../protocols/vless.js';
import { parseTrojanHeader } from '../protocols/trojan.js';
import { parseMandalaHeader } from '../protocols/mandala.js';
import { parseSocks5Header } from '../protocols/socks5.js';
import { parseShadowsocksHeader } from '../protocols/shadowsocks.js';
import { handleTCPOutBound } from './outbound.js';
import { safeCloseWebSocket, base64ToArrayBuffer, isHostBanned } from '../utils/helpers.js';

const protocolManager = new ProtocolManager()
    .register('vless', processVlessHeader)
    .register('trojan', parseTrojanHeader)
    .register('mandala', parseMandalaHeader)
    .register('socks5', parseSocks5Header)
    .register('ss', parseShadowsocksHeader);

function concatUint8(a, b) {
    const res = new Uint8Array(a.length + b.length);
    res.set(a);
    res.set(b, a.length);
    return res;
}

export async function handleWebSocketRequest(request, ctx) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    
    // 状态变量
    let remoteSocketWrapper = { value: null, isConnecting: false, buffer: [] };
    let isConnected = false; 
    let socks5State = 0; 
    let headerBuffer = new Uint8Array(0); 
    
    // 常量配置
    const MAX_HEADER_BUFFER = 4096; // 4KB 防御大包攻击
    const DETECT_TIMEOUT_MS = 10000; // 10秒 协议检测超时

    const log = (info, event) => console.log(`[WS] ${info}`, event || '');

    // [新增] 超时熔断器：如果 10 秒内没能识别出协议，强行断开
    // 这能有效防止 Slowloris 攻击或客户端死锁
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
            // 1. 已连接状态：高性能直通
            if (isConnected) {
                if (remoteSocketWrapper.value) {
                    const writer = remoteSocketWrapper.value.writable.getWriter();
                    await writer.write(chunk);
                    writer.releaseLock();
                } else if (remoteSocketWrapper.isConnecting) {
                    remoteSocketWrapper.buffer.push(chunk);
                }
                return;
            }

            // 2. 数据缓冲
            // 性能提示：Cloudflare Worker 对 Uint8Array 处理优化很好，此处拼接开销可忽略
            headerBuffer = concatUint8(headerBuffer, new Uint8Array(chunk));

            // 3. Socks5 握手处理 (State 0 & 1)
            if (socks5State < 2) {
                const { consumed, newState, error } = tryHandleSocks5Handshake(headerBuffer, socks5State, webSocket, ctx, log);
                
                if (error) {
                    clearTimeout(timeoutTimer); // 失败时也要清理定时器
                    throw new Error(error);
                }

                if (consumed > 0) {
                    headerBuffer = headerBuffer.slice(consumed);
                    socks5State = newState;
                    if (socks5State !== 2) return; // 等待后续数据
                }
            }

            // 4. 协议探测 (Vless / Trojan / Mandala / Socks5 CMD)
            if (headerBuffer.length === 0) return;

            try {
                const result = await protocolManager.detect(headerBuffer, ctx);
                
                if (socks5State === 2 && result.protocol !== 'socks5') {
                    throw new Error('Protocol mismatch after Socks5 handshake');
                }

                // --- 成功识别 ---
                isConnected = true;
                clearTimeout(timeoutTimer); // [重要] 识别成功，取消超时计时
                remoteSocketWrapper.isConnecting = true;

                const { protocol, addressRemote, portRemote, addressType, rawDataIndex, isUDP } = result;
                
                log(`Detected: ${protocol.toUpperCase()} -> ${addressRemote}:${portRemote}`);
                
                if (isHostBanned(addressRemote, ctx.banHosts)) {
                    throw new Error(`Blocked: ${addressRemote}`);
                }

                // 准备 Client Data
                let clientData = headerBuffer; 
                let responseHeader = null;

                if (protocol === 'vless') {
                    clientData = headerBuffer.slice(rawDataIndex);
                    responseHeader = new Uint8Array([result.cloudflareVersion[0], 0]);
                    if (isUDP && portRemote !== 53) throw new Error('UDP only for DNS(53)');
                } else if (protocol === 'trojan' || protocol === 'ss' || protocol === 'mandala') {
                    clientData = result.rawClientData;
                } else if (protocol === 'socks5') {
                    clientData = result.rawClientData;
                    webSocket.send(new Uint8Array([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]));
                    socks5State = 3;
                }

                // 释放内存
                headerBuffer = null; 

                handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);

            } catch (e) {
                // [缓冲策略]
                // 只有当缓冲区较小且未超时时，才认为是分包，继续等待
                // 如果超过 MAX_HEADER_BUFFER，说明发了太多垃圾数据，直接报错
                if (headerBuffer.length < 512 && headerBuffer.length < MAX_HEADER_BUFFER) {
                    return; 
                }
                
                clearTimeout(timeoutTimer);
                log(`Detection failed: ${e.message}`);
                safeCloseWebSocket(webSocket);
            }
        },
        close() { log("Client WebSocket closed"); },
        abort(reason) { log("WebSocket aborted", reason); safeCloseWebSocket(webSocket); },
    })).catch((err) => {
        clearTimeout(timeoutTimer); // 确保任何异常退出都清理定时器
        log("Stream processing failed", err.toString());
        safeCloseWebSocket(webSocket);
    });

    if (ctx.waitUntil) ctx.waitUntil(streamPromise);

    return new Response(null, { status: 101, webSocket: client });
}

// 辅助函数：Socks5 握手状态机 (保持上一版的高效逻辑)
function tryHandleSocks5Handshake(buffer, currentState, webSocket, ctx, log) {
    const res = { consumed: 0, newState: currentState, error: null };
    if (buffer.length === 0) return res;

    if (currentState === 0) {
        if (buffer[0] !== 0x05) return res; 
        if (buffer.length < 2) return res; 
        const nMethods = buffer[1];
        if (buffer.length < 2 + nMethods) return res; 

        const methods = buffer.slice(2, 2 + nMethods);
        let hasAuth = false;
        for (let m of methods) {
            if (m === 0x02) hasAuth = true;
        }

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
        if (buffer[0] !== 0x01) {
            res.error = "Socks5 Auth: Wrong version";
            return res;
        }
        let offset = 1;
        const uLen = buffer[offset++];
        if (buffer.length < offset + uLen + 1) return res;
        const user = new TextDecoder().decode(buffer.slice(offset, offset + uLen));
        offset += uLen;
        const pLen = buffer[offset++];
        if (buffer.length < offset + pLen) return res;
        const pass = new TextDecoder().decode(buffer.slice(offset, offset + pLen));
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
    return new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener('message', (event) => {
                if (readableStreamCancel) return;
                const data = typeof event.data === 'string' 
                    ? new TextEncoder().encode(event.data) 
                    : event.data;
                controller.enqueue(data);
            });
            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                if (!readableStreamCancel) controller.close();
            });
            webSocketServer.addEventListener('error', (err) => {
                log('WebSocket server error');
                controller.error(err);
            });
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() { readableStreamCancel = true; safeCloseWebSocket(webSocketServer); }
    });
}
