/**
 * 文件名: src/handlers/websocket.js
 * 状态: [完整可用]
 * 说明: 
 * 1. 导出名为 handleWebSocketRequest (匹配 index.js)。
 * 2. 包含 SOCKS5 完整握手与鉴权状态机。
 * 3. 集成 ProtocolManager 实现多协议分流。
 */
import { ProtocolManager } from '../protocols/manager.js';
import { processVlessHeader } from '../protocols/vless.js';
import { parseTrojanHeader } from '../protocols/trojan.js';
import { parseMandalaHeader } from '../protocols/mandala.js';
import { parseSocks5Header } from '../protocols/socks5.js';
import { parseShadowsocksHeader } from '../protocols/shadowsocks.js';
import { handleTCPOutBound, handleUDPOutBound } from './outbound.js';
import { safeCloseWebSocket, base64ToArrayBuffer, isHostBanned } from '../utils/helpers.js';

// 初始化协议管理器
const protocolManager = new ProtocolManager()
    .register('vless', processVlessHeader)
    .register('trojan', parseTrojanHeader)
    .register('mandala', parseMandalaHeader)
    .register('socks5', parseSocks5Header)
    .register('ss', parseShadowsocksHeader);

function concatUint8(a, b) {
    const bArr = b instanceof Uint8Array ? b : new Uint8Array(b);
    const res = new Uint8Array(a.length + bArr.length);
    res.set(a);
    res.set(bArr, a.length);
    return res;
}

// SOCKS5 握手状态机 (Method Select -> Auth -> Request)
function tryHandleSocks5Handshake(buffer, currentState, webSocket, ctx, log) {
    const res = { consumed: 0, newState: currentState, error: null };
    if (buffer.length === 0) return res;

    // State 0: 等待客户端发送 Method List
    if (currentState === 0) {
        if (buffer[0] !== 0x05) return res; // 不是 SOCKS5，跳过
        if (buffer.length < 2) return res; // 数据不够
        const nMethods = buffer[1];
        if (buffer.length < 2 + nMethods) return res; // 数据不够

        const methods = buffer.subarray(2, 2 + nMethods);
        let hasAuth = false;
        for (let m of methods) {
            if (m === 0x02) hasAuth = true; // 0x02 = Username/Password Auth
        }

        // 强制要求鉴权
        if (hasAuth) {
            webSocket.send(new Uint8Array([0x05, 0x02]));
            res.newState = 1;
        } else {
            webSocket.send(new Uint8Array([0x05, 0xFF]));
            res.error = "Socks5: No supported auth method (Requires User/Pass)";
            return res;
        }
        res.consumed = 2 + nMethods;
        return res;
    }

    // State 1: 等待客户端发送 Username/Password
    if (currentState === 1) {
        if (buffer.length < 3) return res;
        if (buffer[0] !== 0x01) {
            res.error = "Socks5 Auth: Wrong version";
            return res;
        }
        let offset = 1;
        const uLen = buffer[offset++];
        if (buffer.length < offset + uLen + 1) return res;
        const user = new TextDecoder().decode(buffer.subarray(offset, offset + uLen));
        offset += uLen;
        const pLen = buffer[offset++];
        if (buffer.length < offset + pLen) return res;
        const pass = new TextDecoder().decode(buffer.subarray(offset, offset + pLen));
        offset += pLen;

        // 验证用户名密码
        const isValid = (user === ctx.userID || user === ctx.dynamicUUID || user === ctx.userIDLow) && 
                        (pass === ctx.userID || pass === ctx.dynamicUUID || pass === ctx.userIDLow);
        
        if (isValid) {
            webSocket.send(new Uint8Array([0x01, 0x00])); // Auth Success
            res.newState = 2; // 进入 Request 阶段
            res.consumed = offset;
        } else {
            webSocket.send(new Uint8Array([0x01, 0x01])); // Auth Fail
            res.error = `Socks5 Auth Failed: User=${user}`;
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

// [重要] 确保函数名为 handleWebSocketRequest
export async function handleWebSocketRequest(request, ctx) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    
    let remoteSocketWrapper = { value: null, isConnecting: false, buffer: [] };
    let isConnected = false; 
    let socks5State = 0; // 0:Init, 1:Auth, 2:Request, 3:Established
    let headerBuffer = new Uint8Array(0); 
    
    let activeWriter = null;
    let activeSocket = null;
    
    const MAX_HEADER_BUFFER = 4096; 
    const DETECT_TIMEOUT_MS = 10000; 

    const log = (info, event) => console.log(`[WS] ${info}`, event || '');

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

            // 1. 已连接状态：直接转发数据
            if (isConnected) {
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
                            log('Failed to get writer for new socket', e);
                            safeCloseWebSocket(webSocket);
                            return;
                        }
                    }
                }

                if (activeWriter) {
                    await activeWriter.write(chunkArr);
                } else if (remoteSocketWrapper.isConnecting) {
                    if (remoteSocketWrapper.buffer.length < 1000) { 
                        remoteSocketWrapper.buffer.push(chunkArr);
                    }
                }
                return;
            }

            // 2. 未连接状态：协议探测与握手
            headerBuffer = concatUint8(headerBuffer, chunkArr);

            // SOCKS5 特殊处理
            if (socks5State < 2) {
                const { consumed, newState, error } = tryHandleSocks5Handshake(headerBuffer, socks5State, webSocket, ctx, log);
                if (error) {
                    clearTimeout(timeoutTimer); 
                    throw new Error(error);
                }
                if (consumed > 0) {
                    headerBuffer = headerBuffer.slice(consumed);
                    socks5State = newState;
                    if (socks5State !== 2) return; 
                }
            }

            if (headerBuffer.length === 0) return;

            try {
                // 探测协议
                const result = await protocolManager.detect(headerBuffer, ctx);
                
                const pName = result.protocol; 
                
                if (ctx.disabledProtocols.includes(pName)) {
                    throw new Error(`Protocol ${pName.toUpperCase()} is disabled`);
                }

                // --- 成功识别 ---
                const { protocol, addressRemote, portRemote, addressType, rawDataIndex, isUDP } = result;
                
                log(`Detected: ${protocol.toUpperCase()} -> ${addressRemote}:${portRemote} (UDP: ${isUDP})`);
                
                if (isHostBanned(addressRemote, ctx.banHosts)) {
                    throw new Error(`Blocked: ${addressRemote}`);
                }
                
                isConnected = true;
                clearTimeout(timeoutTimer); 
                remoteSocketWrapper.isConnecting = true;

                let clientData = headerBuffer; 
                let responseHeader = null;

                if (protocol === 'vless') {
                    clientData = headerBuffer.subarray(rawDataIndex);
                    responseHeader = new Uint8Array([result.cloudflareVersion[0], 0]);
                } else if (protocol === 'trojan' || protocol === 'ss' || protocol === 'mandala') {
                    clientData = result.rawClientData;
                } else if (protocol === 'socks5') {
                    clientData = result.rawClientData;
                    // SOCKS5 Connect Success Response
                    webSocket.send(new Uint8Array([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]));
                    socks5State = 3;
                }

                headerBuffer = null; 

                // 发起出站连接
                if (isUDP) {
                    handleUDPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);
                } else {
                    handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);
                }

            } catch (e) {
                if (headerBuffer && headerBuffer.length < 512 && headerBuffer.length < MAX_HEADER_BUFFER) {
                    return; 
                }
                clearTimeout(timeoutTimer);
                log(`Detection failed: ${e.message}`);
                safeCloseWebSocket(webSocket);
            }
        },
        close() { 
            if (activeWriter) { try { activeWriter.releaseLock(); } catch(e) {} }
            if (remoteSocketWrapper.value) { try { remoteSocketWrapper.value.close(); } catch(e) {} }
            log("Client WebSocket closed"); 
        },
        abort(reason) { 
            if (activeWriter) { try { activeWriter.releaseLock(); } catch(e) {} }
            if (remoteSocketWrapper.value) { try { remoteSocketWrapper.value.close(); } catch(e) {} }
            log("WebSocket aborted", reason); 
            safeCloseWebSocket(webSocket); 
        },
    })).catch((err) => {
        clearTimeout(timeoutTimer);
        if (activeWriter) { try { activeWriter.releaseLock(); } catch(e) {} }
        if (remoteSocketWrapper.value) { try { remoteSocketWrapper.value.close(); } catch(e) {} }
        log("Stream processing failed", err.toString());
        safeCloseWebSocket(webSocket);
    });

    if (ctx.waitUntil) ctx.waitUntil(streamPromise);

    return new Response(null, { status: 101, webSocket: client });
}
