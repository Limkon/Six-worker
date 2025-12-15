/**
 * 文件名: src/handlers/websocket.js
 */
import { ProtocolManager } from '../protocols/manager.js';
import { processVlessHeader } from '../protocols/vless.js';
import { parseTrojanHeader } from '../protocols/trojan.js';
import { parseMandalaHeader } from '../protocols/mandala.js'; // [新增] 导入 Mandala 解析器
import { parseSocks5Header } from '../protocols/socks5.js';
import { parseShadowsocksHeader } from '../protocols/shadowsocks.js';
import { handleTCPOutBound } from './outbound.js';
import { safeCloseWebSocket, base64ToArrayBuffer, isHostBanned } from '../utils/helpers.js';

// [修改] 注册 mandala 协议
const protocolManager = new ProtocolManager()
    .register('vless', processVlessHeader)
    .register('trojan', parseTrojanHeader)
    .register('mandala', parseMandalaHeader) // [新增] 注册位置建议在 socks5 之前
    .register('socks5', parseSocks5Header)
    .register('ss', parseShadowsocksHeader);

export async function handleWebSocketRequest(request, ctx) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    
    let remoteSocketWrapper = { value: null, isConnecting: false, buffer: [] };
    let protocolDetected = false;
    let socks5State = 0; 
    
    const log = (info, event) => console.log(`[WS] ${info}`, event || '');
    
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    
    const streamPromise = readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            const bufferView = new Uint8Array(chunk);
            
            // Socks5 协商逻辑 (保持不变)
            if (socks5State > 0 || (!protocolDetected && bufferView[0] === 5)) {
                let currentChunk = chunk;
                let currentOffset = 0;
                
                if (socks5State === 0) {
                    if (bufferView.length < 2) return;
                    const nMethods = bufferView[1];
                    const methods = bufferView.slice(2, 2 + nMethods);
                    let method = 0xFF;
                    for (let i = 0; i < methods.length; i++) {
                        if (methods[i] === 0x02) { method = 0x02; break; }
                    }
                    if (method === 0x02) {
                        webSocket.send(new Uint8Array([0x05, 0x02])); 
                        socks5State = 1;
                        currentOffset = 2 + nMethods;
                    } else {
                        webSocket.send(new Uint8Array([0x05, 0xFF])); 
                        safeCloseWebSocket(webSocket);
                        return;
                    }
                    if (currentOffset >= bufferView.length) return;
                    currentChunk = chunk.slice(currentOffset);
                }
                
                if (socks5State === 1) {
                    const view = new Uint8Array(currentChunk);
                    if (view.length < 3) return;
                    if (view[0] !== 0x01) { safeCloseWebSocket(webSocket); return; }
                    try {
                        let offset = 1;
                        const uLen = view[offset++];
                        const user = new TextDecoder().decode(view.slice(offset, offset + uLen));
                        offset += uLen;
                        const pLen = view[offset++];
                        const pass = new TextDecoder().decode(view.slice(offset, offset + pLen));
                        
                        const isValidUser = (user === ctx.userID || user === ctx.dynamicUUID);
                        const isValidPass = (pass === ctx.dynamicUUID || pass === ctx.userID);
                        
                        if (isValidUser && isValidPass) {
                            webSocket.send(new Uint8Array([0x01, 0x00])); 
                            socks5State = 2;
                            currentOffset = offset + pLen;
                        } else {
                            log(`Socks5 Auth Fail: ${user}`);
                            webSocket.send(new Uint8Array([0x01, 0x01])); 
                            safeCloseWebSocket(webSocket);
                            return;
                        }
                    } catch (e) {
                        safeCloseWebSocket(webSocket);
                        return;
                    }
                    if (currentOffset >= view.length) return;
                    currentChunk = currentChunk.slice(currentOffset);
                }
            }

            // 数据转发逻辑
            if (protocolDetected) {
                if (remoteSocketWrapper.value) {
                    const writer = remoteSocketWrapper.value.writable.getWriter();
                    await writer.write(chunk);
                    writer.releaseLock();
                } else if (remoteSocketWrapper.isConnecting) {
                    remoteSocketWrapper.buffer.push(chunk);
                }
                return;
            }
            
            try {
                // 协议检测
                const result = await protocolManager.detect(chunk, ctx);
                if (socks5State === 2 && result.protocol !== 'socks5') throw new Error('Socks5 protocol mismatch');

                protocolDetected = true;
                remoteSocketWrapper.isConnecting = true;

                const { protocol, addressRemote, portRemote, addressType, rawDataIndex, isUDP } = result;
                
                log(`Detected: ${protocol.toUpperCase()} -> ${addressRemote}:${portRemote}`);
                
                if (isHostBanned(addressRemote, ctx.banHosts)) {
                    throw new Error(`Blocked: ${addressRemote}`);
                }
                
                let responseHeader = null;
                let clientData = chunk;
                
                // [修改] 协议分支处理
                if (protocol === 'vless') {
                    clientData = chunk.slice(rawDataIndex);
                    responseHeader = new Uint8Array([result.cloudflareVersion[0], 0]);
                    if (isUDP && portRemote !== 53) throw new Error('UDP only for DNS(53)');
                } else if (protocol === 'trojan' || protocol === 'ss' || protocol === 'mandala') { 
                    // [新增] mandala 走这里，直接使用解析后的 rawClientData (已去除头部)
                    clientData = result.rawClientData;
                } else if (protocol === 'socks5') {
                    clientData = result.rawClientData;
                    webSocket.send(new Uint8Array([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]));
                    socks5State = 3;
                }
                
                handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);
                
            } catch (e) {
                log('Detection failed: ' + e.message);
                safeCloseWebSocket(webSocket);
            }
        },
        close() { log("Client WebSocket closed"); },
        abort(reason) { log("WebSocket aborted", reason); safeCloseWebSocket(webSocket); },
    })).catch((err) => {
        log("Stream processing failed", err.toString());
        safeCloseWebSocket(webSocket);
    });

    if (ctx.waitUntil) ctx.waitUntil(streamPromise);

    return new Response(null, { status: 101, webSocket: client });
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    return new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener('message', (event) => {
                if (readableStreamCancel) return;
                if (typeof event.data === 'string') {
                    controller.enqueue(new TextEncoder().encode(event.data));
                } else {
                    controller.enqueue(event.data);
                }
            });
            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) return;
                controller.close();
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
