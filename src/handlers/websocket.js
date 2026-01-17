/**
 * 文件名: src/handlers/websocket.js
 * 修改内容: 
 * 1. 优化 concatUint8 避免冗余对象创建
 * 2. WritableStream 中全面使用 subarray 替代 slice
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

// [优化] 如果 b 已经是 Uint8Array，避免 new Uint8Array(b) 的开销
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
    
    // 状态变量
    let remoteSocketWrapper = { value: null, isConnecting: false, buffer: [] };
    let isConnected = false; 
    let socks5State = 0; 
    let headerBuffer = new Uint8Array(0); 
    
    // 常量配置
    const MAX_HEADER_BUFFER = 4096; // 4KB 防御大包攻击
    const DETECT_TIMEOUT_MS = 10000; // 10秒 协议检测超时

    const log = (info, event) => console.log(`[WS] ${info}`, event || '');

    // 超时熔断器
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
            // [优化] 统一转换为 Uint8Array，避免后续重复转换
            const chunkArr = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);

            // 1. 已连接状态：高性能直通
            if (isConnected) {
                if (remoteSocketWrapper.value) {
                    const writer = remoteSocketWrapper.value.writable.getWriter();
                    await writer.write(chunkArr);
                    writer.releaseLock();
                } else if (remoteSocketWrapper.isConnecting) {
                    remoteSocketWrapper.buffer.push(chunkArr);
                }
                return;
            }

            // 2. 数据缓冲
            headerBuffer = concatUint8(headerBuffer, chunkArr);

            // 3. Socks5 握手处理 (State 0 & 1)
            if (socks5State < 2) {
                const { consumed, newState, error } = tryHandleSocks5Handshake(headerBuffer, socks5State, webSocket, ctx, log);
                
                if (error) {
                    clearTimeout(timeoutTimer); 
                    throw new Error(error);
                }

                if (consumed > 0) {
                    // [优化] 使用 subarray 替代 slice
                    // 注意：这里必须重新赋值，因为 headerBuffer 需要指向新的剩余数据
                    // 虽然 subarray 创建视图，但我们需要丢弃已处理部分，
                    // 这里创建一个新副本可能是必要的，或者逻辑上把 headerBuffer 视为视图窗口。
                    // 考虑到 headerBuffer 通常很小 (握手阶段)，这里用 slice 或 subarray 后重新 set 都可以。
                    // 为了安全起见（避免内存泄漏），这里保持 slice 逻辑或者使用 subarray 但意识到这是新引用
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

                // 检查协议是否被禁用
                const pName = result.protocol; 
                const isSocksDisabled = pName === 'socks5' && ctx.disabledProtocols.includes('socks');
                
                if (ctx.disabledProtocols.includes(pName) || isSocksDisabled) {
                    throw new Error(`Protocol ${pName.toUpperCase()} is disabled by admin`);
                }

                // --- 成功识别 ---
                isConnected = true;
                clearTimeout(timeoutTimer); 
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
                    // [优化] 使用 subarray 替代 slice
                    clientData = headerBuffer.subarray(rawDataIndex);
                    responseHeader = new Uint8Array([result.cloudflareVersion[0], 0]);
                    if (isUDP && portRemote !== 53) throw new Error('UDP only for DNS(53)');
                } else if (protocol === 'trojan' || protocol === 'ss' || protocol === 'mandala') {
                    // 这些协议的解析器已经优化为返回 subarray 视图
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
                if (headerBuffer && headerBuffer.length < 512 && headerBuffer.length < MAX_HEADER_BUFFER) {
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
        clearTimeout(timeoutTimer);
        log("Stream processing failed", err.toString());
        safeCloseWebSocket(webSocket);
    });

    if (ctx.waitUntil) ctx.waitUntil(streamPromise);

    return new Response(null, { status: 101, webSocket: client });
}

// 辅助函数：Socks5 握手状态机 (保持不变，内部 slice 对小数据影响不大，为稳妥起见暂不改动关键状态机逻辑)
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
        // Auth 这里数据很短，TextDecoder 开销远大于 slice，保持现状
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
