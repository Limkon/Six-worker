// src/handlers/xhttp.js
/**
 * 文件名: src/handlers/xhttp.js
 * 极致优化版:
 * 1. [Critical Fix] 移除所有 TransformStream 和 JS 层面的 idle timeout 监控。
 * 下行流量直接返回 remoteSocket.readable (C++ Native Stream)，实现真正的 Zero-CPU 转发。
 * 2. [Safety] 保持 writer 锁的 try-finally 释放机制。
 * 3. [Logic] 仅保留连接建立时的握手逻辑，传输过程完全交给底层运行时。
 */
import { CONSTANTS } from '../constants.js';
import { createUnifiedConnection } from './outbound.js';
import { isHostBanned, stringifyUUID, textDecoder } from '../utils/helpers.js';

// --- 工具函数区 ---
async function safe_cancel(reader, reason) {
    if (!reader) return;
    try { await reader.cancel(reason); } catch (_) {}
}

async function safe_read(reader, deadline) {
    if (!reader) return { done: true };
    const remainingTime = deadline - Date.now();
    if (remainingTime <= 0) return { done: true, error: new Error('Read timeout') };

    let timeoutId;
    const timeoutPromise = new Promise(resolve => {
        timeoutId = setTimeout(() => resolve({ timeout: true }), remainingTime);
    });

    try {
        const result = await Promise.race([reader.read(), timeoutPromise]);
        if (result.timeout) return { done: true, error: new Error('Read timeout') };
        return result; 
    } catch (e) {
        const msg = (e.message || '').toLowerCase();
        if (msg.includes('cancelled') || msg.includes('aborted') || msg.includes('closed')) {
            return { done: true };
        }
        throw e;
    } finally {
        if (timeoutId) clearTimeout(timeoutId);
    }
}

// --- 头部解析逻辑 ---
async function read_at_least(reader, minBytes, initialBuffer, deadline) {
    let chunks = []; 
    let totalLength = 0;

    if (initialBuffer && initialBuffer.byteLength > 0) {
        chunks.push(initialBuffer);
        totalLength += initialBuffer.byteLength;
    }

    while (totalLength < minBytes) {
        const { value, done, error } = await safe_read(reader, deadline);
        if (error) throw error;
        if (done) break;
        if (value && value.byteLength > 0) {
            chunks.push(value);
            totalLength += value.byteLength;
        }
    }

    if (chunks.length === 0) return { value: new Uint8Array(0), done: true };
    if (chunks.length === 1) return { value: chunks[0], done: totalLength < minBytes };

    const resultBuffer = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
        resultBuffer.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return { value: resultBuffer, done: totalLength < minBytes };
}

async function read_xhttp_header(readable, ctx) {
    const reader = readable.getReader(); 
    const deadline = Date.now() + 3000;

    try {
        let { value: cache, done } = await read_at_least(reader, 18, null, deadline);
        if (cache.length < 18) throw new Error('header too short');

        const version = cache[0];
        const uuidStr = stringifyUUID(cache.subarray(1, 17));
        
        const expectedID = ctx.userID;
        const expectedIDLow = ctx.userIDLow;
        if (uuidStr !== expectedID && (!expectedIDLow || uuidStr !== expectedIDLow)) {
            throw new Error('invalid UUID');
        }
        
        const pb_len = cache[17];
        const min_len_until_atyp = 22 + pb_len; 
        
        if (cache.length < min_len_until_atyp) {
            const r = await read_at_least(reader, min_len_until_atyp, cache, deadline);
            cache = r.value;
            if (cache.length < min_len_until_atyp) throw new Error('header too short for metadata');
        }

        const cmdIndex = 18 + pb_len;
        if (cache[cmdIndex] !== 1) throw new Error('unsupported command: ' + cache[cmdIndex]);
        
        const portIndex = cmdIndex + 1;
        const view = new DataView(cache.buffer, cache.byteOffset, cache.byteLength);
        const port = view.getUint16(portIndex, false); 
        const atype = cache[portIndex + 2];
        const addr_body_idx = portIndex + 3; 

        let header_len = -1;
        if (atype === CONSTANTS.ADDRESS_TYPE_IPV4) {
            header_len = addr_body_idx + 4;
        } else if (atype === CONSTANTS.ADDRESS_TYPE_IPV6) {
            header_len = addr_body_idx + 16;
        } else if (atype === CONSTANTS.ADDRESS_TYPE_URL) {
            if (cache.length < addr_body_idx + 1) {
                 const r = await read_at_least(reader, addr_body_idx + 1, cache, deadline);
                 cache = r.value;
                 if (cache.length < addr_body_idx + 1) throw new Error('header too short for domain len');
            }
            header_len = addr_body_idx + 1 + cache[addr_body_idx];
        } else {
            throw new Error('unknown address type: ' + atype);
        }
        
        if (cache.length < header_len) {
            const r = await read_at_least(reader, header_len, cache, deadline);
            cache = r.value;
            if (cache.length < header_len) throw new Error('header too short for full address');
        }
        
        let hostname = '';
        const addr_val_idx = addr_body_idx; 
        try {
            if (atype === CONSTANTS.ADDRESS_TYPE_IPV4) {
                hostname = cache.subarray(addr_val_idx, addr_val_idx + 4).join('.');
            } else if (atype === CONSTANTS.ADDRESS_TYPE_URL) {
                const domain_len = cache[addr_val_idx];
                hostname = textDecoder.decode(cache.subarray(addr_val_idx + 1, addr_val_idx + 1 + domain_len));
            } else if (atype === CONSTANTS.ADDRESS_TYPE_IPV6) {
                const ipv6 = [];
                for (let i = 0; i < 8; i++) ipv6.push(view.getUint16(addr_val_idx + i * 2, false).toString(16));
                hostname = ipv6.join(':');
            }
        } catch (e) {
            throw new Error('failed to parse hostname');
        }
        
        if (!hostname) throw new Error('empty hostname');
        
        return {
            hostname, port, atype,
            data: cache.subarray(header_len),
            resp: new Uint8Array([version, 0]),
            reader,
            done: done && cache.subarray(header_len).length === 0,
        };

    } catch (error) {
        await safe_cancel(reader, error.message);
        throw error;
    }
}

// --- 主处理函数 (极致优化版) ---
export async function handleXhttpClient(request, ctx) {
    let result;
    try {
        result = await read_xhttp_header(request.body, ctx);
    } catch (e) {
        const errStr = e.message || '';
        if (!errStr.includes('header too short') && !errStr.includes('invalid UUID')) {
             console.warn('[XHTTP Handshake Error]:', errStr);
        }
        return null;
    }

    const { hostname, port, atype, data, resp, reader, done } = result;

    // 1. 检查黑名单 (已使用 Cached Regex)
    if (isHostBanned(hostname, ctx.banHosts)) {
        console.log('[XHTTP] Blocked:', hostname);
        await safe_cancel(reader, 'blocked');
        return null;
    }

    // 2. 建立连接
    let remoteSocket;
    try {
        remoteSocket = await createUnifiedConnection(ctx, hostname, port, atype, console.log, ctx.proxyIP);
    } catch (e) {
        console.error('[XHTTP] Connect Failed:', e.message);
        await safe_cancel(reader, 'connect failed');
        return null;
    }

    // 3. 上行管道 (Request -> Remote)
    // 使用 pipeTo 实现 Zero-CPU 转发
    const uploaderPromise = (async () => {
        try {
            if (data && data.length > 0) {
                const writer = remoteSocket.writable.getWriter();
                try {
                    await writer.write(data);
                } finally {
                    writer.releaseLock(); 
                }
            }

            if (done) {
                await remoteSocket.writable.close();
            } else {
                reader.releaseLock(); 
                // 原生管道，不经过 JS 循环
                await request.body.pipeTo(remoteSocket.writable); 
            }
        } catch (e) {
            // 管道断开属正常现象
        }
    })();

    // 4. 下行管道 (Remote -> Response)
    // [Critical Fix] 移除 TransformStream，直接使用原生 ReadableStream
    // 牺牲应用层 Idle Timeout，换取系统级 Zero-CPU 转发性能
    // Cloudflare 底层 Socket 会自动处理 TCP Keep-Alive 和超时
    let responseReadable = remoteSocket.readable;
    
    // 如果有握手响应数据(resp)或Early Data，需要拼接
    if ((resp && resp.length > 0) || (remoteSocket.initialData && remoteSocket.initialData.byteLength > 0)) {
        const { readable, writable } = new TransformStream();
        const writer = writable.getWriter();
        
        (async () => {
            try {
                if (resp) await writer.write(resp);
                if (remoteSocket.initialData) await writer.write(remoteSocket.initialData);
                writer.releaseLock();
                // 仅做管道对接，不监控每一块数据
                await remoteSocket.readable.pipeTo(writable);
            } catch (e) {
                try { writable.abort(e); } catch (_) {}
            }
        })();
        
        responseReadable = readable;
    }

    // 5. 生命周期管理
    // 当上行结束或下行结束时，关闭 socket
    // 注意：不再使用 waitUntil(r.closed)，让流自然结束
    const connectionClosed = uploaderPromise.then(() => {
        // 上行结束后，通常不主动关闭 remoteSocket，等待下行自然结束
        // 除非需要在上行结束时强制断开 (视具体协议行为而定)
    });

    return {
        readable: responseReadable,
        closed: connectionClosed 
    };
}
