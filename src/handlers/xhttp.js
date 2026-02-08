// src/handlers/xhttp.js
/**
 * 文件名: src/handlers/xhttp.js
 * 审计修复版:
 * 1. [Fix] 使用 try-finally 确保 writer 锁必定释放，防止异常时的资源泄漏。
 * 2. [Perf] 保持 pipeTo 带来的 Zero-CPU 特性。
 * 3. [Note] 当前仅支持 TCP (CMD=1)，符合绝大多数 XHTTP 使用场景。
 */
import { CONSTANTS } from '../constants.js';
import { createUnifiedConnection } from './outbound.js';
import { isHostBanned, stringifyUUID, textDecoder } from '../utils/helpers.js';

// --- 工具函数区 (保持不变) ---
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

// --- 头部解析逻辑 (保持不变) ---
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

// --- 下载流监控 (保持不变) ---
function create_xhttp_downloader(resp, remote_readable, initialData) {
    const IDLE_TIMEOUT_MS = CONSTANTS.IDLE_TIMEOUT_MS || 45000;
    let lastActivity = Date.now();
    let idleTimer;

    const monitorStream = new TransformStream({
        start(controller) {
            controller.enqueue(resp);
            if (initialData && initialData.byteLength > 0) {
                controller.enqueue(initialData);
            }
            idleTimer = setInterval(() => {
                if (Date.now() - lastActivity > IDLE_TIMEOUT_MS) {
                    try { monitorStream.writable.abort('idle timeout'); } catch (_) {}
                    try { monitorStream.readable.cancel('idle timeout'); } catch (_) {}
                    clearInterval(idleTimer);
                }
            }, 5000);
        },
        transform(chunk, controller) {
            lastActivity = Date.now();
            controller.enqueue(chunk);
        },
        flush() { clearInterval(idleTimer); },
        cancel() { clearInterval(idleTimer); }
    });

    const pipePromise = remote_readable.pipeTo(monitorStream.writable).catch(() => {});

    return {
        readable: monitorStream.readable,
        done: pipePromise,
        abort: () => {
            try { monitorStream.writable.abort(); } catch (_) {}
            try { monitorStream.readable.cancel(); } catch (_) {}
            clearInterval(idleTimer);
        }
    };
}

// --- 主处理函数 (已修复锁释放逻辑) ---
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

    if (isHostBanned(hostname, ctx.banHosts)) {
        console.log('[XHTTP] Blocked:', hostname);
        await safe_cancel(reader, 'blocked');
        return null;
    }

    let remoteSocket;
    try {
        remoteSocket = await createUnifiedConnection(ctx, hostname, port, atype, console.log, ctx.proxyIP);
    } catch (e) {
        console.error('[XHTTP] Connect Failed:', e.message);
        await safe_cancel(reader, 'connect failed');
        return null;
    }

    // [Safety Fix] 确保 writer 锁释放
    const uploaderPromise = (async () => {
        try {
            if (data && data.length > 0) {
                const writer = remoteSocket.writable.getWriter();
                try {
                    await writer.write(data);
                } finally {
                    writer.releaseLock(); // 无论 write 成功与否，必定释放锁
                }
            }

            if (done) {
                await remoteSocket.writable.close();
            } else {
                reader.releaseLock(); // 释放 request.body 的 reader
                await request.body.pipeTo(remoteSocket.writable); // 原生管道传输
            }
        } catch (e) {
            // pipeTo 或 write 错误通常意味着连接中断，无需额外操作
        }
    })();

    const downloader = create_xhttp_downloader(resp, remoteSocket.readable, remoteSocket.initialData);

    const connectionClosed = Promise.allSettled([downloader.done, uploaderPromise]).then(() => {
        try { remoteSocket.close(); } catch (_) {}
        downloader.abort();
    });

    return {
        readable: downloader.readable,
        closed: connectionClosed 
    };
}
