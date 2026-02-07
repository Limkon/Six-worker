// src/handlers/xhttp.js
/**
 * 文件名: src/handlers/xhttp.js
 * 修正说明:
 * 1. [Fix] 移除 reader.read() 的无效参数，避免无意义的内存分配。
 * 2. [Refactor] 移除未使用的死代码 (get_xhttp_buffer)。
 * 3. [Fix] Header 解析失败时显式 cancel reader，防止资源泄漏。
 * 4. [Feat] 增加 Header 解析错误的日志记录，便于排查。
 * 5. [Fix] 全面增强异常捕获：确保 uploader 和 connectionClosed 永远不会 Reject。
 * 6. [Security] 增加 Header 读取超时控制 (3秒)，防止 Slow Loris 攻击导致资源耗尽。
 * 7. [Optimization] 重构 read_at_least，优化 Buffer 拼接逻辑，消除 O(N^2) 性能陷阱。
 */
import { CONSTANTS } from '../constants.js';
import { createUnifiedConnection } from './outbound.js';
import { isHostBanned, stringifyUUID, textDecoder } from '../utils/helpers.js';

function concat_typed_arrays(first, ...args) {
    let len = first.length;
    for (let a of args) len += a.length;
    const r = new first.constructor(len);
    r.set(first, 0);
    len = first.length;
    for (let a of args) {
        r.set(a, len);
        len += a.length;
    }
    return r;
}

// 辅助函数：确保从 reader 读取至少 minBytes 长度的数据
// [Security Fix] 增加 deadline 参数，实现超时控制
// [Optimization] 使用 Array 收集 Buffer 分片，避免循环内的重复内存分配和拷贝 (O(N^2) -> O(N))
async function read_at_least(reader, minBytes, initialBuffer, deadline) {
    let chunks = []; // 用于收集分片
    let totalLength = 0;

    // 1. 处理初始 Buffer
    if (initialBuffer && initialBuffer.byteLength > 0) {
        chunks.push(initialBuffer);
        totalLength += initialBuffer.byteLength;
    }

    // 2. 循环读取直到满足最小长度
    while (totalLength < minBytes) {
        // 计算剩余时间
        const remainingTime = deadline - Date.now();
        if (remainingTime <= 0) {
            throw new Error('Header read timeout');
        }

        // 创建超时 Promise
        let timeoutId;
        const timeoutPromise = new Promise((_, reject) => {
            timeoutId = setTimeout(() => reject(new Error('Header read timeout')), remainingTime);
        });

        // 竞争读取
        let result;
        try {
            result = await Promise.race([reader.read(), timeoutPromise]);
        } finally {
            clearTimeout(timeoutId);
        }

        const { value, done } = result;
        
        if (done) {
            // 如果流结束，跳出循环进行最终合并
            break; 
        }
        
        if (value && value.byteLength > 0) {
            chunks.push(value);
            totalLength += value.byteLength;
        }
    }

    // 3. 高效合并 (Zero/One Copy)
    if (chunks.length === 0) {
        return { value: new Uint8Array(0), done: true };
    }

    // 如果只有一个块，直接返回，避免复制
    if (chunks.length === 1) {
        return { value: chunks[0], done: totalLength < minBytes };
    }

    // 分配精确大小的内存
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
    
    // [Security] 定义头部读取的硬性截止时间 (3秒)
    // 防止恶意客户端通过极慢的发送速度(Slow Loris)占用 Worker 资源
    const HEADER_TIMEOUT = 3000;
    const deadline = Date.now() + HEADER_TIMEOUT;

    const fail = async (msg) => {
        try { await reader.cancel(msg); } catch (_) {}
        return msg;
    };

    try {
        // [Fix] 传递 deadline 到 read_at_least
        let { value: cache, done } = await read_at_least(reader, 18, null, deadline);
        if (cache.length < 18) return fail('header too short');

        const version = cache[0];
        
        const uuidStr = stringifyUUID(cache.subarray(1, 17));
        const expectedID = ctx.userID;
        const expectedIDLow = ctx.userIDLow;

        if (uuidStr !== expectedID && (!expectedIDLow || uuidStr !== expectedIDLow)) {
            return fail('invalid UUID');
        }
        
        const pb_len = cache[17];
        const min_len_until_atyp = 22 + pb_len;
        
        if (cache.length < min_len_until_atyp) {
            // [Fix] 传递 deadline
            const r = await read_at_least(reader, min_len_until_atyp, cache, deadline);
            cache = r.value;
            if (cache.length < min_len_until_atyp) return fail('header too short for metadata');
        }

        const cmdIndex = 18 + pb_len;
        const cmd = cache[cmdIndex];
        if (cmd !== 1) return fail('unsupported command: ' + cmd);
        
        const portIndex = cmdIndex + 1;
        const view = new DataView(cache.buffer, cache.byteOffset, cache.byteLength);
        const port = view.getUint16(portIndex, false); // Big-Endian
        
        const atype = cache[portIndex + 2];
        const addr_body_idx = portIndex + 3; 

        let header_len = -1;
        
        if (atype === CONSTANTS.ADDRESS_TYPE_IPV4) {
            header_len = addr_body_idx + 4;
        } else if (atype === CONSTANTS.ADDRESS_TYPE_IPV6) {
            header_len = addr_body_idx + 16;
        } else if (atype === CONSTANTS.ADDRESS_TYPE_URL) {
            if (cache.length < addr_body_idx + 1) {
                 // [Fix] 传递 deadline
                 const r = await read_at_least(reader, addr_body_idx + 1, cache, deadline);
                 cache = r.value;
                 if (cache.length < addr_body_idx + 1) return fail('header too short for domain len');
            }
            const domain_len = cache[addr_body_idx];
            header_len = addr_body_idx + 1 + domain_len;
        } else {
            return fail('read address type failed: ' + atype);
        }
        
        if (cache.length < header_len) {
            // [Fix] 传递 deadline
            const r = await read_at_least(reader, header_len, cache, deadline);
            cache = r.value;
            if (cache.length < header_len) return fail('header too short for full address');
        }
        
        let hostname = '';
        const addr_val_idx = addr_body_idx; 
        
        try {
            switch (atype) {
                case CONSTANTS.ADDRESS_TYPE_IPV4:
                    hostname = cache.subarray(addr_val_idx, addr_val_idx + 4).join('.');
                    break;
                case CONSTANTS.ADDRESS_TYPE_URL:
                    const domain_len = cache[addr_val_idx];
                    hostname = textDecoder.decode(
                        cache.subarray(addr_val_idx + 1, addr_val_idx + 1 + domain_len)
                    );
                    break;
                case CONSTANTS.ADDRESS_TYPE_IPV6:
                    const ipv6 = [];
                    for (let i = 0; i < 8; i++) {
                        ipv6.push(view.getUint16(addr_val_idx + i * 2, false).toString(16));
                    }
                    hostname = ipv6.join(':');
                    break;
            }
        } catch (e) {
            return fail('failed to parse hostname: ' + e.message);
        }
        
        if (!hostname) return fail('failed to parse hostname');
        
        const data = cache.subarray(header_len);
        
        return {
            hostname,
            port,
            atype,
            data,
            resp: new Uint8Array([version, 0]),
            reader,
            done: done && data.length === 0,
        };
    } catch (error) {
        try { reader.releaseLock(); } catch (_) {}
        throw error;
    }
}

async function upload_to_remote_xhttp(writer, httpx) {
    try {
        if (httpx.data && httpx.data.length > 0) {
            await writer.write(httpx.data);
        }
        
        if (httpx.done) return;

        while (true) {
            const { value, done } = await httpx.reader.read();
            if (done) break;
            if (value && value.length > 0) {
                await writer.write(value);
            }
        }
    } catch (error) {
        throw error;
    }
}

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
        flush() {
            clearInterval(idleTimer);
        },
        cancel() {
            clearInterval(idleTimer);
        }
    });

    const pipePromise = remote_readable.pipeTo(monitorStream.writable)
        .catch(() => {}) 
        .finally(() => {
            clearInterval(idleTimer);
        });

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

export async function handleXhttpClient(request, ctx) {
    try {
        const result = await read_xhttp_header(request.body, ctx);
        if (typeof result === 'string') {
            if (result !== 'stream cancelled' && !result.includes('cancelled')) {
                console.warn('[XHTTP Error] Header parsing failed:', result);
            }
            return null;
        }
        
        const { hostname, port, atype, data, resp, reader, done } = result;
        const httpx = { hostname, port, atype, data, resp, reader, done };
        
        if (isHostBanned(hostname, ctx.banHosts)) {
            console.log('[XHTTP] Blocked:', hostname);
            return null;
        }

        const remoteSocket = await createUnifiedConnection(ctx, hostname, port, atype, console.log, ctx.proxyIP);
        
        const uploader = {
            done: (async () => {
                // [Fix] 将 getWriter 移入 try 块，防止同步抛错导致 Promise Reject
                let writer = null;
                try {
                    writer = remoteSocket.writable.getWriter();
                    await upload_to_remote_xhttp(writer, httpx);
                } catch (e) {
                    const errStr = (e && e.message) ? e.message : String(e);
                    // 仅当错误不是 "Stream was cancelled" 时才记录，避免日志刷屏
                    if (!errStr.includes('cancelled') && !errStr.includes('aborted')) {
                        console.warn('[XHTTP Upload Error]:', errStr);
                    }
                } finally {
                    if (writer) {
                        try { await writer.close(); } catch (_) {}
                    }
                }
            })(),
            abort: () => { try { remoteSocket.writable.abort(); } catch (_) {} }
        };

        const downloader = create_xhttp_downloader(resp, remoteSocket.readable, remoteSocket.initialData);
        
        // [Fix] 终极兜底：确保 connectionClosed 永远不会 Reject
        // 这对于 ctx.waitUntil 是至关重要的，否则任何后台 Rejection 都会被视为 Worker 崩溃
        const connectionClosed = Promise.race([
            downloader.done,
            uploader.done
        ]).finally(() => {
            try { remoteSocket.close(); } catch (_) {}
            try { downloader.abort(); } catch (_) {}
            try { uploader.abort(); } catch (_) {}
        }).catch((err) => {
            // 吞掉所有后台错误，保持 Promise Resolved
            // console.debug('Ignored XHTTP background error:', err);
        });

        return {
            readable: downloader.readable,
            closed: connectionClosed
        };

    } catch (e) {
        const errStr = (e && e.message) ? e.message : String(e);
        if (errStr.includes('cancelled') || errStr.includes('aborted')) {
            return null;
        }
        // 如果是超时错误，在此处被捕获
        console.error('XHTTP Error:', e);
        return null;
    }
}
