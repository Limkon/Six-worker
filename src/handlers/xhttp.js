// src/handlers/xhttp.js
/**
 * 文件名: src/handlers/xhttp.js
 * 审计修复版:
 * 1. [Fix] 修复低频小包(SSH)场景下因采样频率过低导致的 Idle Timeout 误判.
 * 2. [Fix] 修复生命周期结束时，若无上行数据会导致 Reader 阻塞无法退出的死锁问题.
 * 3. [Robust] 增强资源清理逻辑，确保 Request Body Reader 被显式 Cancel.
 */
import { CONSTANTS } from '../constants.js';
import { createUnifiedConnection } from './outbound.js';
import { isHostBanned, stringifyUUID, textDecoder } from '../utils/helpers.js';

// --- 常量定义 ---
// 8分钟轮换，留出 buffer 避免 CPU 熔断
const SESSION_MAX_LIFE_MS = 8 * 60 * 1000; 

// --- 工具函数区 ---

async function safe_cancel(reader, reason) {
    if (!reader) return;
    try {
        await reader.cancel(reason);
    } catch (_) { }
}

async function safe_read(reader, deadline) {
    if (!reader) return { done: true };

    const remainingTime = deadline - Date.now();
    if (remainingTime <= 0) {
        return { done: true, error: new Error('Read timeout') };
    }

    let timeoutId;
    const timeoutPromise = new Promise(resolve => {
        timeoutId = setTimeout(() => resolve({ timeout: true }), remainingTime);
    });

    try {
        const result = await Promise.race([reader.read(), timeoutPromise]);
        
        if (result.timeout) {
            return { done: true, error: new Error('Read timeout') };
        }
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

// --- 业务逻辑区 ---

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

async function upload_to_remote_xhttp(writer, httpx, abortSignal) {
    if (httpx.data && httpx.data.length > 0) {
        await writer.write(httpx.data);
    }
    if (httpx.done) return;

    while (true) {
        // [Fix] 虽然这里有 check，但如果 reader.read 阻塞，break 不会被执行
        // 因此必须依赖外部调用 httpx.reader.cancel() 来打破阻塞
        if (abortSignal && abortSignal.aborted) break;

        try {
            const { value, done } = await httpx.reader.read();
            if (done) break;
            if (value) await writer.write(value);
        } catch (e) {
            break; 
        }
    }
}

// 创建带空闲超时监控的下载流
function create_xhttp_downloader(resp, remote_readable, initialData, abortController) {
    const IDLE_TIMEOUT_MS = CONSTANTS.IDLE_TIMEOUT_MS || 45000;
    let lastActivity = Date.now();
    let idleTimer;
    let chunkCount = 0; 
    // [Fix] 增加时间采样锚点，防止低频流量下 lastActivity 长期不更新
    let lastSampleTime = Date.now(); 

    const monitorStream = new TransformStream({
        start(controller) {
            controller.enqueue(resp);
            if (initialData && initialData.byteLength > 0) {
                controller.enqueue(initialData);
            }
            
            idleTimer = setInterval(() => {
                const now = Date.now();
                if (now - lastActivity > IDLE_TIMEOUT_MS) {
                    abortController.abort('idle timeout');
                    return;
                }
                if (abortController.signal.aborted) {
                    clearInterval(idleTimer);
                }
            }, 5000); 
        },
        transform(chunk, controller) {
            chunkCount++;
            const now = Date.now();
            
            // [Fix] 采样逻辑优化：
            // 1. 累积 50 个包
            // 2. OR 距离上次采样超过 3 秒 (解决 SSH 低频流量问题)
            // 3. OR 大包 (>16KB)
            if (chunkCount >= 50 || (now - lastSampleTime > 3000) || chunk.byteLength > 16384) {
                lastActivity = now;
                lastSampleTime = now;
                chunkCount = 0;
            }

            controller.enqueue(chunk);
        },
        flush() { clearInterval(idleTimer); },
        cancel() { clearInterval(idleTimer); }
    });

    const pipePromise = remote_readable.pipeTo(monitorStream.writable).catch(() => {});

    return {
        readable: monitorStream.readable,
        done: pipePromise
    };
}

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

    const lifeController = new AbortController();
    
    // 1. 设置最大生命周期定时器
    const sessionTimeout = setTimeout(() => {
        lifeController.abort('session_max_life_reached');
    }, SESSION_MAX_LIFE_MS);

    // 上行处理
    const uploaderPromise = (async () => {
        let writer = null;
        try {
            writer = remoteSocket.writable.getWriter();
            await upload_to_remote_xhttp(writer, { data, done, reader }, lifeController.signal);
        } catch (e) {
            // ignore
        } finally {
            if (writer) try { await writer.close(); } catch (_) {}
            // 这里的 cancel 主要是为了防止 upload_to_remote_xhttp 正常退出后 reader 还没关
            // 但如果死锁在 read 中，需要依靠下面的 signal listener
            await safe_cancel(reader, 'upload finished'); 
        }
    })();

    // 下行处理
    const downloader = create_xhttp_downloader(resp, remoteSocket.readable, remoteSocket.initialData, lifeController);

    // [Fix] 监听 Abort 信号，强制打破所有潜在的阻塞
    lifeController.signal.addEventListener('abort', () => {
        // 1. 关闭远程连接 (打破 downloader pipeTo)
        try { remoteSocket.close(); } catch (_) {}
        // 2. [Critical] 强制 Cancel 请求 Body Reader (打破 uploader read 阻塞)
        safe_cancel(reader, 'session aborted');
    });

    const connectionClosed = Promise.allSettled([downloader.done, uploaderPromise]).then(() => {
        clearTimeout(sessionTimeout);
        try { remoteSocket.close(); } catch (_) {}
        try { downloader.readable.cancel(); } catch (_) {}
    });

    return {
        readable: downloader.readable,
        closed: connectionClosed 
    };
}
