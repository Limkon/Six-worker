/**
 * 文件名: src/handlers/xhttp.js
 * 优化说明:
 * 1. [Performance] 重构 create_xhttp_downloader，使用 pipeTo 替代手动 while 循环，大幅提升吞吐量。
 * 2. [Stability] 保持空闲超时检测逻辑。
 * 3. [Memory] 优化数据流转，减少 Promise 创建开销。
 */
import { CONSTANTS } from '../constants.js';
import { createUnifiedConnection } from './outbound.js';
import { isHostBanned } from '../utils/helpers.js';

const XHTTP_BUFFER_SIZE = 128 * 1024;

function parse_uuid_xhttp(uuid_str) {
    uuid_str = uuid_str.replaceAll('-', '');
    const r = [];
    for (let index = 0; index < 16; index++) {
        r.push(parseInt(uuid_str.substr(index * 2, 2), 16));
    }
    return r;
}

function validate_uuid_xhttp(id, uuid_str) {
    const uuid_arr = parse_uuid_xhttp(uuid_str);
    for (let index = 0; index < 16; index++) {
        if (id[index] !== uuid_arr[index]) return false;
    }
    return true;
}

function get_xhttp_buffer(size) {
    return new Uint8Array(new ArrayBuffer(size || XHTTP_BUFFER_SIZE));
}

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

async function read_xhttp_header(readable, ctx) {
    const reader = readable.getReader({ mode: 'byob' });
    try {
        let r = await reader.readAtLeast(1 + 16 + 1, get_xhttp_buffer());
        let rlen = 0;
        let idx = 0;
        let cache = r.value;
        rlen += r.value.length;
        
        const version = cache[0];
        const id = cache.subarray(1, 1 + 16);
        
        if (!validate_uuid_xhttp(id, ctx.userID)) {
            if (!ctx.userIDLow || !validate_uuid_xhttp(id, ctx.userIDLow)) {
                return 'invalid UUID';
            }
        }
        
        const pb_len = cache[1 + 16];
        const addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1;
        
        if (addr_plus1 + 1 > rlen) {
            if (r.done) return 'header too short';
            idx = addr_plus1 + 1 - rlen;
            r = await reader.readAtLeast(idx, get_xhttp_buffer());
            rlen += r.value.length;
            cache = concat_typed_arrays(cache, r.value);
        }
        
        const cmd = cache[1 + 16 + 1 + pb_len];
        if (cmd !== 1) return 'unsupported command: ' + cmd;
        
        const port = (cache[addr_plus1 - 1 - 2] << 8) + cache[addr_plus1 - 1 - 1];
        const atype = cache[addr_plus1 - 1];
        let header_len = -1;
        
        if (atype === CONSTANTS.ADDRESS_TYPE_IPV4) {
            header_len = addr_plus1 + 4;
        } else if (atype === CONSTANTS.ADDRESS_TYPE_IPV6) {
            header_len = addr_plus1 + 16;
        } else if (atype === CONSTANTS.ADDRESS_TYPE_URL) {
            header_len = addr_plus1 + 1 + cache[addr_plus1];
        }
        
        if (header_len < 0) return 'read address type failed';
        
        idx = header_len - rlen;
        if (idx > 0) {
            if (r.done) return 'read address failed';
            r = await reader.readAtLeast(idx, get_xhttp_buffer());
            rlen += r.value.length;
            cache = concat_typed_arrays(cache, r.value);
        }
        
        let hostname = '';
        idx = addr_plus1;
        switch (atype) {
            case CONSTANTS.ADDRESS_TYPE_IPV4:
                hostname = cache.subarray(idx, idx + 4).join('.');
                break;
            case CONSTANTS.ADDRESS_TYPE_URL:
                hostname = new TextDecoder().decode(
                    cache.subarray(idx + 1, idx + 1 + cache[idx]),
                );
                break;
            case CONSTANTS.ADDRESS_TYPE_IPV6:
                hostname = cache
                    .subarray(idx, idx + 16)
                    .reduce(
                        (s, b2, i2, a) =>
                           i2 % 2
                                ? s.concat(((a[i2 - 1] << 8) + b2).toString(16))
                                : s,
                         [],
                    )
                    .join(':');
                break;
        }
        
        if (hostname.length < 1) return 'failed to parse hostname';
        
        const data = cache.subarray(header_len);
        
        return {
            hostname,
            port,
            atype,
            data,
            resp: new Uint8Array([version, 0]),
            reader,
            done: r.done,
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
        
        while (!httpx.done) {
            const r = await httpx.reader.read(get_xhttp_buffer());
            if (r.done) break;
            if (r.value && r.value.length > 0) {
                await writer.write(r.value);
            }
            httpx.done = r.done;
        }
    } catch (error) {
        throw error;
    }
}

// [优化] 重构后的下载器，使用 pipeTo 提升性能
function create_xhttp_downloader(resp, remote_readable, initialData) {
    const IDLE_TIMEOUT_MS = CONSTANTS.IDLE_TIMEOUT_MS || 45000;
    let lastActivity = Date.now();
    let idleTimer;

    // 创建转换流，用于监控数据流动并更新活动时间
    const monitorStream = new TransformStream({
        start(controller) {
            // 首先将响应头和可能的初始数据推入队列
            controller.enqueue(resp);
            if (initialData && initialData.byteLength > 0) {
                controller.enqueue(initialData);
            }
            
            // 启动空闲检测定时器
            idleTimer = setInterval(() => {
                if (Date.now() - lastActivity > IDLE_TIMEOUT_MS) {
                    try { monitorStream.writable.abort('idle timeout'); } catch (_) {}
                    try { monitorStream.readable.cancel('idle timeout'); } catch (_) {}
                    clearInterval(idleTimer);
                }
            }, 5000);
        },
        transform(chunk, controller) {
            // 每当有数据流过，更新时间戳
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

    // 使用 pipeTo 自动管理背压和流传输，比手动循环快得多
    const pipePromise = remote_readable.pipeTo(monitorStream.writable)
        .catch(() => {}) // 忽略流中断错误
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
        if (typeof result === 'string') return null; 
        
        const { hostname, port, atype, data, resp, reader, done } = result;
        const httpx = { hostname, port, atype, data, resp, reader, done };
        
        if (isHostBanned(hostname, ctx.banHosts)) {
            console.log('[XHTTP] Blocked:', hostname);
            return null;
        }

        const remoteSocket = await createUnifiedConnection(ctx, hostname, port, atype, console.log);
        
        const uploader = {
            done: (async () => {
                const writer = remoteSocket.writable.getWriter();
                try {
                    await upload_to_remote_xhttp(writer, httpx);
                } finally {
                    try { await writer.close(); } catch (_) {}
                }
            })(),
            abort: () => { try { remoteSocket.writable.abort(); } catch (_) {} }
        };

        const downloader = create_xhttp_downloader(resp, remoteSocket.readable, remoteSocket.initialData);
        
        const connectionClosed = Promise.race([
            downloader.done,
            uploader.done
        ]).finally(() => {
            try { remoteSocket.close(); } catch (_) {}
            try { downloader.abort(); } catch (_) {}
            try { uploader.abort(); } catch (_) {}
        });

        return {
            readable: downloader.readable,
            closed: connectionClosed
        };

    } catch (e) {
        console.error('XHTTP Error:', e);
        return null;
    }
}
