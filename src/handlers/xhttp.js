/**
 * 文件名: src/handlers/xhttp.js
 * 修正说明:
 * 1. [Fix] 补回 createUnifiedConnection 缺失的 ctx.proxyIP 参数，解决连接问题。
 * 2. 保留了 Six-worker 的标准流读取逻辑和 pipeTo 优化。
 */
import { CONSTANTS } from '../constants.js';
import { createUnifiedConnection } from './outbound.js';
import { isHostBanned } from '../utils/helpers.js';

const XHTTP_BUFFER_SIZE = 128 * 1024;

function parse_uuid_xhttp(uuid_str) {
    if (!uuid_str) return [];
    uuid_str = uuid_str.replaceAll('-', '');
    const r = [];
    for (let index = 0; index < 16; index++) {
        r.push(parseInt(uuid_str.substr(index * 2, 2), 16));
    }
    return r;
}

function validate_uuid_xhttp(id, uuid_str) {
    const uuid_arr = parse_uuid_xhttp(uuid_str);
    if (uuid_arr.length !== 16) return false;
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

// 辅助函数：确保从 reader 读取至少 minBytes 长度的数据
async function read_at_least(reader, minBytes, initialBuffer) {
    let currentBuffer = initialBuffer || new Uint8Array(0);
    
    while (currentBuffer.length < minBytes) {
        // 计算还需要读多少
        const needed = minBytes - currentBuffer.length;
        // 分配缓冲区
        const bufferSize = Math.max(needed, 4096); 
        const { value, done } = await reader.read(new Uint8Array(bufferSize));
        
        if (done) {
            // 流结束了但数据还不够
            return { value: currentBuffer, done: true };
        }
        
        if (value) {
            currentBuffer = concat_typed_arrays(currentBuffer, value);
        }
    }
    return { value: currentBuffer, done: false };
}

async function read_xhttp_header(readable, ctx) {
    // 使用默认 reader
    const reader = readable.getReader(); 
    try {
        // 1. 读取基础头部结构：Version(1) + UUID(16) + PBLen(1) = 18字节
        let { value: cache, done } = await read_at_least(reader, 18);
        if (cache.length < 18) return 'header too short';

        const version = cache[0];
        const id = cache.subarray(1, 1 + 16);
        
        if (!validate_uuid_xhttp(id, ctx.userID)) {
            if (!ctx.userIDLow || !validate_uuid_xhttp(id, ctx.userIDLow)) {
                return 'invalid UUID';
            }
        }
        
        const pb_len = cache[1 + 16];
        // 计算直到 Address Type 结束需要的最小长度
        // Base(18) + PB(pb_len) + Cmd(1) + Port(2) + Atyp(1) = 22 + pb_len
        const min_len_until_atyp = 1 + 16 + 1 + pb_len + 1 + 2 + 1;
        
        // 确保读够到 Atyp
        if (cache.length < min_len_until_atyp) {
            const r = await read_at_least(reader, min_len_until_atyp, cache);
            cache = r.value;
            if (cache.length < min_len_until_atyp) return 'header too short for metadata';
        }

        const cmd = cache[1 + 16 + 1 + pb_len];
        if (cmd !== 1) return 'unsupported command: ' + cmd;
        
        const addr_start_idx = 1 + 16 + 1 + pb_len + 1; // 指向 Port
        const port = (cache[addr_start_idx] << 8) + cache[addr_start_idx + 1];
        const atype = cache[addr_start_idx + 2];
        const addr_body_idx = addr_start_idx + 3; // 指向地址具体内容的开始

        let header_len = -1;
        
        // 根据 atype 判断需要的总长度
        if (atype === CONSTANTS.ADDRESS_TYPE_IPV4) {
            header_len = addr_body_idx + 4;
        } else if (atype === CONSTANTS.ADDRESS_TYPE_IPV6) {
            header_len = addr_body_idx + 16;
        } else if (atype === CONSTANTS.ADDRESS_TYPE_URL) {
            // 需要先读 1 个字节获取域名长度
            if (cache.length < addr_body_idx + 1) {
                 const r = await read_at_least(reader, addr_body_idx + 1, cache);
                 cache = r.value;
                 if (cache.length < addr_body_idx + 1) return 'header too short for domain len';
            }
            const domain_len = cache[addr_body_idx];
            header_len = addr_body_idx + 1 + domain_len;
        } else {
            return 'read address type failed: ' + atype;
        }
        
        // 最终确保读完整个 Header
        if (cache.length < header_len) {
            const r = await read_at_least(reader, header_len, cache);
            cache = r.value;
            if (cache.length < header_len) return 'header too short for full address';
        }
        
        // 解析地址
        let hostname = '';
        const addr_val_idx = addr_body_idx; 
        
        switch (atype) {
            case CONSTANTS.ADDRESS_TYPE_IPV4:
                hostname = cache.subarray(addr_val_idx, addr_val_idx + 4).join('.');
                break;
            case CONSTANTS.ADDRESS_TYPE_URL:
                hostname = new TextDecoder().decode(
                    cache.subarray(addr_val_idx + 1, addr_val_idx + 1 + cache[addr_val_idx]),
                );
                break;
            case CONSTANTS.ADDRESS_TYPE_IPV6:
                hostname = cache
                    .subarray(addr_val_idx, addr_val_idx + 16)
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
            // [Log] 仅在 debug 模式或确实需要时打印，避免日志泛滥
            // console.log('[XHTTP] Header Error:', result);
            return null;
        }
        
        const { hostname, port, atype, data, resp, reader, done } = result;
        const httpx = { hostname, port, atype, data, resp, reader, done };
        
        if (isHostBanned(hostname, ctx.banHosts)) {
            console.log('[XHTTP] Blocked:', hostname);
            return null;
        }

        // [Fix] 传入 ctx.proxyIP，与 Five-worker 保持一致，确保 Cloudflare 环境下的连通性
        const remoteSocket = await createUnifiedConnection(ctx, hostname, port, atype, console.log, ctx.proxyIP);
        
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
