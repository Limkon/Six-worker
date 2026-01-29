/**
 * 文件名: src/handlers/xhttp.js
 * 修正说明:
 * 1. [Optimization] 优化 UUID 校验，复用 stringifyUUID，避免重复解析配置字符串。
 * 2. [Optimization] 优化 IPv6 解析逻辑，移除低效的 reduce，使用循环 + DataView。
 * 3. [Refactor] 统一使用 DataView 读取端口，与 VLESS/Trojan 保持代码风格一致。
 */
import { CONSTANTS } from '../constants.js';
import { createUnifiedConnection } from './outbound.js';
import { isHostBanned, stringifyUUID, textDecoder } from '../utils/helpers.js'; // 引入通用工具

const XHTTP_BUFFER_SIZE = 128 * 1024;

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
        const needed = minBytes - currentBuffer.length;
        const bufferSize = Math.max(needed, 4096); 
        const { value, done } = await reader.read(new Uint8Array(bufferSize));
        
        if (done) return { value: currentBuffer, done: true };
        
        if (value) {
            currentBuffer = concat_typed_arrays(currentBuffer, value);
        }
    }
    return { value: currentBuffer, done: false };
}

async function read_xhttp_header(readable, ctx) {
    const reader = readable.getReader(); 
    try {
        // 1. 读取基础头部结构：Version(1) + UUID(16) + PBLen(1) = 18字节
        let { value: cache, done } = await read_at_least(reader, 18);
        if (cache.length < 18) return 'header too short';

        const version = cache[0];
        
        // [Optimization] 使用 stringifyUUID 进行字符串比对，避免每次手动解析 Hex
        const uuidStr = stringifyUUID(cache.subarray(1, 17));
        const expectedID = ctx.userID;
        const expectedIDLow = ctx.userIDLow;

        // 简单的字符串比较（不区分大小写）
        if (uuidStr !== expectedID && (!expectedIDLow || uuidStr !== expectedIDLow)) {
            return 'invalid UUID';
        }
        
        const pb_len = cache[17];
        // 计算直到 Address Type 结束需要的最小长度
        // Base(18) + PB(pb_len) + Cmd(1) + Port(2) + Atyp(1) = 22 + pb_len
        const min_len_until_atyp = 22 + pb_len;
        
        if (cache.length < min_len_until_atyp) {
            const r = await read_at_least(reader, min_len_until_atyp, cache);
            cache = r.value;
            if (cache.length < min_len_until_atyp) return 'header too short for metadata';
        }

        const cmdIndex = 18 + pb_len;
        const cmd = cache[cmdIndex];
        if (cmd !== 1) return 'unsupported command: ' + cmd;
        
        const portIndex = cmdIndex + 1;
        // [Optimization] 使用 DataView 读取端口
        const view = new DataView(cache.buffer, cache.byteOffset, cache.byteLength);
        const port = view.getUint16(portIndex, false); // Big-Endian
        
        const atype = cache[portIndex + 2];
        const addr_body_idx = portIndex + 3; // 指向地址具体内容的开始

        let header_len = -1;
        
        if (atype === CONSTANTS.ADDRESS_TYPE_IPV4) {
            header_len = addr_body_idx + 4;
        } else if (atype === CONSTANTS.ADDRESS_TYPE_IPV6) {
            header_len = addr_body_idx + 16;
        } else if (atype === CONSTANTS.ADDRESS_TYPE_URL) {
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
        
        if (cache.length < header_len) {
            const r = await read_at_least(reader, header_len, cache);
            cache = r.value;
            if (cache.length < header_len) return 'header too short for full address';
        }
        
        // 解析地址
        let hostname = '';
        const addr_val_idx = addr_body_idx; 
        
        try {
            switch (atype) {
                case CONSTANTS.ADDRESS_TYPE_IPV4:
                    // [Optimization] 使用 join
                    hostname = cache.subarray(addr_val_idx, addr_val_idx + 4).join('.');
                    break;
                case CONSTANTS.ADDRESS_TYPE_URL:
                    const domain_len = cache[addr_val_idx];
                    hostname = textDecoder.decode(
                        cache.subarray(addr_val_idx + 1, addr_val_idx + 1 + domain_len)
                    );
                    break;
                case CONSTANTS.ADDRESS_TYPE_IPV6:
                    // [Optimization] 使用高效循环 + DataView (仿照 VLESS)
                    const ipv6 = [];
                    // 复用 view (注意偏移量需要累加)
                    for (let i = 0; i < 8; i++) {
                        ipv6.push(view.getUint16(addr_val_idx + i * 2, false).toString(16));
                    }
                    hostname = ipv6.join(':');
                    break;
            }
        } catch (e) {
            return 'failed to parse hostname: ' + e.message;
        }
        
        if (!hostname) return 'failed to parse hostname';
        
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
