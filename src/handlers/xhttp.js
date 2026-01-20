/**
 * 文件名: src/handlers/xhttp.js
 * 修复说明:
 * 1. [性能] 移除了 create_xhttp_downloader 和 upload_to_remote_xhttp 中的 setTimeout(r, 0) 节流逻辑。
 * 该逻辑会严重限制大带宽下的吞吐量。
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
        const id = cache.slice(1, 1 + 16);
        
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
                hostname = cache.slice(idx, idx + 4).join('.');
                break;
            case CONSTANTS.ADDRESS_TYPE_URL:
                hostname = new TextDecoder().decode(
                    cache.slice(idx + 1, idx + 1 + cache[idx]),
                );
                break;
            case CONSTANTS.ADDRESS_TYPE_IPV6:
                hostname = cache
                    .slice(idx, idx + 16)
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
        
        const data = cache.slice(header_len);
        
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
        
        // [修复] 移除节流逻辑
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

function create_xhttp_downloader(resp, remote_readable) {
    const IDLE_TIMEOUT_MS = CONSTANTS.IDLE_TIMEOUT_MS || 45000;
    let stream;
    const done = new Promise((resolve, reject) => {
        stream = new TransformStream(
            {
                start(controller) {
                    controller.enqueue(resp);
                },
                transform(chunk, controller) {
                    controller.enqueue(chunk);
                },
                cancel(reason) {
                    reject(`download cancelled: ${reason}`);
                },
            },
            null,
            new ByteLengthQueuingStrategy({ highWaterMark: XHTTP_BUFFER_SIZE }),
        );
        let lastActivity = Date.now();
        const idleTimer = setInterval(() => {
            if (Date.now() - lastActivity > IDLE_TIMEOUT_MS) {
                try { stream.writable.abort?.('idle timeout'); } catch (_) {}
                clearInterval(idleTimer);
                reject('idle timeout');
            }
        }, 5000);
        
        const reader = remote_readable.getReader();
        const writer = stream.writable.getWriter();
        ;(async () => {
            try {
                // [修复] 移除节流逻辑
                while (true) {
                    const r = await reader.read();
                    if (r.done) break;
                    lastActivity = Date.now();
                    await writer.write(r.value);
                }
                await writer.close();
                resolve();
            } catch (err) {
                reject(err);
            } finally {
                try { reader.releaseLock(); } catch (_) {}
                try { writer.releaseLock(); } catch (_) {}
                clearInterval(idleTimer);
            }
        })();
    });
    return {
        readable: stream.readable,
        done,
        abort: () => {
            try { stream.readable.cancel(); } catch (_) {}
            try { stream.writable.abort(); } catch (_) {}
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

        const downloader = create_xhttp_downloader(resp, remoteSocket.readable);
        
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
