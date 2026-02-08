// src/handlers/xhttp.js
/**
 * 文件名: src/handlers/xhttp.js
 * 状态: [最终完整修复版]
 * 1. [Fix] DataView 安全性修复: 移除长生命周期的 view 变量，采用即用即弃策略，
 * 彻底防止因 buffer 扩容/重分配导致的引用失效问题。
 * 2. [Full] 包含所有原版核心逻辑 (UUID校验, 协议解析, 超时控制)。
 * 3. [Security] 集成 isHostBanned 黑名单拦截。
 * 4. [Elegant] 使用 safe_read/safe_cancel 消除 "Stream was cancelled" 报错。
 */
import { CONSTANTS } from '../constants.js';
import { createUnifiedConnection } from './outbound.js';
import { isHostBanned, stringifyUUID, textDecoder } from '../utils/helpers.js';

// --- 工具函数区 ---

/**
 * 优雅地取消流，忽略任何因流已关闭导致的错误
 */
async function safe_cancel(reader, reason) {
    if (!reader) return;
    try {
        await reader.cancel(reason);
    } catch (_) {
        // 忽略所有取消时的错误，因为我们的目标就是关闭它
    }
}

/**
 * 安全读取函数：封装了超时和异常处理
 * 如果流被取消、中断或超时，返回 { done: true, error: Error? }
 */
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
        return result; // { value, done }

    } catch (e) {
        // 核心优化：将"Stream cancelled"等非致命网络错误视为读取结束
        const msg = (e.message || '').toLowerCase();
        if (msg.includes('cancelled') || msg.includes('aborted') || msg.includes('closed')) {
            return { done: true };
        }
        // 其他真正的逻辑错误抛出
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
        
        if (error) throw error; // 抛出超时错误
        if (done) break;        // 流正常结束或被中断，退出循环

        if (value && value.byteLength > 0) {
            chunks.push(value);
            totalLength += value.byteLength;
        }
    }

    // Zero/One Copy 优化
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
    const deadline = Date.now() + 3000; // 3秒超时

    try {
        // 1. 读取基础头部 (18字节: 1B版本 + 16B UUID + 1B MetadataLen)
        let { value: cache, done } = await read_at_least(reader, 18, null, deadline);
        if (cache.length < 18) throw new Error('header too short');

        const version = cache[0];
        const uuidStr = stringifyUUID(cache.subarray(1, 17));
        
        // 校验 UUID (支持 userID 和 userIDLow)
        const expectedID = ctx.userID;
        const expectedIDLow = ctx.userIDLow;
        if (uuidStr !== expectedID && (!expectedIDLow || uuidStr !== expectedIDLow)) {
            throw new Error('invalid UUID');
        }
        
        // 2. 读取元数据长度
        const pb_len = cache[17];
        const min_len_until_atyp = 22 + pb_len; // 18 + pb_len + 1(cmd) + 2(port) + 1(atype)
        
        if (cache.length < min_len_until_atyp) {
            const r = await read_at_least(reader, min_len_until_atyp, cache, deadline);
            cache = r.value;
            if (cache.length < min_len_until_atyp) throw new Error('header too short for metadata');
        }

        // 3. 解析命令
        const cmdIndex = 18 + pb_len;
        if (cache[cmdIndex] !== 1) throw new Error('unsupported command: ' + cache[cmdIndex]);
        
        const portIndex = cmdIndex + 1;
        
        // [Fix] DataView Safety: 
        // 临时创建 DataView 读取端口，不保存 view 引用，防止后续 read_at_least 更新 cache 导致 view 失效。
        const port = new DataView(cache.buffer, cache.byteOffset, cache.byteLength).getUint16(portIndex, false);
        
        const atype = cache[portIndex + 2];
        const addr_body_idx = portIndex + 3; 

        // 4. 计算完整头部长度
        let header_len = -1;
        if (atype === CONSTANTS.ADDRESS_TYPE_IPV4) {
            header_len = addr_body_idx + 4;
        } else if (atype === CONSTANTS.ADDRESS_TYPE_IPV6) {
            header_len = addr_body_idx + 16;
        } else if (atype === CONSTANTS.ADDRESS_TYPE_URL) {
            // 需要读取域名长度
            if (cache.length < addr_body_idx + 1) {
                 const r = await read_at_least(reader, addr_body_idx + 1, cache, deadline);
                 cache = r.value;
                 if (cache.length < addr_body_idx + 1) throw new Error('header too short for domain len');
            }
            header_len = addr_body_idx + 1 + cache[addr_body_idx];
        } else {
            throw new Error('unknown address type: ' + atype);
        }
        
        // 5. 读取完整头部
        if (cache.length < header_len) {
            const r = await read_at_least(reader, header_len, cache, deadline);
            cache = r.value;
            if (cache.length < header_len) throw new Error('header too short for full address');
        }
        
        // 6. 解析 Hostname
        let hostname = '';
        const addr_val_idx = addr_body_idx; 
        try {
            if (atype === CONSTANTS.ADDRESS_TYPE_IPV4) {
                hostname = cache.subarray(addr_val_idx, addr_val_idx + 4).join('.');
            } else if (atype === CONSTANTS.ADDRESS_TYPE_URL) {
                const domain_len = cache[addr_val_idx];
                hostname = textDecoder.decode(cache.subarray(addr_val_idx + 1, addr_val_idx + 1 + domain_len));
            } else if (atype === CONSTANTS.ADDRESS_TYPE_IPV6) {
                // [Fix] 再次创建新的 DataView，确保基于最新的 cache 内存地址
                const view = new DataView(cache.buffer, cache.byteOffset, cache.byteLength);
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
        // 统一在最外层释放 Reader
        await safe_cancel(reader, error.message);
        throw error;
    }
}

async function upload_to_remote_xhttp(writer, { data, done, reader }) {
    // 写入头部携带的剩余数据
    if (data && data.length > 0) {
        await writer.write(data);
    }
    if (done) return;

    // 循环写入 Body
    while (true) {
        try {
            // reader 已在 read_xhttp_header 中被获取，这里继续使用
            const { value, done: readDone } = await reader.read();
            if (readDone) break;
            if (value) await writer.write(value);
        } catch (e) {
            // 读取流出错（如下游断开），停止写入，跳出循环
            break; 
        }
    }
}

// 创建带空闲超时监控的下载流
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
                    // [Restored] 强制清理逻辑：显式 abort 写入端以关闭上游连接
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

    // 管道连接，并在发生错误时自动处理
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

export async function handleXhttpClient(request, ctx) {
    // 1. 读取并解析头部
    let result;
    try {
        result = await read_xhttp_header(request.body, ctx);
    } catch (e) {
        // 此时 reader 已经在 read_xhttp_header 内部被安全 cancel 了
        const errStr = e.message || '';
        // [Restored] 恢复日志记录，但过滤掉预期的短连接错误
        if (!errStr.includes('header too short') && !errStr.includes('invalid UUID')) {
             console.warn('[XHTTP Handshake Error]:', errStr);
        }
        return null; // 握手失败
    }

    const { hostname, port, atype, data, resp, reader, done } = result;

    // 2. 检查黑名单
    // [Fix] 增加 isHostBanned 拦截
    if (isHostBanned(hostname, ctx.banHosts)) {
        console.log('[XHTTP] Blocked:', hostname);
        await safe_cancel(reader, 'blocked');
        return null;
    }

    // 3. 建立远程连接
    let remoteSocket;
    try {
        remoteSocket = await createUnifiedConnection(ctx, hostname, port, atype, console.log, ctx.proxyIP);
    } catch (e) {
        console.error('[XHTTP] Connect Failed:', e.message);
        await safe_cancel(reader, 'connect failed');
        return null;
    }

    // 4. 双向流处理 (Uploader & Downloader)
    
    // 上行: Request Body -> Remote Socket
    const uploaderPromise = (async () => {
        let writer = null;
        try {
            writer = remoteSocket.writable.getWriter();
            await upload_to_remote_xhttp(writer, { data, done, reader });
        } catch (e) {
            // 忽略写入错误
        } finally {
            if (writer) try { await writer.close(); } catch (_) {}
            await safe_cancel(reader, 'upload finished'); 
        }
    })();

    // 下行: Remote Socket -> Response Body
    const downloader = create_xhttp_downloader(resp, remoteSocket.readable, remoteSocket.initialData);

    // 5. 生命周期绑定
    // 使用 Promise.allSettled 确保 connectionClosed 永远 Resolve
    const connectionClosed = Promise.allSettled([downloader.done, uploaderPromise]).then(() => {
        try { remoteSocket.close(); } catch (_) {}
        downloader.abort();
    });

    return {
        readable: downloader.readable,
        closed: connectionClosed 
    };
}
