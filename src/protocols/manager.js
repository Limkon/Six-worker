/**
 * 文件名: src/protocols/manager.js
 * 说明: 简单的协议探测管理器，用于 websocket.js 分流
 */
export class ProtocolManager {
    constructor() {
        this.protocols = [];
    }

    register(name, parser) {
        this.protocols.push({ name, parser });
        return this;
    }

    async detect(buffer, ctx) {
        for (const { name, parser } of this.protocols) {
            // 传入 buffer 和 ctx (包含 userID, expectedUserIDs 等)
            // parser 需要返回 { hasError: boolean, ...metadata }
            let result = null;
            try {
                // 如果是 SOCKS5，parser 可能只需要 buffer，但为了统一，我们传入 ctx
                // 注意：vless/trojan 等 parser 参数签名可能不同，这里做一个适配调用
                if (name === 'vless') {
                    result = await parser(buffer, ctx.expectedUserIDs);
                } else if (name === 'trojan') {
                    result = await parser(buffer, ctx.userID);
                    if (result.hasError && ctx.userIDLow) {
                         const resLow = await parser(buffer, ctx.userIDLow);
                         if (!resLow.hasError) result = resLow;
                    }
                } else if (name === 'ss') {
                    result = await parser(buffer, ctx.userID, ctx.expectedUserIDs);
                } else if (name === 'socks5') {
                    // SOCKS5 Request 阶段通常不需要密码（握手阶段已验证），或者是无密码模式
                    result = await parser(buffer); 
                } else if (name === 'mandala') {
                    result = await parser(buffer, ctx.expectedUserIDs);
                } else {
                    result = await parser(buffer, ctx);
                }
            } catch (e) {
                // 解析器抛错视为不匹配
                continue;
            }

            if (result && !result.hasError) {
                return { protocol: name, ...result };
            }
        }
        throw new Error('Unknown protocol');
    }
}
