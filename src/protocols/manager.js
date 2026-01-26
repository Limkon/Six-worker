/**
 * 文件名: src/protocols/manager.js
 * 修复说明:
 * 1. [Fix] 修复 detect 方法中 credentials 的传递逻辑，确保 Trojan 和 Mandala 能收到密码。
 * 2. [Feature] 支持多用户 ID 匹配 (VLESS/Shadowsocks)。
 */
export class ProtocolManager {
    constructor() { 
        this.handlers = []; 
    }
    
    register(name, validator) { 
        this.handlers.push({ name, validator }); 
        return this; 
    }
    
    async detect(chunk, context) {
        // 准备凭据
        const vlessIds = [context.userID];
        if (context.userIDLow) vlessIds.push(context.userIDLow);
        
        // Trojan 和 Mandala 通常使用 UUID 作为密码
        const password = context.userID; 

        for (const handler of this.handlers) {
            try {
                let result = null;
                
                // 根据协议类型分发不同的凭据
                if (handler.name === 'vless') {
                    // VLESS 需要 ID 列表
                    result = await handler.validator(chunk, vlessIds);
                } else if (handler.name === 'trojan') {
                    // Trojan 需要单个密码 (或尝试主密码)
                    result = await handler.validator(chunk, password);
                    // 如果主密码失败且有副 ID，尝试副 ID (兼容性)
                    if (result.hasError && context.userIDLow) {
                        const resLow = await handler.validator(chunk, context.userIDLow);
                        if (!resLow.hasError) result = resLow;
                    }
                } else if (handler.name === 'mandala') {
                    // Mandala 使用密码进行 Hash 校验
                    result = await handler.validator(chunk, password);
                } else if (handler.name === 'ss') {
                    // SS 需要 ID 列表 (用于多用户支持)
                    result = await handler.validator(chunk, context.userID, vlessIds);
                } else if (handler.name === 'socks5') {
                    // SOCKS5 无需密码 (握手阶段已完成鉴权)
                    result = await handler.validator(chunk);
                } else {
                    // 默认传递整个 context
                    result = await handler.validator(chunk, context);
                }
                
                if (result && !result.hasError) {
                    return { ...result, protocol: handler.name };
                }
            } catch (e) {
                // 忽略解析错误，继续尝试下一个协议
            }
        }
        throw new Error('Protocol detection failed.');
    }
}
