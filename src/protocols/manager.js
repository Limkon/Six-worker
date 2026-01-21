// src/protocols/manager.js
export class ProtocolManager {
    constructor() { 
        this.handlers = []; 
    }
    
    register(name, validator) { 
        this.handlers.push({ name, validator }); 
        return this; 
    }
    
    async detect(chunk, context) {
        // [Bug修复] 使用 config.js 中预处理好的 expectedUserIDs (全小写)
        // 修复了当环境变量 UUID 含大写字母时，因 VLESS 协议解析强制小写导致鉴权失败的问题
        const vlessIds = context.expectedUserIDs || [context.userID]; 
        
        // 注意：userIDLow 已经包含在 expectedUserIDs 中了，不需要重复添加
        // 但为了保持对旧逻辑的防御性兼容，如果 expectedUserIDs 不存在则回退
        if (!context.expectedUserIDs && context.userIDLow) {
            vlessIds.push(context.userIDLow);
        }

        const password = context.dynamicUUID;

        for (const handler of this.handlers) {
            try {
                let credentials = null;
                if (handler.name === 'vless') {
                    credentials = vlessIds;
                } else if (handler.name === 'trojan' || handler.name === 'mandala') {
                    credentials = password;
                }

                const result = await handler.validator(chunk, credentials);
                
                if (!result.hasError) {
                    return { ...result, protocol: handler.name };
                }
            } catch (e) {
                // ignore
            }
        }
        throw new Error('Protocol detection failed.');
    }
}
