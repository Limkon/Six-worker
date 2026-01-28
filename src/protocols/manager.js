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
        const vlessIds = [context.userID];
        if (context.userIDLow) vlessIds.push(context.userIDLow);
        const password = context.dynamicUUID;

        for (const handler of this.handlers) {
            try {
                // [修改部分] 增加 ss 的凭据分发逻辑
                let credentials = null;
                if (handler.name === 'vless') {
                    credentials = vlessIds;
                } else if (handler.name === 'trojan' || handler.name === 'mandala' || handler.name === 'ss') { // <--- [Fix] 增加 ss
                    credentials = password;
                }

                // 调用验证器 (chunk, password)
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
