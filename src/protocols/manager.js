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
                let credentials = null;
                if (handler.name === 'vless') {
                    credentials = vlessIds;
                } else if (handler.name === 'trojan' || handler.name === 'mandala' || handler.name === 'ss') { 
                    // [Critical Fix] 必须在这里加上 || handler.name === 'ss'
                    // 否则 Shadowsocks 拿不到密码，必然验证失败
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
