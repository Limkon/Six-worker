export class ProtocolManager {
    constructor() { 
        this.handlers = []; 
    }
    
    register(name, validator) { 
        this.handlers.push({ name, validator }); 
        return this; 
    }
    
    // 检测数据包协议
    async detect(chunk, context) {
        // VLESS 需要验证 UUID 列表 (当前和上一个周期)
        const vlessIds = [context.userID];
        if (context.userIDLow) vlessIds.push(context.userIDLow);
        
        // Trojan/SS 使用 dynamicUUID (即原始 Key 或 Password)
        const password = context.dynamicUUID;

        for (const handler of this.handlers) {
            try {
                // [完全还原原始逻辑]
                // 只有 vless 传数组，trojan 传密码，其他(socks5/ss) 传 null
                // 这样 Socks5 也就不会收到错误的 offset 参数
                const credentials = (handler.name === 'vless') ? vlessIds : ((handler.name === 'trojan') ? password : null);

                const result = await handler.validator(chunk, credentials);
                
                if (!result.hasError) {
                    return { ...result, protocol: handler.name };
                }
            } catch (e) {
                // 忽略错误，继续尝试下一个协议
            }
        }
        throw new Error('Protocol detection failed.');
    }
}
