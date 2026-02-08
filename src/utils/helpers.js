// src/utils/helpers.js
/**
 * 文件名: src/utils/helpers.js
 * 状态: [Refactored & Optimized]
 * 1. [Optimization] generateDynamicUUID: 增加内存缓存，避免重复计算 SHA-256。
 * 2. [Critical] 包含 REGEX_CACHE，确保 isHostBanned 高效运行。
 * 3. [Full] 包含所有核心工具函数。
 */

// 全局编解码器实例
export const textDecoder = new TextDecoder();
export const textEncoder = new TextEncoder();

// --- UUID Regex ---
const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_SIMPLE_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isStrictV4UUID(uuid) { return UUID_V4_REGEX.test(uuid); }
export function isValidUUID(uuid) { return isStrictV4UUID(uuid) || UUID_SIMPLE_REGEX.test(uuid); }

export async function sha1(str) {
    const buffer = textEncoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- SHA224 静态资源 (保持原样) ---
const SHA224_CONSTANTS = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

const sha224RotateRight = (value, shift) => ((value >>> shift) | (value << (32 - shift))) >>> 0;
const sha224ToUtf8 = (str) => unescape(encodeURIComponent(str));
const sha224BytesToHex = (byteArray) => {
    let hexString = '';
    for (let i = 0; i < byteArray.length; i++) {
        hexString += ((byteArray[i] >>> 4) & 0x0F).toString(16);
        hexString += (byteArray[i] & 0x0F).toString(16);
    }
    return hexString;
};

const computeSha224Core = (inputStr) => {
    let hState = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
    const messageBitLength = inputStr.length * 8;
    inputStr += String.fromCharCode(0x80);
    const currentLen = inputStr.length;
    const padLen = (56 - (currentLen % 64) + 64) % 64;
    if (padLen > 0) inputStr += String.fromCharCode(0).repeat(padLen);
    
    const highBits = Math.floor(messageBitLength / 0x100000000);
    const lowBits = messageBitLength & 0xFFFFFFFF;
    inputStr += String.fromCharCode(
        (highBits >>> 24) & 0xFF, (highBits >>> 16) & 0xFF, (highBits >>> 8) & 0xFF, highBits & 0xFF,
        (lowBits >>> 24) & 0xFF, (lowBits >>> 16) & 0xFF, (lowBits >>> 8) & 0xFF, lowBits & 0xFF
    );
    const words = [];
    for (let i = 0; i < inputStr.length; i += 4) {
        words.push((inputStr.charCodeAt(i) << 24) | (inputStr.charCodeAt(i + 1) << 16) | (inputStr.charCodeAt(i + 2) << 8) | inputStr.charCodeAt(i + 3));
    }
    const w = new Array(64);
    for (let i = 0; i < words.length; i += 16) {
        for (let j = 0; j < 16; j++) w[j] = words[i + j];
        for (let j = 16; j < 64; j++) {
            const s0 = sha224RotateRight(w[j - 15], 7) ^ sha224RotateRight(w[j - 15], 18) ^ (w[j - 15] >>> 3);
            const s1 = sha224RotateRight(w[j - 2], 17) ^ sha224RotateRight(w[j - 2], 19) ^ (w[j - 2] >>> 10);
            w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
        }
        let [a, b, c, d, e, f, g, h] = hState;
        for (let j = 0; j < 64; j++) {
            const S1 = sha224RotateRight(e, 6) ^ sha224RotateRight(e, 11) ^ sha224RotateRight(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (h + S1 + ch + SHA224_CONSTANTS[j] + w[j]) >>> 0;
            const S0 = sha224RotateRight(a, 2) ^ sha224RotateRight(a, 13) ^ sha224RotateRight(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;
            h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
        }
        hState[0] = (hState[0] + a) >>> 0; hState[1] = (hState[1] + b) >>> 0; hState[2] = (hState[2] + c) >>> 0; hState[3] = (hState[3] + d) >>> 0;
        hState[4] = (hState[4] + e) >>> 0; hState[5] = (hState[5] + f) >>> 0; hState[6] = (hState[6] + g) >>> 0; hState[7] = (hState[7] + h) >>> 0;
    }
    return hState.slice(0, 7);
};

const globalSha224Cache = new Map();
const MAX_SHA224_CACHE_SIZE = 50; 
export function sha224Hash(message) {
    if (globalSha224Cache.has(message)) return globalSha224Cache.get(message);
    const utf8Message = sha224ToUtf8(message);
    const hashWords = computeSha224Core(utf8Message);
    const resultHex = sha224BytesToHex(hashWords.flatMap(h => [(h >>> 24) & 0xFF, (h >>> 16) & 0xFF, (h >>> 8) & 0xFF, h & 0xFF]));
    if (globalSha224Cache.size >= MAX_SHA224_CACHE_SIZE) globalSha224Cache.delete(globalSha224Cache.keys().next().value);
    globalSha224Cache.set(message, resultHex);
    return resultHex;
}

export function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: undefined, error: null };
    try {
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const padLen = (4 - (base64Str.length % 4)) % 4;
        if (padLen > 0) base64Str = base64Str.padEnd(base64Str.length + padLen, '=');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) { return { earlyData: undefined, error }; }
}

export async function cleanList(content) {
    if (!content) return [];
    return content.split(/[\t"'\r\n,]+/).filter(Boolean);
}

export function safeCloseWebSocket(socket) {
    try { if (socket.readyState === 1 || socket.readyState === 2) socket.close(); } catch (error) { console.error('safeCloseWebSocket error', error); }
}

const byteToHex = Array.from({ length: 256 }, (v, i) => (i + 256).toString(16).slice(1));
export function stringifyUUID(arr, offset = 0) {
    const uuid = (byteToHex[arr[offset+0]]+byteToHex[arr[offset+1]]+byteToHex[arr[offset+2]]+byteToHex[arr[offset+3]]+"-"+byteToHex[arr[offset+4]]+byteToHex[arr[offset+5]]+"-"+byteToHex[arr[offset+6]]+byteToHex[arr[offset+7]]+"-"+byteToHex[arr[offset+8]]+byteToHex[arr[offset+9]]+"-"+byteToHex[arr[offset+10]]+byteToHex[arr[offset+11]]+byteToHex[arr[offset+12]]+byteToHex[arr[offset+13]]+byteToHex[arr[offset+14]]+byteToHex[arr[offset+15]]).toLowerCase();
    if (!isValidUUID(uuid)) throw TypeError("Invalid stringified UUID");
    return uuid;
}

// [Optimization] UUID 缓存：避免高频计算
const DYNAMIC_UUID_CACHE = new Map();

export async function generateDynamicUUID(key, timeDays, updateHour) {
    // 构建缓存 Key
    const cacheKey = `${key}-${timeDays}-${updateHour}`;
    if (DYNAMIC_UUID_CACHE.has(cacheKey)) {
        return DYNAMIC_UUID_CACHE.get(cacheKey);
    }

    const timezoneOffset = 8;
    const startDate = new Date(2007, 6, 7, updateHour, 0, 0);
    const oneWeekMs = 1000 * 60 * 60 * 24 * timeDays;
    
    function getCurrentCycle() {
        const now = new Date();
        const adjustedNow = new Date(now.getTime() + timezoneOffset * 60 * 60 * 1000);
        const timeDiff = Number(adjustedNow) - Number(startDate);
        return Math.ceil(timeDiff / oneWeekMs);
    }
    
    async function generate(baseStr) {
        const hashBuffer = new TextEncoder().encode(baseStr);
        const hash = await crypto.subtle.digest('SHA-256', hashBuffer);
        const hashArr = Array.from(new Uint8Array(hash));
        const hex = hashArr.map(b => b.toString(16).padStart(2, '0')).join('');
        return `${hex.substr(0, 8)}-${hex.substr(8, 4)}-4${hex.substr(13, 3)}-${(parseInt(hex.substr(16, 2), 16) & 0x3f | 0x80).toString(16)}${hex.substr(18, 2)}-${hex.substr(20, 12)}`;
    }
    
    const currentCycle = getCurrentCycle();
    const current = await generate(key + currentCycle);
    const prev = await generate(key + (currentCycle - 1));
    
    const result = [current, prev];
    
    // 写入缓存 (简单的 LRU 或定时清理机制可以视情况增加，但此处 Key 变化极慢，无需复杂清理)
    if (DYNAMIC_UUID_CACHE.size > 100) DYNAMIC_UUID_CACHE.clear(); // 简单防护
    DYNAMIC_UUID_CACHE.set(cacheKey, result);
    
    return result;
}

// [Optimization] Host 正则缓存 (REGEX_CACHE)
const REGEX_CACHE = new Map();

export function isHostBanned(hostname, banList) {
    if (!banList || banList.length === 0) return false;
    return banList.some(pattern => {
        let regex;
        if (REGEX_CACHE.has(pattern)) {
            regex = REGEX_CACHE.get(pattern);
        } else {
            try {
                let regexPattern = pattern.replace(/\*/g, '.*');
                regex = new RegExp(`^${regexPattern}$`, 'i');
            } catch (e) {
                regex = /^$/;
            }
            if (REGEX_CACHE.size > 500) REGEX_CACHE.delete(REGEX_CACHE.keys().next().value);
            REGEX_CACHE.set(pattern, regex);
        }
        return regex.test(hostname);
    });
}

// --- KV Cache & StreamCipher (保持原样) ---
const GLOBAL_KV_CACHE = new Map();
const MAX_KV_CACHE_SIZE = 200; 
const CACHE_API_PREFIX = 'http://kv-cache.local/';
const CACHE_NULL_SENTINEL = "##NULL##"; 
const KNOWN_KV_KEYS = ['UUID', 'KEY', 'ADMIN_PASS', 'SUPER_PASSWORD', 'PROXYIP', 'SOCKS5', 'GO2SOCKS5', 'DNS64', 'BAN', 'DIS', 'TIME', 'UPTIME', 'SUBNAME', 'ADD.txt', 'ADDAPI', 'ADDNOTLS', 'ADDNOTLSAPI', 'ADDCSV', 'CFPORTS', 'BESTIP_SOURCES', 'REMOTE_CONFIG', 'REMOTE_CONFIG_URL', 'URL', 'URL302', 'SAVED_DOMAIN'];

export async function getKV(env, key) {
    if (!env.KV || !key) return null;
    if (GLOBAL_KV_CACHE.has(key)) return GLOBAL_KV_CACHE.get(key);
    const cache = caches.default;
    const cacheKeyUrl = CACHE_API_PREFIX + encodeURIComponent(key);
    try {
        const match = await cache.match(cacheKeyUrl);
        if (match) {
            const val = await match.text();
            if (val === CACHE_NULL_SENTINEL) { GLOBAL_KV_CACHE.set(key, null); return null; }
            if (GLOBAL_KV_CACHE.size >= MAX_KV_CACHE_SIZE) GLOBAL_KV_CACHE.clear();
            GLOBAL_KV_CACHE.set(key, val);
            return val;
        }
    } catch (e) { console.error(`[KV] Cache API error for ${key}:`, e); }
    let val = null;
    try { val = await env.KV.get(key); } catch (e) { console.error(`[KV] Real KV get failed:`, e); }
    if (GLOBAL_KV_CACHE.size >= MAX_KV_CACHE_SIZE) GLOBAL_KV_CACHE.clear();
    GLOBAL_KV_CACHE.set(key, val);
    const cacheVal = val === null ? CACHE_NULL_SENTINEL : val;
    try { cache.put(cacheKeyUrl, new Response(cacheVal, { headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'max-age=2592000' } })).catch(() => {}); } catch (e) {}
    return val;
}

export async function clearKVCache(keys) {
    const cache = caches.default;
    const targetKeys = keys && Array.isArray(keys) ? keys : KNOWN_KV_KEYS;
    if (keys) keys.forEach(k => GLOBAL_KV_CACHE.delete(k)); else GLOBAL_KV_CACHE.clear();
    await Promise.all(targetKeys.map(key => cache.delete(CACHE_API_PREFIX + encodeURIComponent(key)).catch(() => {})));
    console.log(`[KV] Cache flushed for keys: ${targetKeys.join(', ')}`);
}

function fmix32(h) {
    h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
    return h >>> 0;
}

export class StreamCipher {
    constructor(keyBytes, saltBytes) {
        let s1 = 0, s2 = 0, s3 = 0, s4 = 0;
        for (let i = 0; i < keyBytes.length; i++) s1 = (Math.imul(s1, 31) + keyBytes[i]) | 0;
        for (let i = 0; i < saltBytes.length; i++) s2 = (Math.imul(s2, 31) + saltBytes[i]) | 0;
        s3 = fmix32(s1 ^ 0x12345678); s4 = fmix32(s2 ^ 0x87654321); s1 = fmix32(s1); s2 = fmix32(s2);
        this.s = new Uint32Array([s1, s2, s3, s4]);
    }
    next() {
        let t = this.s[3]; let s = this.s[0]; this.s[3] = this.s[2]; this.s[2] = this.s[1]; this.s[1] = s;
        t ^= t << 11; t ^= t >>> 8; this.s[0] = t ^ s ^ (s >>> 19); return this.s[0];
    }
    process(buffer) {
        let i = 0; const len = buffer.length;
        if (buffer.byteOffset % 4 === 0 && len >= 4) {
            const len32 = Math.floor(len / 4); const view32 = new Uint32Array(buffer.buffer, buffer.byteOffset, len32);
            for (let j = 0; j < len32; j++) view32[j] ^= this.next();
            i = len32 * 4;
        }
        let randomCache = 0; let cacheRemaining = 0;
        for (; i < len; i++) {
            if (cacheRemaining === 0) { randomCache = this.next(); cacheRemaining = 4; }
            buffer[i] ^= (randomCache & 0xFF); randomCache >>>= 8; cacheRemaining--;
        }
    }
}
