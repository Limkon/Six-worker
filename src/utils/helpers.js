/**
 * 文件名: src/utils/helpers.js
 * 优化说明:
 * 1. [Performance] 优化 isHostBanned，增加对纯域名匹配的快速路径，减少正则编译开销。
 * 2. [Stability] 保持 sha224Hash、UUID 生成等核心工具函数的稳定性。
 */
import { CONSTANTS } from '../constants.js';

export const textDecoder = new TextDecoder();
export const textEncoder = new TextEncoder();

// --- UUID Regex (静态资源) ---
const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_SIMPLE_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isStrictV4UUID(uuid) {
    return UUID_V4_REGEX.test(uuid);
}

export function isValidUUID(uuid) {
    return isStrictV4UUID(uuid) || UUID_SIMPLE_REGEX.test(uuid);
}

export async function sha1(str) {
    const buffer = textEncoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- SHA224 静态资源 (一次初始化) ---
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

const sha224RotateRight = (value, shift) => {
    return ((value >>> shift) | (value << (32 - shift))) >>> 0;
};

// 保留原有的 unescape hack 以支持二进制字符串操作，保持核心算法一致性
const sha224ToUtf8 = (str) => { return unescape(encodeURIComponent(str)) };

const sha224BytesToHex = (byteArray) => {
    let hexString = '';
    for (let i = 0; i < byteArray.length; i++) {
        hexString += ((byteArray[i] >>> 4) & 0x0F).toString(16);
        hexString += (byteArray[i] & 0x0F).toString(16);
    }
    return hexString;
};

const computeSha224Core = (inputStr) => {
    // SHA-224 初始哈希值
    let hState = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
    
    const messageBitLength = inputStr.length * 8;
    inputStr += String.fromCharCode(0x80);
    while ((inputStr.length * 8) % 512 !== 448) { inputStr += String.fromCharCode(0) }
    
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

    // 优化：将 w 数组分配移出循环，避免重复分配内存
    const w = new Array(64);

    for (let i = 0; i < words.length; i += 16) {
        for (let j = 0; j < 16; j++) {
            w[j] = words[i + j];
        }
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

            h = g;
            g = f;
            f = e;
            e = (d + temp1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) >>> 0;
        }

        hState[0] = (hState[0] + a) >>> 0;
        hState[1] = (hState[1] + b) >>> 0;
        hState[2] = (hState[2] + c) >>> 0;
        hState[3] = (hState[3] + d) >>> 0;
        hState[4] = (hState[4] + e) >>> 0;
        hState[5] = (hState[5] + f) >>> 0;
        hState[6] = (hState[6] + g) >>> 0;
        hState[7] = (hState[7] + h) >>> 0;
    }
    return hState.slice(0, 7);
};

export function sha224Hash(message) {
    const utf8Message = sha224ToUtf8(message);
    const hashWords = computeSha224Core(utf8Message);
    return sha224BytesToHex(hashWords.flatMap(h => [(h >>> 24) & 0xFF, (h >>> 16) & 0xFF, (h >>> 8) & 0xFF, h & 0xFF]));
}

export function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { earlyData: undefined, error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        // 修复：自动补全 Base64 填充字符 '='
        while (base64Str.length % 4) {
            base64Str += '=';
        }
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: undefined, error };
    }
}

export async function cleanList(content) {
    if (!content) return [];
    let replaced = content.replace(/[\t"'\r\n]+/g, ',').replace(/,+/g, ',');
    if (replaced.startsWith(',')) replaced = replaced.slice(1);
    if (replaced.endsWith(',')) replaced = replaced.slice(0, -1);
    return replaced.split(',').filter(Boolean);
}

export function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === 1 || socket.readyState === 2) {
            socket.close();
        }
    } catch (error) {
        console.error('safeCloseWebSocket error', error);
    }
}

// ByteToHex 查找表 (模块级单例)
const byteToHex = Array.from({ length: 256 }, (v, i) => (i + 256).toString(16).slice(1));

export function stringifyUUID(arr, offset = 0) {
    const uuid = (byteToHex[arr[offset+0]]+byteToHex[arr[offset+1]]+byteToHex[arr[offset+2]]+byteToHex[arr[offset+3]]+"-"+byteToHex[arr[offset+4]]+byteToHex[arr[offset+5]]+"-"+byteToHex[arr[offset+6]]+byteToHex[arr[offset+7]]+"-"+byteToHex[arr[offset+8]]+byteToHex[arr[offset+9]]+"-"+byteToHex[arr[offset+10]]+byteToHex[arr[offset+11]]+byteToHex[arr[offset+12]]+byteToHex[arr[offset+13]]+byteToHex[arr[offset+14]]+byteToHex[arr[offset+15]]).toLowerCase();
    if (!isValidUUID(uuid)) {
        throw TypeError("Invalid stringified UUID");
    }
    return uuid;
}

export async function generateDynamicUUID(key, timeDays, updateHour) {
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
    return [current, prev];
}

export function isHostBanned(hostname, banList) {
    if (!banList || banList.length === 0) return false;
    return banList.some(pattern => {
        // [优化] 快速路径：如果规则不含通配符，直接进行字符串比较，避免 new RegExp 开销
        if (!pattern.includes('*')) {
            return hostname.toLowerCase() === pattern.toLowerCase();
        }
        let regexPattern = pattern.replace(/\*/g, '.*');
        let regex = new RegExp(`^${regexPattern}$`, 'i');
        return regex.test(hostname);
    });
}
