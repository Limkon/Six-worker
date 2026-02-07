var CONSTANTS = {
  SUPER_PASSWORD: "771571215.",
  DEFAULT_PROXY_IP: "xioo.mooo.com",
  SUB_HASH_LENGTH: 6,
  IDLE_TIMEOUT_MS: 45e3,
  MAX_CONCURRENT: 512,
  XHTTP_BUFFER_SIZE: 128 * 1024,
  ADDRESS_TYPE_IPV4: 1,
  ADDRESS_TYPE_URL: 2,
  ADDRESS_TYPE_IPV6: 3,
  ATYP_TROJAN_DOMAIN: 3,
  ATYP_TROJAN_IPV6: 4,
  ATYP_SS_IPV4: 1,
  ATYP_SS_DOMAIN: 3,
  ATYP_SS_IPV6: 4,
  SOCKS_VERSION: 5,
  SOCKS_CMD_CONNECT: 1,
  HTTP_PORTS: ["80", "8080", "8880", "2052", "2082", "2086", "2095"],
  HTTPS_PORTS: ["443", "8443", "2053", "2083", "2087", "2096"],
  DEFAULT_GO2SOCKS5: [
    "*ttvnw.net",
    "*tapecontent.net",
    "*cloudatacdn.com",
    "*.loadshare.org"
  ]
};

var textDecoder = new TextDecoder();
var textEncoder = new TextEncoder();
var UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
var UUID_SIMPLE_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isStrictV4UUID(uuid) {
  return UUID_V4_REGEX.test(uuid);
}
function isValidUUID(uuid) {
  return isStrictV4UUID(uuid) || UUID_SIMPLE_REGEX.test(uuid);
}
async function sha1(str) {
  const buffer = textEncoder.encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-1", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}
var SHA224_CONSTANTS = [
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
];
var sha224RotateRight = (value, shift) => {
  return (value >>> shift | value << 32 - shift) >>> 0;
};
var sha224ToUtf8 = (str) => {
  return unescape(encodeURIComponent(str));
};
var sha224BytesToHex = (byteArray) => {
  let hexString = "";
  for (let i = 0; i < byteArray.length; i++) {
    hexString += (byteArray[i] >>> 4 & 15).toString(16);
    hexString += (byteArray[i] & 15).toString(16);
  }
  return hexString;
};
var computeSha224Core = (inputStr) => {
  let hState = [3238371032, 914150663, 812702999, 4144912697, 4290775857, 1750603025, 1694076839, 3204075428];
  const messageBitLength = inputStr.length * 8;
  inputStr += String.fromCharCode(128);
  const currentLen = inputStr.length;
  const padLen = (56 - currentLen % 64 + 64) % 64;
  if (padLen > 0) {
    inputStr += String.fromCharCode(0).repeat(padLen);
  }
  const highBits = Math.floor(messageBitLength / 4294967296);
  const lowBits = messageBitLength & 4294967295;
  inputStr += String.fromCharCode(
    highBits >>> 24 & 255,
    highBits >>> 16 & 255,
    highBits >>> 8 & 255,
    highBits & 255,
    lowBits >>> 24 & 255,
    lowBits >>> 16 & 255,
    lowBits >>> 8 & 255,
    lowBits & 255
  );
  const words = [];
  for (let i = 0; i < inputStr.length; i += 4) {
    words.push(inputStr.charCodeAt(i) << 24 | inputStr.charCodeAt(i + 1) << 16 | inputStr.charCodeAt(i + 2) << 8 | inputStr.charCodeAt(i + 3));
  }
  const w = new Array(64);
  for (let i = 0; i < words.length; i += 16) {
    for (let j = 0; j < 16; j++) {
      w[j] = words[i + j];
    }
    for (let j = 16; j < 64; j++) {
      const s0 = sha224RotateRight(w[j - 15], 7) ^ sha224RotateRight(w[j - 15], 18) ^ w[j - 15] >>> 3;
      const s1 = sha224RotateRight(w[j - 2], 17) ^ sha224RotateRight(w[j - 2], 19) ^ w[j - 2] >>> 10;
      w[j] = w[j - 16] + s0 + w[j - 7] + s1 >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = hState;
    for (let j = 0; j < 64; j++) {
      const S1 = sha224RotateRight(e, 6) ^ sha224RotateRight(e, 11) ^ sha224RotateRight(e, 25);
      const ch = e & f ^ ~e & g;
      const temp1 = h + S1 + ch + SHA224_CONSTANTS[j] + w[j] >>> 0;
      const S0 = sha224RotateRight(a, 2) ^ sha224RotateRight(a, 13) ^ sha224RotateRight(a, 22);
      const maj = a & b ^ a & c ^ b & c;
      const temp2 = S0 + maj >>> 0;
      h = g;
      g = f;
      f = e;
      e = d + temp1 >>> 0;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2 >>> 0;
    }
    hState[0] = hState[0] + a >>> 0;
    hState[1] = hState[1] + b >>> 0;
    hState[2] = hState[2] + c >>> 0;
    hState[3] = hState[3] + d >>> 0;
    hState[4] = hState[4] + e >>> 0;
    hState[5] = hState[5] + f >>> 0;
    hState[6] = hState[6] + g >>> 0;
    hState[7] = hState[7] + h >>> 0;
  }
  return hState.slice(0, 7);
};
var globalSha224Cache =   new Map();
var MAX_SHA224_CACHE_SIZE = 50;
function sha224Hash(message) {
  if (globalSha224Cache.has(message)) {
    return globalSha224Cache.get(message);
  }
  const utf8Message = sha224ToUtf8(message);
  const hashWords = computeSha224Core(utf8Message);
  const resultHex = sha224BytesToHex(hashWords.flatMap((h) => [h >>> 24 & 255, h >>> 16 & 255, h >>> 8 & 255, h & 255]));
  if (globalSha224Cache.size >= MAX_SHA224_CACHE_SIZE) {
    const oldestKey = globalSha224Cache.keys().next().value;
    globalSha224Cache.delete(oldestKey);
  }
  globalSha224Cache.set(message, resultHex);
  return resultHex;
}
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { earlyData: void 0, error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const padLen = (4 - base64Str.length % 4) % 4;
    if (padLen > 0) base64Str = base64Str.padEnd(base64Str.length + padLen, "=");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { earlyData: void 0, error };
  }
}
async function cleanList(content) {
  if (!content) return [];
  return content.split(/[\t"'\r\n,]+/).filter(Boolean);
}
function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === 1 || socket.readyState === 2) {
      socket.close();
    }
  } catch (error) {
    void(0);
  }
}
var byteToHex = Array.from({ length: 256 }, (v, i) => (i + 256).toString(16).slice(1));
function stringifyUUID(arr, offset = 0) {
  const uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
  if (!isValidUUID(uuid)) {
    throw TypeError("Invalid stringified UUID");
  }
  return uuid;
}
async function generateDynamicUUID(key, timeDays, updateHour) {
  const timezoneOffset = 8;
  const startDate = new Date(2007, 6, 7, updateHour, 0, 0);
  const oneWeekMs = 1e3 * 60 * 60 * 24 * timeDays;
  function getCurrentCycle() {
    const now =   new Date();
    const adjustedNow = new Date(now.getTime() + timezoneOffset * 60 * 60 * 1e3);
    const timeDiff = Number(adjustedNow) - Number(startDate);
    return Math.ceil(timeDiff / oneWeekMs);
  }
  async function generate(baseStr) {
    const hashBuffer = new TextEncoder().encode(baseStr);
    const hash = await crypto.subtle.digest("SHA-256", hashBuffer);
    const hashArr = Array.from(new Uint8Array(hash));
    const hex = hashArr.map((b) => b.toString(16).padStart(2, "0")).join("");
    return `${hex.substr(0, 8)}-${hex.substr(8, 4)}-4${hex.substr(13, 3)}-${(parseInt(hex.substr(16, 2), 16) & 63 | 128).toString(16)}${hex.substr(18, 2)}-${hex.substr(20, 12)}`;
  }
  const currentCycle = getCurrentCycle();
  const current = await generate(key + currentCycle);
  const prev = await generate(key + (currentCycle - 1));
  return [current, prev];
}
function isHostBanned(hostname, banList) {
  if (!banList || banList.length === 0) return false;
  return banList.some((pattern) => {
    let regexPattern = pattern.replace(/\*/g, ".*");
    let regex = new RegExp(`^${regexPattern}$`, "i");
    return regex.test(hostname);
  });
}
var GLOBAL_KV_CACHE =   new Map();
var MAX_KV_CACHE_SIZE = 200;
var CACHE_API_PREFIX = "http://kv-cache.local/";
var CACHE_NULL_SENTINEL = "##NULL##";
var KNOWN_KV_KEYS = [
  "UUID",
  "KEY",
  "ADMIN_PASS",
  "SUPER_PASSWORD",
  "PROXYIP",
  "SOCKS5",
  "GO2SOCKS5",
  "DNS64",
  "BAN",
  "DIS",
  "TIME",
  "UPTIME",
  "SUBNAME",
  "ADD.txt",
  "ADDAPI",
  "ADDNOTLS",
  "ADDNOTLSAPI",
  "ADDCSV",
  "CFPORTS",
  "BESTIP_SOURCES",
  "REMOTE_CONFIG",
  "REMOTE_CONFIG_URL",
  "URL",
  "URL302",
  "SAVED_DOMAIN"
];
async function getKV(env, key) {
  if (!env.KV || !key) return null;
  if (GLOBAL_KV_CACHE.has(key)) {
    return GLOBAL_KV_CACHE.get(key);
  }
  const cache = caches.default;
  const cacheKeyUrl = CACHE_API_PREFIX + encodeURIComponent(key);
  try {
    const match = await cache.match(cacheKeyUrl);
    if (match) {
      const val2 = await match.text();
      if (val2 === CACHE_NULL_SENTINEL) {
        GLOBAL_KV_CACHE.set(key, null);
        return null;
      }
      if (GLOBAL_KV_CACHE.size >= MAX_KV_CACHE_SIZE) GLOBAL_KV_CACHE.clear();
      GLOBAL_KV_CACHE.set(key, val2);
      return val2;
    }
  } catch (e) {
    void(0);
  }
  let val = null;
  try {
    val = await env.KV.get(key);
  } catch (e) {
    void(0);
  }
  if (GLOBAL_KV_CACHE.size >= MAX_KV_CACHE_SIZE) GLOBAL_KV_CACHE.clear();
  GLOBAL_KV_CACHE.set(key, val);
  const cacheVal = val === null ? CACHE_NULL_SENTINEL : val;
  const response = new Response(cacheVal, {
    headers: {
      "Content-Type": "text/plain",
      "Cache-Control": "max-age=2592000"
    }
  });
  try {
    cache.put(cacheKeyUrl, response).catch((e) => void(0));
  } catch (e) {
    void(0);
  }
  return val;
}
async function clearKVCache(keys) {
  const cache = caches.default;
  const targetKeys = keys && Array.isArray(keys) ? keys : KNOWN_KV_KEYS;
  if (keys) {
    keys.forEach((k) => GLOBAL_KV_CACHE.delete(k));
  } else {
    GLOBAL_KV_CACHE.clear();
  }
  const deletePromises = targetKeys.map((key) => {
    const cacheKeyUrl = CACHE_API_PREFIX + encodeURIComponent(key);
    return cache.delete(cacheKeyUrl).catch((e) => void(0));
  });
  await Promise.all(deletePromises);
  void(0);
}
function fmix32(h) {
  h ^= h >>> 16;
  h = Math.imul(h, 2246822507);
  h ^= h >>> 13;
  h = Math.imul(h, 3266489909);
  h ^= h >>> 16;
  return h >>> 0;
}
var StreamCipher = class {
  constructor(keyBytes, saltBytes) {
    let s1 = 0, s2 = 0, s3 = 0, s4 = 0;
    for (let i = 0; i < keyBytes.length; i++) {
      s1 = Math.imul(s1, 31) + keyBytes[i] | 0;
    }
    for (let i = 0; i < saltBytes.length; i++) {
      s2 = Math.imul(s2, 31) + saltBytes[i] | 0;
    }
    s3 = fmix32(s1 ^ 305419896);
    s4 = fmix32(s2 ^ 2271560481);
    s1 = fmix32(s1);
    s2 = fmix32(s2);
    this.s = new Uint32Array([s1, s2, s3, s4]);
  }
  next() {
    let t = this.s[3];
    let s = this.s[0];
    this.s[3] = this.s[2];
    this.s[2] = this.s[1];
    this.s[1] = s;
    t ^= t << 11;
    t ^= t >>> 8;
    this.s[0] = t ^ s ^ s >>> 19;
    return this.s[0];
  }
  process(buffer) {
    let i = 0;
    const len = buffer.length;
    if (buffer.byteOffset % 4 === 0 && len >= 4) {
      const len32 = Math.floor(len / 4);
      const view32 = new Uint32Array(buffer.buffer, buffer.byteOffset, len32);
      for (let j = 0; j < len32; j++) {
        view32[j] ^= this.next();
      }
      i = len32 * 4;
    }
    let randomCache = 0;
    let cacheRemaining = 0;
    for (; i < len; i++) {
      if (cacheRemaining === 0) {
        randomCache = this.next();
        cacheRemaining = 4;
      }
      buffer[i] ^= randomCache & 255;
      randomCache >>>= 8;
      cacheRemaining--;
    }
  }
};

var configCache = {};
var configGeneration = 0;
var parsedListCache = {
  proxyIP: null,
  banHosts: null,
  disabledProtocols: null,
  go2socks5: null
};
var REMOTE_CONFIG_TTL = 360 * 60 * 1e3;
var remoteConfigCache = {
  data: {},
  lastFetch: 0
};
var proxyIPRemoteCache = {
  data: [],
  expires: 0,
  fetchingPromise: null
};
var uuidCache = {
  key: null,
  data: null,
  lastUpdate: 0
};
var UUID_CACHE_TTL = 10 * 60 * 1e3;
async function cleanConfigCache(updatedKeys) {
  configGeneration++;
  if (!updatedKeys || !Array.isArray(updatedKeys) || updatedKeys.includes("REMOTE_CONFIG_URL")) {
    configCache = {};
    remoteConfigCache = { data: {}, lastFetch: 0 };
    proxyIPRemoteCache = { data: [], expires: 0, fetchingPromise: null };
    uuidCache = { key: null, data: null, lastUpdate: 0 };
    parsedListCache = { proxyIP: null, banHosts: null, disabledProtocols: null, go2socks5: null };
    await clearKVCache();
    return;
  }
  for (const key of updatedKeys) {
    delete configCache[key];
  }
  await clearKVCache(updatedKeys);
  if (updatedKeys.includes("PROXYIP")) {
    proxyIPRemoteCache = { data: [], expires: 0, fetchingPromise: null };
    parsedListCache.proxyIP = null;
  }
  if (updatedKeys.includes("BAN")) parsedListCache.banHosts = null;
  if (updatedKeys.includes("DIS")) parsedListCache.disabledProtocols = null;
  if (updatedKeys.includes("GO2SOCKS5")) parsedListCache.go2socks5 = null;
  if (updatedKeys.some((k) => ["UUID", "KEY", "TIME", "UPTIME", "SUPER_PASSWORD"].includes(k))) {
    uuidCache = { key: null, data: null, lastUpdate: 0 };
  }
}
async function loadRemoteConfig(env, forceReload = false) {
  const remoteConfigUrl = await getKV(env, "REMOTE_CONFIG_URL");
  const now = Date.now();
  const isExpired = now - remoteConfigCache.lastFetch > REMOTE_CONFIG_TTL;
  if (!forceReload && !isExpired && remoteConfigCache.data && Object.keys(remoteConfigCache.data).length > 0) {
    return remoteConfigCache.data;
  }
  if (remoteConfigUrl) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5e3);
      const response = await fetch(remoteConfigUrl, {
        signal: controller.signal
      }).finally(() => {
        clearTimeout(timeoutId);
      });
      if (response.ok) {
        const text = await response.text();
        const updateTime = Date.now();
        const parseConfig = (txt) => {
          try {
            return JSON.parse(txt);
          } catch (e) {
            void(0);
            const lines = txt.split("\n");
            const newData2 = {};
            lines.forEach((line) => {
              const trimmedLine = line.trim();
              if (!trimmedLine || trimmedLine.startsWith("#") || trimmedLine.startsWith("//")) return;
              const eqIndex = trimmedLine.indexOf("=");
              if (eqIndex > 0) {
                const k = trimmedLine.substring(0, eqIndex).trim();
                const v = trimmedLine.substring(eqIndex + 1).trim();
                if (k && v) newData2[k] = v;
              }
            });
            return newData2;
          }
        };
        const newData = parseConfig(text);
        remoteConfigCache.data = newData;
        remoteConfigCache.lastFetch = updateTime;
        configCache = {};
        configGeneration++;
        parsedListCache = { proxyIP: null, banHosts: null, disabledProtocols: null, go2socks5: null };
      }
    } catch (e) {
      void(0);
    }
  }
  return remoteConfigCache.data;
}
async function getConfig(env, key, defaultValue = void 0) {
  if (configCache[key] !== void 0) {
    return configCache[key];
  }
  const currentGen = configGeneration;
  let val = void 0;
  if (env.KV) val = await getKV(env, key);
  if ((val === null || val === void 0) && remoteConfigCache.data && remoteConfigCache.data[key]) val = remoteConfigCache.data[key];
  if ((val === null || val === void 0) && env[key]) val = env[key];
  if (!val && key === "UUID") val = env.UUID || env.uuid || env.PASSWORD || env.pswd || env.SUPER_PASSWORD || CONSTANTS.SUPER_PASSWORD;
  if (!val && key === "KEY") val = env.KEY || env.TOKEN;
  const finalVal = val !== void 0 && val !== null ? val : defaultValue;
  if (currentGen === configGeneration) {
    configCache[key] = finalVal;
  }
  return finalVal;
}
async function getCachedUUID(seed, timeDays, updateHour) {
  const cacheKey = `${seed}|${timeDays}|${updateHour}`;
  const now = Date.now();
  if (uuidCache.key === cacheKey && uuidCache.data && now - uuidCache.lastUpdate < UUID_CACHE_TTL) {
    return uuidCache.data;
  }
  const userIDs = await generateDynamicUUID(seed, timeDays, updateHour);
  uuidCache = { key: cacheKey, data: userIDs, lastUpdate: now };
  return userIDs;
}
async function initializeContext(request, env) {
  const url = new URL(request ? request.url : "http://localhost");
  const forceReload = url.searchParams.get("flush") === "1";
  if (forceReload) {
    void(0);
    configCache = {};
    configGeneration++;
    proxyIPRemoteCache = { data: [], expires: 0, fetchingPromise: null };
    uuidCache = { key: null, data: null, lastUpdate: 0 };
    parsedListCache = { proxyIP: null, banHosts: null, disabledProtocols: null, go2socks5: null };
    await clearKVCache();
  }
  const enableRemote = await getConfig(env, "REMOTE_CONFIG", "0");
  if (enableRemote === "1") {
    await loadRemoteConfig(env, forceReload);
  } else {
    if (remoteConfigCache.data && Object.keys(remoteConfigCache.data).length > 0) {
      void(0);
      remoteConfigCache.data = {};
      remoteConfigCache.lastFetch = 0;
      configCache = {};
      configGeneration++;
      parsedListCache = { proxyIP: null, banHosts: null, disabledProtocols: null, go2socks5: null };
    }
  }
  const [adminPass, rawUUID, rawKey, timeDaysStr, updateHourStr] = await Promise.all([
    getConfig(env, "ADMIN_PASS"),
    getConfig(env, "UUID"),
    getConfig(env, "KEY"),
    getConfig(env, "TIME"),
    getConfig(env, "UPTIME")
  ]);
  const [proxyIPStr, dns64, socks5Addr, go2socksStr, banStr] = await Promise.all([
    getConfig(env, "PROXYIP"),
    getConfig(env, "DNS64"),
    getConfig(env, "SOCKS5"),
    getConfig(env, "GO2SOCKS5"),
    getConfig(env, "BAN")
  ]);
  const disStrRaw = await getConfig(env, "DIS", "");
  const ctx = {
    userID: "",
    dynamicUUID: "",
    userIDLow: "",
    expectedUserIDs: [],
    proxyIP: "",
    proxyIPList: [],
    dns64: dns64 || "",
    socks5: socks5Addr || "",
    go2socks5: [],
    banHosts: [],
    enableXhttp: false,
    disabledProtocols: [],
    httpsPorts: CONSTANTS.HTTPS_PORTS,
    startTime: Date.now(),
    adminPass
  };
  if (rawUUID) {
    ctx.userID = rawUUID;
    ctx.dynamicUUID = rawUUID;
  }
  if (rawKey || rawUUID && !isStrictV4UUID(rawUUID)) {
    const seed = rawKey || rawUUID;
    if (seed) {
      const timeDays = Number(timeDaysStr) || 0;
      const updateHour = Number(updateHourStr) || 0;
      const userIDs = await getCachedUUID(seed, timeDays, updateHour);
      ctx.userID = userIDs[0];
      ctx.userIDLow = userIDs[1];
      ctx.dynamicUUID = seed;
    }
  }
  if (!ctx.userID) {
    const superPass = await getConfig(env, "SUPER_PASSWORD") || CONSTANTS.SUPER_PASSWORD;
    if (superPass) {
      const timeDays = Number(timeDaysStr) || 0;
      const updateHour = Number(updateHourStr) || 0;
      const userIDs = await getCachedUUID(superPass, timeDays, updateHour);
      ctx.userID = userIDs[0];
      ctx.userIDLow = userIDs[1];
      ctx.dynamicUUID = superPass;
      void(0);
    } else {
      void(0);
      const tempUUID = crypto.randomUUID();
      ctx.userID = tempUUID;
      ctx.dynamicUUID = tempUUID;
    }
  }
  ctx.expectedUserIDs = [ctx.userID, ctx.userIDLow].filter(Boolean).map((id) => id.toLowerCase());
  const rawProxyIP = proxyIPStr || CONSTANTS.DEFAULT_PROXY_IP;
  let rawList = [];
  if (rawProxyIP) {
    if (rawProxyIP.startsWith("http")) {
      if (Date.now() < proxyIPRemoteCache.expires && proxyIPRemoteCache.data.length > 0) {
        rawList = proxyIPRemoteCache.data;
      } else {
        if (!proxyIPRemoteCache.fetchingPromise) {
          proxyIPRemoteCache.fetchingPromise = (async () => {
            try {
              const controller = new AbortController();
              const timeoutId = setTimeout(() => controller.abort(), 5e3);
              const response = await fetch(rawProxyIP, { signal: controller.signal }).finally(() => clearTimeout(timeoutId));
              if (response.ok) {
                const text = await response.text();
                const list = await cleanList(text);
                proxyIPRemoteCache.data = list;
                proxyIPRemoteCache.expires = Date.now() + 6e5;
                return list;
              } else {
                throw new Error(`ProxyIP fetch failed: ${response.status}`);
              }
            } catch (e) {
              void(0);
              const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map((s) => s.trim()).filter(Boolean);
              proxyIPRemoteCache.data = defParams;
              proxyIPRemoteCache.expires = Date.now() + 6e4;
              return defParams;
            } finally {
              proxyIPRemoteCache.fetchingPromise = null;
            }
          })();
        }
        rawList = await proxyIPRemoteCache.fetchingPromise;
      }
    } else {
      if (parsedListCache.proxyIP) {
        rawList = parsedListCache.proxyIP;
      } else {
        rawList = rawProxyIP.split(/[,;\n]/).map((s) => s.trim()).filter(Boolean);
        parsedListCache.proxyIP = rawList;
      }
    }
  }
  if (rawList && rawList.length > 0) {
    const selectedIP = rawList[Math.floor(Math.random() * rawList.length)];
    ctx.proxyIP = selectedIP;
    ctx.proxyIPList = [selectedIP];
  } else {
    ctx.proxyIP = "";
    ctx.proxyIPList = [];
  }
  if (parsedListCache.go2socks5) {
    ctx.go2socks5 = parsedListCache.go2socks5;
  } else {
    ctx.go2socks5 = go2socksStr ? await cleanList(go2socksStr) : CONSTANTS.DEFAULT_GO2SOCKS5;
    parsedListCache.go2socks5 = ctx.go2socks5;
  }
  if (parsedListCache.banHosts) {
    ctx.banHosts = parsedListCache.banHosts;
  } else if (banStr) {
    ctx.banHosts = await cleanList(banStr);
    parsedListCache.banHosts = ctx.banHosts;
  }
  if (parsedListCache.disabledProtocols) {
    ctx.disabledProtocols = parsedListCache.disabledProtocols;
  } else {
    let disStr = disStrRaw;
    if (disStr) disStr = disStr.replace(/，/g, ",");
    const disList = await cleanList(disStr);
    ctx.disabledProtocols = disList.map((p) => {
      const protocol = p.trim().toLowerCase();
      if (protocol === "shadowsocks") return "ss";
      return protocol;
    });
    parsedListCache.disabledProtocols = ctx.disabledProtocols;
  }
  ctx.enableXhttp = !ctx.disabledProtocols.includes("xhttp");
  if (url.searchParams.has("proxyip")) {
    const manualIP = url.searchParams.get("proxyip");
    ctx.proxyIP = manualIP;
    ctx.proxyIPList = [manualIP];
  }
  if (url.searchParams.has("socks5")) ctx.socks5 = url.searchParams.get("socks5");
  return ctx;
}

var ProtocolManager = class {
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
        if (handler.name === "vless") {
          credentials = vlessIds;
        } else if (handler.name === "trojan" || handler.name === "mandala") {
          credentials = password;
        }
        const result = await handler.validator(chunk, credentials);
        if (!result.hasError) {
          return { ...result, protocol: handler.name };
        }
      } catch (e) {
      }
    }
    throw new Error("Protocol detection failed.");
  }
};

async function processVlessHeader(vlessBuffer, expectedUserIDs) {
  if (vlessBuffer.byteLength < 24) return { hasError: true, message: "Buffer too short" };
  const buffer = vlessBuffer instanceof Uint8Array ? vlessBuffer : new Uint8Array(vlessBuffer);
  const version = buffer[0];
  if (version !== 0) return { hasError: true, message: "Invalid VLESS version" };
  const uuid = stringifyUUID(buffer.subarray(1, 17));
  if (!expectedUserIDs.includes(uuid)) {
    return { hasError: true, message: "Invalid VLESS user" };
  }
  const optLength = buffer[17];
  const commandIndex = 18 + optLength;
  if (commandIndex >= buffer.byteLength) return { hasError: true, message: "Buffer too short for command" };
  const command = buffer[commandIndex];
  const isUDP = command === 2;
  if (command !== 1 && command !== 2) {
    return { hasError: true, message: "Unsupported VLESS command: " + command };
  }
  const portIndex = commandIndex + 1;
  if (buffer.byteLength < portIndex + 2) return { hasError: true, message: "Buffer too short for port" };
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const portRemote = view.getUint16(portIndex, false);
  let addressIndex = portIndex + 2;
  const addressType = buffer[addressIndex];
  addressIndex++;
  let addressRemote = "";
  let addressLength = 0;
  try {
    switch (addressType) {
      case CONSTANTS.ADDRESS_TYPE_IPV4:
        addressLength = 4;
        addressRemote = buffer.subarray(addressIndex, addressIndex + 4).join(".");
        break;
      case CONSTANTS.ADDRESS_TYPE_URL:
        addressLength = buffer[addressIndex];
        addressIndex++;
        addressRemote = textDecoder.decode(buffer.subarray(addressIndex, addressIndex + addressLength));
        break;
      case CONSTANTS.ADDRESS_TYPE_IPV6:
        addressLength = 16;
        const ipv6 = [];
        for (let i = 0; i < 8; i++) {
          const idx = addressIndex + i * 2;
          const high = buffer[idx];
          const low = buffer[idx + 1];
          ipv6.push((high << 8 | low).toString(16));
        }
        addressRemote = "[" + ipv6.join(":") + "]";
        break;
      default:
        return { hasError: true, message: "Invalid VLESS addressType: " + addressType };
    }
  } catch (e) {
    return { hasError: true, message: "Address parse failed" };
  }
  if (!addressRemote) return { hasError: true, message: "VLESS address is empty" };
  const rawDataIndex = addressIndex + addressLength;
  return {
    hasError: false,
    addressRemote,
    addressType,
    portRemote,
    isUDP,
    rawDataIndex,
    cloudflareVersion: new Uint8Array([version])
  };
}

function constantTimeEqual(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  let mismatch = 0;
  for (let i = 0; i < a.byteLength; i++) {
    mismatch |= a[i] ^ b[i];
  }
  return mismatch === 0;
}
async function parseTrojanHeader(trojanBuffer, password) {
  if (trojanBuffer.byteLength < 58) return { hasError: true, message: "Trojan buffer too short." };
  const buffer = trojanBuffer instanceof Uint8Array ? trojanBuffer : new Uint8Array(trojanBuffer);
  const hashHex = sha224Hash(String(password));
  const expectedHashBytes = textEncoder.encode(hashHex);
  const receivedHashBytes = buffer.subarray(0, 56);
  if (!constantTimeEqual(receivedHashBytes, expectedHashBytes)) {
    return { hasError: true, message: "Invalid Trojan password." };
  }
  if (buffer[56] !== 13 || buffer[57] !== 10) {
    return { hasError: true, message: "Invalid Trojan header (Missing CRLF)" };
  }
  const requestOffset = 58;
  const requestData = buffer.subarray(requestOffset);
  if (requestData.byteLength < 4) return { hasError: true, message: "Trojan request too short." };
  const view = new DataView(buffer.buffer, buffer.byteOffset + requestOffset, requestData.byteLength);
  const command = buffer[requestOffset];
  const isUDP = command === 3;
  if (command !== 1 && !isUDP) {
    return { hasError: true, message: "Unsupported Trojan cmd: " + command };
  }
  const atyp = buffer[requestOffset + 1];
  let host = "";
  let port = 0;
  let payloadIndex = 0;
  try {
    switch (atyp) {
      case CONSTANTS.ADDRESS_TYPE_IPV4:
        host = buffer.subarray(requestOffset + 2, requestOffset + 6).join(".");
        port = view.getUint16(6, false);
        payloadIndex = 8;
        break;
      case CONSTANTS.ATYP_TROJAN_DOMAIN:
        const domainLen = buffer[requestOffset + 2];
        host = textDecoder.decode(buffer.subarray(requestOffset + 3, requestOffset + 3 + domainLen));
        port = view.getUint16(3 + domainLen, false);
        payloadIndex = 3 + domainLen + 2;
        break;
      case CONSTANTS.ATYP_TROJAN_IPV6:
        const ipv6 = [];
        for (let i = 0; i < 8; i++) {
          ipv6.push(view.getUint16(2 + i * 2, false).toString(16));
        }
        host = "[" + ipv6.join(":") + "]";
        port = view.getUint16(18, false);
        payloadIndex = 20;
        break;
      default:
        return { hasError: true, message: "Invalid Trojan ATYP: " + atyp };
    }
  } catch (e) {
    return { hasError: true, message: "Address decode failed" };
  }
  const crlfIndex = requestOffset + payloadIndex;
  if (buffer.byteLength < crlfIndex + 2) {
    return { hasError: true, message: "Trojan buffer too short for payload CRLF" };
  }
  if (buffer[crlfIndex] !== 13 || buffer[crlfIndex + 1] !== 10) {
    return { hasError: true, message: "Trojan missing payload CRLF" };
  }
  const rawClientData = buffer.subarray(crlfIndex + 2);
  return {
    hasError: false,
    addressRemote: host,
    addressType: atyp,
    portRemote: port,
    rawClientData,
    isUDP,
    rawDataIndex: 0
  };
}

function constantTimeEqual2(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  let mismatch = 0;
  for (let i = 0; i < a.byteLength; i++) {
    mismatch |= a[i] ^ b[i];
  }
  return mismatch === 0;
}
async function parseMandalaHeader(mandalaBuffer, password) {
  if (!password) {
    return { hasError: true, message: "Password is required" };
  }
  if (mandalaBuffer.byteLength < 40) {
    return { hasError: true, message: "Mandala buffer too short" };
  }
  const buffer = mandalaBuffer instanceof Uint8Array ? mandalaBuffer : new Uint8Array(mandalaBuffer);
  const salt = buffer.subarray(0, 4);
  const ciphertext = buffer.subarray(4);
  const PROBE_LIMIT = 2048;
  const decodeLen = Math.min(ciphertext.byteLength, PROBE_LIMIT);
  const decrypted = new Uint8Array(ciphertext.subarray(0, decodeLen));
  const passwordBytes = textEncoder.encode(password);
  const cipher = new StreamCipher(passwordBytes, salt);
  cipher.process(decrypted);
  const cachedAuthKeyHex = sha224Hash(String(password));
  const cachedAuthKeyBytes = textEncoder.encode(cachedAuthKeyHex);
  const HASH_SIZE = 32;
  if (decrypted.byteLength < HASH_SIZE + 1) return { hasError: true, message: "Data too short" };
  const padLen = decrypted[HASH_SIZE];
  let cursor = HASH_SIZE + 1 + padLen;
  if (cursor >= decrypted.length) return { hasError: true, message: "Padding overflow" };
  const cmd = decrypted[cursor];
  const isUDP = cmd === 3;
  if (cmd !== 1 && !isUDP) return { hasError: true, message: "Unsupported Mandala CMD: " + cmd };
  cursor++;
  if (cursor >= decrypted.length) return { hasError: true, message: "Buffer ended unexpectedly" };
  const atyp = decrypted[cursor];
  cursor++;
  let addressRemote = "";
  let portRemote = 0;
  const view = new DataView(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);
  try {
    switch (atyp) {
      case CONSTANTS.ADDRESS_TYPE_IPV4:
        addressRemote = decrypted.subarray(cursor, cursor + 4).join(".");
        cursor += 4;
        break;
      case CONSTANTS.ATYP_SS_DOMAIN:
        const domainLen = decrypted[cursor];
        cursor++;
        addressRemote = textDecoder.decode(decrypted.subarray(cursor, cursor + domainLen));
        cursor += domainLen;
        break;
      case CONSTANTS.ATYP_SS_IPV6:
        const ipv6 = [];
        for (let i = 0; i < 8; i++) ipv6.push(view.getUint16(cursor + i * 2, false).toString(16));
        addressRemote = "[" + ipv6.join(":") + "]";
        cursor += 16;
        break;
      default:
        return { hasError: true, message: "Unknown ATYP: " + atyp };
    }
    portRemote = view.getUint16(cursor, false);
    cursor += 2;
  } catch (e) {
    return { hasError: true, message: "Header parse failed" };
  }
  const headerEnd = cursor;
  if (headerEnd + 2 > decrypted.byteLength) return { hasError: true, message: "Missing CRLF" };
  if (decrypted[headerEnd] !== 13 || decrypted[headerEnd + 1] !== 10) {
    return { hasError: true, message: "Invalid Footer" };
  }
  const fullHeaderLen = headerEnd + 2;
  const receivedHash = decrypted.subarray(0, HASH_SIZE);
  const headerData = decrypted.subarray(HASH_SIZE, fullHeaderLen);
  const verifyBuffer = new Uint8Array(cachedAuthKeyBytes.length + headerData.length);
  verifyBuffer.set(cachedAuthKeyBytes);
  verifyBuffer.set(headerData, cachedAuthKeyBytes.length);
  const computedHashBuffer = await crypto.subtle.digest("SHA-256", verifyBuffer);
  const computedHash = new Uint8Array(computedHashBuffer);
  if (!constantTimeEqual2(receivedHash, computedHash)) {
    return { hasError: true, message: "Mandala Integrity Check Failed" };
  }
  const rawClientData = ciphertext.subarray(fullHeaderLen);
  return {
    hasError: false,
    addressRemote,
    portRemote,
    addressType: atyp,
    isUDP,
    rawClientData,
    protocol: "mandala"
  };
}

async function parseSocks5Header(socksBuffer) {
  const buffer = socksBuffer instanceof Uint8Array ? socksBuffer : new Uint8Array(socksBuffer);
  if (buffer.byteLength < 4) return { hasError: true, message: "SOCKS buffer too short." };
  const socksVersion = buffer[0];
  if (socksVersion !== CONSTANTS.SOCKS_VERSION) return { hasError: true, message: "Invalid SOCKS version." };
  const cmd = buffer[1];
  const isUDP = cmd === 3;
  if (cmd !== CONSTANTS.SOCKS_CMD_CONNECT && !isUDP) {
    return { hasError: true, message: "Unsupported SOCKS command: " + cmd };
  }
  if (buffer[2] !== 0) return { hasError: true, message: "Invalid SOCKS RSV." };
  const addrType = buffer[3];
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let addressRemote = "";
  let portRemote = 0;
  let payloadStartIndex = 0;
  try {
    switch (addrType) {
      case CONSTANTS.ADDRESS_TYPE_IPV4: {
        if (buffer.byteLength < 10) return { hasError: true, message: "SOCKS buffer too short for IPv4" };
        addressRemote = buffer.subarray(4, 8).join(".");
        portRemote = view.getUint16(8, false);
        payloadStartIndex = 10;
        break;
      }
      case CONSTANTS.ATYP_TROJAN_DOMAIN: {
        if (buffer.byteLength < 5) return { hasError: true, message: "SOCKS buffer too short for Domain len" };
        const domainLen = buffer[4];
        const boundary = 5 + domainLen + 2;
        if (buffer.byteLength < boundary) return { hasError: true, message: "SOCKS buffer too short for Domain" };
        addressRemote = textDecoder.decode(buffer.subarray(5, 5 + domainLen));
        portRemote = view.getUint16(5 + domainLen, false);
        payloadStartIndex = boundary;
        break;
      }
      case CONSTANTS.ATYP_TROJAN_IPV6: {
        if (buffer.byteLength < 22) return { hasError: true, message: "SOCKS buffer too short for IPv6" };
        const ipv6 = [];
        for (let i = 0; i < 8; i++) ipv6.push(view.getUint16(4 + i * 2, false).toString(16));
        addressRemote = "[" + ipv6.join(":") + "]";
        portRemote = view.getUint16(20, false);
        payloadStartIndex = 22;
        break;
      }
      default:
        return { hasError: true, message: "Invalid SOCKS ATYP: " + addrType };
    }
  } catch (e) {
    return { hasError: true, message: "Address parse failed" };
  }
  return {
    hasError: false,
    addressRemote,
    addressType: addrType,
    portRemote,
    rawClientData: buffer.subarray(payloadStartIndex),
    isUDP,
    rawDataIndex: payloadStartIndex,
    isSocks5: true
  };
}

async function parseShadowsocksHeader(ssBuffer) {
  const buffer = ssBuffer instanceof Uint8Array ? ssBuffer : new Uint8Array(ssBuffer);
  if (buffer.byteLength < 4) return { hasError: true, message: "SS buffer too short" };
  const addrType = buffer[0];
  let addressRemote = "";
  let portRemote = 0;
  let headersLength = 0;
  try {
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    switch (addrType) {
      case CONSTANTS.ATYP_SS_IPV4: {
        if (buffer.byteLength < 7) return { hasError: true, message: "SS buffer too short for IPv4" };
        addressRemote = buffer.subarray(1, 5).join(".");
        portRemote = view.getUint16(5, false);
        headersLength = 7;
        break;
      }
      case CONSTANTS.ATYP_SS_DOMAIN: {
        const domainLen = buffer[1];
        headersLength = 1 + 1 + domainLen + 2;
        if (buffer.byteLength < headersLength) return { hasError: true, message: "SS buffer too short for Domain" };
        addressRemote = textDecoder.decode(buffer.subarray(2, 2 + domainLen));
        portRemote = view.getUint16(2 + domainLen, false);
        break;
      }
      case CONSTANTS.ATYP_SS_IPV6: {
        if (buffer.byteLength < 19) return { hasError: true, message: "SS buffer too short for IPv6" };
        const ipv6 = [];
        for (let i = 0; i < 8; i++) {
          ipv6.push(view.getUint16(1 + i * 2, false).toString(16));
        }
        addressRemote = "[" + ipv6.join(":") + "]";
        portRemote = view.getUint16(17, false);
        headersLength = 19;
        break;
      }
      default:
        return { hasError: true, message: `Invalid SS ATYP: ${addrType}` };
    }
  } catch (e) {
    return { hasError: true, message: "SS parse failed: " + e.message };
  }
  return {
    hasError: false,
    addressRemote,
    addressType: addrType,
    portRemote,
    rawClientData: buffer.subarray(headersLength),
    isUDP: false,
    rawDataIndex: headersLength
  };
}

import { connect } from "cloudflare:sockets";

var dnsCache =   new Map();
var inflightRequests =   new Map();
function parseIPv6(ip) {
  if (!ip) return null;
  ip = ip.replace(/[\[\]]/g, "");
  if (ip.includes(".")) {
    const lastColon = ip.lastIndexOf(":");
    const v4Str = ip.substring(lastColon + 1);
    const v6Prefix = ip.substring(0, lastColon);
    const v4Parts = v4Str.split(".").map(Number);
    if (v4Parts.length !== 4) return null;
    const p1 = v4Parts[0] << 8 | v4Parts[1];
    const p2 = v4Parts[2] << 8 | v4Parts[3];
    const prefixParts = parseIPv6(v6Prefix + ":0:0");
    if (!prefixParts) return null;
    prefixParts[6] = p1;
    prefixParts[7] = p2;
    return prefixParts;
  }
  const parts = ip.split(":");
  let res = [];
  const emptyIndex = parts.indexOf("");
  if (emptyIndex !== -1) {
    const head = parts.slice(0, emptyIndex).filter((p) => p !== "").map((p) => parseInt(p, 16) || 0);
    const tail = parts.slice(emptyIndex + 1).filter((p) => p !== "").map((p) => parseInt(p, 16) || 0);
    const middle = new Array(8 - head.length - tail.length).fill(0);
    res = [...head, ...middle, ...tail];
  } else {
    res = parts.map((p) => parseInt(p, 16) || 0);
  }
  return res.slice(0, 8);
}
async function performResolve(domain, dnsServer) {
  let isDoH = false;
  try {
    const u = new URL(dnsServer);
    if (u.protocol === "http:" || u.protocol === "https:") {
      isDoH = true;
    }
  } catch (e) {
  }
  if (isDoH) {
    try {
      const url = new URL(dnsServer);
      url.searchParams.set("name", domain);
      url.searchParams.set("type", "AAAA");
      const response = await fetch(url.toString(), {
        method: "GET",
        headers: { "Accept": "application/dns-json" }
      });
      if (!response.ok) return null;
      let data;
      try {
        data = await response.json();
      } catch (e) {
        return null;
      }
      if (data && data.Status === 0 && Array.isArray(data.Answer)) {
        for (const rec of data.Answer) {
          if (rec.type === 28 && rec.data) {
            return rec.data;
          }
        }
      }
    } catch (e) {
      void(0);
    }
    return null;
  }
  let prefix = dnsServer.split("/")[0].trim();
  if (!prefix.includes(":")) return null;
  let ipv4 = domain;
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(domain)) {
    try {
      const dohUrl = "https://cloudflare-dns.com/dns-query";
      const url = new URL(dohUrl);
      url.searchParams.set("name", domain);
      url.searchParams.set("type", "A");
      const res = await fetch(url, { headers: { "Accept": "application/dns-json" } });
      const data = await res.json();
      if (data && data.Status === 0 && Array.isArray(data.Answer)) {
        const rec = data.Answer.find((r) => r.type === 1);
        if (rec && rec.data) {
          ipv4 = rec.data;
        } else {
          return null;
        }
      } else {
        return null;
      }
    } catch (e) {
      return null;
    }
  }
  const parts = ipv4.split(".").map(Number);
  if (parts.length === 4) {
    if (!prefix.endsWith(":")) prefix += ":";
    const part1 = (parts[0] << 8 | parts[1]).toString(16).padStart(4, "0");
    const part2 = (parts[2] << 8 | parts[3]).toString(16).padStart(4, "0");
    const synthesizedIP = `${prefix}${part1}:${part2}`;
    return synthesizedIP;
  }
  return null;
}
async function resolveToIPv6(domain, dnsServer, ctx) {
  if (!dnsServer) return null;
  if (dnsCache.size > 1e3) {
    dnsCache.clear();
  }
  const cacheKey = `${domain}|${dnsServer}`;
  const cacheUrl = new URL(`http://dns-cache.local/${encodeURIComponent(cacheKey)}`);
  const cache = caches.default;
  const cached = dnsCache.get(cacheKey);
  if (cached && Date.now() < cached.expires) {
    return cached.ip;
  }
  try {
    const response = await cache.match(cacheUrl);
    if (response) {
      const ip = await response.text();
      dnsCache.set(cacheKey, { ip, expires: Date.now() + 6e4 });
      return ip;
    }
  } catch (e) {
    void(0);
  }
  if (inflightRequests.has(cacheKey)) {
    return await inflightRequests.get(cacheKey);
  }
  const promise = performResolve(domain, dnsServer).finally(() => {
    inflightRequests.delete(cacheKey);
  });
  inflightRequests.set(cacheKey, promise);
  try {
    const ip = await promise;
    if (ip) {
      dnsCache.set(cacheKey, { ip, expires: Date.now() + 6e4 });
      const putCache = async () => {
        try {
          const cacheResponse = new Response(ip, {
            headers: {
              "Cache-Control": "max-age=60",
              "Content-Type": "text/plain"
            }
          });
          await cache.put(cacheUrl, cacheResponse);
        } catch (cacheError) {
          void(0);
        }
      };
      if (ctx && typeof ctx.waitUntil === "function") {
        ctx.waitUntil(putCache());
      } else {
        putCache().catch((e) => {
        });
      }
    }
    return ip;
  } catch (e) {
    void(0);
    return null;
  }
}

var IPV4_PRIVATE_REGEX = /^(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[0-1])\.|192\.168\.|169\.254\.|198\.1[89]\.|(?:22[4-9]|23\d|24\d|25[0-5])\.|0\.|localhost)/;
var IPV4_CGNAT_REGEX = /^100\.(?:6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./;
var IPV6_PRIVATE_REGEX = /^(:?(:|f[cd][0-9a-f]{2}|fe[89ab][0-9a-f])):|^(::1)$/i;
function isPrivateIP(address) {
  if (!address) return true;
  if (address.indexOf(":") !== -1) {
    return IPV6_PRIVATE_REGEX.test(address.toLowerCase());
  }
  return IPV4_PRIVATE_REGEX.test(address) || IPV4_CGNAT_REGEX.test(address);
}
var CACHE_TTL = 10 * 60 * 1e3;
var MAX_CACHE_SIZE = 500;
var DirectFailureCache = class {
  constructor() {
    this.cache =   new Map();
  }
  add(host) {
    if (!host) return;
    if (this.has(host)) return;
    if (this.cache.size >= MAX_CACHE_SIZE) this.cache.delete(this.cache.keys().next().value);
    this.cache.set(host, Date.now() + CACHE_TTL);
  }
  has(host) {
    if (!host) return false;
    const expireTime = this.cache.get(host);
    if (!expireTime) return false;
    if (Date.now() > expireTime) {
      this.cache.delete(host);
      return false;
    }
    return true;
  }
};
var failureCache = new DirectFailureCache();
function addToFailureCache(host) {
  if (host) failureCache.add(host);
}
function getSingleProxyIP(proxyIP) {
  if (!proxyIP) return null;
  if (Array.isArray(proxyIP)) {
    if (proxyIP.length === 0) return null;
    return proxyIP[Math.floor(Math.random() * proxyIP.length)];
  }
  return proxyIP;
}
function parseProxyIP(proxyAddr, defaultPort) {
  if (!proxyAddr) return { host: CONSTANTS.DEFAULT_PROXY_IP.split(",")[0].trim(), port: defaultPort };
  let host = proxyAddr;
  let port = defaultPort;
  if (host.startsWith("[")) {
    const bracketEnd = host.indexOf("]");
    if (bracketEnd > 0) {
      const ipPart = host.substring(1, bracketEnd);
      const portPart = host.substring(bracketEnd + 1);
      if (portPart.startsWith(":")) {
        const p = parseInt(portPart.substring(1), 10);
        if (!isNaN(p)) port = p;
      }
      return { host: ipPart, port };
    }
  }
  const colonCount = (host.match(/:/g) || []).length;
  if (colonCount > 1) return { host, port };
  const lastColon = host.lastIndexOf(":");
  if (lastColon > 0) {
    const portStr = host.substring(lastColon + 1);
    if (/^\d+$/.test(portStr)) {
      port = parseInt(portStr, 10);
      host = host.substring(0, lastColon);
    }
  }
  return { host, port };
}
function shouldUseSocks5(addressRemote, go2socks5) {
  if (!go2socks5 || go2socks5.length === 0) return false;
  if (go2socks5.includes("all in") || go2socks5.includes("*")) return true;
  return go2socks5.some((pattern) => {
    let regexPattern = pattern.replace(/\*/g, ".*");
    let regex = new RegExp(`^${regexPattern}$`, "i");
    return regex.test(addressRemote);
  });
}
function parseSocks5Config(address) {
  if (!address) return null;
  if (typeof address === "object") return address;
  const cleanAddr = address.includes("://") ? address.split("://")[1] : address;
  const lastAtIndex = cleanAddr.lastIndexOf("@");
  let [latter, former] = lastAtIndex === -1 ? [cleanAddr, void 0] : [cleanAddr.substring(lastAtIndex + 1), cleanAddr.substring(0, lastAtIndex)];
  let username, password, hostname, port;
  if (former) {
    const formers = former.split(":");
    if (formers.length !== 2) throw new Error("Invalid SOCKS auth format");
    [username, password] = formers;
  }
  const lastColonIndex = latter.lastIndexOf(":");
  if (lastColonIndex === -1) throw new Error("Invalid SOCKS address format, missing port");
  hostname = latter.substring(0, lastColonIndex);
  port = Number(latter.substring(lastColonIndex + 1));
  if (hostname.startsWith("[") && hostname.endsWith("]")) hostname = hostname.slice(1, -1);
  return { username, password, hostname, port };
}
async function readWithTimeout(reader, timeoutMs = 5e3) {
  let timeoutId;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(`Read timeout (${timeoutMs}ms)`)), timeoutMs);
  });
  try {
    const result = await Promise.race([reader.read(), timeoutPromise]);
    return result;
  } finally {
    clearTimeout(timeoutId);
  }
}
async function socks5Connect(socks5Addr, addressType, addressRemote, portRemote, log, isUDP = false) {
  const config = parseSocks5Config(socks5Addr);
  if (!config) throw new Error("Socks5 config missing");
  const { username, password, hostname, port } = config;
  const HANDSHAKE_TIMEOUT = 5e3;
  const socket = connect({ hostname, port });
  try {
    await socket.opened;
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    await writer.write(new Uint8Array([5, 1, 2]));
    let { value: res } = await readWithTimeout(reader, HANDSHAKE_TIMEOUT);
    if (!res || res.length < 2 || res[0] !== 5 || res[1] === 255) throw new Error("SOCKS5 greeting failed");
    if (res[1] === 2) {
      if (!username || !password) throw new Error("SOCKS5 auth required");
      const uBytes = encoder.encode(username);
      const pBytes = encoder.encode(password);
      const authReq = new Uint8Array([1, uBytes.length, ...uBytes, pBytes.length, ...pBytes]);
      await writer.write(authReq);
      const { value: authRes } = await readWithTimeout(reader, HANDSHAKE_TIMEOUT);
      if (!authRes || authRes.length < 2 || authRes[0] !== 1 || authRes[1] !== 0) throw new Error("SOCKS5 auth failed");
    }
    let DSTADDR;
    if (isUDP) {
      DSTADDR = new Uint8Array([1, 0, 0, 0, 0]);
    } else {
      switch (addressType) {
        case CONSTANTS.ADDRESS_TYPE_IPV4:
          DSTADDR = new Uint8Array([1, ...addressRemote.split(".").map(Number)]);
          break;
        case CONSTANTS.ADDRESS_TYPE_IPV6:
        case CONSTANTS.ATYP_TROJAN_IPV6:
          const v6Parts = parseIPv6(addressRemote.replace(/[\[\]]/g, ""));
          if (!v6Parts) throw new Error("Invalid IPv6 address");
          const v6Bytes = new Uint8Array(16);
          for (let i = 0; i < 8; i++) {
            v6Bytes[i * 2] = v6Parts[i] >> 8 & 255;
            v6Bytes[i * 2 + 1] = v6Parts[i] & 255;
          }
          DSTADDR = new Uint8Array([4, ...v6Bytes]);
          break;
        default:
          const domainBytes = encoder.encode(addressRemote);
          DSTADDR = new Uint8Array([3, domainBytes.length, ...domainBytes]);
      }
    }
    const cmd = isUDP ? 3 : 1;
    const portBytes = isUDP ? [0, 0] : [portRemote >> 8, portRemote & 255];
    const socksRequest = new Uint8Array([5, cmd, 0, ...DSTADDR, ...portBytes]);
    await writer.write(socksRequest);
    const { value: connRes } = await readWithTimeout(reader, HANDSHAKE_TIMEOUT);
    if (!connRes || connRes.length < 2 || connRes[0] !== 5 || connRes[1] !== 0) {
      throw new Error(`SOCKS5 connection failed (CMD: ${cmd}, REP: ${connRes ? connRes[1] : "empty"})`);
    }
    if (isUDP) {
      let bndAddr = "";
      let bndPort = 0;
      let addrType = connRes[3];
      let offset = 4;
      if (addrType === 1) {
        bndAddr = connRes.slice(offset, offset + 4).join(".");
        offset += 4;
      } else if (addrType === 3) {
        const len = connRes[offset];
        offset++;
        bndAddr = new TextDecoder().decode(connRes.slice(offset, offset + len));
        offset += len;
      } else if (addrType === 4) {
        const hex = [];
        for (let i = 0; i < 16; i++) hex.push(connRes[offset + i].toString(16).padStart(2, "0"));
        bndAddr = `[${hex.join("").match(/.{1,4}/g).join(":")}]`;
        offset += 16;
      }
      const p1 = connRes[offset];
      const p2 = connRes[offset + 1];
      bndPort = p1 << 8 | p2;
      writer.releaseLock();
      reader.releaseLock();
      socket.isUdpControl = true;
      socket.bndAddr = bndAddr;
      socket.bndPort = bndPort;
      socket.originalHost = hostname;
      return socket;
    }
    let headLen = 0;
    if (connRes.length >= 4) {
      if (connRes[3] === 1) headLen = 10;
      else if (connRes[3] === 4) headLen = 22;
      else if (connRes[3] === 3) headLen = 7 + connRes[4];
    }
    if (headLen > 0 && connRes.length > headLen) {
      socket.initialData = connRes.subarray(headLen);
    }
    writer.releaseLock();
    reader.releaseLock();
    return socket;
  } catch (err) {
    try {
      socket.close();
    } catch (e) {
    }
    throw err;
  }
}
async function connectWithTimeout(host, port, timeoutMs, log, socksConfig = null, addressType = null, addressRemote = null, isUDP = false) {
  let isTimedOut = false;
  let socket = null;
  const timeoutPromise = new Promise((_, reject) => setTimeout(() => {
    isTimedOut = true;
    reject(new Error(`Connect timeout (${timeoutMs}ms)`));
  }, timeoutMs));
  const doConnect = async () => {
    if (socksConfig) {
      return await socks5Connect(socksConfig, addressType, addressRemote, port, log, isUDP);
    } else {
      return connect({ hostname: host, port });
    }
  };
  try {
    socket = await Promise.race([doConnect(), timeoutPromise]);
    if (isTimedOut) {
      if (socket) {
        try {
          socket.close();
        } catch (e) {
        }
      }
      throw new Error(`Connect timeout (${timeoutMs}ms)`);
    }
    if (!socket) throw new Error("Connection failed");
    if (!socksConfig) await Promise.race([socket.opened, timeoutPromise]);
    return socket;
  } catch (err) {
    if (socket) {
      try {
        socket.close();
      } catch (e) {
      }
    }
    throw err;
  }
}
async function createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log, fallbackAddress, isUDP = false) {
  const useSocks = ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5);
  const DIRECT_TIMEOUTS = [1500, 4e3];
  const PROXY_TIMEOUT = 5e3;
  if (!failureCache.has(addressRemote)) {
    const currentTimeout = DIRECT_TIMEOUTS[0];
    try {
      const protoLabel = isUDP ? "UDP" : "TCP";
      log(`[connect:${protoLabel}] Phase 1: Direct ${addressRemote}:${portRemote} (Timeout: ${currentTimeout}ms)`);
      return await connectWithTimeout(addressRemote, portRemote, currentTimeout, log, useSocks ? ctx.socks5 : null, addressType, addressRemote, isUDP);
    } catch (err1) {
      log(`[connect] Phase 1 failed: ${err1.message}`);
      if (err1.message.includes("refused") || err1.message.includes("reset") || err1.message.includes("abort")) {
        addToFailureCache(addressRemote);
      }
    }
  }
  let proxyIP = getSingleProxyIP(fallbackAddress || ctx.proxyIP);
  if (!proxyIP) {
    const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map((s) => s.trim()).filter(Boolean);
    if (defParams.length > 0) proxyIP = defParams[0];
  }
  if (proxyIP) {
    const { host: proxyHost, port: proxyPort } = parseProxyIP(proxyIP, portRemote);
    try {
      return await connectWithTimeout(proxyHost.toLowerCase(), proxyPort, PROXY_TIMEOUT, log);
    } catch (err2) {
      log(`[connect] Phase 2 (ProxyIP: ${proxyHost}) failed: ${err2.message}`);
    }
  }
  if (!useSocks && ctx.dns64) {
    try {
      const v6Address = await resolveToIPv6(addressRemote, ctx.dns64);
      if (v6Address) {
        return await connectWithTimeout(v6Address, portRemote, PROXY_TIMEOUT, log);
      }
    } catch (err3) {
      log(`[connect] Phase 3 (NAT64) failed: ${err3.message}`);
    }
  }
  throw new Error(`All connection attempts failed.`);
}
function concatUint8(a, b) {
  const bArr = b instanceof Uint8Array ? b : new Uint8Array(b);
  const res = new Uint8Array(a.length + bArr.length);
  res.set(a);
  res.set(bArr, a.length);
  return res;
}
function getSocks5UdpHeaderLength(buffer) {
  if (buffer.length < 4) return -1;
  const atyp = buffer[3];
  if (atyp === 1) return 10;
  if (atyp === 4) return 22;
  if (atyp === 3) {
    if (buffer.length < 5) return -1;
    const len = buffer[4];
    return 7 + len;
  }
  return 0;
}
function createSocks5UdpHeader(addressType, addressRemote, portRemote) {
  const rsvFrag = [0, 0, 0];
  let addrBytes;
  let atyp = addressType;
  if (addressType === CONSTANTS.ADDRESS_TYPE_IPV4) {
    addrBytes = addressRemote.split(".").map(Number);
  } else if (addressType === CONSTANTS.ADDRESS_TYPE_IPV6 || addressType === CONSTANTS.ATYP_TROJAN_IPV6) {
    atyp = 4;
    const v6Parts = parseIPv6(addressRemote.replace(/[\[\]]/g, ""));
    addrBytes = [];
    for (let i = 0; i < 8; i++) {
      addrBytes.push(v6Parts[i] >> 8 & 255);
      addrBytes.push(v6Parts[i] & 255);
    }
  } else {
    atyp = 3;
    const encoder = new TextEncoder();
    const domain = encoder.encode(addressRemote);
    addrBytes = [domain.length, ...domain];
  }
  const portBytes = [portRemote >> 8, portRemote & 255];
  return new Uint8Array([...rsvFrag, atyp, ...addrBytes, ...portBytes]);
}
async function safeWrite(writer, chunk) {
  const WRITE_TIMEOUT = 1e4;
  const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error("Write timeout")), WRITE_TIMEOUT));
  await Promise.race([writer.write(chunk), timeoutPromise]);
}
async function flushBuffer(writer, buffer, log) {
  if (!buffer || buffer.length === 0) return;
  const MAX_FLUSH_LOOPS = 20;
  let loops = 0;
  while (buffer.length > 0) {
    if (loops >= MAX_FLUSH_LOOPS) break;
    const batch = [...buffer];
    buffer.length = 0;
    for (const chunk of batch) {
      try {
        await safeWrite(writer, chunk);
      } catch (e) {
        throw e;
      }
    }
    loops++;
  }
}
async function remoteSocketToWS(remoteSocket, webSocket, vlessHeader, retryCallback, log) {
  let hasIncomingData = false;
  let responseHeader = vlessHeader;
  const safeSend = (data) => {
    try {
      if (webSocket.readyState === 1) {
        webSocket.send(data);
        return true;
      }
    } catch (error) {
    }
    return false;
  };
  if (remoteSocket.initialData && remoteSocket.initialData.byteLength > 0) {
    hasIncomingData = true;
    if (responseHeader) {
      const combined = new Uint8Array(responseHeader.length + remoteSocket.initialData.length);
      combined.set(responseHeader);
      combined.set(remoteSocket.initialData, responseHeader.length);
      if (!safeSend(combined)) return;
      responseHeader = null;
    } else {
      if (!safeSend(remoteSocket.initialData)) return;
    }
    remoteSocket.initialData = null;
  }
  await remoteSocket.readable.pipeTo(
    new WritableStream({
      async write(chunk, controller) {
        hasIncomingData = true;
        if (webSocket.readyState !== 1) {
          controller.error(new Error("WS Closed"));
          return;
        }
        const dataToSend = responseHeader ? new Uint8Array([...responseHeader, ...chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)]) : chunk;
        responseHeader = null;
        if (!safeSend(dataToSend)) controller.error(new Error("WS send failed"));
      },
      close() {
        log(`Remote socket closed.`);
      },
      abort(reason) {
        void(0);
      }
    })
  ).catch((error) => {
    safeCloseWebSocket(webSocket);
  });
  if (!hasIncomingData && retryCallback) {
    try {
      await retryCallback();
    } catch (e) {
      safeCloseWebSocket(webSocket);
    }
  }
}
async function handleSocks5UDPFlow(controlSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log, finalizeConnectionCallback) {
  const { bndAddr, bndPort, originalHost } = controlSocket;
  let targetHost = bndAddr;
  const cleanBndAddr = bndAddr.replace(/[\[\]]/g, "");
  const isPrivate = isPrivateIP(cleanBndAddr);
  const isZeroIP = bndAddr === "0.0.0.0" || bndAddr === "::" || bndAddr.startsWith("0:0:0:0") || bndAddr === "[::]";
  if ((isZeroIP || isPrivate) && originalHost) {
    targetHost = originalHost;
    log(`[SOCKS5] BND.ADDR is ${bndAddr} (Private/Zero), falling back to proxy host: ${targetHost}`);
  }
  log(`[SOCKS5] UDP Associate ready. Relay: ${targetHost}:${bndPort}`);
  const udpSocket = connect({ hostname: targetHost, port: bndPort });
  finalizeConnectionCallback(udpSocket);
  const udpWriter = udpSocket.writable.getWriter();
  const header = createSocks5UdpHeader(addressType, addressRemote, portRemote);
  if (rawClientData && rawClientData.byteLength > 0) {
    const packet = new Uint8Array(header.length + rawClientData.byteLength);
    packet.set(header);
    packet.set(new Uint8Array(rawClientData), header.length);
    await safeWrite(udpWriter, packet);
  }
  udpWriter.releaseLock();
  let responseHeader = vlessResponseHeader;
  let udpBuffer = new Uint8Array(0);
  await udpSocket.readable.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (webSocket.readyState !== 1) {
        controller.error(new Error("WS Closed"));
        return;
      }
      udpBuffer = concatUint8(udpBuffer, chunk);
      if (udpBuffer.length > 16384) {
        udpBuffer = new Uint8Array(0);
        return;
      }
      while (udpBuffer.length > 0) {
        const headerLen = getSocks5UdpHeaderLength(udpBuffer);
        if (headerLen === 0) {
          udpBuffer = new Uint8Array(0);
          break;
        }
        if (headerLen === -1) {
          break;
        }
        if (udpBuffer.length >= headerLen) {
          const payload = udpBuffer.subarray(headerLen);
          const dataToSend = responseHeader ? new Uint8Array([...responseHeader, ...payload]) : payload;
          responseHeader = null;
          webSocket.send(dataToSend);
          udpBuffer = new Uint8Array(0);
          break;
        } else {
          break;
        }
      }
    },
    close() {
      log("UDP Relay closed");
      controlSocket.close();
    },
    abort(e) {
      controlSocket.close();
    }
  })).catch(() => {
    controlSocket.close();
    safeCloseWebSocket(webSocket);
  });
}
async function handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
  if (isPrivateIP(addressRemote) || isHostBanned(addressRemote, ctx.banHosts)) {
    log(`[Block] TCP request blocked: ${addressRemote} is private or banned.`);
    safeCloseWebSocket(webSocket);
    return;
  }
  const prepareRetry = () => {
    remoteSocketWrapper.value = null;
    remoteSocketWrapper.isConnecting = true;
  };
  const finalizeConnection = (socket) => {
    remoteSocketWrapper.value = socket;
    remoteSocketWrapper.isConnecting = false;
  };
  const nat64Retry = async () => {
    if (!ctx.dns64) {
      safeCloseWebSocket(webSocket);
      return;
    }
    prepareRetry();
    try {
      const v6Address = await resolveToIPv6(addressRemote, ctx.dns64);
      if (!v6Address) throw new Error("DNS64 failed");
      const natSocket = await connectWithTimeout(v6Address, portRemote, 5e3, log);
      const writer = natSocket.writable.getWriter();
      if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
      await flushBuffer(writer, remoteSocketWrapper.buffer, log);
      writer.releaseLock();
      finalizeConnection(natSocket);
      remoteSocketToWS(natSocket, webSocket, vlessResponseHeader, null, log);
    } catch (e) {
      safeCloseWebSocket(webSocket);
    }
  };
  const proxyIPRetry = async () => {
    prepareRetry();
    let ip = getSingleProxyIP(ctx.proxyIP);
    if (!ip) {
      const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map((s) => s.trim()).filter(Boolean);
      if (defParams.length > 0) ip = defParams[0];
    }
    if (ip) {
      try {
        const { host: proxyHost, port: proxyPort } = parseProxyIP(ip, portRemote);
        const proxySocket = await connectWithTimeout(proxyHost.toLowerCase(), proxyPort, 5e3, log);
        const writer = proxySocket.writable.getWriter();
        if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
        await flushBuffer(writer, remoteSocketWrapper.buffer, log);
        writer.releaseLock();
        finalizeConnection(proxySocket);
        const useSocks = ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5);
        const nextRetry = !useSocks && ctx.dns64 ? nat64Retry : null;
        remoteSocketToWS(proxySocket, webSocket, vlessResponseHeader, nextRetry, log);
        return;
      } catch (e) {
      }
    }
    if (ctx.dns64 && !(ctx.socks5 && shouldUseSocks5(addressRemote, ctx.go2socks5))) await nat64Retry();
    else safeCloseWebSocket(webSocket);
  };
  try {
    const socket = await createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log, null, false);
    const writer = socket.writable.getWriter();
    if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
    await flushBuffer(writer, remoteSocketWrapper.buffer, log);
    writer.releaseLock();
    finalizeConnection(socket);
    remoteSocketToWS(socket, webSocket, vlessResponseHeader, proxyIPRetry, log);
  } catch (error) {
    log("[Outbound] TCP Initial failed: " + error.message);
    safeCloseWebSocket(webSocket);
  }
}
async function handleUDPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log) {
  if (isPrivateIP(addressRemote) || isHostBanned(addressRemote, ctx.banHosts)) {
    log(`[Block] UDP request blocked: ${addressRemote} is private or banned.`);
    safeCloseWebSocket(webSocket);
    return;
  }
  const prepareRetry = () => {
    remoteSocketWrapper.value = null;
    remoteSocketWrapper.isConnecting = true;
  };
  const finalizeConnection = (socket) => {
    remoteSocketWrapper.value = socket;
    remoteSocketWrapper.isConnecting = false;
  };
  const nat64Retry = async () => {
    if (!ctx.dns64) {
      safeCloseWebSocket(webSocket);
      return;
    }
    prepareRetry();
    try {
      const v6Address = await resolveToIPv6(addressRemote, ctx.dns64);
      if (!v6Address) throw new Error("DNS64 failed");
      const natSocket = await connectWithTimeout(v6Address, portRemote, 5e3, log);
      const writer = natSocket.writable.getWriter();
      if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
      await flushBuffer(writer, remoteSocketWrapper.buffer, log);
      writer.releaseLock();
      finalizeConnection(natSocket);
      remoteSocketToWS(natSocket, webSocket, vlessResponseHeader, null, log);
    } catch (e) {
      safeCloseWebSocket(webSocket);
    }
  };
  const proxyIPRetry = async () => {
    prepareRetry();
    let ip = getSingleProxyIP(ctx.proxyIP);
    if (!ip) {
      const defParams = CONSTANTS.DEFAULT_PROXY_IP.split(/[,;\n]/).map((s) => s.trim()).filter(Boolean);
      if (defParams.length > 0) ip = defParams[0];
    }
    if (ip) {
      const { host: proxyHost, port: proxyPort } = parseProxyIP(ip, portRemote);
      try {
        const socksConfig = { hostname: proxyHost, port: proxyPort, username: "", password: "" };
        const connectionObj = await socks5Connect(socksConfig, addressType, addressRemote, portRemote, log, true);
        if (connectionObj.isUdpControl) {
          await handleSocks5UDPFlow(connectionObj, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log, finalizeConnection);
          return;
        }
      } catch (socksErr) {
      }
      try {
        const proxySocket = await connectWithTimeout(proxyHost.toLowerCase(), proxyPort, 5e3, log);
        const writer = proxySocket.writable.getWriter();
        if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
        await flushBuffer(writer, remoteSocketWrapper.buffer, log);
        writer.releaseLock();
        finalizeConnection(proxySocket);
        remoteSocketToWS(proxySocket, webSocket, vlessResponseHeader, null, log);
        return;
      } catch (e) {
      }
    }
    if (ctx.dns64) await nat64Retry();
    else safeCloseWebSocket(webSocket);
  };
  try {
    const connectionObj = await createUnifiedConnection(ctx, addressRemote, portRemote, addressType, log, null, true);
    if (connectionObj.isUdpControl) {
      await handleSocks5UDPFlow(connectionObj, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log, finalizeConnection);
    } else {
      const socket = connectionObj;
      const writer = socket.writable.getWriter();
      if (rawClientData && rawClientData.byteLength > 0) await safeWrite(writer, rawClientData);
      await flushBuffer(writer, remoteSocketWrapper.buffer, log);
      writer.releaseLock();
      finalizeConnection(socket);
      remoteSocketToWS(socket, webSocket, vlessResponseHeader, proxyIPRetry, log);
    }
  } catch (error) {
    log("[Outbound:UDP] Initial failed: " + error.message);
    await proxyIPRetry();
  }
}

var protocolManager = new ProtocolManager().register("vless", processVlessHeader).register("trojan", parseTrojanHeader).register("mandala", parseMandalaHeader).register("socks5", parseSocks5Header).register("ss", parseShadowsocksHeader);
var activeConnectionsInInstance = 0;
function concatUint82(a, b) {
  const bArr = b instanceof Uint8Array ? b : new Uint8Array(b);
  const res = new Uint8Array(a.length + bArr.length);
  res.set(a);
  res.set(bArr, a.length);
  return res;
}
function getDynamicBufferSize() {
  if (activeConnectionsInInstance < 5) return 10 * 1024 * 1024;
  if (activeConnectionsInInstance < 20) return 2 * 1024 * 1024;
  if (activeConnectionsInInstance < 50) return 512 * 1024;
  return 128 * 1024;
}
async function handleWebSocketRequest(request, ctx) {
  if (activeConnectionsInInstance >= CONSTANTS.MAX_CONCURRENT) {
    void(0);
    return new Response("Error: Instance Too Busy (Rate Limit)", { status: 429 });
  }
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  try {
    webSocket.accept();
  } catch (e) {
    void(0);
    return new Response("WebSocket Accept Failed", { status: 500 });
  }
  activeConnectionsInInstance++;
  let remoteSocketWrapper = { value: null, isConnecting: false, buffer: [], bufferedBytes: 0 };
  let isConnected = false;
  let socks5State = 0;
  let vlessBuffer = new Uint8Array(0);
  let activeWriter = null;
  let activeSocket = null;
  const MAX_HEADER_BUFFER = 2048;
  const PROBE_THRESHOLD = 1024;
  const DETECT_TIMEOUT_MS = 1e4;
  const log = (info, event) => void(0);
  const timeoutTimer = setTimeout(() => {
    if (!isConnected) {
      log("Timeout: Protocol detection took too long");
      safeCloseWebSocket(webSocket);
    }
  }, DETECT_TIMEOUT_MS);
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  const streamPromise = readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      const chunkArr = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
      if (isConnected) {
        if (activeSocket !== remoteSocketWrapper.value) {
          if (activeWriter) {
            try {
              await activeWriter.ready;
              activeWriter.releaseLock();
            } catch (e) {
            }
            activeWriter = null;
          }
          activeSocket = remoteSocketWrapper.value;
          if (activeSocket) {
            try {
              activeWriter = activeSocket.writable.getWriter();
            } catch (e) {
              safeCloseWebSocket(webSocket);
              return;
            }
          }
        }
        if (activeWriter) {
          await activeWriter.write(chunkArr);
        } else if (remoteSocketWrapper.isConnecting) {
          if (remoteSocketWrapper.buffer.length === 0) {
            remoteSocketWrapper.bufferedBytes = 0;
          }
          const newSize = remoteSocketWrapper.bufferedBytes + chunkArr.byteLength;
          const dynamicLimit = getDynamicBufferSize();
          if (newSize > dynamicLimit) {
            clearTimeout(timeoutTimer);
            throw new Error(`Smart Buffer Limit Exceeded: ${newSize} > ${dynamicLimit} (ActiveConns: ${activeConnectionsInInstance})`);
          }
          remoteSocketWrapper.buffer.push(chunkArr);
          remoteSocketWrapper.bufferedBytes = newSize;
        }
        return;
      }
      vlessBuffer = concatUint82(vlessBuffer, chunkArr);
      if (vlessBuffer.length > MAX_HEADER_BUFFER) {
        clearTimeout(timeoutTimer);
        throw new Error(`Header buffer limit exceeded`);
      }
      if (socks5State < 2) {
        const { consumed, newState, error } = tryHandleSocks5Handshake(vlessBuffer, socks5State, webSocket, ctx, log);
        if (error) {
          clearTimeout(timeoutTimer);
          throw new Error(error);
        }
        if (consumed > 0) {
          vlessBuffer = vlessBuffer.slice(consumed);
          socks5State = newState;
          if (socks5State !== 2) return;
        }
      }
      if (vlessBuffer.length === 0) return;
      try {
        const result = await protocolManager.detect(vlessBuffer, ctx);
        if (socks5State === 2 && result.protocol !== "socks5") {
          throw new Error("Protocol mismatch after Socks5 handshake");
        }
        const pName = result.protocol;
        const isSocksDisabled = pName === "socks5" && ctx.disabledProtocols.includes("socks");
        if (ctx.disabledProtocols.includes(pName) || isSocksDisabled) {
          throw new Error(`Protocol ${pName} is disabled`);
        }
        const { protocol, addressRemote, portRemote, addressType, rawDataIndex, isUDP } = result;
        log(`Detected: ${protocol.toUpperCase()} -> ${addressRemote}:${portRemote}`);
        if (isHostBanned(addressRemote, ctx.banHosts)) {
          throw new Error(`Blocked: ${addressRemote}`);
        }
        isConnected = true;
        clearTimeout(timeoutTimer);
        remoteSocketWrapper.isConnecting = true;
        let clientData = vlessBuffer;
        let responseHeader = null;
        if (protocol === "vless") {
          clientData = vlessBuffer.subarray(rawDataIndex);
          responseHeader = new Uint8Array([result.cloudflareVersion[0], 0]);
        } else if (protocol === "trojan" || protocol === "ss" || protocol === "mandala") {
          clientData = result.rawClientData;
        } else if (protocol === "socks5") {
          clientData = result.rawClientData;
          webSocket.send(new Uint8Array([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
          socks5State = 3;
        }
        vlessBuffer = null;
        if (isUDP) {
          handleUDPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);
        } else {
          handleTCPOutBound(ctx, remoteSocketWrapper, addressType, addressRemote, portRemote, clientData, webSocket, responseHeader, log);
        }
      } catch (e) {
        if (vlessBuffer && vlessBuffer.length < PROBE_THRESHOLD && vlessBuffer.length < MAX_HEADER_BUFFER) {
          return;
        }
        clearTimeout(timeoutTimer);
        log(`Detection failed: ${e.message}`);
        safeCloseWebSocket(webSocket);
      }
    },
    close() {
      cleanup();
    },
    abort(reason) {
      cleanup();
      safeCloseWebSocket(webSocket);
    }
  })).catch((err) => {
    clearTimeout(timeoutTimer);
    cleanup();
    safeCloseWebSocket(webSocket);
  });
  function cleanup() {
    if (activeWriter) {
      try {
        activeWriter.releaseLock();
      } catch (e) {
      }
      activeWriter = null;
    }
    if (remoteSocketWrapper.value) {
      try {
        remoteSocketWrapper.value.close();
      } catch (e) {
      }
      remoteSocketWrapper.value = null;
    }
  }
  if (ctx.waitUntil) {
    ctx.waitUntil(streamPromise.finally(() => {
      activeConnectionsInInstance--;
      if (activeConnectionsInInstance < 0) activeConnectionsInInstance = 0;
    }));
  } else {
    streamPromise.finally(() => {
      activeConnectionsInInstance--;
      if (activeConnectionsInInstance < 0) activeConnectionsInInstance = 0;
    });
  }
  return new Response(null, { status: 101, webSocket: client });
}
function tryHandleSocks5Handshake(buffer, currentState, webSocket, ctx, log) {
  const res = { consumed: 0, newState: currentState, error: null };
  if (buffer.length === 0) return res;
  if (currentState === 0) {
    if (buffer[0] !== 5) return res;
    if (buffer.length < 2) return res;
    const nMethods = buffer[1];
    if (buffer.length < 2 + nMethods) return res;
    const methods = buffer.subarray(2, 2 + nMethods);
    let hasAuth = false;
    for (let m of methods) {
      if (m === 2) hasAuth = true;
    }
    if (hasAuth) {
      webSocket.send(new Uint8Array([5, 2]));
      res.newState = 1;
    } else {
      webSocket.send(new Uint8Array([5, 255]));
      res.error = "Socks5: No supported auth method";
      return res;
    }
    res.consumed = 2 + nMethods;
    return res;
  }
  if (currentState === 1) {
    if (buffer.length < 3) return res;
    if (buffer[0] !== 1) {
      res.error = "Socks5 Auth: Wrong version";
      return res;
    }
    let offset = 1;
    const uLen = buffer[offset++];
    if (buffer.length < offset + uLen + 1) return res;
    const user = new TextDecoder().decode(buffer.subarray(offset, offset + uLen));
    offset += uLen;
    const pLen = buffer[offset++];
    if (buffer.length < offset + pLen) return res;
    const pass = new TextDecoder().decode(buffer.subarray(offset, offset + pLen));
    offset += pLen;
    const isValid = (user === ctx.userID || user === ctx.dynamicUUID) && (pass === ctx.dynamicUUID || pass === ctx.userID);
    if (isValid) {
      webSocket.send(new Uint8Array([1, 0]));
      res.newState = 2;
      res.consumed = offset;
    } else {
      webSocket.send(new Uint8Array([1, 1]));
      res.error = `Socks5 Auth Failed: ${user}`;
    }
    return res;
  }
  return res;
}
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  let isStreamClosed = false;
  return new ReadableStream({
    start(controller) {
      const safeEnqueue = (chunk) => {
        if (readableStreamCancel || isStreamClosed) return;
        try {
          controller.enqueue(chunk);
        } catch (e) {
        }
      };
      const safeClose = () => {
        if (readableStreamCancel || isStreamClosed) return;
        try {
          controller.close();
          isStreamClosed = true;
        } catch (e) {
        }
      };
      const safeError = (e) => {
        if (readableStreamCancel || isStreamClosed) return;
        try {
          controller.error(e);
          isStreamClosed = true;
        } catch (err) {
        }
      };
      webSocketServer.addEventListener("message", (event) => {
        const data = typeof event.data === "string" ? new TextEncoder().encode(event.data) : event.data;
        safeEnqueue(data);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        safeClose();
      });
      webSocketServer.addEventListener("error", (err) => {
        safeError(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) safeError(error);
      else if (earlyData) safeEnqueue(earlyData);
    },
    cancel() {
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    }
  });
}

async function safe_cancel(reader, reason) {
  if (!reader) return;
  try {
    await reader.cancel(reason);
  } catch (_) {
  }
}
async function safe_read(reader, deadline) {
  if (!reader) return { done: true };
  const remainingTime = deadline - Date.now();
  if (remainingTime <= 0) {
    return { done: true, error: new Error("Read timeout") };
  }
  let timeoutId;
  const timeoutPromise = new Promise((resolve) => {
    timeoutId = setTimeout(() => resolve({ timeout: true }), remainingTime);
  });
  try {
    const result = await Promise.race([reader.read(), timeoutPromise]);
    if (result.timeout) {
      return { done: true, error: new Error("Read timeout") };
    }
    return result;
  } catch (e) {
    const msg = (e.message || "").toLowerCase();
    if (msg.includes("cancelled") || msg.includes("aborted") || msg.includes("closed")) {
      return { done: true };
    }
    throw e;
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}
async function read_at_least(reader, minBytes, initialBuffer, deadline) {
  let chunks = [];
  let totalLength = 0;
  if (initialBuffer && initialBuffer.byteLength > 0) {
    chunks.push(initialBuffer);
    totalLength += initialBuffer.byteLength;
  }
  while (totalLength < minBytes) {
    const { value, done, error } = await safe_read(reader, deadline);
    if (error) throw error;
    if (done) break;
    if (value && value.byteLength > 0) {
      chunks.push(value);
      totalLength += value.byteLength;
    }
  }
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
  const deadline = Date.now() + 3e3;
  try {
    let { value: cache, done } = await read_at_least(reader, 18, null, deadline);
    if (cache.length < 18) throw new Error("header too short");
    const version = cache[0];
    const uuidStr = stringifyUUID(cache.subarray(1, 17));
    const expectedID = ctx.userID;
    const expectedIDLow = ctx.userIDLow;
    if (uuidStr !== expectedID && (!expectedIDLow || uuidStr !== expectedIDLow)) {
      throw new Error("invalid UUID");
    }
    const pb_len = cache[17];
    const min_len_until_atyp = 22 + pb_len;
    if (cache.length < min_len_until_atyp) {
      const r = await read_at_least(reader, min_len_until_atyp, cache, deadline);
      cache = r.value;
      if (cache.length < min_len_until_atyp) throw new Error("header too short for metadata");
    }
    const cmdIndex = 18 + pb_len;
    if (cache[cmdIndex] !== 1) throw new Error("unsupported command: " + cache[cmdIndex]);
    const portIndex = cmdIndex + 1;
    const view = new DataView(cache.buffer, cache.byteOffset, cache.byteLength);
    const port = view.getUint16(portIndex, false);
    const atype = cache[portIndex + 2];
    const addr_body_idx = portIndex + 3;
    let header_len = -1;
    if (atype === CONSTANTS.ADDRESS_TYPE_IPV4) {
      header_len = addr_body_idx + 4;
    } else if (atype === CONSTANTS.ADDRESS_TYPE_IPV6) {
      header_len = addr_body_idx + 16;
    } else if (atype === CONSTANTS.ADDRESS_TYPE_URL) {
      if (cache.length < addr_body_idx + 1) {
        const r = await read_at_least(reader, addr_body_idx + 1, cache, deadline);
        cache = r.value;
        if (cache.length < addr_body_idx + 1) throw new Error("header too short for domain len");
      }
      header_len = addr_body_idx + 1 + cache[addr_body_idx];
    } else {
      throw new Error("unknown address type: " + atype);
    }
    if (cache.length < header_len) {
      const r = await read_at_least(reader, header_len, cache, deadline);
      cache = r.value;
      if (cache.length < header_len) throw new Error("header too short for full address");
    }
    let hostname = "";
    const addr_val_idx = addr_body_idx;
    try {
      if (atype === CONSTANTS.ADDRESS_TYPE_IPV4) {
        hostname = cache.subarray(addr_val_idx, addr_val_idx + 4).join(".");
      } else if (atype === CONSTANTS.ADDRESS_TYPE_URL) {
        const domain_len = cache[addr_val_idx];
        hostname = textDecoder.decode(cache.subarray(addr_val_idx + 1, addr_val_idx + 1 + domain_len));
      } else if (atype === CONSTANTS.ADDRESS_TYPE_IPV6) {
        const ipv6 = [];
        for (let i = 0; i < 8; i++) ipv6.push(view.getUint16(addr_val_idx + i * 2, false).toString(16));
        hostname = ipv6.join(":");
      }
    } catch (e) {
      throw new Error("failed to parse hostname");
    }
    if (!hostname) throw new Error("empty hostname");
    return {
      hostname,
      port,
      atype,
      data: cache.subarray(header_len),
      resp: new Uint8Array([version, 0]),
      reader,
      done: done && cache.subarray(header_len).length === 0
    };
  } catch (error) {
    await safe_cancel(reader, error.message);
    throw error;
  }
}
async function upload_to_remote_xhttp(writer, httpx) {
  if (httpx.data && httpx.data.length > 0) {
    await writer.write(httpx.data);
  }
  if (httpx.done) return;
  while (true) {
    try {
      const { value, done } = await httpx.reader.read();
      if (done) break;
      if (value) await writer.write(value);
    } catch (e) {
      break;
    }
  }
}
function create_xhttp_downloader(resp, remote_readable, initialData) {
  const IDLE_TIMEOUT_MS = CONSTANTS.IDLE_TIMEOUT_MS || 45e3;
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
          try {
            monitorStream.writable.abort("idle timeout");
          } catch (_) {
          }
          try {
            monitorStream.readable.cancel("idle timeout");
          } catch (_) {
          }
          clearInterval(idleTimer);
        }
      }, 5e3);
    },
    transform(chunk, controller) {
      lastActivity = Date.now();
      controller.enqueue(chunk);
    },
    flush() {
      clearInterval(idleTimer);
    },
    cancel() {
      clearInterval(idleTimer);
    }
  });
  const pipePromise = remote_readable.pipeTo(monitorStream.writable).catch(() => {
  });
  return {
    readable: monitorStream.readable,
    done: pipePromise,
    abort: () => {
      try {
        monitorStream.writable.abort();
      } catch (_) {
      }
      try {
        monitorStream.readable.cancel();
      } catch (_) {
      }
      clearInterval(idleTimer);
    }
  };
}
async function handleXhttpClient(request, ctx) {
  let result;
  try {
    result = await read_xhttp_header(request.body, ctx);
  } catch (e) {
    const errStr = e.message || "";
    if (!errStr.includes("header too short") && !errStr.includes("invalid UUID")) {
      void(0);
    }
    return null;
  }
  const { hostname, port, atype, data, resp, reader, done } = result;
  if (isHostBanned(hostname, ctx.banHosts)) {
    void(0);
    await safe_cancel(reader, "blocked");
    return null;
  }
  let remoteSocket;
  try {
    remoteSocket = await createUnifiedConnection(ctx, hostname, port, atype, (()=>{}), ctx.proxyIP);
  } catch (e) {
    void(0);
    await safe_cancel(reader, "connect failed");
    return null;
  }
  const uploaderPromise = (async () => {
    let writer = null;
    try {
      writer = remoteSocket.writable.getWriter();
      await upload_to_remote_xhttp(writer, { data, done, reader });
    } catch (e) {
    } finally {
      if (writer) try {
        await writer.close();
      } catch (_) {
      }
      await safe_cancel(reader, "upload finished");
    }
  })();
  const downloader = create_xhttp_downloader(resp, remoteSocket.readable, remoteSocket.initialData);
  const connectionClosed = Promise.allSettled([downloader.done, uploaderPromise]).then(() => {
    try {
      remoteSocket.close();
    } catch (_) {
    }
    downloader.abort();
  });
  return {
    readable: downloader.readable,
    closed: connectionClosed
  };
}

function getAdminConfigHtml(FileName, formHtml) {
  const ADMIN_CSS = `
    <style>
    :root{--bs-primary:#0d6efd;--bs-secondary:#6c757d;--bs-info:#0dcaf0}
    body{font-family:system-ui,-apple-system,sans-serif;background-color:#f8f9fa;color:#212529;margin:0;line-height:1.5}
    .container{max-width:800px;margin:20px auto;background-color:#fff;padding:2rem;border-radius:8px;box-shadow:0 0 10px rgba(0,0,0,.05)}
    h2{margin-top:0;margin-bottom:.5rem}
    code{color:#d63384}
    .form-text{font-size:0.875em;color:#6c757d;display:block;margin-top:.25rem}
    .env-hint{font-size:0.8em;color:#6c757d;margin-top:4px}
    .btn-group{display:flex;gap:10px;margin-top:1rem}
    .save-status{margin-left:15px;color:#666;align-self:center}
    /* \u6A21\u62DF Bootstrap \u8868\u5355\u6837\u5F0F */
    .mb-3 { margin-bottom: 1rem; }
    label { display: inline-block; margin-bottom: .5rem; font-weight: 500; }
    .form-control { display: block; width: 100%; padding: .375rem .75rem; font-size: 1rem; line-height: 1.5; color: #212529; background-color: #fff; border: 1px solid #ced4da; border-radius: .375rem; box-sizing: border-box; transition: border-color .15s; }
    .form-control:focus { border-color: #86b7fe; outline: 0; box-shadow: 0 0 0 .25rem rgba(13,110,253,.25); }
    textarea.form-control { font-family: monospace; font-size: 0.9em; min-height: 100px; }
    /* \u6A21\u62DF Bootstrap \u6309\u94AE\u6837\u5F0F */
    .btn { display: inline-block; font-weight: 400; line-height: 1.5; text-align: center; text-decoration: none; vertical-align: middle; cursor: pointer; user-select: none; border: 1px solid transparent; padding: .375rem .75rem; font-size: 1rem; border-radius: .375rem; transition: all .15s ease-in-out; }
    .btn-primary { color: #fff; background-color: #0d6efd; border-color: #0d6efd; } .btn-primary:hover { background-color: #0b5ed7; }
    .btn-secondary { color: #fff; background-color: #6c757d; border-color: #6c757d; } .btn-secondary:hover { background-color: #5c636a; }
    .btn-info { color: #000; background-color: #0dcaf0; border-color: #0dcaf0; } .btn-info:hover { background-color: #31d2f2; }
    .btn:disabled { opacity: .65; pointer-events: none; }
    </style>`;
  return `<!DOCTYPE html><html><head><title>\u914D\u7F6E\u7BA1\u7406</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">${ADMIN_CSS}</head><body><div class="container"><h2>${FileName} \u914D\u7F6E\u8BBE\u7F6E</h2><p>\u5728\u6B64\u9875\u9762\u4FEE\u6539\u7684\u914D\u7F6E\u5C06\u4FDD\u5B58\u5728KV\u4E2D, \u4F18\u5148\u7EA7: <b>KV > \u73AF\u5883\u53D8\u91CF</b>\u3002\u5982\u679C\u67D0\u9879\u7559\u7A7A\u5E76\u4FDD\u5B58, \u5219\u8BE5\u9879\u914D\u7F6E\u5C06\u56DE\u9000\u5230\u4F7F\u7528\u4E0B\u7EA7\u914D\u7F6E\u6216\u9ED8\u8BA4\u503C\u3002</p><form id="config-form">` + formHtml + '<div class="btn-group"><button type="button" class="btn btn-secondary" onclick="goBack()">\u8FD4\u56DE\u914D\u7F6E\u9875</button><button type="button" class="btn btn-info" onclick="goBestIP()">\u5728\u7EBF\u4F18\u9009IP</button><button type="submit" class="btn btn-primary" id="save-btn">\u4FDD\u5B58\u6240\u6709\u914D\u7F6E</button><span class="save-status" id="saveStatus"></span></div></form><script>function goBack(){const e=window.location.pathname.substring(0,window.location.pathname.lastIndexOf("/"));window.location.href=e+"/"}function goBestIP(){window.location.href=window.location.pathname.replace("/edit","/bestip")}document.getElementById("config-form").addEventListener("submit",function(e){e.preventDefault();const t=document.getElementById("save-btn"),n=document.getElementById("saveStatus"),o=new FormData(this),a=o.get("BESTIP_SOURCES");if(a){const lines=a.split("\\n");for(let i=0;i<lines.length;i++){const line=lines[i].trim();if(!line)continue;const parts=line.split(/\\s+/);if(parts.length<2){return alert("\u4FDD\u5B58\u5931\u8D25: BestIP IP\u6E90 \u683C\u5F0F\u9519\u8BEF (\u7B2C"+(i+1)+"\u884C)\u3002\\n\u5E94\u4E3A: \u540D\u79F0 \u7F51\u5740"),n.textContent="\u4FDD\u5B58\u51FA\u9519: \u683C\u5F0F\u9519\u8BEF",void 0}}}t.disabled=!0,t.textContent="\u4FDD\u5B58\u4E2D...",n.textContent="",fetch(window.location.href,{method:"POST",body:o}).then(e=>{if(e.ok){const o=(new Date).toLocaleString();n.textContent="\u4FDD\u5B58\u6210\u529F "+o,alert("\u4FDD\u5B58\u6210\u529F\uFF01\u90E8\u5206\u8BBE\u7F6E\u53EF\u80FD\u9700\u8981\u51E0\u79D2\u949F\u751F\u6548\u3002")}else return e.text().then(e=>Promise.reject(e))}).catch(e=>{n.textContent="\u4FDD\u5B58\u51FA\u9519: "+e}).finally(()=>{t.disabled=!1,t.textContent="\u4FDD\u5B58\u6240\u6709\u914D\u7F6E"})});<\/script></body></html>';
}
function getBestIPHtml(ipSourceOptions) {
  return `<!DOCTYPE html><html><head><title>Cloudflare IP\u4F18\u9009</title><style>body{width:80%;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;padding:20px}.ip-list{background-color:#f5f5f5;padding:10px;border-radius:5px;max-height:400px;overflow-y:auto}.ip-item{margin:2px 0;font-family:monospace}.stats{background-color:#e3f2fd;padding:15px;border-radius:5px;margin:20px 0}.test-controls{margin-bottom:20px}.button-group{display:flex;gap:10px}.test-button,.save-button,.append-button,.edit-button,.back-button{background-color:#4CAF50;color:white;padding:15px 32px;text-align:center;text-decoration:none;display:inline-block;font-size:16px;cursor:pointer;border:none;border-radius:4px}.save-button{background-color:#2196F3}.append-button{background-color:#FF9800}.edit-button{background-color:#9C27B0}.back-button{background-color:#607D8B}.test-button:disabled,.save-button:disabled,.append-button:disabled{background-color:#cccccc;cursor:not-allowed}.message{padding:10px;margin:10px 0;border-radius:4px;display:none}.message.success{background-color:#d4edda;color:#155724}.message.error{background-color:#f8d7da;color:#721c24}.progress{width:100%;background-color:#f0f0f0;border-radius:5px;margin-top:10px}.progress-bar{width:0%;height:20px;background-color:#4CAF50;border-radius:5px;transition:width .3s;text-align:center;color:white;line-height:20px}.good-latency{color:#4CAF50;font-weight:700}.medium-latency{color:#FF9800;font-weight:700}.bad-latency{color:#f44336;font-weight:700}</style></head><body><h1>\u5728\u7EBF\u4F18\u9009IP</h1><div class="test-controls"><div class="port-selector"style="margin-bottom:10px"><label for="ip-source-select">IP\u5E93\uFF1A</label><select id="ip-source-select">${ipSourceOptions}</select> <label for="port-select">\u7AEF\u53E3\uFF1A</label><select id="port-select"><option value="443">443</option><option value="2053">2053</option><option value="2083">2083</option><option value="2087">2087</option><option value="2096">2096</option><option value="8443">8443</option></select></div><div class="button-group"><button class="test-button" id="test-btn">\u5F00\u59CB\u5EF6\u8FDF\u6D4B\u8BD5</button><button class="save-button" id="save-btn" disabled>\u8986\u76D6\u4FDD\u5B58\u4F18\u9009IP</button><button class="append-button" id="append-btn" disabled>\u8FFD\u52A0\u4FDD\u5B58\u4F18\u9009IP</button><button class="edit-button" onclick="goEdit()">\u7F16\u8F91\u4F18\u9009\u5217\u8868</button><button class="back-button" onclick="goBack()">\u8FD4\u56DE\u914D\u7F6E\u9875</button></div></div><div class="stats"><p><strong>IP\u603B\u6570\uFF1A</strong> <span id="ip-count">0</span></p><p><strong>\u6D4B\u8BD5\u8FDB\u5EA6\uFF1A</strong> <span id="progress-text">\u672A\u5F00\u59CB</span></p><div class="progress"><div class="progress-bar" id="progress-bar"></div></div></div><h2>IP\u5217\u8868 (\u7ED3\u679C\u5DF2\u6309\u5EF6\u8FDF\u6392\u5E8F)</h2><div class="ip-list" id="ip-list">\u8BF7\u9009\u62E9\u7AEF\u53E3\u548CIP\u5E93\uFF0C\u7136\u540E\u70B9\u51FB"\u5F00\u59CB\u5EF6\u8FDF\u6D4B\u8BD5"</div><div id="message" class="message"></div><script>let testResults=[],originalIPs=[];const testBtn=document.getElementById("test-btn"),saveBtn=document.getElementById("save-btn"),appendBtn=document.getElementById("append-btn"),ipList=document.getElementById("ip-list"),ipCount=document.getElementById("ip-count"),progressBar=document.getElementById("progress-bar"),progressText=document.getElementById("progress-text"),portSelect=document.getElementById("port-select"),ipSourceSelect=document.getElementById("ip-source-select");function getBasePath() {return window.location.pathname.substring(0, window.location.pathname.lastIndexOf("/"));}function goEdit(){window.location.href = getBasePath() + "/edit";}function goBack(){window.location.href = getBasePath() + "/";}async function testIP(e,t){const n=Date.now();try{const response = await fetch('?action=test&ip=' + e + '&port=' + t, {method:"GET",signal:AbortSignal.timeout(3e3)});if(response.ok){const data=await response.json();return data}}catch(err){console.error('Test failed for ' + e + ':' + t,err.name,err.message)}return null}async function startTest(){testBtn.disabled=!0,testBtn.textContent="\u6D4B\u8BD5\u4E2D...",saveBtn.disabled=!0,appendBtn.disabled=!0,ipList.innerHTML="\u6B63\u5728\u52A0\u8F7DIP\u5217\u8868...";const e=portSelect.value,t=ipSourceSelect.value;try{const n=(await(await fetch('?loadIPs=' + encodeURIComponent(t) + '&port=' + e)).json()).ips;originalIPs=n,ipCount.textContent=originalIPs.length,testResults=[],ipList.innerHTML="\u5F00\u59CB\u6D4B\u8BD5...",progressBar.style.width="0%",progressBar.textContent="",progressText.textContent="0/0";let o=0;const s=Math.min(32,originalIPs.length);let i=0;await new Promise(e=>{const t=()=>{if(i>=originalIPs.length){if(0==--o)return void e();return}const n=originalIPs[i++];testIP(n,portSelect.value).then(e=>{if(e&&e.colo!=="FAIL"){testResults.push(e)}progressBar.style.width = (100*(i/originalIPs.length)) + '%';progressBar.textContent = Math.round(100*(i/originalIPs.length)) + '%';progressText.textContent = i + '/' + originalIPs.length;t()})};for(let n=0;n<s;n++)o++,t()});testResults.sort((e,t)=>e.latency-t.latency),ipList.innerHTML=testResults.map(function(e) {var latencyClass = e.latency<100 ? "good-latency" : (e.latency<200 ? "medium-latency" : "bad-latency");return '<div class="ip-item ' + latencyClass + '">' + e.ip + ':' + e.port + '#' + e.colo + ' - ' + e.latency + 'ms</div>';}).join(""),saveBtn.disabled=0===testResults.length,appendBtn.disabled=0===testResults.length}catch(e){ipList.innerHTML="\u52A0\u8F7DIP\u5217\u8868\u5931\u8D25",console.error(e)}finally{testBtn.disabled=!1,testBtn.textContent="\u5F00\u59CB\u5EF6\u8FDF\u6D4B\u8BD5"}}async function saveIPs(e){const t=testResults.slice(16).map(function(e) { return e.ip + ':' + e.port + '#' + e.colo; });try{const n=(await(await fetch('?action=' + e,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ips:t})})).json());showMessage(n.message||n.error,n.success)}catch(e){showMessage("\u64CD\u4F5C\u5931\u8D25: "+e.message,!1)}}function showMessage(e,t){const n=document.getElementById("message");n.textContent=e;n.className = 'message ' + (t ? 'success' : 'error');n.style.display="block",setTimeout(()=>{n.style.display="none"},3e3)}testBtn.addEventListener("click",startTest),saveBtn.addEventListener("click",()=>saveIPs("save"));appendBtn.addEventListener("click",()=>saveIPs("append"));<\/script></body></html>`;
}

function generateBase64Subscription(protocol, id, hostName, tlsOnly, ctx, noLinks = false) {
  let finalLinks = [];
  const httpPorts = CONSTANTS.HTTP_PORTS;
  const httpsPorts = ctx.httpsPorts;
  const path = "/?ed=2560";
  const createLink = (addr, useTls) => {
    const portList = useTls ? httpsPorts : httpPorts;
    const match = addr.match(/^(.*?)(?::(\d+))?(?:#(.*))?$/);
    if (!match) return;
    const ip = match[1];
    const port = match[2] || portList[0];
    const remark = match[3] || `${hostName}-${protocol.toUpperCase()}`;
    if (protocol === "xhttp") {
      const xhttpPath = "/" + id.substring(0, 8);
      finalLinks.push(`vless://${id}@${ip}:${port}?encryption=none&security=tls&sni=${hostName}&fp=random&type=xhttp&host=${hostName}&path=${encodeURIComponent(xhttpPath)}&mode=stream-one#${encodeURIComponent(remark)}`);
    } else if (protocol === "vless") {
      const security = useTls ? `&security=tls&sni=${hostName}&fp=random` : "&security=none";
      finalLinks.push(`vless://${id}@${ip}:${port}?encryption=none${security}&type=ws&host=${hostName}&path=${encodeURIComponent(path)}#${encodeURIComponent(remark)}`);
    } else if (protocol === "trojan") {
      const security = useTls ? `&security=tls&sni=${hostName}&fp=random` : "&security=none";
      finalLinks.push(`trojan://${id}@${ip}:${port}?${security}&type=ws&host=${hostName}&path=${encodeURIComponent(path)}#${encodeURIComponent(remark)}`);
    } else if (protocol === "mandala") {
      const security = useTls ? `&security=tls&sni=${hostName}` : "";
      finalLinks.push(`mandala://${id}@${ip}:${port}?type=ws&host=${hostName}&path=${encodeURIComponent(path)}${security}#${encodeURIComponent(remark)}`);
    } else if (protocol === "ss") {
      const ss_method = "none";
      const ss_b64 = btoa(`${ss_method}:${id}`);
      let plugin_opts = `v2ray-plugin;host=${hostName};path=${encodeURIComponent(path)}`;
      if (useTls) plugin_opts += `;tls;sni=${hostName}`;
      finalLinks.push(`ss://${ss_b64}@${ip}:${port}/?plugin=${encodeURIComponent(plugin_opts)}#${encodeURIComponent(remark)}`);
    } else if (protocol === "socks") {
      const security = useTls ? `security=tls&sni=${hostName}&path=${encodeURIComponent(path)}` : `path=${encodeURIComponent(path)}`;
      const password = ctx.dynamicUUID || ctx.userID;
      const auth = btoa(`${id}:${password}`);
      finalLinks.push(`socks://${auth}@${ip}:${port}?${security}&transport=ws#${encodeURIComponent(remark)}`);
    }
  };
  if (ctx.addresses) ctx.addresses.forEach((addr) => createLink(addr, true));
  if (!tlsOnly && ctx.addressesnotls) ctx.addressesnotls.forEach((addr) => createLink(addr, false));
  if (!noLinks && protocol !== "xhttp" && ctx.hardcodedLinks) {
    finalLinks = finalLinks.concat(ctx.hardcodedLinks);
  }
  return finalLinks.join("\n");
}
function generateClashConfig(protocol, id, hostName, tlsOnly, ctx) {
  let proxies = [];
  const proxyNames = [];
  const httpPorts = CONSTANTS.HTTP_PORTS;
  const httpsPorts = ctx.httpsPorts;
  const path = "/?ed=2560";
  const createProxy = (addr, useTls) => {
    const portList = useTls ? httpsPorts : httpPorts;
    const match = addr.match(/^(.*?)(?::(\d+))?(?:#(.*))?$/);
    if (!match) return;
    const ip = match[1];
    const port = match[2] || portList[0];
    const remark = match[3] || `${hostName}-${protocol.toUpperCase()}`;
    let proxy = {
      name: remark,
      type: protocol === "xhttp" ? "vless" : protocol === "ss" ? "ss" : protocol === "socks" ? "socks5" : protocol,
      server: ip,
      port: parseInt(port),
      tls: useTls,
      "skip-cert-verify": true,
      udp: false
    };
    if (protocol === "vless" || protocol === "xhttp") {
      proxy.uuid = id;
      proxy.cipher = "auto";
    } else if (protocol === "trojan") {
      proxy.password = id;
    } else if (protocol === "ss") {
      proxy.cipher = "none";
      proxy.password = id;
      proxy.plugin = "v2ray-plugin";
      proxy["plugin-opts"] = {
        mode: "websocket",
        tls: useTls,
        host: hostName,
        path
      };
      if (useTls) proxy["plugin-opts"].sni = hostName;
    } else if (protocol === "socks") {
      proxy.username = id;
      proxy.password = ctx.dynamicUUID || ctx.userID;
    }
    if (protocol === "xhttp") {
      proxy.network = "xhttp";
      proxy["xhttp-opts"] = {
        mode: "stream-one",
        path: "/" + id.substring(0, 8),
        headers: {
          "Host": hostName,
          "Content-Type": "application/grpc",
          "User-Agent": "Go-http-client/2.0"
        }
      };
      proxy.servername = hostName;
    } else if (protocol !== "ss" && protocol !== "mandala") {
      proxy.network = "ws";
      proxy["ws-opts"] = {
        path,
        headers: { Host: hostName }
      };
      if (useTls) proxy.servername = hostName;
    }
    if (protocol !== "mandala") {
      proxies.push(proxy);
      proxyNames.push(remark);
    }
  };
  if (ctx.addresses) ctx.addresses.forEach((addr) => createProxy(addr, true));
  if (!tlsOnly && ctx.addressesnotls) ctx.addressesnotls.forEach((addr) => createProxy(addr, false));
  return buildClashYaml(proxies, proxyNames);
}
function generateMixedClashConfig(vlessId, trojanPass, hostName, tlsOnly, enableXhttp, ctx) {
  let proxies = [];
  const proxyNames = [];
  const httpPorts = CONSTANTS.HTTP_PORTS;
  const httpsPorts = ctx.httpsPorts;
  const path = "/?ed=2560";
  const createMixedProxy = (protocol, addr, useTls) => {
    const portList = useTls ? httpsPorts : httpPorts;
    const match = addr.match(/^(.*?)(?::(\d+))?(?:#(.*))?$/);
    if (!match) return;
    const ip = match[1];
    const port = match[2] || portList[0];
    const remark = match[3] ? `${protocol.toUpperCase()}-${match[3]}` : `${hostName}-${protocol.toUpperCase()}`;
    let proxy = {
      name: remark,
      type: protocol === "xhttp" ? "vless" : protocol === "ss" ? "ss" : protocol === "socks" ? "socks5" : protocol,
      server: ip,
      port: parseInt(port),
      tls: useTls,
      "skip-cert-verify": true,
      udp: false
    };
    if (protocol === "vless" || protocol === "xhttp") {
      proxy.uuid = vlessId;
      proxy.cipher = "auto";
    } else if (protocol === "trojan") {
      proxy.password = trojanPass;
    } else if (protocol === "ss") {
      proxy.cipher = "none";
      proxy.password = trojanPass;
      proxy.plugin = "v2ray-plugin";
      proxy["plugin-opts"] = {
        mode: "websocket",
        tls: useTls,
        host: hostName,
        path
      };
      if (useTls) proxy["plugin-opts"].sni = hostName;
    } else if (protocol === "socks") {
      proxy.username = vlessId;
      proxy.password = trojanPass;
    }
    if (protocol === "xhttp") {
      proxy.network = "xhttp";
      proxy["xhttp-opts"] = {
        mode: "stream-one",
        path: "/" + vlessId.substring(0, 8),
        headers: {
          "Host": hostName,
          "Content-Type": "application/grpc",
          "User-Agent": "Go-http-client/2.0"
        }
      };
      proxy.servername = hostName;
    } else if (protocol !== "ss") {
      proxy.network = "ws";
      proxy["ws-opts"] = {
        path,
        headers: { Host: hostName }
      };
      if (useTls) proxy.servername = hostName;
    }
    proxies.push(proxy);
    proxyNames.push(remark);
  };
  let protocols = ["vless", "trojan", "ss", "socks", "xhttp"];
  protocols = protocols.filter((p) => {
    if (ctx.disabledProtocols.includes(p)) return false;
    if (p === "socks" && ctx.disabledProtocols.includes("socks5")) return false;
    return true;
  });
  if (ctx.addresses) {
    ctx.addresses.forEach((addr) => {
      protocols.forEach((p) => {
        if (p === "xhttp") createMixedProxy(p, addr, true);
        else createMixedProxy(p, addr, true);
      });
    });
  }
  if (!tlsOnly && ctx.addressesnotls) {
    ctx.addressesnotls.forEach((addr) => {
      protocols.forEach((p) => {
        if (p !== "xhttp") createMixedProxy(p, addr, false);
      });
    });
  }
  return buildClashYaml(proxies, proxyNames);
}
function buildClashYaml(proxies, proxyNames) {
  const yamlProxies = proxies.map((p) => {
    let s = `- name: ${p.name}
  type: ${p.type}
  server: ${p.server}
  port: ${p.port}
  tls: ${p.tls}
  udp: ${p.udp}
  skip-cert-verify: true
`;
    if (p.uuid) s += `  uuid: ${p.uuid}
`;
    if (p.password) s += `  password: "${p.password}"
`;
    if (p.username) s += `  username: "${p.username}"
`;
    if (p.cipher) s += `  cipher: ${p.cipher}
`;
    if (p.network) s += `  network: ${p.network}
`;
    if (p.servername) s += `  servername: ${p.servername}
`;
    if (p["ws-opts"]) {
      s += `  ws-opts:
    path: "${p["ws-opts"].path}"
    headers:
      Host: ${p["ws-opts"].headers.Host}
`;
    }
    if (p["xhttp-opts"]) {
      s += `  xhttp-opts:
    mode: ${p["xhttp-opts"].mode}
    path: "${p["xhttp-opts"].path}"
    headers:
      Host: ${p["xhttp-opts"].headers.Host}
      Content-Type: ${p["xhttp-opts"].headers["Content-Type"]}
      User-Agent: ${p["xhttp-opts"].headers["User-Agent"]}
`;
    }
    if (p.plugin) {
      s += `  plugin: ${p.plugin}
  plugin-opts:
    mode: ${p["plugin-opts"].mode}
    tls: ${p["plugin-opts"].tls}
    host: ${p["plugin-opts"].host}
    path: "${p["plugin-opts"].path}"
`;
      if (p["plugin-opts"].sni) s += `    sni: ${p["plugin-opts"].sni}
`;
    }
    return s;
  }).join("");
  return `port: 7890
allow-lan: true
mode: rule
log-level: info
proxies:
${yamlProxies}
proxy-groups:
- name: \u8282\u70B9\u9009\u62E9
  type: select
  proxies:
  - \u81EA\u52A8\u9009\u62E9
  - DIRECT
${proxyNames.map((n) => `  - ${n}`).join("\n")}
- name: \u81EA\u52A8\u9009\u62E9
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
${proxyNames.map((n) => `  - ${n}`).join("\n")}
rules:
- MATCH,\u8282\u70B9\u9009\u62E9`;
}
function generateSingBoxConfig(protocol, id, hostName, tlsOnly, ctx) {
  if (protocol === "mandala") return "{}";
  return generateMixedSingBoxConfig(id, ctx.dynamicUUID, hostName, tlsOnly, false, ctx, [protocol]);
}
function generateMixedSingBoxConfig(vlessId, trojanPass, hostName, tlsOnly, enableXhttp, ctx, protocolsFilter = null) {
  let outbounds = [];
  const httpPorts = CONSTANTS.HTTP_PORTS;
  const httpsPorts = ctx.httpsPorts;
  const path = "/?ed=2560";
  const createMixedOutbound = (protocol, addr, useTls) => {
    const portList = useTls ? httpsPorts : httpPorts;
    const match = addr.match(/^(.*?)(?::(\d+))?(?:#(.*))?$/);
    if (!match) return;
    const ip = match[1];
    const port = match[2] || portList[0];
    const remark = match[3] ? `${protocol.toUpperCase()}-${match[3]}` : `${hostName}-${protocol.toUpperCase()}`;
    let outbound = {
      type: protocol === "xhttp" ? "vless" : protocol === "ss" ? "shadowsocks" : protocol === "socks" ? "socks5" : protocol,
      tag: remark,
      server: ip,
      server_port: parseInt(port)
    };
    if (protocol === "vless" || protocol === "xhttp") {
      outbound.uuid = vlessId;
      outbound.packet_encoding = "packetaddr";
    } else if (protocol === "trojan") {
      outbound.password = trojanPass;
    } else if (protocol === "ss") {
      outbound.method = "none";
      outbound.password = trojanPass;
    } else if (protocol === "socks") {
      outbound.username = vlessId;
      outbound.password = trojanPass;
    }
    if (protocol === "xhttp") {
      outbound.transport = {
        type: "xhttp",
        mode: "stream-one",
        path: "/" + vlessId.substring(0, 8),
        headers: {
          Host: hostName,
          "Content-Type": "application/grpc",
          "User-Agent": "Go-http-client/2.0"
        }
      };
    } else {
      outbound.transport = {
        type: "ws",
        path,
        headers: { Host: hostName }
      };
    }
    if (useTls) {
      outbound.tls = {
        enabled: true,
        server_name: hostName,
        insecure: true,
        utls: { enabled: true, fingerprint: "chrome" }
      };
    }
    outbounds.push(outbound);
  };
  let protocols = [];
  if (protocolsFilter) {
    protocols = protocolsFilter;
  } else {
    const all = ["vless", "trojan", "ss", "socks", "xhttp"];
    protocols = all.filter((p) => {
      if (ctx.disabledProtocols.includes(p)) return false;
      if (p === "socks" && ctx.disabledProtocols.includes("socks5")) return false;
      return true;
    });
  }
  if (ctx.addresses) {
    ctx.addresses.forEach((addr) => {
      protocols.forEach((p) => {
        if (p === "xhttp") createMixedOutbound(p, addr, true);
        else createMixedOutbound(p, addr, true);
      });
    });
  }
  if (!tlsOnly && ctx.addressesnotls) {
    ctx.addressesnotls.forEach((addr) => {
      protocols.forEach((p) => {
        if (p !== "xhttp") createMixedOutbound(p, addr, false);
      });
    });
  }
  const tags = outbounds.map((o) => o.tag);
  return JSON.stringify({
    "log": { "level": "info" },
    "inbounds": [{ "type": "tun", "tag": "tun-in" }],
    "outbounds": [
      {
        "type": "selector",
        "tag": "select",
        "outbounds": ["auto", "direct", ...tags]
      },
      {
        "type": "urltest",
        "tag": "auto",
        "outbounds": tags,
        "url": "http://www.gstatic.com/generate_204"
      },
      { "type": "direct", "tag": "direct" },
      ...outbounds
    ],
    "route": {
      "final": "select",
      "rules": [
        { "protocol": "dns", "outbound": "direct" }
      ]
    }
  }, null, 2);
}

async function fetchAndParseAPI(apiUrl, httpsPorts) {
  if (!apiUrl) return [];
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5e3);
    const response = await fetch(apiUrl, {
      signal: controller.signal,
      headers: { "User-Agent": "Mozilla/5.0" }
    });
    clearTimeout(timeout);
    if (response.ok) {
      const text = await response.text();
      return await cleanList(text);
    }
  } catch (e) {
    void(0);
  }
  return [];
}
async function fetchAndParseCSV(csvUrl, isTLS, httpsPorts, DLS, remarkIndex) {
  if (!csvUrl) return [];
  try {
    const response = await fetch(csvUrl, { headers: { "User-Agent": "Mozilla/5.0" } });
    if (!response.ok) return [];
    const text = await response.text();
    const lines = text.split(/\r?\n/).filter((l) => l.trim() !== "");
    if (lines.length === 0) return [];
    let headerLine = lines[0];
    if (headerLine.charCodeAt(0) === 65279) {
      headerLine = headerLine.slice(1);
    }
    const header = headerLine.split(",").map((h) => h.trim().toUpperCase());
    const tlsIndex = header.indexOf("TLS");
    if (tlsIndex === -1) {
      void(0);
      return [];
    }
    const results = [];
    for (let i = 1; i < lines.length; i++) {
      const columns = lines[i].split(",");
      if (columns.length > tlsIndex && columns[tlsIndex]) {
        const tlsValue = columns[tlsIndex].trim().toUpperCase();
        if (tlsValue === (isTLS ? "TRUE" : "FALSE")) {
          const speed = parseFloat(columns[columns.length - 1]);
          if (speed > DLS) {
            const ip = columns[0].trim();
            const port = columns[1].trim();
            const remark = (columns[tlsIndex + remarkIndex] || "CSV").trim();
            results.push(`${ip}:${port}#${remark}`);
          }
        }
      }
    }
    return results;
  } catch (e) {
    void(0);
  }
  return [];
}
async function fetchRemoteNodes(env, ctx, apiLinks, noTlsApiLinks, csvLinks, DLS, remarkIndex) {
  let remoteAddresses = [];
  let remoteAddressesNoTls = [];
  if (apiLinks.length > 0) {
    const results = await Promise.all(apiLinks.map((url) => fetchAndParseAPI(url, ctx.httpsPorts)));
    results.forEach((res) => remoteAddresses.push(...res));
  }
  if (noTlsApiLinks.length > 0) {
    const results = await Promise.all(noTlsApiLinks.map((url) => fetchAndParseAPI(url, CONSTANTS.HTTP_PORTS)));
    results.forEach((res) => remoteAddressesNoTls.push(...res));
  }
  if (csvLinks.length > 0) {
    const [resTLS, resNoTLS] = await Promise.all([
      Promise.all(csvLinks.map((url) => fetchAndParseCSV(url, true, ctx.httpsPorts, DLS, remarkIndex))),
      Promise.all(csvLinks.map((url) => fetchAndParseCSV(url, false, ctx.httpsPorts, DLS, remarkIndex)))
    ]);
    resTLS.forEach((r) => remoteAddresses.push(...r));
    resNoTLS.forEach((r) => remoteAddressesNoTls.push(...r));
  }
  return {
    addresses: remoteAddresses,
    addressesnotls: remoteAddressesNoTls
  };
}
async function getCachedRemoteNodes(env, ctx, apiLinks, noTlsApiLinks, csvLinks, DLS, remarkIndex) {
  const cacheKey = "SUB_REMOTE_CACHE";
  const CACHE_TTL2 = 3600 * 1e3;
  const doRefresh = async () => {
    const data = await fetchRemoteNodes(env, ctx, apiLinks, noTlsApiLinks, csvLinks, DLS, remarkIndex);
    const entry = { ts: Date.now(), data };
    if (env.KV) await env.KV.put(cacheKey, JSON.stringify(entry));
    return data;
  };
  let cached = null;
  if (env.KV) {
    try {
      const str = await env.KV.get(cacheKey);
      if (str) cached = JSON.parse(str);
    } catch (e) {
      void(0);
    }
  }
  if (cached && cached.data) {
    if (Date.now() - cached.ts > CACHE_TTL2) {
      if (ctx.waitUntil) {
        ctx.waitUntil(doRefresh().catch((e) => void(0)));
      }
    }
    return cached.data;
  }
  return await doRefresh();
}
async function prepareSubscriptionData(ctx, env) {
  const addStr = await getConfig(env, "ADD.txt") || await getConfig(env, "ADD");
  const addApiStr = await getConfig(env, "ADDAPI");
  const addNoTlsStr = await getConfig(env, "ADDNOTLS");
  const addNoTlsApiStr = await getConfig(env, "ADDNOTLSAPI");
  const addCsvStr = await getConfig(env, "ADDCSV");
  const linkStr = await getConfig(env, "LINK");
  const DLS = Number(await getConfig(env, "DLS", "8"));
  const remarkIndex = Number(await getConfig(env, "CSVREMARK", "1"));
  let localAddresses = [];
  let localAddressesNoTls = [];
  let apiLinks = [];
  let noTlsApiLinks = [];
  let csvLinks = [];
  if (addStr) {
    const list = await cleanList(addStr);
    list.forEach((item) => {
      if (item.startsWith("http")) apiLinks.push(item);
      else localAddresses.push(item);
    });
  }
  if (addApiStr) apiLinks.push(...await cleanList(addApiStr));
  if (addNoTlsStr) localAddressesNoTls = await cleanList(addNoTlsStr);
  if (addNoTlsApiStr) noTlsApiLinks.push(...await cleanList(addNoTlsApiStr));
  if (addCsvStr) csvLinks = await cleanList(addCsvStr);
  const remoteData = await getCachedRemoteNodes(env, ctx, apiLinks, noTlsApiLinks, csvLinks, DLS, remarkIndex);
  let hardcodedLinks = linkStr ? await cleanList(linkStr) : [];
  ctx.addresses = [...  new Set([...localAddresses, ...remoteData.addresses])].filter(Boolean);
  ctx.addressesnotls = [...  new Set([...localAddressesNoTls, ...remoteData.addressesnotls])].filter(Boolean);
  ctx.hardcodedLinks = hardcodedLinks;
  if (ctx.addresses.length === 0 && ctx.hardcodedLinks.length === 0) {
    ctx.addresses.push("www.visa.com.tw:443#CF-Default-1");
  }
}
async function handleSubscription(request, env, ctx, subPath, hostName) {
  const FileName = await getConfig(env, "SUBNAME", "sub");
  await prepareSubscriptionData(ctx, env);
  const subHashLength = CONSTANTS.SUB_HASH_LENGTH;
  const isEnabled = (p) => {
    if (p === "socks5" && ctx.disabledProtocols.includes("socks")) return false;
    return !ctx.disabledProtocols.includes(p);
  };
  const subPathNames = [
    "all",
    "sub",
    "all-tls",
    "all-clash",
    "all-clash-tls",
    "all-sb",
    "all-sb-tls",
    "vless",
    "vless-tls",
    "vless-clash",
    "vless-clash-tls",
    "vless-sb",
    "vless-sb-tls",
    "trojan",
    "trojan-tls",
    "trojan-clash",
    "trojan-clash-tls",
    "trojan-sb",
    "trojan-sb-tls",
    "ss",
    "ss-tls",
    "ss-clash",
    "ss-clash-tls",
    "ss-sb",
    "ss-sb-tls",
    "socks",
    "socks-tls",
    "socks-clash",
    "socks-clash-tls",
    "socks-sb",
    "socks-sb-tls",
    "mandala-tls",
    "xhttp-tls",
    "xhttp-clash-tls",
    "xhttp-sb-tls"
  ];
  const hashPromises = subPathNames.map((p) => sha1(p));
  const hashes = (await Promise.all(hashPromises)).map((h) => h.toLowerCase().substring(0, subHashLength));
  const hashToName = {};
  hashes.forEach((h, i) => hashToName[h] = subPathNames[i]);
  const requestedHash = subPath.toLowerCase().substring(0, subHashLength);
  const pathName = hashToName[requestedHash];
  if (!pathName) return null;
  const plainHeader = { "Content-Type": "text/plain;charset=utf-8" };
  const plainDownloadHeader = { ...plainHeader, "Content-Disposition": `attachment; filename="${FileName}"` };
  const jsonHeader = { "Content-Type": "application/json;charset=utf-8" };
  const jsonDownloadHeader = { ...jsonHeader, "Content-Disposition": `attachment; filename="${FileName}.json"` };
  const genB64 = (proto, tls) => generateBase64Subscription(proto, ["ss", "trojan", "mandala"].includes(proto) ? ctx.dynamicUUID : ctx.userID, hostName, tls, ctx);
  if (pathName === "all" || pathName === "sub") {
    const content = [];
    ["vless", "trojan", "mandala", "ss", "socks5"].forEach((p) => {
      if (isEnabled(p)) content.push(genB64(p === "socks5" ? "socks" : p, false));
    });
    if (isEnabled("xhttp")) content.push(genB64("xhttp", true));
    return new Response(btoa(unescape(encodeURIComponent(content.join("\n")))), { headers: plainDownloadHeader });
  }
  if (pathName === "all-tls") {
    const content = [];
    ["vless", "trojan", "mandala", "ss", "socks5", "xhttp"].forEach((p) => {
      if (isEnabled(p)) content.push(genB64(p === "socks5" ? "socks" : p, true));
    });
    return new Response(content.join("\n"), { headers: plainHeader });
  }
  if (pathName === "all-clash") return new Response(generateMixedClashConfig(ctx.userID, ctx.dynamicUUID, hostName, false, ctx.enableXhttp, ctx), { headers: plainDownloadHeader });
  if (pathName === "all-clash-tls") return new Response(generateMixedClashConfig(ctx.userID, ctx.dynamicUUID, hostName, true, ctx.enableXhttp, ctx), { headers: plainHeader });
  if (pathName === "all-sb") return new Response(generateMixedSingBoxConfig(ctx.userID, ctx.dynamicUUID, hostName, false, ctx.enableXhttp, ctx), { headers: jsonDownloadHeader });
  if (pathName === "all-sb-tls") return new Response(generateMixedSingBoxConfig(ctx.userID, ctx.dynamicUUID, hostName, true, ctx.enableXhttp, ctx), { headers: jsonHeader });
  const parts = pathName.split("-");
  const protocol = parts[0];
  const isTls = parts.includes("tls");
  const isClash = parts.includes("clash");
  const isSb = parts.includes("sb");
  if (["vless", "trojan", "ss", "socks", "xhttp", "mandala"].includes(protocol)) {
    const checkProto = protocol === "socks" ? "socks5" : protocol;
    if (!isEnabled(checkProto)) return new Response(`${protocol.toUpperCase()} is disabled`, { status: 403 });
    const id = ["trojan", "ss", "mandala"].includes(protocol) ? ctx.dynamicUUID : ctx.userID;
    if (isClash) {
      if (protocol === "mandala") return new Response("Clash not supported for Mandala", { status: 400 });
      return new Response(generateClashConfig(protocol, id, hostName, isTls, ctx), { headers: plainDownloadHeader });
    } else if (isSb) {
      if (protocol === "mandala") return new Response("SingBox not supported for Mandala", { status: 400 });
      return new Response(generateSingBoxConfig(protocol, id, hostName, isTls, ctx), { headers: jsonDownloadHeader });
    } else {
      const content = genB64(protocol, isTls);
      return isTls ? new Response(content, { headers: plainHeader }) : new Response(btoa(unescape(encodeURIComponent(content))), { headers: plainDownloadHeader });
    }
  }
  return null;
}

async function executeWebDavPush(env, ctx, force = false) {
  try {
    const enableWebdav = await getConfig(env, "WEBDAV", "0");
    if (enableWebdav !== "1" && !force) {
      return;
    }
    const rawWebdavUrl = "";
    const webdavUser = "";
    const webdavPass = "";
    if (!rawWebdavUrl || !webdavUser || !webdavPass) {
      if (enableWebdav === "1" || force) {
        void(0);
      }
      return;
    }
    const webdavUrl = rawWebdavUrl.endsWith("/") ? rawWebdavUrl : `${rawWebdavUrl}/`;
    void(0);
    let hostName = await getConfig(env, "WORKER_DOMAIN");
    if (!hostName && env.KV) {
      hostName = await env.KV.get("SAVED_DOMAIN");
      if (hostName) {
        void(0);
      }
    }
    if (!hostName) {
      void(0);
      hostName = "worker.local";
    }
    const subHashLength = CONSTANTS.SUB_HASH_LENGTH;
    const allPathHash = (await sha1("all")).toLowerCase().substring(0, subHashLength);
    const mockRequest = new Request(`https://${hostName}/${ctx.dynamicUUID}/${allPathHash}`);
    const response = await handleSubscription(mockRequest, env, ctx, allPathHash, hostName);
    if (!response || !response.ok) {
      void(0);
      return;
    }
    let content = await response.text();
    try {
      const decoded = atob(content);
      content = decoded;
    } catch (e) {
    }
    const uniqueLines = [...new Set(content.split("\n"))].filter((line) => line.trim() !== "");
    const MAX_BYTES = 10 * 1024;
    const encoder = new TextEncoder();
    let accumulatedBytes = 0;
    const limitedLines = [];
    for (const line of uniqueLines) {
      const lineBytes = encoder.encode(line).length + 1;
      if (accumulatedBytes + lineBytes > MAX_BYTES) {
        void(0);
        break;
      }
      limitedLines.push(line);
      accumulatedBytes += lineBytes;
    }
    const finalContent = limitedLines.join("\n");
    if (env.KV && !force) {
      const currentHash = await sha1(finalContent);
      const lastHash = await env.KV.get("WEBDAV_HASH");
      if (currentHash === lastHash) {
        void(0);
        return;
      }
      if (ctx.waitUntil) ctx.waitUntil(env.KV.put("WEBDAV_HASH", currentHash));
    }
    const subName = await getConfig(env, "SUBNAME", "sub");
    const offset = 8 * 60 * 60 * 1e3;
    const now =   new Date();
    const localDate = new Date(now.getTime() + offset);
    const timestamp = localDate.toISOString().replace(/[-:T.]/g, "").slice(0, 14);
    const fileName = `${subName}_${timestamp}.txt`;
    const targetUrl = `${webdavUrl}${fileName}`;
    const auth = btoa(`${webdavUser}:${webdavPass}`);
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1e4);
    const pushRequest = fetch(targetUrl, {
      method: "PUT",
      headers: {
        "Authorization": `Basic ${auth}`,
        "Content-Type": "text/plain; charset=utf-8",
        "User-Agent": "Cloudflare-Worker-Pusher"
      },
      body: finalContent,
      signal: controller.signal
    }).then((res) => {
      if (res.ok) void(0);
      else void(0);
    }).catch((err) => {
      void(0);
    }).finally(() => {
      clearTimeout(timeoutId);
    });
    if (ctx.waitUntil) ctx.waitUntil(pushRequest);
    else await pushRequest;
  } catch (e) {
    void(0);
  }
}

async function handleEditConfig(request, env, ctx) {
  const FileName = await getConfig(env, "SUBNAME", "sub");
  if (!env.KV) {
    return new Response("<p>\u9519\u8BEF\uFF1A\u672A\u7ED1\u5B9AKV\u7A7A\u95F4\uFF0C\u65E0\u6CD5\u4F7F\u7528\u5728\u7EBF\u914D\u7F6E\u529F\u80FD\u3002</p>", { status: 404, headers: { "Content-Type": "text/html;charset=utf-8" } });
  }
  const configItems = [
    ["ADMIN_PASS", "\u540E\u53F0\u7BA1\u7406\u8BBF\u95EE\u5BC6\u7801", "\u8BBE\u7F6E\u540E\uFF0C\u901A\u8FC7 /KEY \u8DEF\u5F84\u8BBF\u95EE\u7BA1\u7406\u9875\u9700\u8F93\u5165\u6B64\u5BC6\u7801\u3002\u7559\u7A7A\u5219\u4E0D\u5F00\u542F\u9A8C\u8BC1\u3002", "\u4F8B\u5982: 123456", "text"],
    ["UUID", "UUID (\u7528\u6237ID/\u5BC6\u7801)", "VLESS\u7684\u7528\u6237ID, \u4E5F\u662FTrojan/SS\u7684\u5BC6\u7801\u3002", "\u4F8B\u5982: 1234567", "text"],
    ["KEY", "\u52A8\u6001UUID\u5BC6\u94A5", "\u7528\u4E8E\u751F\u6210\u52A8\u6001UUID, \u586B\u5199\u540E\u5C06\u8986\u76D6\u4E0A\u65B9\u9759\u6001UUID\u3002", "\u4F8B\u5982: my-secret-key", "text"],
    ["TIME", "\u52A8\u6001UUID\u6709\u6548\u65F6\u95F4 (\u5929)", "\u52A8\u6001UUID\u7684\u6709\u6548\u5468\u671F, \u5355\u4F4D\u4E3A\u5929\u3002", "\u4F8B\u5982: 1 (\u8868\u793A1\u5929)", "number"],
    ["UPTIME", "\u52A8\u6001UUID\u66F4\u65B0\u65F6\u95F4 (\u5C0F\u65F6)", "\u52A8\u6001UUID\u5728\u5468\u671F\u7684\u7B2C\u51E0\u4E2A\u5C0F\u65F6\u66F4\u65B0\u3002", "\u4F8B\u5982: 0 (\u8868\u793A0\u70B9)", "number"],
    ["PROXYIP", "\u51FA\u7AD9\u4EE3\u7406IP (ProxyIP)", "Worker\u8BBF\u95EE\u76EE\u6807\u7F51\u7AD9\u65F6\u4F7F\u7528\u7684IP, \u591A\u4E2A\u7528\u9017\u53F7\u9694\u5F00\u3002", "\u4F8B\u5982: 1.2.3.4 \u6216 [2606::]", "text"],
    ["SUBNAME", "\u8BA2\u9605\u6587\u4EF6\u540D (FileName)", "\u8BA2\u9605\u94FE\u63A5\u4E0B\u8F7D\u65F6\u7684\u6587\u4EF6\u540D\u524D\u7F00\u3002", "\u4F8B\u5982: sub.txt", "text"],
    ["ADD.txt", "\u4F18\u9009IP\u5217\u8868 (ADD.txt)", "\u8BA2\u9605\u8282\u70B9\u4F7F\u7528\u7684\u5730\u5740\u5217\u8868, \u4E00\u884C\u4E00\u4E2A\u3002", "usa.visa.com#\u5907\u6CE8\n1.2.3.4:8443#\u5907\u6CE8\n[2606:4700::]:2053#IPv6", "textarea"],
    ["ADDAPI", "\u4F18\u9009IP API (ADDAPI)", "\u8FDC\u7A0B\u4F18\u9009IP\u5217\u8868(TXT\u683C\u5F0F)\u7684\u4E0B\u8F7D\u94FE\u63A5\u3002", "https://example.com/ips.txt", "text"],
    ["ADDNOTLS", "\u975ETLS\u8282\u70B9 (ADDNOTLS)", "\u624B\u52A8\u6DFB\u52A0\u975ETLS\u8282\u70B9(80\u7AEF\u53E3\u7B49)\u3002", "www.example.com:80#\u5907\u6CE8", "textarea"],
    ["ADDNOTLSAPI", "\u975ETLS API (ADDNOTLSAPI)", "\u8FDC\u7A0B\u975ETLS\u8282\u70B9\u5217\u8868\u7684\u4E0B\u8F7D\u94FE\u63A5\u3002", "https://example.com/notls.txt", "text"],
    ["ADDCSV", "CSV\u6D4B\u901F\u6587\u4EF6 (ADDCSV)", "CloudflareSpeedTest \u6D4B\u901F\u7ED3\u679C CSV \u6587\u4EF6\u7684\u94FE\u63A5\u3002", "https://example.com/result.csv", "text"],
    ["CFPORTS", "CF\u7AEF\u53E3 (httpsPorts)", "Cloudflare\u652F\u6301\u7684TLS\u7AEF\u53E3, \u9017\u53F7\u9694\u5F00\u3002", "443,8443,2053,2083,2087,2096", "text"],
    ["DIS", "\u7981\u7528\u534F\u8BAE", "\u586B\u5165\u9700\u8981\u5173\u95ED\u7684\u534F\u8BAE(VLESS, Trojan, XHTTP\u7B49), \u82F1\u6587\u9017\u53F7\u5206\u9694, \u4E0D\u533A\u5206\u5927\u5C0F\u5199\u3002\u9ED8\u8BA4\u5168\u90E8\u5F00\u542F\uFF0Cpages\u4E0D\u652F\u6301XHTTP\u3002", "\u4F8B\u5982: XHTTP, SOCKS5", "text"],
    ["DNS64", "NAT64\u670D\u52A1\u5668", "\u7528\u4E8E\u5C06IPv4\u8F6C\u4E3AIPv6\u8BBF\u95EE (\u5982\u65E0\u53EF\u7559\u7A7A)\u3002", "\u4F8B\u5982: 64:ff9b::/96", "text"],
    ["SOCKS5", "SOCKS5/HTTP\u4EE3\u7406", "Worker\u51FA\u7AD9\u65F6\u4F7F\u7528\u7684\u524D\u7F6E\u4EE3\u7406 (\u5982\u65E0\u53EF\u7559\u7A7A)\u3002", "user:pass@host:port \u6216 http://user:pass@host:port", "text"],
    ["GO2SOCKS5", "SOCKS5\u5206\u6D41\u89C4\u5219", "\u54EA\u4E9B\u57DF\u540D\u8D70SOCKS5\u4EE3\u7406, \u9017\u53F7\u9694\u5F00\u3002", "*example.net,*example.com,all in", "text"],
    ["BAN", "\u7981\u6B62\u8BBF\u95EE\u7684\u57DF\u540D", "\u7981\u6B62\u901A\u8FC7Worker\u4EE3\u7406\u8BBF\u95EE\u7684\u57DF\u540D, \u9017\u53F7\u9694\u5F00\u3002", "example.com,example.org", "text"],
    ["URL302", "\u6839\u8DEF\u5F84\u8DF3\u8F6CURL (302)", "\u8BBF\u95EE\u6839\u8DEF\u5F84 / \u65F6\u8DF3\u8F6C\u5230\u7684\u5730\u5740\u3002", "https://github.com/", "text"],
    ["URL", "\u6839\u8DEF\u5F84\u53CD\u4EE3URL", "\u8BBF\u95EE\u6839\u8DEF\u5F84 / \u65F6\u53CD\u4EE3\u7684\u5730\u5740 (302\u4F18\u5148)\u3002", "https://github.com/", "text"],
    [
      "BESTIP_SOURCES",
      "BestIP IP\u6E90",
      "\u81EA\u5B9A\u4E49BestIP\u9875\u9762\u7684IP\u6E90\u5217\u8868 (\u683C\u5F0F: \u540D\u79F0 \u7F51\u5740\uFF0C\u6BCF\u884C\u4E00\u4E2A)\u3002",
      `CF\u5B98\u65B9 https://www.cloudflare.com/ips-v4/`,
      "textarea"
    ]
  ];
  if (request.method === "POST") {
    try {
      const formData = await request.formData();
      const savePromises = [];
      const keysToClear = [];
      for (const [key] of configItems) {
        keysToClear.push(key);
        const value = formData.get(key);
        if (value !== null) {
          if (value === "") {
            savePromises.push(env.KV.delete(key));
          } else {
            if (key === "BESTIP_SOURCES") {
              const lines = value.split("\n");
              for (let i = 0; i < lines.length; i++) {
                const line = lines[i].trim();
                if (!line) continue;
                const parts = line.split(/\s+/);
                if (parts.length < 2) {
                  return new Response(`\u4FDD\u5B58\u5931\u8D25: BestIP IP\u6E90 \u683C\u5F0F\u9519\u8BEF (\u7B2C${i + 1}\u884C)\u3002\u5E94\u4E3A: \u540D\u79F0 \u7F51\u5740`, { status: 400 });
                }
              }
            }
            savePromises.push(env.KV.put(key, value));
          }
        }
      }
      await Promise.all(savePromises);
      await cleanConfigCache();
      if (typeof clearKVCache === "function") {
        await clearKVCache(keysToClear);
      }
      try {
        const appCtx = await initializeContext(request, env);
        appCtx.waitUntil = ctx.waitUntil.bind(ctx);
        ctx.waitUntil(executeWebDavPush(env, appCtx, true));
      } catch (err) {
        void(0);
      }
      return new Response("\u4FDD\u5B58\u6210\u529F", { status: 200 });
    } catch (e) {
      return new Response("\u4FDD\u5B58\u5931\u8D25: " + e.message, { status: 500 });
    }
  }
  const kvPromises = configItems.map((item) => getKV(env, item[0]));
  const kvValues = await Promise.all(kvPromises);
  let formHtml = "";
  configItems.forEach(([key, label, desc, placeholder, type], index) => {
    const kvValue = kvValues[index];
    const envValue = env[key];
    let displayValue = kvValue ?? "";
    if (kvValue === null && key === "BESTIP_SOURCES") displayValue = placeholder;
    let envHint = "";
    if (key !== "ADD.txt" && key !== "BESTIP_SOURCES" && envValue) {
      envHint = `<div class="env-hint">\u73AF\u5883\u53D8\u91CF: <code>${envValue}</code></div>`;
    }
    const escapeHtml = (str) => {
      if (!str) return "";
      return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    };
    let inputField = "";
    if (type === "textarea") {
      const rows = key === "BESTIP_SOURCES" || key === "ADD.txt" || key === "ADDNOTLS" ? 8 : 4;
      inputField = `<textarea class="form-control" id="${key}" name="${key}" rows="${rows}" placeholder="${escapeHtml(placeholder)}">${escapeHtml(displayValue)}</textarea>`;
    } else {
      inputField = `<input type="${type}" class="form-control" id="${key}" name="${key}" value="${escapeHtml(displayValue)}" placeholder="${escapeHtml(placeholder)}">`;
    }
    formHtml += `<div class="mb-3"><label for="${key}" class="form-label">${label}</label>${inputField}<div class="form-text">${desc} (\u7559\u7A7A\u5219\u4F7F\u7528\u73AF\u5883\u53D8\u91CF\u6216\u9ED8\u8BA4\u503C)</div>${envHint}</div><hr>`;
  });
  return new Response(getAdminConfigHtml(FileName, formHtml), { headers: { "Content-Type": "text/html;charset=utf-8" } });
}
async function handleBestIP(request, env) {
  const url = new URL(request.url);
  const txt = "ADD.txt";
  if (url.searchParams.get("action") === "test") {
    const ip = url.searchParams.get("ip");
    const port = url.searchParams.get("port");
    if (!ip || !port) {
      return new Response(JSON.stringify({ error: "Missing ip or port" }), { status: 400, headers: { "Content-Type": "application/json" } });
    }
    const testUrl = "https://cloudflare.com/cdn-cgi/trace";
    const startTime = Date.now();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2e3);
      const response = await fetch(testUrl, {
        method: "GET",
        headers: { "Accept": "text/plain" },
        signal: controller.signal,
        resolveOverride: ip
      });
      clearTimeout(timeoutId);
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      const traceText = await response.text();
      const latency = Date.now() - startTime;
      const coloMatch = traceText.match(/colo=([A-Z]{3})/);
      const result = {
        ip,
        port,
        latency,
        colo: coloMatch ? coloMatch[1] : "N/A"
      };
      return new Response(JSON.stringify(result), { headers: { "Content-Type": "application/json" } });
    } catch (e) {
      return new Response(JSON.stringify({
        ip,
        port,
        latency: 9999,
        colo: "FAIL"
      }), { headers: { "Content-Type": "application/json" } });
    }
  }
  if (request.method === "POST") {
    if (!env.KV) return new Response(JSON.stringify({ error: "\u672A\u7ED1\u5B9AKV\u7A7A\u95F4" }), { status: 400, headers: { "Content-Type": "application/json" } });
    try {
      const data = await request.json();
      const action = url.searchParams.get("action") || "save";
      let inputIps = [];
      if (data.ips && Array.isArray(data.ips)) {
        inputIps = data.ips.slice(0, 50).map((line) => String(line).trim().substring(0, 100)).filter(Boolean);
      }
      if (action === "append") {
        const existing = await getKV(env, txt) || "";
        const existingLines = existing.split("\n").map((l) => l.trim()).filter(Boolean);
        const newContent = [...  new Set([...existingLines, ...inputIps])].join("\n");
        await env.KV.put(txt, newContent);
      } else {
        await env.KV.put(txt, inputIps.join("\n"));
      }
      await cleanConfigCache([txt]);
      if (typeof clearKVCache === "function") await clearKVCache([txt]);
      return new Response(JSON.stringify({ success: true, message: action === "append" ? "\u8FFD\u52A0\u6210\u529F" : "\u4FDD\u5B58\u6210\u529F" }), { headers: { "Content-Type": "application/json" } });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json" } });
    }
  }
  const defaultIpSources = [
    { "name": "CF\u5B98\u65B9", "url": "https://www.cloudflare.com/ips-v4/" }
  ];
  let ipSources = defaultIpSources;
  if (env.KV) {
    const kvData = await getKV(env, "BESTIP_SOURCES");
    const remoteData = await getConfig(env, "BESTIP_SOURCES");
    const sourceData = kvData || remoteData;
    if (sourceData) {
      try {
        if (sourceData.trim().startsWith("[")) {
          try {
            const parsed = JSON.parse(sourceData);
            if (Array.isArray(parsed)) ipSources = parsed;
          } catch (e) {
          }
        } else {
          const lines = sourceData.split("\n");
          const parsedSources = [];
          for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
              const url2 = parts.pop();
              const name = parts.join(" ");
              if (url2 && name) parsedSources.push({ name, url: url2 });
            }
          }
          if (parsedSources.length > 0) ipSources = parsedSources;
        }
      } catch (e) {
        void(0);
      }
    }
  }
  const allIpSources = [...ipSources, { "name": "\u53CD\u4EE3IP\u5217\u8868", "url": "proxyip" }];
  if (url.searchParams.has("loadIPs")) {
    const ipSourceName = url.searchParams.get("loadIPs");
    async function GetCFIPs(sourceName) {
      try {
        let response;
        const source = allIpSources.find((s) => s.name === sourceName);
        if (sourceName === "\u53CD\u4EE3IP\u5217\u8868") {
          response = await fetch("https://raw.githubusercontent.com/cmliu/ACL4SSR/main/baipiao.txt");
          const text2 = response.ok ? await response.text() : "";
          return text2.split("\n").map((l) => l.trim()).filter(Boolean);
        } else if (source) {
          response = await fetch(source.url);
        } else {
          response = await fetch(allIpSources[0].url);
        }
        const text = response.ok ? await response.text() : "";
        const cidrs = text.split("\n").filter((line) => line.trim() && !line.startsWith("#"));
        const ips2 =   new Set();
        while (ips2.size < 512 && cidrs.length > 0) {
          const startSize = ips2.size;
          for (const cidr of cidrs) {
            if (ips2.size >= 512) break;
            try {
              if (!cidr.includes("/")) {
                ips2.add(cidr);
                continue;
              }
              const [network, prefixStr] = cidr.split("/");
              if (network.includes(":")) {
                if (network.endsWith("::")) {
                  const rand = Math.floor(Math.random() * 65535).toString(16);
                  ips2.add(network + rand);
                } else {
                  ips2.add(network);
                }
                continue;
              }
              const prefix = parseInt(prefixStr);
              if (prefix < 12 || prefix > 31) continue;
              const ipToInt = (ip) => ip.split(".").reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
              const intToIp = (int) => [int >>> 24 & 255, int >>> 16 & 255, int >>> 8 & 255, int & 255].join(".");
              const networkInt = ipToInt(network);
              const hostBits = 32 - prefix;
              const numHosts = 1 << hostBits;
              if (numHosts > 2) {
                const randomOffset = Math.floor(Math.random() * (numHosts - 2)) + 1;
                ips2.add(intToIp(networkInt + randomOffset));
              }
            } catch (e) {
            }
          }
          if (ips2.size === startSize) break;
        }
        return Array.from(ips2);
      } catch (error) {
        return [];
      }
    }
    const ips = await GetCFIPs(ipSourceName);
    return new Response(JSON.stringify({ ips }), { headers: { "Content-Type": "application/json" } });
  }
  const ipSourceOptions = allIpSources.map((s) => `<option value="${s.name}">${s.name}</option>`).join("\n");
  return new Response(getBestIPHtml(ipSourceOptions), { headers: { "Content-Type": "text/html; charset=UTF-8" } });
}

var INLINE_CSS = `
<style>
:root{--bs-primary:#0d6efd;--bs-secondary:#6c757d;--bs-info:#0dcaf0;--bs-body-bg:#fff;--bs-body-color:#212529}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background-color:var(--bs-body-bg);color:var(--bs-body-color);line-height:1.5;margin:0}
.container{max-width:900px;margin:0 auto;padding:1.5rem}
h1,h2,h3{margin-top:0;margin-bottom:.5rem;font-weight:500;line-height:1.2}
h1{font-size:calc(1.375rem + 1.5vw)} h2{font-size:calc(1.325rem + .9vw);margin-top:2rem}
hr{margin:1rem 0;color:inherit;border:0;border-top:1px solid;opacity:.25}
.mb-2{margin-bottom:.5rem!important} .mt-4{margin-top:1.5rem!important} .mb-4{margin-bottom:1.5rem!important}
.text-danger{color:#dc3545!important}
.input-group{position:relative;display:flex;flex-wrap:nowrap;width:100%}
.form-control{display:block;width:100%;padding:.2rem .5rem;font-size:1rem;font-weight:400;line-height:1.5;color:#212529;background-color:#fff;background-clip:padding-box;border:1px solid #ced4da;border-radius:.375rem;transition:border-color .15s ease-in-out,box-shadow .15s ease-in-out;min-width:100px}
.form-control[readonly]{background-color:#e9ecef;opacity:1}
.btn{display:inline-block;white-space:nowrap;font-weight:400;line-height:1.5;color:#212529;text-align:center;text-decoration:none;vertical-align:middle;cursor:pointer;user-select:none;background-color:transparent;border:1px solid transparent;padding:.2rem .5rem;font-size:1rem;border-radius:.375rem;transition:color .15s ease-in-out,background-color .15s ease-in-out,border-color .15s ease-in-out,box-shadow .15s ease-in-out}
.btn-primary{color:#fff;background-color:#0d6efd;border-color:#0d6efd} .btn-primary:hover{background-color:#0b5ed7;border-color:#0a58ca}
.btn-secondary{color:#fff;background-color:#6c757d;border-color:#6c757d;border-top-left-radius:0;border-bottom-left-radius:0} .btn-secondary:hover{background-color:#5c636a;border-color:#565e64}
.btn-info{color:#000;background-color:#0dcaf0;border-color:#0dcaf0} .btn-info:hover{background-color:#31d2f2;border-color:#25cff2}
.input-group .form-control{border-top-right-radius:0;border-bottom-right-radius:0}
a.btn{margin-right:5px}
</style>`;
var copyBtn = (val) => `<div class="input-group mb-2"><input type="text" class="form-control" value="${val}" readonly><button class="btn btn-primary" onclick="copyToClipboard('${val}')">\u590D\u5236</button></div>`;
function getHomePageHtml(FileName, mixedTitle, isWorkersDev, subs, nodeDetailsHtml, managementPath) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>\u8282\u70B9\u4FE1\u606F</title>${INLINE_CSS}</head><body><div class="container mt-4 mb-4"><h1>${FileName} \u4EE3\u7406\u8282\u70B9\u7BA1\u7406</h1><hr><h2>${mixedTitle}</h2><p class="text-danger"><b>(\u6CE8\u610F: \u8BA2\u9605\u94FE\u63A5\u5DF2\u5305\u542B\u8BBF\u95EE\u5BC6\u94A5\uFF0C\u8BF7\u52FF\u6CC4\u9732)</b></p>` + (isWorkersDev ? `<b>\u6240\u6709\u534F\u8BAE (\u542B\u65E0TLS):</b>${copyBtn(subs.all)}` : "") + `<b>\u901A\u7528\u8BA2\u9605 (\u63A8\u8350 TLS):</b>${copyBtn(subs.all_tls)}<b>Clash-Meta (TLS):</b>${copyBtn(subs.all_clash_tls)}<b>Sing-Box (TLS):</b>${copyBtn(subs.all_sb_tls)}<hr><h2>\u7BA1\u7406\u5DE5\u5177</h2><div class="mb-2"><a href="${managementPath}/edit" class="btn btn-primary">\u7F16\u8F91\u914D\u7F6E</a> <a href="${managementPath}/bestip" class="btn btn-info">\u5728\u7EBF\u4F18\u9009IP</a></div><hr><h2>\u8282\u70B9\u8BE6\u60C5</h2>` + nodeDetailsHtml + `</div><script>function copyToClipboard(text){navigator.clipboard.writeText(text).then(function(){alert("\u5DF2\u590D\u5236")}, function(err){alert("\u590D\u5236\u5931\u8D25")});}<\/script></body></html>`;
}
function getSectionHtml(title, content) {
  return `<h3>${title}</h3>${content}`;
}
function getCopyBtnHtml(val) {
  return copyBtn(val);
}

async function generateHomePage(env, ctx, hostName) {
  const FileName = await getConfig(env, "SUBNAME", "sub");
  const isWorkersDev = hostName.includes("workers.dev");
  const httpsPorts = ctx.httpsPorts;
  const path = "/?ed=2560";
  const isEnabled = (p) => {
    if (p === "socks5" && ctx.disabledProtocols.includes("socks")) return false;
    return !ctx.disabledProtocols.includes(p);
  };
  const subPathNames = [
    "all",
    "all-tls",
    "all-clash",
    "all-clash-tls",
    "all-sb",
    "all-sb-tls",
    "vless",
    "vless-tls",
    "vless-clash",
    "vless-clash-tls",
    "vless-sb",
    "vless-sb-tls",
    "trojan",
    "trojan-tls",
    "trojan-clash",
    "trojan-clash-tls",
    "trojan-sb",
    "trojan-sb-tls",
    "ss",
    "ss-tls",
    "ss-clash",
    "ss-clash-tls",
    "ss-sb",
    "ss-sb-tls",
    "socks",
    "socks-tls",
    "socks-clash",
    "socks-clash-tls",
    "socks-sb",
    "socks-sb-tls",
    "mandala-tls",
    "xhttp-tls",
    "xhttp-clash-tls",
    "xhttp-sb-tls"
  ];
  const hashPromises = subPathNames.map((p) => sha1(p));
  const hashes = (await Promise.all(hashPromises)).map((h) => h.toLowerCase().substring(0, CONSTANTS.SUB_HASH_LENGTH));
  const subs = {};
  const userHash = (await sha1(ctx.dynamicUUID)).toLowerCase().substring(0, CONSTANTS.SUB_HASH_LENGTH);
  const subPathPrefix = `/${userHash}`;
  subPathNames.forEach((name, i) => {
    const key = name.replace(/-/g, "_");
    subs[key] = `https://${hostName}${subPathPrefix}${hashes[i]}`;
  });
  let nodeDetailsHtml = "";
  const activeProtocols = [];
  if (isEnabled("vless")) {
    const vless_tls = `vless://${ctx.userID}@${hostName}:${httpsPorts[0]}?encryption=none&security=tls&sni=${hostName}&fp=random&type=ws&host=${hostName}&path=${encodeURIComponent(path)}#${hostName}-VLESS-TLS`;
    nodeDetailsHtml += getSectionHtml("VLESS TLS", getCopyBtnHtml(vless_tls));
    activeProtocols.push("VLESS");
  }
  if (isEnabled("trojan")) {
    const trojan_tls = `trojan://${ctx.dynamicUUID}@${hostName}:${httpsPorts[0]}?security=tls&sni=${hostName}&fp=random&type=ws&host=${hostName}&path=${encodeURIComponent(path)}#${hostName}-TROJAN-TLS`;
    nodeDetailsHtml += getSectionHtml("Trojan TLS", getCopyBtnHtml(trojan_tls));
    activeProtocols.push("Trojan");
  }
  if (isEnabled("mandala")) {
    const mandala_tls = `mandala://${ctx.dynamicUUID}@${hostName}:${httpsPorts[0]}?security=tls&sni=${hostName}&type=ws&host=${hostName}&path=${encodeURIComponent(path)}#${hostName}-MANDALA-TLS`;
    nodeDetailsHtml += getSectionHtml("Mandala TLS", getCopyBtnHtml(mandala_tls));
    activeProtocols.push("Mandala");
  }
  if (isEnabled("ss")) {
    const ss_b64 = btoa(`none:${ctx.dynamicUUID}`);
    const ss_tls = `ss://${ss_b64}@${hostName}:${httpsPorts[0]}/?plugin=${encodeURIComponent(`v2ray-plugin;tls;host=${hostName};sni=${hostName};path=${encodeURIComponent(path)}`)}#${hostName}-SS-TLS`;
    nodeDetailsHtml += getSectionHtml("Shadowsocks TLS", getCopyBtnHtml(ss_tls));
    activeProtocols.push("SS");
  }
  if (isEnabled("socks5")) {
    const socks_auth = btoa(`${ctx.userID}:${ctx.dynamicUUID}`);
    const socks_tls = `socks://${socks_auth}@${hostName}:${httpsPorts[0]}?transport=ws&security=tls&sni=${hostName}&path=${encodeURIComponent(path)}#${hostName}-SOCKS-TLS`;
    nodeDetailsHtml += getSectionHtml("Socks5 TLS", getCopyBtnHtml(socks_tls));
    activeProtocols.push("Socks5");
  }
  if (isEnabled("xhttp")) {
    const xhttp_tls = `vless://${ctx.userID}@${hostName}:${httpsPorts[0]}?encryption=none&security=tls&sni=${hostName}&fp=random&allowInsecure=1&type=xhttp&host=${hostName}&path=${encodeURIComponent("/" + ctx.userID.substring(0, 8))}&mode=stream-one#${hostName}-XHTTP-TLS`;
    const content = `<h3>Vless+xhttp+tls</h3><div class="input-group mb-3"><input type="text" class="form-control" value="${xhttp_tls}" readonly><button class="btn btn-outline-secondary" onclick="copyToClipboard('${xhttp_tls}')">\u590D\u5236</button></div>`;
    nodeDetailsHtml += `<hr><h2 class="mt-4">XHTTP \u8282\u70B9 (VLESS)</h2>` + content;
    activeProtocols.push("XHTTP");
  }
  const mixedTitle = `\u6DF7\u5408\u8BA2\u9605 (${activeProtocols.join("+")})`;
  const managementPath = "/" + ctx.dynamicUUID.toLowerCase();
  return getHomePageHtml(FileName, mixedTitle, isWorkersDev, subs, nodeDetailsHtml, managementPath);
}

function getPasswordSetupHtml() {
  return `<!DOCTYPE html><html><head><title>\u521D\u59CB\u5316\u8BBE\u7F6E</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:#f4f4f4;margin:0}.box{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 0 10px rgba(0,0,0,0.1);width:300px;display:flex;flex-direction:column;align-items:center;text-align:center}h1{margin-top:0;font-size:1.5rem}p{color:#666;margin-bottom:1rem}form{width:100%}input,button{width:100%;padding:10px;margin:10px 0;box-sizing:border-box;border-radius:4px;border:1px solid #ccc}button{background:#007bff;color:#fff;border:none;cursor:pointer;font-weight:600}button:hover{background:#0056b3}</style></head><body><div class="box"><h1>\u8BBE\u7F6E\u521D\u59CB\u5BC6\u7801</h1><p>\u8BF7\u8F93\u5165UUID\u6216\u5BC6\u7801\u4F5C\u4E3A\u60A8\u7684\u5BC6\u94A5\u3002</p><form method="POST" action="/"><input type="password" name="password" placeholder="\u8F93\u5165\u5BC6\u7801/UUID" required><button type="submit">\u4FDD\u5B58\u8BBE\u7F6E</button></form></div></body></html>`;
}
function getLoginHtml() {
  return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>\u540E\u53F0\u8BBF\u95EE\u9A8C\u8BC1</title>
    <style>
        :root {
            --primary-color: #007bff;
            --primary-hover: #0056b3;
            --bg-color: #f0f2f5;
            --card-bg: #ffffff;
            --text-color: #333333;
            --border-color: #dee2e6;
            --error-bg: #f8d7da;
            --error-color: #721c24;
            --error-border: #f5c6cb;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-color: var(--bg-color);
            color: var(--text-color);
        }
        .card {
            background: var(--card-bg);
            padding: 2.5rem;
            border-radius: 16px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.05);
            width: 100%;
            max-width: 380px;
            text-align: center;
            transition: transform 0.3s ease;
        }
        .card:hover {
            transform: translateY(-2px);
        }
        h3 {
            margin-top: 0;
            margin-bottom: 1.5rem;
            font-size: 1.5rem;
            font-weight: 600;
            color: #2c3e50;
        }
        form {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        input {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            font-size: 16px;
            box-sizing: border-box;
            transition: all 0.3s ease;
            outline: none;
        }
        input:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.1);
        }
        button {
            width: 100%;
            padding: 12px;
            background-color: var(--primary-color);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s ease, transform 0.1s ease;
        }
        button:hover {
            background-color: var(--primary-hover);
        }
        button:active {
            transform: scale(0.98);
        }
        .error-box {
            background-color: var(--error-bg);
            color: var(--error-color);
            border: 1px solid var(--error-border);
            padding: 0.75rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
            text-align: left;
            display: none; /* \u9ED8\u8BA4\u9690\u85CF\uFF0C\u7531JS\u89E6\u53D1 */
            line-height: 1.4;
        }
    </style>
</head>
<body>
    <div class="card">
        <h3>\u{1F512} \u8BBF\u95EE\u53D7\u9650</h3>
        
        <div id="error-msg" class="error-box"></div>

        <p style="color:#666; margin-bottom: 1.5rem;">\u5F53\u524D\u9875\u9762\u9700\u8981\u7BA1\u7406\u5458\u6743\u9650</p>
        <form method="POST" action="?auth=login">
            <input type="password" name="password" placeholder="\u8BF7\u8F93\u5165\u8BBF\u95EE\u5BC6\u7801" required autofocus autocomplete="current-password">
            <button type="submit">\u7ACB\u5373\u89E3\u9501</button>
        </form>
    </div>

    <script>
        (function() {
            var msgDiv = document.getElementById('error-msg');
            
            // 1. \u9759\u6001\u68C0\u6D4B\uFF1A\u6D4F\u89C8\u5668\u662F\u5426\u5B8C\u5168\u7981\u7528\u4E86 Cookie
            if (!navigator.cookieEnabled) {
                msgDiv.innerHTML = "<strong>\u26A0\uFE0F \u6D4F\u89C8\u5668 Cookie \u5DF2\u7981\u7528</strong><br>\u7CFB\u7EDF\u5FC5\u987B\u4F9D\u8D56 Cookie \u4FDD\u5B58\u767B\u5F55\u72B6\u6001\u3002\u8BF7\u5728\u6D4F\u89C8\u5668\u8BBE\u7F6E\u4E2D\u5F00\u542F Cookie \u540E\u5237\u65B0\u9875\u9762\u91CD\u8BD5\u3002";
                msgDiv.style.display = 'block';
                return;
            }

            // 2. \u52A8\u6001\u68C0\u6D4B\uFF1A\u662F\u5426\u53D1\u751F\u4E86\u201C\u767B\u5F55\u6210\u529F\u4F46Cookie\u4E22\u5931\u201D\u7684\u6B7B\u5FAA\u73AF
            // (\u914D\u5408 index.js \u4E2D\u7684 login_check=1 \u53C2\u6570)
            var urlParams = new URLSearchParams(window.location.search);
            if (urlParams.has('login_check')) {
                msgDiv.innerHTML = "<strong>\u26A0\uFE0F \u65E0\u6CD5\u5199\u5165\u767B\u5F55\u72B6\u6001</strong><br>\u60A8\u7684\u5BC6\u7801\u6B63\u786E\uFF0C\u4F46\u6D4F\u89C8\u5668\u672A\u4FDD\u5B58 Cookie\u3002<br>\u53EF\u80FD\u539F\u56E0\uFF1A<br>1. \u6B63\u5728\u4F7F\u7528\u9690\u79C1\u6A21\u5F0F\u6216\u7B2C\u4E09\u65B9 Cookie \u88AB\u62E6\u622A<br>2. \u8BBF\u95EE\u57DF\u540D\u4E0D\u652F\u6301 HttpOnly Cookie<br>3. \u8BF7\u5C1D\u8BD5\u5207\u6362 HTTPS \u8BBF\u95EE";
                msgDiv.style.display = 'block';
                
                // \u6E05\u7406 URL \u53C2\u6570\uFF0C\u907F\u514D\u7528\u6237\u5237\u65B0\u65F6\u4E00\u76F4\u770B\u5230\u9519\u8BEF
                try {
                    var newUrl = window.location.pathname;
                    window.history.replaceState({}, document.title, newUrl);
                } catch(e) {}
            }
        })();
    <\/script>
</body>
</html>`;
}

var lastSavedDomain = "";
var lastPushTime = 0;
var PUSH_COOLDOWN = 24 * 60 * 60 * 1e3;
function safeWaitUntil(ctx, promise) {
  if (ctx && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(promise);
  } else {
    Promise.resolve(promise).catch((e) => void(0));
  }
}
function normalizePath(urlObj) {
  let p = urlObj.pathname.toLowerCase();
  if (p.length > 1 && p.endsWith("/")) {
    p = p.slice(0, -1);
  }
  return p;
}
async function handlePasswordSetup(request, env, ctx) {
  if (request.method === "POST") {
    const formData = await request.formData();
    const password = formData.get("password");
    if (!password || password.length < 6) return new Response("\u5BC6\u7801\u592A\u77ED", { status: 400 });
    if (!env.KV) return new Response("\u672A\u7ED1\u5B9A KV", { status: 500 });
    await env.KV.put("UUID", password);
    const now = Date.now();
    await env.KV.put("LAST_PUSH_TIME", now.toString());
    lastPushTime = now;
    await cleanConfigCache();
    try {
      const appCtx = await initializeContext(request, env);
      appCtx.waitUntil = (p) => safeWaitUntil(ctx, p);
      safeWaitUntil(ctx, executeWebDavPush(env, appCtx, true));
      void(0);
    } catch (e) {
      void(0);
    }
    return new Response("\u8BBE\u7F6E\u6210\u529F\uFF0C\u8BF7\u5237\u65B0\u9875\u9762", { status: 200, headers: { "Content-Type": "text/html;charset=utf-8" } });
  }
  return new Response(getPasswordSetupHtml(), { headers: { "Content-Type": "text/html;charset=utf-8" } });
}
async function proxyUrl(urlStr, targetUrlObj, request) {
  if (!urlStr) return null;
  try {
    const proxyUrl2 = new URL(urlStr);
    const currentUrl = new URL(request.url);
    if (proxyUrl2.hostname === currentUrl.hostname) return null;
    const path = proxyUrl2.pathname === "/" ? "" : proxyUrl2.pathname;
    const newUrl = proxyUrl2.protocol + "//" + proxyUrl2.hostname + path + targetUrlObj.pathname + targetUrlObj.search;
    const newHeaders = new Headers(request.headers);
    newHeaders.delete("Host");
    newHeaders.delete("Referer");
    return fetch(new Request(newUrl, {
      method: request.method,
      headers: newHeaders,
      body: request.body,
      redirect: "follow"
    }));
  } catch (e) {
    return null;
  }
}
var index_default = {
  async fetch(request, env, ctx) {
    try {
      const context = await initializeContext(request, env);
      context.waitUntil = (promise) => safeWaitUntil(ctx, promise);
      const url = new URL(request.url);
      const path = normalizePath(url);
      const hostName = request.headers.get("Host");
      const upgradeHeader = request.headers.get("Upgrade");
      if (upgradeHeader && upgradeHeader.toLowerCase() === "websocket") {
        if (!context.userID) return new Response("UUID not set", { status: 401 });
        return await handleWebSocketRequest(request, context);
      }
      if (path === "/" || path === "/index.html") {
        const rawUUID = await getConfig(env, "UUID");
        const rawKey = await getConfig(env, "KEY");
        const isUninitialized = rawUUID === CONSTANTS.SUPER_PASSWORD && !rawKey;
        if (isUninitialized && env.KV) {
          return await handlePasswordSetup(request, env, ctx);
        }
        const url302 = await getConfig(env, "URL302");
        if (url302) return Response.redirect(url302, 302);
        const urlProxy = await getConfig(env, "URL");
        if (urlProxy) {
          const resp = await proxyUrl(urlProxy, url, request);
          if (resp) return resp;
        }
        return new Response('<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p><p>For online documentation and support please refer to<a href="http://nginx.org/">nginx.org</a>.<br/>Commercial support is available at<a href="http://nginx.com/">nginx.com</a>.</p><p><em>Thank you for using nginx.</em></p></body></html>', { headers: { "Content-Type": "text/html;charset=utf-8" } });
      }
      const superPassword = CONSTANTS.SUPER_PASSWORD;
      const dynamicID = context.dynamicUUID.toLowerCase();
      const userHash = (await sha1(dynamicID)).toLowerCase().substring(0, CONSTANTS.SUB_HASH_LENGTH);
      const isSuperRoute = path.startsWith("/" + superPassword);
      const isFullUserRoute = path.startsWith("/" + dynamicID);
      const isCalculatedHash = path.startsWith("/" + userHash);
      const isHexFeature = /^\/[a-f0-9]{6,12}(\/|$)/i.test(path);
      const isHashRoute = isCalculatedHash || isHexFeature;
      if (!isSuperRoute && !isFullUserRoute && !isHashRoute) {
        return new Response("404 Not Found", { status: 404 });
      }
      let subPath = "";
      if (isSuperRoute) subPath = path.substring(("/" + superPassword).length);
      else if (isFullUserRoute) subPath = path.substring(("/" + dynamicID).length);
      else if (isCalculatedHash) subPath = path.substring(("/" + userHash).length);
      const isManagementRoute = isSuperRoute || isFullUserRoute;
      const isLoginRequest = url.searchParams.get("auth") === "login";
      if (request.method === "GET" && env.KV && hostName && hostName.includes(".")) {
        if (hostName !== lastSavedDomain) {
          const now = Date.now();
          if (now - lastPushTime > PUSH_COOLDOWN) {
            context.waitUntil((async () => {
              let kvPushTime = await env.KV.get("LAST_PUSH_TIME");
              if (!kvPushTime || now - parseInt(kvPushTime) > PUSH_COOLDOWN) {
                await env.KV.put("SAVED_DOMAIN", hostName);
                await env.KV.put("LAST_PUSH_TIME", now.toString());
                lastSavedDomain = hostName;
                lastPushTime = now;
                await cleanConfigCache(["SAVED_DOMAIN"]);
                await executeWebDavPush(env, context, false);
              }
            })());
          }
        }
      }
      if (isManagementRoute) {
        if (!isSuperRoute && context.adminPass) {
          const cookie = request.headers.get("Cookie") || "";
          if (!cookie.includes(`admin_auth=${context.adminPass}`)) {
            if (request.method === "POST" && isLoginRequest) {
              const formData = await request.formData();
              if (formData.get("password") === context.adminPass) {
                return new Response(null, {
                  status: 302,
                  headers: {
                    "Set-Cookie": `admin_auth=${context.adminPass}; Path=/; HttpOnly; Max-Age=86400; SameSite=Lax`,
                    "Location": url.pathname + "?login_check=1"
                  }
                });
              }
            }
            return new Response(getLoginHtml(), { headers: { "Content-Type": "text/html;charset=utf-8" } });
          }
        }
        if (request.method === "POST") {
          if (subPath === "/edit") return await handleEditConfig(request, env, ctx);
          if (subPath === "/bestip") return await handleBestIP(request, env);
        }
        if (request.method === "GET") {
          const html = await generateHomePage(env, context, hostName);
          return new Response(html, { headers: { "Content-Type": "text/html;charset=utf-8" } });
        }
        return new Response("404 Not Found", { status: 404 });
      }
      if (isHashRoute) {
        if (request.method === "POST") {
          if (context.enableXhttp && !isLoginRequest) {
            const r = await handleXhttpClient(request, context);
            if (r) {
              context.waitUntil(r.closed);
              return new Response(r.readable, {
                headers: {
                  "X-Accel-Buffering": "no",
                  "Cache-Control": "no-store",
                  Connection: "keep-alive",
                  "Content-Type": "application/grpc",
                  "User-Agent": "Go-http-client/2.0"
                }
              });
            }
            return new Response("XHTTP Handshake Failed", { status: 400 });
          }
        }
        if (request.method === "GET" && isCalculatedHash) {
          const response = await handleSubscription(request, env, context, subPath, hostName);
          if (response) return response;
        }
      }
      return new Response("404 Not Found", { status: 404 });
    } catch (e) {
      const errInfo = e && (e.stack || e.message || e.toString()) || "Unknown Internal Error";
      void(0);
      return new Response(errInfo, { status: 500 });
    }
  },
  async scheduled(event, env, ctx) {
  }
};
export {
  index_default as default
};
