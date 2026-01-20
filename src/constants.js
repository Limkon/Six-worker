export const CONSTANTS = {
  SUPER_PASSWORD: '771571215.',
  // 支持配置多个默认 ProxyIP，使用英文逗号分隔，例如: 'xio.hpc.tw, 1.2.3.4, [2001:db8::1]'
  DEFAULT_PROXY_IP: 'xio.hpc.tw,www.digitalocean.com,icook.tw,ct.cs.com.tw',
  SUB_HASH_LENGTH: 6,
  IDLE_TIMEOUT_MS: 45000,
  MAX_CONCURRENT: 512,
  XHTTP_BUFFER_SIZE: 128 * 1024,
  
  // Protocol Types
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
  
  // Ports
  HTTP_PORTS: ["80", "8080", "8880", "2052", "2082", "2086", "2095"],
  HTTPS_PORTS: ["443", "8443", "2053", "2083", "2087", "2096"],
  
  // Default Go2Socks Patterns
  DEFAULT_GO2SOCKS5: [
    '*ttvnw.net',
    '*tapecontent.net',
    '*cloudatacdn.com',
    '*.loadshare.org',
  ]
};
