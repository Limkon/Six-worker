import { CONSTANTS } from '../constants.js';

export function parseIPv6(ipv6String) {
    const sections = new Uint16Array(8);
    let sectionIndex = 0;
    let parts = ipv6String.split(':');
    const lastPart = parts[parts.length - 1];
    let ipv4Part = null;
    if (lastPart.includes('.')) {
        ipv4Part = lastPart;
        parts = parts.slice(0, parts.length - 1);
    }
    const compressionIndex = parts.indexOf('');
    if (compressionIndex !== -1) {
        for (let i = 0; i < compressionIndex; i++) {
            sections[sectionIndex++] = parseInt(parts[i] || '0', 16);
        }
        const rightParts = parts.slice(compressionIndex + 1);
        const partsToSkip = 8 - sectionIndex - rightParts.length - (ipv4Part ? 2 : 0);
        sectionIndex += partsToSkip;
        for (let i = 0; i < rightParts.length; i++) {
            sections[sectionIndex++] = parseInt(rightParts[i] || '0', 16);
        }
    } else {
        for (let i = 0; i < parts.length; i++) {
            if (sectionIndex < 8) {
                sections[sectionIndex++] = parseInt(parts[i] || '0', 16);
            }
        }
    }
    if (ipv4Part) {
        const ipv4Parts = ipv4Part.split('.').map(p => parseInt(p, 10));
        if (sectionIndex <= 6) {
            sections[sectionIndex++] = (ipv4Parts[0] << 8) | ipv4Parts[1];
            sections[sectionIndex++] = (ipv4Parts[2] << 8) | ipv4Parts[3];
        }
    }
    const byteArray = new Uint8Array(16);
    const dataView = new DataView(byteArray.buffer);
    for (let i = 0; i < 8; i++) {
        dataView.setUint16(i * 2, sections[i], false);
    }
    return Array.from(byteArray);
}

export async function resolveToIPv6(target, dns64Server) {
    const defaultAddress = '2a09:bac5:32::226:717b';
    if (!dns64Server) {
        return target;
    }
    function isIPv4(str) { return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$/.test(str); }
    function isIPv6(str) { return str.includes(':'); }
    
    async function fetchIPv4(domain) {
        const response = await fetch(`https://1.1.1.1/dns-query?name=${domain}&type=A`, { headers: { 'Accept': 'application/dns-json' } });
        if (!response.ok) throw new Error('DNS query for A record failed');
        const data = await response.json();
        const ipv4s = (data.Answer || []).filter(r => r.type === 1).map(r => r.data);
        if (ipv4s.length === 0) throw new Error('No A record found');
        return ipv4s[0];
    }
    
    try {
        if (isIPv6(target)) return target;
        const ipv4 = isIPv4(target) ? target : await fetchIPv4(target);
        if (dns64Server.endsWith('/96')) {
            let prefix = dns64Server.split('/96')[0];
            if (prefix.endsWith(':')) {
                prefix = prefix.substring(0, prefix.length - 1);
            }
            const ipv4Bytes = ipv4.split('.').map(part => parseInt(part, 10));
            const hex = ipv4Bytes.map(part => part.toString(16).padStart(2, '0')).join('');
            return `${prefix}:${hex.slice(0, 4)}:${hex.slice(4)}`;
        }
        return defaultAddress;
    } catch (error) {
        console.error('Resolve to IPv6 error:', error);
        return target;
    }
}
