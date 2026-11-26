/**
 * Client IP resolution for rate limiting and access control.
 *
 * X-Forwarded-For is a list that every proxy appends to, and the first entry
 * is whatever the client chose to send. Taking the first entry lets anyone
 * pick their own identity, which defeats per-IP limits. The only entries that
 * can be believed are the ones written by proxies we trust, so the chain is
 * read from the right: skip trusted proxies, and the first address that is not
 * one of them is the client.
 *
 * Trusted by default: loopback and private ranges (the Next.js server, a
 * reverse proxy on the same host or Docker network) and Cloudflare's published
 * edge ranges. TRUSTED_PROXIES overrides the Cloudflare part:
 *   TRUSTED_PROXIES=none                     trust loopback/private only
 *   TRUSTED_PROXIES=cloudflare,198.51.100.7  Cloudflare plus another proxy
 *   TRUSTED_PROXIES=203.0.113.0/24           only this range
 *
 * When every hop is internal, no public client can be told apart: the request
 * is local, from the LAN, or came through a proxy that does not forward the
 * client address. Such requests would all share one rate-limit bucket, so the
 * general limit skips them (`isLocal`). Brute-force limits (login, share
 * passwords) use `bruteForceLimit` and still apply to them.
 */

import net from 'node:net';
import { normalizeIpLiteral } from './net-guard.js';

// https://www.cloudflare.com/ips/ (fetched 2026-11-26)
const CLOUDFLARE_RANGES = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
  '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

const INTERNAL_RANGES = [
  '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16',
  '::1/128', 'fc00::/7', 'fe80::/10',
];

const loopback = new net.BlockList();
loopback.addSubnet('127.0.0.0', 8, 'ipv4');
loopback.addAddress('::1', 'ipv6');

const internal = new net.BlockList();

function addRange(list, entry) {
  const [address, prefix] = entry.split('/');
  const ip = normalizeIpLiteral(address);
  if (!ip) return false;
  const family = net.isIP(ip) === 6 ? 'ipv6' : 'ipv4';
  if (prefix === undefined) {
    list.addAddress(ip, family);
    return true;
  }
  const bits = Number(prefix);
  if (!Number.isInteger(bits) || bits < 0 || bits > (family === 'ipv6' ? 128 : 32)) return false;
  list.addSubnet(ip, bits, family);
  return true;
}

function check(list, ip) {
  return list.check(ip, net.isIP(ip) === 6 ? 'ipv6' : 'ipv4');
}

for (const range of INTERNAL_RANGES) addRange(internal, range);

function peerAddress(request) {
  return normalizeIpLiteral(request.socket?.remoteAddress || '') || normalizeIpLiteral(request.ip || '');
}

/** Server-to-server call from the Next.js process on this host: loopback peer, no forwarding headers. */
export function isInternalRequest(request) {
  const peer = peerAddress(request);
  if (!peer || !check(loopback, peer)) return false;
  return !request.headers?.['x-forwarded-for'] && !request.headers?.['x-real-ip'];
}

/**
 * Route rate-limit config for endpoints that check a secret. Unlike the
 * general limit it also counts requests whose client address is internal, so
 * a proxy that hides client addresses cannot switch it off.
 */
export function bruteForceLimit(max, timeWindow) {
  return { max, timeWindow, allowList: isInternalRequest };
}

export function buildTrustedProxies(setting = process.env.TRUSTED_PROXIES, log = console) {
  const list = new net.BlockList();
  for (const range of INTERNAL_RANGES) addRange(list, range);

  const entries = String(setting ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  if (entries.length === 0) entries.push('cloudflare');

  for (const entry of entries) {
    const keyword = entry.toLowerCase();
    if (keyword === 'none' || keyword === 'loopback' || keyword === 'private') continue;
    if (keyword === 'cloudflare') {
      for (const range of CLOUDFLARE_RANGES) addRange(list, range);
    } else if (!addRange(list, entry)) {
      log.warn?.(`TRUSTED_PROXIES: ignoring invalid entry "${entry}"`);
    }
  }
  return list;
}

/**
 * Matcher for an admin-entered allow list: IPs and CIDRs separated by
 * newlines, commas or spaces. Invalid entries are ignored.
 */
export function createIpMatcher(text) {
  const list = new net.BlockList();
  let size = 0;
  for (const entry of String(text ?? '').split(/[\s,;]+/).filter(Boolean)) {
    if (addRange(list, entry)) size++;
  }
  return {
    size,
    matches(address) {
      const ip = normalizeIpLiteral(address);
      return Boolean(ip) && size > 0 && check(list, ip);
    },
  };
}

function headerValues(value) {
  if (Array.isArray(value)) return value.join(',').split(',');
  if (typeof value === 'string') return value.split(',');
  return [];
}

export function createClientIpResolver({ trustedProxies, log } = {}) {
  const trusted = buildTrustedProxies(trustedProxies, log);

  /** The address of the real client, ignoring anything the client could have forged. */
  function resolve(request) {
    const peer = peerAddress(request);
    const chain = headerValues(request.headers?.['x-forwarded-for']).map((v) => normalizeIpLiteral(v));
    if (peer) chain.push(peer);

    let candidate = '';
    for (let i = chain.length - 1; i >= 0; i--) {
      const address = chain[i];
      if (!address) break; // malformed entry: nothing to its left is reliable
      candidate = address;
      if (!check(trusted, address)) return address;
    }

    // Every hop is a trusted proxy (LAN client, or a proxy that sets only X-Real-IP).
    const realIp = normalizeIpLiteral(headerValues(request.headers?.['x-real-ip'])[0] || '');
    return realIp || candidate || peer || 'unknown';
  }

  /** No public client address in the chain: local, LAN, or a proxy that does not forward one. */
  function isLocal(request) {
    const address = resolve(request);
    return net.isIP(address) !== 0 && check(internal, address);
  }

  return { resolve, isInternal: isInternalRequest, isLocal };
}
