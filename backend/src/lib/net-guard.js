/**
 * Outbound request guard (SSRF protection).
 *
 * Several public tools make the server connect to a host chosen by the
 * visitor (remote log fetch, SSL checker). Without a guard, that lets anyone
 * reach loopback, private networks and cloud metadata endpoints through this
 * server. Everything here refuses non-public destinations.
 *
 * The address is validated at connect time, inside the DNS lookup the socket
 * itself uses, so a hostname cannot pass a check and then resolve to a
 * different (private) address for the real connection.
 *
 * Self-hosters who run the toolkit inside a private network and want to
 * inspect internal hosts can set ALLOW_PRIVATE_TARGETS=true.
 */

import net from 'node:net';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';

const blockedRanges = new net.BlockList();

for (const [address, prefix] of [
  ['0.0.0.0', 8],        // "this" network
  ['10.0.0.0', 8],       // private
  ['100.64.0.0', 10],    // carrier-grade NAT
  ['127.0.0.0', 8],      // loopback
  ['169.254.0.0', 16],   // link-local, cloud metadata
  ['172.16.0.0', 12],    // private
  ['192.0.0.0', 24],     // IETF protocol assignments
  ['192.0.2.0', 24],     // documentation
  ['192.168.0.0', 16],   // private
  ['198.18.0.0', 15],    // benchmarking
  ['198.51.100.0', 24],  // documentation
  ['203.0.113.0', 24],   // documentation
  ['224.0.0.0', 4],      // multicast
  ['240.0.0.0', 4],      // reserved, broadcast
]) {
  blockedRanges.addSubnet(address, prefix, 'ipv4');
}

for (const [address, prefix] of [
  ['::', 128],           // unspecified
  ['::1', 128],          // loopback
  ['64:ff9b::', 96],     // NAT64, embeds an IPv4 address
  ['64:ff9b:1::', 48],   // local-use NAT64
  ['2001:db8::', 32],    // documentation
  ['fc00::', 7],         // unique local
  ['fe80::', 10],        // link-local
  ['ff00::', 8],         // multicast
]) {
  blockedRanges.addSubnet(address, prefix, 'ipv6');
}

export function allowPrivateTargets() {
  return String(process.env.ALLOW_PRIVATE_TARGETS || '').toLowerCase() === 'true';
}

/** Returns the bare IP for an IP literal (brackets and IPv4-mapping removed), or '' for anything else. */
export function normalizeIpLiteral(value) {
  if (typeof value !== 'string') return '';
  let ip = value.trim().replace(/^\[|\]$/g, '');
  const zone = ip.indexOf('%');
  if (zone !== -1) ip = ip.slice(0, zone);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped) ip = mapped[1];
  return net.isIP(ip) ? ip : '';
}

/** True when `address` is an IP that is safe to connect to from a public tool. */
export function isPublicAddress(address) {
  const ip = normalizeIpLiteral(address);
  if (!ip) return false;
  return !blockedRanges.check(ip, net.isIP(ip) === 6 ? 'ipv6' : 'ipv4');
}

function blockedError(target) {
  const error = new Error(`Destination "${target}" is not a public address.`);
  error.code = 'EBLOCKEDDESTINATION';
  error.statusCode = 400;
  return error;
}

/**
 * Throws when `host` is an IP literal in a blocked range. Hostnames pass here
 * and are checked by guardedLookup when the socket resolves them.
 */
export function assertAllowedHost(host) {
  if (allowPrivateTargets()) return;
  const literal = normalizeIpLiteral(host);
  if (literal && !isPublicAddress(literal)) throw blockedError(host);
}

/**
 * Drop-in replacement for dns.lookup, for the `lookup` option of net, tls,
 * http and https. Fails the connection if the name resolves to any blocked
 * address, so a name with one public and one private record is refused.
 */
export function guardedLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  } else if (typeof options === 'number') {
    options = { family: options };
  }
  const wantAll = Boolean(options?.all);

  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    const list = Array.isArray(addresses) ? addresses : [];
    if (list.length === 0) {
      const notFound = new Error(`getaddrinfo ENOTFOUND ${hostname}`);
      notFound.code = 'ENOTFOUND';
      return callback(notFound);
    }
    if (!allowPrivateTargets() && list.some((entry) => !isPublicAddress(entry.address))) {
      return callback(blockedError(hostname));
    }
    if (wantAll) return callback(null, list);
    return callback(null, list[0].address, list[0].family);
  });
}

function decodeBody(buffer, encoding, maxBytes) {
  const value = String(encoding || '').toLowerCase().trim();
  // gzip is left as-is: callers detect the gzip magic bytes themselves.
  if (!value || value === 'identity' || value === 'gzip' || value === 'x-gzip') return buffer;
  if (value === 'br') return zlib.brotliDecompressSync(buffer, { maxOutputLength: maxBytes });
  if (value === 'deflate') return zlib.inflateSync(buffer, { maxOutputLength: maxBytes });
  const error = new Error(`Unsupported content encoding: ${value}`);
  error.statusCode = 502;
  throw error;
}

function requestOnce(url, { method, headers, maxBytes, signal }) {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    const req = transport.request(url, { method, headers, lookup: guardedLookup, signal }, (res) => {
      const chunks = [];
      let total = 0;
      res.on('data', (chunk) => {
        total += chunk.length;
        if (total > maxBytes) {
          const error = new Error('Response exceeds the size limit.');
          error.code = 'ERESPONSETOOLARGE';
          error.statusCode = 413;
          req.destroy(error);
          return;
        }
        chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => {
        resolve({ status: res.statusCode || 0, headers: res.headers, body: Buffer.concat(chunks) });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

/**
 * HTTP(S) request to a visitor-supplied URL. Only http/https, no embedded
 * credentials, public destinations only, redirects followed manually so every
 * hop is re-validated, and the body is capped while it streams.
 *
 * @returns {Promise<{status: number, headers: object, body: Buffer, url: string}>}
 */
export async function guardedRequest(input, {
  method = 'GET',
  headers = {},
  timeoutMs = 30000,
  maxBytes = 10 * 1024 * 1024,
  maxRedirects = 5,
} = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    let current = String(input);
    for (let hop = 0; hop <= maxRedirects; hop++) {
      let url;
      try {
        url = new URL(current);
      } catch {
        const error = new Error('Invalid URL.');
        error.statusCode = 400;
        throw error;
      }
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        const error = new Error('Only http and https URLs are supported.');
        error.statusCode = 400;
        throw error;
      }
      if (url.username || url.password) {
        const error = new Error('URLs with embedded credentials are not supported.');
        error.statusCode = 400;
        throw error;
      }
      assertAllowedHost(url.hostname);

      const res = await requestOnce(url, {
        method,
        headers: { 'Accept-Encoding': 'identity', ...headers },
        maxBytes,
        signal: controller.signal,
      });

      const location = res.headers.location;
      if ([301, 302, 303, 307, 308].includes(res.status) && location) {
        current = new URL(location, url).toString();
        continue;
      }

      return {
        status: res.status,
        headers: res.headers,
        body: decodeBody(res.body, res.headers['content-encoding'], maxBytes),
        url: url.toString(),
      };
    }
    const error = new Error('Too many redirects.');
    error.statusCode = 502;
    throw error;
  } catch (err) {
    if (err?.name === 'AbortError' || err?.code === 'ABORT_ERR') {
      const error = new Error('Request timed out.');
      error.statusCode = 504;
      throw error;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
