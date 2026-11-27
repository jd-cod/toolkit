/**
 * TCP port reachability for the Open Port Checker.
 *
 * The host is resolved once through the SSRF guard and every port is probed
 * on that one address, so a name cannot answer with a public address for the
 * check and a private one for the connection.
 */

import net from 'node:net';
import { assertAllowedHost, guardedLookup } from './net-guard.js';

export const MAX_PORTS_PER_REQUEST = 25;

export const SERVICE_NAMES = {
  20: 'FTP data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
  111: 'RPC portmapper', 123: 'NTP', 135: 'MS RPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP',
  443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog', 587: 'SMTP submission', 636: 'LDAPS', 873: 'rsync',
  993: 'IMAPS', 995: 'POP3S', 1433: 'SQL Server', 1521: 'Oracle', 2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel SSL',
  2086: 'WHM', 2087: 'WHM SSL', 2375: 'Docker API', 2376: 'Docker API TLS', 3000: 'Dev server', 3306: 'MySQL',
  3389: 'RDP', 5432: 'PostgreSQL', 5601: 'Kibana', 5900: 'VNC', 5985: 'WinRM', 5986: 'WinRM TLS', 6379: 'Redis',
  6443: 'Kubernetes API', 8000: 'HTTP alt', 8080: 'HTTP proxy', 8443: 'HTTPS alt', 8888: 'HTTP alt',
  9000: 'PHP-FPM', 9090: 'Prometheus', 9100: 'Node exporter', 9200: 'Elasticsearch', 10000: 'Webmin',
  11211: 'Memcached', 27017: 'MongoDB',
};

// Services that should rarely be reachable from the whole internet.
const SENSITIVE = {
  23: 'Telnet sends passwords in clear text. Close it and use SSH.',
  135: 'MS RPC should not be reachable from the internet.',
  139: 'NetBIOS should not be reachable from the internet.',
  445: 'SMB should not be reachable from the internet. It is a common target for worms and ransomware.',
  1433: 'Databases should accept connections from application servers only.',
  1521: 'Databases should accept connections from application servers only.',
  2375: 'An open Docker API gives full control of the host.',
  3306: 'Databases should accept connections from application servers only.',
  3389: 'RDP open to the internet is a common break-in route. Put it behind a VPN or restrict the source addresses.',
  5432: 'Databases should accept connections from application servers only.',
  5900: 'VNC should not be reachable from the internet.',
  5985: 'WinRM should not be reachable from the internet.',
  6379: 'Redis has no authentication by default. Bind it to localhost or a private network.',
  9200: 'Elasticsearch has no authentication by default. Do not expose it.',
  11211: 'Memcached open to the internet is used for amplification attacks.',
  27017: 'Databases should accept connections from application servers only.',
};

/** Parses `22, 80, 8000-8005` into a sorted list of unique ports. Throws a 400 error on bad input. */
export function parsePorts(input) {
  const fail = message => { throw Object.assign(new Error(message), { statusCode: 400 }); };
  const tokens = Array.isArray(input) ? input.map(String) : String(input ?? '').split(/[\s,]+/);
  const ports = new Set();
  for (const token of tokens.map(value => value.trim()).filter(Boolean)) {
    const range = /^(\d{1,5})-(\d{1,5})$/.exec(token);
    const [from, to] = range ? [Number(range[1]), Number(range[2])] : /^\d{1,5}$/.test(token) ? [Number(token), Number(token)] : [NaN, NaN];
    if (!Number.isInteger(from) || from < 1 || to > 65535 || from > to) fail(`"${token.slice(0, 20)}" is not a valid port or range.`);
    if (to - from >= MAX_PORTS_PER_REQUEST) fail(`A range can cover at most ${MAX_PORTS_PER_REQUEST} ports.`);
    for (let port = from; port <= to; port++) ports.add(port);
    if (ports.size > MAX_PORTS_PER_REQUEST) fail(`At most ${MAX_PORTS_PER_REQUEST} ports can be checked at once.`);
  }
  if (ports.size === 0) fail('Enter at least one port.');
  return [...ports].sort((a, b) => a - b);
}

/** Resolves `host` to one public address, preferring IPv4. Rejects with a 400 error for private destinations. */
export function resolvePublicAddress(host, lookup = guardedLookup) {
  assertAllowedHost(host);
  if (net.isIP(host)) return Promise.resolve({ address: host, family: net.isIP(host) });
  return new Promise((resolve, reject) => {
    lookup(host, { all: true }, (err, addresses) => {
      if (err) {
        if (err.code === 'ENOTFOUND') return reject(Object.assign(new Error(`${host} does not resolve.`), { statusCode: 400 }));
        return reject(err);
      }
      resolve(addresses.find(entry => entry.family === 4) || addresses[0]);
    });
  });
}

/** @returns {Promise<{ port: number, state: 'open' | 'closed' | 'filtered', latency_ms: number | null }>} */
export function probePort(address, port, timeoutMs = 3000, connect = net.connect) {
  return new Promise(resolve => {
    const started = Date.now();
    const socket = connect({ host: address, port });
    let settled = false;
    const done = state => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve({ port, state, latency_ms: state === 'open' ? Date.now() - started : null });
    };
    const timer = setTimeout(() => done('filtered'), timeoutMs);
    socket.once('connect', () => done('open'));
    socket.once('error', err => done(err?.code === 'ECONNREFUSED' ? 'closed' : 'filtered'));
  });
}

export function describePort(result) {
  return {
    ...result,
    service: SERVICE_NAMES[result.port] || '',
    warning: result.state === 'open' ? (SENSITIVE[result.port] || '') : '',
  };
}
