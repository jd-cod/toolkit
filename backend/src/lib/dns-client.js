/**
 * DNS client for the email and blacklist tools.
 *
 * Uses the system resolvers (or TOOLS_DNS_SERVERS) rather than the DoH
 * endpoints the DNS Lookup tool uses: blacklists refuse queries that arrive
 * through the big public resolvers, so those checks need a resolver of our
 * own. Every lookup returns a status instead of throwing, because "no record"
 * is a normal answer here and has to be told apart from "lookup failed".
 */

import { Resolver } from 'node:dns/promises';

const NO_DATA = new Set(['ENODATA', 'NODATA']);
const NO_NAME = new Set(['ENOTFOUND', 'NXDOMAIN']);

/**
 * @typedef {{ status: 'ok' | 'nodata' | 'nxdomain' | 'error', records: any[], error?: string }} DnsAnswer
 */

export function configuredDnsServers() {
  return String(process.env.TOOLS_DNS_SERVERS || '')
    .split(',')
    .map(value => value.trim())
    .filter(Boolean);
}

export function createDnsClient({ servers = configuredDnsServers(), timeoutMs = 4000, tries = 2 } = {}) {
  const resolver = new Resolver({ timeout: timeoutMs, tries });
  if (servers.length > 0) resolver.setServers(servers);

  /** @returns {Promise<DnsAnswer>} */
  async function run(fn) {
    try {
      const records = await fn();
      return { status: records.length > 0 ? 'ok' : 'nodata', records };
    } catch (err) {
      if (NO_DATA.has(err?.code)) return { status: 'nodata', records: [] };
      if (NO_NAME.has(err?.code)) return { status: 'nxdomain', records: [] };
      return { status: 'error', records: [], error: err?.code || err?.message || 'DNS lookup failed' };
    }
  }

  return {
    /** TXT records, each joined into one string. */
    txt: name => run(async () => (await resolver.resolveTxt(name)).map(chunks => chunks.join(''))),
    mx: name => run(() => resolver.resolveMx(name)),
    a: name => run(() => resolver.resolve4(name)),
    aaaa: name => run(() => resolver.resolve6(name)),
    ptr: ip => run(() => resolver.reverse(ip)),
    ns: name => run(() => resolver.resolveNs(name)),
    cname: name => run(() => resolver.resolveCname(name)),
  };
}

/** Runs `worker` over `items` with at most `limit` in flight, keeping order. */
export async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  async function lane() {
    while (next < items.length) {
      const index = next++;
      results[index] = await worker(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, lane));
  return results;
}

const LABEL = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;

/**
 * Normalizes what a visitor typed into a bare hostname: accepts a URL, an
 * email address or a name with a trailing dot. Returns '' when it is not a
 * valid DNS name.
 */
export function normalizeHostname(input) {
  if (typeof input !== 'string') return '';
  let value = input.trim().toLowerCase();
  if (!value || value.length > 320) return '';
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  value = value.split(/[/?#]/)[0];
  if (value.includes('@')) value = value.slice(value.lastIndexOf('@') + 1);
  value = value.replace(/:\d+$/, '').replace(/\.$/, '');
  if (!value || value.length > 253 || !value.includes('.')) return '';
  const labels = value.split('.');
  if (!labels.every(label => LABEL.test(label))) return '';
  if (/^\d+$/.test(labels[labels.length - 1])) return '';
  return value;
}
