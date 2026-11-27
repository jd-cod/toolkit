import type { Rng } from '../_support/rng';
import {
  type Cidr, type Family, aggregate, cidrFirst, cidrLast, cidrSize, compactCount, compareCidr, expandV6,
  formatAddress, formatV4, makeCidr, netmaskV4, parseCidr, reductionPercents, wildcardV4,
} from './oracle';

/**
 * Random, schema-faithful answers of `POST /api/asn` (see backend/src/routes/asn.js)
 * together with the facts the oracle starts from.
 *
 * The prefix sets are built to contain what breaks prefix tools: adjacent
 * halves that merge into a supernet, more-specifics inside a larger block,
 * runs of neighbours that merge only partly, single hosts (/32, /128), and
 * IPv6 next to IPv4.
 */

export interface Scenario {
  asn: string;
  /** Organisation name the page uses in headings and rule comments. */
  holder: string;
  /** The mocked response body. */
  payload: Record<string, any>;
  /** Announced IPv4 prefixes in the order the server sent them. */
  v4: Cidr[];
  /** Announced IPv6 prefixes in the order the server sent them. */
  v6: Cidr[];
  /** Minimal supernet list of `v4`, computed by the oracle. */
  aggregated: Cidr[];
}

export interface ScenarioOptions {
  v4Count?: number;
  v6Count?: number;
  /** Exact prefix lists instead of random ones (CIDR text, in the order the server is to send them). */
  v4?: string[];
  v6?: string[];
  /** Send the prefixes in random order instead of ascending. The page must keep the server's order. */
  shuffle?: boolean;
  asn?: string;
  holder?: string;
  /** Also announce IPv6 prefixes whose length equals an IPv4 prefix length (/24, /32). Off by default. */
  sharedLengths?: boolean;
  /** Leave `aggregated_ipv4` out of the response, so the page has to compute it. */
  omitAggregate?: boolean;
  /** Fields to replace in the payload after it is built. */
  overrides?: Record<string, unknown>;
}

// IPv4 lengths are /8–/28 and /32; IPv6 lengths never repeat one of them unless `sharedLengths` is set.
const V6_LENGTHS = [29, 36, 40, 44, 48, 48, 48, 56, 64, 96, 127, 128];
const V6_FIRST_GROUPS = [0x2001, 0x2400, 0x2404, 0x2600, 0x2606, 0x2620, 0x2800, 0x2a00, 0x2a03, 0x2c0f];

function randomV4Address(rng: Rng): bigint {
  return [rng.int(1, 223), rng.int(0, 255), rng.int(0, 255), rng.int(0, 255)].reduce((acc, octet) => acc * 256n + BigInt(octet), 0n);
}

function randomV6Address(rng: Rng): bigint {
  let value = BigInt(rng.pick(V6_FIRST_GROUPS));
  for (let i = 0; i < 7; i++) value = value * 65536n + BigInt(rng.int(0, 65535));
  return value;
}

export function randomV4Prefixes(rng: Rng, count: number): Cidr[] {
  const taken = new Map<string, Cidr>();
  const add = (cidr: Cidr) => { if (taken.size < count && !taken.has(cidr.text)) taken.set(cidr.text, cidr); };
  const block = (length: number) => makeCidr(4, randomV4Address(rng), length);
  for (let guard = 0; taken.size < count && guard < count * 30; guard++) {
    const shape = rng.weighted(['single', 'halves', 'nested', 'run', 'host'] as const, [5, 3, 3, 2, 1]);
    if (shape === 'single') {
      add(block(rng.weighted([rng.int(8, 15), rng.int(16, 23), 24, rng.int(25, 28)], [1, 4, 4, 1])));
    } else if (shape === 'halves') {
      // Two halves of one parent: they merge into the parent.
      const length = rng.int(10, 28);
      const parent = block(length - 1);
      add(makeCidr(4, parent.network, length));
      add(makeCidr(4, parent.network + cidrSize({ family: 4, length }), length));
    } else if (shape === 'nested') {
      // A block and more-specific announcements inside it: the aggregate keeps only the block.
      const outer = block(rng.int(12, 22));
      add(outer);
      for (let i = rng.int(1, 3); i > 0; i--) {
        const offset = BigInt(rng.int(0, Number(cidrSize(outer) - 1n)));
        add(makeCidr(4, outer.network + offset, rng.int(outer.length + 1, Math.min(28, outer.length + 6))));
      }
    } else if (shape === 'run') {
      // Blocks 1, 2 and 3 of four neighbours: 2+3 merge, 1 stays alone.
      const length = rng.int(16, 26);
      const base = block(length - 2);
      for (let i = 1n; i <= 3n; i++) add(makeCidr(4, base.network + i * cidrSize({ family: 4, length }), length));
    } else {
      const host = block(32);
      add(host);
      if (rng.bool(0.4)) add(makeCidr(4, host.network % 2n === 0n ? host.network + 1n : host.network - 1n, 32));
    }
  }
  return [...taken.values()].sort(compareCidr);
}

export function randomV6Prefixes(rng: Rng, count: number, lengths: number[] = V6_LENGTHS): Cidr[] {
  const taken = new Map<string, Cidr>();
  const add = (cidr: Cidr) => { if (taken.size < count && !taken.has(cidr.text)) taken.set(cidr.text, cidr); };
  for (let guard = 0; taken.size < count && guard < count * 30; guard++) {
    const length = rng.pick(lengths);
    const first = makeCidr(6, randomV6Address(rng), length);
    add(first);
    const shape = rng.weighted(['single', 'sibling', 'nested'] as const, [5, 2, 2]);
    if (shape === 'sibling' && length > 20) {
      const parent = makeCidr(6, first.network, length - 1);
      add(makeCidr(6, parent.network === first.network ? first.network + cidrSize(first) : parent.network, length));
    } else if (shape === 'nested' && length <= 56) {
      const inner = lengths.filter(l => l > length && l <= 64);
      if (inner.length) add(makeCidr(6, first.network + BigInt(rng.int(1, 0xffff)) * 2n ** 64n % cidrSize(first), rng.pick(inner)));
    }
  }
  return [...taken.values()].sort(compareCidr);
}

/** A prefix as the backend serialises it (`parseIpv4Cidr` / `parseIpv6Cidr` in backend/src/lib/asn-utils.js). */
export function wirePrefix(cidr: Cidr): Record<string, unknown> {
  if (cidr.family === 4) {
    return {
      prefix: cidr.text,
      ip_version: 'ipv4',
      mask: cidr.length,
      netmask: netmaskV4(cidr.length),
      wildcard: wildcardV4(cidr.length),
      first_ip: formatV4(cidrFirst(cidr)),
      last_ip: formatV4(cidrLast(cidr)),
      start_long: Number(cidrFirst(cidr)),
      end_long: Number(cidrLast(cidr)),
      total_ips: Number(cidrSize(cidr)),
    };
  }
  // The backend does no IPv6 arithmetic: the range end is empty and the count is the number of /64 networks.
  return {
    prefix: cidr.text,
    ip_version: 'ipv6',
    mask: cidr.length,
    netmask: `/${cidr.length}`,
    wildcard: '',
    first_ip: cidr.text.split('/')[0],
    last_ip: '',
    start_long: null,
    end_long: null,
    total_ips: cidr.length <= 64 ? 2 ** (64 - cidr.length) : 1,
  };
}

const HANDLES = ['NORTHWIND', 'ACME', 'GLOBEX', 'INITECH', 'UMBRA', 'HOOLI', 'VANDELAY', 'TYRELL', 'WAYNE', 'STARK', 'OSCORP', 'SOYLENT'];
const KINDS = ['Networks', 'Hosting', 'Telecom', 'Cloud Services', 'Internet Exchange', 'Datacenters', 'Broadband'];
const SUFFIXES = ['Inc.', 'LLC', 'GmbH', 'B.V.', 'S.A.', 'Ltd', 'AB'];
const COUNTRIES = ['US', 'DE', 'NL', 'FR', 'GB', 'JP', 'BR', 'ZA', 'AU', 'SG', 'CA', 'SE'];
const REGISTRIES = ['ARIN', 'RIPE NCC', 'APNIC', 'LACNIC', 'AFRINIC'];

export function randomAsn(rng: Rng): string {
  // 16-bit, 32-bit and the largest valid number all occur.
  return String(rng.weighted([rng.int(1, 64495), rng.int(131072, 401308), rng.int(1000000, 4199999999), 4294967295], [5, 3, 2, 1]));
}

export function randomHolder(rng: Rng): string {
  const handle = rng.pick(HANDLES);
  const name = handle[0] + handle.slice(1).toLowerCase();
  return `${handle}-${rng.int(1, 99)} - ${name} ${rng.pick(KINDS)} ${rng.pick(SUFFIXES)}`;
}

export function randomScenario(rng: Rng, options: ScenarioOptions = {}): Scenario {
  const asn = options.asn ?? randomAsn(rng);
  const holder = options.holder ?? randomHolder(rng);
  const explicit = (list: string[]) => list.map(text => {
    const cidr = parseCidr(text);
    if (!cidr) throw new Error(`generator: "${text}" is not a CIDR block`);
    return cidr;
  });
  let v4 = options.v4 ? explicit(options.v4) : randomV4Prefixes(rng, options.v4Count ?? rng.int(8, 20));
  let v6 = options.v6 ? explicit(options.v6) : randomV6Prefixes(rng, options.v6Count ?? rng.int(4, 10));
  if (options.sharedLengths) {
    // IPv6 /24 and /32 next to IPv4 /24 and /32.
    const extra = [makeCidr(6, randomV6Address(rng), 32), makeCidr(6, randomV6Address(rng), 32), makeCidr(6, randomV6Address(rng), 24)];
    v6 = [...v6, ...extra.filter(e => !v6.some(p => p.text === e.text))].sort(compareCidr);
    for (const length of [24, 32]) {
      if (!v4.some(p => p.length === length)) v4.push(makeCidr(4, randomV4Address(rng), length));
    }
    v4.sort(compareCidr);
  }
  if (options.shuffle) { v4 = rng.shuffle(v4); v6 = rng.shuffle(v6); }
  const aggregated = aggregate(v4, 4);

  const distribution = (list: Cidr[]) => {
    const out: Record<string, number> = {};
    for (const p of list) out[`/${p.length}`] = (out[`/${p.length}`] || 0) + 1;
    return out;
  };
  // The server adds up the size of every prefix (asn-utils.js calculateSubnetDistribution).
  const serverTotal = v4.reduce((sum, p) => sum + cidrSize(p), 0n);

  const neighbourAsns = new Set<number>();
  while (neighbourAsns.size < rng.int(0, 8)) neighbourAsns.add(rng.int(1, 400000));
  const topPeers = [...neighbourAsns].map(n => ({
    asn: n, asn_formatted: `AS${n}`, type: rng.pick(['left', 'right', 'uncertain']), v4_peers: rng.int(0, 300), v6_peers: rng.int(0, 300),
  }));

  const checkedAt = new Date(Date.UTC(rng.int(2024, 2026), rng.int(0, 11), rng.int(1, 28), rng.int(0, 23), rng.int(0, 59), rng.int(0, 59), rng.int(0, 999)));
  const percents = reductionPercents(v4.length, aggregated.length);

  const payload: Record<string, any> = {
    asn,
    asn_formatted: `AS${asn}`,
    name: holder,
    holder,
    description: rng.pick(['as', `${rng.pick(KINDS)} backbone`, 'Transit and peering network']),
    country_code: rng.pick(COUNTRIES),
    rir: rng.pick(REGISTRIES),
    announced: rng.bool(0.8),
    abuse_emails: rng.sample(['abuse', 'noc', 'security', 'cert'], rng.int(0, 3)).map(box => `${box}@${holder.split(' ')[0].toLowerCase()}.example`),
    resolved_from: null,
    neighbours: {
      upstreams_count: rng.weighted([0, rng.int(1, 60), rng.int(1000, 2500)], [1, 6, 1]),
      downstreams_count: rng.weighted([0, rng.int(1, 400), rng.int(1000, 9000)], [1, 6, 1]),
      peers_count: rng.weighted([0, rng.int(1, 900), rng.int(1000, 60000)], [1, 5, 2]),
      top_peers: topPeers,
    },
    ipv4_prefixes: v4.map(wirePrefix),
    ipv6_prefixes: v6.map(wirePrefix),
    aggregated_ipv4: {
      original_count: v4.length,
      aggregated_count: aggregated.length,
      saved_rules: v4.length - aggregated.length,
      reduction_percent: percents[percents.length - 1],
      prefixes: aggregated.map(wirePrefix),
    },
    stats: {
      total_ipv4_prefixes: v4.length,
      total_ipv6_prefixes: v6.length,
      total_ipv4_ips: Number(serverTotal),
      total_ipv4_ips_formatted: compactCount(serverTotal),
      v4_distribution: distribution(v4),
      v6_distribution: distribution(v6),
    },
    checked_at_utc: checkedAt.toISOString(),
    error: null,
  };
  if (options.omitAggregate) delete payload.aggregated_ipv4;
  Object.assign(payload, options.overrides || {});
  return { asn, holder: String(payload.holder || payload.name || ''), payload, v4, v6, aggregated };
}

/** Several scenarios with different ASNs, so a mocked API can tell the lookups apart. */
export function randomScenarios(rng: Rng, list: ScenarioOptions[]): Scenario[] {
  const used = new Set<string>();
  return list.map(options => {
    let asn = options.asn ?? randomAsn(rng);
    while (used.has(asn)) asn = randomAsn(rng);
    used.add(asn);
    return randomScenario(rng, { ...options, asn });
  });
}

export interface AddressCase {
  /** Text typed into the tester. */
  ip: string;
  family: Family;
  value: bigint;
  /** Why this address was chosen, for failure messages. */
  note: string;
}

/**
 * Addresses on and around the edges of some prefixes, plus random ones far
 * away. Whether each is inside the network is decided by the oracle, not here.
 * IPv6 addresses are spelled in different valid ways (RFC 5952 short form,
 * fully expanded, upper case).
 */
export function addressCases(rng: Rng, prefixes: readonly Cidr[], family: Family, perPrefix = 6): AddressCase[] {
  const max = family === 4 ? 2n ** 32n - 1n : 2n ** 128n - 1n;
  const spell = (value: bigint): string => {
    if (family === 4) return formatV4(value);
    return rng.weighted([formatAddress(6, value), expandV6(value), expandV6(value, true)], [3, 1, 1]);
  };
  const cases: AddressCase[] = [];
  const push = (value: bigint, note: string) => {
    if (value < 0n || value > max) return;
    cases.push({ ip: spell(value), family, value, note });
  };
  for (const prefix of rng.sample(prefixes.filter(p => p.family === family), perPrefix)) {
    const first = cidrFirst(prefix);
    const last = cidrLast(prefix);
    const size = cidrSize(prefix);
    if (family === 4) push(first, `first address of ${prefix.text}`);
    else cases.push({ ip: formatAddress(6, first), family, value: first, note: `first address of ${prefix.text}` });
    push(last, `last address of ${prefix.text}`);
    push(first - 1n, `one before ${prefix.text}`);
    push(last + 1n, `one after ${prefix.text}`);
    if (size > 2n) {
      const offset = family === 4 ? BigInt(rng.int(1, Number(size - 2n))) : 1n + (BigInt(rng.int(0, 0x7fffffff)) * 2n ** 33n + BigInt(rng.int(0, 0x7fffffff))) % (size - 2n);
      push(first + offset, `inside ${prefix.text}`);
    }
  }
  for (let i = 0; i < 4; i++) push(family === 4 ? randomV4Address(rng) : randomV6Address(rng), 'random address');
  return cases;
}
