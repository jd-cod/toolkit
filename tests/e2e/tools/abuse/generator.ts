import type { Rng } from '../_support/rng';
import {
  COUNTRY_NAMES, isSpecialPurpose,
  type AbuseRecord, type AbuseResponse, type BatchEntry, type GeoFacts, type IpInfoRecord, type RiskLevel,
} from './oracle';

/**
 * Random batches and random, schema-faithful answers for the three data
 * sources of /abuse. Every builder returns the input together with the facts
 * the oracle starts from.
 */

// ─── Addresses ──────────────────────────────────────────────────────────

/** A public unicast IPv4 address (first octet chosen outside every special-purpose block). */
export function publicIpv4(rng: Rng): string {
  for (;;) {
    const ip = [rng.int(1, 223), rng.int(0, 255), rng.int(0, 255), rng.int(1, 254)].join('.');
    if (!isSpecialPurpose(ip)) return ip;
  }
}

export function privateIpv4(rng: Rng): string {
  return rng.pick([
    () => `10.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(1, 254)}`,
    () => `172.${rng.int(16, 31)}.${rng.int(0, 255)}.${rng.int(1, 254)}`,
    () => `192.168.${rng.int(0, 255)}.${rng.int(1, 254)}`,
    () => `127.0.0.${rng.int(1, 254)}`,
    () => `169.254.${rng.int(0, 255)}.${rng.int(1, 254)}`,
    () => `100.${rng.int(64, 127)}.${rng.int(0, 255)}.${rng.int(1, 254)}`,
  ])();
}

/** A global-unicast IPv6 address written in full (eight groups, no "::"), random case and zero padding. */
export function publicIpv6Full(rng: Rng): string {
  const groups = [rng.pick([0x2400, 0x2600, 0x2607, 0x2a00, 0x2a01, 0x2a02, 0x2c0f]), ...Array.from({ length: 7 }, () => (rng.bool(0.25) ? 0 : rng.int(1, 0xffff)))];
  return groups.map(group => {
    let text = group.toString(16);
    if (rng.bool(0.3)) text = text.padStart(4, '0');
    return rng.bool(0.3) ? text.toUpperCase() : text;
  }).join(':');
}

export function privateIpv6Full(rng: Rng): string {
  const prefix = rng.pick(['fd00', 'fd12', 'fc00', 'fe80']);
  return [prefix, ...Array.from({ length: 7 }, () => rng.int(0, 0xffff).toString(16))].join(':');
}

/** The same address in the zero-compressed form RFC 5952 recommends (used by the IPv6 input tests). */
export function compressIpv6(full: string): string {
  const groups = full.split(':').map(group => parseInt(group, 16));
  let bestStart = -1, bestLength = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] !== 0) continue;
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLength) { bestStart = i; bestLength = j - i; }
    i = j;
  }
  const hex = groups.map(group => group.toString(16));
  if (bestLength < 2) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLength).join(':')}`;
}

/** Lines that are plainly not an IP address. The page must drop every one of them. */
export const NOT_AN_ADDRESS: { line: string; why: string }[] = [
  { line: 'not-an-ip', why: 'free text' },
  { line: '# scanners seen on web01', why: 'comment' },
  { line: 'example.com', why: 'host name' },
  { line: '10.0.0', why: 'three octets' },
  { line: '10.0.0.1.5', why: 'five octets' },
  { line: '10.0.0.0/24', why: 'CIDR block' },
  { line: '203.0.113.9:8080', why: 'address with a port' },
  { line: 'http://198.51.100.7/', why: 'URL' },
  { line: '1234.1.1.1', why: 'four-digit octet' },
  { line: 'a.b.c.d', why: 'letters in octets' },
  { line: '10.0.0.-1', why: 'negative octet' },
  { line: '10..0.1', why: 'empty octet' },
  { line: '2001:db8:0:0:0:0:0', why: 'IPv6 with seven groups' },
  { line: '2001:db8:0:0:0:0:0:1:2', why: 'IPv6 with nine groups' },
  { line: '2001:db8:0:0:0:0:0:g', why: 'IPv6 with a non-hex digit' },
  { line: '2001:db8:0:0:0:0:0:12345', why: 'IPv6 group with five digits' },
  { line: ';8.8.8.8', why: 'address behind a semicolon' },
  { line: '"8.8.8.8"', why: 'quoted address' },
  { line: '[2001:db8:0:0:0:0:0:1]', why: 'bracketed IPv6' },
  { line: '8.8.8.8;120', why: 'semicolon is not a separator' },
];

export interface BatchLine { text: string; entry?: BatchEntry; why?: string }

export interface GeneratedBatch {
  /** The text to paste. */
  text: string;
  lines: BatchLine[];
  /** Ground truth: the addresses the batch contains, in order, with their request counts. */
  entries: BatchEntry[];
  rejectedLines: string[];
}

export interface BatchOptions {
  publicV4?: number;
  privateV4?: number;
  publicV6?: number;
  privateV6?: number;
  invalid?: number;
  blank?: number;
  /** Share of valid lines that carry a request count. */
  countShare?: number;
  lineEnding?: '\n' | '\r\n';
}

const SEPARATORS = [' ', ' ', '\t', ',', ', ', ' | ', '   ', '|'];

export function generateBatch(rng: Rng, options: BatchOptions = {}): GeneratedBatch {
  const want = { publicV4: 4, privateV4: 1, publicV6: 1, privateV6: 0, invalid: 2, blank: 1, countShare: 0.6, ...options };
  const addresses = new Set<string>();
  const add = (count: number, make: () => string) => {
    for (let made = 0; made < count;) {
      const ip = make();
      if (!addresses.has(ip)) { addresses.add(ip); made++; }
    }
  };
  add(want.publicV4, () => publicIpv4(rng));
  add(want.privateV4, () => privateIpv4(rng));
  add(want.publicV6, () => publicIpv6Full(rng));
  add(want.privateV6, () => privateIpv6Full(rng));

  const lines: BatchLine[] = [...addresses].map(ip => {
    const withCount = rng.bool(want.countShare);
    const hits = withCount ? rng.weighted([rng.int(1, 9), rng.int(10, 999), rng.int(1000, 250000)], [3, 4, 2]) : 1;
    const body = withCount ? `${ip}${rng.pick(SEPARATORS)}${hits}` : ip;
    const text = `${rng.bool(0.2) ? '  ' : ''}${body}${rng.bool(0.2) ? ' \t' : ''}`;
    return { text, entry: { ip, hits } };
  });
  for (const bad of rng.sample(NOT_AN_ADDRESS, want.invalid)) lines.push({ text: bad.line, why: bad.why });
  for (let i = 0; i < want.blank; i++) lines.push({ text: rng.pick(['', '   ', '\t']) });

  const shuffled = rng.shuffle(lines);
  return {
    text: shuffled.map(line => line.text).join(want.lineEnding ?? '\n'),
    lines: shuffled,
    entries: shuffled.filter(line => line.entry).map(line => line.entry as BatchEntry),
    rejectedLines: shuffled.filter(line => line.why).map(line => line.text),
  };
}

// ─── Answers of the three sources ───────────────────────────────────────

const PTR_SUFFIXES = ['example.net', 'isp.example', 'cloud.example.org', 'hosting.example.com', 'mail.example.co.uk'];
const ORGANISATIONS = [
  'Example Hosting GmbH', 'Acme Cloud, Inc.', 'Telefónica Example S.A.', 'O\'Reilly Networks Ltd', 'AT&T Example Services',
  'Very Long Autonomous System Organisation Name For Layout Testing Of The Network Column Co., Ltd.', 'ExampleNet',
  'Société Générale de Réseaux "SGR"', 'DigitalExample LLC', '株式会社サンプル',
];
const USAGE_TYPES = ['Data Center/Web Hosting/Transit', 'Fixed Line ISP', 'Mobile ISP', 'Commercial', 'Content Delivery Network', 'University/College/School'];
const COUNTRY_CODES = Object.keys(COUNTRY_NAMES);

function ptrFor(rng: Rng, ip: string): string {
  const label = ip.replace(/[.:]/g, '-').toLowerCase();
  return `${rng.pick(['host', 'static', 'pool', 'srv', 'mx'])}-${label}.${rng.pick(PTR_SUFFIXES)}`;
}

function versionTag(ip: string): string {
  return ip.includes(':') ? 'IPv6' : 'IPv4';
}

/**
 * POST /api/ipinfo answer in the backend's real shape: private and reserved
 * addresses are `safe` with one reason and no PTR; public ones carry a PTR or
 * none, and a level with its reasons.
 */
export function generateIpInfo(rng: Rng, entries: BatchEntry[], options: { ptrShare?: number; levels?: RiskLevel[] } = {}): IpInfoRecord[] {
  const levels = options.levels ?? ['low', 'low', 'medium', 'high'];
  return entries.map(({ ip }) => {
    if (isSpecialPurpose(ip)) {
      return { ip, is_valid: true, is_private: true, ip_version: versionTag(ip), reverse_dns: '', risk_level: 'safe' as RiskLevel, risk_reasons: ['Private/reserved IP address'] };
    }
    const hasPtr = rng.bool(options.ptrShare ?? 0.6);
    const level = rng.pick(levels);
    const reasons: string[] = [];
    if (!hasPtr) reasons.push('No reverse DNS record');
    if (level !== 'low' && hasPtr) reasons.push('Reverse DNS suggests dynamic/consumer IP');
    if (level === 'high') reasons.push('Unknown ASN organization');
    return { ip, is_valid: true, is_private: false, ip_version: versionTag(ip), reverse_dns: hasPtr ? ptrFor(rng, ip) : '', risk_level: level, risk_reasons: reasons };
  });
}

/** Scores on and around every threshold of the risk badge, plus the extremes. */
export const BOUNDARY_SCORES = [0, 1, 24, 25, 26, 74, 75, 76, 99, 100];

export interface AbuseOptions {
  /** `backend`: the shape backend/src/routes/abuse.js returns. `alternate`: one `results` list with AbuseIPDB's own field names. */
  style?: 'backend' | 'alternate';
  /** Share of addresses AbuseIPDB answers for. */
  coverage?: number;
  /** Fixed scores, used in order, before random ones. */
  scores?: number[];
  /** Give every entry a country (name and code). Default: none, so the GeoIP database decides. */
  withCountry?: boolean;
}

export function generateAbuse(rng: Rng, entries: BatchEntry[], options: AbuseOptions = {}): AbuseResponse {
  const style = options.style ?? 'backend';
  const scores = [...(options.scores ?? [])];
  const records: AbuseRecord[] = [];
  for (const { ip, hits } of entries) {
    if (!rng.bool(options.coverage ?? 1)) continue;
    const score = scores.length ? (scores.shift() as number) : rng.weighted([0, rng.pick(BOUNDARY_SCORES), rng.int(1, 100)], [3, 4, 3]);
    const reports = score === 0 ? 0 : rng.int(1, 5000);
    const code = rng.pick(COUNTRY_CODES);
    const lastReported = score === 0 ? '' : `2026-${String(rng.int(1, 11)).padStart(2, '0')}-${String(rng.int(1, 28)).padStart(2, '0')}T${String(rng.int(0, 23)).padStart(2, '0')}:${String(rng.int(0, 59)).padStart(2, '0')}:07+00:00`;
    const isp = rng.bool(0.8) ? rng.pick(ORGANISATIONS) : '';
    const usage = rng.bool(0.7) ? rng.pick(USAGE_TYPES) : '';
    if (style === 'backend') {
      records.push({
        ip, hits,
        abuse_score: score,
        ...(options.withCountry ? { country: COUNTRY_NAMES[code], country_code: code } : {}),
        isp, usage_type: usage,
        total_reports: reports,
        is_tor: rng.bool(0.2), is_whitelisted: rng.bool(0.15),
        num_distinct_users: score === 0 ? 0 : rng.int(1, Math.max(1, reports)),
        last_reported_at: lastReported,
      });
    } else {
      records.push({
        ipAddress: ip,
        abuseConfidenceScore: score,
        ...(options.withCountry ? { countryName: COUNTRY_NAMES[code], countryCode: code } : {}),
        ...(isp ? { isp } : {}),
        ...(usage ? { usageType: usage } : {}),
        totalReports: reports,
        is_tor: rng.bool(0.2), is_whitelisted: rng.bool(0.15),
        num_distinct_users: score === 0 ? 0 : rng.int(1, Math.max(1, reports)),
        ...(lastReported ? { last_reported_at: lastReported } : {}),
      });
    }
  }
  if (style === 'alternate') return { api_available: true, results: rng.shuffle(records), checked_count: records.length };
  // The backend splits by score and orders each list by request count, highest first.
  const byHits = (a: AbuseRecord, b: AbuseRecord) => (b.hits ?? 0) - (a.hits ?? 0);
  return {
    abusive: records.filter(record => (record.abuse_score ?? 0) > 0).sort(byHits),
    non_abusive: records.filter(record => (record.abuse_score ?? 0) === 0).sort(byHits),
    api_available: true,
    checked_count: records.length,
  };
}

/** The answer of a backend that has no AbuseIPDB key (backend/src/routes/abuse.js, first branch). */
export const ABUSE_NOT_CONFIGURED: AbuseResponse = { abusive: [], non_abusive: [], api_available: false, checked_count: 0 };

/** GeoIP database content for the public addresses of a batch: some unknown, some country only, some ASN only. */
export function generateGeo(rng: Rng, entries: BatchEntry[], options: { coverage?: number } = {}): Record<string, GeoFacts> {
  const table: Record<string, GeoFacts> = {};
  for (const { ip } of entries) {
    if (isSpecialPurpose(ip) || !rng.bool(options.coverage ?? 0.85)) continue;
    const facts: GeoFacts = {};
    if (rng.bool(0.85)) {
      const code = rng.pick(COUNTRY_CODES);
      facts.country_code = code;
      facts.country = COUNTRY_NAMES[code];
    }
    if (rng.bool(0.85)) {
      facts.asn = rng.weighted([rng.int(1, 65535), rng.int(131072, 401308)], [2, 1]);
      facts.asn_org = rng.pick(ORGANISATIONS);
    }
    table[ip] = facts;
  }
  return table;
}

/**
 * A replacement for /js/geoip.js that answers from `table` and keeps the
 * interface and the "not found" values of the real reader
 * (`country: 'Unknown'`, `country_code: '--'`, `asn: 0`, `asn_org: 'Unknown'`).
 * Contract tests serve it so that country and ASN are known to the test.
 */
export function geoScript(table: Record<string, GeoFacts>): string {
  return `(() => {
  const table = ${JSON.stringify(table)};
  const country = ip => ({ country: (table[ip] && table[ip].country) || 'Unknown', country_code: (table[ip] && table[ip].country_code) || '--' });
  const asn = ip => ({ asn: (table[ip] && table[ip].asn) || 0, asn_org: (table[ip] && table[ip].asn_org) || 'Unknown' });
  window.GeoIP = {
    init: async () => {}, isReady: () => true, clearCache: () => {},
    lookupCountry: country, lookupASN: asn, lookupIP: ip => ({ ...country(ip), ...asn(ip) }),
  };
})();`;
}

export interface Scenario {
  batch: GeneratedBatch;
  ipinfo: IpInfoRecord[];
  abuse: AbuseResponse;
  geo: Record<string, GeoFacts>;
}

/** A batch with answers from all three sources (AbuseIPDB configured). */
export function generateScenario(rng: Rng, batch: BatchOptions = {}, abuse: AbuseOptions = {}): Scenario {
  const generated = generateBatch(rng.fork('batch'), batch);
  return {
    batch: generated,
    ipinfo: generateIpInfo(rng.fork('ipinfo'), generated.entries),
    abuse: generateAbuse(rng.fork('abuse'), generated.entries, abuse),
    geo: generateGeo(rng.fork('geo'), generated.entries),
  };
}
