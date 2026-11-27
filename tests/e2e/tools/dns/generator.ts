import type { Rng } from '../_support/rng';
import {
  GLOBAL_REGIONS, OFFERED_TYPES, RESOLVERS,
  type ApiAnswer, type ApiRecord, type GlobalRecord, type GlobalRegion, type Lookup, type ProviderInfo, type Reply,
} from './oracle';

/**
 * Random, schema-faithful answers of `POST /api/dns` and `POST /api/dns/global`.
 *
 * Shapes follow backend/src/routes/dns.js: a successful answer is
 * `{domain, type, resolver, records[{name, type, TTL, data, (MX: priority, value)}], status, _type, dns_provider, hosting_provider}`;
 * no records adds `noRecords` and `message`; a failed lookup is HTTP 200 with
 * `error` (and sometimes no provider objects).
 *
 * Values that trigger defects already reported by a dedicated test are kept
 * out of the general generators so that those defects fail one named test
 * each instead of a different test on every seed:
 *  - MX priority 0  → "an MX priority of 0 is shown …"
 */

/** A probe that sets a flag if the page ever renders a record as HTML. */
export const XSS_FLAG = '__dnsXss';
export const MARKUP_PROBES = [
  `<img src=x onerror="window.${XSS_FLAG}=1">`,
  `<script>window.${XSS_FLAG}=1</script>`,
  `"><svg onload="window.${XSS_FLAG}=1"><b>bold</b>`,
];

/** TTLs on both sides of every unit boundary of the humanised display. */
export const TTL_EDGES = [0, 1, 59, 60, 61, 119, 3599, 3600, 3601, 7199, 86399, 86400, 86401, 90000, 604800, 2147483647];

const TLDS = ['example', 'test', 'com', 'net', 'org', 'io', 'dev', 'co.uk'];

export function randomLabel(rng: Rng, min = 3, max = 12): string {
  const inner = rng.string(rng.int(min, max), 'abcdefghijklmnopqrstuvwxyz0123456789-');
  // A label may not start or end with a hyphen.
  return inner.replace(/^-/, 'a').replace(/-$/, 'z');
}

export function randomDomain(rng: Rng): string {
  const labels = Array.from({ length: rng.weighted([1, 2, 3], [6, 3, 1]) }, () => randomLabel(rng));
  return `${labels.join('.')}.${rng.pick(TLDS)}`;
}

export function randomHost(rng: Rng, suffix?: string): string {
  return `${randomLabel(rng, 2, 10)}.${suffix ?? randomDomain(rng)}`;
}

/** Addresses in networks of well-known operators, private space and documentation space. */
const IPV4_POOL = [
  '8.8.8.8', '1.1.1.1', '104.20.23.154', '13.107.42.14', '52.95.110.1', '151.101.1.69', '23.192.228.80',
  '185.199.108.153', '139.162.130.5', '192.0.43.8', '10.1.2.3', '192.168.1.10', '172.16.5.4', '100.64.0.1',
  '127.0.0.1', '169.254.10.20', '192.0.2.55', '203.0.113.9', '198.51.100.7',
];
const IPV6_POOL = [
  '2606:4700::1111', '2606:4700:10::ac42:93f3', '2001:4860:4860::8888', '2001:500:88:200::8', '2a00:1450:4001:81b::200e',
  '2600:1f18:2148:bc00:8d79:f571:1b18:2b9a', '2620:1ec:c11::200', '2a04:4e42::81', '2001:db8::1', 'fe80::1', 'fd00::1234', '::1',
];

export function randomIpv4(rng: Rng): string {
  if (rng.bool(0.5)) return rng.pick(IPV4_POOL);
  return [rng.int(1, 223), rng.int(0, 255), rng.int(0, 255), rng.int(1, 254)].join('.');
}

export function randomIpv6(rng: Rng): string {
  if (rng.bool(0.5)) return rng.pick(IPV6_POOL);
  const hex = () => rng.int(0, 0xffff).toString(16);
  const first = rng.pick(['2001', '2400', '2600', '2607', '2620', '2800', '2a00', '2a01', '2a02', '2c0f']);
  return rng.bool(0.5)
    ? `${first}:${hex()}:${hex()}::${hex()}`
    : [first, hex(), hex(), hex(), hex(), hex(), hex(), hex()].join(':');
}

export function randomTtl(rng: Rng): number {
  return rng.weighted(
    [() => rng.pick(TTL_EDGES), () => rng.int(0, 600), () => rng.int(600, 172800), () => rng.int(172800, 4_000_000)],
    [3, 3, 3, 1],
  )();
}

function base64ish(rng: Rng, length: number): string {
  return rng.string(length, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/');
}

/** TXT values that are awkward to display, copy and export. */
export function awkwardTxtValues(rng: Rng): string[] {
  return [
    ...MARKUP_PROBES,
    '"quoted, value" with, commas and ""double"" quotes',
    `it's; a=b; c="d"; e='f'`,
    '&amp; &lt;b&gt; entity-looking &#x27; text',
    '=HYPERLINK("http://example.test","click")',
    'two  spaces\tand a tab',
    'first line\nsecond line',
    'unicode ✓ 日本語 üñï 🚀',
    // One unbroken 1,000 character string (a 4096-bit DKIM key is about this long).
    `v=DKIM1; k=rsa; p=${base64ish(rng, 1000)}`,
    // Several character-strings of one record, as the backend joins them.
    [`v=spf1 include:${randomHost(rng)}`, `ip4:${randomIpv4(rng)}/24`, '~all'].join(' '),
  ];
}

function randomTxt(rng: Rng): string {
  return rng.weighted(
    [
      () => `v=spf1 include:_spf.${randomDomain(rng)} ip4:${randomIpv4(rng)} -all`,
      () => `google-site-verification=${base64ish(rng, 43)}`,
      () => `${randomLabel(rng)}-domain-verification=${rng.string(24)}`,
      () => rng.pick(awkwardTxtValues(rng)),
      () => `v=DMARC1; p=${rng.pick(['none', 'quarantine', 'reject'])}; rua=mailto:dmarc@${randomDomain(rng)}`,
    ],
    [3, 2, 2, 4, 1],
  )();
}

/** The `data` text of one record, as the backend formats each type. */
export function randomRecordData(rng: Rng, type: string, domain: string): string {
  switch (type) {
    case 'A': return randomIpv4(rng);
    case 'AAAA': return randomIpv6(rng);
    case 'TXT': return randomTxt(rng);
    case 'SOA':
      return [
        randomHost(rng), `hostmaster.${domain}`, rng.int(1, 4294967295), rng.pick([900, 3600, 7200, 10000, 86400]),
        rng.pick([600, 900, 2400, 7200]), rng.pick([604800, 1209600, 2419200]), rng.pick([60, 300, 1800, 3600, 86400]),
      ].join(' ');
    case 'SRV': return `${rng.int(0, 100)} ${rng.int(0, 100)} ${rng.pick([443, 5060, 5061, 5222, 5269, 8443, rng.int(1, 65535)])} ${randomHost(rng)}`;
    case 'CAA': {
      const tag = rng.pick(['issue', 'issuewild', 'iodef', 'issuemail']);
      const value = tag === 'iodef' ? `mailto:security@${domain}` : rng.pick(['letsencrypt.org', 'digicert.com', 'pki.goog', 'sectigo.com', ';']);
      return `${rng.pick([0, 0, 0, 128])} ${tag} "${value}"`;
    }
    case 'PTR': return randomHost(rng);
    case 'MX': return rng.pick([`mx${rng.int(1, 9)}.${domain}`, randomHost(rng), `aspmx.l.${randomDomain(rng)}`]);
    default: return randomHost(rng); // CNAME, NS
  }
}

export function randomRecords(rng: Rng, type: string, domain: string, count: number): ApiRecord[] {
  const records: ApiRecord[] = [];
  // Records of one set normally share a TTL; sometimes they do not (cached answers).
  const sharedTtl = rng.bool(0.6) ? randomTtl(rng) : null;
  for (let i = 0; i < count; i++) {
    // Now and then repeat a value: nothing may be merged or dropped.
    const data = i > 0 && rng.bool(0.08) ? String(records[rng.int(0, i - 1)].data) : randomRecordData(rng, type, domain);
    const record: ApiRecord = { name: domain, type, TTL: sharedTtl ?? randomTtl(rng), data };
    if (type === 'MX') {
      record.priority = rng.pick([1, 5, 10, 10, 20, 30, 50, 100, 65535]);
      record.value = data;
    }
    records.push(record);
  }
  return records;
}

const DNS_PROVIDERS: ProviderInfo[] = [
  { slug: 'cloudflare-dns', name: 'Cloudflare DNS', confidence: 'high', source: 'NS', matched_on: 'hera.ns.cloudflare.com' },
  { slug: 'aws-route53', name: 'AWS Route 53', confidence: 'high', source: 'NS', matched_on: 'ns-1283.awsdns-32.org' },
  { slug: 'google-cloud-dns', name: 'Google Cloud DNS', confidence: 'medium', source: 'NS', matched_on: 'ns-cloud-a1.googledomains.com' },
  { slug: 'godaddy-dns', name: 'GoDaddy DNS', confidence: 'high', source: 'NS', matched_on: 'ns01.domaincontrol.com' },
  { slug: 'akamai-dns', name: 'Akamai DNS', confidence: 'high', source: 'NS', matched_on: 'a1-64.akam.net' },
];
const HOSTING_PROVIDERS: ProviderInfo[] = [
  { slug: 'cloudflare', name: 'Cloudflare', confidence: 'medium', source: 'CNAME', matched_on: 'shop.cloudflare.net' },
  { slug: 'aws-cloudfront', name: 'AWS CloudFront', confidence: 'high', source: 'CNAME', matched_on: 'd111111abcdef8.cloudfront.net' },
  { slug: 'vercel', name: 'Vercel', confidence: 'medium', source: 'CNAME', matched_on: 'cname.vercel.app' },
  { slug: 'github-pages', name: 'GitHub Pages', confidence: 'high', source: 'CNAME', matched_on: 'octocat.github.io' },
  { slug: 'azure', name: 'Microsoft Azure', confidence: 'medium', source: 'CNAME', matched_on: 'app.cloudapp.azure.com' },
];
export const UNKNOWN: ProviderInfo = { slug: 'unknown', name: 'Unknown', confidence: 'low', source: '', matched_on: '' };

export function randomDnsProvider(rng: Rng): ProviderInfo {
  return rng.bool(0.25) ? UNKNOWN : rng.pick(DNS_PROVIDERS);
}

export function randomHostingProvider(rng: Rng): ProviderInfo {
  return rng.bool(0.4) ? UNKNOWN : rng.pick(HOSTING_PROVIDERS);
}

export type AnswerKind = 'records' | 'none' | 'nxdomain' | 'error';

export interface AnswerOptions {
  kind?: AnswerKind;
  count?: number;
  dns?: ProviderInfo;
  hosting?: ProviderInfo;
}

/** One HTTP 200 answer of POST /api/dns for `type`. */
export function randomAnswer(rng: Rng, domain: string, type: string, resolver: string, options: AnswerOptions = {}): ApiAnswer {
  const kind = options.kind ?? rng.weighted<AnswerKind>(['records', 'none', 'nxdomain', 'error'], [14, 3, 1, 2]);
  const providers = { dns_provider: options.dns ?? UNKNOWN, hosting_provider: options.hosting ?? UNKNOWN };

  if (kind === 'error') {
    return rng.weighted<() => ApiAnswer>(
      [
        () => ({ error: `DNS lookup failed with ${rng.pick(['SERVFAIL', 'REFUSED', 'FORMERR', 'NOTIMP'])}.`, records: [], status: 2, _type: type, ...providers }),
        () => ({ error: 'DNS query failed: fetch failed', records: [], _type: type, dns_provider: UNKNOWN, hosting_provider: UNKNOWN }),
        () => ({ error: `DNS resolver returned HTTP ${rng.pick([400, 502, 503])}`, records: [], _type: type }),
      ],
      [2, 1, 1],
    )();
  }
  if (kind === 'nxdomain') {
    return { domain, type, resolver, records: [], status: 3, _type: type, noRecords: true, message: `No ${type} records found. ${domain} does not exist.`, ...providers };
  }
  if (kind === 'none') {
    return { domain, type, resolver, records: [], status: 0, _type: type, noRecords: true, message: `No ${type} records found for ${domain}.`, ...providers };
  }
  const count = options.count ?? rng.weighted([1, rng.int(2, 6), rng.int(20, 40)], [3, 5, 1]);
  return { domain, type, resolver, records: randomRecords(rng, type, domain, count), status: 0, _type: type, ...providers };
}

export interface LookupOptions {
  domain?: string;
  resolver?: string;
  types?: readonly string[];
  /** Force the kind of every answer; default is a random mix. */
  kind?: AnswerKind;
  /**
   * 'same': every type carries the same detection, as the real backend does.
   * 'mixed': each type carries its own, to exercise how the cards choose.
   */
  providers?: 'same' | 'mixed' | 'unknown';
}

/** A lookup (what the user asks for) with the answer the fake backend gives for each type. */
export function randomLookup(rng: Rng, options: LookupOptions = {}): Lookup {
  const domain = options.domain ?? randomDomain(rng);
  const resolver = options.resolver ?? rng.pick(RESOLVERS).value;
  const types = [...(options.types ?? rng.sample(OFFERED_TYPES, rng.int(1, OFFERED_TYPES.length)))];
  const mode = options.providers ?? rng.pick(['same', 'mixed'] as const);
  const sameDns = randomDnsProvider(rng);
  const sameHosting = randomHostingProvider(rng);

  // 'mixed': at most one named provider holds the top confidence, because the
  // page's choice between two different providers of equal confidence is not
  // defined anywhere (README section 6, tie-breaking).
  const mixed = (pool: ProviderInfo[]) => {
    const winner = rng.pick(pool);
    const weaker = pool.filter(p => p.name !== winner.name).map(p => ({ ...p, confidence: winner.confidence === 'high' ? rng.pick(['medium', 'low']) : 'low' }));
    const choices: ProviderInfo[] = [UNKNOWN, ...weaker];
    const holder = rng.int(0, types.length - 1);
    return types.map((_, i) => (i === holder ? winner : rng.pick(choices)));
  };
  const dnsList = mode === 'mixed' ? mixed(DNS_PROVIDERS) : types.map(() => (mode === 'same' ? sameDns : UNKNOWN));
  const hostingList = mode === 'mixed' ? mixed(HOSTING_PROVIDERS) : types.map(() => (mode === 'same' ? sameHosting : UNKNOWN));

  const replies: Record<string, Reply> = {};
  types.forEach((type, i) => {
    replies[type] = { kind: 'answer', body: randomAnswer(rng, domain, type, resolver, { kind: options.kind, dns: dnsList[i], hosting: hostingList[i] }) };
  });
  return { domain, resolver, types, replies };
}

// ─── Global propagation ───

/** One record in the shape Node's `dns` module returns for `type`. */
export function randomGlobalRecord(rng: Rng, type: string, domain: string): GlobalRecord {
  switch (type) {
    case 'A': return randomIpv4(rng);
    case 'AAAA': return randomIpv6(rng);
    case 'TXT': {
      const text = randomTxt(rng);
      // Long values arrive as several chunks of one record.
      return text.length > 60 && !text.includes(' ') ? [text.slice(0, 40), text.slice(40)] : [text];
    }
    case 'MX': return { exchange: randomHost(rng), priority: rng.pick([0, 1, 10, 20, 50]) };
    case 'SRV': return { name: randomHost(rng), port: rng.int(1, 65535), priority: rng.int(0, 50), weight: rng.int(0, 100) };
    case 'SOA':
      return {
        nsname: randomHost(rng), hostmaster: `hostmaster.${domain}`, serial: rng.int(1, 4294967295),
        refresh: rng.pick([3600, 7200, 10000]), retry: rng.pick([600, 2400]), expire: rng.pick([604800, 1209600]), minttl: rng.pick([300, 3600]),
      };
    case 'CAA': return `0 issue "${rng.pick(['letsencrypt.org', 'digicert.com', 'pki.goog'])}"`;
    default: return randomHost(rng); // CNAME, NS, PTR
  }
}

export type GlobalMix = 'all-ok' | 'some-failed' | 'all-failed' | 'differing';

/** The `results` array of POST /api/dns/global: one entry per region. */
export function randomGlobalResults(rng: Rng, type: string, domain: string, mix: GlobalMix): GlobalRegion[] {
  const consensus = Array.from({ length: rng.int(1, 4) }, () => randomGlobalRecord(rng, type, domain));
  const errors = ['HTTP 502 Bad Gateway', 'The operation was aborted due to timeout', 'fetch failed', `HTTP 403 {"Message":"Forbidden"}`, `<b>${MARKUP_PROBES[0]}</b>`];
  const failedRegions = new Set(
    mix === 'all-failed' ? GLOBAL_REGIONS
      : mix === 'some-failed' ? rng.sample(GLOBAL_REGIONS, rng.int(1, 6))
        : [],
  );
  const stale = new Set(mix === 'differing' ? rng.sample(GLOBAL_REGIONS, rng.int(2, 7)) : []);
  const emptyRegions = new Set(mix === 'all-failed' ? [] : rng.sample(GLOBAL_REGIONS.filter(r => !failedRegions.has(r)), rng.int(0, 2)));

  return GLOBAL_REGIONS.map((region): GlobalRegion => {
    if (failedRegions.has(region)) return { region, status: 'error', error: rng.pick(errors) };
    const records = emptyRegions.has(region) ? []
      : stale.has(region) ? Array.from({ length: rng.int(1, 3) }, () => randomGlobalRecord(rng, type, domain))
        : rng.shuffle(consensus);
    return { region, status: 'success', data: { records, duration_ms: rng.int(1, 2500) } };
  });
}
