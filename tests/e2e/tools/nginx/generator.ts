import type { Rng } from '../_support/rng';
import type { GeoFacts, GeoOracle } from './geo';
import {
  BROWSERS, FEED_CRAWLERS, UNLISTED_AGENTS, FEED_RANGES, NESTED_URLS, PROBE_URLS, FLAT_URLS, REFERRERS,
  METHODS, STATUSES, PROTOCOLS, HEALTH_PATHS, INTERNAL_ADDRESSES, INVALID_LINES,
  type Agent, type TrafficClass,
} from './catalog';

/**
 * Random access-log generator.
 *
 * Returns the log text together with what is true about every line (the
 * ground truth). The oracle computes all expectations from these records and
 * never looks at how the application parses the text.
 */

/** Why a line is left out of the analysis when the matching option is on. */
export type Exclusion = 'none' | 'internal-address' | 'health-check' | 'forbidden';

export interface LogRequest {
  /** 1-based line number in the generated text. */
  lineNo: number;
  line: string;
  ip: string;
  /** Wall-clock time written in the log, as epoch milliseconds (UTC). */
  ts: number;
  method: string;
  /** Request target exactly as logged, including any query string. */
  url: string;
  protocol: string;
  status: number;
  /** Body bytes sent; 0 when the log has `-`. */
  bytes: number;
  /** null when the log has `-`. */
  referrer: string | null;
  agent: Agent;
  trafficClass: TrafficClass;
  geo: GeoFacts;
  internalAddress: boolean;
  healthCheck: boolean;
}

export interface GeneratedLog {
  text: string;
  requests: LogRequest[];
  /** Lines that are not requests (counted by the tool as "invalid"). */
  invalidLines: string[];
  /** Blank lines in the text; the tool ignores them entirely. */
  blankLines: number;
  options: Required<GeneratorOptions>;
}

export interface GeneratorOptions {
  /** Number of request lines. */
  requests?: number;
  /** Number of distinct public client addresses. */
  clients?: number;
  /** Seconds between the first and the last request. */
  spanSeconds?: number;
  /** Time of the first request (UTC). */
  start?: Date;
  /** `nested`: realistic multi-segment paths with query strings. `flat`: one segment, no query. */
  urls?: 'nested' | 'flat';
  /** Share of requests from internal addresses (excluded by "Ignore internal requests"). */
  internalShare?: number;
  /** Share of requests to health-check paths. */
  healthShare?: number;
  /** Number of non-request lines mixed in (after the first 20 lines). */
  invalidLines?: number;
  /** Include IPv6 clients. */
  ipv6?: boolean;
  /** Include 403 responses (subject to "Ignore 403 responses"). */
  forbidden?: boolean;
  /** Let several requests share a second, so the timeline has real peaks. */
  bursts?: boolean;
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad = (n: number) => String(n).padStart(2, '0');

/** `01/Jun/2026:10:00:00 +0000` */
export function logTimestamp(ts: number): string {
  const d = new Date(ts);
  return `${pad(d.getUTCDate())}/${MONTHS[d.getUTCMonth()]}/${d.getUTCFullYear()}:${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +0000`;
}

export function formatLine(r: Pick<LogRequest, 'ip' | 'ts' | 'method' | 'url' | 'protocol' | 'status' | 'bytes' | 'referrer'> & { userAgent: string; bytesDash?: boolean }): string {
  return `${r.ip} - - [${logTimestamp(r.ts)}] "${r.method} ${r.url} ${r.protocol}" ${r.status} ${r.bytesDash ? '-' : r.bytes} "${r.referrer ?? '-'}" "${r.userAgent}"`;
}

function ipv4ToNumber(ip: string): number {
  return ip.split('.').reduce((acc, part) => acc * 256 + Number(part), 0);
}

function numberToIpv4(value: number): string {
  return [24, 16, 8, 0].map(shift => Math.floor(value / 2 ** shift) % 256).join('.');
}

/** True when `ip` (IPv4) lies inside `cidr`. Plain arithmetic, no bit operators. */
export function ipv4InCidr(ip: string, cidr: string): boolean {
  const [base, bits] = cidr.split('/');
  const size = 2 ** (32 - Number(bits));
  const start = Math.floor(ipv4ToNumber(base) / size) * size;
  const value = ipv4ToNumber(ip);
  return value >= start && value < start + size;
}

function randomAddressIn(rng: Rng, cidr: string): string {
  const [base, bits] = cidr.split('/');
  const size = 2 ** (32 - Number(bits));
  const start = Math.floor(ipv4ToNumber(base) / size) * size;
  return numberToIpv4(start + rng.int(1, Math.max(1, size - 2)));
}

/** A public, routable-looking IPv4 address (no private, reserved, multicast or documentation ranges). */
function randomPublicIpv4(rng: Rng): string {
  for (;;) {
    const a = rng.int(1, 223);
    const b = rng.int(0, 255);
    if (a === 10 || a === 127 || a === 0) continue;
    if (a === 100 && b >= 64 && b <= 127) continue;
    if (a === 169 && b === 254) continue;
    if (a === 172 && b >= 16 && b <= 31) continue;
    if (a === 192 && (b === 168 || b === 0)) continue;
    if (a === 198 && (b === 18 || b === 19 || b === 51)) continue;
    if (a === 203 && b === 0) continue;
    const ip = `${a}.${b}.${rng.int(0, 255)}.${rng.int(1, 254)}`;
    if (Object.values(FEED_RANGES).some(entry => entry.ipv4.some(cidr => ipv4InCidr(ip, cidr)))) continue;
    return ip;
  }
}

const IPV6_PREFIXES = ['2606:4700:4700', '2a00:1450:4001', '2620:fe:0', '2a03:2880:f003', '2400:cb00:2048', '2001:67c:2e8'];

function randomPublicIpv6(rng: Rng): string {
  const group = () => rng.int(1, 0xffff).toString(16);
  return `${rng.pick(IPV6_PREFIXES)}:${group()}::${group()}`;
}

interface Client {
  ip: string;
  agent: Agent;
  trafficClass: TrafficClass;
  weight: number;
  probes: boolean;
}

function firstSegment(url: string): string {
  const path = url.split('?')[0];
  const rest = path.slice(1);
  const end = rest.indexOf('/');
  return '/' + (end === -1 ? rest : rest.slice(0, end));
}

/** Guards the promise made in catalog.ts about the default path set. */
function assertUnambiguousUrls(urls: string[]): void {
  const segments = new Set(urls.map(firstSegment).filter(s => s !== '/'));
  for (const segment of segments) {
    for (const url of urls) {
      if (firstSegment(url) !== segment && url.toLowerCase().includes(segment.toLowerCase())) {
        throw new Error(`catalogue error: "${segment}" also occurs inside "${url}"; the default URL set must be unambiguous`);
      }
    }
  }
}
assertUnambiguousUrls([...NESTED_URLS, ...PROBE_URLS]);
assertUnambiguousUrls(FLAT_URLS);

export function generateLog(rng: Rng, geo: GeoOracle, options: GeneratorOptions = {}): GeneratedLog {
  const opts: Required<GeneratorOptions> = {
    requests: options.requests ?? rng.int(350, 800),
    clients: options.clients ?? rng.int(14, 34),
    spanSeconds: options.spanSeconds ?? rng.int(25 * 60, 170 * 60),
    // Any day of 2026; the hour is free, so some runs cross midnight.
    start: options.start ?? new Date(Date.UTC(2026, rng.int(0, 11), rng.int(1, 28), rng.int(0, 23), rng.int(0, 59), rng.int(0, 59))),
    urls: options.urls ?? 'nested',
    internalShare: options.internalShare ?? 0.04,
    healthShare: options.healthShare ?? 0.03,
    invalidLines: options.invalidLines ?? rng.int(2, 5),
    ipv6: options.ipv6 ?? true,
    forbidden: options.forbidden ?? true,
    bursts: options.bursts ?? true,
  };

  // ── Clients ──
  const clients: Client[] = [];
  const used = new Set<string>();
  const add = (ip: string, agent: Agent, trafficClass: TrafficClass, probes = false) => {
    if (used.has(ip)) return;
    used.add(ip);
    // A few heavy hitters and a long tail, like real traffic.
    clients.push({ ip, agent, trafficClass, probes, weight: Math.ceil(60 / (clients.length + 1)) + rng.int(1, 6) });
  };

  // Every traffic class is present in every generated log.
  for (const crawler of FEED_CRAWLERS) {
    const range = FEED_RANGES[crawler.feedKey as string];
    add(randomAddressIn(rng, rng.pick(range.ipv4)), crawler, 'verified');
  }
  for (const crawler of rng.sample(FEED_CRAWLERS, 2)) add(randomPublicIpv4(rng), crawler, 'spoofed', true);
  for (const agent of rng.sample(UNLISTED_AGENTS, 3)) add(randomPublicIpv4(rng), agent, 'unverified', agent.kind === 'tool');

  // Humans fill the rest; neighbours in one /24 share a network and country.
  let anchor = randomPublicIpv4(rng);
  while (clients.length < opts.clients) {
    if (opts.ipv6 && rng.bool(0.12)) { add(randomPublicIpv6(rng), rng.pick(BROWSERS), 'human'); continue; }
    if (rng.bool(0.45)) anchor = randomPublicIpv4(rng);
    const ip = rng.bool(0.5) ? anchor : `${anchor.split('.').slice(0, 3).join('.')}.${rng.int(1, 254)}`;
    add(ip, rng.pick(BROWSERS), 'human');
  }

  const urls = opts.urls === 'flat' ? FLAT_URLS : NESTED_URLS;
  const probeUrls = opts.urls === 'flat' ? FLAT_URLS.filter(u => /wp-login|xmlrpc|\.env/.test(u)) : PROBE_URLS;
  const statuses = opts.forbidden ? STATUSES : STATUSES.filter(s => s.status !== 403);

  // ── Times: sorted, first and last pinned to the requested span ──
  const startMs = Math.floor(opts.start.getTime() / 1000) * 1000;
  const offsets = [0, opts.spanSeconds];
  while (offsets.length < opts.requests) {
    const at = rng.int(0, opts.spanSeconds);
    offsets.push(at);
    if (opts.bursts && rng.bool(0.08)) {
      for (let i = rng.int(2, 6); i > 0 && offsets.length < opts.requests; i--) offsets.push(at);
    }
  }
  offsets.sort((a, b) => a - b);

  // ── Requests ──
  const requests: LogRequest[] = [];
  const weights = clients.map(c => c.weight);
  for (let i = 0; i < opts.requests; i++) {
    const client = rng.weighted(clients, weights);
    let ip = client.ip;
    let agent = client.agent;
    let trafficClass = client.trafficClass;
    let url = client.probes && rng.bool(0.6) ? rng.pick(probeUrls) : rng.pick(urls);
    let internalAddress = false;
    let healthCheck = false;

    const roll = rng.next();
    if (roll < opts.internalShare) {
      ip = rng.pick(INTERNAL_ADDRESSES);
      agent = rng.pick(BROWSERS);
      trafficClass = 'human';
      internalAddress = true;
    } else if (roll < opts.internalShare + opts.healthShare) {
      url = rng.pick(HEALTH_PATHS) + rng.pick(['', '', '/', '?probe=1']);
      healthCheck = true;
    }

    const status = rng.weighted(statuses, statuses.map(s => s.weight)).status;
    const bytesDash = status === 304 && rng.bool(0.5);
    const record = {
      ip,
      ts: startMs + offsets[i] * 1000,
      method: rng.weighted(METHODS, METHODS.map(m => m.weight)).method,
      url,
      protocol: rng.weighted(PROTOCOLS, PROTOCOLS.map(p => p.weight)).protocol,
      status,
      bytes: bytesDash ? 0 : (status === 304 ? 0 : rng.int(0, 60_000)),
      referrer: agent.kind === 'human' && rng.bool(0.45) ? rng.pick(REFERRERS) : null,
    };
    requests.push({
      ...record,
      lineNo: 0,
      line: formatLine({ ...record, userAgent: agent.userAgent, bytesDash }),
      agent,
      trafficClass,
      geo: geo.lookup(ip),
      internalAddress,
      healthCheck,
    });
  }

  // ── Assemble the text: non-request and blank lines go after line 20 ──
  const invalidLines = Array.from({ length: opts.invalidLines }, () => rng.pick(INVALID_LINES));
  const lines: string[] = requests.map(r => r.line);
  const blankLines = rng.int(0, 3);
  const extras = [...invalidLines, ...Array.from({ length: blankLines }, () => '')];
  for (const extra of extras) {
    const at = lines.length <= 21 ? lines.length : rng.int(21, lines.length);
    lines.splice(at, 0, extra);
  }
  let cursor = 0;
  lines.forEach((line, index) => {
    if (cursor < requests.length && line === requests[cursor].line && line !== '') {
      requests[cursor].lineNo = index + 1;
      cursor++;
    }
  });

  return { text: lines.join('\n'), requests, invalidLines, blankLines, options: opts };
}

/** A request record for hand-built logs in edge-case tests. */
export function buildRequest(geo: GeoOracle, fields: Partial<LogRequest> & { ip: string; ts: number; agent: Agent; trafficClass?: TrafficClass }): LogRequest {
  const record = {
    method: 'GET', url: '/', protocol: 'HTTP/1.1', status: 200, bytes: 512, referrer: null as string | null,
    ...fields,
  };
  return {
    lineNo: 0,
    line: formatLine({ ...record, userAgent: fields.agent.userAgent }),
    trafficClass: fields.trafficClass ?? (fields.agent.kind === 'human' ? 'human' : 'unverified'),
    geo: geo.lookup(fields.ip),
    internalAddress: false,
    healthCheck: false,
    ...record,
  } as LogRequest;
}

export function logFromRequests(requests: LogRequest[]): GeneratedLog {
  requests.forEach((r, i) => { r.lineNo = i + 1; });
  return {
    text: requests.map(r => r.line).join('\n'),
    requests,
    invalidLines: [],
    blankLines: 0,
    options: {} as Required<GeneratorOptions>,
  };
}
