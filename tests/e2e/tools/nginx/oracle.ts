import type { GeneratedLog, LogRequest } from './generator';
import { ipv4InCidr } from './generator';

/**
 * Traffic Analyzer oracle: what the dashboard must show for a generated log.
 *
 * Everything here is computed from the generator's records. Nothing is read
 * from the page and no application code is used.
 *
 * DEFINITIONS (sources: the page's own labels and its "What is excluded?" help)
 *
 *  Excluded lines
 *    - "Ignore internal requests" on: a request from a private, loopback,
 *      link-local, CGNAT or IPv6 unique-local address is excluded and counted
 *      under "private/local IP". Otherwise a request to an exact health-check
 *      path (query string and trailing slash ignored) is excluded and counted
 *      under "health-check path".
 *    - "Ignore 403 responses" on: a remaining request with status 403 is
 *      excluded and counted under "ordinary 403", unless its user agent is a
 *      crawler or scripted client (those are kept for bot analysis).
 *    - Each excluded line is counted once, in that order of precedence.
 *    - A line that is not a request is "invalid". Blank lines are ignored.
 *    - Parsed = kept requests. Skipped = all excluded lines + invalid lines.
 *  Time
 *    - Times are the wall-clock times written in the log, shown as written.
 *    - The time span covers every request line, including excluded ones.
 *  Counts (always over the requests that match the active filters)
 *    - Total requests, unique client addresses, unique networks (ASN; "unknown"
 *      is one bucket), unique countries ("Unknown" is one bucket).
 *    - Human share = requests from browsers / total, as a whole percent.
 *    - Verified bots = crawler requests from an address inside the publisher's
 *      published ranges. Spoofed = a crawler user agent whose publisher
 *      publishes ranges, from an address outside them. Unverified = every
 *      other automated client.
 *    - Error share = (4xx + 5xx) / total, one decimal.
 *  Filters
 *    - Method, country, network and traffic class match exactly.
 *    - Address search: text without "/" matches addresses containing it;
 *      "a.b.c.d/n" matches IPv4 addresses inside that network.
 *    - Path search: requests whose URL contains the text, ignoring case.
 *    - Time window: start <= time <= end.
 */

export interface AnalysisOptions {
  skip403: boolean;
  skipInternal: boolean;
}

export type TrafficFilter = 'human' | 'all_bots' | 'verified' | 'spoofed' | 'unverified';

export interface ViewFilters {
  method?: string;
  country?: string;
  /** Bare AS number; 0 is the "unknown network" bucket. */
  asn?: number;
  traffic?: TrafficFilter;
  /** Bot group name, as applied by clicking a Bot Intelligence row. */
  botGroup?: string;
  ipSearch?: string;
  pathSearch?: string;
  window?: { startMs: number; endMs: number };
}

export interface Analysis {
  kept: LogRequest[];
  skipped: { internalAddress: number; healthCheck: number; forbidden: number; invalid: number; total: number };
  /** First and last request time over all request lines, excluded ones included. */
  span: { minTs: number; maxTs: number; minutes: number } | null;
}

export const DEFAULT_OPTIONS: AnalysisOptions = { skip403: true, skipInternal: true };

export function analyse(log: GeneratedLog, options: AnalysisOptions = DEFAULT_OPTIONS): Analysis {
  const kept: LogRequest[] = [];
  const skipped = { internalAddress: 0, healthCheck: 0, forbidden: 0, invalid: log.invalidLines.length, total: 0 };
  for (const request of log.requests) {
    if (options.skipInternal && request.internalAddress) skipped.internalAddress++;
    else if (options.skipInternal && request.healthCheck) skipped.healthCheck++;
    else if (options.skip403 && request.status === 403 && request.agent.kind === 'human') skipped.forbidden++;
    else kept.push(request);
  }
  skipped.total = skipped.internalAddress + skipped.healthCheck + skipped.forbidden + skipped.invalid;

  let span: Analysis['span'] = null;
  if (log.requests.length > 0) {
    const times = log.requests.map(r => r.ts);
    const minTs = times.reduce((a, b) => Math.min(a, b));
    const maxTs = times.reduce((a, b) => Math.max(a, b));
    span = { minTs, maxTs, minutes: Math.floor((maxTs - minTs) / 60_000) };
  }
  return { kept, skipped, span };
}

export function matches(request: LogRequest, filters: ViewFilters): boolean {
  if (filters.method && request.method !== filters.method) return false;
  if (filters.country && request.geo.country !== filters.country) return false;
  if (filters.asn !== undefined && request.geo.asn !== filters.asn) return false;
  if (filters.traffic) {
    const isHuman = request.trafficClass === 'human';
    if (filters.traffic === 'human' && !isHuman) return false;
    if (filters.traffic === 'all_bots' && isHuman) return false;
    if (['verified', 'spoofed', 'unverified'].includes(filters.traffic) && request.trafficClass !== filters.traffic) return false;
  }
  if (filters.botGroup && request.agent.group !== filters.botGroup) return false;
  if (filters.ipSearch) {
    const term = filters.ipSearch.trim().toLowerCase();
    if (term.includes('/')) {
      if (request.ip.includes(':') || !ipv4InCidr(request.ip, term)) return false;
    } else if (!request.ip.toLowerCase().includes(term)) return false;
  }
  if (filters.pathSearch && !request.url.toLowerCase().includes(filters.pathSearch.toLowerCase())) return false;
  if (filters.window && (request.ts < filters.window.startMs || request.ts > filters.window.endMs)) return false;
  return true;
}

export function applyFilters(kept: LogRequest[], filters: ViewFilters): LogRequest[] {
  return kept.filter(request => matches(request, filters));
}

export interface Ranked<K> { key: K; hits: number }

/** Counts by key, highest first. Ties keep no promised order. */
export function rank<K>(requests: LogRequest[], keyOf: (r: LogRequest) => K | null): Ranked<K>[] {
  const counts = new Map<K, number>();
  for (const request of requests) {
    const key = keyOf(request);
    if (key !== null) counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()].map(([key, hits]) => ({ key, hits })).sort((a, b) => b.hits - a.hits);
}

export interface Summary {
  total: number;
  uniqueIps: number;
  uniqueAsns: number;
  uniqueCountries: number;
  human: number;
  verified: number;
  spoofed: number;
  unverified: number;
  errors: number;
  bytes: number;
  methods: Ranked<string>[];
  countries: Ranked<string>[];
  asns: Ranked<number>[];
  asnOrg: Map<number, string>;
  ips: Ranked<string>[];
  /** Referrer exactly as logged; "-" stands for none. */
  referrers: Ranked<string>[];
  /** Request path: the URL without its query string. */
  paths: Ranked<string>[];
  /** First path segment, e.g. "/api" for "/api/v1/users". Root has none. */
  firstSegments: Ranked<string>[];
  /** One entry per bot group and verification status present. */
  botRows: { group: string; status: 'verified' | 'spoofed' | 'unverified'; hits: number }[];
  botGroups: number;
}

export function pathOf(url: string): string {
  const cut = url.search(/[?#]/);
  return cut === -1 ? url : url.slice(0, cut);
}

export function firstSegmentOf(url: string): string | null {
  const parts = pathOf(url).split('/').filter(Boolean);
  return parts.length ? `/${parts[0]}` : null;
}

export function summarise(requests: LogRequest[]): Summary {
  const count = (test: (r: LogRequest) => boolean) => requests.filter(test).length;
  const asnOrg = new Map<number, string>();
  for (const r of requests) asnOrg.set(r.geo.asn, r.geo.asnOrg);

  const groups = new Map<string, { verified: number; spoofed: number; unverified: number }>();
  for (const r of requests) {
    if (r.trafficClass === 'human') continue;
    const entry = groups.get(r.agent.group) ?? { verified: 0, spoofed: 0, unverified: 0 };
    entry[r.trafficClass]++;
    groups.set(r.agent.group, entry);
  }
  const botRows: Summary['botRows'] = [];
  for (const [group, entry] of groups) {
    for (const status of ['verified', 'spoofed', 'unverified'] as const) {
      if (entry[status] > 0) botRows.push({ group, status, hits: entry[status] });
    }
  }

  return {
    total: requests.length,
    uniqueIps: new Set(requests.map(r => r.ip)).size,
    uniqueAsns: new Set(requests.map(r => r.geo.asn)).size,
    uniqueCountries: new Set(requests.map(r => r.geo.country)).size,
    human: count(r => r.trafficClass === 'human'),
    verified: count(r => r.trafficClass === 'verified'),
    spoofed: count(r => r.trafficClass === 'spoofed'),
    unverified: count(r => r.trafficClass === 'unverified'),
    errors: count(r => r.status >= 400 && r.status <= 599),
    bytes: requests.reduce((sum, r) => sum + r.bytes, 0),
    methods: rank(requests, r => r.method),
    countries: rank(requests, r => r.geo.country),
    asns: rank(requests, r => r.geo.asn),
    asnOrg,
    ips: rank(requests, r => r.ip),
    referrers: rank(requests, r => r.referrer ?? '-'),
    paths: rank(requests, r => pathOf(r.url)),
    firstSegments: rank(requests, r => firstSegmentOf(r.url)),
    botRows,
    botGroups: groups.size,
  };
}

/** Share of `part` in `total` as a percentage (exact, unrounded). */
export function share(part: number, total: number): number {
  return total === 0 ? 0 : (part / total) * 100;
}

export interface TimelineBucket { startMs: number; count: number; errors: number }

/**
 * Requests per bucket of `bucketSeconds`, buckets aligned to the clock
 * (a 60 s bucket starts at :00). Runs from the first to the last request and
 * includes empty buckets in between.
 */
export function timeline(requests: LogRequest[], bucketSeconds: number): TimelineBucket[] {
  if (requests.length === 0) return [];
  const size = bucketSeconds * 1000;
  const slot = (ts: number) => Math.floor(ts / size);
  const first = requests.reduce((min, r) => Math.min(min, slot(r.ts)), Infinity);
  const last = requests.reduce((max, r) => Math.max(max, slot(r.ts)), -Infinity);
  const buckets: TimelineBucket[] = [];
  for (let s = first; s <= last; s++) buckets.push({ startMs: s * size, count: 0, errors: 0 });
  for (const r of requests) {
    const bucket = buckets[slot(r.ts) - first];
    bucket.count++;
    if (r.status >= 400 && r.status <= 599) bucket.errors++;
  }
  return buckets;
}

const two = (n: number) => String(n).padStart(2, '0');

/** `2026-06-01 10:00:00` — the wall-clock time as written in the log. */
export function stamp(ts: number): string {
  const d = new Date(ts);
  return `${d.getUTCFullYear()}-${two(d.getUTCMonth() + 1)}-${two(d.getUTCDate())} ${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())}`;
}

/** `10:00:00` */
export function clock(ts: number): string {
  return stamp(ts).slice(11);
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** `01/Jun/2026 10:00:00` — the form used in the "Span" line. */
export function spanStamp(ts: number): string {
  const d = new Date(ts);
  return `${two(d.getUTCDate())}/${MONTHS[d.getUTCMonth()]}/${d.getUTCFullYear()} ${clock(ts)}`;
}

export function sameDay(a: number, b: number): boolean {
  return stamp(a).slice(0, 10) === stamp(b).slice(0, 10);
}

/** `2h 16m 6s`: zero parts are left out; a zero duration is `0s`. */
export function duration(ms: number): string {
  const seconds = Math.round(ms / 1000);
  const parts = [
    seconds >= 3600 ? `${Math.floor(seconds / 3600)}h` : '',
    Math.floor(seconds / 60) % 60 ? `${Math.floor(seconds / 60) % 60}m` : '',
    seconds % 60 || seconds === 0 ? `${seconds % 60}s` : '',
  ];
  return parts.filter(Boolean).join(' ');
}

export interface ExplorerRow {
  time: string;
  ip: string;
  method: string;
  /** The explorer shows at most the first 40 characters of the URL. */
  path: string;
  status: string;
  countryCode: string;
  country: string;
  protocol: string;
  userAgent: string;
}

export function explorerRow(r: LogRequest): ExplorerRow {
  return {
    time: stamp(r.ts),
    ip: r.ip,
    method: r.method,
    path: r.url.slice(0, 40),
    status: String(r.status),
    countryCode: r.geo.countryCode,
    country: r.geo.country,
    protocol: r.protocol,
    userAgent: r.agent.userAgent,
  };
}

export function rowKey(row: ExplorerRow): string {
  return [row.time, row.ip, row.method, row.path, row.status, row.countryCode, row.country, row.protocol, row.userAgent].join(' | ');
}

/** Newest first, as the Log Explorer lists them. Order within one second is not promised. */
export function explorerRows(requests: LogRequest[]): ExplorerRow[] {
  return requests.slice().sort((a, b) => b.ts - a.ts).map(explorerRow);
}

/** `1234567` → `1,234,567` */
export function grouped(value: number): string {
  return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/** Size in the unit the page chose, for comparing a rounded display such as `1.7 MB`. */
export function inUnit(bytes: number, unit: string): number {
  const power = ['B', 'KB', 'MB', 'GB'].indexOf(unit);
  return power < 0 ? NaN : bytes / 1024 ** power;
}
