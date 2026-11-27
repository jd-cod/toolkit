/**
 * Independent expectations for IP Info & Security Risk Lookup (/abuse).
 *
 * Nothing here imports application code. Every rule is written from a
 * definition, stated in words before the code that applies it.
 *
 * ── Definitions ──────────────────────────────────────────────────────────
 *
 * INPUT (source: the guide panel "Enter one IP per line, optionally followed
 * by a request count" and the page's own example "8.8.8.8 100").
 *   - One entry per line. Blank lines are ignored.
 *   - A line holds an address and, optionally, a request count after a
 *     separator. Separators: spaces or tabs (documented example); a comma or
 *     a pipe are also accepted (log exports such as "ip,count").
 *   - The address must be an IPv4 address in dotted-decimal form (RFC 3986
 *     `dec-octet`: four numbers 0–255, no leading zeros) or an IPv6 address
 *     in any RFC 4291 §2.2 text form (full, zero-compressed with one "::",
 *     or with a trailing dotted IPv4 part). Anything else is not an address
 *     and must not be looked up.
 *   - The request count is a whole number of at least 1. Without one the
 *     count is 1.
 *   - "IPs analysed" counts addresses, so an address listed twice is one IP.
 *     (The page has no text about duplicates; the counters are labelled
 *     "Total IPs Analyzed", and counting one address twice doubles every
 *     counter an operator reads. This is a definition made by this suite.)
 *
 * RESULT ROW (source: column headers and the three data sources the page
 * names in its introduction: reverse DNS and risk from POST /api/ipinfo,
 * AbuseIPDB reputation from POST /api/abuse, country and ASN from the GeoIP
 * database the browser loads from /data/*.mmdb).
 *   - Version tag: the version the IP-info service reports, else by syntax.
 *   - Reverse DNS (PTR): the PTR name from the IP-info service; without one,
 *     "No PTR record". The header promises a PTR record, so AbuseIPDB's
 *     registered `domain` is not a PTR, and the backend's "no data" markers
 *     (`N/A`, `ERROR`, `API_ERROR`) are never one.
 *   - Country: the country of the first source that knows one, in this
 *     order: AbuseIPDB, IP-info service, GeoIP database. Flag, name and code
 *     always describe that same country. The name is the source's own name
 *     when it gives one, else the English name of the ISO code. The flag is
 *     the pair of Unicode regional-indicator letters for the code, a globe
 *     when no country is known.
 *   - ASN: the GeoIP database's number, else the IP-info service's.
 *   - Network / ISP: AbuseIPDB's ISP, else the IP-info service's, else the
 *     GeoIP organisation. When nobody knows, a placeholder.
 *   - Usage type: AbuseIPDB's; "Private Network" for private addresses.
 *   - Abuse score: AbuseIPDB's confidence 0–100 with a percent sign; "N/A"
 *     when AbuseIPDB gave no answer for the address. "0%" means "checked,
 *     nothing reported" and must never appear for an address that was not
 *     checked.
 *   - Risk badge (thresholds restated from the page, which is the only place
 *     they are written): start from the IP-info service's level (Safe, Low,
 *     Medium, High, Unknown). An AbuseIPDB score of 75 or more makes it
 *     High; a score of 25 to 74 makes it at least Medium; 1 to 24 leaves it
 *     as it is; 0 or no score leaves it as it is. An address the service
 *     calls `unknown` (it could not classify it) is not "Low".
 *
 * COUNTERS
 *   - Total IPs Analyzed: number of result rows.
 *   - Reverse DNS Found: rows that have a PTR name.
 *   - Risk Flags / Elevated: rows whose badge is Medium or High.
 *   - Abuse Reports: rows whose AbuseIPDB score is above 0.
 *   Filter buttons carry the same numbers and show exactly those rows.
 */

export type RiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'unknown';

/** One element of `results` in the POST /api/ipinfo answer. */
export interface IpInfoRecord {
  ip: string;
  is_valid?: boolean;
  is_private?: boolean;
  ip_version?: string;
  reverse_dns?: string;
  country?: string;
  country_code?: string;
  asn?: number | string;
  asn_org?: string;
  isp?: string;
  risk_level?: RiskLevel;
  risk_reasons?: string[];
}

/** One AbuseIPDB entry, in either spelling the page accepts. */
export interface AbuseRecord {
  ip?: string; ipAddress?: string;
  hits?: number;
  domain?: string;
  isp?: string;
  country?: string; countryName?: string;
  country_code?: string; countryCode?: string;
  usage_type?: string; usageType?: string;
  abuse_score?: number; abuseConfidenceScore?: number;
  total_reports?: number; totalReports?: number;
  num_distinct_users?: number;
  last_reported_at?: string;
  is_tor?: boolean;
  is_whitelisted?: boolean;
  error?: string;
}

export interface AbuseResponse {
  api_available?: boolean;
  abusive?: AbuseRecord[];
  non_abusive?: AbuseRecord[];
  results?: AbuseRecord[];
  checked_count?: number;
  error?: string;
}

/** What the GeoIP database knows about one address. A missing key means "not in the database". */
export interface GeoFacts {
  country?: string;
  country_code?: string;
  asn?: number;
  asn_org?: string;
}

export interface BatchEntry { ip: string; hits: number }

// ─── Address syntax ─────────────────────────────────────────────────────

function isDigits(text: string): boolean {
  if (text.length === 0) return false;
  for (const ch of text) if (ch < '0' || ch > '9') return false;
  return true;
}

/** RFC 3986 `IPv4address`: four `dec-octet`s, 0–255, no leading zeros. */
export function isIpv4(text: string): boolean {
  const parts = text.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!isDigits(part) || part.length > 3) return false;
    if (part.length > 1 && part[0] === '0') return false;
    if (Number(part) > 255) return false;
  }
  return true;
}

function isHexGroup(text: string): boolean {
  if (text.length < 1 || text.length > 4) return false;
  for (const ch of text.toLowerCase()) {
    if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
  }
  return true;
}

/**
 * The 16-bit groups of an RFC 4291 §2.2 IPv6 text address, or null when the
 * text is not one. Accepts the full form, one "::" standing for one or more
 * zero groups, and a dotted IPv4 tail in place of the last two groups.
 */
export function ipv6Groups(text: string): number[] | null {
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const sideGroups = (side: string): number[] | null => {
    if (side === '') return [];
    const fields = side.split(':');
    const out: number[] = [];
    for (let i = 0; i < fields.length; i++) {
      const field = fields[i];
      if (field.includes('.')) {
        if (i !== fields.length - 1 || !isIpv4(field)) return null;
        const [a, b, c, d] = field.split('.').map(Number);
        out.push(a * 256 + b, c * 256 + d);
      } else {
        if (!isHexGroup(field)) return null;
        out.push(parseInt(field, 16));
      }
    }
    return out;
  };
  const head = sideGroups(halves[0]);
  if (head === null) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;
  const tail = sideGroups(halves[1]);
  if (tail === null) return null;
  // A dotted tail is only legal at the very end of the address.
  if (halves[0].includes('.')) return null;
  const present = head.length + tail.length;
  if (present > 7) return null;
  return [...head, ...new Array<number>(8 - present).fill(0), ...tail];
}

export function isIpv6(text: string): boolean {
  return ipv6Groups(text) !== null;
}

export function ipVersionOf(text: string): 'IPv4' | 'IPv6' | '' {
  if (isIpv4(text)) return 'IPv4';
  if (isIpv6(text)) return 'IPv6';
  return '';
}

/**
 * Special-purpose addresses that are not public Internet hosts
 * (IANA IPv4 and IPv6 Special-Purpose Address Registries, RFC 6890):
 * private, loopback, link-local, shared, documentation, benchmarking,
 * multicast, reserved and unspecified ranges.
 */
export function isSpecialPurpose(ip: string): boolean {
  if (isIpv4(ip)) {
    const [a, b, c] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;        // 100.64.0.0/10 shared address space
    if (a === 169 && b === 254) return true;                  // link-local
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return true; // IETF protocol assignments, TEST-NET-1
    if (a === 192 && b === 168) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;     // benchmarking
    if (a === 198 && b === 51 && c === 100) return true;      // TEST-NET-2
    if (a === 203 && b === 0 && c === 113) return true;       // TEST-NET-3
    return a >= 224;                                          // multicast and reserved
  }
  const groups = ipv6Groups(ip);
  if (!groups) return false;
  const [g0, g1] = groups;
  if (groups.every(g => g === 0)) return true;                           // ::
  if (groups.slice(0, 7).every(g => g === 0) && groups[7] === 1) return true; // ::1
  if (groups.slice(0, 5).every(g => g === 0) && groups[5] === 0xffff) return true; // ::ffff:0:0/96
  if (g0 >= 0xfe80 && g0 <= 0xfebf) return true;                         // fe80::/10 link-local
  if (g0 >= 0xfc00 && g0 <= 0xfdff) return true;                         // fc00::/7 unique local
  if (g0 >= 0xff00) return true;                                         // ff00::/8 multicast
  if (g0 === 0x2001 && g1 === 0x0db8) return true;                       // 2001:db8::/32 documentation
  return false;
}

// ─── Batch input ────────────────────────────────────────────────────────

function splitFields(line: string): string[] {
  const fields: string[] = [];
  let current = '';
  for (const ch of line) {
    if (ch === ' ' || ch === '\t' || ch === ',' || ch === '|') {
      if (current !== '') { fields.push(current); current = ''; }
    } else current += ch;
  }
  if (current !== '') fields.push(current);
  return fields;
}

export interface ParsedBatch {
  /** Lines that hold a valid address, in input order (duplicates kept). */
  entries: BatchEntry[];
  /** Non-blank lines that do not start with a valid address. */
  rejected: string[];
}

export function parseBatch(text: string): ParsedBatch {
  const entries: BatchEntry[] = [];
  const rejected: string[] = [];
  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/\r$/, '').trim();
    if (line === '') continue;
    const [address, count] = splitFields(line);
    if (!address || ipVersionOf(address) === '') { rejected.push(line); continue; }
    const hits = count !== undefined && isDigits(count) && Number(count) >= 1 ? Number(count) : 1;
    entries.push({ ip: address, hits });
  }
  return { entries, rejected };
}

/** First occurrence of each address, in input order. */
export function uniqueEntries(entries: BatchEntry[]): BatchEntry[] {
  const seen = new Set<string>();
  return entries.filter(entry => (seen.has(entry.ip) ? false : (seen.add(entry.ip), true)));
}

// ─── Countries ──────────────────────────────────────────────────────────

/** English short names (CLDR) for the ISO 3166-1 codes the generator uses. */
export const COUNTRY_NAMES: Record<string, string> = {
  US: 'United States', DE: 'Germany', FR: 'France', NL: 'Netherlands', JP: 'Japan', BR: 'Brazil',
  IN: 'India', CA: 'Canada', AU: 'Australia', SE: 'Sweden', SG: 'Singapore', ZA: 'South Africa',
  MX: 'Mexico', IT: 'Italy', ES: 'Spain', PL: 'Poland', RU: 'Russia', CN: 'China', KR: 'South Korea',
  GB: 'United Kingdom', CH: 'Switzerland', IE: 'Ireland', FI: 'Finland', NO: 'Norway', UA: 'Ukraine',
  AR: 'Argentina', NZ: 'New Zealand', EG: 'Egypt', VN: 'Vietnam', ID: 'Indonesia',
};

const REGIONAL_INDICATORS = '🇦 🇧 🇨 🇩 🇪 🇫 🇬 🇭 🇮 🇯 🇰 🇱 🇲 🇳 🇴 🇵 🇶 🇷 🇸 🇹 🇺 🇻 🇼 🇽 🇾 🇿'.split(' ');
export const GLOBE = '🌐';

/** Flag emoji of a two-letter country code; a globe when there is none. */
export function flagOf(code: string): string {
  const upper = code.toUpperCase();
  if (upper.length !== 2) return GLOBE;
  const letters = [...upper].map(ch => REGIONAL_INDICATORS['ABCDEFGHIJKLMNOPQRSTUVWXYZ'.indexOf(ch)]);
  return letters.every(Boolean) ? letters.join('') : GLOBE;
}

/** Strings the application and its backend use to say "no value". */
export const PLACEHOLDERS = ['', '—', '-', '--', 'N/A', 'Unknown', 'ERROR', 'API_ERROR'];
export function isPlaceholder(text: string | undefined | null): boolean {
  return text === undefined || text === null || PLACEHOLDERS.includes(String(text).trim());
}
const real = (text: string | undefined | null): string => (isPlaceholder(text) ? '' : String(text));

// ─── Result rows ────────────────────────────────────────────────────────

export const RISK_LABELS: Record<RiskLevel, string> = {
  safe: 'Safe', low: 'Low', medium: 'Medium', high: 'High', unknown: 'Unknown',
};

export interface ExpectedRow {
  ip: string;
  hits: number;
  version: 'IPv4' | 'IPv6' | '';
  isPrivate: boolean;
  /** PTR name, '' when there is none. */
  ptr: string;
  /** ISO code, '' when no source knows the country. */
  countryCode: string;
  /** Name shown next to the flag; '' when no source knows the country. */
  countryName: string;
  flag: string;
  /** Number as text, '' when unknown. */
  asn: string;
  asnOrg: string;
  /** '' when no source names a network operator. */
  isp: string;
  /** '' when unknown. */
  usage: string;
  risk: RiskLevel;
  /** Reasons given by the IP-info service (the AbuseIPDB line is added by the page when the score is above 0). */
  serviceReasons: string[];
  /** null when AbuseIPDB gave no answer for this address. */
  score: number | null;
  reports: number;
  distinctUsers: number;
  lastReported: string;
  tor: boolean;
  whitelisted: boolean;
}

export interface Sources {
  ipinfo?: IpInfoRecord[] | null;
  abuse?: AbuseResponse | null;
  geo?: Record<string, GeoFacts> | null;
}

function abuseEntries(response: AbuseResponse | null | undefined): AbuseRecord[] {
  if (!response) return [];
  return [...(response.abusive ?? []), ...(response.non_abusive ?? []), ...(response.results ?? [])];
}

function firstDefined<T>(...values: (T | undefined | null)[]): T | undefined {
  for (const value of values) if (value !== undefined && value !== null) return value;
  return undefined;
}

export function riskFrom(base: RiskLevel, score: number | null): RiskLevel {
  if (score === null || score <= 0) return base;
  if (score >= 75) return 'high';
  if (score >= 25) return base === 'high' ? 'high' : 'medium';
  return base;
}

export function expectedRow(entry: BatchEntry, sources: Sources): ExpectedRow {
  const info = (sources.ipinfo ?? []).find(record => record.ip === entry.ip);
  const abuse = abuseEntries(sources.abuse).find(record => (record.ip ?? record.ipAddress) === entry.ip);
  const geo = sources.geo?.[entry.ip] ?? {};

  const version = (info?.ip_version as 'IPv4' | 'IPv6' | undefined) || ipVersionOf(entry.ip);
  const isPrivate = info?.is_private ?? isSpecialPurpose(entry.ip);

  // Country: the first source that knows a code decides flag, name and code together.
  const candidates: { code: string; name: string }[] = [
    { code: real(firstDefined(abuse?.country_code, abuse?.countryCode)), name: real(firstDefined(abuse?.country, abuse?.countryName)) },
    { code: real(info?.country_code), name: real(info?.country) },
    { code: real(geo.country_code), name: real(geo.country) },
  ];
  const known = candidates.find(candidate => candidate.code !== '');
  const countryCode = known?.code ?? '';
  const countryName = known ? (known.name || COUNTRY_NAMES[known.code.toUpperCase()] || known.code) : '';

  const asnValue = firstDefined(geo.asn || undefined, info?.asn === '' ? undefined : info?.asn);
  const score = firstDefined(abuse?.abuse_score, abuse?.abuseConfidenceScore);
  const numericScore = typeof score === 'number' ? score : null;
  // Without an answer from the IP-info service nothing is known about the address: that is "unknown", not "low".
  const base: RiskLevel = info?.risk_level ?? 'unknown';

  return {
    ip: entry.ip,
    hits: entry.hits,
    version,
    isPrivate,
    ptr: real(info?.reverse_dns),
    countryCode,
    countryName,
    flag: countryCode ? flagOf(countryCode) : GLOBE,
    asn: asnValue === undefined ? '' : String(asnValue),
    asnOrg: real(geo.asn_org) || real(info?.asn_org),
    isp: real(abuse?.isp) || real(info?.isp) || real(geo.asn_org) || real(info?.asn_org),
    usage: real(firstDefined(abuse?.usage_type, abuse?.usageType)) || (isPrivate ? 'Private Network' : ''),
    risk: riskFrom(base, numericScore),
    serviceReasons: info?.risk_reasons ?? [],
    score: numericScore,
    reports: firstDefined(abuse?.total_reports, abuse?.totalReports) ?? 0,
    distinctUsers: abuse?.num_distinct_users ?? 0,
    lastReported: abuse?.last_reported_at ?? '',
    tor: abuse?.is_tor === true,
    whitelisted: abuse?.is_whitelisted === true,
  };
}

export function expectedRows(entries: BatchEntry[], sources: Sources): ExpectedRow[] {
  return entries.map(entry => expectedRow(entry, sources));
}

// ─── Counters and filters ───────────────────────────────────────────────

export type FilterName = 'all' | 'rdns' | 'risk' | 'abusive';

export function matchesFilter(row: ExpectedRow, filter: FilterName): boolean {
  if (filter === 'rdns') return row.ptr !== '';
  if (filter === 'risk') return row.risk === 'medium' || row.risk === 'high';
  if (filter === 'abusive') return row.score !== null && row.score > 0;
  return true;
}

export interface Counters { total: number; rdns: number; risk: number; abusive: number }

export function countersOf(rows: ExpectedRow[]): Counters {
  const count = (filter: FilterName) => rows.filter(row => matchesFilter(row, filter)).length;
  return { total: rows.length, rdns: count('rdns'), risk: count('risk'), abusive: count('abusive') };
}

// ─── What leaves the page ───────────────────────────────────────────────

/** The line "Copy IP Summary" writes for one row: address, PTR, country, AS number, risk level. */
export function summaryLine(row: ExpectedRow): { ip: string; ptr: string; country: string; asn: string; risk: string } {
  return { ip: row.ip, ptr: row.ptr, country: row.countryName, asn: row.asn, risk: row.risk };
}

/** Today's date (YYYY-MM-DD) in a given time zone at a given instant. */
export function dateIn(timeZone: string, at: Date): string {
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(at);
  const get = (type: string) => parts.find(part => part.type === type)?.value ?? '';
  return `${get('year')}-${get('month')}-${get('day')}`;
}
