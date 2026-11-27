/**
 * Independent expectations for the ASN tool (/asn).
 *
 * Nothing here imports application code. The page and the backend work with
 * 32-bit bit operators and JavaScript numbers; this file uses BigInt ranges and
 * written-out rules, so a mistake on one side is not repeated on the other.
 *
 * DEFINITIONS (what each displayed value means, and where that comes from)
 *
 *  - Prefix: CIDR block `network/length`. It covers the addresses
 *    `network .. network + 2^(bits-length) - 1` (bits = 32 for IPv4, 128 for IPv6).
 *  - "IP Range (Start → End)" column: first and last address of the block.
 *  - "Usable IPs" column / "Total Subnet IPs" / "(n IPs)" in the text report: the
 *    number of addresses the block covers, 2^(bits-length). The page uses the
 *    total for IPv4 (a /24 shows 256), so the same definition is applied to IPv6.
 *  - Netmask / Wildcard (IPv4): the length written as a dotted mask and its complement.
 *  - Containment ("IP Range Matcher"): an address belongs to the network when it
 *    lies inside at least one announced prefix of the same family (RFC 4632 / RFC 4291).
 *    IPv6 text is compared by value, not by spelling (RFC 5952: `2001:db8::1`,
 *    `2001:0DB8:0:0:0:0:0:1` are the same address).
 *  - Aggregated supernets ("Merge adjacent CIDRs"): the smallest list of CIDR
 *    blocks that covers exactly the union of the announced IPv4 prefixes.
 *  - "CIDR Optimization": saved = announced - aggregated; percent = saved / announced,
 *    rounded to the nearest whole percent (a tie may go either way: the page states no rule).
 *  - Unique IPv4 addresses of a network: the size of the union of its prefixes
 *    (a /16 and a /24 inside it are 65,536 addresses, not 65,792).
 *  - Text filter ("Filter prefixes by CIDR, IP range, or netmask..."): keeps a prefix
 *    when the trimmed query, ignoring case, is part of its CIDR, range start, range
 *    end or netmask as displayed.
 *  - Mask chips ("Subnet Mask Distribution"): chip `/n (c)` is built from the IPv4
 *    prefixes; choosing it lists the IPv4 prefixes of length n, and c is their number.
 *  - Pagination: 25 rows per page; "Showing a–b of n prefixes".
 *  - Firewall rules: one rule per selected prefix, in the selected platform's
 *    syntax and address family, with the selected action. See `ruleProblems`.
 */

export type Family = 4 | 6;

export interface Cidr {
  family: Family;
  network: bigint;
  length: number;
  /** Canonical text, e.g. `10.0.0.0/8` or `2001:db8::/32`. */
  text: string;
}

const BITS: Record<Family, number> = { 4: 32, 6: 128 };

// ───────────────────────── addresses ─────────────────────────

/** Strict dotted decimal: four groups of 1–3 digits, each 0–255, nothing else. */
export function parseV4(text: string): bigint | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (part.length < 1 || part.length > 3) return null;
    for (const ch of part) if (ch < '0' || ch > '9') return null;
    const octet = BigInt(part);
    if (octet > 255n) return null;
    value = value * 256n + octet;
  }
  return value;
}

export function formatV4(value: bigint): string {
  const octets: string[] = [];
  for (let i = 3; i >= 0; i--) octets.push(String((value / 256n ** BigInt(i)) % 256n));
  return octets.join('.');
}

/** RFC 4291 text form: eight hex groups, at most one `::`. Dotted tails are not accepted. */
export function parseV6(text: string): bigint | null {
  if (text.length < 2) return null;
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const readGroups = (part: string): bigint[] | null => {
    if (part === '') return [];
    const out: bigint[] = [];
    for (const group of part.split(':')) {
      if (group.length < 1 || group.length > 4) return null;
      for (const ch of group.toLowerCase()) if (!'0123456789abcdef'.includes(ch)) return null;
      out.push(BigInt(`0x${group}`));
    }
    return out;
  };
  const head = readGroups(halves[0]);
  const tail = halves.length === 2 ? readGroups(halves[1]) : [];
  if (!head || !tail) return null;
  let groups: bigint[];
  if (halves.length === 1) {
    if (head.length !== 8) return null;
    groups = head;
  } else {
    const missing = 8 - head.length - tail.length;
    if (missing < 1) return null;
    groups = [...head, ...Array<bigint>(missing).fill(0n), ...tail];
  }
  return groups.reduce((acc, group) => acc * 65536n + group, 0n);
}

function v6Groups(value: bigint): number[] {
  const groups: number[] = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((value / 65536n ** BigInt(i)) % 65536n));
  return groups;
}

/** RFC 5952: lowercase, no leading zeros, the longest run of zero groups (two or more) as `::`. */
export function formatV6(value: bigint): string {
  const groups = v6Groups(value);
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = groups.map(group => group.toString(16));
  if (bestLen < 2) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLen).join(':')}`;
}

/** All eight groups, four digits each: `2001:0db8:0000:…`. Another spelling of the same address. */
export function expandV6(value: bigint, upper = false): string {
  const text = v6Groups(value).map(group => group.toString(16).padStart(4, '0')).join(':');
  return upper ? text.toUpperCase() : text;
}

export function parseAddress(text: string): { family: Family; value: bigint } | null {
  const v4 = parseV4(text);
  if (v4 !== null) return { family: 4, value: v4 };
  const v6 = text.includes(':') ? parseV6(text) : null;
  return v6 !== null ? { family: 6, value: v6 } : null;
}

export function formatAddress(family: Family, value: bigint): string {
  return family === 4 ? formatV4(value) : formatV6(value);
}

// ───────────────────────── CIDR blocks ─────────────────────────

export function cidrSize(cidr: Pick<Cidr, 'family' | 'length'>): bigint {
  return 2n ** BigInt(BITS[cidr.family] - cidr.length);
}

export function cidrFirst(cidr: Cidr): bigint {
  return cidr.network;
}

export function cidrLast(cidr: Cidr): bigint {
  return cidr.network + cidrSize(cidr) - 1n;
}

/** Builds a block from any address inside it; the network is the address rounded down to the block size. */
export function makeCidr(family: Family, address: bigint, length: number): Cidr {
  const size = 2n ** BigInt(BITS[family] - length);
  const network = address - (address % size);
  return { family, network, length, text: `${formatAddress(family, network)}/${length}` };
}

export function parseCidr(text: string): Cidr | null {
  const slash = text.indexOf('/');
  if (slash < 0) return null;
  const address = parseAddress(text.slice(0, slash));
  const lengthText = text.slice(slash + 1);
  if (!address || lengthText === '' || [...lengthText].some(ch => ch < '0' || ch > '9')) return null;
  const length = Number(lengthText);
  if (length > BITS[address.family]) return null;
  return makeCidr(address.family, address.value, length);
}

export function contains(cidr: Cidr, family: Family, address: bigint): boolean {
  return cidr.family === family && address >= cidrFirst(cidr) && address <= cidrLast(cidr);
}

/** Every prefix of the list that holds the address (there can be several when prefixes overlap). */
export function containing(prefixes: readonly Cidr[], family: Family, address: bigint): Cidr[] {
  return prefixes.filter(prefix => contains(prefix, family, address));
}

export function netmaskV4(length: number): string {
  return formatV4(2n ** 32n - 2n ** BigInt(32 - length));
}

export function wildcardV4(length: number): string {
  return formatV4(2n ** BigInt(32 - length) - 1n);
}

/** `4294967296n` → `4,294,967,296` (the page groups counts for en-US). */
export function grouped(value: bigint | number): string {
  const digits = value.toString();
  let out = '';
  for (let i = 0; i < digits.length; i++) {
    if (i > 0 && (digits.length - i) % 3 === 0) out += ',';
    out += digits[i];
  }
  return out;
}

/** Digits of a displayed count as BigInt (`"65,536"` → 65536n); null when it is not a plain number. */
export function readCount(text: string): bigint | null {
  const digits = text.replace(/,/g, '').trim();
  if (digits === '' || [...digits].some(ch => ch < '0' || ch > '9')) return null;
  return BigInt(digits);
}

// ───────────────────────── sets of blocks ─────────────────────────

interface Range { low: bigint; high: bigint }

function mergedRanges(prefixes: readonly Cidr[]): Range[] {
  const ranges = prefixes.map(p => ({ low: cidrFirst(p), high: cidrLast(p) }))
    .sort((a, b) => (a.low < b.low ? -1 : a.low > b.low ? 1 : 0));
  const merged: Range[] = [];
  for (const range of ranges) {
    const last = merged[merged.length - 1];
    if (last && range.low <= last.high + 1n) {
      if (range.high > last.high) last.high = range.high;
    } else merged.push({ ...range });
  }
  return merged;
}

/** Number of distinct addresses covered by the prefixes (overlaps counted once). */
export function unionSize(prefixes: readonly Cidr[]): bigint {
  return mergedRanges(prefixes).reduce((sum, range) => sum + (range.high - range.low + 1n), 0n);
}

/**
 * Minimal CIDR cover of the union of `prefixes` (one family), ascending.
 * Method: merge the address ranges, then cut each range into the largest
 * aligned power-of-two blocks from left to right.
 */
export function aggregate(prefixes: readonly Cidr[], family: Family = 4): Cidr[] {
  const bits = BITS[family];
  const out: Cidr[] = [];
  for (const range of mergedRanges(prefixes.filter(p => p.family === family))) {
    let low = range.low;
    while (low <= range.high) {
      let length = bits;
      // Grow the block while it stays aligned on `low` and inside the range.
      while (length > 0) {
        const size = 2n ** BigInt(bits - (length - 1));
        if (low % size !== 0n || low + size - 1n > range.high) break;
        length--;
      }
      out.push(makeCidr(family, low, length));
      low += 2n ** BigInt(bits - length);
    }
  }
  return out;
}

/** Whole percents that are a correct rounding of saved/original (two values on an exact tie). */
export function reductionPercents(original: number, aggregated: number): number[] {
  if (original <= 0) return [0];
  const saved = BigInt(Math.max(0, original - aggregated));
  const total = BigInt(original);
  const floor = (saved * 100n) / total;
  const twiceRemainder = ((saved * 100n) % total) * 2n;
  if (twiceRemainder === total) return [Number(floor), Number(floor) + 1];
  return [Number(twiceRemainder > total ? floor + 1n : floor)];
}

/** Numeric order: family, then network address, then prefix length. */
export function compareCidr(a: Cidr, b: Cidr): number {
  if (a.family !== b.family) return a.family - b.family;
  if (a.network !== b.network) return a.network < b.network ? -1 : 1;
  return a.length - b.length;
}

// ───────────────────────── compact counts ("4.26M IPs") ─────────────────────────

function fixed(value: bigint, unit: bigint, decimals: number): string {
  const scale = 10n ** BigInt(decimals);
  const scaled = (value * scale * 2n + unit) / (unit * 2n); // round half up
  const whole = scaled / scale;
  return `${whole}.${(scaled % scale).toString().padStart(decimals, '0')}`;
}

/** The server's compact form: `512`, `65.5K`, `4.26M`, `1.07B`. */
export function compactCount(value: bigint): string {
  if (value >= 1_000_000_000n) return `${fixed(value, 1_000_000_000n, 2)}B`;
  if (value >= 1_000_000n) return `${fixed(value, 1_000_000n, 2)}M`;
  if (value >= 1_000n) return `${fixed(value, 1_000n, 1)}K`;
  return grouped(value);
}

/**
 * The range of exact values a compact count can stand for: `4.26M` → 4,255,000..4,265,000.
 * Used for live data, where the last digit may legitimately round either way.
 */
export function compactRange(text: string): { low: bigint; high: bigint } | null {
  const match = text.trim().match(/^([\d,]+)(?:\.(\d+))?([KMB])?$/);
  if (!match) return null;
  const unit = match[3] === 'B' ? 1_000_000_000n : match[3] === 'M' ? 1_000_000n : match[3] === 'K' ? 1_000n : 1n;
  const decimals = match[2] ? match[2].length : 0;
  const scale = 10n ** BigInt(decimals);
  const scaled = BigInt(match[1].replace(/,/g, '') + (match[2] || ''));
  if (unit === 1n) return { low: scaled, high: scaled };
  const half = unit / (scale * 2n);
  const centre = (scaled * unit) / scale;
  return { low: centre - half, high: centre + half };
}

// ───────────────────────── prefix explorer ─────────────────────────

export const PAGE_SIZE = 25;

/** What one row of the prefix table must show. `rangeEnd` and `count` are derived from the block. */
export interface ExpectedRow {
  cidr: Cidr;
  prefix: string;
  rangeStart: string;
  rangeEnd: string;
  count: bigint;
  /** Dotted mask for IPv4, `/length` for IPv6. */
  netmask: string;
  /** IPv4 only. */
  wildcard: string | null;
}

export function expectedRow(cidr: Cidr): ExpectedRow {
  return {
    cidr,
    prefix: cidr.text,
    rangeStart: formatAddress(cidr.family, cidrFirst(cidr)),
    rangeEnd: formatAddress(cidr.family, cidrLast(cidr)),
    count: cidrSize(cidr),
    netmask: cidr.family === 4 ? netmaskV4(cidr.length) : `/${cidr.length}`,
    wildcard: cidr.family === 4 ? wildcardV4(cidr.length) : null,
  };
}

export interface ExplorerState {
  version: 'all' | 'ipv4' | 'ipv6';
  aggregated: boolean;
  /** Selected mask chip, e.g. 24, or null for "All Masks". */
  mask: number | null;
  query: string;
}

export const DEFAULT_EXPLORER: ExplorerState = { version: 'all', aggregated: false, mask: null, query: '' };

export function matchesQuery(cidr: Cidr, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (needle === '') return true;
  const row = expectedRow(cidr);
  return [row.prefix, row.rangeStart, row.rangeEnd, row.netmask].some(text => text.toLowerCase().includes(needle));
}

/**
 * The prefixes the explorer must list for a state, in order: IPv4 first (raw
 * or aggregated), then IPv6. The mask chip concerns IPv4 prefixes only (see
 * DEFINITIONS), so it removes IPv6 rows.
 */
export function explorerList(v4: readonly Cidr[], aggregated: readonly Cidr[], v6: readonly Cidr[], state: ExplorerState): Cidr[] {
  let list: Cidr[] = [];
  if (state.version !== 'ipv6') list = list.concat(state.aggregated ? aggregated : v4);
  if (state.version !== 'ipv4') list = list.concat(v6);
  if (state.mask !== null) list = list.filter(p => p.family === 4 && p.length === state.mask);
  return list.filter(p => matchesQuery(p, state.query));
}

export function pageCount(total: number): number {
  return Math.max(1, Math.ceil(total / PAGE_SIZE));
}

export function pageSlice<T>(list: readonly T[], page: number): T[] {
  return list.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
}

/** Footer text of the table; the page shows it only when there is more than one page. */
export function showingText(total: number, page: number): string {
  const from = (page - 1) * PAGE_SIZE + 1;
  const to = Math.min(page * PAGE_SIZE, total);
  return `Showing ${from}–${to} of ${total} prefixes`;
}

/** Count of IPv4 prefixes per length, ascending by length: the mask chips. */
export function maskDistribution(prefixes: readonly Cidr[]): [number, number][] {
  const counts = new Map<number, number>();
  for (const p of prefixes) counts.set(p.length, (counts.get(p.length) || 0) + 1);
  return [...counts.entries()].sort((a, b) => a[0] - b[0]);
}

// ───────────────────────── time ─────────────────────────

/** `2026-11-27T11:06:20.586Z` → `Fri, 27 Nov 2026 11:06:20 GMT` (the footer promises UTC). */
export function utcStamp(iso: string): string {
  const at = new Date(iso);
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const two = (n: number) => String(n).padStart(2, '0');
  return `${days[at.getUTCDay()]}, ${two(at.getUTCDate())} ${months[at.getUTCMonth()]} ${at.getUTCFullYear()} `
    + `${two(at.getUTCHours())}:${two(at.getUTCMinutes())}:${two(at.getUTCSeconds())} GMT`;
}

/** Today's date in UTC, `YYYY-MM-DD`: the date written into generated rule files. */
export function utcDate(at: Date = new Date()): string {
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone: 'UTC', year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(at);
  const get = (type: string) => parts.find(p => p.type === type)?.value || '';
  return `${get('year')}-${get('month')}-${get('day')}`;
}

/** `Nov 27, 2026` in the browser's time zone: the dates on the shared-view header. */
export function browserDate(at: Date): string {
  return new Intl.DateTimeFormat('en-US', {
    timeZone: process.env.E2E_TIMEZONE ?? 'America/New_York', year: 'numeric', month: 'short', day: 'numeric',
  }).format(at);
}

// ───────────────────────── text report (Copy Summary / Export) ─────────────────────────

export interface ParsedReport {
  title: string;
  fields: Record<string, string>;
  v4Heading: number | null;
  v4: { index: number; prefix: string; first: string; last: string; count: string }[];
  v6Heading: number | null;
  v6: { index: number; prefix: string }[];
  unparsed: string[];
}

/** Reads the plain-text report by its labels, independent of column padding. */
export function parseReport(text: string): ParsedReport {
  const report: ParsedReport = { title: '', fields: {}, v4Heading: null, v4: [], v6Heading: null, v6: [], unparsed: [] };
  let section: 'head' | 'v4' | 'v6' = 'head';
  for (const raw of text.split('\n')) {
    const line = raw.trimEnd();
    if (line === '' || /^[=-]{10,}$/.test(line)) continue;
    let m: RegExpMatchArray | null;
    if ((m = line.match(/^ASN Report: (.*)$/))) { report.title = m[1]; continue; }
    if ((m = line.match(/^IPv4 Announced Prefixes \((\d+)\):$/))) { report.v4Heading = Number(m[1]); section = 'v4'; continue; }
    if ((m = line.match(/^IPv6 Announced Prefixes \((\d+)\):$/))) { report.v6Heading = Number(m[1]); section = 'v6'; continue; }
    if (section === 'head' && (m = line.match(/^([A-Za-z0-9 ]+?):\s*(.*)$/))) { report.fields[m[1]] = m[2]; continue; }
    if (section === 'v4' && (m = line.match(/^\s*\[(\d+)\]\s+(\S+)\s+Range:\s+(\S+)\s+-\s+(\S+)\s+\((.*)\)$/))) {
      report.v4.push({ index: Number(m[1]), prefix: m[2], first: m[3], last: m[4], count: m[5] });
      continue;
    }
    if (section === 'v6' && (m = line.match(/^\s*\[(\d+)\]\s+(\S+)$/))) { report.v6.push({ index: Number(m[1]), prefix: m[2] }); continue; }
    report.unparsed.push(line);
  }
  return report;
}

// ───────────────────────── firewall rules ─────────────────────────

export type RuleFormat =
  | 'nginx' | 'apache' | 'iptables' | 'nftables' | 'ufw' | 'cisco_acl' | 'mikrotik'
  | 'ipset' | 'aws_sg' | 'pfsense' | 'plain_text' | 'csv' | 'json';

export type RuleAction = 'deny' | 'allow';

/** Formats in the order of the page's dropdown, with the option label and the saved file's extension. */
export const RULE_FORMATS: { value: RuleFormat; label: string; extension: string }[] = [
  { value: 'nginx', label: 'Nginx (allow / deny)', extension: 'conf' },
  { value: 'apache', label: 'Apache .htaccess (Require ip)', extension: 'conf' },
  { value: 'iptables', label: 'Linux iptables / ip6tables', extension: 'txt' },
  { value: 'nftables', label: 'Linux nftables (set & chain)', extension: 'txt' },
  { value: 'ufw', label: 'Ubuntu UFW (ufw allow/deny)', extension: 'txt' },
  { value: 'cisco_acl', label: 'Cisco IOS ACL (Wildcard Mask)', extension: 'txt' },
  { value: 'mikrotik', label: 'Mikrotik RouterOS (address-list)', extension: 'txt' },
  { value: 'ipset', label: 'Linux IPset (hash:net)', extension: 'txt' },
  { value: 'aws_sg', label: 'AWS Security Group (JSON)', extension: 'json' },
  { value: 'pfsense', label: 'pfSense / OPNsense Alias (CIDR list)', extension: 'txt' },
  { value: 'plain_text', label: 'Plain Text CIDRs (1 per line)', extension: 'txt' },
  { value: 'csv', label: 'CSV Spreadsheet Format', extension: 'csv' },
  { value: 'json', label: 'Structured JSON Array', extension: 'json' },
];

export interface RuleRequest {
  action: RuleAction;
  asn: string;
  /** Organisation name written into comments. */
  org: string;
  /** The prefixes the user selected, in order. */
  prefixes: Cidr[];
  /** Acceptable `YYYY-MM-DD` dates for the header (two when the test runs across midnight UTC). */
  dates: string[];
}

const HAS_HEADER: RuleFormat[] = ['nginx', 'apache', 'iptables', 'nftables', 'ufw', 'cisco_acl', 'mikrotik', 'ipset', 'pfsense'];

function splitCsvLine(line: string): string[] {
  return line.split(',');
}

/** Compares two ordered lists of lines and describes the first difference. */
function diffLines(kind: string, actual: string[], expected: string[]): string[] {
  const problems: string[] = [];
  if (actual.length !== expected.length) problems.push(`${kind}: ${actual.length} rule lines, expected ${expected.length} (one per selected prefix)`);
  for (let i = 0; i < Math.max(actual.length, expected.length); i++) {
    if (actual[i] !== expected[i]) {
      problems.push(`${kind}: rule line ${i + 1} is ${JSON.stringify(actual[i] ?? '(missing)')}, expected ${JSON.stringify(expected[i] ?? '(nothing)')}`);
      if (problems.length >= 6) { problems.push(`${kind}: further differences not listed`); break; }
    }
  }
  return problems;
}

/** Each wanted prefix must be found exactly once in `found`; nothing else may be there. */
function coverageProblems(kind: string, found: string[], want: Cidr[]): string[] {
  const problems: string[] = [];
  const counts = new Map<string, number>();
  for (const text of found) counts.set(text, (counts.get(text) || 0) + 1);
  const missing = want.filter(p => !counts.has(p.text));
  const repeated = want.filter(p => (counts.get(p.text) || 0) > 1);
  const wanted = new Set(want.map(p => p.text));
  const extra = [...counts.keys()].filter(text => !wanted.has(text));
  const list = (items: string[]) => `${items.slice(0, 5).join(', ')}${items.length > 5 ? ` … (${items.length} in total)` : ''}`;
  if (missing.length) {
    const v6 = missing.filter(p => p.family === 6).length;
    problems.push(`${kind}: ${missing.length} of ${want.length} selected prefixes have no rule (${v6} of them IPv6): ${list(missing.map(p => p.text))}`);
  }
  if (repeated.length) problems.push(`${kind}: prefixes with more than one rule: ${list(repeated.map(p => p.text))}`);
  if (extra.length) problems.push(`${kind}: rules for prefixes that were not selected: ${list(extra)}`);
  return problems;
}

/**
 * Checks generated firewall rules against the request, per platform syntax.
 * Returns a list of problems; empty means the output is correct.
 *
 * Sources for the syntax of each platform:
 *  nginx `deny|allow CIDR;` (ngx_http_access_module) · Apache 2.4 `Require [not] ip`
 *  inside `<RequireAll>`/`<RequireAny>` (mod_authz_core) · `iptables`/`ip6tables -A INPUT -s CIDR -j DROP|ACCEPT`
 *  · nftables named sets typed `ipv4_addr`/`ipv6_addr`, matched with `ip saddr`/`ip6 saddr`
 *  · `ufw deny|allow from CIDR` · Cisco IOS extended ACL `access-list N deny|permit ip NET WILDCARD any`
 *  · RouterOS `/ip firewall address-list` (IPv4) and `/ipv6 firewall address-list` (IPv6)
 *  · `ipset create NAME hash:net family inet|inet6` · AWS `CidrIp`/`CidrIpv6` ranges.
 */
export function ruleProblems(format: RuleFormat, output: string, want: RuleRequest): string[] {
  const problems: string[] = [];
  const deny = want.action === 'deny';
  const lines = output.split('\n');
  let body = lines;

  if (HAS_HEADER.includes(format)) {
    const headers = want.dates.map(date => `# AS${want.asn} (${want.org || 'ASN'}) - Generated ${date} - Total: ${want.prefixes.length} prefixes`);
    if (!headers.includes(lines[0])) problems.push(`${format}: first line is ${JSON.stringify(lines[0])}, expected ${JSON.stringify(headers[0])}`);
    body = lines.slice(1);
  }

  switch (format) {
    case 'nginx':
      return problems.concat(diffLines(format, body, want.prefixes.map(p => `${deny ? 'deny' : 'allow'} ${p.text};`)));

    case 'iptables':
      return problems.concat(diffLines(format, body,
        want.prefixes.map(p => `${p.family === 4 ? 'iptables' : 'ip6tables'} -A INPUT -s ${p.text} -j ${deny ? 'DROP' : 'ACCEPT'}`)));

    case 'ufw':
      return problems.concat(diffLines(format, body, want.prefixes.map(p => `ufw ${deny ? 'deny' : 'allow'} from ${p.text}`)));

    case 'pfsense':
    case 'plain_text':
      return problems.concat(diffLines(format, body, want.prefixes.map(p => p.text)));

    case 'cisco_acl': {
      // IPv4: numbered extended ACL with a wildcard mask. IPv6 cannot be written that way; any line that names the prefix counts.
      const v4 = want.prefixes.filter(p => p.family === 4);
      const v4Lines = body.filter(line => line.startsWith('access-list '));
      problems.push(...diffLines(`${format} (IPv4)`, v4Lines,
        v4.map(p => `access-list 100 ${deny ? 'deny' : 'permit'} ip ${formatV4(p.network)} ${wildcardV4(p.length)} any`)));
      const v6Missing = want.prefixes.filter(p => p.family === 6 && !body.some(line => line.split(/\s+/).includes(p.text)));
      if (v6Missing.length) {
        problems.push(`${format}: ${v6Missing.length} selected IPv6 prefixes have no rule although the header counts ${want.prefixes.length} prefixes: ${v6Missing.slice(0, 5).map(p => p.text).join(', ')}`);
      }
      const other = body.filter(line => !line.startsWith('access-list ') && !line.startsWith('#') && !/ipv6/i.test(line) && line.trim() !== '');
      if (other.length) problems.push(`${format}: unexpected lines: ${other.slice(0, 3).map(l => JSON.stringify(l)).join(', ')}`);
      return problems;
    }

    case 'mikrotik': {
      const listName = `${deny ? 'BLOCKED' : 'ALLOWED'}_AS${want.asn}`;
      const found: string[] = [];
      for (const line of body) {
        const m = line.match(/^(\/ip|\/ipv6) firewall address-list add list=(\S+) address=(\S+) comment="(.*)"$/);
        if (!m) { problems.push(`${format}: line is not an address-list command: ${JSON.stringify(line)}`); continue; }
        found.push(m[3]);
        const family: Family = m[3].includes(':') ? 6 : 4;
        if (family === 6 && m[1] !== '/ipv6' && !problems.some(p => p.includes('/ipv6 firewall'))) {
          problems.push(`${format}: IPv6 prefix ${m[3]} is added under "/ip firewall address-list"; RouterOS keeps IPv6 lists under "/ipv6 firewall address-list", so the command fails on the router`);
        }
        if (family === 4 && m[1] !== '/ip') problems.push(`${format}: IPv4 prefix ${m[3]} is added under "${m[1]} firewall address-list"`);
        if (m[2] !== listName) problems.push(`${format}: list name ${m[2]} for ${m[3]}, expected ${listName}`);
        if (m[4] !== `AS${want.asn} ${want.org}`) problems.push(`${format}: comment ${JSON.stringify(m[4])} for ${m[3]}, expected ${JSON.stringify(`AS${want.asn} ${want.org}`)}`);
      }
      return problems.concat(coverageProblems(format, found, want.prefixes)).slice(0, 8);
    }

    case 'ipset': {
      const sets = new Map<string, Family>();
      const found: string[] = [];
      for (const line of body) {
        if (line.startsWith('#') || line.trim() === '') continue;
        let m: RegExpMatchArray | null;
        if ((m = line.match(/^ipset create (\S+) hash:net family (inet6?)$/))) { sets.set(m[1], m[2] === 'inet' ? 4 : 6); continue; }
        if ((m = line.match(/^ipset add (\S+) (\S+)$/))) {
          const family = sets.get(m[1]);
          if (family === undefined) problems.push(`${format}: "${line}" adds to a set that was not created`);
          else if ((m[2].includes(':') ? 6 : 4) !== family) problems.push(`${format}: ${m[2]} is added to set ${m[1]} of family ${family === 4 ? 'inet' : 'inet6'}`);
          found.push(m[2]);
          continue;
        }
        problems.push(`${format}: unexpected line ${JSON.stringify(line)}`);
      }
      if (sets.size === 0) problems.push(`${format}: no "ipset create … hash:net" line`);
      const hint = body.filter(line => line.startsWith('#')).join('\n');
      if (!hint.includes(`-j ${deny ? 'DROP' : 'ACCEPT'}`)) problems.push(`${format}: the apply hint does not use -j ${deny ? 'DROP' : 'ACCEPT'} for action "${want.action}"`);
      return problems.concat(coverageProblems(format, found, want.prefixes));
    }

    case 'nftables': {
      const sets = new Map<string, { family: Family | null; elements: string[] }>();
      const rules: { keyword: string; set: string; verdict: string }[] = [];
      let current: { family: Family | null; elements: string[] } | null = null;
      let inElements = false;
      let depth = 0;
      for (const raw of body) {
        const line = raw.trim();
        if (line === '' || line.startsWith('#')) continue;
        let m: RegExpMatchArray | null;
        if ((m = line.match(/^set (\S+) \{$/))) { current = { family: null, elements: [] }; sets.set(m[1], current); depth++; continue; }
        if (current && (m = line.match(/^type (ipv4_addr|ipv6_addr);/))) { current.family = m[1] === 'ipv4_addr' ? 4 : 6; continue; }
        if (current && /^elements = \{$/.test(line)) { inElements = true; depth++; continue; }
        if (line === '}') { depth--; if (inElements) inElements = false; else current = null; continue; }
        if (inElements && current) { current.elements.push(...line.split(',').map(s => s.trim()).filter(Boolean)); continue; }
        if ((m = line.match(/^(ip6?) saddr @(\S+) (drop|accept)$/))) { rules.push({ keyword: m[1], set: m[2], verdict: m[3] }); continue; }
        if (line.endsWith('{')) { depth++; continue; }
        problems.push(`${format}: unexpected line ${JSON.stringify(line)}`);
      }
      if (depth !== 0) problems.push(`${format}: braces are not balanced`);
      const found: string[] = [];
      for (const [name, set] of sets) {
        found.push(...set.elements);
        const wrong = set.elements.filter(el => (el.includes(':') ? 6 : 4) !== set.family);
        if (wrong.length) problems.push(`${format}: set ${name} is typed ${set.family === 4 ? 'ipv4_addr' : 'ipv6_addr'} but holds ${wrong.slice(0, 3).join(', ')}`);
        if (set.elements.length === 0 && want.prefixes.length > 0) problems.push(`${format}: set ${name} has an empty "elements = { }" block (nft rejects it), so the rule matches nothing`);
        const rule = rules.find(r => r.set === name);
        if (!rule) problems.push(`${format}: set ${name} is not used by any rule`);
        else {
          if (rule.verdict !== (deny ? 'drop' : 'accept')) problems.push(`${format}: rule for set ${name} says "${rule.verdict}" for action "${want.action}"`);
          if (rule.keyword !== (set.family === 4 ? 'ip' : 'ip6')) problems.push(`${format}: rule for set ${name} matches "${rule.keyword} saddr" but the set is ${set.family === 4 ? 'IPv4' : 'IPv6'}`);
        }
      }
      if (sets.size === 0) problems.push(`${format}: no named set in the output`);
      return problems.concat(coverageProblems(format, found, want.prefixes));
    }

    case 'apache': {
      interface Block { tag: string; positive: number; negative: number; ipLines: number }
      const stack: Block[] = [];
      const closed: Block[] = [];
      const found: string[] = [];
      const top: Block = { tag: '(top level)', positive: 0, negative: 0, ipLines: 0 };
      for (const raw of body) {
        const line = raw.trim();
        if (line === '' || line.startsWith('#')) continue;
        let m: RegExpMatchArray | null;
        if ((m = line.match(/^<(RequireAll|RequireAny|RequireNone)>$/))) { stack.push({ tag: m[1], positive: 0, negative: 0, ipLines: 0 }); continue; }
        if ((m = line.match(/^<\/(RequireAll|RequireAny|RequireNone)>$/))) {
          const block = stack.pop();
          if (!block || block.tag !== m[1]) problems.push(`${format}: ${line} closes a block that is not open`);
          else closed.push(block);
          continue;
        }
        if ((m = line.match(/^Require (not )?(.+)$/))) {
          const block = stack[stack.length - 1] || top;
          const negated = Boolean(m[1]);
          if (negated) block.negative++; else block.positive++;
          const ip = m[2].match(/^ip (.+)$/);
          if (ip) {
            block.ipLines++;
            found.push(...ip[1].split(/\s+/));
            if (deny && !negated && block.tag !== 'RequireNone') problems.push(`${format}: "${line}" grants access although the action is deny`);
            if (!deny && negated) problems.push(`${format}: "${line}" refuses access although the action is allow`);
          }
          continue;
        }
        problems.push(`${format}: unexpected line ${JSON.stringify(line)}`);
      }
      if (stack.length) problems.push(`${format}: <${stack[stack.length - 1].tag}> is never closed`);
      for (const block of closed) {
        if (block.tag === 'RequireAll' && block.positive === 0 && block.negative > 0) {
          problems.push(`${format}: <RequireAll> holds only "Require not" lines. Apache refuses to load that ("<RequireAll> directive contains only negative authorization directives"); a blocklist needs "Require all granted" next to the "Require not ip" lines`);
        }
        if (block.tag === 'RequireAll' && !deny && block.ipLines > 1) {
          problems.push(`${format}: ${block.ipLines} "Require ip" lines sit inside <RequireAll>, which admits a client only if its address is inside every one of these networks at once, so nobody is admitted; an allowlist needs <RequireAny>`);
        }
      }
      return problems.concat(coverageProblems(format, found, want.prefixes));
    }

    case 'aws_sg': {
      let parsed: unknown;
      try { parsed = JSON.parse(output); } catch { return [`${format}: output is not valid JSON`]; }
      if (!Array.isArray(parsed)) return [`${format}: output is not a JSON array`];
      const description = `AS${want.asn} ${want.org}`.trim();
      const found: string[] = [];
      parsed.forEach((entry: Record<string, unknown>, i: number) => {
        const keys = Object.keys(entry).filter(key => key.startsWith('Cidr'));
        const value = String(entry[keys[0]] ?? '');
        found.push(value);
        const wantKey = value.includes(':') ? 'CidrIpv6' : 'CidrIp';
        if (keys.length !== 1 || keys[0] !== wantKey) problems.push(`${format}: entry ${i + 1} (${value}) uses ${keys.join('+') || 'no Cidr key'}, expected only ${wantKey}`);
        if (entry.Description !== description) problems.push(`${format}: entry ${i + 1} description ${JSON.stringify(entry.Description)}, expected ${JSON.stringify(description)}`);
      });
      return problems.concat(diffLines(format, found, want.prefixes.map(p => p.text))).slice(0, 8);
    }

    case 'json': {
      let parsed: unknown;
      try { parsed = JSON.parse(output); } catch { return [`${format}: output is not valid JSON`]; }
      if (!Array.isArray(parsed)) return [`${format}: output is not a JSON array`];
      problems.push(...diffLines(format, parsed.map((entry: Record<string, unknown>) => String(entry.prefix)), want.prefixes.map(p => p.text)));
      parsed.forEach((entry: Record<string, unknown>, i: number) => {
        const cidr = want.prefixes[i];
        if (!cidr || cidr.family !== 4 || entry.first_ip === undefined) return;
        const row = expectedRow(cidr);
        const pairs: [string, unknown, unknown][] = [
          ['first_ip', entry.first_ip, row.rangeStart], ['last_ip', entry.last_ip, row.rangeEnd],
          ['netmask', entry.netmask, row.netmask], ['wildcard', entry.wildcard, row.wildcard],
          ['mask', entry.mask, cidr.length], ['total_ips', String(entry.total_ips), row.count.toString()],
        ];
        for (const [name, got, expected] of pairs) {
          if (got !== expected) problems.push(`${format}: ${cidr.text} ${name} is ${JSON.stringify(got)}, expected ${JSON.stringify(expected)}`);
        }
      });
      return problems.slice(0, 8);
    }

    case 'csv': {
      if (lines[0] !== 'Prefix,IP_Version,Start_IP,End_IP,Netmask,Wildcard_Mask,Total_IPs') problems.push(`${format}: header row is ${JSON.stringify(lines[0])}`);
      const rows = lines.slice(1).map(splitCsvLine);
      problems.push(...diffLines(format, rows.map(cells => cells[0]), want.prefixes.map(p => p.text)));
      rows.forEach((cells, i) => {
        const cidr = want.prefixes[i];
        if (!cidr) return;
        const row = expectedRow(cidr);
        // IPv6 range end and address count are checked by a test of their own (see asn-prefixes.spec.ts).
        const expected = cidr.family === 4
          ? [row.prefix, 'ipv4', row.rangeStart, row.rangeEnd, row.netmask, row.wildcard as string, row.count.toString()]
          : [row.prefix, 'ipv6', row.rangeStart];
        expected.forEach((value, col) => {
          if (cells[col] !== value) problems.push(`${format}: row ${i + 1} (${cidr.text}) column ${col + 1} is ${JSON.stringify(cells[col])}, expected ${JSON.stringify(value)}`);
        });
      });
      return problems.slice(0, 8);
    }
  }
}

/** File name the "Save File" button must use. */
export function ruleFileName(asn: string, format: RuleFormat, action: RuleAction): string {
  const extension = RULE_FORMATS.find(f => f.value === format)?.extension;
  return `AS${asn}-${format}-${action}.${extension}`;
}

// ───────────────────────── inputs that are not addresses ─────────────────────────

/** Text a user could type into the IP tester that is not an IP address. */
export const INVALID_ADDRESSES: { input: string; why: string }[] = [
  { input: 'not-an-ip', why: 'free text' },
  { input: '10.0.0.256', why: 'octet above 255' },
  { input: '10.0.0', why: 'three octets' },
  { input: '10.0.0.1.5', why: 'five octets' },
  { input: '10..0.1', why: 'empty octet' },
  { input: '1e1.0.0.1', why: 'octet in exponent notation' },
  { input: '0x0a.0.0.1', why: 'octet in hexadecimal' },
  { input: '10.0.0.1/32', why: 'CIDR, not an address' },
  { input: '-1.0.0.1', why: 'negative octet' },
  { input: '2001:db8::zz', why: 'IPv6 with a non-hex group' },
  { input: '2001:db8::1::2', why: 'IPv6 with two "::"' },
  { input: '2001:db8:1:2:3:4:5:6:7', why: 'IPv6 with nine groups' },
  { input: '2001:db8::12345', why: 'IPv6 group with five digits' },
];
