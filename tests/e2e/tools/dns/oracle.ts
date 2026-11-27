import { Mmdb, parseIp } from './mmdb';

/**
 * Expected values for the DNS Lookup tool (/dns), computed without the
 * application's code.
 *
 * DEFINITIONS (what each displayed value means, and where that comes from)
 *
 * Query
 *  - The page sends one `POST /api/dns {domain, type, resolver}` per selected
 *    record type. `domain` is the host name of what the user typed: scheme,
 *    path, port, query string, fragment and credentials of a pasted URL are
 *    not part of a DNS name (RFC 3986 section 3.2), and DNS names are compared
 *    case-insensitively, so the host is sent in lower case.
 *
 * Result sections (one per requested type)
 *  - Order: A, AAAA, MX, CNAME, NS, TXT, SOA, PTR, SRV, CAA — the order the
 *    page itself lists the default selection in ("Selected records").
 *  - Heading "<TYPE> Records", then "<n> found · <t>ms" where n is the number
 *    of records in the API answer and t the time the request took.
 *  - API answer with an `error` text, or a failed request: the error text is
 *    shown, no table. Failed request text: the `error` field of the JSON
 *    body, else "Request failed: <status>", else "HTTP <status>" when the body
 *    is not JSON.
 *  - No records: the API's `message`, or "No <TYPE> records found.".
 *  - Records: a table. Columns Value | TTL for every type; MX adds Priority;
 *    A and AAAA add Location and Provider.
 *  - TTL (sidebar help: "How long a resolver may cache a record, in seconds"):
 *    shown humanised as the two largest units (d h / h m / m s, or s alone
 *    below one minute), truncated, with the exact "<n> seconds" as tooltip.
 *  - Priority: the MX preference number as returned (RFC 5321: 0–65535).
 *  - Location: flag + English country name of the address in GeoLite2-Country
 *    (`country`), tooltip the country name; "Unknown" when the database has
 *    no country for the address.
 *  - Provider: the organisation that announces the address in GeoLite2-ASN,
 *    shortened to a brand name for well-known clouds (table CLOUD_BRANDS);
 *    tooltip the full organisation name; "Unknown" when not in the database.
 *
 * Summary cards
 *  - Domain: the queried host. Records Found: sum of n over all sections.
 *  - DNS Provider / Hosting · Edge: the API returns a detection per type
 *    ({slug, name, confidence, source, matched_on}). The card shows the most
 *    confident one; at equal confidence a named provider beats "Unknown".
 *    Below: "<Confidence> confidence · via <source>", or the fallback text
 *    when there is no source.
 *  - Resolver: the label of the selected resolver.
 *  - Checked At: the moment the lookup started, as "DD Mon YYYY HH:MM:SS UTC".
 */

/** Record types in the order the page offers them as checkboxes. */
export const OFFERED_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA', 'PTR', 'SRV', 'CAA'] as const;
/** Checked when the page opens. */
export const DEFAULT_TYPES = ['A', 'AAAA', 'MX', 'CNAME', 'NS', 'TXT'] as const;
/** Order of the result sections. */
export const SECTION_ORDER = ['A', 'AAAA', 'MX', 'CNAME', 'NS', 'TXT', 'SOA', 'PTR', 'SRV', 'CAA'] as const;

export const RESOLVERS = [
  { value: '1.1.1.1', label: 'Cloudflare (1.1.1.1)' },
  { value: '8.8.8.8', label: 'Google (8.8.8.8)' },
  { value: '208.67.222.222', label: 'OpenDNS' },
] as const;

export const SHARE_EXPIRIES = [
  { value: 'never', label: 'Never expires', hours: null },
  { value: '24h', label: '24 hours', hours: 24 },
  { value: '7d', label: '7 days', hours: 7 * 24 },
  { value: '30d', label: '30 days', hours: 30 * 24 },
] as const;

export const TIMEZONE = process.env.E2E_TIMEZONE ?? 'America/New_York';

export function resolverLabel(value: string): string {
  return RESOLVERS.find(r => r.value === value)?.label ?? value;
}

// ─── Input ───

/**
 * Host name a user means by `typed`, per the URL standard: whatever is left
 * after removing scheme, credentials, port, path, query and fragment, in
 * lower case, internationalised labels in their ASCII (punycode) form.
 * Returns null when no host can be read from the text.
 */
export function hostOf(typed: string): string | null {
  const text = typed.trim();
  if (!text) return null;
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`);
    return url.hostname || null;
  } catch {
    return null;
  }
}

// ─── Formatting ───

export function humanTtl(seconds: number): string {
  const units: [string, number][] = [['d', 86400], ['h', 3600], ['m', 60], ['s', 1]];
  const first = units.findIndex(([, size]) => seconds >= size);
  if (first < 0 || first === units.length - 1) return `${seconds}s`;
  const [bigName, bigSize] = units[first];
  const [smallName, smallSize] = units[first + 1];
  const big = Math.trunc(seconds / bigSize);
  const small = Math.trunc((seconds - big * bigSize) / smallSize);
  return `${big}${bigName} ${small}${smallName}`;
}

/** "27 Nov 2026 11:07:08 UTC" for an instant. */
export function utcStamp(instant: Date | string | number): string {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'UTC', year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  }).formatToParts(new Date(instant));
  const get = (type: string) => parts.find(p => p.type === type)?.value ?? '';
  return `${get('day')} ${get('month')} ${get('year')} ${get('hour')}:${get('minute')}:${get('second')} UTC`;
}

/** Every stamp the page may show for a lookup started between two instants. */
export function utcStampsBetween(fromMs: number, toMs: number): string[] {
  const out: string[] = [];
  for (let s = Math.floor(fromMs / 1000); s <= Math.floor(toMs / 1000); s++) out.push(utcStamp(s * 1000));
  return out;
}

/** "Nov 27, 2026": the date of an instant for a viewer in the browser's time zone. */
export function viewerDate(instant: Date | string | number): string {
  return new Intl.DateTimeFormat('en-US', { timeZone: TIMEZONE, year: 'numeric', month: 'short', day: 'numeric' })
    .format(new Date(instant));
}

/** Regional-indicator pair for an ISO 3166 alpha-2 code (Unicode TR51). */
export function flagOf(code: string): string {
  if (!/^[A-Za-z]{2}$/.test(code)) return '';
  return [...code.toUpperCase()].map(ch => String.fromCodePoint(0x1f1e6 + ch.charCodeAt(0) - 'A'.charCodeAt(0))).join('');
}

// ─── Providers ───

export interface ProviderInfo {
  slug?: string;
  name?: string;
  confidence?: string;
  source?: string;
  matched_on?: string;
}

export interface Provider {
  slug: string;
  name: string;
  confidence: 'low' | 'medium' | 'high';
  source: string;
  matched_on: string;
}

export const UNKNOWN_PROVIDER: Provider = { slug: 'unknown', name: 'Unknown', confidence: 'low', source: '', matched_on: '' };

export function cleanProvider(info: ProviderInfo | null | undefined): Provider {
  const text = (value: unknown, fallback: string) => (typeof value === 'string' ? value : fallback);
  return {
    slug: text(info?.slug, 'unknown'),
    name: text(info?.name, '') || 'Unknown',
    confidence: info?.confidence === 'high' ? 'high' : info?.confidence === 'medium' ? 'medium' : 'low',
    source: text(info?.source, ''),
    matched_on: text(info?.matched_on, ''),
  };
}

/** The detection a summary card shows, given the per-type detections in section order. */
export function pickProvider(candidates: (ProviderInfo | null | undefined)[]): Provider {
  const score = { high: 3, medium: 2, low: 1 } as const;
  const all = [UNKNOWN_PROVIDER, ...candidates.map(cleanProvider)];
  const top = Math.max(...all.map(p => score[p.confidence]));
  const best = all.filter(p => score[p.confidence] === top);
  return best.find(p => p.name !== 'Unknown') ?? best[0];
}

export function providerMeta(provider: Provider, kind: 'dns' | 'hosting', separator = ' · '): string {
  const confidence = provider.confidence[0].toUpperCase() + provider.confidence.slice(1);
  const fallback = kind === 'dns' ? 'No strong DNS fingerprint' : 'Derived from DNS answers';
  return `${confidence} confidence${separator}${provider.source ? `via ${provider.source}` : fallback}`;
}

// ─── GeoIP (Location and Provider columns of A / AAAA records) ───

/**
 * Brand shown instead of the registered organisation name. First entry with a
 * matching keyword wins. `word` keywords must stand alone ("OVH SAS", not
 * "novhost"); the others may appear anywhere in the name. Case is ignored.
 */
const CLOUD_BRANDS: { brand: string; anywhere?: string[]; word?: string[] }[] = [
  { brand: 'Amazon', anywhere: ['amazon', 'aws'] },
  { brand: 'Google', anywhere: ['google'] },
  { brand: 'Cloudflare', anywhere: ['cloudflare'] },
  { brand: 'Microsoft Azure', anywhere: ['microsoft', 'azure'] },
  { brand: 'Fastly', anywhere: ['fastly'] },
  { brand: 'Akamai', anywhere: ['akamai'] },
  { brand: 'Sucuri', anywhere: ['sucuri'] },
  { brand: 'DigitalOcean', anywhere: ['digitalocean'] },
  { brand: 'Hetzner', anywhere: ['hetzner'] },
  { brand: 'OVHcloud', word: ['ovh'] },
  { brand: 'Linode', anywhere: ['linode'] },
  { brand: 'Oracle Cloud', anywhere: ['oracle'] },
  { brand: 'IBM Cloud', word: ['ibm'], anywhere: ['softlayer'] },
  { brand: 'Vultr', anywhere: ['vultr', 'choopa'] },
  { brand: 'Netlify', anywhere: ['netlify'] },
  { brand: 'Vercel', anywhere: ['vercel'] },
  { brand: 'Shopify', anywhere: ['shopify'] },
  { brand: 'GitHub', anywhere: ['github'] },
  { brand: 'Alibaba Cloud', anywhere: ['alibaba'], word: ['alicloud'] },
  { brand: 'Tencent Cloud', anywhere: ['tencent'] },
  { brand: 'CDN77', anywhere: ['cdn77', 'datacamp limited'] },
];

export function brandOf(organisation: string): string {
  if (!organisation || organisation === 'Unknown') return 'Unknown';
  const name = organisation.toLowerCase();
  const words = name.split(/[^a-z0-9_]+/);
  for (const entry of CLOUD_BRANDS) {
    if (entry.anywhere?.some(key => name.includes(key))) return entry.brand;
    if (entry.word?.some(key => words.includes(key))) return entry.brand;
  }
  return organisation;
}

export interface GeoFacts {
  country: string;
  countryCode: string;
  organisation: string;
  asn: number;
  /** Text of the Location cell. */
  location: string;
  /** Text of the Provider cell. */
  brand: string;
}

/** Reads the two GeoLite2 files the page downloads, with the suite's own reader. */
export class GeoOracle {
  private static cache = new Map<string, Promise<GeoOracle>>();
  private readonly country: Mmdb;
  private readonly asn: Mmdb;

  private constructor(country: Mmdb, asn: Mmdb) {
    this.country = country;
    this.asn = asn;
  }

  /** Downloads the databases from the site under test, once per worker. */
  static load(baseURL: string): Promise<GeoOracle> {
    let pending = GeoOracle.cache.get(baseURL);
    if (!pending) {
      const fetchDb = async (name: string) => {
        const response = await fetch(new URL(`/data/${name}`, baseURL));
        if (!response.ok) throw new Error(`cannot download ${name} from ${baseURL}: HTTP ${response.status}`);
        return new Mmdb(Buffer.from(await response.arrayBuffer()));
      };
      pending = Promise.all([fetchDb('GeoLite2-Country.mmdb'), fetchDb('GeoLite2-ASN.mmdb')])
        .then(([country, asn]) => new GeoOracle(country, asn));
      GeoOracle.cache.set(baseURL, pending);
    }
    return pending;
  }

  facts(ip: string): GeoFacts {
    const known = parseIp(ip) !== null;
    const place = known ? (this.country.lookup(ip) as { country?: { iso_code?: string; names?: { en?: string } } } | null) : null;
    const network = known ? (this.asn.lookup(ip) as { autonomous_system_number?: number; autonomous_system_organization?: string } | null) : null;
    const country = place?.country?.names?.en || 'Unknown';
    const countryCode = place?.country?.iso_code || '--';
    const organisation = network?.autonomous_system_organization || 'Unknown';
    const flag = flagOf(countryCode);
    return {
      country,
      countryCode,
      organisation,
      asn: network?.autonomous_system_number || 0,
      location: flag ? `${flag} ${country}` : country,
      brand: brandOf(organisation),
    };
  }
}

// ─── API payloads (shape of POST /api/dns, see backend/src/routes/dns.js) ───

export interface ApiRecord {
  name?: string;
  type?: string;
  TTL?: number;
  data?: string;
  value?: string;
  priority?: number;
}

export interface ApiAnswer {
  domain?: string;
  type?: string;
  resolver?: string;
  records?: ApiRecord[];
  status?: number;
  _type?: string;
  noRecords?: boolean;
  message?: string;
  error?: string;
  dns_provider?: ProviderInfo;
  hosting_provider?: ProviderInfo;
}

/** What the test's fake backend answers for one record type. */
export type Reply =
  | { kind: 'answer'; body: ApiAnswer }
  | { kind: 'http'; status: number; body: unknown }
  | { kind: 'network' };

export interface Lookup {
  domain: string;
  resolver: string;
  types: string[];
  replies: Record<string, Reply>;
}

// ─── Expected page content ───

export interface ExpectedCell { text: string; title?: string }

export interface ExpectedSection {
  type: string;
  count: number;
  state: 'table' | 'empty' | 'error';
  /** Error or "no records" text; null when any non-empty error text is acceptable (network failure). */
  note: string | null;
  headers: string[];
  rows: ExpectedCell[][];
  /** Query time the section must show, when the source states one (regional lookups). */
  queryMs?: number;
  /** Records as stored in a shared snapshot. */
  records: Record<string, unknown>[];
  raw: { error: string; message: string; noRecords: boolean; status: number | null; dns: Provider; hosting: Provider };
}

export interface ExpectedView {
  domain: string;
  resolver: string;
  resolverName: string;
  selectedTypes: string[];
  totalRecords: number;
  dnsProvider: Provider;
  hostingProvider: Provider;
  sections: ExpectedSection[];
  /** "No DNS records were returned …" is shown when every section is empty and none failed. */
  nothingFound: boolean;
}

function isAddressType(type: string): boolean {
  return type === 'A' || type === 'AAAA';
}

function failureText(reply: Extract<Reply, { kind: 'http' }>): string {
  if (typeof reply.body === 'string') return `HTTP ${reply.status}`;
  const error = (reply.body as { error?: unknown } | null)?.error;
  return typeof error === 'string' && error ? error : `Request failed: ${reply.status}`;
}

function expectedSection(type: string, reply: Reply, geo: GeoOracle | null): ExpectedSection {
  const headers = ['Value', ...(isAddressType(type) ? ['Location', 'Provider'] : []), ...(type === 'MX' ? ['Priority'] : []), 'TTL'];
  const failed = (note: string | null): ExpectedSection => ({
    type, count: 0, state: 'error', note, headers, rows: [], records: [],
    raw: { error: note ?? '', message: '', noRecords: false, status: null, dns: UNKNOWN_PROVIDER, hosting: UNKNOWN_PROVIDER },
  });
  if (reply.kind === 'network') return failed(null);
  if (reply.kind === 'http') return failed(failureText(reply));

  const body = reply.body;
  const list = Array.isArray(body.records) ? body.records : [];
  const raw = {
    error: body.error ?? '',
    message: body.message ?? '',
    noRecords: body.noRecords === true,
    status: typeof body.status === 'number' ? body.status : null,
    dns: cleanProvider(body.dns_provider),
    hosting: cleanProvider(body.hosting_provider),
  };

  const rows: ExpectedCell[][] = [];
  const records: Record<string, unknown>[] = [];
  for (const record of list) {
    const value = record.data ?? record.value ?? '';
    const ttl = Number(record.TTL ?? 0);
    const facts = isAddressType(type) && geo ? geo.facts(value) : null;
    const row: ExpectedCell[] = [{ text: value }];
    if (isAddressType(type)) {
      row.push(facts ? { text: facts.location, title: facts.country } : { text: '—', title: '' });
      row.push(facts ? { text: facts.brand, title: facts.organisation } : { text: 'Unknown', title: 'Unknown' });
    }
    if (type === 'MX') row.push({ text: record.priority === undefined ? '' : String(record.priority) });
    row.push({ text: humanTtl(ttl), title: `${ttl} seconds` });
    rows.push(row);
    records.push({
      name: record.name ?? '',
      type,
      TTL: ttl,
      data: value,
      value: record.value ?? value,
      priority: record.priority ?? '',
      provider_label: facts?.brand ?? '',
      provider_org: facts?.organisation ?? '',
      provider_asn: facts?.asn ?? 0,
      country: facts?.country ?? '',
      country_code: facts?.countryCode ?? '',
    });
  }

  if (raw.error) return { type, count: list.length, state: 'error', note: raw.error, headers, rows: [], records, raw };
  if (list.length === 0) {
    return { type, count: 0, state: 'empty', note: raw.message || `No ${type} records found.`, headers, rows: [], records, raw };
  }
  return { type, count: list.length, state: 'table', note: null, headers, rows, records, raw };
}

/** Everything the result area must show for a lookup answered with `lookup.replies`. */
export function expectedView(lookup: Lookup, geo: GeoOracle | null): ExpectedView {
  const order = (type: string) => {
    const index = (SECTION_ORDER as readonly string[]).indexOf(type);
    return index < 0 ? SECTION_ORDER.length : index;
  };
  const sections = lookup.types
    .map((type, position) => ({ type, position }))
    .sort((a, b) => order(a.type) - order(b.type) || a.position - b.position)
    .map(({ type }) => expectedSection(type, lookup.replies[type], geo));

  return {
    domain: lookup.domain,
    resolver: lookup.resolver,
    resolverName: resolverLabel(lookup.resolver),
    selectedTypes: [...lookup.types],
    totalRecords: sections.reduce((sum, section) => sum + section.count, 0),
    dnsProvider: pickProvider(sections.map(section => section.raw.dns)),
    hostingProvider: pickProvider(sections.map(section => section.raw.hosting)),
    sections,
    nothingFound: sections.length > 0 && sections.every(section => section.state === 'empty'),
  };
}

/** Index of a column in a section's table, by its header. */
function column(section: ExpectedSection, header: string): number {
  return section.headers.indexOf(header);
}

/**
 * Text "Copy All Records" puts on the clipboard: one block per type that has
 * records, "--- TYPE ---" then one line per record with the value, the TTL in
 * seconds and, where the table has those columns, priority, provider and
 * location in parentheses.
 */
export function expectedCopyText(view: ExpectedView): string {
  return view.sections
    .filter(section => section.state === 'table')
    .map(section => {
      const lines = section.rows.map((row, index) => {
        const parts = [row[0].text, `(TTL: ${section.records[index].TTL})`];
        if (section.type === 'MX' && row[column(section, 'Priority')].text !== '') parts.push(`(Priority: ${row[column(section, 'Priority')].text})`);
        if (isAddressType(section.type)) {
          const provider = String(section.records[index].provider_label);
          const country = String(section.records[index].country);
          if (provider) parts.push(`(Provider: ${provider})`);
          if (country) parts.push(`(${row[column(section, 'Location')].text})`);
        }
        return parts.join(' ');
      });
      return `--- ${section.type} ---\n${lines.join('\n')}`;
    })
    .join('\n\n');
}

export const CSV_HEADER = ['domain', 'resolver', 'type', 'record', 'ttl', 'priority', 'location', 'provider'];

/**
 * Rows of "Export CSV" (header excluded): one row per record; a type without
 * records gets one row that carries its message (or "Error: …", or "No records").
 */
export function expectedCsvRows(view: ExpectedView): string[][] {
  const rows: string[][] = [];
  for (const section of view.sections) {
    if (section.records.length === 0) {
      const note = section.raw.message || (section.raw.error ? `Error: ${section.raw.error}` : 'No records');
      rows.push([view.domain, view.resolver, section.type, note, '', '', '', '']);
      continue;
    }
    section.records.forEach(record => {
      const country = String(record.country);
      const flag = flagOf(String(record.country_code));
      rows.push([
        view.domain, view.resolver, section.type, String(record.data), String(record.TTL), String(record.priority),
        country ? (flag ? `${flag} ${country}` : country) : '', String(record.provider_label),
      ]);
    });
  }
  return rows;
}

/**
 * The snapshot the page stores when a result is shared (body of
 * POST /api/share/dns → `snapshot`). `queryTime` and `checkedAt` are supplied
 * by the caller because they are measured, not derived. `selectedTypes` may be
 * overridden because the order in which the page lists the selected types (the
 * order they were ticked in) is not a promise; callers compare it as a set.
 */
export function expectedSnapshot(view: ExpectedView, measured: { checkedAt: unknown; queryTime: unknown; selectedTypes?: unknown }): Record<string, unknown> {
  return {
    domain: view.domain,
    resolver: view.resolver,
    resolver_name: view.resolverName,
    selected_types: measured.selectedTypes ?? view.selectedTypes,
    total_records: view.totalRecords,
    checked_at_utc: measured.checkedAt,
    dns_provider: view.dnsProvider,
    hosting_provider: view.hostingProvider,
    results: view.sections.map(section => ({
      _type: section.type,
      _queryTime: measured.queryTime,
      error: section.raw.error,
      message: section.raw.message,
      noRecords: section.raw.noRecords,
      status: section.raw.status,
      dns_provider: section.raw.dns,
      hosting_provider: section.raw.hosting,
      records: section.records,
    })),
  };
}

// ─── Global propagation (POST /api/dns/global) ───

export type GlobalRecord = string | string[] | Record<string, unknown>;

export interface GlobalRegion {
  region: string;
  status: string;
  data?: { records?: GlobalRecord[]; duration_ms?: number };
  error?: string;
}

/** The 15 regions the backend queries, in the order it returns them. */
export const GLOBAL_REGIONS = [
  'N. Virginia (US)', 'Ohio (US)', 'N. California (US)', 'Oregon (US)', 'Ireland (Europe)', 'London (UK)',
  'Frankfurt (Germany)', 'Stockholm (Sweden)', 'Mumbai (India)', 'Tokyo (Japan)', 'Seoul (South Korea)',
  'Singapore (Asia)', 'Sydney (Australia)', 'Central (Canada)', 'São Paulo (Brazil)',
];

/**
 * One line of the Result column. The regional services answer in the shapes
 * of Node's `dns` module: a string (A, AAAA, NS, CNAME, PTR), a list of
 * strings (the chunks of one TXT record, shown separated by a space), or an
 * object for MX, SRV and SOA, shown as "label: value | label: value".
 */
export function globalRecordText(record: GlobalRecord): string {
  if (typeof record === 'string') return record;
  if (Array.isArray(record)) return record.join(' ');
  const pairs = (fields: [string, unknown][]) => fields.map(([label, value]) => `${label}: ${value}`).join(' | ');
  if ('nsname' in record) {
    return pairs([['ns', record.nsname], ['admin', record.hostmaster], ['serial', record.serial], ['refresh', record.refresh], ['retry', record.retry], ['expire', record.expire]]);
  }
  if ('exchange' in record) return pairs([['priority', record.priority], ['exchange', record.exchange]]);
  if ('port' in record) return pairs([['priority', record.priority], ['weight', record.weight], ['port', record.port], ['target', record.name]]);
  return String(record.data ?? record.value ?? '');
}

export interface ExpectedGlobalRow {
  region: string;
  status: 'Success' | 'Failed';
  lines: string[];
}

/** Rows of the "Global DNS Propagation" table, in the order the API returned the regions. */
export function expectedGlobalRows(results: GlobalRegion[]): ExpectedGlobalRow[] {
  return results.map(result => {
    const records = result.data?.records;
    if (result.status === 'success' && Array.isArray(records)) {
      return { region: result.region, status: 'Success', lines: records.length ? records.map(globalRecordText) : ['No records'] };
    }
    return { region: result.region, status: 'Failed', lines: [result.error || 'No records found'] };
  });
}

export const GLOBAL_CSV_HEADER = ['region', 'status', 'error', 'record'];

/** Rows of the global "Export CSV": one per record; a region without records gets one row. */
export function expectedGlobalCsvRows(results: GlobalRegion[]): string[][] {
  const rows: string[][] = [];
  for (const result of results) {
    const ok = result.status === 'success';
    const records = result.data?.records ?? [];
    const code = ok ? '200' : '500';
    if (records.length === 0) rows.push([result.region, code, result.error || 'No records', '']);
    else records.forEach(record => rows.push([result.region, code, result.error || '', globalRecordText(record)]));
  }
  return rows;
}

/**
 * A global result as a snapshot view (HTML report and shared page): one
 * section per region, regions with records first, then regions without,
 * then failed regions; inside each group the API order.
 */
export function expectedGlobalView(domain: string, type: string, results: GlobalRegion[]): ExpectedView {
  const sections = results.map((result): ExpectedSection => {
    const ok = result.status === 'success';
    const texts = (result.data?.records ?? []).map(globalRecordText);
    const error = result.error || '';
    const base = {
      type: result.region,
      count: texts.length,
      queryMs: result.data?.duration_ms ?? 0,
      headers: ['Value', 'TTL'],
      rows: texts.map(text => [{ text }, { text: '' }]),
      records: texts.map(text => ({ data: text, type })),
      raw: {
        error, message: ok && texts.length === 0 ? 'No records returned.' : '', noRecords: ok && texts.length === 0,
        status: ok ? 200 : 500, dns: UNKNOWN_PROVIDER, hosting: UNKNOWN_PROVIDER,
      },
    };
    if (error) return { ...base, state: 'error', note: error, rows: [] };
    if (texts.length === 0) return { ...base, state: 'empty', note: ok ? 'No records returned.' : `No ${result.region} records found.` };
    return { ...base, state: 'table', note: null };
  });
  const group = (section: ExpectedSection) => (section.count > 0 ? 0 : section.state === 'error' ? 2 : 1);
  const ordered = sections
    .map((section, position) => ({ section, position }))
    .sort((a, b) => group(a.section) - group(b.section) || a.position - b.position)
    .map(entry => entry.section);
  return {
    domain,
    resolver: 'global',
    resolverName: 'Global AWS Lambda Network (15 Regions)',
    selectedTypes: [type],
    totalRecords: ordered.reduce((sum, section) => sum + section.count, 0),
    dnsProvider: UNKNOWN_PROVIDER,
    hostingProvider: UNKNOWN_PROVIDER,
    sections: ordered,
    nothingFound: ordered.length > 0 && ordered.every(section => section.state === 'empty'),
  };
}
