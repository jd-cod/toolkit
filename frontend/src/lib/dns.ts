'use client';

export const DNS_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA', 'PTR', 'SRV', 'CAA'] as const;
export const DEFAULT_DNS_TYPES = ['A', 'AAAA', 'MX', 'CNAME', 'NS', 'TXT'] as const;

export const RESOLVER_OPTIONS = [
  { label: 'Cloudflare (1.1.1.1)', value: '1.1.1.1' },
  { label: 'Google (8.8.8.8)', value: '8.8.8.8' },
  { label: 'OpenDNS', value: '208.67.222.222' },
] as const;

const RESULT_ORDER: Record<string, number> = {
  A: 0,
  AAAA: 1,
  MX: 2,
  CNAME: 3,
  NS: 4,
  TXT: 5,
  SOA: 6,
  PTR: 7,
  SRV: 8,
  CAA: 9,
};

export type DnsConfidence = 'low' | 'medium' | 'high';

export interface DnsProviderInfo {
  slug?: string;
  name: string;
  confidence: DnsConfidence;
  source: string;
  matched_on: string;
}

export interface DnsRecord {
  name: string;
  type: string;
  TTL: number;
  data: string;
  value?: string;
  priority?: number | string;
  provider_label?: string;
  provider_org?: string;
  provider_asn?: number;
  country?: string;
  country_code?: string;
}

export interface DnsLookupResult {
  _type: string;
  _queryTime: number;
  error: string;
  message: string;
  noRecords: boolean;
  status: number | null;
  dns_provider: DnsProviderInfo;
  hosting_provider: DnsProviderInfo;
  records: DnsRecord[];
}

export interface DnsSnapshot {
  domain: string;
  resolver: string;
  resolver_name: string;
  selected_types: string[];
  total_records: number;
  checked_at_utc: string;
  dns_provider: DnsProviderInfo;
  hosting_provider: DnsProviderInfo;
  results: DnsLookupResult[];
}

type UnknownRecord = Partial<DnsRecord> & Record<string, unknown>;
type UnknownLookup = Partial<DnsLookupResult> & {
  records?: Array<UnknownRecord | DnsRecord>;
  dns_provider?: Partial<DnsProviderInfo>;
  hosting_provider?: Partial<DnsProviderInfo>;
  [key: string]: unknown;
};

export const IP_PROVIDER_PATTERNS = [
  { label: 'Amazon', patterns: [/amazon/i, /aws/i] },
  { label: 'Google', patterns: [/google/i] },
  { label: 'Cloudflare', patterns: [/cloudflare/i] },
  { label: 'Microsoft Azure', patterns: [/microsoft/i, /azure/i] },
  { label: 'Fastly', patterns: [/fastly/i] },
  { label: 'Akamai', patterns: [/akamai/i] },
  { label: 'Sucuri', patterns: [/sucuri/i] },
  { label: 'DigitalOcean', patterns: [/digitalocean/i] },
  { label: 'Hetzner', patterns: [/hetzner/i] },
  { label: 'OVHcloud', patterns: [/\bovh\b/i] },
  { label: 'Linode', patterns: [/linode/i, /akamai connected cloud/i] },
  { label: 'Oracle Cloud', patterns: [/oracle/i] },
  { label: 'IBM Cloud', patterns: [/\bibm\b/i, /softlayer/i] },
  { label: 'Vultr', patterns: [/vultr/i, /choopa/i] },
  { label: 'Netlify', patterns: [/netlify/i] },
  { label: 'Vercel', patterns: [/vercel/i] },
  { label: 'Shopify', patterns: [/shopify/i] },
  { label: 'GitHub', patterns: [/github/i] },
  { label: 'Alibaba Cloud', patterns: [/alibaba/i, /\balicloud\b/i] },
  { label: 'Tencent Cloud', patterns: [/tencent/i] },
  { label: 'CDN77', patterns: [/cdn77/i, /datacamp limited/i] },
] as const;

export function cleanDomain(input: string) {
  return input
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .toLowerCase();
}

export function getResolverName(resolver: string) {
  return RESOLVER_OPTIONS.find((option) => option.value === resolver)?.label || resolver;
}

export function emptyProvider(): DnsProviderInfo {
  return { slug: 'unknown', name: 'Unknown', confidence: 'low', source: '', matched_on: '' };
}

export function normalizeProvider(input?: Partial<DnsProviderInfo> | null): DnsProviderInfo {
  return {
    slug: typeof input?.slug === 'string' ? input.slug : 'unknown',
    name: typeof input?.name === 'string' && input.name ? input.name : 'Unknown',
    confidence: input?.confidence === 'high' || input?.confidence === 'medium' ? input.confidence : 'low',
    source: typeof input?.source === 'string' ? input.source : '',
    matched_on: typeof input?.matched_on === 'string' ? input.matched_on : '',
  };
}

export function normalizeRecord(record: UnknownRecord | DnsRecord, type: string): DnsRecord {
  const data = typeof record.data === 'string'
    ? record.data
    : typeof record.value === 'string'
      ? record.value
      : '';
  return {
    name: typeof record.name === 'string' ? record.name : '',
    type,
    TTL: typeof record.TTL === 'number' ? record.TTL : Number(record.TTL) || 0,
    data,
    value: typeof record.value === 'string' ? record.value : data,
    priority: typeof record.priority === 'number' || typeof record.priority === 'string' ? record.priority : '',
    provider_label: typeof record.provider_label === 'string' ? record.provider_label : '',
    provider_org: typeof record.provider_org === 'string' ? record.provider_org : '',
    provider_asn: typeof record.provider_asn === 'number' ? record.provider_asn : 0,
    country: typeof record.country === 'string' ? record.country : '',
    country_code: typeof record.country_code === 'string' ? record.country_code : '',
  };
}

export function normalizeLookupResult(input: UnknownLookup | DnsLookupResult, requestedType: string): DnsLookupResult {
  const resultType = typeof input._type === 'string' && input._type ? input._type : requestedType;
  return {
    _type: resultType,
    _queryTime: typeof input._queryTime === 'number' ? input._queryTime : Number(input._queryTime) || 0,
    error: typeof input.error === 'string' ? input.error : '',
    message: typeof input.message === 'string' ? input.message : '',
    noRecords: Boolean(input.noRecords),
    status: typeof input.status === 'number' ? input.status : null,
    dns_provider: normalizeProvider(input.dns_provider),
    hosting_provider: normalizeProvider(input.hosting_provider),
    records: Array.isArray(input.records) ? input.records.map((record) => normalizeRecord(record, resultType)) : [],
  };
}

export function createRejectedLookupResult(recordType: string, error: unknown, queryTime: number): DnsLookupResult {
  return {
    _type: recordType,
    _queryTime: queryTime,
    error: error instanceof Error ? error.message : 'DNS query failed.',
    message: '',
    noRecords: false,
    status: null,
    dns_provider: emptyProvider(),
    hosting_provider: emptyProvider(),
    records: [],
  };
}

export function isIpType(type: string) {
  return type === 'A' || type === 'AAAA';
}

export function confidenceRank(confidence: DnsConfidence) {
  if (confidence === 'high') return 3;
  if (confidence === 'medium') return 2;
  return 1;
}

export function chooseBetterProvider(current: DnsProviderInfo, candidate: DnsProviderInfo) {
  if (confidenceRank(candidate.confidence) > confidenceRank(current.confidence)) return candidate;
  if (confidenceRank(candidate.confidence) === confidenceRank(current.confidence) && current.name === 'Unknown' && candidate.name !== 'Unknown') {
    return candidate;
  }
  return current;
}

export function orderDnsResults(results: DnsLookupResult[]) {
  if (!Array.isArray(results)) return [];
  return [...results].sort((left, right) => {
    const leftOrder = RESULT_ORDER[left?._type] ?? 99;
    const rightOrder = RESULT_ORDER[right?._type] ?? 99;
    if (leftOrder !== rightOrder) return leftOrder - rightOrder;

    const leftHasRecords = (left?.records?.length || 0) > 0 ? 1 : 0;
    const rightHasRecords = (right?.records?.length || 0) > 0 ? 1 : 0;
    if (leftHasRecords !== rightHasRecords) return rightHasRecords - leftHasRecords;

    if (Boolean(left?.error) !== Boolean(right?.error)) return Number(Boolean(left?.error)) - Number(Boolean(right?.error));
    return 0;
  });
}

export function capitalize(value: string) {
  return value ? value.charAt(0).toUpperCase() + value.slice(1) : '';
}

export function formatTTL(ttl: number) {
  if (ttl < 60) return `${ttl}s`;
  if (ttl < 3600) return `${Math.floor(ttl / 60)}m ${ttl % 60}s`;
  if (ttl < 86400) return `${Math.floor(ttl / 3600)}h ${Math.floor((ttl % 3600) / 60)}m`;
  return `${Math.floor(ttl / 86400)}d ${Math.floor((ttl % 86400) / 3600)}h`;
}

export function formatUTC(iso: string) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return 'Unknown UTC';
  const formatted = new Intl.DateTimeFormat('en-GB', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZone: 'UTC',
    hour12: false,
  }).format(date).replace(',', '');
  return `${formatted} UTC`;
}

export function normalizeProviderLabel(org: string) {
  if (!org || org === 'Unknown') return 'Unknown';
  const matched = IP_PROVIDER_PATTERNS.find((entry) => entry.patterns.some((pattern) => pattern.test(org)));
  return matched ? matched.label : org;
}

export function countryCodeToFlag(code: string) {
  if (!code || code === '--' || code.length !== 2) return '';
  const upper = code.toUpperCase();
  return String.fromCodePoint(
    0x1F1E6 + upper.charCodeAt(0) - 65,
    0x1F1E6 + upper.charCodeAt(1) - 65,
  );
}

export function formatLocation(record: DnsRecord) {
  const flag = countryCodeToFlag(record.country_code || '');
  const name = record.country || '';
  if (flag && name) return `${flag} ${name}`;
  if (name) return name;
  return '';
}

export function buildDnsSnapshot(params: {
  domain: string;
  resolver: string;
  selectedTypes: string[];
  checkedAtUtc: string;
  results: DnsLookupResult[];
}) {
  const ordered = orderDnsResults(params.results);
  const totalRecords = ordered.reduce((sum, result) => sum + result.records.length, 0);

  const dnsProvider = ordered.reduce((best, result) => chooseBetterProvider(best, normalizeProvider(result.dns_provider)), emptyProvider());
  const hostingProvider = ordered.reduce((best, result) => chooseBetterProvider(best, normalizeProvider(result.hosting_provider)), emptyProvider());

  return {
    domain: params.domain,
    resolver: params.resolver,
    resolver_name: getResolverName(params.resolver),
    selected_types: [...params.selectedTypes],
    total_records: totalRecords,
    checked_at_utc: params.checkedAtUtc,
    dns_provider: dnsProvider,
    hosting_provider: hostingProvider,
    results: ordered,
  } satisfies DnsSnapshot;
}

export function normalizeSharedSnapshot(snapshot: unknown): DnsSnapshot {
  const input = (snapshot ?? {}) as Partial<DnsSnapshot> & { results?: UnknownLookup[] };
  const resolver = typeof input.resolver === 'string' && input.resolver ? input.resolver : '1.1.1.1';
  const results = Array.isArray(input.results)
    ? input.results.map((result) => normalizeLookupResult(result, typeof result._type === 'string' ? result._type : 'A'))
    : [];

  return {
    domain: typeof input.domain === 'string' ? input.domain : '',
    resolver,
    resolver_name: typeof input.resolver_name === 'string' && input.resolver_name ? input.resolver_name : getResolverName(resolver),
    selected_types: Array.isArray(input.selected_types) ? input.selected_types.filter((value): value is string => typeof value === 'string') : results.map((result) => result._type),
    total_records: typeof input.total_records === 'number' ? input.total_records : results.reduce((sum, result) => sum + result.records.length, 0),
    checked_at_utc: typeof input.checked_at_utc === 'string' ? input.checked_at_utc : new Date().toISOString(),
    dns_provider: normalizeProvider(input.dns_provider),
    hosting_provider: normalizeProvider(input.hosting_provider),
    results: orderDnsResults(results),
  };
}

export function snapshotToPlainText(snapshot: DnsSnapshot) {
  return orderDnsResults(snapshot.results)
    .filter((result) => result.records.length > 0)
    .map((result) => {
      const lines = result.records.map((record) => {
        const segments = [`${record.data || record.value || ''}`, `(TTL: ${record.TTL || 0})`];
        if (result._type === 'MX' && record.priority !== '' && record.priority != null) {
          segments.push(`(Priority: ${record.priority})`);
        }
        if (isIpType(result._type) && record.provider_label) {
          segments.push(`(Provider: ${record.provider_label})`);
        }
        if (isIpType(result._type) && record.country) {
          const flag = countryCodeToFlag(record.country_code || '');
          segments.push(`(${flag ? flag + ' ' : ''}${record.country})`);
        }
        return segments.join(' ');
      });
      return `--- ${result._type} ---\n${lines.join('\n')}`;
    })
    .join('\n\n');
}

export function buildRerunHref(snapshot: DnsSnapshot) {
  const params = new URLSearchParams();
  params.set('domain', snapshot.domain);
  params.set('resolver', snapshot.resolver);
  params.set('types', snapshot.selected_types.join(','));
  return `/dns?${params.toString()}`;
}

export function buildDnsSnapshotHtml(snapshot: DnsSnapshot) {
  const orderedResults = orderDnsResults(snapshot.results);
  const dnsProviderConfidence = `${capitalize(snapshot.dns_provider.confidence)} confidence`;
  const dnsProviderSource = snapshot.dns_provider.source ? `via ${snapshot.dns_provider.source}` : 'No strong DNS fingerprint';
  const hostingProviderConfidence = `${capitalize(snapshot.hosting_provider.confidence)} confidence`;
  const hostingProviderSource = snapshot.hosting_provider.source ? `via ${snapshot.hosting_provider.source}` : 'Derived from DNS answers';
  const timestampLine = formatUTC(snapshot.checked_at_utc);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DNS Snapshot Report - ${escapeHtml(snapshot.domain)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0b14; color: #e8ecf4; padding: 40px 20px; }
    .container { max-width: 1100px; margin: 0 auto; }
    h1 { font-size: 2rem; font-weight: 800; background: linear-gradient(135deg, #22d3ee, #6366f1); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 8px; }
    .subtitle { color: #94a3b8; font-size: 0.9rem; margin-bottom: 28px; }
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 20px; }
    .card { background: #12141f; border: 1px solid #1e2235; border-radius: 14px; padding: 22px 18px; text-align: center; min-height: 104px; display: flex; flex-direction: column; justify-content: center; }
    .card-val { font-size: 1.3rem; font-weight: 800; line-height: 1.2; }
    .card-val.big { font-size: 1.9rem; }
    .card-label { font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.1em; margin-top: 6px; }
    .card-meta { font-size: 0.76rem; color: #64748b; margin-top: 6px; }
    .timestamp { color: #cbd5e1; margin-bottom: 22px; font-size: 0.88rem; }
    .section { background: #12141f; border: 1px solid #1e2235; border-radius: 14px; margin-bottom: 18px; overflow: hidden; }
    .section-header { padding: 14px 20px; border-bottom: 1px solid #1e2235; font-weight: 700; }
    .section-meta { font-size: 0.78rem; color: #94a3b8; margin-left: 8px; font-weight: 500; }
    table { width: 100%; border-collapse: collapse; table-layout: fixed; }
    th { background: #0e1019; padding: 12px 16px; text-align: left; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; color: #94a3b8; border-bottom: 2px solid #1e2235; }
    td { padding: 10px 16px; border-bottom: 1px solid rgba(30,34,53,0.5); font-size: 0.88rem; }
    .right { text-align: right; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
    .muted { color: #94a3b8; }
    .footer { text-align: center; color: #64748b; font-size: 0.78rem; margin-top: 36px; padding-top: 18px; border-top: 1px solid #1e2235; }
    .empty { padding: 16px 20px; color: #94a3b8; font-size: 0.86rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>DNS Snapshot Report</h1>
    <p class="subtitle">${escapeHtml(snapshot.domain)} - Resolver ${escapeHtml(snapshot.resolver_name)}</p>
    <p class="timestamp"><strong>Checked At:</strong> ${escapeHtml(timestampLine)}</p>
    <div class="cards">
      <div class="card"><div class="card-val mono">${escapeHtml(snapshot.domain)}</div><div class="card-label">Domain</div></div>
      <div class="card"><div class="card-val big">${snapshot.total_records || 0}</div><div class="card-label">Records Found</div></div>
      <div class="card"><div class="card-val">${escapeHtml(snapshot.dns_provider.name)}</div><div class="card-label">DNS Provider</div><div class="card-meta">${escapeHtml(dnsProviderConfidence)} - ${escapeHtml(dnsProviderSource)}</div></div>
      <div class="card"><div class="card-val">${escapeHtml(snapshot.hosting_provider.name)}</div><div class="card-label">Hosting / Edge</div><div class="card-meta">${escapeHtml(hostingProviderConfidence)} - ${escapeHtml(hostingProviderSource)}</div></div>
      <div class="card"><div class="card-val">${escapeHtml(snapshot.resolver_name)}</div><div class="card-label">Resolver</div></div>
    </div>
    ${orderedResults.map((result) => `
      <div class="section">
        <div class="section-header">${escapeHtml(result._type)} Records <span class="section-meta">${result.records.length} found - ${result._queryTime || 0}ms</span></div>
        ${result.error
          ? `<div class="empty">${escapeHtml(result.error)}</div>`
          : result.records.length === 0
            ? `<div class="empty">${escapeHtml(result.message || `No ${result._type} records found.`)}</div>`
            : buildDnsSnapshotHtmlTable(result)}
      </div>
    `).join('')}
    <div class="footer">Generated offline from a DNS snapshot - Timestamp shown in UTC</div>
  </div>
</body>
</html>`;
}

function buildDnsSnapshotHtmlTable(result: DnsLookupResult) {
  return `
    <table>
      <colgroup>
        <col style="width:auto;">
        ${isIpType(result._type) ? '<col style="width:180px;">' : ''}
        ${isIpType(result._type) ? '<col style="width:180px;">' : ''}
        ${result._type === 'MX' ? '<col style="width:120px;">' : ''}
        <col style="width:110px;">
      </colgroup>
      <thead><tr>
        <th>Value</th>
        ${isIpType(result._type) ? '<th class="right">Location</th>' : ''}
        ${isIpType(result._type) ? '<th class="right">Provider</th>' : ''}
        ${result._type === 'MX' ? '<th class="right">Priority</th>' : ''}
        <th class="right">TTL</th>
      </tr></thead>
      <tbody>
        ${result.records.map((record) => {
          const flag = countryCodeToFlag(record.country_code || '');
          const location = record.country ? `${flag ? flag + ' ' : ''}${record.country}` : '';
          return `
          <tr>
            <td class="mono">${escapeHtml(record.data || record.value || '')}</td>
            ${isIpType(result._type) ? `<td class="right muted">${escapeHtml(location)}</td>` : ''}
            ${isIpType(result._type) ? `<td class="right muted">${escapeHtml(record.provider_label || 'Unknown')}</td>` : ''}
            ${result._type === 'MX' ? `<td class="right muted">${escapeHtml(String(record.priority || ''))}</td>` : ''}
            <td class="right muted">${escapeHtml(formatTTL(record.TTL || 0))}</td>
          </tr>
        `;
        }).join('')}
      </tbody>
    </table>
  `;
}

function escapeHtml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
