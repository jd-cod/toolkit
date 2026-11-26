import { buildReportHtml } from './report-html';

export interface IPInfoResultItem {
  ip: string;
  hits: number;
  ip_version: string;
  is_private: boolean;
  reverse_dns: string;
  country: string;
  country_code: string;
  asn?: number | string;
  asn_org?: string;
  isp: string;
  usage_type: string;
  risk_level: 'safe' | 'low' | 'medium' | 'high' | 'unknown';
  risk_reasons: string[];
  abuse_score: number | null;
  total_reports: number;
  num_distinct_users?: number;
  last_reported_at?: string;
  is_tor?: boolean;
  is_whitelisted?: boolean;
}

export function getCountryFlag(code?: string): string {
  if (!code || code === '--' || code.length !== 2) return '🌐';
  if (code === '🏠') return '🏠';
  const uppercase = code.toUpperCase();
  return String.fromCodePoint(...uppercase.split('').map(c => 127397 + c.charCodeAt(0)));
}

export function getCountryName(code?: string, rawName?: string): string {
  if (!code || code === '--') {
    return (rawName && rawName !== 'Unknown') ? rawName : '';
  }
  if (rawName && rawName !== 'Unknown' && rawName !== code) {
    return rawName;
  }
  try {
    const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });
    const name = regionNames.of(code.toUpperCase());
    if (name) return name;
  } catch {
    // fallback
  }
  return code;
}

/** A batch IP lookup as it is shared. */
export interface IpInfoSnapshot {
  results: IPInfoResultItem[];
  checked_at_utc: string;
}

const RISK_LEVELS = ['safe', 'low', 'medium', 'high', 'unknown'] as const;
const text = (value: unknown, fallback = '') => (typeof value === 'string' ? value : fallback);

/** Rebuilds a snapshot from stored JSON so a damaged or older share still renders. */
export function normalizeIpInfoSnapshot(raw: unknown): IpInfoSnapshot {
  const d = (raw ?? {}) as Partial<IpInfoSnapshot>;
  const rows = Array.isArray(d.results) ? d.results : [];
  return {
    checked_at_utc: text(d.checked_at_utc) || new Date().toISOString(),
    results: rows
      .filter((row): row is IPInfoResultItem => Boolean(row) && typeof row === 'object' && typeof row.ip === 'string')
      .map((row) => ({
        ip: row.ip,
        hits: Number(row.hits) || 1,
        ip_version: text(row.ip_version, row.ip.includes(':') ? 'IPv6' : 'IPv4'),
        is_private: Boolean(row.is_private),
        reverse_dns: text(row.reverse_dns),
        country: text(row.country, 'Unknown'),
        country_code: text(row.country_code, '--'),
        asn: typeof row.asn === 'number' || typeof row.asn === 'string' ? row.asn : '',
        asn_org: text(row.asn_org),
        isp: text(row.isp, 'N/A'),
        usage_type: text(row.usage_type, 'N/A'),
        risk_level: RISK_LEVELS.includes(row.risk_level) ? row.risk_level : 'unknown',
        risk_reasons: Array.isArray(row.risk_reasons) ? row.risk_reasons.filter((reason): reason is string => typeof reason === 'string') : [],
        abuse_score: typeof row.abuse_score === 'number' ? row.abuse_score : null,
        total_reports: Number(row.total_reports) || 0,
        num_distinct_users: Number(row.num_distinct_users) || 0,
        last_reported_at: text(row.last_reported_at),
        is_tor: Boolean(row.is_tor),
        is_whitelisted: Boolean(row.is_whitelisted),
      })),
  };
}

/** Short label for a batch, e.g. "1.1.1.1 +2 more". */
export function ipInfoSubject(results: IPInfoResultItem[]) {
  if (results.length === 0) return 'IP lookup';
  return results.length === 1 ? results[0].ip : `${results[0].ip} +${results.length - 1} more`;
}

export function buildIpInfoSummary(results: IPInfoResultItem[]) {
  return results
    .map(r => `${r.ip} - ${r.reverse_dns || 'No PTR'} - ${r.country || 'Unknown'} - AS${r.asn || 'N/A'} - Risk: ${r.risk_level}`)
    .join('\n');
}

export function ipInfoCounts(results: IPInfoResultItem[]) {
  return {
    total: results.length,
    rdns: results.filter(r => Boolean(r.reverse_dns)).length,
    risk: results.filter(r => r.risk_level === 'high' || r.risk_level === 'medium').length,
    abuse: results.filter(r => r.abuse_score !== null && r.abuse_score > 0).length,
  };
}

export function buildIpInfoReportHtml(snapshot: IpInfoSnapshot) {
  const { results } = snapshot;
  const counts = ipInfoCounts(results);
  const riskLabel = (level: string) => level.charAt(0).toUpperCase() + level.slice(1);

  return buildReportHtml({
    title: 'IP Info & Risk Report',
    subject: ipInfoSubject(results),
    checkedAt: snapshot.checked_at_utc,
    cards: [
      { label: 'Total IPs Analyzed', value: counts.total },
      { label: 'Reverse DNS Found', value: counts.rdns },
      { label: 'Risk Flags / Elevated', value: counts.risk },
      { label: 'Abuse Reports', value: counts.abuse },
    ],
    sections: [
      {
        title: 'Results',
        meta: `${results.length} IPs`,
        empty: 'No IP addresses in this report.',
        table: {
          columns: ['#', 'IP Address', 'Reverse DNS (PTR)', 'Country', 'ASN & Network / ISP', 'Risk', 'Abuse Score'],
          mono: [1, 2],
          rows: results.map((r, i) => [
            i + 1,
            r.ip,
            r.reverse_dns || 'No PTR record',
            [getCountryName(r.country_code, r.country) || 'Unknown', r.country_code && r.country_code !== '--' ? `(${r.country_code})` : ''].filter(Boolean).join(' '),
            [r.asn ? `AS${r.asn}` : '', r.isp].filter(Boolean).join(' '),
            riskLabel(r.risk_level),
            r.abuse_score !== null ? `${r.abuse_score}%` : 'N/A',
          ]),
        },
      },
      {
        title: 'Details',
        empty: 'No details.',
        table: {
          columns: ['IP Address', 'Usage', 'Reports', 'Last Reported', 'TOR', 'Whitelisted', 'Risk Reasons'],
          mono: [0],
          rows: results.map(r => [
            r.ip,
            r.usage_type,
            r.total_reports,
            r.last_reported_at || 'Never',
            r.is_tor ? 'TOR exit node' : 'No',
            r.is_whitelisted ? 'Yes' : 'No',
            r.risk_reasons.join('; '),
          ]),
        },
      },
    ],
  });
}
