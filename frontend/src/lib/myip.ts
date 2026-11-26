import type { MyIPResult } from './api';
import { buildReportHtml } from './report-html';

export interface ConnectionInfo {
  type: string;
  effectiveType: string;
  downlink: number | null;
  rtt: number | null;
  saveData: boolean;
  supported: boolean;
}

export interface ClientInfo {
  browser: string;
  os: string;
  screen: string;
  language: string;
  dnt: string;
  cookies: string;
  webgl: string;
  platform: string;
  connection?: ConnectionInfo;
}

export interface IPDetectionState {
  ipv4: string | null;
  ipv6: string | null;
}

export interface NormalizedMyIPSnapshot extends MyIPResult {
  ipv4: string | null;
  ipv6: string | null;
  isDualStack: boolean;
  client?: ClientInfo;
  connection?: ConnectionInfo;
}

// Country code → flag emoji
export function countryFlag(code: string | null | undefined): string {
  if (!code || code.length !== 2) return '🌐';
  return String.fromCodePoint(
    ...code.toUpperCase().split('').map((c) => 0x1f1e6 + c.charCodeAt(0) - 65)
  );
}

// Network type label + color
export function networkBadge(type: string | undefined): { label: string; color: string; icon: string } {
  const map: Record<string, { label: string; color: string; icon: string }> = {
    residential: { label: 'Residential', color: '#10b981', icon: 'bi-house-fill' },
    hosting: { label: 'Hosting / Data Center', color: '#f59e0b', icon: 'bi-hdd-rack-fill' },
    business: { label: 'Business / Corporate', color: '#6366f1', icon: 'bi-building' },
    mobile: { label: 'Mobile / Cellular', color: '#ec4899', icon: 'bi-phone-fill' },
    education: { label: 'Education', color: '#06b6d4', icon: 'bi-mortarboard-fill' },
    government: { label: 'Government', color: '#ef4444', icon: 'bi-bank2' },
    unknown: { label: 'Unknown', color: 'var(--text-muted)', icon: 'bi-question-circle' },
  };
  return (type && map[type]) || map.unknown;
}

export function formatCity(data: Partial<MyIPResult>): string {
  return data.city || (data.country ? 'City not available for this IP range' : '');
}

export function formatAccuracyRadius(km: number | null | undefined): string {
  return km !== null && km !== undefined ? `${km} km` : '';
}

export function formatProxyStatus(data: Partial<MyIPResult>): string {
  if (!data.proxy_type) return '';
  return `${data.proxy_type}${data.proxy_detected ? ' detected' : ''}`;
}

export function normalizeMyIPSnapshot(raw: unknown): NormalizedMyIPSnapshot {
  const d = (raw ?? {}) as Partial<NormalizedMyIPSnapshot> & { client?: ClientInfo; connection?: ConnectionInfo };
  let ipv4 = typeof d.ipv4 === 'string' ? d.ipv4 : null;
  let ipv6 = typeof d.ipv6 === 'string' ? d.ipv6 : null;

  // Fallback for legacy snapshots that only stored `ip`
  if (!ipv4 && !ipv6 && typeof d.ip === 'string') {
    if (d.ip.includes(':')) {
      ipv6 = d.ip;
    } else {
      ipv4 = d.ip;
    }
  }

  const isDualStack = Boolean(ipv4 && ipv6);

  return {
    ip: d.ip || ipv4 || ipv6 || '',
    ip_version: d.ip_version || (ipv6 ? 'IPv6' : 'IPv4'),
    city: d.city || null,
    region: d.region || null,
    region_code: d.region_code || null,
    country: d.country || null,
    country_code: d.country_code || null,
    registered_country: d.registered_country || null,
    registered_country_code: d.registered_country_code || null,
    represented_country: d.represented_country || null,
    represented_country_code: d.represented_country_code || null,
    represented_country_type: d.represented_country_type || null,
    continent: d.continent || null,
    continent_code: d.continent_code || null,
    postal_code: d.postal_code || null,
    accuracy_radius: typeof d.accuracy_radius === 'number' ? d.accuracy_radius : null,
    latitude: typeof d.latitude === 'number' ? d.latitude : null,
    longitude: typeof d.longitude === 'number' ? d.longitude : null,
    metro_code: typeof d.metro_code === 'number' ? d.metro_code : null,
    timezone: d.timezone || null,
    utc_offset: d.utc_offset || null,
    isp: d.isp || null,
    org: d.org || null,
    asn: typeof d.asn === 'number' ? d.asn : null,
    asn_name: d.asn_name || null,
    domain: d.domain || null,
    usage_type: d.usage_type || null,
    proxy_type: d.proxy_type || null,
    proxy_detected: Boolean(d.proxy_detected),
    reverse_dns: d.reverse_dns || null,
    network_type: d.network_type || 'unknown',
    data_sources: d.data_sources || {},
    headers: d.headers || {
      user_agent: '',
      accept_language: '',
      accept_encoding: '',
      referer: '',
      dnt: '',
    },
    checked_at_utc: d.checked_at_utc || new Date().toISOString(),
    ipv4,
    ipv6,
    isDualStack,
    client: d.client,
    connection: d.connection,
  };
}

export function buildMyIPExportData(data: MyIPResult, ips?: IPDetectionState): Record<string, unknown> {
  const v4 = ips?.ipv4 || (data.ip_version === 'IPv4' ? data.ip : 'Not Detected');
  const v6 = ips?.ipv6 || (data.ip_version === 'IPv6' ? data.ip : 'Not Detected');
  const stack = v4 !== 'Not Detected' && v6 !== 'Not Detected'
    ? 'Dual-Stack (IPv4 + IPv6)'
    : (v4 !== 'Not Detected' ? 'IPv4 Only' : (v6 !== 'Not Detected' ? 'IPv6 Only' : 'Unknown'));

  return {
    ipv4: v4,
    ipv6: v6,
    ip_stack: stack,
    ...data,
  };
}

/** Stand-in for browser details when a snapshot was saved without them. */
export const UNKNOWN_CLIENT: ClientInfo = {
  browser: 'Unknown',
  os: 'Unknown',
  screen: 'Unknown',
  language: 'Unknown',
  dnt: 'Not set',
  cookies: 'Unknown',
  webgl: 'Unknown',
  platform: 'Unknown',
};

/** Base file name for a My IP export, e.g. "my-ip-report-203-0-113-9". */
export function myIPReportFilename(data: Pick<MyIPResult, 'ip'>, ips?: IPDetectionState) {
  return `my-ip-report-${(ips?.ipv4 || data.ip || 'ip').replace(/[.:]/g, '-')}`;
}

export function buildMyIPReportHtml(
  data: MyIPResult,
  clientInfo: ClientInfo,
  ips?: IPDetectionState
): string {
  const ipv4 = ips?.ipv4 ?? (data.ip_version === 'IPv4' ? data.ip : null);
  const ipv6 = ips?.ipv6 ?? (data.ip_version === 'IPv6' ? data.ip : null);
  const stackLabel = ipv4 && ipv6 ? 'Dual-Stack (IPv4 + IPv6)' : ipv4 ? 'IPv4 Only' : 'IPv6 Only';
  const connection = clientInfo.connection;
  const withFlag = (code: string | null | undefined, name: string | null | undefined) =>
    name ? `${countryFlag(code)} ${name}` : '';

  return buildReportHtml({
    title: 'My IP Report',
    subject: [ipv4, ipv6].filter(Boolean).join(' / ') || data.ip,
    subtitle: stackLabel,
    checkedAt: data.checked_at_utc,
    cards: [
      { label: 'IPv4', value: ipv4 || 'Not Detected', mono: true },
      { label: 'IPv6', value: ipv6 || 'Not Detected', mono: true, meta: ipv6 ? undefined : 'Your network does not support IPv6' },
      { label: 'IP Stack', value: stackLabel },
      { label: 'Estimated Network Type', value: networkBadge(data.network_type).label },
    ],
    sections: [
      {
        title: 'Geolocation',
        rows: [
          ['City', formatCity(data)],
          ['Region', data.region],
          ['Country', withFlag(data.country_code, data.country)],
          ['Registered Country', withFlag(data.registered_country_code, data.registered_country)],
          ['Continent', data.continent ? `${data.continent} (${data.continent_code || '—'})` : ''],
          ['Postal Code', data.postal_code],
          ['Accuracy Radius', formatAccuracyRadius(data.accuracy_radius)],
          ['Timezone', data.timezone],
          ['UTC Offset', data.utc_offset],
        ],
      },
      {
        title: 'Network',
        rows: [
          ['ASN Organization', data.isp],
          ['ASN', data.asn ? `AS${data.asn}` : ''],
          ...(data.domain ? [['Domain', data.domain] as [string, string]] : []),
          ...(data.usage_type ? [['Usage Type', data.usage_type] as [string, string]] : []),
          ...(data.proxy_type ? [['Proxy Type', formatProxyStatus(data)] as [string, string]] : []),
          ['Reverse DNS', data.reverse_dns],
        ],
      },
      {
        title: 'Browser & Device',
        rows: [
          ['Browser', clientInfo.browser],
          ['OS', clientInfo.os],
          ['Screen', clientInfo.screen],
          ['Language', clientInfo.language],
          ['Do Not Track', clientInfo.dnt],
          ['Cookies', clientInfo.cookies],
          ['GPU', clientInfo.webgl],
          ['Platform', clientInfo.platform],
        ],
      },
      {
        title: 'HTTP Request Headers',
        rows: [
          ['User-Agent', data.headers.user_agent],
          ['Accept-Language', data.headers.accept_language],
          ['Accept-Encoding', data.headers.accept_encoding],
          ['DNT', data.headers.dnt || 'Not set'],
        ],
      },
      connection && connection.supported
        ? {
            title: 'Browser-Estimated Connection',
            rows: [
              ['Browser Connection Type', connection.type],
              ['Effective Type', connection.effectiveType],
              ['Estimated Bandwidth', connection.downlink !== null ? `${connection.downlink} Mbps` : ''],
              ['Round-Trip Time', connection.rtt !== null ? `${connection.rtt} ms` : ''],
              ['Data Saver', connection.saveData ? 'Enabled' : 'Disabled'],
            ],
          }
        : { title: 'Browser-Estimated Connection', note: 'Network Information API not supported by browser' },
    ],
  });
}
