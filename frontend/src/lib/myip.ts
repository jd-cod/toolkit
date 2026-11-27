import type { MyIPResult } from './api';

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

export function buildMyIPReportHtml(
  data: MyIPResult,
  clientInfo: ClientInfo,
  ips?: IPDetectionState
): string {
  const rows = (label: string, value: string) =>
    `<tr><td style="padding:10px 14px;color:#94a3b8;font-size:0.85rem;width:40%">${label}</td><td style="padding:10px 14px;font-family:monospace;font-size:0.85rem;word-break:break-all">${value || '—'}</td></tr>`;

  const optionalNetworkRows = [
    data.domain ? rows('Domain', data.domain) : '',
    data.usage_type ? rows('Usage Type', data.usage_type) : '',
    data.proxy_type ? rows('Proxy Type', formatProxyStatus(data)) : '',
  ].join('');

  const badge = networkBadge(data.network_type);

  const ipv4 = ips?.ipv4 ?? (data.ip_version === 'IPv4' ? data.ip : null);
  const ipv6 = ips?.ipv6 ?? (data.ip_version === 'IPv6' ? data.ip : null);
  const isDual = Boolean(ipv4 && ipv6);
  const stackLabel = isDual ? 'Dual-Stack (IPv4 + IPv6)' : ipv4 ? 'IPv4 Only' : 'IPv6 Only';

  const connection = clientInfo.connection;

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>My IP Report — ${ipv4 || data.ip}${ipv6 ? ` / ${ipv6}` : ''}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0b14;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:40px 20px}
.container{max-width:800px;margin:0 auto}
.card{background:rgba(15,17,30,0.8);border:1px solid rgba(99,102,241,0.12);border-radius:16px;margin-bottom:20px;overflow:hidden}
.card-header{padding:14px 20px;border-bottom:1px solid rgba(99,102,241,0.08);font-weight:700;font-size:0.95rem}
table{width:100%;border-collapse:collapse}
tr{border-bottom:1px solid rgba(30,34,53,0.5)}
tr:last-child{border:none}
.ip-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;padding:24px}
.ip-box{background:rgba(99,102,241,0.04);border:1px solid rgba(99,102,241,0.15);border-radius:12px;padding:20px;text-align:center}
.ip-box.v6{background:rgba(168,85,247,0.04);border:1px solid rgba(168,85,247,0.15)}
.ip-val{font-size:1.4rem;font-weight:800;font-family:monospace;color:#818cf8;margin-top:8px;word-break:break-all}
.ip-val.v6{font-size:1.05rem;color:#c084fc}
.not-detected{color:#94a3b8;font-size:0.9rem;margin-top:10px}
.not-detected-desc{font-size:0.75rem;color:#64748b;margin-top:4px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:8px;font-size:0.78rem;font-weight:700}
.badge-stack{display:inline-block;padding:4px 14px;border-radius:8px;font-size:0.78rem;font-weight:700;background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.25);color:#10b981;margin-bottom:16px}
.meta{text-align:center;color:#64748b;font-size:0.75rem;margin-top:30px}
</style></head><body>
<div class="container">

<!-- Dual-Stack IP Addresses -->
<div class="card" style="border-top:3px solid #6366f1;text-align:center;padding-top:20px">
  <div style="font-size:0.72rem;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:8px">Your Public IP Addresses</div>
  <div class="badge-stack">${stackLabel}</div>
  <div class="ip-grid">
    <div class="ip-box">
      <span class="badge" style="background:rgba(59,130,246,0.15);color:#3b82f6;border:1px solid rgba(59,130,246,0.3)">IPv4</span>
      ${ipv4 ? `<div class="ip-val">${ipv4}</div>` : `<div class="not-detected">❌ Not Detected</div>`}
    </div>
    <div class="ip-box v6">
      <span class="badge" style="background:rgba(168,85,247,0.15);color:#a855f7;border:1px solid rgba(168,85,247,0.3)">IPv6</span>
      ${ipv6 ? `<div class="ip-val v6">${ipv6}</div>` : `<div class="not-detected">❌ Not Detected<div class="not-detected-desc">Your network does not support IPv6</div></div>`}
    </div>
  </div>
</div>

<!-- 1. Geolocation -->
<div class="card"><div class="card-header">📍 Geolocation</div><table>
${rows('City', formatCity(data))}${rows('Region', data.region || '')}${rows('Country', `${countryFlag(data.country_code)} ${data.country || ''}`)}${rows('Registered Country', data.registered_country ? `${countryFlag(data.registered_country_code)} ${data.registered_country}` : '')}${rows('Continent', data.continent ? `${data.continent} (${data.continent_code || '—'})` : '')}${rows('Postal Code', data.postal_code || '')}${rows('Accuracy Radius', formatAccuracyRadius(data.accuracy_radius))}${rows('Timezone', data.timezone || '')}${rows('UTC Offset', data.utc_offset || '')}
</table></div>

<!-- 2. GeoLite ASN & Network -->
<div class="card"><div class="card-header">🌐 Network</div><table>
${rows('ASN Organization', data.isp || '')}${rows('ASN', data.asn ? `AS${data.asn}` : '')}${optionalNetworkRows}${rows('Reverse DNS', data.reverse_dns || '')}${rows('Estimated Network Type', badge.label)}
</table></div>

<!-- 3. Browser & Device -->
<div class="card"><div class="card-header">🖥️ Browser & Device</div><table>
${rows('Browser', clientInfo.browser)}${rows('OS', clientInfo.os)}${rows('Screen', clientInfo.screen)}${rows('Language', clientInfo.language)}${rows('Do Not Track', clientInfo.dnt)}${rows('Cookies', clientInfo.cookies)}${rows('GPU', clientInfo.webgl)}${rows('Platform', clientInfo.platform)}
</table></div>

<!-- 4. HTTP Request Headers -->
<div class="card"><div class="card-header">📋 HTTP Request Headers</div><table>
${rows('User-Agent', data.headers.user_agent)}${rows('Accept-Language', data.headers.accept_language)}${rows('Accept-Encoding', data.headers.accept_encoding)}${rows('DNT', data.headers.dnt || 'Not set')}
</table></div>

<!-- 5. Browser-Estimated Connection -->
<div class="card"><div class="card-header">📱 Browser-Estimated Connection</div><table>
${connection && connection.supported ? `
${rows('Browser Connection Type', connection.type)}
${rows('Effective Type', connection.effectiveType)}
${rows('Estimated Bandwidth', connection.downlink !== null ? connection.downlink + ' Mbps' : '—')}
${rows('Round-Trip Time', connection.rtt !== null ? connection.rtt + ' ms' : '—')}
${rows('Data Saver', connection.saveData ? 'Enabled' : 'Disabled')}
` : `<tr><td colspan="2" style="padding:16px;text-align:center;color:#94a3b8">Network Information API not supported by browser</td></tr>`}
</table></div>

<div class="meta">Generated by SysAdmin Toolkit · ${data.checked_at_utc}</div>
</div></body></html>`;
}
