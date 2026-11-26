/**
 * ASN & IP Intelligence Client Library
 * Types, IP conversions, subnet math, CIDR aggregation, firewall generator & snapshot export.
 */

export interface ASNPrefix {
  prefix: string;
  ip_version?: 'ipv4' | 'ipv6';
  mask?: number;
  netmask?: string;
  wildcard?: string;
  first_ip?: string;
  last_ip?: string;
  start_long?: number | null;
  end_long?: number | null;
  total_ips?: number;
}

export interface ASNNeighbour {
  asn: number | string;
  asn_formatted: string;
  type: string;
  v4_peers?: number;
  v6_peers?: number;
}

export interface ASNNeighbours {
  upstreams_count: number;
  downstreams_count: number;
  peers_count: number;
  top_peers: ASNNeighbour[];
}

export interface ASNStats {
  total_ipv4_prefixes: number;
  total_ipv6_prefixes: number;
  total_ipv4_ips: number;
  total_ipv4_ips_formatted: string;
  v4_distribution: Record<string, number>;
  v6_distribution: Record<string, number>;
}

export interface AggregatedCidrResult {
  original_count: number;
  aggregated_count: number;
  saved_rules: number;
  reduction_percent: number;
  prefixes: ASNPrefix[];
}

export interface ResolvedFrom {
  input: string;
  type: 'domain' | 'ip' | 'org_search';
  ip?: string;
  domain?: string | null;
  matched_prefix?: string | null;
  matched_org?: string;
}

export interface ASNResult {
  asn: string;
  asn_formatted: string;
  name: string;
  holder?: string;
  description?: string;
  country_code?: string;
  rir?: string;
  announced: boolean;
  abuse_emails?: string[];
  resolved_from?: ResolvedFrom | null;
  neighbours?: ASNNeighbours;
  ipv4_prefixes: ASNPrefix[];
  ipv6_prefixes: ASNPrefix[];
  aggregated_ipv4?: AggregatedCidrResult;
  stats?: ASNStats;
  checked_at_utc: string;
  error?: string | null;
}

export interface IpMatchResult {
  matched: boolean;
  valid?: boolean;
  error?: string;
  ip: string;
  ip_version: 'ipv4' | 'ipv6';
  prefix?: string;
  first_ip?: string;
  last_ip?: string;
  netmask?: string;
  total_ips?: number;
}

export type FirewallFormat =
  | 'nginx'
  | 'apache'
  | 'iptables'
  | 'nftables'
  | 'ufw'
  | 'cisco_acl'
  | 'mikrotik'
  | 'ipset'
  | 'aws_sg'
  | 'pfsense'
  | 'plain_text'
  | 'json'
  | 'csv';

export type FirewallAction = 'deny' | 'allow';

export function ipv4ToLong(ip: string): number | null {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return null;
  }
  return ((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0);
}

export function longToIpv4(long: number): string {
  return [
    (long >>> 24) & 255,
    (long >>> 16) & 255,
    (long >>> 8) & 255,
    long & 255,
  ].join('.');
}

export function parseIpv4Cidr(cidr: string): ASNPrefix | null {
  if (!cidr || typeof cidr !== 'string') return null;
  const [ip, maskStr] = cidr.trim().split('/');
  const mask = parseInt(maskStr, 10);
  if (isNaN(mask) || mask < 0 || mask > 32) return null;

  const ipLong = ipv4ToLong(ip);
  if (ipLong === null) return null;

  const netmaskLong = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
  const wildcardLong = (~netmaskLong) >>> 0;
  const startLong = (ipLong & netmaskLong) >>> 0;
  const endLong = (startLong | wildcardLong) >>> 0;
  const totalIps = Math.pow(2, 32 - mask);

  return {
    prefix: `${longToIpv4(startLong)}/${mask}`,
    ip_version: 'ipv4',
    mask,
    netmask: longToIpv4(netmaskLong),
    wildcard: longToIpv4(wildcardLong),
    first_ip: longToIpv4(startLong),
    last_ip: longToIpv4(endLong),
    start_long: startLong,
    end_long: endLong,
    total_ips: totalIps,
  };
}

export function parseIpv6Cidr(cidr: string): ASNPrefix | null {
  if (!cidr || typeof cidr !== 'string') return null;
  const [ip, maskStr] = cidr.trim().split('/');
  const mask = parseInt(maskStr, 10);
  if (isNaN(mask) || mask < 0 || mask > 128) return null;

  return {
    prefix: cidr.trim(),
    ip_version: 'ipv6',
    mask,
    netmask: `/${mask}`,
    wildcard: '',
    first_ip: ip,
    last_ip: '',
    start_long: null,
    end_long: null,
    total_ips: mask <= 64 ? Math.pow(2, 64 - mask) : 1,
  };
}

export function aggregateIpv4Cidrs(cidrList: (string | ASNPrefix)[]): AggregatedCidrResult {
  const parsed: ASNPrefix[] = [];
  for (const c of cidrList) {
    const p = typeof c === 'string' ? parseIpv4Cidr(c) : (c.start_long != null ? c : parseIpv4Cidr(c.prefix));
    if (p && p.ip_version === 'ipv4') {
      parsed.push(p);
    }
  }

  if (parsed.length === 0) {
    return {
      original_count: 0,
      aggregated_count: 0,
      saved_rules: 0,
      reduction_percent: 0,
      prefixes: [],
    };
  }

  parsed.sort((a, b) => (a.start_long ?? 0) - (b.start_long ?? 0) || (a.mask ?? 0) - (b.mask ?? 0));

  const nonOverlapping: ASNPrefix[] = [];
  for (const block of parsed) {
    if (nonOverlapping.length === 0) {
      nonOverlapping.push(block);
      continue;
    }
    const prev = nonOverlapping[nonOverlapping.length - 1];
    if (
      block.start_long != null &&
      prev.start_long != null &&
      block.end_long != null &&
      prev.end_long != null &&
      block.start_long >= prev.start_long &&
      block.end_long <= prev.end_long
    ) {
      continue;
    }
    nonOverlapping.push(block);
  }

  let merged = true;
  let currentList = nonOverlapping;

  while (merged) {
    merged = false;
    const nextList: ASNPrefix[] = [];
    let i = 0;

    while (i < currentList.length) {
      const a = currentList[i];
      if (i + 1 < currentList.length) {
        const b = currentList[i + 1];
        if (
          a.mask != null &&
          b.mask != null &&
          a.mask === b.mask &&
          a.mask > 0 &&
          a.start_long != null &&
          b.start_long != null &&
          a.end_long != null
        ) {
          const parentMask = a.mask - 1;
          const parentNetmaskLong = parentMask === 0 ? 0 : (~0 << (32 - parentMask)) >>> 0;
          const aParentStart = (a.start_long & parentNetmaskLong) >>> 0;
          const bParentStart = (b.start_long & parentNetmaskLong) >>> 0;

          if (aParentStart === bParentStart && a.end_long + 1 === b.start_long) {
            const parentCidr = parseIpv4Cidr(`${longToIpv4(aParentStart)}/${parentMask}`);
            if (parentCidr) {
              nextList.push(parentCidr);
              i += 2;
              merged = true;
              continue;
            }
          }
        }
      }
      nextList.push(a);
      i += 1;
    }
    currentList = nextList;
  }

  const origCount = parsed.length;
  const aggCount = currentList.length;
  const saved = Math.max(0, origCount - aggCount);
  const reduction = origCount > 0 ? Math.round((saved / origCount) * 100) : 0;

  return {
    original_count: origCount,
    aggregated_count: aggCount,
    saved_rules: saved,
    reduction_percent: reduction,
    prefixes: currentList,
  };
}

export function matchIpInPrefixes(candidateIp: string, prefixes: ASNPrefix[]): IpMatchResult {
  if (!candidateIp || typeof candidateIp !== 'string') {
    return { matched: false, valid: false, error: 'Empty IP address.', ip: '', ip_version: 'ipv4' };
  }
  const cleanIp = candidateIp.trim();

  const isV4 = !cleanIp.includes(':');
  if (isV4) {
    const targetLong = ipv4ToLong(cleanIp);
    if (targetLong === null) return { matched: false, valid: false, error: 'Invalid IPv4 address format.', ip: cleanIp, ip_version: 'ipv4' };

    for (const p of prefixes) {
      const parsed = p.start_long != null ? p : parseIpv4Cidr(p.prefix);
      if (parsed && parsed.start_long != null && parsed.end_long != null && targetLong >= parsed.start_long && targetLong <= parsed.end_long) {
        return {
          matched: true,
          valid: true,
          ip: cleanIp,
          ip_version: 'ipv4',
          prefix: parsed.prefix,
          first_ip: parsed.first_ip,
          last_ip: parsed.last_ip,
          netmask: parsed.netmask,
          total_ips: parsed.total_ips,
        };
      }
    }
    return { matched: false, valid: true, ip: cleanIp, ip_version: 'ipv4' };
  } else {
    for (const p of prefixes) {
      const prefixStr = p.prefix.trim();
      const baseV6 = prefixStr.split('/')[0].toLowerCase();
      if (cleanIp.toLowerCase().startsWith(baseV6)) {
        return {
          matched: true,
          valid: true,
          ip: cleanIp,
          ip_version: 'ipv6',
          prefix: prefixStr,
        };
      }
    }
    return { matched: false, valid: true, ip: cleanIp, ip_version: 'ipv6' };
  }
}

export function generateFirewallRules({
  format = 'nginx',
  action = 'deny',
  asn = '',
  orgName = '',
  prefixes = [],
}: {
  format?: FirewallFormat;
  action?: FirewallAction;
  asn?: string;
  orgName?: string;
  prefixes?: ASNPrefix[];
}): string {
  const isBlock = action === 'deny';
  const lines: string[] = [];
  const headerComment = `# AS${asn} (${orgName || 'ASN'}) - Generated ${new Date().toISOString().slice(0, 10)} - Total: ${prefixes.length} prefixes`;

  switch (format) {
    case 'nginx':
      lines.push(headerComment);
      for (const p of prefixes) {
        lines.push(`${isBlock ? 'deny' : 'allow'} ${p.prefix};`);
      }
      break;

    case 'apache':
      lines.push(headerComment);
      lines.push('<RequireAll>');
      for (const p of prefixes) {
        lines.push(`  ${isBlock ? 'Require not ip' : 'Require ip'} ${p.prefix}`);
      }
      lines.push('</RequireAll>');
      break;

    case 'iptables':
      lines.push(headerComment);
      for (const p of prefixes) {
        if (!p.prefix.includes(':')) {
          lines.push(`iptables -A INPUT -s ${p.prefix} -j ${isBlock ? 'DROP' : 'ACCEPT'}`);
        } else {
          lines.push(`ip6tables -A INPUT -s ${p.prefix} -j ${isBlock ? 'DROP' : 'ACCEPT'}`);
        }
      }
      break;

    case 'nftables':
      lines.push(headerComment);
      lines.push('table inet filter {');
      lines.push(`  set as${asn}_rules {`);
      lines.push('    type ipv4_addr; flags interval;');
      lines.push('    elements = {');
      for (const p of prefixes) {
        if (!p.prefix.includes(':')) {
          lines.push(`      ${p.prefix},`);
        }
      }
      lines.push('    }');
      lines.push('  }');
      lines.push('  chain input {');
      lines.push(`    ip saddr @as${asn}_rules ${isBlock ? 'drop' : 'accept'}`);
      lines.push('  }');
      lines.push('}');
      break;

    case 'ufw':
      lines.push(headerComment);
      for (const p of prefixes) {
        lines.push(`ufw ${isBlock ? 'deny from' : 'allow from'} ${p.prefix}`);
      }
      break;

    case 'cisco_acl':
      lines.push(headerComment);
      for (const p of prefixes) {
        if (!p.prefix.includes(':')) {
          const parsed = p.wildcard ? p : parseIpv4Cidr(p.prefix);
          if (parsed) {
            lines.push(`access-list 100 ${isBlock ? 'deny' : 'permit'} ip ${parsed.first_ip} ${parsed.wildcard} any`);
          }
        }
      }
      break;

    case 'mikrotik':
      lines.push(headerComment);
      const listName = isBlock ? `BLOCKED_AS${asn}` : `ALLOWED_AS${asn}`;
      for (const p of prefixes) {
        lines.push(`/ip firewall address-list add list=${listName} address=${p.prefix} comment="AS${asn} ${orgName}"`);
      }
      break;

    case 'ipset':
      lines.push(headerComment);
      const ipsetName = `as${asn}_${isBlock ? 'block' : 'allow'}`;
      lines.push(`ipset create ${ipsetName} hash:net family inet`);
      for (const p of prefixes) {
        if (!p.prefix.includes(':')) {
          lines.push(`ipset add ${ipsetName} ${p.prefix}`);
        }
      }
      lines.push(`# Apply: iptables -I INPUT -m set --match-set ${ipsetName} src -j ${isBlock ? 'DROP' : 'ACCEPT'}`);
      break;

    case 'aws_sg':
      const awsRules = prefixes.map(p => ({
        CidrIp: p.prefix.includes(':') ? undefined : p.prefix,
        CidrIpv6: p.prefix.includes(':') ? p.prefix : undefined,
        Description: `AS${asn} ${orgName || ''}`.trim(),
      }));
      return JSON.stringify(awsRules, null, 2);

    case 'pfsense':
      lines.push(headerComment);
      for (const p of prefixes) {
        lines.push(p.prefix);
      }
      break;

    case 'csv':
      lines.push('Prefix,IP_Version,Start_IP,End_IP,Netmask,Wildcard_Mask,Total_IPs');
      for (const p of prefixes) {
        const isV6 = p.prefix.includes(':');
        const parsed = isV6 ? parseIpv6Cidr(p.prefix) : (p.first_ip ? p : parseIpv4Cidr(p.prefix));
        if (parsed) {
          lines.push(`${parsed.prefix},${parsed.ip_version},${parsed.first_ip || ''},${parsed.last_ip || ''},${parsed.netmask || ''},${parsed.wildcard || ''},${parsed.total_ips || ''}`);
        }
      }
      break;

    case 'json':
      return JSON.stringify(prefixes, null, 2);

    case 'plain_text':
    default:
      for (const p of prefixes) {
        lines.push(p.prefix);
      }
      break;
  }

  return lines.join('\n');
}

export function formatAsnDate(dateStr?: string | null): string {
  if (!dateStr) return 'Unknown';
  try {
    const d = new Date(dateStr);
    return isNaN(d.getTime()) ? dateStr : d.toUTCString();
  } catch {
    return dateStr;
  }
}

export function formatNumber(num?: number | null): string {
  if (num == null || isNaN(num)) return '0';
  return num.toLocaleString();
}

export function buildAsnPlainText(snapshot: ASNResult): string {
  const lines: string[] = [
    `============================================================`,
    `ASN Report: AS${snapshot.asn} - ${snapshot.name || snapshot.holder || 'Unknown'}`,
    `============================================================`,
    `Organization: ${snapshot.holder || snapshot.name || 'Unknown'}`,
    `Description:  ${snapshot.description || 'None'}`,
    `Country:      ${snapshot.country_code || 'Unknown'}`,
    `RIR Registry: ${snapshot.rir || 'Unknown'}`,
    `Status:       ${snapshot.announced ? 'Announced (Active BGP)' : 'Not Announced'}`,
    `Total IPv4:   ${snapshot.stats?.total_ipv4_prefixes || snapshot.ipv4_prefixes.length} prefixes (${snapshot.stats?.total_ipv4_ips_formatted || formatNumber(snapshot.stats?.total_ipv4_ips)} IPs)`,
    `Total IPv6:   ${snapshot.stats?.total_ipv6_prefixes || snapshot.ipv6_prefixes.length} prefixes`,
    `Upstreams:    ${snapshot.neighbours?.upstreams_count ?? 0}`,
    `Peers:        ${snapshot.neighbours?.peers_count ?? 0}`,
    `Checked At:   ${snapshot.checked_at_utc || new Date().toISOString()}`,
    `------------------------------------------------------------`,
    `IPv4 Announced Prefixes (${snapshot.ipv4_prefixes.length}):`,
  ];

  snapshot.ipv4_prefixes.forEach((p, idx) => {
    lines.push(`  [${idx + 1}] ${p.prefix.padEnd(20)} Range: ${(p.first_ip || '').padEnd(16)} - ${(p.last_ip || '').padEnd(16)} (${p.total_ips ? formatNumber(p.total_ips) + ' IPs' : ''})`);
  });

  if (snapshot.ipv6_prefixes.length > 0) {
    lines.push(`------------------------------------------------------------`);
    lines.push(`IPv6 Announced Prefixes (${snapshot.ipv6_prefixes.length}):`);
    snapshot.ipv6_prefixes.forEach((p, idx) => {
      lines.push(`  [${idx + 1}] ${p.prefix}`);
    });
  }

  lines.push(`============================================================`);
  return lines.join('\n');
}

export function buildAsnSnapshotHtml(snapshot: ASNResult): string {
  const escape = (str: string) => (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const v4Rows = snapshot.ipv4_prefixes.map((p, i) => `
    <tr>
      <td style="padding:6px 12px;border-bottom:1px solid #1e2235;color:#94a3b8;">${i + 1}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #1e2235;font-family:monospace;font-weight:600;color:#38bdf8;">${escape(p.prefix)}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #1e2235;font-family:monospace;">${escape(p.first_ip || '')} - ${escape(p.last_ip || '')}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #1e2235;text-align:right;">${formatNumber(p.total_ips)}</td>
      <td style="padding:6px 12px;border-bottom:1px solid #1e2235;font-family:monospace;color:#94a3b8;">${escape(p.netmask || '')}</td>
    </tr>
  `).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AS${escape(snapshot.asn)} - ${escape(snapshot.name || '')} ASN Intelligence Report</title>
  <style>
    body { background: #0b0f19; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 24px; }
    .container { max-width: 1000px; margin: 0 auto; }
    h1 { color: #38bdf8; margin-bottom: 4px; }
    .meta { color: #94a3b8; font-size: 0.9rem; margin-bottom: 24px; }
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 24px; }
    .card { background: #131b2e; border: 1px solid #1e2235; border-radius: 8px; padding: 16px; text-align: center; }
    .card-val { font-size: 1.5rem; font-weight: bold; color: #f8fafc; }
    .card-lbl { font-size: 0.75rem; text-transform: uppercase; color: #94a3b8; margin-top: 4px; letter-spacing: 0.05em; }
    table { width: 100%; border-collapse: collapse; background: #131b2e; border: 1px solid #1e2235; border-radius: 8px; overflow: hidden; margin-bottom: 24px; }
    th { background: #0f172a; padding: 10px 12px; text-align: left; font-size: 0.8rem; text-transform: uppercase; color: #94a3b8; border-bottom: 1px solid #1e2235; }
  </style>
</head>
<body>
  <div class="container">
    <h1>AS${escape(snapshot.asn)} — ${escape(snapshot.holder || snapshot.name || 'ASN')}</h1>
    <div class="meta">${escape(snapshot.description || '')} • Country: ${escape(snapshot.country_code || 'Unknown')} • Checked ${escape(formatAsnDate(snapshot.checked_at_utc))}</div>
    <div class="cards">
      <div class="card"><div class="card-val">AS${escape(snapshot.asn)}</div><div class="card-lbl">ASN Number</div></div>
      <div class="card"><div class="card-val">${formatNumber(snapshot.ipv4_prefixes.length)}</div><div class="card-lbl">IPv4 Prefixes</div></div>
      <div class="card"><div class="card-val">${snapshot.stats?.total_ipv4_ips_formatted || formatNumber(snapshot.stats?.total_ipv4_ips)}</div><div class="card-lbl">Total IPv4 IPs</div></div>
      <div class="card"><div class="card-val">${formatNumber(snapshot.ipv6_prefixes.length)}</div><div class="card-lbl">IPv6 Prefixes</div></div>
      <div class="card"><div class="card-val">${snapshot.announced ? 'Active' : 'Inactive'}</div><div class="card-lbl">BGP Status</div></div>
    </div>
    <h2>IPv4 Announced Prefixes</h2>
    <table>
      <thead>
        <tr><th>#</th><th>Prefix CIDR</th><th>IP Range</th><th style="text-align:right;">Usable IPs</th><th>Netmask</th></tr>
      </thead>
      <tbody>${v4Rows}</tbody>
    </table>
  </div>
</body>
</html>`;
}

export function normalizeAsnSnapshot(data: unknown): ASNResult {
  const input = (data ?? {}) as Partial<ASNResult>;
  const rawV4 = Array.isArray(input.ipv4_prefixes) ? input.ipv4_prefixes : [];
  const rawV6 = Array.isArray(input.ipv6_prefixes) ? input.ipv6_prefixes : [];

  const ipv4_prefixes = rawV4.map(p => typeof p === 'string' ? (parseIpv4Cidr(p) || { prefix: p }) : p);
  const ipv6_prefixes = rawV6.map(p => typeof p === 'string' ? (parseIpv6Cidr(p) || { prefix: p }) : p);

  const aggregated = input.aggregated_ipv4 || aggregateIpv4Cidrs(ipv4_prefixes);

  return {
    asn: String(input.asn || '').replace('AS', ''),
    asn_formatted: input.asn_formatted || `AS${input.asn || ''}`,
    name: input.name || input.holder || `AS${input.asn || ''}`,
    holder: input.holder || '',
    description: input.description || '',
    country_code: input.country_code || '',
    rir: input.rir || '',
    announced: Boolean(input.announced),
    abuse_emails: Array.isArray(input.abuse_emails) ? input.abuse_emails : [],
    resolved_from: input.resolved_from || null,
    neighbours: input.neighbours || { upstreams_count: 0, downstreams_count: 0, peers_count: 0, top_peers: [] },
    ipv4_prefixes,
    ipv6_prefixes,
    aggregated_ipv4: aggregated,
    stats: input.stats || {
      total_ipv4_prefixes: ipv4_prefixes.length,
      total_ipv6_prefixes: ipv6_prefixes.length,
      total_ipv4_ips: 0,
      total_ipv4_ips_formatted: '0',
      v4_distribution: {},
      v6_distribution: {},
    },
    checked_at_utc: input.checked_at_utc || new Date().toISOString(),
    error: input.error || null,
  };
}
