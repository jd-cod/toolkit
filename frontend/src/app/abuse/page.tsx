'use client';

import React, { useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace, { ToolEmptyState } from '@/components/ToolWorkspace';
import type { AbuseEntry, IPInfoEntry } from '@/lib/tool-results';
import { api } from '@/lib/api';
import { ensureGeoIPReady } from '@/lib/geoip';
import { exportToCSV } from '@/lib/csv-utils';
import { useClipboard } from '@/hooks/useClipboard';

interface IPInfoResultItem {
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

function getCountryFlag(code?: string): string {
  if (!code || code === '--' || code.length !== 2) return '🌐';
  if (code === '🏠') return '🏠';
  const uppercase = code.toUpperCase();
  return String.fromCodePoint(...uppercase.split('').map(c => 127397 + c.charCodeAt(0)));
}

function getCountryName(code?: string, rawName?: string): string {
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

export default function AbusePage() {
  const { copy, isCopied } = useClipboard();
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<IPInfoResultItem[]>([]);
  const [expandedIp, setExpandedIp] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState<'all' | 'rdns' | 'risk' | 'abusive'>('all');
  const [abuseApiAvailable, setAbuseApiAvailable] = useState<boolean | null>(null);

  async function doCheck() {
    const raw = input.trim();
    if (!raw) return;

    // Parse input: one IP per line, or "IP hits" / comma separated format
    const lines = raw.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const ips = lines.map(line => {
      const parts = line.split(/[\s,|]+/);
      return { ip: parts[0], hits: parseInt(parts[1], 10) || 1 };
    }).filter(e => e.ip && /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(e.ip));

    if (ips.length === 0) {
      setError('No valid IP addresses found. Enter one IP per line (e.g. 1.1.1.1 or 8.8.8.8 100).');
      return;
    }

    setLoading(true);
    setError('');
    setResults([]);
    setExpandedIp(null);
    setAbuseApiAvailable(null);

    const ipList = ips.map(i => i.ip);

    try {
      const [ipinfoRes, abuseRes] = await Promise.allSettled([
        api.checkIPs(ipList),
        api.checkAbuse(ips)
      ]);

      const ipinfoData = ipinfoRes.status === 'fulfilled' ? ipinfoRes.value : null;
      const abuseData = abuseRes.status === 'fulfilled' ? abuseRes.value : null;
      if (!ipinfoData && !abuseData) throw new Error('IP lookup services are unavailable. Please try again.');

      if (abuseData && typeof abuseData.api_available === 'boolean') {
        setAbuseApiAvailable(abuseData.api_available);
      } else {
        setAbuseApiAvailable(false);
      }

      const ipinfoMap = new Map((ipinfoData?.results || []).map(r => [r.ip, r]));
      const abuseResults = [
        ...(abuseData?.abusive || []),
        ...(abuseData?.non_abusive || []),
        ...(abuseData?.results || [])
      ];
      const abuseMap = new Map(abuseResults.map(r => [r.ip || r.ipAddress, r]));

      // Optional GeoIP local client lookup
      let geoIp: Awaited<ReturnType<typeof ensureGeoIPReady>> = null;
      try { geoIp = await ensureGeoIPReady(); } catch { /* ignore */ }

      const combined: IPInfoResultItem[] = ips.map(({ ip, hits }) => {
        const info: Partial<IPInfoEntry> = ipinfoMap.get(ip) || {};
        const abuse: AbuseEntry = abuseMap.get(ip) || {};
        const geoInfo = geoIp ? geoIp.lookupIP(ip) : null;

        const isPrivate = info.is_private ?? (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.'));
        const ipVersion = info.ip_version || (ip.includes(':') ? 'IPv6' : 'IPv4');
        const reverseDns = info.reverse_dns || abuse.domain || '';

        const countryCode = abuse.country_code || abuse.countryCode || info.country_code || geoInfo?.country_code || '--';
        const countryName = getCountryName(countryCode, abuse.country || abuse.countryName || info.country || geoInfo?.country);

        const asn = geoInfo?.asn || info.asn || '';
        const asnOrg = geoInfo?.asn_org || info.asn_org || '';

        const isp = abuse.isp || info.isp || asnOrg || (isPrivate ? 'Internal / Private Network' : 'N/A');
        const usageType = abuse.usage_type || abuse.usageType || (isPrivate ? 'Private Network' : 'N/A');
        const abuseScore = typeof abuse.abuse_score === 'number' ? abuse.abuse_score : (typeof abuse.abuseConfidenceScore === 'number' ? abuse.abuseConfidenceScore : null);
        const totalReports = abuse.total_reports ?? abuse.totalReports ?? 0;
        const numDistinctUsers = abuse.num_distinct_users || 0;
        const lastReportedAt = abuse.last_reported_at || '';

        let riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'unknown' = info.risk_level || (isPrivate ? 'safe' : 'low');
        const riskReasons: string[] = [...(info.risk_reasons || [])];

        if (abuseScore !== null && abuseScore > 0) {
          if (abuseScore >= 75) riskLevel = 'high';
          else if (abuseScore >= 25 && riskLevel !== 'high') riskLevel = 'medium';
          riskReasons.push(`AbuseIPDB Score: ${abuseScore}% (${totalReports} reports)`);
        }

        return {
          ip,
          hits,
          ip_version: ipVersion,
          is_private: isPrivate,
          reverse_dns: reverseDns,
          country_code: countryCode,
          country: countryName || (isPrivate ? 'Private Network' : 'Unknown'),
          asn,
          asn_org: asnOrg,
          isp,
          usage_type: usageType,
          risk_level: riskLevel,
          risk_reasons: riskReasons,
          abuse_score: abuseScore,
          total_reports: totalReports,
          num_distinct_users: numDistinctUsers,
          last_reported_at: lastReportedAt,
          is_tor: abuse.is_tor || false,
          is_whitelisted: abuse.is_whitelisted || false,
        };
      });

      if (combined.length === 0) {
        setError('No details returned for the requested IP address(es).');
      } else {
        setResults(combined);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to perform IP Info lookup.');
    }

    setLoading(false);
  }

  const riskBadgeStyle = (level: string) => {
    switch (level) {
      case 'high':
        return { color: 'var(--accent-red)', bg: 'rgba(239, 68, 68, 0.15)', label: 'High' };
      case 'medium':
        return { color: 'var(--accent-amber)', bg: 'rgba(245, 158, 11, 0.15)', label: 'Medium' };
      case 'safe':
        return { color: 'var(--accent-green)', bg: 'rgba(16, 185, 129, 0.15)', label: 'Safe' };
      case 'low':
      default:
        return { color: 'var(--accent-cyan)', bg: 'rgba(34, 211, 238, 0.15)', label: 'Low' };
    }
  };

  const totalCount = results.length;
  const rdnsCount = results.filter(r => Boolean(r.reverse_dns)).length;
  const riskCount = results.filter(r => r.risk_level === 'high' || r.risk_level === 'medium').length;
  const abuseCount = results.filter(r => r.abuse_score !== null && r.abuse_score > 0).length;

  const filteredResults = results.filter(r => {
    if (filter === 'rdns') return Boolean(r.reverse_dns);
    if (filter === 'risk') return r.risk_level === 'high' || r.risk_level === 'medium';
    if (filter === 'abusive') return r.abuse_score !== null && r.abuse_score > 0;
    return true;
  });

  return (
    <>
      <Navbar />
      <main className="main-content">
        <div className="signal-tool-heading tool-hero-compact">
          <div className="tool-hero-icon" style={{ background: 'linear-gradient(135deg, #06b6d4, #6366f1)' }}><i className="bi bi-info-circle-fill"></i></div>
          <h1 className="hero-title">IP Info & Security Risk Lookup</h1>
          <p style={{ color: 'var(--text-secondary)' }}>Look up IP addresses for reverse DNS (PTR), network type, country, ISP, security risk factors, and AbuseIPDB scores.</p>
        </div>

        <ToolWorkspace tool="abuse" wide={results.length > 0}>
        <div className="glass" style={{ padding: '2rem', marginBottom: '2rem' }}>
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="Enter IPs (one per line)&#10;1.1.1.1&#10;8.8.8.8&#10;183.157.231.164&#10;192.168.1.1"
            rows={6}
            style={{ width: '100%', padding: '0.75rem 1rem', background: 'var(--bg-input)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', fontSize: '0.85rem', fontFamily: 'var(--font-mono)', resize: 'vertical', marginBottom: '1rem' }}
          />
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Supports batch lookup up to 50 IPv4 or IPv6 addresses.
            </div>
            <button onClick={doCheck} disabled={loading} className="btn-primary" style={{ minWidth: 200 }}>
              {loading ? '⏳ Resolving IP Info...' : '🔍 Lookup IP Info'}
            </button>
          </div>
        </div>

        {!loading && !results.length && !error && <ToolEmptyState title="Start an IP investigation">Look up an address or a batch of addresses to compare network identity and risk evidence.</ToolEmptyState>}
        {error && (
          <div className="glass" style={{ padding: '1rem 1.5rem', borderColor: 'rgba(239,68,68,0.3)', color: 'var(--accent-red)', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <i className="bi bi-exclamation-triangle-fill"></i>
            <span>{error}</span>
          </div>
        )}

        {abuseApiAvailable === false && !error && (
          <div className="glass" style={{ padding: '1rem 1.5rem', borderColor: 'rgba(99,102,241,0.2)', color: 'var(--text-secondary)', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '0.85rem' }}>
            <i className="bi bi-info-circle" style={{ color: 'var(--accent-cyan)' }}></i>
            <span>Reverse DNS, network type, & risk classification active. AbuseIPDB reputation API key is optional.</span>
          </div>
        )}

        {results.length > 0 && (
          <>
            <div className="glass" style={{ padding: '1rem', marginBottom: '1.5rem', display: 'flex', gap: '0.75rem', justifyContent: 'center' }}>
              <button
                onClick={() => exportToCSV(results, `abuse-ip-report-${new Date().toISOString().split('T')[0]}`)}
                className="btn-secondary"
                style={{ padding: '8px 16px', borderRadius: 10, cursor: 'pointer', fontSize: '0.88rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 6 }}
              >
                <i className="bi bi-download"></i> Export CSV
              </button>
              <button
                onClick={() => void copy(results.map(r => `${r.ip} - ${r.reverse_dns || 'No PTR'} - ${r.country || 'Unknown'} - AS${r.asn || 'N/A'} - Risk: ${r.risk_level}`).join('\n'), 'all_ips')}
                className="btn-secondary"
                style={{ padding: '8px 16px', borderRadius: 10, cursor: 'pointer', fontSize: '0.88rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 6 }}
              >
                <i className={isCopied('all_ips') ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i> {isCopied('all_ips') ? 'Copied Summary!' : 'Copy IP Summary'}
              </button>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
              <div className="glass" style={{ padding: '1.25rem', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--text-primary)' }}>{totalCount}</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Total IPs Analyzed</div>
              </div>
              <div className="glass" style={{ padding: '1.25rem', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--accent-cyan)' }}>{rdnsCount}</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Reverse DNS Found</div>
              </div>
              <div className="glass" style={{ padding: '1.25rem', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                <div style={{ fontSize: '1.75rem', fontWeight: 800, color: riskCount > 0 ? 'var(--accent-amber)' : 'var(--accent-green)' }}>{riskCount}</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Risk Flags / Elevated</div>
              </div>
              <div className="glass" style={{ padding: '1.25rem', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
                <div style={{ fontSize: '1.75rem', fontWeight: 800, color: abuseCount > 0 ? 'var(--accent-red)' : 'var(--text-secondary)' }}>{abuseCount}</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Abuse Reports</div>
              </div>
            </div>

            <div className="glass signal-abuse-results" style={{ overflow: 'hidden' }}>
              <div style={{ padding: '0.85rem 1.25rem', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <i className="bi bi-list-columns-reverse"></i>
                  <span>Results ({filteredResults.length} of {results.length} IPs)</span>
                </div>
                <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                  <button onClick={() => setFilter('all')} className="btn-secondary" style={{ padding: '0.25rem 0.65rem', fontSize: '0.78rem', background: filter === 'all' ? 'var(--accent-primary)' : undefined, color: filter === 'all' ? '#fff' : undefined }}>All ({totalCount})</button>
                  <button onClick={() => setFilter('rdns')} className="btn-secondary" style={{ padding: '0.25rem 0.65rem', fontSize: '0.78rem', background: filter === 'rdns' ? 'var(--accent-cyan)' : undefined, color: filter === 'rdns' ? '#fff' : undefined }}>rDNS ({rdnsCount})</button>
                  <button onClick={() => setFilter('risk')} className="btn-secondary" style={{ padding: '0.25rem 0.65rem', fontSize: '0.78rem', background: filter === 'risk' ? 'var(--accent-amber)' : undefined, color: filter === 'risk' ? '#fff' : undefined }}>Risk Flags ({riskCount})</button>
                  {abuseCount > 0 && (
                    <button onClick={() => setFilter('abusive')} className="btn-secondary" style={{ padding: '0.25rem 0.65rem', fontSize: '0.78rem', background: filter === 'abusive' ? 'var(--accent-red)' : undefined, color: filter === 'abusive' ? '#fff' : undefined }}>Abusive ({abuseCount})</button>
                  )}
                </div>
              </div>

              <div className="signal-abuse-desktop-table" style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
                  <colgroup>{['3%', '13%', '16%', '14%', '20%', '7%', '10%', '17%'].map((width, index) => <col key={index} style={{ width }} />)}</colgroup>
                  <thead>
                    <tr style={{ background: 'rgba(0,0,0,0.1)' }}>
                      {['#', 'IP Address', 'Reverse DNS (PTR)', 'Country & Location', 'ASN & Network / ISP', 'Risk', 'Abuse Score', 'Actions'].map(h => (
                        <th key={h} style={{ padding: '0.75rem 0.5rem', textAlign: 'left', fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.03em' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredResults.map((r: IPInfoResultItem, i: number) => {
                      const badge = riskBadgeStyle(r.risk_level);
                      const isExpanded = expandedIp === r.ip;
                      const flag = getCountryFlag(r.country_code);
                      const countryFullName = getCountryName(r.country_code, r.country);

                      return (
                        <React.Fragment key={i}>
                        <tr style={{ borderBottom: isExpanded ? 'none' : '1px solid var(--border-color)' }}>
                          <td style={{ padding: '0.65rem 1rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>{i + 1}</td>
                          <td style={{ padding: '0.65rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 600 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                              <span>{r.ip}</span>
                              <span style={{ fontSize: '0.68rem', padding: '1px 5px', borderRadius: 4, background: 'rgba(255,255,255,0.06)', color: 'var(--text-muted)' }}>{r.ip_version}</span>
                            </div>
                          </td>
                          <td style={{ padding: '0.65rem 1rem', fontSize: '0.82rem', fontFamily: 'var(--font-mono)' }}>
                            {r.reverse_dns ? <span style={{ color: 'var(--accent-cyan)' }}>{r.reverse_dns}</span> : <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>No PTR record</span>}
                          </td>
                          <td style={{ padding: '0.65rem 1rem', fontSize: '0.85rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                              <span style={{ fontSize: '1.1rem' }}>{flag}</span>
                              <span style={{ fontWeight: 600 }}>{countryFullName || 'Unknown'}</span>
                              {r.country_code && r.country_code !== '--' && <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>({r.country_code})</span>}
                            </div>
                          </td>
                          <td style={{ padding: '0.65rem 1rem', fontSize: '0.82rem', color: 'var(--text-primary)' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                              {r.asn && (
                                <span style={{ fontSize: '0.72rem', padding: '2px 6px', borderRadius: 4, background: 'rgba(6, 182, 212, 0.15)', color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)', fontWeight: 600, display: 'inline-block' }}>
                                  AS{r.asn}
                                </span>
                              )}
                              <span style={{ fontWeight: 500 }}>{r.isp}</span>
                            </div>
                            {r.usage_type && r.usage_type !== 'N/A' && r.usage_type !== r.isp && (
                              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                                {r.usage_type}
                              </div>
                            )}
                          </td>
                          <td style={{ padding: '0.65rem 1rem' }}>
                            <span style={{ fontWeight: 700, color: badge.color, background: badge.bg, padding: '0.2rem 0.55rem', borderRadius: 'var(--radius-sm)', fontSize: '0.8rem', display: 'inline-block' }}>{badge.label}</span>
                          </td>
                          <td style={{ padding: '0.65rem 1rem', fontSize: '0.85rem' }}>
                            {r.abuse_score !== null ? <span style={{ fontWeight: 700, color: r.abuse_score > 0 ? 'var(--accent-red)' : 'var(--accent-green)' }}>{r.abuse_score}%</span> : <span style={{ color: 'var(--text-muted)' }}>N/A</span>}
                          </td>
                          <td style={{ padding: '0.65rem 1rem', fontSize: '0.8rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                              <button className="btn-secondary" style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }} onClick={() => setExpandedIp(isExpanded ? null : r.ip)}>
                                <span>{isExpanded ? 'Hide' : 'Info'}</span>
                                <i className={`bi bi-chevron-${isExpanded ? 'up' : 'down'}`}></i>
                              </button>
                              <a href={`https://www.abuseipdb.com/check/${r.ip}`} target="_blank" rel="noopener noreferrer" className="btn-secondary" style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}><i className="bi bi-box-arrow-up-right"></i></a>
                            </div>
                          </td>
                        </tr>
                        {isExpanded && (
                          <tr style={{ background: 'rgba(0,0,0,0.05)' }}>
                            <td colSpan={8} style={{ padding: '1rem', fontSize: '0.85rem' }}>
                              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                                <div><strong>ASN:</strong> {r.asn || 'N/A'} ({r.asn_org || 'N/A'})</div>
                                <div><strong>Usage:</strong> {r.usage_type}</div>
                                <div><strong>Reports:</strong> {r.total_reports}</div>
                                <div><strong>Last Reported:</strong> {r.last_reported_at || 'Never'}</div>
                                <div><strong>Security:</strong> {r.is_tor ? 'TOR Exit Node' : 'Not TOR'} / {r.is_whitelisted ? 'Whitelisted' : 'Not Whitelisted'}</div>
                              </div>
                            </td>
                          </tr>
                        )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <div className="signal-abuse-mobile-list" aria-label="IP lookup results for mobile screens">
                {filteredResults.map((r: IPInfoResultItem, i: number) => {
                  const badge = riskBadgeStyle(r.risk_level);
                  const isExpanded = expandedIp === r.ip;
                  const flag = getCountryFlag(r.country_code);
                  const countryFullName = getCountryName(r.country_code, r.country);

                  return (
                    <article className="signal-abuse-mobile-card" key={`mobile-${r.ip}-${i}`}>
                      <div className="signal-abuse-mobile-card-heading">
                        <div>
                          <span className="signal-abuse-mobile-index">#{i + 1}</span>
                          <strong>{r.ip}</strong>
                          <small>{r.ip_version}</small>
                        </div>
                        <span style={{ color: badge.color, background: badge.bg }}>{badge.label}</span>
                      </div>
                      <dl className="signal-abuse-mobile-facts">
                        <div><dt>Reverse DNS</dt><dd>{r.reverse_dns || 'No PTR record'}</dd></div>
                        <div><dt>Country</dt><dd>{flag} {countryFullName || 'Unknown'}</dd></div>
                        <div><dt>Network</dt><dd>{r.asn ? `AS${r.asn} · ` : ''}{r.isp}</dd></div>
                        <div><dt>Abuse score</dt><dd className={r.abuse_score !== null && r.abuse_score > 0 ? 'is-risk' : ''}>{r.abuse_score !== null ? `${r.abuse_score}%` : 'N/A'}</dd></div>
                      </dl>
                      <div className="signal-abuse-mobile-actions">
                        <button className="btn-secondary" type="button" aria-expanded={isExpanded} onClick={() => setExpandedIp(isExpanded ? null : r.ip)}>
                          <i className={`bi bi-chevron-${isExpanded ? 'up' : 'down'}`} aria-hidden="true"></i>
                          {isExpanded ? 'Hide details' : 'Show details'}
                        </button>
                        <a href={`https://www.abuseipdb.com/check/${r.ip}`} target="_blank" rel="noopener noreferrer" className="btn-secondary">
                          AbuseIPDB <i className="bi bi-box-arrow-up-right" aria-hidden="true"></i>
                        </a>
                      </div>
                      {isExpanded && (
                        <div className="signal-abuse-mobile-expanded">
                          <span><strong>ASN:</strong> {r.asn || 'N/A'} ({r.asn_org || 'N/A'})</span>
                          <span><strong>Usage:</strong> {r.usage_type}</span>
                          <span><strong>Reports:</strong> {r.total_reports}</span>
                          <span><strong>Last reported:</strong> {r.last_reported_at || 'Never'}</span>
                          <span><strong>Security:</strong> {r.is_tor ? 'TOR exit node' : 'Not TOR'} · {r.is_whitelisted ? 'Whitelisted' : 'Not whitelisted'}</span>
                        </div>
                      )}
                    </article>
                  );
                })}
              </div>
            </div>
          </>
        )}
        </ToolWorkspace>
      </main>
      <Footer />
    </>
  );
}
