'use client';

import { useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace, { ToolEmptyState } from '@/components/ToolWorkspace';
import type { AbuseEntry, IPInfoEntry } from '@/lib/tool-results';
import { api } from '@/lib/api';
import { ensureGeoIPReady } from '@/lib/geoip';
import IpInfoResultView from '@/components/IpInfoResultView';
import { getCountryName, type IPInfoResultItem, type IpInfoSnapshot } from '@/lib/ipinfo';

export default function AbusePage() {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [snapshot, setSnapshot] = useState<IpInfoSnapshot | null>(null);
  const [error, setError] = useState('');
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
    setSnapshot(null);
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
        setSnapshot({ results: combined, checked_at_utc: new Date().toISOString() });
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to perform IP Info lookup.');
    }

    setLoading(false);
  }

  return (
    <>
      <Navbar />
      <main className="main-content">
        <div className="signal-tool-heading tool-hero-compact">
          <div className="tool-hero-icon" style={{ background: 'linear-gradient(135deg, #06b6d4, #6366f1)' }}><i className="bi bi-info-circle-fill"></i></div>
          <h1 className="hero-title">IP Info & Security Risk Lookup</h1>
          <p style={{ color: 'var(--text-secondary)' }}>Look up IP addresses for reverse DNS (PTR), network type, country, ISP, security risk factors, and AbuseIPDB scores.</p>
        </div>

        <ToolWorkspace tool="abuse" wide={Boolean(snapshot)}>
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

        {!loading && !snapshot && !error && <ToolEmptyState title="Start an IP investigation">Look up an address or a batch of addresses to compare network identity and risk evidence.</ToolEmptyState>}
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

        {snapshot && <IpInfoResultView key={snapshot.checked_at_utc} snapshot={snapshot} mode="live" />}
        </ToolWorkspace>
      </main>
      <Footer />
    </>
  );
}
