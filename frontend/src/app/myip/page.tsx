'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace from '@/components/ToolWorkspace';
import { api, MyIPResult } from '@/lib/api';
import { exportToCSV } from '@/lib/csv-utils';
import { useClipboard } from '@/hooks/useClipboard';
import {
  countryFlag,
  networkBadge,
  formatCity,
  formatAccuracyRadius,
  formatProxyStatus,
  buildMyIPReportHtml,
  buildMyIPExportData,
  type ConnectionInfo,
  type ClientInfo,
} from '@/lib/myip';

// Parse User Agent
function parseUserAgent(ua: string) {
  let browser = 'Unknown', os = 'Unknown';

  // Browser
  if (/Edg\//i.test(ua)) { const m = ua.match(/Edg\/([\d.]+)/); browser = `Microsoft Edge ${m?.[1] || ''}`; }
  else if (/OPR\//i.test(ua)) { const m = ua.match(/OPR\/([\d.]+)/); browser = `Opera ${m?.[1] || ''}`; }
  else if (/Chrome\//i.test(ua) && !/Chromium/i.test(ua)) { const m = ua.match(/Chrome\/([\d.]+)/); browser = `Google Chrome ${m?.[1] || ''}`; }
  else if (/Safari\//i.test(ua) && !/Chrome/i.test(ua)) { const m = ua.match(/Version\/([\d.]+)/); browser = `Safari ${m?.[1] || ''}`; }
  else if (/Firefox\//i.test(ua)) { const m = ua.match(/Firefox\/([\d.]+)/); browser = `Firefox ${m?.[1] || ''}`; }

  // OS
  if (/Windows NT 10/i.test(ua)) os = 'Windows 10/11';
  else if (/Windows/i.test(ua)) os = 'Windows';
  else if (/Mac OS X ([\d_]+)/i.test(ua)) { const m = ua.match(/Mac OS X ([\d_]+)/); os = `macOS ${m?.[1]?.replace(/_/g, '.') || ''}`; }
  else if (/Android ([\d.]+)/i.test(ua)) { const m = ua.match(/Android ([\d.]+)/); os = `Android ${m?.[1] || ''}`; }
  else if (/iPhone OS ([\d_]+)/i.test(ua)) { const m = ua.match(/iPhone OS ([\d_]+)/); os = `iOS ${m?.[1]?.replace(/_/g, '.') || ''}`; }
  else if (/Linux/i.test(ua)) os = 'Linux';

  return { browser: browser.trim(), os: os.trim() };
}

function getConnectionInfo(): ConnectionInfo {
  const nav = navigator as any;  // eslint-disable-line @typescript-eslint/no-explicit-any
  const conn = nav.connection || nav.mozConnection || nav.webkitConnection;
  if (!conn) {
    return { type: 'Unknown', effectiveType: 'Unknown', downlink: null, rtt: null, saveData: false, supported: false };
  }
  return {
    type: conn.type || 'Unknown',
    effectiveType: conn.effectiveType || 'Unknown',
    downlink: conn.downlink ?? null,
    rtt: conn.rtt ?? null,
    saveData: !!conn.saveData,
    supported: true,
  };
}

// WebGL renderer
function getWebGLRenderer() {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'Not available';
    const ext = (gl as WebGLRenderingContext).getExtension('WEBGL_debug_renderer_info');
    if (!ext) return 'Restricted';
    return (gl as WebGLRenderingContext).getParameter(ext.UNMASKED_RENDERER_WEBGL) || 'Unknown';
  } catch {
    return 'Not available';
  }
}

export default function MyIPPage() {
  const { copy, isCopied } = useClipboard();
  const [data, setData] = useState<MyIPResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [connection, setConnection] = useState<ConnectionInfo | null>(null);
  const [clientInfo, setClientInfo] = useState<ClientInfo | null>(null);

  // Dual-stack detection
  const [ipv4, setIpv4] = useState<string | null>(null);
  const [ipv6, setIpv6] = useState<string | null>(null);
  const [ipv4Loading, setIpv4Loading] = useState(true);
  const [ipv6Loading, setIpv6Loading] = useState(true);

  // Share modal state
  const [shareModalOpen, setShareModalOpen] = useState(false);
  const [shareTitle, setShareTitle] = useState('');
  const [shareExpiry, setShareExpiry] = useState('never');
  const [sharePassword, setSharePassword] = useState('');
  const [shareLoading, setShareLoading] = useState(false);
  const [shareError, setShareError] = useState('');
  const [shareUrl, setShareUrl] = useState('');

  useEffect(() => {
    // Collect client-side info
    const conn = getConnectionInfo();
    setConnection(conn);

    const ua = navigator.userAgent;
    const parsed = parseUserAgent(ua);
    setClientInfo({
      browser: parsed.browser,
      os: parsed.os,
      screen: `${window.screen.width} × ${window.screen.height}`,
      language: navigator.language || 'Unknown',
      dnt: navigator.doNotTrack === '1' ? 'Enabled' : 'Disabled',
      cookies: navigator.cookieEnabled ? 'Enabled' : 'Disabled',
      webgl: getWebGLRenderer(),
      platform: navigator.platform || 'Unknown',
    });

    async function detectIP(url: string, timeoutMs = 2500) {
      try {
        const response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
        if (!response.ok) return null;
        const result = await response.json();
        return typeof result.ip === 'string' ? result.ip : null;
      } catch {
        return null;
      }
    }

    // 1. Fetch server-side IP details immediately (sub-second rendering without blocking)
    api.getMyIP()
      .then((result) => {
        setData(result);
        if (result.ip_version === 'IPv4') {
          setIpv4((prev) => prev || result.ip);
          setIpv4Loading(false);
        } else if (result.ip_version === 'IPv6') {
          setIpv6((prev) => prev || result.ip);
          setIpv6Loading(false);
        }
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : 'Failed to detect IP details.');
      })
      .finally(() => {
        setLoading(false);
      });

    // 2. Concurrently detect client public IPv6 via endpoint
    const ipv6Endpoint = process.env.NEXT_PUBLIC_IPV6_ENDPOINT || '/api/myip';
    void detectIP(ipv6Endpoint, 2500)
      .then((detected) => {
        if (detected && detected.includes(':')) {
          setIpv6(detected);
        }
      })
      .catch(() => {})
      .finally(() => {
        setIpv6Loading(false);
      });

    // 3. Concurrently detect client public IPv4 via endpoint
    const ipv4Endpoint = process.env.NEXT_PUBLIC_IPV4_ENDPOINT || '/api/myip';
    void detectIP(ipv4Endpoint, 2000)
      .then((detected) => {
        if (detected && !detected.includes(':')) {
          setIpv4(detected);
        }
      })
      .catch(() => {})
      .finally(() => {
        setIpv4Loading(false);
      });
  }, []);

  function copyIPv4() {
    if (!ipv4) return;
    void copy(ipv4, 'v4');
  }

  function copyIPv6() {
    if (!ipv6) return;
    void copy(ipv6, 'v6');
  }

  function openShareModal() {
    if (!data) return;
    const defaultTitle = ipv4 && ipv6
      ? `My IP Report — ${ipv4} / ${ipv6}`
      : `My IP Report — ${ipv4 || ipv6 || data.ip}`;
    setShareTitle(defaultTitle);
    setShareExpiry('never');
    setSharePassword('');
    setShareError('');
    setShareUrl('');
    setShareModalOpen(true);
  }

  async function submitShare() {
    if (!data) return;
    setShareLoading(true);
    setShareError('');
    try {
      const snapshot = { ...data, ipv4, ipv6, client: clientInfo, connection };
      const defaultTitle = ipv4 && ipv6
        ? `My IP Report — ${ipv4} / ${ipv6}`
        : `My IP Report — ${ipv4 || ipv6 || data.ip}`;
      const result = await api.createMyIPShare({
        title: shareTitle.trim() || defaultTitle,
        ip: ipv4 || ipv6 || data.ip,
        expiry: shareExpiry,
        password: sharePassword.trim(),
        checked_at_utc: data.checked_at_utc,
        snapshot,
      });
      setShareUrl(`${window.location.origin}/s/${result.code}`);
    } catch (err: unknown) {
      setShareError(err instanceof Error ? err.message : 'Failed to create share link.');
    } finally {
      setShareLoading(false);
    }
  }

  function downloadHTML() {
    if (!data || !clientInfo || !connection) return;
    const html = buildMyIPReportHtml(data, { connection, ...clientInfo }, { ipv4, ipv6 });
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const filenameIp = (ipv4 || data.ip || 'ip').replace(/[.:]/g, '-');
    a.download = `my-ip-report-${filenameIp}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function downloadCSV() {
    if (!data) return;
    const exportData = buildMyIPExportData(data, { ipv4, ipv6 });
    const filenameIp = (ipv4 || data.ip || 'ip').replace(/[.:]/g, '-');
    exportToCSV(exportData, `my-ip-report-${filenameIp}`);
  }

  const badge = data ? networkBadge(data.network_type) : null;

  return (
    <>
      <Navbar />
      <main className="main-content">
        {/* Hero */}
        <div className="signal-tool-heading">
          <div style={{ width: 56, height: 56, borderRadius: 16, background: 'linear-gradient(135deg, #3b82f6, #6366f1)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.6rem', color: '#fff', marginBottom: '1rem' }}>
            <i className="bi bi-geo-alt-fill"></i>
          </div>
          <h1 className="hero-title" style={{ fontSize: '2rem' }}>What Is My IP</h1>
          <p style={{ color: 'var(--text-secondary)', maxWidth: 500, margin: '0.5rem auto 0' }}>
            Your public IP address with geolocation, ASN details, browser-estimated connection data, and browser fingerprint.
          </p>
        </div>

        <ToolWorkspace tool="myip">
        {/* Loading Skeleton */}
        {loading && (
          <div style={{ maxWidth: 900, margin: '0 auto' }}>
            <div className="glass" style={{ padding: '2.5rem', textAlign: 'center', marginBottom: '1.5rem' }}>
              <div style={{ fontSize: '2.5rem', marginBottom: '1rem', animation: 'iconPulse 1.5s infinite' }}>
                <i className="bi bi-geo-alt-fill" style={{ color: 'var(--accent-primary)' }}></i>
              </div>
              <h3 style={{ fontWeight: 600, marginBottom: '0.5rem' }}>Detecting Your IP Address</h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>Looking up geolocation, network details, and reverse DNS...</p>
            </div>
            {[1, 2, 3].map(i => (
              <div key={i} className="glass" style={{ padding: '1.5rem', marginBottom: '1rem' }}>
                <div className="skeleton" style={{ width: '30%', height: 18, marginBottom: 12 }}></div>
                <div className="skeleton" style={{ width: '100%', height: 14, marginBottom: 8 }}></div>
                <div className="skeleton" style={{ width: '70%', height: 14 }}></div>
              </div>
            ))}
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="glass" style={{ maxWidth: 900, margin: '0 auto', padding: '1rem 1.5rem', borderColor: 'rgba(239,68,68,0.3)', color: 'var(--accent-red)', textAlign: 'center' }}>
            ⚠️ {error}
          </div>
        )}

        {/* Results */}
        {data && (
          <div style={{ maxWidth: 900, margin: '0 auto' }}>

            {/* ─── IP Address Card ─── */}
            <div className="glass" style={{ padding: '2rem', textAlign: 'center', marginBottom: '1.5rem', borderTop: '3px solid #6366f1' }}>
              <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '1rem' }}>
                Your Public IP Addresses
              </div>

              {/* Dual-stack IP display */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 280px), 1fr))', gap: '1rem', textAlign: 'center' }}>
                {/* IPv4 */}
                <div style={{ background: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.12)', borderRadius: 14, padding: '1.25rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginBottom: '0.75rem' }}>
                    <span style={{ background: 'rgba(59,130,246,0.15)', border: '1px solid rgba(59,130,246,0.3)', borderRadius: 6, padding: '2px 10px', fontSize: '0.72rem', fontWeight: 700, color: '#3b82f6' }}>IPv4</span>
                    {!ipv4Loading && ipv4 && <span style={{ background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.25)', borderRadius: 6, padding: '2px 8px', fontSize: '0.68rem', fontWeight: 600, color: '#10b981' }}>Detected</span>}
                  </div>
                  {ipv4Loading ? (
                    <div className="skeleton" style={{ width: '70%', height: 28, margin: '0 auto', borderRadius: 8 }}></div>
                  ) : ipv4 ? (
                    <div>
                      <div style={{ fontSize: '1.6rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-primary)', letterSpacing: '-0.02em', marginBottom: '0.5rem' }}>
                        {ipv4}
                      </div>
                      <button
                        onClick={copyIPv4}
                        style={{ background: isCopied('v4') ? 'rgba(16,185,129,0.15)' : 'rgba(99,102,241,0.1)', border: '1px solid ' + (isCopied('v4') ? 'rgba(16,185,129,0.3)' : 'rgba(99,102,241,0.2)'), borderRadius: 8, padding: '4px 12px', cursor: 'pointer', color: isCopied('v4') ? 'var(--accent-green)' : 'var(--accent-primary)', fontSize: '0.78rem', fontWeight: 600, transition: 'all 0.2s ease', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                      >
                        <i className={isCopied('v4') ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i>
                        {isCopied('v4') ? 'Copied!' : 'Copy'}
                      </button>
                    </div>
                  ) : (
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                      <i className="bi bi-x-circle" style={{ color: 'var(--accent-red)', marginRight: 6 }}></i>
                      Not Detected
                    </div>
                  )}
                </div>

                {/* IPv6 */}
                <div style={{ background: 'rgba(168,85,247,0.04)', border: '1px solid rgba(168,85,247,0.12)', borderRadius: 14, padding: '1.25rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginBottom: '0.75rem' }}>
                    <span style={{ background: 'rgba(168,85,247,0.15)', border: '1px solid rgba(168,85,247,0.3)', borderRadius: 6, padding: '2px 10px', fontSize: '0.72rem', fontWeight: 700, color: 'var(--accent-purple)' }}>IPv6</span>
                    {!ipv6Loading && ipv6 && <span style={{ background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.25)', borderRadius: 6, padding: '2px 8px', fontSize: '0.68rem', fontWeight: 600, color: 'var(--accent-green)' }}>Detected</span>}
                  </div>
                  {ipv6Loading ? (
                    <div className="skeleton" style={{ width: '85%', height: 28, margin: '0 auto', borderRadius: 8 }}></div>
                  ) : ipv6 ? (
                    <div>
                      <div style={{ fontSize: '1.1rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-purple)', letterSpacing: '-0.02em', marginBottom: '0.5rem', wordBreak: 'break-all' }}>
                        {ipv6}
                      </div>
                      <button
                        onClick={copyIPv6}
                        style={{ background: isCopied('v6') ? 'rgba(16,185,129,0.15)' : 'rgba(168,85,247,0.1)', border: '1px solid ' + (isCopied('v6') ? 'rgba(16,185,129,0.3)' : 'rgba(168,85,247,0.2)'), borderRadius: 8, padding: '4px 12px', cursor: 'pointer', color: isCopied('v6') ? 'var(--accent-green)' : 'var(--accent-purple)', fontSize: '0.78rem', fontWeight: 600, transition: 'all 0.2s ease', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                      >
                        <i className={isCopied('v6') ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i>
                        {isCopied('v6') ? 'Copied!' : 'Copy'}
                      </button>
                    </div>
                  ) : (
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                      <i className="bi bi-x-circle" style={{ color: 'var(--accent-red)', marginRight: 6 }}></i>
                      Not Detected
                      <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4, opacity: 0.7 }}>Your network does not support IPv6</p>
                    </div>
                  )}
                </div>
              </div>

              {/* Stack type badge */}
              {!ipv4Loading && !ipv6Loading && (
                <div style={{ marginTop: '1rem', display: 'flex', justifyContent: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <span style={{ background: ipv4 && ipv6 ? 'rgba(16,185,129,0.1)' : 'rgba(245,158,11,0.1)', border: `1px solid ${ipv4 && ipv6 ? 'rgba(16,185,129,0.25)' : 'rgba(245,158,11,0.25)'}`, borderRadius: 8, padding: '4px 14px', fontSize: '0.78rem', fontWeight: 700, color: ipv4 && ipv6 ? 'var(--accent-green)' : 'var(--accent-amber)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                    <i className={ipv4 && ipv6 ? 'bi bi-check-circle-fill' : 'bi bi-exclamation-triangle-fill'} style={{ fontSize: '0.72rem' }}></i>
                    {ipv4 && ipv6 ? 'Dual-Stack (IPv4 + IPv6)' : ipv4 ? 'IPv4 Only' : 'IPv6 Only'}
                  </span>
                  {badge && (
                    <span style={{ background: `${badge.color}15`, border: `1px solid ${badge.color}30`, borderRadius: 8, padding: '4px 14px', fontSize: '0.78rem', fontWeight: 700, color: badge.color, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                      <i className={badge.icon} style={{ fontSize: '0.72rem' }}></i>
                      {badge.label}
                    </span>
                  )}
                </div>
              )}
            </div>

            {/* ─── Action Toolbar ─── */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap', marginBottom: '1.5rem' }}>
              <button
                onClick={openShareModal}
                className="btn-primary"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '8px 16px',
                  borderRadius: 10,
                  fontSize: '0.84rem',
                  fontWeight: 600,
                  boxShadow: '0 2px 10px rgba(99,102,241,0.25)',
                }}
              >
                <i className="bi bi-share-fill"></i>
                Share Results
              </button>
              <button
                onClick={downloadHTML}
                className="btn-secondary"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '8px 16px',
                  borderRadius: 10,
                  fontSize: '0.84rem',
                  fontWeight: 600,
                }}
              >
                <i className="bi bi-download"></i>
                Download HTML
              </button>
              <button
                onClick={downloadCSV}
                className="btn-secondary"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '8px 16px',
                  borderRadius: 10,
                  fontSize: '0.84rem',
                  fontWeight: 600,
                }}
              >
                <i className="bi bi-file-earmark-spreadsheet"></i>
                Export CSV
              </button>

              {data.asn && (
                <Link
                  href={`/asn?asn=${data.asn}`}
                  className="btn-secondary"
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 6,
                    padding: '8px 16px',
                    borderRadius: 10,
                    textDecoration: 'none',
                    fontSize: '0.84rem',
                    fontWeight: 600,
                  }}
                >
                  <i className="bi bi-diagram-3-fill" style={{ color: 'var(--accent-purple)' }}></i>
                  ASN Lookup
                </Link>
              )}

              {data.reverse_dns && (
                <Link
                  href={`/dns?domain=${encodeURIComponent(extractDomainFromRDNS(data.reverse_dns))}`}
                  className="btn-secondary"
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 6,
                    padding: '8px 16px',
                    borderRadius: 10,
                    textDecoration: 'none',
                    fontSize: '0.84rem',
                    fontWeight: 600,
                  }}
                >
                  <i className="bi bi-globe2" style={{ color: 'var(--accent-cyan)' }}></i>
                  DNS Lookup
                </Link>
              )}
            </div>

            {/* ─── Stats Row ─── */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
              <StatCard label="Country" value={data.country ? `${countryFlag(data.country_code)} ${data.country}` : '—'} color="#3b82f6" />
              <StatCard label="City" value={data.city || '—'} color="#06b6d4" />
              <StatCard label="ASN Org" value={data.isp || '—'} color="#10b981" />
              <StatCard label="ASN" value={data.asn ? `AS${data.asn}` : '—'} color="#a855f7" />
            </div>

            {/* ─── Geolocation Card ─── */}
            <SectionCard title="Geolocation" icon="bi-pin-map-fill" iconColor="#3b82f6">
              <>
                <DetailTable rows={[
                  { label: 'City', value: formatCity(data) || '—', icon: 'bi-building' },
                  { label: 'State / Region', value: data.region ? `${data.region}${data.region_code ? ` (${data.region_code})` : ''}` : '—', icon: 'bi-geo' },
                  { label: 'Country', value: data.country ? `${countryFlag(data.country_code)} ${data.country}` : '—', icon: 'bi-flag' },
                  { label: 'Registered Country', value: data.registered_country ? `${countryFlag(data.registered_country_code)} ${data.registered_country}` : '—', icon: 'bi-flag-fill' },
                  { label: 'Continent', value: data.continent ? `${data.continent}${data.continent_code ? ` (${data.continent_code})` : ''}` : '—', icon: 'bi-globe-asia-australia' },
                  { label: 'Postal Code', value: data.postal_code || '—', icon: 'bi-mailbox' },
                  { label: 'Accuracy Radius', value: formatAccuracyRadius(data.accuracy_radius) || '—', icon: 'bi-bullseye' },
                  { label: 'Timezone', value: data.timezone || '—', icon: 'bi-clock' },
                  { label: 'UTC Offset', value: data.utc_offset || '—', icon: 'bi-clock-history' },
                  { label: 'Coordinates', value: data.latitude && data.longitude ? `${data.latitude.toFixed(4)}, ${data.longitude.toFixed(4)}` : '—', icon: 'bi-crosshair' },
                ]} />
              </>
            </SectionCard>

            {/* ─── Network Info Card ─── */}
            <SectionCard title="GeoLite ASN & Network" icon="bi-hdd-network-fill" iconColor="#10b981">
              <DetailTable rows={[
                { label: 'ASN Organization', value: data.isp || '—', icon: 'bi-building' },
                {
                  label: 'ASN',
                  value: data.asn ? `AS${data.asn}` : '—',
                  icon: 'bi-diagram-3',
                  action: data.asn ? { label: 'More info →', href: `/asn?asn=${data.asn}` } : undefined
                },
                ...(data.domain ? [{ label: 'Domain', value: data.domain, icon: 'bi-globe2' }] : []),
                ...(data.usage_type ? [{ label: 'Usage Type', value: data.usage_type, icon: 'bi-tags' }] : []),
                ...(data.proxy_type ? [{ label: 'Proxy Type', value: formatProxyStatus(data), icon: 'bi-shield-exclamation' }] : []),
                { label: 'Reverse DNS (PTR)', value: data.reverse_dns || 'No PTR record found', icon: 'bi-arrow-return-left' },
                {
                  label: 'Estimated Network Type',
                  value: badge?.label || 'Unknown',
                  icon: badge?.icon || 'bi-question-circle',
                  badgeColor: badge?.color
                },
              ]} />
            </SectionCard>

            {/* ─── Browser & Device Card ─── */}
            {clientInfo && (
              <SectionCard title="Browser & Device" icon="bi-laptop" iconColor="#a855f7" collapsible>
                <DetailTable rows={[
                  { label: 'Browser', value: clientInfo.browser, icon: 'bi-browser-chrome' },
                  { label: 'Operating System', value: clientInfo.os, icon: 'bi-pc-display' },
                  { label: 'Screen Resolution', value: clientInfo.screen, icon: 'bi-aspect-ratio' },
                  { label: 'Language', value: clientInfo.language, icon: 'bi-translate' },
                  { label: 'Do Not Track', value: clientInfo.dnt, icon: 'bi-eye-slash' },
                  { label: 'Cookies', value: clientInfo.cookies, icon: 'bi-cookie' },
                  { label: 'GPU / WebGL', value: clientInfo.webgl, icon: 'bi-gpu-card' },
                  { label: 'Platform', value: clientInfo.platform, icon: 'bi-cpu' },
                ]} />
              </SectionCard>
            )}

            {/* ─── HTTP Headers Card ─── */}
            <SectionCard title="HTTP Request Headers" icon="bi-code-slash" iconColor="#06b6d4" collapsible>
              <div style={{ padding: '0.25rem 0' }}>
                <p style={{ padding: '0.5rem 1.25rem', fontSize: '0.8rem', color: 'var(--text-muted)', fontStyle: 'italic', borderBottom: '1px solid rgba(30,34,53,0.5)' }}>
                  These headers are sent by your browser with every request you make
                </p>
                <DetailTable rows={[
                  { label: 'User-Agent', value: data.headers.user_agent || '—', icon: 'bi-person-badge' },
                  { label: 'Accept-Language', value: data.headers.accept_language || '—', icon: 'bi-translate' },
                  { label: 'Accept-Encoding', value: data.headers.accept_encoding || '—', icon: 'bi-file-zip' },
                  { label: 'DNT (Do Not Track)', value: data.headers.dnt || 'Not set', icon: 'bi-eye-slash' },
                ]} />
              </div>
            </SectionCard>

            {/* ─── Browser-Estimated Connection Card ─── */}
            <SectionCard title="Browser-Estimated Connection" icon="bi-speedometer2" iconColor="#f59e0b">
              {connection?.supported ? (
                <DetailTable rows={[
                  { label: 'Browser Connection Type', value: capitalize(connection.type), icon: 'bi-wifi' },
                  { label: 'Effective Type', value: connection.effectiveType.toUpperCase(), icon: 'bi-reception-4' },
                  { label: 'Estimated Bandwidth', value: connection.downlink !== null ? `${connection.downlink} Mbps` : '—', icon: 'bi-speedometer' },
                  { label: 'Round-Trip Time', value: connection.rtt !== null ? `${connection.rtt} ms` : '—', icon: 'bi-arrow-repeat' },
                  { label: 'Data Saver', value: connection.saveData ? 'Enabled' : 'Disabled', icon: 'bi-shield-check' },
                ]} />
              ) : (
                <div style={{ padding: '2rem', textAlign: 'center' }}>
                  <div style={{ width: 48, height: 48, borderRadius: 12, background: 'rgba(245,158,11,0.1)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', marginBottom: '0.75rem' }}>
                    <i className="bi bi-exclamation-triangle" style={{ color: '#f59e0b', fontSize: '1.3rem' }}></i>
                  </div>
                  <p style={{ fontWeight: 600, marginBottom: '0.25rem', color: 'var(--text-primary)' }}>Not Supported in Your Browser</p>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', maxWidth: 400, margin: '0 auto' }}>
                    The Network Information API is not available in your browser.
                    This feature is supported in Chrome, Edge, and Opera.
                  </p>
                </div>
              )}
            </SectionCard>
          </div>
        )}
        </ToolWorkspace>
      </main>
      <Footer />

      {/* Share Modal */}
      {shareModalOpen && data && (
        <div
          onClick={(e) => { if (e.target === e.currentTarget) setShareModalOpen(false); }}
          style={{ position: 'fixed', inset: 0, zIndex: 10000, background: 'rgba(7,8,15,0.75)', backdropFilter: 'blur(6px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '24px' }}
        >
          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 18, padding: '32px 36px', maxWidth: 480, width: '100%', boxShadow: '0 24px 80px rgba(0,0,0,0.5)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ width: 38, height: 38, borderRadius: 10, background: 'rgba(99,102,241,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#6366f1', fontSize: '1.1rem' }}>
                  <i className="bi bi-share-fill"></i>
                </div>
                <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>Share IP Report</h3>
              </div>
              <button onClick={() => setShareModalOpen(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.2rem', cursor: 'pointer' }}>
                <i className="bi bi-x-lg"></i>
              </button>
            </div>

            {shareLoading ? (
              <div style={{ textAlign: 'center', padding: '20px 0' }}>
                <div style={{ width: 40, height: 40, border: '3px solid var(--border-color)', borderTopColor: '#6366f1', borderRadius: '50%', animation: 'spin 1s linear infinite', margin: '0 auto 12px' }}></div>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: 0 }}>Creating share link...</p>
              </div>
            ) : shareUrl ? (
              <div>
                <div style={{ textAlign: 'center', marginBottom: 20 }}>
                  <div style={{ width: 52, height: 52, borderRadius: '50%', background: 'rgba(16,185,129,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#10b981', fontSize: '1.5rem', margin: '0 auto 12px' }}>
                    <i className="bi bi-check-circle-fill"></i>
                  </div>
                  <p style={{ margin: 0, color: 'var(--text-primary)', fontWeight: 600, fontSize: '0.95rem' }}>Share link created!</p>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', background: 'var(--bg-input)', border: '1px solid var(--border-color)', borderRadius: 10, padding: '10px 14px', marginBottom: 12 }}>
                  <span style={{ flex: 1, fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{shareUrl}</span>
                  <button
                    onClick={() => void copy(shareUrl, 'share')}
                    style={{ background: 'var(--gradient-primary)', border: 'none', color: '#fff', padding: '6px 14px', borderRadius: 7, cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600 }}
                  >
                    <i className={isCopied('share') ? 'bi bi-check-lg' : 'bi bi-clipboard'} style={{ marginRight: 4 }}></i>{isCopied('share') ? 'Copied!' : 'Copy'}
                  </button>
                </div>
                <button onClick={() => { setShareUrl(''); setShareError(''); }} style={{ width: '100%', marginTop: 16, padding: 10, borderRadius: 10, border: '1px solid var(--border-color)', background: 'none', color: 'var(--text-secondary)', fontSize: '0.85rem', cursor: 'pointer' }}>
                  Create Another Link
                </button>
              </div>
            ) : (
              <div>
                <div style={{ marginBottom: 16 }}>
                  <label style={modalLabelStyle}>Title</label>
                  <input value={shareTitle} onChange={(e) => setShareTitle(e.target.value)} style={modalInputStyle} />
                </div>
                <div style={{ marginBottom: 16 }}>
                  <label style={modalLabelStyle}>Link Expiry</label>
                  <select value={shareExpiry} onChange={(e) => setShareExpiry(e.target.value)} style={modalInputStyle}>
                    <option value="never">Never expires</option>
                    <option value="24h">24 hours</option>
                    <option value="7d">7 days</option>
                    <option value="30d">30 days</option>
                  </select>
                </div>
                <div style={{ marginBottom: 16 }}>
                  <label style={modalLabelStyle}>Password</label>
                  <input type="password" value={sharePassword} onChange={(e) => setSharePassword(e.target.value)} placeholder="Leave blank for public link" style={modalInputStyle} />
                </div>
                {shareError && (
                  <div style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 8, padding: '10px 14px', color: '#f87171', fontSize: '0.82rem', marginBottom: 12 }}>
                    {shareError}
                  </div>
                )}
                <button onClick={() => void submitShare()} style={{ width: '100%', padding: 12, borderRadius: 10, border: 'none', background: 'var(--gradient-primary)', color: '#fff', fontWeight: 700, fontSize: '0.92rem', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                  <i className="bi bi-link-45deg"></i>
                  Generate Share Link
                </button>
              </div>
            )}
          </div>
        </div>
      )}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } } @keyframes iconPulse { 0%,100% { opacity:1; transform:scale(1); } 50% { opacity:0.5; transform:scale(1.1); } }`}</style>
    </>
  );
}

// ─── Sub-Components ───

function StatCard({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="glass" style={{ padding: '1rem', textAlign: 'center', borderTop: `3px solid ${color}` }}>
      <div style={{ fontSize: '1rem', fontWeight: 700, color, fontFamily: 'var(--font-mono)', wordBreak: 'break-word', lineHeight: 1.3 }}>{value}</div>
      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: '0.35rem' }}>{label}</div>
    </div>
  );
}

function SectionCard({ title, icon, iconColor, children, collapsible = false }: { title: string; icon: string; iconColor: string; children: React.ReactNode; collapsible?: boolean }) {
  if (collapsible) {
    return (
      <details className="glass signal-myip-collapsible" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
        <summary className="signal-myip-collapsible-summary">
          <i className={icon} style={{ color: iconColor }}></i>
          <span>{title}</span>
        </summary>
        <div className="signal-myip-collapsible-body">{children}</div>
      </details>
    );
  }
  return (
    <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
      <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <i className={icon} style={{ color: iconColor }}></i>
        {title}
      </div>
      {children}
    </div>
  );
}

interface DetailRow {
  label: string;
  value: string;
  icon: string;
  action?: { label: string; href: string };
  badgeColor?: string;
}

function DetailTable({ rows }: { rows: DetailRow[] }) {
  return (
    <dl className="signal-myip-details">
        {rows.map((row) => (
          <div key={row.label}>
            <dt>
              <i className={row.icon} style={{ marginRight: '0.5rem', opacity: 0.5 }}></i>
              {row.label}
            </dt>
            <dd>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                {row.badgeColor ? (
                  <span style={{ background: `${row.badgeColor}15`, border: `1px solid ${row.badgeColor}30`, borderRadius: 6, padding: '2px 10px', fontSize: '0.82rem', fontWeight: 700, color: row.badgeColor }}>
                    {row.value}
                  </span>
                ) : (
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>{row.value}</span>
                )}
                {row.action && (
                  <Link href={row.action.href} style={{ fontSize: '0.78rem', color: 'var(--accent-primary)', textDecoration: 'none', fontWeight: 600 }}>
                    {row.action.label}
                  </Link>
                )}
              </div>
            </dd>
          </div>
        ))}
    </dl>
  );
}

const modalLabelStyle = {
  fontSize: '0.78rem',
  fontWeight: 600,
  color: 'var(--text-muted)',
  textTransform: 'uppercase' as const,
  letterSpacing: '0.06em',
  display: 'block',
  marginBottom: 6,
};

const modalInputStyle = {
  width: '100%',
  padding: '10px 14px',
  borderRadius: 10,
  border: '1px solid var(--border-color)',
  background: 'var(--bg-input)',
  color: 'var(--text-primary)',
  fontSize: '0.88rem',
  boxSizing: 'border-box' as const,
  outline: 'none',
};

function capitalize(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function extractDomainFromRDNS(rdns: string) {
  // Extract domain from rDNS like "host-103-157-231-134.liberty.net.in" → "liberty.net.in"
  const parts = rdns.split('.');
  if (parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return rdns;
}
