'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import DnsSnapshotView from '@/components/DnsSnapshotView';
import WhoisSnapshotView from '@/components/WhoisSnapshotView';
import AsnSnapshotView from '@/components/AsnSnapshotView';
import { api, WhoisSnapshot, MyIPResult } from '@/lib/api';
import { DnsSnapshot, normalizeSharedSnapshot } from '@/lib/dns';
import type { GeoIPRuntime } from '@/lib/geoip';
import { normalizeWhoisSnapshot } from '@/lib/whois';
import { normalizeAsnSnapshot, ASNResult } from '@/lib/asn';
import { normalizeMyIPSnapshot, networkBadge, buildMyIPReportHtml, buildMyIPExportData } from '@/lib/myip';
import { exportToCSV } from '@/lib/csv-utils';
import { disposeNginxDashboard, loadNginxEngine } from '@/lib/nginx-engine';

/**
 * Shared Analysis Page — /s/[code]
 *
 * Full flow:
 * 1. Fetch share metadata (GET /api/share/:code)
 * 2. If password-protected, show password prompt
 * 3. Verify password + get the presigned R2 download URL (POST /api/share/:code/verify)
 * 4. For DNS shares → render DNS snapshot table
 * 5. For Nginx shares → fetch the log from R2, init GeoIP, parse, analyze, render dashboard
 */
export default function SharePage() {
  const params = useParams();
  const router = useRouter();
  const code = params.code as string;
  const [shareMeta, setShareMeta] = useState<ShareMeta | null>(null);
  const [dnsSnapshot, setDnsSnapshot] = useState<DnsSnapshot | null>(null);
  const [whoisSnapshot, setWhoisSnapshot] = useState<WhoisSnapshot | null>(null);
  const [myipSnapshot, setMyipSnapshot] = useState<Record<string, unknown> | null>(null);
  const [asnSnapshot, setAsnSnapshot] = useState<ASNResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [needsPassword, setNeedsPassword] = useState(false);
  const [password, setPassword] = useState('');
  const [analysisState, setAnalysisState] = useState<'idle' | 'loading_log' | 'loading_geoip' | 'parsing' | 'analyzing' | 'done' | 'error'>('idle');
  const [analysisError, setAnalysisError] = useState('');
  // The shared runtime survives client navigation; dispose only its rendered view.
  useEffect(() => {
    return () => disposeNginxDashboard();
  }, []);

  async function verifyPassword() {
    setLoading(true); setError('');
    try {
      const d = await api.verifyShare(code, password) as ShareMeta;
      setShareMeta((current) => ({ ...(current || {}), ...d }));
      setNeedsPassword(false);
      if (d.share_type === 'dns') {
        setDnsSnapshot(normalizeSharedSnapshot(d.snapshot));
      } else if (d.share_type === 'whois') {
        setWhoisSnapshot(normalizeWhoisSnapshot(d.snapshot));
      } else if (d.share_type === 'myip') {
        setMyipSnapshot(d.snapshot as Record<string, unknown>);
      } else if (d.share_type === 'asn') {
        setAsnSnapshot(normalizeAsnSnapshot(d.snapshot));
      } else if (d.share_type === 'nginx' && (d.download_url || d.source_url)) {
        void loadAndRenderAnalysis(d.download_url, getFallbackUrls(d));
      }
    } catch (error: unknown) {
      setError(getErrorMessage(error, 'Verification failed.'));
    }
    setLoading(false);
  }

  // The gist_* columns were dropped in migration 005_r2_storage. Only source_url survives
  // — it records where a share was originally ingested from, so it can be re-fetched
  // through /api/storage/upload-external if the R2 object is missing.
  const getFallbackUrls = useCallback((share: ShareMeta) => {
    return share.source_url ? [share.source_url] : [];
  }, []);

  async function fetchLogContentWithFallback(downloadUrl?: string, fallbackUrls: string[] = []) {
    // Priority 1: Direct Cloudflare R2 Presigned Download (zero server bandwidth, fastest)
    if (downloadUrl) {
      try {
        const resp = await fetch(downloadUrl);
        if (resp.ok) {
          const logText = await resp.text();
          return { logText, sourceUrl: downloadUrl };
        }
      } catch (err) {
        console.warn('Direct R2 download error, falling back to URL fetch:', err);
      }
    }

    // Priority 2: Fallback remote URLs if any
    let lastError = '';
    for (const url of fallbackUrls) {
      try {
        const resp = await fetch('/api/storage/upload-external', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url }),
        });
        const result = await resp.json().catch((): GistFetchResponse => ({ error: `HTTP ${resp.status}` }));
        if (resp.ok && result.shareCode) {
          // Fetch download url for new share
          const dlResp = await fetch(`/api/storage/download/${result.shareCode}`);
          const dlData = await dlResp.json();
          if (dlData.downloadUrl) {
            const rawResp = await fetch(dlData.downloadUrl);
            if (rawResp.ok) return { logText: await rawResp.text(), sourceUrl: url };
          }
        }
        lastError = result.error || `HTTP ${resp.status}`;
      } catch (e) {
        lastError = getErrorMessage(e, 'Download error');
      }
    }

    throw new Error(lastError || 'Failed to fetch shared log from storage.');
  }

  const loadAndRenderAnalysis = useCallback(async (downloadUrl?: string, fallbackUrls: string[] = []) => {
    try {
      // Step 1: Fetch log content directly from R2
      setAnalysisState('loading_log');
      const { logText, sourceUrl } = await fetchLogContentWithFallback(downloadUrl, fallbackUrls);

      // Step 2: Wait for scripts to load
      await loadNginxEngine();

      const runtimeWindow = window as AnalysisWindow;
      const GeoIP = runtimeWindow.GeoIP;
      const LogEngine = runtimeWindow.LogEngine;
      const Dashboard = runtimeWindow.Dashboard;

      if (!GeoIP || !LogEngine || !Dashboard) {
        throw new Error('Analysis engine scripts failed to load.');
      }

      // Step 3: Init GeoIP & BotDetector
      setAnalysisState('loading_geoip');
      if (!GeoIP.isReady()) {
        await GeoIP.init((pct: number, msg: string) => {
          const bar = document.getElementById('share-geoip-bar');
          const status = document.getElementById('share-geoip-status');
          if (bar) bar.style.width = pct + '%';
          if (status) status.textContent = msg;
        });
      }
      if (runtimeWindow.BotDetector?.init) {
        await runtimeWindow.BotDetector.init();
      }

      // Step 4: Parse
      setAnalysisState('parsing');
      await new Promise((resolve) => setTimeout(resolve, 50));
      GeoIP.clearCache?.();
      const result = await LogEngine.analyze(logText, { skip403: true, skipInternal: true });
      if (result.parseResult.validLines === 0) {
        result.worker.terminate();
        throw new Error('No valid access-log lines found in the shared logs.');
      }

      // Step 5: Render dashboard (read-only mode)
      setAnalysisState('done');

      // Make input section hidden and dashboard visible
      const inputSection = document.getElementById('nginx-input-section');
      if (inputSection) inputSection.style.display = 'none';

      Dashboard.render(result.data, logText, result.parseResult, {
        source: 'gist',
        gistUrl: sourceUrl, // Dashboard still labels this source 'gist'; see dashboard.js
        skip403: true,
        skipInternal: true,
        sources: [logText],
        worker: result.worker,
        summary: result.summary,
        pageResult: result.pageResult,
      });

      // Hide all action buttons (read-only mode)
      setTimeout(() => {
        const idsToHide = ['dash-back-btn', 'dash-share-btn', 'dash-download-btn', 'dash-new-btn'];
        idsToHide.forEach(id => {
          const el = document.getElementById(id);
          if (el) el.style.display = 'none';
        });
        // Also hide any remaining action buttons by class
        document.querySelectorAll('.dash-action-btn').forEach(el => {
          (el as HTMLElement).style.display = 'none';
        });
      }, 300);

    } catch (error: unknown) {
      setAnalysisState('error');
      setAnalysisError(getErrorMessage(error, 'Analysis failed.'));
    }
  }, []);

  // Fetch share metadata
  useEffect(() => {
    if (!code) return;
    api.getShare(code)
      .then(async (data) => {
        const d = data as ShareMeta;
        if (d.has_password || d.password_required) {
          setShareMeta(d);
          setNeedsPassword(true);
          return;
        }

        setShareMeta(d);
        if (d.share_type === 'dns') {
          const verified = await api.verifyShare(code);
          setDnsSnapshot(normalizeSharedSnapshot(verified.snapshot));
          setShareMeta((current) => ({ ...(current || {}), ...verified }));
          return;
        }

        if (d.share_type === 'whois') {
          const verified = await api.verifyShare(code);
          setWhoisSnapshot(normalizeWhoisSnapshot(verified.snapshot));
          setShareMeta((current) => ({ ...(current || {}), ...verified }));
          return;
        }

        if (d.share_type === 'myip') {
          const verified = await api.verifyShare(code);
          setMyipSnapshot(verified.snapshot as Record<string, unknown>);
          setShareMeta((current) => ({ ...(current || {}), ...verified }));
          return;
        }

        if (d.share_type === 'asn') {
          const verified = await api.verifyShare(code);
          setAsnSnapshot(normalizeAsnSnapshot(verified.snapshot));
          setShareMeta((current) => ({ ...(current || {}), ...verified }));
          return;
        }

        if (d.share_type === 'nginx' && (d.download_url || d.source_url)) {
          void loadAndRenderAnalysis(d.download_url, getFallbackUrls(d));
        }
      })
      .catch((error: unknown) => setError(getErrorMessage(error, 'Failed to load share.')))
      .finally(() => setLoading(false));
  }, [code, getFallbackUrls, loadAndRenderAnalysis]);

  const stateMessages: Record<string, string> = {
    loading_log: 'Fetching shared log data from Cloudflare R2...',
    loading_geoip: 'Loading GeoIP databases...',
    parsing: 'Parsing log entries...',
    analyzing: 'Running analysis...',
  };

  return (
    <>
      <Navbar />
      <main className="main-content" style={{ maxWidth: 1600 }}>
        {/* Loading */}
        {loading && (
          <div style={{ textAlign: 'center', padding: '4rem 0' }}>
            <div className="skeleton" style={{ width: 200, height: 20, margin: '0 auto 1rem' }}></div>
            <div className="skeleton" style={{ width: 300, height: 14, margin: '0 auto' }}></div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="glass" style={{ padding: '1rem 1.5rem', borderColor: 'rgba(239,68,68,0.3)', color: 'var(--accent-red)', textAlign: 'center', marginBottom: '1rem' }}>
            ⚠️ {error}
          </div>
        )}

        {/* Password Prompt */}
        {needsPassword && (
          <div className="glass" style={{ maxWidth: 420, margin: '4rem auto', padding: '3rem 2.5rem', textAlign: 'center' }}>
            <div style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>🔒</div>
            <h2 style={{ fontSize: '1.3rem', fontWeight: 700, marginBottom: '0.5rem' }}>Password Protected</h2>
            <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem', fontSize: '0.88rem' }}>This shared analysis requires a password to view.</p>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && verifyPassword()}
              placeholder="Enter password"
              style={{ width: '100%', padding: '0.75rem 1rem', background: 'var(--bg-input)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', marginBottom: '1rem', boxSizing: 'border-box' }}
            />
            <button onClick={verifyPassword} className="btn-primary" style={{ width: '100%' }}>Unlock</button>
          </div>
        )}

        {/* Shared Analysis Header + Read-Only Banner */}
        {shareMeta && (
          <div style={{ marginBottom: '1.5rem' }}>
            <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
              <div style={{
                display: 'inline-flex', alignItems: 'center', gap: '8px',
                background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.15)',
                borderRadius: '24px', padding: '6px 16px', fontSize: '0.78rem',
                fontWeight: 600, color: 'var(--accent-primary)', marginBottom: '1rem'
              }}>
                <i className="bi bi-share-fill"></i>
                Shared Analysis — Read Only
              </div>
              <h1 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '0.5rem' }}>
                {shareMeta.title || 'Shared Analysis'}
              </h1>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                Created: {shareMeta.created_at
                  ? new Date(shareMeta.created_at).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
                  : 'Unknown'}
                {shareMeta.expires_at && ` · Expires: ${new Date(shareMeta.expires_at).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}`}
              </p>
            </div>
          </div>
        )}

        {/* Analysis Loading State */}
        {analysisState !== 'idle' && analysisState !== 'done' && analysisState !== 'error' && (
          <div className="glass" style={{ padding: '2rem', textAlign: 'center', marginBottom: '1.5rem' }}>
            <div style={{
              width: 44, height: 44, border: '3px solid var(--border-color)',
              borderTopColor: '#6366f1', borderRadius: '50%',
              animation: 'spin 1s linear infinite', margin: '0 auto 16px'
            }}></div>
            <p style={{ fontWeight: 600, marginBottom: '8px' }}>{stateMessages[analysisState] || 'Processing...'}</p>
            {analysisState === 'loading_geoip' && (
              <div style={{ maxWidth: 300, margin: '0 auto' }}>
                <div style={{ width: '100%', height: 6, background: 'var(--bg-secondary)', borderRadius: 3, overflow: 'hidden' }}>
                  <div id="share-geoip-bar" style={{ width: '0%', height: '100%', background: 'var(--gradient-primary)', borderRadius: 3, transition: 'width 0.3s ease' }}></div>
                </div>
                <div id="share-geoip-status" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>Initializing...</div>
              </div>
            )}
          </div>
        )}

        {/* Analysis Error */}
        {analysisState === 'error' && (
          <div className="glass" style={{ padding: '2rem', textAlign: 'center', borderColor: 'rgba(239,68,68,0.3)' }}>
            <div style={{ fontSize: '2rem', marginBottom: '0.75rem' }}>❌</div>
            <h3 style={{ fontWeight: 700, marginBottom: '0.5rem' }}>Analysis Failed</h3>
            <p style={{ color: 'var(--accent-red)', fontSize: '0.88rem' }}>{analysisError}</p>
          </div>
        )}

        {/* DNS Snapshot (for DNS shares) */}
        {shareMeta?.share_type === 'dns' && dnsSnapshot && (
          <div style={{ maxWidth: 1100, margin: '0 auto' }}>
            <DnsSnapshotView
              snapshot={dnsSnapshot}
              mode="shared"
              title={shareMeta.title || 'Shared DNS Snapshot'}
              code={code}
              onRerun={() => router.push(`/dns?domain=${encodeURIComponent(dnsSnapshot.domain)}&resolver=${encodeURIComponent(dnsSnapshot.resolver)}&types=${encodeURIComponent(dnsSnapshot.selected_types.join(','))}`)}
            />
          </div>
        )}

        {shareMeta?.share_type === 'whois' && whoisSnapshot && (
          <div style={{ maxWidth: 1100, margin: '0 auto' }}>
            <WhoisSnapshotView
              snapshot={whoisSnapshot}
              mode="shared"
              title={shareMeta.title || 'Shared WHOIS Snapshot'}
              code={code}
              onRerun={() => router.push(`/whois?domain=${encodeURIComponent(whoisSnapshot.domain)}`)}
            />
          </div>
        )}

        {/* MyIP Snapshot (for MyIP shares) */}
        {shareMeta?.share_type === 'myip' && myipSnapshot && (
          <div style={{ maxWidth: 900, margin: '0 auto' }}>
            <MyIPSharedView snapshot={myipSnapshot} title={shareMeta.title} code={code} />
          </div>
        )}

        {/* ASN Snapshot (for ASN shares) */}
        {shareMeta?.share_type === 'asn' && asnSnapshot && (
          <div style={{ maxWidth: 1100, margin: '0 auto' }}>
            <AsnSnapshotView
              snapshot={asnSnapshot}
              mode="shared"
              title={shareMeta.title || 'Shared ASN Snapshot'}
              code={code}
              onRerun={(asn) => router.push(`/asn?asn=${encodeURIComponent(asn)}`)}
            />
          </div>
        )}

        {/* Nginx Dashboard Container — filled by dashboard.js */}
        <div id="nginx-input-section" style={{ display: 'none' }}></div>
        <div id="nginx-dashboard" style={{ display: 'none' }}></div>
      </main>
      <Footer />
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </>
  );
}

interface ShareMeta {
  share_type?: 'dns' | 'nginx' | 'whois' | 'myip' | 'asn';
  title?: string;
  has_password?: boolean;
  password_required?: boolean;
  expires_at?: string;
  created_at?: string;
  download_url?: string;
  r2_key?: string;
  source_url?: string;
  domain?: string;
  ip?: string;
  asn?: string;
  checked_at_utc?: string;
  snapshot?: unknown;
}

interface GistFetchResponse {
  content?: string;
  error?: string;
}

interface LogAnalysis {
  worker: { terminate: () => void };
  summary: unknown;
  pageResult: unknown;
  data: unknown;
  parseResult: { validLines: number };
}

interface LogEngineRuntime {
  analyze: (input: string, options?: { skip403?: boolean; skipInternal?: boolean }) => Promise<LogAnalysis>;
}

interface DashboardRuntime {
  render: (
    data: unknown,
    logText: string,
    parseResult: LogAnalysis['parseResult'],
    options: {
      source: 'gist';
      gistUrl: string;
      skip403?: boolean;
      skipInternal?: boolean;
      sources: string[];
      worker: LogAnalysis['worker'];
      summary: unknown;
      pageResult: unknown;
    }
  ) => void;
}

interface AnalysisWindow extends Window {
  BotDetector?: { init: () => Promise<void> };
  GeoIP?: GeoIPRuntime;
  LogEngine?: LogEngineRuntime;
  Dashboard?: DashboardRuntime;
}

function getErrorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}

// ─── MyIP Shared View ───

function countryFlag(code: string | null | undefined) {
  if (!code || code.length !== 2) return '🌐';
  return String.fromCodePoint(
    ...code.toUpperCase().split('').map(c => 0x1F1E6 + c.charCodeAt(0) - 65)
  );
}

function DetailRow({ label, value }: { label: string; value?: string | null }) {
  return <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
    <td style={{ padding: '0.625rem 1.25rem', color: 'var(--text-muted)', fontSize: '0.85rem', width: '40%' }}>{label}</td>
    <td style={{ padding: '0.625rem 1.25rem', fontFamily: 'var(--font-mono)', fontSize: '0.85rem', wordBreak: 'break-all' }}>{value || '—'}</td>
  </tr>;
}

function MyIPSharedView({ snapshot, title, code }: { snapshot: Record<string, unknown>; title?: string; code?: string }) {
  const d = normalizeMyIPSnapshot(snapshot);
  const client = d.client;
  const conn = d.connection;
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      void navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    }
  };

  function handleDownloadHtml() {
    if (!d) return;
    const html = buildMyIPReportHtml(d, d.client || {
      browser: 'Unknown',
      os: 'Unknown',
      screen: 'Unknown',
      language: 'Unknown',
      dnt: 'Not set',
      cookies: 'Unknown',
      webgl: 'Unknown',
      platform: 'Unknown',
      connection: d.connection,
    }, { ipv4: d.ipv4, ipv6: d.ipv6 });
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const filenameIp = (d.ipv4 || d.ip || 'ip').replace(/[.:]/g, '-');
    a.download = `my-ip-report-${filenameIp}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function handleDownloadCsv() {
    if (!d) return;
    const exportData = buildMyIPExportData(d, { ipv4: d.ipv4, ipv6: d.ipv6 });
    const filenameIp = (d.ipv4 || d.ip || 'ip').replace(/[.:]/g, '-');
    exportToCSV(exportData, `my-ip-report-${filenameIp}`);
  }

  const badge = networkBadge(d.network_type);

  return (
    <>
      {/* Banner */}
      <div style={{
        background: 'rgba(99,102,241,0.06)',
        border: '1px solid rgba(99,102,241,0.18)',
        borderRadius: 10,
        padding: '10px 16px',
        marginBottom: 20,
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        flexWrap: 'wrap',
        fontSize: '0.82rem',
        color: 'var(--text-secondary)',
      }}>
        <i className="bi bi-geo-alt-fill" style={{ color: 'var(--accent-primary)' }}></i>
        <span>You are viewing <strong style={{ color: 'var(--text-primary)' }}>{title || 'Shared IP Report'}</strong> — read-only snapshot.</span>
        {code && <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>/s/{code}</span>}
        <Link href="/myip" style={{ marginLeft: 'auto', color: 'var(--accent-primary)', textDecoration: 'none', fontWeight: 600 }}>
          <i className="bi bi-arrow-up-right-circle" style={{ marginRight: 4 }}></i>
          Open Live Tool
        </Link>
      </div>

      {/* IP Address Card */}
      <div className="glass" style={{ padding: '2rem', textAlign: 'center', marginBottom: '1.5rem', borderTop: '3px solid #6366f1' }}>
        <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '1rem' }}>
          Public IP Address
        </div>

        {/* Dual-stack IP display */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 280px), 1fr))', gap: '1rem', textAlign: 'center' }}>
          {/* IPv4 */}
          <div style={{ background: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.12)', borderRadius: 14, padding: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginBottom: '0.75rem' }}>
              <span style={{ background: 'rgba(59,130,246,0.15)', border: '1px solid rgba(59,130,246,0.3)', borderRadius: 6, padding: '2px 10px', fontSize: '0.72rem', fontWeight: 700, color: '#3b82f6' }}>IPv4</span>
              {d.ipv4 && <span style={{ background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.25)', borderRadius: 6, padding: '2px 8px', fontSize: '0.68rem', fontWeight: 600, color: 'var(--accent-green)' }}>Detected</span>}
            </div>
            {d.ipv4 ? (
              <div>
                <div style={{ fontSize: '1.6rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-primary)', letterSpacing: '-0.02em', marginBottom: '0.5rem' }}>
                  {d.ipv4}
                </div>
                <button
                  onClick={() => copyToClipboard(d.ipv4!, 'v4')}
                  style={{ background: copiedKey === 'v4' ? 'rgba(16,185,129,0.15)' : 'rgba(99,102,241,0.1)', border: '1px solid ' + (copiedKey === 'v4' ? 'rgba(16,185,129,0.3)' : 'rgba(99,102,241,0.2)'), borderRadius: 8, padding: '4px 12px', cursor: 'pointer', color: copiedKey === 'v4' ? 'var(--accent-green)' : 'var(--accent-primary)', fontSize: '0.78rem', fontWeight: 600, transition: 'all 0.2s ease', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                >
                  <i className={copiedKey === 'v4' ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i>
                  {copiedKey === 'v4' ? 'Copied!' : 'Copy'}
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
              {d.ipv6 && <span style={{ background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.25)', borderRadius: 6, padding: '2px 8px', fontSize: '0.68rem', fontWeight: 600, color: 'var(--accent-green)' }}>Detected</span>}
            </div>
            {d.ipv6 ? (
              <div>
                <div style={{ fontSize: '1.1rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-purple)', letterSpacing: '-0.02em', marginBottom: '0.5rem', wordBreak: 'break-all' }}>
                  {d.ipv6}
                </div>
                <button
                  onClick={() => copyToClipboard(d.ipv6!, 'v6')}
                  style={{ background: copiedKey === 'v6' ? 'rgba(16,185,129,0.15)' : 'rgba(168,85,247,0.1)', border: '1px solid ' + (copiedKey === 'v6' ? 'rgba(16,185,129,0.3)' : 'rgba(168,85,247,0.2)'), borderRadius: 8, padding: '4px 12px', cursor: 'pointer', color: copiedKey === 'v6' ? 'var(--accent-green)' : 'var(--accent-purple)', fontSize: '0.78rem', fontWeight: 600, transition: 'all 0.2s ease', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                >
                  <i className={copiedKey === 'v6' ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i>
                  {copiedKey === 'v6' ? 'Copied!' : 'Copy'}
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
        <div style={{ marginTop: '1rem', display: 'flex', justifyContent: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <span style={{ background: d.isDualStack ? 'rgba(16,185,129,0.1)' : 'rgba(245,158,11,0.1)', border: `1px solid ${d.isDualStack ? 'rgba(16,185,129,0.25)' : 'rgba(245,158,11,0.25)'}`, borderRadius: 8, padding: '4px 14px', fontSize: '0.78rem', fontWeight: 700, color: d.isDualStack ? 'var(--accent-green)' : 'var(--accent-amber)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <i className={d.isDualStack ? 'bi bi-check-circle-fill' : 'bi bi-exclamation-triangle-fill'} style={{ fontSize: '0.72rem' }}></i>
            {d.isDualStack ? 'Dual-Stack (IPv4 + IPv6)' : d.ipv4 ? 'IPv4 Only' : 'IPv6 Only'}
          </span>
          {badge && (
            <span style={{ background: `${badge.color}15`, border: `1px solid ${badge.color}30`, borderRadius: 8, padding: '4px 14px', fontSize: '0.78rem', fontWeight: 700, color: badge.color, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <i className={badge.icon} style={{ fontSize: '0.72rem' }}></i>
              {badge.label}
            </span>
          )}
        </div>
      </div>

      {/* Action Toolbar */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap', marginBottom: '1.5rem' }}>
        <button
          onClick={handleDownloadHtml}
          className="btn-secondary"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '8px 16px', borderRadius: 10, fontSize: '0.84rem', fontWeight: 600 }}
        >
          <i className="bi bi-download"></i>
          Download HTML
        </button>
        <button
          onClick={handleDownloadCsv}
          className="btn-secondary"
          style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '8px 16px', borderRadius: 10, fontSize: '0.84rem', fontWeight: 600 }}
        >
          <i className="bi bi-file-earmark-spreadsheet"></i>
          Export CSV
        </button>
      </div>

      {/* 1. Geolocation */}
      <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
        <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
          <i className="bi bi-pin-map-fill" style={{ color: '#3b82f6', marginRight: '0.5rem' }}></i>Geolocation
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}><tbody>
          <DetailRow label="City" value={d.city} />
          <DetailRow label="Region" value={d.region} />
          <DetailRow label="Country" value={d.country ? `${countryFlag(d.country_code)} ${d.country}` : ''} />
          <DetailRow label="Postal Code" value={d.postal_code} />
          <DetailRow label="Timezone" value={d.timezone} />
          <DetailRow label="UTC Offset" value={d.utc_offset} />
        </tbody></table>
      </div>

      {/* 2. Network */}
      <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
        <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
          <i className="bi bi-hdd-network-fill" style={{ color: '#10b981', marginRight: '0.5rem' }}></i>Network
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}><tbody>
          <DetailRow label="ISP" value={d.isp} />
          <DetailRow label="ASN" value={d.asn ? `AS${d.asn}` : ''} />
          <DetailRow label="Reverse DNS" value={d.reverse_dns} />
        </tbody></table>
      </div>

      {/* 3. Browser & Device */}
      {client?.browser && (
        <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
          <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
            <i className="bi bi-laptop" style={{ color: '#a855f7', marginRight: '0.5rem' }}></i>Browser & Device
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}><tbody>
            <DetailRow label="Browser" value={client.browser} />
            <DetailRow label="OS" value={client.os} />
            <DetailRow label="Screen" value={client.screen} />
            <DetailRow label="Language" value={client.language} />
            <DetailRow label="Cookies" value={client.cookies} />
            <DetailRow label="GPU" value={client.webgl} />
          </tbody></table>
        </div>
      )}

      {/* 4. HTTP Headers */}
      {d.headers && (
        <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
          <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
            <i className="bi bi-code-slash" style={{ color: '#06b6d4', marginRight: '0.5rem' }}></i>HTTP Headers
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}><tbody>
            <DetailRow label="User-Agent" value={d.headers.user_agent} />
            <DetailRow label="Accept-Language" value={d.headers.accept_language} />
            <DetailRow label="Accept-Encoding" value={d.headers.accept_encoding} />
            <DetailRow label="DNT" value={d.headers.dnt || 'Not set'} />
          </tbody></table>
        </div>
      )}

      {/* 5. Connection */}
      {conn?.supported && (
        <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
          <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
            <i className="bi bi-speedometer2" style={{ color: '#f59e0b', marginRight: '0.5rem' }}></i>Connection
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}><tbody>
            <DetailRow label="Type" value={conn.type} />
            <DetailRow label="Effective Type" value={String(conn.effectiveType || '').toUpperCase()} />
            <DetailRow label="Bandwidth" value={conn.downlink != null ? `${conn.downlink} Mbps` : ''} />
            <DetailRow label="RTT" value={conn.rtt != null ? `${conn.rtt} ms` : ''} />
          </tbody></table>
        </div>
      )}

      <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.78rem' }}>
        Checked at {d.checked_at_utc ? new Date(d.checked_at_utc).toUTCString() : 'Unknown'}
      </div>
    </>
  );
}
