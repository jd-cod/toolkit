'use client';

import { useCallback, useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import SharedSnapshot from '@/components/share/SharedSnapshot';
import { api } from '@/lib/api';
import type { GeoIPRuntime } from '@/lib/geoip';
import { isSnapshotTool } from '@/lib/share';
import { disposeNginxDashboard, loadNginxEngine } from '@/lib/nginx-engine';

/**
 * Shared Analysis Page — /s/[code]
 *
 * Full flow:
 * 1. Fetch share metadata (GET /api/share/:code)
 * 2. If password-protected, show password prompt
 * 3. Verify password + get the presigned R2 download URL (POST /api/share/:code/verify)
 * 4. For snapshot shares (DNS, WHOIS, SSL, ...) → render that tool's read-only view
 * 5. For Nginx shares → fetch the log from R2, init GeoIP, parse, analyze, render dashboard
 */
export default function SharePage() {
  const params = useParams();
  const code = params.code as string;
  const [shareMeta, setShareMeta] = useState<ShareMeta | null>(null);
  const [snapshot, setSnapshot] = useState<unknown>(null);
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
      const LogParser = runtimeWindow.LogParser;
      const Analyzer = runtimeWindow.Analyzer;
      const Dashboard = runtimeWindow.Dashboard;

      if (!GeoIP || !LogParser || !Analyzer || !Dashboard) {
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
      const parseResult = LogParser.parseIPs(logText, { skip403: true, skipInternal: true });
      if (parseResult.validLines === 0) {
        throw new Error('No valid access-log lines found in the shared logs.');
      }

      // Step 5: Analyze
      setAnalysisState('analyzing');
      await new Promise((resolve) => setTimeout(resolve, 50));
      Analyzer.enrichLogEntries(parseResult.logEntries);
      const data = Analyzer.analyzeEnhancedLogs(parseResult.logEntries);

      // Step 6: Render dashboard (read-only mode)
      setAnalysisState('done');

      // Make input section hidden and dashboard visible
      const inputSection = document.getElementById('nginx-input-section');
      if (inputSection) inputSection.style.display = 'none';

      Dashboard.render(data, logText, parseResult, {
        source: 'gist',
        gistUrl: sourceUrl, // Dashboard still labels this source 'gist'; see dashboard.js
        skip403: true,
        skipInternal: true,
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

  /** Shows a share once its data is available: after the password check, or straight away for a public link. */
  const showShare = useCallback((d: ShareMeta) => {
    setShareMeta((current) => ({ ...(current || {}), ...d }));
    if (d.share_type === 'nginx') {
      if (d.download_url || d.source_url) void loadAndRenderAnalysis(d.download_url, getFallbackUrls(d));
      return;
    }
    setSnapshot(d.snapshot ?? null);
  }, [getFallbackUrls, loadAndRenderAnalysis]);

  async function verifyPassword() {
    setLoading(true); setError('');
    try {
      const d = await api.verifyShare(code, password) as ShareMeta;
      setNeedsPassword(false);
      showShare(d);
    } catch (error: unknown) {
      setError(getErrorMessage(error, 'Verification failed.'));
    }
    setLoading(false);
  }

  // Fetch share metadata
  useEffect(() => {
    if (!code) return;
    api.getShare(code)
      .then(async (data) => {
        const d = data as ShareMeta;
        setShareMeta(d);
        if (d.has_password || d.password_required) {
          setNeedsPassword(true);
          return;
        }
        // A public Traffic Analyzer share already carries its download URL;
        // every other tool's data comes from the verify call.
        showShare(d.share_type === 'nginx' ? d : await api.verifyShare(code) as ShareMeta);
      })
      .catch((error: unknown) => setError(getErrorMessage(error, 'Failed to load share.')))
      .finally(() => setLoading(false));
  }, [code, showShare]);

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

        {/* Snapshot shares: DNS, WHOIS, My IP, ASN and the rest */}
        {shareMeta && snapshot !== null && isSnapshotTool(shareMeta.share_type) && (
          <SharedSnapshot tool={shareMeta.share_type} snapshot={snapshot} title={shareMeta.title} code={code} />
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
  share_type?: string;
  title?: string;
  has_password?: boolean;
  password_required?: boolean;
  expires_at?: string;
  created_at?: string;
  download_url?: string;
  r2_key?: string;
  source_url?: string;
  subject?: string;
  checked_at_utc?: string;
  snapshot?: unknown;
}

interface GistFetchResponse {
  content?: string;
  error?: string;
}

interface ParseResult {
  ips: unknown[];
  logEntries: unknown[];
  validLines: number;
}

interface LogParserRuntime {
  parseIPs: (text: string, options?: { skip403?: boolean; skipInternal?: boolean }) => ParseResult;
}

interface AnalyzerRuntime {
  enrichLogEntries: (entries: unknown[]) => void;
  analyzeEnhancedLogs: (entries: unknown[]) => unknown;
}

interface DashboardRuntime {
  render: (
    data: unknown,
    logText: string,
    parseResult: ParseResult,
    options: { source: 'gist'; gistUrl: string; skip403?: boolean; skipInternal?: boolean }
  ) => void;
}

interface AnalysisWindow extends Window {
  BotDetector?: { init: () => Promise<void> };
  GeoIP?: GeoIPRuntime;
  LogParser?: LogParserRuntime;
  Analyzer?: AnalyzerRuntime;
  Dashboard?: DashboardRuntime;
}

function getErrorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}
