'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace, { ToolEmptyState } from '@/components/ToolWorkspace';
import SslResultView from '@/components/SslResultView';
import { api } from '@/lib/api';
import type { SslSnapshot } from '@/lib/ssl';

export default function SSLPage() {
  const [domain, setDomain] = useState('');
  const [port, setPort] = useState('443');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SslSnapshot | null>(null);
  const [error, setError] = useState('');
  const prefillApplied = useRef(false);

  const doCheck = useCallback(async (domainOverride?: string, portOverride?: string) => {
    const nextDomain = (domainOverride ?? domain).trim();
    const nextPort = portOverride ?? port;
    if (!nextDomain) return;
    setLoading(true); setError(''); setResult(null);
    try {
      const data = await api.checkSSL(nextDomain, parseInt(nextPort));
      if (data.error && !data.dns) setError(data.error);
      else setResult({ ...data, port: parseInt(nextPort, 10) || 443, checked_at_utc: new Date().toISOString() });
    } catch (e: unknown) { setError(e instanceof Error ? e.message : 'Check failed.'); }
    setLoading(false);
  }, [domain, port]);

  useEffect(() => {
    if (prefillApplied.current) return;
    const params = new URLSearchParams(window.location.search);
    const queryDomain = params.get('domain');
    const queryPort = params.get('port');
    if (!queryDomain) return;
    const timer = window.setTimeout(() => {
      prefillApplied.current = true;
      setDomain(queryDomain);
      if (queryPort) setPort(queryPort);
      void doCheck(queryDomain, queryPort || '443');
    }, 0);
    return () => window.clearTimeout(timer);
  }, [doCheck]);

  return (
    <>
      <Navbar />
      <main className="main-content">
        <div className="signal-tool-heading tool-hero-compact">
          <div className="tool-hero-icon" style={{ background: 'linear-gradient(135deg, #ef4444, #ef4444cc)' }}><i className="bi bi-shield-lock-fill"></i></div>
          <h1 className="hero-title">SSL Certificate Checker</h1>
          <p style={{ color: 'var(--text-secondary)' }}>Inspect certificate, chain, security headers, and trust signals.</p>
        </div>

        <ToolWorkspace tool="ssl">
        <div className="glass" style={{ padding: '2rem', marginBottom: '2rem' }}>
          <div className="signal-query-row">
            <input type="text" value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === 'Enter' && doCheck()} placeholder="example.com" style={{ flex: 1, padding: '0.75rem 1rem', background: 'var(--bg-input)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', fontSize: '0.95rem' }} />
            <input type="text" value={port} onChange={e => setPort(e.target.value)} placeholder="443" style={{ width: 80, padding: '0.75rem', background: 'var(--bg-input)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', fontSize: '0.9rem', textAlign: 'center', fontFamily: 'var(--font-mono)' }} />
            <button onClick={() => void doCheck()} disabled={loading} className="btn-primary">{loading ? '⏳ Checking...' : '🔒 Check'}</button>
          </div>
        </div>

        {loading && (
          <div role="status" className="glass" style={{ textAlign: 'center', padding: '4rem 2rem' }}>
            <div style={{ fontSize: '2.5rem', marginBottom: '1rem', animation: 'iconPulse 1.5s infinite' }}><i className="bi bi-shield-lock-fill" style={{ color: 'var(--accent-primary)' }}></i></div>
            <h3 style={{ fontWeight: 600, marginBottom: '0.5rem' }}>Checking SSL Certificate</h3>
            <p style={{ color: 'var(--text-muted)' }}>Performing DNS resolution, server detection, and TLS handshake...</p>
          </div>
        )}

        {error && <div role="alert" className="glass" style={{ padding: '1rem 1.5rem', borderColor: 'rgba(239,68,68,0.3)', color: 'var(--accent-red)' }}>⚠️ {error}</div>}
        {!loading && !result && !error && <ToolEmptyState title="Inspect a certificate">Enter a hostname and TLS port to review trust, expiry, connection details, and the certificate chain.</ToolEmptyState>}

        {result && !result.error && <SslResultView result={result} mode="live" />}

        {result?.error && (
          <div className="glass" style={{ padding: '1rem 1.5rem', borderColor: 'rgba(239,68,68,0.3)', color: 'var(--accent-red)' }}>⚠️ {result.error}</div>
        )}
        </ToolWorkspace>
      </main>
      <Footer />
    </>
  );
}
