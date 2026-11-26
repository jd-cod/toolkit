'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace, { ToolEmptyState } from '@/components/ToolWorkspace';
import WhoisSnapshotView from '@/components/WhoisSnapshotView';
import { api, WhoisSnapshot } from '@/lib/api';
import { normalizeDomainInput, normalizeWhoisSnapshot } from '@/lib/whois';

export default function WhoisPage() {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [snapshot, setSnapshot] = useState<WhoisSnapshot | null>(null);
  const [error, setError] = useState('');
  const prefillApplied = useRef(false);

  const doLookup = useCallback(async (value?: string) => {
    const normalized = normalizeDomainInput(value || domain);
    if (!normalized) return;

    setDomain(normalized);
    setLoading(true);
    setError('');
    setSnapshot(null);
    try {
      const result = await api.lookupWhois(normalized);
      setSnapshot(normalizeWhoisSnapshot(result));
    } catch (lookupError: unknown) {
      setError(getErrorMessage(lookupError, 'WHOIS lookup failed.'));
    } finally {
      setLoading(false);
    }
  }, [domain]);

  useEffect(() => {
    if (prefillApplied.current) return;
    prefillApplied.current = true;

    const params = new URLSearchParams(window.location.search);
    const domainParam = params.get('domain');
    if (domainParam) {
      const normalized = normalizeDomainInput(domainParam);
      setDomain(normalized);
      void doLookup(normalized);
    }
  }, [doLookup]);

  return (
    <>
      <Navbar />
      <main className="main-content">
        <div className="signal-tool-heading tool-hero-compact">
          <div className="tool-hero-icon" style={{ background: 'linear-gradient(135deg, #38bdf8, #0ea5e9)' }}><i className="bi bi-person-vcard-fill"></i></div>
          <h1 className="hero-title">WHOIS Lookup</h1>
          <p>Inspect domain registration details, registrar metadata, nameservers, DNSSEC signals, expiry risk, and the raw RDAP or WHOIS record from our server.</p>
        </div>

        <ToolWorkspace tool="whois">
        <div className="input-card" style={{ padding: '28px', marginBottom: 24 }}>
          <div style={{ display: 'flex', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
            <input
              type="text"
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              onKeyDown={(event) => event.key === 'Enter' && void doLookup()}
              placeholder="e.g. openai.com"
              className="log-textarea"
              style={{ flex: 1, minWidth: 240, padding: '12px 16px', height: 'auto', fontSize: '1rem' }}
            />
            <button onClick={() => void doLookup()} disabled={loading} className="btn-analyze" style={{ padding: '12px 28px', whiteSpace: 'nowrap' }}>
              <i className={loading ? 'bi bi-hourglass-split' : 'bi bi-search'} style={{ marginRight: 4 }}></i>
              {loading ? 'Looking up...' : 'Lookup'}
            </button>
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.82rem', margin: 0 }}>
            Input accepts a bare domain or URL. The server normalizes it, tries RDAP first, and falls back to the native WHOIS client when RDAP is unavailable.
          </p>
        </div>

        {error && (
          <div className="alert-custom" style={{ maxWidth: 1100, margin: '30px auto 0', padding: '16px 20px' }}>
            <i className="bi bi-exclamation-triangle" style={{ marginRight: 8 }}></i>
            {error}
          </div>
        )}

        {snapshot && (
          <div style={{ maxWidth: 1100, margin: '30px auto 0' }}>
            <WhoisSnapshotView snapshot={snapshot} mode="live" />
          </div>
        )}
        {!loading && !snapshot && !error && <ToolEmptyState title="Explore a domain’s registration">Enter a domain to inspect its registrar, registration timeline, status, and nameservers.</ToolEmptyState>}
        </ToolWorkspace>
      </main>
      <Footer />
    </>
  );
}

function getErrorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}
