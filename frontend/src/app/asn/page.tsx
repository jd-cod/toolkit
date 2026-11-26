'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace, { ToolEmptyState } from '@/components/ToolWorkspace';
import AsnSnapshotView from '@/components/AsnSnapshotView';
import { api } from '@/lib/api';
import { normalizeAsnSnapshot, ASNResult } from '@/lib/asn';

const QUICK_ASNS = [
  { label: 'Cloudflare', asn: '13335' },
  { label: 'Google', asn: '15169' },
  { label: 'Amazon AWS', asn: '16509' },
  { label: 'Microsoft', asn: '8075' },
  { label: 'Hetzner', asn: '24940' },
  { label: 'Fastly', asn: '54113' },
  { label: 'DigitalOcean', asn: '14061' },
  { label: 'OVHcloud', asn: '16276' },
];

export default function ASNPage() {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ASNResult | null>(null);
  const [error, setError] = useState('');
  const prefillApplied = useRef(false);

  const lookupASN = useCallback(async (value?: string) => {
    const target = (value || input).trim();
    if (!target) return;

    setInput(target);
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const data = await api.lookupASN(target);
      if (data.error) {
        setError(String(data.error));
      } else {
        const normalized = normalizeAsnSnapshot(data);
        setResult(normalized);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'ASN Lookup failed.');
    } finally {
      setLoading(false);
    }
  }, [input]);

  useEffect(() => {
    if (prefillApplied.current) return;
    prefillApplied.current = true;

    const params = new URLSearchParams(window.location.search);
    const asnParam = params.get('asn') || params.get('q') || params.get('domain') || params.get('ip');
    if (asnParam) {
      setInput(asnParam);
      void lookupASN(asnParam);
    }
  }, [lookupASN]);

  return (
    <>
      <Navbar />
      <main className="main-content">
        <div className="signal-tool-heading tool-hero-compact">
          <div className="tool-hero-icon" style={{ background: 'linear-gradient(135deg, #06b6d4, #0891b2)' }}><i className="bi bi-diagram-3-fill"></i></div>
          <h1 className="hero-title">ASN to IPs Converter & BGP Intelligence</h1>
          <p>Discover announced IPv4/IPv6 prefixes, calculate CIDR supernets, generate firewall rules (Nginx, iptables, UFW, Cisco ACL), test IP containment, and analyze BGP connectivity.</p>
        </div>

        <ToolWorkspace tool="asn">
        {/* ─── Search Card ─── */}
        <div className="input-card glass" style={{ marginBottom: '1.5rem', padding: '1.5rem' }}>
          <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
            <input
              type="text"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && void lookupASN()}
              placeholder="e.g. AS13335, 13335, Cloudflare, 1.1.1.1, or google.com"
              style={{
                flex: 1,
                minWidth: '260px',
                padding: '0.85rem 1.1rem',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-color)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-primary)',
                fontSize: '1rem',
                fontFamily: 'var(--font-mono)',
              }}
            />
            <button
              onClick={() => void lookupASN()}
              disabled={loading}
              className="btn-primary"
              style={{ padding: '0.85rem 2rem', whiteSpace: 'nowrap', fontSize: '0.95rem' }}
            >
              <i className={loading ? 'bi bi-hourglass-split' : 'bi bi-search'} style={{ marginRight: '0.4rem' }}></i>
              {loading ? 'Discovering...' : 'Lookup ASN'}
            </button>
          </div>

          {/* Quick Select Chips */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600 }}>Quick ASNs:</span>
            {QUICK_ASNS.map(item => (
              <button
                key={item.asn}
                type="button"
                onClick={() => {
                  setInput(item.asn);
                  void lookupASN(item.asn);
                }}
                style={{
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '999px',
                  padding: '0.2rem 0.65rem',
                  fontSize: '0.78rem',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                {item.label} (AS{item.asn})
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="alert-custom glass" style={{ maxWidth: '1100px', margin: '1.5rem auto', padding: '1rem 1.5rem', borderColor: 'rgba(239,68,68,0.4)', color: 'var(--accent-red)' }}>
            <i className="bi bi-exclamation-triangle-fill" style={{ marginRight: '0.5rem' }}></i>
            {error}
          </div>
        )}

        {loading && <p role="status" className="signal-tool-empty">Looking up network announcements and BGP details…</p>}
        {!loading && !result && !error && <ToolEmptyState title="Explore an autonomous system">Look up a network to inspect its announced prefixes, BGP connectivity, and export options.</ToolEmptyState>}
        {result && (
          <div style={{ maxWidth: '1100px', margin: '1.5rem auto 3rem' }}>
            <AsnSnapshotView
              snapshot={result}
              mode="live"
              onRerun={lookupASN}
            />
          </div>
        )}
        </ToolWorkspace>
      </main>
      <Footer />
    </>
  );
}
