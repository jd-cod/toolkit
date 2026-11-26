'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace, { ToolEmptyState } from '@/components/ToolWorkspace';
import AsnSnapshotView from '@/components/AsnSnapshotView';
import { api } from '@/lib/api';
import { normalizeAsnSnapshot, ASNResult } from '@/lib/asn';
import { useClipboard } from '@/hooks/useClipboard';

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
  const { copy, isCopied } = useClipboard();
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ASNResult | null>(null);
  const [error, setError] = useState('');

  // Share Modal State
  const [shareModalOpen, setShareModalOpen] = useState(false);
  const [shareTitle, setShareTitle] = useState('');
  const [shareExpiry, setShareExpiry] = useState('never');
  const [sharePassword, setSharePassword] = useState('');
  const [shareLoading, setShareLoading] = useState(false);
  const [shareError, setShareError] = useState('');
  const [shareUrl, setShareUrl] = useState('');

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

  function openShareModal() {
    if (!result) return;
    setShareTitle(`AS${result.asn} - ${result.holder || result.name || 'ASN'} Intelligence Snapshot`);
    setShareExpiry('never');
    setSharePassword('');
    setShareError('');
    setShareUrl('');
    setShareModalOpen(true);
  }

  async function submitShare() {
    if (!result) return;
    setShareLoading(true);
    setShareError('');
    try {
      const res = await api.createAsnShare({
        title: shareTitle.trim() || `AS${result.asn} Snapshot`,
        asn: result.asn,
        expiry: shareExpiry,
        password: sharePassword.trim(),
        checked_at_utc: result.checked_at_utc,
        snapshot: result,
      });
      setShareUrl(`${window.location.origin}/s/${res.code}`);
    } catch (err: unknown) {
      setShareError(err instanceof Error ? err.message : 'Failed to create share link.');
    } finally {
      setShareLoading(false);
    }
  }

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
              onShare={openShareModal}
              onRerun={lookupASN}
            />
          </div>
        )}
        </ToolWorkspace>
      </main>
      <Footer />

      {/* ─── Share Modal ─── */}
      {shareModalOpen && result && (
        <div
          onClick={e => {
            if (e.target === e.currentTarget) setShareModalOpen(false);
          }}
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 10000,
            background: 'rgba(7,8,15,0.75)',
            backdropFilter: 'blur(6px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '24px',
          }}
        >
          <div
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border-color)',
              borderRadius: '16px',
              padding: '2rem',
              maxWidth: '500px',
              width: '100%',
              boxShadow: '0 24px 80px rgba(0,0,0,0.5)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.25rem', color: 'var(--text-primary)' }}>
                <i className="bi bi-share-fill" style={{ color: 'var(--accent-cyan)', marginRight: '0.5rem' }}></i>
                Share ASN Snapshot
              </h3>
              <button
                onClick={() => setShareModalOpen(false)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.2rem', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            {!shareUrl ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '0.4rem', fontWeight: 600 }}>
                    Snapshot Title:
                  </label>
                  <input
                    type="text"
                    value={shareTitle}
                    onChange={e => setShareTitle(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.65rem 0.9rem',
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-color)',
                      borderRadius: 'var(--radius-sm)',
                      color: 'var(--text-primary)',
                      fontSize: '0.9rem',
                    }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '0.4rem', fontWeight: 600 }}>
                    Link Expiration:
                  </label>
                  <select
                    value={shareExpiry}
                    onChange={e => setShareExpiry(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.65rem 0.9rem',
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-color)',
                      borderRadius: 'var(--radius-sm)',
                      color: 'var(--text-primary)',
                      fontSize: '0.9rem',
                    }}
                  >
                    <option value="never">Never expire</option>
                    <option value="24h">24 Hours</option>
                    <option value="7d">7 Days</option>
                    <option value="30d">30 Days</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '0.4rem', fontWeight: 600 }}>
                    Password Protection (Optional):
                  </label>
                  <input
                    type="password"
                    value={sharePassword}
                    onChange={e => setSharePassword(e.target.value)}
                    placeholder="Leave blank for public access"
                    style={{
                      width: '100%',
                      padding: '0.65rem 0.9rem',
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-color)',
                      borderRadius: 'var(--radius-sm)',
                      color: 'var(--text-primary)',
                      fontSize: '0.9rem',
                    }}
                  />
                </div>

                {shareError && (
                  <div style={{ color: 'var(--accent-red)', fontSize: '0.85rem', padding: '0.5rem', background: 'rgba(239,68,68,0.1)', borderRadius: '4px' }}>
                    {shareError}
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                  <button onClick={() => setShareModalOpen(false)} className="btn-secondary">
                    Cancel
                  </button>
                  <button onClick={submitShare} disabled={shareLoading} className="btn-primary">
                    {shareLoading ? 'Creating Link...' : 'Generate Share Link'}
                  </button>
                </div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                <div style={{ textAlign: 'center', padding: '1rem 0' }}>
                  <div style={{ fontSize: '2.5rem', color: 'var(--accent-green)', marginBottom: '0.5rem' }}>
                    <i className="bi bi-check-circle-fill"></i>
                  </div>
                  <h4 style={{ margin: '0 0 0.5rem 0', fontSize: '1.1rem' }}>Share Link Ready!</h4>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: 0 }}>
                    Anyone with this link can view the frozen AS{result.asn} snapshot.
                  </p>
                </div>

                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <input
                    type="text"
                    readOnly
                    value={shareUrl}
                    style={{
                      flex: 1,
                      padding: '0.65rem 0.9rem',
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-color)',
                      borderRadius: 'var(--radius-sm)',
                      color: 'var(--accent-cyan)',
                      fontSize: '0.9rem',
                      fontFamily: 'var(--font-mono)',
                    }}
                  />
                  <button onClick={() => void copy(shareUrl, 'share')} className="btn-primary" style={{ whiteSpace: 'nowrap' }}>
                    <i className={`bi ${isCopied('share') ? 'bi-check-lg' : 'bi-clipboard'}`}></i> {isCopied('share') ? 'Copied!' : 'Copy'}
                  </button>
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
                  <button onClick={() => setShareModalOpen(false)} className="btn-secondary">
                    Close
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
