'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace, { ToolEmptyState } from '@/components/ToolWorkspace';
import WhoisSnapshotView from '@/components/WhoisSnapshotView';
import { api, WhoisSnapshot } from '@/lib/api';
import { formatWhoisDate, normalizeDomainInput, normalizeWhoisSnapshot } from '@/lib/whois';
import { useClipboard } from '@/hooks/useClipboard';

export default function WhoisPage() {
  const { copy, isCopied } = useClipboard();
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [snapshot, setSnapshot] = useState<WhoisSnapshot | null>(null);
  const [error, setError] = useState('');
  const [shareModalOpen, setShareModalOpen] = useState(false);
  const [shareTitle, setShareTitle] = useState('');
  const [shareExpiry, setShareExpiry] = useState('never');
  const [sharePassword, setSharePassword] = useState('');
  const [shareLoading, setShareLoading] = useState(false);
  const [shareError, setShareError] = useState('');
  const [shareUrl, setShareUrl] = useState('');
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

  function openShareModal() {
    if (!snapshot) return;
    setShareTitle(`${snapshot.domain} WHOIS Snapshot`);
    setShareExpiry('never');
    setSharePassword('');
    setShareError('');
    setShareUrl('');
    setShareModalOpen(true);
  }

  async function submitShare() {
    if (!snapshot) return;
    setShareLoading(true);
    setShareError('');
    try {
      const result = await api.createWhoisShare({
        title: shareTitle.trim() || `${snapshot.domain} WHOIS Snapshot`,
        domain: snapshot.domain,
        expiry: shareExpiry,
        password: sharePassword.trim(),
        checked_at_utc: snapshot.checked_at_utc,
        snapshot,
      });
      setShareUrl(`${window.location.origin}/s/${result.code}`);
    } catch (shareErr: unknown) {
      setShareError(getErrorMessage(shareErr, 'Failed to create share link.'));
    } finally {
      setShareLoading(false);
    }
  }

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
            <WhoisSnapshotView snapshot={snapshot} mode="live" onShare={openShareModal} />
          </div>
        )}
        {!loading && !snapshot && !error && <ToolEmptyState title="Explore a domain’s registration">Enter a domain to inspect its registrar, registration timeline, status, and nameservers.</ToolEmptyState>}
        </ToolWorkspace>
      </main>
      <Footer />

      {shareModalOpen && snapshot && (
        <div
          onClick={(event) => {
            if (event.target === event.currentTarget) setShareModalOpen(false);
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
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-color)',
            borderRadius: 18,
            padding: '32px 36px',
            maxWidth: 480,
            width: '100%',
            boxShadow: '0 24px 80px rgba(0,0,0,0.5)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ width: 38, height: 38, borderRadius: 10, background: 'rgba(56,189,248,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#38bdf8', fontSize: '1.1rem' }}>
                  <i className="bi bi-share-fill"></i>
                </div>
                <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>Share WHOIS Snapshot</h3>
              </div>
              <button onClick={() => setShareModalOpen(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.2rem', cursor: 'pointer' }}>
                <i className="bi bi-x-lg"></i>
              </button>
            </div>

            {shareLoading ? (
              <div style={{ textAlign: 'center', padding: '20px 0' }}>
                <div style={{ width: 40, height: 40, border: '3px solid var(--border-color)', borderTopColor: '#38bdf8', borderRadius: '50%', animation: 'spin 1s linear infinite', margin: '0 auto 12px' }}></div>
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
                    <i className={isCopied('share') ? 'bi bi-check-lg' : 'bi bi-clipboard'} style={{ marginRight: 4 }}></i>
                    {isCopied('share') ? 'Copied!' : 'Copy'}
                  </button>
                </div>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center', margin: 0 }}>
                  Checked at {formatWhoisDate(snapshot.checked_at_utc)}.
                </p>
                <button
                  onClick={() => {
                    setShareUrl('');
                    setShareError('');
                  }}
                  style={{ width: '100%', marginTop: 16, padding: 10, borderRadius: 10, border: '1px solid var(--border-color)', background: 'none', color: 'var(--text-secondary)', fontSize: '0.85rem', cursor: 'pointer' }}
                >
                  Create Another Link
                </button>
              </div>
            ) : (
              <div>
                <div style={{ marginBottom: 16 }}>
                  <label style={modalLabelStyle}>Title</label>
                  <input value={shareTitle} onChange={(event) => setShareTitle(event.target.value)} style={modalInputStyle} />
                </div>
                <div style={{ marginBottom: 16 }}>
                  <label style={modalLabelStyle}>Link Expiry</label>
                  <select value={shareExpiry} onChange={(event) => setShareExpiry(event.target.value)} style={modalInputStyle}>
                    <option value="never">Never expires</option>
                    <option value="24h">24 hours</option>
                    <option value="7d">7 days</option>
                    <option value="30d">30 days</option>
                  </select>
                </div>
                <div style={{ marginBottom: 16 }}>
                  <label style={modalLabelStyle}>Password</label>
                  <input type="password" value={sharePassword} onChange={(event) => setSharePassword(event.target.value)} placeholder="Leave blank for public link" style={modalInputStyle} />
                </div>
                <div style={{ marginBottom: 16, color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
                  <strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Checked At:</strong>{' '}
                  <span style={{ fontFamily: 'var(--font-mono)' }}>{formatWhoisDate(snapshot.checked_at_utc)}</span>
                </div>
                {shareError && (
                  <div style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 8, padding: '10px 14px', color: '#f87171', fontSize: '0.82rem', marginBottom: 12 }}>
                    {shareError}
                  </div>
                )}
                <button
                  onClick={() => void submitShare()}
                  style={{ width: '100%', padding: 12, borderRadius: 10, border: 'none', background: 'var(--gradient-primary)', color: '#fff', fontWeight: 700, fontSize: '0.92rem', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
                >
                  <i className="bi bi-link-45deg"></i>
                  Generate Share Link
                </button>
              </div>
            )}
          </div>
        </div>
      )}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </>
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

function getErrorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}
