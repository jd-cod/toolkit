'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace, { ToolEmptyState } from '@/components/ToolWorkspace';
import type { SSLResult } from '@/lib/tool-results';
import { api } from '@/lib/api';
import { exportToCSV } from '@/lib/csv-utils';
import { useClipboard } from '@/hooks/useClipboard';

export default function SSLPage() {
  const { copy, isCopied } = useClipboard();
  const [domain, setDomain] = useState('');
  const [port, setPort] = useState('443');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SSLResult | null>(null);
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
      else setResult(data);
    } catch (e: unknown) { setError(e instanceof Error ? e.message : 'Check failed.'); }
    setLoading(false);
  }, [domain, port]);

  const gradeColor = (g: string) => g?.startsWith('A') ? 'var(--accent-green)' : g === 'B' ? 'var(--accent-amber)' : 'var(--accent-red)';
  const expiryColor = (d: number) => d < 0 ? 'var(--accent-red)' : d < 7 ? 'var(--accent-red)' : d <= 30 ? 'var(--accent-amber)' : 'var(--accent-green)';
  const fmtDate = (s: string) => { try { return new Date(s).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }); } catch { return s; } };

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

        {result && !result.error && (
          <>
            <div className="glass" style={{ padding: '1rem', marginBottom: '1.5rem', display: 'flex', gap: '0.75rem', justifyContent: 'center' }}>
              <button
                onClick={() => exportToCSV(result, `ssl-report-${result.domain}`)}
                className="btn-secondary"
                style={{ padding: '8px 16px', borderRadius: 10, cursor: 'pointer', fontSize: '0.88rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 6 }}
              >
                <i className="bi bi-download"></i> Export CSV
              </button>
              <button
                onClick={() => void copy(`Domain: ${result.domain}\nIssuer: ${result.issuer || 'N/A'}\nValid Until: ${result.not_after || 'N/A'}\nGrade: ${result.grade || 'N/A'}\nProtocol: ${result.protocol || 'N/A'}`, 'summary')}
                className="btn-secondary"
                style={{ padding: '8px 16px', borderRadius: 10, cursor: 'pointer', fontSize: '0.88rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 6 }}
              >
                <i className={isCopied('summary') ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i> {isCopied('summary') ? 'Copied Details!' : 'Copy Summary'}
              </button>
            </div>
            {/* Validation Checks */}
            <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
              <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
                <i className="bi bi-patch-check-fill" style={{ color: 'var(--accent-green)', marginRight: '0.5rem' }}></i>Validation Checks
              </div>
              <div style={{ padding: '1rem 1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <Check ok={!!result.dns?.ip} text={`${result.domain} resolves to ${result.dns?.ip || 'N/A'}`} />
                <Check ok={result.server_type?.server !== 'Unknown'} text={`Server: ${result.server_type?.server || 'Unknown'}`} />
                <Check ok={result.is_trusted} text={result.is_trusted ? 'Certificate is trusted' : result.is_self_signed ? 'Self-signed certificate' : 'Missing intermediate certificates'} />
                <Check ok={!result.is_expired} text={result.is_expired ? 'Certificate EXPIRED' : `Expires in ${result.days_remaining} days`} />
                <Check ok={result.hostname_match} text={result.hostname_match ? 'Hostname matches certificate' : 'Hostname does NOT match'} />
                <Check ok={!!result.security_headers?.hsts} text={result.security_headers?.hsts ? 'HSTS enabled' : 'HSTS not enabled'} />
              </div>
            </div>

            {/* Stats */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
              <div className="glass" style={{ padding: '1rem', textAlign: 'center', borderTop: `3px solid ${expiryColor(result.days_remaining)}` }}>
                <div style={{ fontSize: '1.8rem', fontWeight: 800, color: expiryColor(result.days_remaining) }}>{result.days_remaining}</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Days Until Expiry</div>
              </div>
              <div className="glass" style={{ padding: '1rem', textAlign: 'center', borderTop: `3px solid ${gradeColor(result.grade)}` }}>
                <div style={{ fontSize: '1.8rem', fontWeight: 800, color: gradeColor(result.grade) }}>{result.grade}</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Security Grade</div>
              </div>
              <div className="glass" style={{ padding: '1rem', textAlign: 'center', borderTop: '3px solid var(--accent-cyan)' }}>
                <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>{result.protocol}</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Protocol</div>
              </div>
              <div className="glass" style={{ padding: '1rem', textAlign: 'center', borderTop: '3px solid var(--accent-purple)' }}>
                <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-purple)', fontFamily: 'var(--font-mono)' }}>{result.key_type} {result.key_size}</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Key Type</div>
              </div>
            </div>

            {/* Certificate Details Table */}
            <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
              <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600, display: 'flex', justifyContent: 'space-between' }}>
                <span><i className="bi bi-shield-check" style={{ marginRight: '0.5rem' }}></i>Certificate Details</span>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{result.response_time_ms}ms</span>
              </div>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}><tbody>
                <DetailRow label="Subject" value={result.subject} icon="person-badge" />
                <DetailRow label="Organization" value={result.subject_org || '—'} icon="building" />
                <DetailRow label="Issuer" value={result.issuer} icon="award" />
                <DetailRow label="Issuer Org" value={result.issuer_org || '—'} icon="building" />
                <DetailRow label="Serial Number" value={result.serial_number} icon="hash" />
                <DetailRow label="Valid From" value={fmtDate(result.not_before)} icon="calendar-check" />
                <DetailRow label="Valid Until" value={fmtDate(result.not_after)} icon="calendar-x" />
                <DetailRow label="Fingerprint (SHA-256)" value={result.fingerprint_sha256} icon="fingerprint" />
              </tbody></table>
            </div>

            {/* SANs */}
            {result.san_names?.length > 0 && (
              <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
                <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
                  <i className="bi bi-diagram-2" style={{ marginRight: '0.5rem' }}></i>Subject Alternative Names ({result.san_names.length})
                </div>
                <div style={{ padding: '1rem 1.25rem', display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                  {result.san_names.map((s: string) => (
                    <span key={s} className="tool-tag" style={{ fontSize: '0.78rem', padding: '0.3rem 0.7rem' }}>{s}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Chain */}
            {result.chain?.length > 0 && (
              <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
                <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
                  <i className="bi bi-diagram-3" style={{ marginRight: '0.5rem' }}></i>Certificate Chain ({result.chain.length})
                </div>
                <div style={{ padding: '1.25rem' }}>
                  {result.chain.map((cert, i) => {
                    const typeLabel = i === 0 ? 'Server' : i === result.chain.length - 1 ? 'Root' : 'Intermediate';
                    const color = i === 0 ? '#6366f1' : i === result.chain.length - 1 ? '#10b981' : '#06b6d4';
                    return (
                      <div key={i} style={{ display: 'flex', gap: '1rem', marginBottom: i < result.chain.length - 1 ? '1rem' : 0 }}>
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 50 }}>
                          <div style={{ width: 40, height: 40, borderRadius: 10, background: `${color}1a`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                            <i className="bi bi-lock-fill" style={{ color, fontSize: '1.1rem' }}></i>
                          </div>
                          <div style={{ fontSize: '0.6rem', fontWeight: 700, color, textTransform: 'uppercase', marginTop: '0.25rem' }}>{typeLabel}</div>
                          {i < result.chain.length - 1 && <div style={{ flex: 1, width: 2, background: `linear-gradient(to bottom, ${color}, transparent)`, marginTop: '0.25rem', minHeight: 20 }}></div>}
                        </div>
                        <div style={{ flex: 1, border: '1px solid var(--border-color)', borderRadius: 12, padding: '1rem 1.25rem' }}>
                          <div style={{ fontWeight: 700, marginBottom: '0.5rem' }}>{cert.subject} <span style={{ background: `${color}1a`, color, fontSize: '0.65rem', fontWeight: 700, padding: '2px 8px', borderRadius: 4, textTransform: 'uppercase', marginLeft: '0.5rem' }}>{typeLabel}</span></div>
                          <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.25rem 1rem' }}>
                            {cert.subject_org && <div><strong>Org:</strong> {cert.subject_org}</div>}
                            <div><strong>Valid:</strong> {fmtDate(cert.not_before)} — {fmtDate(cert.not_after)}</div>
                            <div><strong>Issuer:</strong> {cert.issuer}</div>
                            {cert.key_type && <div><strong>Key:</strong> {cert.key_type} {cert.key_size}</div>}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </>
        )}

        {result?.error && (
          <div className="glass" style={{ padding: '1rem 1.5rem', borderColor: 'rgba(239,68,68,0.3)', color: 'var(--accent-red)' }}>⚠️ {result.error}</div>
        )}
        </ToolWorkspace>
      </main>
      <Footer />
    </>
  );
}

function Check({ ok, text }: { ok: boolean; text: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
      <div style={{ width: 28, height: 28, borderRadius: '50%', background: ok ? 'rgba(16,185,129,0.12)' : 'rgba(239,68,68,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
        <i className={`bi ${ok ? 'bi-check-circle-fill' : 'bi-x-circle-fill'}`} style={{ color: ok ? 'var(--accent-green)' : 'var(--accent-red)', fontSize: '0.95rem' }}></i>
      </div>
      <span style={{ fontSize: '0.9rem', color: ok ? 'var(--accent-green)' : 'var(--accent-red)', fontWeight: 500 }}>{text}</span>
    </div>
  );
}

function DetailRow({ label, value, icon }: { label: string; value: string; icon: string }) {
  return (
    <tr style={{ borderBottom: '1px solid rgba(30,34,53,0.5)' }}>
      <td style={{ padding: '0.625rem 1rem', color: 'var(--text-muted)', fontSize: '0.85rem', width: '35%' }}><i className={`bi bi-${icon}`} style={{ marginRight: '0.5rem', opacity: 0.5 }}></i>{label}</td>
      <td style={{ padding: '0.625rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.82rem', wordBreak: 'break-all' }}>{value || 'N/A'}</td>
    </tr>
  );
}
