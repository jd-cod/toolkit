'use client';

import ResultActions, { ResultActionButton } from '@/components/share/ResultActions';
import { useClipboard } from '@/hooks/useClipboard';
import { snapshotShare } from '@/lib/api';
import { fileSlug } from '@/lib/download';
import { buildSslReportHtml, buildSslSummary, type SslSnapshot } from '@/lib/ssl';

const gradeColor = (g: string) => g?.startsWith('A') ? 'var(--accent-green)' : g === 'B' ? 'var(--accent-amber)' : 'var(--accent-red)';
const expiryColor = (d: number) => d < 0 ? 'var(--accent-red)' : d < 7 ? 'var(--accent-red)' : d <= 30 ? 'var(--accent-amber)' : 'var(--accent-green)';
const fmtDate = (s: string) => { try { return new Date(s).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }); } catch { return s; } };

/** Certificate check results, used by the live SSL page and by shared links. */
export default function SslResultView({ result, mode }: { result: SslSnapshot; mode: 'live' | 'shared' }) {
  const { copy, isCopied } = useClipboard();
  const filename = `ssl-report-${fileSlug(result.domain, 'certificate')}`;

  return (
    <>
      <div style={{ marginBottom: '1.5rem' }}>
        <ResultActions
          className="signal-actions-end"
          share={mode === 'live' ? {
            heading: 'Share Certificate Report',
            title: `${result.domain} SSL Certificate Report`,
            create: snapshotShare('ssl', result.domain, () => result, result.checked_at_utc),
          } : undefined}
          html={{ filename, build: () => buildSslReportHtml(result) }}
          csv={{ filename, rows: () => result }}
        >
          <ResultActionButton
            icon={isCopied('summary') ? 'check-lg' : 'clipboard'}
            onClick={() => void copy(buildSslSummary(result), 'summary')}
          >
            {isCopied('summary') ? 'Copied' : 'Copy Summary'}
          </ResultActionButton>
        </ResultActions>
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
