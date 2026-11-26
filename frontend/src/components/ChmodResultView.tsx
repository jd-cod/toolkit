'use client';

import ResultActions from '@/components/share/ResultActions';
import { useClipboard } from '@/hooks/useClipboard';
import { snapshotShare } from '@/lib/api';
import {
  buildChmodReportHtml,
  chmodCsvRows,
  chmodWarnings,
  describePerms,
  parseOctalMode,
  toSymbolic,
  type ChmodSnapshot,
} from '@/lib/chmod';

/** Permission mode breakdown, used by the live calculator and by shared links. */
export default function ChmodResultView({ octal, mode }: { octal: string; mode: 'live' | 'shared' }) {
  const { copy, isCopied } = useClipboard();
  const parsed = parseOctalMode(octal);
  if (!parsed) {
    return <div className="glass" style={{ padding: '1rem 1.5rem', color: 'var(--accent-red)' }}>Not a valid octal permission mode.</div>;
  }

  const { bits, special } = parsed;
  const sym = toSymbolic(bits, special);
  const warnings = chmodWarnings(bits, special);
  const filename = `chmod-${octal}`;
  const snapshot = (): ChmodSnapshot => ({ octal, checked_at_utc: new Date().toISOString() });

  return (
    <>
      <div style={{ marginBottom: '1.5rem' }}>
        <ResultActions
          className="signal-actions-end"
          share={mode === 'live' ? {
            heading: 'Share Permission Mode',
            title: `chmod ${octal} (${sym})`,
            create: snapshotShare('chmod', octal, snapshot),
          } : undefined}
          html={{ filename, build: () => buildChmodReportHtml(octal, new Date().toISOString()) }}
          csv={{ filename, rows: () => chmodCsvRows(octal) }}
        />
      </div>

      {/* Output Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        <div className="glass" style={{ padding: '1rem', textAlign: 'center', borderTop: '3px solid var(--accent-cyan)' }}>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>{octal}</div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Octal</div>
        </div>
        <div className="glass" style={{ padding: '1rem', textAlign: 'center', borderTop: '3px solid var(--accent-primary)' }}>
          <div style={{ fontSize: '1.3rem', fontWeight: 800, color: 'var(--accent-primary)', fontFamily: 'var(--font-mono)' }}>{sym}</div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Symbolic</div>
        </div>
        <div className="glass" style={{ padding: '1rem', textAlign: 'center', borderTop: '3px solid var(--accent-green)' }}>
          <div style={{ fontSize: '1.3rem', fontWeight: 800, color: 'var(--accent-green)', fontFamily: 'var(--font-mono)' }}>-{sym}</div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>ls -la Output</div>
        </div>
      </div>

      {/* Warnings */}
      {warnings.length > 0 && (
        <div style={{ background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.15)', borderRadius: 10, padding: '0.75rem 1rem', marginBottom: '1.25rem' }}>
          {warnings.map((warning) => (
            <div key={warning.text} style={{ fontSize: '0.85rem', color: warning.level === 'danger' ? 'var(--accent-red)' : 'var(--accent-amber)', marginBottom: 4 }}>
              {warning.level === 'danger' ? '🔴' : '🟡'} {warning.text}
            </div>
          ))}
        </div>
      )}

      {/* Explanation */}
      <div className="glass" style={{ padding: '1.25rem', marginBottom: '1.5rem' }}>
        <div style={{ fontWeight: 600, marginBottom: '0.75rem' }}><i className="bi bi-info-circle" style={{ marginRight: '0.5rem' }}></i>Explanation</div>
        <div style={{ fontSize: '0.88rem', color: 'var(--text-secondary)' }}>
          <p style={{ marginBottom: '0.4rem' }}><i className="bi bi-person-fill" style={{ color: 'var(--accent-primary)', marginRight: 6 }}></i>{describePerms(bits[0], 'Owner')}</p>
          <p style={{ marginBottom: '0.4rem' }}><i className="bi bi-people-fill" style={{ color: 'var(--accent-cyan)', marginRight: 6 }}></i>{describePerms(bits[1], 'Group')}</p>
          <p><i className="bi bi-globe" style={{ color: 'var(--accent-amber)', marginRight: 6 }}></i>{describePerms(bits[2], 'Others')}</p>
        </div>
      </div>

      {/* Command */}
      <div className="glass" style={{ padding: '1.25rem', marginBottom: '1.5rem' }}>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.625rem' }}>Command</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
          <code style={{ flex: 1, fontFamily: 'var(--font-mono)', fontSize: '0.95rem', color: 'var(--accent-cyan)', background: 'rgba(99,102,241,0.06)', padding: '0.625rem 1rem', borderRadius: 8 }}>chmod {octal} filename</code>
          <button onClick={() => void copy(`chmod ${octal} filename`, 'cmd')} className="btn-secondary">
            <i className={isCopied('cmd') ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i> {isCopied('cmd') ? 'Copied!' : 'Copy'}
          </button>
        </div>
      </div>
    </>
  );
}
