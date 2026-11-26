'use client';

import ResultActions, { ResultActionButton } from '@/components/share/ResultActions';
import { useClipboard } from '@/hooks/useClipboard';
import { useHydrated } from '@/hooks/useHydrated';
import { snapshotShare } from '@/lib/api';
import {
  buildCronReportHtml,
  cronCsvRows,
  CRON_FIELD_LABELS,
  DAY_NAMES,
  describeCron,
  getNextRuns,
  parseCron,
  relTime,
  type CronSnapshot,
} from '@/lib/cron';
import { fileSlug } from '@/lib/download';

/** Cron expression breakdown and upcoming runs, used by the live builder and by shared links. */
export default function CronResultView({ expr, mode }: { expr: string; mode: 'live' | 'shared' }) {
  const { copy, isCopied } = useClipboard();
  const mounted = useHydrated();

  const parsed = parseCron(expr);
  const ok = !!parsed;
  const desc = describeCron(expr);
  const runs = ok && mounted ? getNextRuns(expr, 10) : [];
  const filename = `cron-${fileSlug(expr.trim().replace(/\*/g, 'x').replace(/\//g, '-'), 'schedule')}`;
  const snapshot = (): CronSnapshot => ({ expression: expr.trim(), checked_at_utc: new Date().toISOString() });

  return (
    <>
      {ok && (
        <div style={{ marginBottom: '1.5rem' }}>
          <ResultActions
            className="signal-actions-end"
            share={mode === 'live' ? {
              heading: 'Share Cron Schedule',
              title: `Cron: ${expr.trim()}`,
              create: snapshotShare('cron', expr.trim(), snapshot),
            } : undefined}
            html={{ filename, build: () => buildCronReportHtml(expr, runs, new Date().toISOString()) }}
            csv={{ filename, rows: () => cronCsvRows(expr, runs) }}
          >
            <ResultActionButton icon={isCopied('expr') ? 'check-lg' : 'clipboard'} onClick={() => void copy(expr, 'expr')}>
              {isCopied('expr') ? 'Copied' : 'Copy Expression'}
            </ResultActionButton>
            <ResultActionButton icon={isCopied('desc') ? 'check-lg' : 'clipboard'} onClick={() => void copy(desc, 'desc')}>
              {isCopied('desc') ? 'Copied' : 'Copy Description'}
            </ResultActionButton>
          </ResultActions>
        </div>
      )}
      {/* Validity banner */}
      <div style={{ background: ok ? 'rgba(16,185,129,0.06)' : 'rgba(239,68,68,0.06)', border: `1px solid ${ok ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}`, borderRadius: 12, padding: '1.125rem 1.375rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', marginBottom: '0.5rem' }}>
          <span style={{ fontSize: '1.5rem' }}>{ok ? '✅' : '❌'}</span>
          <span style={{ fontWeight: 700, fontSize: '1.05rem', color: ok ? 'var(--accent-green)' : 'var(--accent-red)' }}>{ok ? 'Valid Expression' : 'Invalid Expression'}</span>
        </div>
        <p style={{ fontWeight: 500, margin: 0 }}>{desc}</p>
      </div>

      {ok && parsed && (
        <>
          {/* Field breakdown */}
          <div className="signal-cron-fields">
            {CRON_FIELD_LABELS.map((l, i) => (
              <div key={l} className="glass" style={{ padding: '0.875rem', textAlign: 'center' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.375rem' }}>{l}</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1.15rem', fontWeight: 700, color: 'var(--accent-primary)' }}>{parsed.raw[i]}</div>
              </div>
            ))}
          </div>

          {/* Next runs */}
          <div className="glass" style={{ overflow: 'hidden', marginBottom: '1.5rem' }}>
            <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
              <i className="bi bi-clock-history" style={{ marginRight: '0.5rem' }}></i>Next {runs.length || 10} Executions
            </div>
            <div style={{ maxHeight: 400, overflowY: 'auto' }}>
              <table className="signal-cron-runs-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead><tr>
                  <th style={{ padding: '0.625rem 1rem', textAlign: 'left', fontSize: '0.8rem', color: 'var(--text-muted)' }}>#</th>
                  <th style={{ padding: '0.625rem 1rem', textAlign: 'left', fontSize: '0.8rem', color: 'var(--text-muted)' }}>Date & Time</th>
                  <th style={{ padding: '0.625rem 1rem', textAlign: 'left', fontSize: '0.8rem', color: 'var(--text-muted)' }}>Day</th>
                  <th style={{ padding: '0.625rem 1rem', textAlign: 'right', fontSize: '0.8rem', color: 'var(--text-muted)' }}>Relative</th>
                </tr></thead>
                <tbody>
                  {runs.map((d, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid rgba(30,34,53,0.5)' }}>
                      <td style={{ padding: '0.5rem 1rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>{i + 1}</td>
                      <td style={{ padding: '0.5rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                        {d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}
                        <span style={{ color: 'var(--accent-primary)', fontWeight: 600, marginLeft: 6 }}>{d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true })}</span>
                      </td>
                      <td style={{ padding: '0.5rem 1rem', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>{DAY_NAMES[d.getDay()]}</td>
                      <td style={{ padding: '0.5rem 1rem', textAlign: 'right', color: 'var(--text-muted)', fontSize: '0.82rem' }}>{relTime(d)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </>
  );
}
