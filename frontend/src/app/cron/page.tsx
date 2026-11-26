'use client';

import { useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace from '@/components/ToolWorkspace';
import { useHydrated } from '@/hooks/useHydrated';
import { useClipboard } from '@/hooks/useClipboard';

const PRESETS = [
  { label: 'Every minute', expr: '* * * * *' }, { label: 'Every 5 minutes', expr: '*/5 * * * *' },
  { label: 'Every 15 minutes', expr: '*/15 * * * *' }, { label: 'Every hour', expr: '0 * * * *' },
  { label: 'Daily at midnight', expr: '0 0 * * *' }, { label: 'Daily at 3 AM', expr: '0 3 * * *' },
  { label: 'Weekdays at 9 AM', expr: '0 9 * * 1-5' }, { label: 'Weekly (Sunday)', expr: '0 0 * * 0' },
  { label: 'Monthly (1st)', expr: '0 0 1 * *' }, { label: 'Yearly (Jan 1)', expr: '0 0 1 1 *' },
];
const DAY_NAMES = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
const MONTH_NAMES = ['','Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const DAY_SHORT = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];

function parseField(field: string, min: number, max: number): number[] | null {
  const vals = new Set<number>();
  for (const part of field.split(',')) {
    if (part === '*') { for (let i = min; i <= max; i++) vals.add(i); }
    else if (part.includes('/')) {
      const [r, s] = part.split('/'); const step = parseInt(s, 10);
      if (isNaN(step) || step <= 0) return null;
      let a = min, b = max;
      if (r !== '*') { if (r.includes('-')) { [a, b] = r.split('-').map(Number); } else a = parseInt(r, 10); }
      for (let i = a; i <= b; i += step) vals.add(i);
    } else if (part.includes('-')) {
      const [a, b] = part.split('-').map(Number);
      for (let i = a; i <= b; i++) vals.add(i);
    } else { const n = parseInt(part, 10); if (isNaN(n)) return null; vals.add(n); }
  }
  for (const v of vals) if (v < min || v > max) return null;
  return [...vals].sort((a, b) => a - b);
}

function parseCron(expr: string) {
  const p = expr.trim().split(/\s+/); if (p.length !== 5) return null;
  const m = parseField(p[0], 0, 59), h = parseField(p[1], 0, 23), d = parseField(p[2], 1, 31), mo = parseField(p[3], 1, 12), dw = parseField(p[4], 0, 7);
  if (!m || !h || !d || !mo || !dw) return null;
  return { raw: p, minute: m, hour: h, dom: d, month: mo, dow: [...new Set(dw.map(x => x === 7 ? 0 : x))].sort((a, b) => a - b) };
}

function fmtHour(h: number) { if (h === 0) return '12:00 AM'; if (h === 12) return '12:00 PM'; return h < 12 ? `${h}:00 AM` : `${h - 12}:00 PM`; }

function describe(expr: string): string {
  const p = expr.trim().split(/\s+/); if (p.length !== 5) return '❌ Invalid: need 5 fields';
  const [mf, hf, df, mof, dwf] = p; const pcs: string[] = [];
  if (mf === '*') pcs.push('Every minute');
  else if (mf.startsWith('*/')) pcs.push(`Every ${mf.slice(2)} minutes`);
  else pcs.push(`At minute ${mf}`);
  if (hf === '*') { if (mf !== '*' && !mf.startsWith('*/')) pcs.push('of every hour'); }
  else if (hf.startsWith('*/')) pcs.push(`every ${hf.slice(2)} hours`);
  else if (hf.includes(',')) pcs.push(`at ${hf.split(',').map(x => fmtHour(+x)).join(' and ')}`);
  else { const h = +hf; if (mf === '0') { pcs.length = 0; pcs.push(`At ${fmtHour(h)}`); } else pcs.push(`past ${fmtHour(h)}`); }
  if (df !== '*') pcs.push(`on day ${df} of the month`);
  if (mof !== '*') pcs.push(`in ${mof.split(',').map(x => MONTH_NAMES[+x] || x).join(', ')}`);
  if (dwf !== '*') pcs.push(`on ${dwf.split(',').map(x => DAY_SHORT[+x % 7] || x).join(', ')}`);
  return pcs.join(' ');
}

function getNextRuns(expr: string, count: number): Date[] {
  const parsed = parseCron(expr); if (!parsed) return [];
  const runs: Date[] = [], cur = new Date();
  cur.setSeconds(0, 0); cur.setMinutes(cur.getMinutes() + 1);
  for (let i = 0; runs.length < count && i < 525600; i++) {
    if (parsed.minute.includes(cur.getMinutes()) && parsed.hour.includes(cur.getHours()) &&
      parsed.dom.includes(cur.getDate()) && parsed.month.includes(cur.getMonth() + 1) &&
      parsed.dow.includes(cur.getDay())) runs.push(new Date(cur));
    cur.setMinutes(cur.getMinutes() + 1);
  }
  return runs;
}

function relTime(d: Date): string {
  const diff = d.getTime() - Date.now(), m = Math.floor(diff / 60000);
  if (m < 1) return 'now'; if (m < 60) return `in ${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `in ${h}h ${m % 60}m`; return `in ${Math.floor(h / 24)}d ${h % 24}h`;
}

export default function CronPage() {
  const { copy, isCopied } = useClipboard();
  const mounted = useHydrated();
  const [expr, setExpr] = useState('*/15 * * * *');

  const parsed = parseCron(expr);
  const ok = !!parsed;
  const desc = describe(expr);
  const runs = ok && mounted ? getNextRuns(expr, 10) : [];

  return (
    <>
      <Navbar />
      <main className="main-content">
        <div className="signal-tool-heading tool-hero-compact">
          <div className="tool-hero-icon" style={{ background: 'linear-gradient(135deg, #a855f7, #a855f7cc)' }}><i className="bi bi-clock-fill"></i></div>
          <h1 className="hero-title">Crontab Builder</h1>
          <p>Build, validate, and preview cron expressions.</p>
        </div>

        <ToolWorkspace tool="cron">
        <div className="glass" style={{ padding: '2rem', marginBottom: '2rem' }}>
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <input type="text" value={expr} onChange={e => setExpr(e.target.value)} placeholder="*/5 * * * *" style={{ flex: 1, minWidth: 200, padding: '0.75rem 1rem', background: 'var(--bg-input)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', fontSize: '1.1rem', fontFamily: 'var(--font-mono)', fontWeight: 600 }} />
            <select onChange={e => { if (e.target.value) setExpr(e.target.value); }} defaultValue="" style={{ padding: '0.75rem', background: 'var(--bg-input)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', color: 'var(--text-secondary)', fontSize: '0.85rem', cursor: 'pointer' }}>
              <option value="">Load a preset...</option>
              {PRESETS.map(p => <option key={p.expr} value={p.expr}>{p.label} — {p.expr}</option>)}
            </select>
          </div>
        </div>

        {expr.trim() && (
          <>
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
                  {['Minute', 'Hour', 'Day(M)', 'Month', 'Day(W)'].map((l, i) => (
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

                {/* Copy buttons */}
                <div style={{ display: 'flex', gap: '0.625rem', marginBottom: '1.5rem' }}>
                  <button onClick={() => void copy(expr, 'expr')} className="btn-secondary">
                    <i className={isCopied('expr') ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i> {isCopied('expr') ? 'Copied Expression!' : 'Copy Expression'}
                  </button>
                  <button onClick={() => void copy(desc, 'desc')} className="btn-secondary">
                    <i className={isCopied('desc') ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i> {isCopied('desc') ? 'Copied Description!' : 'Copy Description'}
                  </button>
                </div>
              </>
            )}
          </>
        )}
        </ToolWorkspace>
      </main>
      <Footer />
    </>
  );
}
