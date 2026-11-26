'use client';

import { useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace from '@/components/ToolWorkspace';
import CronResultView from '@/components/CronResultView';

const PRESETS = [
  { label: 'Every minute', expr: '* * * * *' }, { label: 'Every 5 minutes', expr: '*/5 * * * *' },
  { label: 'Every 15 minutes', expr: '*/15 * * * *' }, { label: 'Every hour', expr: '0 * * * *' },
  { label: 'Daily at midnight', expr: '0 0 * * *' }, { label: 'Daily at 3 AM', expr: '0 3 * * *' },
  { label: 'Weekdays at 9 AM', expr: '0 9 * * 1-5' }, { label: 'Weekly (Sunday)', expr: '0 0 * * 0' },
  { label: 'Monthly (1st)', expr: '0 0 1 * *' }, { label: 'Yearly (Jan 1)', expr: '0 0 1 1 *' },
];
export default function CronPage() {
  const [expr, setExpr] = useState('*/15 * * * *');

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

        {expr.trim() && <CronResultView expr={expr} mode="live" />}
        </ToolWorkspace>
      </main>
      <Footer />
    </>
  );
}
