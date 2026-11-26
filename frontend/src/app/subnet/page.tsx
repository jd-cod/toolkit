'use client';

import { useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace, { ToolEmptyState } from '@/components/ToolWorkspace';
import SubnetResultView from '@/components/SubnetResultView';
import { parseCIDR } from '@/lib/subnet';

export default function SubnetPage() {
  const [input, setInput] = useState('192.168.1.0/24');
  const [awsMode, setAwsMode] = useState(false);
  const [result, setResult] = useState<ReturnType<typeof parseCIDR>>(null);
  const [error, setError] = useState('');

  function doCalculate() {
    if (!input.trim()) return;
    const parsed = parseCIDR(input);
    if (!parsed) { setError('Invalid CIDR. Use format: 10.0.0.0/24'); setResult(null); return; }
    setError(''); setResult(parsed);
  }

  return (
    <>
      <Navbar />
      <main className="main-content">
        <div className="signal-tool-heading">
          <div style={{ width: 56, height: 56, borderRadius: 16, background: 'linear-gradient(135deg, #10b981, #10b981cc)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.6rem', color: '#fff', marginBottom: '1rem' }}><i className="bi bi-hdd-network-fill"></i></div>
          <h1 className="hero-title" style={{ fontSize: '2rem' }}>Subnet / CIDR Calculator</h1>
          <p style={{ color: 'var(--text-secondary)' }}>Calculate network details, usable hosts, and AWS impact for CIDR blocks.</p>
        </div>

        <ToolWorkspace tool="subnet">
        <div className="glass" style={{ padding: '2rem', marginBottom: '2rem' }}>
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <input type="text" value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && doCalculate()} placeholder="10.0.0.0/24 or 192.168.1.0 255.255.255.0" style={{ flex: 1, minWidth: 200, padding: '0.75rem 1rem', background: 'var(--bg-input)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', fontSize: '0.95rem', fontFamily: 'var(--font-mono)' }} />
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
              <input type="checkbox" checked={awsMode} onChange={e => setAwsMode(e.target.checked)} style={{ accentColor: 'var(--accent-amber)' }} /> AWS Mode
            </label>
            <button onClick={doCalculate} className="btn-primary">Calculate</button>
          </div>
        </div>

        {error && <div className="glass" style={{ padding: '1rem 1.5rem', borderColor: 'rgba(239,68,68,0.3)', color: 'var(--accent-red)', marginBottom: '1.5rem' }}>⚠️ {error}</div>}

        {!result && !error && <ToolEmptyState title="Size a subnet">Calculate a network to see its address boundaries, host capacity, and exportable details.</ToolEmptyState>}
        {result && <SubnetResultView result={result} awsMode={awsMode} mode="live" />}
        </ToolWorkspace>
      </main>
      <Footer />
    </>
  );
}
