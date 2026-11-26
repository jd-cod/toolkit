'use client';

import { useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace from '@/components/ToolWorkspace';
import { Fragment } from 'react';
import { useClipboard } from '@/hooks/useClipboard';

const PRESETS = [
  { label: 'Standard File', octal: '644', desc: 'Owner read/write, others read-only' },
  { label: 'Executable Script', octal: '755', desc: 'Owner full, others read/execute' },
  { label: 'Private File', octal: '600', desc: 'Owner read/write only' },
  { label: 'SSH Private Key', octal: '400', desc: 'Owner read-only' },
  { label: 'Shared Directory', octal: '775', desc: 'Group write access' },
  { label: 'World Writable', octal: '777', desc: '⚠️ Full access for everyone' },
  { label: 'Setuid Binary', octal: '4755', desc: 'Runs as file owner' },
  { label: 'Sticky /tmp', octal: '1777', desc: 'Users can only delete own files' },
];

const ROLES = ['Owner', 'Group', 'Others'];
const PERMS = ['Read', 'Write', 'Execute'];
const PERM_ICONS = ['bi-eye', 'bi-pencil', 'bi-play-circle'];
const PERM_COLORS = ['var(--accent-green)', 'var(--accent-amber)', 'var(--accent-red)'];

function toSymbolic(bits: number[], special: number): string {
  const chars = ['r', 'w', 'x'];
  let s = '';
  for (let r = 0; r < 3; r++) for (let p = 0; p < 3; p++) s += (bits[r] & (4 >> p)) ? chars[p] : '-';
  if (special & 4) s = s.slice(0, 2) + (s[2] === 'x' ? 's' : 'S') + s.slice(3);
  if (special & 2) s = s.slice(0, 5) + (s[5] === 'x' ? 's' : 'S') + s.slice(6);
  if (special & 1) s = s.slice(0, 8) + (s[8] === 'x' ? 't' : 'T');
  return s;
}

function describePerms(bits: number, role: string): string {
  const names = [];
  if (bits & 4) names.push('read');
  if (bits & 2) names.push('write');
  if (bits & 1) names.push('execute');
  if (names.length === 0) return `${role} has no permissions`;
  if (names.length === 3) return `${role} can read, write, and execute`;
  return `${role} can ${names.join(' and ')}`;
}

export default function ChmodPage() {
  const { copy, isCopied } = useClipboard();
  const [grid, setGrid] = useState<boolean[][]>([[true, true, true], [true, false, true], [true, false, true]]); // 755
  const [special, setSpecial] = useState([false, false, false]);
  const [octalDraft, setOctalDraft] = useState<string | null>(null);

  const bits = grid.map(row => row.reduce((acc, v, i) => acc | (v ? (4 >> i) : 0), 0));
  const specialBits = special.reduce((acc, v, i) => acc | (v ? (4 >> i) : 0), 0);
  const octal = specialBits ? `${specialBits}${bits.join('')}` : bits.join('');
  const octalInput = octalDraft ?? octal;
  const sym = toSymbolic(bits, specialBits);
  const is777 = bits[0] === 7 && bits[1] === 7 && bits[2] === 7;
  const worldWrite = !!(bits[2] & 2);

  const toggleCell = (r: number, p: number) => {
    setOctalDraft(null);
    setGrid(prev => {
      const next = prev.map(row => [...row]);
      next[r][p] = !next[r][p];
      return next;
    });
  };

  const applyOctal = (val: string) => {
    setOctalDraft(val);
    if (!/^[0-7]{3,4}$/.test(val)) return;
    let sp = 0, digits: string;
    if (val.length === 4) { sp = parseInt(val[0]); digits = val.slice(1); } else digits = val;
    const b = digits.split('').map(Number);
    setGrid(b.map(v => [!!(v & 4), !!(v & 2), !!(v & 1)]));
    setSpecial([!!(sp & 4), !!(sp & 2), !!(sp & 1)]);
    setOctalDraft(null);
  };

  return (
    <>
      <Navbar />
      <main className="main-content">
        <div className="signal-tool-heading tool-hero-compact">
          <div className="tool-hero-icon" style={{ background: 'linear-gradient(135deg, #fbbf24, #fbbf24cc)' }}><i className="bi bi-key-fill"></i></div>
          <h1 className="hero-title">chmod Calculator</h1>
          <p>Interactive Linux permission calculator with octal ↔ symbolic conversion.</p>
        </div>

        <ToolWorkspace tool="chmod">
        <div className="glass" style={{ padding: '2rem', marginBottom: '2rem' }}>
          <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
            <input type="text" value={octalInput} onChange={e => applyOctal(e.target.value)} placeholder="755" style={{ width: 120, padding: '0.75rem 1rem', background: 'var(--bg-input)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', fontSize: '1.2rem', fontFamily: 'var(--font-mono)', textAlign: 'center', fontWeight: 700 }} />
            <select onChange={e => { if (e.target.value) applyOctal(e.target.value); e.target.value = ''; }} style={{ flex: 1, minWidth: 200, padding: '0.75rem', background: 'var(--bg-input)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', color: 'var(--text-secondary)', fontSize: '0.85rem', cursor: 'pointer' }}>
              <option value="">Load a preset...</option>
              {PRESETS.map(p => <option key={p.octal + p.label} value={p.octal}>{p.label} ({p.octal}) — {p.desc}</option>)}
            </select>
          </div>

          {/* Permission Grid */}
          <div className="signal-permission-grid">
            <div style={{ padding: 12, background: 'var(--bg-card-hover)', borderBottom: '1px solid var(--border-color)' }}></div>
            {PERMS.map((p, i) => (
              <div key={p} style={{ padding: 12, textAlign: 'center', background: 'var(--bg-card-hover)', borderBottom: '1px solid var(--border-color)', borderLeft: '1px solid var(--border-color)' }}>
                <i className={`bi ${PERM_ICONS[i]}`} style={{ color: PERM_COLORS[i], marginRight: 4 }}></i>
                <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)' }}>{p}</span>
              </div>
            ))}
            {ROLES.map((role, ri) => (
              <Fragment key={role}>
                <div key={`role-${ri}`} style={{ padding: 12, fontSize: '0.85rem', fontWeight: 600, display: 'flex', alignItems: 'center', ...(ri < 2 ? { borderBottom: '1px solid var(--border-color)' } : {}) }}>{role}</div>
                {PERMS.map((_, pi) => (
                  <div key={`${ri}-${pi}`} style={{ padding: 12, textAlign: 'center', borderLeft: '1px solid var(--border-color)', ...(ri < 2 ? { borderBottom: '1px solid var(--border-color)' } : {}) }}>
                    <button type="button" aria-label={`${role} ${PERMS[pi]}`} aria-pressed={grid[ri][pi]} onClick={() => toggleCell(ri, pi)} style={{ cursor: 'pointer', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 36, height: 36, borderRadius: 8, border: `2px solid ${grid[ri][pi] ? 'var(--accent-green)' : 'var(--border-color)'}`, background: grid[ri][pi] ? 'rgba(16,185,129,0.08)' : 'transparent', transition: 'all 0.2s' }}>
                      {grid[ri][pi] && <i className="bi bi-check-lg" style={{ fontSize: '1.1rem', color: 'var(--accent-green)' }}></i>}
                    </button>
                  </div>
                ))}
              </Fragment>
            ))}
          </div>

          {/* Special bits */}
          <div style={{ display: 'flex', gap: '1rem', padding: '0.75rem 1rem', background: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: 10, flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 600 }}>Special:</span>
            {['Setuid (4xxx)', 'Setgid (2xxx)', 'Sticky (1xxx)'].map((l, i) => (
              <label key={l} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                <input type="checkbox" checked={special[i]} onChange={() => { const s = [...special]; s[i] = !s[i]; setSpecial(s); setOctalDraft(null); }} style={{ accentColor: 'var(--accent-primary)' }} />{l}
              </label>
            ))}
          </div>
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
        {(is777 || worldWrite || special[0] || special[1]) && (
          <div style={{ background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.15)', borderRadius: 10, padding: '0.75rem 1rem', marginBottom: '1.25rem' }}>
            {is777 && <div style={{ fontSize: '0.85rem', color: 'var(--accent-red)', marginBottom: 4 }}>🔴 777 gives full access to everyone — major security risk!</div>}
            {worldWrite && !is777 && <div style={{ fontSize: '0.85rem', color: 'var(--accent-amber)', marginBottom: 4 }}>🟡 World-writable — other users can modify this file.</div>}
            {special[0] && <div style={{ fontSize: '0.85rem', color: 'var(--accent-amber)', marginBottom: 4 }}>🟡 Setuid — file executes as the owning user.</div>}
            {special[1] && <div style={{ fontSize: '0.85rem', color: 'var(--accent-amber)' }}>🟡 Setgid — file executes as the owning group.</div>}
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
        </ToolWorkspace>
      </main>
      <Footer />
    </>
  );
}
