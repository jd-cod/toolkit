'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolWorkspace from '@/components/ToolWorkspace';
import { useHydrated } from '@/hooks/useHydrated';
import { useClipboard } from '@/hooks/useClipboard';
import { exportToCSV } from '@/lib/csv-utils';
import {
  LENGTH_PRESETS,
  PIN_PRESETS,
  SEPARATORS,
  WORD_COUNT_PRESETS,
  generatePassphrase,
  generatePassword,
  generatePin,
  poolSize as computePoolSize,
  activeSets,
  type PasswordMode,
  type PasswordOptions,
  type PassphraseOptions,
} from '@/lib/password/generator';
import { assessStrength, describeComposition, LEVELS, passphraseBits } from '@/lib/password/entropy';
import { BITS_PER_WORD } from '@/lib/password/wordlist';
import {
  HISTORY_LIMIT,
  appendHistory,
  clearHistory,
  newId,
  readHistory,
  type HistoryEntry,
} from '@/lib/password/storage';
import { readSettings, writeSettings } from '@/lib/password/settings';

const DEFAULT_PASSWORD_OPTIONS: PasswordOptions = {
  length: 20,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
  excludeAmbiguous: false,
  excludeSimilar: false,
  requireEachClass: true,
};

const DEFAULT_PASSPHRASE_OPTIONS: PassphraseOptions = {
  wordCount: 4,
  separator: '-',
  capitalize: true,
  appendNumber: false,
};

const MODES: { id: PasswordMode; label: string; icon: string; hint: string }[] = [
  { id: 'password', label: 'Random', icon: 'bi bi-shuffle', hint: 'Full-entropy random string' },
  { id: 'passphrase', label: 'Passphrase', icon: 'bi bi-book', hint: 'Memorable words you can retype' },
  { id: 'pin', label: 'PIN', icon: 'bi bi-123', hint: 'Digits only — lockers, doors, MFA backup' },
];

const BULK_COUNTS = [5, 10, 25, 50];

const HISTORY_PUSH_DELAY_MS = 1200;

function relativeTime(ts: number): string {
  const diff = Date.now() - ts;
  if (diff < 60_000) return 'Just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  if (diff < 172_800_000) return 'Yesterday';
  if (diff < 604_800_000) return `${Math.floor(diff / 86_400_000)}d ago`;
  return new Date(ts).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function fullTimestamp(ts: number): string {
  return new Date(ts).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

export default function PasswordGeneratorPage() {
  const hydrated = useHydrated();

  return (
    <>
      <Navbar />
      <main className="main-content">
        <div className="signal-tool-heading">
          <div style={{ width: 56, height: 56, borderRadius: 16, background: 'linear-gradient(135deg, #6366f1, #a855f7cc)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.6rem', color: '#fff', marginBottom: '1rem' }}><i className="bi bi-shield-lock-fill"></i></div>
          <h1 className="hero-title" style={{ fontSize: '2rem' }}>Password Generator</h1>
          <p style={{ color: 'var(--text-secondary)' }}>Create a random password, memorable passphrase, or numeric PIN.</p>
        </div>

        <ToolWorkspace tool="password">
          {/* Privacy callout — the single most important claim on the page. */}
          <div style={{ background: 'rgba(16,185,129,0.06)', border: '1px solid rgba(16,185,129,0.2)', borderRadius: 12, padding: '1.125rem 1.375rem', marginBottom: '1.5rem', display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
            <i className="bi bi-lock-fill" style={{ color: 'var(--accent-green)', fontSize: '1.15rem', marginTop: 2 }}></i>
            <div>
              <div style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--accent-green)', marginBottom: '0.3rem' }}>Everything happens inside your browser</div>
              <p style={{ margin: 0, fontSize: '0.86rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Generated with your browser&rsquo;s cryptographic random number generator.
                Nothing is uploaded or stored on our servers.
              </p>
            </div>
          </div>

          {hydrated ? (
            <PasswordGeneratorControls />
          ) : (
            <div className="glass" style={{ padding: '2rem', textAlign: 'center' }} aria-busy="true">
              <p role="status" style={{ color: 'var(--text-secondary)' }}>Loading your browser-only generator…</p>
            </div>
          )}
        </ToolWorkspace>
      </main>
      <Footer />
    </>
  );
}

function PasswordGeneratorControls() {
  const { copy, isCopied } = useClipboard();
  const [saved] = useState(readSettings);
  const [mode, setMode] = useState<PasswordMode>(saved?.mode || 'password');
  const [options, setOptions] = useState<PasswordOptions>(saved?.options || DEFAULT_PASSWORD_OPTIONS);
  const [passphrase, setPassphrase] = useState<PassphraseOptions>(saved?.passphrase || DEFAULT_PASSPHRASE_OPTIONS);
  const [pinLength, setPinLength] = useState(saved?.pinLength || 6);

  const [password, setPassword] = useState('');
  const [revealed, setRevealed] = useState(true);
  const [history, setHistory] = useState<HistoryEntry[]>(readHistory);
  const [revealedRows, setRevealedRows] = useState<Record<string, boolean>>({});
  const [historyEnabled, setHistoryEnabled] = useState(true);
  const [bulkCount, setBulkCount] = useState(10);
  const [bulk, setBulk] = useState<string[]>([]);

  // This component mounts only after hydration, so persisted state is its initial state.
  const mounted = true;

  // Persist settings (debounce-free: writes are cheap single-key JSON puts).
  useEffect(() => {
    if (!mounted) return;
    writeSettings({ mode, options, passphrase, pinLength });
  }, [mounted, mode, options, passphrase, pinLength]);

  // The pool the current settings would draw from, so entropy is scored against
  // what was actually generated rather than against the string's own characters.
  const pool = useMemo(() => {
    if (mode !== 'password') return undefined;
    return computePoolSize(activeSets(options), options.excludeAmbiguous, options.excludeSimilar);
  }, [mode, options]);

  // A passphrase's entropy is counted in words, not characters. Telling the
  // scorer the exact bits keeps it from grading a 4-word passphrase on its ~40
  // letters, which would roughly double the real number.
  const knownBits = useMemo(() => {
    if (mode === 'passphrase') {
      return passphraseBits(passphrase.wordCount) + (passphrase.appendNumber ? Math.log2(100) : 0);
    }
    if (mode === 'pin') return pinLength * Math.log2(10);
    return undefined;
  }, [mode, passphrase.wordCount, passphrase.appendNumber, pinLength]);

  const strength = useMemo(
    () => assessStrength(password, pool, knownBits),
    [password, pool, knownBits],
  );

  const regenerate = useCallback(() => {
    if (mode === 'passphrase') setPassword(generatePassphrase(passphrase));
    else if (mode === 'pin') setPassword(generatePin(pinLength));
    else setPassword(generatePassword(options));
  }, [mode, options, passphrase, pinLength]);

  // Coalesce rapid slider changes into one CSPRNG request per animation frame.
  useEffect(() => {
    const frame = requestAnimationFrame(regenerate);
    return () => cancelAnimationFrame(frame);
  }, [mounted, regenerate]);

  /**
   * Record the current password once the user stops dragging sliders. Options
   * change on every pixel of slider movement; pushing each intermediate value
   * would fill the table with near-identical rows, so we debounce the write
   * while regenerating the preview immediately.
   */
  const historyTimer = useRef<NodeJS.Timeout | null>(null);

  const scheduleHistory = useCallback(() => {
    if (!historyEnabled) return;
    if (historyTimer.current) clearTimeout(historyTimer.current);
    historyTimer.current = setTimeout(() => {
      setHistory((prev) => {
        const newest = prev[0];
        if (newest && newest.password === password) return prev;
        const entry: HistoryEntry = {
          id: newId(),
          password,
          mode,
          bits: strength.bits,
          level: strength.level,
          createdAt: Date.now(),
        };
        return appendHistory(entry, prev);
      });
    }, HISTORY_PUSH_DELAY_MS);
  }, [historyEnabled, password, mode, strength.bits, strength.level]);

  useEffect(() => {
    if (mounted && password) scheduleHistory();
    return () => {
      if (historyTimer.current) clearTimeout(historyTimer.current);
    };
  }, [mounted, password, scheduleHistory]);

  const setOpt = <K extends keyof PasswordOptions>(key: K, value: PasswordOptions[K]) =>
    setOptions((prev) => ({ ...prev, [key]: value }));

  /**
   * A checkbox that would empty the pool is refused rather than accepted. The
   * generator already falls back to lowercase, but silently ignoring a click
   * the user watched register is worse than telling them why.
   */
  const toggleSet = (key: 'uppercase' | 'lowercase' | 'numbers' | 'symbols') => {
    const next = { ...options, [key]: !options[key] };
    const stillHasOne = next.uppercase || next.lowercase || next.numbers || next.symbols;
    if (!stillHasOne) return;
    setOptions(next);
  };

  const handleCopy = () => {
    if (!password) return;
    void copy(password, 'main');
  };

  const generateBulk = () => {
    const out: string[] = [];
    for (let i = 0; i < bulkCount; i++) {
      if (mode === 'passphrase') out.push(generatePassphrase(passphrase));
      else if (mode === 'pin') out.push(generatePin(pinLength));
      else out.push(generatePassword(options));
    }
    setBulk(out);
  };

  const removeRow = (id: string) => setHistory(readHistory().filter((e) => e.id !== id));

  const clearAll = () => {
    clearHistory();
    setHistory([]);
    setRevealedRows({});
  };

  const lengthValue = mode === 'passphrase' ? passphrase.wordCount : mode === 'pin' ? pinLength : options.length;
  const lengthMax = mode === 'password' ? 128 : mode === 'passphrase' ? 10 : 16;
  const lengthUnit = mode === 'password' ? (options.length === 1 ? 'character' : 'characters') : mode === 'passphrase' ? (passphrase.wordCount === 1 ? 'word' : 'words') : 'digits';
  const presets = mode === 'password' ? LENGTH_PRESETS : mode === 'passphrase' ? WORD_COUNT_PRESETS : PIN_PRESETS;

  const setLength = (v: number) => {
    if (mode === 'passphrase') setPassphrase((p) => ({ ...p, wordCount: v }));
    else if (mode === 'pin') setPinLength(v);
    else setOpt('length', v);
  };

  const toggleRow = (id: string) => setRevealedRows((prev) => ({ ...prev, [id]: !prev[id] }));

  return (
    <>
      {/* Mode tabs */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
          {MODES.map((m) => (
            <button
              key={m.id}
              onClick={() => setMode(m.id)}
              aria-pressed={mode === m.id}
              className={mode === m.id ? 'btn-primary' : 'btn-secondary'}
              style={{ padding: '0.55rem 1.1rem', borderRadius: 10, cursor: 'pointer', fontSize: '0.88rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 7, fontFamily: 'inherit' }}
            >
              <i className={m.icon}></i> {m.label}
            </button>
          ))}
        </div>

        {/* Password display */}
        <div className="glass" style={{ padding: '2rem', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)' }}>
              {MODES.find((m) => m.id === mode)?.hint}
            </span>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <button onClick={() => setRevealed((r) => !r)} className="btn-secondary" aria-label={revealed ? 'Hide password' : 'Show password'} title={revealed ? 'Hide' : 'Show'} style={{ padding: '8px 14px', borderRadius: 10, cursor: 'pointer', fontSize: '0.88rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <i className={revealed ? 'bi bi-eye-slash-fill' : 'bi bi-eye-fill'}></i>
              </button>
              <button onClick={regenerate} className="btn-secondary" title="Generate a new one" style={{ padding: '8px 16px', borderRadius: 10, cursor: 'pointer', fontSize: '0.88rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <i className="bi bi-arrow-clockwise"></i> Regenerate
              </button>
              <button onClick={handleCopy} className="btn-primary" style={{ padding: '8px 20px', borderRadius: 10, cursor: 'pointer', fontSize: '0.88rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 7 }}>
                <i className={isCopied('main') ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i> {isCopied('main') ? 'Copied!' : 'Copy Password'}
              </button>
            </div>
          </div>

          <div
            id="pw-value"
            style={{
              background: 'var(--bg-input)',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-sm)',
              padding: '1.25rem 1.5rem',
              minHeight: 88,
              display: 'flex',
              alignItems: 'center',
              fontFamily: 'var(--font-mono)',
              fontSize: options.length > 40 ? '1rem' : 'clamp(1rem, 2.4vw, 1.5rem)',
              lineHeight: 1.5,
              wordBreak: 'break-all',
              letterSpacing: '0.02em',
              color: 'var(--text-primary)',
              fontWeight: 600,
            }}
          >
            {password ? (
              revealed
                ? password
                : <span style={{ color: 'var(--text-secondary)', letterSpacing: '0.15em', fontWeight: 400 }}>{'•'.repeat(Math.min(password.length, 64))}</span>
            ) : (
              <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>Generating…</span>
            )}
          </div>

          {/* Strength meter */}
          <div style={{ marginTop: '1.25rem' }}>
            <div id="pw-strength" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: '0.5rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <span style={{ fontWeight: 700, fontSize: '0.95rem', color: strength.color }}>{strength.label}</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                {strength.bits} bits · ~{strength.crackTime}
                {!strength.exact && <span title="Estimated by pattern analysis, not measured from a known keyspace"> est.</span>}
              </span>
            </div>
            <div style={{ height: 8, background: 'var(--bg-input)', borderRadius: 999, overflow: 'hidden', border: '1px solid var(--border-color)' }}>
              <div style={{ width: `${strength.percent}%`, height: '100%', background: strength.color, transition: 'width 0.35s cubic-bezier(0.4,0,0.2,1), background 0.35s ease' }} />
            </div>
            {strength.tips.length > 0 && (
              <ul style={{ listStyle: 'none', padding: 0, margin: '0.875rem 0 0', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                {strength.tips.map((tip) => (
                  <li key={tip} style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', gap: 7, alignItems: 'flex-start' }}>
                    <i className="bi bi-info-circle" style={{ marginTop: 2, flexShrink: 0 }}></i> {tip}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {/* Controls */}
        <div className="glass" style={{ padding: '1.75rem', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>
              {mode === 'passphrase' ? 'Number of words' : mode === 'pin' ? 'PIN length' : 'Password length'}
            </span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.95rem', fontWeight: 700, color: 'var(--accent-primary)' }}>
              {lengthValue} {lengthUnit}
            </span>
          </div>

          <input
            type="range"
            min={mode === 'passphrase' ? 3 : 4}
            max={lengthMax}
            value={lengthValue}
            onChange={(e) => setLength(Number(e.target.value))}
            aria-label={mode === 'passphrase' ? 'Number of words' : mode === 'pin' ? 'PIN length' : 'Password length'}
            className="pw-slider"
          />

          <div style={{ display: 'flex', gap: '0.4rem', marginTop: '0.75rem', flexWrap: 'wrap' }}>
            {presets.map((n) => (
              <button
                key={n}
                onClick={() => setLength(n)}
                className={lengthValue === n ? 'btn-primary' : 'btn-secondary'}
                style={{ padding: '5px 12px', borderRadius: 8, cursor: 'pointer', fontSize: '0.8rem', fontWeight: 700, fontFamily: 'inherit' }}
              >
                {n}
              </button>
            ))}
          </div>

          {mode === 'password' && (
            <>
              <div style={{ borderTop: '1px solid var(--border-color)', margin: '1.5rem 0 1.25rem' }} />

              <div style={{ fontWeight: 700, fontSize: '0.95rem', marginBottom: '0.875rem' }}>Character types</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.6rem', marginBottom: '1.25rem' }}>
                {([
                  ['uppercase', 'Uppercase', 'A–Z'],
                  ['lowercase', 'Lowercase', 'a–z'],
                  ['numbers', 'Numbers', '0–9'],
                  ['symbols', 'Symbols', '!@#$%'],
                ] as const).map(([key, label, sample]) => (
                  <button
                    key={key}
                    onClick={() => toggleSet(key)}
                    aria-pressed={options[key]}
                    style={{
                      padding: '0.75rem 1rem',
                      borderRadius: 10,
                      cursor: 'pointer',
                      textAlign: 'left',
                      fontFamily: 'inherit',
                      background: options[key] ? 'rgba(99,102,241,0.10)' : 'var(--bg-input)',
                      border: `1px solid ${options[key] ? 'rgba(99,102,241,0.35)' : 'var(--border-color)'}`,
                      color: options[key] ? 'var(--text-primary)' : 'var(--text-muted)',
                      transition: 'all 0.2s ease',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem' }}>
                      <span style={{ fontSize: '0.85rem', fontWeight: 700 }}>{label}</span>
                      <i className={options[key] ? 'bi bi-check-circle-fill' : 'bi bi-circle'} style={{ color: options[key] ? 'var(--accent-primary)' : 'var(--text-muted)' }}></i>
                    </div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', marginTop: 2, opacity: 0.75 }}>{sample}</div>
                  </button>
                ))}
              </div>

              <div style={{ fontWeight: 700, fontSize: '0.95rem', marginBottom: '0.75rem' }}>Options</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.7rem' }}>
                {([
                  ['requireEachClass', 'Include at least one of each selected type', 'So the password is never all letters or all digits.'],
                  ['excludeAmbiguous', 'Avoid look-alike characters', 'Drops 0 O o 1 l I | / \\ — harder to misread when retyped.'],
                  ['excludeSimilar', 'Avoid shell-hostile symbols', 'Drops quotes, backslash, brackets and spaces — safer in configs and CLIs.'],
                ] as const).map(([key, label, hint]) => (
                  <label key={key} style={{ display: 'flex', gap: '0.65rem', alignItems: 'flex-start', cursor: 'pointer' }}>
                    <input type="checkbox" checked={options[key]} onChange={(e) => setOpt(key, e.target.checked)} style={{ accentColor: 'var(--accent-primary)', marginTop: 3, width: 15, height: 15 }} />
                    <span>
                      <span style={{ display: 'block', fontSize: '0.87rem', fontWeight: 600, color: 'var(--text-primary)' }}>{label}</span>
                      <span style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 1 }}>{hint}</span>
                    </span>
                  </label>
                ))}
              </div>

              <div style={{ marginTop: '1.25rem', paddingTop: '1rem', borderTop: '1px solid var(--border-color)', fontSize: '0.78rem', color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
                <span>Character pool: <strong style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{pool ?? 0}</strong> distinct characters</span>
                <span>Entropy per character: <strong style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{pool ? (Math.log2(pool)).toFixed(2) : '0.00'} bits</strong></span>
              </div>
            </>
          )}

          {mode === 'passphrase' && (
            <>
              <div style={{ borderTop: '1px solid var(--border-color)', margin: '1.5rem 0 1.25rem' }} />
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div>
                  <span style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.4rem' }}>Separator</span>
                  <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                    {SEPARATORS.map((s) => (
                      <button
                        key={s}
                        onClick={() => setPassphrase((p) => ({ ...p, separator: s }))}
                        className={passphrase.separator === s ? 'btn-primary' : 'btn-secondary'}
                        style={{ padding: '5px 14px', borderRadius: 8, cursor: 'pointer', fontSize: '0.85rem', fontWeight: 700, fontFamily: 'var(--font-mono)', minWidth: 42 }}
                      >
                        {s === ' ' ? '␣' : s}
                      </button>
                    ))}
                  </div>
                </div>
                <label style={{ display: 'flex', gap: '0.65rem', alignItems: 'center', cursor: 'pointer' }}>
                  <input type="checkbox" checked={passphrase.capitalize} onChange={(e) => setPassphrase((p) => ({ ...p, capitalize: e.target.checked }))} style={{ accentColor: 'var(--accent-primary)', width: 15, height: 15 }} />
                  <span style={{ fontSize: '0.87rem', fontWeight: 600 }}>Capitalise each word</span>
                </label>
                <label style={{ display: 'flex', gap: '0.65rem', alignItems: 'center', cursor: 'pointer' }}>
                  <input type="checkbox" checked={passphrase.appendNumber} onChange={(e) => setPassphrase((p) => ({ ...p, appendNumber: e.target.checked }))} style={{ accentColor: 'var(--accent-primary)', width: 15, height: 15 }} />
                  <span style={{ fontSize: '0.87rem', fontWeight: 600 }}>Append a random number (0–99)</span>
                </label>
              </div>
              <div style={{ marginTop: '1.25rem', fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                Drawn from the EFF&rsquo;s 7,776-word list — {BITS_PER_WORD.toFixed(2)} bits per word in theory, less in practice once the
                attacker assumes you used a dictionary. Four words is comfortably above the 80-bit target most auditors ask for.
              </div>
            </>
          )}

          {mode === 'pin' && (
            <>
              <div style={{ borderTop: '1px solid var(--border-color)', margin: '1.5rem 0 1.25rem' }} />
              <div style={{ background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.15)', borderRadius: 10, padding: '0.75rem 1rem', fontSize: '0.82rem', color: 'var(--accent-amber)', display: 'flex', gap: '0.6rem', alignItems: 'flex-start' }}>
                <i className="bi bi-exclamation-triangle-fill" style={{ marginTop: 2, flexShrink: 0 }}></i>
                <span>Only {Math.log2(10).toFixed(2)} bits per digit — a {pinLength}-digit PIN has {Math.round(Math.log2(10) * pinLength)} bits and falls to brute force almost instantly. Use PINs only for physical locks and device pairing codes, never for anything reachable over a network.</span>
              </div>
            </>
          )}
        </div>

        {/* Bulk generation */}
        <div className="glass" style={{ padding: '1.75rem', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem', marginBottom: bulk.length ? '1rem' : 0 }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: '0.95rem', marginBottom: 2 }}><i className="bi bi-collection-fill" style={{ marginRight: '0.5rem', color: 'var(--accent-purple)' }}></i>Bulk generate</div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Seed service accounts, test fixtures, or a whole onboarding batch at once. These are not saved to history.</div>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
              <select
                value={bulkCount}
                onChange={(e) => setBulkCount(Number(e.target.value))}
                aria-label="How many passwords to generate"
                style={{ padding: '0.55rem 0.75rem', background: 'var(--bg-input)', border: '1px solid var(--border-color)', borderRadius: 10, color: 'var(--text-secondary)', fontSize: '0.85rem', cursor: 'pointer', fontFamily: 'inherit' }}
              >
                {BULK_COUNTS.map((c) => <option key={c} value={c}>{c} passwords</option>)}
              </select>
              <button onClick={generateBulk} className="btn-primary" style={{ padding: '0.55rem 1.1rem', borderRadius: 10, cursor: 'pointer', fontSize: '0.85rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 6, fontFamily: 'inherit' }}>
                <i className="bi bi-lightning-charge-fill"></i> Generate
              </button>
            </div>
          </div>

          {bulk.length > 0 && (
            <>
              <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
                <button onClick={() => void copy(bulk.join('\n'), 'bulk')} className="btn-secondary" style={{ padding: '8px 16px', borderRadius: 10, cursor: 'pointer', fontSize: '0.85rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  <i className={isCopied('bulk') ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i> {isCopied('bulk') ? 'Copied!' : 'Copy All'}
                </button>
                <button onClick={() => exportToCSV(bulk.map((p, i) => ({ index: i + 1, password: p })), 'generated-passwords')} className="btn-secondary" style={{ padding: '8px 16px', borderRadius: 10, cursor: 'pointer', fontSize: '0.85rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  <i className="bi bi-download"></i> Export CSV
                </button>
                <button onClick={() => setBulk([])} className="btn-secondary" style={{ padding: '8px 16px', borderRadius: 10, cursor: 'pointer', fontSize: '0.85rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  <i className="bi bi-x-lg"></i> Clear
                </button>
              </div>
              <div style={{ maxHeight: 280, overflowY: 'auto', border: '1px solid var(--border-color)', borderRadius: 10, background: 'var(--bg-input)' }}>
                {bulk.map((p, i) => (
                  <div key={`${p}-${i}`} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.5rem 0.875rem', borderBottom: i < bulk.length - 1 ? '1px solid rgba(30,34,53,0.5)' : 'none' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)', minWidth: 22 }}>{String(i + 1).padStart(2, '0')}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-primary)', wordBreak: 'break-all', flex: 1 }}>{p}</span>
                    <button onClick={() => void copy(p, `bulk-${i}`)} className="btn-secondary" aria-label={`Copy password ${i + 1}`} style={{ padding: '4px 10px', borderRadius: 7, cursor: 'pointer', fontSize: '0.78rem', display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                      <i className={isCopied(`bulk-${i}`) ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i>
                    </button>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        {/* History */}
        <div className="glass" style={{ marginBottom: '2rem', overflow: 'hidden' }}>
          <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div style={{ fontWeight: 700 }}>
              <i className="bi bi-clock-history" style={{ marginRight: '0.5rem', color: 'var(--accent-cyan)' }}></i>
              Recent passwords
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 500, marginLeft: '0.5rem' }}>
                {history.length}/{HISTORY_LIMIT}
              </span>
            </div>
            <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                <input type="checkbox" checked={historyEnabled} onChange={(e) => setHistoryEnabled(e.target.checked)} style={{ accentColor: 'var(--accent-primary)', width: 14, height: 14 }} />
                Save to history
              </label>
              {history.length > 0 && (
                <button onClick={clearAll} className="btn-secondary" style={{ padding: '6px 12px', borderRadius: 8, cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                  <i className="bi bi-trash3"></i> Clear all
                </button>
              )}
            </div>
          </div>

          {history.length === 0 ? (
            <div style={{ padding: '2.5rem 1.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
              <i className="bi bi-inbox" style={{ fontSize: '1.75rem', display: 'block', marginBottom: '0.625rem', opacity: 0.6 }}></i>
              <div style={{ fontSize: '0.9rem', fontWeight: 600, marginBottom: '0.25rem', color: 'var(--text-secondary)' }}>Nothing here yet</div>
              <div style={{ fontSize: '0.82rem' }}>
                Enable “Save to history” to find recently generated values here.
              </div>
            </div>
          ) : (
            <div className="signal-password-history-wrap" style={{ overflowX: 'auto' }}>
              <table className="signal-password-history-table" style={{ width: '100%', borderCollapse: 'collapse', minWidth: 620 }}>
                <thead>
                  <tr>
                    {['Password', 'Length', 'Contains', 'Strength', 'Generated', ''].map((h) => (
                      <th key={h} style={{ padding: '0.625rem 1rem', textAlign: 'left', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', borderBottom: '1px solid var(--border-color)', fontWeight: 700 }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {history.map((entry) => {
                    const level = LEVELS[entry.level];
                    const shown = revealedRows[entry.id];
                    return (
                      <tr key={entry.id} data-pw-history-row style={{ borderBottom: '1px solid rgba(30,34,53,0.5)' }}>
                        <td style={{ padding: '0.6rem 1rem', maxWidth: 320 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <code
                              onClick={() => toggleRow(entry.id)}
                              title={shown ? 'Hide' : 'Click to reveal'}
                              style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', cursor: 'pointer', wordBreak: 'break-all', color: shown ? 'var(--text-primary)' : 'var(--text-secondary)', letterSpacing: shown ? 0 : '0.08em', userSelect: shown ? 'auto' : 'none' }}
                            >
                              {shown ? entry.password : '•'.repeat(Math.min(entry.password.length, 24))}
                            </code>
                            <button onClick={() => toggleRow(entry.id)} aria-label={shown ? `Hide password from ${fullTimestamp(entry.createdAt)}` : `Reveal password from ${fullTimestamp(entry.createdAt)}`} className="btn-secondary" style={{ padding: '3px 8px', borderRadius: 6, cursor: 'pointer', fontSize: '0.75rem', flexShrink: 0 }}>
                              <i className={shown ? 'bi bi-eye-slash-fill' : 'bi bi-eye-fill'}></i>
                            </button>
                          </div>
                        </td>
                        <td style={{ padding: '0.6rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{entry.password.length}</td>
                        <td style={{ padding: '0.6rem 1rem', fontSize: '0.78rem', color: 'var(--text-muted)' }}>{describeComposition(entry.password)}</td>
                        <td style={{ padding: '0.6rem 1rem' }}>
                          <span className="tool-tag" style={{ background: `${level.color}1f`, color: level.color, whiteSpace: 'nowrap' }}>{level.label}</span>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)', marginLeft: '0.4rem' }}>{entry.bits}b</span>
                        </td>
                        <td style={{ padding: '0.6rem 1rem', fontSize: '0.8rem', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }} title={fullTimestamp(entry.createdAt)}>
                          {relativeTime(entry.createdAt)}
                        </td>
                        <td style={{ padding: '0.6rem 1rem', whiteSpace: 'nowrap', textAlign: 'right' }}>
                          <button onClick={() => void copy(entry.password, `row-${entry.id}`)} aria-label={`Copy password from ${fullTimestamp(entry.createdAt)}`} className="btn-secondary" style={{ padding: '4px 10px', borderRadius: 7, cursor: 'pointer', fontSize: '0.78rem', marginRight: 6 }}>
                            <i className={isCopied(`row-${entry.id}`) ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i>
                          </button>
                          <button onClick={() => removeRow(entry.id)} aria-label={`Delete password from ${fullTimestamp(entry.createdAt)}`} className="btn-secondary" style={{ padding: '4px 10px', borderRadius: 7, cursor: 'pointer', fontSize: '0.78rem', color: 'var(--accent-red)' }}>
                            <i className="bi bi-trash3"></i>
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          <div style={{ padding: '0.75rem 1.25rem', borderTop: '1px solid var(--border-color)', fontSize: '0.78rem', color: 'var(--text-muted)', display: 'flex', gap: 7, alignItems: 'flex-start' }}>
            <i className="bi bi-info-circle" style={{ marginTop: 2, flexShrink: 0 }}></i>
            <span>History stays in this browser (up to {HISTORY_LIMIT} entries) &amp; clearing browser data erases history.</span>
          </div>
        </div>
    </>
  );
}
