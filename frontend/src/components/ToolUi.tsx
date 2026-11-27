'use client';

import type { InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from 'react';
import { useClipboard } from '@/hooks/useClipboard';

/**
 * Small building blocks for tool pages. Styles are the `tk-` classes in
 * app/tool-kit.css. Use these instead of inline styles in new tools.
 */

export type Tone = 'ok' | 'warn' | 'bad' | 'info' | 'muted';

export function Panel({ title, icon, actions, children, flush = false }: { title?: string; icon?: string; actions?: ReactNode; children: ReactNode; flush?: boolean }) {
  return (
    <section className="glass tk-panel">
      {(title || actions) && (
        <header className="tk-panel-head">
          <h2>{icon && <i className={`bi ${icon}`} aria-hidden="true" />}{title}</h2>
          {actions && <div className="tk-actions">{actions}</div>}
        </header>
      )}
      <div className={flush ? 'tk-panel-body tk-flush' : 'tk-panel-body'}>{children}</div>
    </section>
  );
}

export function Field({ label, hint, children, grow = false }: { label: string; hint?: string; children: ReactNode; grow?: boolean }) {
  return (
    <label className={grow ? 'tk-field tk-grow' : 'tk-field'}>
      <span className="tk-label">{label}</span>
      {children}
      {hint && <small className="tk-hint">{hint}</small>}
    </label>
  );
}

export function TextInput({ mono = false, className = '', ...rest }: InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }) {
  return <input type="text" spellCheck={false} autoComplete="off" {...rest} className={`tk-input${mono ? ' tk-mono' : ''} ${className}`} />;
}

export function TextArea({ mono = true, className = '', ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement> & { mono?: boolean }) {
  return <textarea spellCheck={false} autoComplete="off" {...rest} className={`tk-input tk-textarea${mono ? ' tk-mono' : ''} ${className}`} />;
}

export function Select({ className = '', children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...rest} className={`tk-input ${className}`}>{children}</select>;
}

export function Toggle({ label, hint, checked, onChange, danger = false }: { label: string; hint?: string; checked: boolean; onChange: (next: boolean) => void; danger?: boolean }) {
  return (
    <label className={`tk-toggle${danger ? ' tk-danger' : ''}`}>
      <input type="checkbox" checked={checked} onChange={event => onChange(event.target.checked)} />
      <span><strong>{label}</strong>{hint && <small>{hint}</small>}</span>
    </label>
  );
}

export function Badge({ tone = 'muted', children }: { tone?: Tone; children: ReactNode }) {
  return <span className={`tk-badge tk-${tone}`}>{children}</span>;
}

export function Stat({ label, value, tone = 'info' }: { label: string; value: ReactNode; tone?: Tone }) {
  return (
    <div className={`glass tk-stat tk-${tone}`}>
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

export function StatGrid({ children }: { children: ReactNode }) {
  return <div className="tk-stat-grid">{children}</div>;
}

export function CopyButton({ text, label = 'Copy', copyKey = 'default' }: { text: string; label?: string; copyKey?: string }) {
  const { copy, isCopied } = useClipboard();
  const copied = isCopied(copyKey);
  return (
    <button type="button" className="btn-secondary tk-copy" onClick={() => void copy(text, copyKey)}>
      <i className={copied ? 'bi bi-check-lg' : 'bi bi-clipboard'} aria-hidden="true" /> {copied ? 'Copied' : label}
    </button>
  );
}

/** A command or config snippet with a copy button. */
export function CodeBlock({ label, code, copyLabel }: { label?: string; code: string; copyLabel?: string }) {
  return (
    <div className="tk-code">
      <div className="tk-code-head">
        <span>{label}</span>
        <CopyButton text={code} label={copyLabel} />
      </div>
      <pre><code>{code}</code></pre>
    </div>
  );
}

export interface Finding {
  severity: 'critical' | 'warning' | 'info' | 'ok';
  title: string;
  detail?: string;
}

const FINDING_TONE: Record<Finding['severity'], Tone> = { critical: 'bad', warning: 'warn', info: 'info', ok: 'ok' };
const FINDING_ICON: Record<Finding['severity'], string> = {
  critical: 'bi-x-octagon-fill',
  warning: 'bi-exclamation-triangle-fill',
  info: 'bi-info-circle-fill',
  ok: 'bi-check-circle-fill',
};

export function FindingList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return null;
  return (
    <ul className="tk-findings">
      {findings.map((finding, index) => (
        <li key={`${finding.title}-${index}`} className={`tk-${FINDING_TONE[finding.severity]}`}>
          <i className={`bi ${FINDING_ICON[finding.severity]}`} aria-hidden="true" />
          <div>
            <strong>{finding.title}</strong>
            {finding.detail && <p>{finding.detail}</p>}
          </div>
        </li>
      ))}
    </ul>
  );
}

export function KeyValueTable({ rows }: { rows: Array<[string, ReactNode]> }) {
  return (
    <table className="tk-kv">
      <tbody>
        {rows.map(([key, value]) => (
          <tr key={key}>
            <th scope="row">{key}</th>
            <td>{value === '' || value === null || value === undefined ? '—' : value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function DataTable({ head, rows, empty = 'Nothing to show.' }: { head: string[]; rows: ReactNode[][]; empty?: string }) {
  if (rows.length === 0) return <p className="tk-empty-note">{empty}</p>;
  return (
    <div className="tk-table-wrap">
      <table className="tk-table">
        <thead><tr>{head.map(cell => <th key={cell} scope="col">{cell}</th>)}</tr></thead>
        <tbody>{rows.map((row, index) => <tr key={index}>{row.map((cell, cellIndex) => <td key={cellIndex}>{cell}</td>)}</tr>)}</tbody>
      </table>
    </div>
  );
}

export function ErrorBanner({ children }: { children: ReactNode }) {
  return <div role="alert" className="glass tk-error"><i className="bi bi-exclamation-triangle-fill" aria-hidden="true" /> {children}</div>;
}

export function LoadingPanel({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div role="status" className="glass tk-loading">
      <i className="bi bi-arrow-repeat" aria-hidden="true" />
      <h3>{title}</h3>
      {children && <p>{children}</p>}
    </div>
  );
}
