'use client';

import Link from 'next/link';
import type { CSSProperties, ReactNode } from 'react';
import { useMemo, useState } from 'react';
import { WhoisSnapshot } from '@/lib/api';
import { exportToCSV } from '@/lib/csv-utils';
import {
  buildWhoisPlainText,
  buildWhoisRerunHref,
  buildWhoisSnapshotHtml,
  formatWhoisDate,
} from '@/lib/whois';

interface WhoisSnapshotViewProps {
  snapshot: WhoisSnapshot;
  mode: 'live' | 'shared';
  title?: string;
  code?: string;
  onShare?: () => void;
  onRerun?: () => void;
}

type ContactSection = {
  label: string;
  contact: WhoisSnapshot['contacts']['registrant'];
};

export default function WhoisSnapshotView({
  snapshot,
  mode,
  title,
  code,
  onShare,
  onRerun,
}: WhoisSnapshotViewProps) {
  const [copyLabel, setCopyLabel] = useState('Copy Summary');
  const [downloadLabel, setDownloadLabel] = useState('Download HTML');
  const [showRaw, setShowRaw] = useState(false);
  const sourceLabel = snapshot.data_source === 'rdap' ? 'RDAP' : 'WHOIS';
  const contactSections = useMemo<ContactSection[]>(() => [
    { label: 'Registrant', contact: snapshot.contacts.registrant },
    { label: 'Admin', contact: snapshot.contacts.admin },
    { label: 'Tech', contact: snapshot.contacts.tech },
  ].filter(({ contact }) => contact.name || contact.email || contact.phone), [snapshot.contacts]);

  async function handleCopy() {
    const text = buildWhoisPlainText(snapshot);
    let success = false;
    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        success = true;
      }
    } catch {
      success = false;
    }
    if (!success && typeof document !== 'undefined') {
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      } catch {
        // ignore
      }
    }
    setCopyLabel('Copied!');
    window.setTimeout(() => setCopyLabel('Copy Summary'), 2000);
  }

  function handleDownload() {
    const html = buildWhoisSnapshotHtml(snapshot);
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${snapshot.domain}-whois-snapshot.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    setDownloadLabel('Downloaded!');
    window.setTimeout(() => setDownloadLabel('Download HTML'), 2000);
  }

  function handleJsonDownload() {
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${snapshot.domain}-whois-snapshot.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  function handleCsvDownload() {
    exportToCSV(snapshot, `${snapshot.domain}-whois-snapshot`);
  }

  return (
    <div>
      {mode === 'shared' && (
        <div style={{
          background: 'rgba(56,189,248,0.06)',
          border: '1px solid rgba(56,189,248,0.18)',
          borderRadius: 10,
          padding: '10px 16px',
          marginBottom: 20,
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          flexWrap: 'wrap',
          fontSize: '0.82rem',
          color: 'var(--text-secondary)',
        }}>
          <i className="bi bi-person-vcard-fill" style={{ color: '#38bdf8' }}></i>
          <span>You are viewing <strong style={{ color: 'var(--text-primary)' }}>{title || 'Shared Registration Snapshot'}</strong> - read-only registration data.</span>
          {code && <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>/s/{code}</span>}
          <Link href={buildWhoisRerunHref(snapshot)} style={{ marginLeft: 'auto', color: '#38bdf8', textDecoration: 'none', fontWeight: 600 }}>
            <i className="bi bi-arrow-up-right-circle" style={{ marginRight: 4 }}></i>
            Open Live Lookup
          </Link>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))', gap: 14, marginBottom: 18 }}>
        <StatCard value={snapshot.domain} label="Domain" mono />
        <StatCard value={snapshot.registered ? 'Registered' : 'Unknown / Not Found'} label="Registration" />
        <StatCard value={snapshot.registrar || 'Unknown'} label="Registrar" />
        <StatCard value={snapshot.days_until_expiry == null ? 'Unknown' : String(snapshot.days_until_expiry)} label="Days Until Expiry" accent={expiryColor(snapshot.days_until_expiry)} />
        <StatCard value={snapshot.dnssec} label="DNSSEC" accent={snapshot.dnssec === 'signed' ? '#10b981' : snapshot.dnssec === 'unsigned' ? '#f59e0b' : '#94a3b8'} />
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 20 }}>
        <div style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
          <strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Source:</strong>{' '}
          <span>{sourceLabel}</span>
          <span style={{ margin: '0 8px', color: 'var(--text-muted)' }}>•</span>
          <strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Checked At:</strong>{' '}
          <span style={{ fontFamily: 'var(--font-mono)' }}>{formatWhoisDate(snapshot.checked_at_utc)}</span>
        </div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {mode === 'live' ? (
            <button onClick={onShare} style={actionButtonStyle('rgba(56,189,248,0.28)', '#38bdf8')}>
              <i className="bi bi-share-fill" style={{ marginRight: 6 }}></i>
              Share Snapshot
            </button>
          ) : (
            <button onClick={onRerun} style={actionButtonStyle('rgba(34,211,238,0.35)', '#22d3ee')}>
              <i className="bi bi-arrow-repeat" style={{ marginRight: 6 }}></i>
              Re-run Lookup
            </button>
          )}
          <button onClick={handleCopy} style={actionButtonStyle('var(--border-color)', 'var(--text-secondary)')}>
            <i className="bi bi-clipboard" style={{ marginRight: 6 }}></i>
            {copyLabel}
          </button>
          <button onClick={handleDownload} style={actionButtonStyle('var(--border-color)', 'var(--text-secondary)')}>
            <i className="bi bi-download" style={{ marginRight: 6 }}></i>
            {downloadLabel}
          </button>
          <button onClick={handleJsonDownload} style={actionButtonStyle('var(--border-color)', 'var(--text-secondary)')}>
            <i className="bi bi-filetype-json" style={{ marginRight: 6 }}></i>
            JSON
          </button>
          <button onClick={handleCsvDownload} style={actionButtonStyle('var(--border-color)', 'var(--text-secondary)')}>
            <i className="bi bi-download" style={{ marginRight: 6 }}></i>
            CSV
          </button>
        </div>
      </div>

      <Section title="Domain Status">
        {snapshot.status_labels.length > 0 ? (
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {snapshot.status_labels.map((label) => (
              <span key={label} style={{ padding: '6px 10px', borderRadius: 999, border: '1px solid var(--border-color)', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{label}</span>
            ))}
          </div>
        ) : (
          <EmptyText text={`No explicit status values parsed from ${sourceLabel}.`} />
        )}
      </Section>

      <Section title="Registrar & Dates">
        <KeyValueGrid items={[
          ['Source', sourceLabel],
          ['Registrar', snapshot.registrar || 'Unknown'],
          ['Registrar IANA ID', snapshot.registrar_iana_id || 'Unknown'],
          ['Abuse Email', snapshot.abuse_email || 'Unknown'],
          ['Abuse Phone', snapshot.abuse_phone || 'Unknown'],
          ['Creation Date', formatWhoisDate(snapshot.creation_date)],
          ['Updated Date', formatWhoisDate(snapshot.updated_date)],
          ['Expiry Date', formatWhoisDate(snapshot.expiry_date)],
          ['Privacy', snapshot.privacy_detected ? (snapshot.privacy_provider || 'Detected') : 'Not detected'],
        ]} />
      </Section>

      <Section title="Nameserver Comparison">
        <KeyValueGrid items={[
          [`${sourceLabel} Nameservers`, snapshot.nameservers.join(', ') || 'None'],
          ['Live DNS Nameservers', snapshot.dns_nameservers.join(', ') || 'None'],
          ['Exact Match', snapshot.nameserver_match == null ? 'Unknown' : (snapshot.nameserver_match ? 'Yes' : 'No')],
          [`Only In ${sourceLabel}`, snapshot.nameserver_only_in_whois.join(', ') || 'None'],
          ['Only In DNS', snapshot.nameserver_only_in_dns.join(', ') || 'None'],
        ]} />
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 16 }}>
          <Link href={`/dns?domain=${encodeURIComponent(snapshot.domain)}&types=NS`} style={linkButtonStyle}>
            <i className="bi bi-globe2" style={{ marginRight: 6 }}></i>
            Open DNS Lookup
          </Link>
          <Link href={`/ssl?domain=${encodeURIComponent(snapshot.domain)}`} style={linkButtonStyle}>
            <i className="bi bi-shield-lock" style={{ marginRight: 6 }}></i>
            Open SSL Checker
          </Link>
        </div>
      </Section>

      {contactSections.length > 0 && (
        <Section title="Contacts">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(220px,1fr))', gap: 14 }}>
            {contactSections.map(({ label, contact }) => (
              <div key={label} className="glass" style={{ padding: '16px 18px' }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 10 }}>{label}</div>
                <div style={{ display: 'grid', gap: 6, fontSize: '0.86rem', color: 'var(--text-secondary)' }}>
                  {contact.name && <div>{contact.name}</div>}
                  {contact.email && <div>{contact.email}</div>}
                  {contact.phone && <div>{contact.phone}</div>}
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}

      <Section title="Risk Signals">
        {snapshot.risk_signals.length > 0 ? (
          <ul style={{ margin: 0, paddingLeft: 18, color: 'var(--text-secondary)', display: 'grid', gap: 8 }}>
            {snapshot.risk_signals.map((signal) => <li key={signal}>{signal}</li>)}
          </ul>
        ) : (
          <EmptyText text="No risk signals were generated for this snapshot." />
        )}
      </Section>

      <Section title={`Raw ${sourceLabel}`}>
        <button onClick={() => setShowRaw((current) => !current)} style={actionButtonStyle('var(--border-color)', 'var(--text-secondary)')}>
          <i className={`bi ${showRaw ? 'bi-chevron-up' : 'bi-chevron-down'}`} style={{ marginRight: 6 }}></i>
          {showRaw ? `Hide Raw ${sourceLabel}` : `Show Raw ${sourceLabel}`}
        </button>
        {showRaw && (
          <pre style={{
            marginTop: 16,
            padding: 18,
            background: 'rgba(15,23,42,0.45)',
            borderRadius: 10,
            border: '1px solid var(--border-color)',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.78rem',
            lineHeight: 1.6,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            color: 'var(--text-secondary)',
            overflowX: 'auto',
          }}>
            {snapshot.raw_response || snapshot.raw_whois || `No raw ${sourceLabel} data available.`}
          </pre>
        )}
      </Section>
    </div>
  );
}

function StatCard({ value, label, mono, accent }: { value: string; label: string; mono?: boolean; accent?: string }) {
  return (
    <div className="stat-card">
      <div className="card-body" style={{ minHeight: 102, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', textAlign: 'center' }}>
        <div className="stat-value" style={{ fontSize: mono ? '1rem' : '1.2rem', lineHeight: 1.2, fontFamily: mono ? 'var(--font-mono)' : undefined, color: accent || 'var(--text-primary)' }}>{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="table-card" style={{ marginBottom: 16 }}>
      <div className="table-card-header"><h5 style={{ margin: 0 }}>{title}</h5></div>
      <div style={{ padding: 18 }}>{children}</div>
    </div>
  );
}

function KeyValueGrid({ items }: { items: string[][] }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(220px,1fr))', gap: 14 }}>
      {items.map(([label, value]) => (
        <div key={label}>
          <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>{label}</div>
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', wordBreak: 'break-word' }}>{value}</div>
        </div>
      ))}
    </div>
  );
}

function EmptyText({ text }: { text: string }) {
  return <div style={{ color: 'var(--text-muted)', fontSize: '0.84rem' }}>{text}</div>;
}

function expiryColor(value: number | null) {
  if (value == null) return '#94a3b8';
  if (value < 0) return '#ef4444';
  if (value <= 30) return '#f59e0b';
  return '#10b981';
}

function actionButtonStyle(borderColor: string, color: string): CSSProperties {
  return {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '9px 14px',
    borderRadius: 10,
    border: `1px solid ${borderColor}`,
    background: 'transparent',
    color,
    fontSize: '0.84rem',
    fontWeight: 600,
    cursor: 'pointer',
  };
}

const linkButtonStyle: CSSProperties = {
  ...actionButtonStyle('var(--border-color)', 'var(--text-secondary)'),
  textDecoration: 'none',
};
