'use client';

import Link from 'next/link';
import { useState } from 'react';
import ResultActions from '@/components/share/ResultActions';
import {
  buildMyIPExportData,
  buildMyIPReportHtml,
  countryFlag,
  myIPReportFilename,
  networkBadge,
  normalizeMyIPSnapshot,
  UNKNOWN_CLIENT,
} from '@/lib/myip';

function DetailRow({ label, value }: { label: string; value?: string | null }) {
  return <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
    <td style={{ padding: '0.625rem 1.25rem', color: 'var(--text-muted)', fontSize: '0.85rem', width: '40%' }}>{label}</td>
    <td style={{ padding: '0.625rem 1.25rem', fontFamily: 'var(--font-mono)', fontSize: '0.85rem', wordBreak: 'break-all' }}>{value || '—'}</td>
  </tr>;
}

/** Read-only view of a shared My IP snapshot. */
export default function MyIpSnapshotView({ snapshot, title, code }: { snapshot: unknown; title?: string; code?: string }) {
  const d = normalizeMyIPSnapshot(snapshot);
  const client = d.client;
  const conn = d.connection;
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      void navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    }
  };

  const badge = networkBadge(d.network_type);

  return (
    <>
      {/* Banner */}
      <div style={{
        background: 'rgba(99,102,241,0.06)',
        border: '1px solid rgba(99,102,241,0.18)',
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
        <i className="bi bi-geo-alt-fill" style={{ color: 'var(--accent-primary)' }}></i>
        <span>You are viewing <strong style={{ color: 'var(--text-primary)' }}>{title || 'Shared IP Report'}</strong> — read-only snapshot.</span>
        {code && <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>/s/{code}</span>}
        <Link href="/myip" style={{ marginLeft: 'auto', color: 'var(--accent-primary)', textDecoration: 'none', fontWeight: 600 }}>
          <i className="bi bi-arrow-up-right-circle" style={{ marginRight: 4 }}></i>
          Open Live Tool
        </Link>
      </div>

      {/* IP Address Card */}
      <div className="glass" style={{ padding: '2rem', textAlign: 'center', marginBottom: '1.5rem', borderTop: '3px solid #6366f1' }}>
        <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '1rem' }}>
          Public IP Address
        </div>

        {/* Dual-stack IP display */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 280px), 1fr))', gap: '1rem', textAlign: 'center' }}>
          {/* IPv4 */}
          <div style={{ background: 'rgba(99,102,241,0.04)', border: '1px solid rgba(99,102,241,0.12)', borderRadius: 14, padding: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginBottom: '0.75rem' }}>
              <span style={{ background: 'rgba(59,130,246,0.15)', border: '1px solid rgba(59,130,246,0.3)', borderRadius: 6, padding: '2px 10px', fontSize: '0.72rem', fontWeight: 700, color: '#3b82f6' }}>IPv4</span>
              {d.ipv4 && <span style={{ background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.25)', borderRadius: 6, padding: '2px 8px', fontSize: '0.68rem', fontWeight: 600, color: 'var(--accent-green)' }}>Detected</span>}
            </div>
            {d.ipv4 ? (
              <div>
                <div style={{ fontSize: '1.6rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-primary)', letterSpacing: '-0.02em', marginBottom: '0.5rem' }}>
                  {d.ipv4}
                </div>
                <button
                  onClick={() => copyToClipboard(d.ipv4!, 'v4')}
                  style={{ background: copiedKey === 'v4' ? 'rgba(16,185,129,0.15)' : 'rgba(99,102,241,0.1)', border: '1px solid ' + (copiedKey === 'v4' ? 'rgba(16,185,129,0.3)' : 'rgba(99,102,241,0.2)'), borderRadius: 8, padding: '4px 12px', cursor: 'pointer', color: copiedKey === 'v4' ? 'var(--accent-green)' : 'var(--accent-primary)', fontSize: '0.78rem', fontWeight: 600, transition: 'all 0.2s ease', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                >
                  <i className={copiedKey === 'v4' ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i>
                  {copiedKey === 'v4' ? 'Copied!' : 'Copy'}
                </button>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                <i className="bi bi-x-circle" style={{ color: 'var(--accent-red)', marginRight: 6 }}></i>
                Not Detected
              </div>
            )}
          </div>

          {/* IPv6 */}
          <div style={{ background: 'rgba(168,85,247,0.04)', border: '1px solid rgba(168,85,247,0.12)', borderRadius: 14, padding: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginBottom: '0.75rem' }}>
              <span style={{ background: 'rgba(168,85,247,0.15)', border: '1px solid rgba(168,85,247,0.3)', borderRadius: 6, padding: '2px 10px', fontSize: '0.72rem', fontWeight: 700, color: 'var(--accent-purple)' }}>IPv6</span>
              {d.ipv6 && <span style={{ background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.25)', borderRadius: 6, padding: '2px 8px', fontSize: '0.68rem', fontWeight: 600, color: 'var(--accent-green)' }}>Detected</span>}
            </div>
            {d.ipv6 ? (
              <div>
                <div style={{ fontSize: '1.1rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--accent-purple)', letterSpacing: '-0.02em', marginBottom: '0.5rem', wordBreak: 'break-all' }}>
                  {d.ipv6}
                </div>
                <button
                  onClick={() => copyToClipboard(d.ipv6!, 'v6')}
                  style={{ background: copiedKey === 'v6' ? 'rgba(16,185,129,0.15)' : 'rgba(168,85,247,0.1)', border: '1px solid ' + (copiedKey === 'v6' ? 'rgba(16,185,129,0.3)' : 'rgba(168,85,247,0.2)'), borderRadius: 8, padding: '4px 12px', cursor: 'pointer', color: copiedKey === 'v6' ? 'var(--accent-green)' : 'var(--accent-purple)', fontSize: '0.78rem', fontWeight: 600, transition: 'all 0.2s ease', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                >
                  <i className={copiedKey === 'v6' ? 'bi bi-check-lg' : 'bi bi-clipboard'}></i>
                  {copiedKey === 'v6' ? 'Copied!' : 'Copy'}
                </button>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                <i className="bi bi-x-circle" style={{ color: 'var(--accent-red)', marginRight: 6 }}></i>
                Not Detected
                <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4, opacity: 0.7 }}>Your network does not support IPv6</p>
              </div>
            )}
          </div>
        </div>

        {/* Stack type badge */}
        <div style={{ marginTop: '1rem', display: 'flex', justifyContent: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <span style={{ background: d.isDualStack ? 'rgba(16,185,129,0.1)' : 'rgba(245,158,11,0.1)', border: `1px solid ${d.isDualStack ? 'rgba(16,185,129,0.25)' : 'rgba(245,158,11,0.25)'}`, borderRadius: 8, padding: '4px 14px', fontSize: '0.78rem', fontWeight: 700, color: d.isDualStack ? 'var(--accent-green)' : 'var(--accent-amber)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <i className={d.isDualStack ? 'bi bi-check-circle-fill' : 'bi bi-exclamation-triangle-fill'} style={{ fontSize: '0.72rem' }}></i>
            {d.isDualStack ? 'Dual-Stack (IPv4 + IPv6)' : d.ipv4 ? 'IPv4 Only' : 'IPv6 Only'}
          </span>
          {badge && (
            <span style={{ background: `${badge.color}15`, border: `1px solid ${badge.color}30`, borderRadius: 8, padding: '4px 14px', fontSize: '0.78rem', fontWeight: 700, color: badge.color, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <i className={badge.icon} style={{ fontSize: '0.72rem' }}></i>
              {badge.label}
            </span>
          )}
        </div>
      </div>

      {/* Action Toolbar */}
      <div style={{ marginBottom: '1.5rem' }}>
        <ResultActions
          className="signal-actions-end"
          html={{
            filename: myIPReportFilename(d, { ipv4: d.ipv4, ipv6: d.ipv6 }),
            build: () => buildMyIPReportHtml(d, { ...(d.client || UNKNOWN_CLIENT), connection: d.connection }, { ipv4: d.ipv4, ipv6: d.ipv6 }),
          }}
          csv={{
            filename: myIPReportFilename(d, { ipv4: d.ipv4, ipv6: d.ipv6 }),
            rows: () => buildMyIPExportData(d, { ipv4: d.ipv4, ipv6: d.ipv6 }),
          }}
        />
      </div>

      {/* 1. Geolocation */}
      <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
        <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
          <i className="bi bi-pin-map-fill" style={{ color: '#3b82f6', marginRight: '0.5rem' }}></i>Geolocation
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}><tbody>
          <DetailRow label="City" value={d.city} />
          <DetailRow label="Region" value={d.region} />
          <DetailRow label="Country" value={d.country ? `${countryFlag(d.country_code)} ${d.country}` : ''} />
          <DetailRow label="Postal Code" value={d.postal_code} />
          <DetailRow label="Timezone" value={d.timezone} />
          <DetailRow label="UTC Offset" value={d.utc_offset} />
        </tbody></table>
      </div>

      {/* 2. Network */}
      <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
        <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
          <i className="bi bi-hdd-network-fill" style={{ color: '#10b981', marginRight: '0.5rem' }}></i>Network
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}><tbody>
          <DetailRow label="ISP" value={d.isp} />
          <DetailRow label="ASN" value={d.asn ? `AS${d.asn}` : ''} />
          <DetailRow label="Reverse DNS" value={d.reverse_dns} />
        </tbody></table>
      </div>

      {/* 3. Browser & Device */}
      {client?.browser && (
        <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
          <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
            <i className="bi bi-laptop" style={{ color: '#a855f7', marginRight: '0.5rem' }}></i>Browser & Device
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}><tbody>
            <DetailRow label="Browser" value={client.browser} />
            <DetailRow label="OS" value={client.os} />
            <DetailRow label="Screen" value={client.screen} />
            <DetailRow label="Language" value={client.language} />
            <DetailRow label="Cookies" value={client.cookies} />
            <DetailRow label="GPU" value={client.webgl} />
          </tbody></table>
        </div>
      )}

      {/* 4. HTTP Headers */}
      {d.headers && (
        <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
          <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
            <i className="bi bi-code-slash" style={{ color: '#06b6d4', marginRight: '0.5rem' }}></i>HTTP Headers
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}><tbody>
            <DetailRow label="User-Agent" value={d.headers.user_agent} />
            <DetailRow label="Accept-Language" value={d.headers.accept_language} />
            <DetailRow label="Accept-Encoding" value={d.headers.accept_encoding} />
            <DetailRow label="DNT" value={d.headers.dnt || 'Not set'} />
          </tbody></table>
        </div>
      )}

      {/* 5. Connection */}
      {conn?.supported && (
        <div className="glass" style={{ marginBottom: '1.5rem', overflow: 'hidden' }}>
          <div style={{ padding: '0.75rem 1.25rem', borderBottom: '1px solid var(--border-color)', fontWeight: 600 }}>
            <i className="bi bi-speedometer2" style={{ color: '#f59e0b', marginRight: '0.5rem' }}></i>Connection
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}><tbody>
            <DetailRow label="Type" value={conn.type} />
            <DetailRow label="Effective Type" value={String(conn.effectiveType || '').toUpperCase()} />
            <DetailRow label="Bandwidth" value={conn.downlink != null ? `${conn.downlink} Mbps` : ''} />
            <DetailRow label="RTT" value={conn.rtt != null ? `${conn.rtt} ms` : ''} />
          </tbody></table>
        </div>
      )}

      <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.78rem' }}>
        Checked at {d.checked_at_utc ? new Date(d.checked_at_utc).toUTCString() : 'Unknown'}
      </div>
    </>
  );
}
