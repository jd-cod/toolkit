'use client';

import Link from 'next/link';
import { useState } from 'react';
import { exportToCSV } from '@/lib/csv-utils';
import {
  buildDnsSnapshotHtml,
  buildRerunHref,
  DnsLookupResult,
  DnsSnapshot,
  formatLocation,
  formatTTL,
  formatUTC,
  isIpType,
  orderDnsResults,
  snapshotToPlainText,
  capitalize,
} from '@/lib/dns';

interface DnsSnapshotViewProps {
  snapshot: DnsSnapshot;
  mode: 'live' | 'shared';
  title?: string;
  code?: string;
  onShare?: () => void;
  onRerun?: () => void;
}

export default function DnsSnapshotView({
  snapshot,
  mode,
  title,
  code,
  onShare,
  onRerun,
}: DnsSnapshotViewProps) {
  const [copyLabel, setCopyLabel] = useState('Copy All Records');
  const [downloadLabel, setDownloadLabel] = useState('Download HTML');
  const orderedResults = orderDnsResults(snapshot?.results || []);
  const allNoRecords = orderedResults.length > 0 && orderedResults.every((result) => !result.error && result.records.length === 0);
  const dnsProviderConfidence = `${capitalize(snapshot.dns_provider?.confidence || 'none')} confidence`;
  const dnsProviderSource = snapshot.dns_provider?.source ? `via ${snapshot.dns_provider.source}` : 'No strong DNS fingerprint';
  const hostingProviderConfidence = `${capitalize(snapshot.hosting_provider?.confidence || 'none')} confidence`;
  const hostingProviderSource = snapshot.hosting_provider?.source ? `via ${snapshot.hosting_provider.source}` : 'Derived from DNS answers';

  async function handleCopy() {
    const text = snapshotToPlainText(snapshot);
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
    window.setTimeout(() => setCopyLabel('Copy All Records'), 2000);
  }

  function handleDownload() {
    const html = buildDnsSnapshotHtml(snapshot);
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = mode === 'shared' ? `${snapshot.domain}-shared-dns-snapshot.html` : `${snapshot.domain}-dns-snapshot.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    setDownloadLabel('Downloaded!');
    window.setTimeout(() => setDownloadLabel('Download HTML'), 2000);
  }

  function handleCsvDownload() {
    const rows = orderedResults.flatMap((res) => {
      if (!res.records || res.records.length === 0) {
        return [{
          domain: snapshot.domain,
          resolver: snapshot.resolver,
          type: res._type,
          record: res.message || (res.error ? `Error: ${res.error}` : 'No records'),
          ttl: '',
          priority: '',
          location: '',
          provider: '',
        }];
      }
      return res.records.map((r) => ({
        domain: snapshot.domain,
        resolver: snapshot.resolver,
        type: res._type,
        record: r.data || r.value || '',
        ttl: r.TTL != null ? String(r.TTL) : '',
        priority: r.priority != null ? String(r.priority) : '',
        location: formatLocation(r),
        provider: r.provider_label || '',
      }));
    });
    exportToCSV(rows.length > 0 ? rows : snapshot, `${snapshot.domain}-dns-snapshot`);
  }

  return (
    <div>
      {mode === 'shared' && (
        <div style={{
          background: 'rgba(99,102,241,0.06)',
          border: '1px solid rgba(99,102,241,0.15)',
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
          <i className="bi bi-share-fill" style={{ color: '#6366f1' }}></i>
          <span>
            You are viewing <strong style={{ color: 'var(--text-primary)' }}>{title || 'Shared DNS Snapshot'}</strong> - read-only DNS snapshot.
          </span>
          {code && <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>/s/{code}</span>}
          <Link href="/dns" style={{ marginLeft: 'auto', color: '#6366f1', textDecoration: 'none', fontWeight: 600 }}>
            <i className="bi bi-plus-circle" style={{ marginRight: 4 }}></i>
            New DNS Lookup
          </Link>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))', gap: 14, marginBottom: 18 }}>
        {renderStatCard(snapshot.domain, 'Domain', '', 'stat-card-ips', 'var(--font-mono)', '1.25rem')}
        {renderStatCard(String(snapshot.total_records || 0), 'Records Found', '', 'stat-card-requests', undefined, '1.9rem')}
        {renderStatCard(snapshot.dns_provider.name || 'Unknown', 'DNS Provider', `${dnsProviderConfidence} · ${dnsProviderSource}`, 'stat-card-countries')}
        {renderStatCard(snapshot.hosting_provider.name || 'Unknown', 'Hosting / Edge', `${hostingProviderConfidence} · ${hostingProviderSource}`, 'stat-card-countries')}
        {renderStatCard(snapshot.resolver_name, 'Resolver', '', 'stat-card-asns')}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 20 }}>
        <div style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
          <strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Checked At:</strong>{' '}
          <span style={{ fontFamily: 'var(--font-mono)' }}>{formatUTC(snapshot.checked_at_utc)}</span>
        </div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {mode === 'live' ? (
            <button
              onClick={onShare}
              style={actionButtonStyle('rgba(99,102,241,0.35)', '#818cf8')}
            >
              <i className="bi bi-share-fill" style={{ marginRight: 6 }} aria-hidden="true"></i>
              Share DNS Snapshot
            </button>
          ) : (
            <button
              onClick={onRerun}
              style={actionButtonStyle('rgba(34,211,238,0.35)', '#22d3ee')}
            >
              <i className="bi bi-arrow-repeat" style={{ marginRight: 6 }} aria-hidden="true"></i>
              Re-run DNS Lookup Now
            </button>
          )}
          <button onClick={handleDownload} style={actionButtonStyle('var(--border-color)', 'var(--text-secondary)')}>
            <i className="bi bi-download" style={{ marginRight: 6 }} aria-hidden="true"></i>
            {downloadLabel}
          </button>
          <button onClick={handleCsvDownload} style={actionButtonStyle('var(--border-color)', 'var(--text-secondary)')}>
            <i className="bi bi-download" style={{ marginRight: 6 }} aria-hidden="true"></i>
            Export CSV
          </button>
        </div>
      </div>

      {allNoRecords && (
        <div className="table-card" style={{ marginBottom: 16, padding: '16px 20px', color: 'var(--text-secondary)' }}>
          <i className="bi bi-info-circle" style={{ marginRight: 8 }}></i>
          No DNS records were returned for the selected record types.
        </div>
      )}

      {orderedResults.map((result) => (
        <div key={result._type} className="table-card" style={{ marginBottom: 16 }}>
          <div className="table-card-header" style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 12,
          }}>
            <h5 style={{ margin: 0, fontSize: '0.95rem' }}>
              <i className="bi bi-record-circle" style={{ marginRight: 6, color: result.error ? 'var(--accent-red)' : result.records.length > 0 ? 'var(--accent-green)' : 'var(--text-muted)' }}></i>
              {result._type} Records
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 400, marginLeft: 8 }}>
                {result.records.length} found · {result._queryTime || 0}ms
              </span>
            </h5>
          </div>
          {renderResultBody(result)}
        </div>
      ))}

      {snapshot.total_records > 0 && (
        <div style={{ display: 'flex', gap: 10 }}>
          <button onClick={handleCopy} style={actionButtonStyle('var(--border-color)', 'var(--text-secondary)')}>
            <i className="bi bi-clipboard" style={{ marginRight: 6 }} aria-hidden="true"></i>
            {copyLabel}
          </button>
          {mode === 'shared' && (
            <Link href={buildRerunHref(snapshot)} style={{ ...actionButtonStyle('rgba(99,102,241,0.25)', '#818cf8'), textDecoration: 'none' }}>
              <i className="bi bi-box-arrow-up-right" style={{ marginRight: 6 }}></i>
              Open Live Lookup
            </Link>
          )}
        </div>
      )}
    </div>
  );
}

function renderStatCard(value: string, label: string, meta: string, className: string, fontFamily?: string, fontSize = '1.1rem') {
  return (
    <div className={`stat-card ${className}`}>
      <div className="card-body" style={{ minHeight: 102, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', textAlign: 'center' }}>
        <div className="stat-value" style={{ fontSize, lineHeight: 1.2, fontFamily }}>{value}</div>
        <div className="stat-label">{label}</div>
        {meta && <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.2 }}>{meta}</div>}
      </div>
    </div>
  );
}

function renderResultBody(result: DnsLookupResult) {
  if (result.error) {
    return (
      <div style={{ padding: 16, color: 'var(--accent-red)', fontSize: '0.85rem' }}>
        <i className="bi bi-x-circle" style={{ marginRight: 6 }}></i>
        {result.error}
      </div>
    );
  }

  if (result.records.length === 0) {
    return (
      <div style={{ padding: 16, color: 'var(--text-muted)', fontSize: '0.85rem' }}>
        <i className="bi bi-info-circle" style={{ marginRight: 6 }}></i>
        {result.message || `No ${result._type} records found.`}
      </div>
    );
  }

  return (
    <div className="signal-dns-record-table-wrap">
      <table className="table-dark signal-dns-record-table" role="table" aria-label={`${result._type} records`}>
        <thead role="rowgroup">
          <tr role="row">
            <th scope="col" role="columnheader">Value</th>
            {isIpType(result._type) && <th scope="col" role="columnheader">Location</th>}
            {isIpType(result._type) && <th scope="col" role="columnheader">Provider</th>}
            {result._type === 'MX' && <th scope="col" role="columnheader">Priority</th>}
            <th scope="col" role="columnheader">TTL</th>
          </tr>
        </thead>
        <tbody role="rowgroup">
          {result.records.map((record, index) => (
            <tr key={`${record.data}-${index}`} role="row">
              <td role="cell" data-label="Value" className="signal-dns-value">
                {record.data || record.value || ''}
              </td>
              {isIpType(result._type) && (
                <td
                  role="cell" data-label="Location"
                  title={record.country || ''}
                >
                  {formatLocation(record) || '—'}
                </td>
              )}
              {isIpType(result._type) && (
                <td
                  role="cell" data-label="Provider"
                  title={record.provider_org || record.provider_label || 'Unknown'}
                >
                  {record.provider_label || 'Unknown'}
                </td>
              )}
              {result._type === 'MX' && (
                <td role="cell" data-label="Priority">
                  {record.priority || ''}
                </td>
              )}
              <td role="cell" data-label="TTL" title={`${record.TTL || 0} seconds`}>
                {formatTTL(record.TTL || 0)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function actionButtonStyle(borderColor: string, color: string) {
  return {
    background: 'none',
    border: `1px solid ${borderColor}`,
    color,
    padding: '8px 16px',
    borderRadius: 10,
    cursor: 'pointer',
    fontSize: '0.82rem',
    display: 'inline-flex',
    alignItems: 'center',
  } as const;
}
