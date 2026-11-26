'use client';

import Link from 'next/link';
import ResultActions, { ResultActionButton } from '@/components/share/ResultActions';
import { useClipboard } from '@/hooks/useClipboard';
import { snapshotShare } from '@/lib/api';
import {
  buildDnsSnapshotHtml,
  dnsSnapshotCsvRows,
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
  onRerun?: () => void;
}

export default function DnsSnapshotView({
  snapshot,
  mode,
  title,
  code,
  onRerun,
}: DnsSnapshotViewProps) {
  const { copy, isCopied } = useClipboard();
  const orderedResults = orderDnsResults(snapshot?.results || []);
  const allNoRecords = orderedResults.length > 0 && orderedResults.every((result) => !result.error && result.records.length === 0);
  const dnsProviderConfidence = `${capitalize(snapshot.dns_provider?.confidence || 'none')} confidence`;
  const dnsProviderSource = snapshot.dns_provider?.source ? `via ${snapshot.dns_provider.source}` : 'No strong DNS fingerprint';
  const hostingProviderConfidence = `${capitalize(snapshot.hosting_provider?.confidence || 'none')} confidence`;
  const hostingProviderSource = snapshot.hosting_provider?.source ? `via ${snapshot.hosting_provider.source}` : 'Derived from DNS answers';

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
        <ResultActions
          className="signal-actions-end"
          share={mode === 'live' ? {
            heading: 'Share DNS Snapshot',
            title: `${snapshot.domain} DNS Snapshot`,
            create: snapshotShare('dns', snapshot.domain, () => snapshot, snapshot.checked_at_utc),
          } : undefined}
          html={{
            filename: mode === 'shared' ? `${snapshot.domain}-shared-dns-snapshot` : `${snapshot.domain}-dns-snapshot`,
            build: () => buildDnsSnapshotHtml(snapshot),
          }}
          csv={{ filename: `${snapshot.domain}-dns-snapshot`, rows: () => dnsSnapshotCsvRows(snapshot) }}
        >
          {snapshot.total_records > 0 && (
            <ResultActionButton
              icon={isCopied('records') ? 'check-lg' : 'clipboard'}
              onClick={() => void copy(snapshotToPlainText(snapshot), 'records')}
            >
              {isCopied('records') ? 'Copied' : 'Copy Records'}
            </ResultActionButton>
          )}
          {mode === 'shared' && onRerun && (
            <ResultActionButton icon="arrow-repeat" onClick={onRerun}>Re-run Lookup</ResultActionButton>
          )}
        </ResultActions>
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
