'use client';

import { useMemo, useState } from 'react';
import ResultActions, { ResultActionButton } from '@/components/share/ResultActions';
import { snapshotShare } from '@/lib/api';
import { exportToCSV } from '@/lib/csv-utils';
import { downloadFile } from '@/lib/download';
import {
  ASNResult,
  ASNPrefix,
  asnPrefixCsvRows,
  FirewallFormat,
  FirewallAction,
  aggregateIpv4Cidrs,
  matchIpInPrefixes,
  generateFirewallRules,
  buildAsnPlainText,
  buildAsnSnapshotHtml,
  formatAsnDate,
  formatNumber,
} from '@/lib/asn';

interface AsnSnapshotViewProps {
  snapshot: ASNResult;
  mode: 'live' | 'shared';
  title?: string;
  code?: string;
  onRerun?: (asn: string) => void;
}

export default function AsnSnapshotView({
  snapshot,
  mode,
  title,
  code,
  onRerun,
}: AsnSnapshotViewProps) {
  // Tabs: 'prefixes' | 'firewall' | 'tester' | 'bgp'
  const [activeTab, setActiveTab] = useState<'prefixes' | 'firewall' | 'tester' | 'bgp'>('prefixes');

  // Prefix Explorer State
  const [searchQuery, setSearchQuery] = useState('');
  const [versionFilter, setVersionFilter] = useState<'all' | 'ipv4' | 'ipv6'>('all');
  const [maskFilter, setMaskFilter] = useState<string>('all');
  const [useAggregated, setUseAggregated] = useState(false);
  const [page, setPage] = useState(1);
  const pageSize = 25;
  const [copiedPrefix, setCopiedPrefix] = useState<string | null>(null);

  // Firewall Generator State
  const [fwFormat, setFwFormat] = useState<FirewallFormat>('nginx');
  const [fwAction, setFwAction] = useState<FirewallAction>('deny');
  const [fwVersion, setFwVersion] = useState<'ipv4' | 'ipv6' | 'both'>('both');
  const [fwUseAggregated, setFwUseAggregated] = useState(true);
  const [copiedFw, setCopiedFw] = useState(false);

  // IP Tester State
  const [testIp, setTestIp] = useState('');
  const [testResult, setTestResult] = useState<ReturnType<typeof matchIpInPrefixes> | null>(null);

  // Action Buttons
  const [copiedSummary, setCopiedSummary] = useState(false);

  // Computed: Aggregated IPv4 list
  const aggregatedIpv4 = useMemo(() => {
    return snapshot.aggregated_ipv4 || aggregateIpv4Cidrs(snapshot.ipv4_prefixes);
  }, [snapshot]);

  // Active list of prefixes depending on filters
  const displayedPrefixes = useMemo(() => {
    let list: ASNPrefix[] = [];

    if (versionFilter === 'all') {
      const v4List = useAggregated ? aggregatedIpv4.prefixes : snapshot.ipv4_prefixes;
      list = [...v4List, ...snapshot.ipv6_prefixes];
    } else if (versionFilter === 'ipv4') {
      list = useAggregated ? aggregatedIpv4.prefixes : snapshot.ipv4_prefixes;
    } else {
      list = snapshot.ipv6_prefixes;
    }

    if (maskFilter !== 'all') {
      list = list.filter(p => `/${p.mask}` === maskFilter || p.prefix.endsWith(maskFilter));
    }

    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      list = list.filter(p =>
        p.prefix.toLowerCase().includes(q) ||
        (p.first_ip && p.first_ip.includes(q)) ||
        (p.last_ip && p.last_ip.includes(q)) ||
        (p.netmask && p.netmask.includes(q))
      );
    }

    return list;
  }, [snapshot, aggregatedIpv4, versionFilter, maskFilter, useAggregated, searchQuery]);

  // Paginated Prefixes
  const totalPages = Math.max(1, Math.ceil(displayedPrefixes.length / pageSize));
  const paginatedPrefixes = useMemo(() => {
    const start = (page - 1) * pageSize;
    return displayedPrefixes.slice(start, start + pageSize);
  }, [displayedPrefixes, page, pageSize]);

  // Subnet Masks for Filter Chips
  const maskList = useMemo(() => {
    const counts = { ...(snapshot.stats?.v4_distribution || {}) };
    return Object.entries(counts).sort((a, b) => parseInt(a[0].replace('/', ''), 10) - parseInt(b[0].replace('/', ''), 10));
  }, [snapshot]);

  // Generated Firewall Code
  const generatedRules = useMemo(() => {
    let sourcePrefixes: ASNPrefix[] = [];
    if (fwVersion === 'ipv4') {
      sourcePrefixes = fwUseAggregated ? aggregatedIpv4.prefixes : snapshot.ipv4_prefixes;
    } else if (fwVersion === 'ipv6') {
      sourcePrefixes = snapshot.ipv6_prefixes;
    } else {
      const v4 = fwUseAggregated ? aggregatedIpv4.prefixes : snapshot.ipv4_prefixes;
      sourcePrefixes = [...v4, ...snapshot.ipv6_prefixes];
    }

    return generateFirewallRules({
      format: fwFormat,
      action: fwAction,
      asn: snapshot.asn,
      orgName: snapshot.holder || snapshot.name,
      prefixes: sourcePrefixes,
    });
  }, [snapshot, aggregatedIpv4, fwFormat, fwAction, fwVersion, fwUseAggregated]);

  // Copy helper
  async function copyText(text: string, onDone?: () => void) {
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
        success = true;
      } catch {
        // ignore
      }
    }
    if (onDone) onDone();
  }

  // Handle IP tester execution
  function handleTestIp() {
    if (!testIp.trim()) {
      setTestResult(null);
      return;
    }
    const all = [...snapshot.ipv4_prefixes, ...snapshot.ipv6_prefixes];
    const res = matchIpInPrefixes(testIp.trim(), all);
    setTestResult(res);
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* ─── Top Header Card ─── */}
      <div className="glass" style={{ padding: '1.75rem', position: 'relative', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
              <span
                style={{
                  background: 'linear-gradient(135deg, #06b6d4, #0891b2)',
                  color: '#fff',
                  fontWeight: 800,
                  fontSize: '1.1rem',
                  padding: '0.35rem 0.85rem',
                  borderRadius: '6px',
                  fontFamily: 'var(--font-mono)',
                  letterSpacing: '0.04em',
                }}
              >
                AS{snapshot.asn}
              </span>
              <h2 style={{ margin: 0, fontSize: '1.6rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                {title || snapshot.holder || snapshot.name || `AS${snapshot.asn}`}
              </h2>
              {snapshot.country_code && (
                <span
                  style={{
                    fontSize: '0.8rem',
                    background: 'rgba(255,255,255,0.08)',
                    padding: '0.25rem 0.6rem',
                    borderRadius: '4px',
                    color: 'var(--text-secondary)',
                    fontWeight: 600,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.3rem',
                  }}
                >
                  <i className="bi bi-geo-alt-fill" style={{ color: 'var(--accent-cyan)' }}></i> {snapshot.country_code}
                </span>
              )}
              {snapshot.rir && (
                <span
                  style={{
                    fontSize: '0.8rem',
                    background: 'rgba(56,189,248,0.12)',
                    color: 'var(--accent-cyan)',
                    padding: '0.25rem 0.6rem',
                    borderRadius: '4px',
                    fontWeight: 600,
                  }}
                >
                  {snapshot.rir}
                </span>
              )}
              <span
                style={{
                  fontSize: '0.8rem',
                  padding: '0.25rem 0.6rem',
                  borderRadius: '4px',
                  fontWeight: 600,
                  background: snapshot.announced ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)',
                  color: snapshot.announced ? 'var(--accent-green)' : 'var(--accent-red)',
                }}
              >
                {snapshot.announced ? '● Active (BGP Announced)' : '○ Inactive / Not Announced'}
              </span>
            </div>

            {snapshot.description && (
              <p style={{ color: 'var(--text-secondary)', margin: '0.5rem 0 0 0', fontSize: '0.92rem' }}>
                {snapshot.description}
              </p>
            )}

            {snapshot.resolved_from && (
              <div
                style={{
                  marginTop: '0.75rem',
                  fontSize: '0.85rem',
                  color: 'var(--accent-cyan)',
                  background: 'rgba(6,182,212,0.08)',
                  padding: '0.4rem 0.75rem',
                  borderRadius: '4px',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}
              >
                <i className="bi bi-arrow-return-right"></i>
                Resolved from {snapshot.resolved_from.type === 'domain' ? `domain "${snapshot.resolved_from.input}" (IP: ${snapshot.resolved_from.ip})` : snapshot.resolved_from.type === 'ip' ? `IP "${snapshot.resolved_from.ip}"` : `Organization "${snapshot.resolved_from.matched_org}"`}
              </div>
            )}
          </div>

          {/* Action Buttons */}
          <ResultActions
            className="signal-actions-end"
            share={mode === 'live' ? {
              heading: 'Share ASN Snapshot',
              title: `AS${snapshot.asn} - ${snapshot.holder || snapshot.name || 'ASN'} Intelligence Snapshot`,
              create: snapshotShare('asn', snapshot.asn, () => snapshot, snapshot.checked_at_utc),
            } : undefined}
            html={{ filename: `AS${snapshot.asn}-snapshot`, build: () => buildAsnSnapshotHtml(snapshot) }}
            csv={{ filename: `AS${snapshot.asn}-prefixes`, rows: () => asnPrefixCsvRows(snapshot) }}
          >
            <ResultActionButton
              icon="file-earmark-text"
              title="Download plain text report"
              onClick={() => downloadFile(buildAsnPlainText(snapshot), `AS${snapshot.asn}-report.txt`, 'text/plain')}
            >
              Download Text
            </ResultActionButton>
            <ResultActionButton
              icon={copiedSummary ? 'check-lg' : 'clipboard'}
              onClick={() => {
                copyText(buildAsnPlainText(snapshot), () => {
                  setCopiedSummary(true);
                  setTimeout(() => setCopiedSummary(false), 2000);
                });
              }}
            >
              {copiedSummary ? 'Copied' : 'Copy Summary'}
            </ResultActionButton>
            {mode === 'shared' && onRerun && (
              <ResultActionButton icon="arrow-repeat" onClick={() => onRerun(snapshot.asn)}>Run Live Lookup</ResultActionButton>
            )}
          </ResultActions>
        </div>

        {/* ─── Metric Stat Cards ─── */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '1rem',
            marginTop: '1.5rem',
          }}
        >
          <StatBox
            label="IPv4 Prefixes"
            value={snapshot.stats?.total_ipv4_prefixes ?? snapshot.ipv4_prefixes.length}
            subValue={`${snapshot.stats?.total_ipv4_ips_formatted || formatNumber(snapshot.stats?.total_ipv4_ips)} IPs`}
            color="var(--accent-cyan)"
            icon="bi-diagram-3-fill"
          />
          <StatBox
            label="IPv6 Prefixes"
            value={snapshot.stats?.total_ipv6_prefixes ?? snapshot.ipv6_prefixes.length}
            subValue="Announced blocks"
            color="var(--accent-amber)"
            icon="bi-hdd-network-fill"
          />
          <StatBox
            label="CIDR Optimization"
            value={`${aggregatedIpv4.reduction_percent}%`}
            subValue={`${aggregatedIpv4.saved_rules} rules saved`}
            color="var(--accent-green)"
            icon="bi-lightning-charge-fill"
          />
          <StatBox
            label="BGP Connectivity"
            value={snapshot.neighbours?.peers_count ? formatNumber(snapshot.neighbours.peers_count) : 'N/A'}
            subValue={`${snapshot.neighbours?.upstreams_count || 0} Upstreams • ${snapshot.neighbours?.downstreams_count || 0} Downstreams`}
            color="var(--accent-purple, #a855f7)"
            icon="bi-globe2"
          />
        </div>
      </div>

      {/* ─── Navigation Tabs ─── */}
      <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem', flexWrap: 'wrap' }}>
        <TabButton
          active={activeTab === 'prefixes'}
          onClick={() => setActiveTab('prefixes')}
          icon="bi-list-columns-reverse"
          label={`Prefix Explorer (${displayedPrefixes.length})`}
        />
        <TabButton
          active={activeTab === 'firewall'}
          onClick={() => setActiveTab('firewall')}
          icon="bi-shield-lock-fill"
          label="Firewall & ACL Generator"
        />
        <TabButton
          active={activeTab === 'tester'}
          onClick={() => setActiveTab('tester')}
          icon="bi-search"
          label="IP Range Matcher"
        />
        <TabButton
          active={activeTab === 'bgp'}
          onClick={() => setActiveTab('bgp')}
          icon="bi-bezier2"
          label="BGP & Network Intel"
        />
      </div>

      {/* ─── TAB 1: PREFIX EXPLORER ─── */}
      {activeTab === 'prefixes' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Subnet distribution filter pills */}
          {maskList.length > 0 && (
            <div className="glass" style={{ padding: '1rem 1.25rem' }}>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.5rem', letterSpacing: '0.05em' }}>
                <i className="bi bi-funnel-fill" style={{ marginRight: '0.4rem' }}></i> Subnet Mask Distribution (Click to filter):
              </div>
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                <button
                  onClick={() => { setMaskFilter('all'); setPage(1); }}
                  style={{
                    padding: '0.25rem 0.65rem',
                    borderRadius: '999px',
                    fontSize: '0.8rem',
                    cursor: 'pointer',
                    background: maskFilter === 'all' ? 'var(--accent-cyan)' : 'rgba(255,255,255,0.06)',
                    color: maskFilter === 'all' ? '#000' : 'var(--text-secondary)',
                    border: '1px solid var(--border-color)',
                    fontWeight: 600,
                  }}
                >
                  All Masks ({snapshot.ipv4_prefixes.length})
                </button>
                {maskList.map(([mask, count]) => (
                  <button
                    key={mask}
                    onClick={() => { setMaskFilter(maskFilter === mask ? 'all' : mask); setPage(1); }}
                    style={{
                      padding: '0.25rem 0.65rem',
                      borderRadius: '999px',
                      fontSize: '0.8rem',
                      cursor: 'pointer',
                      background: maskFilter === mask ? 'var(--accent-cyan)' : 'rgba(255,255,255,0.06)',
                      color: maskFilter === mask ? '#000' : 'var(--text-secondary)',
                      border: '1px solid var(--border-color)',
                      fontWeight: 600,
                    }}
                  >
                    {mask} ({count})
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Table Controls */}
          <div className="glass" style={{ padding: '1.25rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', gap: '0.5rem', flex: 1, minWidth: '240px' }}>
                <input
                  type="text"
                  placeholder="Filter prefixes by CIDR, IP range, or netmask..."
                  value={searchQuery}
                  onChange={e => { setSearchQuery(e.target.value); setPage(1); }}
                  style={{
                    width: '100%',
                    padding: '0.6rem 0.9rem',
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-color)',
                    borderRadius: 'var(--radius-sm)',
                    color: 'var(--text-primary)',
                    fontSize: '0.88rem',
                    fontFamily: 'var(--font-mono)',
                  }}
                />
              </div>

              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                {/* Version Selector */}
                <div style={{ display: 'inline-flex', background: 'rgba(0,0,0,0.25)', padding: '2px', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                  {(['all', 'ipv4', 'ipv6'] as const).map(v => (
                    <button
                      key={v}
                      onClick={() => { setVersionFilter(v); setPage(1); }}
                      style={{
                        padding: '0.35rem 0.75rem',
                        fontSize: '0.8rem',
                        fontWeight: 600,
                        borderRadius: '4px',
                        background: versionFilter === v ? 'var(--accent-cyan)' : 'transparent',
                        color: versionFilter === v ? '#000' : 'var(--text-secondary)',
                        border: 'none',
                        cursor: 'pointer',
                        textTransform: 'uppercase',
                      }}
                    >
                      {v}
                    </button>
                  ))}
                </div>

                {/* CIDR Aggregation Toggle */}
                {versionFilter !== 'ipv6' && (
                  <button
                    onClick={() => { setUseAggregated(!useAggregated); setPage(1); }}
                    className="btn-secondary"
                    style={{
                      padding: '0.45rem 0.85rem',
                      fontSize: '0.82rem',
                      borderColor: useAggregated ? 'var(--accent-green)' : 'var(--border-color)',
                      color: useAggregated ? 'var(--accent-green)' : 'var(--text-secondary)',
                    }}
                  >
                    <i className="bi bi-layers-fill"></i> {useAggregated ? '✓ Aggregated Supernets' : 'Raw Prefixes'}
                  </button>
                )}

                {/* Quick Copy / Export Buttons */}
                <button
                  onClick={() => {
                    const text = displayedPrefixes.map(p => p.prefix).join('\n');
                    copyText(text, () => {
                      setCopiedPrefix('all');
                      setTimeout(() => setCopiedPrefix(null), 2000);
                    });
                  }}
                  className="btn-secondary"
                  style={{ padding: '0.45rem 0.85rem', fontSize: '0.82rem' }}
                >
                  <i className={`bi ${copiedPrefix === 'all' ? 'bi-check-lg' : 'bi-clipboard'}`}></i> {copiedPrefix === 'all' ? 'Copied All!' : 'Copy Visible'}
                </button>

                <button
                  onClick={() => exportToCSV(asnPrefixCsvRows(snapshot, displayedPrefixes), `AS${snapshot.asn}-visible-prefixes`)}
                  className="btn-secondary"
                  style={{ padding: '0.45rem 0.85rem', fontSize: '0.82rem' }}
                  title="Download the prefixes currently shown as CSV"
                >
                  <i className="bi bi-file-earmark-spreadsheet"></i> CSV of Visible
                </button>
              </div>
            </div>

            {useAggregated && (
              <div
                style={{
                  background: 'rgba(34,197,94,0.08)',
                  border: '1px solid rgba(34,197,94,0.25)',
                  padding: '0.6rem 1rem',
                  borderRadius: '6px',
                  marginBottom: '1rem',
                  fontSize: '0.85rem',
                  color: 'var(--accent-green)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}
              >
                <i className="bi bi-info-circle-fill"></i>
                Supernet Aggregation Active: Reduced {aggregatedIpv4.original_count} raw subnets down to {aggregatedIpv4.aggregated_count} optimized CIDR blocks ({aggregatedIpv4.reduction_percent}% reduction).
              </div>
            )}

            {/* Prefix Table */}
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '0.65rem 1rem', textAlign: 'left', fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>#</th>
                    <th style={{ padding: '0.65rem 1rem', textAlign: 'left', fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Prefix CIDR</th>
                    <th style={{ padding: '0.65rem 1rem', textAlign: 'left', fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>IP Range (Start → End)</th>
                    <th style={{ padding: '0.65rem 1rem', textAlign: 'right', fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Usable IPs</th>
                    <th style={{ padding: '0.65rem 1rem', textAlign: 'left', fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Netmask</th>
                    <th style={{ padding: '0.65rem 1rem', textAlign: 'left', fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Wildcard</th>
                    <th style={{ padding: '0.65rem 1rem', textAlign: 'center', fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedPrefixes.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                        No prefixes found matching current filters.
                      </td>
                    </tr>
                  ) : (
                    paginatedPrefixes.map((p, idx) => {
                      const rowNum = (page - 1) * pageSize + idx + 1;
                      const isV6 = p.prefix.includes(':');
                      return (
                        <tr
                          key={p.prefix + idx}
                          style={{
                            borderBottom: '1px solid rgba(30,34,53,0.5)',
                            transition: 'background 0.15s ease',
                          }}
                        >
                          <td style={{ padding: '0.55rem 1rem', color: 'var(--text-muted)', fontSize: '0.82rem' }}>{rowNum}</td>
                          <td style={{ padding: '0.55rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.88rem', fontWeight: 600, color: isV6 ? 'var(--accent-amber)' : 'var(--accent-cyan)' }}>
                            {p.prefix}
                          </td>
                          <td style={{ padding: '0.55rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                            {p.first_ip ? `${p.first_ip} → ${p.last_ip}` : '—'}
                          </td>
                          <td style={{ padding: '0.55rem 1rem', textAlign: 'right', fontSize: '0.85rem', fontWeight: 600 }}>
                            {p.total_ips ? formatNumber(p.total_ips) : '—'}
                          </td>
                          <td style={{ padding: '0.55rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                            {p.netmask || '—'}
                          </td>
                          <td style={{ padding: '0.55rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                            {p.wildcard || '—'}
                          </td>
                          <td style={{ padding: '0.55rem 1rem', textAlign: 'center' }}>
                            <button
                              onClick={() => {
                                copyText(p.prefix, () => {
                                  setCopiedPrefix(p.prefix);
                                  setTimeout(() => setCopiedPrefix(null), 1500);
                                });
                              }}
                              style={{
                                background: 'transparent',
                                border: '1px solid var(--border-color)',
                                borderRadius: '4px',
                                color: copiedPrefix === p.prefix ? 'var(--accent-green)' : 'var(--text-secondary)',
                                padding: '0.2rem 0.5rem',
                                fontSize: '0.78rem',
                                cursor: 'pointer',
                              }}
                              title="Copy CIDR"
                            >
                              {copiedPrefix === p.prefix ? '✓' : <i className="bi bi-clipboard"></i>}
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1.25rem', paddingTop: '1rem', borderTop: '1px solid var(--border-color)', flexWrap: 'wrap', gap: '0.75rem' }}>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                  Showing {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, displayedPrefixes.length)} of {displayedPrefixes.length} prefixes
                </div>
                <div style={{ display: 'flex', gap: '0.35rem', alignItems: 'center' }}>
                  <button
                    onClick={() => setPage(1)}
                    disabled={page === 1}
                    className="btn-secondary"
                    style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
                  >
                    « First
                  </button>
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="btn-secondary"
                    style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
                  >
                    ‹ Prev
                  </button>
                  <span style={{ padding: '0 0.5rem', fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: 600 }}>
                    Page {page} of {totalPages}
                  </span>
                  <button
                    onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                    disabled={page === totalPages}
                    className="btn-secondary"
                    style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
                  >
                    Next ›
                  </button>
                  <button
                    onClick={() => setPage(totalPages)}
                    disabled={page === totalPages}
                    className="btn-secondary"
                    style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
                  >
                    Last »
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ─── TAB 2: FIREWALL & ACL GENERATOR ─── */}
      {activeTab === 'firewall' && (
        <div className="glass" style={{ padding: '1.5rem' }}>
          <div style={{ marginBottom: '1.25rem' }}>
            <h3 style={{ margin: '0 0 0.4rem 0', fontSize: '1.2rem', color: 'var(--text-primary)' }}>
              <i className="bi bi-shield-check" style={{ color: 'var(--accent-cyan)', marginRight: '0.5rem' }}></i>
              Firewall & Access Control Rules Generator
            </h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', margin: 0 }}>
              Export ready-to-paste configurations for Nginx, iptables, UFW, Apache, Cisco ACL, Mikrotik, AWS Security Groups, pfSense, and more.
            </p>
          </div>

          {/* Generator Controls */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.25rem', background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '8px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.4rem', fontWeight: 600 }}>
                Target Platform / Format:
              </label>
              <select
                value={fwFormat}
                onChange={e => setFwFormat(e.target.value as FirewallFormat)}
                style={{
                  width: '100%',
                  padding: '0.55rem 0.75rem',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-color)',
                  borderRadius: 'var(--radius-sm)',
                  color: 'var(--text-primary)',
                  fontSize: '0.9rem',
                }}
              >
                <option value="nginx">Nginx (allow / deny)</option>
                <option value="apache">Apache .htaccess (Require ip)</option>
                <option value="iptables">Linux iptables / ip6tables</option>
                <option value="nftables">Linux nftables (set & chain)</option>
                <option value="ufw">Ubuntu UFW (ufw allow/deny)</option>
                <option value="cisco_acl">Cisco IOS ACL (Wildcard Mask)</option>
                <option value="mikrotik">Mikrotik RouterOS (address-list)</option>
                <option value="ipset">Linux IPset (hash:net)</option>
                <option value="aws_sg">AWS Security Group (JSON)</option>
                <option value="pfsense">pfSense / OPNsense Alias (CIDR list)</option>
                <option value="plain_text">Plain Text CIDRs (1 per line)</option>
                <option value="csv">CSV Spreadsheet Format</option>
                <option value="json">Structured JSON Array</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.4rem', fontWeight: 600 }}>
                Action / Policy:
              </label>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button
                  type="button"
                  onClick={() => setFwAction('deny')}
                  style={{
                    flex: 1,
                    padding: '0.55rem',
                    borderRadius: '4px',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    background: fwAction === 'deny' ? 'rgba(239,68,68,0.25)' : 'rgba(255,255,255,0.05)',
                    color: fwAction === 'deny' ? 'var(--accent-red)' : 'var(--text-secondary)',
                    border: fwAction === 'deny' ? '1px solid var(--accent-red)' : '1px solid var(--border-color)',
                  }}
                >
                  🚫 Blacklist (Block / Deny)
                </button>
                <button
                  type="button"
                  onClick={() => setFwAction('allow')}
                  style={{
                    flex: 1,
                    padding: '0.55rem',
                    borderRadius: '4px',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    background: fwAction === 'allow' ? 'rgba(34,197,94,0.25)' : 'rgba(255,255,255,0.05)',
                    color: fwAction === 'allow' ? 'var(--accent-green)' : 'var(--text-secondary)',
                    border: fwAction === 'allow' ? '1px solid var(--accent-green)' : '1px solid var(--border-color)',
                  }}
                >
                  ✓ Whitelist (Allow / Permit)
                </button>
              </div>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.4rem', fontWeight: 600 }}>
                IP Version Scope:
              </label>
              <select
                value={fwVersion}
                onChange={e => setFwVersion(e.target.value as 'ipv4' | 'ipv6' | 'both')}
                style={{
                  width: '100%',
                  padding: '0.55rem 0.75rem',
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-color)',
                  borderRadius: 'var(--radius-sm)',
                  color: 'var(--text-primary)',
                  fontSize: '0.9rem',
                }}
              >
                <option value="both">IPv4 + IPv6 (Both)</option>
                <option value="ipv4">IPv4 Only</option>
                <option value="ipv6">IPv6 Only</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.4rem', fontWeight: 600 }}>
                Optimization:
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.5rem', cursor: 'pointer', fontSize: '0.85rem' }}>
                <input
                  type="checkbox"
                  checked={fwUseAggregated}
                  onChange={e => setFwUseAggregated(e.target.checked)}
                />
                Merge adjacent CIDRs (Supernetting)
              </label>
            </div>
          </div>

          {/* Code Output Box */}
          <div style={{ position: 'relative' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(15,23,42,0.8)', padding: '0.5rem 1rem', borderTopLeftRadius: '6px', borderTopRightRadius: '6px', border: '1px solid var(--border-color)', borderBottom: 'none' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {generatedRules.split('\n').length} lines generated
              </span>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button
                  onClick={() => {
                    copyText(generatedRules, () => {
                      setCopiedFw(true);
                      setTimeout(() => setCopiedFw(false), 2000);
                    });
                  }}
                  className="btn-secondary"
                  style={{ padding: '0.3rem 0.75rem', fontSize: '0.8rem' }}
                >
                  <i className={`bi ${copiedFw ? 'bi-check-lg' : 'bi-clipboard'}`}></i> {copiedFw ? 'Copied Rules!' : 'Copy Rules'}
                </button>
                <button
                  onClick={() => {
                    const ext = fwFormat === 'json' || fwFormat === 'aws_sg' ? 'json' : fwFormat === 'csv' ? 'csv' : fwFormat === 'nginx' || fwFormat === 'apache' ? 'conf' : 'txt';
                    const blob = new Blob([generatedRules], { type: 'text/plain' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `AS${snapshot.asn}-${fwFormat}-${fwAction}.${ext}`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                  }}
                  className="btn-secondary"
                  style={{ padding: '0.3rem 0.75rem', fontSize: '0.8rem' }}
                >
                  <i className="bi bi-download"></i> Save File
                </button>
              </div>
            </div>

            <pre
              style={{
                margin: 0,
                padding: '1.25rem',
                background: '#0a0e1a',
                border: '1px solid var(--border-color)',
                borderBottomLeftRadius: '6px',
                borderBottomRightRadius: '6px',
                maxHeight: '450px',
                overflowY: 'auto',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.85rem',
                lineHeight: '1.5',
                color: '#38bdf8',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}
            >
              {generatedRules}
            </pre>
          </div>
        </div>
      )}

      {/* ─── TAB 3: IP RANGE TESTER ─── */}
      {activeTab === 'tester' && (
        <div className="glass" style={{ padding: '1.75rem' }}>
          <div style={{ marginBottom: '1.25rem' }}>
            <h3 style={{ margin: '0 0 0.4rem 0', fontSize: '1.2rem', color: 'var(--text-primary)' }}>
              <i className="bi bi-search" style={{ color: 'var(--accent-cyan)', marginRight: '0.5rem' }}></i>
              IP-to-Prefix Containment Tester
            </h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', margin: 0 }}>
              Verify if an individual IPv4 or IPv6 address belongs to AS{snapshot.asn} ({snapshot.holder || snapshot.name}).
            </p>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem' }}>
            <input
              type="text"
              placeholder="e.g. 104.28.14.5 or 2606:4700::1"
              value={testIp}
              onChange={e => setTestIp(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleTestIp()}
              style={{
                flex: 1,
                padding: '0.75rem 1rem',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-color)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-primary)',
                fontSize: '0.95rem',
                fontFamily: 'var(--font-mono)',
              }}
            />
            <button onClick={handleTestIp} className="btn-primary" style={{ padding: '0.75rem 1.5rem', whiteSpace: 'nowrap' }}>
              🔍 Test IP
            </button>
          </div>

          {testResult && (
            <div
              style={{
                padding: '1.25rem',
                borderRadius: '8px',
                border: testResult.matched ? '1px solid rgba(34,197,94,0.4)' : '1px solid rgba(239,68,68,0.4)',
                background: testResult.matched ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)',
              }}
            >
              {testResult.matched ? (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-green)', fontWeight: 700, fontSize: '1.1rem', marginBottom: '0.75rem' }}>
                    <i className="bi bi-check-circle-fill"></i>
                    MATCH FOUND: IP {testResult.ip} belongs to AS{snapshot.asn}!
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginTop: '0.75rem' }}>
                    <div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Announced Prefix</div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--accent-cyan)', fontSize: '1rem' }}>{testResult.prefix}</div>
                    </div>
                    {testResult.first_ip && (
                      <div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Subnet Range</div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.88rem' }}>{testResult.first_ip} → {testResult.last_ip}</div>
                      </div>
                    )}
                    {testResult.netmask && (
                      <div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Netmask</div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.88rem' }}>{testResult.netmask}</div>
                      </div>
                    )}
                    {testResult.total_ips && (
                      <div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Subnet IPs</div>
                        <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{formatNumber(testResult.total_ips)}</div>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div style={{ color: 'var(--accent-red)', display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600 }}>
                  <i className="bi bi-x-circle-fill"></i>
                  NO MATCH: IP {testResult.ip || testIp} does NOT fall inside any of AS{snapshot.asn}&apos;s announced prefixes.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ─── TAB 4: BGP & NETWORK INTELLIGENCE ─── */}
      {activeTab === 'bgp' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Top Peers & Upstreams */}
          <div className="glass" style={{ padding: '1.5rem' }}>
            <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.15rem', color: 'var(--text-primary)' }}>
              <i className="bi bi-diagram-2" style={{ color: 'var(--accent-cyan)', marginRight: '0.5rem' }}></i>
              BGP Routing Neighbours & Peering
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
              <div style={{ background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '6px', textAlign: 'center' }}>
                <div style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--accent-cyan)' }}>{snapshot.neighbours?.upstreams_count ?? 0}</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginTop: '0.25rem' }}>Upstream Transit ASNs</div>
              </div>
              <div style={{ background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '6px', textAlign: 'center' }}>
                <div style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--accent-green)' }}>{snapshot.neighbours?.downstreams_count ?? 0}</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginTop: '0.25rem' }}>Downstream Customer ASNs</div>
              </div>
              <div style={{ background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '6px', textAlign: 'center' }}>
                <div style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--accent-purple, #a855f7)' }}>{snapshot.neighbours?.peers_count ? formatNumber(snapshot.neighbours.peers_count) : 0}</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginTop: '0.25rem' }}>Direct Peering Relations</div>
              </div>
            </div>

            {snapshot.neighbours?.top_peers && snapshot.neighbours.top_peers.length > 0 && (
              <div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.75rem' }}>
                  Top Connected Neighbour ASNs:
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem' }}>
                  {snapshot.neighbours.top_peers.map(p => (
                    <div
                      key={p.asn}
                      style={{
                        background: 'rgba(255,255,255,0.04)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '6px',
                        padding: '0.75rem 1rem',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <div>
                        <div style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>AS{p.asn}</div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'capitalize' }}>{p.type}</div>
                      </div>
                      {mode === 'live' && onRerun && (
                        <button
                          onClick={() => onRerun(String(p.asn))}
                          className="btn-secondary"
                          style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                        >
                          Inspect ›
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Abuse & Network Registration Details */}
          <div className="glass" style={{ padding: '1.5rem' }}>
            <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.15rem', color: 'var(--text-primary)' }}>
              <i className="bi bi-info-circle-fill" style={{ color: 'var(--accent-cyan)', marginRight: '0.5rem' }}></i>
              Abuse & Registration Contacts
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.25rem' }}>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Network Holder / Org</div>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{snapshot.holder || snapshot.name || 'Unknown'}</div>
              </div>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Regional Internet Registry (RIR)</div>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{snapshot.rir || 'Unknown'}</div>
              </div>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Country Jurisdiction</div>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{snapshot.country_code || 'Unknown'}</div>
              </div>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>Abuse Contact Emails</div>
                {snapshot.abuse_emails && snapshot.abuse_emails.length > 0 ? (
                  <div>
                    {snapshot.abuse_emails.map(email => (
                      <a key={email} href={`mailto:${email}`} style={{ color: 'var(--accent-cyan)', textDecoration: 'none', display: 'block', fontSize: '0.9rem' }}>
                        <i className="bi bi-envelope-fill" style={{ marginRight: '0.35rem' }}></i>{email}
                      </a>
                    ))}
                  </div>
                ) : (
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>None listed</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Snapshot Footer */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', color: 'var(--text-muted)', padding: '0 0.5rem', flexWrap: 'wrap', gap: '0.5rem' }}>
        <div>
          Data Source: RIPEstat BGP Routing Intelligence • Checked: {formatAsnDate(snapshot.checked_at_utc)}
        </div>
        {code && (
          <div style={{ fontFamily: 'var(--font-mono)' }}>
            Share Code: <strong>{code}</strong>
          </div>
        )}
      </div>
    </div>
  );
}

function StatBox({
  label,
  value,
  subValue,
  color,
  icon,
}: {
  label: string;
  value: string | number;
  subValue?: string;
  color: string;
  icon: string;
}) {
  return (
    <div
      style={{
        background: 'rgba(0,0,0,0.2)',
        border: '1px solid var(--border-color)',
        borderTop: `3px solid ${color}`,
        borderRadius: '8px',
        padding: '1rem',
        textAlign: 'center',
      }}
    >
      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.35rem' }}>
        <i className={`bi ${icon}`} style={{ color }}></i> {label}
      </div>
      <div style={{ fontSize: typeof value === 'number' ? '1.75rem' : '1.35rem', fontWeight: 800, color, fontFamily: 'var(--font-sans)', letterSpacing: '-0.02em' }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      {subValue && (
        <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
          {subValue}
        </div>
      )}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: string;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: '0.6rem 1.1rem',
        fontSize: '0.88rem',
        fontWeight: 600,
        borderRadius: '6px',
        border: active ? '1px solid var(--accent-cyan)' : '1px solid transparent',
        background: active ? 'rgba(6,182,212,0.15)' : 'transparent',
        color: active ? 'var(--accent-cyan)' : 'var(--text-secondary)',
        cursor: 'pointer',
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.45rem',
        transition: 'all 0.15s ease',
      }}
    >
      <i className={`bi ${icon}`}></i> {label}
    </button>
  );
}
