'use client';

import React, { useState } from 'react';
import ResultActions, { ResultActionButton } from '@/components/share/ResultActions';
import { useClipboard } from '@/hooks/useClipboard';
import { snapshotShare } from '@/lib/api';
import {
  buildIpInfoReportHtml,
  buildIpInfoSummary,
  getCountryFlag,
  getCountryName,
  ipInfoCounts,
  ipInfoSubject,
  type IPInfoResultItem,
  type IpInfoSnapshot,
} from '@/lib/ipinfo';

/** Batch IP lookup results, used by the live IP Info page and by shared links. */
export default function IpInfoResultView({ snapshot, mode }: { snapshot: IpInfoSnapshot; mode: 'live' | 'shared' }) {
  const { copy, isCopied } = useClipboard();
  const { results } = snapshot;
  const [expandedIp, setExpandedIp] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'rdns' | 'risk' | 'abusive'>('all');
  const filename = `abuse-ip-report-${snapshot.checked_at_utc.split('T')[0]}`;

  const riskBadgeStyle = (level: string) => {
    switch (level) {
      case 'high':
        return { color: 'var(--accent-red)', bg: 'rgba(239, 68, 68, 0.15)', label: 'High' };
      case 'medium':
        return { color: 'var(--accent-amber)', bg: 'rgba(245, 158, 11, 0.15)', label: 'Medium' };
      case 'safe':
        return { color: 'var(--accent-green)', bg: 'rgba(16, 185, 129, 0.15)', label: 'Safe' };
      case 'low':
      default:
        return { color: 'var(--accent-cyan)', bg: 'rgba(34, 211, 238, 0.15)', label: 'Low' };
    }
  };

  const { total: totalCount, rdns: rdnsCount, risk: riskCount, abuse: abuseCount } = ipInfoCounts(results);

  const filteredResults = results.filter(r => {
    if (filter === 'rdns') return Boolean(r.reverse_dns);
    if (filter === 'risk') return r.risk_level === 'high' || r.risk_level === 'medium';
    if (filter === 'abusive') return r.abuse_score !== null && r.abuse_score > 0;
    return true;
  });

  return (
    <>
      <div style={{ marginBottom: '1.5rem' }}>
        <ResultActions
          className="signal-actions-end"
          share={mode === 'live' ? {
            heading: 'Share IP Report',
            title: `IP Info Report — ${ipInfoSubject(results)}`,
            create: snapshotShare('abuse', ipInfoSubject(results), () => snapshot, snapshot.checked_at_utc),
          } : undefined}
          html={{ filename, build: () => buildIpInfoReportHtml(snapshot) }}
          csv={{ filename, rows: () => results }}
        >
          <ResultActionButton
            icon={isCopied('all_ips') ? 'check-lg' : 'clipboard'}
            onClick={() => void copy(buildIpInfoSummary(results), 'all_ips')}
          >
            {isCopied('all_ips') ? 'Copied' : 'Copy Summary'}
          </ResultActionButton>
        </ResultActions>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        <div className="glass" style={{ padding: '1.25rem', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--text-primary)' }}>{totalCount}</div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Total IPs Analyzed</div>
        </div>
        <div className="glass" style={{ padding: '1.25rem', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--accent-cyan)' }}>{rdnsCount}</div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Reverse DNS Found</div>
        </div>
        <div className="glass" style={{ padding: '1.25rem', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: riskCount > 0 ? 'var(--accent-amber)' : 'var(--accent-green)' }}>{riskCount}</div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Risk Flags / Elevated</div>
        </div>
        <div className="glass" style={{ padding: '1.25rem', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: abuseCount > 0 ? 'var(--accent-red)' : 'var(--text-secondary)' }}>{abuseCount}</div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Abuse Reports</div>
        </div>
      </div>

      <div className="glass signal-abuse-results" style={{ overflow: 'hidden' }}>
        <div style={{ padding: '0.85rem 1.25rem', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <i className="bi bi-list-columns-reverse"></i>
            <span>Results ({filteredResults.length} of {results.length} IPs)</span>
          </div>
          <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
            <button onClick={() => setFilter('all')} className="btn-secondary" style={{ padding: '0.25rem 0.65rem', fontSize: '0.78rem', background: filter === 'all' ? 'var(--accent-primary)' : undefined, color: filter === 'all' ? '#fff' : undefined }}>All ({totalCount})</button>
            <button onClick={() => setFilter('rdns')} className="btn-secondary" style={{ padding: '0.25rem 0.65rem', fontSize: '0.78rem', background: filter === 'rdns' ? 'var(--accent-cyan)' : undefined, color: filter === 'rdns' ? '#fff' : undefined }}>rDNS ({rdnsCount})</button>
            <button onClick={() => setFilter('risk')} className="btn-secondary" style={{ padding: '0.25rem 0.65rem', fontSize: '0.78rem', background: filter === 'risk' ? 'var(--accent-amber)' : undefined, color: filter === 'risk' ? '#fff' : undefined }}>Risk Flags ({riskCount})</button>
            {abuseCount > 0 && (
              <button onClick={() => setFilter('abusive')} className="btn-secondary" style={{ padding: '0.25rem 0.65rem', fontSize: '0.78rem', background: filter === 'abusive' ? 'var(--accent-red)' : undefined, color: filter === 'abusive' ? '#fff' : undefined }}>Abusive ({abuseCount})</button>
            )}
          </div>
        </div>

        <div className="signal-abuse-desktop-table" style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
            <colgroup>{['3%', '13%', '16%', '14%', '20%', '7%', '10%', '17%'].map((width, index) => <col key={index} style={{ width }} />)}</colgroup>
            <thead>
              <tr style={{ background: 'rgba(0,0,0,0.1)' }}>
                {['#', 'IP Address', 'Reverse DNS (PTR)', 'Country & Location', 'ASN & Network / ISP', 'Risk', 'Abuse Score', 'Actions'].map(h => (
                  <th key={h} style={{ padding: '0.75rem 0.5rem', textAlign: 'left', fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.03em' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredResults.map((r: IPInfoResultItem, i: number) => {
                const badge = riskBadgeStyle(r.risk_level);
                const isExpanded = expandedIp === r.ip;
                const flag = getCountryFlag(r.country_code);
                const countryFullName = getCountryName(r.country_code, r.country);

                return (
                  <React.Fragment key={i}>
                  <tr style={{ borderBottom: isExpanded ? 'none' : '1px solid var(--border-color)' }}>
                    <td style={{ padding: '0.65rem 1rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>{i + 1}</td>
                    <td style={{ padding: '0.65rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 600 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                        <span>{r.ip}</span>
                        <span style={{ fontSize: '0.68rem', padding: '1px 5px', borderRadius: 4, background: 'rgba(255,255,255,0.06)', color: 'var(--text-muted)' }}>{r.ip_version}</span>
                      </div>
                    </td>
                    <td style={{ padding: '0.65rem 1rem', fontSize: '0.82rem', fontFamily: 'var(--font-mono)' }}>
                      {r.reverse_dns ? <span style={{ color: 'var(--accent-cyan)' }}>{r.reverse_dns}</span> : <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>No PTR record</span>}
                    </td>
                    <td style={{ padding: '0.65rem 1rem', fontSize: '0.85rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                        <span style={{ fontSize: '1.1rem' }}>{flag}</span>
                        <span style={{ fontWeight: 600 }}>{countryFullName || 'Unknown'}</span>
                        {r.country_code && r.country_code !== '--' && <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>({r.country_code})</span>}
                      </div>
                    </td>
                    <td style={{ padding: '0.65rem 1rem', fontSize: '0.82rem', color: 'var(--text-primary)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                        {r.asn && (
                          <span style={{ fontSize: '0.72rem', padding: '2px 6px', borderRadius: 4, background: 'rgba(6, 182, 212, 0.15)', color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)', fontWeight: 600, display: 'inline-block' }}>
                            AS{r.asn}
                          </span>
                        )}
                        <span style={{ fontWeight: 500 }}>{r.isp}</span>
                      </div>
                      {r.usage_type && r.usage_type !== 'N/A' && r.usage_type !== r.isp && (
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                          {r.usage_type}
                        </div>
                      )}
                    </td>
                    <td style={{ padding: '0.65rem 1rem' }}>
                      <span style={{ fontWeight: 700, color: badge.color, background: badge.bg, padding: '0.2rem 0.55rem', borderRadius: 'var(--radius-sm)', fontSize: '0.8rem', display: 'inline-block' }}>{badge.label}</span>
                    </td>
                    <td style={{ padding: '0.65rem 1rem', fontSize: '0.85rem' }}>
                      {r.abuse_score !== null ? <span style={{ fontWeight: 700, color: r.abuse_score > 0 ? 'var(--accent-red)' : 'var(--accent-green)' }}>{r.abuse_score}%</span> : <span style={{ color: 'var(--text-muted)' }}>N/A</span>}
                    </td>
                    <td style={{ padding: '0.65rem 1rem', fontSize: '0.8rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <button className="btn-secondary" style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }} onClick={() => setExpandedIp(isExpanded ? null : r.ip)}>
                          <span>{isExpanded ? 'Hide' : 'Info'}</span>
                          <i className={`bi bi-chevron-${isExpanded ? 'up' : 'down'}`}></i>
                        </button>
                        <a href={`https://www.abuseipdb.com/check/${r.ip}`} target="_blank" rel="noopener noreferrer" className="btn-secondary" style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}><i className="bi bi-box-arrow-up-right"></i></a>
                      </div>
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr style={{ background: 'rgba(0,0,0,0.05)' }}>
                      <td colSpan={8} style={{ padding: '1rem', fontSize: '0.85rem' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                          <div><strong>ASN:</strong> {r.asn || 'N/A'} ({r.asn_org || 'N/A'})</div>
                          <div><strong>Usage:</strong> {r.usage_type}</div>
                          <div><strong>Reports:</strong> {r.total_reports}</div>
                          <div><strong>Last Reported:</strong> {r.last_reported_at || 'Never'}</div>
                          <div><strong>Security:</strong> {r.is_tor ? 'TOR Exit Node' : 'Not TOR'} / {r.is_whitelisted ? 'Whitelisted' : 'Not Whitelisted'}</div>
                        </div>
                      </td>
                    </tr>
                  )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="signal-abuse-mobile-list" aria-label="IP lookup results for mobile screens">
          {filteredResults.map((r: IPInfoResultItem, i: number) => {
            const badge = riskBadgeStyle(r.risk_level);
            const isExpanded = expandedIp === r.ip;
            const flag = getCountryFlag(r.country_code);
            const countryFullName = getCountryName(r.country_code, r.country);

            return (
              <article className="signal-abuse-mobile-card" key={`mobile-${r.ip}-${i}`}>
                <div className="signal-abuse-mobile-card-heading">
                  <div>
                    <span className="signal-abuse-mobile-index">#{i + 1}</span>
                    <strong>{r.ip}</strong>
                    <small>{r.ip_version}</small>
                  </div>
                  <span style={{ color: badge.color, background: badge.bg }}>{badge.label}</span>
                </div>
                <dl className="signal-abuse-mobile-facts">
                  <div><dt>Reverse DNS</dt><dd>{r.reverse_dns || 'No PTR record'}</dd></div>
                  <div><dt>Country</dt><dd>{flag} {countryFullName || 'Unknown'}</dd></div>
                  <div><dt>Network</dt><dd>{r.asn ? `AS${r.asn} · ` : ''}{r.isp}</dd></div>
                  <div><dt>Abuse score</dt><dd className={r.abuse_score !== null && r.abuse_score > 0 ? 'is-risk' : ''}>{r.abuse_score !== null ? `${r.abuse_score}%` : 'N/A'}</dd></div>
                </dl>
                <div className="signal-abuse-mobile-actions">
                  <button className="btn-secondary" type="button" aria-expanded={isExpanded} onClick={() => setExpandedIp(isExpanded ? null : r.ip)}>
                    <i className={`bi bi-chevron-${isExpanded ? 'up' : 'down'}`} aria-hidden="true"></i>
                    {isExpanded ? 'Hide details' : 'Show details'}
                  </button>
                  <a href={`https://www.abuseipdb.com/check/${r.ip}`} target="_blank" rel="noopener noreferrer" className="btn-secondary">
                    AbuseIPDB <i className="bi bi-box-arrow-up-right" aria-hidden="true"></i>
                  </a>
                </div>
                {isExpanded && (
                  <div className="signal-abuse-mobile-expanded">
                    <span><strong>ASN:</strong> {r.asn || 'N/A'} ({r.asn_org || 'N/A'})</span>
                    <span><strong>Usage:</strong> {r.usage_type}</span>
                    <span><strong>Reports:</strong> {r.total_reports}</span>
                    <span><strong>Last reported:</strong> {r.last_reported_at || 'Never'}</span>
                    <span><strong>Security:</strong> {r.is_tor ? 'TOR exit node' : 'Not TOR'} · {r.is_whitelisted ? 'Whitelisted' : 'Not whitelisted'}</span>
                  </div>
                )}
              </article>
            );
          })}
        </div>
      </div>
    </>
  );
}
