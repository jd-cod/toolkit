'use client';

import Link from 'next/link';
import { useCallback, useEffect, useRef, useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import DnsSnapshotView from '@/components/DnsSnapshotView';
import { api } from '@/lib/api';
import { exportToCSV } from '@/lib/csv-utils';
import { useClipboard } from '@/hooks/useClipboard';
import {
  buildDnsSnapshot,
  buildDnsSnapshotHtml,
  cleanDomain,
  createRejectedLookupResult,
  DEFAULT_DNS_TYPES,
  DNS_TYPES,
  DnsLookupResult,
  DnsSnapshot,
  emptyProvider,
  normalizeLookupResult,
  normalizeProviderLabel,
  RESOLVER_OPTIONS,
  isIpType,
  formatUTC,
} from '@/lib/dns';
import { ensureGeoIPReady } from '@/lib/geoip';
import { formatGlobalDnsRecord, type GlobalDnsRegion } from '@/lib/tool-results';

export default function DNSPage() {
  const [isMounted, setIsMounted] = useState(false);
  const { copy, isCopied } = useClipboard();
  const [mode, setMode] = useState<'standard' | 'global'>('standard');
  const [domain, setDomain] = useState('');
  const [resolver, setResolver] = useState('1.1.1.1');
  const [selectedTypes, setSelectedTypes] = useState<string[]>([...DEFAULT_DNS_TYPES]);
  const [loading, setLoading] = useState(false);
  const [globalResults, setGlobalResults] = useState<GlobalDnsRegion[]>([]);
  const [globalAvailable, setGlobalAvailable] = useState(false);
  const [snapshot, setSnapshot] = useState<DnsSnapshot | null>(null);
  const [error, setError] = useState('');
  const [shareModalOpen, setShareModalOpen] = useState(false);
  const [shareTitle, setShareTitle] = useState('');
  const [shareExpiry, setShareExpiry] = useState('never');
  const [sharePassword, setSharePassword] = useState('');
  const [shareLoading, setShareLoading] = useState(false);
  const [shareError, setShareError] = useState('');
  const [shareUrl, setShareUrl] = useState('');
  const prefillApplied = useRef(false);

  useEffect(() => {
    setIsMounted(true);
    let active = true;
    api.getGlobalDnsCapability().then(result => { if (active) setGlobalAvailable(result.available); }).catch(() => { if (active) setGlobalAvailable(false); });
    return () => { active = false; };
  }, []);

  const doLookup = useCallback(async (overrides?: {
    domainOverride?: string;
    resolverOverride?: string;
    typesOverride?: string[];
  }) => {
    const normalizedDomain = cleanDomain(overrides?.domainOverride || domain);
    const activeResolver = overrides?.resolverOverride || resolver;
    const activeTypes = overrides?.typesOverride || selectedTypes;

    if (!normalizedDomain) return;
    if (activeTypes.length === 0) {
      setError('Select at least one record type.');
      return;
    }

    if (mode === 'global') {
      if (!globalAvailable) { setError('Global propagation is unavailable. Choose Standard Query.'); return; }
      if (activeTypes.length !== 1) {
        setError('Please select exactly one record type for Global Propagation.');
        return;
      }
      setDomain(normalizedDomain);
      setSelectedTypes(activeTypes);
      setLoading(true);
      setError('');
      setGlobalResults([]);
      setSnapshot(null);
      try {
        const res = await api.lookupGlobalDNS(normalizedDomain, activeTypes[0]);
        if (res.error) throw new Error(res.error);
        if (!res.results?.length) throw new Error('No regional results were returned. Try again or use a standard query.');
        setGlobalResults(res.results);
        if (res.results.every(result => result.status !== 'success')) setError('All regional queries failed. Individual errors are shown below.');
      } catch (err: unknown) {
        setError(getErrorMessage(err, 'Global DNS lookup failed.'));
      } finally {
        setLoading(false);
      }
      return;
    }

    setDomain(normalizedDomain);
    setResolver(activeResolver);
    setSelectedTypes(activeTypes);
    setLoading(true);
    setError('');
    setSnapshot(null);
    try {
      const checkedAtUtc = new Date().toISOString();
      const settled = await Promise.allSettled(
        activeTypes.map(async (recordType) => {
          const start = performance.now();
          const data = await api.lookupDNS(normalizedDomain, recordType, activeResolver);
          return normalizeLookupResult(
            { ...data, _type: recordType, _queryTime: Math.round(performance.now() - start) },
            recordType
          );
        })
      );

      const results: DnsLookupResult[] = settled.map((entry, index) => {
        if (entry.status === 'fulfilled') return entry.value;
        return createRejectedLookupResult(activeTypes[index], entry.reason, 0);
      });

      await enrichIpProviders(results);

      setSnapshot(buildDnsSnapshot({
        domain: normalizedDomain,
        resolver: activeResolver,
        selectedTypes: activeTypes,
        checkedAtUtc,
        results,
      }));
    } catch (error: unknown) {
      setError(getErrorMessage(error, 'DNS lookup failed.'));
    } finally {
      setLoading(false);
    }
  }, [domain, resolver, selectedTypes, mode, globalAvailable]);

  useEffect(() => {
    if (prefillApplied.current) return;
    prefillApplied.current = true;

    const params = new URLSearchParams(window.location.search);
    const domainParam = params.get('domain');
    const resolverParam = params.get('resolver');
    const typesParam = params.get('types');
    const nextDomain = domainParam ? cleanDomain(domainParam) : '';
    const nextResolver = resolverParam || '1.1.1.1';
    const nextTypes = (typesParam || '')
      .split(',')
      .map((value) => value.trim().toUpperCase())
      .filter((value) => DNS_TYPES.includes(value as (typeof DNS_TYPES)[number]));

    if (nextDomain) setDomain(nextDomain);
    if (nextResolver) setResolver(nextResolver);
    if (nextTypes.length > 0) setSelectedTypes(nextTypes);

    if (nextDomain) {
      void doLookup({
        domainOverride: nextDomain,
        resolverOverride: nextResolver,
        typesOverride: nextTypes.length > 0 ? nextTypes : [...DEFAULT_DNS_TYPES],
      });
    }
  }, [doLookup]);

  async function enrichIpProviders(results: DnsLookupResult[]) {
    const needsGeoIp = results.some((result) => isIpType(result._type) && result.records.length > 0);
    if (!needsGeoIp) return;

    const geoIp = await ensureGeoIPReady();
    if (!geoIp) return;

    for (const result of results) {
      if (!isIpType(result._type)) continue;

      result.records = result.records.map((record) => {
        const ip = record.data || record.value || '';
        const asnLookup = geoIp.lookupASN(ip);
        const countryLookup = geoIp.lookupCountry(ip);
        const org = asnLookup?.asn_org || 'Unknown';
        return {
          ...record,
          provider_label: normalizeProviderLabel(org),
          provider_org: org,
          provider_asn: asnLookup?.asn || 0,
          country: countryLookup?.country || '',
          country_code: countryLookup?.country_code || '',
        };
      });
    }
  }

  function toggleType(recordType: string) {
    if (mode === 'global') {
      setSelectedTypes([recordType]);
    } else {
      setSelectedTypes((current) => {
        if (current.includes(recordType)) return current.filter((item) => item !== recordType);
        return [...current, recordType];
      });
    }
  }

  function buildGlobalSnapshot(): DnsSnapshot {
    return {
      domain,
      resolver: 'global',
      resolver_name: 'Global AWS Lambda Network (15 Regions)',
      selected_types: [selectedTypes[0]],
      checked_at_utc: new Date().toISOString(),
      total_records: globalResults.reduce((sum, res) => sum + (res.data?.records?.length || 0), 0),
      dns_provider: emptyProvider(),
      hosting_provider: emptyProvider(),
      results: globalResults.map(res => {
        const mappedRecords = (res.data?.records || []).map(record => ({ data: formatGlobalDnsRecord(record), type: selectedTypes[0] }));
        return {
          _type: res.region,
          _queryTime: res.data?.duration_ms || 0,
          error: res.error || '',
          message: res.status === 'success' && mappedRecords.length === 0 ? 'No records returned.' : '',
          noRecords: res.status === 'success' && mappedRecords.length === 0,
          status: res.status === 'success' ? 200 : 500,
          dns_provider: emptyProvider(),
          hosting_provider: emptyProvider(),
          records: mappedRecords,
        } as DnsLookupResult;
      }),
    };
  }

  function openShareModal(snapshotOverride?: DnsSnapshot) {
    const isSnapshot = (s: unknown): s is DnsSnapshot =>
      Boolean(s && typeof s === 'object' && 'domain' in s && 'results' in s);
    const activeSnapshot = isSnapshot(snapshotOverride) ? snapshotOverride : snapshot;
    if (!activeSnapshot) return;
    setSnapshot(activeSnapshot);
    setShareTitle(`${activeSnapshot.domain} ${mode === 'global' ? 'Global ' : ''}DNS Snapshot`);
    setShareExpiry('never');
    setSharePassword('');
    setShareError('');
    setShareUrl('');
    setShareModalOpen(true);
  }

  async function submitShare() {
    if (!snapshot) return;
    setShareLoading(true);
    setShareError('');

    try {
      const result = await api.createDnsShare({
        title: shareTitle.trim() || `${snapshot.domain} DNS Snapshot`,
        domain: snapshot.domain,
        expiry: shareExpiry,
        password: sharePassword.trim(),
        checked_at_utc: snapshot.checked_at_utc,
        snapshot,
      });
      setShareUrl(`${window.location.origin}/s/${result.code}`);
    } catch (error: unknown) {
      setShareError(getErrorMessage(error, 'Failed to create share link.'));
    } finally {
      setShareLoading(false);
    }
  }

  return (
    <>
      <Navbar />
      <main className="main-content">
        <header className="signal-tool-heading">
          <div>
            <i className="bi bi-globe2"></i>
          </div>
          <h1 className="hero-title">DNS Lookup</h1>
          <p>See where a domain points. Understand the records behind it.</p>
        </header>
        <div className="signal-tool-layout">
        <div className="signal-tool-primary">
        <div className="input-card signal-query-panel">

          <div className="signal-mode-controls" role="group" aria-label="DNS query mode">
            <button
               type="button" aria-pressed={mode === 'standard'} disabled={loading}
               onClick={() => { setMode('standard'); setGlobalResults([]); setError(''); }}
            >
              Standard Query
            </button>
            {globalAvailable && <button
               type="button" aria-pressed={mode === 'global'} disabled={loading}
               onClick={() => { setMode('global'); setSelectedTypes([selectedTypes[0] || 'A']); setSnapshot(null); setError(''); }}
            >
              Global Propagation
            </button>}
          </div>

          <label className="signal-query-label" htmlFor="dns-domain">Domain name</label>
          <div className="signal-query-row" style={{ marginBottom: 20 }}>
            <input
              id="dns-domain"
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && void doLookup()}
              placeholder="e.g. google.com"
              className="log-textarea"
              style={{
                flex: 1,
                minWidth: 160,
                padding: '12px 16px',
                height: 'auto',
                fontSize: '1rem',
              }}
            />
            <button onClick={() => void doLookup()} disabled={loading || !domain.trim()} className="btn-analyze" style={{ padding: '12px 20px', whiteSpace: 'nowrap' }}>
              <i className={loading ? 'bi bi-hourglass-split' : 'bi bi-search'} style={{ marginRight: 4 }} aria-hidden="true"></i>
              {loading ? 'Querying...' : 'Lookup'}
            </button>
          </div>

          <div style={{ marginBottom: 12 }}>
            <label style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 600, display: 'block', marginBottom: 6 }}>Record Types</label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {DNS_TYPES.map((recordType) => {
                const active = selectedTypes.includes(recordType);
                return (
                  <label
                    key={recordType}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                      cursor: 'pointer',
                      fontSize: '0.82rem',
                      color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
                      padding: '4px 10px',
                      border: `1px solid ${active ? 'var(--accent-primary)' : 'var(--border-color)'}`,
                      background: active ? 'var(--signal-tint)' : 'transparent',
                      borderRadius: 6,
                      transition: 'all 0.2s ease',
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={active}
                      onChange={() => toggleType(recordType)}
                      style={{ accentColor: 'var(--accent-primary)' }}
                    />
                    {recordType}
                  </label>
                );
              })}
            </div>
          </div>

          {mode === 'standard' && (
            <div>
              <label htmlFor="dns-resolver" style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 600, display: 'block', marginBottom: 6 }}>Resolver</label>
              <select
                id="dns-resolver"
                value={resolver}
              onChange={(e) => setResolver(e.target.value)}
              style={{
                width: '100%',
                padding: '10px 14px',
                background: 'var(--bg-input)',
                border: '1px solid var(--border-color)',
                borderRadius: 8,
                color: 'var(--text-secondary)',
                fontSize: '0.85rem',
                cursor: 'pointer',
              }}
            >
              {RESOLVER_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
            </div>
          )}
          <p className="signal-query-note"><i className="bi bi-lock" aria-hidden="true" /> {mode === 'standard' ? 'DNS queries are sent to your selected resolver over HTTPS.' : 'Compares DNS responses across the configured regional lookup services.'}</p>
        </div>

        {error && (
          <div role="alert" className="alert-custom" style={{ maxWidth: 1100, margin: '30px auto 0', padding: '16px 20px' }}>
            <i className="bi bi-exclamation-triangle" style={{ marginRight: 8 }}></i>
            {error}
          </div>
        )}

        {snapshot && mode === 'standard' && (
          <div style={{ maxWidth: 1100, margin: '30px auto 0' }}>
            <DnsSnapshotView snapshot={snapshot} mode="live" onShare={() => openShareModal()} />
          </div>
        )}

        {mode === 'global' && globalResults.length > 0 && (
          <div className="input-card" style={{ maxWidth: 1100, margin: '30px auto 0', padding: '30px', overflowX: 'auto' }}>
             <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 20 }}>
               <h3 style={{ margin: 0 }}>Global DNS Propagation</h3>
               <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                 <button
                   onClick={() => openShareModal(buildGlobalSnapshot())}
                   style={{ background: 'none', border: '1px solid rgba(99,102,241,0.35)', color: '#818cf8', padding: '8px 16px', borderRadius: 10, cursor: 'pointer', fontSize: '0.82rem', display: 'inline-flex', alignItems: 'center' }}
                 >
                    <i className="bi bi-share-fill" style={{ marginRight: 6 }} aria-hidden="true"></i>
                   Share Global Snapshot
                 </button>
                 <button onClick={() => {
                   const html = buildDnsSnapshotHtml(buildGlobalSnapshot());
                   const blob = new Blob([html], { type: 'text/html' });
                   const url = URL.createObjectURL(blob);
                   const link = document.createElement('a');
                   link.href = url;
                   link.download = `${domain}-global-dns-snapshot.html`;
                   document.body.appendChild(link);
                   link.click();
                   document.body.removeChild(link);
                   URL.revokeObjectURL(url);
                 }} style={{ background: 'none', border: '1px solid var(--border-color)', color: 'var(--text-secondary)', padding: '8px 16px', borderRadius: 10, cursor: 'pointer', fontSize: '0.82rem', display: 'inline-flex', alignItems: 'center' }}>
                    <i className="bi bi-download" style={{ marginRight: 6 }} aria-hidden="true"></i>
                   Download HTML
                 </button>
                 <button onClick={() => {
                   const snap = buildGlobalSnapshot();
                   const rows = snap.results.flatMap(res => {
                     if (!res.records || res.records.length === 0) {
                       return [{ region: res._type, status: res.status, error: res.error || 'No records', record: '' }];
                     }
                     return res.records.map(r => ({
                       region: res._type,
                       status: res.status,
                       error: res.error || '',
                       record: r.data || '',
                     }));
                   });
                   exportToCSV(rows.length > 0 ? rows : snap, `${domain}-global-dns-snapshot`);
                 }} style={{ background: 'none', border: '1px solid var(--border-color)', color: 'var(--text-secondary)', padding: '8px 16px', borderRadius: 10, cursor: 'pointer', fontSize: '0.82rem', display: 'inline-flex', alignItems: 'center' }}>
                    <i className="bi bi-download" style={{ marginRight: 6 }} aria-hidden="true"></i>
                   Export CSV
                 </button>
               </div>
             </div>
             <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '10px 8px' }}>AWS Region</th>
                    <th style={{ padding: '10px 8px' }}>Status</th>
                    <th style={{ padding: '10px 8px' }}>Result</th>
                  </tr>
                </thead>
                <tbody>
                  {globalResults.map((res, idx) => (
                    <tr key={idx} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '10px 8px', color: 'var(--text-primary)', fontWeight: 600 }}>
                        <i className="bi bi-globe" style={{ marginRight: 6, color: 'var(--text-muted)' }}></i>
                        {res.region}
                      </td>
                      <td style={{ padding: '10px 8px' }}>
                        {res.status === 'success' && Array.isArray(res.data?.records) ? (
                          <span style={{ color: '#10b981', background: 'rgba(16,185,129,0.1)', padding: '4px 8px', borderRadius: 6, fontSize: '0.8rem', fontWeight: 600 }}>
                             <i className="bi bi-check-circle-fill"></i> Success
                          </span>
                        ) : (
                          <span style={{ color: '#ef4444', background: 'rgba(239,68,68,0.1)', padding: '4px 8px', borderRadius: 6, fontSize: '0.8rem', fontWeight: 600 }}>
                             <i className="bi bi-x-circle-fill"></i> Failed
                          </span>
                        )}
                      </td>
                      <td style={{ padding: '10px 8px', fontFamily: 'var(--font-mono)', fontSize: '0.82rem', wordBreak: 'break-all' }}>
                        {res.status === 'success' && res.data?.records ? (
                          res.data.records.length > 0 ? (
                            res.data.records.map((r, i) => {
                              const formatted = formatGlobalDnsRecord(r);
                              return (
                                <div key={i} style={{ marginBottom: 4 }}>
                                  {formatted}
                                </div>
                              );
                            })
                          ) : 'No records'
                        ) : res.error || 'No records found'}
                      </td>
                    </tr>
                  ))}
                </tbody>
             </table>
          </div>
        )}
        </div>
        <aside className="signal-tool-context signal-dns-context" aria-label="DNS reference">
          <section className="signal-context-panel"><p className="signal-eyebrow">Query details</p><h2>One domain. A clear answer.</h2><p>Query only what you need, with readable results and the raw response when you want to dig deeper.</p><dl><dt>Query mode</dt><dd>{mode === 'standard' ? 'Standard' : 'Global propagation'}</dd><dt>Resolver</dt><dd>{mode === 'standard' ? RESOLVER_OPTIONS.find(option => option.value === resolver)?.label : 'Regional lookup services'}</dd><dt>Selected records</dt><dd>{selectedTypes.join(', ') || 'None selected'}</dd></dl></section>
          <section className="signal-context-panel"><p className="signal-eyebrow">Records, decoded</p><dl><dt>A / AAAA</dt><dd>Connects a hostname to an IPv4 or IPv6 address.</dd><dt>MX</dt><dd>Routes email. A lower priority number is preferred.</dd><dt>TTL</dt><dd>How long a resolver may cache a record, in seconds.</dd></dl></section>
          <section className="signal-context-panel"><p className="signal-eyebrow">Keep investigating</p><Link href={`/ssl${domain ? `?domain=${encodeURIComponent(cleanDomain(domain))}` : ''}`}>SSL Certificate Checker <i className="bi bi-arrow-up-right" aria-hidden="true" /></Link><Link href={`/whois${domain ? `?domain=${encodeURIComponent(cleanDomain(domain))}` : ''}`}>WHOIS Lookup <i className="bi bi-arrow-up-right" aria-hidden="true" /></Link></section>
        </aside>
        </div>
      </main>
      <Footer />

      {shareModalOpen && snapshot && (
        <div
          onClick={(event) => {
            if (event.target === event.currentTarget) setShareModalOpen(false);
          }}
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 10000,
            background: 'rgba(7,8,15,0.75)',
            backdropFilter: 'blur(6px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '24px',
          }}
        >
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-color)',
            borderRadius: 18,
            padding: '32px 36px',
            maxWidth: 480,
            width: '100%',
            boxShadow: '0 24px 80px rgba(0,0,0,0.5)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ width: 38, height: 38, borderRadius: 10, background: 'rgba(99,102,241,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#6366f1', fontSize: '1.1rem' }}>
                  <i className="bi bi-share-fill"></i>
                </div>
                <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>Share DNS Snapshot</h3>
              </div>
              <button onClick={() => setShareModalOpen(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.2rem', cursor: 'pointer' }}>
                <i className="bi bi-x-lg"></i>
              </button>
            </div>

            {shareLoading ? (
              <div style={{ textAlign: 'center', padding: '20px 0' }}>
                <div style={{ width: 40, height: 40, border: '3px solid var(--border-color)', borderTopColor: '#6366f1', borderRadius: '50%', animation: 'spin 1s linear infinite', margin: '0 auto 12px' }}></div>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', margin: 0 }}>Creating share link...</p>
              </div>
            ) : shareUrl ? (
              <div>
                <div style={{ textAlign: 'center', marginBottom: 20 }}>
                  <div style={{ width: 52, height: 52, borderRadius: '50%', background: 'rgba(16,185,129,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#10b981', fontSize: '1.5rem', margin: '0 auto 12px' }}>
                    <i className="bi bi-check-circle-fill"></i>
                  </div>
                  <p style={{ margin: 0, color: 'var(--text-primary)', fontWeight: 600, fontSize: '0.95rem' }}>Share link created!</p>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', background: 'var(--bg-input)', border: '1px solid var(--border-color)', borderRadius: 10, padding: '10px 14px', marginBottom: 12 }}>
                  <span style={{ flex: 1, fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{shareUrl}</span>
                  <button
                    onClick={() => void copy(shareUrl, 'share')}
                    style={{ background: 'var(--gradient-primary)', border: 'none', color: '#fff', padding: '6px 14px', borderRadius: 7, cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600 }}
                  >
                    <i className={isCopied('share') ? 'bi bi-check-lg' : 'bi bi-clipboard'} style={{ marginRight: 4 }}></i>
                    {isCopied('share') ? 'Copied!' : 'Copy'}
                  </button>
                </div>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center', margin: 0 }}>
                  Checked at {formatUTC(snapshot.checked_at_utc)}.
                </p>
                <button
                  onClick={() => {
                    setShareUrl('');
                    setShareError('');
                  }}
                  style={{ width: '100%', marginTop: 16, padding: 10, borderRadius: 10, border: '1px solid var(--border-color)', background: 'none', color: 'var(--text-secondary)', fontSize: '0.85rem', cursor: 'pointer' }}
                >
                  Create Another Link
                </button>
              </div>
            ) : (
              <div>
                <div style={{ marginBottom: 16 }}>
                  <label style={modalLabelStyle}>Title</label>
                  <input value={shareTitle} onChange={(e) => setShareTitle(e.target.value)} style={modalInputStyle} />
                </div>
                <div style={{ marginBottom: 16 }}>
                  <label style={modalLabelStyle}>Link Expiry</label>
                  <select value={shareExpiry} onChange={(e) => setShareExpiry(e.target.value)} style={modalInputStyle}>
                    <option value="never">Never expires</option>
                    <option value="24h">24 hours</option>
                    <option value="7d">7 days</option>
                    <option value="30d">30 days</option>
                  </select>
                </div>
                <div style={{ marginBottom: 16 }}>
                  <label style={modalLabelStyle}>Password</label>
                  <input type="password" value={sharePassword} onChange={(e) => setSharePassword(e.target.value)} placeholder="Leave blank for public link" style={modalInputStyle} />
                </div>
                <div style={{ marginBottom: 16, color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
                  <strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Checked At:</strong>{' '}
                  <span style={{ fontFamily: 'var(--font-mono)' }}>{formatUTC(snapshot.checked_at_utc)}</span>
                </div>
                {shareError && (
                  <div style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 8, padding: '10px 14px', color: '#f87171', fontSize: '0.82rem', marginBottom: 12 }}>
                    {shareError}
                  </div>
                )}
                <button
                  onClick={() => void submitShare()}
                  style={{ width: '100%', padding: 12, borderRadius: 10, border: 'none', background: 'var(--gradient-primary)', color: '#fff', fontWeight: 700, fontSize: '0.92rem', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
                >
                  <i className="bi bi-link-45deg"></i>
                  Generate Share Link
                </button>
              </div>
            )}
          </div>
        </div>
      )}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </>
  );
}

const modalLabelStyle = {
  fontSize: '0.78rem',
  fontWeight: 600,
  color: 'var(--text-muted)',
  textTransform: 'uppercase' as const,
  letterSpacing: '0.06em',
  display: 'block',
  marginBottom: 6,
};

const modalInputStyle = {
  width: '100%',
  padding: '10px 14px',
  borderRadius: 10,
  border: '1px solid var(--border-color)',
  background: 'var(--bg-input)',
  color: 'var(--text-primary)',
  fontSize: '0.88rem',
  boxSizing: 'border-box' as const,
  outline: 'none',
};

function getErrorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}
