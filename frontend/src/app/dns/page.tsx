'use client';

import Link from 'next/link';
import { useCallback, useEffect, useRef, useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import DnsSnapshotView from '@/components/DnsSnapshotView';
import ResultActions from '@/components/share/ResultActions';
import { api, snapshotShare } from '@/lib/api';
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
} from '@/lib/dns';
import { ensureGeoIPReady } from '@/lib/geoip';
import { formatGlobalDnsRecord, type GlobalDnsRegion } from '@/lib/tool-results';

export default function DNSPage() {
  const [isMounted, setIsMounted] = useState(false);
  const [mode, setMode] = useState<'standard' | 'global'>('standard');
  const [domain, setDomain] = useState('');
  const [resolver, setResolver] = useState('1.1.1.1');
  const [selectedTypes, setSelectedTypes] = useState<string[]>([...DEFAULT_DNS_TYPES]);
  const [loading, setLoading] = useState(false);
  const [globalResults, setGlobalResults] = useState<GlobalDnsRegion[]>([]);
  const [globalAvailable, setGlobalAvailable] = useState(false);
  const [snapshot, setSnapshot] = useState<DnsSnapshot | null>(null);
  const [error, setError] = useState('');
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

  /** Global propagation results as CSV rows: one per record, per region. */
  function globalCsvRows() {
    const rows = buildGlobalSnapshot().results.flatMap(res => {
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
    return rows.length > 0 ? rows : buildGlobalSnapshot();
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
            <DnsSnapshotView snapshot={snapshot} mode="live" />
          </div>
        )}

        {mode === 'global' && globalResults.length > 0 && (
          <div className="input-card" style={{ maxWidth: 1100, margin: '30px auto 0', padding: '30px', overflowX: 'auto' }}>
             <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 20 }}>
               <h3 style={{ margin: 0 }}>Global DNS Propagation</h3>
               <ResultActions
                 className="signal-actions-end"
                 share={{
                   heading: 'Share Global DNS Snapshot',
                   title: `${domain} Global DNS Snapshot`,
                   create: snapshotShare('dns', domain, buildGlobalSnapshot),
                 }}
                 html={{ filename: `${domain}-global-dns-snapshot`, build: () => buildDnsSnapshotHtml(buildGlobalSnapshot()) }}
                 csv={{ filename: `${domain}-global-dns-snapshot`, rows: globalCsvRows }}
               />
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

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </>
  );
}

function getErrorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}
