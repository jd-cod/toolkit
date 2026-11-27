'use client';

import { useState } from 'react';
import ToolPage from '@/components/ToolPage';
import { ToolEmptyState } from '@/components/ToolWorkspace';
import { Badge, DataTable, ErrorBanner, Field, LoadingPanel, Panel, Stat, StatGrid, TextInput, type Tone } from '@/components/ToolUi';
import { useQueryPrefill, useToolRequest } from '@/hooks/useToolRequest';
import { api } from '@/lib/api';
import type { BlacklistEntry, BlacklistResult } from '@/lib/tools/net-types';

const STATE: Record<BlacklistEntry['status'], { label: string; tone: Tone }> = {
  listed: { label: 'Listed', tone: 'bad' },
  policy: { label: 'Policy listing', tone: 'warn' },
  clean: { label: 'Not listed', tone: 'ok' },
  unavailable: { label: 'Not checked', tone: 'muted' },
};
const ORDER: BlacklistEntry['status'][] = ['listed', 'policy', 'unavailable', 'clean'];

function ListRows({ results }: { results: BlacklistEntry[] }) {
  return (
    <DataTable
      head={['List', 'Result', 'Details']}
      rows={results.map(entry => [
        entry.url ? <a key="n" className="tk-link" href={entry.url} target="_blank" rel="noopener noreferrer">{entry.name}</a> : entry.name,
        <Badge key="s" tone={STATE[entry.status].tone}>{STATE[entry.status].label}</Badge>,
        [entry.detail, entry.reason].filter(Boolean).join(' · ') || '—',
      ])}
    />
  );
}

/** Lists that need attention first; the clean ones are folded away so a long result stays readable. */
function ListTable({ results }: { results: BlacklistEntry[] }) {
  const notable = results.filter(entry => entry.status !== 'clean').sort((a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status));
  const clean = results.filter(entry => entry.status === 'clean');
  return (
    <>
      {notable.length > 0 && <ListRows results={notable} />}
      {clean.length > 0 && (
        <details className="tk-details tk-details-flush">
          <summary>Not listed on {clean.length} list{clean.length === 1 ? '' : 's'}</summary>
          <ListRows results={clean} />
        </details>
      )}
    </>
  );
}

function Results({ result }: { result: BlacklistResult }) {
  const { summary } = result;
  return (
    <>
      <StatGrid>
        <Stat label="Listed" value={summary.listed} tone={summary.listed > 0 ? 'bad' : 'ok'} />
        <Stat label="Policy listings" value={summary.policy} tone={summary.policy > 0 ? 'warn' : 'muted'} />
        <Stat label="Not listed" value={summary.clean} tone="ok" />
        <Stat label="Not checked" value={summary.unavailable} tone="muted" />
      </StatGrid>

      {summary.unavailable > 0 && (
        <p className="tk-note">
          {`${summary.unavailable} list${summary.unavailable === 1 ? '' : 's'} could not be checked. Some lists, Spamhaus among them, refuse queries that come through shared DNS resolvers. That is not a listing; check those on the list's own site.`}
        </p>
      )}
      {summary.policy > 0 && (
        <p className="tk-note">A policy listing means a provider marked the address range as one that should not send mail directly (for example home connections). It is expected for dynamic addresses and is not a spam listing.</p>
      )}
      {result.note && <p className="tk-note">{result.note}</p>}

      {result.addresses.map(address => (
        <Panel
          key={address.ip}
          title={`${address.ip}${address.host && address.host !== address.ip ? ` (${address.host})` : ''}`}
          icon="bi-hdd-network"
          actions={<><Badge tone="info">{address.role}</Badge><Badge tone={address.summary.listed > 0 ? 'bad' : 'ok'}>{address.summary.listed} listed</Badge></>}
          flush
        >
          <ListTable results={address.results} />
        </Panel>
      ))}

      {result.domain && (
        <Panel title={`Domain lists for ${result.domain.target}`} icon="bi-globe2" flush>
          <ListTable results={result.domain.results} />
        </Panel>
      )}
    </>
  );
}

export default function BlacklistPage() {
  const [target, setTarget] = useState('');
  const { loading, error, result, run } = useToolRequest<BlacklistResult>();

  const check = (value = target) => {
    if (value.trim()) void run(() => api.checkBlacklist(value.trim()));
  };
  useQueryPrefill('target', value => { setTarget(value); check(value); });

  return (
    <ToolPage tool="blacklist" title="Blacklist (DNSBL) Check" icon="bi-slash-circle-fill" lead="See whether a mail server or IP address is on the common spam blacklists.">
      <Panel>
        <form className="tk-form" onSubmit={event => { event.preventDefault(); check(); }}>
          <Field label="IP address or domain" hint="For a domain, its mail servers and web address are checked." grow>
            <TextInput mono value={target} onChange={event => setTarget(event.target.value)} placeholder="203.0.113.25 or example.com" />
          </Field>
          <button type="submit" className="btn-primary tk-submit" disabled={loading || !target.trim()}>{loading ? 'Checking…' : 'Check blacklists'}</button>
        </form>
      </Panel>

      {loading && <LoadingPanel title="Querying blacklists">Each list is tested first, then asked about the address.</LoadingPanel>}
      {error && <ErrorBanner>{error}</ErrorBanner>}
      {!loading && !error && !result && <ToolEmptyState title="Check a sending address">Enter the public IP address your mail leaves from, or a domain to check its mail servers.</ToolEmptyState>}
      {result && <Results result={result} />}
    </ToolPage>
  );
}
