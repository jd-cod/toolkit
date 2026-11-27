'use client';

import { useState } from 'react';
import ToolPage from '@/components/ToolPage';
import { ToolEmptyState } from '@/components/ToolWorkspace';
import { Badge, DataTable, ErrorBanner, Field, LoadingPanel, Panel, Stat, StatGrid, TextInput, type Tone } from '@/components/ToolUi';
import { useQueryPrefill, useToolRequest } from '@/hooks/useToolRequest';
import { api } from '@/lib/api';
import type { PortCheckResult } from '@/lib/tools/net-types';

const PRESETS = [
  { label: 'Common', ports: '21,22,25,53,80,110,143,443,465,587,993,995,3306,3389,5432,8080,8443' },
  { label: 'Web', ports: '80,443,8080,8443' },
  { label: 'Mail', ports: '25,110,143,465,587,993,995' },
  { label: 'Remote access', ports: '22,23,3389,5900,5985' },
  { label: 'Databases', ports: '1433,1521,3306,5432,6379,9200,11211,27017' },
];

const STATE: Record<PortCheckResult['results'][number]['state'], { label: string; tone: Tone }> = {
  open: { label: 'Open', tone: 'ok' },
  closed: { label: 'Closed', tone: 'muted' },
  filtered: { label: 'Filtered', tone: 'warn' },
};

export default function PortCheckPage() {
  const [host, setHost] = useState('');
  const [ports, setPorts] = useState(PRESETS[0].ports);
  const [ipError, setIpError] = useState('');
  const { loading, error, result, run } = useToolRequest<PortCheckResult>();

  const check = (value = host) => {
    if (value.trim() && ports.trim()) void run(() => api.checkPorts(value.trim(), ports));
  };
  useQueryPrefill('host', value => setHost(value));

  const fillMyIp = async () => {
    setIpError('');
    try {
      const me = await api.getMyIP();
      if (me.ip) setHost(me.ip);
      else setIpError('Your public address could not be detected.');
    } catch {
      setIpError('Your public address could not be detected.');
    }
  };

  const exposed = result?.results.filter(item => item.warning) || [];

  return (
    <ToolPage tool="port-check" title="Open Port Checker" icon="bi-door-open-fill" lead="Test from the internet whether TCP ports on your server are reachable.">
      <Panel>
        <form className="tk-form" onSubmit={event => { event.preventDefault(); check(); }}>
          <Field label="Host or IP address" hint={ipError || 'Only check hosts you are responsible for.'} grow>
            <TextInput mono value={host} onChange={event => setHost(event.target.value)} placeholder="server.example.com or 203.0.113.10" />
          </Field>
          <button type="button" className="btn-secondary tk-submit" onClick={() => void fillMyIp()}>Use my IP</button>
          <button type="submit" className="btn-primary tk-submit" disabled={loading || !host.trim() || !ports.trim()}>{loading ? 'Checking…' : 'Check ports'}</button>
        </form>
        <div style={{ marginTop: '1rem' }}>
          <Field label="Ports" hint="Up to 25 ports. Separate with commas, or use a range such as 8000-8010.">
            <TextInput mono value={ports} onChange={event => setPorts(event.target.value)} placeholder="22,80,443" />
          </Field>
        </div>
        <div className="tk-chip-row" style={{ marginTop: '0.75rem' }}>
          {PRESETS.map(preset => <button key={preset.label} type="button" className="tk-chip" aria-pressed={ports === preset.ports} onClick={() => setPorts(preset.ports)}>{preset.label}</button>)}
        </div>
      </Panel>

      {loading && <LoadingPanel title="Connecting to each port">Ports that do not answer take a few seconds to time out.</LoadingPanel>}
      {error && <ErrorBanner>{error}</ErrorBanner>}
      {!loading && !error && !result && <ToolEmptyState title="Check which ports are reachable">Enter a server name or public IP address and the ports to test. The connection is made from this server, so the result shows what the internet can reach.</ToolEmptyState>}
      {result && (
        <>
          <StatGrid>
            <Stat label="Open" value={result.summary.open} tone="ok" />
            <Stat label="Closed" value={result.summary.closed} tone="muted" />
            <Stat label="Filtered" value={result.summary.filtered} tone={result.summary.filtered > 0 ? 'warn' : 'muted'} />
          </StatGrid>
          {exposed.length > 0 && (
            <ErrorBanner>
              {exposed.length === 1 ? 'A service that should not be public is reachable' : `${exposed.length} services that should not be public are reachable`}: {exposed.map(item => `${item.port} (${item.service})`).join(', ')}.
            </ErrorBanner>
          )}
          <Panel title={`${result.host}${result.host !== result.address ? ` (${result.address})` : ''}`} icon="bi-hdd-network" flush>
            <DataTable
              head={['Port', 'Service', 'State', 'Response', 'Note']}
              rows={result.results.map(item => [
                <span key="p" className="tk-mono">{item.port}</span>,
                item.service || '—',
                <Badge key="s" tone={STATE[item.state].tone}>{STATE[item.state].label}</Badge>,
                item.latency_ms !== null ? `${item.latency_ms} ms` : '—',
                item.warning || '—',
              ])}
            />
          </Panel>
        </>
      )}
    </ToolPage>
  );
}
