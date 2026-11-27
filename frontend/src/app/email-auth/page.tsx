'use client';

import { useState } from 'react';
import ToolPage from '@/components/ToolPage';
import { ToolEmptyState } from '@/components/ToolWorkspace';
import { Badge, CodeBlock, DataTable, ErrorBanner, Field, FindingList, KeyValueTable, LoadingPanel, Panel, Stat, StatGrid, TextInput, type Tone } from '@/components/ToolUi';
import { useQueryPrefill, useToolRequest } from '@/hooks/useToolRequest';
import { api } from '@/lib/api';
import type { EmailAuthResult, SectionStatus, SpfInclude } from '@/lib/tools/net-types';

const STATUS_LABEL: Record<SectionStatus, string> = { pass: 'Pass', warn: 'Review', fail: 'Fail', missing: 'Missing', error: 'Unknown' };
const STATUS_TONE: Record<SectionStatus, Tone> = { pass: 'ok', warn: 'warn', fail: 'bad', missing: 'bad', error: 'muted' };
// MTA-STS, TLS-RPT and BIMI are optional, so "missing" there is not a failure.
const optionalTone = (status: SectionStatus): Tone => (status === 'missing' ? 'muted' : STATUS_TONE[status]);

const DMARC_TAG_NAMES: Record<string, string> = {
  v: 'Version', p: 'Policy', sp: 'Subdomain policy', pct: 'Percentage', rua: 'Aggregate reports', ruf: 'Failure reports',
  adkim: 'DKIM alignment', aspf: 'SPF alignment', fo: 'Failure options', ri: 'Report interval',
};

function IncludeTree({ nodes, depth = 0 }: { nodes: SpfInclude[]; depth?: number }) {
  if (nodes.length === 0) return null;
  return (
    <ul className="tk-tree" style={{ paddingLeft: depth === 0 ? 0 : 18 }}>
      {nodes.map(node => (
        <li key={`${node.type}-${node.domain}`}>
          <div><Badge tone={node.error ? 'bad' : 'info'}>{node.type}</Badge> <code className="tk-mono">{node.domain}</code> {!node.error && <small className="tk-hint">{node.lookups} more lookup{node.lookups === 1 ? '' : 's'} inside</small>}</div>
          {node.error ? <small className="tk-hint tk-bad">{node.error}</small> : <small className="tk-hint tk-mono">{node.record}</small>}
          <IncludeTree nodes={node.children} depth={depth + 1} />
        </li>
      ))}
    </ul>
  );
}

function Results({ result }: { result: EmailAuthResult }) {
  const { mx, spf, dkim, dmarc, mta_sts: mtaSts, tls_rpt: tlsRpt, bimi } = result;
  return (
    <>
      <StatGrid>
        <Stat label="MX" value={STATUS_LABEL[mx.status]} tone={STATUS_TONE[mx.status]} />
        <Stat label="SPF" value={STATUS_LABEL[spf.status]} tone={STATUS_TONE[spf.status]} />
        <Stat label="DKIM" value={dkim.status === 'missing' ? 'Not found' : STATUS_LABEL[dkim.status]} tone={dkim.status === 'missing' ? 'warn' : STATUS_TONE[dkim.status]} />
        <Stat label="DMARC" value={STATUS_LABEL[dmarc.status]} tone={STATUS_TONE[dmarc.status]} />
      </StatGrid>

      <Panel title="SPF" icon="bi-shield-check" actions={spf.record ? <Badge tone={spf.lookups > spf.lookup_limit ? 'bad' : spf.lookups >= 8 ? 'warn' : 'ok'}>{spf.lookups} of {spf.lookup_limit} lookups</Badge> : undefined}>
        {spf.record && <CodeBlock label={`TXT ${result.domain}`} code={spf.record} />}
        <FindingList findings={spf.findings} />
        {spf.includes.length > 0 && <><h3 className="tk-subhead">Include tree</h3><IncludeTree nodes={spf.includes} /></>}
      </Panel>

      <Panel title="DKIM" icon="bi-key" actions={<Badge tone="muted">{dkim.selectors_checked} selectors tried</Badge>}>
        <FindingList findings={dkim.findings} />
        {dkim.found.length > 0 && (
          <div style={{ marginTop: '1rem' }}>
            <DataTable
              head={['Selector', 'Key', 'State']}
              rows={dkim.found.map(key => [
                <code key="s" className="tk-mono">{key.selector}</code>,
                key.revoked ? '—' : key.key_type === 'rsa' ? `RSA ${key.key_bits} bit` : 'Ed25519',
                <Badge key="b" tone={key.revoked ? 'muted' : key.invalid ? 'bad' : key.testing ? 'warn' : 'ok'}>{key.revoked ? 'Revoked' : key.invalid ? 'Invalid' : key.testing ? 'Test mode' : 'Active'}</Badge>,
              ])}
            />
          </div>
        )}
      </Panel>

      <Panel title="DMARC" icon="bi-envelope-check" actions={dmarc.policy ? <Badge tone={dmarc.policy === 'none' ? 'warn' : 'ok'}>p={dmarc.policy}</Badge> : undefined}>
        {dmarc.record && <CodeBlock label={`TXT _dmarc.${dmarc.source_domain}`} code={dmarc.record} />}
        <FindingList findings={dmarc.findings} />
        {dmarc.record && (
          <div style={{ marginTop: '1rem' }}>
            <KeyValueTable rows={Object.entries(dmarc.tags).map(([tag, value]) => [`${DMARC_TAG_NAMES[tag] || tag} (${tag})`, value])} />
          </div>
        )}
      </Panel>

      <Panel title="Mail servers (MX)" icon="bi-hdd-network" actions={mx.provider ? <Badge tone="info">{mx.provider}</Badge> : undefined}>
        <FindingList findings={mx.findings} />
        {mx.records.length > 0 && (
          <div style={{ marginTop: '1rem' }}>
            <DataTable head={['Priority', 'Host', 'Addresses']} rows={mx.records.map(record => [record.priority, <code key="h" className="tk-mono">{record.exchange}</code>, record.addresses.join(', ') || '—'])} />
          </div>
        )}
      </Panel>

      <Panel title="Optional records" icon="bi-plus-circle">
        {[
          { name: 'MTA-STS', section: mtaSts, record: mtaSts.record, label: `TXT _mta-sts.${result.domain}` },
          { name: 'TLS reporting', section: tlsRpt, record: tlsRpt.record, label: `TXT _smtp._tls.${result.domain}` },
          { name: 'BIMI', section: bimi, record: bimi.record, label: `TXT default._bimi.${result.domain}` },
        ].map(item => (
          <div key={item.name} className="tk-block">
            <h3 className="tk-subhead">{item.name} <Badge tone={optionalTone(item.section.status)}>{item.section.status === 'missing' ? 'Not set' : STATUS_LABEL[item.section.status]}</Badge></h3>
            {item.record && <CodeBlock label={item.label} code={item.record} />}
            <FindingList findings={item.section.findings} />
          </div>
        ))}
      </Panel>
    </>
  );
}

export default function EmailAuthPage() {
  const [domain, setDomain] = useState('');
  const [selectors, setSelectors] = useState('');
  const { loading, error, result, run } = useToolRequest<EmailAuthResult>();

  const check = (value = domain) => {
    if (!value.trim()) return;
    void run(() => api.checkEmailAuth(value.trim(), selectors.split(/[\s,]+/).filter(Boolean)));
  };
  useQueryPrefill('domain', value => { setDomain(value); check(value); });

  return (
    <ToolPage tool="email-auth" title="SPF, DKIM & DMARC Checker" icon="bi-envelope-check-fill" lead="Check how a domain authenticates its email and what to fix.">
      <Panel>
        <form className="tk-form" onSubmit={event => { event.preventDefault(); check(); }}>
          <Field label="Domain" grow>
            <TextInput mono value={domain} onChange={event => setDomain(event.target.value)} placeholder="example.com" />
          </Field>
          <Field label="DKIM selectors (optional)" hint="Comma separated. Common selectors are always tried." grow>
            <TextInput mono value={selectors} onChange={event => setSelectors(event.target.value)} placeholder="selector1, mail" />
          </Field>
          <button type="submit" className="btn-primary tk-submit" disabled={loading || !domain.trim()}>{loading ? 'Checking…' : 'Check domain'}</button>
        </form>
      </Panel>

      {loading && <LoadingPanel title="Checking email authentication">Reading MX, SPF, DKIM and DMARC records.</LoadingPanel>}
      {error && <ErrorBanner>{error}</ErrorBanner>}
      {!loading && !error && !result && <ToolEmptyState title="Check a sending domain">Enter the domain after the @ in your From address to review its mail servers, SPF, DKIM and DMARC records.</ToolEmptyState>}
      {result && <Results result={result} />}
    </ToolPage>
  );
}
