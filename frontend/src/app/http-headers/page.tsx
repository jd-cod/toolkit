'use client';

import { useState } from 'react';
import ToolPage from '@/components/ToolPage';
import { ToolEmptyState } from '@/components/ToolWorkspace';
import { Badge, DataTable, ErrorBanner, Field, FindingList, KeyValueTable, LoadingPanel, Panel, Stat, StatGrid, TextInput, type Tone } from '@/components/ToolUi';
import { useQueryPrefill, useToolRequest } from '@/hooks/useToolRequest';
import { api } from '@/lib/api';
import type { HttpCheckResult, HttpHop } from '@/lib/tools/net-types';

const DELIVERY_LABELS: Array<[string, string]> = [
  ['server', 'Server'], ['content_type', 'Content type'], ['content_encoding', 'Compression'], ['cache_control', 'Cache-Control'],
  ['cache_status', 'Cache status'], ['age', 'Age'], ['etag', 'ETag'], ['last_modified', 'Last modified'], ['via', 'Via'], ['alt_svc', 'Alt-Svc'],
];

function statusTone(status: number): Tone {
  if (status >= 200 && status < 300) return 'ok';
  if (status >= 300 && status < 400) return 'info';
  if (status === 0) return 'muted';
  return 'bad';
}

function gradeTone(grade: string): Tone {
  return grade === 'A' || grade === 'B' ? 'ok' : grade === 'C' || grade === 'D' ? 'warn' : 'bad';
}

function HopHeaders({ hop, index }: { hop: HttpHop; index: number }) {
  return (
    <details className="tk-details" open={false}>
      <summary>Hop {index + 1}: {hop.status || 'failed'} {hop.url}</summary>
      {hop.error ? <p className="tk-note">{hop.error}</p> : <KeyValueTable rows={hop.headers.map(([name, value], i) => [`${name}${hop.headers.findIndex(([n]) => n === name) !== i ? ` (${i + 1})` : ''}`, value])} />}
    </details>
  );
}

function Results({ result }: { result: HttpCheckResult }) {
  const final = result.chain.find(hop => hop.url === result.final_url && !hop.redirect_to) || null;
  return (
    <>
      {result.error && <ErrorBanner>{result.error}</ErrorBanner>}
      <StatGrid>
        {result.grade && <Stat label="Security headers" value={result.grade} tone={gradeTone(result.grade)} />}
        <Stat label="Final status" value={final ? final.status : '—'} tone={final ? statusTone(final.status) : 'bad'} />
        <Stat label="Redirects" value={result.redirects} tone={result.redirects >= 3 ? 'warn' : 'info'} />
        <Stat label="Total time" value={`${result.total_ms} ms`} tone="info" />
      </StatGrid>

      <Panel title="Request path" icon="bi-signpost-split" flush>
        <DataTable
          head={['#', 'Status', 'URL', 'Server address', 'Time']}
          rows={result.chain.map((hop, index) => [
            index + 1,
            <Badge key="s" tone={statusTone(hop.status)}>{hop.status ? `${hop.status} ${hop.status_text}`.trim() : 'Failed'}</Badge>,
            <span key="u" className="tk-mono">{hop.url}{hop.error ? ` (${hop.error})` : ''}</span>,
            hop.address || '—',
            hop.status ? `${hop.elapsed_ms} ms` : '—',
          ])}
        />
      </Panel>

      {final && (
        <>
          <Panel title="Security review" icon="bi-shield-check">
            <FindingList findings={result.findings} />
          </Panel>

          <Panel title="Security headers" icon="bi-list-check" flush>
            <DataTable
              head={['Header', 'State', 'Value']}
              rows={result.checks.map(check => [<span key="n" className="tk-nowrap">{check.name}</span>, <Badge key="b" tone={check.present ? 'ok' : 'bad'}>{check.present ? 'Present' : 'Missing'}</Badge>, <span key="v" className="tk-mono tk-clip">{check.detail || '—'}</span>])}
            />
          </Panel>

          <Panel title="Delivery" icon="bi-speedometer2" flush>
            <KeyValueTable rows={[
              ...(final.tls ? [['TLS', `${final.tls.protocol}, certificate for ${final.tls.subject || 'unknown'} by ${final.tls.issuer || 'unknown'}, valid until ${final.tls.valid_to}`] as [string, string]] : []),
              ...DELIVERY_LABELS.filter(([key]) => result.delivery[key]).map(([key, label]) => [label, result.delivery[key]] as [string, string]),
            ]} />
          </Panel>
        </>
      )}

      <Panel title="Response headers" icon="bi-card-list">
        {result.chain.map((hop, index) => <HopHeaders key={`${index}-${hop.url}`} hop={hop} index={index} />)}
      </Panel>
    </>
  );
}

export default function HttpHeadersPage() {
  const [url, setUrl] = useState('');
  const { loading, error, result, run } = useToolRequest<HttpCheckResult>();

  const check = (value = url) => {
    if (value.trim()) void run(() => api.checkHttp(value.trim()));
  };
  useQueryPrefill('url', value => { setUrl(value); check(value); });

  return (
    <ToolPage tool="http-headers" title="HTTP Headers & Redirect Checker" icon="bi-arrow-left-right" lead="See every redirect a URL goes through, the response headers, and which security headers are missing.">
      <Panel>
        <form className="tk-form" onSubmit={event => { event.preventDefault(); check(); }}>
          <Field label="URL" hint="https:// is assumed when no scheme is given." grow>
            <TextInput mono value={url} onChange={event => setUrl(event.target.value)} placeholder="https://example.com" inputMode="url" />
          </Field>
          <button type="submit" className="btn-primary tk-submit" disabled={loading || !url.trim()}>{loading ? 'Checking…' : 'Check URL'}</button>
        </form>
      </Panel>

      {loading && <LoadingPanel title="Requesting the URL">Following redirects and reading response headers.</LoadingPanel>}
      {error && <ErrorBanner>{error}</ErrorBanner>}
      {!loading && !error && !result && <ToolEmptyState title="Inspect a URL">Enter a public URL to see its redirect chain, response headers and a security header review.</ToolEmptyState>}
      {result && <Results result={result} />}
    </ToolPage>
  );
}
