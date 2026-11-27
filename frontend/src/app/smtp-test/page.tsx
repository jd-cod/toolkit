'use client';

import { useState } from 'react';
import ToolPage from '@/components/ToolPage';
import { ToolEmptyState } from '@/components/ToolWorkspace';
import { Badge, CodeBlock, ErrorBanner, Field, FindingList, KeyValueTable, LoadingPanel, Panel, Select, TextInput, Toggle } from '@/components/ToolUi';
import { useQueryPrefill, useToolRequest } from '@/hooks/useToolRequest';
import { api } from '@/lib/api';
import type { SmtpServerResult, SmtpTestResult } from '@/lib/tools/net-types';

const PORTS = [
  { value: 25, label: '25 (server to server)' },
  { value: 587, label: '587 (submission, STARTTLS)' },
  { value: 465, label: '465 (submission, implicit TLS)' },
  { value: 2525, label: '2525 (alternative)' },
];

function formatBytes(bytes: number) {
  return bytes >= 1048576 ? `${Math.round(bytes / 1048576)} MB` : `${Math.round(bytes / 1024)} KB`;
}

function Server({ server }: { server: SmtpServerResult }) {
  const extensions = server.post_tls_ehlo || server.ehlo;
  const cert = server.tls?.certificate;
  const transcript = server.transcript.map(entry => `${entry.from === 'client' ? 'C:' : 'S:'} ${entry.line}`).join('\n');
  return (
    <Panel
      title={server.host}
      icon="bi-send-check"
      actions={<>
        {server.priority !== null && <Badge tone="info">MX priority {server.priority}</Badge>}
        <Badge tone={server.connected && !server.error ? 'ok' : 'bad'}>{server.connected ? (server.error ? 'Session failed' : 'Connected') : 'No connection'}</Badge>
      </>}
    >
      <FindingList findings={server.findings} />
      {server.connected && (
        <div style={{ marginTop: '1rem' }}>
          <KeyValueTable rows={[
            ['Address', server.address],
            ['Reverse DNS', server.ptr.join(', ')],
            ['Banner', server.banner],
            ['Encryption', server.tls ? `${server.tls.protocol}${server.implicit_tls ? ' (implicit TLS)' : ' (STARTTLS)'}` : 'None'],
            ['Certificate', cert ? `${cert.subject || cert.names[0] || 'unnamed'}, issued by ${cert.issuer || 'unknown'}` : ''],
            ['Certificate expires', cert ? `${cert.valid_to}${cert.days_remaining !== null ? ` (${cert.days_remaining} days)` : ''}` : ''],
            ['Message size limit', extensions?.size_limit ? formatBytes(extensions.size_limit) : ''],
            ['AUTH methods', extensions?.auth_mechanisms.join(', ') || ''],
            ['Time to banner', server.timings.banner_ms !== null ? `${server.timings.banner_ms} ms` : ''],
          ]} />
        </div>
      )}
      {extensions && extensions.extensions.length > 0 && (
        <>
          <h3 className="tk-subhead">Extensions</h3>
          <div className="tk-chip-row">{extensions.extensions.map(extension => <Badge key={extension} tone="muted">{extension}</Badge>)}</div>
        </>
      )}
      {transcript && (
        <details className="tk-details" style={{ marginTop: '1rem' }}>
          <summary>Session transcript</summary>
          <CodeBlock label="SMTP session" code={transcript} />
        </details>
      )}
    </Panel>
  );
}

export default function SmtpTestPage() {
  const [target, setTarget] = useState('');
  const [port, setPort] = useState(25);
  const [direct, setDirect] = useState(false);
  const { loading, error, result, run } = useToolRequest<SmtpTestResult>();

  const test = (value = target) => {
    if (value.trim()) void run(() => api.testSmtp(value.trim(), port, direct));
  };
  useQueryPrefill('target', value => { setTarget(value); test(value); });

  return (
    <ToolPage tool="smtp-test" title="SMTP Server Test" icon="bi-send-check-fill" lead="Connect to a mail server and review its greeting, encryption and certificate. No message is sent.">
      <Panel>
        <form className="tk-form" onSubmit={event => { event.preventDefault(); test(); }}>
          <Field label="Domain or mail server" grow>
            <TextInput mono value={target} onChange={event => setTarget(event.target.value)} placeholder="example.com or mail.example.com" />
          </Field>
          <Field label="Port">
            <Select value={port} onChange={event => setPort(Number(event.target.value))}>
              {PORTS.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
            </Select>
          </Field>
          <button type="submit" className="btn-primary tk-submit" disabled={loading || !target.trim()}>{loading ? 'Testing…' : 'Test server'}</button>
        </form>
        <div style={{ marginTop: '1rem' }}>
          <Toggle label="Test this host directly" hint="Skip the MX lookup and connect to the name as typed." checked={direct} onChange={setDirect} />
        </div>
      </Panel>

      {loading && <LoadingPanel title="Talking to the mail server">Connecting, reading the banner and negotiating TLS.</LoadingPanel>}
      {error && <ErrorBanner>{error}</ErrorBanner>}
      {!loading && !error && !result && <ToolEmptyState title="Test a mail server">Enter a domain to test the servers in its MX records, or a server name to test it directly.</ToolEmptyState>}
      {result && (
        <>
          <p className="tk-note">{result.mode === 'mx' ? `Tested the ${result.servers.length === 1 ? 'mail server' : `${result.servers.length} highest-priority mail servers`} from the MX records of ${result.target}, on port ${result.port}.` : `Tested ${result.target} directly on port ${result.port}.`}</p>
          {result.servers.map(server => <Server key={server.host} server={server} />)}
        </>
      )}
    </ToolPage>
  );
}
