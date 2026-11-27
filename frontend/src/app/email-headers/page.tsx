'use client';

import { Fragment, useState, type ReactNode } from 'react';
import ToolPage from '@/components/ToolPage';
import { Badge, DataTable, ErrorBanner, Field, FindingList, KeyValueTable, Panel, TextArea, type Tone } from '@/components/ToolUi';
import { EMAIL_HEADERS_SAMPLE, formatDuration, parseEmailHeaders, type AuthResult, type EmailAnalysis, type Hop } from '@/lib/tools/email-headers';

const WRAP = { overflowWrap: 'anywhere' } as const;
const NOWRAP = { whiteSpace: 'nowrap' } as const;

function resultTone(result: string | null): Tone {
  if (result === null || result === '') return 'muted';
  if (result === 'pass') return 'ok';
  if (result === 'fail' || result === 'hardfail') return 'bad';
  return 'warn';
}

function formatTime(timestamp: number): string {
  return `${new Date(timestamp).toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}

/**
 * Table cell content that may hold long unbroken strings. The minimum width keeps
 * the column readable on narrow screens (the table scrolls sideways instead).
 */
function Cell({ children, min = 160, mono = false }: { children: ReactNode; min?: number; mono?: boolean }) {
  return <span className={mono ? 'tk-mono' : undefined} style={{ ...WRAP, display: 'inline-block', minWidth: min }}>{children}</span>;
}

/** Identity a result was checked against: envelope sender for SPF, signing domain and selector for DKIM, From domain for DMARC. */
function identity(result: AuthResult): string {
  const props = result.props;
  if (result.method === 'spf') return props['smtp.mailfrom'] ?? props['smtp.helo'] ?? '';
  if (result.method === 'dkim') return [props['header.d'] ?? props['header.i'] ?? '', props['header.s'] ? `selector ${props['header.s']}` : ''].filter(Boolean).join(', ');
  if (result.method === 'dmarc') return props['header.from'] ?? '';
  return Object.entries(props).map(([key, value]) => `${key}=${value}`).join(' ');
}

/** Text that may wrap after each dot, so host names break between labels instead of mid-word. */
function Dotted({ text }: { text: string }) {
  if (text.length > 400) return <span style={WRAP}>{text}</span>;
  return <>{text.split('.').map((part, index) => <Fragment key={index}>{index > 0 && <>.<wbr /></>}{part}</Fragment>)}</>;
}

/** A Received clause: the host name on one line, its comment (reverse DNS, address, software) below. */
function Server({ text }: { text: string }) {
  if (!text) return <>—</>;
  const split = text.indexOf(' (');
  const host = split < 0 ? text : text.slice(0, split);
  const rest = split < 0 ? '' : text.slice(split + 1);
  return (
    <div className="tk-mono" style={{ minWidth: 120 }}>
      <div><Dotted text={host} /></div>
      {rest && <small className="tk-muted"><Dotted text={rest} /></small>}
    </div>
  );
}

function authRows(analysis: EmailAnalysis): ReactNode[][] {
  const row = (result: AuthResult, source: string) => [
    <span key="check" style={NOWRAP}>{result.method.toUpperCase()}</span>,
    <Badge key="result" tone={resultTone(result.result)}>{result.result}</Badge>,
    <Cell key="identity" mono>{identity(result) || '—'}</Cell>,
    <Cell key="comment" min={200}>{result.comment || '—'}</Cell>,
    <span key="source" style={NOWRAP}>{source}</span>,
  ];
  return [
    ...analysis.auth.results.map(result => row(result, result.authservId || 'Authentication-Results')),
    ...analysis.auth.receivedSpf.map(spf => [
      'SPF',
      <Badge key="result" tone={resultTone(spf.result)}>{spf.result || 'unknown'}</Badge>,
      <Cell key="identity" mono>{spf.props['envelope-from'] ?? spf.props['client-ip'] ?? '—'}</Cell>,
      <Cell key="comment" min={200}>{spf.comment || '—'}</Cell>,
      'Received-SPF',
    ]),
    ...analysis.auth.arcResults.map(result => row(result, `ARC, ${result.authservId || 'unknown server'}`)),
  ];
}

function hopRows(hops: Hop[]): ReactNode[][] {
  const longest = Math.max(1, ...hops.map(hop => hop.delaySeconds ?? 0));
  return hops.map(hop => [
    hop.index,
    <Server key="from" text={hop.from} />,
    <Server key="by" text={hop.by} />,
    hop.with || '—',
    hop.timestamp !== null ? <span key="time" style={NOWRAP}>{formatTime(hop.timestamp)}</span> : <span key="time" className="tk-muted">{hop.date || 'No timestamp'}</span>,
    hop.delaySeconds === null ? '—' : (
      <div key="delay" style={{ minWidth: 90 }}>
        <div style={{ ...NOWRAP, marginBottom: 4 }}>{formatDuration(hop.delaySeconds)}</div>
        <div className="tk-bar" style={{ width: `${Math.round((hop.delaySeconds / longest) * 100)}%` }} />
        {hop.clockSkew && <div style={{ marginTop: 6 }}><Badge tone="warn">Clock skew</Badge></div>}
      </div>
    ),
  ]);
}

export default function EmailHeadersPage() {
  const [text, setText] = useState('');
  const [analysis, setAnalysis] = useState<EmailAnalysis | null>(null);

  const analyze = (input: string) => setAnalysis(parseEmailHeaders(input));
  const loadSample = () => {
    setText(EMAIL_HEADERS_SAMPLE);
    analyze(EMAIL_HEADERS_SAMPLE);
  };
  const clear = () => {
    setText('');
    setAnalysis(null);
  };

  const found = analysis !== null && analysis.headers.length > 0;
  const summary = analysis?.summary;

  return (
    <ToolPage tool="email-headers" title="Email Header Analyzer" icon="bi-envelope-open" lead="Paste raw email headers to trace each relay hop, find delays and read SPF, DKIM and DMARC results.">
      <Panel title="Headers" icon="bi-envelope-open">
        <Field label="Raw email headers" hint="Headers are parsed in your browser and are not uploaded. A pasted message body is ignored.">
          <TextArea
            value={text}
            onChange={event => setText(event.target.value)}
            placeholder={'Received: from mail.example.com by mx.example.net; Tue, 24 Nov 2026 17:14:50 +0000\nAuthentication-Results: mx.example.net; spf=pass; dkim=pass; dmarc=pass\nFrom: Sender <sender@example.com>\nSubject: ...'}
            style={{ minHeight: 260 }}
          />
        </Field>
        <div className="tk-actions" style={{ marginTop: '1rem' }}>
          <button type="button" className="btn-primary" onClick={() => analyze(text)}>Analyze</button>
          <button type="button" className="btn-secondary" onClick={loadSample}>Load sample</button>
          <button type="button" className="btn-secondary" onClick={clear}>Clear</button>
        </div>
      </Panel>

      {analysis !== null && !found && (
        <ErrorBanner>No headers found. Paste the raw headers of a message, starting with the Received lines.</ErrorBanner>
      )}

      {found && analysis && summary && (
        <div role="region" aria-label="Analysis">
          <Panel title="Summary" icon="bi-card-text" flush>
            <KeyValueTable
              rows={[
                ['From', summary.from],
                ['To', summary.to],
                ['Cc', summary.cc],
                ['Subject', summary.subject],
                ['Date', summary.date],
                ['Message-ID', summary.messageId],
                ['Return-Path', summary.returnPath],
                ['Reply-To', summary.replyTo],
                ['Mail client', summary.mailer],
              ]}
            />
          </Panel>

          <Panel title="Authentication" icon="bi-shield-check">
            <div className="tk-chip-row" style={{ marginBottom: '1rem' }}>
              <Badge tone={resultTone(analysis.auth.spf)}>SPF {analysis.auth.spf ?? 'not found'}</Badge>
              <Badge tone={resultTone(analysis.auth.dkim)}>DKIM {analysis.auth.dkim ?? 'not found'}</Badge>
              <Badge tone={resultTone(analysis.auth.dmarc)}>DMARC {analysis.auth.dmarc ?? 'not found'}</Badge>
            </div>
            <p className="tk-note">Results are what the receiving server wrote in the headers. Trust them only when they come from your own mail server.</p>
            <DataTable head={['Check', 'Result', 'Checked identity', 'Details', 'Reported by']} rows={authRows(analysis)} empty="No authentication results in these headers." />
            {analysis.auth.dkimSignatures.length > 0 && (
              <div style={{ marginTop: '1rem' }}>
                <p className="tk-note">DKIM signatures on the message</p>
                <DataTable
                  head={['Signing domain (d=)', 'Selector (s=)', 'Algorithm (a=)']}
                  rows={analysis.auth.dkimSignatures.map(signature => [<Cell key="d" mono>{signature.d || '—'}</Cell>, <Cell key="s" mono min={90}>{signature.s || '—'}</Cell>, <Cell key="a" mono min={90}>{signature.a || '—'}</Cell>])}
                />
              </div>
            )}
          </Panel>

          <Panel
            title="Delivery path"
            icon="bi-signpost-split"
            actions={analysis.totalTransitSeconds !== null ? <Badge tone="info">Total {formatDuration(analysis.totalTransitSeconds)}</Badge> : undefined}
            flush
          >
            <DataTable head={['Hop', 'From', 'By', 'Protocol', 'Time', 'Delay']} rows={hopRows(analysis.hops)} empty="No Received headers found, so the path cannot be traced." />
          </Panel>

          <Panel title="Findings" icon="bi-list-check">
            <div style={WRAP}><FindingList findings={analysis.findings} /></div>
            {analysis.findings.length === 0 && <p className="tk-note" style={{ marginBottom: 0 }}>Nothing to report for these headers.</p>}
          </Panel>

          <Panel title="All headers" icon="bi-list-ul">
            <details>
              <summary style={{ cursor: 'pointer', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                Show all {analysis.headers.length} headers{analysis.truncated ? ' (the rest were skipped)' : ''}
              </summary>
              <div style={{ marginTop: '1rem' }}>
                <DataTable head={['Header', 'Value']} rows={analysis.headers.map(header => [<span key="name" style={NOWRAP}>{header.name}</span>, <Cell key="value" mono min={260}>{header.value}</Cell>])} />
              </div>
            </details>
          </Panel>
        </div>
      )}
    </ToolPage>
  );
}
