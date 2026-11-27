'use client';

import { useRef, useState, type ChangeEvent, type ReactNode } from 'react';
import Link from 'next/link';
import ToolPage from '@/components/ToolPage';
import { Badge, DataTable, ErrorBanner, Field, FindingList, LoadingPanel, Panel, Stat, StatGrid, TextArea } from '@/components/ToolUi';
import { analyzeMailLog, type MailLogResult, type ReasonRow, type RecipientRow } from '@/lib/tools/mail-log';
import { buildMailLogSample } from '@/lib/tools/mail-log-sample';
import { formatLogTime, type Timeline } from '@/lib/tools/syslog';

const MAX_FILE_BYTES = 100 * 1024 * 1024;
/** Larger files are kept out of the text box, which would freeze on that much text. */
const MAX_EDITABLE_CHARS = 400000;
const PREVIEW_LINES = 200;

const TIMELINE_SERIES = [
  { label: 'Sent', color: 'var(--accent-green)' },
  { label: 'Deferred', color: 'var(--accent-amber)' },
  { label: 'Bounced', color: 'var(--accent-red)' },
  { label: 'Rejected', color: 'var(--accent-purple)' },
];

interface LoadedFile {
  name: string;
  size: number;
  /** The text box shows only the first lines; the whole file is in memory. */
  preview: boolean;
}

function num(value: number): string {
  return value.toLocaleString('en-US');
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)} s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ${Math.round((seconds % 3600) / 60)} min`;
  return `${Math.floor(seconds / 86400)} d ${Math.round((seconds % 86400) / 3600)} h`;
}

function firstLines(text: string, lines: number): string {
  let end = -1;
  for (let index = 0; index < lines; index += 1) {
    end = text.indexOf('\n', end + 1);
    if (end === -1) return text;
  }
  return text.slice(0, end);
}

/** One value that must stay on one line (an address, a name, a time). The table scrolls sideways instead. */
function Mono({ children }: { children: ReactNode }) {
  return <code className="tk-mono" style={{ whiteSpace: 'nowrap' }}>{children}</code>;
}

/** A count with a bar that shows its share of the largest count in the table. */
function CountBar({ value, max, color }: { value: number; max: number; color?: string }) {
  const width = max > 0 ? Math.max(2, Math.round((value / max) * 100)) : 0;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 140 }}>
      <span style={{ minWidth: '4ch', textAlign: 'right' }}>{num(value)}</span>
      <div style={{ flex: '1 1 0' }}>{value > 0 && <div className="tk-bar" style={{ width: `${width}%`, background: color }} />}</div>
    </div>
  );
}

/** Stacked columns, one per hour or day. ToolUi has no chart, so this one is local to the page. */
function TimelineChart({ timeline, series }: { timeline: Timeline; series: Array<{ label: string; color: string }> }) {
  const buckets = timeline.buckets;
  if (buckets.length === 0) return <p className="tk-note" style={{ margin: 0 }}>No recognized line has a timestamp, so there is no timeline.</p>;

  const scale = Math.max(1, timeline.max);
  const describe = (counts: number[]) => series.map((item, index) => `${item.label.toLowerCase()} ${num(counts[index])}`).join(', ');
  let peak = buckets[0];
  let peakSum = -1;
  for (const bucket of buckets) {
    const sum = bucket.counts.reduce((total, value) => total + value, 0);
    if (sum > peakSum) {
      peak = bucket;
      peakSum = sum;
    }
  }
  const summary = `Busiest ${timeline.unit}: ${peak.label} (${describe(peak.counts)}).`;

  return (
    <div>
      <div className="tk-chip-row" style={{ marginBottom: 12 }}>
        {series.map(item => (
          <span key={item.label} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
            <span aria-hidden="true" style={{ width: 10, height: 10, borderRadius: 2, background: item.color }} />
            {item.label}
          </span>
        ))}
      </div>
      <div
        role="img"
        aria-label={`Events per ${timeline.unit} from ${buckets[0].label} to ${buckets[buckets.length - 1].label}. ${summary}`}
        style={{ display: 'flex', alignItems: 'flex-end', gap: buckets.length > 96 ? 1 : 3, height: 150, borderBottom: '1px solid var(--border-color)' }}
      >
        {buckets.map(bucket => (
          <div key={bucket.start} title={`${bucket.label}: ${describe(bucket.counts)}`} style={{ flex: '1 1 0', minWidth: 0, height: '100%', display: 'flex', flexDirection: 'column-reverse' }}>
            {bucket.counts.map((value, index) => (value > 0 ? <div key={series[index].label} style={{ height: `${(value / scale) * 100}%`, minHeight: 2, background: series[index].color }} /> : null))}
          </div>
        ))}
      </div>
      <div className="tk-hint" style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6 }}>
        <span>{buckets[0].label}</span>
        <span>{buckets[buckets.length - 1].label}</span>
      </div>
      <p className="tk-note" style={{ margin: '0.75rem 0 0' }}>
        {summary}{timeline.unit === 'day' ? ' The log covers more than 14 days, so each bar is one day.' : ''}{timeline.truncated ? ` Only the latest ${buckets.length} days are drawn.` : ''}
      </p>
    </div>
  );
}

function Capped({ shown, total }: { shown: number; total: number }) {
  if (total === 0) return null;
  return <span className="tk-hint">{total > shown ? `Top ${num(shown)} of ${num(total)}` : `${num(total)} in total`}</span>;
}

function statusRows(rows: RecipientRow[]) {
  const max = rows.length > 0 ? rows[0].total : 0;
  return rows.map(row => [
    <Mono key="name">{row.name}</Mono>,
    <CountBar key="total" value={row.total} max={max} />,
    num(row.sent),
    num(row.deferred),
    num(row.bounced),
  ]);
}

function reasonRows(rows: ReasonRow[], color: string) {
  const max = rows.length > 0 ? rows[0].count : 0;
  return rows.map(row => [
    <CountBar key="count" value={row.count} max={max} color={color} />,
    row.reason,
    <code key="example" className="tk-mono" style={{ fontSize: '0.76rem', overflowWrap: 'anywhere' }}>{row.example}</code>,
  ]);
}

export default function MailLogPage() {
  const [text, setText] = useState('');
  const [file, setFile] = useState<LoadedFile | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<MailLogResult | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  /** Full text of a large file. It never goes into React state or the text box. */
  const fileText = useRef('');

  function reset() {
    fileText.current = '';
    setFile(null);
    setResult(null);
    setError('');
  }

  async function openFile(event: ChangeEvent<HTMLInputElement>) {
    const picked = event.target.files?.[0];
    event.target.value = '';
    if (!picked) return;
    reset();
    if (picked.size > MAX_FILE_BYTES) {
      setError(`${picked.name} is ${formatBytes(picked.size)}. Files above 100 MB are not opened. Cut out the part you need first, for example with tail or grep postfix.`);
      return;
    }
    if (/\.(gz|bz2|xz|zst|zip)$/i.test(picked.name)) {
      setError(`${picked.name} is compressed. Decompress it first, for example with gunzip or zcat.`);
      return;
    }
    try {
      const content = await picked.text();
      const preview = content.length > MAX_EDITABLE_CHARS;
      fileText.current = preview ? content : '';
      setText(preview ? firstLines(content, PREVIEW_LINES) : content);
      setFile({ name: picked.name, size: picked.size, preview });
    } catch {
      setError('The file could not be read.');
    }
  }

  function loadSample() {
    reset();
    setText(buildMailLogSample());
  }

  function clear() {
    reset();
    setText('');
  }

  function analyze() {
    const input = file?.preview ? fileText.current : text;
    if (!/\S/.test(input)) {
      setResult(null);
      setError('Paste a log or open a file first.');
      return;
    }
    setError('');
    setBusy(true);
    // Let the browser paint the busy state before a large log blocks the page for a moment.
    window.setTimeout(() => {
      try {
        setResult(analyzeMailLog(input));
      } catch {
        setResult(null);
        setError('This log could not be analyzed.');
      }
      setBusy(false);
    }, 30);
  }

  const totals = result?.totals;
  const links = result ? result.findings.flatMap(finding => (finding.link ? [finding.link] : [])) : [];
  const maxSender = result && result.topSenders.length > 0 ? result.topSenders[0].messages : 0;
  const maxReject = result && result.rejectReasons.length > 0 ? result.rejectReasons[0].count : 0;
  const maxClient = result && result.topRejectedClients.length > 0 ? result.topRejectedClients[0].count : 0;
  const maxSasl = result && result.saslClients.length > 0 ? result.saslClients[0].failures : 0;

  return (
    <ToolPage tool="mail-log" title="Mail Log Analyzer" icon="bi-mailbox" lead="See what Postfix delivered, deferred, bounced and rejected, and why." wide>
      <Panel title="Log" icon="bi-file-earmark-text" actions={file && <span className="tk-hint">{file.name} ({formatBytes(file.size)})</span>}>
        <Field label="Mail log" hint="Paste /var/log/mail.log or /var/log/maillog. Only Postfix logs are understood, not Exim or Sendmail, and Dovecot lines are ignored. Syslog and ISO 8601 timestamps are both read.">
          <TextArea
            value={text}
            readOnly={Boolean(file?.preview)}
            onChange={event => {
              setText(event.target.value);
              if (file) setFile(null);
            }}
            placeholder={'Nov 27 10:15:01 mx1 postfix/smtp[1234]: 4F9D21A0C2: to=<user@example.net>, relay=mx.example.net[203.0.113.20]:25, delay=1.4, delays=0.05/0.01/0.6/0.74, dsn=2.0.0, status=sent (250 2.0.0 Ok)'}
            style={{ minHeight: 200 }}
          />
        </Field>
        {file?.preview && (
          <p className="tk-note" style={{ margin: '0.75rem 0 0' }}>
            The box shows the first {PREVIEW_LINES} lines of {file.name}. The whole file is analyzed.
          </p>
        )}
        <div className="tk-form" style={{ marginTop: '1rem', alignItems: 'center' }}>
          <button type="button" className="btn-primary" onClick={analyze} disabled={busy}>Analyze</button>
          <button type="button" className="btn-secondary" onClick={() => fileInput.current?.click()}>Open file</button>
          <button type="button" className="btn-secondary" onClick={loadSample}>Load sample</button>
          <button type="button" className="btn-secondary" onClick={clear}>Clear</button>
          <input ref={fileInput} type="file" hidden aria-label="Open a log file" onChange={event => void openFile(event)} />
        </div>
        <p className="tk-note" style={{ margin: '1rem 0 0' }}>
          The log is read and analyzed in your browser. It is never uploaded or sent to a server. Files up to 100 MB can be opened.
        </p>
      </Panel>

      {error && <ErrorBanner>{error}</ErrorBanner>}
      {busy && <LoadingPanel title="Analyzing the log">Large files take a few seconds.</LoadingPanel>}

      {result && totals && !busy && (
        <>
          <StatGrid>
            <Stat label="Lines read" value={num(totals.lines)} tone="muted" />
            <Stat label="Lines recognized" value={num(totals.recognized)} tone="muted" />
            <Stat label="Messages queued" value={num(totals.queued)} tone="info" />
            <Stat label="Size queued" value={formatBytes(totals.bytesQueued)} tone="info" />
            <Stat label="Delivered" value={num(totals.delivered)} tone="ok" />
            <Stat label="Deferred" value={num(totals.deferred)} tone={totals.deferred > 0 ? 'warn' : 'ok'} />
            <Stat label="Bounced" value={num(totals.bounced)} tone={totals.bounced > 0 ? 'bad' : 'ok'} />
            <Stat label="Expired" value={num(totals.expired)} tone={totals.expired > 0 ? 'bad' : 'ok'} />
            <Stat label="Rejected" value={num(totals.rejected)} tone="warn" />
            <Stat label="SASL failures" value={num(totals.saslFailures)} tone={totals.saslFailures > 0 ? 'bad' : 'ok'} />
            <Stat label="Average delay" value={result.delay.count > 0 ? formatDuration(result.delay.average) : 'None'} tone="muted" />
            <Stat label="Longest delay" value={result.delay.count > 0 ? formatDuration(result.delay.max) : 'None'} tone="muted" />
          </StatGrid>

          <Panel title="Findings" icon="bi-clipboard-check">
            <FindingList findings={result.findings} />
            {links.map(link => (
              <p key={link.href} className="tk-note" style={{ margin: '0.75rem 0 0' }}>
                <Link href={link.href} prefetch={false}>{link.label}</Link>
              </p>
            ))}
            <p className="tk-note" style={{ margin: '1rem 0 0' }}>
              {result.firstSeen !== null && result.lastSeen !== null && <>The recognized lines run from {formatLogTime(result.firstSeen)} to {formatLogTime(result.lastSeen)}, in the time zone of the log. </>}
              Queued counts messages. Delivered, deferred and bounced count delivery attempts per recipient, so a message that is retried three times adds three to deferred.
              Rejected is mail refused before it was queued. Delay is the time from queueing to delivery for delivered mail.
              {totals.connections > 0 && <> Connections from clients: {num(totals.connections)}.</>}
              {totals.bounceNotifications > 0 && <> Non-delivery notices sent: {num(totals.bounceNotifications)}.</>}
              {totals.postscreenDnsbl + totals.postscreenPregreet > 0 && <> postscreen DNSBL hits: {num(totals.postscreenDnsbl)}. Clients that talked before the greeting: {num(totals.postscreenPregreet)}.</>}
            </p>
          </Panel>

          <Panel title="Timeline" icon="bi-bar-chart">
            <TimelineChart timeline={result.timeline} series={TIMELINE_SERIES} />
          </Panel>

          <Panel title="Senders" icon="bi-send" flush actions={<Capped shown={result.topSenders.length} total={result.senderTotal} />}>
            <DataTable
              empty="No queued message in this log."
              head={['Sender', 'Messages', 'Size', 'Sent', 'Deferred', 'Bounced']}
              rows={result.topSenders.map(row => [
                <Mono key="sender">{row.sender}</Mono>,
                <CountBar key="messages" value={row.messages} max={maxSender} />,
                formatBytes(row.bytes),
                num(row.sent),
                num(row.deferred),
                row.bounced > 0 ? <Badge key="bounced" tone="bad">{num(row.bounced)}</Badge> : '0',
              ])}
            />
          </Panel>

          <Panel title="Recipients" icon="bi-person-lines-fill" flush actions={<Capped shown={result.topRecipients.length} total={result.recipientTotal} />}>
            <DataTable empty="No delivery attempt in this log." head={['Recipient', 'Attempts', 'Sent', 'Deferred', 'Bounced']} rows={statusRows(result.topRecipients)} />
          </Panel>

          <Panel title="Recipient domains" icon="bi-globe2" flush actions={<Capped shown={result.topDomains.length} total={result.domainTotal} />}>
            <DataTable empty="No delivery attempt in this log." head={['Domain', 'Attempts', 'Sent', 'Deferred', 'Bounced']} rows={statusRows(result.topDomains)} />
          </Panel>

          <Panel title="Deferred reasons" icon="bi-hourglass-split" flush actions={<Capped shown={result.deferredReasons.length} total={result.deferredReasonTotal} />}>
            <DataTable empty="Nothing was deferred." head={['Count', 'Reason', 'Example from the log']} rows={reasonRows(result.deferredReasons, 'var(--accent-amber)')} />
          </Panel>

          <Panel title="Bounced reasons" icon="bi-arrow-return-left" flush actions={<Capped shown={result.bouncedReasons.length} total={result.bouncedReasonTotal} />}>
            <DataTable empty="Nothing bounced." head={['Count', 'Reason', 'Example from the log']} rows={reasonRows(result.bouncedReasons, 'var(--accent-red)')} />
            {result.bouncedReasons.length + result.deferredReasons.length > 0 && (
              <p className="tk-empty-note">Host names, addresses, queue IDs and long numbers are replaced with placeholders so that similar reasons are counted together.</p>
            )}
          </Panel>

          <Panel title="Reject reasons" icon="bi-slash-circle" flush actions={<Capped shown={result.rejectReasons.length} total={result.rejectReasonTotal} />}>
            <DataTable
              empty="Nothing was rejected."
              head={['Count', 'Code', 'Reason', 'Example from the log']}
              rows={result.rejectReasons.map(row => [
                <CountBar key="count" value={row.count} max={maxReject} color="var(--accent-purple)" />,
                <Badge key="code" tone={row.code.startsWith('4') ? 'warn' : row.code.startsWith('5') ? 'bad' : 'muted'}>{row.code}</Badge>,
                row.category,
                <code key="example" className="tk-mono" style={{ fontSize: '0.76rem', overflowWrap: 'anywhere' }}>{row.example}</code>,
              ])}
            />
          </Panel>

          <Panel title="Rejected clients" icon="bi-hdd-network" flush actions={<Capped shown={result.topRejectedClients.length} total={result.rejectedClientTotal} />}>
            <DataTable
              empty="No client was rejected."
              head={['Address', 'Host name', 'Rejects']}
              rows={result.topRejectedClients.map(row => [
                <Mono key="ip">{row.ip}</Mono>,
                row.host,
                <CountBar key="count" value={row.count} max={maxClient} color="var(--accent-purple)" />,
              ])}
            />
          </Panel>

          <Panel title="SASL login failures" icon="bi-key" flush actions={<Capped shown={result.saslClients.length} total={result.saslClientTotal} />}>
            <DataTable
              empty="No failed SMTP login in this log."
              head={['Address', 'Host name', 'Failed logins', 'Dropped during login']}
              rows={result.saslClients.map(row => [
                <Mono key="ip">{row.ip}</Mono>,
                row.host,
                <CountBar key="count" value={row.failures} max={maxSasl} color="var(--accent-red)" />,
                num(row.aborted),
              ])}
            />
          </Panel>
        </>
      )}
    </ToolPage>
  );
}
