'use client';

import { useMemo, useRef, useState, type ChangeEvent, type ReactNode } from 'react';
import ToolPage from '@/components/ToolPage';
import { Badge, CopyButton, DataTable, ErrorBanner, Field, FindingList, LoadingPanel, Panel, Select, Stat, StatGrid, TextArea, TextInput } from '@/components/ToolUi';
import { analyzeAuthLog, BLOCK_FORMATS, buildBlockList, DEFAULT_BLOCK_THRESHOLD, type AuthLogResult, type BlockFormat } from '@/lib/tools/auth-log';
import { buildAuthLogSample } from '@/lib/tools/auth-log-sample';
import { formatLogTime, type Timeline } from '@/lib/tools/syslog';

const MAX_FILE_BYTES = 100 * 1024 * 1024;
/** Larger files are kept out of the text box, which would freeze on that much text. */
const MAX_EDITABLE_CHARS = 400000;
const PREVIEW_LINES = 200;

const TIMELINE_SERIES = [
  { label: 'Failed attempts', color: 'var(--accent-red)' },
  { label: 'Accepted logins', color: 'var(--accent-green)' },
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
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
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

function Time({ ts }: { ts: number | null }) {
  return <span style={{ whiteSpace: 'nowrap' }}>{formatLogTime(ts) || 'Unknown'}</span>;
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

export default function AuthLogPage() {
  const [text, setText] = useState('');
  const [file, setFile] = useState<LoadedFile | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<AuthLogResult | null>(null);
  const [thresholdText, setThresholdText] = useState(String(DEFAULT_BLOCK_THRESHOLD));
  const [format, setFormat] = useState<BlockFormat>('plain');
  const fileInput = useRef<HTMLInputElement>(null);
  /** Full text of a large file. It never goes into React state or the text box. */
  const fileText = useRef('');

  const thresholdValid = /^\d{1,9}$/.test(thresholdText.trim()) && Number(thresholdText) >= 1;
  const threshold = thresholdValid ? Number(thresholdText) : DEFAULT_BLOCK_THRESHOLD;
  const blockList = useMemo(() => (result ? buildBlockList(result.offenders, { threshold, format }) : null), [result, threshold, format]);

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
      setError(`${picked.name} is ${formatBytes(picked.size)}. Files above 100 MB are not opened. Cut out the part you need first, for example with tail or grep sshd.`);
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
    setText(buildAuthLogSample());
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
        setResult(analyzeAuthLog(input));
      } catch {
        setResult(null);
        setError('This log could not be analyzed.');
      }
      setBusy(false);
    }, 30);
  }

  const totals = result?.totals;
  const maxFailed = result && result.topIps.length > 0 ? result.topIps[0].failed : 0;
  const maxUserFailed = result && result.topUsers.length > 0 ? result.topUsers[0].failed : 0;

  return (
    <ToolPage tool="auth-log" title="SSH Auth Log Analyzer" icon="bi-person-lock" lead="Find brute-force sources, suspicious logins and sudo activity in auth.log or secure." wide>
      <Panel title="Log" icon="bi-file-earmark-text" actions={file && <span className="tk-hint">{file.name} ({formatBytes(file.size)})</span>}>
        <Field label="Auth log" hint="Paste /var/log/auth.log (Debian, Ubuntu), /var/log/secure (RHEL family) or the output of journalctl -u ssh. Syslog and ISO 8601 timestamps are both read.">
          <TextArea
            value={text}
            readOnly={Boolean(file?.preview)}
            onChange={event => {
              setText(event.target.value);
              if (file) setFile(null);
            }}
            placeholder={'Nov 27 10:15:01 web01 sshd[1234]: Failed password for root from 203.0.113.45 port 51122 ssh2'}
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
            <Stat label="Failed attempts" value={num(totals.failedAttempts)} tone={totals.failedAttempts > 0 ? 'bad' : 'ok'} />
            <Stat label="Source addresses" value={num(totals.failedIps)} tone={totals.failedIps > 0 ? 'bad' : 'ok'} />
            <Stat label="Usernames tried" value={num(totals.usernamesTried)} tone="warn" />
            <Stat label="Invalid usernames" value={num(totals.invalidUsernames)} tone="warn" />
            <Stat label="Accepted logins" value={num(totals.acceptedLogins)} tone="ok" />
            <Stat label="Scanner probes" value={num(totals.scannerProbes)} tone="info" />
          </StatGrid>

          <Panel title="Findings" icon="bi-clipboard-check">
            <FindingList findings={result.findings} />
            <p className="tk-note" style={{ margin: '1rem 0 0' }}>
              {result.firstSeen !== null && result.lastSeen !== null && <>The recognized lines run from {formatLogTime(result.firstSeen)} to {formatLogTime(result.lastSeen)}, in the time zone of the log. </>}
              A failed attempt is one &quot;Failed password&quot; (or other method) line, times its count when the log says &quot;message repeated&quot;.
              &quot;Invalid user&quot; and pam_unix lines describe the same attempt again, so they add usernames and addresses but are not counted twice.
              {result.failedByMethod.length > 0 && <> By method: {result.failedByMethod.map(item => `${item.method} ${num(item.count)}`).join(', ')}.</>}
            </p>
          </Panel>

          <Panel title="Timeline" icon="bi-bar-chart">
            <TimelineChart timeline={result.timeline} series={TIMELINE_SERIES} />
          </Panel>

          <Panel title="Source addresses" icon="bi-hdd-network" flush actions={<Capped shown={result.topIps.length} total={result.ipTotal} />}>
            <DataTable
              empty="No address had a failed attempt."
              head={['Address', 'Failed attempts', 'Usernames', 'Other events', 'First seen', 'Last seen', 'Login']}
              rows={result.topIps.map(row => [
                <Mono key="ip">{row.ip}</Mono>,
                <CountBar key="failed" value={row.failed} max={maxFailed} color="var(--accent-red)" />,
                num(row.users),
                num(row.other),
                <Time key="first" ts={row.firstSeen} />,
                <Time key="last" ts={row.lastSeen} />,
                row.accepted ? <Badge key="login" tone="bad">Accepted</Badge> : <Badge key="login">None</Badge>,
              ])}
            />
            {result.topIps.length > 0 && (
              <p className="tk-empty-note">Other events are connections closed before login, scanner probes and &quot;maximum authentication attempts&quot; lines. They are not counted as failed attempts.</p>
            )}
          </Panel>

          <Panel title="Block list" icon="bi-shield-x">
            <div className="tk-form" style={{ marginBottom: '1rem' }}>
              <Field label="Minimum failed attempts" hint={thresholdValid ? undefined : `Enter a whole number, 1 or more. Using ${DEFAULT_BLOCK_THRESHOLD}.`}>
                <TextInput mono inputMode="numeric" value={thresholdText} onChange={event => setThresholdText(event.target.value)} style={{ maxWidth: 160 }} />
              </Field>
              <Field label="Format">
                <Select value={format} onChange={event => setFormat(event.target.value as BlockFormat)}>
                  {BLOCK_FORMATS.map(item => <option key={item.key} value={item.key}>{item.label}</option>)}
                </Select>
              </Field>
            </div>
            {blockList && blockList.ips.length > 0 ? (
              // Same look as ToolUi's CodeBlock, with a height limit: a large log can list thousands of addresses.
              <div className="tk-code">
                <div className="tk-code-head">
                  <span>{num(blockList.ips.length)} {blockList.ips.length === 1 ? 'address' : 'addresses'} with {num(blockList.threshold)} or more failed attempts</span>
                  <CopyButton text={blockList.text} />
                </div>
                <pre tabIndex={0} aria-label="Block list" style={{ maxHeight: 360, overflowY: 'auto' }}><code>{blockList.text}</code></pre>
              </div>
            ) : (
              <p className="tk-note">No address has {num(threshold)} or more failed attempts without an accepted login.</p>
            )}
            {blockList && blockList.review.length > 0 && (
              <div style={{ marginTop: '1rem' }}>
                <FindingList
                  findings={[{
                    severity: 'warning',
                    title: `Review manually: ${num(blockList.review.length)} ${blockList.review.length === 1 ? 'address is' : 'addresses are'} left out of the block list`,
                    detail: `${blockList.review.slice(0, 10).map(item => `${item.ip} (${num(item.failed)} failed, ${item.reason})`).join('; ')}${blockList.review.length > 10 ? `; and ${num(blockList.review.length - 10)} more` : ''}. An address that also logged in successfully may belong to a real user, and private addresses are inside your own network, so neither is blocked automatically.`,
                  }]}
                />
              </div>
            )}
            <p className="tk-note" style={{ margin: '1rem 0 0' }}>
              Blocking single addresses is a short-term fix, because attackers change address. fail2ban, which bans addresses automatically, or key-only authentication (PasswordAuthentication no) is the lasting fix.
            </p>
          </Panel>

          <Panel title="Targeted usernames" icon="bi-person-x" flush actions={<Capped shown={result.topUsers.length} total={result.userTotal} />}>
            <DataTable
              empty="No username was tried."
              head={['Username', 'Failed attempts', 'Other events', 'Account']}
              rows={result.topUsers.map(row => [
                <Mono key="user">{row.user}</Mono>,
                <CountBar key="failed" value={row.failed} max={maxUserFailed} color="var(--accent-amber)" />,
                num(row.other),
                row.invalid ? <Badge key="account">Does not exist</Badge> : <Badge key="account" tone="warn">Exists</Badge>,
              ])}
            />
          </Panel>

          <Panel title="Accepted logins" icon="bi-box-arrow-in-right" flush actions={<Capped shown={result.accepted.length} total={result.acceptedTotal} />}>
            <DataTable
              empty="No accepted login in this log."
              head={['Time', 'User', 'Address', 'Method']}
              rows={result.accepted.map(row => [
                <Time key="time" ts={row.ts} />,
                <Mono key="user">{row.user}</Mono>,
                <Mono key="ip">{row.ip}</Mono>,
                row.method === 'password' ? <Badge key="method" tone="warn">password</Badge> : <Badge key="method" tone="ok">{row.method}</Badge>,
              ])}
            />
          </Panel>

          <Panel title="sudo" icon="bi-terminal" flush actions={<Capped shown={result.sudo.users.length} total={result.sudo.userTotal} />}>
            <DataTable
              empty="No sudo lines in this log."
              head={['User', 'Commands', 'Authentication failures', 'Not in sudoers', 'Last command']}
              rows={result.sudo.users.map(row => [
                <Mono key="user">{row.user}</Mono>,
                num(row.commands),
                num(row.authFailures),
                row.notInSudoers > 0 ? <Badge key="denied" tone="bad">{num(row.notInSudoers)}</Badge> : '0',
                row.lastCommand ? <code key="command" className="tk-mono">{row.lastCommand}</code> : 'None',
              ])}
            />
            {result.sudo.userTotal > 0 && (
              <p className="tk-empty-note">
                Commands run: {num(result.sudo.commands)}. Authentication failures: {num(result.sudo.authFailures)}. Attempts by users who are not in sudoers: {num(result.sudo.notInSudoers)}.{result.sudo.denied > 0 ? ` Commands not allowed: ${num(result.sudo.denied)}.` : ''}
              </p>
            )}
          </Panel>
        </>
      )}
    </ToolPage>
  );
}
