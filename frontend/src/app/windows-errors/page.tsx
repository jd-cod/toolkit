'use client';

import { useEffect, useRef, useState } from 'react';
import ToolPage from '@/components/ToolPage';
import { Badge, CodeBlock, DataTable, Field, FindingList, KeyValueTable, Panel, TextInput, type Finding } from '@/components/ToolUi';
import { decodeErrorCode, KIND_LABELS, NOT_IN_REFERENCE, referenceCounts, searchErrors, type ErrorKind, type Interpretation } from '@/lib/tools/windows-errors';

const SUGGESTIONS = ['0x80070005', '0xC0000005', '1603', '0x800F081F', '0x80004005', '5'];
const COUNTS = referenceCounts();
const TOTAL = Object.values(COUNTS).reduce((sum, count) => sum + count, 0);

const FORMATS: Array<{ kind: ErrorKind; looks: string; examples: string[] }> = [
  { kind: 'win32', looks: 'Small decimal numbers, as shown by net helpmsg and most exit codes.', examples: ['5', '1603'] },
  { kind: 'hresult', looks: 'Values that start with 0x8, from COM, .NET, Windows Update and installers.', examples: ['0x80070005', '0x80240034'] },
  { kind: 'ntstatus', looks: 'Values that start with 0xC, from the kernel, drivers and crashed programs.', examples: ['0xC0000005', '0xC0000135'] },
  { kind: 'exception', looks: 'Values that start with 0xE, raised by the C++ and .NET runtimes.', examples: ['0xE06D7363'] },
  { kind: 'bugcheck', looks: 'Short hex values from a blue screen or System event 1001.', examples: ['0x7B', '0x124'] },
];

const stack = { display: 'grid', gridTemplateColumns: 'minmax(0, 1fr)', gap: '1rem' } as const;
/** Keeps a text column readable on narrow screens: the table scrolls sideways instead of squeezing it. */
const wide = { minWidth: '12rem' } as const;

function InterpretationCard({ item }: { item: Interpretation }) {
  const title = `${item.label} ${item.display}${item.name ? ` · ${item.name}` : ''}`;
  const numbers: Array<[string, string]> = [['Hex', item.hex], ['Decimal', item.decimal]];
  if (item.signed !== item.decimal) numbers.push(['Signed decimal', item.signed]);

  const findings: Finding[] = [];
  if (!item.known) findings.push({ severity: 'info', title: 'The name is not in the reference', detail: NOT_IN_REFERENCE });
  if (item.wraps) {
    const what = item.wraps.kind === 'win32' ? `Win32 error ${item.wraps.display}` : `NTSTATUS ${item.wraps.display}`;
    findings.push({
      severity: 'info',
      title: item.wraps.known ? `Wraps ${what}: ${item.wraps.name}` : `Wraps ${what}`,
      detail: item.wraps.known ? item.wraps.meaning : 'That code is not in the reference.',
    });
  }
  if (item.check) findings.push({ severity: 'info', title: 'What to check', detail: item.check });

  return (
    <Panel title={title} icon="bi-bug" actions={<Badge tone={item.known ? 'info' : 'muted'}>Read as {item.readAs}</Badge>}>
      <div style={stack}>
        {item.meaning && <p className="tk-note" style={{ margin: 0 }}>{item.meaning}</p>}
        {item.note && <p className="tk-note" style={{ margin: 0 }}>{item.note}</p>}
        <KeyValueTable rows={numbers} />
        {item.fields.length > 0 && (
          <DataTable head={['Field', 'Value', 'Meaning']} rows={item.fields.map(field => [field.field, <code key="value" className="tk-mono" style={{ whiteSpace: 'nowrap' }}>{field.value}</code>, <div key="meaning" style={wide}>{field.meaning}</div>])} />
        )}
        <FindingList findings={findings} />
        {item.commands.length > 0 && (
          <div>
            {item.commands.map(command => <CodeBlock key={command.command} label={command.label} code={command.command} />)}
            <small className="tk-hint">Run these on a Windows machine to read the message text that Windows itself has for the code, if it has one.</small>
          </div>
        )}
      </div>
    </Panel>
  );
}

export default function WindowsErrorsPage() {
  const [query, setQuery] = useState('');
  const prefillApplied = useRef(false);

  // Deep link: /windows-errors?code=0x80070005
  useEffect(() => {
    if (prefillApplied.current) return;
    const code = new URLSearchParams(window.location.search).get('code');
    if (!code) return;
    const timer = window.setTimeout(() => {
      prefillApplied.current = true;
      setQuery(code);
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  const decoded = decodeErrorCode(query);
  const matches = decoded.kind === 'text' ? searchErrors(query) : [];

  return (
    <ToolPage tool="windows-errors" title="Windows Error Code Lookup" icon="bi-bug" lead="Decode a Win32 error, HRESULT, NTSTATUS or stop code and see what it is made of.">
      <Panel title="Look up a code" icon="bi-search">
        <div style={stack}>
          <Field label="Error code or name" hint="Decimal (5, -2147024891), hex (0x80070005, c0000005) or part of a name (ACCESS_DENIED).">
            <TextInput mono type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="0x80070005" />
          </Field>
          <div className="tk-chip-row" role="group" aria-label="Common error codes">
            {SUGGESTIONS.map(item => (
              <button key={item} type="button" className="tk-chip tk-mono" onClick={() => setQuery(item)}>{item}</button>
            ))}
          </div>
        </div>
      </Panel>

      {decoded.kind === 'empty' && (
        <Panel title="What the reference covers" icon="bi-collection" flush>
          <p className="tk-note" style={{ margin: 0, padding: '1rem 1.25rem' }}>
            {TOTAL} common codes, not every code Windows defines. A code that is not listed still gets its fields decoded.
          </p>
          <DataTable
            head={['Format', 'Entries', 'Looks like', 'Try']}
            rows={FORMATS.map(format => [
              KIND_LABELS[format.kind],
              COUNTS[format.kind],
              format.looks,
              <div key="try" className="tk-chip-row">
                {format.examples.map(example => <button key={example} type="button" className="tk-chip tk-mono" onClick={() => setQuery(example)}>{example}</button>)}
              </div>,
            ])}
          />
        </Panel>
      )}

      {decoded.kind === 'invalid' && (
        <Panel title="Not a 32-bit code" icon="bi-question-circle">
          <p className="tk-note" style={{ margin: 0 }}>{decoded.message}</p>
        </Panel>
      )}

      {decoded.kind === 'code' && decoded.message && (
        <Panel>
          <p className="tk-note" style={{ margin: 0 }}>{decoded.message}</p>
        </Panel>
      )}

      {decoded.interpretations.map(item => <InterpretationCard key={`${item.kind}-${item.hex}-${item.readAs}`} item={item} />)}

      {decoded.kind === 'text' && (
        <Panel title={matches.length ? `${matches.length} ${matches.length === 1 ? 'match' : 'matches'}` : 'No match'} icon="bi-list-ul" flush>
          <DataTable
            head={['Code', 'Format', 'Name', 'Meaning']}
            rows={matches.map(match => [
              <button key="code" type="button" className="tk-chip tk-mono" style={{ whiteSpace: 'nowrap' }} aria-label={`Decode ${match.display}`} onClick={() => setQuery(match.display)}>{match.display}</button>,
              match.label,
              <code key="name" className="tk-mono">{match.name}</code>,
              <div key="meaning" style={wide}>{match.meaning}</div>,
            ])}
            empty="No name or meaning in the reference matches. It covers common codes only. Enter the number to decode its fields."
          />
        </Panel>
      )}
    </ToolPage>
  );
}
