'use client';

import { useEffect, useRef, useState } from 'react';
import ToolPage from '@/components/ToolPage';
import { Badge, CodeBlock, DataTable, Field, FindingList, KeyValueTable, Panel, TextInput } from '@/components/ToolUi';
import {
  eventCategories,
  eventCommands,
  KERBEROS_FAILURE_CODES,
  LOGON_FAILURE_CODES,
  LOGON_TYPES,
  parseEventId,
  referenceTablesFor,
  searchEvents,
  WINDOWS_EVENTS,
  type CodeRow,
  type WindowsEvent,
} from '@/lib/tools/windows-events';

const SUGGESTIONS = ['4625', '4624', '4740', '7045', '1102', '6008', '41'];
const CATEGORIES = eventCategories();
const SOURCE_COUNT = new Set(WINDOWS_EVENTS.map(event => event.source)).size;
/** Up to this many results are shown as full cards, more as a table. */
const CARD_LIMIT = 6;

const stack = { display: 'grid', gridTemplateColumns: 'minmax(0, 1fr)', gap: '1rem' } as const;
const nowrap = { whiteSpace: 'nowrap' } as const;
/** Keeps a text column readable on narrow screens: the table scrolls sideways instead of squeezing it. */
const wide = { minWidth: '14rem' } as const;

function CodeTable({ head, rows }: { head: string; rows: CodeRow[] }) {
  return (
    <DataTable
      head={[head, 'Name', 'Meaning']}
      rows={rows.map(row => [<code key="code" className="tk-mono" style={nowrap}>{row.code}</code>, <code key="name" className="tk-mono" style={nowrap}>{row.name}</code>, <div key="meaning" style={wide}>{row.meaning}</div>])}
    />
  );
}

function ReferenceTables({ logonTypes, logonFailureCodes, kerberosCodes }: { logonTypes: boolean; logonFailureCodes: boolean; kerberosCodes: boolean }) {
  return (
    <>
      {logonTypes && (
        <Panel title="Logon types (events 4624, 4625, 4634)" icon="bi-door-open" flush>
          <CodeTable head="Type" rows={LOGON_TYPES} />
        </Panel>
      )}
      {logonFailureCodes && (
        <Panel title="Status and Sub Status codes (event 4625, error code of 4776)" icon="bi-x-octagon" flush>
          <CodeTable head="Code" rows={LOGON_FAILURE_CODES} />
        </Panel>
      )}
      {kerberosCodes && (
        <Panel title="Kerberos result codes (events 4768, 4769, 4771)" icon="bi-key" flush>
          <CodeTable head="Code" rows={KERBEROS_FAILURE_CODES} />
        </Panel>
      )}
    </>
  );
}

function EventCard({ event }: { event: WindowsEvent }) {
  const commands = eventCommands(event);
  return (
    <Panel title={`${event.id} · ${event.title}`} icon="bi-journal-text" actions={<Badge tone="info">{event.category}</Badge>}>
      <div style={stack}>
        <p className="tk-note" style={{ margin: 0 }}>{event.meaning}</p>
        <KeyValueTable rows={[['Event ID', event.id], ['Source', event.source], ['Log', event.log]]} />
        <FindingList findings={[{ severity: 'info', title: 'What to check', detail: event.check }]} />
        <div>
          <CodeBlock label="PowerShell" code={commands.powershell} />
          <CodeBlock label="Command prompt" code={commands.wevtutil} />
          <small className="tk-hint">
            {event.log === 'Security' ? 'Reading the Security log needs an elevated prompt. ' : ''}Get-WinEvent reports an error when no event matches.
          </small>
        </div>
      </div>
    </Panel>
  );
}

export default function WindowsEventsPage() {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('');
  const prefillApplied = useRef(false);

  // Deep link: /windows-events?id=4625
  useEffect(() => {
    if (prefillApplied.current) return;
    const id = new URLSearchParams(window.location.search).get('id');
    if (!id) return;
    const timer = window.setTimeout(() => {
      prefillApplied.current = true;
      setQuery(id);
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  const text = query.trim();
  const browsing = !text && !category;
  const results = browsing ? [] : searchEvents(text, { category: category || undefined });
  const id = parseEventId(text);
  const prefixOnly = id !== null && results.length > 0 && results[0].id !== id;
  const tables = referenceTablesFor(results.length <= CARD_LIMIT ? results : []);

  const lookUp = (value: string) => { setCategory(''); setQuery(value); };

  return (
    <ToolPage tool="windows-events" title="Windows Event ID Lookup" icon="bi-journal-text" lead="Find out what a Windows event means, what to check and how to list it on a machine.">
      <Panel title="Look up an event" icon="bi-search">
        <div style={stack}>
          <Field label="Event ID or keyword" hint={`The reference covers ${WINDOWS_EVENTS.length} common events from ${SOURCE_COUNT} sources, not every event Windows can log.`}>
            <TextInput mono type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="4625, lockout, service installed" />
          </Field>
          <div className="tk-chip-row" role="group" aria-label="Common event IDs">
            {SUGGESTIONS.map(item => (
              <button key={item} type="button" className="tk-chip tk-mono" onClick={() => lookUp(item)}>{item}</button>
            ))}
          </div>
          <div className="tk-chip-row" role="group" aria-label="Filter by category">
            <button type="button" className="tk-chip" aria-pressed={category === ''} onClick={() => setCategory('')}>All categories</button>
            {CATEGORIES.map(item => (
              <button key={item.category} type="button" className="tk-chip" aria-pressed={category === item.category} onClick={() => setCategory(category === item.category ? '' : item.category)}>
                {item.category}
              </button>
            ))}
          </div>
        </div>
      </Panel>

      {browsing && (
        <>
          <Panel title="Categories" icon="bi-collection" flush>
            <DataTable
              head={['Category', 'Events', 'Examples']}
              rows={CATEGORIES.map(item => [
                <button key="category" type="button" className="tk-chip" style={nowrap} onClick={() => setCategory(item.category)}>{item.category}</button>,
                item.count,
                WINDOWS_EVENTS.filter(event => event.category === item.category).slice(0, 3).map(event => `${event.id} ${event.title}`).join(', '),
              ])}
            />
          </Panel>
          <ReferenceTables logonTypes logonFailureCodes kerberosCodes />
        </>
      )}

      {!browsing && results.length === 0 && (
        <Panel title="No match" icon="bi-question-circle">
          <p className="tk-note" style={{ margin: 0 }}>
            Nothing in the reference matches{text ? ` "${text}"` : ''}{category ? ` in ${category}` : ''}. It covers common events only, so a missing ID does not mean the event is unimportant.
          </p>
        </Panel>
      )}

      {prefixOnly && (
        <Panel>
          <p className="tk-note" style={{ margin: 0 }}>Event {id} is not in the reference. These IDs start with {id}.</p>
        </Panel>
      )}

      {results.length > 0 && results.length <= CARD_LIMIT && results.map(event => <EventCard key={`${event.id}-${event.source}`} event={event} />)}

      {results.length > CARD_LIMIT && (
        <Panel title={`${results.length} events`} icon="bi-list-ul" flush>
          <DataTable
            head={['ID', 'Event', 'Source', 'Log']}
            rows={results.map(event => [
              <button key="id" type="button" className="tk-chip tk-mono" style={nowrap} aria-label={`Show event ${event.id}`} onClick={() => lookUp(String(event.id))}>{event.id}</button>,
              <div key="title" style={{ minWidth: '10rem' }}>{event.title}</div>,
              event.source,
              event.log,
            ])}
          />
        </Panel>
      )}

      {!browsing && <ReferenceTables {...tables} />}
    </ToolPage>
  );
}
