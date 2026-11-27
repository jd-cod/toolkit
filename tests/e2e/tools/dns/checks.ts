import { parseCsv } from '../_support/csv';
import { expect, type Evidence, type Page } from '../_support/fixtures';
import { XSS_FLAG } from './generator';
import { expectedView, providerMeta, utcStampsBetween, type ExpectedSection, type ExpectedView, type GeoOracle, type Lookup } from './oracle';
import type { DnsCall, DnsPage, ShownSection, ShownView } from './page';

/**
 * Field-by-field comparisons between what a page (or an exported file) shows
 * and what the oracle expects. Every comparison is soft and names the value
 * and the input, so one run reports every wrong field.
 */

export interface ViewCheck {
  /** Names the input in every message, e.g. `lookup of "abc.example" (MX, TXT)`. */
  ctx: string;
  /** Acceptable "Checked At" texts. Omit to skip (the caller checks it another way). */
  stamps?: string[];
  /** Upper bound for a section's query time in ms (wall time of the whole lookup). */
  maxQueryMs?: number;
  /**
   * Regional (global) snapshots carry no TTL; their TTL cells are checked by a
   * dedicated test instead of here.
   */
  skipTtl?: boolean;
}

const CARD_LABELS = ['Domain', 'Records Found', 'DNS Provider', 'Hosting / Edge', 'Resolver'];

export function parseCounter(counter: string): { found: number; ms: number } | null {
  const match = counter.match(/^(\d+) found · (\d+)ms$/);
  return match ? { found: Number(match[1]), ms: Number(match[2]) } : null;
}

function expectSection(shown: ShownSection | undefined, want: ExpectedSection, check: ViewCheck, position: number): void {
  const where = `${check.ctx}: section ${position + 1} (${want.type})`;
  if (!shown) {
    expect.soft(shown, `${where} is missing from the page`).toBeDefined();
    return;
  }
  expect.soft(shown.heading, `${where}: heading`).toBe(`${want.type} Records`);

  const counter = parseCounter(shown.counter);
  expect.soft(counter, `${where}: counter "${shown.counter}" should read "<n> found · <t>ms"`).not.toBeNull();
  if (counter) {
    expect.soft(counter.found, `${where}: number of records in the heading`).toBe(want.count);
    if (want.queryMs !== undefined) expect.soft(counter.ms, `${where}: query time in the heading`).toBe(want.queryMs);
    else if (check.maxQueryMs !== undefined) {
      expect.soft(counter.ms, `${where}: query time ${counter.ms}ms cannot exceed the ${check.maxQueryMs}ms the whole lookup took`).toBeLessThanOrEqual(check.maxQueryMs);
    }
  }

  expect.soft(shown.state, `${where}: should show ${want.state === 'table' ? 'a table of records' : want.state === 'error' ? 'an error' : 'a "no records" note'}`).toBe(want.state);
  if (want.state !== 'table') {
    if (want.note === null) expect.soft(shown.note.trim(), `${where}: a failed request must show an error text`).not.toBe('');
    else expect.soft(shown.note, `${where}: ${want.state === 'error' ? 'error text' : '"no records" text'}`).toBe(want.note);
    expect.soft(shown.rows.length, `${where}: no record rows`).toBe(0);
    return;
  }

  expect.soft(shown.tableName, `${where}: accessible name of the table`).toBe(`${want.type} records`);
  expect.soft(shown.headers, `${where}: column headers`).toEqual(want.headers);
  expect.soft(shown.rows.length, `${where}: number of rows`).toBe(want.rows.length);
  want.rows.forEach((row, r) => {
    const got = shown.rows[r];
    if (!got) return;
    const what = `${where}: record ${r + 1} of ${want.rows.length} (${JSON.stringify(row[0].text.slice(0, 60))})`;
    expect.soft(got.length, `${what}: number of cells`).toBe(row.length);
    row.forEach((cell, c) => {
      const header = want.headers[c];
      if (!got[c]) return;
      if (header === 'TTL' && check.skipTtl) return;
      expect.soft(got[c].text, `${what}: ${header}`).toBe(cell.text);
      if (cell.title !== undefined) expect.soft(got[c].title, `${what}: ${header} tooltip`).toBe(cell.title);
      expect.soft(got[c].label, `${what}: ${header} cell label (used by the mobile layout)`).toBe(header);
    });
  });
}

/** Compares the summary cards, the timestamp, the banner and every section. */
export function expectViewMatches(shown: ShownView, want: ExpectedView, check: ViewCheck): void {
  const { ctx } = check;
  expect.soft(shown.cards.map(card => card.label), `${ctx}: summary cards`).toEqual(CARD_LABELS);
  const card = (label: string) => shown.cards.find(c => c.label === label);
  expect.soft(card('Domain')?.value, `${ctx}: Domain card`).toBe(want.domain);
  expect.soft(card('Records Found')?.value, `${ctx}: Records Found card`).toBe(String(want.totalRecords));
  expect.soft(card('DNS Provider')?.value, `${ctx}: DNS Provider card`).toBe(want.dnsProvider.name);
  expect.soft(card('DNS Provider')?.meta, `${ctx}: DNS Provider confidence and source`).toBe(providerMeta(want.dnsProvider, 'dns'));
  expect.soft(card('Hosting / Edge')?.value, `${ctx}: Hosting / Edge card`).toBe(want.hostingProvider.name);
  expect.soft(card('Hosting / Edge')?.meta, `${ctx}: Hosting / Edge confidence and source`).toBe(providerMeta(want.hostingProvider, 'hosting'));
  expect.soft(card('Resolver')?.value, `${ctx}: Resolver card`).toBe(want.resolverName);

  if (check.stamps) {
    expect.soft(check.stamps, `${ctx}: "Checked At" shows "${shown.checkedAt}", expected one of ${check.stamps.join(' | ')}`).toContain(shown.checkedAt);
  }

  if (want.nothingFound) {
    expect.soft((shown.nothingFoundBanner ?? '').trim(), `${ctx}: banner when no type returned a record`).toBe('No DNS records were returned for the selected record types.');
  } else {
    expect.soft(shown.nothingFoundBanner, `${ctx}: no "nothing returned" banner when a type has records or failed`).toBeNull();
  }

  expect.soft(shown.sections.map(s => s.heading), `${ctx}: result sections and their order`).toEqual(want.sections.map(s => `${s.type} Records`));
  const total = shown.sections.reduce((sum, section) => sum + (parseCounter(section.counter)?.found ?? 0), 0);
  expect.soft(total, `${ctx}: Records Found card (${card('Records Found')?.value}) equals the sum of the section counters`).toBe(Number(card('Records Found')?.value));
  want.sections.forEach((section, i) => expectSection(shown.sections[i], section, check, i));
}

/** No record value, message or name may be interpreted as HTML. */
export async function expectNoMarkupExecuted(page: Page, ctx: string): Promise<void> {
  const found = await page.evaluate(flag => ({
    flag: (window as unknown as Record<string, unknown>)[flag],
    injected: document.querySelectorAll('img[src="x"], svg[onload], main script, main b').length,
  }), XSS_FLAG);
  expect.soft(found.flag, `${ctx}: markup in a DNS answer was executed (window.${XSS_FLAG} is set)`).toBeUndefined();
  expect.soft(found.injected, `${ctx}: markup in a DNS answer was inserted as elements instead of text`).toBe(0);
}

/** Compares an exported CSV with the expected header and rows, cell by cell. */
export function expectCsvMatches(text: string, header: string[], rows: string[][], ctx: string): void {
  const parsed = parseCsv(text);
  expect.soft(parsed[0], `${ctx}: CSV header`).toEqual(header);
  const data = parsed.slice(1);
  expect.soft(data.length, `${ctx}: number of CSV data rows`).toBe(rows.length);
  rows.forEach((row, r) => {
    if (!data[r]) return;
    row.forEach((cell, c) => {
      expect.soft(data[r][c], `${ctx}: CSV row ${r + 1} (${row.slice(0, 4).join(' | ').slice(0, 80)}), column "${header[c]}"`).toBe(cell);
    });
    expect.soft(data[r].length, `${ctx}: CSV row ${r + 1} has one cell per column`).toBe(header.length);
  });
}

// ─── Downloaded HTML report ───

export interface ReportSection { heading: string; counter: string; note: string | null; headers: string[]; rows: string[][] }

export interface ShownReport {
  title: string;
  h1: string;
  subtitle: string;
  timestamp: string;
  cards: { label: string; value: string; meta: string }[];
  sections: ReportSection[];
  footer: string;
  flag: unknown;
  injected: number;
}

/** Opens a downloaded report in a fresh tab of the same browser context and reads it. */
export async function readHtmlReport(page: Page, html: string): Promise<ShownReport> {
  const tab = await page.context().newPage();
  try {
    await tab.setContent(html, { waitUntil: 'load' });
    return await tab.evaluate((flag): ShownReport => {
      const text = (el: Element | null | undefined) => (el ? el.textContent ?? '' : '');
      return {
        title: document.title,
        h1: text(document.querySelector('h1')),
        subtitle: text(document.querySelector('.subtitle')),
        timestamp: text(document.querySelector('.timestamp')),
        cards: Array.from(document.querySelectorAll('.card')).map(card => ({
          label: text(card.querySelector('.card-label')), value: text(card.querySelector('.card-val')), meta: text(card.querySelector('.card-meta')),
        })),
        sections: Array.from(document.querySelectorAll('.section')).map(section => {
          const header = section.querySelector('.section-header') as HTMLElement;
          const empty = section.querySelector('.empty');
          return {
            heading: Array.from(header.childNodes).filter(n => n.nodeType === Node.TEXT_NODE).map(n => n.nodeValue).join('').trim(),
            counter: text(header.querySelector('.section-meta')),
            note: empty ? text(empty) : null,
            headers: Array.from(section.querySelectorAll('thead th')).map(th => text(th)),
            rows: Array.from(section.querySelectorAll('tbody tr')).map(tr => Array.from(tr.querySelectorAll('td')).map(td => text(td))),
          };
        }),
        footer: text(document.querySelector('.footer')),
        flag: (window as unknown as Record<string, unknown>)[flag],
        injected: document.querySelectorAll('img, svg, script, b').length,
      };
    }, XSS_FLAG);
  } finally {
    await tab.close();
  }
}

export interface ReportCheck {
  ctx: string;
  /** Acceptable "Checked At" texts: the one the page showed, or every second of a time window. */
  stamps: string[];
  /** Section counters the page showed ("<n> found · <t>ms"), in order, to compare query times. */
  pageCounters?: string[];
  skipTtl?: boolean;
}

/** Compares a downloaded HTML report with the expected view, field by field. */
export function expectReportMatches(report: ShownReport, want: ExpectedView, check: ReportCheck): void {
  const { ctx } = check;
  expect.soft(report.title, `${ctx}: report <title>`).toBe(`DNS Snapshot Report - ${want.domain}`);
  expect.soft(report.h1, `${ctx}: report heading`).toBe('DNS Snapshot Report');
  expect.soft(report.subtitle, `${ctx}: report subtitle`).toBe(`${want.domain} - Resolver ${want.resolverName}`);
  expect.soft(check.stamps.map(stamp => `Checked At: ${stamp}`), `${ctx}: report shows "${report.timestamp}", expected "Checked At: " + one of ${check.stamps.join(' | ')}`).toContain(report.timestamp);
  expect.soft(report.cards, `${ctx}: report summary cards`).toEqual([
    { label: 'Domain', value: want.domain, meta: '' },
    { label: 'Records Found', value: String(want.totalRecords), meta: '' },
    { label: 'DNS Provider', value: want.dnsProvider.name, meta: providerMeta(want.dnsProvider, 'dns', ' - ') },
    { label: 'Hosting / Edge', value: want.hostingProvider.name, meta: providerMeta(want.hostingProvider, 'hosting', ' - ') },
    { label: 'Resolver', value: want.resolverName, meta: '' },
  ]);
  expect.soft(report.sections.map(s => s.heading), `${ctx}: report sections and their order`).toEqual(want.sections.map(s => `${s.type} Records`));

  want.sections.forEach((section, i) => {
    const got = report.sections[i];
    if (!got) return;
    const where = `${ctx}: report section ${i + 1} (${section.type})`;
    const counter = got.counter.match(/^(\d+) found - (\d+)ms$/);
    expect.soft(counter, `${where}: counter "${got.counter}" should read "<n> found - <t>ms"`).not.toBeNull();
    if (counter) {
      expect.soft(Number(counter[1]), `${where}: number of records`).toBe(section.count);
      const onPage = check.pageCounters?.[i]?.match(/(\d+)ms$/);
      if (onPage) expect.soft(Number(counter[2]), `${where}: query time equals the page's`).toBe(Number(onPage[1]));
      if (section.queryMs !== undefined) expect.soft(Number(counter[2]), `${where}: query time`).toBe(section.queryMs);
    }
    if (section.state !== 'table') {
      if (section.note === null) expect.soft((got.note ?? '').trim(), `${where}: error text`).not.toBe('');
      else expect.soft(got.note, `${where}: ${section.state === 'error' ? 'error text' : '"no records" text'}`).toBe(section.note);
      expect.soft(got.rows.length, `${where}: no record rows`).toBe(0);
      return;
    }
    expect.soft(got.note, `${where}: no "empty" note when there are records`).toBeNull();
    expect.soft(got.headers, `${where}: column headers`).toEqual(section.headers);
    expect.soft(got.rows.length, `${where}: number of rows`).toBe(section.rows.length);
    section.rows.forEach((row, r) => {
      if (!got.rows[r]) return;
      const what = `${where}: record ${r + 1} (${JSON.stringify(row[0].text.slice(0, 60))})`;
      row.forEach((cell, c) => {
        const header = section.headers[c];
        if (header === 'TTL' && check.skipTtl) return;
        // The report leaves Location blank where the page shows a dash.
        const text = header === 'Location' && cell.text === '—' ? '' : cell.text;
        expect.soft(got.rows[r][c], `${what}: ${header}`).toBe(text);
      });
    });
  });

  expect.soft(report.footer, `${ctx}: report footer`).toBe('Generated offline from a DNS snapshot - Timestamp shown in UTC');
  expect.soft(report.flag, `${ctx}: markup in a DNS answer was executed inside the report`).toBeUndefined();
  expect.soft(report.injected, `${ctx}: markup in a DNS answer became elements inside the report`).toBe(0);
}

// ─── Running a lookup and checking the whole result ───

export function describeLookup(lookup: Lookup): string {
  return `lookup of "${lookup.domain}" (${lookup.types.join(', ')}) via ${lookup.resolver}`;
}

/** The page must send exactly one request per selected type, each with the domain, type and resolver chosen. */
export function expectRequestsMatch(calls: DnsCall[], lookup: Lookup, ctx = describeLookup(lookup)): void {
  const sent = calls.map(call => call.body).sort((a, b) => String(a.type).localeCompare(String(b.type)));
  const wanted = [...lookup.types].sort().map(type => ({ domain: lookup.domain, type, resolver: lookup.resolver }));
  expect.soft(sent, `${ctx}: request bodies sent to POST /api/dns (one per selected type)`).toEqual(wanted);
}

/**
 * Submits `lookup` like a user, waits for the result and compares everything
 * on screen with the oracle. Returns both sides for further checks.
 */
export async function runAndCheck(
  dns: DnsPage,
  lookup: Lookup,
  geo: GeoOracle | null,
  evidence: Evidence,
  options: { typed?: string; via?: 'button' | 'enter'; label?: string } = {},
): Promise<{ want: ExpectedView; shown: ShownView; ctx: string }> {
  const ctx = options.label ?? describeLookup(lookup);
  await evidence.save(`lookup-${lookup.domain}.json`, lookup);
  const before = Date.now();
  await dns.run(lookup, options);
  const after = Date.now();
  const shown = await dns.view();
  const want = expectedView(lookup, geo);
  expectViewMatches(shown, want, { ctx, stamps: utcStampsBetween(before - 1000, after + 1000), maxQueryMs: after - before + 250 });
  return { want, shown, ctx };
}
