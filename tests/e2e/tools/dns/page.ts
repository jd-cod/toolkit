import type { Browser, Locator, Route } from '@playwright/test';
import { expect, type Page } from '../_support/fixtures';
import { openTool } from '../_support/navigation';
import type { ApiCall } from '../_support/io';
import { OFFERED_TYPES, TIMEZONE, type Lookup, type Reply } from './oracle';

/**
 * Selectors, user actions and readers for the DNS Lookup page (/dns) and for
 * the DNS part of the shared-view page (/s/<code>). Readers return plain data.
 */

export const ROUTE = '/dns';
export const HEADING = 'DNS Lookup';

// ─── What the page shows, as data ───

export interface ShownCell { text: string; title: string | null; label: string | null }

export interface ShownSection {
  /** Heading without the counter, e.g. "MX Records". */
  heading: string;
  /** The counter next to the heading, e.g. "4 found · 66ms". */
  counter: string;
  state: 'table' | 'empty' | 'error';
  /** Text of the error or "no records" line; '' for a table. */
  note: string;
  tableName: string | null;
  headers: string[];
  rows: ShownCell[][];
}

export interface ShownCard { label: string; value: string; meta: string }

export interface ShownView {
  cards: ShownCard[];
  checkedAt: string | null;
  nothingFoundBanner: string | null;
  sections: ShownSection[];
}

/** Reads the summary cards, the timestamp and every record section inside `scope`. */
export async function readView(scope: Locator): Promise<ShownView> {
  return scope.evaluate((root): ShownView => {
    const text = (el: Element | null | undefined) => (el ? el.textContent ?? '' : '');
    const cards = Array.from(root.querySelectorAll('.stat-card')).map(card => {
      const value = card.querySelector('.stat-value');
      const label = card.querySelector('.stat-label');
      const meta = Array.from(card.querySelector('.card-body')?.children ?? []).find(child => child !== value && child !== label);
      return { label: text(label), value: text(value), meta: text(meta) };
    });

    const stampLabel = Array.from(root.querySelectorAll('strong')).find(el => text(el).trim() === 'Checked At:');
    const checkedAt = stampLabel ? text(stampLabel.nextElementSibling) : null;

    const tableCards = Array.from(root.querySelectorAll('.table-card'));
    const banner = tableCards.find(card => !card.querySelector('.table-card-header'));
    const sections = tableCards.filter(card => card.querySelector('.table-card-header')).map(card => {
      const title = card.querySelector('h5') as HTMLElement;
      const counter = title.querySelector('span');
      const heading = Array.from(title.childNodes).filter(node => node.nodeType === Node.TEXT_NODE).map(node => node.nodeValue).join('');
      const table = card.querySelector('table');
      const body = card.querySelector('.table-card-header')?.nextElementSibling ?? null;
      const isError = !table && !!body?.querySelector('i.bi-x-circle');
      return {
        heading,
        counter: text(counter),
        state: table ? 'table' as const : isError ? 'error' as const : 'empty' as const,
        note: table ? '' : text(body),
        tableName: table ? table.getAttribute('aria-label') : null,
        headers: table ? Array.from(table.querySelectorAll('thead th')).map(th => text(th)) : [],
        rows: table
          ? Array.from(table.querySelectorAll('tbody tr')).map(tr => Array.from(tr.querySelectorAll('td')).map(td => ({
            text: text(td), title: td.getAttribute('title'), label: td.getAttribute('data-label'),
          })))
          : [],
      };
    });

    return { cards, checkedAt, nothingFoundBanner: banner ? text(banner) : null, sections };
  });
}

export interface ShownGlobalRow { region: string; status: string; lines: string[] }

// ─── Fake backend for POST /api/dns ───

export interface DnsCall extends ApiCall {
  body: { domain?: string; type?: string; resolver?: string };
}

export interface ReplyControl {
  reply: Reply;
  /** Resolve to let the answer through; use to hold the page in its loading state. */
  hold?: Promise<unknown>;
}

/**
 * Answers `POST /api/dns` per request and records what the page sent.
 * `mockApi` gives one status and one delay for every request; a lookup sends
 * one request per record type and the tests need them to differ (one type
 * fails, one lookup is slower than the next), hence this variant.
 */
export async function routeDns(page: Page, decide: (call: DnsCall) => Reply | ReplyControl): Promise<DnsCall[]> {
  const calls: DnsCall[] = [];
  await page.route('**/api/dns', async (route: Route) => {
    const request = route.request();
    if (request.method() !== 'POST') return route.fallback();
    let body: DnsCall['body'] = {};
    try { body = JSON.parse(request.postData() ?? '{}'); } catch { /* recorded as empty */ }
    const call: DnsCall = { method: 'POST', url: request.url(), body };
    calls.push(call);
    const decided = decide(call);
    const control: ReplyControl = 'reply' in decided ? decided : { reply: decided };
    if (control.hold) await control.hold;
    const reply = control.reply;
    try {
      if (reply.kind === 'network') return await route.abort('failed');
      const status = reply.kind === 'http' ? reply.status : 200;
      const raw = typeof reply.body === 'string';
      await route.fulfill({
        status,
        contentType: raw ? 'text/html' : 'application/json',
        body: raw ? (reply.body as string) : JSON.stringify(reply.body),
      });
    } catch {
      // The page was closed while the answer was held back.
    }
  });
  return calls;
}

/** Serves the prepared answers of one or more lookups, chosen by domain and type. */
export async function serveLookups(page: Page, ...lookups: Lookup[]): Promise<DnsCall[]> {
  return routeDns(page, call => {
    const lookup = lookups.find(candidate => candidate.domain === call.body.domain) ?? lookups[0];
    return lookup.replies[String(call.body.type)]
      ?? { kind: 'http', status: 599, body: { error: `test has no answer prepared for type ${call.body.type}` } };
  });
}

/** A promise the test resolves itself, to release a held answer. */
export function gate(): { promise: Promise<void>; open: () => void } {
  let open!: () => void;
  const promise = new Promise<void>(resolve => { open = resolve; });
  return { promise, open };
}

// ─── Page object ───

export class DnsPage {
  readonly page: Page;
  readonly main: Locator;
  readonly domain: Locator;
  readonly lookupButton: Locator;
  readonly resolver: Locator;
  readonly alert: Locator;
  readonly standardMode: Locator;
  readonly globalMode: Locator;
  readonly checkedAt: Locator;
  readonly sectionCards: Locator;
  readonly recordTables: Locator;
  readonly shareButton: Locator;
  readonly downloadHtmlButton: Locator;
  readonly exportCsvButton: Locator;
  readonly copyAllButton: Locator;
  readonly globalPanel: Locator;
  readonly shareGlobalButton: Locator;
  readonly share: ShareDialog;

  constructor(page: Page) {
    this.page = page;
    this.main = page.locator('main');
    this.domain = page.locator('#dns-domain');
    // The button reads "Lookup" when idle and "Querying..." while a lookup runs.
    this.lookupButton = page.locator('.signal-query-row button');
    this.resolver = page.locator('#dns-resolver');
    this.alert = this.main.getByRole('alert');
    this.standardMode = page.getByRole('button', { name: 'Standard Query' });
    this.globalMode = page.getByRole('button', { name: 'Global Propagation' });
    this.checkedAt = this.main.locator('strong', { hasText: 'Checked At:' }).locator('xpath=following-sibling::span[1]');
    this.sectionCards = this.main.locator('.table-card:has(.table-card-header)');
    this.recordTables = this.main.locator('table.signal-dns-record-table');
    this.shareButton = page.getByRole('button', { name: 'Share DNS Snapshot' });
    this.downloadHtmlButton = this.main.getByRole('button', { name: /^(Download HTML|Downloaded!)$/ });
    this.exportCsvButton = this.main.getByRole('button', { name: 'Export CSV' });
    this.copyAllButton = this.main.getByRole('button', { name: /^(Copy All Records|Copied!)$/ });
    this.globalPanel = this.main.locator('.input-card', { has: page.getByRole('heading', { name: 'Global DNS Propagation' }) });
    this.shareGlobalButton = page.getByRole('button', { name: 'Share Global Snapshot' });
    this.share = new ShareDialog(page);
  }

  async open(query = ''): Promise<void> {
    await openTool(this.page, `${ROUTE}${query}`, HEADING);
  }

  typeBox(type: string): Locator {
    return this.page.locator('.signal-query-panel').getByRole('checkbox', { name: type, exact: true });
  }

  /** Ticks exactly `types` (Standard Query mode, where the boxes are independent). */
  async selectTypes(types: readonly string[]): Promise<void> {
    for (const type of OFFERED_TYPES) await this.typeBox(type).setChecked(types.includes(type));
  }

  async checkedTypes(): Promise<string[]> {
    const out: string[] = [];
    for (const type of OFFERED_TYPES) if (await this.typeBox(type).isChecked()) out.push(type);
    return out;
  }

  /** Fills the form the way a user would and submits with the button or the Enter key. */
  async submit(typed: string, options: { types?: readonly string[]; resolver?: string; via?: 'button' | 'enter' } = {}): Promise<void> {
    if (options.types) await this.selectTypes(options.types);
    if (options.resolver) await this.resolver.selectOption(options.resolver);
    await this.domain.fill(typed);
    if (options.via === 'enter') await this.domain.press('Enter');
    else await this.lookupButton.click();
  }

  /** Submits a prepared lookup and waits until its result (or failure) is on screen. */
  async run(lookup: Lookup, options: { typed?: string; via?: 'button' | 'enter' } = {}): Promise<void> {
    await this.submit(options.typed ?? lookup.domain, { types: lookup.types, resolver: lookup.resolver, via: options.via });
    await this.waitForResult();
  }

  async waitForResult(): Promise<void> {
    await expect(this.checkedAt, 'the result area should appear after the lookup').toBeVisible({ timeout: 45_000 });
    await expect(this.lookupButton, 'the Lookup button should be idle again').toHaveText('Lookup');
  }

  view(): Promise<ShownView> {
    return readView(this.main);
  }

  /** The "Query details" list in the side panel, as {term: description}. */
  async queryDetails(): Promise<Record<string, string>> {
    return this.page.locator('aside[aria-label="DNS reference"] section').first().evaluate(section => {
      const out: Record<string, string> = {};
      section.querySelectorAll('dt').forEach(dt => { out[dt.textContent ?? ''] = dt.nextElementSibling?.textContent ?? ''; });
      return out;
    });
  }

  investigateLink(name: 'SSL Certificate Checker' | 'WHOIS Lookup'): Locator {
    return this.page.locator('aside[aria-label="DNS reference"]').getByRole('link', { name });
  }

  /** Rows of the "Global DNS Propagation" table. */
  async globalRows(): Promise<ShownGlobalRow[]> {
    return this.globalPanel.locator('tbody tr').evaluateAll(rows => rows.map(row => {
      const cells = row.querySelectorAll('td');
      const lines = Array.from(cells[2].querySelectorAll(':scope > div')).map(div => div.textContent ?? '');
      return {
        region: (cells[0].textContent ?? '').trim(),
        status: (cells[1].textContent ?? '').trim(),
        lines: lines.length ? lines : [cells[2].textContent ?? ''],
      };
    }));
  }
}

/** The "Share DNS Snapshot" dialog. It is rendered after the footer, outside <main>. */
export class ShareDialog {
  readonly page: Page;
  readonly heading: Locator;
  readonly panel: Locator;
  readonly backdrop: Locator;
  readonly closeButton: Locator;
  readonly title: Locator;
  readonly expiry: Locator;
  readonly password: Locator;
  readonly checkedAt: Locator;
  readonly generate: Locator;
  readonly error: Locator;
  readonly created: Locator;
  readonly link: Locator;
  readonly copyLink: Locator;
  readonly createAnother: Locator;
  readonly creating: Locator;

  constructor(page: Page) {
    this.page = page;
    this.heading = page.getByRole('heading', { name: 'Share DNS Snapshot', level: 3 });
    // heading → title row → header row → panel → backdrop
    this.panel = this.heading.locator('xpath=ancestor::div[3]');
    this.backdrop = this.heading.locator('xpath=ancestor::div[4]');
    this.closeButton = this.panel.locator('button:has(i.bi-x-lg)');
    this.title = this.panel.locator('input:not([type="password"])');
    this.expiry = this.panel.locator('select');
    this.password = this.panel.locator('input[type="password"]');
    this.checkedAt = this.panel.locator('strong', { hasText: 'Checked At:' }).locator('xpath=following-sibling::span[1]');
    this.generate = this.panel.getByRole('button', { name: 'Generate Share Link' });
    this.error = this.generate.locator('xpath=preceding-sibling::div[1][not(.//input) and not(.//select) and not(.//strong)]');
    this.created = this.panel.getByText('Share link created!');
    this.link = this.panel.locator('span', { hasText: /\/s\/[A-Za-z0-9]+$/ });
    // By text, not by accessible name: the icon inside is not hidden from assistive technology and its glyph becomes part of the name.
    this.copyLink = this.panel.locator('button', { hasText: /^(Copy|Copied!)$/ });
    this.createAnother = this.panel.getByRole('button', { name: 'Create Another Link' });
    this.creating = this.panel.getByText('Creating share link...');
  }

  /**
   * Fills the dialog, creates the link and returns the code with the request
   * body the page sent to POST /api/share/dns.
   */
  async create(options: { title?: string; expiry?: string; password?: string } = {}): Promise<{ code: string; url: string; request: Record<string, unknown> }> {
    if (options.title !== undefined) await this.title.fill(options.title);
    if (options.expiry !== undefined) await this.expiry.selectOption(options.expiry);
    if (options.password !== undefined) await this.password.fill(options.password);
    const [response] = await Promise.all([
      this.page.waitForResponse(res => res.url().endsWith('/api/share/dns') && res.request().method() === 'POST'),
      this.generate.click(),
    ]);
    expect(response.status(), 'POST /api/share/dns should succeed').toBe(200);
    const body = await response.json() as { code: string };
    await expect(this.created, 'the dialog should confirm the new link').toBeVisible();
    const url = (await this.link.textContent()) ?? '';
    return { code: body.code, url, request: response.request().postDataJSON() as Record<string, unknown> };
  }
}

/** The shared-view page /s/<code> for a DNS snapshot. */
export class SharedPage {
  readonly page: Page;
  readonly main: Locator;
  readonly title: Locator;
  readonly dates: Locator;
  readonly lockHeading: Locator;
  readonly password: Locator;
  readonly unlock: Locator;
  readonly error: Locator;
  readonly banner: Locator;
  readonly checkedAt: Locator;
  readonly rerunButton: Locator;
  readonly downloadHtmlButton: Locator;
  readonly exportCsvButton: Locator;
  readonly copyAllButton: Locator;
  readonly openLiveLink: Locator;
  readonly newLookupLink: Locator;

  constructor(page: Page) {
    this.page = page;
    this.main = page.locator('main');
    this.title = this.main.getByRole('heading', { level: 1 });
    this.dates = this.main.locator('p', { hasText: /^Created:/ });
    this.lockHeading = this.main.getByRole('heading', { name: 'Password Protected' });
    this.password = this.main.getByPlaceholder('Enter password');
    this.unlock = this.main.getByRole('button', { name: 'Unlock' });
    this.error = this.main.locator('div.glass', { hasText: /^⚠️/ });
    this.banner = this.main.locator('span', { hasText: /^You are viewing/ });
    this.checkedAt = this.main.locator('strong', { hasText: 'Checked At:' }).locator('xpath=following-sibling::span[1]');
    this.rerunButton = this.main.getByRole('button', { name: 'Re-run DNS Lookup Now' });
    this.downloadHtmlButton = this.main.getByRole('button', { name: /^(Download HTML|Downloaded!)$/ });
    this.exportCsvButton = this.main.getByRole('button', { name: 'Export CSV' });
    this.copyAllButton = this.main.getByRole('button', { name: /^(Copy All Records|Copied!)$/ });
    this.openLiveLink = this.main.getByRole('link', { name: 'Open Live Lookup' });
    this.newLookupLink = this.main.getByRole('link', { name: 'New DNS Lookup' });
  }

  async open(code: string): Promise<void> {
    const response = await this.page.goto(`/s/${code}`, { waitUntil: 'domcontentloaded' });
    expect(response?.status(), `/s/${code} should answer 200`).toBe(200);
  }

  async waitForSnapshot(): Promise<void> {
    await expect(this.checkedAt, 'the shared snapshot should be shown').toBeVisible({ timeout: 30_000 });
  }

  view(): Promise<ShownView> {
    return readView(this.main);
  }
}

// ─── A second visitor ───

export interface Visitor {
  page: Page;
  /** Page errors, console errors and HTTP 5xx seen by this visitor that no `allow` pattern covers. */
  problems(): string[];
  close(): Promise<void>;
}

/**
 * Opens a new browser context: a different person, with no cookies, storage
 * or cache in common with the test's own page. Shared links must work there.
 * The `guard` fixture only watches the test's own page, so this watches the
 * visitor's page the same way.
 */
export async function openVisitor(
  browser: Browser,
  baseURL: string,
  options: { viewport?: { width: number; height: number }; allow?: RegExp[] } = {},
): Promise<Visitor> {
  const context = await browser.newContext({
    baseURL,
    viewport: options.viewport ?? { width: 1440, height: 1080 },
    timezoneId: TIMEZONE,
    locale: 'en-US',
    permissions: ['clipboard-read', 'clipboard-write'],
    acceptDownloads: true,
  });
  const page = await context.newPage();
  const seen: string[] = [];
  const allowed = [/net::ERR_ABORTED/i, ...(options.allow ?? [])];
  const record = (text: string) => { if (!allowed.some(re => re.test(text))) seen.push(text); };
  page.on('pageerror', err => record(`uncaught exception: ${err.message}`));
  page.on('console', msg => { if (msg.type() === 'error') record(`console.error: ${msg.text()}`); });
  page.on('requestfailed', req => record(`request failed: ${req.method()} ${req.url()} — ${req.failure()?.errorText || 'unknown'}`));
  page.on('response', res => { if (res.status() >= 500) record(`HTTP ${res.status()}: ${res.request().method()} ${res.url()}`); });
  return { page, problems: () => [...seen], close: () => context.close() };
}
