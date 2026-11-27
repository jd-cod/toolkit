import { expect, type Locator, type Page, type Route } from '@playwright/test';
import { openTool } from '../_support/navigation';
import type { ApiCall } from '../_support/io';
import type { RuleAction, RuleFormat } from './oracle';

/**
 * Selectors and user actions for the ASN tool and for its snapshot view.
 *
 * The snapshot view (frontend/src/components/AsnSnapshotView.tsx) is rendered
 * on `/asn` after a lookup and on `/s/<code>` for a shared snapshot, so every
 * reader takes the region it lives in (`scope`). The markup has no ids or
 * classes of its own; elements are found by role, visible text and labels.
 */

export const ROUTE = '/asn';
export const HEADING = 'ASN to IPs Converter & BGP Intelligence';
/** `POST /api/asn` only (not /api/asn/search, /match-ip, /generate-rules). */
export const LOOKUP_API = /\/api\/asn$/;
export const SHARE_API = /\/api\/share\/asn$/;

export const QUICK_ASNS: { label: string; asn: string }[] = [
  { label: 'Cloudflare', asn: '13335' },
  { label: 'Google', asn: '15169' },
  { label: 'Amazon AWS', asn: '16509' },
  { label: 'Microsoft', asn: '8075' },
  { label: 'Hetzner', asn: '24940' },
  { label: 'Fastly', asn: '54113' },
  { label: 'DigitalOcean', asn: '14061' },
  { label: 'OVHcloud', asn: '16276' },
];

export const TABS = {
  // Buttons with an icon carry the icon glyph at the start of their accessible name, so names are matched at the end.
  prefixes: /Prefix Explorer \(\d+\)$/,
  firewall: 'Firewall & ACL Generator',
  tester: 'IP Range Matcher',
  bgp: 'BGP & Network Intel',
} as const;

// ───────────────────────── search card (/asn only) ─────────────────────────

export const primary = (page: Page) => page.locator('.signal-tool-primary');
export const searchInput = (page: Page) => page.getByPlaceholder('e.g. AS13335, 13335, Cloudflare, 1.1.1.1, or google.com');
export const lookupButton = (page: Page) => page.locator('.input-card button.btn-primary');
export const quickChip = (page: Page, asn: string) => page.locator('.input-card').getByRole('button', { name: new RegExp(`\\(AS${asn}\\)$`) });
export const errorBanner = (page: Page) => primary(page).locator('.alert-custom');
export const loadingStatus = (page: Page) => primary(page).getByRole('status');
export const emptyState = (page: Page) => primary(page).getByRole('heading', { name: 'Explore an autonomous system' });
/** The result view is on screen when its tab bar is. */
export const resultTab = (scope: Locator) => scope.getByRole('button', { name: TABS.prefixes });

export async function openAsn(page: Page): Promise<void> {
  await openTool(page, ROUTE, HEADING);
}

/** Types into the search box and presses the button. Does not wait for the answer. */
export async function submitLookup(page: Page, text: string): Promise<void> {
  await searchInput(page).fill(text);
  await lookupButton(page).click();
}

/** Looks a network up and waits until its result (badge `AS<asn>`) is shown. */
export async function lookup(page: Page, text: string, asn: string): Promise<AsnView> {
  await submitLookup(page, text);
  const view = new AsnView(page, primary(page));
  await expect(view.badge(), `result for "${text}" should appear`).toHaveText(`AS${asn}`);
  return view;
}

export interface Gate {
  calls: ApiCall[];
  /** Lets the held request number `index` (0-based) be answered; without an index, all of them. */
  release(index?: number): void;
  /** Resolves when request number `index` has been answered. */
  answered(index: number): Promise<void>;
}

/**
 * Answers matching requests only when the test says so. Lets a test look at
 * the loading state for as long as it needs, and decide the order in which
 * two overlapping requests are answered, without sleeping.
 */
export async function gateApi(
  page: Page,
  url: string | RegExp,
  payload: (call: ApiCall, index: number) => { status?: number; body: unknown; contentType?: string },
): Promise<Gate> {
  const calls: ApiCall[] = [];
  const gates: { open: () => void; done: Promise<void> }[] = [];
  let openAll = false;
  await page.route(url, async (route: Route) => {
    const raw = route.request().postData();
    let body: unknown = raw;
    try { body = raw == null ? null : JSON.parse(raw); } catch { /* keep text */ }
    const call: ApiCall = { method: route.request().method(), url: route.request().url(), body };
    const index = calls.push(call) - 1;
    let open!: () => void;
    const opened = new Promise<void>(resolve => { open = resolve; });
    let finish!: () => void;
    const done = new Promise<void>(resolve => { finish = resolve; });
    gates[index] = { open, done };
    if (!openAll) await opened;
    const answer = payload(call, index);
    await route.fulfill({
      status: answer.status ?? 200,
      contentType: answer.contentType ?? 'application/json',
      body: typeof answer.body === 'string' ? answer.body : JSON.stringify(answer.body),
    }).catch(() => undefined);
    finish();
  });
  return {
    calls,
    release: index => {
      if (index === undefined) { openAll = true; gates.forEach(g => g.open()); } else gates[index]?.open();
    },
    answered: async index => {
      await expect.poll(() => gates.length, { message: `request ${index + 1} should have been sent` }).toBeGreaterThan(index);
      await gates[index].done;
    },
  };
}

// ───────────────────────── snapshot view ─────────────────────────

export interface HeaderFacts {
  badge: string;
  title: string;
  country: string | null;
  registry: string | null;
  status: string;
  description: string | null;
  resolvedFrom: string | null;
}

export interface TableRow {
  number: string;
  prefix: string;
  range: string;
  count: string;
  netmask: string;
  wildcard: string;
}

export interface MatchResult {
  text: string;
  matched: boolean;
  prefix: string | null;
  range: string | null;
  netmask: string | null;
  total: string | null;
}

export class AsnView {
  constructor(readonly page: Page, readonly scope: Locator) {}

  // Header ─────────────────────────────────────────────────────────────
  heading(): Locator { return this.scope.locator('h2').first(); }
  /** The `AS<number>` badge left of the network name. */
  badge(): Locator { return this.heading().locator('xpath=preceding-sibling::span[1]'); }
  tab(name: keyof typeof TABS): Locator { return this.scope.getByRole('button', { name: TABS[name] }); }
  shareButton(): Locator { return this.scope.getByRole('button', { name: 'Share Snapshot' }); }
  rerunButton(): Locator { return this.scope.getByRole('button', { name: 'Run Live Lookup' }); }
  copySummaryButton(): Locator { return this.scope.getByRole('button', { name: /(Copy Summary|Copied!)$/ }); }
  exportButton(): Locator { return this.scope.getByRole('button', { name: /Export$/ }); }
  footer(): Locator { return this.scope.getByText(/^Data Source: /); }
  shareCode(): Locator { return this.scope.getByText(/^Share Code:/); }

  async readHeader(): Promise<HeaderFacts> {
    return this.heading().evaluate((h2: HTMLElement) => {
      const clean = (el: Element | null | undefined) => (el?.textContent || '').replace(/\s+/g, ' ').trim();
      const row = h2.parentElement as HTMLElement;
      const chips = Array.from(row.children).filter(el => el.tagName === 'SPAN');
      const badge = chips.shift();
      const country = chips.find(el => el.querySelector('.bi-geo-alt-fill'));
      const status = chips.find(el => /^[●○]/.test(clean(el)));
      const registry = chips.find(el => el !== country && el !== status);
      const block = row.parentElement as HTMLElement;
      const description = Array.from(block.children).find(el => el.tagName === 'P');
      const resolved = block.querySelector('.bi-arrow-return-right')?.parentElement;
      return {
        badge: clean(badge),
        title: clean(h2),
        country: country ? clean(country) : null,
        registry: registry ? clean(registry) : null,
        status: clean(status),
        description: description ? clean(description) : null,
        resolvedFrom: resolved ? clean(resolved) : null,
      };
    });
  }

  /** The four summary cards: caption → big value and the line under it. */
  async readCards(): Promise<Record<string, { value: string; sub: string }>> {
    return this.scope.evaluate((root: HTMLElement) => {
      const clean = (el: Element | null | undefined) => (el?.textContent || '').replace(/\s+/g, ' ').trim();
      const out: Record<string, { value: string; sub: string }> = {};
      for (const caption of ['IPv4 Prefixes', 'IPv6 Prefixes', 'CIDR Optimization', 'BGP Connectivity']) {
        const label = Array.from(root.querySelectorAll('div')).find(el => clean(el) === caption && el.querySelector(':scope > i.bi'));
        const card = label?.parentElement;
        if (card) out[caption] = { value: clean(card.children[1]), sub: clean(card.children[2]) };
      }
      return out;
    });
  }

  // Prefix explorer ─────────────────────────────────────────────────────
  filterInput(): Locator { return this.scope.getByPlaceholder('Filter prefixes by CIDR, IP range, or netmask...'); }
  versionButton(version: 'all' | 'ipv4' | 'ipv6'): Locator { return this.scope.getByRole('button', { name: version, exact: true }); }
  aggregateToggle(): Locator { return this.scope.getByRole('button', { name: /Raw Prefixes|Aggregated Supernets/ }); }
  aggregateBanner(): Locator { return this.scope.getByText(/^Supernet Aggregation Active:/); }
  copyVisibleButton(): Locator { return this.scope.getByRole('button', { name: /(Copy Visible|Copied All!)$/ }); }
  csvButton(): Locator { return this.scope.getByRole('button', { name: /CSV$/ }); }
  table(): Locator { return this.scope.locator('table'); }
  noRowsMessage(): Locator { return this.table().getByText('No prefixes found matching current filters.'); }
  maskChip(length: number): Locator { return this.scope.getByRole('button', { name: new RegExp(`^/${length} \\(\\d+\\)$`) }); }
  allMasksChip(): Locator { return this.scope.getByRole('button', { name: /^All Masks \(\d+\)$/ }); }
  showing(): Locator { return this.scope.getByText(/^Showing \d/); }
  pageLabel(): Locator { return this.scope.getByText(/^Page \d+ of \d+$/); }
  pager(name: 'First' | 'Prev' | 'Next' | 'Last'): Locator { return this.scope.getByRole('button', { name: new RegExp(`^.?\\s*${name}\\s*.?$`) }); }
  rowCopyButton(prefix: string): Locator {
    return this.table().locator('tbody tr').filter({ has: this.page.locator('td:nth-child(2)', { hasText: new RegExp(`^${prefix.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}$`) }) }).locator('button');
  }

  /** Rows of the current table page; empty when the "no prefixes" message is shown. */
  async readRows(): Promise<TableRow[]> {
    return this.table().evaluate((table: HTMLTableElement) => {
      const clean = (el: Element | undefined) => (el?.textContent || '').replace(/\s+/g, ' ').trim();
      return Array.from(table.tBodies[0].rows).filter(row => row.cells.length >= 6).map(row => ({
        number: clean(row.cells[0]), prefix: clean(row.cells[1]), range: clean(row.cells[2]),
        count: clean(row.cells[3]), netmask: clean(row.cells[4]), wildcard: clean(row.cells[5]),
      }));
    });
  }

  async readColumnHeaders(): Promise<string[]> {
    return this.table().locator('thead th').allTextContents();
  }

  /** Labels of the mask chips in display order, e.g. `['All Masks (12)', '/16 (2)', '/24 (10)']`. */
  async readChips(): Promise<string[]> {
    const caption = this.scope.getByText('Subnet Mask Distribution (Click to filter):');
    if (await caption.count() === 0) return [];
    return caption.locator('xpath=following-sibling::div[1]').getByRole('button').allTextContents();
  }

  /** Number in the tab label `Prefix Explorer (n)`. */
  async tabCount(): Promise<number> {
    const label = (await this.tab('prefixes').textContent()) || '';
    return Number((label.match(/\((\d+)\)/) || [])[1]);
  }

  /** Walks every table page from the first to the last and returns all rows. */
  async readAllRows(): Promise<TableRow[]> {
    if (await this.pager('First').count() && await this.pager('First').isEnabled()) await this.pager('First').click();
    const rows = await this.readRows();
    while (await this.pager('Next').count() && await this.pager('Next').isEnabled()) {
      const before = (await this.pageLabel().textContent()) || '';
      await this.pager('Next').click();
      await expect(this.pageLabel()).not.toHaveText(before);
      rows.push(...await this.readRows());
    }
    return rows;
  }

  // Firewall generator ──────────────────────────────────────────────────
  formatSelect(): Locator { return this.scope.locator('select').filter({ has: this.page.locator('option[value="nginx"]') }); }
  scopeSelect(): Locator { return this.scope.locator('select').filter({ has: this.page.locator('option[value="both"]') }); }
  actionButton(action: RuleAction): Locator { return this.scope.getByRole('button', { name: action === 'deny' ? /Blacklist \(Block \/ Deny\)/ : /Whitelist \(Allow \/ Permit\)/ }); }
  mergeCheckbox(): Locator { return this.scope.getByLabel('Merge adjacent CIDRs (Supernetting)'); }
  rulesOutput(): Locator { return this.scope.locator('pre'); }
  linesLabel(): Locator { return this.scope.getByText(/^\d+ lines generated$/); }
  copyRulesButton(): Locator { return this.scope.getByRole('button', { name: /(Copy Rules|Copied Rules!)$/ }); }
  saveFileButton(): Locator { return this.scope.getByRole('button', { name: 'Save File' }); }

  async setRules(options: { format?: RuleFormat; action?: RuleAction; scope?: 'both' | 'ipv4' | 'ipv6'; merge?: boolean }): Promise<void> {
    if (options.format) await this.formatSelect().selectOption(options.format);
    if (options.action) await this.actionButton(options.action).click();
    if (options.scope) await this.scopeSelect().selectOption(options.scope);
    if (options.merge !== undefined) await this.mergeCheckbox().setChecked(options.merge);
  }

  async readRules(): Promise<string> {
    return (await this.rulesOutput().textContent()) || '';
  }

  // IP tester ───────────────────────────────────────────────────────────
  testerInput(): Locator { return this.scope.getByPlaceholder('e.g. 104.28.14.5 or 2606:4700::1'); }
  testerButton(): Locator { return this.scope.getByRole('button', { name: /Test IP$/ }); }
  verdict(): Locator { return this.scope.getByText(/^(MATCH FOUND|NO MATCH):/); }
  private matchField(label: string): Locator {
    return this.scope.locator('div', { hasText: new RegExp(`^${label}$`) }).locator('xpath=following-sibling::div[1]');
  }

  /** Tests one address and returns what the tester reports for it. */
  async testAddress(ip: string): Promise<MatchResult> {
    await this.testerInput().fill(ip);
    await this.testerButton().click();
    // The verdict names the address it is about; wait for this one, not a previous one.
    await expect(this.verdict(), `the tester should report on ${ip}`).toContainText(`IP ${ip.trim()} `);
    const text = ((await this.verdict().textContent()) || '').replace(/\s+/g, ' ').trim();
    const read = async (label: string) => {
      const field = this.matchField(label);
      return await field.count() ? ((await field.first().textContent()) || '').replace(/\s+/g, ' ').trim() : null;
    };
    const matched = text.startsWith('MATCH FOUND');
    return {
      text, matched,
      prefix: matched ? await read('Announced Prefix') : null,
      range: matched ? await read('Subnet Range') : null,
      netmask: matched ? await read('Netmask') : null,
      total: matched ? await read('Total Subnet IPs') : null,
    };
  }

  // BGP tab ─────────────────────────────────────────────────────────────
  /** Big number above one of the three neighbour captions. */
  neighbourCount(caption: 'Upstream Transit ASNs' | 'Downstream Customer ASNs' | 'Direct Peering Relations'): Locator {
    return this.scope.locator('div', { hasText: new RegExp(`^${caption}$`) }).locator('xpath=preceding-sibling::div[1]');
  }
  /** Value under a caption of the "Abuse & Registration Contacts" card. */
  contactField(caption: string): Locator {
    return this.scope.locator('div', { hasText: new RegExp(`^${caption.replace(/[()/]/g, '\\$&')}$`) }).locator('xpath=following-sibling::*[1]');
  }
  inspectButtons(): Locator { return this.scope.getByRole('button', { name: /^Inspect/ }); }

  async readTopPeers(): Promise<{ asn: string; type: string; hasInspect: boolean }[]> {
    const caption = this.scope.getByText('Top Connected Neighbour ASNs:');
    if (await caption.count() === 0) return [];
    return caption.locator('xpath=following-sibling::div[1]').evaluate((grid: HTMLElement) =>
      Array.from(grid.children).map(card => {
        const texts = card.querySelectorAll(':scope > div > div');
        return {
          asn: (texts[0]?.textContent || '').trim(),
          type: (texts[1]?.textContent || '').trim(),
          hasInspect: card.querySelector('button') !== null,
        };
      }));
  }
}

// ───────────────────────── share dialog (/asn only) ─────────────────────────

/**
 * The dialog has no role, id or class. This CSS selector (its stacking level)
 * is needed only where a helper wants a selector string (the layout audit);
 * everything else goes through `ShareDialog`.
 */
export const SHARE_DIALOG_CSS = 'div[style*="z-index: 10000"]';

export class ShareDialog {
  constructor(readonly page: Page) {}
  heading(): Locator { return this.page.getByRole('heading', { name: 'Share ASN Snapshot' }); }
  /** The dimmed area around the dialog; a click on it closes the dialog. */
  backdrop(): Locator { return this.heading().locator('xpath=../../..'); }
  card(): Locator { return this.heading().locator('xpath=../..'); }
  titleInput(): Locator { return this.card().locator('input[type="text"]').first(); }
  expirySelect(): Locator { return this.card().locator('select'); }
  passwordInput(): Locator { return this.card().locator('input[type="password"]'); }
  generateButton(): Locator { return this.card().getByRole('button', { name: /^(Generate Share Link|Creating Link\.\.\.)$/ }); }
  cancelButton(): Locator { return this.card().getByRole('button', { name: 'Cancel' }); }
  closeButton(): Locator { return this.card().getByRole('button', { name: 'Close' }); }
  xButton(): Locator { return this.card().getByRole('button', { name: '✕' }); }
  error(): Locator { return this.card().locator('div[style*="accent-red"]'); }
  readyHeading(): Locator { return this.card().getByRole('heading', { name: 'Share Link Ready!' }); }
  linkInput(): Locator { return this.card().locator('input[readonly]'); }
  copyButton(): Locator { return this.card().getByRole('button', { name: /(Copy|Copied!)$/ }); }

  /** Fills the form, creates the link and returns the URL the dialog shows. */
  async create(options: { title?: string; expiry?: 'never' | '24h' | '7d' | '30d'; password?: string } = {}): Promise<string> {
    if (options.title !== undefined) await this.titleInput().fill(options.title);
    if (options.expiry) await this.expirySelect().selectOption(options.expiry);
    if (options.password !== undefined) await this.passwordInput().fill(options.password);
    await this.generateButton().click();
    await expect(this.readyHeading(), 'the share link should be created').toBeVisible();
    return this.linkInput().inputValue();
  }
}

// ───────────────────────── shared view (/s/<code>) ─────────────────────────

export class SharedPage {
  readonly view: AsnView;
  constructor(readonly page: Page) { this.view = new AsnView(page, page.locator('main')); }
  title(): Locator { return this.page.getByRole('heading', { level: 1 }); }
  readOnlyBadge(): Locator { return this.page.getByText('Shared Analysis — Read Only'); }
  dates(): Locator { return this.page.getByText(/^Created: /); }
  passwordHeading(): Locator { return this.page.getByRole('heading', { name: 'Password Protected' }); }
  passwordInput(): Locator { return this.page.getByPlaceholder('Enter password'); }
  unlockButton(): Locator { return this.page.getByRole('button', { name: 'Unlock' }); }
  error(): Locator { return this.page.locator('main div.glass').filter({ hasText: /^⚠️/ }); }
}
