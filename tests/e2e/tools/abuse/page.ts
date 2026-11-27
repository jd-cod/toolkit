import { expect, type Locator, type Page } from '@playwright/test';
import { mockApi, type ApiCall } from '../_support/io';
import { geoScript } from './generator';
import type { AbuseResponse, FilterName, GeoFacts, IpInfoRecord } from './oracle';

/**
 * Selectors, user actions and readers for /abuse. Readers return plain data
 * so the specs compare data with data.
 */

export const ROUTE = '/abuse';
export const HEADING = 'IP Info & Security Risk Lookup';

export const IPINFO_URL = '**/api/ipinfo';
export const ABUSE_URL = '**/api/abuse';
export const GEO_SCRIPT_URL = '**/js/geoip.js*';

export const textarea = (page: Page) => page.locator('.signal-tool-primary textarea');
export const lookupButton = (page: Page) => page.locator('.signal-tool-primary button.btn-primary');
export const emptyState = (page: Page) => page.getByRole('heading', { name: 'Start an IP investigation' });
/** The red banner: the only element of the tool that carries the warning icon. */
export const errorBanner = (page: Page) => page.locator('.signal-tool-primary .glass').filter({ has: page.locator('i.bi-exclamation-triangle-fill') });
/** The grey notice shown when AbuseIPDB gave no usable answer. */
export const abuseNotice = (page: Page) => page.locator('.signal-tool-primary .glass').filter({ has: page.locator('i.bi-info-circle') });
export const resultsPanel = (page: Page) => page.locator('.signal-abuse-results');
export const desktopTable = (page: Page) => page.locator('.signal-abuse-desktop-table table');
export const mobileList = (page: Page) => page.locator('.signal-abuse-mobile-list');
export const exportButton = (page: Page) => page.getByRole('button', { name: 'Export CSV' });
export const copyButton = (page: Page) => page.getByRole('button', { name: /Copy IP Summary|Copied Summary!/ });

const FILTER_LABELS: Record<FilterName, string> = { all: 'All', rdns: 'rDNS', risk: 'Risk Flags', abusive: 'Abusive' };
export const filterButton = (page: Page, filter: FilterName) =>
  resultsPanel(page).getByRole('button', { name: new RegExp(`^${FILTER_LABELS[filter]} \\(\\d+\\)$`) });

/** Serves a GeoIP reader that answers from `table` instead of the real database. */
export async function serveGeo(page: Page, table: Record<string, GeoFacts>): Promise<void> {
  await page.route(GEO_SCRIPT_URL, route => route.fulfill({ status: 200, contentType: 'application/javascript', body: geoScript(table) }));
}

export interface Mocks { ipinfoCalls: ApiCall[]; abuseCalls: ApiCall[] }

/** Answers both API calls and the GeoIP reader from the given data. */
export async function mockSources(
  page: Page,
  sources: { ipinfo: IpInfoRecord[]; abuse: AbuseResponse; geo: Record<string, GeoFacts> },
  options: { delayMs?: number } = {},
): Promise<Mocks> {
  await serveGeo(page, sources.geo);
  const ipinfoCalls = await mockApi(page, IPINFO_URL, { results: sources.ipinfo }, options);
  const abuseCalls = await mockApi(page, ABUSE_URL, sources.abuse, options);
  return { ipinfoCalls, abuseCalls };
}

export interface Stage extends Mocks {
  /** Changes what the two API calls answer from now on. */
  set(sources: { ipinfo: IpInfoRecord[]; abuse: AbuseResponse }): void;
}

/**
 * Like `mockSources`, for tests that run several lookups on one page: the
 * GeoIP table is fixed for the page (the reader script loads once), the API
 * answers can be swapped between lookups.
 */
export async function stageSources(page: Page, geo: Record<string, GeoFacts>): Promise<Stage> {
  const current: { ipinfo: IpInfoRecord[]; abuse: AbuseResponse } = { ipinfo: [], abuse: {} };
  await serveGeo(page, geo);
  const ipinfoCalls = await mockApi(page, IPINFO_URL, () => ({ results: current.ipinfo }));
  const abuseCalls = await mockApi(page, ABUSE_URL, () => current.abuse);
  return { ipinfoCalls, abuseCalls, set: sources => { current.ipinfo = sources.ipinfo; current.abuse = sources.abuse; } };
}

/** Types the batch the way a user pastes it and presses the lookup button. */
export async function submit(page: Page, text: string): Promise<void> {
  await textarea(page).fill(text);
  await lookupButton(page).click();
}

/** Submits and waits for the outcome: a result table or an error banner. */
export async function lookup(page: Page, text: string): Promise<void> {
  await submit(page, text);
  await expect(resultsPanel(page).or(errorBanner(page)).first(), 'the lookup should end with results or an error').toBeVisible();
  await expect(lookupButton(page), 'the lookup button should be ready again').toBeEnabled();
}

// ─── Readers ────────────────────────────────────────────────────────────

export interface ShownRow {
  index: string;
  ip: string;
  version: string;
  ptr: string;
  flag: string;
  country: string;
  /** "(US)" as shown, '' when the page shows no code. */
  countryCode: string;
  /** "AS15169" as shown, '' when the page shows no AS number. */
  asn: string;
  isp: string;
  /** Second line of the network cell, '' when absent. */
  usage: string;
  badge: string;
  score: string;
  abuseIpdbHref: string;
  expanded: Record<string, string> | null;
}

/** Every row of the desktop table, with the detail row when it is open. */
export async function readTable(page: Page): Promise<ShownRow[]> {
  if (await desktopTable(page).count() === 0) return [];
  return desktopTable(page).evaluate((table) => {
    const clean = (text: string | null | undefined) => (text || '').replace(/\s+/g, ' ').trim();
    const rows = Array.from(table.querySelectorAll('tbody > tr'));
    const out: any[] = [];
    for (const tr of rows) {
      const cells = Array.from(tr.children) as HTMLElement[];
      if (cells.length === 1) {
        // Detail row: "<strong>Label:</strong> value" blocks.
        const details: Record<string, string> = {};
        for (const block of Array.from(cells[0].querySelectorAll('strong'))) {
          const label = clean(block.textContent).replace(/:$/, '');
          details[label] = clean((block.parentElement?.textContent || '').replace(block.textContent || '', ''));
        }
        if (out.length) out[out.length - 1].expanded = details;
        continue;
      }
      const ipSpans = Array.from(cells[1].querySelectorAll('span'));
      const countrySpans = Array.from(cells[3].querySelectorAll('span'));
      const networkBlocks = Array.from(cells[4].children) as HTMLElement[];
      const networkSpans = networkBlocks[0] ? Array.from(networkBlocks[0].querySelectorAll('span')) : [];
      out.push({
        index: clean(cells[0].textContent),
        ip: clean(ipSpans[0]?.textContent),
        version: clean(ipSpans[1]?.textContent),
        ptr: clean(cells[2].textContent),
        flag: clean(countrySpans[0]?.textContent),
        country: clean(countrySpans[1]?.textContent),
        countryCode: clean(countrySpans[2]?.textContent),
        asn: networkSpans.length > 1 ? clean(networkSpans[0].textContent) : '',
        isp: clean(networkSpans[networkSpans.length - 1]?.textContent),
        usage: clean(networkBlocks[1]?.textContent),
        badge: clean(cells[5].textContent),
        score: clean(cells[6].textContent),
        abuseIpdbHref: cells[7].querySelector('a')?.getAttribute('href') || '',
        expanded: null,
      });
    }
    return out as ShownRow[];
  });
}

export interface ShownCard {
  index: string;
  ip: string;
  version: string;
  badge: string;
  ptr: string;
  /** "<flag> <name>" as shown. */
  country: string;
  /** "AS15169 · Name" or just the name. */
  network: string;
  score: string;
  scoreHighlighted: boolean;
  abuseIpdbHref: string;
  expanded: Record<string, string> | null;
}

/** Every card of the narrow-screen list (the same data as the table, laid out as cards). */
export async function readCards(page: Page): Promise<ShownCard[]> {
  if (await mobileList(page).count() === 0) return [];
  return mobileList(page).evaluate((list) => {
    const clean = (text: string | null | undefined) => (text || '').replace(/\s+/g, ' ').trim();
    return Array.from(list.querySelectorAll('article.signal-abuse-mobile-card')).map((card) => {
      const facts: Record<string, string> = {};
      let highlighted = false;
      for (const row of Array.from(card.querySelectorAll('dl.signal-abuse-mobile-facts > div'))) {
        const label = clean(row.querySelector('dt')?.textContent);
        facts[label] = clean(row.querySelector('dd')?.textContent);
        if (label === 'Abuse score') highlighted = row.querySelector('dd')?.classList.contains('is-risk') || false;
      }
      const box = card.querySelector('.signal-abuse-mobile-expanded');
      let expanded: Record<string, string> | null = null;
      if (box) {
        expanded = {};
        for (const line of Array.from(box.querySelectorAll('span'))) {
          const strong = line.querySelector('strong');
          if (!strong) continue;
          expanded[clean(strong.textContent).replace(/:$/, '')] = clean((line.textContent || '').replace(strong.textContent || '', ''));
        }
      }
      return {
        index: clean(card.querySelector('.signal-abuse-mobile-index')?.textContent),
        ip: clean(card.querySelector('.signal-abuse-mobile-card-heading strong')?.textContent),
        version: clean(card.querySelector('.signal-abuse-mobile-card-heading small')?.textContent),
        badge: clean(card.querySelector('.signal-abuse-mobile-card-heading > span')?.textContent),
        ptr: facts['Reverse DNS'] ?? '',
        country: facts['Country'] ?? '',
        network: facts['Network'] ?? '',
        score: facts['Abuse score'] ?? '',
        scoreHighlighted: highlighted,
        abuseIpdbHref: card.querySelector('.signal-abuse-mobile-actions a')?.getAttribute('href') || '',
        expanded,
      };
    });
  });
}

export interface ShownSummary {
  cards: Record<string, string>;
  /** "Results (x of y IPs)" → [x, y]. */
  shown: number;
  of: number;
  /** Label → count, for every filter button on screen. */
  filters: Record<string, number>;
  /** Labels of the filter buttons drawn as selected. */
  selected: string[];
}

export async function readSummary(page: Page): Promise<ShownSummary> {
  return page.locator('.signal-tool-primary').evaluate((root) => {
    const clean = (text: string | null | undefined) => (text || '').replace(/\s+/g, ' ').trim();
    const cards: Record<string, string> = {};
    for (const label of ['Total IPs Analyzed', 'Reverse DNS Found', 'Risk Flags / Elevated', 'Abuse Reports']) {
      const caption = Array.from(root.querySelectorAll('.glass > div')).find(el => clean(el.textContent) === label);
      cards[label] = clean(caption?.previousElementSibling?.textContent);
    }
    const panel = root.querySelector('.signal-abuse-results');
    const header = clean(panel?.firstElementChild?.querySelector('span')?.textContent);
    const match = header.match(/^Results \((\d+) of (\d+) IPs\)$/);
    const filters: Record<string, number> = {};
    const selected: string[] = [];
    for (const button of Array.from(panel?.firstElementChild?.querySelectorAll('button') || [])) {
      const parts = clean(button.textContent).match(/^(.*) \((\d+)\)$/);
      if (!parts) continue;
      filters[parts[1]] = Number(parts[2]);
      // The page marks the selected filter only by filling its background; there is no aria-pressed.
      if ((button as HTMLElement).style.background) selected.push(parts[1]);
    }
    return { cards, shown: match ? Number(match[1]) : NaN, of: match ? Number(match[2]) : NaN, filters, selected };
  });
}

/** The row's own "Info" / "Hide" button in the desktop table. */
export function rowToggle(page: Page, rowIndex: number): Locator {
  return desktopTable(page).locator('tbody > tr').filter({ has: page.locator('td:nth-child(8)') }).nth(rowIndex).getByRole('button');
}

/** The card's "Show details" / "Hide details" button in the narrow-screen list. */
export function cardToggle(page: Page, cardIndex: number): Locator {
  return mobileList(page).locator('article').nth(cardIndex).getByRole('button');
}
