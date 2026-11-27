import { expect, type Locator, type Page } from '@playwright/test';
import { mockApi, type ApiCall } from '../_support/io';
import { waitForHydration } from '../_support/navigation';
import type { MyIpPayload } from './oracle';

/**
 * Selectors, user actions and readers for /myip and for its shared view
 * (/s/<code>). Readers return plain data.
 */

export const ROUTE = '/myip';
export const HEADING = 'What Is My IP';
export const MYIP_URL = '**/api/myip';

export const loadingCard = (page: Page) => page.getByRole('heading', { name: 'Detecting Your IP Address' });
/** The red box the page shows when the lookup fails. */
export const errorBox = (page: Page) => page.locator('.signal-tool-primary > .glass').filter({ hasText: '⚠️' });
export const addressCard = (page: Page) => page.locator('.glass').filter({ has: page.getByText(/^(Your Public IP Addresses|Public IP Address)$/) }).first();
export const shareButton = (page: Page) => page.getByRole('button', { name: 'Share Results' });
export const htmlButton = (page: Page) => page.getByRole('button', { name: 'Download HTML' });
export const csvButton = (page: Page) => page.getByRole('button', { name: 'Export CSV' });
export const asnLookupLink = (page: Page) => page.locator('.signal-tool-primary').getByRole('link', { name: 'ASN Lookup' });
export const dnsLookupLink = (page: Page) => page.locator('.signal-tool-primary').getByRole('link', { name: 'DNS Lookup' });
export const section = (page: Page, title: string) => page.locator('details.signal-myip-collapsible').filter({ has: page.locator('summary', { hasText: title }) });

/** Opens /myip with the API answered by `payload` (or by a function of the call number, starting at 0). */
export async function openWith(page: Page, payload: MyIpPayload | ((callNumber: number) => unknown), options: { delayMs?: number; status?: number } = {}): Promise<ApiCall[]> {
  let callNumber = 0;
  const calls = await mockApi(page, MYIP_URL, () => (typeof payload === 'function' ? payload(callNumber++) : payload), options);
  await page.goto(ROUTE, { waitUntil: 'domcontentloaded' });
  await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
  await waitForHydration(page);
  return calls;
}

/** Waits until the address card has left its loading state (both boxes resolved). */
export async function waitForResult(page: Page): Promise<void> {
  await expect(addressCard(page), 'the address card should appear').toBeVisible();
  await expect(addressCard(page).locator('.skeleton'), 'both address boxes should finish detecting').toHaveCount(0);
}

export interface AddressBox { tags: string[]; state: 'detected' | 'missing' | 'loading'; value: string; copyLabel: string }
export interface ShownAddressCard { ipv4: AddressBox; ipv6: AddressBox; badges: string[] }

export async function readAddressCard(page: Page): Promise<ShownAddressCard> {
  return addressCard(page).evaluate((card) => {
    const clean = (text: string | null | undefined) => (text || '').replace(/\s+/g, ' ').trim();
    const grid = card.children[1];
    const box = (el: Element) => {
      const tags = Array.from(el.children[0].querySelectorAll('span')).map(span => clean(span.textContent));
      const body = el.children[1];
      if (body.classList.contains('skeleton')) return { tags, state: 'loading' as const, value: '', copyLabel: '' };
      const button = body.querySelector('button');
      if (button) return { tags, state: 'detected' as const, value: clean(body.firstElementChild?.textContent), copyLabel: clean(button.textContent) };
      return { tags, state: 'missing' as const, value: clean(body.textContent), copyLabel: '' };
    };
    const badges = card.children[2] ? Array.from(card.children[2].children).map(el => clean(el.textContent)) : [];
    return { ipv4: box(grid.children[0]), ipv6: box(grid.children[1]), badges };
  });
}

export const copyAddressButton = (page: Page, version: 'IPv4' | 'IPv6') =>
  addressCard(page).locator(':scope > div').nth(1).locator(':scope > div').nth(version === 'IPv4' ? 0 : 1).getByRole('button');

/** The four summary cards under the toolbar: label → value. */
export async function readStats(page: Page): Promise<Record<string, string>> {
  return page.locator('.signal-tool-primary').evaluate((root) => {
    const clean = (text: string | null | undefined) => (text || '').replace(/\s+/g, ' ').trim();
    const out: Record<string, string> = {};
    for (const card of Array.from(root.querySelectorAll('.glass'))) {
      if (card.children.length !== 2 || card.querySelector('dl, table, button')) continue;
      const label = clean(card.children[1].textContent);
      if (['Country', 'City', 'ASN Org', 'ASN'].includes(label)) out[label] = clean(card.children[0].textContent);
    }
    return out;
  });
}

export interface ShownRow { label: string; value: string; link: { label: string; href: string } | null }

/** Every detail card of /myip: card title → rows in order. Reads collapsed cards too. */
export async function readSections(page: Page): Promise<Record<string, ShownRow[]>> {
  return page.locator('.signal-tool-primary').evaluate((root) => {
    const clean = (text: string | null | undefined) => (text || '').replace(/\s+/g, ' ').trim();
    const out: Record<string, ShownRow[]> = {};
    for (const list of Array.from(root.querySelectorAll('dl.signal-myip-details'))) {
      const details = list.closest('details');
      const title = details ? clean(details.querySelector('summary')?.textContent) : clean(list.closest('.glass')?.firstElementChild?.textContent);
      out[title] = Array.from(list.children).map((row) => {
        const anchor = row.querySelector('dd a');
        return {
          label: clean(row.querySelector('dt')?.textContent),
          value: clean(row.querySelector('dd span')?.textContent),
          link: anchor ? { label: clean(anchor.textContent), href: anchor.getAttribute('href') || '' } : null,
        };
      });
    }
    return out;
  });
}

export function rowsToRecord(rows: ShownRow[] | undefined): Record<string, string> {
  return Object.fromEntries((rows ?? []).map(row => [row.label, row.value]));
}

/** Every table card of the shared view (/s/<code>): card title → label → value. */
export async function readSharedSections(page: Page): Promise<Record<string, Record<string, string>>> {
  return page.locator('main').evaluate((root) => {
    const clean = (text: string | null | undefined) => (text || '').replace(/\s+/g, ' ').trim();
    const out: Record<string, Record<string, string>> = {};
    for (const table of Array.from(root.querySelectorAll('.glass > table'))) {
      const title = clean(table.parentElement?.firstElementChild?.textContent);
      out[title] = Object.fromEntries(Array.from(table.querySelectorAll('tr')).map(tr => [clean(tr.children[0]?.textContent), clean(tr.children[1]?.textContent)]));
    }
    return out;
  });
}

// ─── Share dialog ───────────────────────────────────────────────────────

export const shareDialog = (page: Page): Locator => page.getByRole('heading', { name: 'Share IP Report' }).locator('xpath=ancestor::div[3]');
export const shareTitleInput = (page: Page) => shareDialog(page).locator('input:not([type="password"])');
export const shareExpirySelect = (page: Page) => shareDialog(page).locator('select');
export const sharePasswordInput = (page: Page) => shareDialog(page).locator('input[type="password"]');
export const generateLinkButton = (page: Page) => shareDialog(page).getByRole('button', { name: 'Generate Share Link' });
export const shareLinkText = (page: Page) => shareDialog(page).locator('span').filter({ hasText: /\/s\/[A-Za-z0-9]+$/ });

/** Collects every /api/myip answer of a page load, in the order the requests were sent. */
export function recordMyIpResponses(page: Page): { answers: () => Promise<{ status: number; body: unknown }[]> } {
  const pending: Promise<{ status: number; body: unknown }>[] = [];
  page.on('request', (request) => {
    if (!/\/api\/myip(\?|$)/.test(request.url())) return;
    pending.push(request.response().then(async response => ({
      status: response?.status() ?? 0,
      body: response ? await response.json().catch(() => null) : null,
    })));
  });
  return { answers: () => Promise.all(pending) };
}
