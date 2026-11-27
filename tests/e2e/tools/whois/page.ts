import { expect, type Browser, type BrowserContext, type Page, type TestInfo } from '@playwright/test';
import { waitForHydration } from '../_support/navigation';
import type { Visitor } from '../_support/visitor';
import type { ContactCard, ReportView, WhoisView } from './oracle';
import { XSS_FLAG } from './generator';

/** Selectors and user actions for /whois and the shared snapshot view. */

export const ROUTE = '/whois';
export const HEADING = 'WHOIS Lookup';
export const API = '**/api/whois';
export const SHARE_API = '**/api/share/whois';

export const domainInput = (page: Page) => page.getByPlaceholder('e.g. openai.com');
/** The submit button; its label changes while a lookup runs. */
export const lookupButton = (page: Page) => page.locator('.input-card button');
export const errorAlert = (page: Page) => page.locator('.signal-tool-primary .alert-custom');
export const emptyState = (page: Page) => page.locator('.signal-tool-empty');
export const statCards = (page: Page) => page.locator('main .stat-card');
export const actionButton = (page: Page, name: string | RegExp) => page.locator('main').getByRole('button', { name });

/** Value of a summary card, found by its caption. */
export function cardValue(page: Page, caption: string) {
  return page.locator('main .stat-card')
    .filter({ has: page.locator('.stat-label', { hasText: new RegExp(`^${caption}$`) }) })
    .locator('.stat-value');
}

/** Types into the box and submits; `via` picks the button or the Enter key. */
export async function submit(page: Page, typed: string, via: 'button' | 'enter' = 'button') {
  await domainInput(page).fill(typed);
  if (via === 'enter') await domainInput(page).press('Enter');
  else await lookupButton(page).click();
}

/** Submits and waits until the page has finished with the answer (result or error on screen). */
export async function lookup(page: Page, typed: string, via: 'button' | 'enter' = 'button') {
  await submit(page, typed, via);
  // The click handler switches the button to "Looking up..." before it returns,
  // so the label coming back is the end of the request.
  await expect(lookupButton(page), 'the Lookup button returns once the request is over').toHaveText('Lookup', { timeout: 60_000 });
  await expect(page.locator('main .stat-card, .signal-tool-primary .alert-custom').first(), 'a result or an error is shown after a lookup').toBeVisible();
}

/** CSS selector of the share dialog's backdrop (it has no id, class or role). */
export const SHARE_DIALOG = '.signal-workspace > div:has(h3)';
export const shareDialog = (page: Page) => page.locator(SHARE_DIALOG).filter({ has: page.getByRole('heading', { name: 'Share WHOIS Snapshot' }) });
export const shareTitle = (page: Page) => shareDialog(page).locator('input:not([type="password"])');
export const shareExpiry = (page: Page) => shareDialog(page).locator('select');
export const sharePassword = (page: Page) => shareDialog(page).locator('input[type="password"]');
export const shareSubmit = (page: Page) => shareDialog(page).getByRole('button', { name: 'Generate Share Link' });
export const shareLink = (page: Page) => shareDialog(page).locator('span', { hasText: /\/s\/[A-Za-z0-9]+$/ });
export const shareClose = (page: Page) => shareDialog(page).locator('button').filter({ has: page.locator('i.bi-x-lg') });

/** Reads everything the snapshot view shows, as plain data. Works on /whois and on /s/<code>. */
export async function readView(page: Page): Promise<WhoisView> {
  return page.evaluate(() => {
    const root = document.querySelector('main') as HTMLElement;
    const text = (el: Element | null | undefined) => (el?.textContent ?? '');
    const cards = Array.from(root.querySelectorAll('.stat-card')).map(card => [
      text(card.querySelector('.stat-label')), text(card.querySelector('.stat-value')),
    ] as [string, string]);
    const colorOf = (caption: string) => {
      const card = Array.from(root.querySelectorAll('.stat-card')).find(c => text(c.querySelector('.stat-label')) === caption);
      const value = card?.querySelector('.stat-value');
      return value ? getComputedStyle(value).color : '';
    };
    const afterLabel = (label: string) => {
      const strong = Array.from(root.querySelectorAll('strong')).find(s => text(s).trim() === label);
      return text(strong?.nextElementSibling);
    };
    const sections = Array.from(root.querySelectorAll('.table-card'));
    const body = (title: string) => {
      const card = sections.find(s => text(s.querySelector('h5')) === title);
      return card ? card.children[1] as HTMLElement : null;
    };
    const pairs = (el: HTMLElement | null): [string, string][] => {
      const grid = el?.firstElementChild;
      return grid ? Array.from(grid.children).map(cell => [text(cell.children[0]), text(cell.children[1])] as [string, string]) : [];
    };

    const status = body('Domain Status');
    const statusPills = Array.from(status?.querySelectorAll('span') ?? []).map(text);
    const ns = body('Nameserver Comparison');
    const contacts = body('Contacts');
    const risk = body('Risk Signals');
    const riskItems = Array.from(risk?.querySelectorAll('li') ?? []).map(text);
    const rawSection = sections.find(s => text(s.querySelector('h5')).startsWith('Raw '));

    return {
      cards,
      daysColor: colorOf('Days Until Expiry'),
      dnssecColor: colorOf('DNSSEC'),
      source: afterLabel('Source:'),
      checkedAt: afterLabel('Checked At:'),
      sections: sections.map(s => text(s.querySelector('h5'))),
      statusPills,
      statusNote: statusPills.length ? null : text(status),
      registrar: pairs(body('Registrar & Dates')),
      nameservers: pairs(ns),
      links: Array.from(ns?.querySelectorAll('a') ?? []).map(a => [text(a), a.getAttribute('href') ?? ''] as [string, string]),
      contacts: Array.from(contacts?.querySelectorAll('.glass') ?? []).map(card => ({
        label: text(card.children[0]),
        lines: Array.from(card.children[1]?.children ?? []).map(text),
      })),
      riskItems,
      riskNote: riskItems.length ? null : text(risk),
      rawToggle: text(rawSection?.querySelector('button')),
    };
  });
}

/** The raw record as shown after pressing "Show Raw ..."; null while it is collapsed. */
export async function readRaw(page: Page): Promise<string | null> {
  const pre = page.locator('main .table-card pre');
  return (await pre.count()) ? pre.first().textContent() : null;
}

/** Reads the downloaded HTML report (already loaded into `report`) as plain data. */
export async function readReport(report: Page): Promise<ReportView> {
  return report.evaluate(() => {
    const text = (el: Element | null | undefined) => (el?.textContent ?? '');
    const section = (title: string) => Array.from(document.querySelectorAll('.section')).find(s => text(s.querySelector('h2')) === title);
    const sectionStarting = (prefix: string) => Array.from(document.querySelectorAll('.section')).find(s => text(s.querySelector('h2')).startsWith(prefix));
    const pairs = (el: Element | undefined): [string, string][] =>
      Array.from(el?.querySelectorAll('.grid > div') ?? []).map(cell => [text(cell.querySelector('.label')), text(cell.querySelector('.value'))] as [string, string]);
    const status = section('Status');
    const risk = section('Risk Signals');
    const raw = sectionStarting('Raw ');
    const pills = Array.from(status?.querySelectorAll('.pill') ?? []).map(text);
    const riskItems = Array.from(risk?.querySelectorAll('li') ?? []).map(text);
    return {
      title: document.title,
      heading: text(document.querySelector('h1')),
      subtitle: text(document.querySelector('.subtitle')),
      cards: Array.from(document.querySelectorAll('.card')).map(card => [text(card.querySelector('.card-label')), text(card.querySelector('.card-value'))] as [string, string]),
      statusPills: pills,
      statusNote: pills.length ? null : text(status?.querySelector('.section-body')),
      details: pairs(section('Details')),
      nameservers: pairs(section('Nameservers')),
      riskItems,
      riskNote: riskItems.length ? null : text(risk?.querySelector('.section-body')),
      rawHeading: text(raw?.querySelector('h2')),
      raw: text(raw?.querySelector('pre')),
    };
  });
}

/** True when markup from a payload was turned into live elements or ran as script. */
export async function markupWasExecuted(page: Page): Promise<string[]> {
  return page.evaluate((flag) => {
    const found: string[] = [];
    if ((window as unknown as Record<string, unknown>)[flag] !== undefined) found.push('injected script ran');
    const scope = document.querySelector('main') ?? document.body;
    if (scope.querySelector('img[src="x"]')) found.push('an <img src=x> element exists');
    if (scope.querySelector('script')) found.push('a <script> element exists inside the content');
    if (scope.querySelector('b')) found.push('a <b> element from the payload exists');
    return found;
  }, XSS_FLAG);
}

// ─── A second visitor ─────────────────────────────────────────────────────────

export { newVisitor, expectVisitorClean, type Visitor } from '../_support/visitor';

/**
 * Opens /s/<code> as `visitor`, waits until the page has settled on a state,
 * and returns what GET /api/share/<code> answered (the link's metadata).
 */
export async function openShared(visitor: Visitor, code: string): Promise<{ status: number; meta: Record<string, unknown> }> {
  const answered = visitor.page.waitForResponse(res => res.url().endsWith(`/api/share/${code}`) && res.request().method() === 'GET');
  const response = await visitor.page.goto(`/s/${code}`, { waitUntil: 'domcontentloaded' });
  expect(response?.status(), `/s/${code} should answer 200`).toBe(200);
  const metaResponse = await answered;
  const meta = await metaResponse.json().catch(() => ({})) as Record<string, unknown>;
  await waitForHydration(visitor.page);
  await expect(visitor.page.locator('main .skeleton'), 'the loading placeholder goes away').toHaveCount(0);
  return { status: metaResponse.status(), meta };
}

export const passwordPrompt = (page: Page) => page.getByRole('heading', { name: 'Password Protected' });
export const passwordBox = (page: Page) => page.getByPlaceholder('Enter password');
export const unlockButton = (page: Page) => page.getByRole('button', { name: 'Unlock' });
export const sharedError = (page: Page) => page.locator('main > .glass', { hasText: '⚠️' });

export type { ContactCard };
