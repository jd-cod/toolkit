import { expect, type Page } from '@playwright/test';
import { XSS_FLAG } from './generator';

/** Selectors and user actions for /ssl. */

export const ROUTE = '/ssl';
export const HEADING = 'SSL Certificate Checker';
export const API = '**/api/ssl';

const PRIMARY = '.signal-tool-primary';

export const hostInput = (page: Page) => page.getByPlaceholder('example.com');
export const portInput = (page: Page) => page.getByPlaceholder('443');
/** The submit button; its label changes while a check runs. */
export const checkButton = (page: Page) => page.locator(`${PRIMARY} .signal-query-row button`);
export const loadingPanel = (page: Page) => page.locator(`${PRIMARY} [role="status"]`);
export const errorAlert = (page: Page) => page.locator(`${PRIMARY} [role="alert"]`);
/** The box shown when the handshake failed but DNS answered (an error that arrived inside a 200 answer). */
export const failureBox = (page: Page) => page.locator(`${PRIMARY} > .glass:not([role])`, { hasText: '⚠️' });
/** Any error on screen, whichever of the two boxes the page chose. */
export const anyError = (page: Page) => page.locator(`${PRIMARY} > .glass`, { hasText: '⚠️' });
export const emptyState = (page: Page) => page.locator('.signal-tool-empty');
export const resultPanel = (page: Page) => page.locator(`${PRIMARY} > .glass`, { hasText: 'Validation Checks' });
export const exportButton = (page: Page) => page.locator(PRIMARY).getByRole('button', { name: 'Export CSV' });
export const copyButton = (page: Page) => page.locator(PRIMARY).getByRole('button', { name: /Copy Summary|Copied/ });

/** Value of one of the four summary cards, found by its caption. */
export function cardValue(page: Page, caption: string) {
  return page.locator(`${PRIMARY} .glass`)
    .filter({ has: page.locator('div', { hasText: new RegExp(`^${caption}$`) }) })
    .locator('div').first();
}

/** Fills the boxes and submits; `port` undefined leaves the port box as it is. */
export async function submit(page: Page, host: string, port?: string, via: 'button' | 'enter' = 'button') {
  await hostInput(page).fill(host);
  if (port !== undefined) await portInput(page).fill(port);
  if (via === 'enter') await hostInput(page).press('Enter');
  else await checkButton(page).click();
}

/** Submits and waits until the page has finished with the answer (result or error on screen). */
export async function check(page: Page, host: string, port?: string, via: 'button' | 'enter' = 'button') {
  await submit(page, host, port, via);
  // The click handler switches the button to "Checking..." before it returns,
  // so the label coming back is the end of the request.
  await expect(checkButton(page), 'the Check button returns once the request is over').toHaveText('🔒 Check', { timeout: 60_000 });
  await expect(page.locator(`${PRIMARY} > .glass`, { hasText: /Validation Checks|⚠️/ }).first(), 'a result or an error is shown after a check').toBeVisible();
}

export interface ShownCheck { ok: boolean; text: string; color: string }
export interface ShownCard { label: string; value: string; color: string; edge: string }
export interface ShownChainRow {
  subject: string;
  badge: string;
  side: string;
  org: string | null;
  valid: string | null;
  issuer: string | null;
  key: string | null;
}

export interface SslView {
  actions: string[];
  checks: ShownCheck[];
  cards: ShownCard[];
  /** The theme's colour tokens as the result area resolves them. */
  tokens: { good: string; warn: string; bad: string };
  responseTime: string;
  details: [string, string][];
  sanTitle: string | null;
  sans: string[];
  chainTitle: string | null;
  chain: ShownChainRow[];
}

/** Reads everything the result shows, as plain data. */
export async function readView(page: Page): Promise<SslView> {
  return page.evaluate((primarySelector) => {
    const primary = document.querySelector(primarySelector) as HTMLElement;
    const text = (el: Element | null | undefined) => (el?.textContent ?? '');
    const blocks = Array.from(primary.children).filter(el => el.classList.contains('glass')) as HTMLElement[];
    const headed = (start: string) => blocks.find(block => text(block.firstElementChild).trim().startsWith(start));

    const validation = headed('Validation Checks');
    const checks = Array.from(validation?.children[1]?.children ?? []).map(line => {
      const icon = line.querySelector('i');
      const label = line.querySelector('span');
      return {
        ok: Boolean(icon?.classList.contains('bi-check-circle-fill')) && !icon?.classList.contains('bi-x-circle-fill'),
        text: text(label),
        color: label ? getComputedStyle(label).color : '',
      };
    });

    const captions = ['Days Until Expiry', 'Security Grade', 'Protocol', 'Key Type'];
    const cards = Array.from(primary.querySelectorAll('.glass'))
      .filter(card => card.children.length === 2 && captions.includes(text(card.children[1])))
      .map(card => ({
        label: text(card.children[1]),
        value: text(card.children[0]),
        color: getComputedStyle(card.children[0]).color,
        edge: getComputedStyle(card).borderTopColor,
      }));

    const details = headed('Certificate Details');
    const sans = headed('Subject Alternative Names');
    const chain = headed('Certificate Chain');
    const lineValue = (card: Element, label: string) => {
      const line = Array.from(card.children[1]?.children ?? []).find(row => text(row.querySelector('strong')) === label);
      return line ? text(line).slice(label.length).replace(/^ /, '') : null;
    };
    const style = getComputedStyle(primary);

    return {
      actions: Array.from(blocks.find(block => block.querySelector('button.btn-secondary'))?.querySelectorAll('button') ?? []).map(b => text(b).trim()),
      checks,
      cards,
      tokens: {
        good: style.getPropertyValue('--accent-green').trim(),
        warn: style.getPropertyValue('--accent-amber').trim(),
        bad: style.getPropertyValue('--accent-red').trim(),
      },
      responseTime: text(details?.firstElementChild?.children[1]),
      details: Array.from(details?.querySelectorAll('tr') ?? []).map(tr => [text(tr.children[0]), text(tr.children[1])] as [string, string]),
      sanTitle: sans ? text(sans.firstElementChild).trim() : null,
      sans: Array.from(sans?.querySelectorAll('.tool-tag') ?? []).map(text),
      chainTitle: chain ? text(chain.firstElementChild).trim() : null,
      chain: Array.from(chain?.children[1]?.children ?? []).map(rowEl => {
        const side = rowEl.children[0];
        const card = rowEl.children[1];
        const title = card.children[0];
        const ownText = Array.from(title.childNodes).filter(node => node.nodeType === Node.TEXT_NODE).map(node => node.nodeValue ?? '').join('');
        return {
          subject: ownText.replace(/ $/, ''),
          badge: text(title.querySelector('span')),
          side: text(side.children[1]),
          org: lineValue(card, 'Org:'),
          valid: lineValue(card, 'Valid:'),
          issuer: lineValue(card, 'Issuer:'),
          key: lineValue(card, 'Key:'),
        };
      }),
    };
  }, PRIMARY);
}

/** True when markup from an answer was turned into live elements or ran as script. */
export async function markupWasExecuted(page: Page): Promise<string[]> {
  return page.evaluate((flag) => {
    const found: string[] = [];
    if ((window as unknown as Record<string, unknown>)[flag] !== undefined) found.push('injected script ran');
    const scope = document.querySelector('main') ?? document.body;
    if (scope.querySelector('img[src="x"]')) found.push('an <img src=x> element exists');
    if (scope.querySelector('script')) found.push('a <script> element exists inside the content');
    return found;
  }, XSS_FLAG);
}
