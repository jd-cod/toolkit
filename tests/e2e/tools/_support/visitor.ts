import type { Browser, BrowserContext, Page, TestInfo } from '@playwright/test';
import { expect } from './fixtures';

export interface Visitor {
  page: Page;
  context: BrowserContext;
  /** Declare an error this visitor causes on purpose. */
  allow(pattern: RegExp): void;
  /** Browser errors seen in this visitor's page that were not declared. */
  problems(): string[];
}

/**
 * A different person opening a link: a new browser context with no cookies or
 * storage from the first one, same time zone and locale as the test project.
 * Errors in its page are collected the way the `guard` fixture does for the
 * main page; call `expectVisitorClean` before closing.
 */
export async function newVisitor(browser: Browser, testInfo: TestInfo): Promise<Visitor> {
  const use = testInfo.project.use;
  const context = await browser.newContext({
    baseURL: use.baseURL,
    timezoneId: use.timezoneId,
    locale: use.locale,
    viewport: use.viewport ?? { width: 1440, height: 1080 },
    permissions: ['clipboard-read', 'clipboard-write'],
    acceptDownloads: true,
  });
  const page = await context.newPage();
  const allowed: RegExp[] = [/net::ERR_ABORTED/i];
  const seen: string[] = [];
  page.on('pageerror', err => seen.push(`uncaught exception: ${err.message}`));
  page.on('console', msg => { if (msg.type() === 'error') seen.push(`console.error: ${msg.text()}`); });
  page.on('requestfailed', req => seen.push(`request failed: ${req.method()} ${req.url()} — ${req.failure()?.errorText || 'unknown'}`));
  page.on('response', res => { if (res.status() >= 500) seen.push(`HTTP ${res.status()}: ${res.request().method()} ${res.url()}`); });
  return {
    page,
    context,
    allow: pattern => { allowed.push(pattern); },
    problems: () => seen.filter(line => !allowed.some(re => re.test(line))),
  };
}

export function expectVisitorClean(visitor: Visitor, label: string) {
  const list = visitor.problems();
  expect.soft(list, `Unexpected browser errors for ${label}:\n  ${list.join('\n  ')}\n`).toEqual([]);
}
