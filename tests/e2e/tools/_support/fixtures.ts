import { test as base, expect, type Page, type TestInfo } from '@playwright/test';
import { Rng, baseSeed, hashString } from './rng';

/**
 * Shared fixtures for the per-tool suites under tests/e2e/tools.
 *
 *  - `rng`       seeded random source; the seed is recorded on the test.
 *  - `guard`     watches the page for JavaScript errors, console errors and
 *                failed requests, and fails the test at the end if any were
 *                not expected. It is always on.
 *  - `evidence`  saves the inputs a test generated (logs, payloads) so a
 *                failure can be replayed and analysed without re-running.
 */

export interface PageGuard {
  /** Problems seen so far that no `allow` pattern covers. */
  problems(): string[];
  /** Declare an error this test causes on purpose (e.g. a mocked HTTP 500). */
  allow(pattern: RegExp): void;
  /** Assert now instead of waiting for the end of the test. */
  assertClean(label?: string): void;
}

export interface Evidence {
  /** Attach text (or JSON) to the test; kept with the failure report. */
  save(name: string, content: string | object): Promise<void>;
}

/** Browser noise that is not a defect in this application. */
const ALWAYS_ALLOWED: RegExp[] = [
  // Aborted navigations and cancelled fetches when a test moves on.
  /net::ERR_ABORTED/i,
];

function attachGuard(page: Page, allowed: RegExp[]): { problems: string[] } {
  const problems: string[] = [];
  const record = (text: string) => {
    if (![...ALWAYS_ALLOWED, ...allowed].some(re => re.test(text))) problems.push(text);
  };
  page.on('pageerror', err => record(`uncaught exception: ${err.message}`));
  page.on('console', msg => {
    if (msg.type() === 'error') record(`console.error: ${msg.text()} (${msg.location().url || 'inline'})`);
  });
  page.on('requestfailed', req => {
    record(`request failed: ${req.method()} ${req.url()} — ${req.failure()?.errorText || 'unknown'}`);
  });
  page.on('response', res => {
    if (res.status() >= 500) record(`HTTP ${res.status()}: ${res.request().method()} ${res.url()}`);
  });
  return { problems };
}

export const test = base.extend<{ rng: Rng; guard: PageGuard; evidence: Evidence }>({
  rng: async ({}, use, testInfo) => {
    const seed = hashString(`${baseSeed()}:${testInfo.titlePath.slice(1).join(' > ')}`);
    testInfo.annotations.push({ type: 'seed', description: `E2E_SEED=${baseSeed()} (test seed ${seed})` });
    await use(new Rng(seed));
  },

  guard: [async ({ page }, use, testInfo) => {
    const allowed: RegExp[] = [];
    const { problems } = attachGuard(page, allowed);
    const unexpected = () => problems.filter(text => !allowed.some(re => re.test(text)));
    const guard: PageGuard = {
      problems: unexpected,
      allow: pattern => { allowed.push(pattern); },
      assertClean: (label = 'page') => {
        const list = unexpected();
        expect(list, `Unexpected browser errors on ${label}:\n  ${list.join('\n  ')}\n`).toEqual([]);
      },
    };
    await use(guard);
    // Only add this failure when the test itself passed; otherwise the
    // original assertion is the useful message and this is attached as context.
    const list = unexpected();
    if (list.length === 0) return;
    if (testInfo.status === testInfo.expectedStatus) {
      expect(list, `Browser errors during the test:\n  ${list.join('\n  ')}\n`).toEqual([]);
    } else {
      await testInfo.attach('browser-errors.txt', { body: list.join('\n'), contentType: 'text/plain' });
    }
  }, { auto: true }],

  evidence: async ({}, use, testInfo) => {
    await use({
      save: async (name, content) => {
        const body = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
        await testInfo.attach(name, { body, contentType: name.endsWith('.json') ? 'application/json' : 'text/plain' });
      },
    });
  },
});

export { expect };
export type { Page, TestInfo };

/** `1234567` → `1,234,567`, the grouping every tool uses for counts. */
export function withCommas(value: number): string {
  return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/** Text of a locator with whitespace collapsed, for exact comparisons. */
export async function cleanText(locator: import('@playwright/test').Locator): Promise<string> {
  return ((await locator.textContent()) || '').replace(/\s+/g, ' ').trim();
}

/** Digits of a displayed number: `"1,234 requests"` → 1234. NaN when there is none. */
export function parseCount(text: string): number {
  const match = text.replace(/,/g, '').match(/-?\d+(\.\d+)?/);
  return match ? Number(match[0]) : NaN;
}
