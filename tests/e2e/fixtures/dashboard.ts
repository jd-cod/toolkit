import { test as base, expect, type Page } from '@playwright/test';

/**
 * Shared fixture for the Nginx dashboard.
 *
 * Every spec needs the same two steps: paste a log into #nginx-logtext, click
 * analyze, wait for #nginx-dashboard to stop being hidden. Centralising it here
 * keeps the specs readable and means a change to the dashboard's ready signal
 * only has to be made in one place.
 *
 * UI-FIRST: assertions in these specs read visible DOM state and collect
 * console/page errors. We never substitute an API response for a visual check.
 */

/**
 * Minimal but structurally realistic nginx access log.
 *
 * A single repeated line makes cross-filter assertions degenerate (one IP, one
 * ASN), so we mix several clients, paths, status codes and referrers. Keep this
 * in sync with the page's own parser expectations.
 */
const SAMPLE_LOG = [
  '66.249.66.1 - - [20/Sep/2026:10:15:00 +0000] "GET /products HTTP/2.0" 200 4520 "-" "Googlebot/2.1"',
  '203.0.113.45 - - [20/Sep/2026:10:15:05 +0000] "POST /api/login HTTP/1.1" 401 233 "https://example.com/login" "Mozilla/5.0"',
  '198.51.100.7 - - [20/Sep/2026:10:15:11 +0000] "GET /admin HTTP/1.1" 404 153 "-" "curl/8.4.0"',
  '66.249.66.2 - - [20/Sep/2026:10:15:20 +0000] "GET /products HTTP/2.0" 200 4611 "-" "Googlebot/2.1"',
  '203.0.113.91 - - [20/Sep/2026:10:15:33 +0000] "GET /checkout HTTP/1.1" 500 892 "https://example.com/cart" "Mozilla/5.0"',
  '198.51.100.8 - - [20/Sep/2026:10:15:41 +0000] "GET /wp-admin HTTP/1.1" 404 153 "-" "python-requests/2.31.0"',
  '192.0.2.55 - - [20/Sep/2026:10:15:58 +0000] "GET /static/app.js HTTP/2.0" 304 0 "https://example.com/" "Mozilla/5.0"',
  '203.0.113.12 - - [20/Sep/2026:10:16:04 +0000] "DELETE /api/users/9 HTTP/1.1" 403 88 "-" "Mozilla/5.0"',
  '66.249.66.3 - - [20/Sep/2026:10:16:12 +0000] "GET /products HTTP/2.0" 200 4702 "-" "Googlebot/2.1"',
  '198.51.100.9 - - [20/Sep/2026:10:16:30 +0000] "GET /.env HTTP/1.1" 404 153 "-" "python-requests/2.31.0"',
].join('\n');

/** Repeats the sample so charts have enough points to draw a real distribution. */
const BUILD_LOG = Array.from({ length: 60 }, () => SAMPLE_LOG).join('\n');

/**
 * Collects console errors and uncaught exceptions for the life of the page.
 *
 * Zero JS errors is an explicit acceptance criterion in this project, so the
 * fixture hands the array to each spec rather than making every test re-attach
 * listeners.
 */
export type ConsoleWatcher = {
  errors: string[];
  assertClean: () => void;
};

function watchConsole(page: Page): ConsoleWatcher {
  const errors: string[] = [];
  page.on('console', (msg) => {
    if (msg.type() === 'error') errors.push(msg.text());
  });
  page.on('pageerror', (err) => errors.push(err.message));
  return {
    errors,
    assertClean: () => expect(errors, `Console/JS errors:\n${errors.join('\n')}`).toEqual([]),
  };
}

export const test = base.extend<{ console: ConsoleWatcher }>({
  console: async ({ page }, use) => {
    await use(watchConsole(page));
  },
});

export { expect, SAMPLE_LOG, BUILD_LOG };

/**
 * Drives the page from landing → analysed dashboard and returns once the
 * dashboard is visible. Every spec starts here.
 */
export async function gotoAnalyzedDashboard(page: Page): Promise<void> {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  await page.getByRole('tab', { name: 'Paste logs' }).click();

  // The textarea is controlled by the classic dashboard.js, so we set the value
  // and dispatch `input` before clicking — setting .value alone would leave
  // React's tracked value stale and analyze would receive ''.
  await page.fill('#nginx-logtext', BUILD_LOG);
  await page.click('#nginx-analyze-btn');

  // Ready signal: the dashboard container is shown once analysis completes.
  await expect(page.locator('#nginx-dashboard')).toBeVisible({ timeout: 45_000 });
  // Charts paint on a rAF after the container un-hides; wait for real content.
  await expect(page.locator('.kpi-micro-card').first()).toBeVisible();
}

/**
 * Waits until nginx-init.js has run and bound the Analyze handler.
 *
 * This page is a "vanilla JS island": React only renders the DOM skeleton, and
 * the behaviour lives in 11 script tags loaded SEQUENTIALLY — Chart.js from a
 * CDN first, then geoip/log-parser/analyzer/dashboard/.../nginx-init (which
 * binds the click handler) in a promise chain (page.tsx:58-90).
 *
 * `waitUntil: 'load'` does NOT cover this. Chart.js is dynamically injected and
 * the chain continues well after the load event, so clicking Analyze too early
 * hits an inert button and the dashboard never un-hides. Under parallel workers
 * the CDN fetch is slower and the race widens.
 *
 * The input controller publishes an explicit ready marker after binding its DOM.
 */
export async function waitForEngineReady(page: Page): Promise<void> {
  await page.waitForFunction(
    () =>
      ['LogParser', 'Analyzer', 'Dashboard', 'GeoIP', 'BotDetector'].every(
        (g) => !!(window as any)[g],
      ),
    undefined,
    { timeout: 45_000 },
  );

  await expect(page.locator('#nginx-analyze-btn')).toHaveAttribute('data-engine-ready', 'true');
}
