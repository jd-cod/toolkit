import { test, expect } from './fixtures/dashboard';

/**
 * Cross-filter clicks on the dashboard's clickable table rows.
 *
 * REAL public IPs only. The shared SAMPLE_LOG in the fixture uses RFC-5737
 * documentation ranges (203.0.113.x / 198.51.100.x), which resolve to no ASN
 * at all — against an all-'AS0' corpus an ASN filter bug is invisible, because
 * the filter "correctly" matches the one bucket that happens to exist.
 *
 * This file guards the two shape mismatches that silently blanked the
 * dashboard:
 *   - ASN: entries store `asn` as "AS15169" but asn_hits rows render the bare
 *     number, so the equality filter had to compare "AS15169" === "15169".
 *   - Path: entries have NO `path` field (the parser produces `url`), while the
 *     Top Paths table lists path *segments* ("/products").
 */

const REAL_LOG = [
  '8.8.8.8 - - [20/Sep/2026:10:15:00 +0000] "GET /products HTTP/2.0" 200 4520 "-" "Mozilla/5.0"',
  '1.1.1.1 - - [20/Sep/2026:10:15:05 +0000] "POST /api/login HTTP/1.1" 401 233 "https://example.com/login" "Mozilla/5.0"',
  '13.107.42.14 - - [20/Sep/2026:10:15:11 +0000] "GET /admin HTTP/1.1" 404 153 "-" "curl/8.4.0"',
  '208.67.222.222 - - [20/Sep/2026:10:15:20 +0000] "GET /products HTTP/2.0" 200 4611 "-" "Mozilla/5.0"',
  '185.199.108.153 - - [20/Sep/2026:10:15:33 +0000] "GET /checkout HTTP/1.1" 500 892 "https://example.com/cart" "Mozilla/5.0"',
  '8.8.4.4 - - [20/Sep/2026:10:15:41 +0000] "GET /static/app.js HTTP/2.0" 304 0 "https://example.com/" "Mozilla/5.0"',
  '1.0.0.1 - - [20/Sep/2026:10:15:58 +0000] "GET /wp-admin HTTP/1.1" 404 153 "-" "python-requests/2.31.0"',
  '13.107.42.15 - - [20/Sep/2026:10:16:04 +0000] "DELETE /api/users/9 HTTP/1.1" 403 88 "-" "Mozilla/5.0"',
  '8.8.8.8 - - [20/Sep/2026:10:16:12 +0000] "GET /products HTTP/2.0" 200 4702 "-" "Mozilla/5.0"',
  '208.67.222.222 - - [20/Sep/2026:10:16:30 +0000] "GET /.env HTTP/1.1" 404 153 "-" "python-requests/2.31.0"',
].join('\n');

/** x20 = 200 lines; enough rows to draw real charts. */
const BUILD_LOG = Array.from({ length: 20 }, () => REAL_LOG).join('\n');

/** 8.8.8.8 + 8.8.4.4 are AS15169 (Google) and alone account for 60 of 180. */
const GOOGLE_ASN_HITS = 60;

async function analyzeRealLog(page: any) {
  await page.goto('/nginx', { waitUntil: 'load' });
  await page.waitForFunction(
    () => ['LogParser', 'Analyzer', 'Dashboard', 'GeoIP', 'BotDetector'].every((g) => !!(window as any)[g]),
    undefined,
    { timeout: 45_000 },
  );
  await page.getByRole('tab', { name: 'Paste logs' }).click();
  await page.fill('#nginx-logtext', BUILD_LOG);
  await page.click('#nginx-analyze-btn');
  await expect(page.locator('#nginx-dashboard')).toBeVisible({ timeout: 45_000 });
  await expect(page.locator('.kpi-micro-card .stat-value').first()).toBeVisible();
  await page.waitForTimeout(600);
}

/** The top-line card is Total Requests. */
const totalRequests = (page: any) =>
  page.locator('.kpi-micro-card .stat-value').first().innerText();

test.describe('Cross-filter table rows', () => {
  test.beforeEach(async ({ page }) => {
    await analyzeRealLog(page);
  });

  test('clicking an ASN row narrows the dashboard instead of blanking it', async ({ page }) => {
    const before = Number((await totalRequests(page)).replace(/,/g, ''));
    expect(before).toBe(180);

    const asnRows = page.locator('.cross-filter-asn-row');
    await expect(asnRows.first()).toBeVisible();

    // The rows carry the BARE ASN number.
    const attr = await asnRows.first().getAttribute('data-asn');
    expect(attr).toMatch(/^\d+$/);

    await asnRows.first().click();

    // Regression guard: the bug rendered every KPI as 0 and emptied all tables.
    await expect
      .poll(async () => Number((await totalRequests(page)).replace(/,/g, '')), {
        message: 'dashboard must still be populated after an ASN cross-filter',
      })
      .toBe(GOOGLE_ASN_HITS);

    // Downstream tables must not be wiped either.
    await expect(page.locator('.cross-filter-ip-row').first()).toBeVisible();
  });

  test('clicking a path row narrows the dashboard instead of blanking it', async ({ page }) => {
    const before = Number((await totalRequests(page)).replace(/,/g, ''));
    expect(before).toBe(180);

    // "/products" appears 3x per 10-line block => 60 of 180.
    await page.locator('.cross-filter-path-row[data-path="=/products"]').click();

    await expect
      .poll(async () => Number((await totalRequests(page)).replace(/,/g, '')), {
        message: 'dashboard must still be populated after a path cross-filter',
      })
      .toBe(60);

    await expect(page.locator('.cross-filter-ip-row').first()).toBeVisible();
  });

  test('the ASN dropdown is ordered by hits, descending', async ({ page }) => {
    const opts = await page
      .locator('#filter-asn option')
      .evaluateAll((els) =>
        els.map((e) => ({ value: (e as HTMLOptionElement).value, label: e.textContent || '' })),
      );

    expect(opts[0].value).toBe('all');
    const asns = opts.slice(1);
    expect(asns.length).toBeGreaterThan(1);

    // The label must not double up the prefix ("ASAS15169").
    expect(asns.map((o) => o.value)).not.toContain('ASAS15169');

    // Highest-hit ASN first, matching the "All Paths" dropdown's shape
    // ("/products (60)"). Parse the count back out of the rendered label.
    const counts = asns.map((o) => {
      const m = o.label.match(/\(([\d,]+)\)\s*$/);
      expect(m, `ASN option is missing its hit count: ${o.label}`).not.toBeNull();
      return Number((m as RegExpMatchArray)[1].replace(/,/g, ''));
    });
    expect(counts).toEqual([...counts].sort((a, b) => b - a));
    expect(counts[0]).toBe(GOOGLE_ASN_HITS);
  });

  test('the path dropdown is populated from entry URLs, highest hits first', async ({ page }) => {
    const opts = await page
      .locator('#filter-path-select option')
      .evaluateAll((els) =>
        els.map((e) => ({ value: (e as HTMLOptionElement).value, label: e.textContent || '' })),
      );

    // Was permanently just ['all'] because getFilterOptions() read e.path,
    // a field the parser never sets.
    // Options are site sections; `^` selects everything under one.
    expect(opts.map((o) => o.value)).toContain('^/products');

    const counts = opts.slice(1).map((o) => Number(o.label.match(/\(([\d,]+)\)\s*$/)?.[1].replace(/,/g, '')));
    expect(counts).toEqual([...counts].sort((a, b) => b - a));
  });

  test('country cross-filter keeps the dashboard populated', async ({ page }) => {
    const values = await page
      .locator('#filter-country option')
      .evaluateAll((els) => els.map((e) => (e as HTMLOptionElement).value));
    expect(values).toContain('United States');

    await page.selectOption('#filter-country', 'United States');
    await expect
      .poll(async () => Number((await totalRequests(page)).replace(/,/g, '')))
      .toBeGreaterThan(0);
  });

  test('the country dropdown is ordered by hits, descending', async ({ page }) => {
    const opts = await page
      .locator('#filter-country option')
      .evaluateAll((els) =>
        els.map((e) => ({ value: (e as HTMLOptionElement).value, label: e.textContent || '' })),
      );

    expect(opts[0].value).toBe('all');
    // The value must stay the bare country name — selectOption('United States')
    // and applyFilters()'s equality check both key off it.
    expect(opts[1].value).toBe('United States');
    // ...with the count carried in the label only.
    expect(opts[1].label).toMatch(/^United States \(\d[\d,]*\)$/);

    const counts = opts.slice(1).map((o) => Number(o.label.match(/\(([\d,]+)\)\s*$/)?.[1].replace(/,/g, '')));
    expect(counts.every((c) => Number.isFinite(c))).toBe(true);
    expect(counts).toEqual([...counts].sort((a, b) => b - a));
  });

  test('the ASN dropdown selection still filters (prefixed values)', async ({ page }) => {
    // Guards against a "fix" that broke the previously-working select path.
    await page.selectOption('#filter-asn', 'AS15169');
    await expect
      .poll(async () => Number((await totalRequests(page)).replace(/,/g, '')))
      .toBe(GOOGLE_ASN_HITS);
  });

  test('clicking the same ASN row twice clears the filter', async ({ page }) => {
    const row = page.locator('.cross-filter-asn-row').first();

    await row.click();
    await expect.poll(async () => Number((await totalRequests(page)).replace(/,/g, ''))).toBe(GOOGLE_ASN_HITS);

    // The row handler must store the PREFIXED form, otherwise the toggle-off
    // comparison never matches and the second click is a no-op.
    await row.click();
    await expect
      .poll(async () => Number((await totalRequests(page)).replace(/,/g, '')), {
        message: 'second click on the same ASN row must restore the full 180',
      })
      .toBe(180);
  });

  test('an ASN row click is reflected in the ASN dropdown', async ({ page }) => {
    await page.locator('.cross-filter-asn-row').first().click();
    await expect
      .poll(async () => totalRequests(page))
      .toBe(String(GOOGLE_ASN_HITS));

    // Guards the same prefix mismatch in the `selected` attribute: the select
    // used to sit on "All ASNs" while an ASN filter was demonstrably active.
    const selected = await page
      .locator('#filter-asn')
      .evaluate((el) => (el as HTMLSelectElement).selectedOptions[0]?.value);
    expect(selected).toBe('AS15169');
  });
});
