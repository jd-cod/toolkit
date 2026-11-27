import { test, expect, gotoAnalyzedDashboard } from './fixtures/dashboard';

/**
 * Core render contract for the single-page Signal dashboard.
 *
 * Ported from scripts/qa_new_ui2_tests.mjs. Every assertion here reads the
 * rendered DOM — a passing API response with a blank dashboard fails these.
 */

test.describe('Dashboard structure', () => {
  test.beforeEach(async ({ page }) => {
    await gotoAnalyzedDashboard(page);
  });

  test('top action bar exposes New Analysis, Download and Share', async ({ page }) => {
    // getByRole over #id: survives a className restyle, still matches the
    // accessible name the user actually sees.
    await expect(page.getByRole('button', { name: /new analysis/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /download/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /share/i })).toBeVisible();
  });

  test('renders all 8 micro KPI cards', async ({ page }) => {
    await expect(page.locator('.kpi-micro-card')).toHaveCount(8);
  });

  test('the traffic KPI cards add up to the total', async ({ page }) => {
    const number = async (selector: string) =>
      Number(((await page.locator(selector).textContent()) || '').replace(/[^0-9]/g, ''));
    const total = await number('.kpi-card-total .stat-value');
    const human = Number(
      ((await page.locator('.kpi-card-human').getAttribute('title')) || '').match(/^[\d,]+/)?.[0].replace(/,/g, ''),
    );
    const verified = await number('.kpi-card-verified .stat-value');
    const spoofed = await number('.kpi-card-spoofed .stat-value');
    const other = await number('.kpi-card-otherbots .stat-value');

    expect(total).toBeGreaterThan(0);
    expect(human + verified + spoofed + other).toBe(total);
  });

  test('renders the HTTP methods and bandwidth ribbon', async ({ page }) => {
    const ribbon = page.locator('.methods-bandwidth-ribbon');
    await expect(ribbon).toBeVisible();
    await expect(ribbon).toContainText('Data Egress');
  });

  test('renders the timeline scrubber with both tactile handles', async ({ page }) => {
    await expect(page.locator('.slider-handle')).toHaveCount(2);
  });

  test('mounts the request-rate canvas', async ({ page }) => {
    await expect(page.locator('#rps-chart')).toBeAttached();
  });

  test('mounts the country and ASN distribution charts', async ({ page }) => {
    await expect(page.locator('#country-chart')).toBeVisible();
    await expect(page.locator('#asn-chart')).toBeVisible();
  });

  test('shows all incident cards in the original three-column dashboard without result tabs', async ({ page }) => {
    await page.setViewportSize({ width: 1600, height: 1000 });
    const dashboard = page.locator('#nginx-dashboard');
    await expect(dashboard.getByRole('tablist')).toHaveCount(0);
    await expect(dashboard.getByRole('tabpanel')).toHaveCount(0);
    const columns = dashboard.locator('.incident-matrix-col');
    await expect(columns).toHaveCount(3);
    const cards = dashboard.locator('.incident-3col-grid .card-table-wrap');
    await expect(cards).toHaveCount(6);
    for (const card of await cards.all()) await expect(card).toBeVisible();
    const positions = await columns.evaluateAll(elements => elements.map(el => ({ x: el.getBoundingClientRect().x, y: el.getBoundingClientRect().y })));
    expect(positions[0].x).toBeLessThan(positions[1].x);
    expect(positions[1].x).toBeLessThan(positions[2].x);
    expect(positions[0].y).toBe(positions[1].y);
    expect(positions[1].y).toBe(positions[2].y);
  });

  test('populates the Top Bot Intelligence table', async ({ page }) => {
    const rows = page.locator('.cross-filter-bot-row');
    await expect(rows.first()).toBeVisible();
    expect(await rows.count()).toBeGreaterThan(0);
  });

  test('mounts the AbuseIPDB Top 10 scan control', async ({ page }) => {
    // The live control is #btn-center-scan-abuse on a centered overlay.
    // #btn-scan-abuseipdb is deliberately left in the DOM with display:none
    // "for backwards compat" (dashboard.js:468) — assert on the real one.
    await expect(page.locator('#btn-center-scan-abuse')).toBeVisible();

    // Guard the assumption above, so a future removal of the overlay button
    // doesn't silently leave us testing the dead one again.
    await expect(page.locator('#btn-scan-abuseipdb')).toBeHidden();
  });

  test('populates the Top ASNs table', async ({ page }) => {
    const rows = page.locator('.cross-filter-asn-row');
    await expect(rows.first()).toBeVisible();
    expect(await rows.count()).toBeGreaterThan(0);
  });

  test('exposes subnet and path search in the log explorer', async ({ page }) => {
    await expect(page.locator('#log-table-ip-subnet-search')).toBeVisible();
    await expect(page.locator('#log-table-path-search')).toBeVisible();
  });

  test('contains zero Stage 2 / mitigation markup', async ({ page }) => {
    // Asserted by absence. This is the "removed, not just hidden" guard — a
    // leftover-but-display:none section would be a regression.
    await expect(page.locator('#stage-mitigate')).toHaveCount(0);
    await expect(page.locator('.hero-dual-grid')).toHaveCount(0);
  });

  test('completes analysis with zero console errors', async ({ page, console: watcher }) => {
    watcher.assertClean();
    // Sanity: we are actually looking at a rendered dashboard, not a blank page.
    await expect(page.locator('#nginx-dashboard')).toBeVisible();
  });
});
