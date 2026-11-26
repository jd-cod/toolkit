import { test, expect, gotoAnalyzedDashboard } from './fixtures/dashboard';

/**
 * Cross-filter interactions on the Option 2 dashboard.
 *
 * These are the behaviours most easily broken by a layout refactor, because the
 * floating clear button is styled via inline `display` rather than a class.
 */

test.describe('Cross-filtering', () => {
  test.beforeEach(async ({ page }) => {
    await gotoAnalyzedDashboard(page);
  });

  test('shows the floating Clear button once a filter is active', async ({ page }) => {
    // toBeVisible() rather than reading .style.display: it accounts for the
    // element being detached, hidden by an ancestor, or zero-sized.
    await expect(page.locator('#floating-clear-filters-btn')).toBeHidden();

    await page.fill('#filter-ip', '66.249.66.1');

    await expect(page.locator('#floating-clear-filters-btn')).toBeVisible();
  });

  test('floating Clear button resets all active filters', async ({ page }) => {
    await page.fill('#filter-ip', '66.249.66.1');
    await expect(page.locator('#floating-clear-filters-btn')).toBeVisible();

    await page.click('#floating-clear-filters-btn');

    await expect(page.locator('#filter-ip')).toHaveValue('');
    await expect(page.locator('#floating-clear-filters-btn')).toBeHidden();
  });

  test('IP filter narrows the visible bot rows', async ({ page }) => {
    const bots = page.locator('.cross-filter-bot-row');
    const before = await bots.count();
    expect(before).toBeGreaterThan(0);

    // 66.249.66.x is Googlebot traffic; the sample log has no other client on
    // that subnet, so the filtered set must be strictly smaller.
    await page.fill('#filter-ip', '66.249.66.1');

    await expect(bots.first()).toBeVisible();
    await expect
      .poll(async () => bots.count(), { message: 'bot rows should narrow after IP filter' })
      .toBeLessThan(before);
  });

  test('filtering by a non-matching IP yields an empty result set without errors', async ({ page }) => {
    await page.fill('#filter-ip', '203.0.113.200'); // present subnet, absent host

    // Must degrade gracefully: no crash, and the reset path stays available.
    await expect(page.locator('#floating-clear-filters-btn')).toBeVisible();
    await page.click('#floating-clear-filters-btn');
    await expect(page.locator('#filter-ip')).toHaveValue('');
  });
});
