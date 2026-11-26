import { test, expect, waitForEngineReady } from './fixtures/dashboard';
import { existsSync } from 'fs';
import path from 'path';

const SAMPLE = path.resolve(
  __dirname,
  '../../frontend/public/samples/multi-vector-attack.log',
);

test.describe('Log Explorer Pagination & Worker Cross-Filtering', () => {
  test.skip(!existsSync(SAMPLE), `sample log not present at ${SAMPLE}`);

  test.beforeEach(async ({ page }) => {
    await page.goto('/nginx', { waitUntil: 'load' });
    await waitForEngineReady(page);
    await page.setInputFiles('#nginx-logfile', SAMPLE);
    await page.click('#nginx-analyze-btn');
    await expect(page.locator('#nginx-dashboard')).toBeVisible({ timeout: 120_000 });
  });

  test('renders Log Explorer with 50 rows and pagination controls', async ({ page }) => {
    const explorer = page.locator('#nginx-log-explorer');
    await expect(explorer).toBeVisible();

    const rows = explorer.locator('#explorer-rows-body tr');
    await expect(rows).toHaveCount(25); // default per-page

    const pagWrap = page.locator('#explorer-pagination-wrap');
    await expect(pagWrap).toBeVisible();

    // Check First, Prev, Next, Last buttons
    const prevBtn = page.locator('#exp-prev-btn');
    const nextBtn = page.locator('#exp-next-btn');
    const firstBtn = page.locator('#exp-first-btn');
    const lastBtn = page.locator('#exp-last-btn');

    await expect(prevBtn).toBeVisible();
    await expect(nextBtn).toBeVisible();
    await expect(firstBtn).toBeVisible();
    await expect(lastBtn).toBeVisible();

    // On page 1, First and Prev must be disabled
    await expect(firstBtn).toBeDisabled();
    await expect(prevBtn).toBeDisabled();
    await expect(nextBtn).toBeEnabled();
    await expect(lastBtn).toBeEnabled();

    // Page indicator
    await expect(pagWrap).toContainText('Page 1 of');

    // Click Next
    await nextBtn.click();
    await expect(pagWrap).toContainText('Page 2 of');
    await expect(firstBtn).toBeEnabled();
    await expect(prevBtn).toBeEnabled();

    // Click Prev
    await prevBtn.click();
    await expect(pagWrap).toContainText('Page 1 of');
    await expect(firstBtn).toBeDisabled();
    await expect(prevBtn).toBeDisabled();
  });

  test('navigates to Last page and back to First page', async ({ page }) => {
    const lastBtn = page.locator('#exp-last-btn');
    const firstBtn = page.locator('#exp-first-btn');
    const nextBtn = page.locator('#exp-next-btn');
    const pagWrap = page.locator('#explorer-pagination-wrap');

    await lastBtn.click();
    await expect(nextBtn).toBeDisabled();
    await expect(lastBtn).toBeDisabled();
    await expect(firstBtn).toBeEnabled();

    await firstBtn.click();
    await expect(pagWrap).toContainText('Page 1 of');
    await expect(firstBtn).toBeDisabled();
  });

  test('changes rows per page to 50', async ({ page }) => {
    const select = page.locator('#explorer-per-page');
    await select.selectOption('50');

    const rows = page.locator('#explorer-rows-body tr');
    await expect(rows).toHaveCount(50);
  });
});
