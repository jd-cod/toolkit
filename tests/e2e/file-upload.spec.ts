import { test, expect, waitForEngineReady } from './fixtures/dashboard';
import { existsSync } from 'fs';
import path from 'path';

/**
 * File-upload ingestion path, including drag-and-drop filename feedback.
 *
 * Ported from scripts/qa_new_ui_30_tests.mjs. This exercises a route the rest
 * of the suite does not: the real 50,000-line sample, a genuine
 * `setInputFiles` upload, and the Web Worker parse path. Everything else in
 * tests/e2e pastes text into the textarea, which skips the upload and worker
 * code entirely.
 */

const SAMPLE = path.resolve(
  __dirname,
  '../../frontend/public/samples/multi-vector-attack.log',
);

test.describe('File upload ingestion', () => {
  // The sample is a committed fixture, so this should always exist — but a
  // missing 8 MB fixture should skip, not fail, a run on a partial checkout.
  test.skip(!existsSync(SAMPLE), `sample log not present at ${SAMPLE}`);

  test.beforeEach(async ({ page }) => {
    await page.goto('/nginx', { waitUntil: 'load' });
    await waitForEngineReady(page);
  });

  test('uploads a 50,000-line log and renders the dashboard', async ({ page }) => {
    await page.setInputFiles('#nginx-logfile', SAMPLE);

    // The dropzone reflects the chosen file before analysis is triggered.
    await expect(page.locator('#nginx-dropzone-filename')).toContainText(
      'multi-vector-attack.log',
    );

    await page.click('#nginx-analyze-btn');

    // 50k lines takes meaningfully longer than the in-memory sample, and runs
    // through a Web Worker — allow well over the default budget.
    await expect(page.locator('#nginx-dashboard')).toBeVisible({ timeout: 120_000 });
    await expect(page.locator('.kpi-micro-card').first()).toBeVisible();

    // A real 50k-line dataset must populate every table, not just mount it.
    await expect(page.locator('.cross-filter-bot-row').first()).toBeVisible();
    await expect(page.locator('.cross-filter-asn-row').first()).toBeVisible();
  });

  test('completes a large upload with zero console errors', async ({ page, console: watcher }) => {
    await page.setInputFiles('#nginx-logfile', SAMPLE);
    await page.click('#nginx-analyze-btn');
    await expect(page.locator('#nginx-dashboard')).toBeVisible({ timeout: 120_000 });

    watcher.assertClean();
  });
});
