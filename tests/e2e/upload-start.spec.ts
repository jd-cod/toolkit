import { test, expect, waitForEngineReady } from './fixtures/dashboard';

/**
 * The upload/start state, before any analysis has run.
 *
 * Guards regressions from the recent "hide Try Sample bar / start elements on
 * the results view" work: these must be visible on first load and hidden only
 * after analysis.
 */

test.describe('Start page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/nginx', { waitUntil: 'load' });
  });

  test('starts in upload mode and exposes the textarea through Paste logs', async ({ page }) => {
    await waitForEngineReady(page);
    await expect(page.locator('#nginx-dropzone')).toBeVisible();
    await expect(page.locator('#nginx-logtext')).toBeHidden();
    await expect(page.locator('#nginx-analyze-btn')).toBeDisabled();
    await page.getByRole('tab', { name: 'Paste logs' }).click();
    await expect(page.locator('#nginx-logtext')).toBeVisible();
    await expect(page.locator('#nginx-analyze-btn')).toBeVisible();
  });

  test('shows cURL ingest as the second input option', async ({ page }) => {
    await waitForEngineReady(page);

    const tabs = page.getByRole('tab');
    await expect(tabs).toHaveCount(4);
    await expect(tabs.nth(0)).toContainText('Upload file');
    await expect(tabs.nth(1)).toContainText('cURL ingest');
    await expect(tabs.nth(2)).toContainText('Paste logs');
    await expect(tabs.nth(3)).toContainText('Remote URL');

    await page.getByRole('tab', { name: 'cURL ingest' }).click();
    const serverPanel = page.locator('#nginx-panel-server');
    await expect(serverPanel).toBeVisible();
    await expect(serverPanel).toContainText('Send logs with cURL');
    await expect(serverPanel).toContainText('/ingest');
    const copyButtons = serverPanel.locator('.btn-cli-copy');
    await expect(copyButtons).toHaveCount(2);
    await expect(serverPanel.locator('.signal-nginx-server-more')).toBeVisible();
    await copyButtons.first().click();
    await expect(copyButtons.first()).toContainText('Copied!');
    await expect(page.locator('.signal-nginx-options')).toBeHidden();
    await expect(page.locator('#nginx-analyze-btn')).toBeHidden();
    await expect(page.locator('#nginx-input-status')).toContainText('Run the command above');
  });

  test('keeps the dashboard hidden until analysis is triggered', async ({ page }) => {
    await expect(page.locator('#nginx-dashboard')).toBeHidden();
  });

  test('displays streaming engine capability without 400 MB limits', async ({ page }) => {
    await waitForEngineReady(page);
    const dropzoneDesc = page.locator('#nginx-dropzone-filename');
    await expect(dropzoneDesc).toBeVisible();
    await expect(dropzoneDesc).toContainText('Multi-gigabyte streaming support');
    await expect(dropzoneDesc).not.toContainText('400 MB');

    await page.getByRole('tab', { name: 'Remote URL' }).click();
    const urlNote = page.locator('#nginx-url-note');
    await expect(urlNote).toBeVisible();
    await expect(urlNote).not.toContainText('400 MB');
  });

  test('loads without console errors', async ({ page, console: watcher }) => {
    // Wait for the engine: a CDN/load failure logs a console error, and we
    // want this test to assert on a fully-booted page, not a half-loaded one.
    await waitForEngineReady(page);
    watcher.assertClean();
  });
});
