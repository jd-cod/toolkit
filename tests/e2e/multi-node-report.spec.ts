import { test, expect, gotoAnalyzedDashboard } from './fixtures/dashboard';

test.describe('Multi-Node Report & Share Verification', () => {
  test('downloads self-contained offline HTML report with multi-node metrics', async ({ page }) => {
    await gotoAnalyzedDashboard(page);

    // Initial total
    const initialText = await page.locator('.kpi-card-total .stat-value').textContent();
    const initialTotal = parseInt((initialText || '0').replace(/,/g, ''), 10);

    // Open Add More Logs modal
    await page.locator('#dash-add-logs-btn').click();
    await expect(page.locator('#add-logs-modal')).toBeVisible();

    // Switch to Paste tab and append node 2 logs
    await page.locator('#add-logs-tab-paste').click();
    const additionalLogs = [
      '203.0.113.199 - - [20/Sep/2026:10:20:00 +0000] "GET /node2-api HTTP/1.1" 200 1024 "-" "curl/8.0"',
      '203.0.113.200 - - [20/Sep/2026:10:20:01 +0000] "POST /node2-login HTTP/1.1" 200 512 "-" "curl/8.0"',
      '203.0.113.201 - - [20/Sep/2026:10:20:02 +0000] "GET /node2-status HTTP/1.1" 500 256 "-" "curl/8.0"',
    ].join('\n') + '\n';

    await page.locator('#add-logs-paste-text').fill(additionalLogs);
    await page.locator('#btn-append-paste').click();

    await expect(page.locator('#add-logs-modal')).toBeHidden();

    // Assert total requests incremented by 3
    const updatedText = await page.locator('.kpi-card-total .stat-value').textContent();
    const updatedTotal = parseInt((updatedText || '0').replace(/,/g, ''), 10);
    expect(updatedTotal).toBe(initialTotal + 3);

    // Open Download Report modal
    await page.locator('#dash-download-btn').click();
    await expect(page.locator('#download-modal-backdrop')).toBeVisible();

    // Trigger HTML report generation and intercept download
    const downloadPromise = page.waitForEvent('download');
    await page.locator('#dl-start-btn').click();
    const download = await downloadPromise;

    expect(download.suggestedFilename()).toMatch(/^nginx-report-.*\.html$/);

    // Read downloaded content
    const stream = await download.createReadStream();
    const chunks: Buffer[] = [];
    for await (const chunk of stream) {
      chunks.push(Buffer.from(chunk));
    }
    const html = Buffer.concat(chunks).toString('utf-8');

    // Assert HTML contains multi-node cluster indication and updated total requests
    expect(html).toContain(updatedTotal.toLocaleString());
    expect(html).toContain('Multi-Node Cluster');
  });

  test('enforces zero-retention policy for terminal cURL ingest sessions on share attempt', async ({ page }) => {
    const sessionId = 'test-term-zero-retention';

    // Mock terminal ingest session endpoints to avoid external R2 dependencies in dev
    await page.route(`**/api/ingest/${sessionId}/meta`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          sessionId,
          compressedSize: 500,
          decompressedSize: 1000,
          lineCount: 2,
          expiresAt: new Date(Date.now() + 900000).toISOString(),
        }),
      });
    });

    await page.route(`**/api/ingest/${sessionId}`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'text/plain',
        body: [
          '203.0.113.50 - - [20/Sep/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 4500 "-" "curl/8.0"',
          '203.0.113.51 - - [20/Sep/2026:10:00:01 +0000] "POST /api/login HTTP/1.1" 401 200 "-" "curl/8.0"',
        ].join('\n') + '\n',
      });
    });

    await page.route(`**/api/ingest/${sessionId}/purge`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true, purged: true }),
      });
    });

    // Open dashboard with terminal ingest session
    await page.goto(`/nginx?session=${sessionId}`, { waitUntil: 'domcontentloaded' });
    await expect(page.locator('#nginx-dashboard')).toBeVisible({ timeout: 45_000 });

    // Setup dialog handler to verify zero-retention notice alert
    let dialogMessage = '';
    page.once('dialog', async (dialog) => {
      dialogMessage = dialog.message();
      await dialog.accept();
    });

    // Click Share button
    await page.locator('#dash-share-btn').click();

    // Assert dialog alerted with zero-retention message
    expect(dialogMessage).toContain('Zero-Data Retention');
    expect(dialogMessage).toContain('Download Report');

    // Assert share modal was NOT opened
    await expect(page.locator('#share-modal-backdrop')).toBeHidden();
  });
});
