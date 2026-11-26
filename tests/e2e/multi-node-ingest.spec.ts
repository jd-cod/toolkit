import { test, expect, gotoAnalyzedDashboard } from './fixtures/dashboard';

test.describe('Multi-Node Ingest & Log Merging Workflow', () => {
  test('displays "Add More Logs" button and opens multi-tab append modal', async ({ page }) => {
    await gotoAnalyzedDashboard(page);

    const addLogsBtn = page.locator('#dash-add-logs-btn');
    await expect(addLogsBtn).toBeVisible();
    await expect(addLogsBtn).toContainText('Add More Logs');

    // Click to open modal
    await addLogsBtn.click();
    const modal = page.locator('#add-logs-modal');
    await expect(modal).toBeVisible();

    // Verify 4 tabs exist
    await expect(page.locator('#add-logs-tab-curl')).toBeVisible();
    await expect(page.locator('#add-logs-tab-file')).toBeVisible();
    await expect(page.locator('#add-logs-tab-paste')).toBeVisible();
    await expect(page.locator('#add-logs-tab-url')).toBeVisible();

    // Close modal
    await page.locator('#add-logs-modal-close').click();
    await expect(modal).toBeHidden();
  });

  test('appends additional logs via Paste tab and increments total requests', async ({ page }) => {
    await gotoAnalyzedDashboard(page);

    const initialTotalText = await page.locator('.kpi-card-total .stat-value').textContent();
    const initialTotal = parseInt((initialTotalText || '0').replace(/,/g, ''), 10);
    expect(initialTotal).toBeGreaterThan(0);

    // Open Add More Logs modal
    await page.locator('#dash-add-logs-btn').click();
    await expect(page.locator('#add-logs-modal')).toBeVisible();

    // Switch to Paste tab
    await page.locator('#add-logs-tab-paste').click();
    const appendTextarea = page.locator('#add-logs-paste-text');
    await expect(appendTextarea).toBeVisible();

    const additionalLogs = [
      '203.0.113.199 - - [20/Sep/2026:10:20:00 +0000] "GET /node2-api HTTP/1.1" 200 1024 "-" "curl/8.0"',
      '203.0.113.200 - - [20/Sep/2026:10:20:01 +0000] "POST /node2-login HTTP/1.1" 200 512 "-" "curl/8.0"',
      '203.0.113.201 - - [20/Sep/2026:10:20:02 +0000] "GET /node2-status HTTP/1.1" 500 256 "-" "curl/8.0"',
    ].join('\n') + '\n';

    await appendTextarea.fill(additionalLogs);
    await page.locator('#btn-append-paste').click();

    // Modal should close or show success and dashboard updates
    await expect(page.locator('#add-logs-modal')).toBeHidden({ timeout: 15_000 });

    // Assert total count updated by 3
    const updatedTotalText = await page.locator('.kpi-card-total .stat-value').textContent();
    const updatedTotal = parseInt((updatedTotalText || '0').replace(/,/g, ''), 10);
    expect(updatedTotal).toBe(initialTotal + 3);

    // Verify source badge reflects merged nodes
    const sourceBadge = page.locator('#dash-source-badge');
    await expect(sourceBadge).toBeVisible();
    await expect(sourceBadge).toContainText('2 nodes');
  });

  test('manages FIFO approval queue with Accept & Merge and Discard', async ({ page }) => {
    // Intercept backend queue endpoints to test multi-chunk approval workflow
    const testSession = 'test-e2e-session';
    let queueItems = [
      {
        chunkId: 'chunk-2',
        compressedSize: 2048,
        decompressedSize: 10240,
        lineCount: 50,
        uploadedAt: Date.now() - 60000,
      },
      {
        chunkId: 'chunk-3',
        compressedSize: 4096,
        decompressedSize: 20480,
        lineCount: 100,
        uploadedAt: Date.now() - 30000,
      }
    ];

    await page.route(`**/api/ingest/${testSession}/queue`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true, sessionId: testSession, chunks: queueItems })
      });
    });

    await page.route(`**/api/ingest/${testSession}/chunk/chunk-2`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          sessionId: testSession,
          chunkId: 'chunk-2',
          downloadUrl: `http://localhost:3000/mock-chunk-2.log`
        })
      });
    });

    await page.route(`**/mock-chunk-2.log`, async (route) => {
      const logs = [
        '198.51.100.50 - - [20/Sep/2026:10:25:00 +0000] "GET /chunk2-item HTTP/1.1" 200 1024 "-" "curl/8.0"',
        '198.51.100.51 - - [20/Sep/2026:10:25:01 +0000] "GET /chunk2-item2 HTTP/1.1" 200 1024 "-" "curl/8.0"',
      ].join('\n') + '\n';
      await route.fulfill({ status: 200, contentType: 'text/plain', body: logs });
    });

    await page.route(`**/api/ingest/${testSession}/chunk/chunk-2/purge`, async (route) => {
      queueItems = queueItems.filter(q => q.chunkId !== 'chunk-2');
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: true, purged: true }) });
    });

    await page.route(`**/api/ingest/${testSession}/chunk/chunk-3/discard`, async (route) => {
      queueItems = queueItems.filter(q => q.chunkId !== 'chunk-3');
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: true, discarded: true }) });
    });

    await gotoAnalyzedDashboard(page);

    // Set active session on window for test
    await page.evaluate((sid) => {
      (window as any)._activeNginxSessionId = sid;
    }, testSession);

    // Open Add More Logs modal
    await page.locator('#dash-add-logs-btn').click();
    await expect(page.locator('#add-logs-modal')).toBeVisible();

    // With 2 items in queue, "Accept & Merge All" should be visible
    const mergeAllBtn = page.locator('#queue-merge-all-btn');
    await expect(mergeAllBtn).toBeVisible({ timeout: 10_000 });

    // Verify individual chunk cards rendered in FIFO order
    const chunkCards = page.locator('.queue-chunk-card');
    await expect(chunkCards).toHaveCount(2);
    await expect(chunkCards.first()).toContainText('chunk-2');

    // Click Merge on chunk-2
    await page.locator('#btn-merge-chunk-2').click();

    // After merge, chunk-2 is removed and chunk-3 remains
    await expect(page.locator('#btn-merge-chunk-2')).toBeHidden({ timeout: 10_000 });
    await expect(page.locator('.queue-chunk-card')).toHaveCount(1);
    await expect(page.locator('.queue-chunk-card').first()).toContainText('chunk-3');

    // With 1 item in queue, single "Accept & Merge" is shown on the card
    await expect(page.locator('#btn-merge-chunk-3')).toContainText('Accept & Merge');

    // Click Discard on chunk-3
    await page.locator('#btn-discard-chunk-3').click();

    // Queue is now empty
    await expect(page.locator('.queue-chunk-card')).toHaveCount(0);
    await expect(page.locator('#queue-empty-state')).toBeVisible();
  });

  test('ensures standard single-node visitors never poll queue', async ({ page }) => {
    let queuePollCount = 0;
    await page.route('**/api/ingest/**/queue', async (route) => {
      queuePollCount++;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true, chunks: [] })
      });
    });

    await gotoAnalyzedDashboard(page);

    // Stay on dashboard for 3 seconds without clicking "Add More Logs"
    await page.waitForTimeout(3000);

    expect(queuePollCount).toBe(0);
    await expect(page.locator('#dash-queue-badge')).toBeHidden();
    await expect(page.locator('#dash-ingest-toast')).toHaveCount(0);
  });

  test('detects incoming node chunk in background while modal is closed and renders floating toast', async ({ page }) => {
    const testSession = 'test-toast-bg-session';
    let queueItems: any[] = [];

    await page.route(`**/api/ingest/${testSession}/queue`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true, sessionId: testSession, chunks: queueItems })
      });
    });

    await gotoAnalyzedDashboard(page);

    await page.evaluate((sid) => {
      (window as any)._activeNginxSessionId = sid;
    }, testSession);

    // Engage multi-node mode by opening and closing modal
    await page.locator('#dash-add-logs-btn').click();
    await expect(page.locator('#add-logs-modal')).toBeVisible();
    await page.locator('#add-logs-modal-close').click();
    await expect(page.locator('#add-logs-modal')).toBeHidden();

    // Incoming chunk arrives from Node 3 while modal is closed
    queueItems = [
      {
        chunkId: 'chunk-3',
        compressedSize: 3072,
        decompressedSize: 15360,
        lineCount: 75,
        uploadedAt: Date.now(),
      }
    ];

    // Trigger tab visibility event to poll immediately
    await page.evaluate(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });

    const toast = page.locator('#dash-ingest-toast');
    const badge = page.locator('#dash-queue-badge');

    await expect(badge).toBeVisible({ timeout: 10_000 });
    await expect(badge).toHaveText('1');
    await expect(toast).toBeVisible();
    await expect(toast).toContainText('New Node Log Available');
    await expect(toast).toContainText('chunk-3');
    await expect(page.locator('#toast-merge-btn')).toBeVisible();
  });

  test('merges chunk directly from floating toast in 1 click and updates metrics', async ({ page }) => {
    const testSession = 'test-toast-merge-session';
    let queueItems = [
      {
        chunkId: 'chunk-node3',
        compressedSize: 2048,
        decompressedSize: 8192,
        lineCount: 10,
        uploadedAt: Date.now(),
      }
    ];

    await page.route(`**/api/ingest/${testSession}/queue`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true, sessionId: testSession, chunks: queueItems })
      });
    });

    await page.route(`**/api/ingest/${testSession}/chunk/chunk-node3`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          sessionId: testSession,
          chunkId: 'chunk-node3',
          downloadUrl: 'http://localhost:3000/mock-chunk-node3.log'
        })
      });
    });

    await page.route('**/mock-chunk-node3.log', async (route) => {
      const logs = [
        '203.0.113.100 - - [20/Sep/2026:10:30:00 +0000] "GET /from-toast HTTP/1.1" 200 1024 "-" "curl/8.0"',
      ].join('\n') + '\n';
      await route.fulfill({ status: 200, contentType: 'text/plain', body: logs });
    });

    await page.route(`**/api/ingest/${testSession}/chunk/chunk-node3/purge`, async (route) => {
      queueItems = [];
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: true, purged: true }) });
    });

    await gotoAnalyzedDashboard(page);

    const initialTotalText = await page.locator('.kpi-card-total .stat-value').textContent();
    const initialTotal = parseInt((initialTotalText || '0').replace(/,/g, ''), 10);

    await page.evaluate((sid) => {
      (window as any)._activeNginxSessionId = sid;
    }, testSession);

    // Engage multi-node session
    await page.locator('#dash-add-logs-btn').click();
    await page.locator('#add-logs-modal-close').click();

    // Trigger tab visibility change to poll immediately
    await page.evaluate(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });

    const toast = page.locator('#dash-ingest-toast');
    await expect(toast).toBeVisible({ timeout: 10_000 });
    await expect(toast).toContainText('chunk-node3');

    // Click "Accept & Merge" directly on toast
    await page.locator('#toast-merge-btn').click();

    // Toast should dismiss after merge
    await expect(toast).toBeHidden({ timeout: 10_000 });

    // Metric should increment by 1
    const updatedTotalText = await page.locator('.kpi-card-total .stat-value').textContent();
    const updatedTotal = parseInt((updatedTotalText || '0').replace(/,/g, ''), 10);
    expect(updatedTotal).toBe(initialTotal + 1);

    // Source badge updates to 2 nodes
    await expect(page.locator('#dash-source-badge')).toContainText('2 nodes');
  });

  test('dismisses toast notification via [x] but keeps queue badge visible', async ({ page }) => {
    const testSession = 'test-toast-dismiss-session';
    const queueItems = [
      {
        chunkId: 'chunk-dismiss',
        compressedSize: 1024,
        decompressedSize: 4096,
        lineCount: 5,
        uploadedAt: Date.now(),
      }
    ];

    await page.route(`**/api/ingest/${testSession}/queue`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true, sessionId: testSession, chunks: queueItems })
      });
    });

    await gotoAnalyzedDashboard(page);

    await page.evaluate((sid) => {
      (window as any)._activeNginxSessionId = sid;
    }, testSession);

    await page.locator('#dash-add-logs-btn').click();
    await page.locator('#add-logs-modal-close').click();

    await page.evaluate(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });

    const toast = page.locator('#dash-ingest-toast');
    const badge = page.locator('#dash-queue-badge');
    await expect(toast).toBeVisible({ timeout: 10_000 });
    await expect(badge).toBeVisible();
    await expect(badge).toHaveText('1');

    // Dismiss toast
    await page.locator('#toast-close-btn').click();
    await expect(toast).toBeHidden();

    // Badge remains visible with count
    await expect(badge).toBeVisible();
    await expect(badge).toHaveText('1');
  });
});
