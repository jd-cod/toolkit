import { test, expect, SAMPLE_LOG, waitForEngineReady } from './fixtures/dashboard';
import { gzipSync } from 'node:zlib';

test('directory search and category filters retain enabled, configured ordering', async ({ page }) => {
  await page.route('**/api/site/config', async route => {
    const response = await route.fetch();
    const config = await response.json();
    config.tools = config.tools.map((tool: { tool_key: string }) => ({ ...tool, is_enabled: tool.tool_key === 'nginx' ? 0 : 1 }));
    await route.fulfill({ json: config });
  });
  await page.goto('/');
  await expect(page.locator('#tool-grid .tool-card').first()).toBeVisible();
  await expect(page.locator('#tool-card-nginx')).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Analyze your logs' })).toHaveCount(0);
  await page.getByRole('searchbox', { name: 'Search tools', exact: true }).fill('password');
  await expect(page.locator('#tool-grid .tool-card')).toHaveCount(1);
  await expect(page.locator('#tool-card-password')).toHaveAttribute('href', '/password-generator');
  await page.getByRole('group', { name: 'Filter tools by category' }).getByRole('button', { name: /^Network/ }).click();
  await expect(page.getByRole('heading', { name: 'No tools found' })).toBeVisible();
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await expect(page.locator('#tool-card-password')).toBeVisible();
});

test('configuration errors can be retried and maintenance settings are respected', async ({ page }) => {
  let calls = 0;
  await page.route('**/api/site/config', async route => {
    if (++calls === 1) return route.fulfill({ status: 503, json: { error: 'Temporarily offline' } });
    const response = await route.fetch();
    const config = await response.json();
    config.settings.maintenance_mode = '1';
    config.settings.maintenance_message = 'Scheduled maintenance test';
    await route.fulfill({ json: config });
  });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Tool directory unavailable' })).toBeVisible();
  await page.getByRole('button', { name: 'Try again' }).click();
  await expect(page.getByRole('heading', { name: 'Under Maintenance' })).toBeVisible();
  await expect(page.getByText('Scheduled maintenance test')).toBeVisible();
  await expect(page.locator('#tool-grid')).toHaveCount(0);
});

test('keyboard tool search navigates and theme choice survives reload', async ({ page, console: watcher }) => {
  await page.goto('/');
  await expect(page.locator('#tool-card-dns')).toBeVisible();
  await page.keyboard.press('Control+k');
  const dialog = page.getByRole('dialog', { name: 'Find a tool', exact: true });
  await expect(dialog).toBeVisible();
  await page.getByLabel('Search all tools').fill('DNS');
  await dialog.getByRole('link', { name: 'DNS Lookup Network', exact: true }).click();
  await expect(page).toHaveURL(/\/dns$/);
  await expect(page.getByLabel('Domain name')).toBeVisible();
  await page.getByRole('button', { name: 'Toggle theme' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  watcher.assertClean();
});

test('mobile navigation supports Escape, restores focus, and opens a tool', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await expect(page.locator('#tool-card-dns')).toBeVisible();
  const opener = page.getByRole('button', { name: 'Open tool navigation' });
  await opener.click();
  const drawer = page.getByRole('dialog', { name: 'Tool navigation menu' });
  await expect(drawer).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(drawer).toBeHidden();
  await expect(opener).toBeFocused();
  await opener.click();
  await drawer.locator('a[href="/dns"]').click();
  await expect(page.getByLabel('Domain name')).toBeVisible();
  await expect(page.getByRole('dialog', { name: 'Tool navigation menu' })).toBeHidden();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('Nginx modes ignore stale URL and file drafts and retain paste text', async ({ page, console: watcher }) => {
  await page.goto('/nginx');
  await waitForEngineReady(page);
  await page.locator('#nginx-logfile').setInputFiles({ name: 'empty.log', mimeType: 'text/plain', buffer: Buffer.from('') });
  await page.getByRole('tab', { name: 'Remote URL' }).click();
  await page.locator('#nginx-gist-url').fill('https://example.invalid/stale.log');
  await page.getByRole('tab', { name: 'Paste logs' }).click();
  await page.locator('#nginx-logtext').fill(SAMPLE_LOG);
  await page.getByRole('button', { name: 'Analyze Logs', exact: true }).click();
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('9', { timeout: 45000 });
  await expect(page.locator('.signal-dashboard-source')).toContainText('Pasted logs');
  await page.getByRole('button', { name: 'New Analysis' }).click();
  await expect(page.locator('#nginx-logtext')).toHaveValue(SAMPLE_LOG);
  watcher.assertClean();
});

test('Nginx engine can be revisited through the sidebar without duplicate scripts', async ({ page, console: watcher }) => {
  await page.goto('/nginx');
  await waitForEngineReady(page);
  await page.locator('.signal-sidebar a[href="/dns"]').click();
  await expect(page.getByLabel('Domain name')).toBeVisible();
  await page.locator('.signal-sidebar a[href="/nginx"]').click();
  await waitForEngineReady(page);
  await page.getByRole('tab', { name: 'Paste logs' }).click();
  await page.locator('#nginx-logtext').fill(SAMPLE_LOG);
  await page.getByRole('button', { name: 'Analyze Logs', exact: true }).click();
  await expect(page.locator('#rps-chart')).toBeVisible({ timeout: 45000 });
  await expect(page.locator('script[src*="/js/dashboard.js"]')).toHaveCount(1);
  watcher.assertClean();
});

test('Nginx input tabs support keyboard navigation and invalid files explain the issue', async ({ page }) => {
  await page.goto('/nginx');
  await waitForEngineReady(page);
  await page.getByRole('tab', { name: 'Upload file' }).focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: 'cURL ingest' })).toBeFocused();
  await expect(page.locator('#nginx-panel-server')).toBeVisible();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: 'Paste logs' })).toBeFocused();
  await expect(page.locator('#nginx-logtext')).toBeVisible();
  await page.keyboard.press('End');
  await expect(page.getByRole('tab', { name: 'Remote URL' })).toBeFocused();
  await page.locator('#nginx-gist-url').fill('file:///etc/passwd');
  await expect(page.locator('#nginx-analyze-btn')).toBeDisabled();
  await expect(page.locator('#nginx-input-status')).toContainText('HTTP(S)');
  await page.getByRole('tab', { name: 'Upload file' }).click();
  await page.locator('#nginx-logfile').setInputFiles({ name: 'photo.png', mimeType: 'image/png', buffer: Buffer.from('not a log') });
  await expect(page.locator('#nginx-analyze-btn')).toBeDisabled();
  await expect(page.locator('#nginx-input-status')).toContainText('Choose .log');
});

test('Nginx combines raw and compressed files and keeps report and share controls usable', async ({ page, console: watcher }) => {
  await page.goto('/nginx');
  await waitForEngineReady(page);
  await page.locator('#nginx-logfile').setInputFiles([
    { name: 'access.log', mimeType: 'text/plain', buffer: Buffer.from(SAMPLE_LOG) },
    { name: 'rotation.LOG.GZ', mimeType: 'application/gzip', buffer: gzipSync(SAMPLE_LOG) },
  ]);
  await page.getByRole('button', { name: 'Analyze Logs', exact: true }).click();
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('18', { timeout: 45000 });
  await expect(page.locator('.signal-dashboard-source')).toContainText('rotation.LOG.GZ');
  await page.locator('#dash-download-btn').click();
  await expect(page.locator('#download-modal-backdrop')).toBeVisible();
  await page.locator('#dl-modal-close').click();
  await page.locator('#dash-share-btn').click();
  const shareDialog = page.getByRole('dialog');
  await expect(shareDialog.getByRole('heading', { name: 'Share Analysis' })).toBeVisible();
  await expect(shareDialog.getByLabel('Link expiry').locator('option')).toHaveText(['1 hour', '24 hours', '7 days', '30 days', 'Never expires']);
  await expect(shareDialog.getByLabel(/^Password/)).toBeVisible();
  watcher.assertClean();
});

test('Nginx remote mode analyzes the fetched source rather than retained paste text', async ({ page }) => {
  await page.route('**/api/storage/upload-external', route => route.fulfill({ json: { shareCode: 'signal-test' } }));
  await page.route('**/api/storage/download/signal-test', route => route.fulfill({ json: { downloadUrl: 'http://localhost:3001/signal-test.log' } }));
  await page.route('**/signal-test.log', route => route.fulfill({ contentType: 'text/plain', body: SAMPLE_LOG }));
  await page.goto('/nginx');
  await waitForEngineReady(page);
  await page.getByRole('tab', { name: 'Paste logs' }).click();
  await page.locator('#nginx-logtext').fill('This stale draft is not a valid log.');
  await page.getByRole('tab', { name: 'Remote URL' }).click();
  await page.locator('#nginx-gist-url').fill('https://example.com/access.log');
  await page.getByRole('button', { name: 'Analyze Logs', exact: true }).click();
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('9', { timeout: 45000 });
  await expect(page.locator('.signal-dashboard-source')).toContainText('Remote URL · example.com');
});

test('DNS query preserves record selection, resolver, exports, and distinct empty/error states', async ({ page }) => {
  let outcome = 'success';
  const queries: unknown[] = [];
  await page.route('**/api/dns', async route => {
    const query = route.request().postDataJSON();
    queries.push(query);
    await route.fulfill({ json: {
      domain: query.domain, type: query.type, resolver: query.resolver, status: 0,
      records: outcome === 'success' ? [{ name: query.domain, type: 'TXT', TTL: 300, data: 'v=spf1 -all' }] : [],
      ...(outcome === 'empty' ? { noRecords: true, message: 'No TXT records found.' } : {}),
      ...(outcome === 'failure' ? { error: 'DNS resolver timed out.' } : {}),
    } });
  });
  await page.goto('/dns');
  await page.getByLabel('Domain name').fill('example.com');
  for (const type of ['A', 'AAAA', 'MX', 'CNAME', 'NS']) await page.getByRole('checkbox', { name: type, exact: true }).uncheck();
  await page.getByLabel('Resolver', { exact: true }).selectOption('8.8.8.8');
  await page.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(page.getByText('v=spf1 -all', { exact: true })).toBeVisible();
  expect(queries).toEqual([{ domain: 'example.com', type: 'TXT', resolver: '8.8.8.8' }]);
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download CSV', exact: true }).click();
  expect((await downloadPromise).suggestedFilename()).toContain('example.com');
  outcome = 'empty';
  await page.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(page.getByText('No TXT records found.', { exact: true })).toBeVisible();
  await expect(page.getByText('v=spf1 -all', { exact: true })).toHaveCount(0);
  outcome = 'failure';
  await page.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(page.getByText('DNS resolver timed out.', { exact: true })).toBeVisible();
  await expect(page.getByText('No TXT records found.', { exact: true })).toHaveCount(0);
});

test('shared Nginx snapshots use the same engine and remain read-only', async ({ page, console: watcher }) => {
  await page.route('**/api/share/signal-fixture', route => route.fulfill({ json: { share_type: 'nginx', title: 'Signal test snapshot', download_url: 'http://localhost:3001/signal-fixture.log' } }));
  await page.route('**/signal-fixture.log', route => route.fulfill({ contentType: 'text/plain', body: SAMPLE_LOG }));
  await page.goto('/s/signal-fixture');
  await expect(page.locator('#rps-chart')).toBeVisible({ timeout: 45000 });
  await expect(page.locator('.signal-dashboard-source')).toContainText('Shared snapshot');
  await expect(page.locator('.signal-dashboard-source')).toContainText('403 exclusion enabled');
  await expect(page.locator('#dash-share-btn')).toBeHidden();
  await expect(page.locator('#dash-back-btn')).toBeHidden();
  await expect(page.locator('#nginx-dashboard').getByRole('tablist')).toHaveCount(0);
  await page.locator('#filter-ip').fill('66.249.66.1');
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('1');
  for (const selector of ['#rps-chart', '#country-chart', '#asn-chart', '.cross-filter-bot-row', '.incident-3col-grid', '#nginx-log-explorer']) await expect(page.locator(selector).first()).toBeVisible();
  // A shared snapshot cannot be re-shared or restarted, but it can still be downloaded.
  for (const id of ['dash-share-btn', 'dash-back-btn']) await expect(page.locator(`#${id}`)).toBeHidden();
  for (const id of ['dash-download-btn', 'dash-csv-btn']) await expect(page.locator(`#${id}`)).toBeVisible();
  await page.locator('.signal-sidebar a[href="/nginx"]').click();
  await waitForEngineReady(page);
  await expect(page.getByRole('tab', { name: 'Upload file' })).toBeVisible();
  watcher.assertClean();
});
