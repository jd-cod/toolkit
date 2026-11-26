import { test, expect, waitForEngineReady } from './fixtures/dashboard';
import type { Page } from '@playwright/test';

const line = (ip: string, path: string, status = 200, ua = 'Mozilla/5.0', second = 0, bytes = 100) =>
  `${ip} - - [05/Oct/2026:00:00:${String(second).padStart(2, '0')} +0000] "GET ${path} HTTP/1.1" ${status} ${bytes} "-" "${ua}"`;

// Labels are independently chosen network/path contracts. Public boundary
// addresses and Unknown ASN traffic are deliberately preserved.
const PRIVATE = ['10.1.2.3', '172.16.0.1', '172.31.255.254', '192.168.1.1', '127.0.0.2',
  '169.254.1.1', '100.64.0.1', '100.127.255.254', '0.0.0.0', '::1', '0:0:0:0:0:0:0:1',
  '::', 'fe80::1', 'febf::1', 'fc00::1', 'fd12:3456::1', '::ffff:192.168.1.1',
  '::ffff:c0a8:101', '0:0:0:0:0:ffff:c0a8:102'];
const PUBLIC = ['172.15.255.254', '172.32.0.1', '100.63.255.254', '100.128.0.1',
  '2001:4860:4860::8888', '203.0.113.4', '::ffff:8.8.8.8'];
const HEALTH = ['/health', '/healthz', '/healthcheck', '/health-check', '/health_check', '/readyz', '/livez', '/_health'];
const NORMAL = ['/healthcare', '/api/healthcheck', '/healthcheck-admin', '/products?next=/healthcheck', '/HealthCheck'];

const LOG = [
  line('10.0.0.5', '/healthcheck', 200, 'curl/8.4.0', 0, 100),
  line('0:0:0:0:0:0:0:1', '/healthz', 200, 'kube-probe/1.29', 1, 200),
  line('8.8.8.8', '/healthcheck/?service=api', 200, 'ELB-HealthChecker/2.0', 2, 300),
  line('1.1.1.1', '/api', 200, 'Mozilla/5.0', 3, 400),
  line('93.184.216.34', '/forbidden', 403, 'Mozilla/5.0', 4, 500),
  line('192.168.1.1', '/internal-admin', 403, 'Mozilla/5.0', 5, 600),
  line('203.0.113.4', '/shop', 200, 'Mozilla/5.0', 6, 700),
].join('\n');

async function analyze(page: Page, log = LOG) {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  await page.getByRole('tab', { name: 'Paste logs' }).click();
  await expect(page.locator('#nginx-skip-403')).toBeChecked();
  await expect(page.locator('#nginx-skip-internal')).toBeChecked();
  await page.locator('#nginx-logtext').fill(log);
  await page.locator('#nginx-analyze-btn').click();
  await expect(page.locator('#dashboard-exclusions')).toBeVisible();
}

test('internal IP ranges and exact health paths are excluded identically in main thread and worker', async ({ page, console: watcher }) => {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  const internal = PRIVATE.map(ip => line(ip, '/internal', 200, 'curl/8.4.0'));
  const health = HEALTH.map(path => line('8.8.8.8', path + '/?probe=1', 200, 'Googlebot/2.1'));
  const external = [...PUBLIC.map(ip => line(ip, '/products')), ...NORMAL.map(path => line('1.1.1.1', path))];
  const privateBot403 = line('::ffff:ac10:2', '/admin', 403, 'ClaudeBot/1.0');
  const public403 = line('1.1.1.1', '/blocked', 403);
  const publicBot403 = line('185.220.101.5', '/wp-admin', 403, 'Googlebot/2.1');
  const log = [...internal, ...health, ...external, privateBot403, public403, publicBot403].join('\n');
  for (const skipInternal of [true, false]) {
    for (const skip403 of [true, false]) {
      const result = await page.evaluate(async ({ log, skipInternal, skip403 }) => {
        const parser = (window as any).LogParser;
        const options = { skipInternal, skip403 };
        const direct = parser.parseIPs(log, options);
        const worker = await parser.parseAsync(log, options);
        return { equal: JSON.stringify(direct) === JSON.stringify(worker),
          kept: direct.parsedLines.map((r: any) => r.line), counts: direct.skipCounts,
          options: direct.options, private: direct.ips.filter((ip: string) => parser.isPrivateIP(ip)) };
      }, { log, skipInternal, skip403 });
      expect(result.equal).toBe(true);
      expect(result.options).toEqual({ skipInternal, skip403 });
      expect(result.kept).toEqual([
        ...(!skipInternal ? [...internal, ...health] : []), ...external,
        ...(!skipInternal ? [privateBot403] : []), ...(!skip403 ? [public403] : []), publicBot403,
      ]);
      expect(result.counts).toEqual({ privateIP: skipInternal ? PRIVATE.length + 1 : 0,
        healthCheck: skipInternal ? HEALTH.length : 0, forbidden: skip403 ? 1 : 0, invalid: 0 });
      if (skipInternal) expect(result.private).toEqual([]);
    }
  }
  watcher.assertClean();
});

test('two default-on controls exclude internal traffic before metrics, Unknown ASN, charts, and reports', async ({ page, console: watcher }) => {
  await analyze(page);
  await expect(page.locator('#dash-skip-403')).toBeChecked();
  await expect(page.locator('#dash-skip-internal')).toBeChecked();
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('2');
  await expect(page.locator('.signal-dashboard-toolbar')).toContainText('Skipped: 5 lines');
  await expect(page.locator('#exclusion-counts')).toHaveText('Skipped: 3 private/local IP · 1 health-check path · 1 ordinary 403 · 0 invalid');
  await expect(page.locator('.cross-filter-asn-row[data-asn="0"] td').nth(1)).toHaveText('1');
  await expect(page.locator('#explorer-rows-body tr')).toHaveCount(2);
  await expect(page.locator('#explorer-rows-body')).not.toContainText('/health');
  const stats = await page.evaluate(() => {
    const chart = (window as any).Chart.getChart(document.getElementById('rps-chart'));
    return { sum: chart.data.datasets[0].data.reduce((n: number, p: any) => n + p.y, 0), min: chart.scales.x.min, max: chart.scales.x.max };
  });
  expect(stats).toEqual({ sum: 2, min: Date.parse('2026-10-05T00:00:00Z'), max: Date.parse('2026-10-05T00:00:06Z') });
  await page.locator('#dash-download-btn').click();
  const [download] = await Promise.all([page.waitForEvent('download'), page.locator('#dl-start-btn').click()]);
  const chunks: Buffer[] = [];
  for await (const chunk of await download.createReadStream()) chunks.push(chunk as Buffer);
  const report = Buffer.concat(chunks).toString('utf8');
  expect(report).toContain('internal requests excluded');
  expect(report).toContain('3 private/local IP');
  for (const forbidden of ['10.0.0.5', '0:0:0:0:0:0:0:1', '192.168.1.1', '/healthcheck', '/healthz']) expect(report).not.toContain(forbidden);
  expect(report).toContain('203.0.113.4');
  watcher.assertClean();
});

test('result controls recalculate the original dataset independently and synchronize with the input controls', async ({ page, console: watcher }) => {
  await analyze(page);
  await page.locator('#dash-skip-403').uncheck();
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('3');
  await expect(page.locator('#dash-skip-internal')).toBeChecked();
  await expect(page.locator('#explorer-rows-body')).not.toContainText('192.168.1.1');
  await page.locator('#dash-skip-internal').uncheck();
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('7');
  await expect(page.locator('#exclusion-counts')).toHaveText('Skipped: 0 private/local IP · 0 health-check path · 0 ordinary 403 · 0 invalid');
  await page.locator('#filter-ip').fill('10.0.0.5');
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('1');
  await page.locator('#filter-clear-btn').click();
  await expect(page.locator('#dash-skip-internal')).not.toBeChecked();
  await page.locator('#dash-skip-403').check();
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('5');
  await expect(page.locator('#exclusion-counts')).toContainText('2 ordinary 403');
  await page.locator('#dash-skip-internal').check();
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('2');
  await page.locator('#dash-skip-internal').uncheck();
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('5');
  await page.locator('#dash-back-btn').click();
  await expect(page.locator('#nginx-skip-403')).toBeChecked();
  await expect(page.locator('#nginx-skip-internal')).not.toBeChecked();
  await page.locator('#nginx-analyze-btn').click();
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('5');
  watcher.assertClean();
});

test('all-internal logs show an explanatory empty result and can be included with the checkbox', async ({ page, console: watcher }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await analyze(page, LOG.split('\n').slice(0, 3).join('\n'));
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('0');
  await expect(page.locator('#dash-exclusion-status')).toHaveText('All valid requests are excluded. Adjust the options above to include them.');
  await expect(page.locator('#analysis-error-modal')).toHaveCount(0);
  await page.locator('#dash-skip-internal').focus();
  await page.keyboard.press('Space');
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('3');
  await expect(page.locator('#dash-skip-internal')).toBeFocused();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  watcher.assertClean();
});

test('New Analysis cancels a pending exclusion recalculation without replacing the new input', async ({ page, console: watcher }) => {
  await analyze(page);
  // Hold the asynchronous parse result so this interaction is deterministic,
  // even on fast machines. The real parser still supplies the result.
  await page.evaluate(() => {
    const runtime = window as any;
    const parser = runtime.LogParser;
    const original = parser.parseAsync;
    parser.parseAsync = (text: string, options: any) => new Promise(resolve => {
      runtime.finishPendingExclusion = () => {
        parser.parseAsync = original;
        resolve(parser.parseIPs(text, options));
      };
    });
  });
  await page.locator('#dash-skip-internal').uncheck();
  await expect(page.locator('#dash-skip-internal')).toBeDisabled();
  await expect(page.locator('#dash-exclusion-status')).toHaveText('Recalculating exclusions…');
  await page.locator('#dash-back-btn').click();
  const nextLog = line('8.8.8.8', '/new-analysis');
  await page.locator('#nginx-logtext').fill(nextLog);
  await page.evaluate(async () => {
    (window as any).finishPendingExclusion();
    // Let the parse promise and resulting render continuation finish.
    await new Promise<void>(resolve => requestAnimationFrame(() => resolve()));
  });
  await expect(page.locator('#nginx-input-section')).toBeVisible();
  await expect(page.locator('#nginx-dashboard')).toBeHidden();
  await expect(page.locator('#nginx-logtext')).toHaveValue(nextLog);
  await expect(page.locator('#nginx-skip-internal')).toBeChecked();
  await page.locator('#nginx-analyze-btn').click();
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('1');
  await expect(page.locator('#explorer-rows-body')).toContainText('/new-analysis');
  watcher.assertClean();
});

test('shared logs apply the same internal default and allow local inclusion without enabling sharing actions', async ({ page, console: watcher }) => {
  await page.route('**/api/share/internal-policy', route => route.fulfill({ json: {
    share_type: 'nginx', title: 'Internal policy fixture', download_url: 'http://localhost:3001/internal-policy.log',
  } }));
  await page.route('**/internal-policy.log', route => route.fulfill({ body: LOG, contentType: 'text/plain' }));
  await page.goto('/s/internal-policy', { waitUntil: 'domcontentloaded' });
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('2', { timeout: 45000 });
  await expect(page.locator('#dash-skip-internal')).toBeChecked();
  await page.locator('#dash-skip-internal').uncheck();
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('5');
  await expect(page.locator('#dash-share-btn')).toBeHidden();
  await expect(page.locator('#dash-download-btn')).toBeVisible();
  watcher.assertClean();
});
