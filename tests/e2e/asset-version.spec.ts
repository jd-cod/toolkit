import { test, expect, waitForEngineReady, SAMPLE_LOG } from './fixtures/dashboard';

/**
 * The scripts under /js are cached for 30 days, so each URL to one carries a
 * version (`?v=`). It is made at build time from the scripts' contents; a
 * hand-kept number was forgotten more than once, which serves a month-old
 * script next to new ones.
 */
test('every analyzer script, on the page and in the worker, is loaded with the same version', async ({ page, console: watcher }) => {
  const scripts: string[] = [];
  page.on('request', request => {
    const url = new URL(request.url());
    if (url.pathname.startsWith('/js/') && url.pathname.endsWith('.js')) scripts.push(url.pathname + url.search);
  });

  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  await page.getByRole('tab', { name: 'Upload file' }).click();
  await page.setInputFiles('#nginx-logfile', { name: 'small.log', mimeType: 'text/plain', buffer: Buffer.from(SAMPLE_LOG + '\n') });
  await page.click('#nginx-analyze-btn');
  await expect(page.locator('#nginx-dashboard')).toBeVisible({ timeout: 45_000 });

  const names = scripts.map(s => s.split('?')[0]);
  for (const name of ['/js/geoip.js', '/js/log-parser.js', '/js/analyzer.js', '/js/dashboard.js', '/js/nginx-init.js', '/js/log-parser.worker.js']) {
    expect(names, `${name} was requested`).toContain(name);
  }
  // The worker loads its own copies; the same file is then requested twice.
  expect(names.filter(name => name === '/js/log-parser.js').length).toBeGreaterThanOrEqual(2);

  const versions = new Set(scripts.map(s => new URLSearchParams(s.split('?')[1] || '').get('v')));
  expect([...versions], `versions seen in ${scripts.join(', ')}`).toHaveLength(1);
  const [version] = versions;
  expect(version).toMatch(/^[0-9a-f]{12}$/);
  expect(await page.evaluate(() => (window as any).__ASSET_VERSION__)).toBe(version);
  watcher.assertClean();
});
