import { test, expect, gotoAnalyzedDashboard } from './fixtures/dashboard';
import type { GlobalDnsRegion } from '../../frontend/src/lib/tool-results';

test('all dashboard results stay visible together through filtering, resizing, and theme changes', async ({ page, console: watcher }) => {
  await gotoAnalyzedDashboard(page);
  const expectAllResults = async () => {
    await expect(page.locator('#nginx-dashboard').getByRole('tab')).toHaveCount(0);
    await expect(page.locator('.signal-dashboard-context, .signal-traffic-summary, #geomap-container')).toHaveCount(0);
    for (const selector of ['#rps-chart', '#country-chart', '#asn-chart', '.cross-filter-ip-row', '.cross-filter-bot-row', '.cross-filter-path-row', '#btn-center-scan-abuse', '.cross-filter-asn-row', '#nginx-log-explorer']) {
      await expect(page.locator(selector).first()).toBeVisible();
    }
  };
  await expectAllResults();
  await page.locator('#filter-ip').fill('66.249.66.1');
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('60');
  await expect(page.locator('#explorer-rows-body')).toContainText('66.249.66.1');
  await expectAllResults();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.locator('#asn-chart').evaluate(el => el.getBoundingClientRect().width)).toBeGreaterThan(150);
  await page.getByRole('button', { name: 'Toggle theme' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expectAllResults();
  await expect(page.locator('#filter-ip')).toHaveValue('66.249.66.1');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.locator('#floating-clear-filters-btn').click();
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('540');
  await expectAllResults();
  watcher.assertClean();
});

test('DNS hides global propagation when server capability is unavailable', async ({ page }) => {
  await page.route('**/api/dns/global-capability', route => route.fulfill({ json: { available: false } }));
  await page.goto('/dns');
  await expect(page.getByRole('button', { name: 'Standard Query' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Global Propagation', exact: true })).toHaveCount(0);
  await expect(page.getByLabel('Resolver', { exact: true })).toBeVisible();
});

test('global DNS distinguishes partial success, empty results, and all-region failures', async ({ page }) => {
  let results: GlobalDnsRegion[] = [
    { region: 'Virginia', status: 'success', data: { records: [{ exchange: 'mail.example.com', priority: 10 }] } },
    { region: 'Tokyo', status: 'error', error: 'Regional request timed out' },
    { region: 'London', status: 'success', data: { records: [] } },
  ];
  await page.route('**/api/dns/global-capability', route => route.fulfill({ json: { available: true } }));
  await page.route('**/api/dns/global', route => route.fulfill({ json: { results } }));
  await page.goto('/dns');
  await page.getByRole('button', { name: 'Global Propagation', exact: true }).click();
  await page.getByLabel('Domain name').fill('example.com');
  await page.getByRole('checkbox', { name: 'MX', exact: true }).check();
  await page.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(page.getByRole('row').filter({ hasText: 'Virginia' })).toContainText('priority: 10 | exchange: mail.example.com');
  await expect(page.getByRole('row').filter({ hasText: 'Tokyo' })).toContainText('Regional request timed out');
  await expect(page.getByRole('row').filter({ hasText: 'London' })).toContainText('No records');
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export CSV', exact: true }).click();
  expect((await download).suggestedFilename()).toBe('example.com-global-dns-snapshot.csv');
  results = results.filter(result => result.status === 'error');
  await page.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(page.getByText('All regional queries failed. Individual errors are shown below.')).toBeVisible();
  results = [];
  await page.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(page.getByText('No regional results were returned. Try again or use a standard query.')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Global DNS Propagation' })).toHaveCount(0);
});

test('a global capability that becomes unavailable produces an explicit recoverable error', async ({ page }) => {
  await page.route('**/api/dns/global-capability', route => route.fulfill({ json: { available: true } }));
  await page.route('**/api/dns/global', route => route.fulfill({ status: 503, json: { error: 'Global propagation is unavailable on this server. Use a standard DNS query.', results: [] } }));
  await page.goto('/dns');
  await page.getByRole('button', { name: 'Global Propagation', exact: true }).click();
  await page.getByLabel('Domain name').fill('example.com');
  await page.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(page.getByText('Global propagation is unavailable on this server. Use a standard DNS query.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Lookup', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Standard Query' }).click();
  await expect(page.getByLabel('Resolver', { exact: true })).toBeVisible();
  await expect(page.getByRole('alert').filter({ hasText: 'Global propagation is unavailable' })).toHaveCount(0);
});

test('admin appearance previews validate, save, and apply independent public themes and custom CSS', async ({ page, console: watcher }) => {
  let settings: Record<string, string> = {};
  let saves = 0;
  await page.route('**/api/admin/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/me')) return route.fulfill({ json: { id: 1, username: 'appearance-test' } });
    if (path.endsWith('/settings')) {
      if (route.request().method() === 'PUT') { settings = route.request().postDataJSON(); saves++; return route.fulfill({ json: { success: true } }); }
      return route.fulfill({ json: settings });
    }
    return route.fulfill({ json: { items: [], total: 0, recent_activity: [], stats: {} } });
  });
  await page.route('**/api/site/config', async route => {
    const response = await route.fetch();
    const config = await response.json();
    config.settings = { ...config.settings, ...settings };
    await route.fulfill({ json: config });
  });
  await page.goto('/admin');
  await page.getByRole('button', { name: 'Site Settings', exact: true }).click();
  await page.getByLabel('dark Primary action', { exact: true }).fill('invalid');
  await page.getByRole('button', { name: /Save Changes/ }).click();
  await expect(page.getByText('Correct the invalid appearance colors before saving.')).toBeVisible();
  expect(saves).toBe(0);
  await page.getByLabel('dark Primary action', { exact: true }).fill('#ffcc00');
  await page.getByLabel('light Primary action', { exact: true }).fill('#003366');
  await expect(page.locator('.appearance-preview span').first()).toHaveCSS('background-color', 'rgb(255, 204, 0)');
  await expect(page.locator('.appearance-preview span').first()).toHaveCSS('color', 'rgb(0, 0, 0)');
  await page.getByPlaceholder('/* Your custom CSS rules */').fill('.signal-tool-heading { outline: 3px solid rgb(123, 45, 67); }');
  await page.getByRole('button', { name: /Save Changes/ }).click();
  await expect(page.getByText('Settings saved successfully!')).toBeVisible();
  expect(settings.palette_primary_light).toBe('#003366');
  await page.goto('/ssl');
  await expect(page.locator('.signal-tool-heading')).toHaveCSS('outline-width', '3px');
  await expect(page.locator('.signal-tool-primary .btn-primary')).toHaveCSS('background-color', 'rgb(255, 204, 0)');
  await page.getByRole('button', { name: 'Toggle theme' }).click();
  await expect(page.locator('.signal-tool-primary .btn-primary')).toHaveCSS('background-color', 'rgb(0, 51, 102)');
  await expect(page.locator('.signal-tool-primary .btn-primary')).toHaveCSS('color', 'rgb(255, 255, 255)');
  watcher.assertClean();
});

test('SSL lookup renders returned fields and copies the actual issuer and expiry', async ({ page, context, console: watcher }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.route('**/api/ssl', route => route.fulfill({ json: {
    domain: 'example.com', subject: 'example.com', issuer: 'Test CA', issuer_org: 'Test CA', subject_org: '',
    not_before: '2026-01-01', not_after: '2027-01-01', grade: 'A', days_remaining: 90,
    protocol: 'TLSv1.3', key_type: 'RSA', key_size: 2048, dns: { ip: '1.1.1.1' },
    is_trusted: true, hostname_match: true, is_expired: false, serial_number: '1234',
    fingerprint_sha256: 'AA:BB', response_time_ms: 20, san_names: ['example.com'], chain: [],
  } }));
  await page.goto('/ssl');
  await expect(page.getByRole('heading', { name: 'Inspect a certificate' })).toBeVisible();
  await page.getByPlaceholder('example.com', { exact: true }).fill('example.com');
  await page.getByRole('button', { name: /Check$/ }).click();
  await expect(page.getByText('Certificate is trusted', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Copy Summary' }).click();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  expect(copied).toContain('Issuer: Test CA');
  expect(copied).toContain('Valid Until: 2027-01-01');
  watcher.assertClean();
});

test('local utilities calculate a subnet and expose keyboard-operable permission controls', async ({ page, console: watcher }) => {
  await page.goto('/subnet');
  await page.getByPlaceholder('10.0.0.0/24 or 192.168.1.0 255.255.255.0').fill('192.168.10.0/24');
  await page.getByRole('button', { name: 'Calculate', exact: true }).click();
  await expect(page.getByRole('row').filter({ hasText: 'Broadcast Address' })).toContainText('192.168.10.255');
  await expect(page.getByRole('row').filter({ hasText: 'Usable Hosts' })).toContainText('254');
  await page.goto('/chmod');
  await expect(page.getByRole('button', { name: 'Owner Execute', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('code').filter({ hasText: 'chmod 755 filename' })).toBeVisible();
  const permission = page.getByRole('button', { name: 'Others Write', exact: true });
  await expect(permission).toHaveAttribute('aria-pressed', 'false');
  await permission.focus();
  await page.keyboard.press('Space');
  await expect(permission).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByText(/World-writable/)).toBeVisible();
  await page.getByRole('checkbox', { name: 'Setuid (4xxx)', exact: true }).check();
  await expect(page.getByPlaceholder('755', { exact: true })).toHaveValue('4757');
  watcher.assertClean();
});
