import { test, expect } from './fixtures/dashboard';

/**
 * Functional checks for the 2026-11 tools pack (docs/TOOLS_ROADMAP.md).
 *
 * Browser-only tools are driven for real. Server-backed tools get a mocked
 * API response, so the suite does not depend on DNS, mail servers or the
 * network; the backend logic itself is covered by backend/test/.
 */

test('rsync builder: options change the command and destructive ones warn', async ({ page, console: watcher }) => {
  await page.goto('/rsync');
  const command = page.locator('.tk-code code').first();
  await expect(command).toHaveText('rsync -a -v -z -h --dry-run /var/www/ backup@backup.example.com:/srv/backups/www/');

  await page.getByLabel('Dry run (--dry-run)').uncheck();
  await page.getByLabel('Delete extra files').check();
  await page.getByLabel('SSH port').fill('2222');
  await expect(command).toHaveText("rsync -a -v -z -h --delete -e 'ssh -p 2222' /var/www/ backup@backup.example.com:/srv/backups/www/");
  await expect(page.getByText('--delete removes files from the destination. Run once with --dry-run first.')).toBeVisible();

  await page.getByLabel('SSH port').fill('99999');
  await expect(page.getByText('SSH port must be between 1 and 65535.')).toBeVisible();
  await expect(command).not.toContainText('99999');
  watcher.assertClean();
});

test('certificate decoder: reads the sample without any network request', async ({ page, console: watcher }) => {
  const requests: string[] = [];
  await page.goto('/cert-decoder');
  page.on('request', request => { if (!request.url().includes('/_next/')) requests.push(`${request.method()} ${request.url()}`); });

  await page.getByRole('button', { name: 'Load sample' }).click();
  await expect(page.getByText('Certificate request matches the certificate for www.example.com')).toBeVisible();
  await expect(page.getByRole('row').filter({ hasText: 'Names (SAN)' }).first()).toContainText('www.example.com, example.com');
  await expect(page.getByRole('row').filter({ hasText: 'Public key' }).first()).toContainText('EC P-256');
  await expect(page.getByRole('row').filter({ hasText: 'SHA-256 fingerprint' })).toContainText(/^.*([0-9A-F]{2}:){31}[0-9A-F]{2}/);

  await page.getByLabel('Host name to check (optional)').fill('other.example.org');
  await expect(page.getByText('Does not cover other.example.org')).toBeVisible();

  await page.getByLabel('Certificate, chain, CSR or key (PEM)').fill('-----BEGIN CERTIFICATE-----\nnot base64 !!\n-----END CERTIFICATE-----');
  await page.getByRole('button', { name: 'Decode', exact: true }).click();
  await expect(page.locator('.tk-error')).toContainText('not valid base64');

  expect(requests, 'the decoder must not send its input anywhere').toEqual([]);
  watcher.assertClean();
});

test('email authentication checker: renders findings from the API', async ({ page, console: watcher }) => {
  const section = (status: string, findings: object[], extra: object = {}) => ({ status, findings, ...extra });
  let requestBody: unknown;
  await page.route('**/api/email/auth', async route => {
    requestBody = route.request().postDataJSON();
    await route.fulfill({ json: {
      domain: 'example.com', checked_at_utc: '2026-11-27T10:00:00Z',
      mx: section('pass', [{ severity: 'ok', title: '1 MX record found', detail: '' }], { records: [{ exchange: 'mx.example.com', priority: 10, addresses: ['192.0.2.5'] }], provider: '', null_mx: false }),
      spf: section('fail', [{ severity: 'critical', title: 'SPF needs 12 DNS lookups, the limit is 10', detail: 'Remove unused includes.' }], { record: 'v=spf1 include:a.example -all', records: [], lookups: 12, lookup_limit: 10, all: '-', includes: [{ type: 'include', domain: 'a.example', record: 'v=spf1 -all', lookups: 0, children: [], error: '' }] }),
      dkim: section('missing', [{ severity: 'info', title: 'No DKIM key found at the common selectors', detail: '' }], { selectors_checked: 41, found: [] }),
      dmarc: section('warn', [{ severity: 'warning', title: 'DMARC policy is none (monitoring only)', detail: '' }], { record: 'v=DMARC1; p=none', source_domain: 'example.com', inherited: false, tags: { v: 'DMARC1', p: 'none' }, policy: 'none' }),
      mta_sts: section('missing', [], { record: '', policy: null }),
      tls_rpt: section('missing', [], { record: '' }),
      bimi: section('missing', [], { record: '' }),
      summary: { critical: 1, warning: 1, info: 1, ok: 1 },
    } });
  });

  await page.goto('/email-auth');
  await page.getByLabel('Domain', { exact: true }).fill('Example.com');
  await page.getByLabel(/DKIM selectors/).fill('mail, s1');
  await page.getByRole('button', { name: 'Check domain' }).click();

  await expect(page.getByText('SPF needs 12 DNS lookups, the limit is 10')).toBeVisible();
  await expect(page.getByText('12 of 10 lookups')).toBeVisible();
  await expect(page.getByText('DMARC policy is none (monitoring only)')).toBeVisible();
  await expect(page.locator('.tk-stat').filter({ hasText: 'SPF' })).toContainText('Fail');
  expect(requestBody).toEqual({ domain: 'Example.com', selectors: ['mail', 's1'] });
  watcher.assertClean();
});

test('port checker: shows states and flags a service that should not be public', async ({ page, console: watcher }) => {
  await page.route('**/api/port-check', route => route.fulfill({ json: {
    host: 'server.example.com', address: '192.0.2.10', checked_at_utc: '2026-11-27T10:00:00Z',
    results: [
      { port: 22, state: 'open', latency_ms: 12, service: 'SSH', warning: '' },
      { port: 3306, state: 'open', latency_ms: 14, service: 'MySQL', warning: 'Databases should accept connections from application servers only.' },
      { port: 8080, state: 'filtered', latency_ms: null, service: 'HTTP proxy', warning: '' },
    ],
    summary: { open: 2, closed: 0, filtered: 1 },
  } }));

  await page.goto('/port-check?host=server.example.com');
  await expect(page.getByLabel('Host or IP address')).toHaveValue('server.example.com');
  await page.getByRole('button', { name: 'Databases' }).click();
  await page.getByRole('button', { name: 'Check ports' }).click();

  await expect(page.locator('.tk-error')).toContainText('3306 (MySQL)');
  await expect(page.getByRole('row').filter({ hasText: 'MySQL' })).toContainText('Open');
  await expect(page.getByRole('row').filter({ hasText: 'HTTP proxy' })).toContainText('Filtered');
  watcher.assertClean();
});

test('a failed check shows the reason the API gave', async ({ page }) => {
  await page.route('**/api/port-check', route => route.fulfill({ status: 400, json: { error: 'Destination "10.0.0.5" is not a public address.' } }));
  await page.goto('/port-check');
  await page.getByLabel('Host or IP address').fill('10.0.0.5');
  await page.getByRole('button', { name: 'Check ports' }).click();
  await expect(page.locator('.tk-error')).toHaveText(/Destination "10\.0\.0\.5" is not a public address\./);
});

test('Windows lookups open from a deep link', async ({ page, console: watcher }) => {
  await page.goto('/windows-events?id=4625');
  await expect(page.getByText('Failed logon').first()).toBeVisible();
  await expect(page.getByText("Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50")).toBeVisible();

  await page.goto('/windows-errors?code=0x80070005');
  await expect(page.getByText('ERROR_ACCESS_DENIED').first()).toBeVisible();
  watcher.assertClean();
});

test('new tools appear in the directory under their categories', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: /^Email/ }).click();
  await expect(page.locator('#tool-grid .tool-card')).toHaveCount(4);
  await expect(page.locator('#tool-card-blacklist')).toBeVisible();
  await page.getByRole('button', { name: /^Windows/ }).click();
  await expect(page.locator('#tool-grid .tool-card')).toHaveCount(3);
});
