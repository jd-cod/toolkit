import type { Locator, Page } from '@playwright/test';
import { test, expect, gotoAnalyzedDashboard } from './fixtures/dashboard';

/**
 * Every tool shows the same result actions — Share, Download HTML, Download CSV —
 * and Share always opens the same dialog with expiry and password options.
 *
 * The first group pins that contract per tool with the upstream lookups mocked,
 * so a tool that grows its own buttons or loses an option fails here. The
 * second group drives one real share end to end against the backend.
 */

const STANDARD_ACTIONS = ['Share', 'Download HTML', 'Download CSV'];
const EXPIRY_OPTIONS = ['1 hour', '24 hours', '7 days', '30 days', 'Never expires'];

interface ToolCase {
  name: string;
  /** Mocks upstream calls and gets the tool to show a result. */
  open: (page: Page) => Promise<void>;
  htmlFile: RegExp;
  csvFile: RegExp;
}

const provider = { name: 'Example DNS', confidence: 'high', source: 'NS' };

const TOOLS: ToolCase[] = [
  {
    name: 'DNS',
    open: async (page) => {
      await page.route('**/api/dns/global-capability', route => route.fulfill({ json: { available: false } }));
      await page.route('**/api/dns', async route => {
        const query = route.request().postDataJSON();
        await route.fulfill({ json: {
          domain: query.domain, type: query.type, resolver: query.resolver, status: 0, _type: query.type,
          records: [{ name: query.domain, type: query.type, TTL: 300, data: '192.0.2.10' }],
          dns_provider: provider, hosting_provider: provider,
        } });
      });
      await page.goto('/dns');
      await page.getByLabel('Domain name').fill('example.com');
      await page.getByRole('button', { name: 'Lookup', exact: true }).click();
    },
    htmlFile: /^example\.com-dns-snapshot\.html$/,
    csvFile: /^example\.com-dns-snapshot\.csv$/,
  },
  {
    name: 'WHOIS',
    open: async (page) => {
      await page.route('**/api/whois', route => route.fulfill({ json: {
        domain: 'example.com', registered: true, registrar: 'Example Registrar', data_source: 'rdap', dnssec: 'signed',
        days_until_expiry: 120, status_labels: ['ok'], nameservers: ['a.iana-servers.net'], dns_nameservers: ['a.iana-servers.net'],
        risk_signals: [], checked_at_utc: '2026-11-26T10:00:00.000Z', raw_response: '{}',
      } }));
      await page.goto('/whois?domain=example.com');
    },
    htmlFile: /^example\.com-whois-snapshot\.html$/,
    csvFile: /^example\.com-whois-snapshot\.csv$/,
  },
  {
    name: 'ASN',
    open: async (page) => {
      await page.route('**/api/asn', route => route.fulfill({ json: {
        asn: '64500', name: 'EXAMPLE-NET', holder: 'Example Networks', announced: true, country_code: 'US',
        ipv4_prefixes: ['192.0.2.0/24'], ipv6_prefixes: ['2001:db8::/32'], checked_at_utc: '2026-11-26T10:00:00.000Z',
      } }));
      await page.goto('/asn?asn=64500');
    },
    htmlFile: /^AS64500-snapshot\.html$/,
    csvFile: /^AS64500-prefixes\.csv$/,
  },
  {
    name: 'My IP',
    open: async (page) => {
      await page.route('**/api/myip*', route => route.fulfill({ json: {
        ip: '203.0.113.9', ip_version: 'IPv4', country: 'United States', country_code: 'US', city: 'Example City',
        isp: 'Example ISP', asn: 64500, network_type: 'residential', data_sources: {},
        headers: { user_agent: 'test', accept_language: 'en', accept_encoding: 'gzip', referer: '', dnt: '' },
        checked_at_utc: '2026-11-26T10:00:00.000Z',
      } }));
      await page.goto('/myip');
    },
    htmlFile: /^my-ip-report-203-0-113-9\.html$/,
    csvFile: /^my-ip-report-203-0-113-9\.csv$/,
  },
  {
    name: 'SSL',
    open: async (page) => {
      await page.route('**/api/ssl', route => route.fulfill({ json: {
        domain: 'example.com', subject: 'example.com', issuer: 'Test CA', subject_org: '', issuer_org: 'Test CA',
        not_before: '2026-01-01', not_after: '2027-01-01', grade: 'A', days_remaining: 90,
        protocol: 'TLSv1.3', key_type: 'RSA', key_size: 2048, dns: { ip: '192.0.2.10' },
        is_trusted: true, hostname_match: true, is_expired: false, is_self_signed: false, serial_number: '1234',
        fingerprint_sha256: 'AA:BB', response_time_ms: 20, san_names: ['example.com'], chain: [],
      } }));
      await page.goto('/ssl?domain=example.com');
    },
    htmlFile: /^ssl-report-example\.com\.html$/,
    csvFile: /^ssl-report-example\.com\.csv$/,
  },
  {
    name: 'IP Info',
    open: async (page) => {
      await page.route('**/api/ipinfo', route => route.fulfill({ json: { results: [{ ip: '192.0.2.10', ip_version: 'IPv4', reverse_dns: 'host.example.com', country: 'United States', country_code: 'US', isp: 'Example ISP', risk_level: 'low' }] } }));
      await page.route('**/api/abuse', route => route.fulfill({ json: { api_available: false, results: [] } }));
      await page.goto('/abuse');
      await page.locator('textarea').fill('192.0.2.10');
      await page.getByRole('button', { name: /Lookup IP Info/ }).click();
    },
    htmlFile: /^abuse-ip-report-\d{4}-\d{2}-\d{2}\.html$/,
    csvFile: /^abuse-ip-report-\d{4}-\d{2}-\d{2}\.csv$/,
  },
  {
    name: 'Subnet',
    open: async (page) => {
      await page.goto('/subnet');
      await page.getByPlaceholder(/10\.0\.0\.0\/24/).fill('10.0.0.0/24');
      await page.getByRole('button', { name: 'Calculate', exact: true }).click();
    },
    htmlFile: /^subnet-report-10\.0\.0\.0-24\.html$/,
    csvFile: /^subnet-report-10\.0\.0\.0-24\.csv$/,
  },
  {
    name: 'Cron',
    open: async (page) => { await page.goto('/cron'); },
    htmlFile: /^cron-.+\.html$/,
    csvFile: /^cron-.+\.csv$/,
  },
  {
    name: 'chmod',
    open: async (page) => { await page.goto('/chmod'); },
    htmlFile: /^chmod-755\.html$/,
    csvFile: /^chmod-755\.csv$/,
  },
];

const actionBar = (page: Page) => page.getByRole('group', { name: 'Result actions' }).first();

async function expectDownload(page: Page, bar: Locator, name: string, file: RegExp) {
  const download = page.waitForEvent('download');
  await bar.getByRole('button', { name, exact: true }).click();
  expect((await download).suggestedFilename()).toMatch(file);
}

/** Opens Share and checks the dialog is the common one: title, every expiry option, optional password. */
async function openShareDialog(page: Page, bar: Locator) {
  await bar.getByRole('button', { name: 'Share', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByLabel('Title')).not.toHaveValue('');
  await expect(dialog.getByLabel('Link expiry').locator('option')).toHaveText(EXPIRY_OPTIONS);
  await expect(dialog.getByLabel(/^Password/)).toHaveAttribute('type', 'password');
  return dialog;
}

test.describe('Result actions are the same on every tool', () => {
  for (const tool of TOOLS) {
    test(`${tool.name}: Share, Download HTML, Download CSV and the common share dialog`, async ({ page }) => {
      await tool.open(page);
      const bar = actionBar(page);
      await expect(bar).toBeVisible({ timeout: 20_000 });

      // The standard three come first, in this order, whatever extras a tool adds.
      const labels = (await bar.getByRole('button').allInnerTexts()).map(label => label.trim());
      expect(labels.slice(0, 3)).toEqual(STANDARD_ACTIONS);

      await expectDownload(page, bar, 'Download HTML', tool.htmlFile);
      await expectDownload(page, bar, 'Download CSV', tool.csvFile);

      const dialog = await openShareDialog(page, bar);
      await page.keyboard.press('Escape');
      await expect(dialog).toBeHidden();
    });
  }

  test('Traffic Analyzer: the dashboard toolbar carries the same three actions and dialog', async ({ page }) => {
    await gotoAnalyzedDashboard(page);
    const bar = page.locator('#dash-result-actions').getByRole('group', { name: 'Result actions' });
    await expect(bar.getByRole('button')).toHaveText(STANDARD_ACTIONS);

    await expectDownload(page, bar, 'Download CSV', /^nginx-report-\d{4}-\d{2}-\d{2}\.csv$/);
    await bar.getByRole('button', { name: 'Download HTML', exact: true }).click();
    await expect(page.locator('#download-modal-backdrop')).toBeVisible();
    await page.locator('#dl-modal-close').click();

    await openShareDialog(page, bar);
  });

  test('Traffic Analyzer: sharing uploads the log, then publishes it with the chosen expiry and password', async ({ page }) => {
    let published: Record<string, unknown> | null = null;
    await page.route('**/api/storage/upload', route => route.fulfill({ json: { success: true, shareCode: 'Fixture01' } }));
    await page.route('**/api/share', async route => {
      published = route.request().postDataJSON();
      await route.fulfill({ json: { success: true, code: 'Fixture01', url: '/s/Fixture01' } });
    });
    await gotoAnalyzedDashboard(page);

    const dialog = await openShareDialog(page, page.locator('#dash-result-actions'));
    await dialog.getByLabel('Link expiry').selectOption({ label: '1 hour' });
    await dialog.getByLabel(/^Password/).fill('log-secret');
    await dialog.getByRole('button', { name: 'Create share link' }).click();

    await expect(dialog.getByLabel('Share link')).toHaveValue(/\/s\/Fixture01$/);
    await expect(dialog).toContainText('Expires in 1 hour · Password protected');
    expect(published).toMatchObject({ shareCode: 'Fixture01', expiry: '1h', password: 'log-secret' });
  });

  test('Password Generator: downloads only, because generated passwords never leave the browser', async ({ page }) => {
    const posts: string[] = [];
    page.on('request', request => { if (request.method() !== 'GET') posts.push(request.url()); });
    await page.goto('/password-generator');
    // The bulk button's icon glyph is part of its accessible name, so match the word at the end.
    await page.getByRole('button', { name: /\WGenerate$/ }).click();

    const bar = actionBar(page);
    await expect(bar).toBeVisible();
    await expect(bar.getByRole('button', { name: 'Share', exact: true })).toHaveCount(0);
    await expectDownload(page, bar, 'Download HTML', /^generated-passwords\.html$/);
    await expectDownload(page, bar, 'Download CSV', /^generated-passwords\.csv$/);
    expect(posts, 'no request may be sent while exporting passwords').toEqual([]);
  });
});

test.describe('Share links', () => {
  test('a link with a password and expiry is gated, then opens the same result with downloads but no Share', async ({ page }) => {
    await page.goto('/cron');
    const dialog = await openShareDialog(page, actionBar(page));
    await dialog.getByLabel('Title').fill('Quarter-hourly job');
    await dialog.getByLabel('Link expiry').selectOption({ label: '1 hour' });
    await dialog.getByLabel(/^Password/).fill('open-sesame');
    await dialog.getByRole('button', { name: 'Create share link' }).click();

    await expect(dialog.getByText('Share link created')).toBeVisible({ timeout: 10_000 });
    await expect(dialog).toContainText('Expires in 1 hour · Password protected');
    const sharePath = new URL(await dialog.getByLabel('Share link').inputValue()).pathname;

    // The stored result is not handed out before the password is given.
    const meta = await (await page.request.get(`/api${sharePath.replace('/s/', '/share/')}`)).json();
    expect(meta.password_required).toBe(true);
    expect(meta.snapshot).toBeUndefined();
    expect(new Date(meta.expires_at).getTime() - Date.now()).toBeLessThanOrEqual(60 * 60 * 1000);
    expect(new Date(meta.expires_at).getTime() - Date.now()).toBeGreaterThan(55 * 60 * 1000);

    await page.goto(sharePath);
    await expect(page.getByText('Password Protected')).toBeVisible({ timeout: 15_000 });
    await page.getByPlaceholder('Enter password').fill('wrong');
    await page.getByRole('button', { name: 'Unlock' }).click();
    await expect(page.getByText(/Incorrect password/i)).toBeVisible();

    await page.getByPlaceholder('Enter password').fill('open-sesame');
    await page.getByRole('button', { name: 'Unlock' }).click();
    await expect(page.getByRole('heading', { name: 'Quarter-hourly job' })).toBeVisible();
    await expect(page.getByText('Valid Expression')).toBeVisible();

    const bar = actionBar(page);
    await expect(bar.getByRole('button', { name: 'Share', exact: true })).toHaveCount(0);
    await expectDownload(page, bar, 'Download HTML', /^cron-.+\.html$/);
    await expectDownload(page, bar, 'Download CSV', /^cron-.+\.csv$/);
  });

  test('a public link without expiry opens straight away', async ({ page }) => {
    await page.goto('/chmod');
    const dialog = await openShareDialog(page, actionBar(page));
    await dialog.getByRole('button', { name: 'Create share link' }).click();
    await expect(dialog).toContainText('Never expires · Anyone with the link can view');
    const sharePath = new URL(await dialog.getByLabel('Share link').inputValue()).pathname;

    await page.goto(sharePath);
    await expect(page.getByText('rwxr-xr-x').first()).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText('read-only snapshot')).toBeVisible();
  });
});
