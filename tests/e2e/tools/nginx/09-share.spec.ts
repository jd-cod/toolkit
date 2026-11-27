import { test, expect } from './fixtures';
import type { Browser, BrowserContext, Page } from '@playwright/test';
import { checkDashboard } from './checks';
import { readClipboard, clearClipboard } from '../_support/io';
import { expectNoUiGlitches } from '../_support/ui-audit';
import { TrafficAnalyzer } from './page';
import { StorageStandIn, pinBotFeed } from './storage';

/**
 * Traffic Analyzer — Share Snapshot and the shared view (/s/<code>).
 *
 * The share record, password check and expiry run on the real backend. The
 * object storage behind it is replaced by a stand-in when the stack has no
 * storage configured (see storage.ts); with real storage nothing is replaced.
 *
 * A shared link is always opened in a NEW browser context: a different
 * visitor with no cookies, cache or state from the person who shared it.
 */

const storage = new StorageStandIn();
let standIn = false;

test.beforeEach(async ({ context, request }) => {
  standIn = await StorageStandIn.needed(request);
  if (standIn) await storage.install(context);
});

async function newVisitor(browser: Browser, baseURL: string): Promise<{ context: BrowserContext; page: Page; errors: string[] }> {
  const context = await browser.newContext({ baseURL, viewport: { width: 1440, height: 1080 }, timezoneId: process.env.E2E_TIMEZONE ?? 'America/New_York', locale: 'en-US' });
  await pinBotFeed(context);
  if (standIn) await storage.install(context);
  const page = await context.newPage();
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(`uncaught exception: ${e.message}`));
  page.on('console', m => { if (m.type() === 'error') errors.push(`console.error: ${m.text()}`); });
  return { context, page, errors };
}

/** Fills the share dialog and returns the link it shows. */
async function createShare(analyzer: TrafficAnalyzer, options: { title?: string; password?: string; expiry?: '1h' | '24h' | '7d' | 'never' } = {}): Promise<{ url: string; code: string }> {
  const { page } = analyzer;
  await page.locator('#dash-share-btn').click();
  await expect(page.locator('#share-modal')).toBeVisible();
  if (options.title !== undefined) await page.locator('#share-title').fill(options.title);
  if (options.password) await page.locator('#share-password').fill(options.password);
  if (options.expiry) await page.locator('#share-expiry').selectOption(options.expiry);
  await page.locator('#share-submit-btn').click();
  await expect(page.locator('#share-result-section'), 'the dialog shows the created link').toBeVisible({ timeout: 30_000 });
  const url = ((await page.locator('#share-url-display').textContent()) || '').trim();
  return { url, code: url.split('/').pop() as string };
}

async function waitForSharedDashboard(page: Page): Promise<TrafficAnalyzer> {
  const shared = new TrafficAnalyzer(page);
  await shared.waitForDashboard();
  return shared;
}

test.describe('Traffic Analyzer — share dialog', () => {
  test('opens with empty fields, "Never" as expiry, and closes by both of its buttons', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 150 });
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    await page.locator('#dash-share-btn').click();
    await expect(page.locator('#share-modal')).toBeVisible();
    await expect.soft(page.locator('#share-title')).toHaveValue('');
    await expect.soft(page.locator('#share-password')).toHaveValue('');
    await expect.soft(page.locator('#share-expiry')).toHaveValue('never');
    await expect.soft(page.locator('#share-expiry option')).toHaveText(['1 Hour', '24 Hours', '7 Days', 'Never']);
    await expect.soft(page.locator('#share-password'), 'the password is not shown in clear text').toHaveAttribute('type', 'password');
    await page.locator('#share-close-btn').click();
    await expect(page.locator('#share-modal-backdrop')).toBeHidden();

    // Values typed and abandoned must not come back.
    await page.locator('#dash-share-btn').click();
    await page.locator('#share-title').fill('draft');
    await page.locator('#share-password').fill('secret');
    await page.locator('#share-close-btn').click();
    await page.locator('#dash-share-btn').click();
    await expect.soft(page.locator('#share-title'), 'title is cleared when the dialog is reopened').toHaveValue('');
    await expect.soft(page.locator('#share-password'), 'password is cleared when the dialog is reopened').toHaveValue('');
  });
});

test.describe('Traffic Analyzer — sharing without a password', () => {
  test('the link opens for another visitor and shows the same analysis, read-only', async ({ analyzer, newLog, browser, baseURL, rng }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    const title = `Suspicious traffic ${rng.string(6)}`;

    const { url, code } = await createShare(analyzer, { title });
    expect(url, 'the link points at this site').toBe(`${new URL(baseURL as string).origin}/s/${code}`);
    expect(code, 'share code format').toMatch(/^[A-Za-z0-9]{8}$/);
    if (standIn) expect.soft(storage.objects.get(code), 'the stored copy is exactly the analysed log').toBe(log.text);

    await clearClipboard(page);
    await page.locator('#share-copy-btn').click();
    await expect(page.locator('#share-copy-btn')).toHaveText('Copied!');
    expect.soft(await readClipboard(page), '"Copy Link" copies the link').toBe(url);
    await page.locator('#share-done-btn').click();
    await expect(page.locator('#share-modal-backdrop')).toBeHidden();

    const visitor = await newVisitor(browser, baseURL as string);
    await visitor.page.goto(`/s/${code}`);
    const shared = await waitForSharedDashboard(visitor.page);
    await expect.soft(visitor.page.locator('main'), 'the shared view shows the title given by the sharer').toContainText(title);
    const snap = await shared.snapshot();
    checkDashboard(snap, log, {}, 'shared view');
    expect.soft(snap.sourceLabel, 'source label in the shared view').toBe('Shared snapshot');
    for (const id of ['dash-back-btn', 'dash-share-btn', 'dash-download-btn']) {
      await expect.soft(visitor.page.locator(`#${id}`), `#${id} is not offered in a read-only shared view`).toBeHidden();
    }

    // The recipient can explore: filters work in the shared view too.
    await shared.selectTraffic('spoofed');
    checkDashboard(await shared.snapshot(), log, { filters: { traffic: 'spoofed' } }, 'shared view, filtered');
    await expectNoUiGlitches(visitor.page, 'shared traffic analysis');
    expect.soft(visitor.errors, 'browser errors in the shared view').toEqual([]);
    await visitor.context.close();
  });

  test('an empty title becomes "Untitled Analysis"', async ({ analyzer, newLog, request }) => {
    const log = await newLog({ requests: 120 });
    await analyzer.analysePasted(log.text);
    const { code } = await createShare(analyzer);
    const meta = await (await request.get(`/api/share/${code}`)).json();
    expect.soft(meta.title).toBe('Untitled Analysis');
    expect.soft(meta.has_password).toBe(false);
    expect.soft(meta.share_type).toBe('nginx');
  });

  const LIFETIMES: [expiry: '1h' | '24h' | '7d' | 'never', label: string, seconds: number | null][] = [
    ['1h', '1 Hour', 3600], ['24h', '24 Hours', 86400], ['7d', '7 Days', 7 * 86400], ['never', 'Never', null],
  ];
  for (const [expiry, label, seconds] of LIFETIMES) {
    test(`expiry "${label}" is stored as that lifetime`, async ({ analyzer, newLog, request }) => {
      const log = await newLog({ requests: 120 });
      await analyzer.analysePasted(log.text);
      const before = Date.now();
      const { code } = await createShare(analyzer, { title: `expiry ${expiry}`, expiry });
      const meta = await (await request.get(`/api/share/${code}`)).json();
      if (seconds === null) {
        expect.soft(meta.expires_at, 'expiry "Never" stores no expiry date').toBeNull();
      } else {
        expect.soft(meta.expires_at, `a share created with expiry "${label}" must have an expiry date; without one the link never expires`).not.toBeNull();
        const lifetime = Math.round((new Date(meta.expires_at ?? 0).getTime() - before) / 1000);
        expect.soft(Math.abs(lifetime - seconds) < 120, `expiry "${label}" should end about ${seconds}s from now; stored ${meta.expires_at} (${lifetime}s from now)`).toBe(true);
      }
    });
  }

  test('a second snapshot can be shared from the same dashboard without reloading', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 120 });
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    const first = await createShare(analyzer, { title: 'first' });
    await page.locator('#share-done-btn').click();
    await page.locator('#dash-share-btn').click();
    await expect(page.locator('#share-form-section'), 'the form is shown again').toBeVisible();
    await expect.soft(page.locator('#share-submit-btn'), 'the "Create Share Link" button must be ready for the next share').toBeEnabled();
    await expect.soft(page.locator('#share-submit-btn')).toHaveText('Create Share Link');
    expect(first.code).toMatch(/^[A-Za-z0-9]{8}$/);
  });

  test('a snapshot shared with 403 responses and internal requests included shows the recipient the same totals', async ({ analyzer, newLog, browser, baseURL }) => {
    const log = await newLog({ internalShare: 0.08, healthShare: 0.06 });
    const options = { skip403: false, skipInternal: false };
    await analyzer.analysePasted(log.text, options);
    const mine = await analyzer.snapshot();
    const { code } = await createShare(analyzer, { title: 'everything included' });

    const visitor = await newVisitor(browser, baseURL as string);
    await visitor.page.goto(`/s/${code}`);
    const theirs = await (await waitForSharedDashboard(visitor.page)).snapshot();
    expect.soft(theirs.kpis.total, `the sharer saw ${mine.kpis.total} total requests (403 and internal requests included); the recipient must see the same`).toBe(mine.kpis.total);
    expect.soft(theirs.kpis.uniqueIps, 'unique IPs seen by the recipient').toBe(mine.kpis.uniqueIps);
    await visitor.context.close();
  });
});

test.describe('Traffic Analyzer — sharing with a password', () => {
  test('the content stays hidden until the right password is entered; a wrong one is refused', async ({ analyzer, newLog, browser, baseURL, request, rng }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    const password = `pw-${rng.string(10)}`;
    const title = `Protected ${rng.string(5)}`;
    const { code } = await createShare(analyzer, { title, password });

    // The API must not hand out the log location before the password is given.
    const meta = await (await request.get(`/api/share/${code}`)).json();
    expect.soft(meta.password_required, 'the share is marked as password-protected').toBe(true);
    expect.soft(meta.download_url, 'no download link in the public metadata of a protected share').toBeUndefined();
    expect.soft(meta.r2_key, 'no storage key in the public metadata of a protected share').toBeUndefined();
    const wrongApi = await request.post(`/api/share/${code}/verify`, { data: { password: `${password}x` } });
    expect.soft(wrongApi.status(), 'API answer to a wrong password').toBe(401);

    const visitor = await newVisitor(browser, baseURL as string);
    const downloadsBefore = storage.downloads.filter(c => c === code).length;
    await visitor.page.goto(`/s/${code}`);
    await expect(visitor.page.getByRole('heading', { name: 'Password Protected' })).toBeVisible();
    await expect.soft(visitor.page.locator('#nginx-dashboard'), 'no analysis is shown before the password').toBeHidden();
    if (standIn) expect.soft(storage.downloads.filter(c => c === code).length, 'the log must not be fetched before the password is entered').toBe(downloadsBefore);
    await expectNoUiGlitches(visitor.page, 'password prompt of a shared analysis');

    const field = visitor.page.getByPlaceholder('Enter password');
    await field.fill(`${password}-wrong`);
    await visitor.page.getByRole('button', { name: 'Unlock' }).click();
    await expect.soft(visitor.page.getByText('Incorrect password.'), 'a wrong password is refused with a message').toBeVisible();
    await expect.soft(visitor.page.locator('#nginx-dashboard'), 'still no analysis after a wrong password').toBeHidden();

    await field.fill('');
    await visitor.page.getByRole('button', { name: 'Unlock' }).click();
    await expect.soft(visitor.page.getByText('Password required.'), 'an empty password is refused with a message').toBeVisible();

    await field.fill(password);
    await field.press('Enter');
    const shared = await waitForSharedDashboard(visitor.page);
    await expect.soft(visitor.page.getByRole('heading', { name: 'Password Protected' }), 'the prompt disappears after unlocking').toBeHidden();
    await expect.soft(visitor.page.locator('main')).toContainText(title);
    checkDashboard(await shared.snapshot(), log, {}, 'shared view after unlocking');
    // The 401 answers above are the expected result of the wrong and the empty password.
    expect.soft(visitor.errors.filter(e => !/401/.test(e)), 'browser errors in the shared view').toEqual([]);
    await visitor.context.close();
  });

  test('the stored log cannot be fetched through the storage endpoint without the password', async ({ analyzer, newLog, request }) => {
    test.skip(standIn, 'needs real object storage: with the stand-in, /api/storage/download is not served by the backend');
    const log = await newLog({ requests: 120 });
    await analyzer.analysePasted(log.text);
    const { code } = await createShare(analyzer, { title: 'protected', password: 'correct horse' });
    const response = await request.get(`/api/storage/download/${code}`);
    expect.soft(response.ok() ? (await response.json()).downloadUrl : undefined,
      'GET /api/storage/download/<code> must not return a download link for a password-protected share').toBeUndefined();
  });
});

test.describe('Traffic Analyzer — share failures', () => {
  test('an unknown share code shows "Share not found."', async ({ page, guard }) => {
    guard.allow(/404/);
    await page.goto('/s/NoSuchCd');
    await expect(page.getByText('Share not found.')).toBeVisible();
    await expect(page.locator('#nginx-dashboard')).toBeHidden();
  });

  test('when the upload fails the dialog says why and can be used again', async ({ analyzer, newLog, guard }) => {
    const log = await newLog({ requests: 120 });
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    guard.allow(/storage\/upload|503/);
    await page.route('**/api/storage/upload', route => route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'Storage service is not configured.' }) }));
    await page.locator('#dash-share-btn').click();
    await page.locator('#share-submit-btn').click();
    await expect(page.locator('#share-error')).toHaveText('Upload failed: Storage service is not configured.');
    await expect.soft(page.locator('#share-submit-btn'), 'the button is usable again').toBeEnabled();
    await expect.soft(page.locator('#share-submit-btn')).toHaveText('Create Share Link');
    await expect.soft(page.locator('#share-result-section'), 'no link is shown').toBeHidden();
  });

  test('when the share record cannot be created the dialog says why', async ({ analyzer, newLog, guard }) => {
    const log = await newLog({ requests: 120 });
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    guard.allow(/api\/share|500/);
    await page.route(/\/api\/share$/, route => route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'database unavailable' }) }));
    await page.locator('#dash-share-btn').click();
    await page.locator('#share-submit-btn').click();
    await expect(page.locator('#share-error')).toHaveText('Share creation failed: database unavailable');
    await expect.soft(page.locator('#share-submit-btn')).toBeEnabled();
  });
});
