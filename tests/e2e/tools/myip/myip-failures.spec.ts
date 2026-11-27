import { test, expect } from '../_support/fixtures';
import { failApi, mockApi } from '../_support/io';
import { waitForHydration } from '../_support/navigation';
import { generatePayload } from './generator';
import type { MyIpPayload } from './oracle';
import { HEADING, MYIP_URL, ROUTE, addressCard, errorBox, loadingCard, readAddressCard, shareButton, waitForResult } from './page';

/**
 * /myip — failures of GET /api/myip and recovery. Inventory and layer map:
 * see myip.spec.ts.
 */

async function expectErrorState(page: import('@playwright/test').Page, ctx: string) {
  await expect(errorBox(page), `${ctx}: a visible error`).toBeVisible();
  await expect.soft(errorBox(page), `${ctx}: the error has a readable text`).toContainText(/\w{4,}/);
  await expect.soft(errorBox(page), `${ctx}: the error leaks no placeholder`).not.toContainText(/undefined|\[object|null/);
  await expect(loadingCard(page), `${ctx}: the loading card is gone`).toHaveCount(0);
  expect.soft(await page.locator('.signal-tool-primary .skeleton').count(), `${ctx}: no skeleton placeholder is left`).toBe(0);
  expect.soft(await addressCard(page).count(), `${ctx}: no address card next to the error`).toBe(0);
  expect.soft(await shareButton(page).count(), `${ctx}: nothing to share after a failure`).toBe(0);
}

test.describe('What Is My IP — failures', () => {
  for (const status of [400, 429, 500, 503]) {
    test(`HTTP ${status} shows an error with no spinner, and a reload with a healthy backend recovers`, async ({ page, rng, guard }) => {
      const payload = generatePayload(rng, { missing: 0 });
      const state = { fail: true };
      guard.allow(new RegExp(`status of ${status}|HTTP ${status}`));
      const message = `Simulated failure ${status}`;
      await page.route(MYIP_URL, route => (state.fail ? route.fulfill({ status, json: { error: message } }) : route.fulfill({ json: payload })));
      await page.goto(ROUTE, { waitUntil: 'domcontentloaded' });
      await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
      await expectErrorState(page, `HTTP ${status}`);
      await expect.soft(errorBox(page), 'the backend\'s own error text is passed on').toContainText(message);

      state.fail = false;
      await page.reload({ waitUntil: 'domcontentloaded' });
      await waitForResult(page);
      await expect(errorBox(page), 'no error after the reload').toHaveCount(0);
      expect.soft((await readAddressCard(page))[payload.ip_version === 'IPv4' ? 'ipv4' : 'ipv6'].value, 'address after recovery').toBe(payload.ip);
    });
  }

  test('an unreachable backend shows an error with no spinner', async ({ page, guard }) => {
    guard.allow(/request failed: GET .*\/api\/myip|ERR_FAILED/);
    await failApi(page, MYIP_URL);
    await page.goto(ROUTE, { waitUntil: 'domcontentloaded' });
    await expectErrorState(page, 'network failure');
  });

  test('an answer that is not JSON shows an error instead of an empty page', async ({ page }) => {
    await page.route(MYIP_URL, route => route.fulfill({ status: 200, contentType: 'text/html', body: '<html><body>Bad gateway</body></html>' }));
    await page.goto(ROUTE, { waitUntil: 'domcontentloaded' });
    await expectErrorState(page, 'HTML instead of JSON');
  });

  test('a slow backend keeps the loading card up, then shows the address even though both detection calls gave up', async ({ page, rng }) => {
    const payload = generatePayload(rng, { version: 'IPv4', missing: 0 });
    // Slower than the 2 s and 2.5 s the two detection calls wait.
    await mockApi(page, MYIP_URL, payload, { delayMs: 3200 });
    await page.goto(ROUTE, { waitUntil: 'domcontentloaded' });
    await waitForHydration(page);
    await expect(loadingCard(page), 'loading card while the answer is pending').toBeVisible();
    await expect(page.getByText('Looking up geolocation, network details, and reverse DNS...')).toBeVisible();
    expect.soft(await addressCard(page).count(), 'no address card while loading').toBe(0);
    await waitForResult(page);
    await expect(loadingCard(page), 'loading card gone after the answer').toHaveCount(0);
    const card = await readAddressCard(page);
    expect.soft(card.ipv4.value, 'IPv4 box after a slow answer').toBe(payload.ip);
    expect.soft(card.badges[0], 'stack badge after a slow answer').toBe('IPv4 Only');
    await expect(errorBox(page)).toHaveCount(0);
  });

  test('when only the two detection calls fail, the details call still fills the page', async ({ page, rng, guard }) => {
    const payload = generatePayload(rng, { version: 'IPv6', missing: 0 });
    guard.allow(/status of 503|HTTP 503/);
    let call = 0;
    await page.route(MYIP_URL, route => (call++ === 0 ? route.fulfill({ json: payload }) : route.fulfill({ status: 503, json: { error: 'detection endpoint down' } })));
    await page.goto(ROUTE, { waitUntil: 'domcontentloaded' });
    await waitForResult(page);
    const card = await readAddressCard(page);
    expect.soft(card.ipv6.value, 'IPv6 box filled from the details call').toBe(payload.ip);
    expect.soft(card.ipv4.value, 'IPv4 box').toBe('Not Detected');
    await expect(errorBox(page), 'a failed detection call is not an error for the visitor').toHaveCount(0);
  });

  test('when the details call fails the page shows the error, even if a detection call succeeded', async ({ page, rng, guard }) => {
    const payload: MyIpPayload = generatePayload(rng, { version: 'IPv4', missing: 0 });
    guard.allow(/status of 500|HTTP 500/);
    let call = 0;
    await page.route(MYIP_URL, route => (call++ === 0 ? route.fulfill({ status: 500, json: { error: 'GeoIP database unavailable' } }) : route.fulfill({ json: payload })));
    await page.goto(ROUTE, { waitUntil: 'domcontentloaded' });
    await expectErrorState(page, 'details call failed');
    await expect.soft(errorBox(page)).toContainText('GeoIP database unavailable');
  });
});
