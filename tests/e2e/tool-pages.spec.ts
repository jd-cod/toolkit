import { test, expect } from './fixtures/dashboard';

/**
 * Smoke coverage for the non-nginx tool pages.
 *
 * Ported from scripts/qa_verification.mjs, which was the only thing exercising
 * these ten routes — it just lived outside the test runner, so it never ran
 * automatically and had no failure artifacts.
 *
 * Scope is deliberately a SMOKE test, not a functional one. Several of these
 * tools call live third-party APIs (AbuseIPDB, RDAP/WHOIS, DNS resolvers), so
 * asserting on their results would make the suite fail whenever an external
 * service rate-limits or is down — training us to ignore red. What we DO assert
 * is the part we own: the route resolves, React hydrates, and the page renders
 * its real UI with no JS errors. Deep behaviour for a given tool should be a
 * dedicated spec that mocks the upstream.
 */

const TOOL_PAGES = [
  { path: '/dns', label: 'DNS Lookup' },
  { path: '/myip', label: 'My IP' },
  { path: '/whois', label: 'WHOIS' },
  { path: '/asn', label: 'ASN Lookup' },
  { path: '/ssl', label: 'SSL Checker' },
  { path: '/subnet', label: 'Subnet Calculator' },
  { path: '/abuse', label: 'AbuseIPDB' },
  { path: '/chmod', label: 'chmod' },
  { path: '/cron', label: 'Cron Explainer' },
  { path: '/password-generator', label: 'Password Generator' },
];

/**
 * Noise we must not fail on, because it is not our code failing.
 *
 * These pages call third-party APIs on load (geo-location, RDAP, DNS). In a
 * sandboxed/offline runner those resolve to ERR_NAME_NOT_RESOLVED, and /admin's
 * auth probe legitimately 401s. Treating these as regressions would make the
 * suite red for reasons the team cannot fix, which trains everyone to ignore
 * it. Everything else is still asserted.
 */
const EXTERNAL_NOISE = [
  /ERR_NAME_NOT_RESOLVED/i,
  /ERR_INTERNET_DISCONNECTED/i,
  /Failed to load resource: the server responded with a status of 401/i,
  /Failed to load resource: the server responded with a status of 403/i,
];

/** Console errors that represent a real defect in our own code. */
function realErrors(watcher: { errors: string[] }): string[] {
  return watcher.errors.filter((e) => !EXTERNAL_NOISE.some((re) => re.test(e)));
}

test.describe('Tool pages render', () => {
  for (const { path, label } of TOOL_PAGES) {
    test(`${label} (${path}) loads and renders without JS errors`, async ({
      page,
      console: watcher,
    }) => {
      const response = await page.goto(path, { waitUntil: 'domcontentloaded' });

      expect(response?.status(), `${path} should return 200`).toBe(200);

      // React must have hydrated — a real heading is the cheapest proof that
      // the island mounted rather than serving a bare shell. Not restricted to
      // h1: /dns uses h2, and pinning the level here would be brittle for no
      // benefit.
      await expect(
        page.getByRole('heading').first(),
        `${path} should render a heading`,
      ).toBeVisible({ timeout: 15_000 });

      // And the body must not be a blank/error page.
      const textLength = (await page.locator('body').innerText()).trim().length;
      expect(textLength, `${path} rendered almost no text`).toBeGreaterThan(50);

      expect(realErrors(watcher), `${path} console errors`).toEqual([]);
    });
  }

  test('legacy /password URL redirects to /password-generator', async ({ page }) => {
    const response = await page.goto('/password', { waitUntil: 'domcontentloaded' });
    await expect(page).toHaveURL(/\/password-generator$/);
    expect(response?.status()).toBe(200);
  });
});

test.describe('Admin dashboard', () => {
  test('/admin loads its login gate', async ({ page, console: watcher }) => {
    const response = await page.goto('/admin', { waitUntil: 'domcontentloaded' });
    expect(response?.status()).toBe(200);

    // Deliberately NOT asserting we are past the login gate. This page
    // requires an admin password from backend/.env; adding credentials to a
    // committed spec would leak them. Reaching the login form still proves the
    // route and its auth boundary work.
    await expect(
      page.getByRole('heading').first(),
      '/admin should render its login form',
    ).toBeVisible({ timeout: 15_000 });

    // The 401 on the auth probe is EXPECTED here, so only assert that nothing
    // beyond it broke.
    expect(realErrors(watcher), '/admin unexpected errors').toEqual([]);
  });
});
