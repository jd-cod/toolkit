import { test, expect, type Page } from '../_support/fixtures';
import { failApi, mockApi } from '../_support/io';
import { catalogueEntry, enabledTools, expectedNav, expectedPaletteResults, type SiteConfig } from './oracle';
import { stamp } from './generator';
import {
  CONFIG_API, cards, directory, directoryAlert, expectConfigApplied, fetchConfig, grid, openHome, openPaletteByShortcut,
  openRoute, readCardKeys, readNav, readPaletteResults, sidebar, toolCount,
} from './page';
import { expectShell, expectWorkspaceMatches, softly } from './checks';

/**
 * What the shell does when the browser cannot refresh the site configuration.
 *
 * The server renders every page with the configuration it fetched itself.
 * After the page loads, the browser asks `GET /api/site/config` again. These
 * tests make that second request fail, hang or answer slowly.
 *
 * Behaviour the page promises (its own texts):
 *  - Directory: "Tool directory unavailable", the reason, and "Try again".
 *  - Sidebar: "Tool navigation is temporarily unavailable." and "Retry"; the
 *    tools the server already delivered stay listed and usable.
 *  - While a retry is under way: placeholder cards ("Loading tools") and
 *    "Loading tools…" in the sidebar.
 *  - Either button recovers the page once the API answers again.
 *
 * Inventory and layer map: see home.spec.ts.
 */

const sidebarStatus = (page: Page) => sidebar(page).locator('.signal-nav-status');
const skeleton = (page: Page) => directory(page).locator('[aria-label="Loading tools"]');

/** The failed-refresh state on the home page. */
async function expectDirectoryUnavailable(page: Page, real: SiteConfig, ctx: string): Promise<string> {
  await expect(directoryAlert(page), `${ctx}: the directory should say that it is unavailable`).toBeVisible();
  await softly(directoryAlert(page).getByRole('heading'), `${ctx}: heading of the message`).toHaveText('Tool directory unavailable');
  await softly(directoryAlert(page).getByRole('button', { name: 'Try again' }), `${ctx}: "Try again" is offered`).toBeVisible();
  await softly(grid(page), `${ctx}: no tool cards while the directory is unavailable`).toHaveCount(0);
  await softly(skeleton(page), `${ctx}: no loading placeholders once the request has failed`).toHaveCount(0);
  await softly(toolCount(page), `${ctx}: no tool count while the directory is unavailable`).toHaveCount(0);

  // The reason must be something a person can read: not empty, no leaked placeholder, no parser jargon, no markup.
  const reason = ((await directoryAlert(page).locator('p').textContent()) || '').trim();
  expect.soft(reason, `${ctx}: the message gives a reason`).not.toBe('');
  expect.soft(reason, `${ctx}: reason "${reason}" must not leak a placeholder, a JSON parser error or markup`)
    .not.toMatch(/undefined|null|\[object|NaN|Unexpected token|is not valid JSON|SyntaxError|<\/?[a-z]/i);

  // The sidebar says so too, and keeps the tools the server delivered.
  await softly(sidebarStatus(page).locator('p'), `${ctx}: sidebar notice`).toHaveText('Tool navigation is temporarily unavailable.');
  await softly(sidebarStatus(page).getByRole('button', { name: 'Retry' }), `${ctx}: sidebar "Retry"`).toBeVisible();
  await softly.poll(() => readNav(sidebar(page)), { message: `${ctx}: the sidebar keeps the navigation the server rendered` }).toEqual(expectedNav(real, '/'));
  await softly(page.locator('#hero-section h1'), `${ctx}: the hero title stays`).toBeVisible();
  return reason;
}

async function expectRecovered(page: Page, config: SiteConfig, ctx: string): Promise<void> {
  await expect(grid(page), `${ctx}: the directory is back`).toBeVisible();
  await softly(directoryAlert(page), `${ctx}: the "unavailable" message is gone`).toHaveCount(0);
  await softly(sidebarStatus(page), `${ctx}: the sidebar notice is gone`).toHaveCount(0);
  await softly(skeleton(page), `${ctx}: the loading placeholders are gone`).toHaveCount(0);
  await expectWorkspaceMatches(page, config, ctx);
}

test.describe('Configuration refresh fails', () => {
  test('an error answer from the API shows "Tool directory unavailable" with the API\'s reason; "Try again" shows placeholders, then the directory', async ({ page, request, guard, rng, evidence }) => {
    guard.allow(/api\/site\/config/);
    const real = await fetchConfig(request);
    const status = rng.pick([500, 502, 503, 429]);
    const reason = `Config store offline ${rng.string(6)}`;
    await evidence.save('error-response.json', { status, body: { error: reason } });

    const failed = await mockApi(page, CONFIG_API, { error: reason }, { status });
    await openHome(page);
    const shown = await expectDirectoryUnavailable(page, real, `HTTP ${status} {"error": "${reason}"}`);
    expect.soft(shown, `HTTP ${status}: the reason shown is the one the API gave`).toBe(reason);
    expect.soft(failed.length, 'the browser asked for the configuration once').toBe(1);

    // The API recovers, slowly: the retry must show its loading state, then the directory.
    const served = stamp(rng, real);
    await page.unroute(CONFIG_API);
    const retried = await mockApi(page, CONFIG_API, served, { delayMs: 3_000 });
    await directoryAlert(page).getByRole('button', { name: 'Try again' }).click();

    await expect(skeleton(page), 'while retrying: placeholder cards are shown').toBeVisible();
    await softly(skeleton(page), 'while retrying: the placeholder grid is marked busy').toHaveAttribute('aria-busy', 'true');
    await softly(skeleton(page).locator('.signal-card-skeleton'), 'while retrying: six placeholder cards').toHaveCount(6);
    await softly(directoryAlert(page), 'while retrying: the error message is gone').toHaveCount(0);
    await softly(sidebar(page).getByRole('status'), 'while retrying: sidebar status').toHaveText('Loading tools…');

    await expectConfigApplied(page, served);
    await expectRecovered(page, served, 'after "Try again"');
    expect.soft(retried.length, '"Try again" sent exactly one new request').toBe(1);
  });

  test('a network failure shows a readable reason, and the sidebar "Retry" recovers', async ({ page, request, guard }) => {
    guard.allow(/api\/site\/config/);
    const real = await fetchConfig(request);
    await failApi(page, CONFIG_API);
    await openHome(page);
    await expectDirectoryUnavailable(page, real, 'network failure');

    // Still failing: retry must end in the same state, not in an endless spinner.
    await sidebarStatus(page).getByRole('button', { name: 'Retry' }).click();
    await expectDirectoryUnavailable(page, real, 'network failure, after a retry that failed again');

    await page.unroute(CONFIG_API);
    await sidebarStatus(page).getByRole('button', { name: 'Retry' }).click();
    await expectRecovered(page, real, 'after the sidebar "Retry"');
  });

  test('an error page from a proxy (HTML, not JSON) is reported without parser jargon', async ({ page, request, guard, rng }) => {
    guard.allow(/api\/site\/config/);
    const real = await fetchConfig(request);
    const status = rng.pick([502, 504]);
    await mockApi(page, CONFIG_API, '<html><body><h1>Bad Gateway</h1></body></html>', { status });
    await openHome(page);
    const shown = await expectDirectoryUnavailable(page, real, `HTTP ${status} with an HTML body`);
    expect.soft(shown, `the reason names the HTTP status ${status}, the only fact the page has`).toContain(String(status));
  });

  test('while the directory is unavailable the sidebar and "Find a tool" still open tools', async ({ page, request, guard, rng }) => {
    guard.allow(/api\/site\/config/);
    const real = await fetchConfig(request);
    const [viaSidebar, viaPalette] = rng.sample(enabledTools(real), 2);
    await failApi(page, CONFIG_API);
    await openHome(page);
    await expect(directoryAlert(page)).toBeVisible();

    await openPaletteByShortcut(page);
    await softly.poll(() => readPaletteResults(page), { message: 'the palette lists the tools the server delivered' }).toEqual(expectedPaletteResults(real, ''));
    const paletteRoute = catalogueEntry(viaPalette.tool_key).route;
    await page.locator(`dialog.signal-command .signal-command-results a[href="${paletteRoute}"]`).click();
    await expect(page, `the palette opens ${paletteRoute}`).toHaveURL(new RegExp(`${paletteRoute}$`));
    await softly(page.getByRole('heading', { level: 1 }).first(), `${paletteRoute} shows its h1`).toBeVisible();

    const sidebarRoute = catalogueEntry(viaSidebar.tool_key).route;
    await sidebar(page).locator(`a[href="${sidebarRoute}"]`).click();
    await expect(page, `the sidebar opens ${sidebarRoute}`).toHaveURL(new RegExp(`${sidebarRoute}$`));
    await softly(page.getByRole('heading', { level: 1 }).first(), `${sidebarRoute} shows its h1`).toBeVisible();
  });

  test('on a tool page a failed refresh leaves the tool usable, says so in the sidebar, and "Retry" clears the notice', async ({ page, request, guard, rng }) => {
    guard.allow(/api\/site\/config/);
    const real = await fetchConfig(request);
    const tool = rng.pick(enabledTools(real));
    const route = catalogueEntry(tool.tool_key).route;
    await mockApi(page, CONFIG_API, { error: 'Service Unavailable' }, { status: 503 });
    await openRoute(page, route);

    await expect(sidebarStatus(page).locator('p'), `${route}: sidebar notice after a failed refresh`).toHaveText('Tool navigation is temporarily unavailable.');
    await softly(page.getByRole('heading', { level: 1 }).first(), `${route}: the tool itself is still shown`).toBeVisible();
    await expectShell(page, real, route, `${route} with a failed refresh`);

    await page.unroute(CONFIG_API);
    await sidebarStatus(page).getByRole('button', { name: 'Retry' }).click();
    await expect(sidebarStatus(page), `${route}: the notice goes away after a successful "Retry"`).toHaveCount(0);
    await expectShell(page, real, route, `${route} after "Retry"`);
  });
});

test.describe('Configuration refresh is slow', () => {
  test('the directory the server rendered stays on screen and usable until the answer arrives, then follows it', async ({ page, request, rng }) => {
    const real = await fetchConfig(request);
    const served = stamp(rng, real);
    const hidden = rng.pick(served.tools);
    hidden.is_enabled = 0;
    const calls = await mockApi(page, CONFIG_API, served, { delayMs: 3_000 });
    await openHome(page);

    // Before the answer: the real tools, no placeholders, no error.
    await expect.poll(() => calls.length, { message: 'the browser asks for the configuration after loading' }).toBe(1);
    expect.soft(await readCardKeys(page), 'while the refresh is pending: the cards the server rendered').toEqual(enabledTools(real).map(tool => tool.tool_key));
    await expect.soft(skeleton(page), 'while the refresh is pending: no placeholders over a directory that is already there').toHaveCount(0);
    await expect.soft(directoryAlert(page), 'while the refresh is pending: no error').toHaveCount(0);

    // After the answer: the page follows it (one tool fewer).
    await expectConfigApplied(page, served);
    await softly(cards(page), `after the answer: "${hidden.label}" was disabled in it, so one card fewer`).toHaveCount(enabledTools(served).length);
    await expectWorkspaceMatches(page, served, 'after the slow answer');
  });
});
