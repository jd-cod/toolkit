import { test, expect, type Page } from '../_support/fixtures';
import { catalogueEntry, enabledTools, expectedMenu, type SiteConfig, type ToolRow } from './oracle';
import {
  breadcrumb, fetchConfig, loadingBar, menuButton, openHome, openRoute, sidebar, topbar,
} from './page';
import { expectDirectory, expectIconsDrawn, expectShell, softly } from './checks';

/**
 * Sidebar, top bar, footer and moving between tools (desktop width).
 * Inventory and layer map: see home.spec.ts.
 */

const routeOf = (tool: ToolRow) => catalogueEntry(tool.tool_key).route;
const urlEndsWith = (route: string) => new RegExp(`${route.replace(/[/-]/g, '\\$&')}$`);

/** The tool page is on screen and the shell around it describes it. */
async function expectOnTool(page: Page, config: SiteConfig, tool: ToolRow, ctx: string): Promise<void> {
  const route = routeOf(tool);
  await expect(page, `${ctx}: address bar`).toHaveURL(urlEndsWith(route));
  await softly(page.getByRole('heading', { level: 1 }), `${ctx}: ${route} shows exactly one h1`).toHaveCount(1);
  await softly(page.getByRole('heading', { level: 1 }).first(), `${ctx}: the h1 of ${route} is visible`).toBeVisible();
  await expectShell(page, config, route, ctx);
  await softly(sidebar(page).locator('[aria-current="page"]'), `${ctx}: exactly one sidebar entry is marked as the current page`).toHaveCount(1);
  await softly(loadingBar(page), `${ctx}: the navigation loading bar is gone once ${route} is shown`).toHaveCount(0);
}

test.describe('Sidebar and top bar', () => {
  test('the sidebar lists Overview, then the tools grouped by category in catalogue order, with brand and version', async ({ page, request }) => {
    const config = await fetchConfig(request);
    await openHome(page);
    await expectShell(page, config, '/', 'home page');
    await expectIconsDrawn(page, 'home page');
    await expect.soft(sidebar(page), 'the sidebar is on screen at desktop width').toBeVisible();
    await expect.soft(breadcrumb(page), 'the breadcrumb is on screen at desktop width').toBeVisible();
    await expect.soft(menuButton(page), 'the mobile menu button is not shown at desktop width').toBeHidden();
    await expect.soft(sidebar(page).getByRole('button', { name: /Find a tool/ }), '"Find a tool" button in the sidebar').toBeVisible();
    for (const tool of enabledTools(config)) {
      await expect.soft(sidebar(page).locator(`a[href="${routeOf(tool)}"]`), `sidebar link for "${tool.label}" is visible`).toBeVisible();
    }
  });

  test('on every tool route the sidebar marks that tool, the breadcrumb names it, and the footer line fits how the tool works', async ({ page, request }) => {
    const config = await fetchConfig(request);
    for (const tool of enabledTools(config)) {
      await openRoute(page, routeOf(tool));
      await expectOnTool(page, config, tool, `opened ${routeOf(tool)} directly`);
    }
  });

  test('the visible header menu entries are in the top bar and each one opens its target', async ({ page, request }) => {
    const config = await fetchConfig(request);
    const menu = expectedMenu(config.menus.header);
    await openHome(page);
    const links = topbar(page).locator('nav[aria-label="Site navigation"] a');
    await expect.soft(links, `top bar shows the ${menu.length} visible header menu entries`).toHaveText(menu.map(item => item.label));
    for (const [index, item] of menu.entries()) {
      await expect.soft(links.nth(index), `menu entry "${item.label}" is on screen at desktop width`).toBeVisible();
      if (!item.href.startsWith('/') || item.target) continue; // external or new-tab entries: attributes are checked by expectShell
      await links.nth(index).click();
      await expect(page, `menu entry "${item.label}" should open ${item.href}`).toHaveURL(urlEndsWith(item.href));
      await softly(page.getByRole('heading', { level: 1 }).first(), `menu entry "${item.label}": target page shows an h1`).toBeVisible();
      await openHome(page);
    }
  });

  test('"Skip to content" is the first Tab stop and moves focus to the main region', async ({ page, request, rng }) => {
    const config = await fetchConfig(request);
    const tool = rng.pick(enabledTools(config));
    for (const route of ['/', routeOf(tool)]) {
      await openRoute(page, route);
      await page.keyboard.press('Tab');
      const skip = page.getByRole('button', { name: 'Skip to content' });
      await expect(skip, `${route}: the first Tab stop is "Skip to content"`).toBeFocused();
      await expect.soft(skip, `${route}: the focused skip button is on screen`).toBeInViewport();
      await page.keyboard.press('Enter');
      await expect.soft(page.locator('main'), `${route}: activating "Skip to content" focuses the main region`).toBeFocused();
    }
  });
});

test.describe('Moving between tools', () => {
  test('sidebar links open each tool with the shell intact, and browser back and forward retrace the visits', async ({ page, request, rng, evidence }) => {
    const config = await fetchConfig(request);
    const tools = enabledTools(config);
    const visits = rng.sample(tools, Math.min(4, tools.length));
    await evidence.save('visit-order.json', visits.map(routeOf));
    await openHome(page);

    for (const tool of visits) {
      await sidebar(page).locator(`a[href="${routeOf(tool)}"]`).click();
      await expectOnTool(page, config, tool, `sidebar click on "${tool.label}"`);
    }

    // Back through the visits, to the home page, then forward again.
    for (const tool of visits.slice(0, -1).reverse()) {
      await page.goBack();
      await expectOnTool(page, config, tool, `browser Back to ${routeOf(tool)}`);
    }
    await page.goBack();
    await expect(page, 'browser Back from the first tool returns to the home page').toHaveURL(/\/$/);
    await expectShell(page, config, '/', 'home page after browser Back');
    await expectDirectory(page, config, {}, 'home page after browser Back');
    for (const tool of visits) {
      await page.goForward();
      await expectOnTool(page, config, tool, `browser Forward to ${routeOf(tool)}`);
    }
  });

  test('"Overview", the brand and the breadcrumb each return to the home page from a tool', async ({ page, request, rng }) => {
    const config = await fetchConfig(request);
    const tool = rng.pick(enabledTools(config));
    const ways: [string, (p: Page) => ReturnType<Page['locator']>][] = [
      ['sidebar "Overview"', p => sidebar(p).getByRole('link', { name: 'Overview' })],
      ['sidebar brand', p => sidebar(p).locator('.signal-brand')],
      ['breadcrumb "Workspace"', p => breadcrumb(p).getByRole('link', { name: 'Workspace' })],
    ];
    for (const [name, link] of ways) {
      await openRoute(page, routeOf(tool));
      await link(page).click();
      await expect(page, `${name} on ${routeOf(tool)} should open the home page`).toHaveURL(/\/$/);
      await expectShell(page, config, '/', `home page reached by ${name}`);
      await softly(loadingBar(page), `${name}: the loading bar is gone on the home page`).toHaveCount(0);
    }
  });

  test('clicking the sidebar link of the page you are on keeps you there and shows no loading bar', async ({ page, request, rng }) => {
    const config = await fetchConfig(request);
    const tool = rng.pick(enabledTools(config));
    await openRoute(page, routeOf(tool));
    await sidebar(page).locator(`a[href="${routeOf(tool)}"]`).click();
    await expectOnTool(page, config, tool, `clicked the current page's own link (${routeOf(tool)})`);

    await openHome(page);
    await sidebar(page).getByRole('link', { name: 'Overview' }).click();
    await expect(page).toHaveURL(/\/$/);
    await softly(loadingBar(page), 'clicked "Overview" on the home page: no loading bar').toHaveCount(0);
  });

  test('opening a sidebar link in a new tab opens the tool there and leaves this tab idle (no loading bar)', async ({ page, context, request, rng }) => {
    const config = await fetchConfig(request);
    const [here, there] = rng.sample(enabledTools(config), 2);
    await openRoute(page, routeOf(here));

    // Ctrl+click (Cmd+click on macOS) is how a visitor opens a link in a new tab.
    const [newTab] = await Promise.all([
      context.waitForEvent('page'),
      sidebar(page).locator(`a[href="${routeOf(there)}"]`).click({ modifiers: ['ControlOrMeta'] }),
    ]);
    await expect(newTab, `the new tab should show ${routeOf(there)}`).toHaveURL(urlEndsWith(routeOf(there)));
    await expect(page, 'this tab stays on its page').toHaveURL(urlEndsWith(routeOf(here)));
    await newTab.close();

    // The bar means "a page is loading in this tab". Nothing is: it must not be shown, or must go away.
    await softly(
      loadingBar(page),
      `after opening "${there.label}" in a new tab from ${routeOf(here)}, this tab still shows the navigation loading bar although it is not navigating`,
    ).toHaveCount(0);
  });
});
