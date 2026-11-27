import { test, expect, type Page } from '../_support/fixtures';
import { VIEWPORTS } from '../_support/ui-audit';
import {
  catalogueEntry, enabledTools, expectedBrandMark, expectedMenu, expectedNav, expectedPaletteResults, type SiteConfig,
} from './oracle';
import { randomMenus, randomPages, stamp } from './generator';
import {
  breadcrumb, drawer, fetchConfig, loadingBar, menuButton, openDrawer, openHome, openRoute, openWithConfig, palette,
  paletteInput, readBrandMark, readMenu, readNav, readPaletteResults, sidebar, themeToggle, topbar,
} from './page';
import { softly } from './checks';

/**
 * Phone width (390px): the sidebar is replaced by a menu button that opens a
 * drawer with the same navigation. Inventory and layer map: see home.spec.ts.
 */

const urlEndsWith = (route: string) => new RegExp(`${route.replace(/[/-]/g, '\\$&')}$`);

async function sidewaysScroll(page: Page): Promise<{ content: number; viewport: number }> {
  return page.evaluate(() => ({ content: document.documentElement.scrollWidth, viewport: document.documentElement.clientWidth }));
}

async function expectNoSidewaysScroll(page: Page, ctx: string): Promise<void> {
  const { content, viewport } = await sidewaysScroll(page);
  expect.soft(content, `${ctx}: the page is ${content}px wide in a ${viewport}px viewport and scrolls sideways`).toBeLessThanOrEqual(viewport + 1);
}

/** The drawer shows what the sidebar shows on a wide screen, plus the header menu as "Site links". */
async function expectDrawerMatches(page: Page, config: SiteConfig, pathname: string, ctx: string): Promise<void> {
  await softly.poll(() => readNav(drawer(page)), { message: `${ctx}: drawer navigation on ${pathname} (Overview, groups, tools, current page, site pages, version, brand)` })
    .toEqual(expectedNav(config, pathname));
  await softly.poll(() => readBrandMark(drawer(page)), { message: `${ctx}: brand mark in the drawer` }).toEqual(expectedBrandMark(config.settings));
  const siteLinks = expectedMenu(config.menus.header);
  await softly.poll(() => readMenu(drawer(page).locator('nav[aria-label="Site links"] a')), {
    message: `${ctx}: "Site links" in the drawer (the visible header menu entries, which the top bar hides at this width)`,
  }).toEqual(siteLinks);
  for (const tool of enabledTools(config)) {
    await softly(drawer(page).locator(`nav[aria-label="Tool navigation"] a[href="${catalogueEntry(tool.tool_key).route}"]`), `${ctx}: drawer link for "${tool.label}" is visible`).toBeVisible();
  }
}

test.describe('Phone width (390px)', () => {
  test.use({ viewport: VIEWPORTS.mobile });

  test('the sidebar, breadcrumb and top-bar menu give way to the brand and a menu button, without sideways scrolling', async ({ page, request }) => {
    const config = await fetchConfig(request);
    const tools = enabledTools(config);
    for (const route of ['/', catalogueEntry(tools[0].tool_key).route]) {
      await openRoute(page, route);
      const ctx = `${route} at 390px`;
      await expect.soft(sidebar(page), `${ctx}: the sidebar is not shown`).toBeHidden();
      await expect.soft(breadcrumb(page), `${ctx}: the breadcrumb is not shown`).toBeHidden();
      await expect.soft(topbar(page).locator('nav[aria-label="Site navigation"]'), `${ctx}: the top-bar menu is not shown`).toBeHidden();
      await expect.soft(menuButton(page), `${ctx}: the menu button is shown`).toBeVisible();
      await expect.soft(themeToggle(page), `${ctx}: the theme toggle is shown`).toBeVisible();
      await expect.soft(topbar(page).locator('.signal-mobile-brand .signal-brand-name'), `${ctx}: brand in the top bar`)
        .toContainText(expectedNav(config, route).brandName);
      await expect.soft(topbar(page).locator('.signal-mobile-brand a'), `${ctx}: the brand links home`).toHaveAttribute('href', '/');
      await expectNoSidewaysScroll(page, ctx);
    }
  });

  test('the drawer lists the same navigation as the sidebar, on the home page and on a tool page', async ({ page, request, rng }) => {
    const config = await fetchConfig(request);
    const route = catalogueEntry(rng.pick(enabledTools(config)).tool_key).route;
    for (const pathname of ['/', route]) {
      await openRoute(page, pathname);
      await expect(drawer(page), 'the drawer is closed when the page opens').toBeHidden();
      await openDrawer(page);
      await expectDrawerMatches(page, config, pathname, 'real configuration');
      await softly(drawer(page).locator('[aria-current="page"]'), `drawer on ${pathname}: exactly one entry is the current page`).toHaveCount(1);
      await expectNoSidewaysScroll(page, `drawer open on ${pathname}`);
      await expect.soft(drawer(page), 'the drawer fits on the screen').toBeInViewport({ ratio: 1 });
    }
  });

  test('the drawer follows a served configuration: site pages, hidden and new-tab menu entries, brand and version', async ({ page, request, rng, evidence }) => {
    const config = stamp(rng, await fetchConfig(request));
    config.pages = randomPages(rng, 2);
    config.menus = randomMenus(rng);
    config.settings.site_title = `Ops ${rng.string(5)}`;
    config.settings.brand_icon = 'bi-hdd-rack';
    config.settings.favicon_emoji = '';
    rng.pick(config.tools).is_enabled = 0;
    await evidence.save('served-config.json', config);
    await openWithConfig(page, config);
    await openDrawer(page);
    await expectDrawerMatches(page, config, '/', 'served configuration');
  });

  test('the close button, a tap outside the drawer and Esc each close it', async ({ page }) => {
    await openHome(page);
    const closers: [string, () => Promise<void>][] = [
      ['the close button', () => drawer(page).getByRole('button', { name: 'Close navigation' }).click()],
      // The drawer is at most 330px wide: x=375 is the dimmed page next to it.
      ['a tap outside the drawer', () => page.mouse.click(375, 420)],
      ['Esc', () => page.keyboard.press('Escape')],
    ];
    for (const [name, close] of closers) {
      await openDrawer(page);
      await close();
      await expect(drawer(page), `${name} should close the drawer`).toBeHidden();
      await expect.soft(page, `${name} must not navigate`).toHaveURL(/\/$/);
    }
    // A tap inside the drawer that is not on a link keeps it open.
    await openDrawer(page);
    await drawer(page).locator('.signal-local-note').click();
    await expect.soft(drawer(page), 'a tap on the drawer itself keeps it open').toBeVisible();
  });

  test('choosing a tool in the drawer opens it and closes the drawer; the drawer then marks that tool', async ({ page, request, rng, evidence }) => {
    const config = await fetchConfig(request);
    const visits = rng.sample(enabledTools(config), 3);
    await evidence.save('drawer-visits.json', visits.map(tool => tool.tool_key));
    await openHome(page);
    for (const tool of visits) {
      const route = catalogueEntry(tool.tool_key).route;
      await openDrawer(page);
      await drawer(page).locator(`nav[aria-label="Tool navigation"] a[href="${route}"]`).click();
      await expect(page, `drawer link "${tool.label}" should open ${route}`).toHaveURL(urlEndsWith(route));
      await expect(drawer(page), `the drawer closes after choosing "${tool.label}"`).toBeHidden();
      await softly(page.getByRole('heading', { level: 1 }).first(), `${route} shows its h1`).toBeVisible();
      await softly(loadingBar(page), `the loading bar is gone once ${route} is shown`).toHaveCount(0);
      await expectNoSidewaysScroll(page, `${route} at 390px`);

      await openDrawer(page);
      await softly(drawer(page).locator('[aria-current="page"]'), `drawer on ${route}: the current entry`).toHaveAttribute('href', route);
      await page.keyboard.press('Escape');
      await expect(drawer(page)).toBeHidden();
    }
    // The entry of the page you are on closes the drawer and stays put.
    const last = catalogueEntry(visits[visits.length - 1].tool_key).route;
    await openDrawer(page);
    await drawer(page).locator(`nav[aria-label="Tool navigation"] a[href="${last}"]`).click();
    await expect(drawer(page), 'choosing the current page closes the drawer').toBeHidden();
    await expect.soft(page, 'choosing the current page stays on it').toHaveURL(urlEndsWith(last));
    await softly(loadingBar(page), 'choosing the current page shows no loading bar').toHaveCount(0);

    await openDrawer(page);
    await drawer(page).getByRole('link', { name: 'Overview' }).click();
    await expect(page, '"Overview" in the drawer opens the home page').toHaveURL(/\/$/);
    await expect(drawer(page), 'the drawer closes after "Overview"').toBeHidden();
  });

  test('"Find a tool" in the drawer closes the drawer and opens the palette, which opens the chosen tool', async ({ page, request, rng }) => {
    const config = await fetchConfig(request);
    const target = rng.pick(enabledTools(config));
    const route = catalogueEntry(target.tool_key).route;
    await openHome(page);
    await openDrawer(page);
    await drawer(page).getByRole('button', { name: /Find a tool/ }).click();
    await expect(palette(page), 'the palette opens').toBeVisible();
    await expect(drawer(page), 'the drawer closes when the palette opens').toBeHidden();
    await expect.soft(paletteInput(page), 'the cursor is in the palette search field').toBeFocused();
    await expect.soft(palette(page), 'the palette fits on the screen').toBeInViewport({ ratio: 1 });
    await softly.poll(() => readPaletteResults(page), { message: 'palette on a phone: every enabled tool' }).toEqual(expectedPaletteResults(config, ''));

    await paletteInput(page).fill(target.tool_key);
    await palette(page).locator(`.signal-command-results a[href="${route}"]`).click();
    await expect(page, `choosing "${target.label}" should open ${route}`).toHaveURL(urlEndsWith(route));
    await expect.soft(palette(page), 'the palette closes').toBeHidden();
  });
});

test.describe('Between phone and desktop (1000px)', () => {
  test.use({ viewport: { width: 1000, height: 800 } });

  test('the sidebar stays, the top-bar menu moves into the drawer behind the menu button', async ({ page, request }) => {
    const config = await fetchConfig(request);
    await openHome(page);
    await expect.soft(sidebar(page), 'the sidebar is shown at 1000px').toBeVisible();
    await expect.soft(topbar(page).locator('nav[aria-label="Site navigation"]'), 'the top-bar menu is hidden at 1000px').toBeHidden();
    await expect(menuButton(page), 'the menu button is shown at 1000px, so the hidden menu stays reachable').toBeVisible();
    await openDrawer(page);
    await expectDrawerMatches(page, config, '/', 'real configuration at 1000px');
    await expectNoSidewaysScroll(page, 'drawer open at 1000px');
  });
});
