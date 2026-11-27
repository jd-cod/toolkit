import { test, expect, type Page } from '../_support/fixtures';
import { catalogueEntry, enabledTools } from './oracle';
import { fetchConfig, openHome, openRoute, sidebar, themeToggle } from './page';
import { softly } from './checks';

/**
 * Theme toggle in the top bar (oracle definition 8).
 *
 *  - The page is dark or light: `data-theme` on <html>.
 *  - The button offers the other theme: in the dark theme it shows a sun and
 *    is titled "Switch to light theme"; in the light theme a moon and
 *    "Switch to dark theme".
 *  - The choice is stored in localStorage under `theme` and applies to every
 *    page of the site from then on.
 *  - Without a stored choice the visitor's system preference decides.
 *
 * Inventory and layer map: see home.spec.ts.
 */

type Theme = 'dark' | 'light';
const other = (theme: Theme): Theme => (theme === 'dark' ? 'light' : 'dark');

const ORIGIN = new URL(process.env.E2E_BASE_URL ?? 'http://localhost:3001').origin;
/** A browser profile that has `value` stored as the theme choice from an earlier visit. */
const returningVisitor = (value: string) => ({
  cookies: [],
  origins: [{ origin: ORIGIN, localStorage: [{ name: 'theme', value }] }],
});

const storedChoice = (page: Page) => page.evaluate(() => window.localStorage.getItem('theme'));

/** Perceived lightness of the page background, 0 (black) to 1 (white). */
async function backgroundLightness(page: Page): Promise<number> {
  return page.evaluate(() => {
    const [r, g, b] = (getComputedStyle(document.body).backgroundColor.match(/[\d.]+/g) || []).map(Number);
    return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
  });
}

/** Everything that tells a visitor which theme is on. */
async function expectTheme(page: Page, theme: Theme, ctx: string): Promise<void> {
  await softly(page.locator('html'), `${ctx}: data-theme on <html>`).toHaveAttribute('data-theme', theme);
  await softly(themeToggle(page), `${ctx}: the toggle offers the ${other(theme)} theme (title)`).toHaveAttribute('title', `Switch to ${other(theme)} theme`);
  await softly(themeToggle(page).locator('i'), `${ctx}: the toggle shows a ${theme === 'dark' ? 'sun' : 'moon'}`)
    .toHaveClass(theme === 'dark' ? /\bbi-sun\b/ : /\bbi-moon\b/);
  // The colours themselves: a dark page background in the dark theme, a light one in the light theme.
  const check = softly.poll(() => backgroundLightness(page), { message: `${ctx}: lightness of the page background in the ${theme} theme (0 = black, 1 = white)` });
  if (theme === 'dark') await check.toBeLessThan(0.3); else await check.toBeGreaterThan(0.7);
}

test.describe('Theme — first visit with a dark system preference', () => {
  test.use({ colorScheme: 'dark' });

  test('the site opens dark, and the toggle switches to light and back, updating icon, title, colours and the stored choice', async ({ page }) => {
    await openHome(page);
    await expectTheme(page, 'dark', 'first visit');
    expect.soft(await storedChoice(page), 'nothing is stored before the visitor chooses').toBeNull();

    let theme: Theme = 'dark';
    for (const click of [1, 2, 3]) {
      await themeToggle(page).click();
      theme = other(theme);
      await expectTheme(page, theme, `after click ${click} on the toggle`);
      expect.soft(await storedChoice(page), `after click ${click}: choice stored under localStorage "theme"`).toBe(theme);
    }
  });

  test('the chosen theme survives a reload, moving to a tool through the sidebar, and opening a tool directly', async ({ page, request, rng }) => {
    const config = await fetchConfig(request);
    const [viaSidebar, direct] = rng.sample(enabledTools(config), 2).map(tool => catalogueEntry(tool.tool_key).route);
    await openHome(page);
    await themeToggle(page).click();
    await expectTheme(page, 'light', 'after choosing light');

    await page.reload({ waitUntil: 'domcontentloaded' });
    await expectTheme(page, 'light', 'after a reload');

    await sidebar(page).locator(`a[href="${viaSidebar}"]`).click();
    await expect(page).toHaveURL(new RegExp(`${viaSidebar}$`));
    await expectTheme(page, 'light', `after moving to ${viaSidebar} through the sidebar`);

    await openRoute(page, direct);
    await expectTheme(page, 'light', `after opening ${direct} directly`);

    // And back to dark from a tool page: the toggle works everywhere, and the choice follows to the home page.
    await themeToggle(page).click();
    await expectTheme(page, 'dark', `after choosing dark on ${direct}`);
    await openHome(page);
    await expectTheme(page, 'dark', 'home page after choosing dark on a tool page');
  });
});

for (const stored of ['light', 'dark'] as const) {
  // The system preference is set to the opposite, to show that the stored choice wins.
  test.describe(`Theme — returning visitor who chose ${stored}`, () => {
    test.use({ storageState: returningVisitor(stored), colorScheme: other(stored) });

    test(`the site opens in the ${stored} theme on the home page and on a tool page`, async ({ page, request, rng }) => {
      const config = await fetchConfig(request);
      const route = catalogueEntry(rng.pick(enabledTools(config)).tool_key).route;
      await openHome(page);
      await expectTheme(page, stored, `home page, stored choice "${stored}", system preference ${other(stored)}`);
      await openRoute(page, route);
      await expectTheme(page, stored, `${route}, stored choice "${stored}", system preference ${other(stored)}`);
      expect.soft(await storedChoice(page), 'opening pages does not change the stored choice').toBe(stored);
    });
  });
}

test.describe('Theme — stored value that is not a theme', () => {
  test.use({ storageState: returningVisitor('solarized'), colorScheme: 'dark' });

  test('an unusable stored value is ignored and the toggle still works', async ({ page }) => {
    await openHome(page);
    await expectTheme(page, 'dark', 'stored value "solarized"');
    await themeToggle(page).click();
    await expectTheme(page, 'light', 'stored value "solarized", after one click');
    expect.soft(await storedChoice(page), 'the click replaces the unusable value').toBe('light');
  });
});

test.describe('Theme — first visit with a light system preference', () => {
  test.use({ colorScheme: 'light' });

  test('with nothing stored, a visitor whose system asks for light gets the light theme', async ({ page }) => {
    await openHome(page);
    expect(await storedChoice(page), 'precondition: nothing stored').toBeNull();
    expect(await page.evaluate(() => window.matchMedia('(prefers-color-scheme: light)').matches), 'precondition: the browser reports a light system preference').toBe(true);
    await expectTheme(page, 'light', 'first visit, system preference light (prefers-color-scheme: light), nothing stored');
  });
});
