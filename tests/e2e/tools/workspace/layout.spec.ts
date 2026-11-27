import { test, expect, type Page } from '../_support/fixtures';
import { expectNoUiGlitches, VIEWPORTS } from '../_support/ui-audit';
import { failApi } from '../_support/io';
import { CATEGORY_ORDER, enabledTools, toolsInCategory } from './oracle';
import { noMatchQuery, stamp } from './generator';
import { softly } from './checks';
import {
  CONFIG_API, cards, categoryButton, contrastRatios, directoryAlert, drawer, emptyState, fetchConfig, openDrawer,
  openHome, openPaletteByShortcut, openWithConfig, palette, paletteInput, searchBox, themeToggle,
} from './page';

/**
 * Layer 2: nothing is visually broken, in every state of the shell, at
 * desktop, laptop and phone width, in the dark and the light theme.
 *
 * The audit looks at the whole page (`body`), not only `main`, because the
 * sidebar and the top bar are what this suite is about. While a dialog is open
 * the page behind it cannot be used, so the audit looks at the dialog.
 */

const WHOLE_PAGE = { scope: 'body' };

/**
 * Text must be readable against its background: contrast of at least 4.5:1,
 * the WCAG 2.1 level AA minimum for normal-size text. A theme colour that was
 * not applied shows up here as text close to its background colour.
 */
const READABLE = 4.5;
const TEXT_SAMPLES = [
  '#hero-section h1', '#hero-section p', '.signal-directory h2', '.tool-card-title', '.tool-card-description',
  '.signal-tool-card-meta span', '.signal-category-filters button[aria-pressed="true"]',
  '.signal-category-filters button[aria-pressed="false"]', '.signal-directory-search input',
  'aside.signal-sidebar .signal-brand-name', 'aside.signal-sidebar .signal-nav-link.is-active',
  'aside.signal-sidebar .signal-nav-link:not(.is-active)', 'aside.signal-sidebar .signal-nav-caption',
  '.signal-breadcrumb [aria-current="page"]', '.signal-custom-menu a', '#theme-toggle-btn', 'footer#main-footer p',
  '.signal-feature-copy h2', '.signal-feature-actions a.signal-primary', '.signal-feature-actions a:not(.signal-primary)',
  '.signal-mobile-brand .signal-brand-name', '.signal-empty h3', '.signal-empty p',
];

async function expectReadable(page: Page, label: string, selectors: string[] = TEXT_SAMPLES): Promise<void> {
  // Colours cross-fade for a moment after the theme changes; poll until they have settled.
  const tooFaint = async () => Object.entries(await contrastRatios(page, selectors))
    .filter(([, ratio]) => !(ratio >= READABLE))
    .map(([selector, ratio]) => `${selector} (contrast ${ratio}:1)`);
  await softly.poll(tooFaint, { message: `${label}: text that is hard to read against its background (contrast below ${READABLE}:1)`, timeout: 5_000 }).toEqual([]);
}

async function useTheme(page: Page, theme: 'dark' | 'light'): Promise<void> {
  if (theme === 'light') await themeToggle(page).click();
  await expect(page.locator('html'), `the page should be in the ${theme} theme`).toHaveAttribute('data-theme', theme);
}

for (const [size, viewport] of Object.entries(VIEWPORTS)) {
  for (const theme of ['dark', 'light'] as const) {
    test.describe(`Layout at ${size} size (${viewport.width}px), ${theme} theme`, () => {
      test.use({ viewport });

      test('home page: default, filtered by category, nothing found, and "Find a tool" open', async ({ page, request, rng }) => {
        const config = await fetchConfig(request);
        const tools = enabledTools(config);
        const where = `home @${size}, ${theme} theme`;
        await openHome(page);
        await useTheme(page, theme);

        await expectNoUiGlitches(page, `${where}, default`, WHOLE_PAGE);
        await expectReadable(page, `${where}, default`);

        const category = rng.pick(CATEGORY_ORDER.filter(name => toolsInCategory(tools, name).length > 0));
        await categoryButton(page, category).click();
        await expect(cards(page)).toHaveCount(toolsInCategory(tools, category).length);
        await expectNoUiGlitches(page, `${where}, filtered by "${category}"`, WHOLE_PAGE);

        await searchBox(page).fill(noMatchQuery(rng, tools));
        await expect(emptyState(page)).toBeVisible();
        await expectNoUiGlitches(page, `${where}, nothing found`, WHOLE_PAGE);
        await expectReadable(page, `${where}, nothing found`);

        await openPaletteByShortcut(page);
        await expectNoUiGlitches(page, `${where}, "Find a tool" open`, { scope: 'dialog.signal-command' });
        await expect.soft(palette(page), `${where}: the palette fits on the screen`).toBeInViewport({ ratio: 1 });
        await expectReadable(page, `${where}, "Find a tool" open`, [
          '#signal-command-title', '#signal-command-search', '.signal-command-results strong', '.signal-command-results small', '.signal-command-hint',
        ]);
        await paletteInput(page).fill(noMatchQuery(rng, tools));
        await expect(palette(page).getByRole('status')).toBeVisible();
        await expectNoUiGlitches(page, `${where}, "Find a tool" with no match`, { scope: 'dialog.signal-command' });
      });

      if (size === 'mobile') {
        test('navigation drawer open', async ({ page }) => {
          const where = `drawer @${size}, ${theme} theme`;
          await openHome(page);
          await useTheme(page, theme);
          await openDrawer(page);
          await expectNoUiGlitches(page, where, { scope: 'dialog.signal-drawer' });
          await expect.soft(drawer(page), `${where}: the drawer fits on the screen`).toBeInViewport({ ratio: 1 });
          await expectReadable(page, where, [
            'dialog.signal-drawer .signal-brand-name', 'dialog.signal-drawer .signal-nav-link.is-active',
            'dialog.signal-drawer .signal-nav-link:not(.is-active)', 'dialog.signal-drawer .signal-nav-caption',
            'dialog.signal-drawer .signal-find-tool', 'dialog.signal-drawer .signal-mobile-site-links a',
          ]);
        });
      }
    });
  }

  test.describe(`Layout at ${size} size (${viewport.width}px), other states`, () => {
    test.use({ viewport });

    test('the page for an unknown address', async ({ page, guard, rng }) => {
      guard.allow(/status of 404/);
      const response = await page.goto(`/no-such-tool-${rng.string(6)}`, { waitUntil: 'domcontentloaded' });
      expect(response?.status(), 'an unknown address answers 404').toBe(404);
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
      await expectNoUiGlitches(page, `404 page @${size}`, WHOLE_PAGE);
    });

    test('directory unavailable after a failed refresh', async ({ page, guard }) => {
      guard.allow(/api\/site\/config/);
      await failApi(page, CONFIG_API);
      await openHome(page);
      await expect(directoryAlert(page)).toBeVisible();
      await expectNoUiGlitches(page, `refresh failed @${size}`, WHOLE_PAGE);
      await expectReadable(page, `refresh failed @${size}`, ['.signal-empty h3', '.signal-empty p', '.signal-empty button', 'aside .signal-nav-status p', 'aside .signal-nav-status button']);
    });

    test('maintenance screen and announcement bar', async ({ page, request, rng }) => {
      const real = await fetchConfig(request);
      const config = stamp(rng, real);
      config.settings.announcement_enabled = '1';
      config.settings.announcement_text = `Planned maintenance window ${rng.string(8)}: lookups may be slower than usual between 02:00 and 03:00 UTC.`;
      config.settings.announcement_type = rng.pick(['info', 'warning']);
      await openWithConfig(page, config);
      await expect(page.locator('.announcement-bar')).toBeVisible();
      await expectNoUiGlitches(page, `announcement bar (${config.settings.announcement_type}) @${size}`, WHOLE_PAGE);
      await expectReadable(page, `announcement bar (${config.settings.announcement_type}) @${size}`, ['.announcement-bar']);

      config.settings.maintenance_mode = '1';
      await page.reload({ waitUntil: 'domcontentloaded' });
      await expect(page.getByRole('heading', { level: 1, name: 'Under Maintenance' })).toBeVisible();
      await expectNoUiGlitches(page, `maintenance screen @${size}`, WHOLE_PAGE);
      await expectReadable(page, `maintenance screen @${size}`, ['main h1', 'main p']);
    });
  });
}
