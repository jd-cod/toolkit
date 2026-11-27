import { expect, type APIRequestContext, type Locator, type Page } from '@playwright/test';
import { waitForHydration } from '../_support/navigation';
import { mockApi, type ApiCall } from '../_support/io';
import type {
  BrandMark, CardView, CategoryButtonView, FooterView, MenuLinkView, NavView, PaletteResultView, SiteConfig,
} from './oracle';

/**
 * Selectors, user actions and readers for the workspace shell. Readers return
 * plain data in the same shape as the oracle's expectations, so a spec
 * compares data with data.
 */

export const CONFIG_API = '**/api/site/config';

/** The configuration the site is running with right now: the oracle's input. */
export async function fetchConfig(request: APIRequestContext): Promise<SiteConfig> {
  const response = await request.get('/api/site/config');
  expect(response.status(), 'GET /api/site/config should answer 200').toBe(200);
  const config = (await response.json()) as SiteConfig;
  for (const part of ['settings', 'tools', 'menus', 'footer', 'pages'] as const) {
    expect(config[part], `GET /api/site/config should return "${part}"`).toBeTruthy();
  }
  return config;
}

// ─── Locators ───

export const sidebar = (page: Page) => page.locator('aside.signal-sidebar');
export const drawer = (page: Page) => page.locator('dialog.signal-drawer');
export const palette = (page: Page) => page.locator('dialog.signal-command');
export const paletteInput = (page: Page) => page.locator('#signal-command-search');
export const paletteResults = (page: Page) => palette(page).locator('.signal-command-results a');
export const topbar = (page: Page) => page.locator('header.signal-topbar');
export const breadcrumb = (page: Page) => topbar(page).locator('.signal-breadcrumb');
export const breadcrumbCurrent = (page: Page) => breadcrumb(page).locator('[aria-current="page"]');
export const themeToggle = (page: Page) => page.getByRole('button', { name: 'Toggle theme' });
export const menuButton = (page: Page) => page.getByRole('button', { name: 'Open tool navigation' });
export const loadingBar = (page: Page) => page.locator('.signal-nav-loading-bar');
export const footer = (page: Page) => page.locator('footer#main-footer');

export const directory = (page: Page) => page.locator('section.signal-directory');
export const grid = (page: Page) => page.locator('#tool-grid');
export const cards = (page: Page) => grid(page).locator('a.tool-card');
export const searchBox = (page: Page) => page.getByRole('searchbox', { name: 'Search tools' });
export const categoryGroup = (page: Page) => page.getByRole('group', { name: 'Filter tools by category' });
export const categoryButton = (page: Page, name: string) => categoryGroup(page).locator('button').filter({ hasText: new RegExp(`^${name}\\d*$`) });
export const resultStatus = (page: Page) => directory(page).locator('p[role="status"]');
export const emptyState = (page: Page) => directory(page).locator('.signal-empty');
export const directoryAlert = (page: Page) => directory(page).locator('[role="alert"]');
export const toolCount = (page: Page) => page.locator('#hero-section .signal-tool-count');
export const announcement = (page: Page) => page.locator('.announcement-bar');

// ─── Opening pages ───

export async function openHome(page: Page): Promise<void> {
  await openRoute(page, '/');
}

/** Loads a route as a new visit and waits until its controls respond. */
export async function openRoute(page: Page, route: string): Promise<void> {
  const response = await page.goto(route, { waitUntil: 'domcontentloaded' });
  expect(response?.status(), `${route} should answer 200`).toBe(200);
  await waitForHydration(page);
}

/**
 * Serves `config` to the browser in place of the real configuration, opens
 * `route` and waits until the page shows the served configuration.
 *
 * The server renders the page with the real configuration; the browser then
 * asks for it again and re-renders with the answer. The served configuration
 * carries a unique version badge (generator `stamp`), which the sidebar shows:
 * once it is there, the swap has happened.
 */
export async function openWithConfig(page: Page, config: SiteConfig, route = '/'): Promise<ApiCall[]> {
  const calls = await mockApi(page, CONFIG_API, () => config);
  await openRoute(page, route);
  await expectConfigApplied(page, config);
  return calls;
}

export async function expectConfigApplied(page: Page, config: SiteConfig): Promise<void> {
  await expect(
    sidebar(page).locator('.signal-sidebar-version span').last(),
    'the page should re-render with the configuration the browser received (version badge in the sidebar)',
  ).toHaveText(config.settings.version_badge);
}

// ─── Readers ───

export async function readCards(page: Page): Promise<CardView[]> {
  return cards(page).evaluateAll(elements => elements.map(element => {
    const el = element as HTMLElement;
    const meta = Array.from(el.querySelectorAll('.signal-tool-card-meta span')).map(span => span.textContent || '');
    return {
      key: el.id.replace(/^tool-card-/, ''),
      href: el.getAttribute('href') || '',
      label: el.querySelector('.tool-card-title')?.textContent || '',
      description: el.querySelector('.tool-card-description')?.textContent || '',
      category: meta[0] ?? '',
      processing: meta[1] ?? '',
      icon: el.querySelector('.tool-card-icon i')?.className || '',
      color: el.style.getPropertyValue('--tool-color'),
    };
  }));
}

export async function readCardKeys(page: Page): Promise<string[]> {
  return cards(page).evaluateAll(elements => elements.map(el => el.id.replace(/^tool-card-/, '')));
}

export async function readCategoryButtons(page: Page): Promise<CategoryButtonView[]> {
  return categoryGroup(page).locator('button').evaluateAll(buttons => buttons.map(button => {
    const count = button.querySelector('span');
    const name = Array.from(button.childNodes).filter(node => node.nodeType === Node.TEXT_NODE).map(node => node.textContent).join('');
    return { name, count: Number((count?.textContent || '').trim() || 'NaN'), pressed: button.getAttribute('aria-pressed') === 'true' };
  }));
}

/** Reads the navigation inside the sidebar or the mobile drawer. */
export async function readNav(scope: Locator): Promise<NavView> {
  return scope.evaluate(root => {
    const nav = root.querySelector('nav[aria-label="Tool navigation"]');
    const overview = nav?.querySelector(':scope > a');
    const groups = Array.from(nav?.querySelectorAll('.signal-nav-group') || []).map(group => ({
      caption: group.querySelector('.signal-nav-caption')?.textContent || '',
      links: Array.from(group.querySelectorAll('a')).map(link => ({
        href: link.getAttribute('href') || '',
        label: link.querySelector('span')?.textContent || '',
        icon: link.querySelector('i')?.className || '',
        current: link.getAttribute('aria-current') === 'page',
      })),
    }));
    const pages = Array.from(root.querySelectorAll('nav[aria-label="Site pages"] a')).map(link => ({
      href: link.getAttribute('href') || '',
      label: link.textContent || '',
    }));
    const brandName = root.querySelector('.signal-brand-name');
    return {
      overview: { href: overview?.getAttribute('href') || '', current: overview?.getAttribute('aria-current') === 'page' },
      groups,
      pages,
      version: root.querySelector('.signal-sidebar-version span:last-child')?.textContent || '',
      brandName: Array.from(brandName?.childNodes || []).filter(node => node.nodeType === Node.TEXT_NODE).map(node => node.textContent).join(''),
      brandTagline: brandName?.querySelector('small')?.textContent || '',
    };
  });
}

export async function readBrandMark(scope: Locator): Promise<BrandMark> {
  return scope.locator('.signal-brand-mark').first().evaluate(mark => {
    if (mark.querySelector('svg')) return { kind: 'shield' as const };
    const icon = mark.querySelector('i');
    if (icon) return { kind: 'icon' as const, name: Array.from(icon.classList).filter(name => name !== 'bi').pop() || '' };
    return { kind: 'text' as const, text: mark.textContent || '' };
  });
}

export async function readMenu(links: Locator): Promise<MenuLinkView[]> {
  return links.evaluateAll(elements => elements.map(link => ({
    label: link.textContent || '',
    href: link.getAttribute('href') || '',
    target: link.getAttribute('target'),
    rel: link.getAttribute('rel'),
  })));
}

export async function readFooter(page: Page): Promise<FooterView> {
  const lines = await footer(page).locator('p').allTextContents();
  return { lines, links: await readMenu(footer(page).locator('nav[aria-label="Footer links"] a')) };
}

export async function readPaletteResults(page: Page): Promise<PaletteResultView[]> {
  return paletteResults(page).evaluateAll(links => links.map(link => ({
    href: link.getAttribute('href') || '',
    label: link.querySelector('strong')?.textContent || '',
    category: link.querySelector('small')?.textContent || '',
    icon: link.querySelector('i')?.className || '',
  })));
}

/**
 * Class lists of icons under `scope` that draw nothing: the icon font has no
 * glyph for the class, so the visitor sees an empty square where the icon
 * should be.
 */
export async function blankIcons(scope: Locator): Promise<string[]> {
  return scope.locator('i.bi').evaluateAll(icons => icons
    .filter(icon => {
      const content = getComputedStyle(icon, '::before').content;
      return content === 'none' || content === 'normal' || content === '""';
    })
    .map(icon => icon.className));
}

// ─── Actions ───

/** The shortcut the palette listens for: Ctrl+K, and Cmd+K on a Mac keyboard. */
export type PaletteShortcut = 'Control+k' | 'Meta+k' | 'Control+K' | 'Meta+K';

export async function openPaletteByShortcut(page: Page, shortcut: PaletteShortcut = 'Control+k'): Promise<void> {
  await page.keyboard.press(shortcut);
  await expect(palette(page), `"Find a tool" should open with ${shortcut}`).toBeVisible();
}

export async function openPaletteByButton(page: Page): Promise<void> {
  await sidebar(page).getByRole('button', { name: /Find a tool/ }).click();
  await expect(palette(page), '"Find a tool" should open from the sidebar button').toBeVisible();
}

export async function openDrawer(page: Page): Promise<void> {
  await menuButton(page).click();
  await expect(drawer(page), 'the navigation drawer should open from the menu button').toBeVisible();
}

// ─── Readability ───

/**
 * Contrast ratio (WCAG formula) between the text colour of the first element
 * matching each selector and the background it sits on. A theme whose colours
 * were not applied shows up here as a ratio near 1 (text the same colour as
 * its background). Selectors that match nothing are left out.
 */
export async function contrastRatios(page: Page, selectors: string[]): Promise<Record<string, number>> {
  return page.evaluate(list => {
    const parse = (value: string): [number, number, number, number] | null => {
      const rgb = value.match(/^rgba?\(([^)]+)\)$/);
      if (rgb) {
        const parts = rgb[1].split(/[,\s/]+/).filter(Boolean).map(Number);
        return [parts[0], parts[1], parts[2], parts.length > 3 ? parts[3] : 1];
      }
      const srgb = value.match(/^color\(srgb ([^)]+)\)$/);
      if (srgb) {
        const parts = srgb[1].split(/[\s/]+/).filter(Boolean).map(Number);
        return [parts[0] * 255, parts[1] * 255, parts[2] * 255, parts.length > 3 ? parts[3] : 1];
      }
      return null;
    };
    const luminance = ([r, g, b]: number[]) => {
      const [x, y, z] = [r, g, b].map(channel => {
        const v = channel / 255;
        return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * x + 0.7152 * y + 0.0722 * z;
    };
    const out: Record<string, number> = {};
    for (const selector of list) {
      const el = Array.from(document.querySelectorAll(selector)).find(node => (node as HTMLElement).offsetParent !== null);
      if (!el) continue;
      const text = parse(getComputedStyle(el).color);
      // Paint the backgrounds from the page canvas up to the element.
      const layers: [number, number, number, number][] = [];
      for (let node: Element | null = el; node; node = node.parentElement) {
        const colour = parse(getComputedStyle(node).backgroundColor);
        if (colour && colour[3] > 0) layers.unshift(colour);
      }
      let back = [255, 255, 255];
      for (const [r, g, b, a] of layers) back = [r * a + back[0] * (1 - a), g * a + back[1] * (1 - a), b * a + back[2] * (1 - a)];
      if (!text) { out[selector] = Number.NaN; continue; }
      const front = [0, 1, 2].map(i => text[i] * text[3] + back[i] * (1 - text[3]));
      const [hi, lo] = [luminance(front), luminance(back)].sort((a, b) => b - a);
      out[selector] = Math.round(((hi + 0.05) / (lo + 0.05)) * 100) / 100;
    }
    return out;
  }, selectors);
}
