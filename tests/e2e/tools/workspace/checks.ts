import { expect, type Page } from '../_support/fixtures';
import {
  ALL_TOOLS, enabledTools, expectedAnnouncement, expectedBrandMark, expectedBreadcrumb, expectedCard,
  expectedCategoryButtons, expectedFooter, expectedHero, expectedMenu, expectedNav, expectedPaletteResults,
  visibleTools, type SiteConfig,
} from './oracle';
import {
  announcement, blankIcons, breadcrumbCurrent, categoryGroup, directory, emptyState, grid, palette, paletteInput,
  readBrandMark, readCardKeys, readCards, readCategoryButtons, readFooter, readMenu, readNav, readPaletteResults,
  resultStatus, searchBox, sidebar, toolCount, topbar, openPaletteByShortcut,
} from './page';

/**
 * The full comparisons of the workspace shell with a site configuration.
 * Every spec uses these after each change of state, so one wrong card, count
 * or link is reported wherever it shows up. All comparisons are soft: one run
 * lists every mismatch.
 */

/**
 * Soft assertions with a short wait. The shell re-renders within one frame of
 * a click or a key press, so a value that is still wrong after this long is
 * wrong; the default 15 s would only make a failing run slow.
 */
export const softly = expect.configure({ soft: true, timeout: 3_000 });
/** For the checks that follow one that already waited: the page has settled. */
const settled = expect.configure({ soft: true, timeout: 1_000 });

export interface DirectoryState {
  category?: string;
  query?: string;
}

/** The directory section: cards, their order and content, counts, status text, empty state. */
export async function expectDirectory(page: Page, config: SiteConfig, state: DirectoryState, ctx: string): Promise<void> {
  const category = state.category ?? ALL_TOOLS;
  const query = state.query ?? '';
  const want = visibleTools(config, category, query);
  const total = enabledTools(config).length;
  const where = `${ctx} [category "${category}", search ${JSON.stringify(query)}]`;

  await softly.poll(() => readCardKeys(page), {
    message: `${where}: tools listed in the directory, in order. Expected ${want.length}: ${want.map(t => t.tool_key).join(', ') || '(none)'}`,
  }).toEqual(want.map(tool => tool.tool_key));
  await settled.poll(() => readCards(page), {
    message: `${where}: label, description, category, processing note, icon and colour of each card`,
  }).toEqual(want.map(expectedCard));
  await settled(resultStatus(page), `${where}: status text announced to screen readers`).toHaveText(`${want.length} tools found`);
  await settled.poll(() => readCategoryButtons(page), {
    message: `${where}: category buttons (name, count, pressed state)`,
  }).toEqual(expectedCategoryButtons(config, category));
  await settled(searchBox(page), `${where}: text in the search box`).toHaveValue(query);

  if (want.length > 0) {
    await settled(emptyState(page), `${where}: no empty-state message while tools are listed`).toHaveCount(0);
    return;
  }
  const heading = total > 0 ? 'No tools found' : 'No tools enabled yet';
  const hint = total > 0 ? 'Try a different keyword or browse all tools.' : 'Check back soon for available tools.';
  await settled(emptyState(page).locator('h3'), `${where}: empty-state heading`).toHaveText(heading);
  await settled(emptyState(page).locator('p'), `${where}: empty-state hint`).toHaveText(hint);
  await settled(emptyState(page).getByRole('button', { name: 'Clear filters' }), `${where}: "Clear filters" is offered only when tools exist`)
    .toHaveCount(total > 0 ? 1 : 0);
}

/** Everything on the home page above and around the directory. */
export async function expectHomeContent(page: Page, config: SiteConfig, ctx: string): Promise<void> {
  const hero = expectedHero(config);
  await softly(page.locator('#hero-section h1'), `${ctx}: hero title`).toHaveText(hero.title);
  await softly(page.locator('#hero-section p'), `${ctx}: hero subtitle`).toHaveText(hero.subtitle);
  await softly(toolCount(page), `${ctx}: tool count next to the hero`).toHaveText(hero.countText);
  await softly(directory(page).locator('.signal-section-heading .signal-eyebrow'), `${ctx}: tagline beside the directory heading`).toHaveText(hero.tagline);
  await softly(directory(page).getByRole('heading', { level: 2 }), `${ctx}: directory heading`).toHaveText('The right tool, one click away.');

  const hasAnalyzer = enabledTools(config).some(tool => tool.tool_key === 'nginx');
  const why = hasAnalyzer ? 'the Traffic Analyzer (nginx) is enabled' : 'the Traffic Analyzer (nginx) is not enabled';
  const count = hasAnalyzer ? 1 : 0;
  await softly(page.locator('section.signal-feature'), `${ctx}: log-analysis feature panel, because ${why}`).toHaveCount(count);
  await softly(page.locator('.signal-trust-strip'), `${ctx}: trust strip under the feature panel, because ${why}`).toHaveCount(count);
  await softly(page.locator('.signal-terminal-strip'), `${ctx}: "From a terminal to an answer" strip, because ${why}`).toHaveCount(count);
  if (hasAnalyzer) {
    await softly(page.getByRole('link', { name: 'Analyze your logs' }), `${ctx}: "Analyze your logs" target`).toHaveAttribute('href', '/nginx');
    await softly(page.getByRole('link', { name: 'Explore a sample' }), `${ctx}: "Explore a sample" target`).toHaveAttribute('href', '/nginx?sample=ecommerce-normal.log');
    await softly(page.getByRole('link', { name: 'Try the traffic log analyzer' }), `${ctx}: terminal strip link target`).toHaveAttribute('href', '/nginx');
  }

  const bar = expectedAnnouncement(config.settings);
  if (bar) {
    await softly(announcement(page), `${ctx}: announcement text`).toHaveText(bar.text);
    await softly(announcement(page), `${ctx}: announcement style for type "${config.settings.announcement_type}"`)
      .toHaveClass(bar.warning ? /(^|\s)warning(\s|$)/ : /^(?!.*\bwarning\b)/);
  } else {
    await softly(announcement(page), `${ctx}: no announcement bar (enabled="${config.settings.announcement_enabled}", text=${JSON.stringify(config.settings.announcement_text)})`).toHaveCount(0);
  }
}

/** Sidebar, brand, top bar and footer for the page at `pathname`. */
export async function expectShell(page: Page, config: SiteConfig, pathname: string, ctx: string): Promise<void> {
  await softly.poll(() => readNav(sidebar(page)), {
    message: `${ctx}: sidebar on ${pathname} (Overview, groups, tools, current page, site pages, version, brand)`,
  }).toEqual(expectedNav(config, pathname));
  await softly.poll(() => readBrandMark(sidebar(page)), { message: `${ctx}: brand mark in the sidebar (favicon_emoji=${JSON.stringify(config.settings.favicon_emoji)}, brand_icon=${JSON.stringify(config.settings.brand_icon)})` })
    .toEqual(expectedBrandMark(config.settings));
  await softly(sidebar(page).locator('.signal-brand'), `${ctx}: brand links to the home page`).toHaveAttribute('href', '/');

  await softly(breadcrumbCurrent(page), `${ctx}: breadcrumb on ${pathname}`).toHaveText(expectedBreadcrumb(config, pathname));
  await softly(topbar(page).locator('.signal-breadcrumb a'), `${ctx}: breadcrumb "Workspace" links home`).toHaveAttribute('href', '/');
  await softly.poll(() => readMenu(topbar(page).locator('nav[aria-label="Site navigation"] a')), {
    message: `${ctx}: top bar menu (visible header entries; new-tab entries carry target and rel)`,
  }).toEqual(expectedMenu(config.menus.header));

  await softly.poll(() => readFooter(page), { message: `${ctx}: footer text and links on ${pathname}` }).toEqual(expectedFooter(config, pathname));
}

/** Opens "Find a tool", compares the unfiltered list, closes it again. */
export async function expectPaletteLists(page: Page, config: SiteConfig, ctx: string): Promise<void> {
  await openPaletteByShortcut(page);
  await softly(paletteInput(page), `${ctx}: palette search field starts empty`).toHaveValue('');
  await softly.poll(() => readPaletteResults(page), { message: `${ctx}: tools offered by "Find a tool" before typing` })
    .toEqual(expectedPaletteResults(config, ''));
  await page.keyboard.press('Escape');
  await expect(palette(page), `${ctx}: Esc closes "Find a tool"`).toBeHidden();
}

/** No icon in the directory, sidebar or palette may be an empty box. */
export async function expectIconsDrawn(page: Page, ctx: string): Promise<void> {
  expect.soft(await blankIcons(grid(page)), `${ctx}: directory card icons that draw nothing (unknown icon class)`).toEqual([]);
  expect.soft(await blankIcons(sidebar(page)), `${ctx}: sidebar icons that draw nothing (unknown icon class)`).toEqual([]);
  expect.soft(await blankIcons(categoryGroup(page)), `${ctx}: filter icons that draw nothing`).toEqual([]);
}

/** The whole home page against a configuration: content, directory, shell and palette. */
export async function expectWorkspaceMatches(page: Page, config: SiteConfig, ctx: string): Promise<void> {
  await expectHomeContent(page, config, ctx);
  await expectDirectory(page, config, {}, ctx);
  await expectShell(page, config, '/', ctx);
  await expectPaletteLists(page, config, ctx);
}
