import { test, expect, type Page } from '../_support/fixtures';
import { mockApi } from '../_support/io';
import {
  ALL_TOOLS, CATALOGUE, CATEGORY_ORDER, DEFAULT_MAINTENANCE_MESSAGE, catalogueEntry, enabledTools, expectedHero,
  expectedPaletteResults, paletteColorAsRgb, toolsInCategory, visibleTools, type SiteConfig,
} from './oracle';
import { describeConfig, randomConfig, randomMenus, randomPages, randomQueries, stamp, unknownTool } from './generator';
import {
  CONFIG_API, announcement, cards, categoryButton, directory, emptyState, expectConfigApplied, fetchConfig, footer,
  grid, openPaletteByShortcut, openRoute, openWithConfig, palette, paletteInput, readPaletteResults, searchBox, sidebar,
  themeToggle, toolCount,
} from './page';
import { expectDirectory, expectHomeContent, expectShell, expectWorkspaceMatches, softly } from './checks';

/**
 * The shell against configurations served by the test in place of the real
 * one. Each test changes what an administrator can change (or what a new tool
 * brings) and checks that the directory, the counts, the category counts, the
 * sidebar and the command palette all follow, and agree with each other.
 *
 * Inventory and layer map: see home.spec.ts.
 */

/** Serves whatever `holder.config` is at the time of the request. */
async function serve(page: Page, holder: { config: SiteConfig }): Promise<void> {
  await mockApi(page, CONFIG_API, () => holder.config);
}

async function showConfig(page: Page, holder: { config: SiteConfig }, config: SiteConfig, route = '/'): Promise<void> {
  holder.config = config;
  await openRoute(page, route);
  await expectConfigApplied(page, config);
}

test.describe('Served configuration — everything agrees with it', () => {
  test('random configurations: hero, counts, cards, category filters, search, sidebar, top bar, footer and palette all follow', async ({ page, request, rng, evidence }) => {
    const real = await fetchConfig(request);
    const holder = { config: real };
    await serve(page, holder);

    for (const round of [1, 2, 3]) {
      const config = randomConfig(rng.fork(`round ${round}`), real);
      if (round === 1) config.pages = randomPages(rng, 2); // site pages at least once
      await evidence.save(`served-config-${round}.json`, config);
      const ctx = `served configuration ${round} (${describeConfig(config)})`;
      await showConfig(page, holder, config);
      await expectWorkspaceMatches(page, config, ctx);

      const tools = enabledTools(config);
      for (const category of rng.sample(CATEGORY_ORDER, 2)) {
        await categoryButton(page, category).click();
        await expectDirectory(page, config, { category }, ctx);
      }
      await categoryButton(page, ALL_TOOLS).click();
      for (const { query, kind } of randomQueries(rng, tools, 6)) {
        await searchBox(page).fill(query);
        await expectDirectory(page, config, { query }, `${ctx}, search (${kind})`);
        await openPaletteByShortcut(page);
        await paletteInput(page).fill(query);
        await softly.poll(() => readPaletteResults(page), { message: `${ctx}: palette results for ${JSON.stringify(query)} (${kind})` })
          .toEqual(expectedPaletteResults(config, query));
        await paletteInput(page).fill('');
        await page.keyboard.press('Escape');
      }
    }
  });

  test('a served configuration also drives the shell around a tool page', async ({ page, request, rng, evidence }) => {
    const real = await fetchConfig(request);
    const config = randomConfig(rng, real);
    // One tool that stays enabled (the page we open) and one that is switched off (opened as well).
    const [kept, dropped] = rng.sample(real.tools.filter(tool => tool.tool_key in CATALOGUE), 2);
    for (const tool of config.tools) {
      if (tool.tool_key === kept.tool_key) tool.is_enabled = 1;
      if (tool.tool_key === dropped.tool_key) tool.is_enabled = 0;
    }
    await evidence.save('served-config.json', config);
    const holder = { config };
    await serve(page, holder);

    const keptRoute = catalogueEntry(kept.tool_key).route;
    await showConfig(page, holder, config, keptRoute);
    await expectShell(page, config, keptRoute, `${keptRoute} (enabled in the served configuration)`);

    // A tool that was switched off is not in the sidebar, and the breadcrumb no longer names it.
    const droppedRoute = catalogueEntry(dropped.tool_key).route;
    await showConfig(page, holder, config, droppedRoute);
    await expectShell(page, config, droppedRoute, `${droppedRoute} (disabled in the served configuration)`);
    await softly(sidebar(page).locator(`a[href="${droppedRoute}"]`), `the sidebar does not list the disabled tool ${droppedRoute}`).toHaveCount(0);
  });
});

test.describe('Served configuration — tools', () => {
  test('a tool with is_enabled 0 disappears from the directory, the counts, the sidebar and the palette', async ({ page, request, rng, evidence }) => {
    const real = await fetchConfig(request);
    const config = stamp(rng, real);
    const off = rng.sample(config.tools, rng.int(1, 3));
    for (const tool of off) tool.is_enabled = 0;
    await evidence.save('disabled-tools.json', off.map(tool => tool.tool_key));
    const ctx = `disabled: ${off.map(tool => tool.tool_key).join(', ')}`;

    await openWithConfig(page, config);
    await expectWorkspaceMatches(page, config, ctx);
    for (const tool of off) {
      const route = catalogueEntry(tool.tool_key).route;
      await softly(page.locator(`#tool-card-${tool.tool_key}`), `${ctx}: no card for "${tool.label}"`).toHaveCount(0);
      await softly(sidebar(page).locator(`nav[aria-label="Tool navigation"] a[href="${route}"]`), `${ctx}: no sidebar link to ${route}`).toHaveCount(0);
      await softly(palette(page).locator(`.signal-command-results a[href="${route}"]`), `${ctx}: no palette result for ${route}`).toHaveCount(0);
      // Searching for it by its key must not bring it back.
      await searchBox(page).fill(tool.tool_key);
      await expectDirectory(page, config, { query: tool.tool_key }, `${ctx}, searching for the disabled tool's key`);
    }
  });

  test('with the Traffic Analyzer disabled its feature panel, trust strip and terminal strip are gone, and the empty "Observability" filter says so', async ({ page, request, rng }) => {
    const real = await fetchConfig(request);
    const config = stamp(rng, real);
    for (const tool of config.tools) if (tool.tool_key === 'nginx') tool.is_enabled = 0;
    const ctx = 'nginx disabled';

    await openWithConfig(page, config);
    await expectWorkspaceMatches(page, config, ctx);
    await softly(page.getByRole('link', { name: /Analyze your logs|Explore a sample|Try the traffic log analyzer/ }), `${ctx}: no link to the disabled analyzer in the page body`).toHaveCount(0);

    await categoryButton(page, 'Observability').click();
    await expectDirectory(page, config, { category: 'Observability' }, ctx);
    if (toolsInCategory(enabledTools(config), 'Observability').length === 0) {
      await emptyState(page).getByRole('button', { name: 'Clear filters' }).click();
      await expectDirectory(page, config, {}, `${ctx}, after "Clear filters"`);
    }
  });

  test('sort_order decides the order everywhere, and equal sort_order falls back to id', async ({ page, request, rng, evidence }) => {
    const real = await fetchConfig(request);
    const holder = { config: real };
    await serve(page, holder);

    // 1: reversed. 2: all equal (id order). 3: random with ties and negatives, array shuffled.
    const reversed = stamp(rng, real);
    reversed.tools.forEach(tool => { tool.sort_order = 1000 - tool.sort_order; });
    const allEqual = stamp(rng, real);
    allEqual.tools.forEach(tool => { tool.sort_order = 7; });
    allEqual.tools = rng.shuffle(allEqual.tools);
    const random = stamp(rng, real);
    random.tools.forEach(tool => { tool.sort_order = rng.int(-3, 3); });
    random.tools = rng.shuffle(random.tools);

    for (const [name, config] of [['reversed sort_order', reversed], ['every sort_order equal', allEqual], ['random sort_order with ties', random]] as const) {
      await evidence.save(`${name.replace(/ /g, '-')}.json`, config.tools.map(tool => ({ key: tool.tool_key, id: tool.id, sort_order: tool.sort_order })));
      await showConfig(page, holder, config);
      await expectWorkspaceMatches(page, config, name);
    }
  });

  test('a tool key the catalogue does not know opens /<key>, is filed under Utilities as "Utility" with the tools icon', async ({ page, request, rng, evidence }) => {
    const real = await fetchConfig(request);
    const config = stamp(rng, real);
    const plain = unknownTool(rng, config, { icon: '', color: '', sort_order: -5 });
    config.tools.push(plain);
    const withIcon = unknownTool(rng, config, { icon: 'bi-cpu', color: '#12ab9f', sort_order: 99 });
    config.tools.push(withIcon);
    // A key that needs URL-encoding to be a path.
    const spaced = unknownTool(rng, config, { tool_key: `log tail ${rng.string(3)}`, sort_order: 3 });
    config.tools.push(spaced);
    await evidence.save('unknown-tools.json', [plain, withIcon, spaced]);
    const ctx = `unknown keys "${plain.tool_key}", "${withIcon.tool_key}", "${spaced.tool_key}"`;

    await openWithConfig(page, config);
    await expectWorkspaceMatches(page, config, ctx);

    for (const tool of [plain, withIcon, spaced]) {
      const card = page.locator(`[id="tool-card-${tool.tool_key}"]`);
      await softly(card, `${ctx}: card of "${tool.tool_key}" links to /<key>`).toHaveAttribute('href', `/${encodeURIComponent(tool.tool_key)}`);
      await softly(card.locator('.signal-tool-card-meta span'), `${ctx}: card of "${tool.tool_key}" category and note`).toHaveText(['Utilities', 'Utility']);
      await softly(card.locator('.tool-card-icon i'), `${ctx}: card icon of "${tool.tool_key}" (configured icon, else bi-tools)`).toHaveClass(`bi ${tool.icon || 'bi-tools'}`);
      await softly(sidebar(page).locator('.signal-nav-group').last().locator(`a[href="/${encodeURIComponent(tool.tool_key)}"] i`), `${ctx}: sidebar lists "${tool.tool_key}" in the last group (Utilities) with the tools icon`).toHaveClass('bi bi-tools');
    }
    await softly(sidebar(page).locator('.signal-nav-group').last().locator('.signal-nav-caption'), `${ctx}: the last sidebar group is Utilities`).toHaveText('Utilities');

    await categoryButton(page, 'Utilities').click();
    await expectDirectory(page, config, { category: 'Utilities' }, ctx);
    await searchBox(page).fill('utilities');
    await expectDirectory(page, config, { category: 'Utilities', query: 'utilities' }, `${ctx}: unknown tools are found by their category name`);
  });

  test('with no tool enabled the directory says "No tools enabled yet" and offers nothing to clear', async ({ page, request, rng }) => {
    const real = await fetchConfig(request);
    const config = stamp(rng, real);
    if (rng.bool()) config.tools = []; else config.tools.forEach(tool => { tool.is_enabled = 0; });
    const ctx = `no enabled tools (${config.tools.length} tools in the payload)`;

    await openWithConfig(page, config);
    await expectWorkspaceMatches(page, config, ctx);
    await expect(emptyState(page).getByRole('heading', { name: 'No tools enabled yet' }), `${ctx}: empty-state heading`).toBeVisible();
    await softly(toolCount(page), `${ctx}: hero count`).toHaveText('0 purpose-built tools');
    await softly(sidebar(page).locator('.signal-nav-group'), `${ctx}: no tool groups in the sidebar`).toHaveCount(0);
    await softly(sidebar(page).getByRole('link', { name: 'Overview' }), `${ctx}: "Overview" stays`).toBeVisible();

    // Filters on an empty directory keep saying that nothing is enabled.
    await categoryButton(page, rng.pick(CATEGORY_ORDER)).click();
    await softly(emptyState(page).locator('h3'), `${ctx}: heading after pressing a category`).toHaveText('No tools enabled yet');

    await openPaletteByShortcut(page);
    await softly(palette(page).locator('.signal-command-results a'), `${ctx}: the palette has no results`).toHaveCount(0);
    await softly(palette(page).getByRole('status'), `${ctx}: the palette says that there is nothing to choose`).toBeVisible();
  });
});

test.describe('Served configuration — site texts', () => {
  test('hero title, subtitle, tagline, brand and version follow the settings, each with its fall-back', async ({ page, request, rng, evidence }) => {
    const real = await fetchConfig(request);
    const holder = { config: real };
    await serve(page, holder);
    const word = () => rng.string(6);
    const cases: [string, Record<string, string>][] = [
      ['every text set', { home_hero_title: `Hero ${word()}`, home_hero_subtitle: `Sub ${word()}`, site_title: `Site ${word()}`, site_description: `Desc ${word()}`, site_tagline: `Tag ${word()}` }],
      ['no hero texts: site title and description stand in', { home_hero_title: '', home_hero_subtitle: '', site_title: `Site ${word()}`, site_description: `Desc ${word()}`, site_tagline: `Tag ${word()}` }],
      ['nothing set: built-in texts', { home_hero_title: '', home_hero_subtitle: '', site_title: '', site_description: '', site_tagline: '' }],
      ['long texts', { home_hero_title: `Operations workspace for the ${word()} platform team and everyone on call this week`, home_hero_subtitle: `${'Diagnostics and utilities. '.repeat(8)}${word()}`, site_title: `Infrastructure Tools ${word()}`, site_description: '', site_tagline: `Internal platform engineering ${word()}` }],
    ];
    for (const [name, settings] of cases) {
      const config = stamp(rng, real);
      Object.assign(config.settings, settings);
      await evidence.save(`settings-${name.split(':')[0].replace(/ /g, '-')}.json`, config.settings);
      await showConfig(page, holder, config);
      await expectHomeContent(page, config, name);
      await expectShell(page, config, '/', name);
      const hero = expectedHero(config);
      await softly(page.locator('#hero-section h1'), `${name}: the hero title is on screen`).toBeVisible();
      expect.soft(hero.title, `${name}: a hero title is always shown`).not.toBe('');
    }
  });

  test('the brand mark is the shield by default, the configured icon or emoji otherwise', async ({ page, request, rng }) => {
    const real = await fetchConfig(request);
    const holder = { config: real };
    await serve(page, holder);
    const cases: [string, string][] = [
      ['🛡️', 'bi-shield-lock-fill'], ['', 'bi-shield-lock-fill'], ['', ''], ['', 'bi-hdd-rack'], ['', 'bi bi-router'], ['🧰', 'bi-hdd-rack'], ['🛠', ''],
    ];
    for (const [favicon_emoji, brand_icon] of cases) {
      const config = stamp(rng, real);
      Object.assign(config.settings, { favicon_emoji, brand_icon });
      await showConfig(page, holder, config);
      // expectShell compares the brand mark with the oracle and names both settings in its message.
      await expectShell(page, config, '/', `favicon_emoji=${JSON.stringify(favicon_emoji)}, brand_icon=${JSON.stringify(brand_icon)}`);
    }
  });

  test('the announcement bar shows the text when enabled, in the info or the warning style, and nothing otherwise', async ({ page, request, rng, evidence }) => {
    const real = await fetchConfig(request);
    const holder = { config: real };
    await serve(page, holder);
    const text = `Resolver maintenance ${rng.string(8)} on Saturday`;
    const cases: Record<string, string>[] = [
      { announcement_enabled: '1', announcement_text: text, announcement_type: 'info' },
      { announcement_enabled: '1', announcement_text: text, announcement_type: 'warning' },
      { announcement_enabled: '0', announcement_text: text, announcement_type: 'warning' },
      { announcement_enabled: '1', announcement_text: '', announcement_type: 'info' },
    ];
    await evidence.save('announcement-cases.json', cases);
    const colours: Record<string, string> = {};
    for (const settings of cases) {
      const config = stamp(rng, real);
      Object.assign(config.settings, settings);
      const ctx = `announcement ${JSON.stringify(settings)}`;
      await showConfig(page, holder, config);
      await expectHomeContent(page, config, ctx);
      if (settings.announcement_enabled === '1' && settings.announcement_text) {
        await expect.soft(announcement(page), `${ctx}: the bar is on screen`).toBeVisible();
        colours[settings.announcement_type] = await announcement(page).evaluate(bar => getComputedStyle(bar).color);
      }
      // The announcement is extra: the directory under it is unchanged.
      await expectDirectory(page, config, {}, ctx);
    }
    expect.soft(colours.warning, `a warning (${colours.warning}) is told apart from an info announcement (${colours.info}) by its colour`).not.toBe(colours.info);
  });

  test('maintenance mode replaces the home page with the maintenance message; no hero, feature panel or directory', async ({ page, request, rng }) => {
    const real = await fetchConfig(request);
    const holder = { config: real };
    await serve(page, holder);
    const custom = `Back at ${rng.int(1, 12)}:${rng.pick(['00', '15', '30', '45'])} UTC, ticket ${rng.string(6)}`;
    for (const message of [custom, '']) {
      const config = stamp(rng, real);
      config.settings.maintenance_mode = '1';
      config.settings.maintenance_message = message;
      config.settings.announcement_enabled = '1';
      config.settings.announcement_text = 'not shown during maintenance';
      const ctx = `maintenance_mode "1", message ${JSON.stringify(message)}`;
      await showConfig(page, holder, config);

      await expect(page.getByRole('heading', { level: 1 }), `${ctx}: heading`).toHaveText('Under Maintenance');
      await softly(page.locator('main p'), `${ctx}: message (the built-in sentence when none is configured)`).toHaveText(message || DEFAULT_MAINTENANCE_MESSAGE);
      await softly(directory(page), `${ctx}: no tool directory`).toHaveCount(0);
      await softly(grid(page), `${ctx}: no tool cards`).toHaveCount(0);
      await softly(page.locator('section.signal-feature'), `${ctx}: no feature panel`).toHaveCount(0);
      await softly(page.locator('.signal-terminal-strip'), `${ctx}: no terminal strip`).toHaveCount(0);
      await softly(searchBox(page), `${ctx}: no search box`).toHaveCount(0);
      await softly(toolCount(page), `${ctx}: no tool count`).toHaveCount(0);
      await softly(announcement(page), `${ctx}: no announcement bar`).toHaveCount(0);
      await softly(themeToggle(page), `${ctx}: the top bar stays`).toBeVisible();
    }

    // Any other value is not maintenance mode.
    const config = stamp(rng, real);
    config.settings.maintenance_mode = '0';
    config.settings.maintenance_message = custom;
    await showConfig(page, holder, config);
    await expectWorkspaceMatches(page, config, 'maintenance_mode "0" with a maintenance message configured');
  });

  test('site pages, header and footer menus (hidden and new-tab entries) and footer texts follow the configuration', async ({ page, request, rng, evidence }) => {
    const real = await fetchConfig(request);
    const holder = { config: real };
    await serve(page, holder);
    const footers: [string, string][] = [
      [`Run by the ${rng.string(6)} team`, `© ${rng.int(2020, 2030)} ${rng.string(5)} GmbH`],
      ['', ''],
      ['SysAdmin Toolkit · GeoIP by MaxMind · All processing runs in your browser', `© ${rng.string(5)}`],
      ['SysAdmin Toolkit · GeoIP by MaxMind · Local log analysis. Remote network lookups.', ''],
    ];
    for (const [footer_text, copyright_text] of footers) {
      const config = stamp(rng, real);
      config.pages = randomPages(rng, rng.int(1, 3));
      config.menus = randomMenus(rng);
      Object.assign(config.footer, { footer_text, copyright_text });
      await evidence.save(`menus-pages-footer-${footers.findIndex(f => f[0] === footer_text)}.json`, { pages: config.pages, menus: config.menus, footer: config.footer });
      const ctx = `footer_text=${JSON.stringify(footer_text)}, copyright_text=${JSON.stringify(copyright_text)}, ${config.pages.length} pages`;
      await showConfig(page, holder, config);
      await expectShell(page, config, '/', ctx);
      await softly(sidebar(page).getByRole('navigation', { name: 'Site pages' }).locator('a'), `${ctx}: site page links are visible in the sidebar`).toHaveText(config.pages.map(p => p.title));
      for (const hidden of [...config.menus.header, ...config.menus.footer].filter(item => item.is_visible === 0)) {
        await softly(page.getByRole('link', { name: hidden.label }), `${ctx}: hidden menu entry "${hidden.label}" is shown nowhere`).toHaveCount(0);
      }
      await softly(footer(page), `${ctx}: the footer is on screen`).toBeVisible();
    }

    // Without pages there is no "Site pages" block at all.
    const none = stamp(rng, real);
    none.pages = [];
    await showConfig(page, holder, none);
    await softly(sidebar(page).getByRole('navigation', { name: 'Site pages' }), 'no pages: no "Site pages" navigation').toHaveCount(0);
  });

  test('markup in labels, descriptions and site texts is shown as text and never runs', async ({ page, request, rng, evidence }) => {
    const real = await fetchConfig(request);
    const config = stamp(rng, real);
    const mark = `e2e${rng.string(6)}`;
    const img = `<img src=x onerror="window.${mark}=1">`;
    const script = `<script>window.${mark}=1</script>`;
    const bold = `<b>${rng.string(5)}</b> &amp; &lt;i&gt;`;

    const targets = rng.sample(config.tools.filter(tool => tool.tool_key in CATALOGUE), 3);
    targets[0].label = `${img} ${targets[0].label}`;
    targets[0].description = `${script} ${targets[0].description}`;
    targets[1].label = bold;
    targets[1].description = `${img}${bold}`;
    targets[2].tags = `${img},${script}`;
    targets.forEach(tool => { tool.is_enabled = 1; });
    Object.assign(config.settings, {
      home_hero_title: `${img} hero`, home_hero_subtitle: `${script} subtitle`, site_title: `${bold} site`, site_tagline: `${img} tag`,
      announcement_enabled: '1', announcement_text: `${img}${script} notice`, announcement_type: 'info',
    });
    Object.assign(config.footer, { footer_text: `${img} footer`, copyright_text: `${script} copyright` });
    config.pages = [{ id: 901, slug: 'markup', title: `${img} page`, sort_order: 1 }];
    config.menus.header.push({ id: 902, location: 'header', label: `${bold} menu`, url: '/subnet', icon: '', sort_order: 99, is_visible: 1, open_in_new_tab: 0 });
    await evidence.save('markup-config.json', config);

    let dialogs = 0;
    page.on('dialog', dialog => { dialogs += 1; void dialog.dismiss(); });
    await openWithConfig(page, config);

    // Shown as text: every widget equals the configured strings, character for character.
    await expectWorkspaceMatches(page, config, 'configuration with markup');
    await softly(page.locator(`#tool-card-${targets[0].tool_key} .tool-card-title`), 'the label with <img> is visible as text').toContainText('<img src=x onerror=');

    // Search treats the markup as text too.
    for (const query of ['<img', 'onerror', '<script>', '&amp;']) {
      await searchBox(page).fill(query);
      await expectDirectory(page, config, { query }, `search for ${JSON.stringify(query)} in a configuration with markup`);
    }

    // Never executed, never turned into elements.
    expect.soft(await page.evaluate(name => (window as unknown as Record<string, unknown>)[name], mark), 'the injected handler/script must not have run').toBeUndefined();
    expect.soft(dialogs, 'no dialog was opened by injected markup').toBe(0);
    await softly(page.locator('.signal-workspace img'), 'no <img> element was created from configured text').toHaveCount(0);
    await softly(page.locator('.signal-workspace b'), 'no <b> element was created from configured text').toHaveCount(0);
    expect.soft(
      await page.locator('.signal-workspace script').evaluateAll((scripts, name) => scripts.filter(s => (s.textContent || '').trim() === `window.${name}=1`).length, mark),
      'no <script> element was created from configured text',
    ).toBe(0);
  });
});

test.describe('Served configuration — appearance', () => {
  test('palette colours apply to their theme when they are valid hex colours and are ignored otherwise; custom CSS is applied', async ({ page, request, rng, evidence }) => {
    const real = await fetchConfig(request);
    const hex = (length: 3 | 6) => `#${rng.string(length, '0123456789abcdef')}`;
    const token = (name: string) => page.evaluate(n => getComputedStyle(document.querySelector('.signal-workspace') as Element).getPropertyValue(n).trim(), name);
    /** A colour value as the browser reports it, for comparing `#abc` with `rgb(...)`. */
    const asRgb = (value: string) => page.evaluate(v => {
      const probe = document.createElement('span');
      probe.style.color = v;
      document.body.appendChild(probe);
      const out = getComputedStyle(probe).color;
      probe.remove();
      return out;
    }, value);

    // Defaults first, from a page without palette settings.
    const plain = stamp(rng, real);
    for (const key of Object.keys(plain.settings)) if (key.startsWith('palette_')) delete plain.settings[key];
    plain.settings.custom_css = '';
    const holder = { config: plain };
    await serve(page, holder);
    await showConfig(page, holder, plain);
    const defaults = { dark: { primary: await asRgb(await token('--accent-primary')), text: await asRgb(await token('--text-primary')) }, light: { primary: '', text: '' } };
    await themeToggle(page).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    defaults.light = { primary: await asRgb(await token('--accent-primary')), text: await asRgb(await token('--text-primary')) };
    await themeToggle(page).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');

    const config = stamp(rng, real);
    const invalid = rng.pick(['red', '#12345', '#gggggg', 'rgb(1,2,3)', '#1234567', '']);
    Object.assign(config.settings, {
      palette_primary: hex(6),                // dark theme, six digits
      palette_primary_light: hex(3),          // light theme, shorthand
      palette_text_primary: invalid,          // ignored: the built-in colour stays
      palette_text_primary_light: ` ${hex(6).toUpperCase()} `, // upper case and padded: still a colour
      custom_css: `.signal-tool-count { outline: 3px solid rgb(${rng.int(1, 250)}, ${rng.int(1, 250)}, ${rng.int(1, 250)}); }`,
    });
    await evidence.save('appearance-settings.json', config.settings);
    await showConfig(page, holder, config);
    const s = config.settings;

    expect.soft(await asRgb(await token('--accent-primary')), `dark theme: --accent-primary for palette_primary "${s.palette_primary}"`).toBe(paletteColorAsRgb(s.palette_primary));
    expect.soft(await asRgb(await token('--text-primary')), `dark theme: --text-primary keeps its built-in value because palette_text_primary "${invalid}" is not a hex colour`).toBe(defaults.dark.text);
    expect.soft(paletteColorAsRgb(invalid), `oracle check: "${invalid}" is not a valid palette colour`).toBeNull();
    const outline = s.custom_css.match(/rgb\([^)]+\)/)?.[0] as string;
    await softly(toolCount(page), `custom_css "${s.custom_css}" is applied`).toHaveCSS('outline-color', outline);

    await themeToggle(page).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    expect.soft(await asRgb(await token('--accent-primary')), `light theme: --accent-primary for palette_primary_light "${s.palette_primary_light}" (3-digit shorthand)`).toBe(paletteColorAsRgb(s.palette_primary_light));
    expect.soft(await asRgb(await token('--text-primary')), `light theme: --text-primary for palette_text_primary_light "${s.palette_text_primary_light}"`).toBe(paletteColorAsRgb(s.palette_text_primary_light));

    // The colour is used, not only declared: the pressed filter button is drawn in the primary colour.
    await softly(categoryButton(page, ALL_TOOLS), 'light theme: the pressed "All tools" button uses the configured primary colour').toHaveCSS('color', paletteColorAsRgb(s.palette_primary_light) as string);
    // The directory itself is unaffected by appearance settings.
    await softly(cards(page), 'appearance settings do not change the directory').toHaveCount(visibleTools(config, ALL_TOOLS, '').length);
    expect.soft(defaults.light.primary, 'the light and dark themes have different built-in primary colours').not.toBe(defaults.dark.primary);
  });
});
