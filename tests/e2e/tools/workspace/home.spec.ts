import { test, expect } from '../_support/fixtures';
import { VIEWPORTS } from '../_support/ui-audit';
import { ALL_TOOLS, CATEGORY_ORDER, catalogueEntry, enabledTools, expectedHero, toolsInCategory, visibleTools } from './oracle';
import { noMatchQuery, randomQueries } from './generator';
import {
  breadcrumbCurrent, cards, categoryButton, emptyState, fetchConfig, openHome, searchBox, sidebar, toolCount,
} from './page';
import { expectDirectory, expectHomeContent, expectIconsDrawn, softly } from './checks';

/**
 * Workspace shell: the home page tool directory and the navigation chrome
 * every tool lives in. Runs against the real site configuration
 * (GET /api/site/config) and, in config-variants.spec.ts and degraded.spec.ts,
 * against configurations the test serves in its place.
 *
 * Oracle: ./oracle.ts (definitions 1-8 at its top). Inputs: ./generator.ts.
 *
 * INVENTORY (each entry names the spec that covers it)
 *
 * Inputs
 *  - Site configuration: settings, tools, menus, footer, pages ......... all specs (real), config-variants (served)
 *  - Directory search box (typing) .................................... home
 *  - Command palette search field (typing) ............................ command-palette
 *  - Stored theme choice (localStorage `theme`), system colour scheme .. theme
 *  - Viewport width (desktop 1440, laptop 1024, mobile 390) ............ mobile, layout
 *  - URL: `/`, every tool route, `/password`, unknown routes, `/page/<slug>`, `/robots.txt`, `/sitemap.xml`, `/admin` .. seo, navigation
 *
 * Controls
 *  - Category filter buttons (All tools + 4 categories) ................ home
 *  - "Clear filters" (empty state) ..................................... home
 *  - Directory cards (links) ........................................... home
 *  - Feature panel links ("Analyze your logs", "Explore a sample"), terminal strip link .. home (targets)
 *  - Sidebar: brand, "Find a tool", Overview, tool links, site page links .. navigation
 *  - Top bar: breadcrumb "Workspace", custom menu links, theme toggle, mobile menu button .. navigation, theme, mobile
 *  - Command palette: open (button, Ctrl+K, Cmd+K), type, Tab+Enter, click, Esc, close button, backdrop .. command-palette
 *  - Mobile drawer: open, close button, backdrop, Esc, link, "Find a tool" .. mobile
 *  - "Skip to content" .................................................. navigation
 *  - "Try again" (directory) and "Retry" (sidebar) after a failed refresh .. degraded
 *  - Browser back / forward, reload, opening a link in a new tab ....... navigation, theme
 *
 * Displayed values
 *  - Hero title, subtitle, "N purpose-built tools", tagline ............ home, config-variants
 *  - Feature panel, trust strip, terminal strip (only with nginx) ...... home, config-variants
 *  - Announcement bar (text, info/warning) ............................. config-variants
 *  - Category buttons: name, count, pressed state ...................... home, config-variants
 *  - Cards: order, label, description, category, processing note, icon, colour, link .. home, config-variants
 *  - Screen-reader status "N tools found" .............................. home
 *  - Empty states "No tools found" / "No tools enabled yet" ............ home, config-variants
 *  - Sidebar: brand name, tagline, brand mark, groups, links, icons, current page, site pages, version .. navigation, config-variants
 *  - Top bar: breadcrumb label, custom menu (visible entries, new-tab attributes), theme icon and title .. navigation, theme
 *  - Command palette: results (label, category, icon, link), "No tools match" message, hint .. command-palette
 *  - Footer: text line, copyright, links ............................... navigation, config-variants
 *  - Maintenance screen ................................................ config-variants
 *  - Appearance: palette colours and custom CSS from settings .......... config-variants
 *  - <title>, meta description, canonical, robots.txt, sitemap.xml ..... seo
 *
 * Outputs
 *  - None: the shell has no copy, export or share. Its "outputs" are navigations (links land on the right
 *    route) and the stored theme choice. Layer 6 is otherwise not applicable.
 *
 * States
 *  - Default, filtered by category, filtered by search, both, nothing found ........ home
 *  - Refreshing (skeleton cards, "Loading tools…"), refresh failed, recovered ..... degraded
 *  - No tools enabled, maintenance mode ............................................ config-variants
 *  - Palette open / closed; drawer open / closed; dark / light theme ............... command-palette, mobile, theme
 *  - 404 page ....................................................................... seo, layout
 *
 * Layers: 1 reachable (home, seo, navigation) · 2 layout (layout) · 3 input paths (home, command-palette)
 * · 4 displayed values (all) · 5 controls (home, command-palette, theme, mobile) · 6 not applicable (see Outputs)
 * · 7 failure (degraded, config-variants markup test, seo 404) · 8 state and navigation (navigation, theme).
 *
 * Not covered here: the admin area (only that `/admin` asks for a login, in seo.spec.ts).
 */

test.describe('Home page — content from the site configuration', () => {
  test('hero, tool count, tagline, feature panel and announcement follow the settings', async ({ page, request }) => {
    const config = await fetchConfig(request);
    await openHome(page);
    await expectHomeContent(page, config, 'real configuration');
    await expect(page, 'home page URL').toHaveURL(/\/$/);
    await expect.soft(toolCount(page), 'the tool count is visible on a desktop screen').toBeVisible();
    await expect.soft(page.getByRole('heading', { level: 1 }), 'exactly one h1 on the home page').toHaveCount(1);
    await expect.soft(breadcrumbCurrent(page), 'breadcrumb on the home page').toHaveText('Overview');
  });

  test('the directory lists exactly the enabled tools in sort order, each card with its configured content', async ({ page, request, evidence }) => {
    const config = await fetchConfig(request);
    await evidence.save('site-config.json', config);
    await openHome(page);
    await expectDirectory(page, config, {}, 'real configuration');
    await expectIconsDrawn(page, 'real configuration');
    // The number in the hero, the "All tools" button and the cards are the same quantity.
    const total = enabledTools(config).length;
    await expect.soft(cards(page), `number of cards equals the ${total} enabled tools`).toHaveCount(total);
    await expect.soft(toolCount(page), 'hero count equals the number of cards').toHaveText(expectedHero(config).countText);
  });

  test('every card opens its tool: the route answers 200, shows an h1, and the shell marks that tool as current', async ({ page, request }) => {
    const config = await fetchConfig(request);
    const tools = enabledTools(config);
    expect(tools.length, 'the site should have at least one enabled tool').toBeGreaterThan(0);
    for (const tool of tools) {
      const route = catalogueEntry(tool.tool_key).route;
      const ctx = `card "${tool.label}" (${tool.tool_key})`;

      const direct = await request.get(route);
      expect.soft(direct.status(), `${ctx}: GET ${route}`).toBe(200);

      await openHome(page);
      await page.locator(`#tool-card-${tool.tool_key}`).click();
      await expect(page, `${ctx}: clicking the card should open ${route}`).toHaveURL(new RegExp(`${route.replace(/[/-]/g, '\\$&')}$`));
      await softly(page.getByRole('heading', { level: 1 }).first(), `${ctx}: the tool page shows an h1`).toBeVisible();
      await softly(page.getByRole('heading', { level: 1 }), `${ctx}: the tool page has exactly one h1`).toHaveCount(1);
      await softly(breadcrumbCurrent(page), `${ctx}: breadcrumb names the tool`).toHaveText(tool.label);
      await softly(sidebar(page).locator('a[aria-current="page"]'), `${ctx}: sidebar marks ${route} as the current page`).toHaveAttribute('href', route);
    }
  });
});

test.describe('Home page — category filter', () => {
  test('each button shows its count, shows exactly the tools of its category when pressed, and "All tools" restores', async ({ page, request, rng, evidence }) => {
    const config = await fetchConfig(request);
    await openHome(page);
    // Every category once in random order, then a few random switches (including pressing the same one twice).
    const sequence = [...rng.shuffle(CATEGORY_ORDER), ...Array.from({ length: 4 }, () => rng.pick([...CATEGORY_ORDER, ALL_TOOLS]))];
    await evidence.save('category-sequence.json', sequence);
    for (const category of sequence) {
      await categoryButton(page, category).click();
      await expectDirectory(page, config, { category }, `after pressing "${category}"`);
      // What the button promised is what the list shows.
      const promised = toolsInCategory(enabledTools(config), category).length;
      await softly(cards(page), `"${category}" shows as many cards as its button counts (${promised})`).toHaveCount(promised);
    }
    await categoryButton(page, ALL_TOOLS).click();
    await expectDirectory(page, config, {}, 'after pressing "All tools" again');
  });

  test('the counts are hidden on a phone but the buttons still filter', async ({ page, request, rng }) => {
    const config = await fetchConfig(request);
    await page.setViewportSize(VIEWPORTS.mobile);
    await openHome(page);
    const category = rng.pick(CATEGORY_ORDER);
    await categoryButton(page, category).click();
    await expectDirectory(page, config, { category }, `phone width, after pressing "${category}"`);
    await expect.soft(categoryButton(page, category), 'the pressed button is on screen').toBeInViewport();
  });
});

test.describe('Home page — search', () => {
  test('random queries show exactly the tools whose label, description, tags, key or category contain every word', async ({ page, request, rng, evidence }) => {
    const config = await fetchConfig(request);
    const queries = randomQueries(rng, enabledTools(config), 45);
    await evidence.save('search-queries.json', queries.map(q => ({ ...q, expected: visibleTools(config, ALL_TOOLS, q.query).map(t => t.tool_key) })));
    await openHome(page);
    for (const { query, kind } of queries) {
      await searchBox(page).fill(query);
      await expectDirectory(page, config, { query }, `search (${kind})`);
    }
    await searchBox(page).fill('');
    await expectDirectory(page, config, {}, 'after emptying the search box');
  });

  test('typing a query key by key gives the same result as pasting it', async ({ page, request, rng }) => {
    const config = await fetchConfig(request);
    const [{ query }] = randomQueries(rng.fork('typed'), enabledTools(config), 1);
    await openHome(page);
    await searchBox(page).click();
    await page.keyboard.type(query);
    await expectDirectory(page, config, { query }, 'typed key by key');
    // Deleting the last character re-filters for the shorter text.
    await page.keyboard.press('Backspace');
    await expectDirectory(page, config, { query: query.slice(0, -1) }, 'after Backspace');
  });

  test('a query that matches nothing shows "No tools found", and "Clear filters" restores every tool', async ({ page, request, rng, evidence }) => {
    const config = await fetchConfig(request);
    const query = noMatchQuery(rng, enabledTools(config));
    await evidence.save('no-match-query.txt', query);
    await openHome(page);
    await searchBox(page).fill(query);
    await expectDirectory(page, config, { query }, 'query that matches nothing');
    await expect(emptyState(page).getByRole('heading', { name: 'No tools found' }), `"${query}" matches no tool: the empty state must be shown`).toBeVisible();

    await emptyState(page).getByRole('button', { name: 'Clear filters' }).click();
    await expectDirectory(page, config, {}, 'after "Clear filters"');
  });

  test('category and search combine: only tools that satisfy both are shown, and "Clear filters" resets both', async ({ page, request, rng, evidence }) => {
    const config = await fetchConfig(request);
    const tools = enabledTools(config);
    const queries = randomQueries(rng, tools, 14);
    const steps = queries.map(q => ({ ...q, category: rng.pick([...CATEGORY_ORDER, ...CATEGORY_ORDER, ALL_TOOLS]) }));
    await evidence.save('category-and-search.json', steps.map(s => ({ ...s, expected: visibleTools(config, s.category, s.query).map(t => t.tool_key) })));
    await openHome(page);
    for (const [index, { query, kind, category }] of steps.entries()) {
      // Alternate which control is used first: the result must not depend on the order.
      if (index % 2 === 0) {
        await categoryButton(page, category).click();
        await searchBox(page).fill(query);
      } else {
        await searchBox(page).fill(query);
        await categoryButton(page, category).click();
      }
      await expectDirectory(page, config, { category, query }, `category + search (${kind})`);
    }

    // A combination that certainly matches nothing: a word of one category searched inside another.
    const filled = CATEGORY_ORDER.filter(category => toolsInCategory(tools, category).length > 0);
    expect(filled.length, 'the site should have tools in at least two categories').toBeGreaterThanOrEqual(2);
    const [here, there] = rng.sample(filled, 2);
    const outsider = rng.pick(toolsInCategory(tools, there));
    await categoryButton(page, here).click();
    await searchBox(page).fill(outsider.tool_key);
    await expectDirectory(page, config, { category: here, query: outsider.tool_key }, `key of a "${there}" tool searched inside "${here}"`);

    if (visibleTools(config, here, outsider.tool_key).length === 0) {
      await emptyState(page).getByRole('button', { name: 'Clear filters' }).click();
    } else {
      await categoryButton(page, ALL_TOOLS).click();
      await searchBox(page).fill('');
    }
    await expectDirectory(page, config, {}, 'after clearing category and search');
  });

  test('filters do not survive a reload: the directory starts unfiltered', async ({ page, request, rng }) => {
    const config = await fetchConfig(request);
    const category = rng.pick(CATEGORY_ORDER);
    const [{ query }] = randomQueries(rng, enabledTools(config), 1);
    await openHome(page);
    await categoryButton(page, category).click();
    await searchBox(page).fill(query);
    await expectDirectory(page, config, { category, query }, 'before reload');
    await page.reload({ waitUntil: 'domcontentloaded' });
    await expectDirectory(page, config, {}, 'after reload');
  });
});
