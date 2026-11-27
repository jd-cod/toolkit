import { test, expect } from '../_support/fixtures';
import { ALL_TOOLS, catalogueEntry, enabledTools, expectedPaletteResults, visibleTools } from './oracle';
import { noMatchQuery, randomQueries } from './generator';
import {
  fetchConfig, loadingBar, openHome, openPaletteByButton, openPaletteByShortcut, openRoute, palette, paletteInput,
  paletteResults, readPaletteResults, searchBox, sidebar, breadcrumbCurrent, type PaletteShortcut,
} from './page';
import { softly } from './checks';

/**
 * "Find a tool": the command palette in the sidebar, also opened with Ctrl+K
 * or Cmd+K. Its own hint line is the definition of its keys:
 * "Tab to a result, Enter to open · Esc to close".
 * Inventory and layer map: see home.spec.ts.
 */

const urlEndsWith = (route: string) => new RegExp(`${route.replace(/[/-]/g, '\\$&')}$`);

test.describe('Find a tool — opening and closing', () => {
  test('the sidebar button opens it with the cursor in the search field and every enabled tool listed', async ({ page, request }) => {
    const config = await fetchConfig(request);
    await openHome(page);
    await expect(palette(page), 'the palette is closed when the page opens').toBeHidden();
    await openPaletteByButton(page);
    await expect.soft(paletteInput(page), 'the cursor is in the search field').toBeFocused();
    await expect.soft(paletteInput(page), 'the search field starts empty').toHaveValue('');
    await expect.soft(palette(page).getByRole('heading', { name: 'Find a tool' }), 'palette title').toBeVisible();
    await expect.soft(palette(page).locator('.signal-command-hint'), 'hint line').toHaveText('Tab to a result, Enter to open · Esc to close');
    await softly.poll(() => readPaletteResults(page), { message: 'results before typing: every enabled tool with label, category, icon and link' })
      .toEqual(expectedPaletteResults(config, ''));
    await expect.soft(palette(page).getByRole('status'), 'no "no match" message while tools are listed').toHaveCount(0);
  });

  const shortcuts: [PaletteShortcut, string][] = [
    ['Control+k', 'Ctrl+K'],
    ['Meta+k', 'Cmd+K'],
    ['Control+K', 'Ctrl+K with Caps Lock on'],
  ];
  for (const [shortcut, name] of shortcuts) {
    test(`${name} opens it from the home page, from inside the directory search box, and from a tool page`, async ({ page, request, rng }) => {
      const config = await fetchConfig(request);
      const tool = rng.pick(enabledTools(config));
      await openHome(page);
      await openPaletteByShortcut(page, shortcut);
      await expect.soft(paletteInput(page), `${name} on the home page: cursor in the search field`).toBeFocused();
      await page.keyboard.press('Escape');
      await expect(palette(page)).toBeHidden();

      // The shortcut must not be swallowed, or typed, by a text field that has the focus.
      await searchBox(page).click();
      await openPaletteByShortcut(page, shortcut);
      await expect.soft(paletteInput(page), `${name} from the directory search box: cursor moves to the palette`).toBeFocused();
      await expect.soft(searchBox(page), `${name} must not type into the directory search box`).toHaveValue('');
      await page.keyboard.press('Escape');

      await openRoute(page, catalogueEntry(tool.tool_key).route);
      await openPaletteByShortcut(page, shortcut);
      await expect.soft(paletteInput(page), `${name} on ${catalogueEntry(tool.tool_key).route}: cursor in the search field`).toBeFocused();
      await softly.poll(() => readPaletteResults(page), { message: `${name} on a tool page: every enabled tool is listed` })
        .toEqual(expectedPaletteResults(config, ''));
    });
  }

  test('Esc, the close button and a click outside the box each close it', async ({ page }) => {
    await openHome(page);
    const closers: [string, () => Promise<void>][] = [
      ['Esc', () => page.keyboard.press('Escape')],
      ['the close button', () => palette(page).getByRole('button', { name: 'Close tool search' }).click()],
      // The backdrop: a point of the page that the palette box does not cover.
      ['a click outside the box', () => page.mouse.click(8, 8)],
    ];
    for (const [name, close] of closers) {
      await openPaletteByShortcut(page);
      await close();
      await expect(palette(page), `${name} should close "Find a tool"`).toBeHidden();
    }
    // A click inside the box must not close it.
    await openPaletteByShortcut(page);
    await palette(page).getByRole('heading', { name: 'Find a tool' }).click();
    await expect.soft(palette(page), 'a click inside the box keeps it open').toBeVisible();
  });

  test('reopening it starts fresh: empty search field and the full list', async ({ page, request, rng }) => {
    const config = await fetchConfig(request);
    const tools = enabledTools(config);
    // A query that hides at least one tool, so a left-over filter is visible.
    const narrowing = tools.map(tool => tool.tool_key).filter(key => visibleTools(config, ALL_TOOLS, key).length < tools.length);
    const query = narrowing.length > 0 ? rng.pick(narrowing) : noMatchQuery(rng, tools);
    await openHome(page);
    await openPaletteByShortcut(page);
    await paletteInput(page).fill(query);
    await softly.poll(() => readPaletteResults(page), { message: `results for "${query}"` }).toEqual(expectedPaletteResults(config, query));
    await page.keyboard.press('Escape');
    await expect(palette(page)).toBeHidden();

    await openPaletteByShortcut(page);
    await softly(paletteInput(page), `after closing with "${query}" typed and reopening, the search field should be empty again`).toHaveValue('');
    await softly.poll(() => readPaletteResults(page), {
      message: `after closing with "${query}" typed and reopening, every enabled tool should be listed again (a left-over filter hides tools from a visitor who opens the palette to browse)`,
    }).toEqual(expectedPaletteResults(config, ''));
  });
});

test.describe('Find a tool — searching', () => {
  test('random queries list exactly the tools the directory search would, in the same order', async ({ page, request, rng, evidence }) => {
    const config = await fetchConfig(request);
    const queries = randomQueries(rng, enabledTools(config), 30);
    await evidence.save('palette-queries.json', queries.map(q => ({ ...q, expected: expectedPaletteResults(config, q.query).map(r => r.href) })));
    await openHome(page);
    await openPaletteByShortcut(page);
    for (const { query, kind } of queries) {
      await paletteInput(page).fill(query);
      const want = expectedPaletteResults(config, query);
      const ctx = `palette search ${JSON.stringify(query)} (${kind})`;
      await softly.poll(() => readPaletteResults(page), { message: `${ctx}: results (label, category, icon, link), in order` }).toEqual(want);
      if (want.length === 0) {
        await softly(palette(page).getByRole('status'), `${ctx}: message when nothing matches`).toHaveText(`No tools match “${query}”. Try a different search.`);
      } else {
        await softly(palette(page).getByRole('status'), `${ctx}: no "no match" message while results are listed`).toHaveCount(0);
      }
    }
  });

  test('the directory search box and the palette give the same answer for the same query', async ({ page, request, rng, evidence }) => {
    const config = await fetchConfig(request);
    const queries = randomQueries(rng, enabledTools(config), 8);
    await evidence.save('shared-queries.json', queries);
    await openHome(page);
    for (const { query, kind } of queries) {
      await searchBox(page).fill(query);
      const inDirectory = await page.locator('#tool-grid a.tool-card').evaluateAll(links => links.map(link => link.getAttribute('href')));
      await openPaletteByShortcut(page);
      await paletteInput(page).fill(query);
      await softly.poll(async () => (await readPaletteResults(page)).map(result => result.href), {
        message: `query ${JSON.stringify(query)} (${kind}): the palette lists the same tools as the directory`,
      }).toEqual(inDirectory);
      await paletteInput(page).fill('');
      await page.keyboard.press('Escape');
    }
  });
});

test.describe('Find a tool — opening a tool', () => {
  test('Tab moves to the first result and Enter opens it', async ({ page, request, rng }) => {
    const config = await fetchConfig(request);
    const target = rng.pick(enabledTools(config));
    const first = expectedPaletteResults(config, target.tool_key)[0];
    await openHome(page);
    await openPaletteByShortcut(page);
    await page.keyboard.type(target.tool_key);
    await expect(paletteResults(page).first(), `first result for "${target.tool_key}"`).toHaveAttribute('href', first.href);
    await page.keyboard.press('Tab');
    await expect(paletteResults(page).first(), 'Tab from the search field should focus the first result').toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page, `Enter on "${first.label}" should open ${first.href}`).toHaveURL(urlEndsWith(first.href));
    await expect.soft(palette(page), 'the palette closes when a tool is opened').toBeHidden();
    await softly(breadcrumbCurrent(page), 'the breadcrumb names the opened tool').toHaveText(first.label);
    await softly(page.getByRole('heading', { level: 1 }).first(), 'the opened tool shows its h1').toBeVisible();
    await softly(loadingBar(page), 'the loading bar is gone once the tool is shown').toHaveCount(0);
  });

  test('clicking a result opens that tool, from the home page and from another tool', async ({ page, request, rng }) => {
    const config = await fetchConfig(request);
    const [start, target] = rng.sample(enabledTools(config), 2);
    for (const from of ['/', catalogueEntry(start.tool_key).route]) {
      const route = catalogueEntry(target.tool_key).route;
      await openRoute(page, from);
      await openPaletteByButton(page);
      await paletteResults(page).and(page.locator(`[href="${route}"]`)).click();
      await expect(page, `clicking "${target.label}" in the palette on ${from} should open ${route}`).toHaveURL(urlEndsWith(route));
      await expect.soft(palette(page), 'the palette closes when a tool is opened').toBeHidden();
      await softly(sidebar(page).locator('a[aria-current="page"]'), 'the sidebar marks the opened tool').toHaveAttribute('href', route);
      await softly(loadingBar(page), 'the loading bar is gone once the tool is shown').toHaveCount(0);
    }
  });

  test('choosing the tool that is already open closes the palette and leaves the page idle (no loading bar)', async ({ page, request, rng }) => {
    const config = await fetchConfig(request);
    const tool = rng.pick(enabledTools(config));
    const route = catalogueEntry(tool.tool_key).route;
    await openRoute(page, route);
    await openPaletteByShortcut(page);
    await paletteResults(page).and(page.locator(`[href="${route}"]`)).click();
    await expect(palette(page), 'the palette closes').toBeHidden();
    await expect(page, 'the page stays where it is').toHaveURL(urlEndsWith(route));
    await softly(
      loadingBar(page),
      `after choosing "${tool.label}" in the palette while already on ${route}, the navigation loading bar keeps running although nothing is loading`,
    ).toHaveCount(0);
  });

  test('a query that matches nothing offers no result to open', async ({ page, request, rng }) => {
    const config = await fetchConfig(request);
    const query = noMatchQuery(rng, enabledTools(config));
    await openHome(page);
    await openPaletteByShortcut(page);
    await paletteInput(page).fill(query);
    await expect(palette(page).getByRole('status'), `message for "${query}"`).toHaveText(`No tools match “${query}”. Try a different search.`);
    await expect.soft(paletteResults(page), `no results for "${query}"`).toHaveCount(0);
    await page.keyboard.press('Enter');
    await expect.soft(page, 'Enter with no result stays on the page').toHaveURL(/\/$/);
    await expect.soft(palette(page), 'the palette stays open').toBeVisible();
  });
});
