import { test, expect } from '@playwright/test';

/**
 * Custom tool ordering — the public half.
 *
 * The feature has two sides: the admin panel writes `sort_order`, and the
 * homepage reads it via GET /api/site/config (`ORDER BY sort_order ASC`,
 * backend/src/routes/public.js). The write side needs an authenticated admin
 * session and mutates the dev database, so it is not exercised here. What this
 * spec pins is the half a visitor actually sees, plus the invariant that makes
 * the ordering deterministic at all.
 *
 * Read-only by design: no request here mutates `tools`.
 */

const API = 'http://localhost:4001/api/site/config';

test.describe('Custom tool ordering', () => {
  test('homepage renders tools in the order stored in sort_order', async ({ page }) => {
    const cfg = await (await page.request.get(API)).json();
    const expected: string[] = cfg.tools.map((t: any) => t.tool_key);
    expect(expected.length).toBeGreaterThan(0);

    await page.goto('http://localhost:3001/');
    await page.waitForLoadState('networkidle');

    const cards = page.locator('.tool-card');
    await expect(cards.first()).toBeVisible();

    // The persistent tool identity is independent of routes: password uses
    // /password-generator. Compare the cards' keys with configured ordering.
    const rendered = await cards.evaluateAll(els =>
      els.map(e => (e.id || '').replace(/^tool-card-/, ''))
    );
    expect(rendered).toEqual(expected);
  });

  test('the API serves tools in ascending sort_order', async ({ page }) => {
    const cfg = await (await page.request.get(API)).json();
    const orders: number[] = cfg.tools.map((t: any) => t.sort_order);

    expect(orders).toEqual([...orders].sort((a, b) => a - b));
  });

  test('every enabled tool has a distinct sort_order', async ({ page }) => {
    // The real teeth of this feature. `tools.sort_order` has no UNIQUE
    // constraint (backend/migrations/001_initial.sql) and the default is 0, so
    // any migration adding a tool without picking a value lands it on the same
    // 0 as every other such tool. MySQL promises no order among rows tied on
    // the sort key, so the homepage would reshuffle those tools on reload.
    // That already happened once: migration 007 shipped 'password' with
    // sort_order 10, colliding with 'myip', and needed a follow-up statement
    // to separate them.
    //
    // This asserts the invariant rather than a fixed order, so it stays true
    // as tools are added and reordered.
    const cfg = await (await page.request.get(API)).json();
    const orders: number[] = cfg.tools.map((t: any) => t.sort_order);
    const duplicates = orders.filter((o, i) => orders.indexOf(o) !== i);

    expect(duplicates, `duplicate sort_order values: ${[...new Set(duplicates)].join(', ')}`).toEqual([]);
  });

  test('no enabled tool is left on the schema default of 0', async ({ page }) => {
    // sort_order INT DEFAULT 0 (001_initial.sql). A tool still sitting on 0
    // was registered without choosing a position, and with more than one such
    // tool the tie check above is what would fail first.
    const cfg = await (await page.request.get(API)).json();
    const unpositioned = cfg.tools.filter((t: any) => t.sort_order === 0).map((t: any) => t.tool_key);

    expect(unpositioned, `tools on the default sort_order 0: ${unpositioned.join(', ')}`).toEqual([]);
  });
});
