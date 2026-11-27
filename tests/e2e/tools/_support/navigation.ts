import { expect, type Page } from '@playwright/test';

/**
 * Opens a tool the way a visitor does and checks the page that answers.
 *
 * Returns after the tool's heading is on screen and React has hydrated, so the
 * next step can type or click straight away.
 */
export async function openTool(page: Page, route: string, heading: string | RegExp): Promise<void> {
  const response = await page.goto(route, { waitUntil: 'domcontentloaded' });
  expect(response?.status(), `${route} should answer 200`).toBe(200);
  await expect(page.getByRole('heading', { level: 1, name: heading }), `${route} should show its title`).toBeVisible();
  await waitForHydration(page);
}

/**
 * React attaches event handlers after the HTML arrives. A click before that
 * is lost, which looks like a broken control. React 19 marks hydrated DOM
 * nodes with a `__reactFiber$…` property; wait for it on the main region.
 */
export async function waitForHydration(page: Page): Promise<void> {
  await page.waitForFunction(() => {
    const main = document.querySelector('main');
    return !!main && Object.keys(main).some(key => key.startsWith('__reactFiber$') || key.startsWith('__reactProps$'));
  }, undefined, { timeout: 30_000 });
}

/**
 * The tool must be reachable from the home page directory and from the
 * sidebar, and both links must land on `route`.
 */
export async function expectToolLinkedFromHome(page: Page, route: string): Promise<void> {
  await page.goto('/', { waitUntil: 'domcontentloaded' });
  await waitForHydration(page);
  const card = page.locator(`#tool-grid a[href="${route}"]`).first();
  await expect(card, `home page directory should list a card linking to ${route}`).toBeVisible();
  const sidebarLink = page.locator(`aside.signal-sidebar a[href="${route}"]`).first();
  await expect(sidebarLink, `sidebar should link to ${route}`).toBeVisible();
  await card.click();
  await expect(page, `the home page card should open ${route}`).toHaveURL(new RegExp(`${route.replace(/[/-]/g, '\\$&')}$`));
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible();
}
