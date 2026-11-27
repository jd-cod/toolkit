import { test, expect, waitForEngineReady } from './fixtures/dashboard';

/**
 * The sample logs offered on the start page. They are not in the repository:
 * `npm run samples` in frontend/ writes them before `dev` and `build`. A
 * missing file shows as "Could not load sample file: HTTP 404".
 */
const SAMPLES: Record<string, { requests: number; expect: (cards: Record<string, number>) => void }> = {
  'ecommerce-normal.log': { requests: 5243, expect: c => expect(c.human).toBeGreaterThan(90) },
  'attack-scanners.log': { requests: 4150, expect: c => expect(c.human).toBeLessThan(60) },
  'ddos-flood.log': { requests: 15213, expect: c => expect(c.human).toBeLessThan(40) },
  'bot-crawlers.log': { requests: 4468, expect: c => expect(c.human).toBeLessThan(50) },
  'heavy-traffic.log': { requests: 100000, expect: c => { expect(c.human).toBeGreaterThan(65); expect(c.human).toBeLessThan(75); } },
};

test.describe('Sample logs on the start page', () => {
  test('the page offers exactly the samples that are checked here', async ({ page }) => {
    await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
    await waitForEngineReady(page);
    const offered = await page.locator('.btn-sample').evaluateAll(buttons => buttons.map(b => (b as HTMLElement).dataset.sample));
    expect(offered.sort()).toEqual(Object.keys(SAMPLES).sort());
  });

  for (const [file, sample] of Object.entries(SAMPLES)) {
    test(`${file} loads and is analysed`, async ({ page, console: watcher }) => {
      await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
      await waitForEngineReady(page);
      await page.locator(`.btn-sample[data-sample="${file}"]`).click();
      await expect(page.locator('#nginx-dashboard')).toBeVisible({ timeout: 90_000 });
      await expect(page.locator('.kpi-card-total .stat-value')).toHaveText(sample.requests.toLocaleString('en-US'));
      const human = Number((await page.locator('.kpi-card-human .stat-value').innerText()).replace('%', ''));
      sample.expect({ human });
      watcher.assertClean();
    });
  }
});
