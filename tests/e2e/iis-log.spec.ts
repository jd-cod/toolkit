import { test, expect, waitForEngineReady } from './fixtures/dashboard';

/**
 * IIS (W3C extended) logs in the Traffic Analyzer.
 *
 * The parser reads the column layout from the "#Fields:" header, so this
 * pins the whole path: header detection, row mapping and the dashboard
 * totals. Parser details are covered by tests/unit/iis-log-parser.test.js.
 */

const HEADER = [
  '#Software: Microsoft Internet Information Services 10.0',
  '#Version: 1.0',
  '#Date: 2026-11-20 10:15:00',
  '#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken',
];
const CLIENTS = ['66.249.66.1', '8.8.4.4', '1.1.1.1', '9.9.9.9'];
const ROWS = Array.from({ length: 120 }, (_, i) => {
  const second = String(i % 60).padStart(2, '0');
  const minute = String(15 + Math.floor(i / 60)).padStart(2, '0');
  const status = i % 10 === 0 ? 404 : 200;
  return `2026-11-20 10:${minute}:${second} 10.0.0.5 GET /page${i % 5} - 443 - ${CLIENTS[i % CLIENTS.length]} Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) - ${status} 0 0 12`;
});

test('an IIS log with a #Fields header is analysed like an nginx log', async ({ page, console: watcher }) => {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  await page.getByRole('tab', { name: 'Paste logs' }).click();
  await page.fill('#nginx-logtext', [...HEADER, ...ROWS].join('\n'));
  await page.click('#nginx-analyze-btn');

  await expect(page.locator('#nginx-dashboard')).toBeVisible({ timeout: 45_000 });
  const cards = page.locator('.kpi-micro-card');
  await expect(cards.first()).toBeVisible();
  await expect(cards.filter({ hasText: /total requests/i })).toContainText('120');
  await expect(cards.filter({ hasText: /unique ips/i })).toContainText('4');
  watcher.assertClean();
});
