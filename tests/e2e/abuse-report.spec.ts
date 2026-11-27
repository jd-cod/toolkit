import type { Page, Route } from '@playwright/test';
import { test, expect, waitForEngineReady } from './fixtures/dashboard';

/**
 * The AbuseIPDB card of the dashboard, and what it adds to the report: the
 * score of every checked address and the requests that address made.
 * AbuseIPDB itself is answered here, so no API key is needed.
 */

const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
const p2 = (n: number) => String(n).padStart(2, '0');

type Row = { s: number; ip: string; method: string; url: string; status: number; bytes: number };
const ROWS: Row[] = [];
// 24 addresses; 81.2.69.1 is the most active, 81.2.69.24 the least.
for (let a = 1; a <= 24; a++) {
  for (let i = 0; i < 30 - a; i++) {
    ROWS.push({ s: a * 100 + i, ip: `81.2.69.${a}`, method: i % 5 === 0 ? 'POST' : 'GET', url: `/shop/item-${a}-${i}?ref=${i}`, status: i % 7 === 0 ? 404 : 200, bytes: 100 + i });
  }
}
ROWS.sort((x, y) => x.s - y.s);
const clock = (s: number) => `${p2(10 + Math.floor(s / 3600))}:${p2(Math.floor(s / 60) % 60)}:${p2(s % 60)}`;
const LOG = ROWS.map(r => `${r.ip} - - [27/Nov/2026:${clock(r.s)} +0200] "${r.method} ${r.url} HTTP/1.1" ${r.status} ${r.bytes} "-" "${BROWSER}"`).join('\n') + '\n';
const of = (ip: string) => ROWS.filter(r => r.ip === ip);

const SCORES: Record<string, number> = { '81.2.69.1': 100, '81.2.69.2': 40, '81.2.69.3': 0 };

/** Answers /api/abuse like the backend does; records what the page asked for. */
async function answerAbuse(page: Page, asked: string[][], reply?: (route: Route, ips: string[]) => Promise<void> | void) {
  await page.route('**/api/abuse', async route => {
    const body = route.request().postDataJSON();
    const ips: string[] = body.ips.map((item: { ip: string }) => item.ip);
    asked.push(ips);
    expect(body.max).toBe(20);
    if (reply) return reply(route, ips);
    const results = ips.map(ip => (ip === '81.2.69.4'
      ? { ip, hits: 0, domain: 'API_ERROR', abuse_score: 0, country: 'Unknown', error: 'HTTP 429' }
      : { ip, hits: 0, domain: `host-${ip.split('.')[3]}.example`, abuse_score: SCORES[ip] ?? 5, country_code: 'GB', total_reports: 3 }));
    return route.fulfill({ json: { abusive: results.filter(r => r.abuse_score > 0), non_abusive: results.filter(r => r.abuse_score === 0), api_available: true, checked_count: results.length } });
  });
}

async function analyse(page: Page) {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  await page.getByRole('tab', { name: 'Paste logs' }).click();
  await page.fill('#nginx-logtext', LOG);
  await page.click('#nginx-analyze-btn');
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText(String(ROWS.length), { timeout: 45_000 });
}

async function downloadReport(page: Page, compact: boolean): Promise<string> {
  await page.click('#dash-download-btn');
  await expect(page.locator('#download-modal-backdrop')).toBeVisible();
  await page.locator('#dl-compact-cb').setChecked(compact);
  const [download] = await Promise.all([page.waitForEvent('download', { timeout: 30_000 }), page.click('#dl-start-btn')]);
  const chunks: Buffer[] = [];
  for await (const chunk of await download.createReadStream()) chunks.push(chunk as Buffer);
  await page.locator('#dl-modal-close').click();
  return Buffer.concat(chunks).toString('utf8');
}

const abuseRows = (page: Page) => page.locator('#abuse-table-rows tr');
const plain = (html: string) => html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');

test.describe('AbuseIPDB on the dashboard and in the report', () => {
  test('the 20 most active addresses are checked, and a failed lookup is not shown as clean', async ({ page, console: watcher }) => {
    const asked: string[][] = [];
    await answerAbuse(page, asked);
    await analyse(page);
    await expect(abuseRows(page)).toHaveCount(20);
    await page.click('#btn-center-scan-abuse');

    await expect(abuseRows(page).nth(0)).toContainText('100% Bad');
    expect(asked).toEqual([Array.from({ length: 20 }, (_, i) => `81.2.69.${i + 1}`)]);
    await expect(abuseRows(page)).toHaveCount(20);
    await expect(abuseRows(page).nth(0)).toContainText('host-1.example');
    await expect(abuseRows(page).nth(1)).toContainText('40% Susp.');
    await expect(abuseRows(page).nth(2)).toContainText('0% Clean');
    await expect(abuseRows(page).nth(3)).toContainText('Lookup failed');
    await expect(abuseRows(page).nth(3)).not.toContainText('Clean');
    await expect(page.locator('#abuse-scan-note')).toHaveText('1 of 20 addresses could not be looked up.');

    // "Check the rest" asks only for the address that has no answer yet.
    await page.click('#btn-scan-abuseipdb');
    await expect.poll(() => asked.length).toBe(2);
    expect(asked[1]).toEqual(['81.2.69.4']);
    watcher.assertClean();
  });

  test('the report lists the checked addresses with their scores and their requests', async ({ page, console: watcher }) => {
    await answerAbuse(page, []);
    await analyse(page);
    await page.click('#btn-center-scan-abuse');
    await expect(abuseRows(page).nth(0)).toContainText('100% Bad');

    // Compact: the requests are data in the file, drawn when a row is opened.
    const compact = await downloadReport(page, true);
    expect(plain(compact)).toContain('AbuseIPDB Results');
    const table = plain(compact.slice(compact.indexOf('AbuseIPDB Results')));
    // Highest score first; the address whose lookup failed is not in the table.
    expect(table.indexOf('81.2.69.1 ')).toBeLessThan(table.indexOf('81.2.69.2 '));
    expect(table).toContain(`View Logs (${of('81.2.69.1').length})`);
    expect(compact).not.toContain('data-ip="81.2.69.4"');
    const json = JSON.parse(compact.match(/<script type="application\/json" id="_log_json">([\s\S]*?)<\/script>/)![1]);
    // In the order of the log, with the time as the server wrote it.
    expect(json['81.2.69.1']).toEqual(of('81.2.69.1').map(r => [`2026-11-27 ${clock(r.s)}`, r.method, r.status, r.url.replace('&', '&amp;'), r.bytes]));
    expect(Object.keys(json).sort()).toEqual(Array.from({ length: 20 }, (_, i) => `81.2.69.${i + 1}`).filter(ip => ip !== '81.2.69.4').sort());

    // Full: the requests are rows of the report itself.
    const full = plain(await downloadReport(page, false));
    const first = of('81.2.69.2')[0];
    expect(full).toContain(`2026-11-27 ${clock(first.s)} ${first.method} ${first.status} ${first.url} ${first.bytes} B`);
    watcher.assertClean();
  });

  test('the report of a filtered view holds the requests the filter lets through', async ({ page, console: watcher }) => {
    const asked: string[][] = [];
    await answerAbuse(page, asked);
    await analyse(page);
    await page.click('#btn-center-scan-abuse');
    await expect(abuseRows(page).nth(0)).toContainText('100% Bad');

    await page.locator('#filter-status').selectOption('4xx');
    await expect(page.locator('.kpi-card-total .stat-value')).toHaveText(String(ROWS.filter(r => r.status === 404).length));
    // The scores are kept: every address of the filtered view is known, so nothing is asked again.
    await expect(abuseRows(page).nth(0)).toContainText('100% Bad');
    await expect(page.locator('#abuse-overlay')).toBeHidden();
    expect(asked.length).toBe(1);

    const report = await downloadReport(page, true);
    const json = JSON.parse(report.match(/<script type="application\/json" id="_log_json">([\s\S]*?)<\/script>/)![1]);
    expect(json['81.2.69.1'].map((entry: unknown[]) => entry[2])).toEqual(of('81.2.69.1').filter(r => r.status === 404).map(() => 404));
    watcher.assertClean();
  });

  test('without a scan the report has no AbuseIPDB table', async ({ page, console: watcher }) => {
    await analyse(page);
    expect(plain(await downloadReport(page, true))).not.toContain('AbuseIPDB Results');
    watcher.assertClean();
  });

  test('a server without an API key says so', async ({ page, console: watcher }) => {
    await answerAbuse(page, [], route => route.fulfill({ json: { abusive: [], non_abusive: [], api_available: false, checked_count: 0 } }));
    await analyse(page);
    await page.click('#btn-center-scan-abuse');
    await expect(page.locator('#abuse-scan-note')).toHaveText('AbuseIPDB is not set up on this server (no API key), so no address was checked.');
    await expect(abuseRows(page).nth(0)).toContainText('Unchecked');
    await expect(page.locator('#btn-scan-abuseipdb')).toBeHidden();
    watcher.assertClean();
  });

  test('a scan that fails can be tried again', async ({ page }) => {
    let calls = 0;
    await answerAbuse(page, [], (route, ips) => (++calls === 1
      ? route.fulfill({ status: 502, body: 'Bad gateway' })
      : route.fulfill({ json: { abusive: ips.map(ip => ({ ip, abuse_score: 77, domain: 'x.example', country_code: 'NL' })), non_abusive: [], api_available: true } })));
    await analyse(page);
    await page.click('#btn-center-scan-abuse');
    await expect(page.locator('#abuse-scan-note')).toHaveText('AbuseIPDB could not be asked (HTTP 502).');
    await expect(abuseRows(page).nth(0)).toContainText('Unchecked');
    await page.click('#btn-scan-abuseipdb');
    await expect(abuseRows(page).nth(0)).toContainText('77% Susp.');
    await expect(page.locator('#abuse-scan-note')).toBeHidden();
    await expect(page.locator('#btn-scan-abuseipdb')).toBeHidden();
  });
});
