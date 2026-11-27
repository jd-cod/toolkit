import { gzipSync } from 'node:zlib';
import type { Page } from '@playwright/test';
import { test, expect, waitForEngineReady } from './fixtures/dashboard';

/**
 * One log, pasted and uploaded.
 *
 * Both go through the same engine: a pasted text is read like a file. Every
 * number here is read from the page in both modes and has to be the same, and
 * the totals have to match what the log below contains.
 */

const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
const p2 = (n: number) => String(n).padStart(2, '0');
const clock = (s: number) => `27/Nov/2026:${p2(10 + Math.floor(s / 3600))}:${p2(Math.floor(s / 60) % 60)}:${p2(s % 60)} +0000`;

type Row = { s: number; ip: string; method: string; url: string; status: number | '-'; ref: string; ua: string };
const ROWS: Row[] = [];
for (let i = 0; i < 240; i++) {
  const url = ['/', '/products', `/products?sku=${i % 9}`, `/api/items/${i % 5}`, '/pricing', '/static/app.js', `/missing/${i % 4}`][i % 7];
  ROWS.push({
    s: i * 5,
    ip: `81.2.69.${1 + (i % 24)}`,
    method: i % 6 === 0 ? 'POST' : 'GET',
    url,
    status: url.startsWith('/missing') ? 404 : (i % 17 === 0 ? 500 : (i % 5 === 0 ? 304 : 200)),
    ref: i % 4 === 0 ? `https://www.google.com/search?q=${i}` : (i % 4 === 1 ? 'https://shop.test/' : '-'),
    ua: BROWSER,
  });
}
// A script that polls one address, requests the server answered without a status,
// a burst inside one second, and refusals that "Ignore 403" hides.
for (let i = 0; i < 20; i++) ROWS.push({ s: 10 + i * 30, ip: '45.142.120.10', method: 'GET', url: '/api/status', status: 200, ref: '-', ua: 'curl/8.4.0' });
for (let i = 0; i < 4; i++) ROWS.push({ s: 100 + i, ip: `81.2.70.${i + 1}`, method: 'GET', url: '/aborted', status: '-', ref: '-', ua: BROWSER });
for (let i = 0; i < 12; i++) ROWS.push({ s: 601, ip: `81.2.71.${i + 1}`, method: 'GET', url: '/sale', status: i % 4 === 0 ? 503 : 200, ref: 'https://news.example.org/story', ua: BROWSER });
const REFUSED: Row[] = [];
for (let i = 0; i < 9; i++) REFUSED.push({ s: 700 + i, ip: `81.2.72.${i + 1}`, method: 'GET', url: `/members/${i}`, status: 403, ref: '-', ua: BROWSER });

const line = (r: Row) => `${r.ip} - - [${clock(r.s)}] "${r.method} ${r.url} HTTP/1.1" ${r.status} 512 "${r.ref}" "${r.ua}"`;
const LOG = [...ROWS, ...REFUSED].map(line).join('\n') + '\n';
const TOTAL = ROWS.length;
const count = (test: (r: Row) => boolean) => ROWS.filter(test).length;
const path = (r: Row) => r.url.split('?')[0];

type Mode = 'paste' | 'upload';
const MODES: Mode[] = ['paste', 'upload'];

async function analyse(page: Page, mode: Mode) {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  if (mode === 'paste') {
    await page.getByRole('tab', { name: 'Paste logs' }).click();
    await page.fill('#nginx-logtext', LOG);
  } else {
    await page.getByRole('tab', { name: 'Upload file' }).click();
    await page.setInputFiles('#nginx-logfile', { name: 'shop.log.gz', mimeType: 'application/gzip', buffer: gzipSync(LOG) });
  }
  await page.click('#nginx-analyze-btn');
  await expect(page.locator('#nginx-dashboard')).toBeVisible({ timeout: 45_000 });
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText(String(TOTAL));
}

const total = (page: Page) => page.locator('.kpi-card-total .stat-value');
const badge = (page: Page) => page.locator('#filter-matching-badge');

/** Makes a share link with the storage API answered here; returns the log text the page sent. */
async function sharedContent(page: Page): Promise<string> {
  let content = '';
  await page.route('**/api/storage/upload', route => {
    content = route.request().postDataJSON().content;
    return route.fulfill({ json: { r2Key: 'logs/test.gz', shareCode: 'parity' } });
  });
  await page.route('**/api/share', route => route.fulfill({ json: { code: 'parity' } }));
  await page.click('#dash-share-btn');
  await page.click('#share-submit-btn');
  await expect(page.locator('#share-url-display')).toContainText('/s/parity');
  return content;
}

/** Everything the dashboard counts, as text, so two modes can be compared. */
async function numbers(page: Page) {
  return page.evaluate(() => {
    const text = (el: Element | null) => (el?.textContent || '').replace(/\s+/g, ' ').trim();
    const cells = (selector: string) => [...document.querySelectorAll(selector)].map(row => [...row.querySelectorAll('td')].map(text));
    const options = (id: string) => [...(document.getElementById(id) as HTMLSelectElement).options].map(o => `${o.value}|${text(o)}`);
    const chart = (window as any).Chart.getChart(document.getElementById('rps-chart'));
    return {
      cards: [...document.querySelectorAll('.kpi-micro-card')].map(text),
      methods: text(document.querySelector('.methods-bandwidth-ribbon')),
      badge: text(document.getElementById('filter-matching-badge')),
      explorer: text(document.querySelector('#nginx-log-explorer h5 + span')),
      addresses: cells('.cross-filter-ip-row').map(row => row.slice(0, 2)),
      paths: cells('.cross-filter-path-row'),
      otherPaths: cells('.path-other-row'),
      bots: cells('.cross-filter-bot-row').map(row => row.slice(0, 2)),
      networks: cells('.cross-filter-asn-row'),
      referrers: cells('.referrer-site-row'),
      choices: Object.fromEntries(['filter-method', 'filter-status', 'filter-country', 'filter-path-select', 'filter-asn', 'filter-bot'].map(id => [id, options(id)])),
      timeline: chart.data.datasets.map((d: any) => d.data.map((p: any) => [p.x, p.y])),
      skipped: text(document.getElementById('exclusion-counts')),
    };
  });
}

test.describe('Pasted text and an uploaded file give the same dashboard', () => {
  test('every count on the page is the same in both modes', async ({ browser }) => {
    const seen: Record<string, Awaited<ReturnType<typeof numbers>>> = {};
    for (const mode of MODES) {
      const page = await browser.newPage();
      await analyse(page, mode);
      await expect(badge(page)).toContainText(`Matching ${TOTAL} / ${TOTAL} requests`);
      seen[mode] = await numbers(page);
      await page.close();
    }
    expect(seen.paste.explorer).toBe(`(${TOTAL} entries)`);
    expect(seen.paste.skipped).toContain('9 ordinary 403');
    expect(seen.paste.paths.find(row => row[0] === '/sale')).toEqual(['/sale', '12', `${(12 / TOTAL * 100).toFixed(1)}%`, '200 75% 503 25%']);
    expect(seen.paste.choices['filter-status']).toContain('other|No status (4)');
    expect(seen.paste.timeline[0].reduce((sum: number, p: number[]) => sum + p[1], 0)).toBe(TOTAL);
    expect(seen.upload).toEqual(seen.paste);
  });

  test('the downloaded report has the same tables in both modes', async ({ browser }) => {
    const sections: Record<string, Record<string, string>> = {};
    for (const mode of MODES) {
      const page = await browser.newPage();
      await analyse(page, mode);
      await page.click('#dash-download-btn');
      const [download] = await Promise.all([page.waitForEvent('download', { timeout: 30_000 }), page.click('#dl-start-btn')]);
      const chunks: Buffer[] = [];
      for await (const chunk of await download.createReadStream()) chunks.push(chunk as Buffer);
      const html = Buffer.concat(chunks).toString('utf8');
      await page.route('**/parity-report.html', route => route.fulfill({ contentType: 'text/html', body: html }));
      await page.goto('/parity-report.html', { waitUntil: 'domcontentloaded' });
      sections[mode] = await page.evaluate(() => {
        const text = (el: Element | null | undefined) => (el?.textContent || '').replace(/\s+/g, ' ').trim();
        const section = (title: string) => text([...document.querySelectorAll('.section')].find(s => text(s.querySelector('.section-header')).includes(title)));
        return {
          cards: text(document.querySelector('.container > .stat-cards')),
          http: section('HTTP'),
          rate: [...document.querySelectorAll('.stat-cards')].map(text).find(t => t.includes('Peak Rate')) || '',
          countries: section('Country Breakdown'),
          networks: section('ASN Breakdown'),
          addresses: section('Top'),
          bots: section('Bot'),
        };
      });
      await page.close();
    }
    // The tables carry the numbers that used to be missing after an upload.
    expect(sections.paste.countries).toMatch(/IPs from /);
    expect(sections.paste.http).toMatch(/Median: ?[\d,]+ bytes/);
    expect(sections.paste.rate).toContain('Busiest second');
    for (const [name, text] of Object.entries(sections.paste)) expect(text, name).not.toBe('');
    expect(sections.upload).toEqual(sections.paste);
  });

  for (const mode of MODES) {
    test(`${mode}: each filter keeps exactly the requests it names`, async ({ page, console: watcher }) => {
      await analyse(page, mode);
      const expectMatching = async (n: number) => {
        await expect(badge(page)).toContainText(`Matching ${n} / ${TOTAL} requests`);
        await expect(total(page)).toHaveText(String(n));
        await expect(page.locator('#nginx-log-explorer h5 + span')).toHaveText(`(${n} entries)`);
      };
      const clear = async () => { await page.click('#filter-clear-btn'); await expectMatching(TOTAL); };

      await page.selectOption('#filter-method', 'POST');
      await expectMatching(count(r => r.method === 'POST'));
      await clear();
      await page.selectOption('#filter-status', '5xx');
      await expectMatching(count(r => r.status !== '-' && r.status >= 500));
      await page.selectOption('#filter-status', '404');
      await expectMatching(count(r => r.status === 404));
      await page.selectOption('#filter-status', 'other');
      await expectMatching(4);
      await clear();
      await page.selectOption('#filter-path-select', '^/products');
      await expectMatching(count(r => path(r) === '/products'));
      await clear();
      await page.locator('.cross-filter-path-row[data-path="=/api/items/3"]').click();
      await expectMatching(count(r => path(r) === '/api/items/3'));
      await clear();
      await page.fill('#filter-path', '/api');
      await expectMatching(count(r => r.url.includes('/api')));
      await clear();
      await page.fill('#filter-ip', '81.2.69.1');
      await expectMatching(count(r => r.ip === '81.2.69.1'));
      await page.fill('#filter-ip', '81.2.70.');
      await expectMatching(count(r => r.ip.startsWith('81.2.70.')));
      await page.fill('#filter-ip', '81.2.71.0/29');
      await expectMatching(count(r => r.ip.startsWith('81.2.71.') && Number(r.ip.split('.')[3]) < 8));
      await clear();
      await page.fill('#filter-ua', 'CURL');
      await expectMatching(20);
      // Two filters together.
      await page.selectOption('#filter-method', 'GET');
      await page.fill('#filter-ua', 'chrome');
      await expectMatching(count(r => r.method === 'GET' && r.ua === BROWSER));
      watcher.assertClean();
    });

    test(`${mode}: the search boxes above the log table and in the filter bar are one filter`, async ({ page, console: watcher }) => {
      await analyse(page, mode);
      await page.locator('#log-table-ip-subnet-search').pressSequentially('45.142.120.10', { delay: 30 });
      await expect(total(page)).toHaveText('20');
      await expect(page.locator('#filter-ip')).toHaveValue('45.142.120.10');
      await expect(page.locator('#log-table-ip-subnet-search')).toBeFocused();
      await page.locator('#filter-path').pressSequentially('/api', { delay: 30 });
      await expect(page.locator('#log-table-path-search')).toHaveValue('/api');
      await page.click('#filter-clear-btn');
      await expect(total(page)).toHaveText(String(TOTAL));
      for (const box of ['#filter-ip', '#log-table-ip-subnet-search', '#filter-path', '#log-table-path-search']) {
        await expect(page.locator(box)).toHaveValue('');
      }
      watcher.assertClean();
    });

    test(`${mode}: the address window lists what the filters let through`, async ({ page, console: watcher }) => {
      await analyse(page, mode);
      const inspect = page.locator('.btn-inspect-ip-logs[data-ip="81.2.69.1"]').first();
      const all = count(r => r.ip === '81.2.69.1');
      const missing = count(r => r.ip === '81.2.69.1' && r.status === 404);
      expect(missing).toBeGreaterThan(0);
      expect(missing).toBeLessThan(all);

      await inspect.click();
      await expect(page.locator('#ip-log-modal-title')).toContainText(`(${all} entries)`);
      await expect(page.locator('#ip-log-modal-show-all')).toHaveCount(0);
      await page.keyboard.press('Escape');
      await expect(page.locator('#ip-log-modal')).toBeHidden();

      await page.selectOption('#filter-status', '404');
      await expect(total(page)).toHaveText(String(count(r => r.status === 404)));
      await inspect.click();
      await expect(page.locator('#ip-log-modal-title')).toContainText(`(${missing} ${missing === 1 ? 'entry matches' : 'entries match'} the active filters)`);
      await page.click('#ip-log-modal-show-all');
      await expect(page.locator('#ip-log-modal-title')).toContainText(`(${all} entries)`);
      watcher.assertClean();
    });

    test(`${mode}: turning "Ignore 403" off brings the refused requests back`, async ({ page, console: watcher }) => {
      await analyse(page, mode);
      await expect(page.locator('#dash-skip-403')).toBeEnabled();
      await page.uncheck('#dash-skip-403');
      await expect(total(page)).toHaveText(String(TOTAL + REFUSED.length));
      await expect(page.locator('#exclusion-counts')).toContainText('0 ordinary 403');
      await page.selectOption('#filter-status', '403');
      await expect(badge(page)).toContainText(`Matching ${REFUSED.length} / ${TOTAL + REFUSED.length} requests`);
      watcher.assertClean();
    });

    test(`${mode}: lines from two time zones are both shown as written`, async ({ page, console: watcher }) => {
      const two = (ip: string, time: string, zone: string, url: string) => `${ip} - - [27/Nov/2026:${time} ${zone}] "GET ${url} HTTP/1.1" 200 512 "-" "${BROWSER}"`;
      const text = [
        ...Array.from({ length: 40 }, (_, i) => two(`81.2.69.${1 + i}`, `12:00:${p2(i % 10)}`, '+0200', '/berlin')),
        ...Array.from({ length: 10 }, (_, i) => two(`81.2.70.${1 + i}`, `10:00:${p2(i)}`, '+0000', '/utc')),
      ].join('\n') + '\n';
      await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
      await waitForEngineReady(page);
      if (mode === 'paste') {
        await page.getByRole('tab', { name: 'Paste logs' }).click();
        await page.fill('#nginx-logtext', text);
      } else {
        await page.getByRole('tab', { name: 'Upload file' }).click();
        await page.setInputFiles('#nginx-logfile', { name: 'two-zones.log', mimeType: 'text/plain', buffer: Buffer.from(text) });
      }
      await page.click('#nginx-analyze-btn');
      await expect(total(page)).toHaveText('50', { timeout: 45_000 });
      await expect(page.locator('#log-clock-note')).toHaveAttribute('title', /exactly as the server wrote them/);
      await expect(page.locator('#time-window-readout')).toContainText('10:00:00 → 12:00:09');
      await page.locator('.cross-filter-path-row[data-path="=/utc"]').click();
      await expect(total(page)).toHaveText('10');
      const times = await page.locator('#explorer-rows-body tr td:first-child').allInnerTexts();
      expect(times.length).toBe(10);
      for (const time of times) expect(time).toMatch(/10:00:0\d$/);
      watcher.assertClean();
    });

    test(`${mode}: the Log Explorer lists the newest request first and names country and protocol`, async ({ page, console: watcher }) => {
      // Two servers one after the other, so the log is not in time order.
      const row = (ip: string, time: string, url: string, version: string) => `${ip} - - [27/Nov/2026:${time} +0000] "GET ${url} ${version}" 200 512 "-" "${BROWSER}"`;
      const text = [
        row('81.2.69.1', '10:00:20', '/second', 'HTTP/2.0'),
        row('81.2.69.2', '10:00:40', '/fourth', 'HTTP/1.1'),
        row('81.2.69.3', '10:00:10', '/first', 'HTTP/1.0'),
        row('81.2.69.4', '10:00:30', '/third', 'HTTP/3.0'),
      ].join('\n') + '\n';
      await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
      await waitForEngineReady(page);
      if (mode === 'paste') {
        await page.getByRole('tab', { name: 'Paste logs' }).click();
        await page.fill('#nginx-logtext', text);
      } else {
        await page.getByRole('tab', { name: 'Upload file' }).click();
        await page.setInputFiles('#nginx-logfile', { name: 'two-servers.log', mimeType: 'text/plain', buffer: Buffer.from(text) });
      }
      await page.click('#nginx-analyze-btn');
      await expect(total(page)).toHaveText('4', { timeout: 45_000 });
      const cells = (column: number) => page.locator(`#explorer-rows-body tr td:nth-child(${column})`);
      await expect(cells(4)).toHaveText(['/fourth', '/third', '/second', '/first']);
      await expect(cells(7)).toHaveText(['HTTP/1.1', 'HTTP/3.0', 'HTTP/2.0', 'HTTP/1.0']);
      // A filter keeps that order.
      await page.locator('#filter-status').selectOption('2xx');
      await expect(cells(4)).toHaveText(['/fourth', '/third', '/second', '/first']);
      watcher.assertClean();
    });

    test(`${mode}: the report downloads and carries the page's numbers`, async ({ page, console: watcher }) => {
      await analyse(page, mode);
      await page.click('#dash-download-btn');
      await expect(page.locator('#download-modal-backdrop')).toBeVisible();
      const [download] = await Promise.all([
        page.waitForEvent('download', { timeout: 30_000 }),
        page.click('#dl-start-btn'),
      ]);
      const chunks: Buffer[] = [];
      for await (const chunk of await download.createReadStream()) chunks.push(chunk as Buffer);
      const report = Buffer.concat(chunks).toString('utf8').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');

      expect(report).toContain('Analysis exclusions: internal requests excluded; ordinary 403 responses excluded');
      expect(report).toContain('9 ordinary 403');
      // Twelve requests share one second; nothing else falls into it.
      expect(report).toContain('Busiest second 12 reqs at 10:10:01');
      expect(report).toContain('no status 4');
      expect(report).toContain(`5xx ${count(r => r.status !== '-' && r.status >= 500)}`);
      watcher.assertClean();
    });

    test(`${mode}: a share link is made from the log that was analysed`, async ({ page, console: watcher }) => {
      await analyse(page, mode);
      expect(await sharedContent(page)).toBe(LOG);
      watcher.assertClean();
    });
  }

  test('a share link after several files carries all of them, gzip opened', async ({ page, console: watcher }) => {
    const half = LOG.indexOf('\n', LOG.length / 2) + 1;
    await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
    await waitForEngineReady(page);
    await page.getByRole('tab', { name: 'Upload file' }).click();
    await page.setInputFiles('#nginx-logfile', [
      { name: 'shop.log.1.gz', mimeType: 'application/gzip', buffer: gzipSync(LOG.slice(0, half)) },
      { name: 'shop.log', mimeType: 'text/plain', buffer: Buffer.from(LOG.slice(half)) },
    ]);
    await page.click('#nginx-analyze-btn');
    await expect(total(page)).toHaveText(String(TOTAL), { timeout: 45_000 });
    expect(await sharedContent(page)).toBe(LOG.slice(0, half) + '\n' + LOG.slice(half));
    watcher.assertClean();
  });
});
