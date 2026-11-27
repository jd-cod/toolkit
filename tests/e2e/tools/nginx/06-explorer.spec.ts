import { test, expect } from './fixtures';
import { checkDashboard, checkExplorer, expectationFor } from './checks';
import { analyse, explorerRows, rowKey } from './oracle';
import { BROWSERS } from './catalog';
import { buildRequest, logFromRequests } from './generator';

/**
 * Traffic Analyzer — Log Explorer.
 *
 * Every row of every page against the generated log, the counters, page
 * size, every pagination control and the explorer's own search boxes.
 */

test.describe('Traffic Analyzer — Log Explorer content', () => {
  test('walking through every page shows every analysed request exactly once, newest first', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 320 });
    await analyzer.analysePasted(log.text);
    const want = expectationFor(log);
    const expected = explorerRows(want.matching);
    const pages = Math.ceil(expected.length / 25);

    const seen: string[] = [];
    for (let page = 1; page <= pages; page++) {
      const snap = await analyzer.snapshot();
      checkExplorer(snap, want, {}, 'walk:', page);
      seen.push(...snap.explorer.rows.map(rowKey));
      if (page < pages) await analyzer.goToPage('next');
    }
    expect.soft(seen.length, 'rows seen across all pages').toBe(expected.length);
    expect.soft(seen.slice().sort(), 'the rows of all pages together are exactly the analysed requests').toEqual(expected.map(rowKey).sort());
  });

  test('each column shows the value from the log line (time, address, method, path, status, country, protocol, user agent)', async ({ analyzer, geo }) => {
    // A hand-written log: one request per interesting value, so each cell can be named.
    const t = Date.UTC(2026, 10, 3, 23, 59, 58);
    const requests = [
      buildRequest(geo, { ip: '8.8.8.8', ts: t, agent: BROWSERS[0], method: 'GET', url: '/a', protocol: 'HTTP/1.1', status: 200 }),
      buildRequest(geo, { ip: '1.1.1.1', ts: t + 1000, agent: BROWSERS[1], method: 'POST', url: '/b?x=1', protocol: 'HTTP/2.0', status: 302 }),
      buildRequest(geo, { ip: '2606:4700:4700::1111', ts: t + 2000, agent: BROWSERS[2], method: 'DELETE', url: '/c/d', protocol: 'HTTP/1.0', status: 404 }),
      buildRequest(geo, { ip: '9.9.9.9', ts: t + 3000, agent: BROWSERS[3], method: 'PATCH', url: '/e', protocol: 'HTTP/1.1', status: 503 }),
    ];
    const log = logFromRequests(requests);
    await analyzer.analysePasted(log.text);
    const snap = await analyzer.snapshot();
    checkDashboard(snap, log, {}, 'hand-written log');
    const newest = snap.explorer.rows[0];
    expect.soft(newest.time, 'time crosses midnight correctly (log line says 04/Nov/2026:00:00:01)').toBe('2026-11-04 00:00:01');
    expect.soft(snap.explorer.rows.map(r => r.status), 'status column, newest first').toEqual(['503', '404', '302', '200']);

    const colours = await analyzer.page.locator('#explorer-rows-body tr td:nth-child(5) span').evaluateAll(spans => spans.map(s => getComputedStyle(s).color));
    expect.soft(colours[0] === colours[1] && colours[2] === colours[3] && colours[0] !== colours[3],
      `error statuses (503, 404) share one colour and success statuses (302, 200) another; colours: ${colours.join(' | ')}`).toBe(true);
  });

  test('a long URL and a long user agent can be read in full', async ({ analyzer, geo }) => {
    const url = '/api/v1/customers/1234567890/orders/9876543210/items?include=shipping,billing&sort=-created';
    const log = logFromRequests([buildRequest(geo, { ip: '8.8.8.8', ts: Date.UTC(2026, 0, 5, 8, 0, 0), agent: BROWSERS[0], url })]);
    await analyzer.analysePasted(log.text);
    const cell = analyzer.page.locator('#explorer-rows-body tr').first().locator('td').nth(3);
    const readable = await cell.evaluate((td, full) => (td.textContent || '').includes(full) || (td.getAttribute('title') || '').includes(full) || (td.querySelector('[title]')?.getAttribute('title') || '').includes(full), url);
    expect.soft(readable, `the path cell shows "${(await cell.textContent())?.trim()}"; the full URL (${url.length} characters) must be available as text or as a tooltip`).toBe(true);
    const ua = analyzer.page.locator('#explorer-rows-body tr').first().locator('td').nth(7);
    const uaReadable = await ua.evaluate((td, full) => td.scrollWidth <= td.clientWidth || (td.getAttribute('title') || '').includes(full), BROWSERS[0].userAgent);
    expect.soft(uaReadable, 'the user-agent cell is cut off by the column width; the full text must be available as a tooltip').toBe(true);
  });
});

test.describe('Traffic Analyzer — Log Explorer paging', () => {
  test('page size 10, 25, 50 and 100 each show that many rows and the right number of pages', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 330 });
    await analyzer.analysePasted(log.text);
    const want = expectationFor(log);
    for (const size of [10, 50, 100, 25] as const) {
      await analyzer.setPerPage(size);
      checkExplorer(await analyzer.snapshot(), want, { perPage: size }, `page size ${size}:`);
    }
  });

  test('First, Prev, Next, Last and the numbered buttons go to the page they name', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 420 });
    await analyzer.analysePasted(log.text);
    const want = expectationFor(log);
    const pages = Math.ceil(want.matching.length / 25);
    expect(pages, 'sanity: enough pages to exercise the controls').toBeGreaterThan(6);
    const at = async (page: number, label: string) => {
      const snap = await analyzer.snapshot();
      checkExplorer(snap, want, {}, `${label}:`, page);
      // The numbered buttons show a window of five pages around the current one.
      const first = Math.max(1, Math.min(page - 2, pages - 4));
      expect.soft(snap.explorer.pageButtons.map(b => b.page), `${label}: numbered buttons`).toEqual(Array.from({ length: 5 }, (_, i) => String(first + i)));
    };

    await at(1, 'start');
    await analyzer.goToPage('next');
    await at(2, 'Next');
    await analyzer.goToPage(4);
    await at(4, 'button 4');
    await analyzer.goToPage('prev');
    await at(3, 'Prev');
    await analyzer.goToPage('last');
    await at(pages, 'Last');
    await analyzer.goToPage('prev');
    await at(pages - 1, 'Prev from last');
    await analyzer.goToPage('first');
    await at(1, 'First');
  });

  test('changing the page size or a filter returns to page 1', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 420 });
    await analyzer.analysePasted(log.text);
    await analyzer.goToPage(3);
    await analyzer.setPerPage(50);
    checkExplorer(await analyzer.snapshot(), expectationFor(log), { perPage: 50 }, 'after changing page size on page 3:');
    await analyzer.goToPage('next');
    await analyzer.selectMethod('GET');
    const snap = await analyzer.snapshot();
    expect.soft(snap.explorer.pageText, 'page indicator after applying a filter on page 2').toMatch(/^Page 1 of /);
    expect.soft(snap.explorer.rows.every(r => r.method === 'GET'), 'only GET rows are listed').toBe(true);
  });
});

test.describe('Traffic Analyzer — Log Explorer search boxes', () => {
  test('"Filter IP / CIDR Subnet" filters the whole dashboard like the IP search in the ribbon', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    const kept = analyse(log).kept;
    const ip = kept.find(r => !r.ip.includes(':'))!.ip;
    const subnet = `${ip.split('.').slice(0, 2).join('.')}.0.0/16`;
    for (const ipSearch of [ip, subnet]) {
      await analyzer.explorerSearchIp(ipSearch);
      const snap = await analyzer.snapshot();
      checkDashboard(snap, log, { filters: { ipSearch } }, 'explorer IP box');
      expect.soft(snap.explorer.ipSearch, 'the explorer box keeps the text that was typed').toBe(ipSearch);
    }
    await analyzer.explorerSearchIp('');
    checkDashboard(await analyzer.snapshot(), log, {}, 'explorer IP box cleared');
  });

  test('"Filter Path / URI Keyword" filters the whole dashboard like the path search in the ribbon', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    for (const pathSearch of ['/static', 'orders']) {
      await analyzer.explorerSearchPath(pathSearch);
      const snap = await analyzer.snapshot();
      checkDashboard(snap, log, { filters: { pathSearch } }, 'explorer path box');
      expect.soft(snap.explorer.pathSearch, 'the explorer box keeps the text that was typed').toBe(pathSearch);
    }
    await analyzer.explorerSearchPath('');
    checkDashboard(await analyzer.snapshot(), log, {}, 'explorer path box cleared');
  });

  for (const [name, selector] of [
    ['ribbon "Search IP"', '#filter-ip'],
    ['ribbon "Search Path"', '#filter-path'],
    ['explorer "Filter IP / CIDR Subnet"', '#log-table-ip-subnet-search'],
    ['explorer "Filter Path / URI Keyword"', '#log-table-path-search'],
  ] as const) {
    test(`typing slowly in the ${name} box keeps the cursor in the box until the text is complete`, async ({ analyzer, newLog }) => {
      const log = await newLog({ requests: 300 });
      await analyzer.analysePasted(log.text);
      const { page } = analyzer;
      const text = selector.includes('path') ? '/static/css' : '66.249.';
      await page.locator(selector).click();
      // A person types a few characters per second; the dashboard refreshes 150 ms after each key.
      await page.keyboard.type(text, { delay: 260 });
      await expect.soft(page.locator(selector), `after typing "${text}" one key at a time the box must contain all of it`).toHaveValue(text);
      const focused = await page.evaluate(() => document.activeElement?.id || document.activeElement?.tagName);
      expect.soft(`#${focused}`, 'the box must still have keyboard focus').toBe(selector);
    });
  }
});
