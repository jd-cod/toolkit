import { test, expect } from './fixtures';
import { checkDashboard, checkKpis, expectationFor } from './checks';
import { captureDownload } from '../_support/io';
import { parseCsv } from '../_support/csv';
import { analyse, summarise, grouped } from './oracle';
import { BROWSERS, UNLISTED_AGENTS, FEED_CRAWLERS, type Agent } from './catalog';
import { buildRequest, logFromRequests, formatLine } from './generator';

/**
 * Traffic Analyzer — awkward and hostile input, one concern per test.
 *
 * The default generated logs are unambiguous on purpose. Everything that
 * real logs contain and that can trip an analyser is collected here, each in
 * a small hand-written log, so a failure names exactly one cause.
 */

const T0 = Date.UTC(2026, 3, 14, 12, 0, 0);
const human = BROWSERS[0];

test.describe('Traffic Analyzer — who is a bot', () => {
  const BROWSER_LOOKALIKES: [string, string][] = [
    ['a CUBOT phone (brand name contains "bot")', 'Mozilla/5.0 (Linux; Android 11; CUBOT NOTE 20) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36'],
    ['Internet Explorer 11 (engine name "Trident")', 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'],
    ['an Archos tablet ("archive" look-alike)', 'Mozilla/5.0 (Linux; Android 8.1.0; Archos Core 101 3G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36'],
  ];
  for (const [name, userAgent] of BROWSER_LOOKALIKES) {
    test(`${name} is counted as human traffic`, async ({ analyzer, geo }) => {
      const agent: Agent = { id: 'lookalike', kind: 'human', group: '', userAgent };
      const requests = Array.from({ length: 10 }, (_, i) => buildRequest(geo, { ip: '8.8.8.8', ts: T0 + i * 1000, agent }));
      const log = logFromRequests(requests);
      await analyzer.analysePasted(log.text);
      const snap = await analyzer.snapshot();
      expect.soft(snap.kpis.human, `HUMAN TRAFFIC for 10 requests from "${userAgent}"`).toBe('100%');
      expect.soft(snap.tables.bots.rows.map(r => r.label), 'no bot rows for a browser').toEqual([]);
    });
  }

  test('a crawler that mentions another crawler in its user agent is listed under its own name', async ({ analyzer, geo }) => {
    const agent: Agent = { id: 'telegram', kind: 'crawler', group: 'Telegram', userAgent: 'TelegramBot (like TwitterBot)' };
    const requests = Array.from({ length: 6 }, (_, i) => buildRequest(geo, { ip: '9.9.9.9', ts: T0 + i * 1000, agent }));
    const log = logFromRequests(requests);
    await analyzer.analysePasted(log.text);
    const snap = await analyzer.snapshot();
    expect.soft(snap.tables.bots.rows.map(r => r.group), 'bot group for "TelegramBot (like TwitterBot)"').toEqual(['Telegram']);
  });

  test('"N active indicators" counts impersonating addresses and probed sensitive paths, and is 0 for clean traffic', async ({ analyzer, geo }) => {
    const clean = logFromRequests(Array.from({ length: 8 }, (_, i) => buildRequest(geo, { ip: '8.8.8.8', ts: T0 + i * 1000, agent: human, url: '/pricing' })));
    await analyzer.analysePasted(clean.text);
    expect.soft((await analyzer.snapshot()).signalsHeading, 'heading for clean traffic').toBe('Security signals 0 active indicators');

    await analyzer.page.locator('#dash-back-btn').click();
    const fake = FEED_CRAWLERS[0];
    const noisy = logFromRequests([
      buildRequest(geo, { ip: '8.8.8.8', ts: T0, agent: human, url: '/pricing' }),
      buildRequest(geo, { ip: '9.9.9.9', ts: T0 + 1000, agent: fake, trafficClass: 'spoofed', url: '/pricing' }),
      buildRequest(geo, { ip: '9.9.9.10', ts: T0 + 2000, agent: fake, trafficClass: 'spoofed', url: '/pricing' }),
      buildRequest(geo, { ip: '8.8.4.4', ts: T0 + 3000, agent: UNLISTED_AGENTS[2], url: '/.env' }),
    ]);
    await analyzer.analysePasted(noisy.text);
    expect.soft((await analyzer.snapshot()).signalsHeading, 'heading for 2 impersonating addresses + 1 sensitive path').toBe('Security signals 3 active indicators');
  });

  test('a network whose name merely contains the letters "tor" is not counted as a Tor indicator', async ({ analyzer, geo, rng }) => {
    // Find an address whose network name contains "tor" inside another word (e.g. "Operator", "Storage").
    let ip = '';
    let org = '';
    for (let i = 0; i < 40_000 && !ip; i++) {
      const candidate = `${rng.int(1, 223)}.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(1, 254)}`;
      const name = geo.lookup(candidate).asnOrg;
      if (/[a-z]tor|tor[a-z]/i.test(name) && !/\btor\b/i.test(name) && !/zwiebel/i.test(name)) { ip = candidate; org = name; }
    }
    test.skip(!ip, 'no such network name found in the GeoIP database');
    const log = logFromRequests(Array.from({ length: 5 }, (_, i) => buildRequest(geo, { ip, ts: T0 + i * 1000, agent: human, url: '/pricing' })));
    await analyzer.analysePasted(log.text);
    expect.soft((await analyzer.snapshot()).signalsHeading, `heading for ordinary browser traffic from "${org}" (${ip})`).toBe('Security signals 0 active indicators');
  });
});

test.describe('Traffic Analyzer — log format details', () => {
  test('nginx statuses 499 and 444 are counted like any other status', async ({ analyzer, geo }) => {
    const statuses = [499, 444, 200, 499, 200, 404, 499, 200, 200, 444, 200, 200, 500, 200, 200, 200, 499, 200];
    const requests = statuses.map((status, i) => buildRequest(geo, { ip: i % 2 ? '8.8.8.8' : '9.9.9.9', ts: T0 + i * 1000, agent: human, status, url: `/item/${i}` }));
    const log = logFromRequests(requests);
    await analyzer.analysePasted(log.text);
    const snap = await analyzer.snapshot();
    checkDashboard(snap, log, {}, 'log with 499 and 444');
    expect.soft(snap.explorer.rows.filter(r => r.status === '499').length, 'rows with status 499 in the explorer').toBe(4);
  });

  test('a damaged line near the top of the file does not change how the other lines are read', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 200, invalidLines: 0 });
    const lines = log.text.split('\n');
    lines.splice(2, 0, 'Binary file (standard input) matches');
    const damaged = { ...log, text: lines.join('\n'), invalidLines: ['Binary file (standard input) matches'] };
    await analyzer.analysePasted(damaged.text);
    checkDashboard(await analyzer.snapshot(), damaged, {}, 'damaged third line');
  });

  test('extra fields after the user agent (request time, upstream) are ignored', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 200, invalidLines: 0 });
    const text = log.text.split('\n').map((line, i) => (line ? `${line} ${(i % 7) / 10} "-" upstream=10.0.0.${i % 200}` : line)).join('\n');
    await analyzer.analysePasted(text);
    checkDashboard(await analyzer.snapshot(), log, {}, 'combined format with trailing fields');
  });

  test('Windows line endings (CRLF) give the same result', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 200 });
    await analyzer.analysePasted(log.text.replace(/\n/g, '\r\n'));
    checkDashboard(await analyzer.snapshot(), log, {}, 'CRLF log');
  });

  test('the common log format (no referrer and user agent) is analysed', async ({ analyzer, geo }) => {
    const requests = Array.from({ length: 20 }, (_, i) => buildRequest(geo, { ip: i % 3 ? '8.8.8.8' : '1.1.1.1', ts: T0 + i * 1000, agent: human, url: `/p/${i % 4}`, status: i % 5 ? 200 : 404 }));
    const text = requests.map(r => r.line.replace(/ "-" "[^"]*"$/, '')).join('\n');
    await analyzer.analysePasted(text);
    const snap = await analyzer.snapshot();
    const want = expectationFor(logFromRequests(requests));
    expect.soft(snap.kpis.total, 'TOTAL REQUESTS for 20 common-format lines').toBe('20');
    expect.soft(snap.kpis.uniqueIps, 'UNIQUE IPS').toBe('2');
    expect.soft(snap.explorer.rows.map(r => r.status).filter(s => s === '404').length, '404 rows on the first page').toBe(want.matching.filter(r => r.status === 404).length);
  });

  test('a single request is a valid log', async ({ analyzer, geo }) => {
    const log = logFromRequests([buildRequest(geo, { ip: '8.8.8.8', ts: T0, agent: human, url: '/only', status: 200, bytes: 1234 })]);
    await analyzer.analysePasted(log.text);
    checkDashboard(await analyzer.snapshot(), log, {}, 'one-line log');
  });

  test('text that contains no access-log lines is refused with an explanation', async ({ analyzer, guard }) => {
    const { page } = analyzer;
    guard.allow(/\[AnalysisError\]/);
    await analyzer.chooseSource('paste');
    await page.locator('#nginx-logtext').fill('hello world\nthis is not a log\n12345');
    await page.locator('#nginx-analyze-btn').click();
    const dialog = page.locator('#analysis-error-modal');
    await expect(dialog).toBeVisible();
    await expect.soft(dialog).toContainText('No valid access-log lines found');
    await page.locator('#analysis-error-close').click();
    await expect(dialog).toBeHidden();
    await expect(page.locator('#nginx-dashboard')).toBeHidden();
    await expect.soft(page.locator('#nginx-analyze-btn'), 'the input screen is usable again').toBeEnabled();
  });
});

test.describe('Traffic Analyzer — addresses', () => {
  test('an IPv4-mapped IPv6 address is the same client as its IPv4 address, and internal when that is internal', async ({ analyzer, geo }) => {
    const requests = [
      buildRequest(geo, { ip: '8.8.8.8', ts: T0, agent: human }),
      { ...buildRequest(geo, { ip: '8.8.8.8', ts: T0 + 1000, agent: human }), line: formatLine({ ip: '::ffff:8.8.8.8', ts: T0 + 1000, method: 'GET', url: '/', protocol: 'HTTP/1.1', status: 200, bytes: 512, referrer: null, userAgent: human.userAgent }) },
      { ...buildRequest(geo, { ip: '10.0.0.5', ts: T0 + 2000, agent: human }), internalAddress: true, line: formatLine({ ip: '::ffff:10.0.0.5', ts: T0 + 2000, method: 'GET', url: '/', protocol: 'HTTP/1.1', status: 200, bytes: 512, referrer: null, userAgent: human.userAgent }) },
      buildRequest(geo, { ip: '1.1.1.1', ts: T0 + 3000, agent: human }),
    ];
    const log = logFromRequests(requests);
    await analyzer.analysePasted(log.text);
    checkDashboard(await analyzer.snapshot(), log, {}, 'IPv4-mapped addresses');
  });

  test('the same IPv6 address written in two notations is one client', async ({ analyzer, geo }) => {
    const facts = geo.lookup('2606:4700:4700::1111');
    const line = (ip: string, i: number) => formatLine({ ip, ts: T0 + i * 1000, method: 'GET', url: '/', protocol: 'HTTP/1.1', status: 200, bytes: 100, referrer: null, userAgent: human.userAgent });
    const text = [line('2606:4700:4700::1111', 0), line('2606:4700:4700:0:0:0:0:1111', 1), line('2606:4700:4700:0000:0000:0000:0000:1111', 2), line('2606:4700:4700::1111', 3)].join('\n');
    await analyzer.analysePasted(text);
    const snap = await analyzer.snapshot();
    expect.soft(snap.kpis.total, 'TOTAL REQUESTS').toBe('4');
    expect.soft(snap.kpis.uniqueIps, `UNIQUE IPS: all four lines come from one address (${facts.asnOrg})`).toBe('1');
    expect.soft(snap.tables.ips.rows.length, 'rows in "Most Active IPs"').toBe(1);
  });

  test('clicking an address row shows only that address, even when another address contains it as text', async ({ analyzer, geo }) => {
    const requests = [
      ...Array.from({ length: 5 }, (_, i) => buildRequest(geo, { ip: '1.2.3.4', ts: T0 + i * 1000, agent: human })),
      ...Array.from({ length: 3 }, (_, i) => buildRequest(geo, { ip: '11.2.3.40', ts: T0 + 10_000 + i * 1000, agent: human })),
      ...Array.from({ length: 2 }, (_, i) => buildRequest(geo, { ip: '1.2.3.45', ts: T0 + 20_000 + i * 1000, agent: human })),
    ];
    const log = logFromRequests(requests);
    await analyzer.analysePasted(log.text);
    await analyzer.rerender(() => analyzer.page.locator('.cross-filter-ip-row[data-ip="1.2.3.4"]').click());
    const snap = await analyzer.snapshot();
    expect.soft(snap.kpis.total, 'the row for 1.2.3.4 said 5 hits; after clicking it TOTAL REQUESTS must be 5 (11.2.3.40 and 1.2.3.45 are other clients)').toBe('5');
    expect.soft(snap.kpis.uniqueIps, 'UNIQUE IPS after clicking the row for 1.2.3.4').toBe('1');
  });

  test('an IPv4 network search does not match IPv6 clients', async ({ analyzer, geo }) => {
    const requests = [
      ...Array.from({ length: 4 }, (_, i) => buildRequest(geo, { ip: '2606:4700:4700::1111', ts: T0 + i * 1000, agent: human })),
      ...Array.from({ length: 3 }, (_, i) => buildRequest(geo, { ip: '8.8.8.8', ts: T0 + 10_000 + i * 1000, agent: human })),
    ];
    const log = logFromRequests(requests);
    await analyzer.analysePasted(log.text);
    await analyzer.searchIp('0.0.0.0/5');
    const snap = await analyzer.snapshot();
    expect.soft(snap.kpis.total, 'no client of this log is inside 0.0.0.0/5 (addresses 0.x to 7.x)').toBe('0');
  });
});

test.describe('Traffic Analyzer — paths that overlap', () => {
  test('each entry of the path dropdown selects the number of requests its label shows', async ({ analyzer, geo }) => {
    const urls = ['/api/users', '/api/users', '/api-docs/index.html', '/login', '/admin/login', '/admin/login', '/search?next=/login', '/apiary', '/api'];
    const log = logFromRequests(urls.map((url, i) => buildRequest(geo, { ip: '8.8.8.8', ts: T0 + i * 1000, agent: human, url })));
    await analyzer.analysePasted(log.text);
    const options = (await analyzer.snapshot()).filters.path.options.slice(1);
    for (const option of options) {
      const promised = Number((option.label.match(/\((\d+)\)$/) || [])[1]);
      await analyzer.selectPath(option.value);
      const snap = await analyzer.snapshot();
      expect.soft(Number(snap.kpis.total), `path dropdown entry "${option.label}" must select ${promised} request(s); listed after selecting: ${snap.explorer.rows.map(r => r.path).join(', ')}`).toBe(promised);
    }
  });

  test('every country shown in the Country Distribution can be chosen in the country filter, including "Unknown"', async ({ analyzer, geo }) => {
    // 192.0.2.0/24 is reserved for documentation: no country is known for it.
    const requests = [
      ...Array.from({ length: 4 }, (_, i) => buildRequest(geo, { ip: '192.0.2.10', ts: T0 + i * 1000, agent: human })),
      ...Array.from({ length: 3 }, (_, i) => buildRequest(geo, { ip: '8.8.8.8', ts: T0 + 10_000 + i * 1000, agent: human })),
    ];
    const log = logFromRequests(requests);
    expect(requests[0].geo.country, 'sanity: the documentation range has no country').toBe('Unknown');
    await analyzer.analysePasted(log.text);
    const snap = await analyzer.snapshot();
    const selectable = snap.filters.country.options.map(o => o.value);
    expect.soft(snap.countryChart.labels.filter(c => !selectable.includes(c)), 'countries shown in the chart that cannot be selected in the filter (4 of 7 requests here have no known country)').toEqual([]);
  });
});

test.describe('Traffic Analyzer — hostile content', () => {
  test('markup in the URL, referrer and user agent is shown as text and never executed (dashboard, dialogs, report)', async ({ analyzer, geo }) => {
    const { page } = analyzer;
    const dialogs: string[] = [];
    page.on('dialog', d => { dialogs.push(d.message()); void d.dismiss(); });
    const evil: Agent = { id: 'evil', kind: 'human', group: '', userAgent: '<img src=x onerror=window.__xss=1>' };
    const requests = Array.from({ length: 6 }, (_, i) => buildRequest(geo, {
      ip: '8.8.8.8', ts: T0 + i * 1000, agent: evil,
      url: '/<script>window.__xss=2</script>', referrer: 'https://evil.example/?q=<svg/onload=window.__xss=3>',
    }));
    const log = logFromRequests(requests);
    await analyzer.analysePasted(log.text);
    await page.locator('.btn-inspect-ip-logs').first().click();
    await expect(page.locator('#ip-log-modal')).toBeVisible();
    await expect.soft(page.locator('#ip-log-modal-body'), 'the dialog shows the markup as text').toContainText('<img src=x onerror=window.__xss=1>');
    await page.locator('#ip-log-modal-close').click();

    const snap = await analyzer.snapshot();
    expect.soft(snap.explorer.rows[0].userAgent, 'user agent column shows the markup as text').toBe('<img src=x onerror=window.__xss=1>');
    expect.soft(snap.explorer.rows[0].path, 'path column shows the markup as text').toBe('/<script>window.__xss=2</script>'.slice(0, 40));
    expect.soft(snap.tables.referrers.rows[0]?.referrer, 'referrer table shows the markup as text').toBe('https://evil.example/?q=<svg/onload=window.__xss=3>');
    expect.soft(await page.evaluate(() => (window as any).__xss), 'no injected script ran on the dashboard').toBeUndefined();
    expect.soft(await page.locator('#nginx-dashboard img[src="x"], #nginx-dashboard svg[onload]').count(), 'no injected elements exist in the dashboard').toBe(0);

    await page.locator('#dash-download-btn').click();
    const file = await captureDownload(page, () => page.locator('#dl-start-btn').click(), 60_000);
    const report = await page.context().newPage();
    await report.setContent(file.text, { waitUntil: 'load' });
    expect.soft(await report.evaluate(() => (window as any).__xss), 'no injected script ran inside the downloaded report').toBeUndefined();
    expect.soft(dialogs, 'no alert/confirm dialogs were opened').toEqual([]);
  });

  test('CSV export neutralises cells that a spreadsheet would run as a formula', async ({ analyzer, geo }) => {
    const urls = ['=1+1', '@SUM(1,1)', '+1+1', '-1+1', '/normal'];
    const log = logFromRequests(urls.flatMap((url, n) => Array.from({ length: 2 }, (_, i) => buildRequest(geo, { ip: '8.8.8.8', ts: T0 + (n * 2 + i) * 1000, agent: human, url }))));
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    await page.locator('#dash-download-btn').click();
    const file = await captureDownload(page, () => page.locator('#dl-csv-btn').click());
    const cells = parseCsv(file.text).flat();
    const formulas = cells.filter(cell => /^[=@+]/.test(cell) || /^-\d/.test(cell));
    expect.soft(formulas, 'CSV cells that start with = @ + or - (a spreadsheet runs them as formulas; they must be prefixed, e.g. with a single quote)').toEqual([]);
  });
});

test.describe('Traffic Analyzer — size', () => {
  test('a 15,000-line log is analysed within a minute and its totals are right', async ({ analyzer, newLog }) => {
    test.setTimeout(240_000);
    const log = await newLog({ requests: 15_000, clients: 40, spanSeconds: 6 * 3600 });
    const started = Date.now();
    await analyzer.analysePastedWithShortcut(log.text);
    const seconds = (Date.now() - started) / 1000;
    expect.soft(seconds, `analysis of 15,000 lines took ${seconds.toFixed(1)}s`).toBeLessThan(60);
    const snap = await analyzer.snapshot();
    const want = checkDashboard(snap, log, {}, '15,000-line log');
    expect.soft(snap.kpis.total, 'TOTAL REQUESTS is grouped with a thousands separator').toBe(grouped(want.summary.total));

    const filterStarted = Date.now();
    await analyzer.selectTraffic('human');
    expect.soft((Date.now() - filterStarted) / 1000, 'applying a filter on 15,000 lines').toBeLessThan(10);
    checkKpis(await analyzer.snapshot(), expectationFor(log, { filters: { traffic: 'human' } }), '15,000-line log, human only:');
    expect(summarise(analyse(log).kept).total).toBeGreaterThan(10_000);
  });
});
