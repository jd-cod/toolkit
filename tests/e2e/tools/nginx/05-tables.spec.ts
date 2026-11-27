import { test, expect } from './fixtures';
import { checkDashboard, checkTables, expectationFor } from './checks';
import { analyse, summarise } from './oracle';
import { mockApi, type ApiCall } from '../_support/io';
import { BROWSERS } from './catalog';
import { buildRequest, logFromRequests } from './generator';

/**
 * Traffic Analyzer — the "Security signals" tables.
 *
 * Content of every table is covered by checkDashboard in the other specs;
 * this file covers what the rows DO (click to filter, inspect logs, scan) and
 * the cases the default data does not reach (many entries, nested paths).
 */

test.describe('Traffic Analyzer — clicking a table row filters the dashboard', () => {
  test('a row of "Most Active IPs" filters to that address; a second click removes the filter', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    // Rows are taken from the table as shown: with equal hit counts, which address closes the list is not defined.
    const shown = await page.locator('.cross-filter-ip-row').evaluateAll((rows) => rows.map((r) => r.getAttribute('data-ip') ?? ''));
    expect(shown.length, 'the table lists addresses').toBeGreaterThanOrEqual(3);
    const hitsByIp = new Map(summarise(analyse(log).kept).ips.map((entry) => [entry.key, entry.hits]));
    for (const ip of [shown[0], shown[Math.floor(shown.length / 2)], shown[shown.length - 1]]) {
      const hits = hitsByIp.get(ip);
      expect(hits, `${ip} is listed in "Most Active IPs" and must be a client of the log`).toBeDefined();
      await analyzer.rerender(() => page.locator(`.cross-filter-ip-row[data-ip="${ip}"]`).click());
      const snap = await analyzer.snapshot();
      const want = checkDashboard(snap, log, { filters: { ipSearch: ip } }, `clicked IP row ${ip}`);
      expect.soft(want.summary.total, `the row said ${hits} hits for ${ip}; the filtered dashboard must show ${hits} requests`).toBe(hits);
      await analyzer.rerender(() => page.locator(`.cross-filter-ip-row[data-ip="${ip}"]`).click());
      checkDashboard(await analyzer.snapshot(), log, {}, `clicked IP row ${ip} again`);
    }
  });

  test('a row of "ASNs & Networks" filters to that network; a second click removes the filter', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    const shown = await page.locator('.cross-filter-asn-row').evaluateAll((rows) => rows.map((r) => r.getAttribute('data-asn') ?? ''));
    expect(shown.length, 'the table lists networks').toBeGreaterThanOrEqual(2);
    const hitsByAsn = new Map(summarise(analyse(log).kept).asns.map((entry) => [String(entry.key), entry.hits]));
    for (const asn of [shown[0], shown[shown.length - 1]]) {
      const hits = hitsByAsn.get(asn);
      expect(hits, `AS${asn} is listed in "ASNs & Networks" and must be a network of the log`).toBeDefined();
      await analyzer.rerender(() => page.locator(`.cross-filter-asn-row[data-asn="${asn}"]`).click());
      const want = checkDashboard(await analyzer.snapshot(), log, { filters: { asn: Number(asn) } }, `clicked ASN row AS${asn}`);
      expect.soft(want.summary.total, `the row said ${hits} hits for AS${asn}`).toBe(hits);
      await analyzer.rerender(() => page.locator(`.cross-filter-asn-row[data-asn="${asn}"]`).click());
      checkDashboard(await analyzer.snapshot(), log, {}, `clicked ASN row AS${asn} again`);
    }
  });

  test('each row of "Bot Intelligence" filters to that bot group and verification status', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    const rows = summarise(analyse(log).kept).botRows;
    expect(rows.length, 'the generated log has verified, spoofed and unverified bot rows').toBeGreaterThanOrEqual(3);
    for (const row of rows) {
      const locator = page.locator(`.cross-filter-bot-row[data-bot="${row.status}"][data-bot-group="${row.group}"]`);
      await analyzer.rerender(() => locator.click());
      const snap = await analyzer.snapshot();
      const want = checkDashboard(snap, log, { filters: { traffic: row.status, botGroup: row.group } }, `clicked bot row ${row.group}/${row.status}`);
      expect.soft(want.summary.total, `the row said ${row.hits} hits for ${row.group} (${row.status})`).toBe(row.hits);
      await analyzer.rerender(() => page.locator(`.cross-filter-bot-row[data-bot="${row.status}"][data-bot-group="${row.group}"]`).click());
      checkDashboard(await analyzer.snapshot(), log, {}, `clicked bot row ${row.group}/${row.status} again`);
    }
  });

  test('a row of "Targeted Paths" filters to that path and shows the number of requests the row promised (single-segment paths)', async ({ analyzer, newLog }) => {
    const log = await newLog({ urls: 'flat' });
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    const paths = summarise(analyse(log).kept).paths.slice(0, 15);
    for (const { key: path, hits } of [paths[0], paths[paths.length - 1]]) {
      await analyzer.rerender(() => page.locator(`.cross-filter-path-row[data-path="${path}"]`).click());
      const want = checkDashboard(await analyzer.snapshot(), log, { filters: { pathSearch: path } }, `clicked path row ${path}`);
      expect.soft(want.summary.total, `the row said ${hits} hits for ${path}`).toBe(hits);
      await analyzer.rerender(() => page.locator(`.cross-filter-path-row[data-path="${path}"]`).click());
      checkDashboard(await analyzer.snapshot(), log, {}, `clicked path row ${path} again`);
    }
  });
});

test.describe('Traffic Analyzer — Targeted Paths with realistic URLs', () => {
  test('lists request paths (URL without query string) with their request counts', async ({ analyzer, newLog }) => {
    const log = await newLog({ urls: 'nested' });
    await analyzer.analysePasted(log.text);
    const snap = await analyzer.snapshot();
    checkTables(snap, expectationFor(log), 'nested URLs:', { paths: true });
  });

  test('every row is a path that was requested, and clicking it shows exactly the requests the row counted', async ({ analyzer, newLog }) => {
    const log = await newLog({ urls: 'nested' });
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    const before = await analyzer.snapshot();
    const kept = analyse(log).kept;
    const requested = new Set(kept.map(r => r.url.split('?')[0]));
    const notRequested = before.tables.paths.rows.filter(r => !requested.has(r.path)).map(r => r.path);
    expect.soft(notRequested, '"Endpoint Path" entries that are not the path of any request in the log').toEqual([]);

    for (const row of before.tables.paths.rows.slice(0, 6)) {
      await analyzer.rerender(() => page.locator(`.cross-filter-path-row[data-path="${row.path}"]`).click());
      const after = await analyzer.snapshot();
      expect.soft(after.kpis.total, `row "${row.path}" said ${row.hits} hits; after clicking it TOTAL REQUESTS must be ${row.hits}`).toBe(row.hits);
      await analyzer.clearFilters();
    }
  });
});

test.describe('Traffic Analyzer — more entries than a table shows', () => {
  test('with 120 clients, 40 networks and many referrers every table shows its top entries and every badge the real total', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 1500, clients: 120 });
    await analyzer.analysePasted(log.text);
    const snap = await analyzer.snapshot();
    const want = checkDashboard(snap, log, {}, '120 clients');
    expect(want.summary.uniqueIps, 'sanity: more client addresses than the table shows').toBeGreaterThan(50);
    expect.soft(snap.tables.ips.rows.length, '"Most Active IPs" shows 15 rows').toBe(15);
  });
});

test.describe('Traffic Analyzer — IP access-log dialog', () => {
  test('shows the requests of the chosen address, in log order, and closes again', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    const kept = analyse(log).kept;
    const ips = summarise(kept).ips;
    for (const { key: ip } of [ips[0], ips[Math.min(ips.length - 1, 9)]]) {
      const mine = kept.filter(r => r.ip === ip);
      await page.locator(`.btn-inspect-ip-logs[data-ip="${ip}"]`).click();
      await expect(page.locator('#ip-log-modal')).toBeVisible();
      await expect.soft(page.locator('#ip-log-modal-title'), `dialog title for ${ip}`).toHaveText(`Access Logs for ${ip} (${mine.length} entries)`);
      const rows = await page.locator('#ip-log-modal-body > div > div').evaluateAll(divs =>
        divs.map(d => Array.from(d.children).map(c => (c.textContent || '').trim())));
      const expected = mine.slice(0, 100).map((r, i) => [String(i + 1), r.method, r.url, String(r.status), `"${r.agent.userAgent}"`]);
      expect.soft(rows, `dialog rows for ${ip} (number, method, URL, status, user agent)`).toEqual(expected);
      await page.locator('#ip-log-modal-close').click();
      await expect(page.locator('#ip-log-modal')).toBeHidden();
    }
    // Clicking outside the dialog closes it as well.
    await page.locator('.btn-inspect-ip-logs').first().click();
    await expect(page.locator('#ip-log-modal')).toBeVisible();
    const backdrop = (await page.locator('#ip-log-modal').boundingBox())!;
    await page.mouse.click(backdrop.x + backdrop.width - 8, backdrop.y + backdrop.height - 8);
    await expect(page.locator('#ip-log-modal')).toBeHidden();
    checkDashboard(await analyzer.snapshot(), log, {}, 'inspecting logs must not change the dashboard');
  });

  test('an address with more than 100 requests says how many are shown', async ({ analyzer, geo }) => {
    const start = Date.UTC(2026, 5, 1, 10, 0, 0);
    const requests = Array.from({ length: 130 }, (_, i) => buildRequest(geo, { ip: '8.8.8.8', ts: start + i * 1000, agent: BROWSERS[0], url: `/page/${i}` }));
    const log = logFromRequests(requests);
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    await page.locator('.btn-inspect-ip-logs[data-ip="8.8.8.8"]').click();
    await expect(page.locator('#ip-log-modal-title')).toHaveText('Access Logs for 8.8.8.8 (130 entries)');
    await expect(page.locator('#ip-log-modal-body > div > div')).toHaveCount(100);
    await expect.soft(page.locator('#ip-log-modal-body'), 'the dialog must tell the user that only 100 of 130 entries are listed').toContainText(/100 of 130|first 100/i);
  });
});

test.describe('Traffic Analyzer — AbuseIPDB scan', () => {
  test('sends the most active addresses and shows each returned score, domain and country', async ({ analyzer, newLog, rng }) => {
    const log = await newLog({ clients: 30 });
    const { page } = analyzer;
    const calls = await mockApi(page, '**/api/abuse', (call: ApiCall) => {
      const ips = (call.body as { ips: { ip: string; hits: number }[] }).ips;
      const results = ips.map((entry, i) => ({
        ip: entry.ip, hits: entry.hits,
        // Scores on and around the badge thresholds (80 and 25), plus random ones.
        abuse_score: [100, 80, 79, 25, 24, 0][i] ?? rng.int(0, 100),
        total_reports: rng.int(0, 500), country_code: rng.pick(['US', 'DE', 'CN', 'BR']), domain: `host-${i}.example.net`,
      }));
      return { abusive: results.filter(r => r.abuse_score > 0), non_abusive: results.filter(r => r.abuse_score === 0), api_available: true, checked_count: results.length };
    });
    await analyzer.analysePasted(log.text);
    const top = summarise(analyse(log).kept).ips;

    await page.locator('#btn-center-scan-abuse').click();
    await expect(page.locator('#btn-scan-abuseipdb')).toContainText('Scanned');
    expect(calls.length, 'one request to /api/abuse').toBe(1);
    const sent = (calls[0].body as { ips: { ip: string; hits: number }[] }).ips;
    expect.soft(sent.length, 'the button says "Scan Top 20 IPs": 20 addresses should be sent').toBe(Math.min(20, top.length));
    expect.soft(sent.map(s => s.hits), 'the addresses sent are the most active ones, with their hit counts').toEqual(top.slice(0, sent.length).map(t => t.hits));

    const rows = (await analyzer.snapshot()).tables.abuse.rows;
    expect.soft(rows.length, 'one result row per scanned address').toBe(sent.length);
    const scores = [100, 80, 79, 25, 24, 0];
    const badge = (score: number) => (score >= 80 ? `${score}% Bad` : score >= 25 ? `${score}% Susp.` : `${score}% Clean`);
    rows.slice(0, 6).forEach((row, i) => {
      expect.soft(row.confidence, `confidence badge of row ${i + 1} (score ${scores[i]})`).toBe(badge(scores[i]));
      expect.soft(row.domain, `domain of row ${i + 1}`).toBe(`host-${i}.example.net`);
      expect.soft(['US', 'DE', 'CN', 'BR']).toContain(row.country);
    });
  });

  test('says so when the reputation service is not available, instead of reporting "Scanned"', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 200 });
    const { page } = analyzer;
    await mockApi(page, '**/api/abuse', { abusive: [], non_abusive: [], api_available: false, checked_count: 0 });
    await analyzer.analysePasted(log.text);
    await page.locator('#btn-center-scan-abuse').click();
    const card = page.locator('.card-table-wrap', { hasText: 'Abusive IPs' });
    await expect.soft(card, 'the card must explain that no reputation data is available').toContainText(/not (configured|available)|unavailable/i);
    await expect.soft(page.locator('#btn-scan-abuseipdb'), 'nothing was scanned, so the button must not claim "Scanned"').not.toContainText('Scanned');
  });

  test('a lookup that failed for an address is not shown as "Clean"', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 200 });
    const { page } = analyzer;
    await mockApi(page, '**/api/abuse', (call: ApiCall) => {
      const ips = (call.body as { ips: { ip: string; hits: number }[] }).ips;
      // The shape the backend returns when AbuseIPDB answers with an error for an address.
      const failed = ips.map(entry => ({ ip: entry.ip, hits: entry.hits, domain: 'API_ERROR', abuse_score: 0, country: 'Unknown', error: 'HTTP 429' }));
      return { abusive: [], non_abusive: failed, api_available: true, checked_count: failed.length };
    });
    await analyzer.analysePasted(log.text);
    await page.locator('#btn-center-scan-abuse').click();
    await expect(page.locator('#btn-scan-abuseipdb')).toContainText(/Scanned|Scan/);
    await expect(page.locator('#abuse-table-rows tr').first()).not.toContainText('Ready to scan');
    const rows = (await analyzer.snapshot()).tables.abuse.rows;
    expect.soft(rows.filter(r => /Clean/.test(r.confidence)).map(r => r.ip), 'addresses whose lookup failed (HTTP 429) but are labelled "0% Clean"').toEqual([]);
  });

  test('a failing scan request leaves the dashboard usable', async ({ analyzer, newLog, guard }) => {
    const log = await newLog({ requests: 200 });
    const { page } = analyzer;
    guard.allow(/api\/abuse|status of 500/);
    await mockApi(page, '**/api/abuse', { error: 'boom' }, { status: 500 });
    await analyzer.analysePasted(log.text);
    await page.locator('#btn-center-scan-abuse').click();
    await expect.soft(page.locator('.card-table-wrap', { hasText: 'Abusive IPs' }), 'a failed scan must be reported to the user').toContainText(/fail|error|unavailable|try again/i);
    checkDashboard(await analyzer.snapshot(), log, {}, 'after a failed scan');
  });
});
