import { test, expect } from './fixtures';
import { checkDashboard } from './checks';
import { analyse, summarise, firstSegmentOf, type ViewFilters, type TrafficFilter } from './oracle';
import type { LogRequest } from './generator';
import type { Rng } from '../_support/rng';

/**
 * Traffic Analyzer — the filter ribbon.
 *
 * After every filter change the WHOLE dashboard is compared again: cards,
 * ribbon, charts, tables, explorer, matching counter and the clear pill.
 */

/** Random filters that are guaranteed to match at least `seed`. */
function filtersMatching(rng: Rng, seed: LogRequest, size: number): ViewFilters {
  const candidates: ViewFilters[] = [
    { method: seed.method },
    ...(seed.geo.country !== 'Unknown' ? [{ country: seed.geo.country }] : []),
    { asn: seed.geo.asn },
    { traffic: rng.pick<TrafficFilter>(seed.trafficClass === 'human' ? ['human'] : ['all_bots', seed.trafficClass as TrafficFilter]) },
    { ipSearch: rng.pick([seed.ip, seed.ip.slice(0, Math.max(3, seed.ip.length - rng.int(1, 4)))]) },
    ...(firstSegmentOf(seed.url) ? [{ pathSearch: rng.pick([firstSegmentOf(seed.url) as string, (firstSegmentOf(seed.url) as string).toUpperCase()]) }] : []),
  ];
  return Object.assign({}, ...rng.sample(candidates, size));
}

test.describe('Traffic Analyzer — single filters', () => {
  test('every HTTP method in the dropdown shows only requests with that method', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    const methods = summarise(analyse(log).kept).methods.map(m => m.key);
    for (const method of methods) {
      await analyzer.selectMethod(method);
      checkDashboard(await analyzer.snapshot(), log, { filters: { method } }, 'method filter');
    }
    await analyzer.selectMethod('all');
    checkDashboard(await analyzer.snapshot(), log, {}, 'method filter reset to "All HTTP Methods"');
  });

  test('every country in the dropdown shows only requests from that country', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    const countries = summarise(analyse(log).kept).countries.map(c => c.key).filter(c => c !== 'Unknown');
    expect(countries.length, 'the generated log should span several countries').toBeGreaterThan(1);
    for (const country of countries) {
      await analyzer.selectCountry(country);
      checkDashboard(await analyzer.snapshot(), log, { filters: { country } }, 'country filter');
    }
    await analyzer.selectCountry('all');
    checkDashboard(await analyzer.snapshot(), log, {}, 'country filter reset to "All Countries"');
  });

  test('every network in the ASN dropdown shows only requests from that network', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    for (const { key: asn } of summarise(analyse(log).kept).asns) {
      await analyzer.selectAsn(`AS${asn}`);
      checkDashboard(await analyzer.snapshot(), log, { filters: { asn } }, 'ASN filter');
    }
    await analyzer.selectAsn('all');
    checkDashboard(await analyzer.snapshot(), log, {}, 'ASN filter reset to "All ASNs"');
  });

  test('every traffic class (human, all bots, verified, spoofed, unverified) shows only that class', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    for (const traffic of ['human', 'all_bots', 'verified', 'spoofed', 'unverified'] as const) {
      await analyzer.selectTraffic(traffic);
      const want = checkDashboard(await analyzer.snapshot(), log, { filters: { traffic } }, 'traffic filter');
      expect.soft(want.summary.total, `sanity: the generated log contains "${traffic}" traffic`).toBeGreaterThan(0);
    }
    await analyzer.selectTraffic('all');
    checkDashboard(await analyzer.snapshot(), log, {}, 'traffic filter reset to "All Traffic"');
  });

  test('every entry of the path dropdown shows the number of requests its label promises', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    const segments = summarise(analyse(log).kept).firstSegments.slice(0, 25);
    for (const { key: segment, hits } of segments) {
      await analyzer.selectPath(segment);
      const snap = await analyzer.snapshot();
      const want = checkDashboard(snap, log, { filters: { pathSearch: segment } }, 'path dropdown');
      expect.soft(want.summary.total, `path dropdown entry "${segment} (${hits})" must select exactly ${hits} requests`).toBe(hits);
      expect.soft(snap.filters.path.value, `path dropdown keeps "${segment}" selected`).toBe(segment);
    }
    await analyzer.selectPath('all');
    checkDashboard(await analyzer.snapshot(), log, {}, 'path dropdown reset to "All Paths"');
  });

  test('IP search matches by full address, by partial text and by CIDR network', async ({ analyzer, newLog, rng }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    const kept = analyse(log).kept;
    const v4 = summarise(kept.filter(r => !r.ip.includes(':'))).ips;
    const v6 = summarise(kept.filter(r => r.ip.includes(':'))).ips;
    const top = v4[0].key;
    const octets = top.split('.');
    const other = rng.pick(v4.slice(1)).key;
    const searches = [
      top,
      `${octets[0]}.${octets[1]}.`,
      other.slice(0, other.length - 2),
      `${octets.slice(0, 3).join('.')}.0/24`,
      `${octets[0]}.${octets[1]}.0.0/16`,
      `${octets[0]}.0.0.0/8`,
      `${top}/32`,
      `${Number(octets[0]) - (Number(octets[0]) % 16)}.0.0.0/4`,
      ...(v6.length ? [v6[0].key, v6[0].key.split(':').slice(0, 2).join(':')] : []),
      '  ' + top + '  ',
    ];
    for (const ipSearch of searches) {
      await analyzer.searchIp(ipSearch);
      const snap = await analyzer.snapshot();
      const want = checkDashboard(snap, log, { filters: { ipSearch } }, 'IP search');
      expect.soft(want.summary.total, `sanity: search "${ipSearch}" should match something in this log`).toBeGreaterThan(0);
    }
    await analyzer.searchIp('');
    checkDashboard(await analyzer.snapshot(), log, {}, 'IP search cleared');
  });

  test('path search matches request URLs containing the text, ignoring case', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    for (const pathSearch of ['/api', 'PRODUCTS', '/static/css', '.php', 'v1/orders', '/blog/2026']) {
      await analyzer.searchPath(pathSearch);
      checkDashboard(await analyzer.snapshot(), log, { filters: { pathSearch } }, 'path search');
    }
    await analyzer.searchPath('');
    checkDashboard(await analyzer.snapshot(), log, {}, 'path search cleared');
  });
});

test.describe('Traffic Analyzer — combined filters', () => {
  test('random combinations of two to four filters show exactly the requests matching all of them', async ({ analyzer, newLog, rng }) => {
    const log = await newLog({ requests: 900, clients: 36 });
    await analyzer.analysePasted(log.text);
    const kept = analyse(log).kept;
    for (let i = 0; i < 12; i++) {
      const filters = filtersMatching(rng, rng.pick(kept), rng.int(2, 4));
      await analyzer.applyFilters(filters);
      const want = checkDashboard(await analyzer.snapshot(), log, { filters }, `combination ${i + 1}`);
      expect(want.summary.total, 'sanity: the combination was built to match at least one request').toBeGreaterThan(0);
      await analyzer.clearFilters();
    }
    checkDashboard(await analyzer.snapshot(), log, {}, 'after the last "Clear Active Filters"');
  });

  test('filters added one at a time narrow the result step by step, and removing them widens it again', async ({ analyzer, newLog, rng }) => {
    const log = await newLog({ requests: 900 });
    await analyzer.analysePasted(log.text);
    const kept = analyse(log).kept;
    const seed = rng.pick(kept.filter(r => r.trafficClass === 'human' && r.geo.country !== 'Unknown'));
    const filters: ViewFilters = {};

    filters.traffic = 'human';
    await analyzer.selectTraffic('human');
    checkDashboard(await analyzer.snapshot(), log, { filters: { ...filters } }, 'step 1');
    filters.country = seed.geo.country;
    await analyzer.selectCountry(seed.geo.country);
    checkDashboard(await analyzer.snapshot(), log, { filters: { ...filters } }, 'step 2');
    filters.method = seed.method;
    await analyzer.selectMethod(seed.method);
    checkDashboard(await analyzer.snapshot(), log, { filters: { ...filters } }, 'step 3');
    filters.ipSearch = seed.ip;
    await analyzer.searchIp(seed.ip);
    checkDashboard(await analyzer.snapshot(), log, { filters: { ...filters } }, 'step 4');

    delete filters.country;
    await analyzer.selectCountry('all');
    checkDashboard(await analyzer.snapshot(), log, { filters: { ...filters } }, 'country removed');
    delete filters.ipSearch;
    await analyzer.searchIp('');
    checkDashboard(await analyzer.snapshot(), log, { filters: { ...filters } }, 'IP search removed');
    delete filters.traffic;
    await analyzer.selectTraffic('all');
    checkDashboard(await analyzer.snapshot(), log, { filters: { ...filters } }, 'traffic removed');
  });

  test('a combination that matches nothing shows zeros and empty tables, not leftovers', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 400 });
    await analyzer.analysePasted(log.text);
    const filters: ViewFilters = { traffic: 'verified', ipSearch: '203.0.113.250' };
    await analyzer.applyFilters(filters);
    const snap = await analyzer.snapshot();
    const want = checkDashboard(snap, log, { filters }, 'no match');
    expect(want.summary.total, 'sanity: nothing matches').toBe(0);
    expect.soft(snap.tables.ips.rows, '"Most Active IPs" is empty').toEqual([]);
    expect.soft(snap.tables.asns.rows, '"ASNs & Networks" is empty').toEqual([]);
    expect.soft(snap.tables.referrers.rows, '"Top Referrers" is empty').toEqual([]);
    expect.soft(snap.methods, 'methods ribbon is empty').toEqual([]);
    await expect.soft(analyzer.page.locator('#signal-investigation'), 'empty-table messages').toContainText('No IPs recorded');

    await analyzer.clearFilters();
    checkDashboard(await analyzer.snapshot(), log, {}, 'after clearing the empty result');
  });

  test('filters stay applied while the chart interval and the explorer page change', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 900 });
    await analyzer.analysePasted(log.text);
    const filters: ViewFilters = { method: 'GET' };
    await analyzer.selectMethod('GET');
    await analyzer.chooseInterval(60);
    await analyzer.goToPage('next');
    const snap = await analyzer.snapshot();
    expect.soft(snap.filters.method.value, 'method filter still selected').toBe('GET');
    expect.soft(snap.kpis.total, 'total still filtered').toBe(String(analyse(log).kept.filter(r => r.method === 'GET').length));
    await analyzer.goToPage('first');
    checkDashboard(await analyzer.snapshot(), log, { filters }, 'GET after interval and page changes');
  });
});

