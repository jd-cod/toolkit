import { test, expect } from '../_support/fixtures';
import { openTool } from '../_support/navigation';
import { VIEWPORTS } from '../_support/ui-audit';
import { captureDownload, clearClipboard, readClipboard } from '../_support/io';
import { parseCsv } from '../_support/csv';
import { expectDetails, expectResults } from './checks';
import {
  ABUSE_NOT_CONFIGURED, BOUNDARY_SCORES, generateAbuse, generateBatch, generateGeo, generateIpInfo, generateScenario,
  publicIpv4, publicIpv6Full, type Scenario,
} from './generator';
import { MmdbReader, geoFacts } from './mmdb';
import {
  COUNTRY_NAMES, GLOBE, RISK_LABELS, countersOf, dateIn, expectedRows, flagOf, isPlaceholder, matchesFilter, riskFrom,
  type AbuseRecord, type BatchEntry, type ExpectedRow, type FilterName, type GeoFacts, type IpInfoRecord, type RiskLevel,
} from './oracle';
import {
  ABUSE_URL, GEO_SCRIPT_URL, HEADING, IPINFO_URL, ROUTE, cardToggle, copyButton, desktopTable, exportButton, filterButton,
  lookup, mobileList, mockSources, readCards, readSummary, readTable, resultsPanel, rowToggle, stageSources,
} from './page';
import { mockApi } from '../_support/io';

/**
 * /abuse — every displayed value, every control and every output, against
 * generated answers of the three data sources (contract tests).
 * Inventory and layer map: see abuse.spec.ts.
 */

const TIME_ZONE = process.env.E2E_TIMEZONE ?? 'America/New_York';

function mergeGeo(scenarios: Scenario[]): Record<string, GeoFacts> {
  return Object.assign({}, ...scenarios.map(scenario => scenario.geo));
}

test.describe('IP Info lookup — every displayed value', () => {
  for (const style of ['backend', 'alternate'] as const) {
    test(`rows, cards and counters equal the three sources (AbuseIPDB answer in ${style === 'backend' ? "the backend's shape" : 'the alternate field spelling'})`, async ({ page, rng, evidence }) => {
      const scenarios = [
        generateScenario(rng.fork('a'), { publicV4: 7, privateV4: 2, publicV6: 2, privateV6: 1, invalid: 3 }, { style, scores: [100, 0, 25, 74, 75, 1] }),
        generateScenario(rng.fork('b'), { publicV4: 1, privateV4: 0, publicV6: 0, invalid: 0, blank: 0 }, { style }),
        generateScenario(rng.fork('c'), { publicV4: 12, privateV4: 3, publicV6: 4, privateV6: 2, invalid: 4 }, { style, coverage: 0.7, withCountry: true }),
      ];
      await evidence.save('scenarios.json', scenarios);
      const geo = mergeGeo(scenarios);
      const stage = await stageSources(page, geo);
      await openTool(page, ROUTE, HEADING);
      for (const [number, scenario] of scenarios.entries()) {
        stage.set(scenario);
        await lookup(page, scenario.batch.text);
        const want = expectedRows(scenario.batch.entries, { ...scenario, geo });
        await expectResults(page, want, `scenario ${number + 1} (${want.length} addresses, ${style} shape)`);
      }
    });
  }

  test('the risk badge follows the service level and the AbuseIPDB score at every threshold', async ({ page, rng, evidence }) => {
    const levels: RiskLevel[] = ['safe', 'low', 'medium', 'high'];
    const scores: (number | null)[] = [null, ...BOUNDARY_SCORES];
    const cases = levels.flatMap(level => scores.map(score => ({ level, score, ip: '' })));
    const used = new Set<string>();
    for (const item of cases) {
      do { item.ip = publicIpv4(rng); } while (used.has(item.ip));
      used.add(item.ip);
    }
    const entries = cases.map(item => ({ ip: item.ip, hits: 1 }));
    const ipinfo: IpInfoRecord[] = cases.map(item => ({ ip: item.ip, is_valid: true, is_private: false, ip_version: 'IPv4', reverse_dns: '', risk_level: item.level, risk_reasons: [] }));
    const records: AbuseRecord[] = cases.filter(item => item.score !== null).map(item => ({ ip: item.ip, hits: 1, abuse_score: item.score as number, total_reports: item.score ? 3 : 0 }));
    const abuse = { abusive: records.filter(record => (record.abuse_score ?? 0) > 0), non_abusive: records.filter(record => record.abuse_score === 0), api_available: true, checked_count: records.length };
    await evidence.save('threshold-cases.json', cases);
    expect(entries.length, 'the threshold batch stays within the documented 50 addresses').toBeLessThanOrEqual(50);
    await mockSources(page, { ipinfo, abuse, geo: {} });
    await openTool(page, ROUTE, HEADING);
    await lookup(page, entries.map(entry => entry.ip).join('\n'));

    const shown = await readTable(page);
    const cards = await readCards(page);
    cases.forEach((item, i) => {
      const want = RISK_LABELS[riskFrom(item.level, item.score)];
      const what = `service level "${item.level}" with AbuseIPDB score ${item.score === null ? 'absent' : item.score} (${item.ip})`;
      expect.soft(shown[i]?.badge, `risk badge in the table for ${what}`).toBe(want);
      expect.soft(cards[i]?.badge, `risk badge on the card for ${what}`).toBe(want);
      expect.soft(shown[i]?.score, `abuse score cell for ${what}`).toBe(item.score === null ? 'N/A' : `${item.score}%`);
    });
    await expectResults(page, expectedRows(entries, { ipinfo, abuse, geo: {} }), 'threshold batch');
  });

  test('an address the service could not classify (level "unknown") is not shown as Low risk', async ({ page, rng }) => {
    const ip = publicIpv4(rng);
    const ipinfo: IpInfoRecord[] = [{ ip, is_valid: true, is_private: false, ip_version: 'IPv4', reverse_dns: '', risk_level: 'unknown', risk_reasons: ['Lookup failed'] }];
    await mockSources(page, { ipinfo, abuse: ABUSE_NOT_CONFIGURED, geo: {} });
    await openTool(page, ROUTE, HEADING);
    await lookup(page, ip);
    const [row] = await readTable(page);
    const [card] = await readCards(page);
    expect.soft(row?.badge, `risk badge in the table for ${ip}, which /api/ipinfo reports with risk_level "unknown"`).toBe(RISK_LABELS.unknown);
    expect.soft(card?.badge, `risk badge on the card for ${ip}, risk_level "unknown"`).toBe(RISK_LABELS.unknown);
  });

  test('the country comes from the first source that knows it: AbuseIPDB, then the IP-info service, then GeoIP', async ({ page, rng, evidence }) => {
    const codes = rng.sample(Object.keys(COUNTRY_NAMES), 6);
    const [abuseCode, infoCode, geoCode, codeOnly, lowerAll, other] = codes;
    const ips = Array.from({ length: 6 }, () => publicIpv4(rng));
    const entries = ips.map(ip => ({ ip, hits: 1 }));
    const base = (ip: string): IpInfoRecord => ({ ip, is_valid: true, is_private: false, ip_version: 'IPv4', reverse_dns: '', risk_level: 'low', risk_reasons: [] });
    const ipinfo: IpInfoRecord[] = [
      { ...base(ips[0]), country: COUNTRY_NAMES[infoCode], country_code: infoCode },   // all three know: AbuseIPDB wins
      { ...base(ips[1]), country: COUNTRY_NAMES[infoCode], country_code: infoCode },   // IP-info and GeoIP know: IP-info wins
      base(ips[2]),                                                                    // only GeoIP knows
      base(ips[3]),                                                                    // AbuseIPDB gives a code and no name
      base(ips[4]),                                                                    // nobody knows
      base(ips[5]),                                                                    // AbuseIPDB code as the backend sends it, with country "Unknown"
    ];
    const abuse = {
      abusive: [], api_available: true, checked_count: 3,
      non_abusive: [
        { ip: ips[0], hits: 1, abuse_score: 0, country: COUNTRY_NAMES[abuseCode], country_code: abuseCode },
        { ip: ips[3], hits: 1, abuse_score: 0, country_code: codeOnly },
        { ip: ips[5], hits: 1, abuse_score: 0, country: 'Unknown', country_code: other },
      ] as AbuseRecord[],
    };
    const geo: Record<string, GeoFacts> = {
      [ips[0]]: { country: COUNTRY_NAMES[geoCode], country_code: geoCode },
      [ips[1]]: { country: COUNTRY_NAMES[geoCode], country_code: geoCode },
      [ips[2]]: { country: COUNTRY_NAMES[lowerAll], country_code: lowerAll },
    };
    await evidence.save('country-sources.json', { ipinfo, abuse, geo });
    await mockSources(page, { ipinfo, abuse, geo });
    await openTool(page, ROUTE, HEADING);
    await lookup(page, ips.join('\n'));
    const shown = await readTable(page);
    const want: [string, string, string][] = [
      [abuseCode, COUNTRY_NAMES[abuseCode], 'AbuseIPDB, IP-info and GeoIP all name a country: AbuseIPDB decides'],
      [infoCode, COUNTRY_NAMES[infoCode], 'IP-info and GeoIP name a country: IP-info decides'],
      [lowerAll, COUNTRY_NAMES[lowerAll], 'only GeoIP names a country'],
      [codeOnly, COUNTRY_NAMES[codeOnly], 'AbuseIPDB gives only a code: the English name of that code'],
      ['', 'Unknown', 'no source names a country'],
      [other, COUNTRY_NAMES[other], 'AbuseIPDB gives a code and the name "Unknown": the English name of that code'],
    ];
    want.forEach(([code, name, why], i) => {
      expect.soft(shown[i]?.flag, `flag for ${ips[i]} (${why})`).toBe(code ? flagOf(code) : GLOBE);
      expect.soft(shown[i]?.country, `country name for ${ips[i]} (${why})`).toBe(name);
      expect.soft(shown[i]?.countryCode, `country code for ${ips[i]} (${why})`).toBe(code ? `(${code})` : '');
    });
    await expectResults(page, expectedRows(entries, { ipinfo, abuse, geo }), 'country sources');
  });

  test('flag, country name and code always describe the same country when AbuseIPDB and GeoIP disagree', async ({ page, rng, evidence }) => {
    const [abuseCode, geoCode] = rng.sample(Object.keys(COUNTRY_NAMES), 2);
    const ips = [publicIpv4(rng), publicIpv4(rng), publicIpv4(rng)];
    const ipinfo: IpInfoRecord[] = ips.map(ip => ({ ip, is_valid: true, is_private: false, ip_version: 'IPv4', reverse_dns: '', risk_level: 'low', risk_reasons: [] }));
    // Three ways an AbuseIPDB entry can carry a code without a usable name (all allowed by the page's AbuseEntry type).
    const abuse = { api_available: true, results: [
      { ipAddress: ips[0], abuseConfidenceScore: 0, countryCode: abuseCode },
      { ip: ips[1], abuse_score: 0, country_code: abuseCode },
      { ip: ips[2], abuse_score: 0, country_code: abuseCode, country: '' },
    ] as AbuseRecord[] };
    const geo = Object.fromEntries(ips.map(ip => [ip, { country: COUNTRY_NAMES[geoCode], country_code: geoCode }]));
    await evidence.save('disagreeing-sources.json', { abuse, geo });
    await mockSources(page, { ipinfo, abuse, geo });
    await openTool(page, ROUTE, HEADING);
    await lookup(page, ips.join('\n'));
    const shown = await readTable(page);
    const cards = await readCards(page);
    ips.forEach((ip, i) => {
      const got = `${shown[i]?.flag} ${shown[i]?.country} ${shown[i]?.countryCode}`;
      expect.soft(got, `country cell for ${ip}: AbuseIPDB says ${abuseCode}, GeoIP says ${geoCode} (${COUNTRY_NAMES[geoCode]}); flag, name and code must all be ${abuseCode}`)
        .toBe(`${flagOf(abuseCode)} ${COUNTRY_NAMES[abuseCode]} (${abuseCode})`);
      expect.soft(cards[i]?.country, `country on the card for ${ip}`).toBe(`${flagOf(abuseCode)} ${COUNTRY_NAMES[abuseCode]}`);
    });
  });

  test('AbuseIPDB\'s "no country" marker does not hide the country the GeoIP database knows', async ({ page, rng }) => {
    const code = rng.pick(Object.keys(COUNTRY_NAMES));
    const ip = publicIpv4(rng);
    const ipinfo: IpInfoRecord[] = [{ ip, is_valid: true, is_private: false, ip_version: 'IPv4', reverse_dns: '', risk_level: 'low', risk_reasons: [] }];
    // backend/src/routes/abuse.js sends country "Unknown" and country_code "--" when AbuseIPDB has none.
    const abuse = { abusive: [], non_abusive: [{ ip, hits: 1, abuse_score: 0, country: 'Unknown', country_code: '--', isp: '', usage_type: '', total_reports: 0 }], api_available: true, checked_count: 1 };
    await mockSources(page, { ipinfo, abuse, geo: { [ip]: { country: COUNTRY_NAMES[code], country_code: code } } });
    await openTool(page, ROUTE, HEADING);
    await lookup(page, ip);
    const [row] = await readTable(page);
    expect.soft(`${row?.flag} ${row?.country} ${row?.countryCode}`, `country cell for ${ip}: AbuseIPDB has no country ("--"), the GeoIP database says ${code}`)
      .toBe(`${flagOf(code)} ${COUNTRY_NAMES[code]} (${code})`);
  });

  test('the Reverse DNS column shows PTR records only: AbuseIPDB\'s domain and its "no data" markers are not a PTR', async ({ page, rng, evidence }) => {
    const markers = ['N/A', 'API_ERROR', 'ERROR', 'example-registrar-domain.com'];
    const ips = markers.map(() => publicIpv4(rng));
    const ipinfo: IpInfoRecord[] = ips.map(ip => ({ ip, is_valid: true, is_private: false, ip_version: 'IPv4', reverse_dns: '', risk_level: 'medium', risk_reasons: ['No reverse DNS record'] }));
    // The backend's own shape: `domain` is always present ("N/A" when AbuseIPDB has none, "ERROR"/"API_ERROR" on failure).
    const abuse = { abusive: [], non_abusive: ips.map((ip, i) => ({ ip, hits: 1, domain: markers[i], abuse_score: 0, country: 'Unknown', country_code: '--', isp: '', usage_type: '', total_reports: 0, is_tor: false, is_whitelisted: false, num_distinct_users: 0, last_reported_at: '' })), api_available: true, checked_count: ips.length };
    await evidence.save('sources.json', { ipinfo, abuse });
    await mockSources(page, { ipinfo, abuse, geo: {} });
    await openTool(page, ROUTE, HEADING);
    await lookup(page, ips.join('\n'));
    const shown = await readTable(page);
    const summary = await readSummary(page);
    ips.forEach((ip, i) => {
      expect.soft(shown[i]?.ptr, `Reverse DNS (PTR) for ${ip}: /api/ipinfo found no PTR record; AbuseIPDB's domain field is "${markers[i]}"`).toBe('No PTR record');
    });
    expect.soft(summary.cards['Reverse DNS Found'], `"Reverse DNS Found" when no address has a PTR record`).toBe('0');
    expect.soft(summary.filters['rDNS'], 'count on the "rDNS" filter when no address has a PTR record').toBe(0);
  });

  test('markup in a PTR name, an ISP name, a usage type or a country name is shown as text', async ({ page, rng }) => {
    const ips = [publicIpv4(rng), publicIpv4(rng)];
    const markup = {
      ptr: '<img src=x onerror="window.__xss=1">.example.net',
      isp: '<script>window.__xss=2</script><b>Bold ISP</b>',
      usage: '<i onmouseover="window.__xss=3">Hosting</i>',
      country: '<u>Nowhere</u>',
      org: '<svg onload="window.__xss=4">',
    };
    const ipinfo: IpInfoRecord[] = [
      { ip: ips[0], is_valid: true, is_private: false, ip_version: 'IPv4', reverse_dns: markup.ptr, risk_level: 'low', risk_reasons: [] },
      { ip: ips[1], is_valid: true, is_private: false, ip_version: 'IPv4', reverse_dns: '', risk_level: 'low', risk_reasons: [] },
    ];
    const abuse = { abusive: [], non_abusive: [{ ip: ips[0], hits: 1, abuse_score: 0, isp: markup.isp, usage_type: markup.usage, country: markup.country, country_code: 'ZZ', total_reports: 0 }], api_available: true, checked_count: 1 };
    const geo = { [ips[1]]: { asn: 64500, asn_org: markup.org } };
    let dialogs = 0;
    page.on('dialog', dialog => { dialogs++; void dialog.dismiss(); });
    await mockSources(page, { ipinfo, abuse, geo });
    await openTool(page, ROUTE, HEADING);
    await lookup(page, ips.join('\n'));
    const shown = await readTable(page);
    expect.soft(shown[0]?.ptr, 'PTR with markup, as text').toBe(markup.ptr);
    expect.soft(shown[0]?.isp, 'ISP with markup, as text').toBe(markup.isp);
    expect.soft(shown[0]?.usage, 'usage type with markup, as text').toBe(markup.usage);
    expect.soft(shown[0]?.country, 'country name with markup, as text').toBe(markup.country);
    expect.soft(shown[1]?.isp, 'GeoIP organisation with markup, as text').toBe(markup.org);
    await rowToggle(page, 1).click();
    const open = (await readTable(page))[1]?.expanded;
    expect.soft(open?.['ASN'], 'detail row ASN organisation with markup, as text').toBe(`64500 (${markup.org})`);
    const injected = await resultsPanel(page).evaluate(panel => ({
      elements: panel.querySelectorAll('img, script, svg, u, b').length,
      flag: (window as unknown as { __xss?: number }).__xss ?? null,
    }));
    expect.soft(injected, 'no element may be created from source data and no injected script may run').toEqual({ elements: 0, flag: null });
    expect.soft(dialogs, 'no dialog may open').toBe(0);
  });
});

test.describe('IP Info lookup — filters and details', () => {
  test('each filter shows exactly its rows, its count, and "All" restores the full list', async ({ page, rng, evidence }) => {
    const scenario = generateScenario(rng, { publicV4: 10, privateV4: 2, publicV6: 3, invalid: 1 }, { scores: [0, 5, 30, 80, 100, 0, 24, 25] });
    await evidence.save('scenario.json', scenario);
    await mockSources(page, scenario);
    await openTool(page, ROUTE, HEADING);
    await lookup(page, scenario.batch.text);
    const rows = expectedRows(scenario.batch.entries, scenario);
    expect((await readSummary(page)).selected, '"All" is selected after a lookup').toEqual(['All']);

    const order = rng.shuffle<FilterName>(['rdns', 'risk', 'abusive', 'rdns', 'abusive', 'risk']);
    for (const filter of order) {
      await filterButton(page, filter).click();
      await expectResults(page, rows, `filter "${filter}"`, filter);
      const summary = await readSummary(page);
      expect.soft(summary.selected.length, `exactly one filter is marked selected after choosing "${filter}" (marked: ${summary.selected})`).toBe(1);
      if (rng.bool(0.5)) {
        await filterButton(page, 'all').click();
        await expectResults(page, rows, `back to "All" after "${filter}"`, 'all');
      }
    }
    await filterButton(page, 'all').click();
    await expectResults(page, rows, 'final "All"', 'all');
  });

  test('a filter that matches nothing shows an empty list with "0 of n", not stale rows', async ({ page, rng }) => {
    const batch = generateBatch(rng, { publicV4: 4, privateV4: 1, publicV6: 0, invalid: 0 });
    // Every public address: level low and no PTR; AbuseIPDB not configured. Nothing is elevated, nothing has a PTR.
    const ipinfo = generateIpInfo(rng, batch.entries, { ptrShare: 0, levels: ['low'] });
    const sources = { ipinfo, abuse: ABUSE_NOT_CONFIGURED, geo: generateGeo(rng, batch.entries) };
    await mockSources(page, sources);
    await openTool(page, ROUTE, HEADING);
    await lookup(page, batch.text);
    const rows = expectedRows(batch.entries, sources);
    expect(countersOf(rows), 'the generated batch has no PTR and no elevated address').toMatchObject({ rdns: 0, risk: 0, abusive: 0 });
    for (const filter of ['rdns', 'risk'] as const) {
      await filterButton(page, filter).click();
      await expectResults(page, rows, `filter "${filter}" with no match`, filter);
    }
    await filterButton(page, 'all').click();
    await expectResults(page, rows, 'back to "All"', 'all');
  });

  test('"Info" opens the details of one row with its own values, "Hide" closes them, and only one row is open at a time', async ({ page, rng, evidence }) => {
    const scenario = generateScenario(rng, { publicV4: 6, privateV4: 1, publicV6: 1, invalid: 0 }, { scores: [90, 0, 40] });
    await evidence.save('scenario.json', scenario);
    await mockSources(page, scenario);
    await openTool(page, ROUTE, HEADING);
    await lookup(page, scenario.batch.text);
    const rows = expectedRows(scenario.batch.entries, scenario);

    let previous = -1;
    for (const index of rng.shuffle(rows.map((_, i) => i))) {
      await expect(rowToggle(page, index), `row ${index + 1} offers "Info" while closed`).toHaveText('Info');
      await rowToggle(page, index).click();
      await expect(rowToggle(page, index), `row ${index + 1} offers "Hide" while open`).toHaveText('Hide');
      const shown = await readTable(page);
      expectDetails(shown[index].expanded, rows[index], `details of row ${index + 1}`, 'table');
      const open = shown.map((row, i) => (row.expanded ? i : -1)).filter(i => i >= 0);
      expect.soft(open, `only row ${index + 1} is open (the previously open row ${previous + 1} closes)`).toEqual([index]);
      previous = index;
    }
    await rowToggle(page, previous).click();
    await expect(rowToggle(page, previous)).toHaveText('Info');
    expect.soft((await readTable(page)).filter(row => row.expanded).length, 'no detail row after "Hide"').toBe(0);
    await expectResults(page, rows, 'after opening and closing details');
  });

  test('an open detail row stays with its address when a filter changes the list', async ({ page, rng }) => {
    const scenario = generateScenario(rng, { publicV4: 6, privateV4: 0, publicV6: 0, invalid: 0 }, { scores: [0, 90, 0, 80, 0, 70] });
    await mockSources(page, scenario);
    await openTool(page, ROUTE, HEADING);
    await lookup(page, scenario.batch.text);
    const rows = expectedRows(scenario.batch.entries, scenario);
    const abusive = rows.filter(row => matchesFilter(row, 'abusive'));
    const target = abusive[1];
    await rowToggle(page, rows.indexOf(target)).click();
    await filterButton(page, 'abusive').click();
    const shown = await readTable(page);
    const open = shown.filter(row => row.expanded);
    expect.soft(open.map(row => row.ip), `after filtering to "Abusive", the open details still belong to ${target.ip}`).toEqual([target.ip]);
    if (open[0]) expectDetails(open[0].expanded, target, 'details under the Abusive filter', 'table');
  });

  test('on a narrow screen "Show details" opens the card\'s details with the same values', async ({ page, rng }) => {
    await page.setViewportSize(VIEWPORTS.mobile);
    const scenario = generateScenario(rng, { publicV4: 3, privateV4: 1, publicV6: 1, invalid: 0 }, { scores: [100, 0, 30] });
    await mockSources(page, scenario);
    await openTool(page, ROUTE, HEADING);
    await lookup(page, scenario.batch.text);
    await expect(mobileList(page), 'the card list is used on a phone').toBeVisible();
    await expect(desktopTable(page), 'the table is hidden on a phone').toBeHidden();
    const rows = expectedRows(scenario.batch.entries, scenario);
    for (const index of rows.map((_, i) => i)) {
      const toggle = cardToggle(page, index);
      await expect(toggle).toHaveText('Show details');
      await expect(toggle).toHaveAttribute('aria-expanded', 'false');
      await toggle.click();
      await expect(toggle).toHaveText('Hide details');
      await expect(toggle).toHaveAttribute('aria-expanded', 'true');
      const cards = await readCards(page);
      expectDetails(cards[index].expanded, rows[index], `details of card ${index + 1}`, 'card');
      expect.soft(cards.filter(card => card.expanded).length, 'one card open at a time').toBe(1);
    }
    await expectResults(page, rows, 'phone layout');
  });

  test('the details of a row list the risk reasons, as the guide on the page promises', async ({ page, rng }) => {
    // Guide panel: "Expand a row to see risk reasons and report details."
    const ip = publicIpv4(rng);
    const reasons = ['No reverse DNS record', 'Reverse DNS suggests dynamic/consumer IP'];
    const ipinfo: IpInfoRecord[] = [{ ip, is_valid: true, is_private: false, ip_version: 'IPv4', reverse_dns: '', risk_level: 'medium', risk_reasons: reasons }];
    await mockSources(page, { ipinfo, abuse: ABUSE_NOT_CONFIGURED, geo: {} });
    await openTool(page, ROUTE, HEADING);
    await expect(page.getByRole('complementary', { name: 'Investigate an address' })).toContainText('Expand a row to see risk reasons and report details.');
    await lookup(page, ip);
    await rowToggle(page, 0).click();
    const detailText = await desktopTable(page).locator('tbody > tr').nth(1).innerText();
    for (const reason of reasons) {
      expect.soft(detailText, `the open details of ${ip} (badge Medium) must show the reason "${reason}" returned by /api/ipinfo`).toContain(reason);
    }
  });
});

test.describe('IP Info lookup — copy and export', () => {
  test('"Copy IP Summary" puts one line per analysed address on the clipboard and confirms', async ({ page, rng, evidence }) => {
    const scenario = generateScenario(rng, { publicV4: 6, privateV4: 1, publicV6: 2, invalid: 1 }, { scores: [100, 0, 30] });
    await evidence.save('scenario.json', scenario);
    await mockSources(page, scenario);
    await openTool(page, ROUTE, HEADING);
    await lookup(page, scenario.batch.text);
    const rows = expectedRows(scenario.batch.entries, scenario);
    // The summary covers every analysed address, whatever filter is on.
    await filterButton(page, 'rdns').click();
    await clearClipboard(page);
    await copyButton(page).click();
    await expect(page.getByRole('button', { name: 'Copied Summary!' }), 'the button confirms the copy').toBeVisible();
    const text = await readClipboard(page);
    await evidence.save('clipboard.txt', text);
    const lines = text.split('\n');
    expect(lines.length, 'one clipboard line per analysed address').toBe(rows.length);
    rows.forEach((row, i) => {
      // Format: "<ip> - <PTR or No PTR> - <country> - AS<number> - Risk: <level>".
      const parts = lines[i].split(' - ');
      const at = `clipboard line ${i + 1} ("${lines[i]}")`;
      expect.soft(parts[0], `${at}: address`).toBe(row.ip);
      expect.soft(parts[1], `${at}: PTR`).toBe(row.ptr || 'No PTR');
      const country = parts.slice(2, parts.length - 2).join(' - ');
      expect.soft(country, `${at}: country`).toBe(row.countryName || (row.isPrivate ? 'Private Network' : 'Unknown'));
      const asnPart = parts[parts.length - 2];
      if (row.asn) expect.soft(asnPart, `${at}: AS number`).toBe(`AS${row.asn}`);
      else expect.soft(/\d/.test(asnPart), `${at}: no AS number is known, so none may be printed (got "${asnPart}")`).toBe(false);
      expect.soft(parts[parts.length - 1], `${at}: risk level`).toBe(`Risk: ${row.risk}`);
    });
    await expect(page.getByRole('button', { name: 'Copy IP Summary' }), 'the label returns after two seconds').toBeVisible({ timeout: 5_000 });
  });

  test('"Export CSV" downloads every analysed address with the values the page shows', async ({ page, rng, evidence }) => {
    const scenario = generateScenario(rng, { publicV4: 7, privateV4: 2, publicV6: 2, privateV6: 1, invalid: 2 }, { scores: [100, 0, 30, 75] });
    await evidence.save('scenario.json', scenario);
    await mockSources(page, scenario);
    await openTool(page, ROUTE, HEADING);
    // A fixed instant at which the UTC date and the browser's local date differ.
    const now = new Date('2026-03-15T02:30:00Z');
    await page.clock.setFixedTime(now);
    await lookup(page, scenario.batch.text);
    const rows = expectedRows(scenario.batch.entries, scenario);
    await filterButton(page, 'risk').click();

    const file = await captureDownload(page, () => exportButton(page).click());
    await evidence.save('export.csv', file.text);
    const allowedNames = [...new Set([dateIn('UTC', now), dateIn(TIME_ZONE, now)])].map(date => `abuse-ip-report-${date}.csv`);
    expect.soft(allowedNames, `file name "${file.filename}" carries today's date (UTC or the browser's zone ${TIME_ZONE})`).toContain(file.filename);

    const [header, ...records] = parseCsv(file.text);
    expect(records.length, 'one CSV row per analysed address (the active filter does not shorten the export)').toBe(rows.length);
    const column = (record: string[], name: string) => record[header.indexOf(name)];
    for (const name of ['ip', 'hits', 'ip_version', 'is_private', 'reverse_dns', 'country_code', 'country', 'asn', 'asn_org', 'isp', 'usage_type', 'risk_level', 'risk_reasons', 'abuse_score', 'total_reports', 'num_distinct_users', 'last_reported_at', 'is_tor', 'is_whitelisted']) {
      expect.soft(header, `CSV header has a "${name}" column`).toContain(name);
    }
    rows.forEach((row, i) => {
      const record = records[i];
      const at = `CSV row ${i + 1} (${row.ip})`;
      const text = (name: string) => column(record, name);
      const placeholderOr = (name: string, value: string) => {
        if (value) expect.soft(text(name), `${at}: ${name}`).toBe(value);
        else expect.soft(isPlaceholder(text(name)), `${at}: ${name} has no source value, a placeholder is expected, got "${text(name)}"`).toBe(true);
      };
      expect.soft(text('ip'), `${at}: ip`).toBe(row.ip);
      expect.soft(text('hits'), `${at}: hits (request count typed for this address)`).toBe(String(row.hits));
      expect.soft(text('ip_version'), `${at}: ip_version`).toBe(row.version);
      expect.soft(text('is_private'), `${at}: is_private`).toBe(String(row.isPrivate));
      expect.soft(text('reverse_dns'), `${at}: reverse_dns`).toBe(row.ptr);
      placeholderOr('country_code', row.countryCode);
      expect.soft(text('country'), `${at}: country`).toBe(row.countryName || (row.isPrivate ? 'Private Network' : 'Unknown'));
      placeholderOr('asn', row.asn);
      placeholderOr('asn_org', row.asnOrg);
      if (row.isp) expect.soft(text('isp'), `${at}: isp`).toBe(row.isp);
      else expect.soft(['N/A', 'Unknown', 'Internal / Private Network'], `${at}: isp placeholder, got "${text('isp')}"`).toContain(text('isp'));
      placeholderOr('usage_type', row.usage);
      expect.soft(text('risk_level'), `${at}: risk_level`).toBe(row.risk);
      const reasons = JSON.parse(text('risk_reasons') || '[]') as string[];
      expect.soft(reasons.slice(0, row.serviceReasons.length), `${at}: risk_reasons from /api/ipinfo`).toEqual(row.serviceReasons);
      const extra = reasons.slice(row.serviceReasons.length);
      if (row.score !== null && row.score > 0) {
        expect.soft(extra.length, `${at}: one extra reason for the AbuseIPDB score ${row.score}`).toBe(1);
        expect.soft(extra[0] ?? '', `${at}: the AbuseIPDB reason names the score ${row.score}% and ${row.reports} reports`).toMatch(new RegExp(`\\b${row.score}%.*\\b${row.reports} reports`));
      } else {
        expect.soft(extra, `${at}: no AbuseIPDB reason without a score above 0`).toEqual([]);
      }
      if (row.score !== null) expect.soft(text('abuse_score'), `${at}: abuse_score`).toBe(String(row.score));
      expect.soft(text('total_reports'), `${at}: total_reports`).toBe(String(row.reports));
      expect.soft(text('num_distinct_users'), `${at}: num_distinct_users`).toBe(String(row.distinctUsers));
      expect.soft(text('last_reported_at'), `${at}: last_reported_at`).toBe(row.lastReported);
      expect.soft(text('is_tor'), `${at}: is_tor`).toBe(String(row.tor));
      expect.soft(text('is_whitelisted'), `${at}: is_whitelisted`).toBe(String(row.whitelisted));
    });
  });

  test('the CSV leaves a cell empty when there is no value: no literal "null" or "undefined"', async ({ page, rng, evidence }) => {
    const batch = generateBatch(rng, { publicV4: 2, privateV4: 1, publicV6: 0, invalid: 0 });
    await mockSources(page, { ipinfo: generateIpInfo(rng, batch.entries), abuse: ABUSE_NOT_CONFIGURED, geo: {} });
    await openTool(page, ROUTE, HEADING);
    await lookup(page, batch.text);
    const file = await captureDownload(page, () => exportButton(page).click());
    await evidence.save('export.csv', file.text);
    const [header, ...records] = parseCsv(file.text);
    records.forEach((record, i) => record.forEach((cell, c) => {
      expect.soft(cell, `CSV row ${i + 1} (${record[0]}), column "${header[c]}": AbuseIPDB gave no score, the cell must be empty`).not.toMatch(/^(null|undefined|NaN)$/);
    }));
  });
});

test.describe('IP Info lookup — the GeoIP database in the browser', () => {
  test('country and AS number equal an independent read of the same .mmdb files', async ({ page, request, rng, evidence }) => {
    test.slow();
    // Real /js/geoip.js and real database files; only the two API calls are answered by the test.
    const [countryFile, asnFile] = await Promise.all([request.get('/data/GeoLite2-Country.mmdb'), request.get('/data/GeoLite2-ASN.mmdb')]);
    expect(countryFile.ok() && asnFile.ok(), 'the frontend serves both GeoLite2 files under /data').toBe(true);
    const countries = new MmdbReader(await countryFile.body());
    const networks = new MmdbReader(await asnFile.body());

    const addresses = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222', '2001:4860:4860:0:0:0:0:8888', '2606:4700:4700:0:0:0:0:1111', '2620:fe:0:0:0:0:0:fe', '10.1.2.3'];
    while (addresses.length < 30) addresses.push(rng.bool(0.8) ? publicIpv4(rng) : publicIpv6Full(rng));
    const entries: BatchEntry[] = addresses.map(ip => ({ ip, hits: 1 }));
    const ipinfo = generateIpInfo(rng, entries);
    const geo = Object.fromEntries(addresses.map(ip => [ip, geoFacts(countries, networks, ip)]));
    await evidence.save('geo-from-mmdb.json', geo);
    expect(Object.values(geo).filter(facts => facts.asn).length, 'the sample must hit the ASN database often enough to mean something').toBeGreaterThan(10);

    await mockApi(page, IPINFO_URL, { results: ipinfo });
    await mockApi(page, ABUSE_URL, ABUSE_NOT_CONFIGURED);
    await openTool(page, ROUTE, HEADING);
    await lookup(page, addresses.join('\n'));
    await expectResults(page, expectedRows(entries, { ipinfo, abuse: ABUSE_NOT_CONFIGURED, geo }), 'real GeoLite2 files');
  });

  test('when the GeoIP reader cannot be loaded the lookup still works, with no country and no AS number invented', async ({ page, rng, guard }) => {
    const batch = generateBatch(rng, { publicV4: 4, privateV4: 1, publicV6: 1, invalid: 0 });
    const sources = { ipinfo: generateIpInfo(rng, batch.entries), abuse: generateAbuse(rng, batch.entries), geo: {} };
    guard.allow(/geoip\.js|status of 404|ERR_FAILED/);
    await page.route(GEO_SCRIPT_URL, route => route.fulfill({ status: 404, contentType: 'text/plain', body: 'not found' }));
    await mockApi(page, IPINFO_URL, { results: sources.ipinfo });
    await mockApi(page, ABUSE_URL, sources.abuse);
    await openTool(page, ROUTE, HEADING);
    await lookup(page, batch.text);
    await expectResults(page, expectedRows(batch.entries, sources), 'GeoIP reader missing');
  });

  test('when the database files cannot be downloaded the lookup still works, with no country and no AS number invented', async ({ page, rng, guard }) => {
    const batch = generateBatch(rng, { publicV4: 4, privateV4: 1, publicV6: 1, invalid: 0 });
    const sources = { ipinfo: generateIpInfo(rng, batch.entries), abuse: generateAbuse(rng, batch.entries), geo: {} };
    guard.allow(/GeoIP|mmdb|status of 503|HTTP 503/);
    await page.route('**/data/*.mmdb*', route => route.fulfill({ status: 503, contentType: 'text/plain', body: 'unavailable' }));
    await mockApi(page, IPINFO_URL, { results: sources.ipinfo });
    await mockApi(page, ABUSE_URL, sources.abuse);
    await openTool(page, ROUTE, HEADING);
    await lookup(page, batch.text);
    await expectResults(page, expectedRows(batch.entries, sources), 'GeoIP database files missing');
  });
});
