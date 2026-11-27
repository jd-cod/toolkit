import { test, expect, type Page } from '../_support/fixtures';
import { captureApi, captureDownload, failApi, mockApi, type ApiCall } from '../_support/io';
import { expectNoUiGlitches, VIEWPORTS } from '../_support/ui-audit';
import { expectCsvMatches, expectNoMarkupExecuted, expectReportMatches, expectViewMatches, readHtmlReport, runAndCheck } from './checks';
import { randomDomain, randomGlobalRecord, randomGlobalResults, randomLookup, type GlobalMix } from './generator';
import {
  GLOBAL_CSV_HEADER, GLOBAL_REGIONS, GeoOracle, OFFERED_TYPES, RESOLVERS, expectedGlobalCsvRows, expectedGlobalRows, expectedGlobalView,
  utcStamp, utcStampsBetween, type GlobalRegion,
} from './oracle';
import { DnsPage, ROUTE, SharedPage, gate, openVisitor, serveLookups } from './page';

/**
 * DNS Lookup (/dns) — Global Propagation mode.
 *
 * `POST /api/dns/global` asks AWS Lambda functions in 15 regions; they are not
 * reachable from a test machine and the endpoint allows 5 calls per minute, so
 * the mode is tested against a mocked capability and mocked regional answers
 * (README section 7). What the real backend reports as capability is honoured
 * in dns.spec.ts ("opens with its controls ready …").
 *
 * Definitions: oracle.ts (`expectedGlobalRows`, `globalRecordText`, `expectedGlobalView`).
 */

const GLOBAL_API = /\/api\/dns\/global$/;

interface GlobalSetup {
  dns: DnsPage;
  calls: Awaited<ReturnType<typeof mockApi>>;
}

/** Opens the tool with Global Propagation available and `answers[type]` as the regional results. */
async function openGlobal(page: Page, answers: Record<string, GlobalRegion[]>): Promise<GlobalSetup> {
  await mockApi(page, '**/api/dns/global-capability', { available: true });
  const calls = await mockApi(page, '**/api/dns/global', (call: ApiCall) => {
    const body = call.body as { domain: string; type: string };
    return { domain: body.domain, type: body.type, results: answers[body.type] ?? [] };
  }, { method: 'POST' });
  const dns = new DnsPage(page);
  await dns.open();
  await expect(dns.globalMode, 'Global Propagation is offered when the backend reports it available').toBeVisible();
  await dns.globalMode.click();
  await expect(dns.globalMode).toHaveAttribute('aria-pressed', 'true');
  return { dns, calls };
}

/** Types a domain, picks a type, presses Lookup and waits for the regional answer to be on screen. */
async function globalLookup(dns: DnsPage, domain: string, type: string): Promise<void> {
  await dns.typeBox(type).check();
  await dns.domain.fill(domain);
  await captureApi(dns.page, GLOBAL_API, () => dns.lookupButton.click());
  await expect(dns.lookupButton, 'the lookup has finished').toHaveText('Lookup');
}

function expectGlobalTable(shown: Awaited<ReturnType<DnsPage['globalRows']>>, results: GlobalRegion[], ctx: string): void {
  const want = expectedGlobalRows(results);
  expect.soft(shown.map(row => row.region), `${ctx}: regions and their order`).toEqual(want.map(row => row.region));
  want.forEach((row, i) => {
    if (!shown[i]) return;
    expect.soft(shown[i].status, `${ctx}: status of ${row.region}`).toBe(row.status);
    expect.soft(shown[i].lines, `${ctx}: result of ${row.region}`).toEqual(row.lines);
  });
}

test.describe('DNS Lookup, Global Propagation — availability and form', () => {
  test('the Global Propagation button is offered only when the backend says the feature is available', async ({ page, guard }) => {
    const dns = new DnsPage(page);
    await mockApi(page, '**/api/dns/global-capability', { available: false });
    await dns.open();
    await expect(dns.standardMode).toBeVisible();
    await expect.soft(dns.globalMode, 'available=false: no Global Propagation button').toHaveCount(0);

    await page.unroute('**/api/dns/global-capability');
    await mockApi(page, '**/api/dns/global-capability', { available: true });
    await dns.open();
    await expect.soft(dns.globalMode, 'available=true: Global Propagation button').toBeVisible();

    guard.allow(/status of 500|HTTP 500/);
    await page.unroute('**/api/dns/global-capability');
    await mockApi(page, '**/api/dns/global-capability', { error: 'Internal Server Error' }, { status: 500 });
    await dns.open();
    await expect(dns.standardMode).toBeVisible();
    await expect.soft(dns.globalMode, 'capability check failed: no Global Propagation button').toHaveCount(0);
  });

  test('switching to Global Propagation hides the resolver, keeps exactly one record type and updates the side panel', async ({ page, rng }) => {
    const dns = new DnsPage(page);
    await mockApi(page, '**/api/dns/global-capability', { available: true });
    await dns.open();
    const ticked = rng.sample(OFFERED_TYPES, rng.int(2, 6));
    await dns.selectTypes(ticked);
    await dns.globalMode.click();

    await expect.soft(dns.globalMode).toHaveAttribute('aria-pressed', 'true');
    await expect.soft(dns.standardMode).toHaveAttribute('aria-pressed', 'false');
    await expect.soft(dns.resolver, 'no resolver choice in Global mode').toHaveCount(0);
    await expect.soft(page.locator('.signal-query-note')).toHaveText(/Compares DNS responses across the configured regional lookup services\./);
    const kept = await dns.checkedTypes();
    expect.soft(kept.length, `Global mode keeps exactly one of the ticked types (${ticked.join(', ')}); now ticked: ${kept.join(', ')}`).toBe(1);
    expect.soft(ticked, 'the kept type is one the user had ticked').toContain(kept[0]);
    expect.soft(await dns.queryDetails(), 'side panel in Global mode').toEqual({ 'Query mode': 'Global propagation', Resolver: 'Regional lookup services', 'Selected records': kept[0] });

    // Ticking another type moves the selection: always exactly one.
    for (const type of rng.sample(OFFERED_TYPES, 4)) {
      await dns.typeBox(type).click();
      expect.soft(await dns.checkedTypes(), `after clicking ${type} in Global mode`).toEqual([type]);
      expect.soft((await dns.queryDetails())['Selected records'], `side panel after clicking ${type}`).toBe(type);
    }

    await dns.standardMode.click();
    await expect.soft(dns.resolver, 'the resolver choice returns in Standard mode').toBeVisible();
    await expect.soft(page.locator('.signal-query-note')).toHaveText(/DNS queries are sent to your selected resolver over HTTPS\./);
    expect.soft((await dns.queryDetails())['Query mode']).toBe('Standard');
    // Boxes are independent again.
    const stillTicked = await dns.checkedTypes();
    const [first, second] = rng.sample(OFFERED_TYPES.filter(type => !stillTicked.includes(type)), 2);
    await dns.typeBox(first).check();
    await dns.typeBox(second).check();
    expect.soft((await dns.checkedTypes()).length, 'Standard mode allows several types again').toBe(3);
  });
});

test.describe('DNS Lookup, Global Propagation — regional results', () => {
  test('every record type: each region is listed with its status and its records in readable form', async ({ page, rng, evidence }) => {
    const domain = randomDomain(rng);
    const mixes: GlobalMix[] = ['all-ok', 'some-failed', 'differing'];
    const answers: Record<string, GlobalRegion[]> = {};
    for (const type of OFFERED_TYPES) answers[type] = randomGlobalResults(rng, type, domain, rng.pick(mixes));
    await evidence.save('global-answers.json', { domain, answers });
    const { dns, calls } = await openGlobal(page, answers);

    for (const type of rng.shuffle(OFFERED_TYPES)) {
      const sentBefore = calls.length;
      await globalLookup(dns, domain, type);
      const ctx = `global lookup of "${domain}" ${type}`;
      expect.soft(calls.slice(sentBefore).map(call => call.body), `${ctx}: request body sent to POST /api/dns/global`).toEqual([{ domain, type }]);
      await expect(dns.globalPanel, `${ctx}: the result table is shown`).toBeVisible();
      expectGlobalTable(await dns.globalRows(), answers[type], ctx);
      const anyOk = answers[type].some(region => region.status === 'success');
      await expect.soft(dns.alert, `${ctx}: error banner only when every region failed`).toHaveCount(anyOk ? 0 : 1);
      await expect.soft(dns.checkedAt, `${ctx}: no Standard-mode result area in Global mode`).toHaveCount(0);
    }
    await expectNoMarkupExecuted(page, 'global lookups');
  });

  test('regions that disagree, fail, return nothing or answer without a record list are each reported as such', async ({ page, rng, evidence }) => {
    const domain = randomDomain(rng);
    const results: GlobalRegion[] = [
      { region: GLOBAL_REGIONS[0], status: 'success', data: { records: ['192.0.2.1', '192.0.2.2'], duration_ms: 41 } },
      { region: GLOBAL_REGIONS[1], status: 'success', data: { records: ['192.0.2.2', '192.0.2.1'], duration_ms: 39 } },
      { region: GLOBAL_REGIONS[2], status: 'success', data: { records: ['198.51.100.77'], duration_ms: 1200 } },
      { region: GLOBAL_REGIONS[3], status: 'success', data: { records: [], duration_ms: 12 } },
      { region: GLOBAL_REGIONS[4], status: 'error', error: 'HTTP 502 Bad Gateway' },
      { region: GLOBAL_REGIONS[5], status: 'error', error: 'The operation was aborted due to timeout' },
      { region: GLOBAL_REGIONS[6], status: 'error' },
      { region: GLOBAL_REGIONS[7], status: 'success', data: { duration_ms: 9 } },
      { region: GLOBAL_REGIONS[14], status: 'success', data: { records: [randomGlobalRecord(rng, 'A', domain)], duration_ms: 77 } },
    ];
    await evidence.save('global-edge-regions.json', results);
    const { dns } = await openGlobal(page, { A: results });
    await globalLookup(dns, domain, 'A');
    const shown = await dns.globalRows();
    expectGlobalTable(shown, results, `global lookup of "${domain}" A`);
    // Written out by hand, independent of the oracle function.
    expect.soft(shown.map(row => `${row.status}: ${row.lines.join(' / ')}`).slice(0, 8), 'statuses and results, by hand').toEqual([
      'Success: 192.0.2.1 / 192.0.2.2', 'Success: 192.0.2.2 / 192.0.2.1', 'Success: 198.51.100.77', 'Success: No records',
      'Failed: HTTP 502 Bad Gateway', 'Failed: The operation was aborted due to timeout', 'Failed: No records found', 'Failed: No records found',
    ]);
    await expect.soft(dns.alert, 'no error banner while some regions answered').toHaveCount(0);
  });

  test('when every region fails the page says so and still lists each region with its error', async ({ page, rng, evidence }) => {
    const domain = randomDomain(rng);
    const type = rng.pick(OFFERED_TYPES);
    const results = randomGlobalResults(rng, type, domain, 'all-failed');
    await evidence.save('global-all-failed.json', results);
    const { dns } = await openGlobal(page, { [type]: results });
    await globalLookup(dns, domain, type);
    await expect.soft(dns.alert).toHaveText('All regional queries failed. Individual errors are shown below.');
    expectGlobalTable(await dns.globalRows(), results, `all regions failed for "${domain}" ${type}`);
    await expectNoMarkupExecuted(page, 'all regions failed');
  });

  test('while the regions are being asked the button reads "Querying...", is disabled, and the previous table is gone', async ({ page, rng, evidence }) => {
    const domain = randomDomain(rng);
    const first = randomGlobalResults(rng, 'A', domain, 'all-ok');
    const second = randomGlobalResults(rng, 'MX', domain, 'some-failed');
    await evidence.save('global-slow.json', { domain, first, second });
    const held = gate();
    await mockApi(page, '**/api/dns/global-capability', { available: true });
    const calls: unknown[] = [];
    await page.route('**/api/dns/global', async route => {
      const body = route.request().postDataJSON() as { type: string };
      calls.push(body);
      if (body.type === 'MX') await held.promise;
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ domain, type: body.type, results: body.type === 'MX' ? second : first }) }).catch(() => undefined);
    });
    const dns = new DnsPage(page);
    await dns.open();
    await dns.globalMode.click();
    await globalLookup(dns, domain, 'A');
    expectGlobalTable(await dns.globalRows(), first, 'first global lookup (A)');

    await dns.typeBox('MX').check();
    await dns.lookupButton.click();
    await expect(dns.lookupButton).toHaveText('Querying...');
    await expect.soft(dns.lookupButton, 'no second submit while waiting').toBeDisabled();
    await expect.soft(dns.standardMode, 'mode buttons are locked while waiting').toBeDisabled();
    await expect.soft(dns.globalMode).toBeDisabled();
    await expect.soft(dns.globalPanel, 'the table of the previous lookup (A) must not stay while MX is being asked').toHaveCount(0);
    held.open();
    await expect(dns.lookupButton).toHaveText('Lookup');
    expectGlobalTable(await dns.globalRows(), second, 'second global lookup (MX) after the slow answer');
    expect.soft(calls, 'requests sent to POST /api/dns/global').toEqual([{ domain, type: 'A' }, { domain, type: 'MX' }]);
  });
});

test.describe('DNS Lookup, Global Propagation — failed requests', () => {
  const failures: { name: string; status: number; body: unknown; message: string | RegExp; allow?: RegExp }[] = [
    { name: 'HTTP 503 (feature unavailable on the server)', status: 503, body: { error: 'Global propagation is unavailable on this server. Use a standard DNS query.', results: [] }, message: 'Global propagation is unavailable on this server. Use a standard DNS query.', allow: /status of 503|HTTP 503/ },
    { name: 'HTTP 429 (5 lookups per minute)', status: 429, body: { statusCode: 429, error: 'Too Many Requests', message: 'Rate limit exceeded, retry in 1 minute' }, message: 'Too Many Requests', allow: /status of 429/ },
    { name: 'HTTP 500', status: 500, body: { statusCode: 500, error: 'Internal Server Error', message: 'boom' }, message: 'Internal Server Error', allow: /status of 500|HTTP 500/ },
    { name: 'HTTP 400 with an error message', status: 400, body: { error: 'Invalid domain name.', results: [] }, message: 'Invalid domain name.', allow: /status of 400/ },
    { name: 'HTTP 200 carrying an error', status: 200, body: { error: 'Invalid record type: ZZ', results: [] }, message: 'Invalid record type: ZZ' },
    { name: 'an answer without any region', status: 200, body: { domain: 'x', type: 'A', results: [] }, message: 'No regional results were returned. Try again or use a standard query.' },
  ];

  for (const failure of failures) {
    test(`${failure.name}: the message is shown, no table, and the form is usable again`, async ({ page, rng, guard }) => {
      if (failure.allow) guard.allow(failure.allow);
      await mockApi(page, '**/api/dns/global-capability', { available: true });
      const calls = await mockApi(page, '**/api/dns/global', failure.body, { method: 'POST', status: failure.status });
      const dns = new DnsPage(page);
      await dns.open();
      await dns.globalMode.click();
      const domain = randomDomain(rng);
      await globalLookup(dns, domain, 'A');
      await expect.soft(dns.alert, `${failure.name}: message`).toHaveText(failure.message);
      await expect.soft(dns.globalPanel, `${failure.name}: no result table`).toHaveCount(0);
      await expect.soft(dns.lookupButton, `${failure.name}: button usable again`).toBeEnabled();
      expect.soft(calls.map(call => call.body), `${failure.name}: request body`).toEqual([{ domain, type: 'A' }]);

      // Leaving Global mode clears the message.
      await dns.standardMode.click();
      await expect.soft(dns.alert, 'the error disappears when switching to Standard Query').toHaveCount(0);
    });
  }

  test('a network failure shows an error and a later lookup works', async ({ page, rng, guard, evidence }) => {
    guard.allow(/request failed: POST .*\/api\/dns\/global|net::ERR_FAILED/);
    await mockApi(page, '**/api/dns/global-capability', { available: true });
    await failApi(page, '**/api/dns/global');
    const dns = new DnsPage(page);
    await dns.open();
    await dns.globalMode.click();
    const domain = randomDomain(rng);
    await dns.domain.fill(domain);
    await dns.lookupButton.click();
    await expect(dns.alert, 'an error is shown when the request cannot be sent').toBeVisible();
    await expect.soft(dns.alert).not.toHaveText('');
    await expect.soft(dns.globalPanel).toHaveCount(0);
    await expect.soft(dns.lookupButton).toHaveText('Lookup');

    const results = randomGlobalResults(rng, 'A', domain, 'all-ok');
    await evidence.save('global-recovery.json', results);
    await page.unroute('**/api/dns/global');
    await mockApi(page, '**/api/dns/global', { domain, type: 'A', results }, { method: 'POST' });
    await globalLookup(dns, domain, 'A');
    await expect.soft(dns.alert, 'the error is cleared by a successful lookup').toHaveCount(0);
    expectGlobalTable(await dns.globalRows(), results, 'recovery lookup');
  });
});

test.describe('DNS Lookup, Global Propagation — exports and sharing', () => {
  test('Export CSV has one row per regional record (one per region without records), named after the domain', async ({ page, rng, evidence }) => {
    const domain = randomDomain(rng);
    const type = rng.pick(['A', 'MX', 'TXT', 'SOA', 'SRV']);
    const results = randomGlobalResults(rng, type, domain, 'some-failed');
    await evidence.save('global-csv-answer.json', { domain, type, results });
    const { dns } = await openGlobal(page, { [type]: results });
    await globalLookup(dns, domain, type);
    const file = await captureDownload(page, () => dns.globalPanel.getByRole('button', { name: 'Export CSV' }).click());
    await evidence.save('global-export.csv', file.text);
    const ctx = `global CSV for "${domain}" ${type}`;
    expect.soft(file.filename, `${ctx}: file name`).toBe(`${domain}-global-dns-snapshot.csv`);
    expectCsvMatches(file.text, GLOBAL_CSV_HEADER, expectedGlobalCsvRows(results), ctx);
  });

  test('Download HTML saves a report with one section per region, its records and its query time', async ({ page, rng, evidence }) => {
    const domain = randomDomain(rng);
    const type = rng.pick(['A', 'AAAA', 'MX', 'TXT', 'NS']);
    const results = randomGlobalResults(rng, type, domain, 'some-failed');
    await evidence.save('global-html-answer.json', { domain, type, results });
    const { dns } = await openGlobal(page, { [type]: results });
    await globalLookup(dns, domain, type);
    const before = Date.now();
    const file = await captureDownload(page, () => dns.globalPanel.getByRole('button', { name: 'Download HTML' }).click());
    await evidence.save('global-report.html', file.text);
    const ctx = `global HTML report for "${domain}" ${type}`;
    expect.soft(file.filename, `${ctx}: file name`).toBe(`${domain}-global-dns-snapshot.html`);
    expectReportMatches(await readHtmlReport(page, file.text), expectedGlobalView(domain, type, results), {
      ctx, stamps: utcStampsBetween(before - 120_000, Date.now() + 1000), skipTtl: true,
    });
  });

  test('a shared global snapshot shows another visitor the same regions, records and query times', async ({ page, rng, evidence, browser, baseURL }) => {
    const domain = randomDomain(rng);
    const type = rng.pick(['A', 'MX', 'TXT', 'CNAME']);
    const results = randomGlobalResults(rng, type, domain, 'some-failed');
    await evidence.save('global-share-answer.json', { domain, type, results });
    const { dns } = await openGlobal(page, { [type]: results });
    await globalLookup(dns, domain, type);
    await dns.shareGlobalButton.click();
    await expect(dns.share.heading).toBeVisible();
    await expect.soft(dns.share.title, 'default title of a global share').toHaveValue(`${domain} Global DNS Snapshot`);
    const { code, request } = await dns.share.create();
    const want = expectedGlobalView(domain, type, results);
    const ctx = `shared global snapshot /s/${code} of "${domain}" ${type}`;
    expect.soft(request.domain, `${ctx}: domain stored with the share`).toBe(domain);
    expect.soft((request.snapshot as { selected_types: string[] }).selected_types, `${ctx}: record type stored`).toEqual([type]);

    const visitor = await openVisitor(browser, baseURL!);
    try {
      const shared = new SharedPage(visitor.page);
      await shared.open(code);
      await shared.waitForSnapshot();
      await expect.soft(shared.title, `${ctx}: title`).toHaveText(`${domain} Global DNS Snapshot`);
      expectViewMatches(await shared.view(), want, { ctx, skipTtl: true });
      expect.soft(visitor.problems(), `${ctx}: browser errors for the visitor`).toEqual([]);
    } finally {
      await visitor.close();
    }
  });

  test('exports and shares describe the lookup that produced the table, not what is typed in the form afterwards', async ({ page, rng, evidence }) => {
    const domain = randomDomain(rng);
    const other = randomDomain(rng);
    const results = randomGlobalResults(rng, 'A', domain, 'all-ok');
    await evidence.save('global-relabel.json', { lookedUp: { domain, type: 'A' }, typedAfterwards: { domain: other, type: 'MX' }, results });
    const { dns } = await openGlobal(page, { A: results });
    const shares = await mockApi(page, '**/api/share/dns', { success: true, code: 'TESTCODE', url: '/s/TESTCODE' }, { method: 'POST' });
    await globalLookup(dns, domain, 'A');
    expectGlobalTable(await dns.globalRows(), results, `global lookup of "${domain}" A`);

    // The user starts preparing the next lookup but has not pressed Lookup yet.
    await dns.domain.fill(other);
    await dns.typeBox('MX').check();
    expectGlobalTable(await dns.globalRows(), results, `the table still shows the answers for "${domain}" A`);
    const ctx = `table holds "${domain}" A, form now says "${other}" MX`;

    const csv = await captureDownload(page, () => dns.globalPanel.getByRole('button', { name: 'Export CSV' }).click());
    expect.soft(csv.filename, `${ctx}: CSV file name`).toBe(`${domain}-global-dns-snapshot.csv`);
    const html = await captureDownload(page, () => dns.globalPanel.getByRole('button', { name: 'Download HTML' }).click());
    expect.soft(html.filename, `${ctx}: report file name`).toBe(`${domain}-global-dns-snapshot.html`);
    const report = await readHtmlReport(page, html.text);
    expect.soft(report.cards[0]?.value, `${ctx}: Domain card of the report`).toBe(domain);
    expect.soft(report.title, `${ctx}: report title`).toBe(`DNS Snapshot Report - ${domain}`);

    await dns.shareGlobalButton.click();
    await expect.soft(dns.share.title, `${ctx}: share title`).toHaveValue(`${domain} Global DNS Snapshot`);
    await dns.share.generate.click();
    await expect(dns.share.created).toBeVisible();
    const sent = shares[0]?.body as { domain: string; snapshot: { domain: string; selected_types: string[] } };
    expect.soft(sent?.domain, `${ctx}: domain sent to POST /api/share/dns`).toBe(domain);
    expect.soft(sent?.snapshot.domain, `${ctx}: snapshot.domain sent to POST /api/share/dns`).toBe(domain);
    expect.soft(sent?.snapshot.selected_types, `${ctx}: snapshot.selected_types sent to POST /api/share/dns`).toEqual(['A']);
  });

  test('the "Checked At" time of a global snapshot is when the regions were asked, not when it is shared', async ({ page, rng, evidence }) => {
    await page.clock.install();
    const domain = randomDomain(rng);
    const results = randomGlobalResults(rng, 'A', domain, 'all-ok');
    const { dns } = await openGlobal(page, { A: results });
    const before = Date.now();
    await globalLookup(dns, domain, 'A');
    const after = Date.now();
    const minutesLater = rng.int(7, 55);
    await evidence.save('global-checked-at.json', { domain, lookedUpBetween: [utcStamp(before), utcStamp(after)], sharedMinutesLater: minutesLater });
    await page.clock.fastForward(minutesLater * 60_000);

    await dns.shareGlobalButton.click();
    await expect(dns.share.heading).toBeVisible();
    const shown = await dns.share.checkedAt.textContent();
    expect.soft(utcStampsBetween(before - 2000, after + 2000), `lookup ran at ${utcStamp(before)}; ${minutesLater} minutes later the share dialog says "Checked At: ${shown}" — the snapshot must keep the time of the lookup`).toContain(shown);
  });

  test('a global report does not present a TTL the regional lookups never measured as "0s"', async ({ page, rng, evidence }) => {
    const domain = randomDomain(rng);
    const results = randomGlobalResults(rng, 'A', domain, 'all-ok');
    await evidence.save('global-ttl.json', results);
    const { dns } = await openGlobal(page, { A: results });
    await globalLookup(dns, domain, 'A');
    const file = await captureDownload(page, () => dns.globalPanel.getByRole('button', { name: 'Download HTML' }).click());
    const report = await readHtmlReport(page, file.text);
    const claimed = report.sections.flatMap(section => {
      const ttl = section.headers.indexOf('TTL');
      return ttl < 0 ? [] : section.rows.map(row => `${section.heading}: ${row[0]} → TTL "${row[ttl]}"`).filter(line => /TTL "\d/.test(line));
    });
    expect.soft(claimed.slice(0, 5), `regional answers carry no TTL (see the API answer), yet the report of "${domain}" states a TTL for ${claimed.length} records; the shared view of a global snapshot does the same`).toEqual([]);
  });

  test('going back to Standard Query after sharing a global snapshot shows an empty result area', async ({ page, rng, evidence }) => {
    const domain = randomDomain(rng);
    const results = randomGlobalResults(rng, 'A', domain, 'all-ok');
    await evidence.save('global-then-standard.json', results);
    const { dns } = await openGlobal(page, { A: results });
    await globalLookup(dns, domain, 'A');
    await dns.shareGlobalButton.click();
    await expect(dns.share.heading).toBeVisible();
    await dns.share.closeButton.click();
    await expect(dns.share.heading).toHaveCount(0);

    await dns.standardMode.click();
    await expect(dns.resolver).toBeVisible();
    await expect.soft(dns.globalPanel, 'the global table is gone in Standard mode').toHaveCount(0);
    await expect.soft(dns.sectionCards, `no Standard lookup was run, yet Standard mode shows result sections (the regional snapshot of "${domain}")`).toHaveCount(0, { timeout: 3_000 });
    await expect.soft(dns.checkedAt, 'no "Checked At" without a Standard lookup').toHaveCount(0, { timeout: 3_000 });
  });

  test('switching between the modes never carries a result over', async ({ page, rng, evidence, baseURL }) => {
    const lookup = randomLookup(rng, { types: ['A', 'NS'], kind: 'records', resolver: RESOLVERS[1].value });
    const results = randomGlobalResults(rng, 'A', lookup.domain, 'all-ok');
    await serveLookups(page, lookup);
    await mockApi(page, '**/api/dns/global-capability', { available: true });
    await mockApi(page, '**/api/dns/global', { domain: lookup.domain, type: 'A', results }, { method: 'POST' });
    const dns = new DnsPage(page);
    await dns.open();
    await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);

    await dns.globalMode.click();
    await expect.soft(dns.sectionCards, 'the Standard result is not shown in Global mode').toHaveCount(0);
    await expect.soft(dns.checkedAt).toHaveCount(0);
    await globalLookup(dns, lookup.domain, 'A');
    expectGlobalTable(await dns.globalRows(), results, 'global lookup after a standard one');

    await dns.standardMode.click();
    await expect.soft(dns.globalPanel, 'the Global table is not shown in Standard mode').toHaveCount(0);
    await expect.soft(dns.sectionCards, 'the earlier Standard result does not come back').toHaveCount(0);
  });
});

test.describe('DNS Lookup, Global Propagation — layout', () => {
  for (const [name, viewport] of Object.entries(VIEWPORTS)) {
    test(`has no layout problems at ${name} size (${viewport.width}px): form, regions being asked, table, all regions failed`, async ({ page, rng, evidence }) => {
      await page.setViewportSize(viewport);
      const domain = randomDomain(rng);
      const answers = { TXT: randomGlobalResults(rng, 'TXT', domain, 'some-failed'), SOA: randomGlobalResults(rng, 'SOA', domain, 'all-failed') };
      await evidence.save('global-layout.json', answers);
      const held = gate();
      await mockApi(page, '**/api/dns/global-capability', { available: true });
      await page.route('**/api/dns/global', async route => {
        const body = route.request().postDataJSON() as { type: 'TXT' | 'SOA' };
        if (body.type === 'TXT') await held.promise;
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ domain, type: body.type, results: answers[body.type] }) }).catch(() => undefined);
      });
      const dns = new DnsPage(page);
      await dns.open();
      await dns.globalMode.click();
      await expect(dns.globalMode).toHaveAttribute('aria-pressed', 'true');
      await page.mouse.move(0, 0);
      await expectNoUiGlitches(page, `${ROUTE} global form @${name}`);

      await dns.typeBox('TXT').check();
      await dns.domain.fill(domain);
      await dns.domain.press('Enter');
      await expect(dns.lookupButton).toHaveText('Querying...');
      await expectNoUiGlitches(page, `${ROUTE} global lookup in progress @${name}`);
      held.open();
      await expect(dns.globalPanel).toBeVisible();
      await expectNoUiGlitches(page, `${ROUTE} global table @${name}`);

      await dns.typeBox('SOA').check();
      await dns.domain.press('Enter');
      await expect(dns.alert).toHaveText('All regional queries failed. Individual errors are shown below.');
      await expectNoUiGlitches(page, `${ROUTE} global, all regions failed @${name}`);
    });
  }
});
