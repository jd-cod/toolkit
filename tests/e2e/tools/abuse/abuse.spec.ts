import { test, expect } from '../_support/fixtures';
import { openTool, expectToolLinkedFromHome } from '../_support/navigation';
import { expectNoUiGlitches, expectControlsUsable, VIEWPORTS } from '../_support/ui-audit';
import { mockApi, readClipboard } from '../_support/io';
import { expectResults } from './checks';
import {
  ABUSE_NOT_CONFIGURED, NOT_AN_ADDRESS, compressIpv6, generateAbuse, generateBatch, generateGeo, generateIpInfo,
  generateScenario, privateIpv4, publicIpv4, publicIpv6Full,
} from './generator';
import { expectedRows, parseBatch, uniqueEntries, type AbuseResponse, type BatchEntry, type IpInfoRecord } from './oracle';
import {
  ABUSE_URL, HEADING, IPINFO_URL, ROUTE, abuseNotice, cardToggle, desktopTable, emptyState, errorBanner, filterButton,
  lookup, lookupButton, mobileList, mockSources, readSummary, readTable, resultsPanel, rowToggle, serveGeo, submit, textarea,
} from './page';

/**
 * IP Info & Security Risk Lookup (/abuse) — server-backed.
 *
 * INVENTORY (the coverage contract; each entry maps to at least one test)
 *
 * Inputs
 *   - Batch textarea: one address per line, optional request count after a space, tab, comma or pipe;
 *     blank lines; lines that are not addresses; IPv4, IPv6 (full and zero-compressed), private and
 *     reserved addresses; duplicates; CRLF line ends; the stated limit of 50 addresses.
 *   - No URL parameters, no file upload, no sample button, no Enter-to-submit (Enter adds a line).
 * Controls
 *   - "Lookup IP Info" button (label and disabled state while a lookup runs).
 *   - Filter buttons All / rDNS / Risk Flags / Abusive (the last only when an address has a score above 0).
 *   - Per row: "Info"/"Hide" detail toggle; link to abuseipdb.com/check/<ip> (new tab).
 *   - "Export CSV", "Copy IP Summary".
 *   - There is no sorting control, no pagination, no JSON export, no share link and no request-count column.
 * Displayed values
 *   - Notice when AbuseIPDB gave no usable answer.
 *   - Cards: Total IPs Analyzed, Reverse DNS Found, Risk Flags / Elevated, Abuse Reports.
 *   - "Results (x of y IPs)" and the count on every filter button.
 *   - Table (wide screens): #, IP + version tag, Reverse DNS (PTR), flag + country + code, AS number + ISP +
 *     usage type, risk badge, abuse score, actions. Detail row: ASN (organisation), Usage, Reports,
 *     Last Reported, Security (TOR / whitelist).
 *   - Cards (results area narrower than 1050px): the same data per address.
 * Outputs
 *   - POST /api/ipinfo { ips: string[] } and POST /api/abuse { ips: [{ ip, hits }] }.
 *   - Clipboard summary, CSV file abuse-ip-report-<date>.csv.
 * States
 *   - Empty, loading, results (AbuseIPDB configured / not configured), filtered (including no match),
 *     detail open, error (bad input, both services down), partial failures.
 *
 * LAYERS: 1 this file; 2 this file; 3 this file ("batch input"); 4 and 5 abuse-results.spec.ts;
 * 6 abuse-results.spec.ts (clipboard, CSV) and this file (request bodies); share links: not applicable,
 * the tool has none; 7 abuse-failures.spec.ts and this file (bad input); 8 this file ("state"); browser
 * back/forward, deep links and remembered settings: not applicable, the tool keeps nothing in the URL or
 * in storage (the reload test proves the clean start).
 * Real backend: abuse-failures.spec.ts (AbuseIPDB not configured, limits) and abuse-live.spec.ts (@live).
 *
 * Oracle: ./oracle.ts (definitions at its top). Contract tests answer the two API calls and the GeoIP
 * reader script from generated data (./generator.ts), so every displayed field has a known source value.
 */

const NO_VALID_INPUT = /No valid IP addresses found/;

test.describe('IP Info lookup — access and layout', () => {
  test('is linked from the home page and the sidebar', async ({ page }) => {
    await expectToolLinkedFromHome(page, ROUTE);
    await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
  });

  test('opens with its controls ready, the documented limit and an empty result area', async ({ page }) => {
    await openTool(page, ROUTE, HEADING);
    await expect(page, 'the page title names the tool').toHaveTitle(/IP .*Lookup/i);
    await expectControlsUsable(page, {
      'batch textarea': '.signal-tool-primary textarea',
      'lookup button': '.signal-tool-primary button.btn-primary',
    });
    await expect(textarea(page), 'the textarea starts empty').toHaveValue('');
    await expect(lookupButton(page)).toHaveText('🔍 Lookup IP Info');
    await expect(page.getByText('Supports batch lookup up to 50 IPv4 or IPv6 addresses.'), 'documented limit').toBeVisible();
    await expect(emptyState(page), 'empty state before the first lookup').toBeVisible();
    await expect(resultsPanel(page), 'no result table before a lookup').toHaveCount(0);
    await expect(errorBanner(page), 'no error before a lookup').toHaveCount(0);
    await expect(page.getByRole('complementary', { name: 'Investigate an address' }), 'guide panel').toBeVisible();
  });

  for (const [name, viewport] of Object.entries(VIEWPORTS)) {
    test(`has no layout problems at ${name} size (${viewport.width}px): empty, loading and error states`, async ({ page, rng, guard }) => {
      await page.setViewportSize(viewport);
      const scenario = generateScenario(rng, { publicV4: 3, publicV6: 1, invalid: 0 });
      await mockSources(page, { ipinfo: scenario.ipinfo, abuse: scenario.abuse, geo: scenario.geo }, { delayMs: 1500 });
      await openTool(page, ROUTE, HEADING);
      await expectNoUiGlitches(page, `${ROUTE} empty state @${name}`);

      await submit(page, 'definitely not an address');
      await expect(errorBanner(page)).toContainText(NO_VALID_INPUT);
      await expectNoUiGlitches(page, `${ROUTE} input error @${name}`);

      await submit(page, scenario.batch.text);
      await expect(lookupButton(page), 'the lookup is held open by a slow answer').toBeDisabled();
      await expectNoUiGlitches(page, `${ROUTE} loading state @${name}`);
      await expect(resultsPanel(page)).toBeVisible();

      await page.unroute(IPINFO_URL);
      await page.unroute(ABUSE_URL);
      guard.allow(/HTTP 500|status of 500/);
      await mockApi(page, IPINFO_URL, { error: 'Internal Server Error' }, { status: 500 });
      await mockApi(page, ABUSE_URL, { error: 'Internal Server Error' }, { status: 500 });
      await lookup(page, scenario.batch.text);
      await expect(errorBanner(page)).toBeVisible();
      await expectNoUiGlitches(page, `${ROUTE} service error @${name}`);
    });

    test(`has no layout problems at ${name} size (${viewport.width}px): results, filter and open details`, async ({ page, rng, evidence }) => {
      await page.setViewportSize(viewport);
      // Long values on purpose: a full-length IPv6 address, a long PTR name and the longest organisation name.
      const scenario = generateScenario(rng, { publicV4: 4, publicV6: 2, privateV4: 1, privateV6: 1, invalid: 1 }, { scores: [100, 0, 30] });
      await evidence.save('batch.txt', scenario.batch.text);
      await evidence.save('sources.json', scenario);
      await mockSources(page, { ipinfo: scenario.ipinfo, abuse: scenario.abuse, geo: scenario.geo });
      await openTool(page, ROUTE, HEADING);
      await lookup(page, scenario.batch.text);
      await expect(resultsPanel(page)).toBeVisible();

      // The results area chooses its own layout from its width: a table when wide, cards when narrow.
      const tableShown = await desktopTable(page).isVisible();
      const cardsShown = await mobileList(page).isVisible();
      expect(tableShown !== cardsShown, `exactly one of table and card list is visible @${name} (table ${tableShown}, cards ${cardsShown})`).toBe(true);
      expect(tableShown, `the table is used at desktop width, cards below (viewport ${viewport.width}px)`).toBe(name === 'desktop');
      await expectNoUiGlitches(page, `${ROUTE} results @${name}`);

      await (tableShown ? rowToggle(page, 0) : cardToggle(page, 0)).click();
      await expectNoUiGlitches(page, `${ROUTE} results with details open @${name}`);

      await filterButton(page, 'abusive').click();
      await expectNoUiGlitches(page, `${ROUTE} "Abusive" filter @${name}`);
    });

    test(`has no layout problems at ${name} size (${viewport.width}px): results without AbuseIPDB`, async ({ page, rng }) => {
      await page.setViewportSize(viewport);
      const batch = generateBatch(rng, { publicV4: 3, publicV6: 1, privateV4: 1, invalid: 0 });
      await mockSources(page, { ipinfo: generateIpInfo(rng, batch.entries), abuse: ABUSE_NOT_CONFIGURED, geo: generateGeo(rng, batch.entries) });
      await openTool(page, ROUTE, HEADING);
      await lookup(page, batch.text);
      await expect(abuseNotice(page)).toBeVisible();
      await expectNoUiGlitches(page, `${ROUTE} results without AbuseIPDB @${name}`);
    });
  }
});

test.describe('IP Info lookup — batch input', () => {
  for (const lineEnding of ['\n', '\r\n'] as const) {
    test(`a mixed batch (${lineEnding === '\n' ? 'LF' : 'CRLF'} line ends) sends exactly its addresses and counts, and drops every other line`, async ({ page, rng, evidence }) => {
      const scenario = generateScenario(rng, { publicV4: 6, privateV4: 2, publicV6: 2, privateV6: 1, invalid: 5, blank: 3, lineEnding });
      await evidence.save('batch.txt', scenario.batch.text);
      await evidence.save('sources.json', scenario);
      const mocks = await mockSources(page, scenario);
      await openTool(page, ROUTE, HEADING);
      await lookup(page, scenario.batch.text);

      // Two independent statements of the expected entries must agree: the generator's record and the oracle's parser.
      const parsed = parseBatch(scenario.batch.text);
      expect(parsed.entries, 'oracle parser and generator ground truth agree on the batch').toEqual(scenario.batch.entries);

      expect(mocks.ipinfoCalls.length, 'one POST /api/ipinfo per lookup').toBe(1);
      expect(mocks.abuseCalls.length, 'one POST /api/abuse per lookup').toBe(1);
      expect.soft(mocks.ipinfoCalls[0].method, 'method of the IP-info request').toBe('POST');
      expect.soft((mocks.ipinfoCalls[0].body as { ips: string[] }).ips, 'addresses sent to /api/ipinfo, in input order').toEqual(parsed.entries.map(entry => entry.ip));
      expect.soft((mocks.abuseCalls[0].body as { ips: BatchEntry[] }).ips, 'addresses and request counts sent to /api/abuse, in input order').toEqual(parsed.entries);

      const shown = await readTable(page);
      for (const line of scenario.batch.rejectedLines) {
        expect.soft(shown.some(row => row.ip !== '' && line.includes(row.ip)), `"${line}" is not an address and must not become a result row`).toBe(false);
      }
      await expectResults(page, expectedRows(parsed.entries, scenario), `batch of ${parsed.entries.length} addresses`);
    });
  }

  test('every separator between address and request count gives the same request', async ({ page, rng, evidence }) => {
    const separators: [string, string][] = [['space', ' '], ['tab', '\t'], ['comma', ','], ['comma and space', ', '], ['pipe', '|'], ['spaced pipe', ' | '], ['several spaces', '    ']];
    const entries = separators.map(() => ({ ip: publicIpv4(rng), hits: rng.int(2, 99999) }));
    const text = entries.map((entry, i) => `${entry.ip}${separators[i][1]}${entry.hits}`).join('\n');
    await evidence.save('batch.txt', text);
    const mocks = await mockSources(page, { ipinfo: generateIpInfo(rng, entries), abuse: ABUSE_NOT_CONFIGURED, geo: {} });
    await openTool(page, ROUTE, HEADING);
    await lookup(page, text);
    const sent = (mocks.abuseCalls[0]?.body as { ips: BatchEntry[] } | undefined)?.ips ?? [];
    entries.forEach((entry, i) => {
      expect.soft(sent[i], `line "${entry.ip}<${separators[i][0]}>${entry.hits}" as sent to /api/abuse`).toEqual(entry);
    });
    expect.soft(sent.length, 'number of addresses sent').toBe(entries.length);
  });

  test('typing line by line and pasting from the clipboard reach the same result as filling the field', async ({ page, rng }) => {
    const entries = [{ ip: publicIpv4(rng), hits: rng.int(2, 500) }, { ip: privateIpv4(rng), hits: 1 }, { ip: publicIpv6Full(rng), hits: rng.int(2, 500) }];
    const text = entries.map(entry => (entry.hits > 1 ? `${entry.ip} ${entry.hits}` : entry.ip)).join('\n');
    const sources = { ipinfo: generateIpInfo(rng, entries), abuse: generateAbuse(rng, entries), geo: generateGeo(rng, entries) };
    const mocks = await mockSources(page, sources);
    const want = expectedRows(entries, sources);
    await openTool(page, ROUTE, HEADING);

    // Typed: Enter starts a new line, it does not submit.
    await textarea(page).click();
    await page.keyboard.type(text);
    await expect(textarea(page), 'Enter adds a line break').toHaveValue(text);
    expect(mocks.ipinfoCalls.length, 'typing (including Enter) must not start a lookup').toBe(0);
    await lookupButton(page).click();
    await expect(resultsPanel(page)).toBeVisible();
    await expectResults(page, want, 'typed batch');

    // Pasted.
    await textarea(page).fill('');
    await page.evaluate(value => navigator.clipboard.writeText(value), text);
    await textarea(page).focus();
    await page.keyboard.press('ControlOrMeta+V');
    await expect(textarea(page), 'pasted text arrives unchanged').toHaveValue(text);
    expect(await readClipboard(page)).toBe(text);
    await lookupButton(page).click();
    await expect(resultsPanel(page)).toBeVisible();
    await expectResults(page, want, 'pasted batch');
    expect.soft(mocks.abuseCalls.map(call => (call.body as { ips: BatchEntry[] }).ips), 'both input paths send the same request').toEqual([entries, entries]);
  });

  test('a batch without any address is refused with a message and sends nothing', async ({ page }) => {
    const ipinfoCalls = await mockApi(page, IPINFO_URL, { results: [] });
    const abuseCalls = await mockApi(page, ABUSE_URL, ABUSE_NOT_CONFIGURED);
    await openTool(page, ROUTE, HEADING);
    for (const { line, why } of NOT_AN_ADDRESS) {
      await submit(page, line);
      await expect.soft(errorBanner(page), `"${line}" (${why}) is not an address: an error must be shown`).toContainText(NO_VALID_INPUT);
      await expect.soft(resultsPanel(page), `"${line}" (${why}): no result may be shown`).toHaveCount(0);
    }
    await submit(page, NOT_AN_ADDRESS.map(bad => bad.line).join('\n'));
    await expect(errorBanner(page), 'all the non-address lines together').toContainText(NO_VALID_INPUT);
    expect(ipinfoCalls.length + abuseCalls.length, 'no request may be sent for a batch without addresses').toBe(0);
  });

  test('an empty or blank field does nothing: no request, no error, the empty state stays', async ({ page }) => {
    const ipinfoCalls = await mockApi(page, IPINFO_URL, { results: [] });
    await openTool(page, ROUTE, HEADING);
    for (const blank of ['', '   ', '\n\n\t\n']) {
      await submit(page, blank);
      await expect(emptyState(page), `blank input ${JSON.stringify(blank)} keeps the empty state`).toBeVisible();
      await expect(errorBanner(page)).toHaveCount(0);
    }
    expect(ipinfoCalls.length, 'no lookup for blank input').toBe(0);
  });

  test('zero-compressed IPv6 addresses (RFC 4291 "::" form) are accepted and looked up', async ({ page, rng, evidence }) => {
    const full = publicIpv6Full(rng).split(':').map((group, i) => (i >= 3 && i <= 5 ? '0' : group)).join(':');
    const addresses = ['2001:4860:4860::8888', '2606:4700:4700::1111', '::1', 'fe80::1', '2001:db8::', '::ffff:192.0.2.1', compressIpv6(full)];
    await evidence.save('batch.txt', addresses.join('\n'));
    const entries = addresses.map(ip => ({ ip, hits: 1 }));
    const mocks = await mockSources(page, { ipinfo: generateIpInfo(rng, entries), abuse: ABUSE_NOT_CONFIGURED, geo: {} });
    await openTool(page, ROUTE, HEADING);
    for (const ip of addresses) {
      await lookup(page, ip);
      expect.soft(await errorBanner(page).count(), `"${ip}" is a valid IPv6 address (the page says it supports IPv6) and must not be refused; the page says "${(await errorBanner(page).allInnerTexts()).join(' ')}"`).toBe(0);
    }
    await lookup(page, addresses.join('\n'));
    expect.soft(await resultsPanel(page).count(), 'a batch of compressed IPv6 addresses gives a result table').toBe(1);
    const sent = mocks.ipinfoCalls.at(-1)?.body as { ips: string[] } | undefined;
    expect.soft(sent?.ips ?? [], 'compressed IPv6 addresses sent to /api/ipinfo').toEqual(addresses);
  });

  test('IPv4-looking text with an octet above 255 is not treated as an address', async ({ page, rng }) => {
    const impossible = ['256.1.1.1', '999.999.999.999', '192.168.1.256', '1.2.3.300', '8.8.8.800'];
    const good = publicIpv4(rng);
    const mocks = await mockSources(page, {
      ipinfo: [
        ...generateIpInfo(rng, [{ ip: good, hits: 1 }]),
        // What the real backend answers for such text (backend/src/routes/ipinfo.js).
        ...impossible.map(ip => ({ ip, is_valid: false, is_private: false, ip_version: '', reverse_dns: '', risk_level: 'unknown' as const, risk_reasons: ['Invalid IP address format'] })),
      ],
      abuse: ABUSE_NOT_CONFIGURED, geo: {},
    });
    await openTool(page, ROUTE, HEADING);
    for (const text of impossible) {
      await lookup(page, text);
      expect.soft((await errorBanner(page).allInnerTexts()).join(' '), `"${text}" has an octet above 255: it is not an IP address and must be refused`).toMatch(NO_VALID_INPUT);
      expect.soft((await readTable(page).catch(() => [])).map(row => `${row.ip} → ${row.badge}`), `"${text}" must not produce a result row`).toEqual([]);
    }
    await lookup(page, [good, ...impossible].join('\n'));
    const sent = (mocks.ipinfoCalls.at(-1)?.body as { ips: string[] } | undefined)?.ips ?? [];
    expect.soft(sent, 'only the real address may be sent to /api/ipinfo').toEqual([good]);
    const shown = await readTable(page);
    expect.soft(shown.map(row => `${row.ip} → ${row.badge}`), 'only the real address may get a row and a risk badge').toEqual([`${good} → ${shown[0]?.badge}`]);
  });

  test('an address listed more than once is analysed once', async ({ page, rng, evidence }) => {
    const a = publicIpv4(rng), b = publicIpv4(rng), c = publicIpv6Full(rng);
    const text = [a, `${b} 40`, a, c, `${b} 2`, a].join('\n');
    await evidence.save('batch.txt', text);
    const unique = uniqueEntries(parseBatch(text).entries);
    const sources = { ipinfo: generateIpInfo(rng, unique, { ptrShare: 1 }), abuse: generateAbuse(rng, unique, { scores: [80, 80, 80] }), geo: {} };
    const mocks = await mockSources(page, sources);
    await openTool(page, ROUTE, HEADING);
    await lookup(page, text);
    const summary = await readSummary(page);
    const shown = await readTable(page);
    expect.soft(summary.cards['Total IPs Analyzed'], `"Total IPs Analyzed" for 3 distinct addresses on 6 lines`).toBe('3');
    expect.soft(summary.cards['Abuse Reports'], '"Abuse Reports" counts each reported address once').toBe('3');
    expect.soft(shown.map(row => row.ip), 'one row per distinct address, in order of first appearance').toEqual(unique.map(entry => entry.ip));
    expect.soft((mocks.ipinfoCalls[0].body as { ips: string[] }).ips, 'each address is sent to /api/ipinfo once').toEqual(unique.map(entry => entry.ip));
  });

  test('a request count is always a whole number of at least 1', async ({ page, rng }) => {
    const cases: [string, number][] = [['abc', 1], ['0', 1], ['-5', 1], ['-1', 1], ['1e3', 1], ['# note', 1], ['x12', 1]];
    const entries = cases.map(() => publicIpv4(rng));
    const text = entries.map((ip, i) => `${ip} ${cases[i][0]}`).join('\n');
    const mocks = await mockSources(page, { ipinfo: generateIpInfo(rng, entries.map(ip => ({ ip, hits: 1 }))), abuse: ABUSE_NOT_CONFIGURED, geo: {} });
    await openTool(page, ROUTE, HEADING);
    await lookup(page, text);
    const sent = (mocks.abuseCalls[0]?.body as { ips: BatchEntry[] } | undefined)?.ips ?? [];
    expect.soft(sent.map(entry => entry.ip), 'every address is still looked up').toEqual(entries);
    cases.forEach(([typed, want], i) => {
      expect.soft(sent[i]?.hits, `request count sent for "${entries[i]} ${typed}" (not a count of at least 1, so the count is ${want})`).toBe(want);
    });
  });

  test('more than 50 addresses are either all analysed or refused with a message, never cut silently', async ({ page, rng, evidence }) => {
    const batch = generateBatch(rng, { publicV4: 45, privateV4: 4, publicV6: 2, invalid: 0, blank: 0 });
    expect(batch.entries.length).toBe(51);
    await evidence.save('batch.txt', batch.text);
    const sources = { ipinfo: generateIpInfo(rng, batch.entries), abuse: ABUSE_NOT_CONFIGURED as AbuseResponse, geo: generateGeo(rng, batch.entries) };
    await mockSources(page, sources);
    await openTool(page, ROUTE, HEADING);
    await lookup(page, batch.text);
    if (await errorBanner(page).count()) {
      await expect(errorBanner(page), 'a refusal must name the limit of 50').toContainText('50');
      await expect(resultsPanel(page)).toHaveCount(0);
    } else {
      await expectResults(page, expectedRows(batch.entries, sources), '51 addresses');
    }
  });

  test('the AbuseIPDB request asks for every address of a batch up to the documented 50', async ({ page, rng }) => {
    // backend/src/routes/abuse.js checks only `body.max || 20` addresses. A batch of 21–50 addresses
    // therefore needs `max` in the request, or the addresses after the 20th come back without a score.
    const batch = generateBatch(rng, { publicV4: 46, privateV4: 2, publicV6: 2, invalid: 0, blank: 0 });
    const mocks = await mockSources(page, { ipinfo: generateIpInfo(rng, batch.entries), abuse: generateAbuse(rng, batch.entries.slice(0, 20)), geo: {} });
    await openTool(page, ROUTE, HEADING);
    await lookup(page, batch.text);
    const body = mocks.abuseCalls[0].body as { ips: BatchEntry[]; max?: number };
    expect.soft(body.ips.length, 'addresses sent to /api/abuse').toBe(50);
    expect(body.max ?? 20, `POST /api/abuse carries max=${body.max}; the backend then checks only the first ${body.max ?? 20} of ${body.ips.length} addresses and the rest show "N/A" with no explanation`).toBeGreaterThanOrEqual(50);
  });
});

test.describe('IP Info lookup — state', () => {
  test('while a lookup runs the button is disabled, old results are gone, and the answer belongs to the submitted batch', async ({ page, rng, evidence }) => {
    const first = generateScenario(rng.fork('first'), { publicV4: 3, invalid: 0 });
    const second = generateScenario(rng.fork('second'), { publicV4: 4, publicV6: 1, invalid: 0 });
    await evidence.save('first.txt', first.batch.text);
    await evidence.save('second.txt', second.batch.text);
    const current: { ipinfo: IpInfoRecord[]; abuse: AbuseResponse; delay: number } = { ipinfo: first.ipinfo, abuse: first.abuse, delay: 0 };
    await serveGeo(page, { ...first.geo, ...second.geo });
    const hold = () => new Promise(resolve => setTimeout(resolve, current.delay));
    await page.route(IPINFO_URL, async route => { await hold(); await route.fulfill({ json: { results: current.ipinfo } }); });
    await page.route(ABUSE_URL, async route => { await hold(); await route.fulfill({ json: current.abuse }); });

    await openTool(page, ROUTE, HEADING);
    await lookup(page, first.batch.text);
    await expectResults(page, expectedRows(first.batch.entries, { ...first, geo: { ...first.geo, ...second.geo } }), 'first lookup');

    Object.assign(current, { ipinfo: second.ipinfo, abuse: second.abuse, delay: 1500 });
    await submit(page, second.batch.text);
    await expect(lookupButton(page), 'the button is disabled while the lookup runs, so a second lookup cannot overtake it').toBeDisabled();
    await expect(lookupButton(page), 'the button says the lookup is running').toHaveText('⏳ Resolving IP Info...');
    await expect(resultsPanel(page), 'the previous results are removed while the new lookup runs').toHaveCount(0);
    await expect(emptyState(page), 'the empty-state invitation is not shown during a lookup').toHaveCount(0);
    // Editing the field mid-flight must not change which batch the answer belongs to.
    await textarea(page).fill('198.51.100.200');
    await expect(resultsPanel(page)).toBeVisible();
    await expect(lookupButton(page), 'no spinner is left running').toHaveText('🔍 Lookup IP Info');
    await expect(lookupButton(page)).toBeEnabled();
    const want = expectedRows(second.batch.entries, { ...second, geo: { ...first.geo, ...second.geo } });
    const shown = await expectResults(page, want, 'second lookup');
    for (const { ip } of first.batch.entries) {
      expect.soft(shown.table.some(row => row.ip === ip), `${ip} belongs to the first batch and must be gone after the second lookup`).toBe(false);
    }
  });

  test('a new lookup shows all of its rows: the filter chosen for the previous result does not hide them', async ({ page, rng }) => {
    const first = generateBatch(rng.fork('first'), { publicV4: 4, invalid: 0 });
    const second = generateBatch(rng.fork('second'), { publicV4: 3, invalid: 0 });
    const current = {
      ipinfo: generateIpInfo(rng, first.entries),
      abuse: generateAbuse(rng, first.entries, { scores: [90, 60, 0, 10, 0, 0] }),
    };
    await serveGeo(page, {});
    await page.route(IPINFO_URL, route => route.fulfill({ json: { results: current.ipinfo } }));
    await page.route(ABUSE_URL, route => route.fulfill({ json: current.abuse }));
    await openTool(page, ROUTE, HEADING);
    await lookup(page, first.text);
    await filterButton(page, 'abusive').click();
    await expect.poll(async () => (await readSummary(page)).selected, 'the Abusive filter is selected').toEqual(['Abusive']);

    current.ipinfo = generateIpInfo(rng, second.entries);
    current.abuse = generateAbuse(rng, second.entries, { scores: second.entries.map(() => 0) });
    await lookup(page, second.text);
    const summary = await readSummary(page);
    const shown = await readTable(page);
    expect.soft(summary.selected.length, `exactly one filter is marked as selected after the new lookup (marked: ${JSON.stringify(summary.selected)}; buttons: ${JSON.stringify(summary.filters)})`).toBe(1);
    expect.soft(shown.map(row => row.ip), `rows shown for the new batch of ${second.entries.length} addresses, none of which is abusive (header says ${summary.shown} of ${summary.of})`).toEqual(second.entries.map(entry => entry.ip));
  });

  test('a batch without addresses after a successful lookup leaves no old results under the error', async ({ page, rng }) => {
    const scenario = generateScenario(rng, { publicV4: 3, invalid: 0 });
    await mockSources(page, scenario);
    await openTool(page, ROUTE, HEADING);
    await lookup(page, scenario.batch.text);
    await expect(resultsPanel(page)).toBeVisible();
    await submit(page, 'nothing to look up here');
    await expect(errorBanner(page)).toContainText(NO_VALID_INPUT);
    expect(await resultsPanel(page).count(), `the results of the previous batch (${scenario.batch.entries.map(entry => entry.ip).join(', ')}) must not stay on screen next to "No valid IP addresses found"`).toBe(0);
  });

  test('a valid batch after an input error clears the error and shows only the new results', async ({ page, rng }) => {
    const scenario = generateScenario(rng, { publicV4: 3, privateV4: 1, invalid: 0 });
    await mockSources(page, scenario);
    await openTool(page, ROUTE, HEADING);
    await submit(page, 'oops');
    await expect(errorBanner(page)).toContainText(NO_VALID_INPUT);
    await lookup(page, scenario.batch.text);
    await expect(errorBanner(page), 'the error disappears with the next valid lookup').toHaveCount(0);
    await expectResults(page, expectedRows(scenario.batch.entries, scenario), 'lookup after an input error');
  });

  test('reloading the page returns to a clean tool: nothing is remembered', async ({ page, rng }) => {
    const scenario = generateScenario(rng, { publicV4: 2, invalid: 0 });
    await mockSources(page, scenario);
    await openTool(page, ROUTE, HEADING);
    await lookup(page, scenario.batch.text);
    await expect(resultsPanel(page)).toBeVisible();
    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(emptyState(page), 'empty state after reload').toBeVisible();
    await expect(textarea(page), 'the field is empty after reload').toHaveValue('');
    await expect(resultsPanel(page)).toHaveCount(0);
  });
});
