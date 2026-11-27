import { test, expect, type Page } from '../_support/fixtures';
import { openTool } from '../_support/navigation';
import { captureApi, failApi, mockApi, type LiveExchange } from '../_support/io';
import { expectResults } from './checks';
import { ABUSE_NOT_CONFIGURED, generateAbuse, generateBatch, generateGeo, generateIpInfo, generateScenario } from './generator';
import {
  RISK_LABELS, expectedRows, isSpecialPurpose,
  type AbuseResponse, type BatchEntry, type IpInfoRecord,
} from './oracle';
import {
  ABUSE_URL, HEADING, IPINFO_URL, ROUTE, abuseNotice, emptyState, errorBanner, lookup, lookupButton, mockSources,
  readSummary, readTable, resultsPanel, rowToggle, serveGeo, submit,
} from './page';

/**
 * /abuse — what the page does when a data source is missing, fails or
 * answers only in part. Inventory and layer map: see abuse.spec.ts.
 */

/** Text of every banner above the results (red error and grey notice). */
async function bannerText(page: Page): Promise<string> {
  return [...await errorBanner(page).allInnerTexts(), ...await abuseNotice(page).allInnerTexts()].join(' | ');
}

/** Words by which a banner can tell the user that something went wrong. */
const SAYS_FAILURE = /fail|unavailable|error|could not|couldn't|unable|try again|not available|problem|limit|maximum|too many/i;

/** Runs a lookup against the real backend and returns both real answers. */
async function liveLookup(page: Page, text: string): Promise<{ ipinfo: LiveExchange<{ results?: IpInfoRecord[]; error?: string }>; abuse: LiveExchange<AbuseResponse> }> {
  let abuse: LiveExchange<AbuseResponse> | undefined;
  const ipinfo = await captureApi<{ results?: IpInfoRecord[]; error?: string }>(page, '/api/ipinfo', async () => {
    abuse = await captureApi<AbuseResponse>(page, '/api/abuse', () => submit(page, text));
  });
  await expect(resultsPanel(page).or(errorBanner(page)).first()).toBeVisible();
  await expect(lookupButton(page)).toBeEnabled();
  return { ipinfo, abuse: abuse as LiveExchange<AbuseResponse> };
}

/** Private and reserved IPv4 addresses: the backend classifies them itself, without any third party. */
const LOCAL_ONLY_ADDRESSES = [
  '10.20.30.40', '172.16.0.1', '172.31.255.254', '192.168.1.1', '127.0.0.1', '169.254.10.20', '100.64.0.1',
  '100.127.255.254', '192.0.2.5', '198.51.100.7', '203.0.113.9', '198.18.0.1', '224.0.0.1', '240.0.0.1',
];

test.describe('IP Info lookup — AbuseIPDB not configured (real backend)', () => {
  test('the page says AbuseIPDB is not in use, shows no score for any address, and equals the real answers', async ({ page, evidence }) => {
    const entries: BatchEntry[] = LOCAL_ONLY_ADDRESSES.map((ip, i) => ({ ip, hits: i % 3 === 0 ? 10 + i : 1 }));
    const text = entries.map(entry => (entry.hits > 1 ? `${entry.ip} ${entry.hits}` : entry.ip)).join('\n');
    await evidence.save('batch.txt', text);
    await openTool(page, ROUTE, HEADING);
    const live = await liveLookup(page, text);
    await evidence.save('real-answers.json', live);
    test.skip(live.abuse.response.api_available === true, 'this backend has an AbuseIPDB key; the "not configured" behaviour cannot be observed');

    expect(live.abuse.status, 'POST /api/abuse answers 200 without a key').toBe(200);
    expect(live.abuse.response, 'the "API not available" answer of the backend').toMatchObject({ api_available: false, abusive: [], non_abusive: [] });
    expect.soft(live.ipinfo.request, 'request sent to /api/ipinfo').toEqual({ ips: entries.map(entry => entry.ip) });
    expect.soft(live.abuse.request, 'request sent to /api/abuse').toEqual({ ips: entries });

    for (const record of live.ipinfo.response.results ?? []) {
      expect.soft(isSpecialPurpose(record.ip), `${record.ip} is a special-purpose address by the IANA registry (test data check)`).toBe(true);
      expect.soft(record.is_private, `/api/ipinfo must classify ${record.ip} as private/reserved`).toBe(true);
      expect.soft(record.risk_level, `/api/ipinfo risk level for ${record.ip}`).toBe('safe');
    }

    await expect(abuseNotice(page), 'a notice explains that AbuseIPDB reputation is not in use').toContainText(/AbuseIPDB/);
    await expect(errorBanner(page), 'a missing AbuseIPDB key is not an error').toHaveCount(0);
    const rows = expectedRows(entries, { ipinfo: live.ipinfo.response.results, abuse: live.abuse.response, geo: {} });
    const shown = await expectResults(page, rows, 'real backend without AbuseIPDB key');
    for (const row of shown.table) {
      expect.soft(row.score, `abuse score for ${row.ip}: nothing was checked, so no number may be shown`).toBe('N/A');
      expect.soft(row.badge, `risk badge for ${row.ip} (private/reserved)`).toBe(RISK_LABELS.safe);
      expect.soft(row.country, `country for ${row.ip} (private/reserved)`).toBe('Private Network');
    }
  });

  test('details of an address that AbuseIPDB never checked do not claim "0 reports", "never reported" or "not TOR"', async ({ page }) => {
    await openTool(page, ROUTE, HEADING);
    const live = await liveLookup(page, '192.168.50.1\n10.9.8.7');
    test.skip(live.abuse.response.api_available === true, 'this backend has an AbuseIPDB key');
    await rowToggle(page, 0).click();
    const details = (await readTable(page))[0]?.expanded ?? {};
    const ctx = 'AbuseIPDB was not consulted (api_available: false) for 192.168.50.1, so its detail row';
    expect.soft(details['Reports'], `${ctx} must not state a report count`).not.toBe('0');
    expect.soft(details['Last Reported'], `${ctx} must not state "Never"`).not.toBe('Never');
    expect.soft(details['Security'], `${ctx} must not state TOR and whitelist findings`).not.toBe('Not TOR / Not Whitelisted');
  });

  test('a batch above the backend limit of 100 addresses ends in an error, not in a table of defaults', async ({ page, guard, evidence }) => {
    // 101 private addresses: /api/ipinfo refuses the batch with HTTP 400 before contacting anyone.
    const addresses = Array.from({ length: 101 }, (_, i) => `172.16.${Math.floor(i / 50)}.${1 + (i % 50)}`);
    await evidence.save('batch.txt', addresses.join('\n'));
    guard.allow(/status of 400/);
    await serveGeo(page, {});
    await openTool(page, ROUTE, HEADING);
    const live = await liveLookup(page, addresses.join('\n'));
    expect(live.ipinfo.status, 'real /api/ipinfo refuses 101 addresses').toBe(400);
    expect(live.ipinfo.response.error, 'refusal text of the backend').toBe('Maximum 100 IPs per request.');
    const shown = await readTable(page);
    const badges = [...new Set(shown.map(row => row.badge))];
    expect.soft(await bannerText(page), `the backend refused the batch ("${live.ipinfo.response.error}"); the page must tell the user`).toMatch(SAYS_FAILURE);
    expect.soft(shown.length, `no result rows may be shown for a refused batch; the page shows ${shown.length} rows with badges ${JSON.stringify(badges)} for private addresses it never got an answer for`).toBe(0);
  });
});

test.describe('IP Info lookup — service failures', () => {
  for (const status of [400, 429, 500, 503]) {
    test(`HTTP ${status} from both services shows an error, leaves no spinner, and the next lookup works`, async ({ page, rng, guard }) => {
      const scenario = generateScenario(rng, { publicV4: 3, invalid: 0 });
      guard.allow(new RegExp(`status of ${status}|HTTP ${status}`));
      await serveGeo(page, scenario.geo);
      const message = status === 429 ? 'Rate limit exceeded, retry in 1 minute' : `Simulated failure ${status}`;
      await mockApi(page, IPINFO_URL, { error: message }, { status });
      await mockApi(page, ABUSE_URL, { error: message }, { status });
      await openTool(page, ROUTE, HEADING);
      await lookup(page, scenario.batch.text);
      await expect(errorBanner(page), `HTTP ${status} from /api/ipinfo and /api/abuse must end in a visible error`).toBeVisible();
      await expect.soft(errorBanner(page), 'the error has a readable text').toContainText(/\w{4,}/);
      await expect.soft(errorBanner(page), 'the error does not leak a placeholder').not.toContainText(/undefined|\[object/);
      expect.soft(await resultsPanel(page).count(), 'no result table next to the error').toBe(0);
      await expect(lookupButton(page), 'no spinner is left running').toHaveText('🔍 Lookup IP Info');
      await expect(emptyState(page), 'the empty-state invitation is not shown together with an error').toHaveCount(0);

      await page.unroute(IPINFO_URL);
      await page.unroute(ABUSE_URL);
      await mockApi(page, IPINFO_URL, { results: scenario.ipinfo });
      await mockApi(page, ABUSE_URL, scenario.abuse);
      await lookup(page, scenario.batch.text);
      await expect(errorBanner(page), 'the error disappears after a successful lookup').toHaveCount(0);
      await expectResults(page, expectedRows(scenario.batch.entries, scenario), `recovery after HTTP ${status}`);
    });
  }

  test('a network failure of both services shows an error, leaves no spinner, and the next lookup works', async ({ page, rng, guard }) => {
    const scenario = generateScenario(rng, { publicV4: 3, invalid: 0 });
    guard.allow(/request failed: POST .*\/api\/(ipinfo|abuse)|ERR_FAILED/);
    await serveGeo(page, scenario.geo);
    await failApi(page, IPINFO_URL);
    await failApi(page, ABUSE_URL);
    await openTool(page, ROUTE, HEADING);
    await lookup(page, scenario.batch.text);
    await expect(errorBanner(page), 'an unreachable backend must end in a visible error').toBeVisible();
    await expect.soft(errorBanner(page)).toContainText(/\w{4,}/);
    expect.soft(await resultsPanel(page).count(), 'no result table next to the error').toBe(0);
    await expect(lookupButton(page), 'no spinner is left running').toHaveText('🔍 Lookup IP Info');

    await page.unroute(IPINFO_URL);
    await page.unroute(ABUSE_URL);
    await mockApi(page, IPINFO_URL, { results: scenario.ipinfo });
    await mockApi(page, ABUSE_URL, scenario.abuse);
    await lookup(page, scenario.batch.text);
    await expectResults(page, expectedRows(scenario.batch.entries, scenario), 'recovery after a network failure');
  });

  test('when only the IP-info service fails the page says so instead of showing "No PTR record" and "Low" for every address', async ({ page, rng, guard, evidence }) => {
    const batch = generateBatch(rng, { publicV4: 4, privateV4: 0, publicV6: 0, invalid: 0 });
    await evidence.save('batch.txt', batch.text);
    guard.allow(/status of (400|500)|HTTP 500|request failed: POST .*\/api\/ipinfo|ERR_FAILED/);
    await serveGeo(page, {});
    await mockApi(page, ABUSE_URL, ABUSE_NOT_CONFIGURED);
    await openTool(page, ROUTE, HEADING);
    const failures: [string, () => Promise<unknown>][] = [
      ['HTTP 500', () => mockApi(page, IPINFO_URL, { error: 'Internal Server Error' }, { status: 500 })],
      ['HTTP 400 "Maximum 100 IPs per request."', () => mockApi(page, IPINFO_URL, { error: 'Maximum 100 IPs per request.' }, { status: 400 })],
      ['a network failure', () => failApi(page, IPINFO_URL)],
    ];
    for (const [what, arrange] of failures) {
      await page.unroute(IPINFO_URL);
      await arrange();
      await lookup(page, batch.text);
      const shown = await readTable(page);
      expect.soft(await bannerText(page), `/api/ipinfo answered with ${what}: reverse DNS and risk are unknown and the page must say that the lookup failed`).toMatch(SAYS_FAILURE);
      expect.soft(shown.map(row => `${row.ip}: ${row.ptr} / ${row.badge}`), `after ${what} from /api/ipinfo no address may be shown as "No PTR record" with a "Low" badge: nothing is known about it`)
        .toEqual(shown.map(row => `${row.ip}: ${row.ptr === 'No PTR record' ? '(not stated)' : row.ptr} / ${row.badge === 'Low' ? RISK_LABELS.unknown : row.badge}`));
    }
  });

  test('when only the AbuseIPDB lookup fails the page says so and shows no score', async ({ page, rng, guard, evidence }) => {
    const batch = generateBatch(rng, { publicV4: 4, privateV4: 1, publicV6: 0, invalid: 0 });
    await evidence.save('batch.txt', batch.text);
    const ipinfo = generateIpInfo(rng, batch.entries);
    guard.allow(/status of (429|500)|HTTP 500|request failed: POST .*\/api\/abuse|ERR_FAILED/);
    await serveGeo(page, {});
    await mockApi(page, IPINFO_URL, { results: ipinfo });
    await openTool(page, ROUTE, HEADING);
    const failures: [string, () => Promise<unknown>][] = [
      ['HTTP 500', () => mockApi(page, ABUSE_URL, { error: 'Internal Server Error' }, { status: 500 })],
      ['HTTP 429 (rate limit)', () => mockApi(page, ABUSE_URL, { error: 'Rate limit exceeded, retry in 1 minute' }, { status: 429 })],
      ['a network failure', () => failApi(page, ABUSE_URL)],
    ];
    for (const [what, arrange] of failures) {
      await page.unroute(ABUSE_URL);
      await arrange();
      await lookup(page, batch.text);
      // The IP-info half of every row is still right, and no score is invented.
      await expectResults(page, expectedRows(batch.entries, { ipinfo, abuse: null, geo: {} }), `/api/abuse failed with ${what}`);
      expect.soft(await bannerText(page), `/api/abuse answered with ${what}: the page must say that the reputation lookup failed, not that the key "is optional"`).toMatch(SAYS_FAILURE);
    }
  });

  test('an address missing from the IP-info answer is shown as unknown while the others are right', async ({ page, rng, evidence }) => {
    const batch = generateBatch(rng, { publicV4: 6, privateV4: 0, publicV6: 0, invalid: 0 });
    const all = generateIpInfo(rng, batch.entries);
    const missing = rng.sample(batch.entries, 2).map(entry => entry.ip);
    const ipinfo = all.filter(record => !missing.includes(record.ip));
    const sources = { ipinfo, abuse: generateAbuse(rng, batch.entries, { scores: batch.entries.map(() => 0) }), geo: generateGeo(rng, batch.entries) };
    await evidence.save('sources.json', { batch: batch.text, missing, ...sources });
    await mockSources(page, sources);
    await openTool(page, ROUTE, HEADING);
    await lookup(page, batch.text);
    const shown = await readTable(page);
    const want = expectedRows(batch.entries, sources);
    want.forEach((row, i) => {
      const what = missing.includes(row.ip) ? `${row.ip}, for which /api/ipinfo returned nothing` : `${row.ip}, answered by /api/ipinfo as "${row.risk}"`;
      expect.soft(shown[i]?.badge, `risk badge for ${what}`).toBe(RISK_LABELS[row.risk]);
    });
    expect.soft((await readSummary(page)).cards['Total IPs Analyzed'], 'every submitted address keeps a row').toBe(String(batch.entries.length));
  });
});
