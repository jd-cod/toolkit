import { test, expect } from '../_support/fixtures';
import { failApi } from '../_support/io';
import { describeLookup, expectRequestsMatch, expectViewMatches, runAndCheck } from './checks';
import { randomDomain, randomLookup } from './generator';
import { DEFAULT_TYPES, GeoOracle, OFFERED_TYPES, RESOLVERS, expectedView, type Lookup, type Reply } from './oracle';
import { DnsPage, gate, routeDns, serveLookups } from './page';

/**
 * DNS Lookup (/dns) — layer 7 (bad answers and failures) and layer 8 (state).
 * Inventory and definitions: see dns.spec.ts and oracle.ts.
 */

/** A lookup whose every type gets the same failing reply. */
function failingLookup(rng: Parameters<typeof randomLookup>[0], reply: Reply): Lookup {
  const lookup = randomLookup(rng, { types: rng.sample(OFFERED_TYPES, rng.int(2, 4)), kind: 'records' });
  for (const type of lookup.types) lookup.replies[type] = reply;
  return lookup;
}

const FAILURES: { name: string; reply: Reply; allow: RegExp }[] = [
  { name: 'HTTP 400 with an error message', reply: { kind: 'http', status: 400, body: { error: 'Invalid domain name.', records: [] } }, allow: /status of 400/ },
  { name: 'HTTP 429 (rate limit)', reply: { kind: 'http', status: 429, body: { statusCode: 429, error: 'Too Many Requests', message: 'Rate limit exceeded, retry in 1 minute' } }, allow: /status of 429/ },
  { name: 'HTTP 500 with a JSON error', reply: { kind: 'http', status: 500, body: { statusCode: 500, error: 'Internal Server Error', message: 'boom' } }, allow: /status of 500|HTTP 500/ },
  { name: 'HTTP 503 with JSON that has no error field', reply: { kind: 'http', status: 503, body: { message: 'upstream unavailable' } }, allow: /status of 503|HTTP 503/ },
  { name: 'HTTP 502 with an HTML body from a proxy', reply: { kind: 'http', status: 502, body: '<html><body><h1>502 Bad Gateway</h1></body></html>' }, allow: /status of 502|HTTP 502/ },
  { name: 'a network failure', reply: { kind: 'network' }, allow: /request failed: POST .*\/api\/dns|net::ERR_FAILED/ },
];

test.describe('DNS Lookup — failed requests', () => {
  for (const failure of FAILURES) {
    test(`${failure.name}: every type shows an error, nothing keeps spinning, and the next lookup works`, async ({ page, rng, evidence, guard, baseURL }) => {
      guard.allow(failure.allow);
      const dns = new DnsPage(page);
      const geo = await GeoOracle.load(baseURL!);
      const broken = failingLookup(rng, failure.reply);
      const healthy = randomLookup(rng, { types: rng.sample(OFFERED_TYPES, 3), kind: 'records' });
      const calls = await serveLookups(page, broken, healthy);
      await dns.open();

      const { want } = await runAndCheck(dns, broken, geo, evidence, { label: `${failure.name} for ${describeLookup(broken)}` });
      expectRequestsMatch(calls.splice(0), broken);
      expect(want.sections.every(section => section.state === 'error'), 'oracle: every section of a failed lookup is an error').toBe(true);
      await expect.soft(dns.recordTables, `${failure.name}: no record table may be shown`).toHaveCount(0);
      await expect.soft(dns.copyAllButton, `${failure.name}: nothing to copy`).toHaveCount(0);
      await expect.soft(dns.lookupButton, `${failure.name}: the Lookup button is usable again`).toBeEnabled();
      await expect.soft(dns.lookupButton).toHaveText('Lookup');

      await runAndCheck(dns, healthy, geo, evidence, { label: `recovery after ${failure.name}: ${describeLookup(healthy)}` });
      expectRequestsMatch(calls, healthy);
    });
  }

  test('one failing type does not hide the records of the other types', async ({ page, rng, evidence, guard, baseURL }) => {
    guard.allow(/status of 500|HTTP 500|request failed: POST .*\/api\/dns|net::ERR_FAILED/);
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: ['A', 'MX', 'NS', 'TXT', 'CAA'], kind: 'records' });
    lookup.replies.MX = { kind: 'http', status: 500, body: { error: 'Internal Server Error' } };
    lookup.replies.CAA = { kind: 'network' };
    await serveLookups(page, lookup);
    await dns.open();
    const { want } = await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    await expect.soft(dns.recordTables, 'the three answered types keep their tables').toHaveCount(want.sections.filter(s => s.state === 'table').length);
  });

  test('failApi: with the API unreachable the page reports the failure for the default lookup', async ({ page, rng, guard, evidence }) => {
    guard.allow(/request failed: POST .*\/api\/dns|net::ERR_FAILED/);
    const dns = new DnsPage(page);
    await failApi(page, '**/api/dns');
    await dns.open();
    const domain = randomDomain(rng);
    const lookup: Lookup = { domain, resolver: RESOLVERS[0].value, types: [...DEFAULT_TYPES], replies: Object.fromEntries(DEFAULT_TYPES.map(type => [type, { kind: 'network' } as Reply])) };
    await evidence.save('unreachable.json', lookup);
    await dns.domain.fill(domain);
    await dns.lookupButton.click();
    await dns.waitForResult();
    expectViewMatches(await dns.view(), expectedView(lookup, null), { ctx: `API unreachable, ${describeLookup(lookup)}` });
  });
});

test.describe('DNS Lookup — slow answers and overlapping lookups', () => {
  test('while a lookup runs the button reads "Querying...", is disabled, and the previous result is gone', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const first = randomLookup(rng, { types: ['NS', 'TXT'], kind: 'records' });
    const slow = randomLookup(rng, { types: rng.sample(OFFERED_TYPES, 3), kind: 'records' });
    const held = gate();
    const calls = await routeDns(page, call => (call.body.domain === slow.domain
      ? { reply: slow.replies[String(call.body.type)], hold: held.promise }
      : first.replies[String(call.body.type)]));
    await dns.open();
    await runAndCheck(dns, first, geo, evidence);
    calls.splice(0);

    await dns.submit(slow.domain, { types: slow.types, resolver: slow.resolver });
    await expect(dns.lookupButton, 'button label while waiting').toHaveText('Querying...');
    await expect.soft(dns.lookupButton, 'the button cannot be pressed twice').toBeDisabled();
    await expect.soft(dns.standardMode, 'the mode cannot be changed mid-lookup').toBeDisabled();
    await expect.soft(dns.checkedAt, `the result of "${first.domain}" must not stay on screen while "${slow.domain}" is being queried`).toHaveCount(0);
    await expect.soft(dns.sectionCards, 'no stale sections while waiting').toHaveCount(0);
    await expect.soft(dns.alert, 'no error while waiting').toHaveCount(0);
    expectRequestsMatch(calls, slow, `${describeLookup(slow)} while waiting`);

    held.open();
    await dns.waitForResult();
    expectViewMatches(await dns.view(), expectedView(slow, geo), { ctx: `${describeLookup(slow)} after the slow answer arrived` });
    await expect.soft(dns.lookupButton, 'the button is usable again').toBeEnabled();
    expect.soft(calls.length, 'the slow lookup was sent exactly once per type').toBe(slow.types.length);
  });

  test('pressing Enter again while a lookup is running does not send the lookup a second time', async ({ page, rng, evidence }) => {
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: rng.sample(OFFERED_TYPES, 2), kind: 'records' });
    await evidence.save('double-submit.json', lookup);
    const held = gate();
    const calls = await routeDns(page, call => ({ reply: lookup.replies[String(call.body.type)], hold: held.promise }));
    await dns.open();
    await dns.submit(lookup.domain, { types: lookup.types, resolver: lookup.resolver, via: 'enter' });
    await expect(dns.lookupButton).toHaveText('Querying...');
    await expect(dns.lookupButton, 'the button itself is disabled during the lookup').toBeDisabled();
    await dns.domain.press('Enter');
    await dns.domain.press('Enter');
    held.open();
    await dns.waitForResult();
    expect.soft(calls.length, `Enter pressed twice more during the lookup of "${lookup.domain}": requests sent (one per type = ${lookup.types.length} expected; the button is disabled, the Enter key must be too)`).toBe(lookup.types.length);
  });

  test('when a second lookup is started before a slow first one answers, the page ends up showing the second', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const slow = randomLookup(rng, { types: ['NS'], kind: 'records', resolver: '1.1.1.1' });
    const fast = randomLookup(rng, { types: ['NS'], kind: 'records', resolver: '1.1.1.1' });
    await evidence.save('overlapping-lookups.json', { slow, fast });
    const held = gate();
    await routeDns(page, call => (call.body.domain === slow.domain
      ? { reply: slow.replies.NS, hold: held.promise }
      : fast.replies.NS));
    await dns.open();

    await dns.submit(slow.domain, { types: ['NS'], via: 'enter' });
    await expect(dns.lookupButton).toHaveText('Querying...');
    // The user changes their mind: types another domain and presses Enter.
    await dns.submit(fast.domain, { via: 'enter' });
    const domainCard = page.locator('.stat-card .stat-value').first();
    await expect(domainCard, `the answer for "${fast.domain}" arrives first and is shown`).toHaveText(fast.domain);

    // Now the answer of the abandoned lookup arrives.
    const staleAnswer = page.waitForResponse(res => res.url().endsWith('/api/dns') && res.request().postDataJSON()?.domain === slow.domain);
    held.open();
    await (await staleAnswer).finished();
    const overwritten = await page.waitForFunction(stale => document.querySelector('.stat-card .stat-value')?.textContent === stale, slow.domain, { timeout: 3_000 }).then(() => true, () => false);
    expect.soft(overwritten, `the late answer for "${slow.domain}" replaced the result of the newer lookup of "${fast.domain}" (domain box says "${await dns.domain.inputValue()}")`).toBe(false);
    expectViewMatches(await dns.view(), expectedView(fast, geo), { ctx: `final state after overlapping lookups (last asked: ${describeLookup(fast)})` });
    await expect.soft(dns.domain, 'the domain box still names the last lookup').toHaveValue(fast.domain);
  });
});

test.describe('DNS Lookup — state between lookups', () => {
  test('a second lookup replaces the first completely', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const first = randomLookup(rng, { types: ['A', 'AAAA', 'MX', 'TXT', 'SOA'], kind: 'records', resolver: '8.8.8.8' });
    const second = randomLookup(rng, { types: ['CNAME', 'CAA'], kind: 'none', resolver: '208.67.222.222' });
    const third = randomLookup(rng, { types: ['SRV', 'PTR', 'NS'], kind: 'records', resolver: '1.1.1.1' });
    const calls = await serveLookups(page, first, second, third);
    await dns.open();
    for (const lookup of [first, second, third, first]) {
      const sentBefore = calls.length;
      await runAndCheck(dns, lookup, geo, evidence);
      expectRequestsMatch(calls.slice(sentBefore), lookup);
    }
  });

  test('reloading the page returns to the empty form with the default settings', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: ['SOA', 'SRV'], resolver: '8.8.8.8' });
    await serveLookups(page, lookup);
    await dns.open();
    await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    await dns.open();
    await expect.soft(dns.domain, 'domain box after reload').toHaveValue('');
    await expect.soft(dns.resolver, 'resolver after reload').toHaveValue(RESOLVERS[0].value);
    expect.soft(await dns.checkedTypes(), 'ticked types after reload').toEqual(OFFERED_TYPES.filter(type => (DEFAULT_TYPES as readonly string[]).includes(type)));
    await expect.soft(dns.checkedAt, 'no result after reload').toHaveCount(0);
    await expect.soft(dns.sectionCards).toHaveCount(0);
  });

  test('browser Back to a deep link shows its lookup again', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const lookup = randomLookup(rng, { types: ['MX', 'TXT'], resolver: '8.8.8.8' });
    await evidence.save('back-forward.json', lookup);
    const calls = await serveLookups(page, lookup);
    await dns.open(`?domain=${lookup.domain}&resolver=${lookup.resolver}&types=MX,TXT`);
    await dns.waitForResult();
    await dns.investigateLink('SSL Certificate Checker').click();
    await expect(page).toHaveURL(/\/ssl\?domain=/);
    await page.goBack();
    await expect(page).toHaveURL(new RegExp(`/dns\\?domain=${lookup.domain.replace(/\./g, '\\.')}`));
    await dns.waitForResult();
    expectViewMatches(await dns.view(), expectedView(lookup, geo), { ctx: `after Back to the deep link of ${describeLookup(lookup)}` });
    await expect.soft(dns.domain).toHaveValue(lookup.domain);
    expect.soft(calls.length % lookup.types.length, 'every run of the deep link sends one request per type').toBe(0);
  });
});
