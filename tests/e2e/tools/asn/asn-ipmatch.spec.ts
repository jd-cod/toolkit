import { test, expect } from '../_support/fixtures';
import { addressCases, randomScenario, type AddressCase, type Scenario } from './generator';
import { type Cidr, type Family, INVALID_ADDRESSES, cidrFirst, cidrLast, cidrSize, containing, formatV4, grouped, netmaskV4, parseCidr } from './oracle';
import { openWith } from './checks';
import type { AsnView } from './page';

/**
 * IP Range Matcher tab of /asn ("does this address belong to the network?")
 * and the backend endpoint POST /api/asn/match-ip (our own code, no third
 * party; the page does not call it, it runs a second copy in the browser).
 *
 * Oracle: BigInt containment over the announced prefixes (./oracle.ts), for
 * the first and last address of prefixes, the addresses just outside them,
 * random addresses inside and random addresses elsewhere.
 */

async function openTester(page: import('@playwright/test').Page, scenario: Scenario): Promise<AsnView> {
  const { view } = await openWith(page, scenario);
  await view.tab('tester').click();
  await expect(view.testerInput()).toBeVisible();
  return view;
}

/** Runs every address through the tester and returns one line per wrong answer. */
async function wrongVerdicts(view: AsnView, scenario: Scenario, cases: AddressCase[], family: Family): Promise<string[]> {
  const prefixes = family === 4 ? scenario.v4 : scenario.v6;
  const wrong: string[] = [];
  for (const item of cases) {
    const holders = containing(prefixes, family, item.value);
    const result = await view.testAddress(item.ip);
    const inside = holders.length > 0;
    const label = `${item.ip} (${item.note})`;
    const expectedText = inside
      ? `MATCH FOUND: IP ${item.ip} belongs to AS${scenario.asn}!`
      : `NO MATCH: IP ${item.ip} does NOT fall inside any of AS${scenario.asn}'s announced prefixes.`;
    if (result.matched !== inside) {
      wrong.push(`${label}: ${inside ? `is inside ${holders.map(h => h.text).join(', ')}` : 'is in no announced prefix'}, but the page says "${result.text}"`);
      continue;
    }
    if (result.text !== expectedText) wrong.push(`${label}: verdict text "${result.text}", expected "${expectedText}"`);
    if (!inside) continue;
    const reported = holders.find(h => h.text === result.prefix);
    if (!reported) {
      wrong.push(`${label}: reported prefix "${result.prefix}" does not hold the address (holders: ${holders.map(h => h.text).join(', ')})`);
      continue;
    }
    if (family === 4) {
      const range = `${formatV4(cidrFirst(reported))} → ${formatV4(cidrLast(reported))}`;
      if (result.range !== range) wrong.push(`${label}: Subnet Range "${result.range}", expected "${range}" for ${reported.text}`);
      if (result.netmask !== netmaskV4(reported.length)) wrong.push(`${label}: Netmask "${result.netmask}", expected ${netmaskV4(reported.length)}`);
      if (result.total !== grouped(cidrSize(reported))) wrong.push(`${label}: Total Subnet IPs "${result.total}", expected ${grouped(cidrSize(reported))}`);
    }
  }
  return wrong;
}

test.describe('ASN IP tester — in the page', () => {
  test('IPv4: addresses on, inside and just outside prefix edges get the right verdict and prefix details', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: rng.int(20, 40), v6Count: 3 });
    const cases = addressCases(rng, scenario.v4, 4, 5);
    await evidence.save('asn-response.json', scenario.payload);
    await evidence.save('addresses.json', cases.map(c => ({ ip: c.ip, note: c.note })));
    const view = await openTester(page, scenario);
    const wrong = await wrongVerdicts(view, scenario, cases, 4);
    expect(wrong, `IPv4 addresses with a wrong answer (${wrong.length} of ${cases.length}):\n  ${wrong.join('\n  ')}\n`).toEqual([]);
  });

  test('IPv6: addresses on, inside and just outside prefix edges get the right verdict, in any valid spelling', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: 3, v6Count: rng.int(8, 14) });
    const cases = addressCases(rng, scenario.v6, 6, 5);
    await evidence.save('asn-response.json', scenario.payload);
    await evidence.save('addresses.json', cases.map(c => ({ ip: c.ip, note: c.note })));
    const view = await openTester(page, scenario);
    const wrong = await wrongVerdicts(view, scenario, cases, 6);
    expect(wrong, `IPv6 addresses with a wrong answer (${wrong.length} of ${cases.length}):\n  ${wrong.join('\n  ')}\n`).toEqual([]);
  });

  test('text that is not an IP address is reported as invalid, not as "match" or "no match"', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: 4, v6Count: 2, v4: ['10.0.0.0/8', '198.51.100.0/24'], v6: ['2001:db8::/32'] });
    await evidence.save('asn-response.json', scenario.payload);
    const view = await openTester(page, scenario);
    const invalidNote = view.scope.getByText(/invalid|not a valid/i);
    const wrong: string[] = [];
    for (const { input, why } of INVALID_ADDRESSES) {
      await view.testerInput().fill(input);
      await view.testerButton().click();
      await expect(view.verdict().filter({ hasText: input }).or(invalidNote).first(), `the tester should react to "${input}"`).toBeVisible();
      if (await invalidNote.count() === 0) {
        wrong.push(`"${input}" (${why}): the page says "${((await view.verdict().textContent()) || '').replace(/\s+/g, ' ').trim()}"`);
      }
    }
    expect(wrong, `inputs that are not IP addresses but got a verdict (${wrong.length} of ${INVALID_ADDRESSES.length}):\n  ${wrong.join('\n  ')}\n`).toEqual([]);
  });

  test('Enter runs the test, spaces around the address are ignored, and an empty box clears the verdict', async ({ page, rng }) => {
    const scenario = randomScenario(rng, { v4Count: 6, v6Count: 2 });
    const view = await openTester(page, scenario);
    await expect.soft(view.scope.getByText(`Verify if an individual IPv4 or IPv6 address belongs to AS${scenario.asn} (${scenario.holder}).`),
      'the intro names the network').toBeVisible();
    await expect(view.verdict(), 'no verdict before a test').toHaveCount(0);

    const target = rng.pick(scenario.v4);
    const inside = formatV4(cidrLast(target));
    await view.testerInput().fill(`   ${inside}  `);
    await view.testerInput().press('Enter');
    await expect.soft(view.verdict(), `"   ${inside}  " + Enter`).toHaveText(`MATCH FOUND: IP ${inside} belongs to AS${scenario.asn}!`);

    await view.testerInput().fill('   ');
    await view.testerButton().click();
    await expect.soft(view.verdict(), 'an empty box removes the previous verdict').toHaveCount(0);

    // The verdict is about the announced prefixes whatever the explorer is filtered to.
    await view.tab('prefixes').click();
    await view.versionButton('ipv6').click();
    await view.tab('tester').click();
    const again = await view.testAddress(inside);
    expect.soft(again.matched, `${inside} still matches after the explorer was switched to IPv6`).toBe(true);
  });
});

test.describe('ASN IP match API (POST /api/asn/match-ip, real backend)', () => {
  type Page = import('@playwright/test').Page;
  const match = (page: Page, data: Record<string, unknown>) => page.request.post('/api/asn/match-ip', { data });

  async function wrongAnswers(page: Page, prefixes: Cidr[], cases: AddressCase[], family: Family): Promise<string[]> {
    const wrong: string[] = [];
    for (const [i, item] of cases.entries()) {
      // The endpoint accepts prefix records and plain strings; use both.
      const list = i % 2 === 0 ? prefixes.map(p => ({ prefix: p.text })) : prefixes.map(p => p.text);
      const response = await match(page, { ip: item.ip, prefixes: list });
      const body = await response.json();
      const holders = containing(prefixes, family, item.value);
      const label = `${item.ip} (${item.note})`;
      if (response.status() !== 200) { wrong.push(`${label}: HTTP ${response.status()} ${JSON.stringify(body)}`); continue; }
      if (Boolean(body.matched) !== holders.length > 0) {
        wrong.push(`${label}: ${holders.length ? `is inside ${holders.map(h => h.text).join(', ')}` : 'is in no prefix'}, API says ${JSON.stringify(body)}`);
        continue;
      }
      if (!holders.length) continue;
      const reported = parseCidr(String(body.prefix));
      if (!reported || !holders.some(h => h.text === reported.text)) { wrong.push(`${label}: API reports prefix ${body.prefix}, which does not hold it`); continue; }
      if (family === 4) {
        const want = { first_ip: formatV4(cidrFirst(reported)), last_ip: formatV4(cidrLast(reported)), netmask: netmaskV4(reported.length), total_ips: Number(cidrSize(reported)) };
        for (const [key, value] of Object.entries(want)) {
          if (body[key] !== value) wrong.push(`${label}: ${key} is ${JSON.stringify(body[key])}, expected ${JSON.stringify(value)} for ${reported.text}`);
        }
      }
    }
    return wrong;
  }

  test('IPv4 answers equal BigInt containment for edge and random addresses', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: rng.int(20, 40), v6Count: 0 });
    const cases = addressCases(rng, scenario.v4, 4, 5);
    await evidence.save('prefixes.json', scenario.v4.map(p => p.text));
    await evidence.save('addresses.json', cases.map(c => ({ ip: c.ip, note: c.note })));
    const wrong = await wrongAnswers(page, scenario.v4, cases, 4);
    expect(wrong, `IPv4 addresses the API answers wrongly (${wrong.length} of ${cases.length}):\n  ${wrong.join('\n  ')}\n`).toEqual([]);
  });

  test('IPv6 answers equal BigInt containment for edge and random addresses', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: 0, v6Count: rng.int(8, 14) });
    const cases = addressCases(rng, scenario.v6, 6, 5);
    await evidence.save('prefixes.json', scenario.v6.map(p => p.text));
    await evidence.save('addresses.json', cases.map(c => ({ ip: c.ip, note: c.note })));
    const wrong = await wrongAnswers(page, scenario.v6, cases, 6);
    expect(wrong, `IPv6 addresses the API answers wrongly (${wrong.length} of ${cases.length}):\n  ${wrong.join('\n  ')}\n`).toEqual([]);
  });

  test('a missing address or an empty prefix list is refused with HTTP 400 and a message', async ({ page }) => {
    const noIp = await match(page, { prefixes: ['10.0.0.0/8'] });
    expect.soft(noIp.status(), 'no ip: status').toBe(400);
    expect.soft((await noIp.json()).error, 'no ip: message').toBe('Missing IP address to test.');
    for (const prefixes of [[], undefined, 'text']) {
      const response = await match(page, { ip: '10.0.0.1', prefixes });
      expect.soft(response.status(), `prefixes ${JSON.stringify(prefixes)}: status`).toBe(400);
      expect.soft((await response.json()).error, `prefixes ${JSON.stringify(prefixes)}: message`).toBe('No prefix list provided for testing.');
    }
  });

  test('text that is not an IP address is never reported as matched', async ({ page }) => {
    const prefixes = ['10.0.0.0/8', '198.51.100.0/24', '2001:db8::/32'];
    const wrong: string[] = [];
    for (const { input, why } of INVALID_ADDRESSES) {
      const response = await match(page, { ip: input, prefixes });
      const text = await response.text();
      let body: Record<string, unknown> = {};
      try { body = JSON.parse(text); } catch { /* not JSON */ }
      if (response.status() >= 500) wrong.push(`"${input}" (${why}): HTTP ${response.status()} ${text.slice(0, 120)}`);
      else if (body.matched === true) wrong.push(`"${input}" (${why}): API says it belongs to ${body.prefix}`);
      else if (response.status() === 200 && body.valid !== false) wrong.push(`"${input}" (${why}): API treats it as a valid address (${text.slice(0, 120)})`);
    }
    expect(wrong, `inputs that are not IP addresses but were accepted (${wrong.length} of ${INVALID_ADDRESSES.length}):\n  ${wrong.join('\n  ')}\n`).toEqual([]);
  });
});
