import { Resolver } from 'node:dns/promises';
import type { Response } from '@playwright/test';
import { test, expect, type Page } from '../_support/fixtures';
import { captureApi } from '../_support/io';
import { expectViewMatches } from './checks';
import { parseIp } from './mmdb';
import { GeoOracle, RESOLVERS, expectedView, utcStampsBetween, type ApiAnswer, type Lookup } from './oracle';
import { DnsPage } from './page';

/**
 * DNS Lookup — live lookups through the real backend (tagged @live; skipped
 * with E2E_LIVE=0). Two independent sources are compared with the page:
 *
 *  1. the real answer of POST /api/dns, captured in the browser: the page must
 *     show exactly that (same oracle as the contract tests);
 *  2. Node's own resolver asking 1.1.1.1 / 8.8.8.8 over plain DNS: the page
 *     must show the same record SET. Only TTLs and the order of the records
 *     may differ.
 */

const resolver = new Resolver({ timeout: 5000, tries: 3 });
resolver.setServers(['1.1.1.1', '8.8.8.8']);

/** Runs a lookup in the page and returns every real API answer it received, by record type. */
async function liveLookup(dns: DnsPage, page: Page, typed: string, types: string[], resolverValue: string): Promise<{ lookup: Lookup; before: number; after: number }> {
  const responses: Response[] = [];
  const listen = (response: Response) => {
    if (response.url().endsWith('/api/dns') && response.request().method() === 'POST') responses.push(response);
  };
  page.on('response', listen);
  const before = Date.now();
  await dns.submit(typed, { types, resolver: resolverValue });
  await dns.waitForResult();
  const after = Date.now();
  page.off('response', listen);

  const lookup: Lookup = { domain: '', resolver: resolverValue, types, replies: {} };
  for (const response of responses) {
    const sent = response.request().postDataJSON() as { domain: string; type: string; resolver: string };
    expect(response.status(), `POST /api/dns for ${sent.type}`).toBe(200);
    expect.soft(sent.resolver, `resolver sent for ${sent.type}`).toBe(resolverValue);
    lookup.domain = sent.domain;
    lookup.replies[sent.type] = { kind: 'answer', body: await response.json() as ApiAnswer };
  }
  expect(Object.keys(lookup.replies).sort(), `one API answer per requested type for "${typed}"`).toEqual([...types].sort());
  return { lookup, before, after };
}

/** Values the page shows in the Value column of one section. */
function shownValues(view: Awaited<ReturnType<DnsPage['view']>>, type: string): string[] {
  return (view.sections.find(section => section.heading === `${type} Records`)?.rows ?? []).map(row => row[0].text);
}

const lower = (list: string[]) => list.map(item => item.toLowerCase().replace(/\.$/, '')).sort();
const addresses = (list: string[]) => list.map(ip => String(parseIp(ip)?.value)).sort();

test.describe('DNS Lookup — live lookups @live', { tag: '@live' }, () => {
  test.skip(process.env.E2E_LIVE === '0', 'live tests disabled');

  test('example.com A, AAAA, NS, SOA and TXT: the page shows the API answer, and the same records as an independent resolver', async ({ page, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    await dns.open();
    const types = ['A', 'AAAA', 'NS', 'SOA', 'TXT'];
    const { lookup, before, after } = await liveLookup(dns, page, 'example.com', types, '1.1.1.1');
    await evidence.save('live-example.com.json', lookup);
    const view = await dns.view();
    expectViewMatches(view, expectedView(lookup, geo), { ctx: 'live example.com', stamps: utcStampsBetween(before - 1000, after + 1000), maxQueryMs: after - before + 250 });

    const [a, aaaa, ns, soa, txt] = await Promise.all([
      resolver.resolve4('example.com'), resolver.resolve6('example.com'), resolver.resolveNs('example.com'),
      resolver.resolveSoa('example.com'), resolver.resolveTxt('example.com'),
    ]);
    await evidence.save('node-resolver-example.com.json', { a, aaaa, ns, soa, txt });
    expect.soft(addresses(shownValues(view, 'A')), 'A records shown vs Node resolver').toEqual(addresses(a));
    expect.soft(addresses(shownValues(view, 'AAAA')), 'AAAA records shown vs Node resolver').toEqual(addresses(aaaa));
    expect.soft(lower(shownValues(view, 'NS')), 'NS records shown vs Node resolver').toEqual(lower(ns));
    expect.soft(shownValues(view, 'SOA'), 'SOA record shown vs Node resolver (primary, contact, serial, refresh, retry, expire, minimum)')
      .toEqual([`${soa.nsname} ${soa.hostmaster} ${soa.serial} ${soa.refresh} ${soa.retry} ${soa.expire} ${soa.minttl}`]);
    // The character-strings of one TXT record form one value (RFC 7208 section 3.3).
    expect.soft([...shownValues(view, 'TXT')].sort(), 'TXT records shown vs Node resolver').toEqual(txt.map(chunks => chunks.join('')).sort());
    const provider = view.cards.find(card => card.label === 'DNS Provider');
    expect.soft(ns.some(name => name.endsWith('.ns.cloudflare.com')) ? provider?.value : 'Cloudflare DNS', 'example.com is served by Cloudflare name servers: DNS Provider card').toBe('Cloudflare DNS');
  });

  test('stable public records of the other types (MX, CAA, PTR, CNAME, SRV) through each resolver match an independent resolver', async ({ page, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    await dns.open();
    const cases: { name: string; type: string; resolver: string; expected: () => Promise<string[]>; shown: (view: Awaited<ReturnType<DnsPage['view']>>) => string[] }[] = [
      {
        name: 'iana.org', type: 'MX', resolver: RESOLVERS[1].value,
        expected: async () => (await resolver.resolveMx('iana.org')).map(mx => `${mx.priority} ${mx.exchange.toLowerCase()}`).sort(),
        shown: view => (view.sections[0]?.rows ?? []).map(row => `${row[1].text} ${row[0].text.toLowerCase()}`).sort(),
      },
      {
        name: 'iana.org', type: 'CAA', resolver: RESOLVERS[2].value,
        expected: async () => (await resolver.resolveCaa('iana.org')).map(caa => {
          const [tag, value] = Object.entries(caa).find(([key]) => key !== 'critical' && key !== 'type') as [string, string];
          return `${caa.critical} ${tag} "${value}"`;
        }).sort(),
        shown: view => shownValues(view, 'CAA').sort(),
      },
      { name: '8.8.8.8.in-addr.arpa', type: 'PTR', resolver: RESOLVERS[0].value, expected: async () => lower(await resolver.resolvePtr('8.8.8.8.in-addr.arpa')), shown: view => lower(shownValues(view, 'PTR')) },
      { name: 'www.github.com', type: 'CNAME', resolver: RESOLVERS[1].value, expected: async () => lower(await resolver.resolveCname('www.github.com')), shown: view => lower(shownValues(view, 'CNAME')) },
      {
        name: '_xmpp-server._tcp.jabber.org', type: 'SRV', resolver: RESOLVERS[0].value,
        expected: async () => (await resolver.resolveSrv('_xmpp-server._tcp.jabber.org')).map(srv => `${srv.priority} ${srv.weight} ${srv.port} ${srv.name}`).sort(),
        shown: view => shownValues(view, 'SRV').sort(),
      },
    ];
    for (const entry of cases) {
      const ctx = `live ${entry.name} ${entry.type} via ${entry.resolver}`;
      const { lookup, before, after } = await liveLookup(dns, page, entry.name, [entry.type], entry.resolver);
      await evidence.save(`live-${entry.name}-${entry.type}.json`, lookup);
      const view = await dns.view();
      expectViewMatches(view, expectedView(lookup, geo), { ctx, stamps: utcStampsBetween(before - 1000, after + 1000) });
      const independent = await entry.expected();
      expect(independent.length, `${ctx}: the independent resolver finds records (test precondition)`).toBeGreaterThan(0);
      expect.soft(entry.shown(view), `${ctx}: records shown vs Node resolver`).toEqual(independent);
    }
  });

  test('a name that does not exist shows "does not exist" for every type, zero records and no table', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    await dns.open();
    const name = `nx-${rng.string(16)}.invalid`; // RFC 6761: .invalid never resolves
    const types = ['A', 'AAAA', 'MX', 'TXT'];
    const { lookup } = await liveLookup(dns, page, name, types, rng.pick(RESOLVERS).value);
    await evidence.save('live-nxdomain.json', lookup);
    const view = await dns.view();
    expectViewMatches(view, expectedView(lookup, await GeoOracle.load(baseURL!)), { ctx: `live ${name}` });
    for (const type of types) {
      const section = view.sections.find(s => s.heading === `${type} Records`);
      expect.soft(section?.state, `${name} ${type}: state`).toBe('empty');
      expect.soft(section?.note, `${name} ${type}: message`).toBe(`No ${type} records found. ${name} does not exist.`);
    }
    expect.soft(view.cards.find(card => card.label === 'Records Found')?.value, 'Records Found').toBe('0');
    expect.soft((view.nothingFoundBanner ?? '').trim(), 'banner').toBe('No DNS records were returned for the selected record types.');
    await expect.soft(dns.recordTables).toHaveCount(0);
    await expect.soft(dns.copyAllButton).toHaveCount(0);
    await expect(resolver.resolve4(name), 'independent resolver: the name does not exist').rejects.toMatchObject({ code: 'ENOTFOUND' });
  });

  test('a fully qualified name with a trailing dot finds the same records as without it', async ({ page, evidence }) => {
    const dns = new DnsPage(page);
    await dns.open();
    const { lookup } = await liveLookup(dns, page, 'iana.org.', ['NS'], '1.1.1.1');
    await evidence.save('live-trailing-dot.json', lookup);
    expect.soft(lower(shownValues(await dns.view(), 'NS')), 'NS of "iana.org." vs Node resolver for iana.org').toEqual(lower(await resolver.resolveNs('iana.org')));
  });

  test('the null MX of example.com (RFC 7505: "0 .") is shown as priority 0 with a visible host, not as an empty row', async ({ page, evidence }) => {
    const published = await resolver.resolveMx('example.com');
    test.skip(!(published.length === 1 && published[0].priority === 0 && published[0].exchange === ''), 'example.com no longer publishes a null MX');
    const dns = new DnsPage(page);
    await dns.open();
    const { lookup } = await liveLookup(dns, page, 'example.com', ['MX'], '1.1.1.1');
    await evidence.save('live-null-mx.json', lookup);
    const section = (await dns.view()).sections[0];
    expect(section?.counter, 'one MX record is found').toMatch(/^1 found/);
    const [value, priority] = (section?.rows[0] ?? []).map(cell => cell.text);
    expect.soft(priority, 'example.com MX: Priority cell (the record is "0 .")').toBe('0');
    expect.soft(value?.trim(), 'example.com MX: Value cell must not be blank (the null MX host is ".")').not.toBe('');
  });

  test('an internationalised domain typed in its native spelling is looked up (as punycode) and finds its records', async ({ page, evidence }) => {
    const unicodeName = 'münchen.de';
    const independent = await resolver.resolve4('xn--mnchen-3ya.de').catch(() => [] as string[]);
    test.skip(independent.length === 0, 'xn--mnchen-3ya.de has no A record any more');
    const dns = new DnsPage(page);
    await dns.open();
    const { lookup } = await liveLookup(dns, page, unicodeName, ['A'], '1.1.1.1');
    await evidence.save('live-idn.json', { lookup, independent });
    const view = await dns.view();
    expect.soft(view.sections[0]?.note ?? '', `"${unicodeName}" exists (xn--mnchen-3ya.de → ${independent.join(', ')}); the page must not say otherwise`).not.toContain('does not exist');
    expect.soft(addresses(shownValues(view, 'A')), `A records of "${unicodeName}" vs Node resolver for xn--mnchen-3ya.de`).toEqual(addresses(independent));
  });

  test('a PTR lookup for an IP address finds its reverse name or is refused with a message, but does not claim the address "does not exist"', async ({ page, evidence }) => {
    const names = lower(await resolver.reverse('8.8.8.8'));
    const dns = new DnsPage(page);
    await dns.open();
    const { lookup } = await liveLookup(dns, page, '8.8.8.8', ['PTR'], '1.1.1.1').catch(() => ({ lookup: null }));
    await evidence.save('live-ptr-ip.json', { lookup, names });
    if (await dns.alert.count()) return; // refused with a message: acceptable
    const view = await dns.view();
    expect.soft(view.sections[0]?.note ?? '', `PTR for 8.8.8.8 (reverse name: ${names.join(', ')}): the page answers`).not.toContain('does not exist');
    expect.soft(lower(shownValues(view, 'PTR')), 'PTR names shown for 8.8.8.8 vs Node resolver.reverse()').toEqual(names);
  });

  test('a TXT record made of several character-strings (a 2048-bit DKIM key) is shown as one unbroken value', async ({ page, evidence }) => {
    // First candidate that still publishes a multi-string TXT record directly (no CNAME in between).
    let name = '';
    let published: string[][] = [];
    for (const candidate of ['s2048._domainkey.yahoo.com', 'isc.org', 'icann.org']) {
      const txt = await resolver.resolveTxt(candidate).catch(() => [] as string[][]);
      const alias = await resolver.resolveCname(candidate).catch(() => [] as string[]);
      if (alias.length === 0 && txt.some(chunks => chunks.length > 1)) { name = candidate; published = txt; break; }
    }
    test.skip(!name, 'none of the candidate names publishes a multi-string TXT record any more');
    const dns = new DnsPage(page);
    await dns.open();
    const { lookup } = await liveLookup(dns, page, name, ['TXT'], '1.1.1.1');
    await evidence.save('live-txt-chunks.json', { lookup, published });
    const shown = shownValues(await dns.view(), 'TXT').sort();
    const joined = published.map(chunks => chunks.join('')).sort();
    const quoted = published.map(chunks => chunks.map(chunk => `"${chunk}"`).join(' ')).sort();
    const split = published.find(chunks => chunks.length > 1) as string[];
    // Either the concatenated value (RFC 6376 section 3.6.2.2) or the zone-file form with each string quoted is unambiguous.
    const matches = JSON.stringify(shown) === JSON.stringify(joined) || JSON.stringify(shown) === JSON.stringify(quoted);
    expect.soft(matches, `${name} TXT has a record of ${split.length} strings (${split.map(c => c.length).join(' + ')} characters) that form one value "${split.join('').slice(0, 40)}…"; `
      + `the page shows ${JSON.stringify(shown.find(value => value.startsWith(split[0].slice(0, 20)))?.slice(0, 60))}… with a space inserted at each join, which corrupts the value when it is copied`).toBe(true);
  });

  test('an A lookup of a name that is an alias (www.github.com → github.com) lists only addresses as A records', async ({ page, evidence }) => {
    const name = 'www.github.com';
    const [alias, independent] = await Promise.all([resolver.resolveCname(name).catch(() => [] as string[]), resolver.resolve4(name)]);
    test.skip(alias.length === 0, `${name} is no longer a CNAME`);
    const dns = new DnsPage(page);
    await dns.open();
    const { lookup } = await liveLookup(dns, page, name, ['A'], '1.1.1.1');
    await evidence.save('live-cname-chain.json', { lookup, alias, independent });
    const view = await dns.view();
    const shown = shownValues(view, 'A');
    const notAddresses = shown.filter(value => parseIp(value) === null);
    expect.soft(notAddresses, `${name} A: the "A Records" table lists ${JSON.stringify(shown)}; values that are not IPv4 addresses (the CNAME target of the alias chain)`).toEqual([]);
    expect.soft(view.sections[0]?.counter.split(' ·')[0], `${name} A: the resolver returns ${independent.length} address(es) (alias target ${alias.join(', ')} is a CNAME, not an A record)`).toBe(`${shown.filter(value => parseIp(value) !== null).length} found`);
    expect.soft(shown.filter(value => parseIp(value) !== null).length, `${name} A: at least one address is listed`).toBeGreaterThan(0);
  });

  test('captureApi: a single live lookup shows exactly the captured answer (iana.org A via Google)', async ({ page, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    await dns.open();
    await dns.selectTypes(['A']);
    await dns.resolver.selectOption('8.8.8.8');
    await dns.domain.fill('iana.org');
    const exchange = await captureApi<ApiAnswer>(page, /\/api\/dns$/, () => dns.lookupButton.click());
    await dns.waitForResult();
    await evidence.save('live-iana-a.json', exchange);
    expect(exchange.status).toBe(200);
    expect.soft(exchange.request, 'request body').toEqual({ domain: 'iana.org', type: 'A', resolver: '8.8.8.8' });
    const lookup: Lookup = { domain: 'iana.org', resolver: '8.8.8.8', types: ['A'], replies: { A: { kind: 'answer', body: exchange.response } } };
    const view = await dns.view();
    expectViewMatches(view, expectedView(lookup, await GeoOracle.load(baseURL!)), { ctx: 'live iana.org A' });
    expect.soft(addresses(shownValues(view, 'A')), 'A records vs Node resolver').toEqual(addresses(await resolver.resolve4('iana.org')));
  });
});
