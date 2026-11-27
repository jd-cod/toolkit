import { test, expect } from '../_support/fixtures';
import { expectToolLinkedFromHome } from '../_support/navigation';
import { expectControlsUsable, expectNoUiGlitches, VIEWPORTS } from '../_support/ui-audit';
import { captureApi, mockApi, type ApiCall } from '../_support/io';
import { describeLookup, expectNoMarkupExecuted, expectRequestsMatch, expectViewMatches, runAndCheck } from './checks';
import { MARKUP_PROBES, TTL_EDGES, UNKNOWN, awkwardTxtValues, randomAnswer, randomDomain, randomLabel, randomLookup, randomRecords } from './generator';
import {
  DEFAULT_TYPES, GeoOracle, OFFERED_TYPES, RESOLVERS, SECTION_ORDER, expectedView, hostOf, humanTtl,
  type ApiAnswer, type Lookup, type Reply,
} from './oracle';
import { DnsPage, HEADING, ROUTE, gate, routeDns, serveLookups } from './page';

/**
 * DNS Lookup (/dns) — server-backed tool.
 *
 * INVENTORY (coverage contract; "→" names the spec file that covers the entry)
 *
 * Inputs
 *  - Domain name text box (#dns-domain): typed text, pasted URL (scheme, path, port, query, credentials),
 *    upper case, surrounding spaces, trailing dot, IDN, IP address, empty, markup            → dns, dns-live
 *  - Submit by "Lookup" button or Enter key                                                 → dns
 *  - Record type checkboxes: A AAAA MX TXT CNAME NS SOA PTR SRV CAA (default A AAAA MX CNAME NS TXT);
 *    independent in Standard mode, exactly one in Global mode                               → dns, dns-global
 *  - Resolver select (Standard mode): Cloudflare 1.1.1.1 (default), Google 8.8.8.8, OpenDNS  → dns
 *  - Query mode buttons: Standard Query; Global Propagation (only when
 *    GET /api/dns/global-capability says available)                                         → dns-global
 *  - Deep link /dns?domain=&resolver=&types= (runs the lookup on load)                      → dns
 *
 * Displayed values (Standard mode)
 *  - Summary cards: Domain, Records Found, DNS Provider (+confidence · source), Hosting / Edge
 *    (+confidence · source), Resolver                                                       → dns
 *  - "Checked At" UTC timestamp                                                             → dns
 *  - One section per requested type: heading, "<n> found · <t>ms", then a table (Value, TTL; MX +Priority;
 *    A/AAAA +Location +Provider from GeoLite2), a "no records" note, or an error text        → dns
 *  - Banner when no type returned a record                                                  → dns
 *  - Side panel "Query details" (mode, resolver, selected records) and links to /ssl and /whois → dns
 *
 * Displayed values (Global mode): table AWS Region | Status | Result, error banner           → dns-global
 *
 * Outputs
 *  - Requests: POST /api/dns {domain,type,resolver} per type; POST /api/dns/global {domain,type} → dns, dns-global
 *  - Copy All Records (clipboard)                                                           → dns-outputs
 *  - Export CSV, Download HTML (standard, global, shared view)                               → dns-outputs, dns-global, dns-share
 *  - Share dialog: title, expiry (never/24h/7d/30d), password, link, copy link, create another → dns-share
 *  - Shared view /s/<code>: same snapshot, password prompt, re-run, open live lookup         → dns-share
 *
 * States
 *  - Empty form, lookup in progress ("Querying...", button disabled), result, per-type error,
 *    validation alert ("Select at least one record type."), HTTP 400/429/500, network failure,
 *    slow answer, overlapping lookups, second lookup, reload                                → dns, dns-failures
 *
 * Not present in this tool: history of recent lookups, JSON export, per-record copy buttons,
 * settings kept in localStorage. Unreachable through the UI (and therefore not tested): the
 * messages "Global propagation is unavailable. Choose Standard Query." and "Please select exactly
 * one record type for Global Propagation." — the Global button is hidden when unavailable and
 * Global mode always keeps exactly one type selected.
 *
 * LAYERS: 1 access (this file) · 2 layout (this file, dns-global, dns-share) · 3 input paths (this file) ·
 * 4 displayed values (this file, dns-global, dns-live) · 5 controls (this file, dns-global) ·
 * 6 outputs (dns-outputs, dns-share, dns-global) · 7 failures (dns-failures, dns-global) ·
 * 8 state and navigation (dns-failures, this file for deep links).
 */

const answer = (body: ApiAnswer): Reply => ({ kind: 'answer', body });

test.describe('DNS Lookup — access and layout', () => {
  test('is linked from the home page and the sidebar', async ({ page }) => {
    await expectToolLinkedFromHome(page, ROUTE);
    await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
  });

  test('opens with its controls ready, the documented defaults and an empty result area', async ({ page }) => {
    const dns = new DnsPage(page);
    const capability = await captureApi<{ available: boolean }>(page, '/api/dns/global-capability', () => dns.open());
    await expect(page).toHaveTitle(/DNS Lookup/i);
    await expectControlsUsable(page, {
      'domain input': '#dns-domain',
      'resolver select': '#dns-resolver',
      'Standard Query button': '.signal-mode-controls button',
      'record type checkbox': '.signal-query-panel input[type="checkbox"]',
    });
    await expect(dns.domain, 'the domain box starts empty').toHaveValue('');
    await expect(dns.domain).toHaveAttribute('placeholder', 'e.g. google.com');
    await expect(dns.lookupButton, 'Lookup is disabled until a domain is typed').toBeDisabled();
    await expect(dns.lookupButton).toHaveText('Lookup');

    const offered = await page.locator('.signal-query-panel input[type="checkbox"]').evaluateAll(boxes => boxes.map(box => box.closest('label')?.textContent ?? ''));
    expect.soft(offered, 'record types offered, in order').toEqual([...OFFERED_TYPES]);
    expect.soft(await dns.checkedTypes(), 'record types ticked by default').toEqual(OFFERED_TYPES.filter(type => (DEFAULT_TYPES as readonly string[]).includes(type)));

    const options = await dns.resolver.locator('option').evaluateAll(list => list.map(o => ({ value: (o as HTMLOptionElement).value, label: o.textContent ?? '' })));
    expect.soft(options, 'resolver choices').toEqual(RESOLVERS.map(r => ({ value: r.value, label: r.label })));
    await expect.soft(dns.resolver, 'default resolver').toHaveValue(RESOLVERS[0].value);

    await expect.soft(dns.standardMode, 'Standard Query is the active mode').toHaveAttribute('aria-pressed', 'true');
    expect(capability.status, 'GET /api/dns/global-capability').toBe(200);
    await expect.soft(dns.globalMode, `Global Propagation button must ${capability.response.available ? 'be offered' : 'be hidden'} when the backend reports available=${capability.response.available}`)
      .toHaveCount(capability.response.available ? 1 : 0);

    expect.soft(await dns.queryDetails(), 'side panel "Query details"').toEqual({
      'Query mode': 'Standard', Resolver: RESOLVERS[0].label, 'Selected records': DEFAULT_TYPES.join(', '),
    });
    await expect.soft(dns.investigateLink('SSL Certificate Checker')).toHaveAttribute('href', '/ssl');
    await expect.soft(dns.investigateLink('WHOIS Lookup')).toHaveAttribute('href', '/whois');
    await expect(dns.checkedAt, 'no result before the first lookup').toHaveCount(0);
    await expect(dns.sectionCards).toHaveCount(0);
    await expect(dns.alert).toHaveCount(0);
  });

  for (const [name, viewport] of Object.entries(VIEWPORTS)) {
    test(`has no layout problems at ${name} size (${viewport.width}px): empty form, lookup in progress, every record type, validation error`, async ({ page, rng, evidence, baseURL }) => {
      await page.setViewportSize(viewport);
      const dns = new DnsPage(page);
      const domain = randomDomain(rng);
      // Every type once: tables of each shape, a long unbroken TXT value, an empty type and a failed type.
      const lookup: Lookup = { domain, resolver: '8.8.8.8', types: [...OFFERED_TYPES], replies: {} };
      for (const type of OFFERED_TYPES) lookup.replies[type] = answer(randomAnswer(rng, domain, type, lookup.resolver, { kind: 'records', count: 3 }));
      (lookup.replies.TXT as { body: ApiAnswer }).body.records = awkwardTxtValues(rng).map(data => ({ name: domain, type: 'TXT', TTL: 300, data }));
      lookup.replies.PTR = answer(randomAnswer(rng, domain, 'PTR', lookup.resolver, { kind: 'none' }));
      lookup.replies.SRV = answer({ error: 'DNS lookup failed with SERVFAIL.', records: [], status: 2, _type: 'SRV' });
      await evidence.save('layout-lookup.json', lookup);

      const held = gate();
      await routeDns(page, call => ({ reply: lookup.replies[String(call.body.type)], hold: held.promise }));
      await dns.open();
      await expectNoUiGlitches(page, `${ROUTE} empty form @${name}`);

      // Submitted with Enter: a pointer resting on the button starts its hover animation, which the audit would measure.
      await dns.submit(domain, { types: lookup.types, resolver: lookup.resolver, via: 'enter' });
      await expect(dns.lookupButton, 'the button shows the lookup is running').toHaveText('Querying...');
      await expectNoUiGlitches(page, `${ROUTE} lookup in progress @${name}`);
      held.open();
      await dns.waitForResult();
      await expect(dns.sectionCards).toHaveCount(OFFERED_TYPES.length);
      await expectNoUiGlitches(page, `${ROUTE} results for every record type @${name}`);
      expectViewMatches(await dns.view(), expectedView(lookup, await GeoOracle.load(baseURL!)), { ctx: `layout lookup @${name}` });

      await dns.selectTypes([]);
      await dns.domain.press('Enter');
      await expect(dns.alert).toHaveText('Select at least one record type.');
      await expectNoUiGlitches(page, `${ROUTE} validation error @${name}`);
    });
  }
});

test.describe('DNS Lookup — what is sent to the resolver', () => {
  test('upper case, spaces, scheme and path are removed: the bare host name is queried and shown', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const forms: ((host: string) => string)[] = [
      host => host.toUpperCase(),
      host => `   ${host}  `,
      host => `https://${host}/`,
      host => `http://${host}/some/path/index.html`,
      host => `HTTPS://${host.toUpperCase()}/Path?query=1#top`,
      host => `${host}/path/only`,
      host => `\t${host[0].toUpperCase()}${host.slice(1)}/`,
    ];
    const cases = forms.map(form => {
      const lookup = randomLookup(rng, { types: rng.sample(OFFERED_TYPES, 2), kind: 'records' });
      return { typed: form(lookup.domain), lookup };
    });
    await evidence.save('typed-domains.json', cases.map(c => ({ typed: c.typed, host: c.lookup.domain })));
    const calls = await serveLookups(page, ...cases.map(c => c.lookup));
    await dns.open();

    for (const { typed, lookup } of cases) {
      expect(hostOf(typed), `oracle: host name of ${JSON.stringify(typed)}`).toBe(lookup.domain);
      const ctx = `typed ${JSON.stringify(typed)}`;
      const sentBefore = calls.length;
      await runAndCheck(dns, lookup, geo, evidence, { typed, label: ctx });
      expectRequestsMatch(calls.slice(sentBefore), lookup, ctx);
      await expect.soft(dns.domain, `${ctx}: the box is rewritten to the host that was queried`).toHaveValue(lookup.domain);
    }
  });

  test('a pasted URL with a port, query string, fragment or credentials is reduced to its host name', async ({ page, rng, evidence }) => {
    const dns = new DnsPage(page);
    const host = randomDomain(rng);
    const typedForms = [
      `https://${host}:8443/login`,
      `${host}:8080`,
      `https://${host}?utm_source=mail`,
      `https://${host}#section`,
      `https://admin:secret@${host}/`,
    ];
    await evidence.save('pasted-urls.json', { host, typedForms });
    const calls = await mockApi(page, '**/api/dns', (call: ApiCall) => randomAnswer(rng, host, String((call.body as { type: string }).type), '1.1.1.1', { kind: 'none' }), { method: 'POST' });
    await dns.open();
    await dns.selectTypes(['A']);
    for (const typed of typedForms) {
      expect(hostOf(typed), `oracle: host name of ${typed}`).toBe(host);
      const sentBefore = calls.length;
      await dns.submit(typed);
      await dns.waitForResult();
      const sent = calls.slice(sentBefore).map(call => (call.body as { domain: string }).domain);
      expect.soft(sent, `typed "${typed}": domain sent to POST /api/dns must be the host "${host}" (a port, query, fragment or user name is not part of a DNS name)`).toEqual([host]);
      expect.soft((await dns.view()).cards[0]?.value, `typed "${typed}": Domain card`).toBe(host);
    }
  });

  test('the Enter key runs the same lookup as the Lookup button', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const lookup = randomLookup(rng, { types: rng.sample(OFFERED_TYPES, 3) });
    const calls = await serveLookups(page, lookup);
    await dns.open();
    await runAndCheck(dns, lookup, geo, evidence, { via: 'button', label: `${describeLookup(lookup)} by button` });
    const byButton = calls.splice(0).map(call => call.body);
    await dns.open();
    await runAndCheck(dns, lookup, geo, evidence, { via: 'enter', label: `${describeLookup(lookup)} by Enter` });
    const sort = (list: typeof byButton) => [...list].sort((a, b) => String(a.type).localeCompare(String(b.type)));
    expect.soft(sort(calls.map(call => call.body)), 'requests sent by Enter equal the requests sent by the button').toEqual(sort(byButton));
    expectRequestsMatch(calls, lookup);
  });

  test('an empty or blank domain sends nothing and shows neither a result nor an error', async ({ page }) => {
    const dns = new DnsPage(page);
    const calls = await mockApi(page, '**/api/dns', { error: 'must not be called', records: [] }, { method: 'POST' });
    await dns.open();
    for (const typed of ['', '   ', '\t']) {
      await dns.domain.fill(typed);
      await expect.soft(dns.lookupButton, `Lookup stays disabled for ${JSON.stringify(typed)}`).toBeDisabled();
      await dns.domain.press('Enter');
    }
    // A slash-only or scheme-only text has no host either.
    for (const typed of ['/', 'https://', 'http:///path']) {
      await dns.domain.fill(typed);
      await dns.domain.press('Enter');
    }
    await expect(dns.lookupButton).toHaveText('Lookup');
    expect.soft(calls.length, 'no request may be sent without a host name').toBe(0);
    await expect.soft(dns.checkedAt, 'no result area').toHaveCount(0);
    await expect.soft(dns.alert, 'no error banner').toHaveCount(0);
  });

  test('each resolver choice is sent with the request and named on the Resolver card and in the side panel', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const lookups = rng.shuffle(RESOLVERS).map(resolver => randomLookup(rng, { resolver: resolver.value, types: rng.sample(OFFERED_TYPES, 2) }));
    const calls = await serveLookups(page, ...lookups);
    await dns.open();
    for (const lookup of lookups) {
      const sentBefore = calls.length;
      await runAndCheck(dns, lookup, geo, evidence);
      expectRequestsMatch(calls.slice(sentBefore), lookup);
      const label = RESOLVERS.find(r => r.value === lookup.resolver)!.label;
      expect.soft((await dns.queryDetails()).Resolver, `resolver ${lookup.resolver}: side panel`).toBe(label);
      await expect.soft(dns.resolver.locator('option:checked'), `resolver ${lookup.resolver}: select`).toHaveText(label);
    }
  });

  test('random selections of record types send one request per ticked type and show one section each', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const lookups = Array.from({ length: 4 }, () => randomLookup(rng, { types: rng.shuffle(rng.sample(OFFERED_TYPES, rng.int(1, 9))) }));
    const calls = await serveLookups(page, ...lookups);
    await dns.open();
    for (const lookup of lookups) {
      const sentBefore = calls.length;
      await runAndCheck(dns, lookup, geo, evidence);
      expectRequestsMatch(calls.slice(sentBefore), lookup);
      expect.soft(await dns.checkedTypes(), `${describeLookup(lookup)}: ticked boxes`).toEqual(OFFERED_TYPES.filter(type => lookup.types.includes(type)));
      const listed = (await dns.queryDetails())['Selected records'].split(', ').sort();
      expect.soft(listed, `${describeLookup(lookup)}: "Selected records" in the side panel`).toEqual([...lookup.types].sort());
    }
  });

  test('with no record type ticked the lookup is refused with a message and nothing is sent', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: ['NS'], kind: 'records' });
    const calls = await serveLookups(page, lookup);
    await dns.open();
    await dns.submit(lookup.domain, { types: [] });
    await expect(dns.alert, 'a clear message').toHaveText('Select at least one record type.');
    expect.soft(calls.length, 'no request without a record type').toBe(0);
    await expect.soft(dns.checkedAt, 'no result area').toHaveCount(0);
    expect.soft((await dns.queryDetails())['Selected records'], 'side panel').toBe('None selected');

    await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    await expect.soft(dns.alert, 'the message disappears once a valid lookup runs').toHaveCount(0);
  });

  test('a deep link fills the form and runs the lookup it describes', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const lookup = randomLookup(rng, { types: rng.sample(OFFERED_TYPES, rng.int(1, 4)), resolver: rng.pick(RESOLVERS.slice(1)).value });
    const calls = await serveLookups(page, lookup);
    await evidence.save('deep-link.json', lookup);
    // Types in lower case, an unknown type and extra spaces, as a hand-written link may have them.
    const typesParam = [...lookup.types.map(type => (rng.bool() ? type.toLowerCase() : type)), 'BOGUS'].join(', ');
    const before = Date.now();
    await dns.open(`?domain=${encodeURIComponent(`HTTPS://${lookup.domain.toUpperCase()}/x`)}&resolver=${lookup.resolver}&types=${encodeURIComponent(typesParam)}`);
    await dns.waitForResult();
    const ctx = `deep link for ${describeLookup(lookup)}`;
    expectViewMatches(await dns.view(), expectedView(lookup, geo), { ctx, maxQueryMs: Date.now() - before });
    expectRequestsMatch(calls, lookup, ctx);
    await expect.soft(dns.domain, `${ctx}: domain box`).toHaveValue(lookup.domain);
    await expect.soft(dns.resolver, `${ctx}: resolver select`).toHaveValue(lookup.resolver);
    expect.soft(await dns.checkedTypes(), `${ctx}: ticked types (unknown ones ignored)`).toEqual(OFFERED_TYPES.filter(type => lookup.types.includes(type)));

    // Reloading the link runs the same lookup again.
    calls.splice(0);
    await page.reload();
    await dns.waitForResult();
    expectViewMatches(await dns.view(), expectedView(lookup, geo), { ctx: `${ctx} after reload` });
    expectRequestsMatch(calls, lookup, `${ctx} after reload`);
  });

  test('a deep link with only a domain uses the default record types and resolver', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: DEFAULT_TYPES, resolver: RESOLVERS[0].value });
    const calls = await serveLookups(page, lookup);
    await evidence.save('deep-link-default.json', lookup);
    await dns.open(`?domain=${lookup.domain}`);
    await dns.waitForResult();
    expectViewMatches(await dns.view(), expectedView(lookup, await GeoOracle.load(baseURL!)), { ctx: `deep link ?domain=${lookup.domain}` });
    expectRequestsMatch(calls, lookup);
  });

  test('a deep link naming a resolver the tool does not offer never shows one resolver while using another', async ({ page, rng, evidence }) => {
    // "Open Live Lookup" on a shared global snapshot produces exactly this link (resolver=global).
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: ['A'], kind: 'none' });
    const unsupported = rng.pick(['global', '9.9.9.9']);
    await evidence.save('deep-link-resolver.json', { unsupported, lookup });
    const calls = await routeDns(page, () => lookup.replies.A);
    await dns.open(`?domain=${lookup.domain}&resolver=${unsupported}&types=A`);
    await dns.waitForResult();

    const selected = await dns.resolver.locator('option:checked').evaluate(option => ({ value: (option as HTMLOptionElement).value, label: option.textContent ?? '' }));
    const offered = RESOLVERS.map(r => r.value as string);
    expect.soft(offered, `resolver sent with the request for ?resolver=${unsupported} must be one the tool offers`).toContain(calls[0]?.body.resolver);
    expect.soft(calls[0]?.body.resolver, `the request must use the resolver the form shows as selected ("${selected.label}")`).toBe(selected.value);
    expect.soft((await dns.view()).cards.find(card => card.label === 'Resolver')?.value, `Resolver card must name the resolver the form shows as selected for ?resolver=${unsupported}`).toBe(selected.label);
    expect.soft((await dns.queryDetails()).Resolver, 'side panel Resolver must name the selected resolver').toBe(selected.label);
  });

  test('the side panel links to the SSL and WHOIS tools carry the host name being typed', async ({ page, rng }) => {
    const dns = new DnsPage(page);
    await dns.open();
    const host = randomDomain(rng);
    for (const typed of [host, `https://${host.toUpperCase()}/path`, `  ${host} `]) {
      await dns.domain.fill(typed);
      for (const [name, route] of [['SSL Certificate Checker', '/ssl'], ['WHOIS Lookup', '/whois']] as const) {
        await expect.soft(dns.investigateLink(name), `typed ${JSON.stringify(typed)}: ${name} link`).toHaveAttribute('href', `${route}?domain=${encodeURIComponent(host)}`);
      }
    }
    await dns.domain.fill('');
    await expect.soft(dns.investigateLink('WHOIS Lookup'), 'no domain parameter for an empty box').toHaveAttribute('href', '/whois');
    await dns.domain.fill(host);
    await dns.investigateLink('WHOIS Lookup').click();
    await expect(page, 'the WHOIS link opens the WHOIS tool for the same domain').toHaveURL(new RegExp(`/whois\\?domain=${host.replace(/\./g, '\\.')}$`));
  });
});

test.describe('DNS Lookup — results match the API answer', () => {
  test('every record type on its own: all records, fields, counts and cards', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const lookups = rng.shuffle(OFFERED_TYPES).map(type => randomLookup(rng, { types: [type], kind: 'records' }));
    const calls = await serveLookups(page, ...lookups);
    await dns.open();
    for (const lookup of lookups) {
      const sentBefore = calls.length;
      await runAndCheck(dns, lookup, geo, evidence);
      expectRequestsMatch(calls.slice(sentBefore), lookup);
      await expect.soft(dns.recordTables.first(), `${describeLookup(lookup)}: the record table is visible`).toBeVisible();
    }
    await expectNoMarkupExecuted(page, 'after ten single-type lookups');
  });

  test('all ten record types in one lookup, sections in the documented order', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: rng.shuffle(OFFERED_TYPES) });
    const calls = await serveLookups(page, lookup);
    await dns.open();
    const { shown } = await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    expectRequestsMatch(calls, lookup);
    expect.soft(shown.sections.map(section => section.heading.replace(' Records', '')), 'section order').toEqual([...SECTION_ORDER]);
    await expectNoMarkupExecuted(page, describeLookup(lookup));
  });

  test('random mixes of record counts (none, one, many), answers without records and failed types', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const lookups = Array.from({ length: 4 }, () => randomLookup(rng, { types: rng.sample(OFFERED_TYPES, rng.int(3, 8)) }));
    // Make sure a large record set is part of every run.
    const big = lookups[0];
    big.replies[big.types[0]] = answer(randomAnswer(rng, big.domain, big.types[0], big.resolver, { kind: 'records', count: rng.int(45, 70) }));
    const calls = await serveLookups(page, ...lookups);
    await dns.open();
    for (const lookup of lookups) {
      const sentBefore = calls.length;
      await runAndCheck(dns, lookup, geo, evidence);
      expectRequestsMatch(calls.slice(sentBefore), lookup);
    }
    await expectNoMarkupExecuted(page, 'after four mixed lookups');
  });

  test('TTLs on every unit boundary are humanised correctly and keep the exact seconds as tooltip', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const domain = randomDomain(rng);
    const ttls = [...TTL_EDGES, ...Array.from({ length: 12 }, () => rng.int(0, 1_000_000))];
    const lookup: Lookup = {
      domain, resolver: '1.1.1.1', types: ['NS'],
      replies: { NS: answer({ domain, type: 'NS', resolver: '1.1.1.1', status: 0, _type: 'NS', dns_provider: UNKNOWN, hosting_provider: UNKNOWN, records: ttls.map((TTL, i) => ({ name: domain, type: 'NS', TTL, data: `ns${i}.${domain}` })) }) },
    };
    await serveLookups(page, lookup);
    await dns.open();
    const { shown } = await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    // The same check written out, so a failure names the TTL.
    ttls.forEach((ttl, i) => {
      const cell = shown.sections[0]?.rows[i]?.[1];
      expect.soft(cell?.text, `TTL ${ttl} seconds is shown as`).toBe(humanTtl(ttl));
      expect.soft(cell?.title, `TTL ${ttl} seconds: tooltip`).toBe(`${ttl} seconds`);
    });
    // Spot values fixed by hand, independent of the oracle function.
    const byHand: [number, string][] = [[0, '0s'], [59, '59s'], [60, '1m 0s'], [3599, '59m 59s'], [3600, '1h 0m'], [86399, '23h 59m'], [86400, '1d 0h'], [90000, '1d 1h'], [604800, '7d 0h']];
    for (const [ttl, text] of byHand) expect(humanTtl(ttl), `oracle self-check: ${ttl}s`).toBe(text);
  });

  test('MX records show their priority next to the mail host, in the order the resolver returned them', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const domain = randomDomain(rng);
    const records = randomRecords(rng, 'MX', domain, 8);
    [1, 5, 10, 10, 20, 100, 32768, 65535].forEach((priority, i) => { records[i].priority = priority; });
    const lookup: Lookup = { domain, resolver: '8.8.8.8', types: ['MX'], replies: { MX: answer({ domain, type: 'MX', resolver: '8.8.8.8', status: 0, _type: 'MX', records: rng.shuffle(records), dns_provider: UNKNOWN, hosting_provider: UNKNOWN }) } };
    await serveLookups(page, lookup);
    await dns.open();
    await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
  });

  test('an MX priority of 0 is shown as 0, not as an empty cell', async ({ page, rng, evidence, baseURL }) => {
    // Priority 0 is valid and common (RFC 5321 section 5.1; RFC 7505 "null MX" uses it).
    const dns = new DnsPage(page);
    const domain = randomDomain(rng);
    const records = [
      { name: domain, type: 'MX', TTL: 300, data: `mail.${domain}`, value: `mail.${domain}`, priority: 0 },
      { name: domain, type: 'MX', TTL: 300, data: `backup.${domain}`, value: `backup.${domain}`, priority: 10 },
    ];
    const lookup: Lookup = { domain, resolver: '1.1.1.1', types: ['MX'], replies: { MX: answer({ domain, type: 'MX', resolver: '1.1.1.1', status: 0, _type: 'MX', records, dns_provider: UNKNOWN, hosting_provider: UNKNOWN }) } };
    await serveLookups(page, lookup);
    await dns.open();
    await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
  });

  test('the provider cards show the most confident detection among the per-type answers', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const lookups = [
      ...Array.from({ length: 3 }, () => randomLookup(rng, { types: rng.sample(OFFERED_TYPES, rng.int(3, 6)), providers: 'mixed', kind: 'records' })),
      randomLookup(rng, { types: rng.sample(OFFERED_TYPES, 3), providers: 'same', kind: 'records' }),
      randomLookup(rng, { types: rng.sample(OFFERED_TYPES, 3), providers: 'unknown', kind: 'records' }),
    ];
    // An answer that lacks the provider objects entirely (the backend omits them on some failures).
    const bare = lookups[4];
    delete (bare.replies[bare.types[0]] as { body: ApiAnswer }).body.dns_provider;
    delete (bare.replies[bare.types[0]] as { body: ApiAnswer }).body.hosting_provider;
    await serveLookups(page, ...lookups);
    await dns.open();
    for (const lookup of lookups) {
      const { want } = await runAndCheck(dns, lookup, geo, evidence);
      await evidence.save(`expected-providers-${lookup.domain}.json`, { dns: want.dnsProvider, hosting: want.hostingProvider });
    }
  });

  test('answers without records show the resolver message, a fallback text, and the "nothing returned" banner', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const nxdomain = randomLookup(rng, { types: rng.sample(OFFERED_TYPES, 4), kind: 'nxdomain', providers: 'unknown' });
    const empty = randomLookup(rng, { types: rng.sample(OFFERED_TYPES, 3), kind: 'none' });
    // An answer with no records and no message at all.
    const silent = randomLookup(rng, { types: ['CAA', 'SOA'], kind: 'none' });
    for (const type of silent.types) silent.replies[type] = answer({ records: [], status: 0, _type: type });
    // One type has records: the banner must not appear.
    const partial = randomLookup(rng, { types: ['A', 'MX', 'TXT'], kind: 'none' });
    partial.replies.MX = answer(randomAnswer(rng, partial.domain, 'MX', partial.resolver, { kind: 'records', count: 2 }));
    await serveLookups(page, nxdomain, empty, silent, partial);
    await dns.open();
    for (const lookup of [nxdomain, empty, silent, partial]) {
      const { want } = await runAndCheck(dns, lookup, geo, evidence);
      await expect.soft(dns.recordTables, `${describeLookup(lookup)}: record tables`).toHaveCount(want.sections.filter(s => s.state === 'table').length);
      await expect.soft(dns.copyAllButton, `${describeLookup(lookup)}: "Copy All Records" is offered only when there are records`).toHaveCount(want.totalRecords > 0 ? 1 : 0);
    }
  });

  test('a type the resolver could not answer shows its error text while the other types show their records', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: ['A', 'MX', 'NS', 'TXT', 'SOA', 'CAA'], kind: 'records' });
    lookup.replies.MX = answer({ error: 'DNS lookup failed with SERVFAIL.', records: [], status: 2, _type: 'MX', dns_provider: UNKNOWN, hosting_provider: UNKNOWN });
    lookup.replies.SOA = answer({ error: 'DNS resolver returned HTTP 502', records: [], _type: 'SOA' });
    lookup.replies.CAA = answer({ error: `Invalid record type: ${MARKUP_PROBES[0]}`, records: [] });
    await serveLookups(page, lookup);
    await dns.open();
    await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    await expectNoMarkupExecuted(page, describeLookup(lookup));
  });

  test('markup in record values, messages, errors and provider names is shown as text and never executed', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const domain = randomDomain(rng);
    const evil = { slug: 'x', name: `Evil ${MARKUP_PROBES[0]} DNS & Co`, confidence: 'high', source: MARKUP_PROBES[2], matched_on: MARKUP_PROBES[1] };
    const base = { domain, resolver: '1.1.1.1', status: 0, dns_provider: evil, hosting_provider: evil };
    const lookup: Lookup = {
      domain, resolver: '1.1.1.1', types: ['TXT', 'CNAME', 'MX', 'NS', 'SRV'],
      replies: {
        TXT: answer({ ...base, type: 'TXT', _type: 'TXT', records: awkwardTxtValues(rng).map(data => ({ name: domain, type: 'TXT', TTL: rng.int(1, 9999), data })) }),
        CNAME: answer({ ...base, type: 'CNAME', _type: 'CNAME', records: MARKUP_PROBES.map(data => ({ name: domain, type: 'CNAME', TTL: 60, data })) }),
        MX: answer({ ...base, type: 'MX', _type: 'MX', records: [{ name: domain, type: 'MX', TTL: 60, data: MARKUP_PROBES[0], value: MARKUP_PROBES[0], priority: 10 }] }),
        NS: answer({ ...base, type: 'NS', _type: 'NS', records: [], noRecords: true, message: `No NS records found for ${MARKUP_PROBES[0]}.` }),
        SRV: answer({ error: `DNS query failed: ${MARKUP_PROBES[1]}`, records: [], _type: 'SRV' }),
      },
    };
    await serveLookups(page, lookup);
    await dns.open();
    await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    await expectNoMarkupExecuted(page, describeLookup(lookup));
  });

  test('A and AAAA records show the country and the network operator of each address from the GeoLite2 files', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const domain = randomDomain(rng);
    // Well-known operators (brand names), an address without a country in the database (anycast),
    // private and documentation addresses (not in the database), plus random public addresses.
    const v4 = ['8.8.8.8', '1.1.1.1', '13.107.42.14', '52.95.110.1', '151.101.1.69', '23.192.228.80', '139.162.130.5', '192.0.43.8', '10.1.2.3', '192.0.2.55', '127.0.0.1',
      ...Array.from({ length: 12 }, () => [rng.int(1, 223), rng.int(0, 255), rng.int(0, 255), rng.int(1, 254)].join('.'))];
    const v6 = ['2606:4700::1111', '2001:4860:4860::8888', '2001:500:88:200::8', '2a00:1450:4001:81b::200e', '2600:1f18:2148:bc00:8d79:f571:1b18:2b9a', '2001:db8::1', 'fe80::1', '::1',
      ...Array.from({ length: 8 }, () => `${rng.pick(['2001', '2400', '2600', '2a00', '2a02', '2c0f', '2800'])}:${rng.int(0, 0xffff).toString(16)}:${rng.int(0, 0xffff).toString(16)}::${rng.int(1, 0xffff).toString(16)}`)];
    const base = { domain, resolver: '1.1.1.1', status: 0, dns_provider: UNKNOWN, hosting_provider: UNKNOWN };
    const lookup: Lookup = {
      domain, resolver: '1.1.1.1', types: ['A', 'AAAA'],
      replies: {
        A: answer({ ...base, type: 'A', _type: 'A', records: v4.map(data => ({ name: domain, type: 'A', TTL: 300, data })) }),
        AAAA: answer({ ...base, type: 'AAAA', _type: 'AAAA', records: v6.map(data => ({ name: domain, type: 'AAAA', TTL: 300, data })) }),
      },
    };
    await evidence.save('geo-expected.json', [...v4, ...v6].map(ip => ({ ip, ...geo.facts(ip) })));
    await serveLookups(page, lookup);
    await dns.open();
    await runAndCheck(dns, lookup, geo, evidence);

    // The oracle's own reading of the database must be plausible, or the comparison above proves nothing.
    expect(geo.facts('8.8.8.8'), 'oracle self-check: 8.8.8.8').toMatchObject({ brand: 'Google', countryCode: 'US', location: '🇺🇸 United States' });
    expect(geo.facts('10.1.2.3'), 'oracle self-check: private address').toMatchObject({ brand: 'Unknown', location: 'Unknown' });
  });

  test('when the GeoLite2 files cannot be loaded the records are still shown, without location or provider', async ({ page, rng, evidence, guard }) => {
    guard.allow(/GeoLite2|GeoIP|geoip/i);
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: ['A', 'AAAA', 'NS'], kind: 'records' });
    await serveLookups(page, lookup);
    await page.route('**/data/GeoLite2-*.mmdb*', route => route.abort('failed'));
    await dns.open();
    // geo = null: Location is a dash and Provider "Unknown" for every address.
    await runAndCheck(dns, lookup, null, evidence);
  });

  test('the query time of a section is the time its own request took', async ({ page, rng, evidence }) => {
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: ['NS', 'TXT'], kind: 'records' });
    const slowMs = rng.int(600, 900);
    await evidence.save('slow-lookup.json', { slowMs, lookup });
    await routeDns(page, call => ({
      reply: lookup.replies[String(call.body.type)],
      hold: call.body.type === 'TXT' ? new Promise(resolve => setTimeout(resolve, slowMs)) : undefined,
    }));
    await dns.open();
    const before = Date.now();
    await dns.run(lookup);
    const elapsed = Date.now() - before;
    const shown = await dns.view();
    const ms = (heading: string) => Number(shown.sections.find(s => s.heading === heading)?.counter.match(/(\d+)ms$/)?.[1]);
    expect.soft(ms('TXT Records'), `TXT answer was held for ${slowMs}ms: its query time`).toBeGreaterThanOrEqual(slowMs - 20);
    expect.soft(ms('TXT Records'), 'TXT query time cannot exceed the whole lookup').toBeLessThanOrEqual(elapsed + 100);
    expect.soft(ms('NS Records'), 'NS answer was immediate: its query time is below the TXT delay').toBeLessThan(slowMs - 20);
  });

  test('a random label in the domain is echoed exactly on the Domain card and in every message', async ({ page, rng, evidence, baseURL }) => {
    // Long names and labels with digits and hyphens must not be shortened or altered.
    const dns = new DnsPage(page);
    const domain = `${randomLabel(rng, 50, 63)}.${randomLabel(rng, 40, 63)}.${randomLabel(rng, 30, 63)}.example`;
    const lookup = randomLookup(rng, { domain, types: ['A', 'CNAME'], kind: 'none' });
    await serveLookups(page, lookup);
    await dns.open();
    // Submitted with Enter: a pointer resting on the Lookup button starts its hover animation, which the audit would measure.
    await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence, { via: 'enter' });
    await expectNoUiGlitches(page, `${ROUTE} with a ${domain.length}-character domain`);
  });
});
