import { test, expect } from '../_support/fixtures';
import { expectToolLinkedFromHome } from '../_support/navigation';
import { expectNoUiGlitches, expectControlsUsable, VIEWPORTS } from '../_support/ui-audit';
import { captureApi, captureDownload, clearClipboard, failApi, mockApi, readClipboard } from '../_support/io';
import { randomScenario, randomScenarios, type Scenario } from './generator';
import { formatV4, cidrFirst, cidrLast, readCount } from './oracle';
import { expectExplorer, expectOverview, expectReport, mockLookups, openWith, DEFAULT_EXPLORER } from './checks';
import {
  AsnView, HEADING, LOOKUP_API, QUICK_ASNS, ROUTE, ShareDialog,
  emptyState, errorBanner, gateApi, loadingStatus, lookup, lookupButton, openAsn, primary, quickChip,
  searchInput, submitLookup,
} from './page';

/**
 * ASN to IPs Converter & BGP Intelligence (/asn) — server-backed lookup, everything after it runs in the browser.
 *
 * Files: asn.spec.ts (access, layout, lookup, overview, BGP tab, report, failures, state) · asn-prefixes.spec.ts
 * (prefix explorer) · asn-firewall.spec.ts (rule generator, POST /api/asn/generate-rules) · asn-ipmatch.spec.ts
 * (IP tester, POST /api/asn/match-ip) · asn-share.spec.ts (share dialog, /s/<code>) · asn-live.spec.ts (@live).
 * Oracle: ./oracle.ts (BigInt). Inputs: ./generator.ts (random networks, each run).
 *
 * INVENTORY
 * Inputs
 *  - Search box (ASN `AS15169`/`15169`/`as15169`, IP, domain, organisation name); sent trimmed as `{asn}` to POST /api/asn.
 *    The page does no validation of its own; the backend normalises and validates.
 *  - Lookup ASN button, Enter key, eight "Quick ASNs" chips, URL parameters `asn`, `q`, `domain`, `ip`.
 *  - Prefix filter box, IP tester box, share dialog: title, expiry, password. Shared view: password box.
 * Controls
 *  - Tabs: Prefix Explorer (n) · Firewall & ACL Generator · IP Range Matcher · BGP & Network Intel.
 *  - Explorer: mask chips (All Masks + one per IPv4 length), ALL/IPV4/IPV6, Raw Prefixes ⇄ Aggregated Supernets,
 *    Copy Visible, CSV, row copy button, pagination « First ‹ Prev Next › Last » (25 rows per page).
 *  - Firewall: format (13), action (deny/allow), IP version scope (both/IPv4/IPv6), merge checkbox, Copy Rules, Save File.
 *  - Tester: Test IP button, Enter. BGP: Inspect › on each neighbour. Header: Share Snapshot, Copy Summary, Export.
 *  - Shared view: Unlock, Run Live Lookup (no Share, no Inspect).
 * Displayed values
 *  - Header: AS badge, holder, country chip, registry chip, BGP status chip, description, "Resolved from …" note.
 *  - Cards: IPv4 prefixes + address total, IPv6 prefixes, CIDR optimization % + rules saved, BGP peers + upstream/downstream.
 *  - Explorer table: #, prefix, range, address count, netmask, wildcard; chip counts; tab count; aggregation banner;
 *    "Showing a–b of n prefixes"; "Page x of y"; empty-list message.
 *  - Firewall: rule text, "n lines generated". Tester: verdict, prefix, range, netmask, total.
 *  - BGP: three neighbour counts, top neighbours, holder, registry, country, abuse e-mails. Footer: source and UTC time,
 *    share code (shared view). Shared view header: title, created and expiry dates.
 * Outputs
 *  - Clipboard: Copy Summary, Copy Visible, row copy, Copy Rules, share link Copy.
 *  - Downloads: Export (AS<n>-report.txt), CSV (AS<n>-prefixes.csv), Save File (AS<n>-<format>-<action>.<ext>).
 *  - Share link (POST /api/share/asn) and the shared view /s/<code>, with and without password.
 *  - Requests: POST /api/asn {asn}; POST /api/share/asn {title, asn, expiry, password, checked_at_utc, snapshot}.
 * States
 *  - Empty, loading, result (four tabs), error (400/404/429/500, 200 with `error`, network failure), share dialog
 *    (form, link ready, error), shared view (loading, password prompt, wrong password, snapshot, not found).
 * Not in the UI (checked through the API only): POST /api/asn/search, /api/asn/match-ip, /api/asn/generate-rules are
 *  not called by the frontend; the tester and the generator run in the browser. JSON and HTML exports exist in the
 *  code (downloadExport) but no control triggers them. There are no recent searches and nothing is kept in localStorage.
 *
 * LAYERS: 1 access · 2 layout (this file; share dialog and shared view in asn-share) · 3 input paths · 4 values (all files) · 5 controls
 *  (asn-prefixes, asn-firewall) · 6 copy/export/share/requests · 7 failures (this file, asn-ipmatch) · 8 state (this file).
 */

const CONTROLS = {
  'search box': 'input[placeholder^="e.g. AS13335"]',
  'Lookup ASN button': '.input-card button.btn-primary',
  'first quick ASN chip': '.input-card button[type="button"]',
};

test.describe('ASN lookup — access and layout', () => {
  test('is linked from the home page and the sidebar', async ({ page }) => {
    await expectToolLinkedFromHome(page, ROUTE);
    await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
  });

  test('opens with its controls ready, eight network shortcuts and an empty result area', async ({ page }) => {
    await openAsn(page);
    await expect(page).toHaveTitle(/ASN/);
    await expectControlsUsable(page, CONTROLS);
    await expect(searchInput(page), 'the search box starts empty').toHaveValue('');
    await expect(lookupButton(page)).toHaveText('Lookup ASN');
    const chips = await page.locator('.input-card button[type="button"]').allTextContents();
    expect.soft(chips, 'quick ASN chips, in order').toEqual(QUICK_ASNS.map(c => `${c.label} (AS${c.asn})`));
    await expect(emptyState(page), 'empty state before the first lookup').toBeVisible();
    await expect(errorBanner(page)).toHaveCount(0);
    await expect(loadingStatus(page)).toHaveCount(0);
    await expect(primary(page).locator('table'), 'no result before a lookup').toHaveCount(0);
    await expect(page.getByRole('complementary', { name: 'Network intelligence' }), 'guide panel').toBeVisible();
  });

  for (const [name, viewport] of Object.entries(VIEWPORTS)) {
    test(`has no layout problems at ${name} size (${viewport.width}px) in any state of the page`, async ({ page, rng, evidence, guard }) => {
      guard.allow(/status of 400/);
      const scenario = randomScenario(rng, { v4Count: 34, v6Count: 6 });
      await evidence.save('asn-response.json', scenario.payload);
      const gate = await gateApi(page, LOOKUP_API, (_call, index) => index === 0
        ? { body: scenario.payload }
        : { status: 400, body: { error: 'Could not resolve "nonsense" to a valid ASN. Please enter an ASN number (e.g. AS13335), IP, or domain.' } });
      const at = (state: string) => `${ROUTE} ${state} @${name}`;

      await page.setViewportSize(viewport);
      await openAsn(page);
      await expectNoUiGlitches(page, at('empty state'));

      await submitLookup(page, scenario.asn);
      await expect(loadingStatus(page)).toBeVisible();
      await expectNoUiGlitches(page, at('loading state'));
      gate.release();

      const view = new AsnView(page, primary(page));
      await expect(view.badge()).toHaveText(`AS${scenario.asn}`);
      await expectNoUiGlitches(page, at('result, prefix explorer page 1'));
      await view.pager('Last').click();
      await expectNoUiGlitches(page, at('result, prefix explorer last page'));
      await view.aggregateToggle().click();
      await expect(view.aggregateBanner()).toBeVisible();
      await expectNoUiGlitches(page, at('prefix explorer, aggregated supernets'));
      await view.filterInput().fill('no-such-prefix');
      await expect(view.noRowsMessage()).toBeVisible();
      await expectNoUiGlitches(page, at('prefix explorer, filter without matches'));

      await view.tab('firewall').click();
      await expect(view.rulesOutput()).toBeVisible();
      await expectNoUiGlitches(page, at('firewall tab, nginx rules'));
      await view.setRules({ format: 'aws_sg', action: 'allow', scope: 'ipv6' });
      await expectNoUiGlitches(page, at('firewall tab, AWS JSON for IPv6'));

      await view.tab('tester').click();
      await view.testAddress(formatV4(cidrFirst(scenario.v4[0])));
      await expectNoUiGlitches(page, at('IP tester, match'));
      await view.testAddress('203.0.113.77');
      await expectNoUiGlitches(page, at('IP tester, no match'));

      await view.tab('bgp').click();
      await expect(view.contactField('Network Holder / Org')).toBeVisible();
      await expectNoUiGlitches(page, at('BGP tab'));

      await submitLookup(page, 'nonsense');
      await expect(errorBanner(page)).toBeVisible();
      await expectNoUiGlitches(page, at('error state'));
    });
  }
});

test.describe('ASN lookup — input paths and the request', () => {
  test('whatever is typed is sent once, trimmed and otherwise unchanged', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: 3, v6Count: 1 });
    const calls = await mockApi(page, LOOKUP_API, scenario.payload, { method: 'POST' });
    await openAsn(page);
    const typed = [
      'AS15169', '15169', 'as15169', '  AS15169  ', 'As15169', '1.1.1.1', '2606:4700::1111', 'google.com', 'Cloudflare',
      'AS4294967295', '4294967296', '0', '-5', 'some text', String(rng.int(1, 4294967295)),
    ];
    await evidence.save('typed-inputs.json', typed);
    for (const [i, text] of typed.entries()) {
      await submitLookup(page, text);
      await expect.poll(() => calls.length, { message: `"${text}" should send exactly one request` }).toBe(i + 1);
      await expect(new AsnView(page, primary(page)).badge()).toBeVisible();
      expect.soft(calls[i].method, `"${text}": request method`).toBe('POST');
      expect.soft(calls[i].body, `"${text}": request body`).toEqual({ asn: text.trim() });
      await expect.soft(searchInput(page), `"${text}": search box after the lookup`).toHaveValue(text.trim());
    }
    expect(calls.length, 'one request per lookup, none extra').toBe(typed.length);
  });

  test('Enter in the search box runs the lookup like the button does', async ({ page, rng }) => {
    const scenario = randomScenario(rng, { v4Count: 12, v6Count: 3 });
    const calls = await mockApi(page, LOOKUP_API, scenario.payload, { method: 'POST' });
    await openAsn(page);
    await searchInput(page).fill(`AS${scenario.asn}`);
    await searchInput(page).press('Enter');
    const view = new AsnView(page, primary(page));
    await expect(view.badge()).toHaveText(`AS${scenario.asn}`);
    expect(calls.map(c => c.body), 'request sent by Enter').toEqual([{ asn: `AS${scenario.asn}` }]);
    await expectOverview(view, scenario, `AS${scenario.asn} via Enter`);
    await expectExplorer(view, scenario, DEFAULT_EXPLORER, `AS${scenario.asn} via Enter`);
  });

  test('each quick ASN chip looks up its own network and fills the search box', async ({ page, rng }) => {
    const scenarios = new Map(QUICK_ASNS.map(chip => [chip.asn, randomScenario(rng, { asn: chip.asn, v4Count: 4, v6Count: 2 })]));
    const calls = await mockLookups(page, [...scenarios.values()]);
    await openAsn(page);
    for (const [i, chip] of rng.shuffle(QUICK_ASNS).entries()) {
      await quickChip(page, chip.asn).click();
      const view = new AsnView(page, primary(page));
      await expect(view.badge(), `chip "${chip.label}" should show AS${chip.asn}`).toHaveText(`AS${chip.asn}`);
      expect.soft(calls[i]?.body, `chip "${chip.label}": request body`).toEqual({ asn: chip.asn });
      await expect.soft(searchInput(page), `chip "${chip.label}": search box`).toHaveValue(chip.asn);
      await expectOverview(view, scenarios.get(chip.asn) as Scenario, `chip "${chip.label}"`);
    }
    expect(calls.length, 'one request per chip').toBe(QUICK_ASNS.length);
  });

  test('a link with ?asn=, ?q=, ?domain= or ?ip= fills the search box and runs the lookup', async ({ page, rng }) => {
    const scenario = randomScenario(rng, { v4Count: 5, v6Count: 2 });
    const calls = await mockApi(page, LOOKUP_API, scenario.payload, { method: 'POST' });
    const links: [string, string][] = [
      [`asn=AS${scenario.asn}`, `AS${scenario.asn}`],
      [`q=${scenario.asn}`, scenario.asn],
      ['domain=example.org', 'example.org'],
      ['ip=198.51.100.7', '198.51.100.7'],
      [`asn=%20%20${scenario.asn}%20`, scenario.asn],
    ];
    for (const [i, [query, expected]] of links.entries()) {
      await page.goto(`${ROUTE}?${query}`, { waitUntil: 'domcontentloaded' });
      const view = new AsnView(page, primary(page));
      await expect(view.badge(), `/asn?${query} should show a result without a click`).toHaveText(`AS${scenario.asn}`);
      expect.soft(calls.length, `/asn?${query}: requests sent so far`).toBe(i + 1);
      expect.soft(calls[i]?.body, `/asn?${query}: request body`).toEqual({ asn: expected });
      await expect.soft(searchInput(page), `/asn?${query}: search box`).toHaveValue(expected);
    }
    await expectOverview(new AsnView(page, primary(page)), scenario, 'deep link result');
  });

  test('an empty or blank search box sends nothing and keeps the empty state', async ({ page }) => {
    const calls = await mockApi(page, LOOKUP_API, { error: 'must not be called' }, { method: 'POST' });
    await openAsn(page);
    for (const text of ['', '   ', '\t']) {
      await submitLookup(page, text);
      await searchInput(page).press('Enter');
      await expect(emptyState(page), `blank input ${JSON.stringify(text)} keeps the empty state`).toBeVisible();
      await expect(errorBanner(page)).toHaveCount(0);
      await expect(loadingStatus(page)).toHaveCount(0);
    }
    expect(calls.length, 'no request for blank input').toBe(0);
  });
});

test.describe('ASN lookup — the overview shows the response', () => {
  test('header, cards, tab count and footer for random networks, one after another', async ({ page, rng, evidence }) => {
    const variants: Record<string, unknown>[] = [
      {},
      { country_code: '', rir: '', description: '', announced: false, abuse_emails: [] },
      { neighbours: { upstreams_count: 0, downstreams_count: 0, peers_count: 0, top_peers: [] } },
      { neighbours: { upstreams_count: 1234, downstreams_count: 56789, peers_count: 1234567, top_peers: [] }, announced: true },
    ];
    const scenarios = randomScenarios(rng, variants.map((overrides, i) => ({
      overrides, v4Count: [14, 1, 30, 1100][i], v6Count: [5, 0, 1, 1003][i],
    })));
    await evidence.save('asn-responses.json', scenarios.map(s => s.payload));
    await mockLookups(page, scenarios);
    await openAsn(page);
    for (const scenario of scenarios) {
      const view = await lookup(page, scenario.asn, scenario.asn);
      await expectOverview(view, scenario, `AS${scenario.asn} (${scenario.v4.length} IPv4, ${scenario.v6.length} IPv6)`);
      expect.soft(await view.tabCount(), `AS${scenario.asn}: Prefix Explorer tab count`).toBe(scenario.v4.length + scenario.v6.length);
    }
  });

  test('the "Resolved from" note names the domain, the IP or the organisation that was typed', async ({ page, rng }) => {
    const notes = [
      { input: 'example.org', type: 'domain', ip: '198.51.100.7', domain: 'example.org', matched_prefix: '198.51.100.0/24' },
      { input: '2001:db8::7', type: 'ip', ip: '2001:db8::7', domain: null, matched_prefix: '2001:db8::/32' },
      { input: 'cloudfl', type: 'org_search', matched_org: 'Cloudflare' },
      null,
    ];
    const scenarios = randomScenarios(rng, notes.map(resolved_from => ({ v4Count: 3, v6Count: 1, overrides: { resolved_from } })));
    await mockLookups(page, scenarios);
    await openAsn(page);
    for (const scenario of scenarios) {
      const view = await lookup(page, scenario.asn, scenario.asn);
      await expectOverview(view, scenario, `resolved_from ${JSON.stringify(scenario.payload.resolved_from)}`);
    }
  });

  test('markup in the holder name, description and error text is shown as text, never run', async ({ page, rng, guard }) => {
    guard.allow(/status of 400/);
    const holder = '<img src=x onerror=alert(1)>';
    const scenario = randomScenario(rng, {
      holder, v4Count: 3, v6Count: 1,
      overrides: { description: '<script>alert(2)</script><b>bold</b>', country_code: '<i>X</i>', rir: '<u>RIR</u>', abuse_emails: ['"><svg onload=alert(3)>@example.org'] },
    });
    const dialogs: string[] = [];
    page.on('dialog', dialog => { dialogs.push(dialog.message()); void dialog.dismiss(); });
    const gate = await gateApi(page, LOOKUP_API, (_call, index) => index === 0
      ? { body: scenario.payload }
      : { status: 400, body: { error: `Could not resolve "${holder}" to a valid ASN.` } });
    gate.release();
    await openAsn(page);
    const view = await lookup(page, scenario.asn, scenario.asn);
    await expectOverview(view, scenario, 'holder with markup');
    await view.tab('tester').click();
    await expect.soft(primary(page).getByText(`belongs to AS${scenario.asn} (${holder}).`), 'tester intro shows the holder as text').toBeVisible();
    await view.tab('bgp').click();
    await expect.soft(view.contactField('Network Holder / Org'), 'BGP tab holder').toHaveText(holder);
    await expect.soft(view.contactField('Country Jurisdiction'), 'BGP tab country').toHaveText('<i>X</i>');
    await view.tab('firewall').click();
    expect.soft((await view.readRules()).split('\n')[0], 'rule header keeps the holder as text').toContain(`(${holder})`);
    await view.shareButton().click();
    await expect.soft(new ShareDialog(page).titleInput(), 'share title proposal').toHaveValue(`AS${scenario.asn} - ${holder} Intelligence Snapshot`);
    await new ShareDialog(page).cancelButton().click();

    await submitLookup(page, holder);
    await expect(errorBanner(page), 'error text with markup').toHaveText(`Could not resolve "${holder}" to a valid ASN.`);
    for (const selector of ['img[src="x"]', 'main script', 'main svg', 'main b', 'main u']) {
      expect.soft(await page.locator(selector).count(), `no <${selector}> element may be created from response text`).toBe(0);
    }
    expect.soft(dialogs, 'no script from the response may run').toEqual([]);
  });
});

test.describe('ASN lookup — BGP & Network Intel tab', () => {
  test('neighbour counts, top neighbours and contacts equal the response', async ({ page, rng, evidence }) => {
    const scenarios = randomScenarios(rng, [
      { v4Count: 4, v6Count: 2, overrides: { abuse_emails: ['abuse@example.net', 'noc@example.net'] } },
      { v4Count: 4, v6Count: 2, overrides: { abuse_emails: [], country_code: '', rir: '', neighbours: { upstreams_count: 0, downstreams_count: 0, peers_count: 0, top_peers: [] } } },
    ]);
    await evidence.save('asn-responses.json', scenarios.map(s => s.payload));
    await mockLookups(page, scenarios);
    await openAsn(page);
    for (const scenario of scenarios) {
      const p = scenario.payload;
      const ctx = `AS${scenario.asn}`;
      const view = await lookup(page, scenario.asn, scenario.asn);
      await view.tab('bgp').click();
      const counts: [Parameters<AsnView['neighbourCount']>[0], number][] = [
        ['Upstream Transit ASNs', p.neighbours.upstreams_count],
        ['Downstream Customer ASNs', p.neighbours.downstreams_count],
        ['Direct Peering Relations', p.neighbours.peers_count],
      ];
      for (const [caption, value] of counts) {
        const shown = (await view.neighbourCount(caption).textContent()) || '';
        expect.soft(readCount(shown), `${ctx}: "${caption}" (shown "${shown}")`).toBe(BigInt(value));
      }
      const peers = await view.readTopPeers();
      expect.soft(peers.map(peer => peer.asn), `${ctx}: top neighbour ASNs, in order`).toEqual(p.neighbours.top_peers.map((peer: any) => `AS${peer.asn}`));
      expect.soft(peers.map(peer => peer.type), `${ctx}: top neighbour relation types`).toEqual(p.neighbours.top_peers.map((peer: any) => peer.type));
      expect.soft(peers.every(peer => peer.hasInspect), `${ctx}: every neighbour has an Inspect button on the live page`).toBe(true);
      await expect.soft(view.contactField('Network Holder / Org'), `${ctx}: holder`).toHaveText(scenario.holder);
      await expect.soft(view.contactField('Regional Internet Registry (RIR)'), `${ctx}: registry`).toHaveText(p.rir || 'Unknown');
      await expect.soft(view.contactField('Country Jurisdiction'), `${ctx}: country`).toHaveText(p.country_code || 'Unknown');
      const contacts = view.contactField('Abuse Contact Emails');
      if (p.abuse_emails.length) {
        expect.soft(await contacts.locator('a').allTextContents(), `${ctx}: abuse e-mail addresses`).toEqual(p.abuse_emails);
        expect.soft(await contacts.locator('a').evaluateAll(links => links.map(a => a.getAttribute('href'))), `${ctx}: abuse e-mail links`)
          .toEqual(p.abuse_emails.map((mail: string) => `mailto:${mail}`));
      } else {
        await expect.soft(contacts, `${ctx}: no abuse contact`).toHaveText('None listed');
      }
    }
  });

  test('Inspect on a neighbour looks that network up and replaces the result', async ({ page, rng }) => {
    const first = randomScenario(rng, { v4Count: 6, v6Count: 2 });
    first.payload.neighbours.top_peers = [64496, 64497, 64498].map(asn => ({ asn, asn_formatted: `AS${asn}`, type: 'left', v4_peers: 1, v6_peers: 1 }));
    const target = rng.pick([64496, 64497, 64498]);
    const second = randomScenario(rng, { asn: String(target), v4Count: 3, v6Count: 1 });
    const calls = await mockLookups(page, [first, second]);
    await openAsn(page);
    const view = await lookup(page, first.asn, first.asn);
    await view.tab('bgp').click();
    await primary(page).locator('div', { hasText: new RegExp(`^AS${target}$`) }).locator('xpath=../..').getByRole('button', { name: /^Inspect/ }).click();
    await expect(view.badge(), `Inspect on AS${target} should show AS${target}`).toHaveText(`AS${target}`);
    expect.soft(calls[1]?.body, 'request sent by Inspect').toEqual({ asn: String(target) });
    await expect.soft(searchInput(page), 'search box after Inspect').toHaveValue(String(target));
    await expectOverview(view, second, `after Inspect on AS${target}`);
    await expectExplorer(view, second, DEFAULT_EXPLORER, `after Inspect on AS${target}`);
  });
});

test.describe('ASN lookup — text report', () => {
  test('Copy Summary puts the report of this network on the clipboard and confirms', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: rng.int(3, 30), v6Count: rng.int(0, 6) });
    await evidence.save('asn-response.json', scenario.payload);
    const { view } = await openWith(page, scenario);
    await clearClipboard(page);
    await view.copySummaryButton().click();
    await expect(view.copySummaryButton(), 'button confirms the copy').toHaveText(/Copied!/);
    const text = await readClipboard(page);
    await evidence.save('summary.txt', text);
    expectReport(text, scenario, 'Copy Summary');
    await expect(view.copySummaryButton(), 'label returns after two seconds').toHaveText(/Copy Summary/, { timeout: 5_000 });
  });

  test('Export downloads AS<n>-report.txt with the same report', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: rng.int(3, 30), v6Count: rng.int(1, 6), overrides: { description: '', country_code: '', rir: '', announced: false } });
    await evidence.save('asn-response.json', scenario.payload);
    const { view } = await openWith(page, scenario);
    const file = await captureDownload(page, () => view.exportButton().click());
    await evidence.save('report.txt', file.text);
    expect.soft(file.filename, 'file name').toBe(`AS${scenario.asn}-report.txt`);
    expectReport(file.text, scenario, 'exported report');
    await clearClipboard(page);
    await view.copySummaryButton().click();
    await expect(view.copySummaryButton()).toHaveText(/Copied!/);
    expect.soft(file.text, 'the exported file and the copied summary are the same text').toBe(await readClipboard(page));
  });
});

test.describe('ASN lookup — failure and loading', () => {
  test('every error answer is shown as an error, without a result or a spinner, and the next lookup works', async ({ page, rng, guard }) => {
    guard.allow(/status of (400|404|429|500|502)/);
    guard.allow(/HTTP 50\d/);
    const scenario = randomScenario(rng, { v4Count: 6, v6Count: 2 });
    const empty = randomScenario(rng, { v4Count: 0, v6Count: 0 });
    const answers: { name: string; status: number; body: unknown; contentType?: string; shown: string | RegExp }[] = [
      { name: 'HTTP 400 with a message', status: 400, body: { error: 'Could not resolve "zzz" to a valid ASN. Please enter an ASN number (e.g. AS13335), IP, or domain.' }, shown: 'Could not resolve "zzz" to a valid ASN. Please enter an ASN number (e.g. AS13335), IP, or domain.' },
      { name: 'HTTP 404 unknown ASN', status: 404, body: { error: 'ASN 64496 not found or no data available.' }, shown: 'ASN 64496 not found or no data available.' },
      { name: 'HTTP 429 rate limit', status: 429, body: { error: 'Rate limit exceeded, retry in 1 minute', statusCode: 429 }, shown: 'Rate limit exceeded, retry in 1 minute' },
      { name: 'HTTP 500', status: 500, body: { error: 'Internal server error.', statusCode: 500 }, shown: 'Internal server error.' },
      { name: 'HTTP 502 without JSON', status: 502, body: '<html><body>Bad Gateway</body></html>', contentType: 'text/html', shown: /502/ },
      { name: 'HTTP 200 with an error field (no prefixes)', status: 200, body: { ...empty.payload, error: `No prefixes found for AS${empty.asn}. The ASN may not announce any BGP routes.` }, shown: `No prefixes found for AS${empty.asn}. The ASN may not announce any BGP routes.` },
    ];
    let next: { status: number; body: unknown; contentType?: string } = answers[0];
    const gate = await gateApi(page, LOOKUP_API, () => next);
    gate.release();
    await openAsn(page);
    const view = new AsnView(page, primary(page));
    for (const answer of answers) {
      next = answer;
      await submitLookup(page, 'AS64496');
      await expect(errorBanner(page), `${answer.name}: an error must be shown`).toBeVisible();
      await expect.soft(errorBanner(page), `${answer.name}: error text`).toHaveText(answer.shown);
      await expect.soft(view.tab('prefixes'), `${answer.name}: no result may be shown`).toHaveCount(0);
      await expect.soft(loadingStatus(page), `${answer.name}: no spinner may stay`).toHaveCount(0);
      await expect.soft(lookupButton(page), `${answer.name}: the button is usable again`).toBeEnabled();
      await expect.soft(lookupButton(page), `${answer.name}: button label`).toHaveText('Lookup ASN');
      await expect.soft(emptyState(page), `${answer.name}: the empty-state hint is not shown next to an error`).toHaveCount(0);
      await expect.soft(errorBanner(page), `${answer.name}: no raw markup in the error`).not.toContainText('<html>');
    }
    next = { status: 200, body: scenario.payload };
    await lookup(page, scenario.asn, scenario.asn);
    await expect(errorBanner(page), 'a successful lookup clears the error').toHaveCount(0);
    await expectOverview(view, scenario, 'lookup after errors');
  });

  test('the real backend refuses text that cannot be an ASN, with a message that quotes it', async ({ page, guard, rng }) => {
    // None of these reaches a third party: the backend rejects them before it asks RIPEstat or DNS.
    guard.allow(/status of 400/);
    const typed = ['-5', 'AS-15169', '15169abc', '1.5', '+15169', '0x3B41', 'AS 15169', 'AS15169AS', `zz${rng.string(8)}`, '<img src=x onerror=alert(1)>'];
    await openAsn(page);
    const view = new AsnView(page, primary(page));
    for (const text of typed) {
      const exchange = await captureApi(page, LOOKUP_API, () => submitLookup(page, text));
      expect.soft(exchange.status, `"${text}": HTTP status of POST /api/asn`).toBe(400);
      await expect(errorBanner(page), `"${text}" is not an ASN: an error must be shown`).toBeVisible();
      await expect.soft(errorBanner(page), `"${text}": error text`)
        .toHaveText(`Could not resolve "${text}" to a valid ASN. Please enter an ASN number (e.g. AS13335), IP, or domain.`);
      expect.soft(await view.tab('prefixes').count(), `"${text}": no result may be shown`).toBe(0);
      await expect.soft(loadingStatus(page), `"${text}": no spinner may stay`).toHaveCount(0);
    }
    expect.soft(await page.locator('img[src="x"]').count(), 'markup in the quoted input is not rendered').toBe(0);
  });

  test('a network failure shows an error and the tool recovers', async ({ page, rng, guard }) => {
    guard.allow(/ERR_FAILED|Failed to fetch/);
    const scenario = randomScenario(rng, { v4Count: 5, v6Count: 1 });
    await failApi(page, LOOKUP_API);
    await openAsn(page);
    await submitLookup(page, scenario.asn);
    await expect(errorBanner(page), 'a failed request must show an error').toBeVisible();
    await expect.soft(errorBanner(page), 'the error has a readable text').toHaveText(/\S{3,}/);
    await expect.soft(loadingStatus(page), 'no spinner after the failure').toHaveCount(0);
    await expect.soft(lookupButton(page)).toBeEnabled();
    await expect.soft(new AsnView(page, primary(page)).tab('prefixes'), 'no result after the failure').toHaveCount(0);

    await page.unroute(LOOKUP_API);
    await mockApi(page, LOOKUP_API, scenario.payload, { method: 'POST' });
    const view = await lookup(page, scenario.asn, scenario.asn);
    await expect(errorBanner(page)).toHaveCount(0);
    await expectOverview(view, scenario, 'lookup after a network failure');
  });

  test('while the answer is pending the page shows a loading state and hides the previous result', async ({ page, rng }) => {
    const [first, second] = randomScenarios(rng, [{ v4Count: 4, v6Count: 1 }, { v4Count: 7, v6Count: 2 }]);
    const gate = await gateApi(page, LOOKUP_API, call => ({ body: ((call.body as { asn: string }).asn === second.asn ? second : first).payload }));
    await openAsn(page);
    const view = new AsnView(page, primary(page));

    await submitLookup(page, first.asn);
    await expect(loadingStatus(page), 'loading message').toHaveText('Looking up network announcements and BGP details…');
    await expect.soft(lookupButton(page), 'button is disabled while loading').toBeDisabled();
    await expect.soft(lookupButton(page), 'button label while loading').toHaveText('Discovering...');
    await expect.soft(emptyState(page), 'empty-state hint is hidden while loading').toHaveCount(0);
    await expect.soft(errorBanner(page)).toHaveCount(0);
    gate.release(0);
    await expect(view.badge()).toHaveText(`AS${first.asn}`);
    await expect.soft(loadingStatus(page), 'loading message is gone after the answer').toHaveCount(0);
    await expect.soft(lookupButton(page)).toBeEnabled();
    await expect.soft(lookupButton(page)).toHaveText('Lookup ASN');

    await submitLookup(page, second.asn);
    await expect(loadingStatus(page)).toBeVisible();
    await expect.soft(view.tab('prefixes'), 'the previous result is hidden while the next lookup is pending').toHaveCount(0);
    gate.release(1);
    await expect(view.badge()).toHaveText(`AS${second.asn}`);
    await expectOverview(view, second, 'second lookup');
  });

  test('pressing Enter again while a lookup is pending does not send a second request', async ({ page, rng }) => {
    const scenario = randomScenario(rng, { v4Count: 4, v6Count: 1 });
    const gate = await gateApi(page, LOOKUP_API, () => ({ body: scenario.payload }));
    await openAsn(page);
    await searchInput(page).fill(scenario.asn);
    await searchInput(page).press('Enter');
    await expect(loadingStatus(page)).toBeVisible();
    await expect(lookupButton(page), 'the button is disabled while the lookup is pending').toBeDisabled();
    await searchInput(page).press('Enter');
    await searchInput(page).press('Enter');
    gate.release();
    await expect(new AsnView(page, primary(page)).badge()).toHaveText(`AS${scenario.asn}`);
    await expect(loadingStatus(page)).toHaveCount(0);
    expect(gate.calls.length, `one lookup of AS${scenario.asn} was asked for; requests sent to POST /api/asn (the button is disabled while loading, the Enter key is not)`).toBe(1);
  });

  test('a slow answer for an earlier lookup does not replace the result of a later one', async ({ page, rng, evidence }) => {
    const [slowChip, fastChip] = rng.sample(QUICK_ASNS, 2);
    const slow = randomScenario(rng, { asn: slowChip.asn, v4Count: 4, v6Count: 1 });
    const fast = randomScenario(rng, { asn: fastChip.asn, v4Count: 6, v6Count: 2 });
    await evidence.save('race.json', { slow: slow.asn, fast: fast.asn });
    const gate = await gateApi(page, LOOKUP_API, call => ({ body: ((call.body as { asn: string }).asn === slow.asn ? slow : fast).payload }));
    await openAsn(page);
    const view = new AsnView(page, primary(page));

    await quickChip(page, slow.asn).click();
    await expect.poll(() => gate.calls.length).toBe(1);
    await quickChip(page, fast.asn).click();
    await expect.poll(() => gate.calls.length).toBe(2);
    gate.release(1);
    await expect(view.badge(), 'the later lookup is answered first and shown').toHaveText(`AS${fast.asn}`);
    gate.release(0);
    await gate.answered(0);

    // The search box says AS<fast>. If the late answer for AS<slow> is applied, the badge changes within moments.
    const replaced = await view.badge().filter({ hasText: `AS${slow.asn}` }).waitFor({ timeout: 2_500 }).then(() => true, () => false);
    await expect.soft(searchInput(page), 'search box names the last network asked for').toHaveValue(fast.asn);
    expect(replaced, `chip AS${slow.asn} was clicked first and answered last; chip AS${fast.asn} was clicked last. The page must keep showing AS${fast.asn}, but it now shows AS${slow.asn} under a search box that says ${fast.asn}`).toBe(false);
    await expectOverview(view, fast, 'result after the late answer arrived');
  });
});

test.describe('ASN lookup — state', () => {
  test('a second lookup replaces the first completely, including filters, tab and generator settings', async ({ page, rng, evidence }) => {
    const [first, second] = randomScenarios(rng, [{ v4Count: 40, v6Count: 8 }, { v4Count: 9, v6Count: 3 }]);
    await evidence.save('asn-responses.json', [first.payload, second.payload]);
    await mockLookups(page, [first, second]);
    await openAsn(page);
    let view = await lookup(page, first.asn, first.asn);
    await view.aggregateToggle().click();
    await view.versionButton('ipv4').click();
    await view.filterInput().fill(first.v4[0].text.slice(0, 4));
    await view.tab('firewall').click();
    await view.setRules({ format: 'json', action: 'allow', scope: 'ipv6', merge: false });
    await view.tab('tester').click();
    await view.testAddress(formatV4(cidrLast(first.v4[0])));

    view = await lookup(page, second.asn, second.asn);
    await expect(view.table(), 'the new result opens on the Prefix Explorer tab').toBeVisible();
    await expect.soft(view.filterInput(), 'prefix filter is empty again').toHaveValue('');
    await expect.soft(view.aggregateToggle(), 'aggregation is off again').toHaveText(/Raw Prefixes/);
    await expectOverview(view, second, 'second network');
    await expectExplorer(view, second, DEFAULT_EXPLORER, 'second network');
    await view.tab('firewall').click();
    await expect.soft(view.formatSelect(), 'rule format is back to the default').toHaveValue('nginx');
    await expect.soft(view.scopeSelect(), 'rule scope is back to the default').toHaveValue('both');
    await expect.soft(view.mergeCheckbox(), 'merge option is back to the default').toBeChecked();
    const rules = await view.readRules();
    for (const prefix of first.v4.concat(first.v6).filter(p => !second.v4.concat(second.v6).some(q => q.text === p.text)).slice(0, 10)) {
      expect.soft(rules.includes(prefix.text), `rules of the second network must not mention ${prefix.text} of the first`).toBe(false);
    }
    await view.tab('tester').click();
    await expect.soft(view.verdict(), 'no IP test verdict is carried over').toHaveCount(0);
    await expect.soft(view.testerInput(), 'IP tester box is empty').toHaveValue('');
  });

  test('an error replaces the previous result, and a reload returns to the clean start', async ({ page, rng, guard }) => {
    guard.allow(/status of 400/);
    const scenario = randomScenario(rng, { v4Count: 5, v6Count: 2 });
    const gate = await gateApi(page, LOOKUP_API, call => (call.body as { asn: string }).asn === scenario.asn
      ? { body: scenario.payload }
      : { status: 400, body: { error: 'Could not resolve "bogus" to a valid ASN.' } });
    gate.release();
    await openAsn(page);
    const view = await lookup(page, scenario.asn, scenario.asn);
    await submitLookup(page, 'bogus');
    await expect(errorBanner(page)).toHaveText('Could not resolve "bogus" to a valid ASN.');
    await expect(view.tab('prefixes'), 'the stale result must disappear').toHaveCount(0);
    await lookup(page, scenario.asn, scenario.asn);
    await expect(errorBanner(page), 'the error must clear').toHaveCount(0);

    const before = gate.calls.length;
    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(emptyState(page), 'after a reload the tool starts empty (nothing is remembered)').toBeVisible();
    await expect(searchInput(page)).toHaveValue('');
    expect(gate.calls.length, 'a reload sends no lookup').toBe(before);
    expect(await page.evaluate(() => Object.keys(localStorage).filter(key => /asn/i.test(key))), 'the tool keeps nothing in localStorage').toEqual([]);
  });
});

test.describe('ASN lookup — organisation search API (POST /api/asn/search, real backend)', () => {
  // The page has no search-as-you-type; the endpoint is the directory behind the quick chips and name lookups.
  interface Entry { asn: string; name: string; holder: string; country: string; description: string }
  const search = async (page: import('@playwright/test').Page, query: unknown) => {
    const response = await page.request.post('/api/asn/search', { data: { query } });
    expect(response.status(), `POST /api/asn/search ${JSON.stringify(query)} status`).toBe(200);
    return (await response.json()).results as Entry[];
  };

  test('every result contains the query, in any letter case; an unknown word finds nothing', async ({ page, rng }) => {
    for (const query of rng.sample(['cloud', 'GOOGLE', 'Amazon', 'hosting', '133', 'inc.', 'akamai', 'Edge', 'x corp', 'net'], 6)) {
      const results = await search(page, query);
      expect.soft(results.length, `"${query}" should find at least one network`).toBeGreaterThan(0);
      for (const entry of results) {
        const haystack = [entry.asn, entry.name, entry.holder, entry.description].join('\n').toLowerCase();
        expect.soft(haystack.includes(query.toLowerCase()), `"${query}": result AS${entry.asn} ${entry.name} must contain the query`).toBe(true);
        expect.soft(/^\d+$/.test(entry.asn), `"${query}": asn "${entry.asn}" is a number`).toBe(true);
        expect.soft(/^[A-Z]{2}$/.test(entry.country), `"${query}": country "${entry.country}" is a two-letter code`).toBe(true);
      }
      expect.soft(new Set(results.map(r => r.asn)).size, `"${query}": no network listed twice`).toBe(results.length);
    }
    expect.soft(await search(page, `zz${rng.string(10)}`), 'a word that matches nothing').toEqual([]);
  });

  test('an empty query lists ten popular networks, and every quick chip is in the directory under the same name', async ({ page }) => {
    for (const query of ['', '   ']) {
      const results = await search(page, query);
      expect.soft(results.length, `empty query ${JSON.stringify(query)}: number of suggestions`).toBe(10);
    }
    for (const chip of QUICK_ASNS) {
      const results = await search(page, chip.asn);
      const entry = results.find(r => r.asn === chip.asn);
      expect.soft(entry?.name, `chip "${chip.label} (AS${chip.asn})" and the directory entry for AS${chip.asn}`).toBe(chip.label);
    }
  });
});
