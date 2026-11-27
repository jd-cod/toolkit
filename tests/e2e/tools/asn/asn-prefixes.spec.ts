import { test, expect } from '../_support/fixtures';
import { captureDownload, readClipboard } from '../_support/io';
import { csvToRecords } from '../_support/csv';
import type { Rng } from '../_support/rng';
import { randomScenario, randomScenarios, type Scenario } from './generator';
import {
  type Cidr, type ExplorerState, PAGE_SIZE, cidrLast, expectedRow, explorerList, formatV4, formatV6, grouped,
  maskDistribution, netmaskV4, pageCount, pageSlice, parseV6, readCount, reductionPercents, showingText,
} from './oracle';
import { DEFAULT_EXPLORER, applyExplorerState, expectExplorer, expectOverview, expectPrefixCsv, mockLookups, openWith } from './checks';
import { type AsnView, lookup, openAsn } from './page';

/**
 * Prefix Explorer tab of /asn: the table, mask chips, version filter, text
 * filter, aggregation, pagination, copy buttons and the CSV export.
 * The lookup API is mocked with random networks; ./oracle.ts decides what
 * each state must list.
 */

/**
 * Filter texts a user could type for this network: parts of prefixes, range
 * ends and netmasks, different letter case, padding, and texts that match nothing.
 * Texts that would match an IPv6 prefix only through the END of its range are
 * left out: that column has a test of its own ("IPv6 rows show …").
 */
function randomQueries(rng: Rng, scenario: Scenario, count: number): string[] {
  const piece = (text: string) => {
    const start = rng.int(0, Math.max(0, text.length - 3));
    return text.slice(start, start + rng.int(2, 7));
  };
  const v4 = () => rng.pick(scenario.v4);
  const makers: (() => string)[] = [
    () => 'zz-no-such-prefix',
    () => String(rng.int(0, 9)),
  ];
  if (scenario.v4.length) {
    makers.push(
      () => v4().text,
      () => piece(v4().text),
      () => v4().text.split('.').slice(0, 2).join('.'),
      () => `/${v4().length}`,
      () => piece(formatV4(cidrLast(v4()))),
      () => formatV4(cidrLast(v4())),
      () => piece(netmaskV4(v4().length)),
      () => `  ${piece(v4().text)}  `,
    );
  }
  if (scenario.v6.length) {
    makers.push(
      () => rng.pick(scenario.v6).text,
      () => piece(rng.pick(scenario.v6).text).toUpperCase(),
      () => rng.pick(scenario.v6).text.split(':')[0],
    );
  }
  const visibleMatch = (p: Cidr, q: string) => {
    const row = expectedRow(p);
    return [row.prefix, row.rangeStart, row.netmask].some(text => text.toLowerCase().includes(q.trim().toLowerCase()));
  };
  const out: string[] = [];
  for (let guard = 0; out.length < count && guard < count * 20; guard++) {
    const query = rng.pick(makers)();
    const viaRangeEndOnly = scenario.v6.some(p => !visibleMatch(p, query) && formatV6(cidrLast(p)).includes(query.trim().toLowerCase()));
    if (query.trim() !== '' && !viaRangeEndOnly && !out.includes(query)) out.push(query);
  }
  return out;
}

test.describe('ASN prefix explorer — table', () => {
  test('lists every prefix in the order the server sent, with range, address count, netmask and wildcard', async ({ page, rng, evidence }) => {
    const scenarios = randomScenarios(rng, [
      { v4Count: rng.int(30, 60), v6Count: rng.int(5, 12) },
      { v4Count: rng.int(8, 20), v6Count: rng.int(3, 6), shuffle: true },
    ]);
    await evidence.save('asn-responses.json', scenarios.map(s => s.payload));
    await mockLookups(page, scenarios);
    await openAsn(page);
    for (const scenario of scenarios) {
      const ctx = `AS${scenario.asn}${scenario === scenarios[1] ? ' (server order shuffled)' : ''}`;
      const view = await lookup(page, scenario.asn, scenario.asn);
      expect.soft(await view.readColumnHeaders(), `${ctx}: table columns`)
        .toEqual(['#', 'Prefix CIDR', 'IP Range (Start → End)', 'Usable IPs', 'Netmask', 'Wildcard', 'Action']);
      await expectExplorer(view, scenario, DEFAULT_EXPLORER, ctx);
      expect.soft(await view.readChips(), `${ctx}: mask chips (IPv4 prefixes per length, ascending)`)
        .toEqual([`All Masks (${scenario.v4.length})`, ...maskDistribution(scenario.v4).map(([length, count]) => `/${length} (${count})`)]);
    }
  });

  test('IPv6 rows show the end of the range and the number of addresses', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: 2, v6: ['2001:db8::/32', '2001:db8:4000::/36', '2a00:1450:4001::/48', '2606:4700:10::/64', '2620:4f:8000::1/128'] });
    await evidence.save('asn-response.json', scenario.payload);
    const { view } = await openWith(page, scenario);
    await view.versionButton('ipv6').click();
    const rows = await view.readRows();
    expect(rows.map(r => r.prefix), 'IPv6 prefixes listed').toEqual(scenario.v6.map(p => p.text));
    rows.forEach((row, i) => {
      const want = expectedRow(scenario.v6[i]);
      const [, end = ''] = row.range.split('→').map(part => part.trim());
      expect.soft(parseV6(end) === cidrLast(want.cidr), `${want.prefix}: column "IP Range (Start → End)" shows "${row.range}"; the range ends at ${want.rangeEnd}`).toBe(true);
      expect.soft(readCount(row.count) === want.count,
        `${want.prefix}: column "Usable IPs" shows "${row.count}"; a /${want.cidr.length} holds 2^${128 - want.cidr.length} = ${grouped(want.count)} addresses`
        + (want.cidr.length <= 64 ? ` (${grouped(2n ** BigInt(64 - want.cidr.length))} is its number of /64 networks)` : '')).toBe(true);
    });

    const file = await captureDownload(page, () => view.csvButton().click());
    await evidence.save('ipv6-prefixes.csv', file.text);
    csvToRecords(file.text).forEach((record, i) => {
      const want = expectedRow(scenario.v6[i]);
      expect.soft(parseV6(record.last_ip) === cidrLast(want.cidr), `CSV ${want.prefix}: last_ip is "${record.last_ip}", expected ${want.rangeEnd}`).toBe(true);
      expect.soft(record.total_ips, `CSV ${want.prefix}: total_ips`).toBe(want.count.toString());
    });

    const target = scenario.v6[1];
    await view.filterInput().fill(formatV6(cidrLast(target)));
    expect.soft((await view.readRows()).map(r => r.prefix), `filtering by the last address of ${target.text} (${formatV6(cidrLast(target))}) finds that prefix`).toContain(target.text);
  });

  test('a network with only IPv4 or only IPv6 prefixes shows zero for the other family', async ({ page, rng }) => {
    const [onlyV4, onlyV6, single] = randomScenarios(rng, [{ v4Count: 7, v6Count: 0 }, { v4Count: 0, v6Count: 5 }, { v4Count: 1, v6Count: 0 }]);
    await mockLookups(page, [onlyV4, onlyV6, single]);
    await openAsn(page);

    let view = await lookup(page, onlyV4.asn, onlyV4.asn);
    await expectOverview(view, onlyV4, 'IPv4-only network');
    await expectExplorer(view, onlyV4, DEFAULT_EXPLORER, 'IPv4-only network');
    await view.versionButton('ipv6').click();
    await expectExplorer(view, onlyV4, { ...DEFAULT_EXPLORER, version: 'ipv6' }, 'IPv4-only network');

    view = await lookup(page, onlyV6.asn, onlyV6.asn);
    await expectOverview(view, onlyV6, 'IPv6-only network');
    await expectExplorer(view, onlyV6, DEFAULT_EXPLORER, 'IPv6-only network');
    expect.soft(await view.readChips(), 'IPv6-only network: no mask chips without IPv4 prefixes').toEqual([]);
    await view.versionButton('ipv4').click();
    await expectExplorer(view, onlyV6, { ...DEFAULT_EXPLORER, version: 'ipv4' }, 'IPv6-only network');

    view = await lookup(page, single.asn, single.asn);
    await expectOverview(view, single, 'network with one prefix');
    await expectExplorer(view, single, DEFAULT_EXPLORER, 'network with one prefix');
  });
});

test.describe('ASN prefix explorer — pagination', () => {
  async function expectPage(view: AsnView, list: Cidr[], current: number, ctx: string) {
    const pages = pageCount(list.length);
    const at = `${ctx}: page ${current} of ${pages} (${list.length} prefixes)`;
    await expect.soft(view.pageLabel(), `${at}: page label`).toHaveText(`Page ${current} of ${pages}`);
    await expect.soft(view.showing(), `${at}: "Showing" text`).toHaveText(showingText(list.length, current));
    const rows = await view.readRows();
    const slice = pageSlice(list, current);
    expect.soft(rows.map(r => r.prefix), `${at}: rows`).toEqual(slice.map(p => p.text));
    expect.soft(rows.map(r => r.number), `${at}: row numbers continue across pages`)
      .toEqual(slice.map((_, i) => String((current - 1) * PAGE_SIZE + i + 1)));
    for (const name of ['First', 'Prev'] as const) {
      await expect.soft(view.pager(name), `${at}: "${name}" is ${current === 1 ? 'disabled' : 'enabled'}`).toBeEnabled({ enabled: current !== 1 });
    }
    for (const name of ['Next', 'Last'] as const) {
      await expect.soft(view.pager(name), `${at}: "${name}" is ${current === pages ? 'disabled' : 'enabled'}`).toBeEnabled({ enabled: current !== pages });
    }
  }

  test('hundreds of prefixes are paged 25 at a time and every button lands on the right slice', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: rng.int(180, 320), v6Count: rng.int(20, 60) });
    await evidence.save('asn-response.json', scenario.payload);
    const { view } = await openWith(page, scenario);
    const list = explorerList(scenario.v4, scenario.aggregated, scenario.v6, DEFAULT_EXPLORER);
    const pages = pageCount(list.length);
    let current = 1;
    await expectPage(view, list, current, 'on arrival');
    const steps: ('First' | 'Prev' | 'Next' | 'Last')[] = ['Next', 'Next', 'Prev', 'Last', 'Prev', 'First', 'Last'];
    for (let i = 0; i < 8; i++) steps.push(rng.pick(['First', 'Prev', 'Next', 'Last'] as const));
    await evidence.save('pagination-steps.json', steps);
    for (const step of steps) {
      const target = step === 'First' ? 1 : step === 'Last' ? pages : step === 'Next' ? Math.min(pages, current + 1) : Math.max(1, current - 1);
      if (target === current) {
        await expect.soft(view.pager(step), `"${step}" on page ${current} of ${pages} has nowhere to go`).toBeDisabled();
        continue;
      }
      await view.pager(step).click();
      current = target;
      await expectPage(view, list, current, `after "${step}"`);
    }

    // Changing a filter while on a later page goes back to page 1 of the new list.
    if (current === 1) { await view.pager('Last').click(); current = pages; }
    await view.versionButton('ipv4').click();
    await expectPage(view, scenario.v4, 1, 'after choosing IPV4 on a later page');
  });

  test('25 prefixes fit one page without pagination; the 26th starts a second page', async ({ page, rng }) => {
    const [exact, over] = randomScenarios(rng, [{ v4Count: 25, v6Count: 0 }, { v4Count: 20, v6Count: 6 }]);
    await mockLookups(page, [exact, over]);
    await openAsn(page);
    let view = await lookup(page, exact.asn, exact.asn);
    await expectExplorer(view, exact, DEFAULT_EXPLORER, '25 prefixes');
    await expect.soft(view.showing(), '25 prefixes: no "Showing" line').toHaveCount(0);
    await expect.soft(view.pager('Next'), '25 prefixes: no page buttons').toHaveCount(0);

    view = await lookup(page, over.asn, over.asn);
    const list = explorerList(over.v4, over.aggregated, over.v6, DEFAULT_EXPLORER);
    await expectPage(view, list, 1, '26 prefixes');
    await view.pager('Next').click();
    await expectPage(view, list, 2, '26 prefixes');
    expect.soft((await view.readRows()).length, '26 prefixes: the second page holds one row').toBe(1);
  });
});

test.describe('ASN prefix explorer — filters', () => {
  test('ALL / IPV4 / IPV6 list the matching family and ALL restores everything', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: rng.int(20, 40), v6Count: rng.int(6, 30) });
    await evidence.save('asn-response.json', scenario.payload);
    const { view } = await openWith(page, scenario);
    let state: ExplorerState = DEFAULT_EXPLORER;
    for (const version of ['ipv4', 'ipv6', 'all', 'ipv6', 'ipv4', 'all'] as const) {
      const next = { ...state, version };
      await applyExplorerState(view, state, next);
      state = next;
      await expectExplorer(view, scenario, state, `AS${scenario.asn}`);
      await expect.soft(view.aggregateToggle(), `version ${version}: the aggregation toggle is offered unless only IPv6 is listed`).toHaveCount(version === 'ipv6' ? 0 : 1);
    }
  });

  test('each mask chip lists the IPv4 prefixes of that length; a second click or "All Masks" clears it', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: rng.int(35, 60), v6Count: rng.int(4, 8) });
    await evidence.save('asn-response.json', scenario.payload);
    const { view } = await openWith(page, scenario);
    const lengths = maskDistribution(scenario.v4);
    let state: ExplorerState = DEFAULT_EXPLORER;
    for (const [length, count] of rng.sample(lengths, 6)) {
      const next = { ...state, mask: length };
      await applyExplorerState(view, state, next);
      state = next;
      const listed = await expectExplorer(view, scenario, state, `chip /${length}`);
      expect.soft(listed.length, `chip "/${length} (${count})": number of prefixes it lists`).toBe(count);
    }
    // Same chip again: filter off.
    await view.maskChip(state.mask as number).click();
    state = { ...state, mask: null };
    await expectExplorer(view, scenario, state, 'second click on the active chip');

    // A chip chosen on a later page starts at page 1; "All Masks" brings everything back.
    if (await view.pager('Last').isEnabled()) await view.pager('Last').click();
    await expect(view.pager('Last'), 'the table is on its last page').toBeDisabled();
    const [length] = rng.pick(lengths);
    await view.maskChip(length).click();
    expect.soft((await view.readRows())[0]?.number, `chip /${length} chosen on the last page: the list starts at row 1`).toBe('1');
    await view.allMasksChip().click();
    await expectExplorer(view, scenario, DEFAULT_EXPLORER, 'after "All Masks"');
  });

  test('a mask chip lists exactly as many prefixes as its label says when IPv6 prefixes have the same length', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: 12, v6Count: 4, sharedLengths: true });
    await evidence.save('asn-response.json', scenario.payload);
    const { view } = await openWith(page, scenario);
    for (const length of [24, 32]) {
      const count = scenario.v4.filter(p => p.length === length).length;
      const v6Same = scenario.v6.filter(p => p.length === length).map(p => p.text);
      await view.maskChip(length).click();
      const rows = await view.readRows();
      expect.soft(rows.length, `chip "/${length} (${count})" is built from the IPv4 prefixes and says ${count}; the table lists ${rows.length} rows: `
        + `${rows.map(r => r.prefix).join(', ')} (IPv6 /${length} in this network: ${v6Same.join(', ')})`).toBe(count);
      expect.soft(await view.tabCount(), `chip "/${length} (${count})": number in the tab label`).toBe(count);
      await view.allMasksChip().click();
    }
  });

  test('the text filter keeps prefixes whose CIDR, range or netmask contains the text', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: rng.int(30, 50), v6Count: rng.int(6, 12) });
    const queries = randomQueries(rng, scenario, 14);
    await evidence.save('asn-response.json', scenario.payload);
    await evidence.save('filter-texts.json', queries);
    const { view } = await openWith(page, scenario);
    for (const query of queries) {
      await view.filterInput().fill(query);
      await expectExplorer(view, scenario, { ...DEFAULT_EXPLORER, query }, 'text filter');
    }
    await view.filterInput().fill('');
    await expectExplorer(view, scenario, DEFAULT_EXPLORER, 'text filter cleared');
  });

  test('random combinations of version, mask chip, aggregation and text filter list what each of them allows', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: rng.int(40, 70), v6Count: rng.int(8, 16) });
    await evidence.save('asn-response.json', scenario.payload);
    const { view } = await openWith(page, scenario);
    const lengths = maskDistribution(scenario.v4).map(([length]) => length);
    const queries = randomQueries(rng, scenario, 8);
    const states: ExplorerState[] = [];
    for (let i = 0; i < 12; i++) {
      states.push({
        version: rng.pick(['all', 'ipv4', 'ipv6'] as const),
        aggregated: rng.bool(0.4),
        mask: rng.bool(0.5) ? rng.pick(lengths) : null,
        query: rng.bool(0.5) ? rng.pick(queries) : '',
      });
    }
    // Always include a combination that can match nothing, and the way back to everything.
    states.push({ version: 'ipv6', aggregated: false, mask: lengths[0], query: '' });
    states.push({ version: 'ipv4', aggregated: true, mask: null, query: 'zz-no-such-prefix' });
    states.push(DEFAULT_EXPLORER);
    await evidence.save('explorer-states.json', states);
    let state: ExplorerState = DEFAULT_EXPLORER;
    for (const next of states) {
      await applyExplorerState(view, state, next);
      state = next;
      await expectExplorer(view, scenario, state, 'combination');
    }
  });
});

test.describe('ASN prefix explorer — aggregation', () => {
  async function expectBanner(view: AsnView, scenario: Scenario, ctx: string) {
    const text = ((await view.aggregateBanner().textContent()) || '').replace(/\s+/g, ' ').trim();
    const accepted = reductionPercents(scenario.v4.length, scenario.aggregated.length).map(percent =>
      `Supernet Aggregation Active: Reduced ${scenario.v4.length} raw subnets down to ${scenario.aggregated.length} optimized CIDR blocks (${percent}% reduction).`);
    expect.soft(accepted, `${ctx}: aggregation banner`).toContain(text);
  }

  test('"Aggregated Supernets" lists the smallest set of blocks covering the IPv4 prefixes, and the toggle goes back', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: rng.int(40, 90), v6Count: rng.int(3, 8) });
    await evidence.save('asn-response.json', scenario.payload);
    const { view } = await openWith(page, scenario);
    await expect(view.aggregateToggle(), 'toggle label before').toHaveText(/Raw Prefixes/);
    await expect(view.aggregateBanner()).toHaveCount(0);

    await view.aggregateToggle().click();
    await expect(view.aggregateToggle(), 'toggle label when on').toHaveText(/Aggregated Supernets/);
    await expectBanner(view, scenario, `AS${scenario.asn}`);
    await expectExplorer(view, scenario, { ...DEFAULT_EXPLORER, aggregated: true }, 'aggregated, all versions');
    await view.versionButton('ipv4').click();
    await expectExplorer(view, scenario, { ...DEFAULT_EXPLORER, aggregated: true, version: 'ipv4' }, 'aggregated, IPv4');
    await view.versionButton('all').click();

    await view.aggregateToggle().click();
    await expect(view.aggregateBanner(), 'banner disappears when aggregation is off').toHaveCount(0);
    await expectExplorer(view, scenario, DEFAULT_EXPLORER, 'raw again');
  });

  test('when the response carries no aggregate the page computes the same minimal supernets itself', async ({ page, rng, evidence }) => {
    const scenarios = randomScenarios(rng, [
      { omitAggregate: true, v4Count: rng.int(40, 80), v6Count: 2 },
      { omitAggregate: true, v4Count: rng.int(120, 200), v6Count: 0 },
      // Hand-made edges: the two halves of the address space, the last two hosts, a cascade that folds four times,
      // a block announced next to its own more-specifics, neighbours that are not halves of one parent.
      { omitAggregate: true, v6Count: 1, v4: ['0.0.0.0/1', '128.0.0.0/1'] },
      { omitAggregate: true, v6Count: 1, v4: ['10.0.0.0/24', '10.0.1.0/24', '10.0.2.0/23', '10.0.4.0/22', '10.0.8.0/21', '192.0.2.0/25', '192.0.2.128/26', '192.0.2.192/26',
        '198.51.100.0/24', '198.51.100.64/26', '203.0.113.0/25', '203.0.113.128/25', '203.0.113.7/32', '172.16.1.0/24', '172.16.2.0/24', '255.255.255.254/32', '255.255.255.255/32'] },
    ]);
    await evidence.save('asn-responses.json', scenarios.map(s => s.payload));
    await mockLookups(page, scenarios);
    await openAsn(page);
    for (const scenario of scenarios) {
      const ctx = `AS${scenario.asn} (${scenario.v4.length} IPv4 prefixes, aggregate left to the page)`;
      const view = await lookup(page, scenario.asn, scenario.asn);
      const cards = await view.readCards();
      expect.soft(reductionPercents(scenario.v4.length, scenario.aggregated.length).map(n => `${n}%`), `${ctx}: CIDR Optimization percent`).toContain(cards['CIDR Optimization']?.value);
      expect.soft(cards['CIDR Optimization']?.sub, `${ctx}: rules saved`).toBe(`${scenario.v4.length - scenario.aggregated.length} rules saved`);
      await view.aggregateToggle().click();
      await expectBanner(view, scenario, ctx);
      await expectExplorer(view, scenario, { ...DEFAULT_EXPLORER, aggregated: true }, ctx);
    }
  });
});

test.describe('ASN prefix explorer — copy and CSV', () => {
  test('the copy button of a row puts that CIDR on the clipboard and confirms', async ({ page, rng }) => {
    const scenario = randomScenario(rng, { v4Count: 12, v6Count: 6 });
    const { view } = await openWith(page, scenario);
    for (const prefix of [...rng.sample(scenario.v4, 3), ...rng.sample(scenario.v6, 2)]) {
      await page.evaluate(() => navigator.clipboard.writeText('not copied yet'));
      await view.rowCopyButton(prefix.text).click();
      await expect.soft(view.rowCopyButton(prefix.text), `row ${prefix.text}: the button confirms`).toHaveText('✓');
      expect.soft(await readClipboard(page), `row ${prefix.text}: clipboard`).toBe(prefix.text);
    }
  });

  test('"Copy Visible" copies the prefixes that pass the current filters, one per line', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: rng.int(30, 45), v6Count: rng.int(5, 9) });
    await evidence.save('asn-response.json', scenario.payload);
    const { view } = await openWith(page, scenario);
    const states: ExplorerState[] = [
      DEFAULT_EXPLORER,
      { ...DEFAULT_EXPLORER, version: 'ipv6' },
      { ...DEFAULT_EXPLORER, version: 'ipv4', aggregated: true },
      { ...DEFAULT_EXPLORER, mask: rng.pick(maskDistribution(scenario.v4))[0] },
      { ...DEFAULT_EXPLORER, query: randomQueries(rng, scenario, 3)[1] },
      { ...DEFAULT_EXPLORER, query: 'zz-no-such-prefix' },
    ];
    let state: ExplorerState = DEFAULT_EXPLORER;
    for (const next of states) {
      await applyExplorerState(view, state, next);
      state = next;
      const expected = explorerList(scenario.v4, scenario.aggregated, scenario.v6, state);
      await page.evaluate(() => navigator.clipboard.writeText('not copied yet'));
      await view.copyVisibleButton().click();
      // The confirmation stays for two seconds; the clipboard is the proof for the later states.
      if (next === states[0]) await expect.soft(view.copyVisibleButton(), 'the button confirms').toHaveText(/Copied All!/);
      await expect.poll(() => readClipboard(page), { message: `state ${JSON.stringify(state)}: the clipboard is written` }).not.toBe('not copied yet');
      expect.soft((await readClipboard(page)).split('\n').filter(Boolean), `state ${JSON.stringify(state)}: clipboard lines (${expected.length} prefixes pass the filters)`)
        .toEqual(expected.map(p => p.text));
    }
  });

  test('CSV downloads AS<n>-prefixes.csv with one row per listed prefix, also when filters are on', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: rng.int(28, 40), v6Count: rng.int(4, 8), holder: 'ACME "Fast" Networks, Inc. & Sons' });
    await evidence.save('asn-response.json', scenario.payload);
    const { view } = await openWith(page, scenario);
    const states: ExplorerState[] = [
      DEFAULT_EXPLORER,
      { ...DEFAULT_EXPLORER, version: 'ipv4', query: scenario.v4[0].text.split('.')[0] },
      { ...DEFAULT_EXPLORER, aggregated: true },
      { ...DEFAULT_EXPLORER, version: 'ipv6' },
    ];
    let state: ExplorerState = DEFAULT_EXPLORER;
    for (const [i, next] of states.entries()) {
      await applyExplorerState(view, state, next);
      state = next;
      const expected = explorerList(scenario.v4, scenario.aggregated, scenario.v6, state);
      const file = await captureDownload(page, () => view.csvButton().click());
      await evidence.save(`prefixes-${i}.csv`, file.text);
      expect.soft(file.filename, 'CSV file name').toBe(`AS${scenario.asn}-prefixes.csv`);
      expectPrefixCsv(file.text, scenario, expected, `state ${JSON.stringify(state)}`);
    }
  });

  test('CSV holds no prefix rows when the filters match nothing', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: 9, v6Count: 3 });
    const { view } = await openWith(page, scenario);
    await view.filterInput().fill('zz-no-such-prefix');
    await expect(view.noRowsMessage()).toBeVisible();
    const file = await captureDownload(page, () => view.csvButton().click());
    await evidence.save('prefixes-empty-filter.csv', file.text);
    const records = csvToRecords(file.text);
    expect(records.length, `the table says "No prefixes found matching current filters." and "Copy Visible" copies nothing, `
      + `but the CSV holds ${records.length} prefix rows (the network has ${scenario.v4.length + scenario.v6.length}): ${records.slice(0, 4).map(r => r.prefix).join(', ')} …`).toBe(0);
  });
});
