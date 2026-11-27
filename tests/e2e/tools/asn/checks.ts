import { expect, type Page } from '../_support/fixtures';
import { mockApi, type ApiCall } from '../_support/io';
import { csvToRecords, parseCsv } from '../_support/csv';
import type { Scenario } from './generator';
import {
  type Cidr, type ExplorerState, DEFAULT_EXPLORER, PAGE_SIZE, expectedRow, explorerList, grouped, pageCount,
  parseReport, reductionPercents, utcStamp,
} from './oracle';
import { type AsnView, LOOKUP_API, lookup, openAsn } from './page';

/**
 * Comparisons shared by the ASN specs: each takes what the page shows and the
 * generated scenario, and reports every difference (soft assertions).
 */

/** Opens /asn with the lookup API answered by `scenario` and shows its result. */
export async function openWith(page: Page, scenario: Scenario): Promise<{ view: AsnView; calls: ApiCall[] }> {
  const calls = await mockApi(page, LOOKUP_API, scenario.payload, { method: 'POST' });
  await openAsn(page);
  const view = await lookup(page, scenario.asn, scenario.asn);
  return { view, calls };
}

/**
 * Answers `POST /api/asn` by the ASN in the request: each scenario answers its
 * own number, anything else gets the first scenario.
 */
export async function mockLookups(page: Page, scenarios: Scenario[]): Promise<ApiCall[]> {
  const byAsn = new Map(scenarios.map(s => [s.asn, s]));
  return mockApi(page, LOOKUP_API, (call: ApiCall) => (byAsn.get(String((call.body as { asn?: unknown })?.asn)) ?? scenarios[0]).payload, { method: 'POST' });
}

export function resolvedFromText(resolved: Record<string, any> | null | undefined): string | null {
  if (!resolved) return null;
  if (resolved.type === 'domain') return `Resolved from domain "${resolved.input}" (IP: ${resolved.ip})`;
  if (resolved.type === 'ip') return `Resolved from IP "${resolved.ip}"`;
  return `Resolved from Organization "${resolved.matched_org}"`;
}

/** Header, the four cards, the tab count and the footer against the response. */
export async function expectOverview(view: AsnView, scenario: Scenario, ctx: string, options: { title?: string } = {}): Promise<void> {
  const p = scenario.payload;
  const header = await view.readHeader();
  expect.soft(header.badge, `${ctx}: ASN badge`).toBe(`AS${scenario.asn}`);
  expect.soft(header.title, `${ctx}: network name heading`).toBe(options.title ?? (p.holder || p.name || `AS${scenario.asn}`));
  expect.soft(header.country, `${ctx}: country chip (country_code ${JSON.stringify(p.country_code)})`).toBe(p.country_code || null);
  expect.soft(header.registry, `${ctx}: registry chip (rir ${JSON.stringify(p.rir)})`).toBe(p.rir || null);
  expect.soft(header.status, `${ctx}: BGP status chip (announced ${p.announced})`)
    .toBe(p.announced ? '● Active (BGP Announced)' : '○ Inactive / Not Announced');
  expect.soft(header.description, `${ctx}: description line`).toBe(p.description || null);
  expect.soft(header.resolvedFrom, `${ctx}: "Resolved from" note`).toBe(resolvedFromText(p.resolved_from));

  const cards = await view.readCards();
  expect.soft(cards['IPv4 Prefixes']?.value, `${ctx}: IPv4 Prefixes card (${scenario.v4.length} IPv4 prefixes in the response)`).toBe(grouped(scenario.v4.length));
  expect.soft(cards['IPv4 Prefixes']?.sub, `${ctx}: IPv4 address total under the IPv4 card (server sent "${p.stats.total_ipv4_ips_formatted}")`)
    .toBe(`${p.stats.total_ipv4_ips_formatted} IPs`);
  expect.soft(cards['IPv6 Prefixes']?.value, `${ctx}: IPv6 Prefixes card (${scenario.v6.length} IPv6 prefixes in the response)`).toBe(grouped(scenario.v6.length));
  expect.soft(cards['IPv6 Prefixes']?.sub, `${ctx}: line under the IPv6 card`).toBe('Announced blocks');

  const saved = scenario.v4.length - scenario.aggregated.length;
  const percents = reductionPercents(scenario.v4.length, scenario.aggregated.length).map(n => `${n}%`);
  expect.soft(percents, `${ctx}: CIDR Optimization percent (${scenario.v4.length} prefixes merge into ${scenario.aggregated.length})`)
    .toContain(cards['CIDR Optimization']?.value);
  expect.soft(cards['CIDR Optimization']?.sub, `${ctx}: rules saved (${scenario.v4.length} - ${scenario.aggregated.length})`).toBe(`${saved} rules saved`);

  const n = p.neighbours;
  expect.soft(cards['BGP Connectivity']?.value, `${ctx}: BGP Connectivity card (peers_count ${n.peers_count})`).toBe(n.peers_count ? grouped(n.peers_count) : 'N/A');
  expect.soft(cards['BGP Connectivity']?.sub, `${ctx}: upstream/downstream line`).toBe(`${n.upstreams_count} Upstreams • ${n.downstreams_count} Downstreams`);

  await expect.soft(view.footer(), `${ctx}: footer time (checked_at_utc ${p.checked_at_utc}, shown in UTC)`)
    .toHaveText(`Data Source: RIPEstat BGP Routing Intelligence • Checked: ${utcStamp(p.checked_at_utc)}`);
}

/**
 * The prefix explorer (tab count and every row of every table page) against the
 * list the oracle derives for `state`.
 *
 * For IPv6 rows the range and the address count are left to the test
 * "IPv6 rows show the end of the range and the number of addresses"; every
 * other column is compared here.
 */
export async function expectExplorer(view: AsnView, scenario: Scenario, state: ExplorerState, ctx: string): Promise<Cidr[]> {
  const expected = explorerList(scenario.v4, scenario.aggregated, scenario.v6, state);
  const where = `${ctx} [version ${state.version}, ${state.aggregated ? 'aggregated' : 'raw'}, mask ${state.mask === null ? 'all' : `/${state.mask}`}, filter ${JSON.stringify(state.query)}]`;

  expect.soft(await view.tabCount(), `${where}: number in the "Prefix Explorer (n)" tab`).toBe(expected.length);
  const rows = await view.readAllRows();
  expect.soft(rows.map(r => r.prefix), `${where}: prefixes listed, in order`).toEqual(expected.map(p => p.text));

  if (expected.length === 0) {
    await expect.soft(view.noRowsMessage(), `${where}: message for an empty list`).toBeVisible();
  } else {
    await expect.soft(view.noRowsMessage(), `${where}: no "nothing found" message while rows are listed`).toHaveCount(0);
  }
  const pages = pageCount(expected.length);
  await expect.soft(view.pageLabel(), `${where}: pagination shown only for more than ${PAGE_SIZE} rows (${expected.length} rows)`).toHaveCount(pages > 1 ? 1 : 0);

  if (rows.length !== expected.length) return expected;
  rows.forEach((row, i) => {
    const want = expectedRow(expected[i]);
    expect.soft(row.number, `${where}: row number of ${want.prefix}`).toBe(String(i + 1));
    expect.soft(row.netmask, `${where}: netmask of ${want.prefix}`).toBe(want.netmask);
    if (want.cidr.family === 4) {
      expect.soft(row.range, `${where}: range of ${want.prefix}`).toBe(`${want.rangeStart} → ${want.rangeEnd}`);
      expect.soft(row.count, `${where}: address count of ${want.prefix}`).toBe(grouped(want.count));
      expect.soft(row.wildcard, `${where}: wildcard of ${want.prefix}`).toBe(want.wildcard);
    } else {
      expect.soft(row.range.startsWith(`${want.rangeStart} →`), `${where}: range of ${want.prefix} starts at ${want.rangeStart} (shown "${row.range}")`).toBe(true);
    }
  });
  return expected;
}

/** Puts the explorer into `state` through its controls, starting from `from`. */
export async function applyExplorerState(view: AsnView, from: ExplorerState, to: ExplorerState): Promise<void> {
  let version = from.version;
  if (to.aggregated !== from.aggregated) {
    // The aggregation toggle is not offered in the IPv6 view; switch it while IPv4 rows are shown.
    if (version === 'ipv6') { await view.versionButton('all').click(); version = 'all'; }
    await view.aggregateToggle().click();
  }
  if (to.version !== version) await view.versionButton(to.version).click();
  if (to.mask !== from.mask) {
    if (to.mask === null) await view.allMasksChip().click();
    else await view.maskChip(to.mask).click();
  }
  if (to.query !== from.query) await view.filterInput().fill(to.query);
}

export { DEFAULT_EXPLORER };

/** The CSV of the prefix explorer against the list that is on screen. */
export function expectPrefixCsv(text: string, scenario: Scenario, expected: Cidr[], ctx: string): void {
  const table = parseCsv(text);
  expect.soft(table[0], `${ctx}: CSV header row`).toEqual(['asn', 'holder', 'prefix', 'ip_version', 'mask', 'total_ips', 'first_ip', 'last_ip', 'netmask']);
  const records = csvToRecords(text);
  expect.soft(records.map(r => r.prefix), `${ctx}: prefixes in the CSV, in order`).toEqual(expected.map(p => p.text));
  if (records.length !== expected.length) return;
  records.forEach((record, i) => {
    const want = expectedRow(expected[i]);
    const at = `${ctx}: CSV row ${i + 1} (${want.prefix})`;
    expect.soft(record.asn, `${at} asn`).toBe(`AS${scenario.asn}`);
    expect.soft(record.holder, `${at} holder`).toBe(scenario.holder);
    expect.soft(record.ip_version, `${at} ip_version`).toBe(want.cidr.family === 4 ? 'ipv4' : 'ipv6');
    expect.soft(record.mask, `${at} mask`).toBe(String(want.cidr.length));
    expect.soft(record.first_ip, `${at} first_ip`).toBe(want.rangeStart);
    expect.soft(record.netmask, `${at} netmask`).toBe(want.netmask);
    if (want.cidr.family === 4) {
      expect.soft(record.last_ip, `${at} last_ip`).toBe(want.rangeEnd);
      expect.soft(record.total_ips, `${at} total_ips`).toBe(want.count.toString());
    }
  });
}

/** The plain-text report (Copy Summary and Export) against the response. */
export function expectReport(text: string, scenario: Scenario, ctx: string): void {
  const p = scenario.payload;
  const report = parseReport(text);
  const field = (name: string) => report.fields[name];
  expect.soft(report.unparsed, `${ctx}: lines of the report that are not a known field or prefix row`).toEqual([]);
  expect.soft(report.title, `${ctx}: report title`).toBe(`AS${scenario.asn} - ${p.name || p.holder || 'Unknown'}`);
  expect.soft(field('Organization'), `${ctx}: Organization`).toBe(p.holder || p.name || 'Unknown');
  expect.soft(field('Description'), `${ctx}: Description`).toBe(p.description || 'None');
  expect.soft(field('Country'), `${ctx}: Country`).toBe(p.country_code || 'Unknown');
  expect.soft(field('RIR Registry'), `${ctx}: RIR Registry`).toBe(p.rir || 'Unknown');
  expect.soft(field('Status'), `${ctx}: Status`).toBe(p.announced ? 'Announced (Active BGP)' : 'Not Announced');
  expect.soft(field('Total IPv4'), `${ctx}: Total IPv4`).toBe(`${scenario.v4.length} prefixes (${p.stats.total_ipv4_ips_formatted} IPs)`);
  expect.soft(field('Total IPv6'), `${ctx}: Total IPv6`).toBe(`${scenario.v6.length} prefixes`);
  expect.soft(field('Upstreams'), `${ctx}: Upstreams`).toBe(String(p.neighbours.upstreams_count));
  expect.soft(field('Peers'), `${ctx}: Peers`).toBe(String(p.neighbours.peers_count));
  expect.soft(field('Checked At'), `${ctx}: Checked At`).toBe(p.checked_at_utc);

  expect.soft(report.v4Heading, `${ctx}: count in the "IPv4 Announced Prefixes (n)" heading`).toBe(scenario.v4.length);
  expect.soft(report.v4.map(r => r.prefix), `${ctx}: IPv4 prefixes in the report, in order`).toEqual(scenario.v4.map(c => c.text));
  report.v4.forEach((row, i) => {
    const cidr = scenario.v4[i];
    if (!cidr) return;
    const want = expectedRow(cidr);
    expect.soft(row.index, `${ctx}: report row number of ${want.prefix}`).toBe(i + 1);
    expect.soft(`${row.first} - ${row.last}`, `${ctx}: report range of ${want.prefix}`).toBe(`${want.rangeStart} - ${want.rangeEnd}`);
    expect.soft(row.count, `${ctx}: report address count of ${want.prefix}`).toBe(`${grouped(want.count)} IPs`);
  });
  if (scenario.v6.length > 0) {
    expect.soft(report.v6Heading, `${ctx}: count in the "IPv6 Announced Prefixes (n)" heading`).toBe(scenario.v6.length);
    expect.soft(report.v6.map(r => r.prefix), `${ctx}: IPv6 prefixes in the report, in order`).toEqual(scenario.v6.map(c => c.text));
  } else {
    expect.soft(report.v6Heading, `${ctx}: no IPv6 section without IPv6 prefixes`).toBeNull();
  }
}
