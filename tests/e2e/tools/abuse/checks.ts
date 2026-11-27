import { expect, type Page } from '@playwright/test';
import {
  RISK_LABELS, countersOf, isPlaceholder, matchesFilter,
  type ExpectedRow, type FilterName,
} from './oracle';
import { readCards, readSummary, readTable, type ShownCard, type ShownRow } from './page';

/**
 * Full comparison of what /abuse shows with the oracle's rows. Used after
 * every action, so a control is never checked by a single spot value.
 */

const NO_NETWORK_NAME = ['N/A', 'Unknown', 'Internal / Private Network'];

function countryText(row: ExpectedRow): string {
  return row.countryName || (row.isPrivate ? 'Private Network' : 'Unknown');
}

function scoreText(row: ExpectedRow): string {
  return row.score === null ? 'N/A' : `${row.score}%`;
}

export function expectDetails(shown: Record<string, string> | null, row: ExpectedRow, ctx: string, layout: 'table' | 'card'): void {
  expect(shown, `${ctx}: the detail block of ${row.ip} should be open`).not.toBeNull();
  if (!shown) return;
  const lower = (text: string | undefined) => (text ?? '').toLowerCase();
  const asnLine = shown['ASN'] ?? '';
  const asnMatch = asnLine.match(/^(.*?) \((.*)\)$/);
  expect.soft(asnMatch?.[1], `${ctx}: detail "ASN" number for ${row.ip} (shown "${asnLine}")`).toBe(row.asn || 'N/A');
  if (row.asnOrg) expect.soft(asnMatch?.[2], `${ctx}: detail "ASN" organisation for ${row.ip} (shown "${asnLine}")`).toBe(row.asnOrg);
  else expect.soft(isPlaceholder(asnMatch?.[2]), `${ctx}: detail "ASN" organisation for ${row.ip} should be a placeholder, shown "${asnLine}"`).toBe(true);
  expect.soft(shown['Usage'], `${ctx}: detail "Usage" for ${row.ip}`).toBe(row.usage || 'N/A');
  expect.soft(shown['Reports'], `${ctx}: detail "Reports" for ${row.ip}`).toBe(String(row.reports));
  const lastLabel = layout === 'table' ? 'Last Reported' : 'Last reported';
  expect.soft(shown[lastLabel], `${ctx}: detail "${lastLabel}" for ${row.ip}`).toBe(row.lastReported || 'Never');
  const separator = layout === 'table' ? ' / ' : ' · ';
  const security = `${row.tor ? 'TOR Exit Node' : 'Not TOR'}${separator}${row.whitelisted ? 'Whitelisted' : 'Not Whitelisted'}`;
  expect.soft(lower(shown['Security']), `${ctx}: detail "Security" for ${row.ip}`).toBe(lower(security));
}

function expectTableRow(shown: ShownRow | undefined, row: ExpectedRow, position: number, ctx: string): void {
  const at = `${ctx}: table row ${position + 1} (${row.ip})`;
  expect(shown, `${at} should exist`).toBeTruthy();
  if (!shown) return;
  expect.soft(shown.index, `${at}: "#" column`).toBe(String(position + 1));
  expect.soft(shown.ip, `${at}: IP address`).toBe(row.ip);
  expect.soft(shown.version, `${at}: version tag`).toBe(row.version);
  expect.soft(shown.ptr, `${at}: Reverse DNS (PTR)`).toBe(row.ptr || 'No PTR record');
  expect.soft(shown.flag, `${at}: flag for country code "${row.countryCode}"`).toBe(row.flag);
  expect.soft(shown.country, `${at}: country name`).toBe(countryText(row));
  expect.soft(shown.countryCode, `${at}: country code`).toBe(row.countryCode ? `(${row.countryCode})` : '');
  expect.soft(shown.asn, `${at}: AS number`).toBe(row.asn ? `AS${row.asn}` : '');
  if (row.isp) expect.soft(shown.isp, `${at}: network / ISP name`).toBe(row.isp);
  else expect.soft(NO_NETWORK_NAME, `${at}: no source names the network, so a placeholder is expected, shown "${shown.isp}"`).toContain(shown.isp);
  expect.soft(shown.usage, `${at}: usage type line`).toBe(row.usage && row.usage !== shown.isp ? row.usage : '');
  expect.soft(shown.badge, `${at}: risk badge (service level and AbuseIPDB score ${row.score})`).toBe(RISK_LABELS[row.risk]);
  expect.soft(shown.score, `${at}: abuse score`).toBe(scoreText(row));
  expect.soft(shown.abuseIpdbHref, `${at}: AbuseIPDB link`).toBe(`https://www.abuseipdb.com/check/${row.ip}`);
}

function expectCard(shown: ShownCard | undefined, row: ExpectedRow, position: number, ctx: string): void {
  const at = `${ctx}: card ${position + 1} (${row.ip})`;
  expect(shown, `${at} should exist`).toBeTruthy();
  if (!shown) return;
  expect.soft(shown.index, `${at}: index`).toBe(`#${position + 1}`);
  expect.soft(shown.ip, `${at}: IP address`).toBe(row.ip);
  expect.soft(shown.version, `${at}: version tag`).toBe(row.version);
  expect.soft(shown.badge, `${at}: risk badge`).toBe(RISK_LABELS[row.risk]);
  expect.soft(shown.ptr, `${at}: Reverse DNS`).toBe(row.ptr || 'No PTR record');
  expect.soft(shown.country, `${at}: country`).toBe(`${row.flag} ${countryText(row)}`);
  const prefix = row.asn ? `AS${row.asn} · ` : '';
  if (row.isp) expect.soft(shown.network, `${at}: network`).toBe(`${prefix}${row.isp}`);
  else expect.soft(NO_NETWORK_NAME.map(name => `${prefix}${name}`), `${at}: network placeholder, shown "${shown.network}"`).toContain(shown.network);
  expect.soft(shown.score, `${at}: abuse score`).toBe(scoreText(row));
  expect.soft(shown.scoreHighlighted, `${at}: abuse score is highlighted only when above 0`).toBe(row.score !== null && row.score > 0);
  expect.soft(shown.abuseIpdbHref, `${at}: AbuseIPDB link`).toBe(`https://www.abuseipdb.com/check/${row.ip}`);
}

export interface ShownState { table: ShownRow[]; cards: ShownCard[] }

/**
 * Compares counters, filter buttons, the "x of y" header, the desktop table
 * and the narrow-screen cards with the oracle, for the given filter.
 */
export async function expectResults(page: Page, rows: ExpectedRow[], ctx: string, filter: FilterName = 'all'): Promise<ShownState> {
  const counters = countersOf(rows);
  const visible = rows.filter(row => matchesFilter(row, filter));
  const summary = await readSummary(page);

  expect.soft(summary.cards['Total IPs Analyzed'], `${ctx}: "Total IPs Analyzed" card`).toBe(String(counters.total));
  expect.soft(summary.cards['Reverse DNS Found'], `${ctx}: "Reverse DNS Found" card`).toBe(String(counters.rdns));
  expect.soft(summary.cards['Risk Flags / Elevated'], `${ctx}: "Risk Flags / Elevated" card (Medium or High badges)`).toBe(String(counters.risk));
  expect.soft(summary.cards['Abuse Reports'], `${ctx}: "Abuse Reports" card (AbuseIPDB score above 0)`).toBe(String(counters.abusive));

  expect.soft(summary.filters['All'], `${ctx}: count on the "All" filter`).toBe(counters.total);
  expect.soft(summary.filters['rDNS'], `${ctx}: count on the "rDNS" filter`).toBe(counters.rdns);
  expect.soft(summary.filters['Risk Flags'], `${ctx}: count on the "Risk Flags" filter`).toBe(counters.risk);
  if (counters.abusive > 0) expect.soft(summary.filters['Abusive'], `${ctx}: count on the "Abusive" filter`).toBe(counters.abusive);
  else expect.soft(summary.filters['Abusive'], `${ctx}: no "Abusive" filter when no address has a score above 0`).toBeUndefined();

  expect.soft(summary.shown, `${ctx}: "Results (x of y IPs)" — x`).toBe(visible.length);
  expect.soft(summary.of, `${ctx}: "Results (x of y IPs)" — y`).toBe(rows.length);

  const table = await readTable(page);
  const cards = await readCards(page);
  expect.soft(table.map(row => row.ip), `${ctx}: addresses in the table, in order`).toEqual(visible.map(row => row.ip));
  expect.soft(cards.map(card => card.ip), `${ctx}: addresses in the card list, in order`).toEqual(visible.map(row => row.ip));
  visible.forEach((row, position) => {
    expectTableRow(table[position], row, position, ctx);
    expectCard(cards[position], row, position, ctx);
  });
  return { table, cards };
}
