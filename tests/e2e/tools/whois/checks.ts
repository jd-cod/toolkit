import { expect, type Page } from '@playwright/test';
import { expectedReport, expectedView, rawText, sameMonthSpelling, sourceWord, type ReportView, type Snapshot, type WhoisView } from './oracle';
import { actionButton, markupWasExecuted, readRaw, readReport, readView } from './page';

/** Comparisons shared by the WHOIS specs. Every mismatch is reported (soft) with the field and the input named. */

const DATE_ROWS = new Set(['Creation Date', 'Updated Date', 'Expiry Date']);

function comparePairs(shown: [string, string][], want: [string, string][], ctx: string, where: string) {
  expect.soft(shown.map(([label]) => label), `${ctx}: labels in "${where}", in order`).toEqual(want.map(([label]) => label));
  for (const [label, value] of want) {
    const row = shown.find(([name]) => name === label);
    if (!row) continue; // already reported by the label comparison
    const got = DATE_ROWS.has(label) ? sameMonthSpelling(row[1]) : row[1];
    expect.soft(got, `${ctx}: "${label}" in "${where}"`).toBe(value);
  }
}

/** Compares a view read from the page with the view the oracle expects. */
export function expectViewEquals(shown: WhoisView, want: WhoisView, ctx: string) {
  comparePairs(shown.cards, want.cards, ctx, 'summary cards');
  expect.soft(shown.daysColor, `${ctx}: colour of the "Days Until Expiry" card (value ${want.cards[3][1]})`).toBe(want.daysColor);
  expect.soft(shown.dnssecColor, `${ctx}: colour of the "DNSSEC" card (value ${want.cards[4][1]})`).toBe(want.dnssecColor);
  expect.soft(shown.source, `${ctx}: "Source:" in the line under the cards`).toBe(want.source);
  expect.soft(sameMonthSpelling(shown.checkedAt), `${ctx}: "Checked At:" in the line under the cards`).toBe(want.checkedAt);
  expect.soft(shown.sections, `${ctx}: section headings, in order`).toEqual(want.sections);
  expect.soft(shown.statusPills, `${ctx}: status labels in "Domain Status"`).toEqual(want.statusPills);
  expect.soft(shown.statusNote, `${ctx}: note shown in "Domain Status" when there is no status`).toBe(want.statusNote);
  comparePairs(shown.registrar, want.registrar, ctx, 'Registrar & Dates');
  comparePairs(shown.nameservers, want.nameservers, ctx, 'Nameserver Comparison');
  expect.soft(shown.links, `${ctx}: cross-tool links [text, href]`).toEqual(want.links);
  expect.soft(shown.contacts, `${ctx}: contact cards (role and lines)`).toEqual(want.contacts);
  expect.soft(shown.riskItems, `${ctx}: risk signals`).toEqual(want.riskItems);
  expect.soft(shown.riskNote, `${ctx}: note shown in "Risk Signals" when there is none`).toBe(want.riskNote);
  expect.soft(shown.rawToggle, `${ctx}: label of the raw-record button while collapsed`).toBe(want.rawToggle);
}

/** Reads the page and compares everything in the snapshot view with `snapshot`. */
export async function expectPageShows(page: Page, snapshot: Snapshot, ctx: string): Promise<WhoisView> {
  const shown = await readView(page);
  expectViewEquals(shown, expectedView(snapshot), ctx);
  return shown;
}

/** Opens the raw record, compares it with the snapshot, and collapses it again. */
export async function expectRawShows(page: Page, snapshot: Snapshot, ctx: string) {
  const word = sourceWord(snapshot);
  expect.soft(await readRaw(page), `${ctx}: the raw record is collapsed until asked for`).toBeNull();
  await actionButton(page, `Show Raw ${word}`).click();
  await expect(actionButton(page, `Hide Raw ${word}`), `${ctx}: the button offers to hide the raw ${word} record once it is open`).toBeVisible();
  expect.soft(await readRaw(page), `${ctx}: raw ${word} record`).toBe(rawText(snapshot));
  await actionButton(page, `Hide Raw ${word}`).click();
  await expect(actionButton(page, `Show Raw ${word}`), `${ctx}: the button offers to show the raw record again`).toBeVisible();
  expect.soft(await readRaw(page), `${ctx}: the raw record is hidden again`).toBeNull();
}

export async function expectNoMarkupExecuted(page: Page, ctx: string) {
  expect.soft(await markupWasExecuted(page), `${ctx}: markup inside values must be shown as text, never turned into elements or run`).toEqual([]);
}

/** Loads a downloaded HTML report in a fresh tab and compares every field with the snapshot. */
export async function expectReportShows(page: Page, html: string, snapshot: Snapshot, ctx: string) {
  const tab = await page.context().newPage();
  const dialogs: string[] = [];
  tab.on('dialog', dialog => { dialogs.push(dialog.message()); void dialog.dismiss(); });
  try {
    await tab.setContent(html, { waitUntil: 'load' });
    const shown: ReportView = await readReport(tab);
    const want = expectedReport(snapshot);
    expect.soft(shown.title, `${ctx}: report <title>`).toBe(want.title);
    expect.soft(shown.heading, `${ctx}: report heading`).toBe(want.heading);
    expect.soft(sameMonthSpelling(shown.subtitle), `${ctx}: report subtitle (domain and check time)`).toBe(want.subtitle);
    comparePairs(shown.cards, want.cards, ctx, 'report cards');
    expect.soft(shown.statusPills, `${ctx}: report status labels`).toEqual(want.statusPills);
    expect.soft(shown.statusNote, `${ctx}: report note when there is no status`).toBe(want.statusNote);
    comparePairs(shown.details, want.details, ctx, 'report Details');
    comparePairs(shown.nameservers, want.nameservers, ctx, 'report Nameservers');
    expect.soft(shown.riskItems, `${ctx}: report risk signals`).toEqual(want.riskItems);
    expect.soft(shown.riskNote, `${ctx}: report note when there is no risk signal`).toBe(want.riskNote);
    expect.soft(shown.rawHeading, `${ctx}: report raw section heading`).toBe(want.rawHeading);
    expect.soft(shown.raw, `${ctx}: report raw record`).toBe(want.raw);
    const live = await tab.evaluate(() => document.querySelectorAll('script, img, b, iframe').length);
    expect.soft(live, `${ctx}: the report must contain no element created from snapshot values (script, img, b, iframe)`).toBe(0);
    expect.soft(dialogs, `${ctx}: the report must not open any dialog`).toEqual([]);
  } finally {
    await tab.close();
  }
}
