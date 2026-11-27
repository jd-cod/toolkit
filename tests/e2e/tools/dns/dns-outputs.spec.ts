import { test, expect } from '../_support/fixtures';
import { captureDownload, clearClipboard, readClipboard } from '../_support/io';
import { describeLookup, expectCsvMatches, expectReportMatches, readHtmlReport, runAndCheck } from './checks';
import { UNKNOWN, awkwardTxtValues, randomAnswer, randomDomain, randomLookup } from './generator';
import { CSV_HEADER, GeoOracle, OFFERED_TYPES, expectedCopyText, expectedCsvRows, type ApiAnswer, type Lookup, type Reply } from './oracle';
import { DnsPage, serveLookups } from './page';

/**
 * DNS Lookup (/dns) — layer 6: everything that leaves the page in Standard mode
 * (clipboard, CSV export, HTML report). Share links: dns-share.spec.ts.
 * Global mode exports: dns-global.spec.ts.
 */

const answer = (body: ApiAnswer): Reply => ({ kind: 'answer', body });

/** A lookup that exercises every column and every kind of section in one result. */
function richLookup(rng: Parameters<typeof randomLookup>[0]): Lookup {
  const lookup = randomLookup(rng, { types: ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA', 'SRV'], kind: 'records' });
  const { domain, resolver } = lookup;
  (lookup.replies.TXT as { body: ApiAnswer }).body.records = rng.shuffle(awkwardTxtValues(rng)).map(data => ({ name: domain, type: 'TXT', TTL: rng.int(0, 99999), data }));
  lookup.replies.CNAME = answer(randomAnswer(rng, domain, 'CNAME', resolver, { kind: 'none' }));
  lookup.replies.SRV = answer({ error: 'DNS lookup failed with SERVFAIL.', records: [], status: 2, _type: 'SRV', dns_provider: UNKNOWN, hosting_provider: UNKNOWN });
  lookup.replies.CAA = answer({ records: [], status: 0, _type: 'CAA' });
  return lookup;
}

test.describe('DNS Lookup — copy and export', () => {
  test('Copy All Records puts every record with TTL, priority, provider and location on the clipboard and confirms', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const lookup = richLookup(rng);
    await serveLookups(page, lookup);
    await dns.open();
    const { want, ctx } = await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    await clearClipboard(page);

    await dns.copyAllButton.click();
    await expect(dns.copyAllButton, 'the button confirms the copy').toHaveText('Copied!');
    const copied = await readClipboard(page);
    const expected = expectedCopyText(want);
    await evidence.save('clipboard.txt', copied);
    await evidence.save('clipboard-expected.txt', expected);
    const gotBlocks = copied.split('\n\n--- ');
    const wantBlocks = expected.split('\n\n--- ');
    expect.soft(gotBlocks.length, `${ctx}: number of "--- TYPE ---" blocks on the clipboard (types with records only)`).toBe(wantBlocks.length);
    wantBlocks.forEach((block, i) => {
      expect.soft(gotBlocks[i], `${ctx}: clipboard block ${i + 1} (${block.split('\n')[0].replace(/-/g, '').trim()})`).toBe(block);
    });
    expect.soft(copied, `${ctx}: whole clipboard text`).toBe(expected);
    await expect(dns.copyAllButton, 'the label returns after two seconds').toHaveText('Copy All Records', { timeout: 6_000 });
  });

  test('Export CSV downloads one row per record (and one per empty or failed type) with every cell equal to the result', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const lookup = richLookup(rng);
    await serveLookups(page, lookup);
    await dns.open();
    const { want, ctx } = await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);

    const file = await captureDownload(page, () => dns.exportCsvButton.click());
    await evidence.save('export.csv', file.text);
    expect.soft(file.filename, `${ctx}: CSV file name`).toBe(`${lookup.domain}-dns-snapshot.csv`);
    expectCsvMatches(file.text, CSV_HEADER, expectedCsvRows(want), ctx);
  });

  test('Download HTML saves a report that shows the same cards, sections and records as the page', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const lookup = richLookup(rng);
    await serveLookups(page, lookup);
    await dns.open();
    const { want, shown, ctx } = await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);

    const file = await captureDownload(page, () => dns.downloadHtmlButton.click());
    await evidence.save('report.html', file.text);
    await expect.soft(dns.downloadHtmlButton, 'the button confirms the download').toHaveText('Downloaded!');
    expect.soft(file.filename, `${ctx}: report file name`).toBe(`${lookup.domain}-dns-snapshot.html`);
    const report = await readHtmlReport(page, file.text);
    expectReportMatches(report, want, { ctx, stamps: [shown.checkedAt ?? ''], pageCounters: shown.sections.map(s => s.counter) });
    await expect(dns.downloadHtmlButton, 'the label returns').toHaveText('Download HTML', { timeout: 6_000 });
  });

  test('random lookups: the CSV and the HTML report always agree with the page', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const lookups = Array.from({ length: 3 }, () => randomLookup(rng, { types: rng.sample(OFFERED_TYPES, rng.int(2, 7)) }));
    await serveLookups(page, ...lookups);
    await dns.open();
    for (const lookup of lookups) {
      const { want, shown, ctx } = await runAndCheck(dns, lookup, geo, evidence);
      const csv = await captureDownload(page, () => dns.exportCsvButton.click());
      expect.soft(csv.filename, `${ctx}: CSV file name`).toBe(`${lookup.domain}-dns-snapshot.csv`);
      expectCsvMatches(csv.text, CSV_HEADER, expectedCsvRows(want), ctx);
      const html = await captureDownload(page, () => dns.downloadHtmlButton.click());
      expect.soft(html.filename, `${ctx}: report file name`).toBe(`${lookup.domain}-dns-snapshot.html`);
      expectReportMatches(await readHtmlReport(page, html.text), want, { ctx, stamps: [shown.checkedAt ?? ''], pageCounters: shown.sections.map(s => s.counter) });
    }
  });

  test('a lookup without any record still exports: one CSV row per type with its message, a report with the notes, nothing to copy', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: rng.sample(OFFERED_TYPES, 4), kind: 'nxdomain', providers: 'unknown' });
    await serveLookups(page, lookup);
    await dns.open();
    const { want, shown, ctx } = await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    await expect.soft(dns.copyAllButton, `${ctx}: no "Copy All Records" without records`).toHaveCount(0);
    const csv = await captureDownload(page, () => dns.exportCsvButton.click());
    expectCsvMatches(csv.text, CSV_HEADER, expectedCsvRows(want), ctx);
    const html = await captureDownload(page, () => dns.downloadHtmlButton.click());
    expectReportMatches(await readHtmlReport(page, html.text), want, { ctx, stamps: [shown.checkedAt ?? ''], pageCounters: shown.sections.map(s => s.counter) });
  });

  test('an MX priority of 0 is kept in the copied text, the CSV and the HTML report', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const domain = randomDomain(rng);
    const records = [
      { name: domain, type: 'MX', TTL: 3600, data: `mx0.${domain}`, value: `mx0.${domain}`, priority: 0 },
      { name: domain, type: 'MX', TTL: 3600, data: `mx5.${domain}`, value: `mx5.${domain}`, priority: 5 },
    ];
    const lookup: Lookup = { domain, resolver: '1.1.1.1', types: ['MX'], replies: { MX: answer({ domain, type: 'MX', resolver: '1.1.1.1', status: 0, _type: 'MX', records, dns_provider: UNKNOWN, hosting_provider: UNKNOWN }) } };
    await evidence.save('mx-zero.json', lookup);
    await serveLookups(page, lookup);
    await dns.open();
    await dns.run(lookup);
    const ctx = `MX priority 0 for ${describeLookup(lookup)}`;

    await clearClipboard(page);
    await dns.copyAllButton.click();
    await expect(dns.copyAllButton).toHaveText('Copied!');
    expect.soft(await readClipboard(page), `${ctx}: clipboard`).toBe(`--- MX ---\nmx0.${domain} (TTL: 3600) (Priority: 0)\nmx5.${domain} (TTL: 3600) (Priority: 5)`);

    const csv = await captureDownload(page, () => dns.exportCsvButton.click());
    expectCsvMatches(csv.text, CSV_HEADER, [
      [domain, '1.1.1.1', 'MX', `mx0.${domain}`, '3600', '0', '', ''],
      [domain, '1.1.1.1', 'MX', `mx5.${domain}`, '3600', '5', '', ''],
    ], ctx);

    const html = await captureDownload(page, () => dns.downloadHtmlButton.click());
    const report = await readHtmlReport(page, html.text);
    expect.soft(report.sections[0]?.rows.map(row => row[1]), `${ctx}: Priority column of the HTML report`).toEqual(['0', '5']);
  });
});
