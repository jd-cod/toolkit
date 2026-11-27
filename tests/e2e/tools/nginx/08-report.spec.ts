import { test, expect } from './fixtures';
import type { Page } from '@playwright/test';
import { writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { captureDownload } from '../_support/io';
import { parseCsv } from '../_support/csv';
import { analyse, applyFilters, summarise, rank, timeline, share, grouped, spanStamp, pathOf, type ViewFilters } from './oracle';
import type { GeneratedLog, LogRequest } from './generator';
import type { TrafficAnalyzer } from './page';

/**
 * Traffic Analyzer — Download Report (HTML) and Export CSV.
 *
 * The downloaded files are opened and parsed, and every figure in them is
 * compared with the oracle (and therefore with the dashboard, which other
 * specs compare with the same oracle).
 */

interface ReportContent {
  title: string;
  headerLines: string[];
  cards: Record<string, string>;
  sections: Record<string, string[][]>;
  chips: Record<string, Record<string, string>>;
  paths: string[][];
  responseSize: Record<string, string>;
  rate: { caption: string; cards: Record<string, { value: string; note: string }> } | null;
  alert: string;
  botHeader: string;
  countryPills: Record<string, string[]>;
  charts: Record<string, { labels: string[]; data: number[] } | null>;
  hasLogData: boolean;
}

async function readReport(page: Page): Promise<ReportContent> {
  return page.evaluate(() => {
    const text = (el: Element | null | undefined) => (el?.textContent || '').replace(/\s+/g, ' ').trim();
    const all = (sel: string, root: ParentNode = document) => Array.from(root.querySelectorAll(sel));
    const sections: Record<string, string[][]> = {};
    for (const section of all('.section')) {
      const name = text(section.querySelector('.section-header')).replace(/\s*\(.*$/, '').replace(/^[^A-Za-z]+/, '');
      const table = section.querySelector('.scroll-wrap > table');
      if (table) sections[name] = all(':scope > tbody > tr:not(.detail-row)', table).map(tr => Array.from(tr.children).map(text));
      const attackers = Array.from(section.querySelectorAll('.detail-title')).find(d => /Spoofed Bot Attackers/.test(d.textContent || ''));
      if (attackers) sections['Spoofed Bot Attackers'] = all('tbody > tr', attackers.parentElement!.querySelector('table')!).map(tr => Array.from(tr.children).map(text));
    }
    const chips: Record<string, Record<string, string>> = {};
    for (const box of all('.metric-box')) {
      const label = text(box.querySelector('.metric-label'));
      const found = all('.metric-chip', box);
      if (found.length) chips[label] = Object.fromEntries(found.map(c => [text(c.querySelector('.metric-chip-key')), text(c.querySelector('.metric-chip-val'))]));
    }
    const rateSection = all('.section').find(s => /Request Rate/.test(text(s.querySelector('.section-header'))));
    const lib = (window as any).Chart;
    const chart = (id: string) => {
      const canvas = document.getElementById(id) as HTMLCanvasElement | null;
      const model = canvas && lib ? lib.getChart(canvas) : null;
      return model ? { labels: [...model.data.labels], data: [...model.data.datasets[0].data] } : null;
    };
    const countryPills: Record<string, string[]> = {};
    for (const row of all('tr.detail-row[data-detail-id^="c-"]')) {
      countryPills[text(row.querySelector('.detail-title')).replace(/^IPs from /, '')] = all('.ip-pill', row).map(text);
    }
    return {
      title: document.title,
      headerLines: [text(document.querySelector('.report-title')), text(document.querySelector('.report-badge')), ...all('.report-period').map(text)],
      cards: Object.fromEntries(all('.container > .stat-cards .stat-card').map(c => [text(c.querySelector('.stat-label')), text(c.querySelector('.stat-value'))])),
      sections,
      chips,
      paths: all('.path-row').map(r => Array.from(r.children).map(text)),
      responseSize: Object.fromEntries(all('.resp-row').map(r => [text(r.children[0]).replace(/:$/, ''), text(r.children[1])])),
      rate: rateSection ? {
        caption: text(rateSection.querySelector('.section-header span:last-child')),
        cards: Object.fromEntries(all('.stat-card', rateSection).map(c => [text(c.querySelector('.stat-label')), { value: text(c.querySelector('.stat-value')), note: text(c.children[2]) }])),
      } : null,
      alert: text(all('.section').find(s => /Bot Traffic/.test(text(s.querySelector('.section-header'))))?.querySelector('div[style*="padding:16px 20px 0"]')),
      botHeader: text(all('.section-header').find(h => /Bot Traffic/.test(h.textContent || ''))),
      countryPills,
      charts: { rps: chart('report-rps-chart'), country: chart('report-country-chart'), asn: chart('report-asn-chart') },
      hasLogData: !!document.getElementById('_log_json'),
    };
  });
}

async function downloadHtmlReport(analyzer: TrafficAnalyzer, compact: boolean) {
  const { page } = analyzer;
  await page.locator('#dash-download-btn').click();
  await expect(page.locator('#download-modal')).toBeVisible();
  await page.locator('#dl-compact-cb').setChecked(compact);
  const file = await captureDownload(page, () => page.locator('#dl-start-btn').click(), 60_000);
  await expect(page.locator('#dl-done-section'), 'the dialog confirms the download').toBeVisible();
  await expect(page.locator('#dl-file-size')).toContainText(compact ? '(compact)' : '(full)');
  await expect(page.locator('#download-modal-backdrop'), 'the dialog closes by itself after the download').toBeHidden({ timeout: 10_000 });
  // The browser stores downloads without an extension; save a copy it will open as HTML.
  const saved = test.info().outputPath(`report-${Date.now()}.html`);
  writeFileSync(saved, file.text);
  const report = await page.context().newPage();
  await report.goto(pathToFileURL(saved).href);
  return { file, report };
}

const pct1 = (part: number, total: number) => share(part, total);
/** Digit grouping removed: figures are compared by value here; grouping has its own test. */
const plain = (text: string) => text.replace(/(\d),(?=\d{3})/g, '$1');
const close = (shown: string, exact: number, decimals: number) => Math.abs(Number(shown.replace(/[^0-9.-]/g, '')) - exact) <= 0.5 / 10 ** decimals + 1e-9;

function uniqueIpsBy<K>(requests: LogRequest[], keyOf: (r: LogRequest) => K): Map<K, Set<string>> {
  const map = new Map<K, Set<string>>();
  for (const r of requests) map.set(keyOf(r), (map.get(keyOf(r)) ?? new Set()).add(r.ip));
  return map;
}

/** Rows keyed by their first distinguishing cell; order is checked through the hits column. */
function expectRows(shown: string[][], hitsColumn: number, expected: Map<string, string[]>, keyOf: (row: string[]) => string, expectedHits: number[], label: string) {
  expect.soft(shown.map(r => Number(r[hitsColumn].replace(/,/g, ''))), `${label}: hit counts, highest first`).toEqual(expectedHits);
  for (const row of shown) {
    const want = expected.get(keyOf(row));
    expect.soft(row, `${label}: row for "${keyOf(row)}"`).toEqual(want ?? [`<no such entry in the log: ${keyOf(row)}>`]);
  }
}

/** The same content with thousands separators removed from every text. */
function withoutGrouping<T>(value: T): T {
  if (typeof value === 'string') return plain(value) as unknown as T;
  if (Array.isArray(value)) return value.map(withoutGrouping) as unknown as T;
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [plain(k), withoutGrouping(v)])) as T;
  return value;
}

function checkReport(raw: ReportContent, log: GeneratedLog, filters: ViewFilters, label: string) {
  const report = withoutGrouping(raw);
  const analysis = analyse(log);
  const requests = applyFilters(analysis.kept, filters);
  const s = summarise(requests);
  const total = s.total;

  // Header
  expect.soft(report.headerLines[0], `${label} report title`).toContain('Traffic Log Analysis Report');
  expect.soft(report.headerLines.find(l => l.includes('Log Period')), `${label} log period line`)
    .toBe(`📅 Log Period: ${spanStamp(analysis.span!.minTs)} → ${spanStamp(analysis.span!.maxTs)} (${analysis.span!.minutes} min)`);
  const exclusions = report.headerLines.find(l => l.includes('Analysis exclusions')) ?? '';
  expect.soft(exclusions, `${label} exclusions line names the active options`).toContain('internal requests excluded; ordinary 403 responses excluded (recognized crawlers retained)');
  expect.soft(plain(exclusions), `${label} exclusions line skipped counts`)
    .toContain(`Skipped: ${analysis.skipped.internalAddress} private/local IP · ${analysis.skipped.healthCheck} health-check path · ${analysis.skipped.forbidden} ordinary 403 · ${analysis.skipped.invalid} invalid`);

  // Summary cards
  expect.soft(report.cards['Total Requests'], `${label} card Total Requests`).toBe(String(total));
  expect.soft(report.cards['Unique IPs'], `${label} card Unique IPs`).toBe(String(s.uniqueIps));
  expect.soft(report.cards['Countries'], `${label} card Countries`).toBe(String(s.uniqueCountries));
  expect.soft(report.cards['ASNs'], `${label} card ASNs`).toBe(String(s.uniqueAsns));
  expect.soft(close(report.cards['Human Traffic'] ?? '', pct1(s.human, total), 0), `${label} card Human Traffic: shown ${report.cards['Human Traffic']}, real ${pct1(s.human, total).toFixed(3)}%`).toBe(true);
  const verifiedLabel = Object.keys(report.cards).find(k => k.startsWith('Verified Bots')) ?? 'missing';
  const spoofedLabel = Object.keys(report.cards).find(k => k.startsWith('Spoofed Bots')) ?? 'missing';
  expect.soft(report.cards[verifiedLabel], `${label} card Verified Bots`).toBe(String(s.verified));
  expect.soft(report.cards[spoofedLabel], `${label} card Spoofed Bots`).toBe(String(s.spoofed));
  expect.soft(close(verifiedLabel, pct1(s.verified, total), 1), `${label} Verified Bots percentage in "${verifiedLabel}", real ${pct1(s.verified, total).toFixed(3)}%`).toBe(true);
  expect.soft(close(spoofedLabel, pct1(s.spoofed, total), 1), `${label} Spoofed Bots percentage in "${spoofedLabel}", real ${pct1(s.spoofed, total).toFixed(3)}%`).toBe(true);

  // HTTP metrics
  const category = (digit: number) => requests.filter(r => Math.floor(r.status / 100) === digit).length;
  expect.soft(report.chips['Status Categories'], `${label} status categories`).toEqual(Object.fromEntries([1, 2, 3, 4, 5].map(d => [`${d}xx`, String(category(d))])));
  expect.soft(report.chips['Request Methods'], `${label} request methods`).toEqual(Object.fromEntries(s.methods.map(m => [m.key, String(m.hits)])));
  const sizes = requests.map(r => r.bytes).sort((a, b) => a - b);
  const middle = Math.floor(sizes.length / 2);
  const median = sizes.length % 2 ? sizes[middle] : Math.round((sizes[middle - 1] + sizes[middle]) / 2);
  expect.soft(Object.fromEntries(Object.entries(report.responseSize).map(([k, v]) => [k, plain(v)])), `${label} response size block`).toEqual({
    Total: `${s.bytes} bytes`,
    Average: `${Math.round(s.bytes / sizes.length)} bytes`,
    Median: `${median} bytes`,
    Range: `${sizes[0]} – ${sizes[sizes.length - 1]} bytes`,
  });
  if (log.options.urls === 'flat') {
    const paths = s.paths.slice(0, 20);
    expect.soft(report.paths.map(r => Number(r[2].replace(/,/g, ''))), `${label} top paths: hit counts`).toEqual(paths.map(p => p.hits));
    for (const row of report.paths) {
      const real = s.paths.find(p => p.key === row[1]);
      expect.soft(real && String(real.hits) === row[2] && close(row[3], pct1(real.hits, total), 1), `${label} top paths row ${row.join(' | ')}`).toBe(true);
    }
  }

  // Request rate
  expect.soft(report.rate, `${label} request-rate section is present`).not.toBeNull();
  if (report.rate) {
    const caption = report.rate.caption.match(/\((\d+)(s|m|h|d) buckets • (\d+) points\)/);
    expect.soft(caption, `${label} request-rate caption "${report.rate.caption}" names bucket size and point count`).not.toBeNull();
    if (caption) {
      const bucket = Number(caption[1]) * { s: 1, m: 60, h: 3600, d: 86400 }[caption[2] as 's'];
      const buckets = timeline(requests, bucket);
      expect.soft(Number(caption[3]), `${label} request-rate point count for ${bucket}s buckets`).toBe(buckets.length);
      const peak = buckets.reduce((best, b) => (b.count > best.count ? b : best), buckets[0]);
      const first = requests.reduce((m, r) => Math.min(m, r.ts), Infinity);
      const last = requests.reduce((m, r) => Math.max(m, r.ts), -Infinity);
      const seconds = Math.max(1, Math.round((last - first) / 1000));
      const peakCard = report.rate.cards['Peak Rate'];
      const averageCard = report.rate.cards['Average Rate'];
      expect.soft(close(peakCard.value, peak.count / bucket, 2), `${label} peak rate: shown "${peakCard.value}", busiest ${bucket}s bucket has ${peak.count} requests = ${(peak.count / bucket).toFixed(4)} req/s`).toBe(true);
      expect.soft(peakCard.note, `${label} peak rate note`).toContain(`(${String(peak.count)} reqs)`);
      expect.soft(close(averageCard.value, total / seconds, 2), `${label} average rate: shown "${averageCard.value}", ${total} requests over ${seconds}s = ${(total / seconds).toFixed(4)} req/s`).toBe(true);
      expect.soft(plain(averageCard.note), `${label} average rate note`).toBe(`over ${seconds}s window`);
      expect.soft(close(report.rate.cards['Peak Errors'].value, share(peak.errors, peak.count), 1), `${label} peak errors: shown "${report.rate.cards['Peak Errors'].value}", real ${share(peak.errors, peak.count).toFixed(3)}%`).toBe(true);
      expect.soft(report.charts.rps?.data.length, `${label} request-rate chart point count`).toBe(buckets.length);
      const wrong = (report.charts.rps?.data ?? []).filter((v, i) => Math.abs(v - buckets[i].count / bucket) > 0.005 + 1e-9).length;
      expect.soft(wrong, `${label} request-rate chart points that differ from requests-per-second of their bucket`).toBe(0);
    }
  }

  // Country table
  const ipsByCountry = uniqueIpsBy(requests, r => r.geo.country);
  const codeOf = new Map(requests.map(r => [r.geo.country, r.geo.countryCode]));
  const countryRows = report.sections['Country Breakdown'] ?? [];
  expect.soft(countryRows.length, `${label} country table row count`).toBe(s.countries.length);
  expect.soft(countryRows.map(r => Number(r[1].replace(/,/g, ''))), `${label} country table hits, highest first`).toEqual(s.countries.map(c => c.hits));
  for (const row of countryRows) {
    const name = row[0].replace(/\s*▸$/, '');
    const real = s.countries.find(c => `${codeOf.get(c.key)} ${c.key}` === name);
    expect.soft(!!real && row[1] === String(real.hits) && row[2] === String(ipsByCountry.get(real.key)!.size) && close(row[3], pct1(real.hits, total), 1),
      `${label} country row "${row.join(' | ')}" (expected ${real ? `${String(real.hits)} hits, ${ipsByCountry.get(real.key)!.size} IPs, ${pct1(real.hits, total).toFixed(1)}%` : 'no such country in the log'})`).toBe(true);
  }
  const topCountry = s.countries[0].key;
  const wantPills = rank(requests.filter(r => r.geo.country === topCountry), r => r.ip).map(i => `${i.key}${String(i.hits)} hits`).sort();
  expect.soft((report.countryPills[topCountry] ?? []).slice().sort(), `${label} addresses listed under ${topCountry}`).toEqual(wantPills);

  // ASN table
  const ipsByAsn = uniqueIpsBy(requests, r => r.geo.asn);
  const asnRows = report.sections['ASN Breakdown'] ?? [];
  expect.soft(asnRows.length, `${label} ASN table row count`).toBe(s.asns.length);
  expect.soft(asnRows.map(r => Number(r[2].replace(/,/g, ''))), `${label} ASN table hits, highest first`).toEqual(s.asns.map(a => a.hits));
  for (const row of asnRows) {
    const asn = Number(row[0].replace(/[^0-9]/g, ''));
    const real = s.asns.find(a => a.key === asn);
    expect.soft(!!real && row[1] === (s.asnOrg.get(asn) ?? '').replace(/\s+/g, ' ').trim() && row[2] === String(real.hits) && row[3] === String(ipsByAsn.get(asn)!.size) && close(row[4], pct1(real.hits, total), 1),
      `${label} ASN row "${row.join(' | ')}" (expected ${real ? `${s.asnOrg.get(asn)}, ${String(real.hits)} hits, ${ipsByAsn.get(asn)!.size} IPs` : 'no such network in the log'})`).toBe(true);
  }

  // Top IPs
  const facts = new Map(requests.map(r => [r.ip, r.geo]));
  const ipRows = report.sections['Top IPs'] ?? [];
  const wantIps = new Map(s.ips.map(i => {
    const g = facts.get(i.key)!;
    return [i.key, [i.key, String(i.hits), `${g.countryCode} ${g.country}`, `AS${g.asn} ${g.asnOrg.replace(/\s+/g, ' ').trim()}`]];
  }));
  expectRows(ipRows.map(r => r.slice(1)), 1, wantIps, row => row[0], s.ips.slice(0, 30).map(i => i.hits), `${label} top IPs table`);
  expect.soft(ipRows.map(r => r[0]), `${label} top IPs numbering`).toEqual(ipRows.map((_, i) => String(i + 1)));

  // Bots
  const botPct = 100 - Math.round(pct1(s.human, total));
  expect.soft(report.botHeader, `${label} bot section header`).toContain(`(${botPct}% of total)`);
  const groups = new Map<string, { requests: LogRequest[] }>();
  for (const r of requests) if (r.trafficClass !== 'human') groups.set(r.agent.group, { requests: [...(groups.get(r.agent.group)?.requests ?? []), r] });
  const botRows = report.sections['Bot Traffic Analysis & Spoofing Guard'] ?? [];
  expect.soft(botRows.length, `${label} bot table row count`).toBe(groups.size);
  for (const row of botRows) {
    const name = row[0].replace(/\s*\(\d+ sub-bots\)/, '').replace(/\s*▸$/, '');
    const group = groups.get(name);
    if (!group) { expect.soft(name, `${label} bot table lists a group that is not in the log`).toBe('<a group from the log>'); continue; }
    const verified = group.requests.filter(r => r.trafficClass === 'verified').length;
    const spoofed = group.requests.filter(r => r.trafficClass === 'spoofed').length;
    const status = verified && spoofed ? 'Mixed' : spoofed ? `Fake / Spoofed (${String(spoofed)})` : verified ? 'Verified Genuine' : 'Unverified';
    expect.soft(row.slice(1, 4), `${label} bot row "${name}" (status, requests, unique IPs)`).toEqual([status, String(group.requests.length), String(new Set(group.requests.map(r => r.ip)).size)]);
    expect.soft(close(row[4], pct1(group.requests.length, total), 1), `${label} bot row "${name}" share: shown ${row[4]}, real ${pct1(group.requests.length, total).toFixed(3)}%`).toBe(true);
  }
  const spoofedRequests = requests.filter(r => r.trafficClass === 'spoofed');
  if (spoofedRequests.length) {
    expect.soft(report.alert, `${label} fake-bot alert`).toContain(`Detected ${String(spoofedRequests.length)} requests impersonating official crawlers`);
    expect.soft(report.alert, `${label} fake-bot alert address count`).toContain(`${new Set(spoofedRequests.map(r => r.ip)).size} unique IP(s)`);
    const attackers = rank(spoofedRequests, r => `${r.ip}|${r.agent.name}`);
    const rows = report.sections['Spoofed Bot Attackers'] ?? [];
    expect.soft(rows.map(r => Number(r[3].replace(/,/g, ''))), `${label} spoofed attackers hits, highest first`).toEqual(attackers.map(a => a.hits));
    for (const row of rows) {
      const real = attackers.find(a => a.key === `${row[1]}|${row[2]}`);
      const g = facts.get(row[1]);
      expect.soft(row.slice(1), `${label} spoofed attacker row for ${row[1]}`).toEqual(real && g
        ? [row[1], row[2], String(real.hits), g.country, g.asnOrg.replace(/\s+/g, ' ').trim(), `Fake/Spoofed ${row[2]} (Untrusted IP)`]
        : ['<not an impersonating address in the log>']);
    }
  }

  // Charts
  expect.soft(report.charts.country?.data, `${label} country chart values (top 10)`).toEqual(s.countries.slice(0, 10).map(c => c.hits));
  expect.soft(report.charts.asn?.data, `${label} ASN chart values (top 10)`).toEqual(s.asns.slice(0, 10).map(a => a.hits));
}

test.describe('Traffic Analyzer — HTML report', () => {
  test('the downloaded report contains the same figures as the analysis (single-segment paths)', async ({ analyzer, newLog, evidence }) => {
    const log = await newLog({ urls: 'flat' });
    await analyzer.analysePasted(log.text);
    const { file, report } = await downloadHtmlReport(analyzer, true);
    await evidence.save('report.html', file.text);
    expect.soft(file.filename, 'report file name carries today\'s date (UTC)').toBe(`nginx-report-${new Date().toISOString().slice(0, 10)}.html`);
    const errors: string[] = [];
    report.on('pageerror', e => errors.push(e.message));
    await report.reload();
    checkReport(await readReport(report), log, {}, 'report:');
    expect.soft(errors, 'JavaScript errors inside the downloaded report').toEqual([]);
    expect.soft(await report.title(), 'report document title').toContain('Traffic Log Report');
  });

  test('the report works without network access (charts and styles are embedded)', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 300 });
    await analyzer.analysePasted(log.text);
    const { report } = await downloadHtmlReport(analyzer, true);
    const external: string[] = [];
    await report.route(/^https?:\/\//, route => { external.push(route.request().url()); return route.abort(); });
    await report.reload();
    const content = await readReport(report);
    expect.soft(external, 'requests the report makes to the network when opened').toEqual([]);
    expect.soft(content.charts.country, 'country chart is drawn from the embedded chart library').not.toBeNull();
    expect.soft(content.charts.rps, 'request-rate chart is drawn from the embedded chart library').not.toBeNull();
  });

  test('the full (non-compact) report contains the same figures', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 300 });
    await analyzer.analysePasted(log.text);
    const { report } = await downloadHtmlReport(analyzer, false);
    checkReport(await readReport(report), log, {}, 'full report:');
  });

  test('large numbers are grouped with thousands separators, as on the dashboard', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 1400 });
    await analyzer.analysePasted(log.text);
    const total = analyse(log).kept.length;
    expect(total, 'sanity: more than 1,000 requests are analysed').toBeGreaterThan(1000);
    const bytes = summarise(analyse(log).kept).bytes;
    const { report } = await downloadHtmlReport(analyzer, true);
    const content = await readReport(report);
    expect.soft(content.cards['Total Requests'], 'report card Total Requests').toBe(grouped(total));
    expect.soft(content.responseSize.Total, 'report response size total').toBe(`${grouped(bytes)} bytes`);
  });

  test('country, ASN and bot rows expand to show their addresses', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 300 });
    await analyzer.analysePasted(log.text);
    const { report } = await downloadHtmlReport(analyzer, true);
    for (const prefix of ['c-', 'a-', 'b-']) {
      const row = report.locator(`tr.expand-row[data-detail-key^="${prefix}"]`).first();
      const key = await row.getAttribute('data-detail-key');
      const detail = report.locator(`tr[data-detail-id="${key}"]`);
      await expect(detail, `detail row ${key} starts collapsed`).toBeHidden();
      await row.click();
      await expect.soft(detail, `detail row ${key} opens on click`).toBeVisible();
      await row.click();
      await expect.soft(detail, `detail row ${key} closes on a second click`).toBeHidden();
    }
  });

  test('a report downloaded while a filter is active contains the filtered figures and says which filter applies', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    await analyzer.selectMethod('GET');
    const { report } = await downloadHtmlReport(analyzer, true);
    const content = await readReport(report);
    checkReport(content, log, { method: 'GET' }, 'filtered report:');
    await expect.soft(report.locator('.report-header'), 'a report that covers only part of the log (method GET) must say so in its header, otherwise it reads as the whole log').toContainText(/filter/i);
  });

  test('the compact option is remembered for the next download', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 150 });
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    await page.locator('#dash-download-btn').click();
    await expect(page.locator('#dl-compact-cb'), 'compact is the default').toBeChecked();
    await page.locator('#dl-compact-cb').uncheck();
    await page.locator('#dl-modal-close').click();
    await expect(page.locator('#download-modal-backdrop')).toBeHidden();
    await page.locator('#dash-download-btn').click();
    await expect.soft(page.locator('#dl-compact-cb'), 'the unchecked state is restored').not.toBeChecked();
    // Clicking outside the dialog closes it.
    const box = (await page.locator('#download-modal-backdrop').boundingBox())!;
    await page.mouse.click(box.x + box.width - 6, box.y + box.height - 6);
    await expect(page.locator('#download-modal-backdrop')).toBeHidden();
  });
});

test.describe('Traffic Analyzer — CSV export', () => {
  test('every row of the exported CSV matches the analysis', async ({ analyzer, newLog, evidence }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    await page.locator('#dash-download-btn').click();
    const file = await captureDownload(page, () => page.locator('#dl-csv-btn').click());
    await evidence.save('export.csv', file.text);
    expect.soft(file.filename, 'CSV file name').toBe(`nginx-report-${new Date().toISOString().slice(0, 10)}.csv`);
    await expect(page.locator('#download-modal-backdrop'), 'the dialog closes after the export').toBeHidden();

    const [header, ...rows] = parseCsv(file.text);
    expect(header, 'CSV columns').toEqual(['Section', 'Category', 'Item', 'Value', 'Details']);
    const section = (name: string) => rows.filter(r => r[0] === name).map(r => r.slice(1));
    const requests = analyse(log).kept;
    const s = summarise(requests);
    const facts = new Map(requests.map(r => [r.ip, r.geo]));
    const sortRows = (list: string[][]) => list.map(r => r.join(' | ')).sort();

    expect.soft(section('Summary'), 'CSV Summary row').toEqual([['Overview', 'Total Requests', String(s.total), `Unique IPs: ${s.uniqueIps}, Countries: ${s.uniqueCountries}, ASNs: ${s.uniqueAsns}`]]);

    const topIps = section('Top IPs');
    expect.soft(topIps.map(r => Number(r[2])), 'CSV Top IPs: hits, highest first (up to 50)').toEqual(s.ips.slice(0, 50).map(i => i.hits));
    for (const row of topIps) {
      const g = facts.get(row[1]);
      const real = s.ips.find(i => i.key === row[1]);
      expect.soft(row, `CSV Top IPs row for ${row[1]}`).toEqual(g && real ? [g.country, row[1], String(real.hits), `ASN: ${g.asn || ''} ${g.asnOrg}`.trim()] : ['<address not in the log>']);
    }

    const ipsByCountry = uniqueIpsBy(requests, r => r.geo.country);
    const codeOf = new Map(requests.map(r => [r.geo.country, r.geo.countryCode]));
    expect.soft(sortRows(section('Country Distribution')), 'CSV Country Distribution rows')
      .toEqual(sortRows(s.countries.map(c => [codeOf.get(c.key)!, c.key, String(c.hits), `Unique IPs: ${ipsByCountry.get(c.key)!.size}`])));

    const ipsByAsn = uniqueIpsBy(requests, r => r.geo.asn);
    expect.soft(sortRows(section('ASN Distribution')), 'CSV ASN Distribution rows')
      .toEqual(sortRows(s.asns.map(a => [`AS${a.key}`, s.asnOrg.get(a.key)!, String(a.hits), `Unique IPs: ${ipsByAsn.get(a.key)!.size}`])));

    const urls = section('Top URLs');
    const urlRank = rank(requests, r => pathOf(r.url));
    expect.soft(urls.map(r => Number(r[2])), 'CSV Top URLs: hits, highest first (up to 20)').toEqual(urlRank.slice(0, 20).map(u => u.hits));
    for (const row of urls) {
      const real = urlRank.find(u => u.key === row[1]);
      expect.soft(!!real && row[0] === 'HTTP' && Number(row[2]) === real.hits && close(row[3], share(real.hits, s.total), 1), `CSV Top URLs row "${row.join(' | ')}"`).toBe(true);
    }

    const statusRank = rank(requests, r => String(r.status));
    const statuses = section('Status Codes');
    expect.soft(sortRows(statuses.map(r => r.slice(0, 3))), 'CSV Status Codes rows').toEqual(sortRows(statusRank.map(x => ['HTTP Status', x.key, String(x.hits)])));
    for (const row of statuses) {
      const real = statusRank.find(x => x.key === row[1]);
      if (real) expect.soft(close(row[3], share(real.hits, s.total), 1), `CSV Status Codes share of ${row[1]}: "${row[3]}"`).toBe(true);
    }

    const groups = new Map<string, LogRequest[]>();
    for (const r of requests) if (r.trafficClass !== 'human') groups.set(r.agent.group, [...(groups.get(r.agent.group) ?? []), r]);
    const bots = section('Bot Traffic');
    expect.soft(bots.map(r => r[0]).sort(), 'CSV Bot Traffic groups').toEqual([...groups.keys()].sort());
    for (const row of bots) {
      const list = groups.get(row[0]) ?? [];
      const verified = list.filter(r => r.trafficClass === 'verified').length;
      const spoofed = list.filter(r => r.trafficClass === 'spoofed').length;
      const status = verified && spoofed ? 'mixed' : spoofed ? 'spoofed' : verified ? 'verified' : 'unverified';
      expect.soft(row.slice(0, 3), `CSV Bot Traffic row "${row[0]}"`).toEqual([row[0], `Status: ${status}`, String(list.length)]);
      expect.soft(row[3], `CSV Bot Traffic details for "${row[0]}"`).toMatch(new RegExp(`^${new Set(list.map(r => r.ip)).size} IPs \\([\\d.]+%\\) \\| Verified: ${verified}, Spoofed: ${spoofed}$`));
    }

    const attackers = rank(requests.filter(r => r.trafficClass === 'spoofed'), r => `${r.agent.name}|${r.ip}`);
    expect.soft(sortRows(section('Spoofed Bot Attackers').map(r => r.slice(0, 3))), 'CSV Spoofed Bot Attackers rows (claimed bot, address, hits)')
      .toEqual(sortRows(attackers.map(a => [...a.key.split('|'), String(a.hits)])));
  });

  test('the CSV exported while a filter is active contains the filtered figures', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    await analyzer.selectTraffic('human');
    const { page } = analyzer;
    await page.locator('#dash-download-btn').click();
    const file = await captureDownload(page, () => page.locator('#dl-csv-btn').click());
    const rows = parseCsv(file.text);
    const human = analyse(log).kept.filter(r => r.trafficClass === 'human');
    const s = summarise(human);
    expect.soft(rows.find(r => r[0] === 'Summary')?.slice(3), 'CSV Summary for human traffic only').toEqual([String(s.total), `Unique IPs: ${s.uniqueIps}, Countries: ${s.uniqueCountries}, ASNs: ${s.uniqueAsns}`]);
    expect.soft(rows.filter(r => r[0] === 'Bot Traffic').length, 'no bot rows when only human traffic is shown').toBe(0);
  });
});
