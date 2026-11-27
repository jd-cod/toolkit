import { expect } from '@playwright/test';
import type { GeneratedLog, LogRequest } from './generator';
import type { DashboardSnapshot } from './page';
import {
  analyse, applyFilters, summarise, timeline, share, grouped, inUnit, stamp, clock, spanStamp, sameDay, duration,
  explorerRows, rowKey, DEFAULT_OPTIONS,
  type AnalysisOptions, type ViewFilters, type Ranked, type Summary, type Analysis,
} from './oracle';

/**
 * Compares a dashboard snapshot with the oracle, value by value.
 *
 * All comparisons are soft: one call reports every wrong number on the
 * dashboard. Messages name the widget, the value and the active filters.
 */

export interface ViewState {
  options?: AnalysisOptions;
  filters?: ViewFilters;
  /** How the time window was chosen; decides the wording of the range label. */
  rangeLabel?: { kind: 'all' } | { kind: 'last'; minutes: number } | { kind: 'custom' };
  /** Rows per page in the Log Explorer. */
  perPage?: number;
  /** Number of active filters the "Clear" pill should report. */
  activeFilterCount?: number;
}

export interface Expectation {
  analysis: Analysis;
  matching: LogRequest[];
  summary: Summary;
  /** Summary of everything kept (no view filters): feeds the filter dropdowns and the timeline. */
  overall: Summary;
}

export function expectationFor(log: GeneratedLog, state: ViewState = {}): Expectation {
  const analysis = analyse(log, state.options ?? DEFAULT_OPTIONS);
  const matching = applyFilters(analysis.kept, state.filters ?? {});
  return { analysis, matching, summary: summarise(matching), overall: summarise(analysis.kept) };
}

export function describeFilters(state: ViewState): string {
  const f = state.filters ?? {};
  const parts = [
    f.method && `method=${f.method}`, f.country && `country=${f.country}`, f.asn !== undefined && `asn=AS${f.asn}`,
    f.traffic && `traffic=${f.traffic}`, f.botGroup && `botGroup=${f.botGroup}`,
    f.ipSearch && `ip~"${f.ipSearch}"`, f.pathSearch && `path~"${f.pathSearch}"`,
    f.window && `time=${stamp(f.window.startMs)}..${stamp(f.window.endMs)}`,
    state.options && !state.options.skip403 && '403 included', state.options && !state.options.skipInternal && 'internal included',
  ].filter(Boolean);
  return parts.length ? `[${parts.join(', ')}]` : '[no filters]';
}

/** Whitespace as the browser renders it: runs collapsed, ends trimmed. */
const rendered = (text: string) => text.replace(/\s+/g, ' ').trim();

const num = (text: string) => Number(text.replace(/,/g, '').replace(/[^0-9.-]/g, ''));

/** A displayed percentage must be the true share rounded to `decimals` places. */
function expectPercent(shown: string, part: number, total: number, decimals: number, message: string): void {
  const value = Number(shown.replace(/[()%\s]/g, ''));
  const exact = share(part, total);
  const tolerance = 0.5 / 10 ** decimals + 1e-9;
  expect.soft(Number.isFinite(value) && Math.abs(value - exact) <= tolerance,
    `${message}: shown "${shown}", true share is ${exact.toFixed(4)}% (${part} of ${total})`).toBe(true);
  const shownDecimals = (shown.replace(/[()%\s]/g, '').split('.')[1] || '').length;
  expect.soft(shownDecimals <= decimals, `${message}: "${shown}" should have at most ${decimals} decimal place(s)`).toBe(true);
}

/**
 * A "top N" list must show the N highest counts, each with its real count.
 * Entries with equal counts may come in any order, and at the cut-off any of
 * the tied entries may be shown.
 */
function expectTopN(shown: { key: string; hits: string }[], truth: Ranked<string>[], limit: number, message: string): void {
  const want = truth.slice(0, limit);
  expect.soft(shown.map(r => num(r.hits)), `${message}: counts, highest first (expected keys: ${want.map(w => `${w.key}=${w.hits}`).join(', ')})`)
    .toEqual(want.map(w => w.hits));
  const pool = truth.map(t => `${t.key}\u0000${t.hits}`);
  const problems: string[] = [];
  for (const row of shown) {
    const at = pool.indexOf(`${row.key}\u0000${num(row.hits)}`);
    if (at === -1) {
      const real = truth.find(t => t.key === row.key);
      problems.push(real ? `"${row.key}" shows ${row.hits}, real count is ${real.hits}` : `"${row.key}" (${row.hits}) is not in the data`);
    } else pool.splice(at, 1);
  }
  expect.soft(problems, `${message}: every listed entry must exist with that count`).toEqual([]);
}

export function checkHeader(snap: DashboardSnapshot, want: Expectation, ctx: string): void {
  const { analysis } = want;
  expect.soft(snap.parsedLines, `${ctx} toolbar "Parsed"`).toBe(`Parsed: ${grouped(analysis.kept.length)} lines`);
  expect.soft(snap.skippedLines, `${ctx} toolbar "Skipped"`).toBe(`Skipped: ${grouped(analysis.skipped.total)} lines`);
  if (analysis.span) {
    expect.soft(snap.spanText, `${ctx} toolbar "Span" (first and last request time, and whole minutes between them)`)
      .toBe(`Span: ${spanStamp(analysis.span.minTs)} → ${spanStamp(analysis.span.maxTs)} (${analysis.span.minutes}m)`);
  }
  expect.soft(snap.exclusions.privateIp, `${ctx} skipped "private/local IP" count`).toBe(grouped(analysis.skipped.internalAddress));
  expect.soft(snap.exclusions.healthCheck, `${ctx} skipped "health-check path" count`).toBe(grouped(analysis.skipped.healthCheck));
  expect.soft(snap.exclusions.forbidden, `${ctx} skipped "ordinary 403" count`).toBe(grouped(analysis.skipped.forbidden));
  expect.soft(snap.exclusions.invalid, `${ctx} skipped "invalid" count`).toBe(grouped(analysis.skipped.invalid));
}

export function checkKpis(snap: DashboardSnapshot, want: Expectation, ctx: string): void {
  const s = want.summary;
  expect.soft(snap.kpis.total, `${ctx} TOTAL REQUESTS`).toBe(grouped(s.total));
  expect.soft(snap.kpis.uniqueIps, `${ctx} UNIQUE IPS`).toBe(grouped(s.uniqueIps));
  expect.soft(snap.kpis.asns, `${ctx} ASNS & NETWORKS`).toBe(grouped(s.uniqueAsns));
  expect.soft(snap.kpis.countries, `${ctx} COUNTRIES`).toBe(grouped(s.uniqueCountries));
  expectPercent(snap.kpis.human, s.human, s.total, 0, `${ctx} HUMAN TRAFFIC`);
  expect.soft(snap.kpis.verified, `${ctx} VERIFIED BOTS count`).toBe(grouped(s.verified));
  expect.soft(snap.kpis.spoofed, `${ctx} SPOOFED BOTS count`).toBe(grouped(s.spoofed));
  expectPercent((snap.kpis.verifiedLabel.match(/\(([^)]*)\)/) || [])[1] || 'missing', s.verified, s.total, 1, `${ctx} VERIFIED BOTS percentage in the label`);
  expectPercent((snap.kpis.spoofedLabel.match(/\(([^)]*)\)/) || [])[1] || 'missing', s.spoofed, s.total, 1, `${ctx} SPOOFED BOTS percentage in the label`);
  expectPercent((snap.errorText.match(/^[\d.]+%/) || ['missing'])[0], s.errors, s.total, 1, `${ctx} error responses (4xx + 5xx) percentage`);
  expect.soft(snap.filters.matching, `${ctx} "Matching x / y requests" counter`)
    .toBe(`Matching ${grouped(s.total)} / ${grouped(want.analysis.kept.length)} requests`);
}

export function checkMethodsAndEgress(snap: DashboardSnapshot, want: Expectation, ctx: string): void {
  const s = want.summary;
  expectTopN(snap.methods.map(m => ({ key: m.method, hits: m.count })), s.methods, 99, `${ctx} Methods ribbon`);
  for (const m of snap.methods) {
    const real = s.methods.find(x => x.key === m.method);
    if (real) expectPercent(m.pct, real.hits, s.total, 1, `${ctx} Methods ribbon share of ${m.method}`);
  }
  const egress = snap.egress.match(/([\d.]+)\s*(B|KB|MB|GB) Transferred/);
  expect.soft(egress, `${ctx} Data Egress should read "<number> <unit> Transferred", shown "${snap.egress}"`).not.toBeNull();
  if (egress) {
    const real = inUnit(s.bytes, egress[2]);
    expect.soft(Math.abs(Number(egress[1]) - real) <= 0.05 + 1e-9 && (real < 1024 || egress[2] === 'GB') && (real >= 1 || egress[2] === 'B'),
      `${ctx} Data Egress: shown "${egress[1]} ${egress[2]}", the kept requests sent ${s.bytes} bytes (= ${real.toFixed(3)} ${egress[2]})`).toBe(true);
  }
}

/** The dropdowns list what is in the analysed log (not only what matches the current filters). */
export function checkFilterOptions(snap: DashboardSnapshot, want: Expectation, ctx: string): void {
  const all = want.overall;
  const counted = (label: string) => Number((label.match(/\(([\d,]+)\)\s*$/) || [])[1]?.replace(/,/g, ''));

  expect.soft(snap.filters.method.options.map(o => o.value), `${ctx} method dropdown options`)
    .toEqual(['all', ...all.methods.map(m => m.key).sort()]);

  const countries = snap.filters.country.options.slice(1);
  const knownCountries = all.countries.filter(c => c.key !== 'Unknown');
  expect.soft(countries.map(o => o.value).sort(), `${ctx} country dropdown lists every identified country`).toEqual(knownCountries.map(c => c.key).sort());
  for (const option of countries) {
    expect.soft(counted(option.label), `${ctx} country dropdown count for "${option.value}" (label "${option.label}")`)
      .toBe(all.countries.find(c => c.key === option.value)?.hits);
  }
  expect.soft(countries.map(o => counted(o.label)), `${ctx} country dropdown is ordered by count, highest first`)
    .toEqual(countries.map(o => counted(o.label)).sort((a, b) => b - a));

  const asns = snap.filters.asn.options.slice(1);
  expect.soft(asns.map(o => o.value).sort(), `${ctx} ASN dropdown lists every network`).toEqual(all.asns.map(a => `AS${a.key}`).sort());
  for (const option of asns) {
    const asn = Number(option.value.replace(/^AS/, ''));
    expect.soft(counted(option.label), `${ctx} ASN dropdown count for ${option.value} (label "${option.label}")`).toBe(all.asns.find(a => a.key === asn)?.hits);
    const org = all.asnOrg.get(asn) ?? '';
    expect.soft(rendered(option.label).startsWith(rendered(`${option.value} - ${org.slice(0, 20)}`)), `${ctx} ASN dropdown label for ${option.value} should start with the network name "${org.slice(0, 20)}", shown "${option.label}"`).toBe(true);
  }

  const paths = snap.filters.path.options.slice(1);
  expectTopN(paths.map(o => ({ key: o.value, hits: String(counted(o.label)) })), all.firstSegments, 25, `${ctx} path dropdown (first path segment, with its request count)`);

  expect.soft(snap.filters.traffic.options.map(o => o.value), `${ctx} traffic dropdown options`)
    .toEqual(['all', 'human', 'all_bots', 'verified', 'spoofed', 'unverified']);
}

const BUCKET_LABELS: Record<number, string> = { 1: '1s', 2: '2s', 5: '5s', 10: '10s', 15: '15s', 30: '30s', 60: '1m', 120: '2m', 300: '5m', 600: '10m', 900: '15m', 1800: '30m', 3600: '1h', 7200: '2h', 14400: '4h', 21600: '6h', 43200: '12h', 86400: '1d' };

function bucketFromNote(note: string): number | null {
  const match = note.match(/Using (\d+)(s|m|h|d) buckets/);
  if (!match) return null;
  return Number(match[1]) * { s: 1, m: 60, h: 3600, d: 86400 }[match[2] as 's' | 'm' | 'h' | 'd'];
}

/**
 * The timeline always draws the whole analysed log; the shaded window marks
 * the selected time range. So it is compared with all kept requests.
 */
export function checkTimeline(snap: DashboardSnapshot, want: Expectation, state: ViewState, ctx: string): void {
  const { analysis } = want;
  const t = snap.timeline;
  if (!analysis.span || analysis.kept.length === 0) return;
  const { minTs, maxTs } = analysis.span;

  expect.soft(t.painted, `${ctx} timeline canvas should be drawn (not blank)`).toBe(true);
  expect.soft(t.chart, `${ctx} timeline chart should exist`).not.toBeNull();
  if (!t.chart) return;

  // Axis: starts at the first request, ends at the last, labelled with those times.
  const withDate = !sameDay(minTs, maxTs);
  const tickLabel = (ts: number) => (withDate ? stamp(ts) : clock(ts));
  expect.soft(t.chart.xMin, `${ctx} timeline axis starts at the first request (${stamp(minTs)}); shown ${stamp(t.chart.xMin)}`).toBe(minTs);
  if (maxTs > minTs) expect.soft(t.chart.xMax, `${ctx} timeline axis ends at the last request (${stamp(maxTs)}); shown ${stamp(t.chart.xMax)}`).toBe(maxTs);
  const ticks = t.chart.ticks;
  expect.soft(ticks.length >= 2 || maxTs === minTs, `${ctx} timeline axis should have tick labels`).toBe(true);
  for (const tick of ticks) {
    expect.soft(tick.label, `${ctx} timeline tick at ${stamp(tick.value)} should be labelled with that time`).toBe(tickLabel(Math.round(tick.value)));
  }
  if (ticks.length >= 2) {
    expect.soft(ticks[0].value, `${ctx} first timeline tick is the first request time`).toBe(minTs);
    expect.soft(ticks[ticks.length - 1].value, `${ctx} last timeline tick is the last request time`).toBe(maxTs);
  }

  // Bucket size: the chosen interval, unless that needs more than 1,500 points; then the note names the size used.
  const requested = Number(t.activeInterval);
  const keptMin = analysis.kept.reduce((m, r) => Math.min(m, r.ts), Infinity);
  const keptMax = analysis.kept.reduce((m, r) => Math.max(m, r.ts), -Infinity);
  const pointsNeeded = (seconds: number) => Math.floor(keptMax / (seconds * 1000)) - Math.floor(keptMin / (seconds * 1000)) + 1;
  const fromNote = bucketFromNote(t.note);
  const bucket = fromNote ?? requested;
  if (pointsNeeded(requested) <= 1500) {
    expect.soft(t.note, `${ctx} timeline: the ${requested}s interval fits in 1,500 points, so no fallback note is expected`).toBe('');
  } else {
    expect.soft(fromNote, `${ctx} timeline: ${requested}s needs ${pointsNeeded(requested)} points (limit 1,500); a note must name the bucket size used, shown "${t.note}"`).not.toBeNull();
    expect.soft(pointsNeeded(bucket) <= 1500 && bucket > requested, `${ctx} timeline fallback bucket (${bucket}s) must be coarser than requested and fit in 1,500 points`).toBe(true);
  }
  expect.soft(t.chart.yTitle, `${ctx} timeline y-axis title names the bucket size`).toBe(`Requests / ${BUCKET_LABELS[bucket] ?? `${bucket}s`}`);

  // Data: one point per bucket, count = requests in that bucket.
  const buckets = timeline(analysis.kept, bucket);
  const total = t.chart.datasets[0];
  expect.soft(total?.label, `${ctx} timeline first series`).toBe('Total Traffic');
  const clampX = (ts: number) => Math.max(minTs, Math.min(maxTs, ts));
  expect.soft(total?.points.map(p => p.y), `${ctx} timeline request count per ${bucket}s bucket, from ${stamp(buckets[0].startMs)}`).toEqual(buckets.map(b => b.count));
  expect.soft(total?.points.map(p => p.x), `${ctx} timeline bucket positions on the time axis`).toEqual(buckets.map(b => clampX(b.startMs)));
  expect.soft(total?.points.reduce((sum, p) => sum + p.y, 0), `${ctx} timeline: sum of all buckets equals the analysed requests`).toBe(analysis.kept.length);

  const errorTotal = buckets.reduce((sum, b) => sum + b.errors, 0);
  const errors = t.chart.datasets[1];
  if (errorTotal > 0) {
    expect.soft(errors?.label, `${ctx} timeline second series`).toBe('Error responses (4xx, 5xx)');
    expect.soft(errors?.points.map(p => p.y), `${ctx} timeline 4xx+5xx count per ${bucket}s bucket`).toEqual(buckets.map(b => b.errors));
  } else {
    expect.soft(errors, `${ctx} timeline: no error series when there are no error responses`).toBeUndefined();
  }

  // Selection: handles, readout and range label.
  const window = state.filters?.window ?? { startMs: minTs, endMs: maxTs };
  const readoutLabel = (ts: number) => (withDate ? stamp(ts) : clock(ts));
  expect.soft(t.handles.start.min, `${ctx} start handle lower bound is the first request time`).toBe(minTs);
  expect.soft(t.handles.end.max, `${ctx} end handle upper bound is the last request time`).toBe(maxTs);
  expect.soft(t.handles.start.now, `${ctx} start handle position (${stamp(t.handles.start.now)}) should be ${stamp(window.startMs)}`).toBe(window.startMs);
  expect.soft(t.handles.end.now, `${ctx} end handle position (${stamp(t.handles.end.now)}) should be ${stamp(window.endMs)}`).toBe(window.endMs);
  expect.soft(t.handles.start.text, `${ctx} start handle spoken value`).toBe(stamp(window.startMs));
  expect.soft(t.handles.end.text, `${ctx} end handle spoken value`).toBe(stamp(window.endMs));
  expect.soft(t.handles.start.label, `${ctx} start handle label`).toBe(clock(window.startMs));
  expect.soft(t.handles.end.label, `${ctx} end handle label`).toBe(clock(window.endMs));
  expect.soft(t.readout?.start, `${ctx} range readout start`).toBe(readoutLabel(window.startMs));
  expect.soft(t.readout?.end, `${ctx} range readout end`).toBe(readoutLabel(window.endMs));
  const length = duration(window.endMs - window.startMs);
  const isFull = window.startMs === minTs && window.endMs === maxTs;
  const kind = state.rangeLabel?.kind ?? (isFull ? 'all' : 'custom');
  const pill = isFull ? `All time · ${length}` : kind === 'last' ? `Last ${length}` : length;
  expect.soft(t.readout?.pill, `${ctx} range readout label`).toBe(pill);
}

export function checkDistributionCharts(snap: DashboardSnapshot, want: Expectation, ctx: string): void {
  const s = want.summary;
  const c = snap.countryChart;
  expect.soft(c.badge, `${ctx} Country Distribution badge`).toBe(`${s.uniqueCountries} Nations`);
  if (s.total > 0) expect.soft(c.painted, `${ctx} country chart should be drawn (not blank)`).toBe(true);
  expectTopN(c.labels.map((label, i) => ({ key: label, hits: String(c.data[i]) })), s.countries, 7, `${ctx} country chart slices (top 7 countries)`);
  expect.soft(c.legend.map(l => l.country), `${ctx} country legend lists the same countries as the chart, in the same order`).toEqual(c.labels);
  for (const item of c.legend) {
    const real = s.countries.find(x => x.key === item.country);
    if (real) expectPercent(item.pct, real.hits, s.total, 0, `${ctx} country legend share of ${item.country}`);
  }

  const a = snap.asnChart;
  expect.soft(a.badge, `${ctx} ASN Distribution badge`).toBe(`${s.uniqueAsns} ASNs`);
  if (s.total > 0) expect.soft(a.painted, `${ctx} ASN chart should be drawn (not blank)`).toBe(true);
  const barLabel = (asn: number) => {
    const org = s.asnOrg.get(asn) || `AS${asn}`;
    return org.length > 25 ? `${org.slice(0, 25)}...` : org;
  };
  expectTopN(a.labels.map((label, i) => ({ key: label, hits: String(a.data[i]) })),
    s.asns.map(x => ({ key: barLabel(x.key), hits: x.hits })), 10, `${ctx} ASN chart bars (top 10 networks, names cut at 25 characters)`);
}

export function checkTables(snap: DashboardSnapshot, want: Expectation, ctx: string, options: { paths?: boolean } = {}): void {
  const s = want.summary;
  const t = snap.tables;

  // 1. Most Active IPs
  expect.soft(t.ips.badge, `${ctx} "Most Active IPs" badge (number of client addresses in view)`).toBe(`${s.uniqueIps} IPs`);
  expectTopN(t.ips.rows.map(r => ({ key: r.ip, hits: r.hits })), s.ips, 15, `${ctx} "Most Active IPs" table (top 15)`);

  // 2. Bot Intelligence
  expect.soft(t.bots.badge, `${ctx} "Bot Intelligence" badge`).toBe(`${s.botGroups} bot groups`);
  const statusWord = { verified: 'Verified', spoofed: 'Spoof', unverified: 'Bot' } as const;
  const wantBots = s.botRows.map(r => `${r.status === 'spoofed' ? `Fake ${r.group} (Impersonator)` : r.group} | ${grouped(r.hits)} | ${statusWord[r.status]} | filter=${r.status}/${r.group}`).sort();
  const shownBots = t.bots.rows.map(r => `${r.label} | ${r.hits} | ${r.status.replace(/^[^A-Za-z]+/, '')} | filter=${r.filter}/${r.group}`).sort();
  expect.soft(shownBots, `${ctx} "Bot Intelligence" rows (group, hits, status, and the filter a click applies)`).toEqual(wantBots);
  if (s.botRows.length === 0) expect.soft(t.bots.empty, `${ctx} "Bot Intelligence" empty text`).toBe('No bots detected');

  // 3. Targeted Paths (request path = URL without query string)
  if (options.paths) {
    expect.soft(t.paths.badge, `${ctx} "Targeted Paths" badge (number of distinct request paths)`).toBe(`${s.paths.length} Paths`);
    expectTopN(t.paths.rows.map(r => ({ key: r.path, hits: r.hits })), s.paths, 15, `${ctx} "Targeted Paths" table (top 15 request paths)`);
    for (const row of t.paths.rows) {
      const real = s.paths.find(p => p.key === row.path);
      if (real) expectPercent(row.share, real.hits, s.total, 1, `${ctx} "Targeted Paths" share of ${row.path}`);
    }
  }

  // 5. ASNs & Networks
  expect.soft(t.asns.badge, `${ctx} "ASNs & Networks" badge`).toBe(`${s.uniqueAsns} ASNs`);
  expectTopN(t.asns.rows.map(r => ({ key: r.asn, hits: r.hits })), s.asns.map(a => ({ key: String(a.key), hits: a.hits })), 15, `${ctx} "ASNs & Networks" table (top 15)`);
  for (const row of t.asns.rows) {
    const asn = Number(row.asn);
    expect.soft(row.code, `${ctx} "ASNs & Networks" code for network ${row.asn}`).toBe(`AS${row.asn}`);
    expect.soft(row.org, `${ctx} "ASNs & Networks" name of AS${row.asn}`).toBe(rendered(s.asnOrg.get(asn) ?? 'missing from data'));
    const real = s.asns.find(a => a.key === asn);
    if (real) expectPercent(row.share, real.hits, s.total, 1, `${ctx} "ASNs & Networks" share of AS${row.asn}`);
  }

  // 6. Top Referrers
  expect.soft(t.referrers.badge, `${ctx} "Top Referrers" badge`).toBe(`${Math.min(s.referrers.length, 20)} Sites`);
  expectTopN(t.referrers.rows.map(r => ({ key: r.referrer, hits: r.hits })), s.referrers, 15, `${ctx} "Top Referrers" table (top 15; "-" is direct traffic)`);
  for (const row of t.referrers.rows) {
    const real = s.referrers.find(r => r.key === row.referrer);
    if (real) expectPercent(row.share, real.hits, s.total, 1, `${ctx} "Top Referrers" share of ${row.referrer}`);
  }

  // 4. AbuseIPDB table lists the most active addresses, not yet scanned.
  expectTopN(t.abuse.rows.filter(r => r.ip).map(r => ({ key: r.ip, hits: String(s.ips.find(i => i.key === r.ip)?.hits ?? -1) })), s.ips, 20, `${ctx} "Abusive IPs" table lists the 20 most active addresses`);
}

/** First page of the Log Explorer plus its counters. */
export function checkExplorer(snap: DashboardSnapshot, want: Expectation, state: ViewState, ctx: string, page = 1): void {
  const perPage = state.perPage ?? 25;
  const rows = explorerRows(want.matching);
  const total = rows.length;
  const pages = Math.max(1, Math.ceil(total / perPage));
  const e = snap.explorer;

  expect.soft(e.count, `${ctx} Log Explorer header count`).toBe(`(${grouped(total)} entries)`);
  expect.soft(e.pageText, `${ctx} Log Explorer page indicator`).toBe(`Page ${page} of ${pages} (${grouped(total)} entries)`);
  expect.soft(e.perPage, `${ctx} Log Explorer page size`).toBe(String(perPage));

  const slice = rows.slice((page - 1) * perPage, page * perPage);
  if (total === 0) {
    expect.soft(e.emptyMessage, `${ctx} Log Explorer empty message`).toBe('No log entries match the current filters.');
    return;
  }
  expect.soft(e.rows.length, `${ctx} Log Explorer rows on page ${page}`).toBe(slice.length);
  expect.soft(e.rows.map(r => r.time), `${ctx} Log Explorer page ${page}: times, newest first`).toEqual(slice.map(r => r.time));

  // Rows that share a second may be listed in any order.
  const pool = rows.map(rowKey);
  const wrong: string[] = [];
  for (const row of e.rows) {
    const at = pool.indexOf(rowKey(row));
    if (at === -1) wrong.push(rowKey(row));
    else pool.splice(at, 1);
  }
  expect.soft(wrong, `${ctx} Log Explorer page ${page}: rows that do not correspond to a matching log line (time | ip | method | path | status | cc | country | protocol | user agent)`).toEqual([]);

  expect.soft(e.firstDisabled, `${ctx} Log Explorer "First" disabled on page 1 only`).toBe(page === 1);
  expect.soft(e.prevDisabled, `${ctx} Log Explorer "Prev" disabled on page 1 only`).toBe(page === 1);
  expect.soft(e.nextDisabled, `${ctx} Log Explorer "Next" disabled on the last page only`).toBe(page === pages);
  expect.soft(e.lastDisabled, `${ctx} Log Explorer "Last" disabled on the last page only`).toBe(page === pages);
  const active = e.pageButtons.filter(b => b.active).map(b => b.page);
  expect.soft(active, `${ctx} Log Explorer highlighted page button`).toEqual([String(page)]);
}

export function checkFilterControls(snap: DashboardSnapshot, want: Expectation, state: ViewState, ctx: string): void {
  const f = state.filters ?? {};
  expect.soft(snap.filters.method.value, `${ctx} method dropdown shows the active filter`).toBe(f.method ?? 'all');
  expect.soft(snap.filters.country.value, `${ctx} country dropdown shows the active filter`).toBe(f.country ?? 'all');
  expect.soft(snap.filters.asn.value, `${ctx} ASN dropdown shows the active filter`).toBe(f.asn !== undefined ? `AS${f.asn}` : 'all');
  expect.soft(snap.filters.traffic.value, `${ctx} traffic dropdown shows the active filter`).toBe(f.traffic ?? 'all');
  expect.soft(snap.filters.ipSearch, `${ctx} IP search box shows the active search`).toBe(f.ipSearch ?? '');
  expect.soft(snap.filters.pathSearch, `${ctx} path search box shows the active search`).toBe(f.pathSearch ?? '');

  const active = state.activeFilterCount
    ?? [f.method, f.country, f.asn !== undefined ? 1 : undefined, f.traffic, f.ipSearch, f.pathSearch, f.window].filter(v => v !== undefined && v !== '').length;
  expect.soft(snap.clearPill.visible, `${ctx} "Clear Active Filters" pill is shown only while a filter is active`).toBe(active > 0);
  if (active > 0) {
    expect.soft(snap.clearPill.text, `${ctx} "Clear Active Filters" pill text`)
      .toBe(`✕ Clear Active Filters (${active} active · ${grouped(want.summary.total)} hits)`);
  }
}

/** The complete comparison used after every action. */
export function checkDashboard(snap: DashboardSnapshot, log: GeneratedLog, state: ViewState = {}, label = ''): Expectation {
  const want = expectationFor(log, state);
  const ctx = `${label ? `${label} ` : ''}${describeFilters(state)}:`;
  checkHeader(snap, want, ctx);
  checkKpis(snap, want, ctx);
  checkMethodsAndEgress(snap, want, ctx);
  checkFilterOptions(snap, want, ctx);
  checkFilterControls(snap, want, state, ctx);
  checkTimeline(snap, want, state, ctx);
  checkDistributionCharts(snap, want, ctx);
  checkTables(snap, want, ctx, { paths: log.options.urls === 'flat' });
  checkExplorer(snap, want, state, ctx);
  return want;
}
