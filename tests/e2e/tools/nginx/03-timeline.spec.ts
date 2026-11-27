import { test, expect } from './fixtures';
import { checkDashboard, checkTimeline, expectationFor } from './checks';
import { analyse, stamp, clock, duration } from './oracle';

/**
 * Traffic Analyzer — Traffic Timeline card.
 *
 * Chart interval buttons, time-range buttons, the hours stepper, both drag
 * handles (mouse and keyboard), the legend toggles, and how the rest of the
 * dashboard follows the selected time window.
 */

const MINUTE = 60_000;

test.describe('Traffic Analyzer — timeline chart intervals', () => {
  test('each interval regroups the same requests (12-minute log: every interval fits)', async ({ analyzer, newLog }) => {
    const log = await newLog({ spanSeconds: 12 * 60 + 17, requests: 500 });
    await analyzer.analysePasted(log.text);
    for (const seconds of [1, 5, 60, 900, 1] as const) {
      await analyzer.chooseInterval(seconds);
      const snap = await analyzer.snapshot();
      expect.soft(snap.timeline.activeInterval, `interval button highlighted after choosing ${seconds}s`).toBe(String(seconds));
      checkTimeline(snap, expectationFor(log), {}, `interval ${seconds}s:`);
    }
  });

  test('an interval that needs more than 1,500 points falls back to a coarser bucket and says so (4-hour log)', async ({ analyzer, newLog }) => {
    const log = await newLog({ spanSeconds: 4 * 3600 + 211, requests: 700 });
    await analyzer.analysePasted(log.text);
    for (const seconds of [1, 5, 60, 900] as const) {
      await analyzer.chooseInterval(seconds);
      checkTimeline(await analyzer.snapshot(), expectationFor(log), {}, `interval ${seconds}s on a 4h log:`);
    }
  });

  test('a log that crosses midnight labels the axis, the handles and the readout with dates', async ({ analyzer, newLog }) => {
    const log = await newLog({ start: new Date(Date.UTC(2026, 4, 30, 21, 40, 13)), spanSeconds: 26 * 3600 + 95, requests: 600 });
    await analyzer.analysePasted(log.text);
    const snap = await analyzer.snapshot();
    checkDashboard(snap, log, {}, 'multi-day log');
    expect.soft(snap.timeline.readout?.start, 'readout start carries the date').toBe('2026-05-30 21:40:13');
    for (const seconds of [60, 900] as const) {
      await analyzer.chooseInterval(seconds);
      checkTimeline(await analyzer.snapshot(), expectationFor(log), {}, `multi-day log, interval ${seconds}s:`);
    }
  });

  test('a log whose requests all share one second still draws a consistent timeline', async ({ analyzer, newLog }) => {
    const log = await newLog({ spanSeconds: 0, requests: 60, bursts: false, invalidLines: 0 });
    await analyzer.analysePasted(log.text);
    const snap = await analyzer.snapshot();
    checkDashboard(snap, log, {}, 'single-second log');
    expect.soft(snap.timeline.handles.start.disabled, 'handles are disabled when there is no time span to select').toBe('true');
    expect.soft(snap.timeline.handles.end.disabled).toBe('true');
  });

  test('legend entries hide and show their series', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 300 });
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    for (const [id, index, name] of [['legend-item-total', 0, 'Total Traffic'], ['legend-item-errors', 1, 'Error responses']] as const) {
      await page.locator(`#${id}`).click();
      let snap = await analyzer.snapshot();
      expect.soft(snap.timeline.chart?.datasets[index].hidden, `"${name}" series hidden after clicking its legend entry`).toBe(true);
      await expect.soft(page.locator(`#${id}`), `"${name}" legend entry is struck through while hidden`).toHaveCSS('text-decoration-line', 'line-through');
      await page.locator(`#${id}`).click();
      snap = await analyzer.snapshot();
      expect.soft(snap.timeline.chart?.datasets[index].hidden, `"${name}" series visible again after a second click`).toBe(false);
    }
  });

  test('hovering a bucket shows its time range and its counts', async ({ analyzer, newLog }) => {
    const log = await newLog({ spanSeconds: 40 * 60, requests: 500 });
    await analyzer.analysePasted(log.text);
    await analyzer.chooseInterval(60);
    const { page } = analyzer;
    const kept = analyse(log).kept;
    const span = analyse(log).span!;

    // Hover the busiest minute so the tooltip has something to say.
    await page.locator('#rps-chart').scrollIntoViewIfNeeded();
    const target = await page.evaluate(() => {
      const chart = (window as any).Chart.getChart(document.getElementById('rps-chart'));
      const points = chart.data.datasets[0].data as { x: number; y: number }[];
      const index = points.reduce((best, p, i) => (p.y > points[best].y ? i : best), 0);
      const el = chart.getDatasetMeta(0).data[index];
      const box = chart.canvas.getBoundingClientRect();
      return { index, x: box.left + el.x, y: box.top + el.y };
    });
    await page.mouse.move(target.x - 6, target.y + 4);
    await page.mouse.move(target.x, target.y + 1, { steps: 3 });
    const tooltip = await page.evaluate(() => {
      const chart = (window as any).Chart.getChart(document.getElementById('rps-chart'));
      return { opacity: chart.tooltip?.opacity ?? 0, title: chart.tooltip?.title ?? [], body: (chart.tooltip?.body ?? []).flatMap((b: any) => b.lines) };
    });
    const bucketStart = Math.floor((kept.reduce((m, r) => Math.min(m, r.ts), Infinity)) / MINUTE) * MINUTE + target.index * MINUTE;
    const inBucket = kept.filter(r => r.ts >= bucketStart && r.ts < bucketStart + MINUTE);
    const from = Math.max(span.minTs, bucketStart);
    const to = Math.min(span.maxTs, bucketStart + MINUTE - 1000);
    expect.soft(tooltip.opacity, 'a tooltip with the bucket\'s numbers appears when the mouse is over a point of the timeline (if this is 0, something lies on top of the chart and swallows the mouse)').toBeGreaterThan(0);
    expect.soft(tooltip.title, 'tooltip title is the bucket time range').toEqual([`${stamp(from)} → ${stamp(to)}`]);
    expect.soft(tooltip.body.map((l: string) => l.trim().replace(/\s+/g, ' ')), 'tooltip lines')
      .toEqual([`Total Requests: ${inBucket.length}`, `HTTP 4xx/5xx Errors: ${inBucket.filter(r => r.status >= 400).length}`]);
  });
});

test.describe('Traffic Analyzer — time range', () => {
  test('"Last 30m", "1h" and "2h" keep exactly the requests of that last period, and "All time" restores everything', async ({ analyzer, newLog }) => {
    const log = await newLog({ spanSeconds: 3 * 3600 + 20 * 60 + 41, requests: 800 });
    await analyzer.analysePasted(log.text);
    const span = analyse(log).span!;
    for (const minutes of [30, 60, 120] as const) {
      await analyzer.lastMinutes(minutes);
      const snap = await analyzer.snapshot();
      const window = { startMs: span.maxTs - minutes * MINUTE, endMs: span.maxTs };
      checkDashboard(snap, log, { filters: { window }, rangeLabel: { kind: 'last', minutes } }, `Last ${minutes}m`);
      expect.soft(snap.timeline.activeRange.length, `exactly one time-range button is highlighted after choosing ${minutes} minutes (highlighted: ${snap.timeline.activeRange.join(', ') || 'none'})`).toBe(1);
    }
    await analyzer.allTime();
    const snap = await analyzer.snapshot();
    checkDashboard(snap, log, {}, 'All time');
    expect.soft(snap.timeline.activeRange, '"All time" is the highlighted range').toEqual(['All time']);
  });

  test('a range longer than the log keeps every request and is not reported as an active filter', async ({ analyzer, newLog }) => {
    const log = await newLog({ spanSeconds: 17 * 60 + 9, requests: 300 });
    await analyzer.analysePasted(log.text);
    for (const minutes of [30, 60, 120] as const) {
      await analyzer.lastMinutes(minutes);
      checkDashboard(await analyzer.snapshot(), log, {}, `Last ${minutes}m on a 17-minute log`);
    }
  });

  test('the hours stepper selects the last N hours, by buttons and by typing, within the length of the log', async ({ analyzer, newLog }) => {
    const log = await newLog({ spanSeconds: 5 * 3600 + 10 * 60 + 5, requests: 800 });
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    const span = analyse(log).span!;
    const lastHours = (hours: number) => ({ startMs: Math.max(span.minTs, span.maxTs - hours * 60 * MINUTE), endMs: span.maxTs });
    const check = async (hours: number, label: string) => {
      const snap = await analyzer.snapshot();
      const window = lastHours(hours);
      const whole = window.startMs === span.minTs;
      checkDashboard(snap, log, whole ? {} : { filters: { window }, rangeLabel: { kind: 'last', minutes: hours * 60 } }, label);
      expect.soft(snap.timeline.stepper, `${label}: stepper field`).toBe(String(hours));
    };

    await analyzer.stepHours('plus');
    await check(2, 'stepper + (2 hours)');
    await analyzer.stepHours('plus');
    await check(3, 'stepper + (3 hours)');
    await analyzer.stepHours('minus');
    await check(2, 'stepper - (2 hours)');

    const typeHours = (value: string) => analyzer.rerender(async () => {
      await page.locator('#stepper-val').fill(value);
      await page.locator('#stepper-val').press('Enter');
    });
    await typeHours('4');
    await check(4, 'typed 4 hours');
    // The log is 5h10m long: the largest meaningful value is 6 hours (the whole log).
    await typeHours('99');
    await check(6, 'typed 99 hours (limited to the log length)');
    await typeHours('abc');
    await check(1, 'typed text (falls back to 1 hour)');
  });

  test('arrow keys move a handle by one second, Shift+arrow by one minute, Home/End to the ends', async ({ analyzer, newLog }) => {
    const log = await newLog({ spanSeconds: 50 * 60 + 3, requests: 500 });
    await analyzer.analysePasted(log.text);
    const span = analyse(log).span!;
    let start = span.minTs;
    let end = span.maxTs;
    const check = async (label: string) => {
      const whole = start === span.minTs && end === span.maxTs;
      checkDashboard(await analyzer.snapshot(), log, whole ? {} : { filters: { window: { startMs: start, endMs: end } }, rangeLabel: { kind: 'custom' } }, label);
    };

    for (let i = 0; i < 3; i++) await analyzer.pressOnHandle('start', 'ArrowRight');
    start += 3000;
    await check('start handle: ArrowRight x3');
    await analyzer.pressOnHandle('start', 'Shift+ArrowRight');
    start += MINUTE;
    await check('start handle: Shift+ArrowRight');
    await analyzer.pressOnHandle('start', 'ArrowLeft');
    start -= 1000;
    await check('start handle: ArrowLeft');
    await analyzer.pressOnHandle('end', 'ArrowLeft');
    end -= 1000;
    await check('end handle: ArrowLeft');
    await analyzer.pressOnHandle('end', 'Shift+ArrowLeft');
    end -= MINUTE;
    await check('end handle: Shift+ArrowLeft');
    await analyzer.pressOnHandle('end', 'End');
    end = span.maxTs;
    await check('end handle: End');
    await analyzer.pressOnHandle('start', 'Home');
    start = span.minTs;
    await check('start handle: Home (whole log again)');
  });

  test('dragging the handles with the mouse selects the window they are dropped on', async ({ analyzer, newLog }) => {
    const log = await newLog({ spanSeconds: 90 * 60 + 31, requests: 700 });
    await analyzer.analysePasted(log.text);
    const span = analyse(log).span!;
    const length = span.maxTs - span.minTs;
    const trackWidth = (await analyzer.page.locator('#slider-scrubber-track').boundingBox())!.width;
    // One pixel of the track is this much time; allow two pixels plus rounding to the second.
    const tolerance = (length / trackWidth) * 2 + 1000;

    await analyzer.dragHandle('start', 0.35);
    let snap = await analyzer.snapshot();
    const start = snap.timeline.handles.start.now;
    expect.soft(Math.abs(start - (span.minTs + length * 0.35)) <= tolerance,
      `start handle dropped at 35% of the track should select about ${stamp(span.minTs + length * 0.35)}; it selected ${stamp(start)}`).toBe(true);
    checkDashboard(snap, log, { filters: { window: { startMs: start, endMs: span.maxTs } }, rangeLabel: { kind: 'custom' } }, 'after dragging the start handle');

    await analyzer.dragHandle('end', 0.8);
    snap = await analyzer.snapshot();
    const end = snap.timeline.handles.end.now;
    expect.soft(Math.abs(end - (span.minTs + length * 0.8)) <= tolerance,
      `end handle dropped at 80% of the track should select about ${stamp(span.minTs + length * 0.8)}; it selected ${stamp(end)}`).toBe(true);
    checkDashboard(snap, log, { filters: { window: { startMs: start, endMs: end } }, rangeLabel: { kind: 'custom' } }, 'after dragging both handles');
    expect.soft(snap.timeline.readout?.pill, 'readout shows the length of the selection').toBe(duration(end - start));
    expect.soft(snap.timeline.handles.start.label, 'start handle label').toBe(clock(start));

    await analyzer.allTime();
    checkDashboard(await analyzer.snapshot(), log, {}, 'All time after dragging');
  });

  test('a time range combines with other filters', async ({ analyzer, newLog }) => {
    const log = await newLog({ spanSeconds: 2 * 3600 + 30 * 60, requests: 800 });
    await analyzer.analysePasted(log.text);
    const span = analyse(log).span!;
    const window = { startMs: span.maxTs - 60 * MINUTE, endMs: span.maxTs };
    await analyzer.lastMinutes(60);
    await analyzer.selectMethod('GET');
    checkDashboard(await analyzer.snapshot(), log, { filters: { window, method: 'GET' }, rangeLabel: { kind: 'last', minutes: 60 } }, 'Last 1h + GET');
    await analyzer.selectTraffic('human');
    checkDashboard(await analyzer.snapshot(), log, { filters: { window, method: 'GET', traffic: 'human' }, rangeLabel: { kind: 'last', minutes: 60 } }, 'Last 1h + GET + human');
    await analyzer.clearFilters();
    checkDashboard(await analyzer.snapshot(), log, {}, 'after clearing');
  });
});
