import { test, expect, waitForEngineReady } from './fixtures/dashboard';
import type { Page } from '@playwright/test';

// Deliberately unaligned to chart buckets, with a log offset and different
// browser timezone. Excluded 403s mark the file edges.
const START = Date.UTC(2026, 9, 1, 4, 30, 7);
const END = START + 4 * 60 * 60 * 1000;
const EVENTS = Array.from({ length: 17 }, (_, i) => START + i * 15 * 60 * 1000);
const INCLUDED = EVENTS.slice(1, -1);
const LOG = EVENTS.map((ts, i) => {
  const wall = new Date(ts).toISOString();
  return `203.0.113.10 - - [01/Oct/2026:${wall.slice(11, 19)} +0530] "GET /event-${i} HTTP/1.1" ${i === 0 || i === 16 ? 403 : 200} 123 "-" "Mozilla/5.0"`;
}).reverse().join('\n');

function fmtTime(ms: number) {
  return new Date(ms).toISOString().replace('T', ' ').slice(0, 19);
}

async function analyze(page: Page, log = LOG) {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  await page.getByRole('tab', { name: 'Paste logs' }).click();
  await page.locator('#nginx-logtext').fill(log);
  await page.locator('#nginx-analyze-btn').click();
  await expect(page.locator('#rps-chart')).toBeVisible({ timeout: 45000 });
  await page.locator('#signal-traffic').scrollIntoViewIfNeeded();
}

async function selection(page: Page) {
  const start = Number(await page.locator('#handle-start').getAttribute('aria-valuenow'));
  const end = Number(await page.locator('#handle-end').getAttribute('aria-valuenow'));
  return { start, end };
}

async function assertReadout(page: Page, start: number, end: number) {
  await expect(page.getByRole('slider', { name: 'Start time', exact: true })).toHaveAttribute('aria-valuetext', fmtTime(start));
  await expect(page.getByRole('slider', { name: 'End time', exact: true })).toHaveAttribute('aria-valuetext', fmtTime(end));
  await expect(page.locator('#time-window-readout time').first()).toHaveAttribute('datetime', new Date(start).toISOString());
  await expect(page.locator('#time-window-readout time').last()).toHaveAttribute('datetime', new Date(end).toISOString());
  await expect(page.locator('#time-window-readout')).not.toContainText('UTC');
}

async function assertFilteredRequests(page: Page, start: number, end: number) {
  const count = INCLUDED.filter(ts => ts >= start && ts <= end).length;
  await expect(page.locator('#filter-matching-badge strong')).toHaveText(String(count));
  if (count === 0) {
    await expect(page.locator('#explorer-rows-body tr td')).toHaveText('No log entries match the current filters.');
  } else {
    await expect(page.locator('#explorer-rows-body tr')).toHaveCount(count);
    const expected = INCLUDED.filter(ts => ts >= start && ts <= end).reverse().map(fmtTime);
    await expect(page.locator('#explorer-rows-body tr td:first-child')).toHaveText(expected);
  }
}

async function dragHandle(page: Page, side: 'start' | 'end', fraction: number) {
  const handle = page.locator(`#handle-${side}`);
  await handle.scrollIntoViewIfNeeded();
  const box = (await handle.boundingBox())!;
  const track = (await page.locator('#slider-scrubber-track').boundingBox())!;
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(track.x + track.width * fraction, box.y + box.height / 2, { steps: 8 });
  const { start, end } = await selection(page);
  // Readout and handles must agree while the pointer is still held down.
  await assertReadout(page, start, end);
  const expected = START + (END - START) * Math.max(0, Math.min(1, fraction));
  expect(Math.abs((side === 'start' ? start : end) - expected)).toBeLessThan((END - START) / track.width + 1000);
  await page.mouse.up();
  await assertReadout(page, start, end);
  await assertFilteredRequests(page, start, end);
  return { start, end };
}

test.describe('Timeline time accuracy', () => {
  test.use({ timezoneId: 'America/New_York' });

  test('main thread and worker honor log offsets and preserve excluded log endpoints', async ({ page, console: watcher }) => {
    await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
    await waitForEngineReady(page);
    const result = await page.evaluate(async log => {
      const direct = (window as any).LogParser.parseIPs(log);
      const worker = new Worker('/js/log-parser.worker.js');
      const threaded: any = await new Promise((resolve, reject) => {
        worker.onmessage = e => e.data.type === 'success' ? resolve(e.data.result) : reject(new Error(e.data.error));
        worker.onerror = reject;
        worker.postMessage({ action: 'parse', logText: log });
      }).finally(() => worker.terminate());
      return [direct, threaded].map(parsed => ({ min: parsed.minTimestamp, max: parsed.maxTimestamp, count: parsed.logEntries.length }));
    }, LOG);
    expect(result).toEqual([{ min: START, max: END, count: 15 }, { min: START, max: END, count: 15 }]);
    watcher.assertClean();
  });

  test('all chart intervals keep the exact log start and end without timezone shifts', async ({ page, console: watcher }) => {
    await analyze(page);
    await assertReadout(page, START, END);
    for (const res of ['1', '5', '60', '900']) {
      await page.locator(`.rps-res-btn[data-res="${res}"]`).click();
      const axis = await page.evaluate(() => {
        const chart = (window as any).Chart.getChart(document.getElementById('rps-chart'));
        const x = chart.scales.x;
        return { type: x.type, min: x.min, max: x.max, middle: x.getValueForPixel((chart.chartArea.left + chart.chartArea.right) / 2) };
      });
      expect(axis).toEqual({ type: 'linear', min: START, max: END, middle: (START + END) / 2 });
      await assertReadout(page, START, END);
    }
    watcher.assertClean();
  });

  test('both drag handles and the floating window match the filtered requests through resets and presets', async ({ page, console: watcher }) => {
    await analyze(page);
    await dragHandle(page, 'start', 0.23);
    const range = await dragHandle(page, 'end', 0.77);
    await page.locator('.rps-res-btn[data-res="900"]').click();
    await assertReadout(page, range.start, range.end);

    const window = (await page.locator('#slider-active-window').boundingBox())!;
    const track = (await page.locator('#slider-scrubber-track').boundingBox())!;
    const x = window.x + window.width / 2;
    const y = window.y + window.height * 0.75;
    await page.mouse.move(x, y);
    await page.mouse.down();
    await page.mouse.move(x - track.width * 0.1, y, { steps: 8 });
    const moved = await selection(page);
    await assertReadout(page, moved.start, moved.end);
    expect(Math.abs((moved.end - moved.start) - (range.end - range.start))).toBeLessThanOrEqual(1000);
    expect(moved.start).toBeLessThan(range.start);
    await page.mouse.up();
    await assertFilteredRequests(page, moved.start, moved.end);

    await page.getByRole('button', { name: 'Last 30m', exact: true }).click();
    await assertReadout(page, END - 30 * 60000, END);
    await assertFilteredRequests(page, END - 30 * 60000, END);
    await page.getByRole('button', { name: 'All time', exact: true }).click();
    await assertReadout(page, START, END);
    await assertFilteredRequests(page, START, END);
    watcher.assertClean();
  });

  test('a single timestamp keeps both boundaries equal', async ({ page, console: watcher }) => {
    const ts = Date.UTC(2026, 9, 1, 7, 23, 5);
    await analyze(page, '203.0.113.10 - - [01/Oct/2026:07:23:05 -0700] "GET /only HTTP/1.1" 200 123 "-" "Mozilla/5.0"');
    await assertReadout(page, ts, ts);
    await page.locator('.rps-res-btn[data-res="900"]').click();
    await assertReadout(page, ts, ts);
    await expect(page.locator('#filter-matching-badge strong')).toHaveText('1');
    watcher.assertClean();
  });

  test('keyboard adjustments include exact boundary seconds and an empty window keeps the full clock', async ({ page, console: watcher }) => {
    await analyze(page);
    await page.getByRole('button', { name: 'Last 30m', exact: true }).click();
    await assertFilteredRequests(page, END - 30 * 60000, END);
    await page.locator('#handle-start').focus();
    await page.keyboard.press('ArrowRight');
    await assertReadout(page, END - 30 * 60000 + 1000, END);
    await assertFilteredRequests(page, END - 30 * 60000 + 1000, END);
    await page.keyboard.press('Home');
    await assertReadout(page, START, END);
    await dragHandle(page, 'start', 0.46);
    await dragHandle(page, 'end', 0.47);
    await expect(page.locator('#filter-matching-badge strong')).toHaveText('0');
    await dragHandle(page, 'start', -0.02);
    await dragHandle(page, 'end', 1.02);
    await assertReadout(page, START, END);
    watcher.assertClean();
  });
});

test.describe('Mobile timeline', () => {
  test.use({ viewport: { width: 390, height: 844 }, hasTouch: true, timezoneId: 'Asia/Kolkata' });

  test('touch dragging updates the end time without scrolling or changing the log clock', async ({ page, console: watcher }) => {
    await analyze(page);
    await assertReadout(page, START, END);
    const handle = (await page.locator('#handle-end').boundingBox())!;
    const track = (await page.locator('#slider-scrubber-track').boundingBox())!;
    const beforeScroll = await page.evaluate(() => scrollY);
    const client = await page.context().newCDPSession(page);
    const point = { x: handle.x + handle.width / 2, y: handle.y + handle.height / 2 };
    await client.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [point] });
    for (let i = 1; i <= 6; i++) {
      await client.send('Input.dispatchTouchEvent', {
        type: 'touchMove', touchPoints: [{ x: point.x + (track.x + track.width * 0.7 - point.x) * i / 6, y: point.y }],
      });
    }
    const { start, end } = await selection(page);
    expect(start).toBe(START);
    expect(Math.abs(end - (START + (END - START) * 0.7))).toBeLessThan((END - START) / track.width + 1000);
    await assertReadout(page, start, end);
    await client.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] });
    await assertFilteredRequests(page, start, end);
    const labelsClear = await page.evaluate(() => {
      const badge = document.getElementById('time-window-readout')!.getBoundingClientRect();
      return Array.from(document.querySelectorAll('.slider-handle-time')).every(label => {
        const rect = label.getBoundingClientRect();
        return rect.right <= badge.left || rect.left >= badge.right || rect.bottom <= badge.top || rect.top >= badge.bottom;
      });
    });
    expect(labelsClear).toBe(true);
    expect(await page.evaluate(() => scrollY)).toBe(beforeScroll);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await client.detach();
    watcher.assertClean();
  });
});
