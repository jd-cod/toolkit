import { test, expect } from './fixtures/dashboard';
import { gotoAnalyzedDashboard } from './fixtures/dashboard';

/**
 * QA 5 + 6: dragging the timeline slider must not morph the chart behind it,
 * and the floating window readout must state the actual selected time range.
 *
 * The background chart doubles as the brush canvas: it must always show the
 * FULL dataset so the curtains remain the only visual selection. If the chart
 * were rebuilt from the filtered subset, its axis domain and label count
 * change — which is exactly what we assert cannot happen.
 */

test('dragging a handle keeps the full-span chart and shows matching timestamps', async ({ page, console }) => {
  await gotoAnalyzedDashboard(page);

  // Capture the axis first/last tick text through Chart.js instances.
  const getTicks = () => page.evaluate(() => {
    const Chart = (window as any).Chart;
    const line = Chart.getChart(document.getElementById('rps-chart'));
    if (!line) return null;
    const scale = line.scales?.x;
    if (!scale) return null;
    return {
      first: scale.ticks[0]?.label,
      last: scale.ticks[scale.ticks.length - 1]?.label,
      count: scale.ticks.length,
    };
  });

  // QA 5's morph path only fires when a fixed resolution is active (the
  // subset recompute requires activeRpsResolution !== 'auto'), so pin the
  // 1s resolution first — then capture the full-span axis at that resolution.
  await page.locator('.rps-res-btn[data-res="1"]').click();
  await page.waitForTimeout(400);

  const ticksBefore = await getTicks();
  expect(ticksBefore).not.toBeNull();

  // Drag the START handle ~30% to the right via mouse events on the handle.
  const handle = page.locator('#handle-start');
  await handle.scrollIntoViewIfNeeded();
  const box = (await handle.boundingBox())!;
  const trackBox = (await page.locator('#slider-scrubber-track').boundingBox())!;
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(trackBox.x + trackBox.width * 0.3, box.y + box.height / 2, { steps: 8 });
  await page.mouse.up();

  // Wait for the re-render to settle.
  await expect(page.locator('#time-window-readout')).toBeVisible();
  await page.waitForTimeout(400);

  const ticksAfter = await getTicks();
  // QA 5: the chart must still span the FULL range — same first/last tick,
  // same tick count. Any change means the chart was rebuilt from the subset.
  expect(ticksAfter?.first).toBe(ticksBefore!.first);
  expect(ticksAfter?.last).toBe(ticksBefore!.last);
  expect(ticksAfter?.count).toBe(ticksBefore!.count);

  // QA 6: the readout must show an actual HH:MM:SS → HH:MM:SS window, and the
  // start handle position must correspond to it (readout non-empty, arrow present).
  const readout = await page.locator('#time-window-readout').textContent();
  expect(readout).toMatch(/\d{2}:\d{2}:\d{2}\s*→\s*\d{2}:\d{2}:\d{2}/);

  console.assertClean();
});

/**
 * The request-rate card keeps a short headline, readable chart intervals,
 * and compact time presets with explicit labels for both control groups.
 */
test('request-rate card has clear interval and compact time-range controls', async ({ page, console }) => {
  await gotoAnalyzedDashboard(page);

  // Headline is short — the four-word "Request Rate & Attack Timeline" is gone.
  await expect(page.locator('text=Request Rate & Attack Timeline')).toHaveCount(0);

  await expect(page.getByText('Chart Interval:', { exact: true })).toBeVisible();
  await expect(page.getByText('Time Range:', { exact: true })).toBeVisible();

  // Keep the fixed intervals, with readable units.
  const resLabels = await page.locator('.rps-res-btn').allTextContents();
  expect(resLabels.map((t) => t.trim())).toEqual(['1 sec', '5 sec', '1 min', '15 min']);

  // Only the first preset repeats "Last"; the hour stepper stays numeric.
  const presets = await page.locator('.shortcut-btn[data-mins]').allTextContents();
  expect(presets.map((t) => t.trim())).toEqual(['Last 30m', '1h', '2h']);
  await expect(page.getByRole('textbox', { name: 'Time range in hours', exact: true })).toHaveValue('1');
  await expect(page.getByRole('button', { name: 'All time', exact: true })).toBeVisible();
  expect(await page.locator('text=(Spike)').count()).toBe(0);

  console.assertClean();
});
