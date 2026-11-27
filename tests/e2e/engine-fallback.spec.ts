import { test, expect, waitForEngineReady, BUILD_LOG } from './fixtures/dashboard';

// The engine runs in a Web Worker. A browser that cannot start one (workers
// switched off, a policy that blocks them) runs the same engine on the page.

test('the engine gives the same analysis in a worker and on the page', async ({ page, console: watcher }) => {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  const result = await page.evaluate(async log => {
    const runtime = window as any;
    const RealWorker = runtime.Worker;
    const shown = (analysis: any) => JSON.stringify({ data: analysis.data, reading: analysis.parseResult, firstPage: analysis.pageResult });
    const errors = async (analysis: any) => (await runtime.LogEngine.filter(analysis.worker, { statusCategory: '4xx' })).data.total_requests;

    const threaded = await runtime.LogEngine.analyze(log);
    runtime.Worker = function () { throw new Error('workers are switched off'); };
    let onPage;
    try {
      onPage = await runtime.LogEngine.analyze(log);
    } finally {
      runtime.Worker = RealWorker;
    }
    const out = {
      threadedIsWorker: threaded.worker instanceof RealWorker,
      onPageIsWorker: onPage.worker instanceof RealWorker,
      same: shown(threaded) === shown(onPage),
      total: onPage.data.total_requests,
      errors: [await errors(threaded), await errors(onPage)],
    };
    threaded.worker.terminate();
    onPage.worker.terminate();
    return out;
  }, BUILD_LOG);
  // Of the ten sample lines, repeated 60 times, one is an ordinary 403.
  expect(result).toEqual({ threadedIsWorker: true, onPageIsWorker: false, same: true, total: 540, errors: [240, 240] });
  watcher.assertClean();
});

test('without workers the dashboard still analyses, filters and pages a pasted log', async ({ page, console: watcher }) => {
  await page.addInitScript(() => {
    (window as any).Worker = function () { throw new Error('workers are switched off'); };
  });
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  await page.getByRole('tab', { name: 'Paste logs' }).click();
  await page.fill('#nginx-logtext', BUILD_LOG);
  await page.click('#nginx-analyze-btn');
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('540', { timeout: 45_000 });

  await page.locator('#filter-status').selectOption('5xx');
  await expect(page.locator('#filter-matching-badge')).toContainText('Matching 60 / 540 requests');
  await expect(page.locator('#explorer-rows-body tr')).toHaveCount(25);
  await page.locator('.exp-page-btn[data-page="2"]').click();
  await expect(page.locator('#explorer-pagination-wrap')).toContainText('Page 2 of 3');

  // Switching an exclusion reads the pasted text again.
  await page.locator('#dash-skip-403').uncheck();
  await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('600');
  watcher.assertClean();
});
