import { gzipSync } from 'node:zlib';
import { test, expect } from './fixtures';
import { checkDashboard } from './checks';
import { analyse, grouped } from './oracle';
import type { GeneratedLog } from './generator';
import { StorageStandIn } from './storage';

/**
 * Traffic Analyzer — every way to give it logs, and starting over.
 *
 * The same log must produce the same dashboard whether it is pasted,
 * uploaded as a file, uploaded compressed, dropped on the page, split over
 * several files, or fetched from a URL.
 */

function merge(...logs: GeneratedLog[]): GeneratedLog {
  return {
    text: logs.map(l => l.text).join('\n'),
    requests: logs.flatMap(l => l.requests),
    invalidLines: logs.flatMap(l => l.invalidLines),
    blankLines: logs.reduce((sum, l) => sum + l.blankLines, 0),
    options: logs[0].options,
  };
}

test.describe('Traffic Analyzer — file upload', () => {
  test('a plain .log file gives the same dashboard as pasting its content', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analyseUploaded([{ name: 'access.log', mimeType: 'text/plain', buffer: Buffer.from(log.text) }]);
    const snap = await analyzer.snapshot();
    checkDashboard(snap, log, {}, 'uploaded access.log');
    expect.soft(snap.sourceLabel, 'source label names the uploaded file').toBe('access.log');
  });

  test('filters work on an uploaded file exactly as on pasted logs', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analyseUploaded([{ name: 'access.log', mimeType: 'text/plain', buffer: Buffer.from(log.text) }]);
    const kept = analyse(log).kept;
    const seed = kept.find(r => r.trafficClass === 'human' && r.geo.country !== 'Unknown')!;

    await analyzer.selectMethod(seed.method);
    checkDashboard(await analyzer.snapshot(), log, { filters: { method: seed.method } }, 'uploaded file, method filter');
    await analyzer.selectMethod('all');
    await analyzer.selectCountry(seed.geo.country);
    checkDashboard(await analyzer.snapshot(), log, { filters: { country: seed.geo.country } }, 'uploaded file, country filter');
    await analyzer.selectCountry('all');
    await analyzer.selectTraffic('human');
    checkDashboard(await analyzer.snapshot(), log, { filters: { traffic: 'human' } }, 'uploaded file, traffic filter');
    await analyzer.selectTraffic('all');
    await analyzer.searchIp(seed.ip.slice(0, seed.ip.length - 2));
    checkDashboard(await analyzer.snapshot(), log, { filters: { ipSearch: seed.ip.slice(0, seed.ip.length - 2) } }, 'uploaded file, IP search');
    await analyzer.searchIp('');
    await analyzer.searchPath('/api');
    checkDashboard(await analyzer.snapshot(), log, { filters: { pathSearch: '/api' } }, 'uploaded file, path search');
  });

  test('the exclusion options can be changed after uploading a file', async ({ analyzer, newLog }) => {
    const log = await newLog({ internalShare: 0.08, healthShare: 0.06 });
    await analyzer.analyseUploaded([{ name: 'access.log', mimeType: 'text/plain', buffer: Buffer.from(log.text) }]);
    await analyzer.rerender(() => analyzer.page.locator('#dash-skip-internal').click());
    checkDashboard(await analyzer.snapshot(), log, { options: { skip403: true, skipInternal: false } }, 'uploaded file, internal requests included');
  });

  test('a gzip-compressed file gives the same dashboard', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analyseUploaded([{ name: 'access.log.gz', mimeType: 'application/gzip', buffer: gzipSync(Buffer.from(log.text)) }]);
    const snap = await analyzer.snapshot();
    checkDashboard(snap, log, {}, 'uploaded access.log.gz');
    expect.soft(snap.sourceLabel).toBe('access.log.gz');
  });

  test('several files (a log rotation, one of them compressed) are analysed together', async ({ analyzer, newLog }) => {
    const first = await newLog({ requests: 300, start: new Date(Date.UTC(2026, 6, 1, 8, 0, 0)), spanSeconds: 3000 });
    const second = await newLog({ requests: 300, start: new Date(Date.UTC(2026, 6, 1, 9, 30, 0)), spanSeconds: 3000 });
    await analyzer.analyseUploaded([
      { name: 'access.log.1', mimeType: 'text/plain', buffer: Buffer.from(first.text) },
      { name: 'access.log.2.gz', mimeType: 'application/gzip', buffer: gzipSync(Buffer.from(second.text)) },
    ].map(f => ({ ...f, name: f.name.endsWith('.gz') ? f.name : `${f.name}.log` })));
    const snap = await analyzer.snapshot();
    checkDashboard(snap, merge(first, second), {}, 'two uploaded files');
    expect.soft(snap.sourceLabel, 'source label lists both files').toBe('access.log.1.log, access.log.2.gz');
  });

  test('a file dropped on the drop zone is selected and analysed', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 250 });
    const { page } = analyzer;
    const data = await page.evaluateHandle((content) => {
      const transfer = new DataTransfer();
      transfer.items.add(new File([content], 'dropped.log', { type: 'text/plain' }));
      return transfer;
    }, log.text);
    await page.dispatchEvent('#nginx-dropzone', 'dragenter', { dataTransfer: data });
    await expect.soft(page.locator('#nginx-dropzone'), 'the drop zone highlights while a file is dragged over it').toHaveClass(/dragover/);
    await page.dispatchEvent('#nginx-dropzone', 'drop', { dataTransfer: data });
    await expect.soft(page.locator('#nginx-dropzone')).not.toHaveClass(/dragover/);
    await expect(page.locator('#nginx-dropzone-filename')).toContainText('dropped.log');
    await page.locator('#nginx-analyze-btn').click();
    await analyzer.waitForDashboard();
    checkDashboard(await analyzer.snapshot(), log, {}, 'dropped file');
  });
});

test.describe('Traffic Analyzer — paste shortcut', () => {
  test('pasting log text anywhere on the input screen fills the paste box', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 150 });
    const { page } = analyzer;
    await page.evaluate(text => navigator.clipboard.writeText(text), log.text);
    await page.locator('h1').click();
    await page.keyboard.press('ControlOrMeta+V');
    await expect(page.locator('#nginx-tab-paste'), 'the paste source becomes selected').toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#nginx-logtext')).toHaveValue(log.text);
    // The Analyze button must reflect the pasted content without further typing.
    await expect.soft(page.locator('#nginx-analyze-btn'), 'Analyze is enabled after the shortcut paste').toBeEnabled();
  });
});

test.describe('Traffic Analyzer — remote URL', () => {
  test('a log fetched from a URL gives the same dashboard, labelled with the host', async ({ analyzer, newLog, request }) => {
    const log = await newLog({ requests: 300 });
    const { page } = analyzer;
    const storage = new StorageStandIn();
    const standIn = await StorageStandIn.needed(request);
    test.skip(!standIn, 'with real storage the backend fetches the URL itself; this test needs a reachable log URL (set up per environment)');
    await storage.install(page.context());
    // The server-side fetch of the remote URL is replaced: it "downloads" the generated log.
    let sentUrl = '';
    await page.route('**/api/storage/upload-external', async route => {
      sentUrl = (route.request().postDataJSON() as { url: string }).url;
      storage.objects.set('RemoteE2E', log.text);
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: true, shareCode: 'RemoteE2E', r2Key: 'shares/RemoteE2E.log.gz' }) });
    });
    await analyzer.chooseSource('url');
    await page.locator('#nginx-gist-url').fill('https://logs.example.com/nginx/access.log.gz');
    await page.locator('#nginx-analyze-btn').click();
    await analyzer.waitForDashboard();
    expect.soft(sentUrl, 'the URL typed by the user is what the server is asked to fetch').toBe('https://logs.example.com/nginx/access.log.gz');
    const snap = await analyzer.snapshot();
    checkDashboard(snap, log, {}, 'remote URL');
    expect.soft(snap.sourceLabel).toBe('Remote URL · logs.example.com');
  });

  test('a failing fetch is reported in a dialog and the input screen stays usable', async ({ analyzer, guard }) => {
    const { page } = analyzer;
    guard.allow(/upload-external|status of 4\d\d|status of 5\d\d|\[AnalysisError\]/);
    await page.route('**/api/storage/upload-external', route => route.fulfill({ status: 400, contentType: 'application/json', body: JSON.stringify({ error: 'Remote server answered 404' }) }));
    await analyzer.chooseSource('url');
    await page.locator('#nginx-gist-url').fill('https://logs.example.com/missing.log');
    await page.locator('#nginx-analyze-btn').click();
    const dialog = page.locator('#analysis-error-modal');
    await expect(dialog).toBeVisible();
    await expect.soft(dialog, 'the dialog repeats the reason').toContainText('Remote server answered 404');
    await page.locator('#analysis-error-dismiss').click();
    await expect(dialog).toBeHidden();
    await expect.soft(page.locator('#nginx-analyze-btn'), 'Analyze is usable again').toBeEnabled();
    await expect.soft(page.locator('#nginx-analyze-btn')).toContainText('Analyze Logs');
    await expect(page.locator('#nginx-dashboard')).toBeHidden();
  });
});

test.describe('Traffic Analyzer — sample data sets', () => {
  const SAMPLES = ['ecommerce-normal.log', 'attack-scanners.log', 'ddos-flood.log', 'bot-crawlers.log', 'heavy-traffic.log'];

  test('every sample offered on the page exists on the server', async ({ request }) => {
    for (const file of SAMPLES) {
      const response = await request.get(`/samples/${file}`);
      expect.soft(response.status(), `GET /samples/${file}`).toBe(200);
    }
  });

  test('clicking a sample analyses it and shows a dashboard', async ({ analyzer }) => {
    const { page } = analyzer;
    await page.locator('.btn-sample[data-sample="ecommerce-normal.log"]').click();
    await analyzer.waitForDashboard();
    const snap = await analyzer.snapshot();
    expect.soft(Number(snap.kpis.total.replace(/,/g, '')), 'the sample contains requests').toBeGreaterThan(0);
    expect.soft(snap.sourceNote, 'the source line says this is example data').toContain('Example dataset');
  });

  test('the home page link "Explore a sample" opens the analyzer with the sample analysed', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('link', { name: 'Explore a sample' }).click();
    await expect(page).toHaveURL(/\/nginx\?sample=ecommerce-normal\.log$/);
    await expect(page.locator('#signal-overview .kpi-micro-card').first(), 'the sample dashboard appears without further clicks').toBeVisible({ timeout: 90_000 });
  });
});

test.describe('Traffic Analyzer — starting over and adding logs', () => {
  test('"New Analysis" returns to a clean input screen, and a second log shows only its own data', async ({ analyzer, newLog }) => {
    const first = await newLog({ requests: 400, spanSeconds: 3 * 3600 });
    const second = await newLog({ requests: 250, urls: 'flat', spanSeconds: 20 * 60 });
    await analyzer.analysePasted(first.text);
    const { page } = analyzer;
    // Leave state behind on purpose: a filter, a time range, a stepper value, another page size.
    await analyzer.selectMethod('POST');
    await analyzer.stepHours('plus');
    await analyzer.setPerPage(50);

    await page.locator('#dash-back-btn').click();
    await expect(page.locator('#nginx-dashboard')).toBeHidden();
    await expect(page.locator('#nginx-input-section')).toBeVisible();
    await expect.soft(page.locator('#nginx-hero-section'), 'the page heading is back').toBeVisible();
    await expect.soft(page.locator('#nginx-sample-bar'), 'the samples are back').toBeVisible();

    await analyzer.analysePasted(second.text);
    const snap = await analyzer.snapshot();
    checkDashboard(snap, second, {}, 'second analysis');
    expect.soft(snap.timeline.stepper, 'the hours stepper starts at 1 for a new analysis').toBe('1');
  });

  test('"Add More Logs" by pasting merges the new lines into the analysis', async ({ analyzer, newLog }) => {
    const first = await newLog({ requests: 300, start: new Date(Date.UTC(2026, 8, 9, 6, 0, 0)), spanSeconds: 1800 });
    const second = await newLog({ requests: 260, start: new Date(Date.UTC(2026, 8, 9, 7, 15, 0)), spanSeconds: 2400 });
    await analyzer.analysePasted(first.text);
    const { page } = analyzer;

    await page.locator('#dash-add-logs-btn').click();
    const modal = page.locator('#add-logs-modal');
    await expect(modal).toBeVisible();
    for (const tab of ['file', 'url', 'curl', 'paste']) {
      await page.locator(`#add-logs-tab-${tab}`).click();
      for (const other of ['curl', 'file', 'paste', 'url']) {
        await expect.soft(page.locator(`#add-logs-panel-${other}`), `panel "${other}" while tab "${tab}" is selected`).toBeVisible({ visible: other === tab });
      }
    }
    await page.locator('#add-logs-paste-text').fill(second.text);
    await analyzer.rerender(() => page.locator('#btn-append-paste').click());
    await expect(modal, 'the dialog closes after merging').toBeHidden();

    const merged = merge(first, second);
    const snap = await analyzer.snapshot();
    checkDashboard(snap, merged, {}, 'after adding more logs');
    await expect.soft(page.locator('#dash-source-badge'), 'node badge after merging a second source')
      .toHaveText(`2 nodes · ${grouped(analyse(merged).kept.length)} requests`);
  });

  test('the "Add More Logs" dialog closes by its button and by clicking outside', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 150 });
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    const modal = page.locator('#add-logs-modal');
    await page.locator('#dash-add-logs-btn').click();
    await expect(modal).toBeVisible();
    await page.locator('#add-logs-modal-close').click();
    await expect(modal).toBeHidden();
    await page.locator('#dash-add-logs-btn').click();
    const box = (await modal.boundingBox())!;
    await page.mouse.click(box.x + box.width - 6, box.y + box.height - 6);
    await expect(modal).toBeHidden();
    checkDashboard(await analyzer.snapshot(), log, {}, 'after opening and closing the dialog');
  });
});
