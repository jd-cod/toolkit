import fs from 'node:fs';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { test, expect, waitForEngineReady } from './fixtures/dashboard';

const FIXTURE_DIR = path.resolve(__dirname, '..', 'fixtures');
const GOLD_LOG_PATH = path.join(FIXTURE_DIR, 'nginx-release-golden.log');
const GOLD_LOG = fs.existsSync(GOLD_LOG_PATH) ? fs.readFileSync(GOLD_LOG_PATH, 'utf8') : '';
const MANIFEST = JSON.parse(
  fs.readFileSync(path.join(FIXTURE_DIR, 'nginx-release-golden.json'), 'utf8'),
) as any;

type GoldenMode = 'default_skip_403' | 'include_403';

async function loadGolden(page: Parameters<typeof waitForEngineReady>[0], skip403 = true) {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  await page.getByRole('tab', { name: 'Paste logs' }).click();
  if (!skip403) await page.locator('#nginx-skip-403').uncheck();
  await page.fill('#nginx-logtext', GOLD_LOG);
  await page.getByRole('button', { name: 'Analyze Logs', exact: true }).click();
  await expect(page.locator('#nginx-dashboard')).toBeVisible({ timeout: 45_000 });
  await expect(page.locator('.kpi-micro-card').first()).toBeVisible();
}

async function engineSnapshot(page: Parameters<typeof waitForEngineReady>[0], skip403: boolean) {
  return page.evaluate(({ log, skip }) => {
    const parseResult = (window as any).LogParser.parseIPs(log, { skip403: skip });
    const entries = parseResult.logEntries;
    (window as any).Analyzer.enrichLogEntries(entries);
    const data = (window as any).Analyzer.analyzeEnhancedLogs(entries);
    const countMap = (items: Array<{ [key: string]: unknown }>, key: string, value: string) =>
      Object.fromEntries(items.map((item) => [String(item[key]), item[value]]));
    const nonzero = (items: Array<{ [key: string]: unknown }>, key: string) =>
      Object.fromEntries(items.filter((item) => Number(item.count) > 0).map((item) => [String(item[key]), item.count]));

    return {
      parse: {
        parsedLines: parseResult.parsedLines.length,
        skippedLines: parseResult.skippedLines.length,
        skipReasons: parseResult.skippedLines.reduce((acc: Record<string, number>, item: { reason: string }) => {
          acc[item.reason] = (acc[item.reason] || 0) + 1;
          return acc;
        }, {}),
        minIso: new Date(parseResult.minTimestamp).toISOString(),
        maxIso: new Date(parseResult.maxTimestamp).toISOString(),
        spanMinutes: parseResult.logSpanMinutes,
      },
      analysis: {
        totalRequests: data.total_requests,
        uniqueIps: data.unique_ips,
        uniqueCountries: data.unique_countries,
        uniqueAsns: data.unique_asns,
        humanRequests: data.human_requests,
        verifiedBots: data.verified_bots_count,
        spoofedBots: data.spoofed_bots_count,
        unverifiedBots: data.unverified_bots_count,
        automatedRequests: data.automated_count,
        statusCategories: data.http_metrics.status_categories,
        statusHits: countMap(data.http_metrics.status_hits, 'code', 'count'),
        methodHits: countMap(data.http_metrics.method_hits, 'method', 'count'),
        responseSize: data.http_metrics.response_size,
        errorRate: data.security_metrics.error_rate,
        errorPercentage: data.security_metrics.error_percentage,
        countryHits: countMap(data.country_hits, 'country', 'hits'),
        asnHits: countMap(data.asn_hits, 'asn', 'hits'),
        ipHits: countMap(data.top_ips, 'ip', 'hits'),
        referrers: countMap(data.referrers, 'referrer', 'hits'),
        urls: countMap(data.http_metrics.top_urls, 'url', 'count'),
        paths: countMap(data.http_metrics.top_paths, 'path', 'count'),
        hourlyNonzeroUtc: nonzero(data.temporal_distribution.hourly, 'hour'),
        dailyNonzeroUtc: nonzero(data.temporal_distribution.daily, 'day'),
        requestRate: {
          bucketSeconds: data.request_rate.bucket_seconds,
          bucketLabel: data.request_rate.bucket_label,
          totalBuckets: data.request_rate.total_buckets,
          totalRequests: data.request_rate.total_requests,
          durationSeconds: data.request_rate.duration_seconds,
          startTime: data.request_rate.start_time,
          endTime: data.request_rate.end_time,
          peakCount: data.request_rate.peak_count,
          peakTimestampIso: new Date(data.request_rate.peak_timestamp).toISOString(),
          nonzeroBuckets: data.request_rate.buckets
            .filter((bucket: { count: number }) => bucket.count > 0)
            .map((bucket: Record<string, unknown>) => ({
              label: bucket.label,
              count: bucket.count,
              status_2xx: bucket.status_2xx,
              status_3xx: bucket.status_3xx,
              status_4xx: bucket.status_4xx,
              status_5xx: bucket.status_5xx,
            })),
        },
      },
    };
  }, { log: GOLD_LOG, skip: skip403 });
}

function expectEngineSnapshot(snapshot: any, mode: GoldenMode) {
  const expected = MANIFEST[mode];
  expect(snapshot.parse).toEqual({
    parsedLines: expected.parsed_lines,
    skippedLines: expected.skipped_lines,
    skipReasons: expected.skip_reasons,
    minIso: MANIFEST.bounds.min_iso,
    maxIso: MANIFEST.bounds.max_iso,
    spanMinutes: MANIFEST.bounds.span_minutes,
  });
  expect(snapshot.analysis).toMatchObject({
    totalRequests: expected.total_requests,
    humanRequests: expected.human_requests,
    unverifiedBots: expected.unverified_bots,
    automatedRequests: expected.automated_requests,
    statusCategories: expected.status_categories,
    methodHits: expected.method_hits,
    responseSize: expected.response_size,
    errorRate: expected.error_rate,
    errorPercentage: expected.error_percentage,
    countryHits: expected.country_hits,
    asnHits: expected.asn_hits,
  });

  if (mode === 'default_skip_403') {
    expect(snapshot.analysis).toMatchObject({
      uniqueIps: expected.unique_ips,
      uniqueCountries: expected.unique_countries,
      uniqueAsns: expected.unique_asns,
      verifiedBots: expected.verified_bots,
      spoofedBots: expected.spoofed_bots,
      statusHits: expected.status_hits,
      ipHits: expected.ip_hits,
      referrers: expected.referrers,
      urls: expected.top_urls,
      paths: expected.top_paths,
      hourlyNonzeroUtc: expected.hourly_nonzero_utc,
      dailyNonzeroUtc: expected.daily_nonzero_utc,
      requestRate: {
        bucketSeconds: expected.request_rate.bucket_seconds,
        bucketLabel: expected.request_rate.bucket_label,
        totalBuckets: expected.request_rate.total_buckets,
        totalRequests: expected.request_rate.total_requests,
        durationSeconds: expected.request_rate.duration_seconds,
        startTime: expected.request_rate.start_time,
        endTime: expected.request_rate.end_time,
        peakCount: expected.request_rate.peak_count,
        peakTimestampIso: expected.request_rate.peak_timestamp_iso,
        nonzeroBuckets: expected.request_rate.nonzero_buckets,
      },
    });
  }
}

test.describe('Nginx release golden analysis', () => {
  test.skip(!GOLD_LOG, `fixture not present at ${GOLD_LOG_PATH}`);
  test.use({ timezoneId: 'Asia/Kolkata' });
  test('parser and analyzer match the independent default oracle', async ({ page, console: watcher }) => {
    await loadGolden(page);
    const snapshot = await engineSnapshot(page, true);
    expectEngineSnapshot(snapshot, 'default_skip_403');
    watcher.assertClean();
  });

  test('disabling 403 filtering changes only the expected metrics', async ({ page, console: watcher }) => {
    await loadGolden(page, false);
    const snapshot = await engineSnapshot(page, false);
    expectEngineSnapshot(snapshot, 'include_403');
    expect(snapshot.analysis.uniqueIps).toBe(MANIFEST.default_skip_403.unique_ips);
    expect(snapshot.analysis.uniqueCountries).toBe(MANIFEST.default_skip_403.unique_countries);
    expect(snapshot.analysis.uniqueAsns).toBe(MANIFEST.default_skip_403.unique_asns);
    expect(snapshot.analysis.verifiedBots).toBe(MANIFEST.default_skip_403.verified_bots);
    expect(snapshot.analysis.spoofedBots).toBe(MANIFEST.default_skip_403.spoofed_bots);
    watcher.assertClean();
  });

  test('dashboard renders the golden totals, metrics, bounds, and timeline', async ({ page, console: watcher }) => {
    await loadGolden(page);

    await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('15');
    await expect(page.locator('.kpi-card-ips .stat-value')).toHaveText('11');
    // "Unknown" is not counted as a country, nor AS0 as a network.
    await expect(page.locator('.kpi-card-asns .stat-value')).toHaveText(String(MANIFEST.default_skip_403.unique_asns));
    await expect(page.locator('.kpi-card-countries .stat-value')).toHaveText(String(MANIFEST.default_skip_403.unique_countries));
    await expect(page.locator('.kpi-card-human .stat-value')).toHaveText('60%');
    await expect(page.locator('.kpi-card-verified .stat-value')).toHaveText('3');
    await expect(page.locator('.kpi-card-spoofed .stat-value')).toHaveText('2');

    await expect(page.locator('.signal-dashboard-toolbar')).toContainText('Parsed: 15 lines');
    await expect(page.locator('.signal-dashboard-toolbar')).toContainText('Skipped: 5 lines');
    await expect(page.locator('.methods-bandwidth-ribbon')).toContainText(/GET:\s*11/);
    await expect(page.locator('.methods-bandwidth-ribbon')).toContainText(/POST:\s*2/);
    await expect(page.locator('.methods-bandwidth-ribbon')).toContainText('19.3 KB Transferred');
    await expect(page.locator('#filter-matching-badge')).toContainText('Matching 15 / 15 requests');
    await expect(page.locator('#time-window-readout')).toContainText('00:00:00 → 05:00:00');
    await expect(page.locator('#time-window-readout')).not.toContainText('UTC');
    await expect(page.locator('#time-window-readout')).toContainText('All time · 5h');
    await expect(page.locator('#nginx-log-explorer')).toContainText('(15 entries)');
    await expect(page.locator('#rps-resolution-note')).toHaveText('Using 10s buckets (1,500-point limit)');

    const timeline = await page.evaluate(() => {
      const chart = (window as any).Chart.getChart(document.getElementById('rps-chart'));
      const start = document.getElementById('handle-start');
      const end = document.getElementById('handle-end');
      return {
        scaleType: chart?.options?.scales?.x?.type,
        min: chart?.options?.scales?.x?.min,
        max: chart?.options?.scales?.x?.max,
        startNow: start?.getAttribute('aria-valuenow'),
        endNow: end?.getAttribute('aria-valuenow'),
        startDateTime: start?.querySelector('time')?.getAttribute('datetime'),
        endDateTime: end?.querySelector('time')?.getAttribute('datetime'),
        firstTick: chart?.scales?.x?.ticks?.[0]?.value,
        lastTick: chart?.scales?.x?.ticks?.at(-1)?.value,
      };
    });
    const min = Date.parse(MANIFEST.bounds.min_iso);
    const max = Date.parse(MANIFEST.bounds.max_iso);
    expect(timeline).toMatchObject({
      scaleType: 'linear',
      min,
      max,
      startNow: String(min),
      endNow: String(max),
      startDateTime: MANIFEST.bounds.min_iso,
      endDateTime: MANIFEST.bounds.max_iso,
      firstTick: min,
      lastTick: max,
    });

    await expect(page.locator('#country-chart-legend')).toContainText('United States');
    await expect(page.locator('#country-chart-legend')).toContainText('Germany');
    await expect(page.locator('#country-chart-legend')).toContainText('France');
    watcher.assertClean();
  });

  test('filters recompute the visible totals without changing the original denominator', async ({ page, console: watcher }) => {
    await loadGolden(page);
    await page.locator('#filter-method').selectOption('POST');
    await expect(page.locator('#filter-matching-badge')).toContainText('Matching 2 / 15 requests');
    await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('2');
    await expect(page.locator('.kpi-card-verified .stat-value')).toHaveText('1');
    await expect(page.locator('.kpi-card-spoofed .stat-value')).toHaveText('0');

    await page.locator('#filter-clear-btn').click();
    await page.locator('#filter-bot').selectOption('spoofed');
    await expect(page.locator('#filter-matching-badge')).toContainText('Matching 2 / 15 requests');
    await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('2');
    await expect(page.locator('.kpi-card-spoofed .stat-value')).toHaveText('2');
    watcher.assertClean();
  });

  test('every parser field, enriched verdict, and visible log row agrees with the oracle', async ({ page, console: watcher }) => {
    await loadGolden(page);
    const entries = await page.evaluate(log => {
      const entries = (window as any).LogParser.parseIPs(log).logEntries;
      (window as any).Analyzer.enrichLogEntries(entries);
      return entries.map((e: any) => ({ ...e, timestamp: e.timestamp.toISOString() }));
    }, GOLD_LOG);
    const lines = GOLD_LOG.trim().split('\n');
    for (const [index, expected] of MANIFEST.default_entries.entries()) {
      const [line, ip, timestamp, method, url, status, size, country, asn, bot] = expected;
      expect(entries[index]).toMatchObject({ ip, timestamp, method, url, status_code: status,
        response_size: size, country, asn_num: asn, raw_line: lines[line - 1],
        bot_status: bot === 'unverified' ? 'unverified_publisher' : bot });
      expect(entries[index].traffic_class).toBe(bot);
      // The literal quoted fixture fields are the oracle for preservation, not
      // the application's parser result.
      const quoted = lines[line - 1].split('"');
      expect(entries[index].http_version).toBe(quoted[1].split(' ')[2]);
      expect(entries[index].referrer).toBe(quoted[3] === '-' ? null : quoted[3]);
      expect(entries[index].user_agent).toBe(quoted[5]);
    }
    const cells = await page.locator('#explorer-rows-body tr').evaluateAll(rows =>
      rows.map(row => Array.from(row.querySelectorAll('td'), cell => cell.textContent!.trim())));
    expect(cells).toHaveLength(15);
    for (const [i, expected] of [...MANIFEST.default_entries].reverse().entries()) {
      const [line, ip, stamp, method, url, status, , country] = expected;
      expect(cells[i].slice(0, 5)).toEqual([stamp.replace('T', ' ').replace('.000Z', ''), ip, method, url, String(status)]);
      expect(cells[i][5]).toContain(country);
      expect(cells[i]).toHaveLength(8);
      expect(cells[i][6]).toBe(lines[line - 1].split('"')[1].split(' ')[2]);
      expect(cells[i][7]).toBe(lines[line - 1].split('"')[5]);
    }
    await page.locator('.btn-inspect-ip-logs[data-ip="1.1.1.1"]').click();
    await expect(page.locator('#ip-log-modal-body')).toContainText('500');
    watcher.assertClean();
  });

  test('script traffic and individual bot rows filter exactly their displayed requests', async ({ page, console: watcher }) => {
    await loadGolden(page);
    // curl is a tool, not a crawler that could be verified: class "automated".
    await page.locator('#filter-bot').selectOption('automated');
    await expect(page.locator('#filter-matching-badge strong')).toHaveText('1');
    await expect(page.locator('#explorer-rows-body')).toContainText('curl/8.4.0');
    await page.locator('#filter-clear-btn').click();
    await page.locator('.cross-filter-bot-row').filter({ hasText: 'Fake Google' }).click();
    await expect(page.locator('#filter-matching-badge strong')).toHaveText('1');
    await expect(page.locator('#explorer-rows-body')).toContainText('185.220.101.5');
    await page.locator('#filter-clear-btn').click();
    await page.locator('.cross-filter-bot-row').filter({ hasText: 'Google' }).filter({ hasText: 'Verified' }).click();
    await expect(page.locator('#filter-matching-badge strong')).toHaveText('2');
    await expect(page.locator('.kpi-card-spoofed .stat-value')).toHaveText('0');
    watcher.assertClean();
  });

  test('country, ASN, IP and path tables and chart series agree with exact hit counts', async ({ page, console: watcher }) => {
    await loadGolden(page);
    const expected = MANIFEST.default_skip_403;
    for (const [ip, hits] of Object.entries(expected.ip_hits)) {
      await expect(page.locator(`.cross-filter-ip-row[data-ip="${ip}"] td`).nth(1)).toHaveText(String(hits));
    }
    for (const [asn, hits] of Object.entries(expected.asn_hits)) {
      await expect(page.locator(`.cross-filter-asn-row[data-asn="${asn}"] td`).nth(1)).toHaveText(String(hits));
    }
    const charts = await page.evaluate(() => {
      const chart = (id: string) => (window as any).Chart.getChart(document.getElementById(id));
      const country = chart('country-chart');
      const asn = chart('asn-chart');
      const rate = chart('rps-chart');
      return {
        countries: Object.fromEntries(country.data.labels.map((name: string, i: number) => [name, country.data.datasets[0].data[i]])),
        asnCounts: asn.data.datasets[0].data,
        requests: rate.data.datasets[0].data.reduce((total: number, p: { y: number }) => total + p.y, 0),
        errors: rate.data.datasets[1].data.reduce((total: number, p: { y: number }) => total + p.y, 0),
      };
    });
    expect(charts.countries).toEqual(expected.country_hits);
    expect([...charts.asnCounts].sort()).toEqual(Object.values(expected.asn_hits).sort());
    expect(charts.requests).toBe(15);
    expect(charts.errors).toBe(4);
    await page.locator('#filter-country').selectOption('Germany');
    await expect(page.locator('#filter-matching-badge strong')).toHaveText('1');
    await page.locator('#filter-clear-btn').click();
    await page.locator('.cross-filter-asn-row[data-asn="15169"]').click();
    await expect(page.locator('#filter-matching-badge strong')).toHaveText('3');
    await page.locator('#filter-clear-btn').click();
    await page.locator('#filter-path-select').selectOption('^/products');
    await expect(page.locator('#filter-matching-badge strong')).toHaveText('4');
    await expect(page.locator('.methods-bandwidth-ribbon')).toContainText('7.7 KB Transferred');
    watcher.assertClean();
  });

  test('worker parsing and a gzip file upload preserve the golden dataset', async ({ page, console: watcher }) => {
    await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
    await waitForEngineReady(page);
    const results = await page.evaluate(async log => {
      const worker = new Worker('/js/log-parser.worker.js');
      try {
        const workerResult: any = await new Promise((resolve, reject) => {
          worker.onmessage = e => e.data.type === 'success' ? resolve(e.data.result) : reject(new Error(e.data.error));
          worker.onerror = reject;
          worker.postMessage({ action: 'parse', logText: log });
        });
        return { worker: JSON.stringify(workerResult), direct: JSON.stringify((window as any).LogParser.parseIPs(log)) };
      } finally { worker.terminate(); }
    }, GOLD_LOG);
    expect(results.worker).toBe(results.direct);
    await page.locator('#nginx-logfile').setInputFiles({ name: 'golden.log.gz', mimeType: 'application/gzip', buffer: gzipSync(GOLD_LOG) });
    await page.locator('#nginx-analyze-btn').click();
    await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('15', { timeout: 45000 });
    await expect(page.locator('.methods-bandwidth-ribbon')).toContainText('19.3 KB Transferred');
    watcher.assertClean();
  });

  test('remote URL mode renders the golden response fixture', async ({ page, console: watcher }) => {
    await page.route('**/api/storage/upload-external', route => route.fulfill({ json: { shareCode: 'golden-remote' } }));
    await page.route('**/api/storage/download/golden-remote', route => route.fulfill({ json: { downloadUrl: 'http://localhost:3001/golden-remote.log' } }));
    await page.route('**/golden-remote.log', route => route.fulfill({ contentType: 'text/plain', body: GOLD_LOG }));
    await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
    await waitForEngineReady(page);
    await page.getByRole('tab', { name: 'Remote URL' }).click();
    await page.locator('#nginx-gist-url').fill('https://example.com/golden.log');
    await page.locator('#nginx-analyze-btn').click();
    await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('15', { timeout: 45000 });
    await expect(page.locator('.signal-dashboard-source')).toContainText('Remote URL · example.com');
    await expect(page.locator('.methods-bandwidth-ribbon')).toContainText('19.3 KB Transferred');
    watcher.assertClean();
  });

  test('live terminal ingest with a localhost CORS bridge renders golden data and consumes its session', async ({ page, request, console: watcher }, testInfo) => {
    testInfo.annotations.push({ type: 'environment', description: 'R2 does not allow localhost CORS. Real storage download is bridged by route.fetch; native storage-origin CORS remains a deployment check.' });
    await page.route('**/api/ingest/*', async route => {
      if (!/^\/api\/ingest\/[a-f0-9]{24}$/.test(new URL(route.request().url()).pathname)) return route.continue();
      // Follow the real backend redirect outside browser CORS and return the
      // retrieved object on the original same-origin request.
      const storage = await route.fetch();
      expect(storage.status()).toBe(200);
      const headers = { ...storage.headers(), 'access-control-allow-origin': '*' };
      // APIRequestContext decodes Content-Encoding before returning its body.
      delete headers['content-encoding'];
      delete headers['content-length'];
      await route.fulfill({ status: storage.status(), headers, body: await storage.body() });
    });
    const response = await request.post('/api/ingest', { multipart: {
      file: { name: 'golden.log.gz', mimeType: 'application/gzip', buffer: gzipSync(GOLD_LOG) },
    } });
    // The ingest endpoint keeps the upload in object storage (R2).
    test.skip(response.status() === 503 && /Storage service is not configured/.test(await response.text()), 'object storage is not configured on this instance');
    expect(response.status(), await response.text()).toBe(200);
    const { sessionId } = await response.json();
    expect(sessionId).toMatch(/^[a-f0-9]{24}$/);
    try {
      await page.goto(`/nginx?session=${sessionId}`, { waitUntil: 'domcontentloaded' });
      await expect(page.locator('.kpi-card-total .stat-value')).toHaveText('15', { timeout: 45000 });
      await expect(page.locator('#terminal-ingest-banner')).toBeVisible();
      await expect(page.locator('.methods-bandwidth-ribbon')).toContainText('19.3 KB Transferred');
      expect((await request.get(`/api/ingest/${sessionId}/meta`)).status()).toBe(404);
      expect((await request.get(`/api/ingest/${sessionId}`)).status()).toBe(404);
      watcher.assertClean();
    } finally {
      await request.post(`/api/ingest/${sessionId}/purge`);
    }
  });

  test('generated HTML report carries the golden analysis values', async ({ page, console: watcher }) => {
    await loadGolden(page);
    await page.locator('#dash-download-btn').click();
    await expect(page.locator('#download-modal-backdrop')).toBeVisible();
    const [download] = await Promise.all([
      page.waitForEvent('download', { timeout: 30_000 }),
      page.locator('#dl-start-btn').click(),
    ]);
    const chunks: Buffer[] = [];
    for await (const chunk of await download.createReadStream()) chunks.push(chunk as Buffer);
    const report = Buffer.concat(chunks).toString('utf8');

    expect(report).toContain('01/Oct/2026 00:00:00');
    expect(report).toContain('01/Oct/2026 05:00:00');
    expect(report).not.toContain('UTC');
    expect(report).toContain('>15</div>');
    expect(report).toContain('19744 bytes');
    expect(report).toContain('Median:</span><span class="resp-val">800 bytes');
    expect(report).toContain('Fake Bot Alert: Detected 2 requests');
    expect(report).toContain('Detected Spoofed Bot Attackers');
    expect(report).toContain('United States');
    expect(report).toContain('AS15169');
    await page.route('**/golden-report.html', route => route.fulfill({ contentType: 'text/html', body: report }));
    await page.goto('/golden-report.html', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('heading', { name: /Traffic Log Analysis Report/ })).toBeVisible();
    const summary = page.locator('.container > .stat-cards').first();
    // Requests, addresses, countries, networks, human share, verified, spoofed, other bots.
    await expect(summary.locator('.stat-value')).toHaveText(['15', '11', '3', '6', '60%', '3', '2', '1']);
    const statuses = page.locator('.metric-box').filter({ hasText: 'Status Categories' });
    await expect(statuses.locator('.metric-chip-val')).toHaveText(['1', '8', '2', '3', '1']);
    await expect(page.locator('[data-detail-key="c-United_States"] .hits-badge')).toHaveText('9');
    await expect(page.locator('[data-detail-key="a-15169"] .hits-badge')).toHaveText('3');
    await page.locator('[data-detail-key="b-Google"]').click();
    await expect(page.locator('[data-detail-id="b-Google"]')).toBeVisible();
    await expect(page.locator('[data-detail-id="b-Google"]')).toContainText('66.249.66.1');
    await expect(page.locator('#report-country-chart')).toBeVisible();
    watcher.assertClean();
  });
});
