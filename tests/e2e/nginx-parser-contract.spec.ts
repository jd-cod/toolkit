import { test, expect, waitForEngineReady } from './fixtures/dashboard';

test('common, combined, zero-byte, extended and incomplete requests preserve their fields', async ({ page, console: watcher }) => {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  const lines = [
    '8.8.8.8 - user [01/Oct/2026:00:00:00 +0000] "HEAD /common HTTP/1.1" 204 -',
    '1.1.1.1 - - [01/Oct/2026:00:00:01 +0000] "GET /zero HTTP/1.1" 304 - "-" "Mozilla/5.0"',
    '192.168.1.100 - - [01/Oct/2026:00:00:02 +0000] "GET /admin HTTP/1.1" 403 128 "-" "ClaudeBot/1.0" "proxy-extra"',
    '8.8.8.8 - - [01/Oct/2026:00:00:03 +0000] "-" 400 10 "-" "-"',
    '8.8.8.8 - - [01/Oct/2026:00:00:04 +0000] "GET /legacy" 200 5 "-" "Mozilla/5.0"',
  ];
  const result = await page.evaluate(log => {
    const r = (window as any).LogParser.parseIPs(log, { skipInternal: false });
    return { skipped: r.skippedLines, entries: r.logEntries.map((e: any) =>
      [e.method, e.url, e.http_version, e.status_code, e.response_size, e.user_agent, e.raw_line]) };
  }, lines.join('\n'));
  expect(result.skipped).toEqual([]);
  expect(result.entries).toEqual([
    ['HEAD', '/common', 'HTTP/1.1', 204, 0, null, lines[0]],
    ['GET', '/zero', 'HTTP/1.1', 304, 0, 'Mozilla/5.0', lines[1]],
    ['GET', '/admin', 'HTTP/1.1', 403, 128, 'ClaudeBot/1.0', lines[2]],
    [null, null, null, 400, 10, null, lines[3]],
    ['GET', '/legacy', null, 200, 5, 'Mozilla/5.0', lines[4]],
  ]);
  await page.getByRole('tab', { name: 'Paste logs' }).click();
  await page.locator('#nginx-logtext').fill(lines[3]);
  await page.locator('#nginx-analyze-btn').click();
  await expect(page.locator('#explorer-rows-body tr')).toHaveCount(1);
  await expect(page.locator('#explorer-rows-body td').nth(2)).toHaveText('-');
  await expect(page.locator('#explorer-rows-body td').nth(3)).toHaveText('-');
  await expect(page.locator('#explorer-rows-body td').nth(4)).toHaveText('400');
  watcher.assertClean();
});

test('malformed HTTP methods are displayed as text in summary and filter controls', async ({ page, console: watcher }) => {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  await page.getByRole('tab', { name: 'Paste logs' }).click();
  await page.locator('#nginx-logtext').fill('8.8.8.8 - - [01/Oct/2026:00:00:00 +0000] "<b> /invalid HTTP/1.1" 400 1 "-" "Mozilla/5.0"');
  await page.locator('#nginx-analyze-btn').click();
  await expect(page.locator('.methods-bandwidth-ribbon')).toContainText('<B>');
  await expect(page.locator('.methods-bandwidth-ribbon b')).toHaveCount(0);
  await expect(page.locator('#filter-method option').nth(1)).toHaveText('<b>');
  watcher.assertClean();
});

test('IP validation rejects impossible IPv6 and normalizes mapped clients', async ({ page, console: watcher }) => {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  const ips = ['123.456.789.0', '01.1.1.1', ':', '::::', '1:2:3', '2001::db8::1',
    '2001:db8:0:0:0:0:0:12345', '2001:4860:4860::8888', '::ffff:8.8.8.8'];
  const result = await page.evaluate(ips => ips.map(ip => ({
    valid: (window as any).LogParser.isValidIP(ip),
    entries: (window as any).LogParser.parseIPs(`${ip} - - [01/Oct/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0"`).ips,
  })), ips);
  expect(result).toEqual([
    ...Array.from({ length: 7 }, () => ({ valid: false, entries: [] })),
    { valid: true, entries: ['2001:4860:4860::8888'] },
    { valid: true, entries: ['8.8.8.8'] },
  ]);
  watcher.assertClean();
});

test('invalid dates stay untimed and an offset-less legacy date is interpreted in UTC', async ({ page, console: watcher }) => {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  const stamps = ['31/Feb/2026:01:00:00 +0000', '01/Foo/2026:01:00:00 +0000',
    '01/Oct/2026:25:00:00 +0000', '01/Oct/2026:00:00:00 +0060', '01/Oct/2026:00:00:00'];
  const result = await page.evaluate(stamps => (window as any).LogParser.parseIPs(stamps.map(t =>
    `8.8.8.8 - - [${t}] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0"`).join('\n')).logEntries.map((e: any) => e.timestamp?.toISOString() || null), stamps);
  expect(result).toEqual([null, null, null, null, '2026-10-01T00:00:00.000Z']);
  watcher.assertClean();
});

// Every notation keeps the clock the server wrote, so `05:30:00+05:30` reads
// 05:30:00 like `[.. 05:30:00 +0530]` does (see timeline-accuracy.spec.ts).
test('ISO-8601 timestamps and bracketed ISO dates keep the clock the server wrote', async ({ page, console: watcher }) => {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  const isoLines = [
    '8.8.8.8 - - [2026-10-01T00:00:00Z] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0"',
    '8.8.8.8 - - [2026-10-01T05:30:00+05:30] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0"',
    '8.8.8.8 - - [2026-10-01T00:00:00+00:00] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0"',
  ];
  const result = await page.evaluate(lines => (window as any).LogParser.parseIPs(lines.join('\n')).logEntries.map((e: any) => e.timestamp?.toISOString() || null), isoLines);
  expect(result).toEqual([
    '2026-10-01T00:00:00.000Z',
    '2026-10-01T05:30:00.000Z',
    '2026-10-01T00:00:00.000Z',
  ]);
  watcher.assertClean();
});

test('JSON log lines parse accurately into normalized fields', async ({ page, console: watcher }) => {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  const jsonLines = [
    JSON.stringify({
      remote_addr: '8.8.8.8',
      time_local: '01/Oct/2026:00:00:00 +0000',
      request: 'GET /api/v1/status HTTP/1.1',
      status: 200,
      body_bytes_sent: 512,
      http_referer: 'http://localhost:3000',
      http_user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    }),
    JSON.stringify({
      client_ip: '1.1.1.1',
      time_iso8601: '2026-10-01T00:00:01Z',
      request_method: 'POST',
      request_uri: '/api/v1/auth',
      server_protocol: 'HTTP/2.0',
      status_code: 401,
      bytes_sent: 128,
      user_agent: 'ClaudeBot/1.0'
    })
  ];
  const result = await page.evaluate(text => {
    const res = (window as any).LogParser.parseIPs(text);
    return res.logEntries.map((e: any) => [
      e.ip, e.method, e.url, e.status_code, e.response_size, e.user_agent
    ]);
  }, jsonLines.join('\n'));

  expect(result).toEqual([
    ['8.8.8.8', 'GET', '/api/v1/status', 200, 512, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'],
    ['1.1.1.1', 'POST', '/api/v1/auth', 401, 128, 'ClaudeBot/1.0'],
  ]);
  watcher.assertClean();
});

test('shuffled field formats and vhost-first logs are automatically detected and parsed', async ({ page, console: watcher }) => {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  const shuffledLines = [
    'example.com 8.8.8.8 - - [01/Oct/2026:00:00:00 +0000] "GET /vhost HTTP/1.1" 200 128 "-" "Mozilla/5.0"',
    'example.com 1.1.1.1 - - [01/Oct/2026:00:00:01 +0000] "POST /vhost2 HTTP/1.1" 201 256 "https://ref.com" "Mozilla/5.0"',
  ];
  const result = await page.evaluate(text => {
    const res = (window as any).LogParser.parseIPs(text);
    return res.logEntries.map((e: any) => [
      e.ip, e.method, e.url, e.status_code, e.response_size
    ]);
  }, shuffledLines.join('\n'));

  expect(result).toEqual([
    ['8.8.8.8', 'GET', '/vhost', 200, 128],
    ['1.1.1.1', 'POST', '/vhost2', 201, 256],
  ]);
  watcher.assertClean();
});

test('request-rate safety limits retain endpoint requests at 1500 seconds and year-long spans', async ({ page, console: watcher }) => {
  await page.goto('/nginx', { waitUntil: 'domcontentloaded' });
  await waitForEngineReady(page);
  const results = await page.evaluate(() => [1500, 366 * 86400, 5 * 366 * 86400].flatMap(span => ['1', 'auto'].map(resolution => {
    const start = Date.UTC(2026, 0, 1);
    const rate = (window as any).Analyzer.computeRequestRate([
      { timestamp: new Date(start), status_code: 200 },
      { timestamp: new Date(start + span * 1000), status_code: 500 },
    ], { resolution });
    return { span, resolution, count: rate.total_buckets,
      requests: rate.buckets.reduce((n: number, b: any) => n + b.count, 0),
      errors: rate.buckets.reduce((n: number, b: any) => n + b.status_5xx, 0) };
  })));
  for (const row of results) {
    expect(row.requests, JSON.stringify(row)).toBe(2);
    expect(row.errors, JSON.stringify(row)).toBe(1);
    expect(row.count).toBeLessThanOrEqual(row.resolution === 'auto' ? 160 : 1500);
  }
  watcher.assertClean();
});
