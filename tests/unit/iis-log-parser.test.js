import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const LogParser = require('../../frontend/public/js/log-parser.js');
const { createWorkerHandler } = require('../../frontend/public/js/log-parser.worker.js');

const HEADER = [
  '#Software: Microsoft Internet Information Services 10.0',
  '#Version: 1.0',
  '#Date: 2026-11-20 10:15:00',
  '#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken',
];
const ROWS = [
  '2026-11-20 10:15:00 10.0.0.5 GET /products id=7&sort=asc 443 - 66.249.66.1 Mozilla/5.0+(compatible;+Googlebot/2.1;++http://www.google.com/bot.html) - 200 0 0 31',
  '2026-11-20 10:15:05 10.0.0.5 POST /api/login - 443 - 8.8.4.4 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) https://example.com/login 401 0 0 12',
  '2026-11-20 10:16:10 10.0.0.5 GET /admin - 443 CORP\\jsmith 1.1.1.1 curl/8.4.0 - 404 0 2 5',
  '2026-11-20 10:17:00 10.0.0.5 GET /internal - 443 - 192.168.1.20 Mozilla/5.0 - 200 0 0 3',
  '2026-11-20 10:18:00 10.0.0.5 GET /secret - 443 - 9.9.9.9 Mozilla/5.0 - 403 14 0 2',
];
const LOG = [...HEADER, ...ROWS].join('\n');

test('a log with a #Fields header is detected as W3C', () => {
  assert.equal(LogParser.detectFormat(LOG.split('\n')).type, 'w3c');
  assert.equal(LogParser.detectFormat(LOG).type, 'w3c');
});

test('W3C rows map to the same fields as nginx rows', () => {
  const { parseLine } = LogParser.detectFormat(LOG.split('\n'));
  const first = parseLine(ROWS[0], { skip403: false, skipInternal: false });
  assert.equal(first.valid, true);
  assert.equal(first.ip, '66.249.66.1');
  assert.equal(first.method, 'GET');
  assert.equal(first.url, '/products?id=7&sort=asc');
  assert.equal(first.statusCode, 200);
  assert.equal(first.userAgent, 'Mozilla/5.0 (compatible; Googlebot/2.1;  http://www.google.com/bot.html)');
  assert.equal(first.isCrawler, true);
  assert.equal(first.referrer, null);
  assert.equal(first.timestamp.toISOString(), '2026-11-20T10:15:00.000Z');
  assert.equal(first.timeSec, Date.UTC(2026, 10, 20, 10, 15, 0) / 1000);

  const second = parseLine(ROWS[1], { skip403: false, skipInternal: false });
  assert.equal(second.url, '/api/login');
  assert.equal(second.referrer, 'https://example.com/login');
  assert.equal(second.statusCode, 401);
});

test('header lines are skipped, and private addresses and plain 403s follow the usual options', () => {
  const result = LogParser.parseIPs(LOG);
  assert.deepEqual(result.ips, ['66.249.66.1', '8.8.4.4', '1.1.1.1']);
  assert.equal(result.skipCounts.privateIP, 1);
  assert.equal(result.skipCounts.forbidden, 1);
  assert.equal(result.skipCounts.invalid, 4);

  const everything = LogParser.parseIPs(LOG, { skip403: false, skipInternal: false });
  assert.equal(everything.ips.length, 5);
});

test('a second #Fields directive with another layout takes effect mid-file', () => {
  const rotated = [
    ...HEADER, ROWS[0],
    '#Software: Microsoft Internet Information Services 10.0',
    '#Fields: date time c-ip cs-method cs-uri-stem sc-status sc-bytes cs-version',
    '2026-11-21 08:00:00 8.8.8.8 GET /download.zip 200 52428 HTTP/2.0',
  ].join('\n');
  const result = LogParser.parseIPs(rotated, { skip403: false, skipInternal: false });
  assert.deepEqual(result.ips, ['66.249.66.1', '8.8.8.8']);
  assert.equal(result.logEntries[1].url, '/download.zip');
  assert.equal(result.logEntries[1].response_size, 52428);
  assert.equal(result.logEntries[1].http_version, 'HTTP/2.0');
});

test('rows pasted without the header use the default IIS layout', () => {
  const format = LogParser.detectFormat(ROWS);
  assert.equal(format.type, 'w3c');
  assert.equal(format.parseLine(ROWS[2], { skipInternal: false }).ip, '1.1.1.1');
  assert.equal(format.parseLine(ROWS[2], { skipInternal: false }).url, '/admin');
});

test('short, malformed and non-IP rows are rejected without throwing', () => {
  const { parseLine } = LogParser.detectFormat(LOG.split('\n'));
  assert.equal(parseLine('2026-11-20 10:15:00 10.0.0.5 GET').valid, false);
  assert.equal(parseLine('2026-11-20 10:15:00 10.0.0.5 GET / - 443 - not-an-ip UA - 200 0 0 1').valid, false);
  assert.equal(parseLine('').valid, false);
  assert.equal(parseLine('#Fields: nothing useful').valid, false);
  // The useless directive above must not have replaced the working layout.
  assert.equal(parseLine(ROWS[0], { skipInternal: false }).valid, true);
});

test('nginx logs are still detected as before', () => {
  const nginx = [
    '66.249.66.1 - - [20/Sep/2026:10:15:00 +0000] "GET /products HTTP/2.0" 200 4520 "-" "Googlebot/2.1"',
    '8.8.8.8 - - [20/Sep/2026:10:15:05 +0000] "POST /api/login HTTP/1.1" 401 233 "https://example.com/login" "Mozilla/5.0"',
  ];
  assert.equal(LogParser.detectFormat(nginx).type, 'standard');
  assert.equal(LogParser.detectFormat(['# a comment', ...nginx]).type, 'standard');
  assert.equal(LogParser.parseIPs(nginx.join('\n')).ips.length, 2);
});

test('the streaming worker analyses an IIS log split across chunks', async () => {
  const messages = [];
  const handler = createWorkerHandler(msg => messages.push(msg));
  const bytes = new TextEncoder().encode(LOG + '\n');
  const cut = Math.floor(bytes.length / 2);
  handler({ data: { action: 'parse_stream_chunk', chunk: bytes.slice(0, cut), isLast: false, options: { skip403: false, skipInternal: false } } });
  handler({ data: { action: 'parse_stream_chunk', chunk: bytes.slice(cut), isLast: true, options: { skip403: false, skipInternal: false } } });
  await new Promise(resolve => setTimeout(resolve, 50));
  const done = messages.find(m => m.type === 'complete');
  assert.ok(done, 'worker did not complete');
  assert.equal(done.summary.matchingCount, 5);
  assert.equal(done.summary.uniqueIps, 5);
  assert.deepEqual(done.summary.statusCounts, { 200: 2, 401: 1, 403: 1, 404: 1 });
  assert.equal(done.summary.minTimeSec, Date.UTC(2026, 10, 20, 10, 15, 0) / 1000);
});
