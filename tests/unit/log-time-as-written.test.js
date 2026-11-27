import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

// A log time is shown exactly as the server wrote it, so the charts line up
// with the server's own clock. Nothing is converted, also not when a log mixes
// time zones.
const require = createRequire(import.meta.url);
require('../../frontend/public/js/request-paths.js');
require('../../frontend/public/js/bot-detector.js');
require('../../frontend/public/js/traffic-classifier.js');
const LogParser = require('../../frontend/public/js/log-parser.js');
globalThis.LogParser = LogParser;
require('../../frontend/public/js/columnar-storage.js');
const { createWorkerHandler } = require('../../frontend/public/js/log-parser.worker.js');

const ALL = { skip403: false, skipInternal: false };
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
const p2 = n => String(n).padStart(2, '0');
const clf = (ip, clock, zone, path = '/') => `${ip} - - [10/Oct/2026:${clock} ${zone}] "GET ${path} HTTP/1.1" 200 10 "-" "${UA}"`;
const clock = entry => entry.timestamp.toISOString().slice(11, 19);

function upload(...files) {
    const messages = [];
    const handler = createWorkerHandler(msg => messages.push(msg));
    files.forEach((text, i) => handler({ data: { action: i === 0 ? 'parse_stream_chunk' : 'append_stream_chunk', chunk: new TextEncoder().encode(text), isLast: true, options: ALL } }));
    const done = messages.filter(m => m.type === 'complete' || m.type === 'append_complete').pop();
    messages.length = 0;
    handler({ data: { action: 'get_page', pageNumber: 1, pageSize: 1000, filters: {} } });
    const rows = messages.find(m => m.type === 'page_result').pageResult.rows;
    return { done, times: rows.map(r => new Date(r.timestamp).toISOString().slice(11, 19)).sort() };
}

test('a log reads as written, whatever its zone', () => {
    const text = Array.from({ length: 30 }, (_, i) => clf('81.2.69.1', `07:23:${p2(i)}`, '-0700')).join('\n') + '\n';
    const r = LogParser.parseIPs(text, ALL);
    assert.equal(clock(r.logEntries[0]), '07:23:00');
    assert.equal(clock(r.logEntries[29]), '07:23:29');
    const u = upload(text);
    assert.equal(u.times[0], '07:23:00');
    assert.equal(u.times[29], '07:23:29');
});

test('lines written in two zones each keep their own time', () => {
    const berlin = Array.from({ length: 40 }, (_, i) => clf('81.2.69.1', `12:00:${p2(i % 10)}`, '+0200', '/berlin'));
    const utc = Array.from({ length: 10 }, (_, i) => clf('81.2.69.2', `10:00:${p2(i)}`, '+0000', '/utc'));
    const text = [...berlin, ...utc].join('\n') + '\n';
    const r = LogParser.parseIPs(text, ALL);
    assert.deepEqual(r.logEntries.filter(e => e.url === '/utc').map(clock), Array.from({ length: 10 }, (_, i) => `10:00:${p2(i)}`));
    assert.deepEqual(r.logEntries.filter(e => e.url === '/berlin').slice(0, 10).map(clock), Array.from({ length: 10 }, (_, i) => `12:00:${p2(i)}`));

    const u = upload(text);
    assert.deepEqual(u.times, r.logEntries.map(clock).sort());
    assert.equal(u.times[0], '10:00:00');
    assert.equal(u.times[49], '12:00:09');
});

test('an added file keeps its own times too', () => {
    const first = Array.from({ length: 20 }, (_, i) => clf('81.2.69.1', `12:00:${p2(i)}`, '+0200')).join('\n') + '\n';
    const second = Array.from({ length: 20 }, (_, i) => clf('81.2.69.2', `10:00:${p2(20 + i)}`, '+0000')).join('\n') + '\n';
    const u = upload(first, second);
    assert.equal(u.times[0], '10:00:20');
    assert.equal(u.times[39], '12:00:19');
});

test('the result carries no time zone fields', () => {
    const text = Array.from({ length: 12 }, (_, i) => clf('81.2.69.1', `12:00:${p2(i)}`, '+0200')).join('\n') + '\n';
    const r = LogParser.parseIPs(text, ALL);
    assert.equal('zoneOffsetMinutes' in r, false);
    assert.equal('zoneConvertedLines' in r, false);
    assert.equal(LogParser.readTimestamp, undefined);
});
