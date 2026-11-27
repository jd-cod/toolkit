import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

// A log is shown in its own clock. When lines are written in different zones
// (two servers, or the night daylight-saving time ends) they are moved to the
// zone most lines use, so every request sits at the right place on one time line.
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

test('a timestamp says which zone it was written in', () => {
    const offset = text => LogParser.readTimestamp(text).offset;
    assert.equal(offset('10/Oct/2026:13:55:36 -0700'), -420);
    assert.equal(offset('10/Oct/2026:13:55:36 +0530'), 330);
    assert.equal(offset('10/Oct/2026:13:55:36 +0000'), 0);
    assert.equal(offset('2026-10-10T13:55:36+05:30'), 330);
    assert.equal(offset('2026-10-10T13:55:36-07:00'), -420);
    assert.equal(offset('2026-10-10T13:55:36+02'), 120);
    assert.equal(offset('2026-10-10T13:55:36.123Z'), 0);
    assert.equal(offset('2026-10-10 13:55:36'), null);
    assert.equal(offset('10/Oct/2026:13:55:36'), null);
    assert.equal(offset('1791640536'), 0);
    assert.equal(offset('Sat, 10 Oct 2026 13:55:36 GMT'), 0);
    assert.equal(offset('Sat, 10 Oct 2026 13:55:36 -0700'), -420);
    assert.equal(LogParser.readTimestamp('not a time'), null);
});

test('a log in one zone reads as written and names its zone', () => {
    const text = Array.from({ length: 30 }, (_, i) => clf('81.2.69.1', `07:23:${p2(i)}`, '-0700')).join('\n');
    const r = LogParser.parseIPs(text, ALL);
    assert.equal(clock(r.logEntries[0]), '07:23:00');
    assert.equal(r.zoneOffsetMinutes, -420);
    assert.equal(r.zoneConvertedLines, 0);
    const u = upload(text + '\n');
    assert.equal(u.done.zoneOffsetMinutes, -420);
    assert.equal(u.done.zoneConvertedLines, 0);
    assert.equal(u.times[0], '07:23:00');
});

test('a log without zones is left alone', () => {
    const text = Array.from({ length: 5 }, (_, i) => JSON.stringify({ remote_addr: '81.2.69.1', time: `2026-10-10 12:00:0${i}`, request: 'GET / HTTP/1.1', status: 200, http_user_agent: UA })).join('\n');
    const r = LogParser.parseIPs(text, ALL);
    assert.equal(r.logEntries.length, 5);
    assert.equal(clock(r.logEntries[4]), '12:00:04');
    assert.equal(r.zoneOffsetMinutes, null);
});

test('two servers in different zones end up on one time line', () => {
    // The same ten seconds, written by a server on +0200 (most lines) and one on UTC.
    const berlin = Array.from({ length: 40 }, (_, i) => clf('81.2.69.1', `12:00:${p2(i % 10)}`, '+0200', '/berlin'));
    const utc = Array.from({ length: 10 }, (_, i) => clf('81.2.69.2', `10:00:${p2(i)}`, '+0000', '/utc'));
    const text = [...berlin, ...utc].join('\n') + '\n';
    const r = LogParser.parseIPs(text, ALL);
    assert.equal(r.zoneOffsetMinutes, 120);
    assert.equal(r.zoneConvertedLines, 10);
    const fromUtc = r.logEntries.filter(e => e.url === '/utc').map(clock);
    assert.deepEqual(fromUtc, Array.from({ length: 10 }, (_, i) => `12:00:${p2(i)}`));
    assert.equal(r.logSpanMinutes, 0, 'not two hours apart');

    const u = upload(text);
    assert.equal(u.done.zoneOffsetMinutes, 120);
    assert.equal(u.done.zoneConvertedLines, 10);
    assert.deepEqual(u.times, r.logEntries.map(clock).sort());
    assert.equal(u.done.summary.maxTimeSec - u.done.summary.minTimeSec, 9);
});

test('the hour that repeats when daylight-saving time ends is not folded onto itself', () => {
    // 02:00-02:59 +0200, then the clock goes back: 02:00-02:59 +0100.
    const summer = Array.from({ length: 240 }, (_, i) => clf('81.2.69.1', `02:${p2(Math.floor(i / 4))}:${p2((i % 4) * 15)}`, '+0200'));
    const winter = Array.from({ length: 240 }, (_, i) => clf('81.2.69.1', `02:${p2(Math.floor(i / 4))}:${p2((i % 4) * 15)}`, '+0100'));
    const r = LogParser.parseIPs([...summer, ...winter].join('\n'), ALL);
    const times = r.logEntries.map(e => e.timestamp.getTime());
    for (let i = 1; i < times.length; i++) assert.ok(times[i] >= times[i - 1], `request ${i} is before the one written before it`);
    assert.equal(r.logSpanMinutes, 119);
    assert.equal(r.zoneOffsetMinutes, 120);
    assert.equal(clock(r.logEntries[240]), '03:00:00');
});

test('an added file is shown in the zone of the first one', () => {
    const first = Array.from({ length: 20 }, (_, i) => clf('81.2.69.1', `12:00:${p2(i)}`, '+0200')).join('\n') + '\n';
    const second = Array.from({ length: 20 }, (_, i) => clf('81.2.69.2', `10:00:${p2(20 + i)}`, '+0000')).join('\n') + '\n';
    const u = upload(first, second);
    assert.equal(u.done.zoneOffsetMinutes, 120);
    assert.equal(u.done.zoneConvertedLines, 20);
    assert.equal(u.times[0], '12:00:00');
    assert.equal(u.times[39], '12:00:39');

    // Pasted text added to an analysis gets the zone from the caller.
    const added = LogParser.parseIPs(second, { ...ALL, zoneOffset: 120 });
    assert.equal(clock(added.logEntries[0]), '12:00:20');
    assert.equal(added.zoneConvertedLines, 20);
    assert.deepEqual(added.options, ALL, 'the zone is not one of the exclusion options');
});

test('epoch numbers join a log that has a zone', () => {
    const lines = Array.from({ length: 20 }, (_, i) => JSON.stringify({ remote_addr: '81.2.69.1', time: `2026-10-10T12:00:${p2(i)}+02:00`, request: 'GET / HTTP/1.1', status: 200, http_user_agent: UA }));
    // 2026-10-10T10:00:30Z as an epoch number.
    lines.push(JSON.stringify({ remote_addr: '81.2.69.2', time: String(Date.UTC(2026, 9, 10, 10, 0, 30) / 1000), request: 'GET /epoch HTTP/1.1', status: 200, http_user_agent: UA }));
    const r = LogParser.parseIPs(lines.join('\n'), ALL);
    assert.equal(r.logEntries.length, 21);
    assert.equal(clock(r.logEntries[20]), '12:00:30');
});
