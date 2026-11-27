import { test } from 'node:test';
import assert from 'node:assert/strict';
import engine from './helpers/engine.js';

// A log time is shown exactly as the server wrote it, so the charts line up
// with the server's own clock. Nothing is converted, also not when a log mixes
// time zones.
const { analyze } = engine;

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
const p2 = n => String(n).padStart(2, '0');
const clf = (ip, clock, zone, path = '/') => `${ip} - - [10/Oct/2026:${clock} ${zone}] "GET ${path} HTTP/1.1" 200 10 "-" "${UA}"`;
const clock = row => new Date(row.timestamp).toISOString().slice(11, 19);

test('a log reads as written, whatever its zone', async () => {
    const text = Array.from({ length: 30 }, (_, i) => clf('81.2.69.1', `07:23:${p2(i)}`, '-0700')).join('\n') + '\n';
    const r = await analyze(text);
    const times = (await r.rows()).map(clock);
    assert.equal(times[0], '07:23:00');
    assert.equal(times[29], '07:23:29');
    assert.equal(r.parseResult.logStart, '10/Oct/2026 07:23:00');
    assert.equal(r.parseResult.logEnd, '10/Oct/2026 07:23:29');
});

test('lines written in two zones each keep their own time', async () => {
    const berlin = Array.from({ length: 40 }, (_, i) => clf('81.2.69.1', `12:00:${p2(i % 10)}`, '+0200', '/berlin'));
    const utc = Array.from({ length: 10 }, (_, i) => clf('81.2.69.2', `10:00:${p2(i)}`, '+0000', '/utc'));
    const r = await analyze([...berlin, ...utc].join('\n') + '\n');
    assert.deepEqual((await r.rows({ pathSearch: '=/utc' })).map(clock), Array.from({ length: 10 }, (_, i) => `10:00:${p2(i)}`));
    assert.deepEqual((await r.rows({ pathSearch: '=/berlin' })).slice(0, 10).map(clock), Array.from({ length: 10 }, (_, i) => `12:00:${p2(i)}`));
    assert.equal(r.parseResult.logStart, '10/Oct/2026 10:00:00');
    assert.equal(r.parseResult.logEnd, '10/Oct/2026 12:00:09');
});

test('an added file keeps its own times too', async () => {
    const first = Array.from({ length: 20 }, (_, i) => clf('81.2.69.1', `12:00:${p2(i)}`, '+0200')).join('\n') + '\n';
    const second = Array.from({ length: 20 }, (_, i) => clf('81.2.69.2', `10:00:${p2(20 + i)}`, '+0000')).join('\n') + '\n';
    const r = await analyze(first);
    await r.append(second);
    const times = (await r.rows()).map(clock).sort();
    assert.equal(times.length, 40);
    assert.equal(times[0], '10:00:20');
    assert.equal(times[39], '12:00:19');
});

test('the analysis carries no time zone fields', async () => {
    const text = Array.from({ length: 12 }, (_, i) => clf('81.2.69.1', `12:00:${p2(i)}`, '+0200')).join('\n') + '\n';
    const r = await analyze(text);
    assert.equal('zoneOffsetMinutes' in r.parseResult, false);
    assert.equal('zoneConvertedLines' in r.parseResult, false);
});
