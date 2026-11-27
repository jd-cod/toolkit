import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
require('../../frontend/public/js/request-paths.js');
require('../../frontend/public/js/bot-detector.js');
require('../../frontend/public/js/traffic-classifier.js');
const LogParser = require('../../frontend/public/js/log-parser.js');
globalThis.LogParser = LogParser;
const { ColumnarStorage } = require('../../frontend/public/js/columnar-storage.js');
const Analyzer = require('../../frontend/public/js/analyzer.js');
const { createWorkerHandler } = require('../../frontend/public/js/log-parser.worker.js');

globalThis.GeoIP = { lookupIP: () => ({ country: 'Unknown', country_code: '--', asn: 0, asn_org: 'Unknown' }), lookupCountry: () => ({ country: 'Unknown', country_code: '--' }) };

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const p2 = n => String(n).padStart(2, '0');
const stamp = sec => { const t = new Date(sec * 1000); return `${p2(t.getUTCDate())}/${MONTHS[t.getUTCMonth()]}/${t.getUTCFullYear()}:${p2(t.getUTCHours())}:${p2(t.getUTCMinutes())}:${p2(t.getUTCSeconds())} +0000`; };
const line = (sec, status = 200, i = 0) => `81.2.69.${1 + (i % 50)} - - [${stamp(sec)}] "GET /p/${i % 40} HTTP/1.1" ${status} 512 "-" "${UA}"`;
const T0 = Date.UTC(2026, 10, 27, 10, 0, 0) / 1000;

// Deterministic pseudo-random spread with a burst in the middle.
function log(spanSeconds, n) {
    let seed = 11;
    const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    const rows = [];
    for (let i = 0; i < n; i++) {
        const at = i % 7 === 0 ? Math.floor(spanSeconds / 2) + Math.floor(rnd() * Math.min(60, spanSeconds)) : Math.floor(rnd() * spanSeconds);
        rows.push(line(T0 + Math.min(at, spanSeconds), [200, 200, 200, 304, 404, 500][Math.floor(rnd() * 6)], i));
    }
    rows.push(line(T0, 200), line(T0 + spanSeconds, 200));
    return rows.join('\n') + '\n';
}

function engines(text) {
    const parsed = LogParser.parseIPs(text, { skip403: false, skipInternal: false });
    const messages = [];
    const handler = createWorkerHandler(msg => messages.push(msg));
    handler({ data: { action: 'parse_stream_chunk', chunk: new TextEncoder().encode(text), isLast: true, options: { skip403: false, skipInternal: false } } });
    const complete = messages.find(m => m.type === 'complete');
    const filter = filters => {
        messages.length = 0;
        handler({ data: { action: 'filter', filters } });
        return messages.find(m => m.type === 'filter_result').summary;
    };
    return { entries: parsed.logEntries, summary: complete.summary, filter };
}
const plain = value => JSON.parse(JSON.stringify(value));

for (const [name, span, n] of [['3 minutes', 180, 600], ['25 minutes', 1500, 2000], ['6 hours', 6 * 3600, 5000], ['3 days', 3 * 86400, 6000], ['45 days', 45 * 86400, 6000]]) {
    test(`timeline and rate numbers are the same in both engines: ${name}`, () => {
        const { entries, summary } = engines(log(span, n));
        assert.ok(summary.rateSeries, 'the worker sends a rate series');
        assert.ok(summary.rateSeries.times.length <= 20000);
        for (const resolution of [undefined, 1, 5, 60, 900]) {
            const paste = plain(Analyzer.computeRequestRate(entries, { resolution }));
            const upload = plain(Analyzer.requestRateFromSeries(summary.rateSeries, { resolution }));
            assert.deepEqual(upload, paste, `resolution ${resolution}`);
        }
        const data = Analyzer.analyzeFromWorkerSummary(summary);
        assert.deepEqual(plain(data.request_rate), plain(Analyzer.computeRequestRate(entries)));
        assert.equal(data.request_rate.buckets.reduce((a, b) => a + b.count, 0), entries.length);
        assert.ok(data.request_rate.buckets.some(b => b.status_4xx > 0 && b.status_5xx > 0 && b.status_3xx > 0), 'the status split is there');
    });
}

test('a filtered upload has the timeline of the filtered requests', () => {
    const { entries, filter } = engines(log(1500, 2000));
    const errors = entries.filter(e => e.status_code >= 400 && e.status_code < 500);
    assert.deepEqual(plain(Analyzer.analyzeFromWorkerSummary(filter({ statusCategory: '4xx' })).request_rate), plain(Analyzer.computeRequestRate(errors)));
    assert.deepEqual(Analyzer.analyzeFromWorkerSummary(filter({ ipSearch: '203.0.113.1' })).request_rate.buckets, []);
});

test('one stray date does not stretch the timeline in either engine', () => {
    const text = log(600, 800) + line(Date.UTC(2016, 0, 1) / 1000) + '\n';
    const { entries, summary } = engines(text);
    const paste = Analyzer.computeRequestRate(entries);
    const upload = Analyzer.requestRateFromSeries(summary.rateSeries);
    assert.equal(paste.duration_seconds, 600);
    for (const key of ['bucket_seconds', 'total_buckets', 'total_requests', 'duration_seconds', 'start_time', 'end_time', 'peak_count', 'avg_rps']) {
        assert.equal(upload[key], paste[key], key);
    }
    assert.deepEqual(plain(upload.buckets), plain(paste.buckets));
});

test('requests without a time are left out of the timeline, not out of the totals', () => {
    const text = log(300, 100) + '81.2.69.9 - - [not a date] "GET / HTTP/1.1" 200 5 "-" "' + UA + '"\n';
    const { entries, summary } = engines(text);
    assert.equal(entries.length, 103);
    assert.equal(summary.matchingCount, 103);
    assert.equal(summary.rateSeries.requests, 102);
    assert.equal(Analyzer.computeRequestRate(entries).total_requests, 102);
});

test('slot size of the series fits every span', () => {
    assert.equal(ColumnarStorage.rateSeriesBase(T0, T0 + 19999), 1);
    assert.equal(ColumnarStorage.rateSeriesBase(T0, T0 + 20000), 5);
    assert.equal(ColumnarStorage.rateSeriesBase(T0, T0 + 86400), 5);
    assert.equal(ColumnarStorage.rateSeriesBase(T0, T0 + 7 * 86400), 60);
    assert.equal(ColumnarStorage.rateSeriesBase(T0, T0 + 365 * 86400), 3600);
    const tenYears = ColumnarStorage.rateSeriesBase(T0, T0 + 3650 * 86400);
    assert.ok(tenYears % 3600 === 0 && 3650 * 86400 / tenYears <= 20000);
});
