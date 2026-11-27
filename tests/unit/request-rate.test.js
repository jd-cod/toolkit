import { test } from 'node:test';
import assert from 'node:assert/strict';
import engine from './helpers/engine.js';

// Requests over time. Each log is generated from a list of (second, status),
// so what the engine reports can be recounted here from that list.
const { analyze, Analyzer, ColumnarStorage, plain } = engine;

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
    const requests = [];
    for (let i = 0; i < n; i++) {
        const at = i % 7 === 0 ? Math.floor(spanSeconds / 2) + Math.floor(rnd() * Math.min(60, spanSeconds)) : Math.floor(rnd() * spanSeconds);
        requests.push({ sec: T0 + Math.min(at, spanSeconds), status: [200, 200, 200, 304, 404, 500][Math.floor(rnd() * 6)], i });
    }
    requests.push({ sec: T0, status: 200, i: 0 }, { sec: T0 + spanSeconds, status: 200, i: 0 });
    return { requests, text: requests.map(r => line(r.sec, r.status, r.i)).join('\n') + '\n' };
}

const statusClass = status => `status_${Math.floor(status / 100)}xx`;

// Every bucket holds exactly the generated requests of its stretch, split by status class.
function assertBuckets(rate, requests, label) {
    const step = rate.bucket_seconds;
    const expected = new Map();
    for (const r of requests) {
        const key = Math.floor(r.sec / step) * step * 1000;
        const bucket = expected.get(key) || { count: 0, status_2xx: 0, status_3xx: 0, status_4xx: 0, status_5xx: 0 };
        bucket.count++;
        bucket[statusClass(r.status)]++;
        expected.set(key, bucket);
    }
    const filled = rate.buckets.filter(b => b.count > 0);
    assert.equal(filled.length, expected.size, `${label}: buckets with requests`);
    for (const b of filled) {
        const want = expected.get(b.timestamp);
        assert.ok(want, `${label}: a bucket at ${new Date(b.timestamp).toISOString()}`);
        assert.deepEqual({ count: b.count, status_2xx: b.status_2xx, status_3xx: b.status_3xx, status_4xx: b.status_4xx, status_5xx: b.status_5xx }, want, `${label}: ${new Date(b.timestamp).toISOString()}`);
    }
}

for (const [name, span, n] of [['3 minutes', 180, 600], ['25 minutes', 1500, 2000], ['6 hours', 6 * 3600, 5000], ['3 days', 3 * 86400, 6000], ['45 days', 45 * 86400, 6000]]) {
    test(`the timeline holds every request at its time: ${name}`, async () => {
        const { requests, text } = log(span, n);
        const { summary, data } = await analyze(text);
        assert.ok(summary.rateSeries, 'the engine sends a rate series');
        assert.ok(summary.rateSeries.times.length <= 20000);
        for (const resolution of [undefined, 1, 5, 60, 900]) {
            const rate = Analyzer.requestRateFromSeries(summary.rateSeries, { resolution });
            assert.equal(rate.total_requests, requests.length, `resolution ${resolution}`);
            assert.equal(rate.duration_seconds, span, `resolution ${resolution}`);
            assert.ok(rate.bucket_seconds % summary.rateSeries.base === 0, 'a chart interval is a multiple of the series step');
            assertBuckets(rate, requests, `resolution ${resolution}`);
        }
        assert.deepEqual(plain(data.request_rate), plain(Analyzer.requestRateFromSeries(summary.rateSeries)));
        assert.ok(data.request_rate.buckets.some(b => b.status_4xx > 0 && b.status_5xx > 0 && b.status_3xx > 0), 'the status split is there');
    });
}

test('a filtered view has the timeline of the filtered requests', async () => {
    const { requests, text } = log(1500, 2000);
    const { filter } = await analyze(text);
    const errors = requests.filter(r => r.status >= 400 && r.status < 500);
    const rate = (await filter({ statusCategory: '4xx' })).request_rate;
    assert.equal(rate.total_requests, errors.length);
    assertBuckets(rate, errors, '4xx');
    assert.deepEqual((await filter({ ipSearch: '203.0.113.1' })).request_rate.buckets, []);
});

test('one stray date does not stretch the timeline', async () => {
    const { requests, text } = log(600, 800);
    const { data } = await analyze(text + line(Date.UTC(2016, 0, 1) / 1000) + '\n');
    assert.equal(data.total_requests, requests.length + 1);
    const rate = data.request_rate;
    assert.equal(rate.duration_seconds, 600);
    assert.equal(rate.total_requests, requests.length);
    assert.equal(rate.start_time, '10:00:00');
    assert.equal(rate.end_time, '10:10:00');
    assertBuckets(rate, requests, 'without the stray date');
});

test('requests without a time are left out of the timeline, not out of the totals', async () => {
    const { text } = log(300, 100);
    const { summary, data } = await analyze(text + '81.2.69.9 - - [not a date] "GET / HTTP/1.1" 200 5 "-" "' + UA + '"\n');
    assert.equal(summary.matchingCount, 103);
    assert.equal(summary.rateSeries.requests, 102);
    assert.equal(data.request_rate.total_requests, 102);
});

test('the busiest second does not depend on the chart interval', async () => {
    const rows = [];
    for (let i = 0; i < 600; i++) rows.push(line(T0 + i, 200, i));
    // 37 requests inside one second, straddled by nothing else.
    for (let i = 0; i < 36; i++) rows.push(line(T0 + 301, 500, i));
    const { summary } = await analyze(rows.join('\n') + '\n');
    for (const resolution of [undefined, 1, 5, 60, 300]) {
        const rate = Analyzer.requestRateFromSeries(summary.rateSeries, { resolution });
        assert.equal(rate.busiest_window_seconds, 1);
        assert.equal(rate.busiest_window_label, 'second');
        assert.equal(rate.busiest_count, 37);
        assert.equal(rate.busiest_rps, 37);
        assert.equal(rate.busiest_timestamp, (T0 + 301) * 1000);
        assert.equal(rate.busiest_time_str, '10:05:01');
    }
    // The chart peak is an average over a bucket, so it is lower.
    assert.ok(Analyzer.requestRateFromSeries(summary.rateSeries).peak_rps < 37);
});

test('a long log names the stretch its busiest count is for', async () => {
    const { requests, text } = log(3 * 86400, 6000);
    const rate = (await analyze(text)).data.request_rate;
    assert.equal(rate.busiest_window_seconds, 30);
    assert.equal(rate.busiest_window_label, '30s');
    // The fullest half minute of the generated requests; the earliest when several tie.
    const perWindow = new Map();
    for (const r of requests) perWindow.set(Math.floor(r.sec / 30), (perWindow.get(Math.floor(r.sec / 30)) || 0) + 1);
    const most = Math.max(...perWindow.values());
    const first = Math.min(...[...perWindow].filter(([, count]) => count === most).map(([key]) => key));
    assert.equal(rate.busiest_count, most);
    assert.equal(rate.busiest_timestamp, first * 30 * 1000);
    assert.equal(rate.busiest_rps, Number((most / 30).toFixed(2)));
    const tie = await analyze([line(T0, 200), line(T0 + 50, 200), line(T0 + 100, 200)].join('\n') + '\n');
    assert.equal(tie.data.request_rate.busiest_timestamp, T0 * 1000);
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
