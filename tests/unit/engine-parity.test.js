import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

// One log through both engines (pasted text and the upload worker): the
// numbers on the page have to be the same.
const require = createRequire(import.meta.url);
require('../../frontend/public/js/request-paths.js');
require('../../frontend/public/js/bot-detector.js');
require('../../frontend/public/js/traffic-classifier.js');
const LogParser = require('../../frontend/public/js/log-parser.js');
globalThis.LogParser = LogParser;
require('../../frontend/public/js/columnar-storage.js');
const Analyzer = require('../../frontend/public/js/analyzer.js');
const { createWorkerHandler } = require('../../frontend/public/js/log-parser.worker.js');

globalThis.GeoIP = { lookupIP: () => ({ country: 'Unknown', country_code: '--', asn: 0, asn_org: 'Unknown' }), lookupCountry: () => ({ country: 'Unknown', country_code: '--' }) };

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
const OPTIONS = { skip403: false, skipInternal: false };
const p2 = n => String(n).padStart(2, '0');
const line = (i, url, status) => `81.2.69.${1 + (i % 40)} - - [27/Nov/2026:10:${p2(Math.floor(i / 60) % 60)}:${p2(i % 60)} +0000] "GET ${url} HTTP/1.1" ${status} 512 "-" "${UA}"`;

function engines(text) {
    const parsed = LogParser.parseIPs(text, OPTIONS);
    Analyzer.enrichLogEntries(parsed.logEntries);
    const messages = [];
    const handler = createWorkerHandler(msg => messages.push(msg));
    handler({ data: { action: 'parse_stream_chunk', chunk: new TextEncoder().encode(text), isLast: true, options: OPTIONS } });
    const complete = messages.find(m => m.type === 'complete');
    const filter = filters => {
        messages.length = 0;
        handler({ data: { action: 'filter', filters } });
        return Analyzer.analyzeFromWorkerSummary(messages.find(m => m.type === 'filter_result').summary);
    };
    return {
        entries: parsed.logEntries,
        paste: Analyzer.analyzeEnhancedLogs(parsed.logEntries),
        upload: Analyzer.analyzeFromWorkerSummary(complete.summary),
        filter,
    };
}
const plain = value => JSON.parse(JSON.stringify(value));

function mixedLog() {
    const rows = [];
    for (let i = 0; i < 400; i++) {
        const url = ['/', '/shop/item?id=' + (i % 9), '/shop/item', '/api/v1/users/' + (i % 5), '/login', '/missing/' + (i % 3), '/static/app.js?v=' + (i % 4)][i % 7];
        const status = url.startsWith('/missing') ? 404 : (i % 11 === 0 ? 500 : (i % 5 === 0 ? 304 : 200));
        rows.push(line(i, url, status));
    }
    return rows.join('\n') + '\n';
}

test('paths carry the same status split in both engines', () => {
    const { paste, upload, filter, entries } = engines(mixedLog());
    assert.ok(paste.http_metrics.top_paths.length >= 6);
    assert.ok(paste.http_metrics.top_paths.some(p => p.status_breakdown.length >= 3), 'a path with several statuses');
    assert.deepEqual(plain(upload.http_metrics.top_paths), plain(paste.http_metrics.top_paths));
    assert.deepEqual(plain(upload.http_metrics.top_urls), plain(paste.http_metrics.top_urls));
    for (const p of upload.http_metrics.top_paths) {
        assert.equal(p.status_breakdown.reduce((sum, s) => sum + s.count, 0), p.count, p.path);
    }
    // Under a filter the split is that of the requests left.
    const errors = entries.filter(e => e.status_code >= 500);
    assert.deepEqual(plain(filter({ statusCategory: '5xx' }).http_metrics.top_paths), plain(Analyzer.analyzeEnhancedLogs(errors).http_metrics.top_paths));
    const shop = entries.filter(e => e.url.startsWith('/shop'));
    const filtered = filter({ pathSearch: '^/shop' }).http_metrics.top_paths;
    assert.deepEqual(plain(filtered), plain(Analyzer.analyzeEnhancedLogs(shop).http_metrics.top_paths));
    assert.deepEqual(filtered.map(p => p.path), ['/shop/item']);
});

test('requests without an HTTP status are a class of their own in both engines', () => {
    const rows = [];
    for (let i = 0; i < 10; i++) rows.push(line(i, '/ok', 200));
    for (let i = 10; i < 15; i++) rows.push(line(i, '/odd', 999));
    for (let i = 15; i < 20; i++) rows.push(line(i, '/none', '-'));
    for (let i = 20; i < 23; i++) rows.push(line(i, '/early', 103));
    const { paste, upload, filter } = engines(rows.join('\n') + '\n');
    const expected = { '1xx': 3, '2xx': 10, '3xx': 0, '4xx': 0, '5xx': 0, other: 10 };
    assert.deepEqual(paste.http_metrics.status_categories, expected);
    assert.deepEqual(upload.http_metrics.status_categories, expected);
    assert.equal(Object.values(expected).reduce((a, b) => a + b, 0), paste.total_requests);
    assert.equal(filter({ statusCategory: 'other' }).total_requests, 10);
    assert.equal(filter({ statusCategory: '1xx' }).total_requests, 3);
    assert.equal(filter({ statusCategory: '2xx' }).total_requests, 10);
    assert.equal(filter({ statusCategory: '103' }).total_requests, 3);
});

test('a log where every request has a status has no "other" class', () => {
    const { paste, upload } = engines(mixedLog());
    assert.deepEqual(Object.keys(paste.http_metrics.status_categories), ['1xx', '2xx', '3xx', '4xx', '5xx']);
    assert.deepEqual(upload.http_metrics.status_categories, paste.http_metrics.status_categories);
});
