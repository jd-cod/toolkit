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

test('text in the method position is counted as sent by both engines', () => {
    const rows = ['GET', 'get', 'Get', '<b>', 'POST', 'PROPFIND'].map((method, i) => line(i, '/x', 200).replace('"GET ', `"${method} `));
    const { paste, upload, filter } = engines(rows.join('\n') + '\n');
    const hits = data => data.http_metrics.method_hits.map(m => [m.method, m.count]);
    assert.deepEqual(hits(paste), [['GET', 3], ['<b>', 1], ['POST', 1], ['PROPFIND', 1]]);
    assert.deepEqual(hits(upload), hits(paste));
    assert.equal(filter({ method: '<b>' }).total_requests, 1);
    assert.equal(filter({ method: '<B>' }).total_requests, 1);
    assert.equal(filter({ method: 'get' }).total_requests, 3);
});

test('a log where every request has a status has no "other" class', () => {
    const { paste, upload } = engines(mixedLog());
    assert.deepEqual(Object.keys(paste.http_metrics.status_categories), ['1xx', '2xx', '3xx', '4xx', '5xx']);
    assert.deepEqual(upload.http_metrics.status_categories, paste.http_metrics.status_categories);
});

// ── The whole result object ────────────────────────────────────────────────
// Countries and networks come from a small table here, so the test needs no
// GeoIP database. 81.2.69.x has no country and no network on purpose.
const { streamChunksToWorker } = require('../../frontend/public/js/stream-line-splitter.js');
const DashboardFilters = require('../../frontend/public/js/dashboard-filters.js');
const PLACES = {
    '66.249': { country: 'United States', country_code: 'US', asn: 15169, asn_org: 'GOOGLE' },
    '40.77': { country: 'United States', country_code: 'US', asn: 8075, asn_org: 'MICROSOFT' },
    '91.64': { country: 'Germany', country_code: 'DE', asn: 3209, asn_org: 'Vodafone GmbH' },
    '90.55': { country: 'France', country_code: 'FR', asn: 3215, asn_org: 'Orange' },
    '45.142': { country: 'The Netherlands', country_code: 'NL', asn: 0, asn_org: 'Unknown' },
};
const NOWHERE = { country: 'Unknown', country_code: '--', asn: 0, asn_org: 'Unknown' };
const place = ip => PLACES[ip.split('.').slice(0, 2).join('.')] || NOWHERE;
const fakeGeoIP = {
    isReady: () => true,
    lookupIP: place,
    lookupCountry: ip => ({ country: place(ip).country, country_code: place(ip).country_code }),
    lookupASN: ip => ({ asn: place(ip).asn, asn_org: place(ip).asn_org }),
};

function fakeWorker() {
    const listeners = { message: new Set(), error: new Set() };
    const worker = {
        onmessage: null,
        addEventListener: (type, fn) => listeners[type].add(fn),
        removeEventListener: (type, fn) => listeners[type].delete(fn),
        postMessage: message => setTimeout(() => handler({ data: message }), 0),
    };
    const handler = createWorkerHandler(message => setTimeout(() => {
        for (const fn of [...listeners.message]) fn({ data: message });
        if (worker.onmessage) worker.onmessage({ data: message });
    }, 0));
    return worker;
}

async function bothEngines(text) {
    const previous = globalThis.GeoIP;
    globalThis.GeoIP = fakeGeoIP;
    try {
        const parsed = LogParser.parseIPs(text, OPTIONS);
        Analyzer.enrichLogEntries(parsed.logEntries);
        const worker = fakeWorker();
        const result = await streamChunksToWorker(new Response(text).body, worker, OPTIONS);
        const filter = filters => new Promise(resolve => {
            worker.onmessage = e => { if (e.data.type === 'filter_result') resolve(Analyzer.analyzeFromWorkerSummary(e.data.summary)); };
            worker.postMessage({ action: 'filter', filters });
        });
        // Analysed while the table is in place: the paste engine looks addresses up as it goes.
        const paste = entries => plainResult(Analyzer.analyzeEnhancedLogs(entries));
        return { entries: parsed.logEntries, paste, upload: plainResult(Analyzer.analyzeFromWorkerSummary(result.summary)), filter: async filters => plainResult(await filter(filters)), restore: () => { globalThis.GeoIP = previous; } };
    } catch (error) {
        globalThis.GeoIP = previous;
        throw error;
    }
}

// What the two engines are allowed to differ in: the paste engine keeps every
// request, so it alone has the full referrer addresses and the lines per address.
function plainResult(data) {
    const copy = plain(data);
    delete copy.referrers;
    delete copy.ip_log_entries;
    return copy;
}

function shopLog() {
    const BOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    const rows = [];
    const row = (i, ip, method, url, status, bytes, ref, ua) => rows.push(`${ip} - - [27/Nov/2026:${p2(8 + Math.floor(i / 3600))}:${p2(Math.floor(i / 60) % 60)}:${p2(i % 60)} +0100] "${method} ${url} HTTP/1.1" ${status} ${bytes} "${ref}" "${ua}"`);
    for (let i = 0; i < 900; i++) {
        const net = ['91.64.203', '90.55.130', '81.2.69', '91.64.7'][i % 4];
        const url = ['/', '/products', `/products/item-${i % 23}`, '/cart', `/search?q=${i % 5}`, '/static/app.js', '/static/app.css', `/missing/${i % 6}`][i % 8];
        row(i * 7, `${net}.${1 + (i % 61)}`, i % 9 === 0 ? 'POST' : 'GET', url, url.startsWith('/missing') ? 404 : (i % 31 === 0 ? 502 : (i % 6 === 0 ? 304 : 200)), i % 6 === 0 ? 0 : 500 + (i * 37) % 9000, i % 3 === 0 ? 'https://www.google.com/' : (i % 3 === 1 ? `https://shop.example.com/p/${i % 4}` : '-'), UA);
    }
    for (let i = 0; i < 160; i++) row(i * 31, `66.249.66.${1 + (i % 9)}`, 'GET', i % 10 === 0 ? '/robots.txt' : `/products/item-${i % 40}`, 200, 4000 + i, '-', BOT);
    for (let i = 0; i < 70; i++) row(2000 + i, '45.142.120.10', 'GET', ['/.env', '/wp-login.php', '/.git/config', '/phpmyadmin/'][i % 4], 404, 162, '-', 'python-requests/2.31.0');
    for (let i = 0; i < 40; i++) row(3000 + i * 2, `40.77.167.${1 + (i % 4)}`, 'GET', '/sale', i % 5 === 0 ? 503 : 200, 900, 'https://news.example.org/story', UA);
    return rows.join('\n') + '\n';
}

test('the whole result is the same in both engines', async () => {
    const run = await bothEngines(shopLog());
    try {
        const paste = run.paste(run.entries);
        assert.equal(paste.total_requests, 1170);
        // The log exercises what is compared.
        assert.ok(paste.country_hits.some(c => c.country === 'Unknown') && paste.country_hits.length === 5);
        assert.ok(paste.asn_hits.some(a => a.asn === 0) && paste.asn_hits.every(a => typeof a.asn === 'number'));
        assert.ok(paste.country_hits.every(c => c.unique_ips > 0 && c.ip_details.length === Math.min(c.unique_ips, 100)));
        assert.ok(paste.http_metrics.response_size.median > 0 && paste.http_metrics.response_size.min === 0);
        assert.equal(paste.temporal_distribution.hourly.reduce((sum, h) => sum + h.count, 0), 1170);
        assert.ok(paste.traffic_classes.filter(c => c.requests > 0).length >= 3);
        assert.ok(paste.top_ips[0].country !== undefined && paste.top_ips.length === 50);

        assert.deepEqual(run.upload, paste);

        for (const [name, filters, keep] of [
            ['a country', { country: 'Germany' }, e => place(e.ip).country === 'Germany'],
            ['addresses without a country', { country: 'Unknown' }, e => place(e.ip).country === 'Unknown'],
            ['a network', { asn: 'AS3215' }, e => place(e.ip).asn === 3215],
            ['addresses without a network', { asn: 'AS0' }, e => place(e.ip).asn === 0],
            ['errors', { statusCategory: '5xx' }, e => e.status_code >= 500],
            ['a method and a section', { method: 'POST', pathSearch: '^/products' }, e => e.method === 'POST' && e.url.split('?')[0].startsWith('/products')],
            ['an address block', { ipSearch: '91.64.0.0/16' }, e => e.ip.startsWith('91.64.')],
            ['a User-Agent', { uaSearch: 'googlebot' }, e => /googlebot/i.test(e.user_agent)],
            ['a traffic class', { bot: 'human' }, e => e.traffic_class === 'human'],
        ]) {
            const kept = run.entries.filter(keep);
            assert.ok(kept.length > 0 && kept.length < run.entries.length, `${name}: the filter keeps a part of the log`);
            // The page's own filter for pasted logs names the same requests.
            assert.deepEqual(DashboardFilters.apply(run.entries, { ...DashboardFilters.none(), ...filters }), kept, `${name}: paste filter`);
            assert.deepEqual(await run.filter(filters), run.paste(kept), name);
        }
    } finally {
        run.restore();
    }
});
