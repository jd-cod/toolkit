import { test } from 'node:test';
import assert from 'node:assert/strict';
import engine from './helpers/engine.js';

// The numbers on the page, checked against the log they come from. Each log
// here is generated from a list of requests, so every number the engine
// reports can be recounted from that list with a plain loop.
const { analyze } = engine;
const RequestPaths = globalThis.RequestPaths;

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
const p2 = n => String(n).padStart(2, '0');

// Countries and networks come from a small table, so no GeoIP database is
// needed. 81.2.69.x has no country and no network on purpose.
const PLACES = {
    '66.249': { country: 'United States', country_code: 'US', asn: 15169, asn_org: 'GOOGLE' },
    '40.77': { country: 'United States', country_code: 'US', asn: 8075, asn_org: 'MICROSOFT' },
    '91.64': { country: 'Germany', country_code: 'DE', asn: 3209, asn_org: 'Vodafone GmbH' },
    '90.55': { country: 'France', country_code: 'FR', asn: 3215, asn_org: 'Orange' },
    '45.142': { country: 'The Netherlands', country_code: 'NL', asn: 0, asn_org: 'Unknown' },
};
const NOWHERE = { country: 'Unknown', country_code: '--', asn: 0, asn_org: 'Unknown' };
const place = ip => PLACES[ip.split('.').slice(0, 2).join('.')] || NOWHERE;
globalThis.GeoIP = {
    isReady: () => true,
    lookupIP: place,
    lookupCountry: ip => ({ country: place(ip).country, country_code: place(ip).country_code }),
    lookupASN: ip => ({ asn: place(ip).asn, asn_org: place(ip).asn_org }),
};

// One request per line. `sec` counts from 08:00:00.
const text = requests => requests.map(r => `${r.ip} - - [27/Nov/2026:${p2(8 + Math.floor(r.sec / 3600))}:${p2(Math.floor(r.sec / 60) % 60)}:${p2(r.sec % 60)} +0100] "${r.method} ${r.url} HTTP/1.1" ${r.status} ${r.bytes} "${r.ref}" "${r.ua}"`).join('\n') + '\n';
const request = (sec, ip, url, status, over = {}) => ({ sec, ip, method: 'GET', url, status, bytes: 512, ref: '-', ua: UA, ...over });

// Count a list by a key: [[key, count], ...], most frequent first.
function tally(list, keyOf) {
    const counts = new Map();
    for (const item of list) counts.set(keyOf(item), (counts.get(keyOf(item)) || 0) + 1);
    return [...counts].sort((a, b) => b[1] - a[1]);
}
const sorted = pairs => [...pairs].sort((a, b) => String(a[0]).localeCompare(String(b[0])));

function mixedLog() {
    const requests = [];
    for (let i = 0; i < 400; i++) {
        const url = ['/', '/shop/item?id=' + (i % 9), '/shop/item', '/api/v1/users/' + (i % 5), '/login', '/missing/' + (i % 3), '/static/app.js?v=' + (i % 4)][i % 7];
        const status = url.startsWith('/missing') ? 404 : (i % 11 === 0 ? 500 : (i % 5 === 0 ? 304 : 200));
        requests.push(request(i, `81.2.69.${1 + (i % 40)}`, url, status));
    }
    return requests;
}

// Requests per path with their statuses, as the path table shows them.
function pathTable(requests) {
    const byPath = new Map();
    for (const r of requests) {
        const path = RequestPaths.normalizePath(r.url);
        if (!byPath.has(path)) byPath.set(path, []);
        byPath.get(path).push(r);
    }
    return sorted([...byPath].map(([path, list]) => [path, list.length, sorted(tally(list, r => r.status))]));
}
const shownPaths = data => sorted(data.http_metrics.top_paths.map(p => [p.path, p.count, sorted(p.status_breakdown.map(s => [s.code, s.count]))]));

test('each path carries its requests and their statuses', async () => {
    const requests = mixedLog();
    const { data, filter } = await analyze(text(requests));
    assert.ok(data.http_metrics.top_paths.length >= 6);
    assert.ok(data.http_metrics.top_paths.some(p => p.status_breakdown.length >= 3), 'a path with several statuses');
    assert.deepEqual(shownPaths(data), pathTable(requests));
    assert.deepEqual(data.http_metrics.top_urls.map(u => [u.url, u.count]), data.http_metrics.top_paths.slice(0, 20).map(p => [p.path, p.count]));
    // Under a filter the split is that of the requests left.
    assert.deepEqual(shownPaths(await filter({ statusCategory: '5xx' })), pathTable(requests.filter(r => r.status >= 500)));
    const shop = await filter({ pathSearch: '^/shop' });
    assert.deepEqual(shownPaths(shop), pathTable(requests.filter(r => r.url.startsWith('/shop'))));
    assert.deepEqual(shop.http_metrics.top_paths.map(p => p.path), ['/shop/item']);
});

test('requests without an HTTP status are a class of their own', async () => {
    const requests = [];
    for (let i = 0; i < 10; i++) requests.push(request(i, '81.2.69.1', '/ok', 200));
    for (let i = 10; i < 15; i++) requests.push(request(i, '81.2.69.1', '/odd', 999));
    for (let i = 15; i < 20; i++) requests.push(request(i, '81.2.69.1', '/none', '-'));
    for (let i = 20; i < 23; i++) requests.push(request(i, '81.2.69.1', '/early', 103));
    const { data, filter } = await analyze(text(requests));
    const expected = { '1xx': 3, '2xx': 10, '3xx': 0, '4xx': 0, '5xx': 0, other: 10 };
    assert.deepEqual(data.http_metrics.status_categories, expected);
    assert.equal(Object.values(expected).reduce((a, b) => a + b, 0), data.total_requests);
    assert.equal((await filter({ statusCategory: 'other' })).total_requests, 10);
    assert.equal((await filter({ statusCategory: '1xx' })).total_requests, 3);
    assert.equal((await filter({ statusCategory: '2xx' })).total_requests, 10);
    assert.equal((await filter({ statusCategory: '103' })).total_requests, 3);
});

test('text in the method position is counted as sent', async () => {
    const requests = ['GET', 'get', 'Get', '<b>', 'POST', 'PROPFIND'].map((method, i) => request(i, '81.2.69.1', '/x', 200, { method }));
    const { data, filter } = await analyze(text(requests));
    assert.deepEqual(data.http_metrics.method_hits.map(m => [m.method, m.count]), [['GET', 3], ['<b>', 1], ['POST', 1], ['PROPFIND', 1]]);
    assert.equal((await filter({ method: '<b>' })).total_requests, 1);
    assert.equal((await filter({ method: '<B>' })).total_requests, 1);
    assert.equal((await filter({ method: 'get' })).total_requests, 3);
});

test('a log where every request has a status has no "other" class', async () => {
    const { data } = await analyze(text(mixedLog()));
    assert.deepEqual(Object.keys(data.http_metrics.status_categories), ['1xx', '2xx', '3xx', '4xx', '5xx']);
});

// ── The whole result ───────────────────────────────────────────────────────
function shopLog() {
    const BOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    const requests = [];
    for (let i = 0; i < 900; i++) {
        const net = ['91.64.203', '90.55.130', '81.2.69', '91.64.7'][i % 4];
        const url = ['/', '/products', `/products/item-${i % 23}`, '/cart', `/search?q=${i % 5}`, '/static/app.js', '/static/app.css', `/missing/${i % 6}`][i % 8];
        requests.push(request(i * 7, `${net}.${1 + (i % 61)}`, url, url.startsWith('/missing') ? 404 : (i % 31 === 0 ? 502 : (i % 6 === 0 ? 304 : 200)), {
            method: i % 9 === 0 ? 'POST' : 'GET',
            bytes: i % 6 === 0 ? 0 : 500 + (i * 37) % 9000,
            ref: i % 3 === 0 ? 'https://www.google.com/' : (i % 3 === 1 ? `https://shop.example.com/p/${i % 4}` : '-'),
        }));
    }
    for (let i = 0; i < 160; i++) requests.push(request(i * 31, `66.249.66.${1 + (i % 9)}`, i % 10 === 0 ? '/robots.txt' : `/products/item-${i % 40}`, 200, { bytes: 4000 + i, ua: BOT }));
    for (let i = 0; i < 70; i++) requests.push(request(2000 + i, '45.142.120.10', ['/.env', '/wp-login.php', '/.git/config', '/phpmyadmin/'][i % 4], 404, { bytes: 162, ua: 'python-requests/2.31.0' }));
    for (let i = 0; i < 40; i++) requests.push(request(3000 + i * 2, `40.77.167.${1 + (i % 4)}`, '/sale', i % 5 === 0 ? 503 : 200, { bytes: 900, ref: 'https://news.example.org/story' }));
    return requests;
}

// What the page shows of a list of requests, recounted from the list.
function recount(requests) {
    const ips = new Set(requests.map(r => r.ip));
    const sizes = requests.map(r => r.bytes).sort((a, b) => a - b);
    const mid = Math.floor(sizes.length / 2);
    const sites = requests.filter(r => r.ref !== '-').map(r => new URL(r.ref).hostname);
    return {
        total: requests.length,
        addresses: ips.size,
        countries: sorted(tally(requests, r => place(r.ip).country).map(([country, hits]) => [country, hits, new Set(requests.filter(r => place(r.ip).country === country).map(r => r.ip)).size])),
        networks: sorted(tally(requests, r => place(r.ip).asn).map(([asn, hits]) => [asn, hits, new Set(requests.filter(r => place(r.ip).asn === asn).map(r => r.ip)).size])),
        statuses: sorted(tally(requests, r => r.status)),
        methods: sorted(tally(requests, r => r.method)),
        bytes: sizes.reduce((sum, size) => sum + size, 0),
        smallest: sizes[0],
        largest: sizes[sizes.length - 1],
        median: sizes.length % 2 ? sizes[mid] : Math.round((sizes[mid - 1] + sizes[mid]) / 2),
        hours: sorted(tally(requests, r => 8 + Math.floor(r.sec / 3600))),
        sites: sorted(tally(sites, site => site)),
        direct: requests.length - sites.length,
    };
}

function shown(data) {
    const size = data.http_metrics.response_size;
    return {
        total: data.total_requests,
        addresses: data.unique_ips,
        countries: sorted(data.country_hits.map(c => [c.country, c.hits, c.unique_ips])),
        networks: sorted(data.asn_hits.map(a => [a.asn, a.hits, a.unique_ips])),
        statuses: sorted(data.http_metrics.status_hits.map(s => [s.code, s.count])),
        methods: sorted(data.http_metrics.method_hits.map(m => [m.method, m.count])),
        bytes: size.total,
        smallest: size.min,
        largest: size.max,
        median: size.median,
        hours: sorted(data.temporal_distribution.hourly.filter(h => h.count > 0).map(h => [h.hour, h.count])),
        sites: sorted(data.referrer_sites.map(s => [s.site, s.hits])),
        direct: data.direct_requests,
    };
}

test('the whole result is that of the log, with and without filters', async () => {
    const requests = shopLog();
    const run = await analyze(text(requests));
    const { data } = run;
    assert.equal(data.total_requests, 1170);
    assert.deepEqual(shown(data), recount(requests));

    // What is listed beside the counts.
    assert.equal(data.country_hits.length, 5);
    assert.ok(data.country_hits.some(c => c.country === 'Unknown'));
    assert.ok(data.asn_hits.some(a => a.asn === 0) && data.asn_hits.every(a => typeof a.asn === 'number'));
    assert.ok(data.country_hits.every(c => c.unique_ips > 0 && c.ip_details.length === Math.min(c.unique_ips, 100)));
    assert.equal(data.unique_countries, 4, '"Unknown" is not a country');
    assert.equal(data.unique_asns, 4, 'AS0 is not a network');
    assert.equal(data.top_ips.length, 50);
    const busiest = tally(requests, r => r.ip)[0];
    assert.deepEqual([data.top_ips[0].ip, data.top_ips[0].hits, data.top_ips[0].country], [busiest[0], busiest[1], place(busiest[0]).country]);
    assert.equal(data.traffic_classes.reduce((sum, c) => sum + c.requests, 0), 1170);
    assert.ok(data.traffic_classes.filter(c => c.requests > 0).length >= 3);

    for (const [name, filters, keep] of [
        ['a country', { country: 'Germany' }, r => place(r.ip).country === 'Germany'],
        ['addresses without a country', { country: 'Unknown' }, r => place(r.ip).country === 'Unknown'],
        ['a network', { asn: 'AS3215' }, r => place(r.ip).asn === 3215],
        ['addresses without a network', { asn: 'AS0' }, r => place(r.ip).asn === 0],
        ['errors', { statusCategory: '5xx' }, r => r.status >= 500],
        ['a method and a section', { method: 'POST', pathSearch: '^/products' }, r => r.method === 'POST' && r.url.split('?')[0].startsWith('/products')],
        ['an address block', { ipSearch: '91.64.0.0/16' }, r => r.ip.startsWith('91.64.')],
        ['a User-Agent', { uaSearch: 'googlebot' }, r => /googlebot/i.test(r.ua)],
    ]) {
        const kept = requests.filter(keep);
        assert.ok(kept.length > 0 && kept.length < requests.length, `${name}: the filter keeps a part of the log`);
        assert.deepEqual(shown(await run.filter(filters)), recount(kept), name);
    }

    // A traffic class: the requests listed for it are the ones counted for it.
    const humans = (await run.rows()).filter(row => row.traffic_class === 'human');
    const human = await run.filter({ bot: 'human' });
    assert.ok(humans.length > 0 && humans.length < requests.length);
    assert.equal(human.total_requests, humans.length);
    assert.equal(human.human_requests, humans.length);
    assert.equal(human.unique_ips, new Set(humans.map(row => row.ip)).size);
});

test('the Log Explorer lists the newest request first, whatever the order of the log', async () => {
    const UNTIMED = '81.2.69.99 - - [not a date] "GET /untimed HTTP/1.1" 200 5 "-" "' + UA + '"';
    const ordered = [request(10, '81.2.69.1', '/a', 200), request(20, '81.2.69.1', '/b', 200), request(20, '81.2.69.1', '/c', 200), request(30, '81.2.69.1', '/d', 200)];
    const inOrder = await analyze(text(ordered));
    assert.deepEqual((await inOrder.rows({}, 'newest')).map(r => r.url), ['/d', '/c', '/b', '/a'], 'of two in the same second, the one read later');
    assert.deepEqual((await inOrder.rows({}, 'file')).map(r => r.url), ['/a', '/b', '/c', '/d']);
    assert.deepEqual(inOrder.pageResult.rows.map(r => r.url), ['/d', '/c', '/b', '/a'], 'the first page that comes with the analysis');

    // Two servers one after the other, and a line without a time.
    const mixed = await analyze(text([ordered[3], ordered[0]]) + UNTIMED + '\n' + text([ordered[2], ordered[1]]));
    assert.deepEqual((await mixed.rows({}, 'newest')).map(r => r.url), ['/d', '/b', '/c', '/a', '/untimed']);
    assert.deepEqual((await mixed.rows({ pathSearch: '=/b' }, 'newest')).map(r => r.url), ['/b'], 'a filter keeps the order');
    assert.deepEqual((await mixed.rows({}, 'file')).map(r => r.url), ['/d', '/a', '/untimed', '/c', '/b']);
    // A source added later is sorted in with the rest.
    await mixed.append(text([request(25, '81.2.69.1', '/e', 200)]));
    assert.deepEqual((await mixed.rows({}, 'newest')).map(r => r.url), ['/d', '/e', '/b', '/c', '/a', '/untimed']);
});

test('a row names the country, the protocol and the User-Agent of its request', async () => {
    const run = await analyze('91.64.203.5 - - [27/Nov/2026:08:00:00 +0100] "GET /h2 HTTP/2.0" 200 5 "-" "' + UA + '"\n81.2.69.1 - - [27/Nov/2026:08:00:01 +0100] "GET /old" 200 5 "-" "-"\n');
    const [h2, old] = await run.rows();
    assert.deepEqual([h2.country, h2.country_code, h2.http_version, h2.user_agent, h2.status_code], ['Germany', 'DE', 'HTTP/2.0', UA, 200]);
    assert.deepEqual([old.country, old.country_code, old.http_version], ['Unknown', '--', null]);
});

test('the time span of the log includes excluded lines', async () => {
    // The first and the last line are refused requests, left out by "Ignore 403".
    const requests = [request(0, '81.2.69.1', '/first', 403), request(600, '81.2.69.1', '/a', 200), request(1200, '81.2.69.1', '/b', 200), request(1800, '81.2.69.1', '/last', 403)];
    const all = await analyze(text(requests));
    const without = await analyze(text(requests), { skip403: true, skipInternal: false });
    assert.equal(without.data.total_requests, 2);
    assert.equal(without.parseResult.skipCounts.forbidden, 2);
    assert.equal(without.parseResult.validLines, 4);
    for (const key of ['minTimestamp', 'maxTimestamp', 'logSpanMinutes', 'logStart', 'logEnd']) assert.equal(without.parseResult[key], all.parseResult[key], key);
    assert.equal(all.parseResult.logSpanMinutes, 30);
    assert.equal(all.parseResult.logStart, '27/Nov/2026 08:00:00');
    assert.equal(all.parseResult.logEnd, '27/Nov/2026 08:30:00');
});

test('several sources are one log, and each may have its own format', async () => {
    const first = text([request(0, '81.2.69.1', '/a', 200), request(1, '81.2.69.2', '/b', 200)]);
    const second = Array.from({ length: 3 }, (_, i) => JSON.stringify({ remote_addr: '81.2.69.3', time: `2026-11-27T08:00:1${i}+01:00`, request: `GET /j${i} HTTP/1.1`, status: 200, body_bytes_sent: 5, http_user_agent: UA })).join('\n') + '\n';
    const run = await analyze([first, new Blob([second])]);
    assert.equal(run.data.total_requests, 5);
    assert.equal(run.data.unique_ips, 3);
    assert.deepEqual((await run.rows()).map(r => r.url), ['/a', '/b', '/j0', '/j1', '/j2']);
});

test('questions asked at the same time each get their own answer', async () => {
    const requests = mixedLog();
    const run = await analyze(text(requests));
    const [errors, all, shop, page] = await Promise.all([
        run.filter({ statusCategory: '5xx' }),
        run.filter({}),
        run.filter({ pathSearch: '^/shop' }),
        run.rows({ statusCategory: '404' }),
    ]);
    assert.equal(errors.total_requests, requests.filter(r => r.status >= 500).length);
    assert.equal(all.total_requests, requests.length);
    assert.equal(shop.total_requests, requests.filter(r => r.url.startsWith('/shop')).length);
    assert.equal(page.length, requests.filter(r => r.status === 404).length);
});

test('a flood spread over many addresses is counted as suspected, and its visitors are not', async () => {
    const requests = [];
    // 25 visitors who load a page with its assets.
    for (let v = 0; v < 25; v++) {
        for (let p = 0; p < 3; p++) {
            requests.push(request(v * 10 + p * 45, `91.64.3.${v + 1}`, `/article/${p}`, 200, { ref: 'https://shop.test/' }));
            requests.push(request(v * 10 + p * 45, `91.64.3.${v + 1}`, '/static/app.css', 200, { ref: 'https://shop.test/' }));
        }
    }
    // 40 addresses ask for one page six times a minute, for three minutes.
    const flood = [];
    for (let i = 0; i < 18; i++) {
        for (let c = 0; c < 40; c++) flood.push(request(200 + i * 10 + (c % 7), `45.142.${c >> 4}.${c + 1}`, `/search?q=${i}-${c}`, i > 6 ? 503 : 200));
    }
    const run = await analyze(text([...requests, ...flood].sort((a, b) => a.sec - b.sec)));
    const classes = Object.fromEntries(run.data.traffic_classes.map(c => [c.key, [c.requests, c.unique_ips]]));
    assert.deepEqual(classes.suspected, [flood.length, 40]);
    assert.deepEqual(classes.human, [requests.length, 25]);
    const group = run.data.bot_groups.find(g => g.group_name === 'Suspected automation');
    assert.deepEqual(group.sub_bots.map(b => [b.bot_name, b.requests, b.unique_ips]), [['Distributed request flood', flood.length, 40]]);
    assert.match(run.data.suspected_clients[0].reason, /^One of 40 clients that kept requesting \/search at the same time, about 24\d requests in one minute together/);
    // The class is a filter like any other.
    assert.equal((await run.filter({ bot: 'suspected' })).total_requests, flood.length);
});

test('the sources can be read back as one text, gzip opened', async () => {
    const { gzipSync } = await import('node:zlib');
    const first = text([request(0, '81.2.69.1', '/a', 200)]);
    const second = text([request(5, '81.2.69.2', '/b', 404)]);
    assert.equal(await engine.LogEngine.readText([first, new Blob([gzipSync(second)])]), `${first}\n${second}`);
});
