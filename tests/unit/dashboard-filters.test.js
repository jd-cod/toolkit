import { test } from 'node:test';
import assert from 'node:assert/strict';
import engine from './helpers/engine.js';
import { createRequire } from 'node:module';

// The dashboard names the filters, the engine decides which requests pass
// them. Five requests with known properties show both.
const { ColumnarStorage } = engine;
const DashboardFilters = createRequire(import.meta.url)('../../frontend/public/js/dashboard-filters.js');

const at = (h, m, s = 0) => Date.UTC(2026, 10, 27, h, m, s) / 1000;
const CLASSES = globalThis.TrafficClassifier.CLASSES;
const REQUESTS = [
    { ip: '81.2.69.1', time: at(10, 0), method: 'GET', url: '/', status: 200, country: 'DE', asn: 3209, ua: 'Mozilla/5.0 Chrome/128', cls: 'human', group: '' },
    { ip: '81.2.69.2', time: at(10, 10), method: 'POST', url: '/api/login?next=/', status: 401, country: 'DE', asn: 3209, ua: 'Mozilla/5.0 Chrome/128', cls: 'human', group: '' },
    { ip: '81.2.70.9', time: at(10, 20), method: 'GET', url: '/products/7', status: 503, country: 'FR', asn: 3215, ua: 'Mozilla/5.0 Chrome/128', cls: 'human', group: '' },
    { ip: '2001:db8::1', time: at(10, 30), method: 'GET', url: '/products', status: 0, country: '-', asn: 0, ua: 'curl/8.4.0', cls: 'automated', group: 'Scripts & HTTP libraries' },
    { ip: '66.249.66.1', time: 0, method: 'GET', url: '/robots.txt', status: 103, country: 'DE', asn: 3209, ua: 'Googlebot/2.1', cls: 'verified', group: 'Google' },
];
const storage = new ColumnarStorage();
REQUESTS.forEach((r, client) => storage.appendRow(r.ip, r.time, r.status, 512, r.url, 'None', r.country, r.asn, r.method, client));
storage.countryNames = { DE: 'Germany', FR: 'France' };
storage.setClientClasses(CLASSES, Uint8Array.from(REQUESTS, r => CLASSES.indexOf(r.cls)), REQUESTS.map(r => r.group), client => REQUESTS[client].ua);

// Which of the five requests pass, by their position.
const kept = (filters, window) => storage
    .getPage(1, 100, DashboardFilters.forWorker({ ...DashboardFilters.none(), ...filters }, window)).rows
    .map(row => REQUESTS.findIndex(r => r.url === row.url));

test('no filter keeps every request', () => {
    assert.deepEqual(kept({}), [0, 1, 2, 3, 4]);
    assert.equal(DashboardFilters.count(DashboardFilters.none()), 0);
    assert.equal(DashboardFilters.isActive(DashboardFilters.none()), false);
});

test('each filter keeps the requests it names', () => {
    assert.deepEqual(kept({ method: 'post' }), [1]);
    assert.deepEqual(kept({ statusCategory: '2xx' }), [0]);
    assert.deepEqual(kept({ statusCategory: '4xx' }), [1]);
    assert.deepEqual(kept({ statusCategory: '1xx' }), [4]);
    assert.deepEqual(kept({ statusCategory: '503' }), [2]);
    assert.deepEqual(kept({ statusCategory: 'other' }), [3], 'no HTTP status');
    assert.deepEqual(kept({ country: 'France' }), [2]);
    assert.deepEqual(kept({ country: 'Unknown' }), [3]);
    assert.deepEqual(kept({ asn: '3209' }), [0, 1, 4], 'the network table sends the bare number');
    assert.deepEqual(kept({ asn: 'AS3215' }), [2]);
    assert.deepEqual(kept({ asn: 'AS0' }), [3]);
    assert.deepEqual(kept({ bot: 'human' }), [0, 1, 2]);
    assert.deepEqual(kept({ bot: 'all_bots' }), [3, 4]);
    assert.deepEqual(kept({ bot: 'verified' }), [4]);
    assert.deepEqual(kept({ bot: 'Google' }), [4], 'a bot group by name');
    assert.deepEqual(kept({ bot: 'all_bots', botGroup: 'Google' }), [4]);
    assert.deepEqual(kept({ pathSearch: '/products' }), [2, 3], 'text anywhere in the URL');
    assert.deepEqual(kept({ pathSearch: '=/products' }), [3], 'an exact path');
    assert.deepEqual(kept({ pathSearch: '^/products' }), [2, 3], 'a section');
    assert.deepEqual(kept({ pathSearch: '=/api/login' }), [1], 'the query string is not part of the path');
    assert.deepEqual(kept({ ipSearch: '81.2.69.1' }), [0], 'a full address is that address only');
    assert.deepEqual(kept({ ipSearch: '81.2.' }), [0, 1, 2]);
    assert.deepEqual(kept({ ipSearch: '81.2.70.0/24' }), [2]);
    assert.deepEqual(kept({ ipSearch: '2001:DB8:0:0::1' }), [3], 'IPv6 in any notation');
    assert.deepEqual(kept({ uaSearch: ' CURL ' }), [3]);
    assert.deepEqual(kept({ method: 'GET', statusCategory: '5xx', country: 'France' }), [2], 'filters combine');
});

test('the handles leave out requests without a time, "last minutes" keeps them', () => {
    const handles = { startMs: at(10, 5) * 1000, endMs: at(10, 20) * 1000, keepUntimed: false };
    assert.deepEqual(kept({}, handles), [1, 2], 'both ends are inside the window');
    const last = { startMs: at(10, 15) * 1000, endMs: null, keepUntimed: true };
    assert.deepEqual(kept({}, last), [2, 3, 4]);
    assert.deepEqual(kept({ bot: 'human' }, last), [2]);
});

test('the engine gets the same filters, with the window in seconds', () => {
    const filters = { ...DashboardFilters.none(), method: 'GET' };
    assert.deepEqual(DashboardFilters.forWorker(filters), filters);
    assert.notEqual(DashboardFilters.forWorker(filters), filters, 'a copy');
    const both = DashboardFilters.forWorker(filters, { startMs: 1_000_500, endMs: 2_000_999, keepUntimed: false });
    assert.equal(both.startTimeSec, 1000);
    assert.equal(both.endTimeSec, 2000);
    assert.equal('keepUntimed' in both, false);
    const open = DashboardFilters.forWorker(filters, { startMs: 5_000, endMs: null, keepUntimed: true });
    assert.equal(open.startTimeSec, 5);
    assert.equal('endTimeSec' in open, false);
    assert.equal(open.keepUntimed, true);
});

test('counting the active filters', () => {
    const filters = { ...DashboardFilters.none(), method: 'GET', ipSearch: '81.', uaSearch: '  ' };
    assert.equal(DashboardFilters.count(filters), 2, 'blank text is not a filter');
    assert.equal(DashboardFilters.count({ ...DashboardFilters.none(), statusCategory: '4xx', country: 'France', asn: 'AS1', bot: 'human', pathSearch: '/a', uaSearch: 'x' }), 6);
});

test('status choices: classes that occur, the most frequent codes, and requests without a status', () => {
    const options = DashboardFilters.statusOptions([{ code: 200, count: 50 }, { code: 404, count: 7 }, { code: 301, count: 7 }, { code: 0, count: 3 }, { code: 999, count: 2 }, { code: 500, count: 0 }]);
    assert.deepEqual(options.classes, [{ value: '2xx', count: 50 }, { value: '3xx', count: 7 }, { value: '4xx', count: 7 }, { value: 'other', label: 'No status', count: 5 }]);
    assert.deepEqual(options.codes, [{ value: '200', count: 50 }, { value: '301', count: 7 }, { value: '404', count: 7 }]);
    assert.deepEqual(DashboardFilters.statusOptions(undefined), { classes: [], codes: [] });
});

test('dropdown choices come from the analysis of the whole log', () => {
    const options = DashboardFilters.options({
        http_metrics: { method_hits: [{ method: 'POST', count: 2 }, { method: 'GET', count: 9 }], status_hits: [{ code: 200, count: 11 }], path_sections: [{ path: '/api', count: 6 }, { path: '/', count: 5 }] },
        country_hits: [{ country: 'Germany', hits: 8 }, { country: 'Unknown', hits: 3 }],
        asn_hits: [{ asn: 3209, asn_org: 'Vodafone GmbH with a very long name', hits: 8 }, { asn: 0, asn_org: 'Unknown', hits: 3 }],
        human_requests: 9, verified_bots_count: 1, spoofed_bots_count: 0, unverified_bots_count: 0, automated_count: 1, suspected_count: 0,
    });
    assert.deepEqual(options.methods, ['GET', 'POST']);
    assert.deepEqual(options.countries, [{ country: 'Germany', count: 8 }, { country: 'Unknown', count: 3 }]);
    assert.deepEqual(options.asns, [{ asn: 'AS3209', count: 8, label: 'AS3209 - Vodafone GmbH with a' }, { asn: 'AS0', count: 3, label: 'AS0 - Unknown' }]);
    assert.deepEqual(options.paths, [{ path: '/api', count: 6 }, { path: '/', count: 5 }]);
    assert.deepEqual(options.trafficStats, { human: 9, verified: 1, fake: 0, unverified: 0, automated: 1, suspected: 0 });
    assert.deepEqual(DashboardFilters.options(null).methods, []);
});
