import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const SOURCE = fs.readFileSync(fileURLToPath(new URL('../../frontend/public/js/geoip.js', import.meta.url)), 'utf8');

// ── A valid one-node MMDB: every address resolves to `record` ──
const str = s => { const b = Buffer.from(s); return b.length < 29 ? [(2 << 5) | b.length, ...b] : [(2 << 5) | 29, b.length - 29, ...b]; };
const uint = (type, v) => { const b = []; while (v > 0) { b.unshift(v & 0xff); v = Math.floor(v / 256); } return [(type << 5) | b.length, ...b]; };
const encode = v => {
    if (typeof v === 'string') return str(v);
    if (typeof v === 'number') return uint(6, v);
    const keys = Object.keys(v);
    return [(7 << 5) | keys.length, ...keys.flatMap(k => [...str(k), ...encode(v[k])])];
};
function mmdb(record) {
    const tree = [0, 0, 17, 0, 0, 17]; // both branches of the only node point at the first data item
    const meta = [(7 << 5) | 2, ...str('node_count'), ...uint(6, 1), ...str('record_size'), ...uint(5, 24)];
    return Buffer.from([...tree, ...new Array(16).fill(0), ...encode(record), 0xab, 0xcd, 0xef, ...Buffer.from('MaxMind.com'), ...meta]);
}
const COUNTRY = mmdb({ country: { iso_code: 'GB', names: { en: 'United Kingdom' } } });
const ASN = mmdb({ autonomous_system_number: 15169, autonomous_system_organization: 'GOOGLE' });
const META = { version: '1', databases: { 'GeoLite2-Country.mmdb': { version: '1' }, 'GeoLite2-ASN.mmdb': { version: '1' } } };

// ── A browser as far as geoip.js needs one ──
function fakeIndexedDB(store = new Map()) {
    const request = run => { const req = {}; setTimeout(() => run(req), 0); return req; };
    const db = {
        objectStoreNames: { contains: () => true },
        createObjectStore() {},
        transaction() {
            const tx = {
                objectStore: () => ({
                    get: key => request(req => { req.result = store.get(key); req.onsuccess && req.onsuccess(); }),
                    put: (value, key) => { store.set(key, value); setTimeout(() => tx.oncomplete && tx.oncomplete(), 0); },
                    delete: key => { store.delete(key); setTimeout(() => tx.oncomplete && tx.oncomplete(), 0); },
                }),
            };
            return tx;
        },
    };
    return { store, open: () => request(req => { req.result = db; req.onsuccess && req.onsuccess(); }) };
}

/** @param routes path -> Buffer | object (JSON) | number (HTTP status) | function returning one of these */
function browser(routes, indexedDB = fakeIndexedDB()) {
    const requests = [];
    const fetch = async (url, init = {}) => {
        const path = String(url).split('?')[0];
        requests.push(`${init.method || 'GET'} ${path}`);
        let answer = routes[path];
        if (typeof answer === 'function') answer = await answer();
        if (answer === undefined) answer = 404;
        if (typeof answer === 'number') return { ok: false, status: answer, headers: { get: () => null } };
        const body = Buffer.isBuffer(answer) ? answer : Buffer.from(JSON.stringify(answer));
        let sent = false;
        return {
            ok: true, status: 200, headers: { get: () => null },
            json: async () => JSON.parse(body.toString()),
            body: { getReader: () => ({ read: async () => (sent ? { done: true } : (sent = true, { done: false, value: new Uint8Array(body) })) }) },
        };
    };
    const quiet = { log() {}, info() {}, warn() {}, error() {} };
    const sandbox = { window: {}, indexedDB, fetch, console: quiet, TextDecoder, setTimeout, clearTimeout, setInterval, clearInterval };
    vm.runInNewContext(SOURCE, sandbox);
    return { GeoIP: sandbox.window.GeoIP, requests, indexedDB };
}
const healthy = () => ({ '/data/geoip-meta.json': META, '/data/GeoLite2-Country.mmdb': COUNTRY, '/data/GeoLite2-ASN.mmdb': ASN });
const settled = (promise, ms = 2000) => Promise.race([promise.then(() => 'settled'), new Promise(r => setTimeout(() => r('still pending'), ms))]);
const plain = value => JSON.parse(JSON.stringify(value));

test('both databases load and answer lookups; a second init downloads nothing', async () => {
    const b = browser(healthy());
    assert.deepEqual(plain(await b.GeoIP.init()), { country: 'ready', asn: 'ready', errors: { country: null, asn: null } });
    assert.equal(b.GeoIP.isReady(), true);
    assert.deepEqual(plain(b.GeoIP.lookupIP('81.2.69.142')), { country: 'United Kingdom', country_code: 'GB', asn: 15169, asn_org: 'GOOGLE' });
    const before = b.requests.length;
    await b.GeoIP.init();
    assert.equal(b.requests.length, before);
});

test('one database missing: the analysis still gets the other one, and a later call tries again', async () => {
    const routes = { ...healthy(), '/data/GeoLite2-ASN.mmdb': 404 };
    const b = browser(routes);
    const status = plain(await b.GeoIP.init());
    assert.equal(status.country, 'ready');
    assert.equal(status.asn, 'failed');
    assert.match(status.errors.asn, /HTTP 404/);
    assert.equal(b.GeoIP.isReady(), false);
    assert.deepEqual(plain(b.GeoIP.lookupIP('81.2.69.142')), { country: 'United Kingdom', country_code: 'GB', asn: 0, asn_org: 'Unknown' });

    routes['/data/GeoLite2-ASN.mmdb'] = ASN;
    assert.equal(plain(await b.GeoIP.init()).asn, 'ready');
    assert.equal(b.GeoIP.isReady(), true);
    assert.equal(b.GeoIP.lookupIP('81.2.69.142').asn, 15169);
});

test('a caller that arrives during a failing load is released with it', async () => {
    const b = browser({ ...healthy(), '/data/GeoLite2-ASN.mmdb': () => new Promise(r => setTimeout(() => r(404), 60)) });
    const first = b.GeoIP.init();
    const second = b.GeoIP.init();
    assert.equal(await settled(first), 'settled');
    assert.equal(await settled(second), 'settled');
    assert.equal(b.GeoIP.status().asn, 'failed');
});

test('progress reaches every caller of a shared load', async () => {
    const b = browser(healthy());
    const seen = [[], []];
    await Promise.all([b.GeoIP.init(pct => seen[0].push(pct)), b.GeoIP.init(pct => seen[1].push(pct))]);
    assert.equal(seen[0].at(-1), 100);
    assert.equal(seen[1].at(-1), 100);
});

test('an error page or a cut-off file is not used and not cached', async () => {
    for (const bad of [Buffer.from('<!doctype html><html><body>502 Bad Gateway</body></html>'), COUNTRY.subarray(0, COUNTRY.length - 20)]) {
        const routes = { ...healthy(), '/data/GeoLite2-Country.mmdb': bad };
        const visit1 = browser(routes);
        const status = plain(await visit1.GeoIP.init());
        assert.equal(status.country, 'failed');
        assert.equal(status.asn, 'ready');
        assert.equal(visit1.indexedDB.store.has('GeoLite2-Country.mmdb'), false, 'bad bytes were cached');

        // Next visit: same browser storage, same database version, healthy server.
        const visit2 = browser(healthy(), visit1.indexedDB);
        assert.equal(plain(await visit2.GeoIP.init()).country, 'ready');
    }
});

test('bad bytes already in the cache are thrown away and downloaded again', async () => {
    const indexedDB = fakeIndexedDB();
    const poisoned = Buffer.from('<html>captive portal</html>');
    indexedDB.store.set('GeoLite2-Country.mmdb', { data: poisoned.buffer.slice(poisoned.byteOffset, poisoned.byteOffset + poisoned.length), version: '1' });
    const b = browser(healthy(), indexedDB);
    assert.equal(plain(await b.GeoIP.init()).country, 'ready');
    assert.equal(b.GeoIP.lookupCountry('81.2.69.142').country_code, 'GB');
    assert.ok(b.requests.includes('GET /data/GeoLite2-Country.mmdb'));
    assert.equal(indexedDB.store.get('GeoLite2-Country.mmdb').data.byteLength, COUNTRY.length);
});

test('a cached database is used without a download while its version is current', async () => {
    const first = browser(healthy());
    await first.GeoIP.init();
    const second = browser(healthy(), first.indexedDB);
    await second.GeoIP.init();
    assert.deepEqual(second.requests, ['GET /data/geoip-meta.json']);
    assert.equal(second.GeoIP.isReady(), true);
});

test('a failed update falls back to the cached database', async () => {
    const first = browser(healthy());
    await first.GeoIP.init();
    const newer = { version: '2', databases: { 'GeoLite2-Country.mmdb': { version: '2' }, 'GeoLite2-ASN.mmdb': { version: '2' } } };
    const second = browser({ '/data/geoip-meta.json': newer, '/data/GeoLite2-Country.mmdb': Buffer.from('oops'), '/data/GeoLite2-ASN.mmdb': 503 }, first.indexedDB);
    assert.deepEqual(plain(await second.GeoIP.init()), { country: 'ready', asn: 'ready', errors: { country: null, asn: null } });
    assert.equal(second.GeoIP.lookupIP('81.2.69.142').country_code, 'GB');
});

test('without browser storage the databases still load', async () => {
    const b = browser(healthy(), { open() { throw new Error('IndexedDB is disabled'); } });
    assert.equal(plain(await b.GeoIP.init()).country, 'ready');
    assert.equal(b.GeoIP.isReady(), true);
});

test('nothing reachable: init still resolves and lookups say Unknown', async () => {
    const b = browser({});
    const status = plain(await b.GeoIP.init());
    assert.deepEqual([status.country, status.asn], ['failed', 'failed']);
    assert.deepEqual(plain(b.GeoIP.lookupIP('81.2.69.142')), { country: 'Unknown', country_code: '--', asn: 0, asn_org: 'Unknown' });
});
