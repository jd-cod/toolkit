import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ColumnarStorage } = require('../../frontend/public/js/columnar-storage.js');

describe('ColumnarStorage', () => {
    test('appends rows and deduplicates dictionaries', () => {
        const storage = new ColumnarStorage(10);
        storage.appendRow('1.1.1.1', 1700000000, 200, 1024, '/index.html', 'Googlebot', 'US', 13335);
        storage.appendRow('1.1.1.1', 1700000005, 404, 512, '/missing.html', 'Googlebot', 'US', 13335);
        storage.appendRow('2.2.2.2', 1700000010, 200, 2048, '/index.html', 'Human', 'DE', 24940);

        assert.equal(storage.rowCount, 3);
        assert.equal(storage.ipDict.length, 2); // 1.1.1.1, 2.2.2.2
        assert.equal(storage.urlDict.length, 2); // /index.html, /missing.html
        assert.equal(storage.botDict.length, 2); // Googlebot, Human
        assert.equal(storage.countryDict.length, 2); // US, DE
    });

    test('dynamically expands capacity when exceeded', () => {
        // Start with small capacity = 2
        const storage = new ColumnarStorage(2);
        for (let i = 0; i < 15; i++) {
            storage.appendRow(`192.168.1.${i}`, 1700000000 + i, 200, 100 * i, `/page${i}`, 'None', 'US', 12345);
        }

        assert.equal(storage.rowCount, 15);
        assert.ok(storage.capacity >= 15);

        // Verify data integrity after reallocation
        const page = storage.getPage(1, 15);
        assert.equal(page.rows.length, 15);
        assert.equal(page.rows[0].ip, '192.168.1.0');
        assert.equal(page.rows[14].ip, '192.168.1.14');
        assert.equal(page.rows[14].bytes, 1400);
    });

    test('queries aggregated metrics without filters', () => {
        const storage = new ColumnarStorage(10);
        storage.appendRow('1.1.1.1', 1700000000, 200, 1000, '/a', 'Googlebot', 'US', 100);
        storage.appendRow('1.1.1.1', 1700000010, 500, 500, '/b', 'Googlebot', 'US', 100);
        storage.appendRow('2.2.2.2', 1700000020, 404, 200, '/c', 'Bingbot', 'FR', 200);

        const res = storage.query({});
        assert.equal(res.matchingCount, 3);
        assert.equal(res.uniqueIps, 2);
        assert.equal(res.totalBytes, 1700);
        assert.equal(res.statusCounts['200'], 1);
        assert.equal(res.statusCounts['500'], 1);
        assert.equal(res.statusCounts['404'], 1);
        assert.equal(res.botCounts['Googlebot'], 2);
        assert.equal(res.botCounts['Bingbot'], 1);
        assert.equal(res.countryCounts['US'], 2);
        assert.equal(res.countryCounts['FR'], 1);
        assert.equal(res.asnHits[100], 2);
        assert.equal(res.asnHits[200], 1);
    });

    test('queries with country and status filters', () => {
        const storage = new ColumnarStorage(10);
        storage.appendRow('1.1.1.1', 1700000000, 200, 1000, '/a', 'Googlebot', 'US', 100);
        storage.appendRow('1.1.1.1', 1700000010, 404, 500, '/b', 'Googlebot', 'US', 100);
        storage.appendRow('2.2.2.2', 1700000020, 404, 200, '/c', 'Bingbot', 'FR', 200);

        // Filter by country = 'US'
        const usRes = storage.query({ country: 'US' });
        assert.equal(usRes.matchingCount, 2);
        assert.equal(usRes.uniqueIps, 1);
        assert.equal(usRes.statusCounts['200'], 1);
        assert.equal(usRes.statusCounts['404'], 1);

        // Filter by status category = '4xx'
        const fourXxRes = storage.query({ statusCategory: '4xx' });
        assert.equal(fourXxRes.matchingCount, 2);
        assert.equal(fourXxRes.uniqueIps, 2);
        assert.equal(fourXxRes.countryCounts['US'], 1);
        assert.equal(fourXxRes.countryCounts['FR'], 1);

        // Filter by both country = 'US' and statusCategory = '4xx'
        const combined = storage.query({ country: 'US', statusCategory: '4xx' });
        assert.equal(combined.matchingCount, 1);
        assert.equal(combined.statusCounts['404'], 1);
        assert.equal(combined.totalBytes, 500);
    });

    test('retrieves paginated rows with correct page metadata', () => {
        const storage = new ColumnarStorage(20);
        for (let i = 1; i <= 12; i++) {
            storage.appendRow(`10.0.0.${i}`, 1700000000 + i, 200, 100, `/item/${i}`, 'Bot', 'GB', 500);
        }

        // Page 1 with pageSize 5 -> 5 rows
        const page1 = storage.getPage(1, 5);
        assert.equal(page1.page, 1);
        assert.equal(page1.totalPages, 3); // 12 / 5 = 2.4 -> 3 pages
        assert.equal(page1.totalRows, 12);
        assert.equal(page1.rows.length, 5);
        assert.equal(page1.rows[0].ip, '10.0.0.1');
        assert.equal(page1.rows[4].ip, '10.0.0.5');

        // Page 3 with pageSize 5 -> remaining 2 rows
        const page3 = storage.getPage(3, 5);
        assert.equal(page3.page, 3);
        assert.equal(page3.rows.length, 2);
        assert.equal(page3.rows[0].ip, '10.0.0.11');
        assert.equal(page3.rows[1].ip, '10.0.0.12');
    });

    test('enriches GeoIP metadata across columns and returns top IPs', () => {
        const storage = new ColumnarStorage(10);
        storage.appendRow('1.1.1.1', 1700000000, 200, 100, '/a', 'None', '-', 0);
        storage.appendRow('1.1.1.1', 1700000001, 200, 100, '/b', 'None', '-', 0);
        storage.appendRow('8.8.8.8', 1700000002, 200, 100, '/c', 'None', '-', 0);

        storage.enrichGeo({
            '1.1.1.1': { country_code: 'AU', country: 'Australia', asn: 13335, asn_org: 'Cloudflare' },
            '8.8.8.8': { country_code: 'US', country: 'United States', asn: 15169, asn_org: 'Google' }
        });

        const res = storage.query({});
        assert.equal(res.countryCounts['AU'], 2);
        assert.equal(res.countryCounts['US'], 1);
        assert.equal(res.asnHits[13335], 2);
        assert.equal(res.asnHits[15169], 1);
        assert.equal(res.asnOrgMap[13335], 'Cloudflare');

        const topIps = storage.getTopIps(5);
        assert.equal(topIps.length, 2);
        assert.equal(topIps[0].ip, '1.1.1.1');
        assert.equal(topIps[0].hits, 2);
        assert.equal(topIps[1].ip, '8.8.8.8');
        assert.equal(topIps[1].hits, 1);
    });
});

describe('ColumnarStorage summary numbers', () => {
    test('selectNth gives the value a sort would put at that index', () => {
        let seed = 3;
        const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
        for (const size of [1, 2, 3, 10, 101, 1000, 5000]) {
            for (const spread of [3, 50, 1e9]) {
                const values = Float64Array.from({ length: size }, () => Math.floor(rnd() * spread));
                const sorted = Float64Array.from(values).sort();
                for (const n of [0, Math.floor(size / 2), size - 1]) {
                    const copy = Float64Array.from(values);
                    assert.equal(ColumnarStorage.selectNth(copy, n), sorted[n], `size ${size}, spread ${spread}, index ${n}`);
                    for (let i = 0; i < n; i++) assert.ok(copy[i] <= copy[n]);
                    for (let i = n + 1; i < size; i++) assert.ok(copy[i] >= copy[n]);
                }
            }
        }
    });

    test('median, smallest and largest response size, hours and weekdays', () => {
        const storage = new ColumnarStorage(10);
        // Friday 27 November 2026, 10:00, 10:30 and 23:59 UTC; then Saturday 00:00.
        const t = Date.UTC(2026, 10, 27, 10, 0, 0) / 1000;
        storage.appendRow('1.1.1.1', t, 200, 500, '/a', 'None', '-', 0);
        storage.appendRow('1.1.1.2', t + 1800, 200, 100, '/b', 'None', '-', 0);
        storage.appendRow('1.1.1.3', t + 50340, 404, 0, '/c', 'None', '-', 0);
        storage.appendRow('1.1.1.4', t + 50400, 200, 5 * 2 ** 32, '/d', 'None', '-', 0);
        let r = storage.query({});
        assert.deepEqual(r.responseSize, { median: 300, min: 0, max: 5 * 2 ** 32 });
        assert.equal(r.hourly[10], 2);
        assert.equal(r.hourly[23], 1);
        assert.equal(r.hourly[0], 1);
        assert.equal(r.daily[5], 3, 'Friday');
        assert.equal(r.daily[6], 1, 'Saturday');
        r = storage.query({ statusCategory: '2xx' });
        assert.deepEqual(r.responseSize, { median: 500, min: 100, max: 5 * 2 ** 32 });
        r = storage.query({ statusCategory: '5xx' });
        assert.deepEqual(r.responseSize, { median: 0, min: 0, max: 0 });
    });
});
