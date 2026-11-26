import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

describe('Analyzer.analyzeFromWorkerSummary', () => {
    test('transforms columnar query summary into dashboard data object', async () => {
        // Load Analyzer
        const Analyzer = (await import('../../frontend/public/js/analyzer.js')).default || (await import('../../frontend/public/js/analyzer.js'));
        assert.equal(typeof Analyzer.analyzeFromWorkerSummary, 'function');

        const mockSummary = {
            matchingCount: 1000,
            uniqueIps: 150,
            totalBytes: 52428800,
            minTimeSec: 1730894400,
            maxTimeSec: 1730898000,
            statusCounts: {
                '200': 850,
                '304': 50,
                '404': 80,
                '500': 20
            },
            botCounts: {
                'Googlebot': 200,
                'Bingbot': 50
            },
            countryCounts: {
                'US': 600,
                'DE': 250,
                'FR': 150
            },
            asnHits: {
                'AS15169': 200,
                'AS16509': 150
            },
            timeBuckets: [
                { time: 1730894400, total: 100, error: 2 },
                { time: 1730894460, total: 120, error: 5 }
            ]
        };

        const data = Analyzer.analyzeFromWorkerSummary(mockSummary);
        assert.equal(data.total_requests, 1000);
        assert.equal(data.unique_ips, 150);
        assert.equal(data.unique_countries, 3);
        assert.equal(data.country_hits.length, 3);
        assert.equal(data.country_hits[0].country, 'US');
        assert.equal(data.country_hits[0].count, 600);
        assert.equal(data.http_metrics.status_categories['2xx'], 850);
        assert.equal(data.http_metrics.status_categories['4xx'], 80);
        assert.equal(data.http_metrics.status_categories['5xx'], 20);
        assert.equal(data.request_rate.buckets.length, 2);
    });
});
