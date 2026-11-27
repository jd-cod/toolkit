import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

describe('Analyzer.analyzeFromWorkerSummary', () => {
    test('transforms columnar query summary into dashboard data object', async () => {
        // Load Analyzer and the scripts it expects as globals
        await import('../../frontend/public/js/request-paths.js');
        await import('../../frontend/public/js/bot-detector.js');
        await import('../../frontend/public/js/traffic-classifier.js');
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

    test('a summary without traffic classes does not count humans as a bot', async () => {
        await import('../../frontend/public/js/request-paths.js');
        await import('../../frontend/public/js/bot-detector.js');
        await import('../../frontend/public/js/traffic-classifier.js');
        const Analyzer = (await import('../../frontend/public/js/analyzer.js')).default;

        // "None" is what the parser stores for a request with no bot User-Agent.
        const data = Analyzer.analyzeFromWorkerSummary({
            matchingCount: 1000,
            botCounts: { 'None': 700, 'Googlebot': 250, 'Bingbot': 50 },
        });
        assert.equal(data.human_requests, 700);
        assert.equal(data.verified_bots_count, 0);
        assert.equal(data.unverified_bots_count, 300);
        assert.deepEqual(data.bot_groups.map(g => g.group_name), ['Googlebot', 'Bingbot']);
        assert.equal(data.traffic_classes.reduce((sum, c) => sum + c.requests, 0), 1000);
    });
});
