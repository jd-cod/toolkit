import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createWorkerHandler } = require('../../frontend/public/js/log-parser.worker.js');
const { appendStreamToWorker } = require('../../frontend/public/js/stream-line-splitter.js');

describe('Worker Stream Appending & Incremental GeoIP', () => {
    test('appends Node 2 logs onto existing Node 1 session without resetting state', () => {
        const messages = [];
        const handler = createWorkerHandler((msg) => messages.push(msg));
        const encoder = new TextEncoder();

        // Node 1 initial logs
        const node1Logs = [
            '93.184.216.34 - - [06/Nov/2026:12:00:00 +0000] "GET /node1-page.html HTTP/1.1" 200 1024 "-" "curl/7.88.1"',
            '93.184.216.34 - - [06/Nov/2026:12:01:00 +0000] "GET /node1-api.html HTTP/1.1" 200 512 "-" "curl/7.88.1"',
            '198.51.100.1 - - [06/Nov/2026:12:02:00 +0000] "POST /node1-login HTTP/1.1" 500 256 "-" "curl/7.88.1"',
        ].join('\n') + '\n';

        handler({
            data: {
                action: 'parse_stream_chunk',
                chunk: encoder.encode(node1Logs),
                isLast: true,
                options: {}
            }
        });

        const complete1 = messages.find(m => m.type === 'complete');
        assert.ok(complete1, 'Should emit complete for node 1');
        assert.equal(complete1.summary.matchingCount, 3);
        assert.equal(complete1.summary.uniqueIps, 2);

        // Enrich Node 1 GeoIP
        handler({
            data: {
                action: 'enrich_geo',
                countryIds: new Uint16Array([1, 2]),
                asns: new Uint32Array([15169, 13335]),
                countryDict: ['-', 'US', 'DE'],
                asnOrgMap: { 15169: 'GOOGLE', 13335: 'CLOUDFLARE' }
            }
        });

        const enriched1 = messages.find(m => m.type === 'enriched');
        assert.ok(enriched1, 'Should emit enriched for node 1');

        // Node 2 logs (contains 1 new IP and 1 existing IP)
        const node2Logs = [
            '93.184.216.34 - - [06/Nov/2026:12:03:00 +0000] "GET /node2-page.html HTTP/1.1" 200 2048 "-" "curl/7.88.1"',
            '203.0.113.50 - - [06/Nov/2026:12:04:00 +0000] "GET /node2-cart.html HTTP/1.1" 404 128 "-" "curl/7.88.1"',
            '203.0.113.50 - - [06/Nov/2026:12:05:00 +0000] "POST /node2-checkout HTTP/1.1" 200 4096 "-" "curl/7.88.1"',
        ].join('\n') + '\n';

        messages.length = 0;
        handler({
            data: {
                action: 'append_stream_chunk',
                chunk: encoder.encode(node2Logs),
                isLast: true,
                options: {}
            }
        });

        const appendMsg = messages.find(m => m.type === 'append_complete');
        assert.ok(appendMsg, 'Worker should emit append_complete message');
        // Total should now be 3 (node1) + 3 (node2) = 6 rows
        assert.equal(appendMsg.summary.matchingCount, 6);
        assert.equal(appendMsg.summary.uniqueIps, 3); // 93.184.216.34, 198.51.100.1, 203.0.113.50
        assert.equal(appendMsg.totalLinesParsed, 6);
        assert.equal(appendMsg.startRowIndex, 3);
        assert.equal(appendMsg.startIpIndex, 2);

        // Verify incremental GeoIP enrichment
        messages.length = 0;
        // 3 IPs total: IP 0 ('US'=1), IP 1 ('DE'=2), IP 2 ('JP'=3)
        handler({
            data: {
                action: 'enrich_geo_incremental',
                countryIds: new Uint16Array([1, 2, 3]),
                asns: new Uint32Array([15169, 13335, 2514]),
                countryDict: ['-', 'US', 'DE', 'JP'],
                asnOrgMap: { 2514: 'NTT' },
                startIpIndex: 2,
                startRowIndex: 3
            }
        });

        const enriched2 = messages.find(m => m.type === 'enriched');
        assert.ok(enriched2, 'Worker should emit enriched after incremental geo');
        assert.equal(enriched2.summary.matchingCount, 6);

        // Check Explorer rows: should include all 6 rows
        assert.equal(enriched2.pageResult.rows.length, 6);
        assert.equal(enriched2.pageResult.rows[0].url, '/node1-page.html');
        assert.equal(enriched2.pageResult.rows[3].url, '/node2-page.html');
        assert.equal(enriched2.pageResult.rows[4].country, 'JP');
        assert.equal(enriched2.pageResult.rows[4].asn, 2514);
        assert.equal(enriched2.pageResult.rows[0].country, 'US');
    });

    test('appendStreamToWorker feeds a ReadableStream and resolves with merged results', async () => {
        const encoder = new TextEncoder();
        const logs = '1.1.1.1 - - [06/Nov/2026:12:00:00 +0000] "GET /stream-append HTTP/1.1" 200 100 "-" "test"\n';

        const stream = new ReadableStream({
            start(controller) {
                controller.enqueue(encoder.encode(logs));
                controller.close();
            }
        });

        const mockWorker = {
            listeners: [],
            addEventListener(event, fn) {
                this.listeners.push(fn);
            },
            removeEventListener(event, fn) {
                this.listeners = this.listeners.filter(l => l !== fn);
            },
            postMessage(msg) {
                if (msg.action === 'append_stream_chunk' && msg.isLast) {
                    setTimeout(() => {
                        this.listeners.forEach(fn => fn({
                            data: {
                                type: 'append_complete',
                                summary: { matchingCount: 10 },
                                pageResult: { rows: [] },
                                ipDict: ['1.1.1.1'],
                                startIpIndex: 0,
                                startRowIndex: 0
                            }
                        }));
                    }, 10);
                }
            }
        };

        const result = await appendStreamToWorker(stream, mockWorker);
        assert.equal(result.summary.matchingCount, 10);
    });
});
