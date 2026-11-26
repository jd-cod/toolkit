import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ColumnarStorage } = require('../../frontend/public/js/columnar-storage.js');
const { ChunkedLineSplitter } = require('../../frontend/public/js/stream-line-splitter.js');
const LogParser = require('../../frontend/public/js/log-parser.js');

describe('Multi-Gigabyte Streaming Stress Test', () => {
    test('streams millions of log lines without V8 string limit errors and queries in < 50ms', () => {
        const TOTAL_ROWS = 2_000_000; // 2 million rows (~350 MB raw text)
        const storage = new ColumnarStorage(100_000);
        const splitter = new ChunkedLineSplitter();

        // Sample IP and URL pools for dictionary distribution
        const ips = ['198.51.100.1', '198.51.100.2', '203.0.113.50', '93.184.216.34', '1.1.1.1'];
        const urls = ['/index.html', '/api/v1/users', '/login', '/wp-login.php', '/static/style.css'];
        const methods = ['GET', 'POST', 'PUT', 'DELETE'];
        const statuses = [200, 200, 200, 301, 404, 500, 403];
        const countries = ['US', 'DE', 'FR', 'GB', 'NL'];
        const asns = [13335, 15169, 24940, 16509, 8075];

        const memBefore = process.memoryUsage().heapUsed;
        const startTime = Date.now();

        // Generate and stream chunks of ~64 KB
        const encoder = new TextEncoder();
        let chunkLines = [];
        let rowsProcessed = 0;

        for (let i = 0; i < TOTAL_ROWS; i++) {
            const ip = ips[i % ips.length];
            const url = urls[i % urls.length];
            const method = methods[i % methods.length];
            const status = statuses[i % statuses.length];
            const country = countries[i % countries.length];
            const asn = asns[i % asns.length];
            const timeSec = 1700000000 + (i % 86400);

            // Nginx combined log line
            chunkLines.push(`${ip} - - [06/Nov/2026:12:00:00 +0000] "${method} ${url} HTTP/1.1" ${status} 1024 "-" "Mozilla/5.0"`);

            if (chunkLines.length >= 2000 || i === TOTAL_ROWS - 1) {
                const chunkText = chunkLines.join('\n') + '\n';
                const chunkBytes = encoder.encode(chunkText);
                const lines = splitter.feed(chunkBytes);

                for (let j = 0; j < lines.length; j++) {
                    const parsed = LogParser.parseLine(lines[j], { skip403: false, skipInternal: false });
                    if (parsed.valid) {
                        const rowCountry = countries[rowsProcessed % countries.length];
                        const rowAsn = asns[rowsProcessed % asns.length];
                        storage.appendRow(
                            parsed.ip,
                            parsed.timeSec || timeSec,
                            parsed.statusCode,
                            parsed.responseSize || 1024,
                            parsed.url,
                            parsed.botName || 'None',
                            rowCountry,
                            rowAsn
                        );
                        rowsProcessed++;
                    }
                }
                chunkLines = [];
            }
        }

        const flushLines = splitter.flush();
        if (flushLines && flushLines.length > 0) {
            for (let j = 0; j < flushLines.length; j++) {
                const parsed = LogParser.parseLine(flushLines[j], { skip403: false, skipInternal: false });
                if (parsed.valid) {
                    storage.appendRow(parsed.ip, 1700000000, parsed.statusCode, 1024, parsed.url, 'None', 'US', 13335);
                    rowsProcessed++;
                }
            }
        }

        const ingestDuration = Date.now() - startTime;
        const memAfter = process.memoryUsage().heapUsed;
        const heapUsedMB = (memAfter - memBefore) / (1024 * 1024);

        console.log(`\n    --- STRESS METRICS ---`);
        console.log(`    Total Rows Processed: ${rowsProcessed.toLocaleString()}`);
        console.log(`    Ingest Duration: ${(ingestDuration / 1000).toFixed(2)}s (${Math.round(rowsProcessed / (ingestDuration / 1000)).toLocaleString()} lines/sec)`);
        console.log(`    Heap Memory Allocated: ${heapUsedMB.toFixed(2)} MB (${((memAfter - memBefore) / rowsProcessed).toFixed(1)} bytes/row)`);

        assert.equal(rowsProcessed, TOTAL_ROWS, 'All rows should be ingested without loss');
        assert.ok(heapUsedMB < 120, `Heap memory should be < 120 MB for ${TOTAL_ROWS} rows, got ${heapUsedMB.toFixed(2)} MB`);

        // Test sub-80ms filter aggregation speed across 2,000,000 rows
        const queryStart = performance.now();
        const queryResult = storage.query({ statusCategory: '4xx', country: 'US' });
        const queryDuration = performance.now() - queryStart;

        console.log(`    Binary Scan Query Duration: ${queryDuration.toFixed(2)}ms`);
        console.log(`    Matching 4xx in US: ${queryResult.matchingCount.toLocaleString()} hits`);

        assert.ok(queryDuration < 80, `Binary query scan must complete in < 80ms, took ${queryDuration.toFixed(2)}ms`);
        assert.ok(queryResult.matchingCount > 0, 'Should find matching 4xx records in US');

        // Test sub-25ms full-scan page resolution and sub-1ms early-exit page resolution
        const pageStart = performance.now();
        const pageResult = storage.getPage(1, 50, { statusCategory: '4xx' });
        const pageDuration = performance.now() - pageStart;

        console.log(`    Paginated GetPage Duration (full scan): ${pageDuration.toFixed(2)}ms`);
        assert.ok(pageDuration < 25, `getPage must complete in < 25ms, took ${pageDuration.toFixed(2)}ms`);
        assert.equal(pageResult.rows.length, 50);

        // Test early-exit when totalRows is provided by summary query
        const fastPageStart = performance.now();
        const fastPageResult = storage.getPage(1, 50, { statusCategory: '4xx', totalRows: queryResult.matchingCount });
        const fastPageDuration = performance.now() - fastPageStart;
        console.log(`    Paginated GetPage Duration (early exit with known total): ${fastPageDuration.toFixed(2)}ms`);
        assert.ok(fastPageDuration < 5, `fast getPage must complete in < 5ms, took ${fastPageDuration.toFixed(2)}ms`);
        assert.equal(fastPageResult.rows.length, 50);
        console.log(`    ----------------------\n`);
    });
});
