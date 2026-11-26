import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createWorkerHandler } = require('../../frontend/public/js/log-parser.worker.js');

describe('Worker Streaming Protocol', () => {
    test('handles streamed chunks and completes with initial summary', async () => {
        const messages = [];
        const handler = createWorkerHandler((msg) => messages.push(msg));

        const encoder = new TextEncoder();
        const logData = [
            '93.184.216.34 - - [06/Nov/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0 Googlebot/2.1"',
            '93.184.216.34 - - [06/Nov/2026:12:01:00 +0000] "GET /about.html HTTP/1.1" 404 512 "-" "Mozilla/5.0 Googlebot/2.1"',
            '198.51.100.1 - - [06/Nov/2026:12:02:00 +0000] "POST /api/login HTTP/1.1" 500 256 "-" "curl/7.68.0"',
        ].join('\n') + '\n';

        // Send first chunk
        handler({
            data: {
                action: 'parse_stream_chunk',
                chunk: encoder.encode(logData),
                isLast: true,
                options: { skip403: false, skipInternal: true }
            }
        });

        // Check emitted messages
        const completeMsg = messages.find(m => m.type === 'complete');
        assert.ok(completeMsg, 'Worker should emit complete message');
        assert.equal(completeMsg.summary.matchingCount, 3);
        assert.equal(completeMsg.summary.uniqueIps, 2);
        assert.equal(completeMsg.summary.statusCounts['200'], 1);
        assert.equal(completeMsg.summary.statusCounts['404'], 1);
        assert.equal(completeMsg.summary.statusCounts['500'], 1);

        // Check first page of log explorer
        assert.ok(completeMsg.pageResult, 'Should include initial pageResult');
        assert.equal(completeMsg.pageResult.rows.length, 3);
        assert.equal(completeMsg.pageResult.rows[0].url, '/index.html');
    });

    test('executes filter query and returns filter_result', () => {
        const messages = [];
        const handler = createWorkerHandler((msg) => messages.push(msg));
        const encoder = new TextEncoder();

        const logData = [
            '93.184.216.34 - - [06/Nov/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Googlebot"',
            '93.184.216.34 - - [06/Nov/2026:12:01:00 +0000] "GET /missing.html HTTP/1.1" 404 512 "-" "Googlebot"',
            '198.51.100.1 - - [06/Nov/2026:12:02:00 +0000] "POST /api/login HTTP/1.1" 500 256 "-" "curl"',
        ].join('\n') + '\n';

        handler({
            data: { action: 'parse_stream_chunk', chunk: encoder.encode(logData), isLast: true }
        });

        // Request filter for 4xx status
        messages.length = 0;
        handler({
            data: { action: 'filter', filters: { statusCategory: '4xx' } }
        });

        const filterMsg = messages.find(m => m.type === 'filter_result');
        assert.ok(filterMsg, 'Worker should emit filter_result');
        assert.equal(filterMsg.summary.matchingCount, 1);
        assert.equal(filterMsg.summary.statusCounts['404'], 1);
        assert.equal(filterMsg.pageResult.rows.length, 1);
        assert.equal(filterMsg.pageResult.rows[0].url, '/missing.html');
    });

    test('retrieves paginated rows via get_page', () => {
        const messages = [];
        const handler = createWorkerHandler((msg) => messages.push(msg));
        const encoder = new TextEncoder();

        const lines = [];
        for (let i = 1; i <= 6; i++) {
            lines.push(`192.0.2.${i} - - [06/Nov/2026:12:00:00 +0000] "GET /page${i} HTTP/1.1" 200 100 "-" "Mozilla"`);
        }
        handler({
            data: { action: 'parse_stream_chunk', chunk: encoder.encode(lines.join('\n') + '\n'), isLast: true }
        });

        messages.length = 0;
        handler({
            data: { action: 'get_page', page: 2, pageSize: 2 }
        });

        const pageMsg = messages.find(m => m.type === 'page_result');
        assert.ok(pageMsg, 'Worker should emit page_result');
        assert.equal(pageMsg.pageResult.page, 2);
        assert.equal(pageMsg.pageResult.totalPages, 3);
        assert.equal(pageMsg.pageResult.rows.length, 2);
        assert.equal(pageMsg.pageResult.rows[0].url, '/page3');
        assert.equal(pageMsg.pageResult.rows[1].url, '/page4');
    });

    test('supports get_page with pageNumber and reqId passthrough', () => {
        const messages = [];
        const handler = createWorkerHandler((msg) => messages.push(msg));
        const encoder = new TextEncoder();

        const lines = [
            '198.51.100.1 - - [06/Nov/2026:12:00:00 +0000] "GET /one HTTP/1.1" 200 100 "-" "Mozilla"',
            '198.51.100.2 - - [06/Nov/2026:12:00:01 +0000] "GET /two HTTP/1.1" 404 100 "-" "Mozilla"',
            '198.51.100.1 - - [06/Nov/2026:12:00:02 +0000] "GET /three HTTP/1.1" 200 100 "-" "Mozilla"',
        ];
        handler({
            data: { action: 'parse_stream_chunk', chunk: encoder.encode(lines.join('\n') + '\n'), isLast: true }
        });

        messages.length = 0;
        handler({
            data: {
                action: 'get_page',
                pageNumber: 1,
                pageSize: 50,
                filters: { ipSearch: '198.51.100.1' },
                reqId: 'ip_logs',
                ip: '198.51.100.1'
            }
        });

        const pageMsg = messages.find(m => m.type === 'page_result');
        assert.ok(pageMsg, 'Worker should emit page_result');
        assert.equal(pageMsg.reqId, 'ip_logs');
        assert.equal(pageMsg.ip, '198.51.100.1');
        assert.equal(pageMsg.pageResult.totalRows, 2);
        assert.equal(pageMsg.pageResult.rows.length, 2);
        assert.equal(pageMsg.pageResult.rows[0].ip, '198.51.100.1');
        assert.equal(pageMsg.pageResult.rows[1].ip, '198.51.100.1');
    });
});
