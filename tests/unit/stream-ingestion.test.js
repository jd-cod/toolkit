import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createWorkerHandler } from '../../frontend/public/js/log-parser.worker.js';

describe('Streaming Ingestion Pipeline', () => {
    test('peekAndDecompressStream transparently decompresses gzipped stream', async () => {
        const { peekAndDecompressStream } = await import('../../frontend/public/js/stream-line-splitter.js');
        assert.equal(typeof peekAndDecompressStream, 'function');

        // Create a gzipped stream of text
        const sampleText = '93.184.216.34 - - [06/Nov/2026:12:00:00 +0000] "GET /test HTTP/1.1" 200 123 "-" "Mozilla/5.0"\n';
        const encoder = new TextEncoder();
        const rawStream = new Response(encoder.encode(sampleText)).body.pipeThrough(new CompressionStream('gzip'));

        const decompressedStream = await peekAndDecompressStream(rawStream);
        const resultText = await new Response(decompressedStream).text();
        assert.equal(resultText, sampleText);
    });

    test('peekAndDecompressStream passes raw uncompressed stream unchanged', async () => {
        const { peekAndDecompressStream } = await import('../../frontend/public/js/stream-line-splitter.js');
        const sampleText = '93.184.216.34 - - [06/Nov/2026:12:00:00 +0000] "GET /test HTTP/1.1" 200 123 "-" "Mozilla/5.0"\n';
        const encoder = new TextEncoder();
        const rawStream = new Response(encoder.encode(sampleText)).body;

        const processedStream = await peekAndDecompressStream(rawStream);
        const resultText = await new Response(processedStream).text();
        assert.equal(resultText, sampleText);
    });

    test('streamChunksToWorker streams chunks and receives progress and complete', async () => {
        const { streamChunksToWorker } = await import('../../frontend/public/js/stream-line-splitter.js');
        assert.equal(typeof streamChunksToWorker, 'function');

        const lines = [];
        for (let i = 0; i < 50; i++) {
            lines.push(`93.184.216.${i % 250} - - [06/Nov/2026:12:00:${String(i % 60).padStart(2, '0')} +0000] "GET /item/${i} HTTP/1.1" 200 ${100 + i} "-" "Mozilla/5.0"`);
        }
        const logContent = lines.join('\n') + '\n';
        const stream = new Response(new TextEncoder().encode(logContent)).body;

        const sentMessages = [];
        let workerListener = null;

        const mockWorker = {
            postMessage(msg) {
                // Dispatch directly to worker handler
                workerHandler({ data: msg });
            },
            onmessage: null,
            terminate() {}
        };

        const workerHandler = createWorkerHandler((msg) => {
            if (mockWorker.onmessage) {
                mockWorker.onmessage({ data: msg });
            }
        });

        const progressUpdates = [];
        const result = await streamChunksToWorker(stream, mockWorker, { skip403: false, skipInternal: false }, (p) => {
            progressUpdates.push(p);
        });

        assert.ok(result.summary);
        assert.equal(result.summary.matchingCount, 50);
        assert.equal(result.pageResult.rows.length, 50);
    });
});
