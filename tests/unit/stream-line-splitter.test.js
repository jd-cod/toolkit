import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ChunkedLineSplitter, detectTextEncoding } = require('../../frontend/public/js/stream-line-splitter.js');

describe('ChunkedLineSplitter', () => {
    test('splits complete lines in a single chunk', () => {
        const splitter = new ChunkedLineSplitter();
        const chunk = 'line 1\nline 2\nline 3\n';
        const lines = splitter.feed(chunk);
        assert.deepEqual(lines, ['line 1', 'line 2', 'line 3']);
        assert.deepEqual(splitter.flush(), []);
    });

    test('handles lines split across multiple chunks', () => {
        const splitter = new ChunkedLineSplitter();
        const chunk1 = 'first part of ';
        const chunk2 = 'line 1\nsecond ';
        const chunk3 = 'line\n';

        const lines1 = splitter.feed(chunk1);
        assert.deepEqual(lines1, []);

        const lines2 = splitter.feed(chunk2);
        assert.deepEqual(lines2, ['first part of line 1']);

        const lines3 = splitter.feed(chunk3);
        assert.deepEqual(lines3, ['second line']);

        assert.deepEqual(splitter.flush(), []);
    });

    test('reads lines that end in a lone CR, and a CRLF cut between two chunks', () => {
        let splitter = new ChunkedLineSplitter();
        assert.deepEqual(splitter.feed('line 1\rline 2\rline'), ['line 1', 'line 2']);
        assert.deepEqual(splitter.feed(' 3\rline 4\r'), ['line 3']);
        assert.deepEqual(splitter.flush(), ['line 4']);

        splitter = new ChunkedLineSplitter();
        assert.deepEqual(splitter.feed('line 1\r'), []);
        assert.deepEqual(splitter.feed('\nline 2\r'), ['line 1']);
        assert.deepEqual(splitter.feed('\r'), ['line 2']);
        assert.deepEqual(splitter.feed('\nline 3\r\n'), ['', 'line 3']);
        assert.deepEqual(splitter.flush(), []);

        splitter = new ChunkedLineSplitter();
        assert.deepEqual(splitter.feed('a\rb\nc\r\n'), ['a', 'b', 'c']);
    });

    test('reads UTF-16 files, with or without a byte order mark, cut anywhere', () => {
        const text = 'line 1 caf\u00e9\r\nline 2 \u65e5\u672c\nline 3\n';
        const le = Buffer.from(text, 'utf16le');
        const be = Buffer.from(le).swap16();
        const inputs = {
            'UTF-16LE with BOM': Buffer.concat([Buffer.from([0xff, 0xfe]), le]),
            'UTF-16BE with BOM': Buffer.concat([Buffer.from([0xfe, 0xff]), be]),
            'UTF-16LE without BOM': Buffer.from('plain ascii line one\nplain ascii line two\n', 'utf16le'),
            'UTF-16BE without BOM': Buffer.from(Buffer.from('plain ascii line one\nplain ascii line two\n', 'utf16le')).swap16(),
        };
        for (const [name, bytes] of Object.entries(inputs)) {
            const expected = name.includes('without') ? ['plain ascii line one', 'plain ascii line two'] : ['line 1 caf\u00e9', 'line 2 \u65e5\u672c', 'line 3'];
            for (const size of [bytes.length, 64, 7, 3]) {
                if (size < 16 && name.includes('without')) continue; // too little to tell without a mark
                const splitter = new ChunkedLineSplitter();
                const lines = [];
                for (let i = 0; i < bytes.length; i += size) lines.push(...splitter.feed(new Uint8Array(bytes.subarray(i, i + size))));
                lines.push(...splitter.flush());
                assert.deepEqual(lines, expected, `${name}, chunks of ${size}`);
            }
        }
    });

    test('UTF-8 stays UTF-8, and one splitter reads files in different encodings one after the other', () => {
        assert.equal(detectTextEncoding(new TextEncoder().encode('8.8.8.8 - - [27/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5')), 'utf-8');
        assert.equal(detectTextEncoding(new Uint8Array([0xef, 0xbb, 0xbf, 0x38, 0x2e, 0x38, 0x2e, 0x38, 0x2e, 0x38])), 'utf-8');
        assert.equal(detectTextEncoding(new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03])), 'utf-8');

        const splitter = new ChunkedLineSplitter();
        assert.deepEqual(splitter.feed(new Uint8Array(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('first file\n', 'utf16le')]))), ['first file']);
        assert.deepEqual(splitter.flush(), []);
        assert.deepEqual(splitter.feed(new TextEncoder().encode('second file caf\u00e9\n')), ['second file caf\u00e9']);
    });

    test('handles CRLF (Windows) and LF (Linux) newlines cleanly', () => {
        const splitter = new ChunkedLineSplitter();
        const chunk = 'line 1\r\nline 2\nline 3\r\n';
        const lines = splitter.feed(chunk);
        assert.deepEqual(lines, ['line 1', 'line 2', 'line 3']);
    });

    test('flushes trailing line when EOF has no newline', () => {
        const splitter = new ChunkedLineSplitter();
        splitter.feed('line 1\nline 2 without newline');
        const flushed = splitter.flush();
        assert.deepEqual(flushed, ['line 2 without newline']);
    });

    test('handles Uint8Array input with multi-byte UTF-8 split across chunk boundary', () => {
        const splitter = new ChunkedLineSplitter();
        // Euro symbol: € is 3 bytes in UTF-8: [0xE2, 0x82, 0xAC]
        const encoder = new TextEncoder();
        const fullBytes = encoder.encode('Price: €100\n');

        // Split right inside the € character: 7 bytes before, 2 bytes of €, 1 byte of € + rest
        const part1 = fullBytes.slice(0, 9); // 'Price: ' (7) + [0xE2, 0x82]
        const part2 = fullBytes.slice(9);    // [0xAC] + '100\n'

        const lines1 = splitter.feed(part1);
        assert.deepEqual(lines1, []);

        const lines2 = splitter.feed(part2);
        assert.deepEqual(lines2, ['Price: €100']);
    });

    test('reset clears internal buffer', () => {
        const splitter = new ChunkedLineSplitter();
        splitter.feed('incomplete line');
        splitter.reset();
        assert.deepEqual(splitter.flush(), []);
    });
});
