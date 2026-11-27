import { test } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { peekAndDecompressStream } = require('../../frontend/public/js/stream-line-splitter.js');

const lines = (label, n) => Array.from({ length: n }, (_, i) => `8.8.8.8 - - [27/Nov/2026:10:00:00 +0000] "GET /${label}/${i} HTTP/1.1" 200 ${i} "-" "curl/8"`).join('\n') + '\n';
const A = lines('a', 4000);
const B = lines('b', 3000);

async function read(input) {
    const warnings = [];
    const stream = await peekAndDecompressStream(input, { onWarning: w => warnings.push(w) });
    return { text: await new Response(stream).text(), warnings };
}

test('one gzip member', async () => {
    const r = await read(new Blob([zlib.gzipSync(A)]));
    assert.equal(r.text, A);
    assert.deepEqual(r.warnings, []);
});

test('several gzip members in one file are all read', async () => {
    const r = await read(new Blob([zlib.gzipSync(A), zlib.gzipSync(B), zlib.gzipSync('last line\n')]));
    assert.equal(r.text, A + B + 'last line\n');
    assert.deepEqual(r.warnings, []);
});

test('bytes that look like a member start inside compressed data do not split a member', async () => {
    // Stored (uncompressed) blocks keep these bytes as they are in the archive.
    const tricky = Buffer.concat([Buffer.from(A), Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x1f, 0x8b, 0x08, 0x00]), Buffer.from(B)]);
    const r = await read(new Blob([zlib.gzipSync(tricky, { level: 0 }), zlib.gzipSync(B)]));
    assert.equal(Buffer.compare(Buffer.from(r.text, 'latin1').subarray(0, 10), tricky.subarray(0, 10)), 0);
    const bytes = new Uint8Array(await new Response(await peekAndDecompressStream(new Blob([zlib.gzipSync(tricky, { level: 0 }), zlib.gzipSync(B)]))).arrayBuffer());
    assert.equal(Buffer.compare(Buffer.from(bytes), Buffer.concat([tricky, Buffer.from(B)])), 0);
});

test('an archive cut off in the middle gives what was readable, and says so', async () => {
    const whole = zlib.gzipSync(A + B);
    const r = await read(new Blob([whole.subarray(0, Math.floor(whole.length * 0.6))]));
    assert.ok(r.text.length > 1000, 'nothing was read');
    assert.ok((A + B).startsWith(r.text), 'the output is not a prefix of the content');
    assert.equal(r.warnings.length, 1);
    assert.match(r.warnings[0], /incomplete or damaged/);
});

test('a complete member followed by a cut-off one keeps the first', async () => {
    const second = zlib.gzipSync(B);
    const r = await read(new Blob([zlib.gzipSync(A), second.subarray(0, second.length - 200)]));
    assert.ok(r.text.startsWith(A));
    assert.equal(r.warnings.length, 1);
});

test('zero padding after the archive is ignored silently, other data with a warning', async () => {
    let r = await read(new Blob([zlib.gzipSync(A), Buffer.alloc(512)]));
    assert.equal(r.text, A);
    assert.deepEqual(r.warnings, []);
    r = await read(new Blob([zlib.gzipSync(A), zlib.gzipSync(B), Buffer.alloc(4096)]));
    assert.equal(r.text, A + B);
    assert.deepEqual(r.warnings, []);
    r = await read(new Blob([zlib.gzipSync(A), Buffer.from('not gzip at all')]));
    assert.equal(r.text, A);
    assert.equal(r.warnings.length, 1);
});

test('a decompressor that reads several members itself does not give a member twice', async () => {
    // Browsers stop with an error after the first member. zlib reads on into
    // the next ones, and fails only at data that is not gzip.
    const { Duplex } = await import('node:stream');
    const strict = globalThis.DecompressionStream;
    globalThis.DecompressionStream = class { constructor() { return Duplex.toWeb(zlib.createGunzip()); } };
    try {
        let r = await read(new Blob([zlib.gzipSync(A), zlib.gzipSync(B), zlib.gzipSync('last line\n')]));
        assert.equal(r.text, A + B + 'last line\n');
        r = await read(new Blob([zlib.gzipSync(A), zlib.gzipSync(B), Buffer.from('not gzip at all, and long enough to be read as a header')]));
        assert.equal(r.text, A + B);
    } finally {
        globalThis.DecompressionStream = strict;
    }
});

test('plain text is passed through whatever the file is called', async () => {
    const r = await read(new File([A], 'access.log.gz', { type: 'application/gzip' }));
    assert.equal(r.text, A);
    assert.deepEqual(r.warnings, []);
});

test('gzip magic followed by rubbish is an error, not an empty analysis', async () => {
    await assert.rejects(read(new Blob([Buffer.from([0x1f, 0x8b, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])])), /not a readable gzip archive/);
});

test('a stream that ends early gives what was readable, and says so', async () => {
    const whole = zlib.gzipSync(A + B);
    const r = await read(new Response(whole.subarray(0, Math.floor(whole.length * 0.6))).body);
    assert.ok(r.text.length > 1000);
    assert.ok((A + B).startsWith(r.text));
    assert.equal(r.warnings.length, 1);
});

test('an empty file is an empty stream', async () => {
    assert.equal((await read(new Blob([]))).text, '');
});
