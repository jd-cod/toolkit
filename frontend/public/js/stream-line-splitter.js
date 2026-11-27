/**
 * Chunked Line Splitter for Web Streams
 *
 * Emits discrete lines on the fly from streamed Uint8Array / string chunks,
 * handling multi-byte UTF-8 split boundaries and CRLF endings without accumulating
 * monolithic strings in memory.
 */

/**
 * The text encoding of a file, from its first bytes: UTF-16 when it starts
 * with a byte order mark or when every second byte of its start is zero
 * (Windows tools such as PowerShell's `>` write logs that way), else UTF-8.
 * @param {Uint8Array} bytes
 * @returns {'utf-8'|'utf-16le'|'utf-16be'}
 */
function detectTextEncoding(bytes) {
    if (!bytes || bytes.length < 2) return 'utf-8';
    if (bytes[0] === 0xff && bytes[1] === 0xfe) return 'utf-16le';
    if (bytes[0] === 0xfe && bytes[1] === 0xff) return 'utf-16be';
    const length = Math.min(bytes.length - (bytes.length % 2), 256);
    if (length < 8) return 'utf-8';
    let evenZero = 0, oddZero = 0;
    for (let i = 0; i < length; i += 2) {
        if (bytes[i] === 0) evenZero++;
        if (bytes[i + 1] === 0) oddZero++;
    }
    const pairs = length / 2;
    if (oddZero >= pairs * 0.8 && evenZero === 0) return 'utf-16le';
    if (evenZero >= pairs * 0.8 && oddZero === 0) return 'utf-16be';
    return 'utf-8';
}

function textDecoderFor(firstBytes) {
    if (typeof TextDecoder === 'undefined') return null;
    try {
        return new TextDecoder(detectTextEncoding(firstBytes), { fatal: false });
    } catch {
        return new TextDecoder('utf-8', { fatal: false });
    }
}

class ChunkedLineSplitter {
    constructor() {
        // Chosen from the first bytes of the file, see detectTextEncoding.
        this.decoder = null;
        this.remainder = '';
    }

    /**
     * Process a chunk and return an array of complete lines.
     * @param {Uint8Array|string} chunk
     * @returns {string[]}
     */
    feed(chunk) {
        let text;
        if (typeof chunk === 'string') {
            text = this.remainder + chunk;
        } else if (chunk && chunk.buffer) {
            if (!this.decoder) this.decoder = textDecoderFor(chunk);
            text = this.remainder + (this.decoder ? this.decoder.decode(chunk, { stream: true }) : String.fromCharCode.apply(null, chunk));
        } else {
            return [];
        }

        const lines = [];
        let start = 0;
        let idx = text.indexOf('\n', start);

        while (idx !== -1) {
            let line = text.slice(start, idx);
            if (line.endsWith('\r')) {
                line = line.slice(0, -1);
            }
            if (line.indexOf('\r') === -1) lines.push(line);
            else for (const part of line.split('\r')) lines.push(part);
            start = idx + 1;
            idx = text.indexOf('\n', start);
        }

        // A file whose lines end in a lone CR has no LF to split on. The last
        // CR stays in the remainder: it may be the first half of a CRLF.
        let rest = text.slice(start);
        const lastCR = rest.length > 1 ? rest.lastIndexOf('\r', rest.length - 2) : -1;
        if (lastCR !== -1) {
            for (const part of rest.slice(0, lastCR).split('\r')) lines.push(part);
            rest = rest.slice(lastCR + 1);
        }
        this.remainder = rest;
        return lines;
    }

    /**
     * Flush remaining buffered line at EOF.
     * @returns {string[]}
     */
    flush() {
        let text = '';
        if (this.decoder) {
            text = this.decoder.decode();
        }
        this.decoder = null; // the next file may be in another encoding
        text = this.remainder + text;
        this.remainder = '';

        if (!text) return [];
        if (text.endsWith('\r')) {
            text = text.slice(0, -1);
        }
        if (text.length === 0) return [];
        return text.indexOf('\r') === -1 ? [text] : text.split('\r');
    }

    /**
     * Reset internal buffer state.
     */
    reset() {
        this.remainder = '';
        this.decoder = null; // the next file may be in another encoding
    }
}

const GZIP_UNSUPPORTED = 'This browser cannot open gzip files. Extract the .gz file first.';
const GZIP_UNREADABLE = 'The file is not a readable gzip archive.';
const GZIP_INCOMPLETE = 'The gzip archive is incomplete or damaged at the end. Everything readable before that point was analysed.';

// Raised for input that cannot be read, as opposed to a fault in the analysis.
function inputError(message) {
    const error = new Error(message);
    error.inputError = true;
    return error;
}

function isGzipStart(bytes) {
    return Boolean(bytes && bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b);
}

function streamFromGenerator(generator) {
    return new ReadableStream({
        async pull(controller) {
            try {
                const { done, value } = await generator.next();
                if (done) controller.close();
                else controller.enqueue(value);
            } catch (err) {
                controller.error(err);
            }
        },
        cancel() {
            return generator.return();
        },
    });
}

/**
 * Offsets after the start of the file where a gzip member may begin: the
 * bytes 1f 8b 08 followed by a flag byte without reserved bits. Compressed
 * data can contain the same bytes by chance, so these are candidates only.
 */
async function findGzipMemberStarts(blob) {
    const STEP = 4 * 1024 * 1024;
    const starts = [];
    for (let base = 0; base < blob.size; base += STEP) {
        // Three bytes of overlap, so a header across two steps is seen once.
        const bytes = new Uint8Array(await blob.slice(base, Math.min(blob.size, base + STEP + 3)).arrayBuffer());
        const last = Math.min(bytes.length - 3, STEP);
        for (let i = bytes.indexOf(0x1f); i !== -1 && i < last; i = bytes.indexOf(0x1f, i + 1)) {
            if (bytes[i + 1] === 0x8b && bytes[i + 2] === 0x08 && (bytes[i + 3] & 0xe0) === 0 && base + i > 0) starts.push(base + i);
        }
    }
    return starts;
}

/** Offset where the run of zero bytes at the end of the file begins. */
async function zeroPaddingStart(blob, from) {
    const STEP = 65536;
    let end = blob.size;
    while (end > from) {
        const begin = Math.max(from, end - STEP);
        const bytes = new Uint8Array(await blob.slice(begin, end).arrayBuffer());
        for (let i = bytes.length - 1; i >= 0; i--) {
            if (bytes[i] !== 0) return begin + i + 1;
        }
        end = begin;
    }
    return from;
}

/**
 * Decompress a gzip file that may hold several members (`cat a.gz b.gz`, an
 * appending compressor), which the browser's own decompressor rejects after
 * the first one.
 *
 * The browser does not say where a member ends, so each member is found by
 * trying: decompress up to the next place a member could begin. A wrong guess
 * ends in an error after a correct prefix of the output, and the next, longer
 * attempt skips what was already passed on. A file that ends early or is
 * damaged gives everything readable and a warning instead of nothing.
 */
async function* gunzipMembers(blob, onWarning) {
    const size = blob.size;
    let start = 0;
    let memberStarts = null; // looked for only after an attempt fails
    let padding = size;      // where zero padding at the end of the file begins
    let total = 0;
    let carried = 0;         // output of the next member that was passed on already

    // Places where the member that begins at `from` may end, nearest first.
    const possibleEnds = (from) => {
        const ends = memberStarts.filter(offset => offset > from);
        // A member ends where the padding begins; its last eight bytes
        // (checksum and length) may be zero themselves.
        for (let k = 0; k <= 8 && padding < size; k++) {
            if (padding + k > from && padding + k < size) ends.push(padding + k);
        }
        return [...new Set(ends)].sort((x, y) => x - y);
    };

    while (start < size) {
        if (!isGzipStart(new Uint8Array(await blob.slice(start, start + 2).arrayBuffer()))) {
            // Zero padding after the last member is common and harmless.
            const tail = new Uint8Array(await blob.slice(start, Math.min(size, start + 65536)).arrayBuffer());
            if (tail.some(byte => byte !== 0) && onWarning) onWarning('Data after the end of the gzip archive was ignored.');
            return;
        }

        // The first attempt takes the rest of the file: right for the usual
        // archive with one member, at no extra cost.
        let ends = memberStarts ? [...possibleEnds(start), size] : [size];
        let emitted = carried;
        let finished = false;
        for (let i = 0; i < ends.length; i++) {
            let skip = emitted;
            let produced = 0;
            try {
                const reader = blob.slice(start, ends[i]).stream().pipeThrough(new DecompressionStream('gzip')).getReader();
                for (;;) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    produced += value.length;
                    if (skip >= value.length) { skip -= value.length; continue; }
                    const chunk = skip > 0 ? value.subarray(skip) : value;
                    skip = 0;
                    emitted += chunk.length;
                    total += chunk.length;
                    yield chunk;
                }
                finished = true;
                start = ends[i];
                // A decompressor that reads on into the next member has
                // already passed on the beginning of what follows.
                carried = Math.max(0, emitted - produced);
                break;
            } catch {
                if (!memberStarts) {
                    memberStarts = await findGzipMemberStarts(blob);
                    padding = await zeroPaddingStart(blob, start);
                    ends = possibleEnds(start); // the whole rest was just tried
                    i = -1;
                }
            }
        }
        if (!finished) {
            if (total === 0) throw inputError(GZIP_UNREADABLE);
            if (onWarning) onWarning(GZIP_INCOMPLETE);
            return;
        }
    }
}

/** A stream cannot be read twice, so only the first member can be recovered. */
async function* gunzipStreamOnce(stream, onWarning) {
    let total = 0;
    try {
        const reader = stream.pipeThrough(new DecompressionStream('gzip')).getReader();
        for (;;) {
            const { done, value } = await reader.read();
            if (done) return;
            total += value.length;
            yield value;
        }
    } catch {
        if (total === 0) throw inputError(GZIP_UNREADABLE);
        if (onWarning) onWarning(GZIP_INCOMPLETE);
    }
}

/**
 * Returns the content of a file or stream as a byte stream, decompressed when
 * it starts with the gzip magic bytes (0x1f 0x8b), whatever its name says.
 *
 * Pass the File or Blob itself where there is one: only then can an archive
 * with several members be read completely.
 *
 * @param {Blob|ReadableStream} input
 * @param {{ onWarning?: (message: string) => void }} [options] - Called when
 *   part of the input could not be read; the stream then ends normally.
 * @returns {Promise<ReadableStream>}
 */
async function peekAndDecompressStream(input, options = {}) {
    const onWarning = typeof options.onWarning === 'function' ? options.onWarning : null;

    if (typeof Blob !== 'undefined' && input instanceof Blob) {
        if (!isGzipStart(new Uint8Array(await input.slice(0, 2).arrayBuffer()))) return input.stream();
        if (typeof DecompressionStream === 'undefined') throw inputError(GZIP_UNSUPPORTED);
        return streamFromGenerator(gunzipMembers(input, onWarning));
    }

    const readableStream = input;
    if (!readableStream || typeof readableStream.getReader !== 'function') {
        return readableStream;
    }
    const reader = readableStream.getReader();
    const { done, value } = await reader.read();
    if (done) {
        return new ReadableStream({
            start(controller) { controller.close(); }
        });
    }

    const reconstructedStream = new ReadableStream({
        start(controller) {
            controller.enqueue(value);
        },
        async pull(controller) {
            const res = await reader.read();
            if (res.done) {
                controller.close();
            } else {
                controller.enqueue(res.value);
            }
        },
        cancel(reason) {
            return reader.cancel(reason);
        }
    });

    if (!isGzipStart(value)) return reconstructedStream;
    if (typeof DecompressionStream === 'undefined') throw inputError(GZIP_UNSUPPORTED);
    return streamFromGenerator(gunzipStreamOnce(reconstructedStream, onWarning));
}

/**
 * The whole stream as text. `new Response(stream).text()` reports any error
 * in the stream as "Failed to fetch"; this keeps the real reason.
 */
async function readStreamAsText(stream) {
    const reader = stream.getReader();
    let decoder = null;
    let text = '';
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (typeof value === 'string') { text += value; continue; }
        if (!decoder) decoder = textDecoderFor(value);
        text += decoder.decode(value, { stream: true });
    }
    return decoder ? text + decoder.decode() : text;
}

/** A worker 'error' event carries no readable text of its own. */
function workerUnavailableError(event) {
    const detail = event && typeof event.message === 'string' && event.message ? ` (${event.message})` : '';
    const error = new Error(`The log parser could not be started${detail}. Reload the page and try again.`);
    error.workerUnavailable = true;
    return error;
}

// One loaded database is enough: lookups against the other answer "Unknown".
function geoUsable(geoip) {
    if (!geoip || typeof geoip.lookupCountry !== 'function') return false;
    if (typeof geoip.status === 'function') {
        const state = geoip.status();
        return state.country === 'ready' || state.asn === 'ready';
    }
    return typeof geoip.isReady === 'function' && geoip.isReady();
}

/**
 * Feeds a ReadableStream chunk-by-chunk to a Web Worker running createWorkerHandler.
 * @param {ReadableStream} stream
 * @param {Worker} worker
 * @param {Object} options - parsing options (skip403, skipInternal)
 * @param {Function} [onProgress] - progress callback
 * @returns {Promise<{ summary: Object, page1: Object, durationMs: number }>}
 */
function streamChunksToWorker(stream, worker, options = {}, onProgress = null) {
    return new Promise((resolve, reject) => {
        let stopped = false;
        const messageHandler = (e) => {
            const data = e.data || {};
            if (data.type === 'progress') {
                if (typeof onProgress === 'function') onProgress(data);
            } else if (data.type === 'complete') {
                const geoipObj = (typeof window !== 'undefined' ? window.GeoIP : null) || (typeof globalThis !== 'undefined' ? globalThis.GeoIP : null);
                if (data.ipDict && geoUsable(geoipObj)) {
                    (async () => {
                        try {
                            const ipCount = data.ipDict.length;
                            const countryIds = new Uint16Array(ipCount);
                            const asns = new Uint32Array(ipCount);
                            const countryDict = ['-'];
                            const countryNames = {};
                            const countryMap = new Map([['-', 0]]);
                            const asnOrgMap = {};

                            const YIELD_EVERY = 10000;
                            for (let id = 0; id < ipCount; id++) {
                                const ip = data.ipDict[id];
                                const c = geoipObj.lookupCountry(ip);
                                const a = geoipObj.lookupASN(ip);
                                const cCode = c.country_code || '-';
                                let cId = countryMap.get(cCode);
                                if (cId === undefined) {
                                    cId = countryDict.length;
                                    countryDict.push(cCode);
                                    if (c.country && c.country !== 'Unknown') countryNames[cCode] = c.country;
                                    countryMap.set(cCode, cId);
                                }
                                countryIds[id] = cId;
                                const asn = a.asn || 0;
                                asns[id] = asn;
                                if (asn > 0 && a.asn_org && !asnOrgMap[asn]) {
                                    asnOrgMap[asn] = a.asn_org;
                                }

                                if (id > 0 && id % YIELD_EVERY === 0) {
                                    if (typeof onProgress === 'function') {
                                        onProgress({
                                            type: 'geo_progress',
                                            current: id,
                                            total: ipCount
                                        });
                                    }
                                    await new Promise(r => setTimeout(r, 0));
                                }
                            }

                            if (typeof onProgress === 'function') {
                                onProgress({
                                    type: 'geo_progress',
                                    current: ipCount,
                                    total: ipCount
                                });
                            }

                            if (worker.postMessage) {
                                try {
                                    worker.postMessage({
                                        action: 'enrich_geo',
                                        countryIds,
                                        asns,
                                        countryDict,
                                        countryNames,
                                        asnOrgMap
                                    }, [countryIds.buffer, asns.buffer]);
                                } catch {
                                    worker.postMessage({
                                        action: 'enrich_geo',
                                        countryIds,
                                        asns,
                                        countryDict,
                                        countryNames,
                                        asnOrgMap
                                    });
                                }
                            }
                        } catch (err) {
                            cleanup();
                            resolve(data);
                        }
                    })();
                    return;
                }
                cleanup();
                resolve(data);
            } else if (data.type === 'enriched') {
                cleanup();
                resolve(data);
            } else if (data.type === 'error') {
                cleanup();
                reject(new Error(data.error || 'Worker streaming error'));
            }
        };

        const errorHandler = (event) => {
            stopped = true;
            cleanup();
            reject(workerUnavailableError(event));
        };

        function cleanup() {
            if (worker.removeEventListener) {
                worker.removeEventListener('message', messageHandler);
                worker.removeEventListener('error', errorHandler);
            } else if (worker.onmessage === messageHandler) {
                worker.onmessage = null;
            }
        }

        if (worker.addEventListener) {
            worker.addEventListener('message', messageHandler);
            worker.addEventListener('error', errorHandler);
        } else {
            worker.onmessage = messageHandler;
            worker.onerror = errorHandler;
        }

        (async () => {
            try {
                // The worker checks bot addresses against the ranges the page
                // already loaded.
                const detector = (typeof window !== 'undefined' ? window.BotDetector : null) || (typeof globalThis !== 'undefined' ? globalThis.BotDetector : null);
                const botFeed = detector && typeof detector.getData === 'function' ? detector.getData() : null;
                if (botFeed) worker.postMessage({ action: 'configure', botFeed });

                const reader = stream.getReader();
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    if (stopped) { reader.cancel().catch(() => {}); return; }
                    worker.postMessage({
                        action: 'parse_stream_chunk',
                        chunk: value,
                        isLast: false,
                        options
                    });
                }
                worker.postMessage({
                    action: 'parse_stream_chunk',
                    chunk: null,
                    isLast: true,
                    options
                });
            } catch (err) {
                cleanup();
                reject(err);
            }
        })();
    });
}

/**
 * Streams chunks from a Web ReadableStream to an existing Web Worker using append_stream_chunk,
 * performs incremental GeoIP enrichment on completion, and resolves with updated results.
 *
 * @param {ReadableStream} stream - input stream of Uint8Array chunks
 * @param {Worker} worker - active log-parser.worker instance
 * @param {Object} [options] - parsing options
 * @param {Function} [onProgress] - progress callback
 * @returns {Promise<{ summary: Object, pageResult: Object, durationMs: number }>}
 */
function appendStreamToWorker(stream, worker, options = {}, onProgress = null) {
    return new Promise((resolve, reject) => {
        let stopped = false;
        const messageHandler = (e) => {
            const data = e.data || {};
            if (data.type === 'progress') {
                if (typeof onProgress === 'function') onProgress(data);
            } else if (data.type === 'append_complete') {
                const geoipObj = (typeof window !== 'undefined' ? window.GeoIP : null) || (typeof globalThis !== 'undefined' ? globalThis.GeoIP : null);
                if (data.ipDict && geoUsable(geoipObj)) {
                    (async () => {
                        try {
                            const ipCount = data.ipDict.length;
                            const countryIds = new Uint16Array(ipCount);
                            const asns = new Uint32Array(ipCount);
                            const countryDict = ['-'];
                            const countryNames = {};
                            const countryMap = new Map([['-', 0]]);
                            const asnOrgMap = {};

                            const YIELD_EVERY = 10000;
                            for (let id = 0; id < ipCount; id++) {
                                const ip = data.ipDict[id];
                                const c = geoipObj.lookupCountry(ip);
                                const a = geoipObj.lookupASN(ip);
                                const cCode = c.country_code || '-';
                                let cId = countryMap.get(cCode);
                                if (cId === undefined) {
                                    cId = countryDict.length;
                                    countryDict.push(cCode);
                                    if (c.country && c.country !== 'Unknown') countryNames[cCode] = c.country;
                                    countryMap.set(cCode, cId);
                                }
                                countryIds[id] = cId;
                                const asn = a.asn || 0;
                                asns[id] = asn;
                                if (asn > 0 && a.asn_org && !asnOrgMap[asn]) {
                                    asnOrgMap[asn] = a.asn_org;
                                }

                                if (id > 0 && id % YIELD_EVERY === 0) {
                                    if (typeof onProgress === 'function') {
                                        onProgress({
                                            type: 'geo_progress',
                                            current: id,
                                            total: ipCount
                                        });
                                    }
                                    await new Promise(r => setTimeout(r, 0));
                                }
                            }

                            if (worker.postMessage) {
                                try {
                                    worker.postMessage({
                                        action: 'enrich_geo_incremental',
                                        countryIds,
                                        asns,
                                        countryDict,
                                        countryNames,
                                        asnOrgMap,
                                        startIpIndex: data.startIpIndex || 0,
                                        startRowIndex: data.startRowIndex || 0
                                    }, [countryIds.buffer, asns.buffer]);
                                } catch {
                                    worker.postMessage({
                                        action: 'enrich_geo_incremental',
                                        countryIds,
                                        asns,
                                        countryDict,
                                        countryNames,
                                        asnOrgMap,
                                        startIpIndex: data.startIpIndex || 0,
                                        startRowIndex: data.startRowIndex || 0
                                    });
                                }
                            }
                        } catch (err) {
                            cleanup();
                            resolve(data);
                        }
                    })();
                    return;
                }
                cleanup();
                resolve(data);
            } else if (data.type === 'enriched') {
                cleanup();
                resolve(data);
            } else if (data.type === 'error') {
                cleanup();
                reject(new Error(data.error || 'Worker streaming error'));
            }
        };

        const errorHandler = (event) => {
            stopped = true;
            cleanup();
            reject(workerUnavailableError(event));
        };

        function cleanup() {
            if (worker.removeEventListener) {
                worker.removeEventListener('message', messageHandler);
                worker.removeEventListener('error', errorHandler);
            } else if (worker.onmessage === messageHandler) {
                worker.onmessage = null;
            }
        }

        if (worker.addEventListener) {
            worker.addEventListener('message', messageHandler);
            worker.addEventListener('error', errorHandler);
        } else {
            worker.onmessage = messageHandler;
            worker.onerror = errorHandler;
        }

        (async () => {
            try {
                const reader = stream.getReader();
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    if (stopped) { reader.cancel().catch(() => {}); return; }
                    worker.postMessage({
                        action: 'append_stream_chunk',
                        chunk: value,
                        isLast: false,
                        options
                    });
                }
                worker.postMessage({
                    action: 'append_stream_chunk',
                    chunk: null,
                    isLast: true,
                    options
                });
            } catch (err) {
                cleanup();
                reject(err);
            }
        })();
    });
}

// Universal export: CommonJS (Node.js tests) and Worker/Browser global (importScripts / <script>)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ChunkedLineSplitter, detectTextEncoding, peekAndDecompressStream, readStreamAsText, streamChunksToWorker, appendStreamToWorker };
}
if (typeof self !== 'undefined') {
    self.ChunkedLineSplitter = ChunkedLineSplitter;
    self.peekAndDecompressStream = peekAndDecompressStream;
    self.readStreamAsText = readStreamAsText;
    self.streamChunksToWorker = streamChunksToWorker;
    self.appendStreamToWorker = appendStreamToWorker;
}
if (typeof window !== 'undefined') {
    window.ChunkedLineSplitter = ChunkedLineSplitter;
    window.peekAndDecompressStream = peekAndDecompressStream;
    window.readStreamAsText = readStreamAsText;
    window.streamChunksToWorker = streamChunksToWorker;
    window.appendStreamToWorker = appendStreamToWorker;
}
