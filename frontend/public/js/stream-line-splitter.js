/**
 * Chunked Line Splitter for Web Streams
 *
 * Emits discrete lines on the fly from streamed Uint8Array / string chunks,
 * handling multi-byte UTF-8 split boundaries and CRLF endings without accumulating
 * monolithic strings in memory.
 */

class ChunkedLineSplitter {
    constructor() {
        this.decoder = typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { fatal: false, stream: true }) : null;
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
            lines.push(line);
            start = idx + 1;
            idx = text.indexOf('\n', start);
        }

        this.remainder = text.slice(start);
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
        text = this.remainder + text;
        this.remainder = '';

        if (!text) return [];
        if (text.endsWith('\r')) {
            text = text.slice(0, -1);
        }
        return text.length > 0 ? [text] : [];
    }

    /**
     * Reset internal buffer state.
     */
    reset() {
        this.remainder = '';
        if (this.decoder) {
            this.decoder.decode(); // Clears any internal decoder state
        }
    }
}

/**
 * Detects gzip magic bytes (0x1f 0x8b) from the first chunk of a ReadableStream
 * and pipes through DecompressionStream('gzip') if compressed, or returns the
 * stream uncompressed without buffering the entire body.
 * @param {ReadableStream} readableStream
 * @returns {Promise<ReadableStream>}
 */
async function peekAndDecompressStream(readableStream) {
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

    let isGzip = false;
    if (value && value.length >= 2 && value[0] === 0x1f && value[1] === 0x8b) {
        isGzip = true;
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

    if (isGzip && typeof DecompressionStream !== 'undefined') {
        return reconstructedStream.pipeThrough(new DecompressionStream('gzip'));
    }
    return reconstructedStream;
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
        const messageHandler = (e) => {
            const data = e.data || {};
            if (data.type === 'progress') {
                if (typeof onProgress === 'function') onProgress(data);
            } else if (data.type === 'complete') {
                const geoipObj = (typeof window !== 'undefined' ? window.GeoIP : null) || (typeof globalThis !== 'undefined' ? globalThis.GeoIP : null);
                if (data.ipDict && geoipObj && typeof geoipObj.lookupCountry === 'function' && typeof geoipObj.isReady === 'function' && geoipObj.isReady()) {
                    (async () => {
                        try {
                            const ipCount = data.ipDict.length;
                            const countryIds = new Uint16Array(ipCount);
                            const asns = new Uint32Array(ipCount);
                            const countryDict = ['-'];
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
                                        asnOrgMap
                                    }, [countryIds.buffer, asns.buffer]);
                                } catch {
                                    worker.postMessage({
                                        action: 'enrich_geo',
                                        countryIds,
                                        asns,
                                        countryDict,
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

        const errorHandler = (err) => {
            cleanup();
            reject(err);
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
        const messageHandler = (e) => {
            const data = e.data || {};
            if (data.type === 'progress') {
                if (typeof onProgress === 'function') onProgress(data);
            } else if (data.type === 'append_complete') {
                const geoipObj = (typeof window !== 'undefined' ? window.GeoIP : null) || (typeof globalThis !== 'undefined' ? globalThis.GeoIP : null);
                if (data.ipDict && geoipObj && typeof geoipObj.lookupCountry === 'function' && typeof geoipObj.isReady === 'function' && geoipObj.isReady()) {
                    (async () => {
                        try {
                            const ipCount = data.ipDict.length;
                            const countryIds = new Uint16Array(ipCount);
                            const asns = new Uint32Array(ipCount);
                            const countryDict = ['-'];
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

        const errorHandler = (err) => {
            cleanup();
            reject(err);
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
    module.exports = { ChunkedLineSplitter, peekAndDecompressStream, streamChunksToWorker, appendStreamToWorker };
}
if (typeof self !== 'undefined') {
    self.ChunkedLineSplitter = ChunkedLineSplitter;
    self.peekAndDecompressStream = peekAndDecompressStream;
    self.streamChunksToWorker = streamChunksToWorker;
    self.appendStreamToWorker = appendStreamToWorker;
}
if (typeof window !== 'undefined') {
    window.ChunkedLineSplitter = ChunkedLineSplitter;
    window.peekAndDecompressStream = peekAndDecompressStream;
    window.streamChunksToWorker = streamChunksToWorker;
    window.appendStreamToWorker = appendStreamToWorker;
}
