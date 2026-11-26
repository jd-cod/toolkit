/**
 * Nginx Log Parser — Web Worker (Streaming Columnar Engine)
 *
 * Streams chunks of access logs directly into high-efficiency columnar TypedArrays
 * with dictionary encoding, handles instant binary filter queries (<50ms),
 * and serves paginated 50-row slices to the Log Explorer.
 */

/* global importScripts, ChunkedLineSplitter, ColumnarStorage, BotDetector, LogParser */

function ensureDependencies() {
    if (typeof importScripts !== 'undefined') {
        if (typeof ChunkedLineSplitter === 'undefined') {
            importScripts('/js/stream-line-splitter.js?v=6.53');
        }
        if (typeof ColumnarStorage === 'undefined') {
            importScripts('/js/columnar-storage.js?v=6.53');
        }
        if (typeof BotDetector === 'undefined') {
            importScripts('/js/bot-detector.js?v=6.53');
        }
        if (typeof LogParser === 'undefined') {
            importScripts('/js/log-parser.js?v=6.53');
        }
    } else if (typeof require !== 'undefined') {
        if (typeof ChunkedLineSplitter === 'undefined') {
            try { globalThis.ChunkedLineSplitter = require('./stream-line-splitter.js').ChunkedLineSplitter; } catch (_) {}
        }
        if (typeof ColumnarStorage === 'undefined') {
            try { globalThis.ColumnarStorage = require('./columnar-storage.js').ColumnarStorage; } catch (_) {}
        }
        if (typeof LogParser === 'undefined') {
            try { globalThis.LogParser = require('./log-parser.js'); } catch (_) {}
        }
    }
}

function createWorkerHandler(postMessageFn) {
    ensureDependencies();

    const splitter = new (globalThis.ChunkedLineSplitter || ChunkedLineSplitter)();
    const columnarStorage = new (globalThis.ColumnarStorage || ColumnarStorage)(250000);

    let totalBytesRead = 0;
    let totalLinesParsed = 0;
    let totalLinesSkipped = 0;
    let lastProgressEmit = 0;
    let currentFilters = {};
    let startIpIndex = 0;
    let startRowIndex = 0;
    let isAppending = false;
    let activeFormat = null;

    function processLines(lines, options) {
        const parser = globalThis.LogParser || LogParser;
        if (!activeFormat && lines.length > 0 && parser && parser.detectFormat) {
            activeFormat = parser.detectFormat(lines.slice(0, 15));
        }
        const lineParser = (activeFormat && activeFormat.parseLine) || parser.parseLine;
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const res = lineParser(line, options);
            if (res.valid) {
                columnarStorage.appendRow(
                    res.ip,
                    res.timeSec,
                    res.statusCode,
                    res.responseSize,
                    res.url,
                    res.botName,
                    '-',
                    0,
                    res.method || 'GET'
                );
                totalLinesParsed++;
            } else {
                totalLinesSkipped++;
            }
        }
    }

    return function onMessage(e) {
        const data = e.data || {};
        const action = data.action;

        try {
            ensureDependencies();

            if (action === 'parse_stream_chunk') {
                const { chunk, isLast, options } = data;

                if (chunk) {
                    totalBytesRead += chunk.length || chunk.byteLength || 0;
                    const lines = splitter.feed(chunk);
                    processLines(lines, options);

                    if (totalLinesParsed - lastProgressEmit >= 25000) {
                        postMessageFn({
                            type: 'progress',
                            parsedLines: totalLinesParsed,
                            bytesRead: totalBytesRead
                        });
                        lastProgressEmit = totalLinesParsed;
                    }
                }

                if (isLast) {
                    const trailing = splitter.flush();
                    if (trailing && trailing.length > 0) {
                        processLines(trailing, options);
                    }

                    const summary = columnarStorage.query({});
                    const pageResult = columnarStorage.getPage(1, 50, { totalRows: summary.matchingCount });

                    activeFormat = null;
                    postMessageFn({
                        type: 'complete',
                        summary,
                        pageResult,
                        ipDict: columnarStorage.ipDict,
                        totalBytesRead,
                        totalLinesParsed,
                        totalLinesSkipped
                    });
                }
            } else if (action === 'append_stream_chunk') {
                const { chunk, isLast, options } = data;

                if (!isAppending) {
                    isAppending = true;
                    startRowIndex = columnarStorage.rowCount;
                    startIpIndex = columnarStorage.ipDict.length;
                }

                if (chunk) {
                    totalBytesRead += chunk.length || chunk.byteLength || 0;
                    const lines = splitter.feed(chunk);
                    processLines(lines, options);

                    if (totalLinesParsed - lastProgressEmit >= 25000) {
                        postMessageFn({
                            type: 'progress',
                            parsedLines: totalLinesParsed,
                            bytesRead: totalBytesRead
                        });
                        lastProgressEmit = totalLinesParsed;
                    }
                }

                if (isLast) {
                    const trailing = splitter.flush();
                    if (trailing && trailing.length > 0) {
                        processLines(trailing, options);
                    }

                    const emittedStartRow = startRowIndex;
                    const emittedStartIp = startIpIndex;
                    isAppending = false;

                    const summary = columnarStorage.query({});
                    const pageResult = columnarStorage.getPage(1, 50, { totalRows: summary.matchingCount });

                    postMessageFn({
                        type: 'append_complete',
                        summary,
                        pageResult,
                        ipDict: columnarStorage.ipDict,
                        startIpIndex: emittedStartIp,
                        startRowIndex: emittedStartRow,
                        totalBytesRead,
                        totalLinesParsed,
                        totalLinesSkipped
                    });
                }
            } else if (action === 'enrich_geo') {
                if (data.countryIds && data.asns) {
                    columnarStorage.enrichGeoCompact(data.countryIds, data.asns, data.countryDict, data.asnOrgMap);
                } else {
                    const geoMap = data.geoMap || {};
                    columnarStorage.enrichGeo(geoMap);
                }
                const summary = columnarStorage.query(currentFilters);
                const pageResult = columnarStorage.getPage(1, 50, { ...currentFilters, totalRows: summary.matchingCount });

                postMessageFn({
                    type: 'enriched',
                    summary,
                    pageResult,
                    totalBytesRead,
                    totalLinesParsed,
                    totalLinesSkipped
                });
            } else if (action === 'enrich_geo_incremental') {
                if (data.countryIds && data.asns) {
                    columnarStorage.enrichGeoCompactIncremental(
                        data.countryIds,
                        data.asns,
                        data.countryDict,
                        data.asnOrgMap,
                        data.startIpIndex || 0,
                        data.startRowIndex || 0
                    );
                }
                const summary = columnarStorage.query(currentFilters);
                const pageResult = columnarStorage.getPage(1, 50, { ...currentFilters, totalRows: summary.matchingCount });

                postMessageFn({
                    type: 'enriched',
                    summary,
                    pageResult,
                    totalBytesRead,
                    totalLinesParsed,
                    totalLinesSkipped
                });
            } else if (action === 'filter') {
                currentFilters = data.filters || {};
                const summary = columnarStorage.query(currentFilters);
                const pageResult = columnarStorage.getPage(1, 50, { ...currentFilters, totalRows: summary.matchingCount });

                postMessageFn({
                    type: 'filter_result',
                    summary,
                    pageResult
                });
            } else if (action === 'get_page') {
                const page = data.pageNumber || data.page || 1;
                const pageSize = data.pageSize || 50;
                const filters = data.filters || currentFilters;
                const pageResult = columnarStorage.getPage(page, pageSize, filters);

                postMessageFn({
                    type: 'page_result',
                    reqId: data.reqId,
                    ip: data.ip,
                    pageResult
                });
            } else if (action === 'parse' && typeof data.logText === 'string') {
                // Legacy non-streaming parsing fallback
                const parser = globalThis.LogParser || LogParser;
                const result = parser.parseIPs(data.logText, data.options);
                postMessageFn({ type: 'success', result });
            }
        } catch (err) {
            postMessageFn({ type: 'error', error: err.message || String(err) });
        }
    };
}

// Bind to worker environment if self exists
if (typeof self !== 'undefined' && typeof self.postMessage === 'function') {
    self.onmessage = createWorkerHandler((msg) => self.postMessage(msg));
}

// Export for Node.js unit testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { createWorkerHandler };
}
