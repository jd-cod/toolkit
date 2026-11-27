/**
 * Nginx Log Parser — Web Worker (Streaming Columnar Engine)
 *
 * Streams chunks of access logs directly into high-efficiency columnar TypedArrays
 * with dictionary encoding, handles instant binary filter queries (<50ms),
 * and serves paginated 50-row slices to the Log Explorer.
 */

/* global importScripts, ChunkedLineSplitter, ColumnarStorage, RequestPaths, BotDetector, TrafficClassifier, LogParser */

function ensureDependencies() {
    if (typeof importScripts !== 'undefined') {
        if (typeof ChunkedLineSplitter === 'undefined') {
            importScripts('/js/stream-line-splitter.js?v=6.55');
        }
        if (typeof ColumnarStorage === 'undefined') {
            importScripts('/js/columnar-storage.js?v=6.55');
        }
        if (typeof RequestPaths === 'undefined') {
            importScripts('/js/request-paths.js?v=6.55');
        }
        if (typeof BotDetector === 'undefined') {
            importScripts('/js/bot-detector.js?v=6.55');
        }
        if (typeof TrafficClassifier === 'undefined') {
            importScripts('/js/traffic-classifier.js?v=6.55');
        }
        if (typeof LogParser === 'undefined') {
            importScripts('/js/log-parser.js?v=6.55');
        }
    } else if (typeof require !== 'undefined') {
        if (typeof ChunkedLineSplitter === 'undefined') {
            try { globalThis.ChunkedLineSplitter = require('./stream-line-splitter.js').ChunkedLineSplitter; } catch (_) {}
        }
        if (typeof ColumnarStorage === 'undefined') {
            try { globalThis.ColumnarStorage = require('./columnar-storage.js').ColumnarStorage; } catch (_) {}
        }
        if (typeof RequestPaths === 'undefined') {
            try { globalThis.RequestPaths = require('./request-paths.js'); } catch (_) {}
        }
        if (typeof BotDetector === 'undefined') {
            try { globalThis.BotDetector = require('./bot-detector.js'); } catch (_) {}
        }
        if (typeof TrafficClassifier === 'undefined') {
            try { globalThis.TrafficClassifier = require('./traffic-classifier.js'); } catch (_) {}
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
    let forwardedLines = 0;
    const skipCounts = { privateIP: 0, healthCheck: 0, forbidden: 0, invalid: 0 };

    const classifier = globalThis.TrafficClassifier || (typeof TrafficClassifier !== 'undefined' ? TrafficClassifier : null);
    const session = classifier ? classifier.createSession() : null;

    // Classify every client seen so far and hand the result to the store.
    // Runs again after GeoIP enrichment, when each address has its network.
    function classifyClients() {
        if (!session) return;
        session.finalize(ip => {
            const id = columnarStorage.ipMap.get(ip);
            return (id !== undefined && columnarStorage.ipAsns) ? columnarStorage.ipAsns[id] : 0;
        });
        const count = session.clientCount;
        const classes = new Uint8Array(count);
        const groups = new Array(count);
        for (let id = 0; id < count; id++) {
            const client = session.client(id);
            classes[id] = classifier.CLASS_INDEX[client.cls];
            groups[id] = client.group || '';
        }
        columnarStorage.setClientClasses(classifier.CLASSES, classes, groups, id => session.client(id).ua);
    }

    // Query the store and replace the raw per-client counts with the traffic
    // classes and bot groups the dashboard shows.
    function summarize(filters) {
        const summary = columnarStorage.query(filters);
        const urlHits = summary.urlHits;
        delete summary.urlHits;
        const paths = globalThis.RequestPaths || (typeof RequestPaths !== 'undefined' ? RequestPaths : null);
        if (urlHits && paths) {
            const urls = columnarStorage.urlDict;
            summary.paths = paths.summarize(
                (function* () { for (let id = 0; id < urlHits.length; id++) if (urlHits[id]) yield [urls[id], urlHits[id]]; })(),
                summary.matchingCount
            );
        }
        const counts = summary.clientCounts;
        if (counts && session) {
            delete summary.clientCounts;
            const items = [];
            for (let id = 0; id < counts.length; id++) {
                if (counts[id]) items.push({ client: session.client(id), count: counts[id] });
            }
            summary.traffic = classifier.aggregate(items, {
                geo: ip => columnarStorage.ipGeo(ip),
                ipDetailLimit: 100,
            });
            summary.uaFieldMissing = session.uaFieldMissing;
        }
        return summary;
    }

    // Lines wait here until there are enough to decide the format. A first
    // chunk can hold only a line or two.
    const DETECT_LINES = 200;
    let pendingLines = [];

    function processLines(lines, options, isLast = false) {
        const parser = globalThis.LogParser || LogParser;
        if (!activeFormat) {
            for (let i = 0; i < lines.length; i++) pendingLines.push(lines[i]);
            if (pendingLines.length < DETECT_LINES && !isLast) return;
            lines = pendingLines;
            pendingLines = [];
            if (lines.length === 0) return;
            activeFormat = parser.detectFormat(lines.slice(0, DETECT_LINES));
        }
        const lineParser = (activeFormat && activeFormat.parseLine) || parser.parseLine;
        const paths = globalThis.RequestPaths || (typeof RequestPaths !== 'undefined' ? RequestPaths : null);
        const referrerSite = paths && paths.referrerSite;
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (!line || !line.trim() || line[0] === '#') continue;
            const res = lineParser(line, options);
            if (res.valid) {
                const clientId = session ? session.add(res.ip, res.userAgent, {
                    timeSec: res.timeSec,
                    status: res.statusCode,
                    method: res.method || '',
                    url: res.url || '',
                    hasReferrer: Boolean(res.referrer && res.referrer !== '-'),
                    httpVersion: res.httpVersion || '',
                }) : undefined;
                columnarStorage.appendRow(
                    res.ip,
                    res.timeSec,
                    res.statusCode,
                    res.responseSize,
                    res.url,
                    res.botName,
                    '-',
                    0,
                    res.method || '-',
                    clientId,
                    referrerSite ? referrerSite(res.referrer) : ''
                );
                totalLinesParsed++;
                if (res.viaForwarded) forwardedLines++;
            } else {
                totalLinesSkipped++;
                if (res.reasonType && skipCounts[res.reasonType] !== undefined) skipCounts[res.reasonType]++;
            }
        }
    }

    // Each file is detected on its own: an added file can be in another format.
    function endOfStream(options) {
        const trailing = splitter.flush();
        processLines(trailing || [], options, true);
        activeFormat = null;
    }

    function ingestStats() {
        return { totalBytesRead, totalLinesParsed, totalLinesSkipped, skipCounts: { ...skipCounts }, forwardedLines };
    }

    return function onMessage(e) {
        const data = e.data || {};
        const action = data.action;

        try {
            ensureDependencies();

            if (action === 'configure') {
                // Verified-bot IP ranges, loaded by the page.
                const detector = globalThis.BotDetector || (typeof BotDetector !== 'undefined' ? BotDetector : null);
                if (data.botFeed && detector && detector.loadData) detector.loadData(data.botFeed);
            } else if (action === 'parse_stream_chunk') {
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
                    endOfStream(options);

                    classifyClients();
                    const summary = summarize({});
                    const pageResult = columnarStorage.getPage(1, 50, { totalRows: summary.matchingCount });

                    postMessageFn({
                        type: 'complete',
                        summary,
                        pageResult,
                        ipDict: columnarStorage.ipDict,
                        ...ingestStats()
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
                    endOfStream(options);

                    const emittedStartRow = startRowIndex;
                    const emittedStartIp = startIpIndex;
                    isAppending = false;

                    classifyClients();
                    const summary = summarize({});
                    const pageResult = columnarStorage.getPage(1, 50, { totalRows: summary.matchingCount });

                    postMessageFn({
                        type: 'append_complete',
                        summary,
                        pageResult,
                        ipDict: columnarStorage.ipDict,
                        startIpIndex: emittedStartIp,
                        startRowIndex: emittedStartRow,
                        ...ingestStats()
                    });
                }
            } else if (action === 'enrich_geo') {
                if (data.countryNames) columnarStorage.countryNames = Object.assign(columnarStorage.countryNames || {}, data.countryNames);
                if (data.countryIds && data.asns) {
                    columnarStorage.enrichGeoCompact(data.countryIds, data.asns, data.countryDict, data.asnOrgMap);
                } else {
                    const geoMap = data.geoMap || {};
                    columnarStorage.enrichGeo(geoMap);
                }
                classifyClients();
                const summary = summarize(currentFilters);
                const pageResult = columnarStorage.getPage(1, 50, { ...currentFilters, totalRows: summary.matchingCount });

                postMessageFn({
                    type: 'enriched',
                    summary,
                    pageResult,
                    ...ingestStats()
                });
            } else if (action === 'enrich_geo_incremental') {
                if (data.countryNames) columnarStorage.countryNames = Object.assign(columnarStorage.countryNames || {}, data.countryNames);
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
                classifyClients();
                const summary = summarize(currentFilters);
                const pageResult = columnarStorage.getPage(1, 50, { ...currentFilters, totalRows: summary.matchingCount });

                postMessageFn({
                    type: 'enriched',
                    summary,
                    pageResult,
                    ...ingestStats()
                });
            } else if (action === 'filter') {
                currentFilters = data.filters || {};
                const summary = summarize(currentFilters);
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
