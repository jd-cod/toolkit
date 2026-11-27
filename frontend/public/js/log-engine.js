/**
 * Traffic Analyzer — the analysis engine, as the page uses it.
 *
 * One way in for every source: pasted text, files, remote streams. The source
 * is read in chunks by the engine (log-parser.worker.js), which keeps the
 * requests in compact columns and answers every later question: the numbers of
 * a filtered view, a page of rows. The page never holds the requests itself,
 * so a pasted sample and a file of many gigabytes take the same path.
 *
 * Needs stream-line-splitter, log-parser and analyzer to be loaded first.
 */
const LogEngine = (() => {
    const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

    function dependency(name) {
        const found = typeof globalThis !== 'undefined' ? globalThis[name] : undefined;
        if (found) return found;
        throw new Error(`LogEngine needs ${name} to be loaded first.`);
    }

    /** Text and files can be read again, with other exclusions; a stream is gone once read. */
    function canReread(input) {
        return typeof input === 'string' || (typeof Blob !== 'undefined' && input instanceof Blob);
    }

    // The source as a stream of bytes, with gzip opened.
    function open(input, warnings, named) {
        const source = typeof input === 'string' ? new Blob([input]) : input;
        const name = named && typeof Blob !== 'undefined' && source instanceof Blob && source.name ? `${source.name}: ` : '';
        return dependency('peekAndDecompressStream')(source, { onWarning: message => warnings.push(name + message) });
    }

    /**
     * The sources as one text, files after one another, gzip opened. Reads
     * everything into memory: for sharing, not for analysis.
     */
    async function readText(inputs) {
        const texts = [];
        for (const input of Array.isArray(inputs) ? inputs : [inputs]) {
            texts.push(typeof input === 'string' ? input : await dependency('readStreamAsText')(await open(input, [], false)));
        }
        return texts.join('\n');
    }

    function startWorker() {
        if (typeof Worker === 'undefined') return null;
        try {
            return new Worker(dependency('LogParser').workerUrl());
        } catch (error) {
            console.warn('The parser worker could not be created:', error);
            return null;
        }
    }

    let handlerLoad = null;
    function loadHandler() {
        if (typeof createWorkerHandler === 'function') return Promise.resolve(createWorkerHandler);
        if (!handlerLoad) {
            handlerLoad = new Promise((resolve, reject) => {
                const script = document.createElement('script');
                script.src = dependency('LogParser').workerUrl();
                script.onload = () => resolve(createWorkerHandler);
                script.onerror = () => {
                    script.remove();
                    handlerLoad = null;
                    reject(new Error('The log parser could not be loaded. Reload the page and try again.'));
                };
                document.head.appendChild(script);
            });
        }
        return handlerLoad;
    }

    /**
     * The engine on the page itself, with the interface of a Worker. For a
     * browser that cannot start workers; the page does not respond while a
     * large log is read this way.
     */
    async function pageWorker() {
        const createHandler = await loadHandler();
        const listeners = { message: new Set(), error: new Set() };
        let stopped = false;
        const worker = {
            onmessage: null,
            onerror: null,
            addEventListener(type, fn) { if (listeners[type]) listeners[type].add(fn); },
            removeEventListener(type, fn) { if (listeners[type]) listeners[type].delete(fn); },
            postMessage(message) { setTimeout(() => { if (!stopped) handle({ data: message }); }, 0); },
            terminate() { stopped = true; },
        };
        const handle = createHandler(message => setTimeout(() => {
            if (stopped) return;
            const event = { data: message };
            for (const fn of [...listeners.message]) fn(event);
            if (worker.onmessage) worker.onmessage(event);
        }, 0));
        return worker;
    }

    // 10/Oct/2026 13:55:36, the time as the log has it.
    function clock(sec) {
        if (!(sec > 0)) return '';
        const d = new Date(sec * 1000);
        const p2 = n => String(n).padStart(2, '0');
        return `${p2(d.getUTCDate())}/${MONTHS[d.getUTCMonth()]}/${d.getUTCFullYear()} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}`;
    }

    /**
     * What was read, beside the analysis itself.
     *
     * The time span is that of every readable line, excluded ones too, so it
     * stays the same when an exclusion is switched.
     */
    function readingOf(result, warnings) {
        const summary = result.summary || {};
        const skipCounts = result.skipCounts || { privateIP: 0, healthCheck: 0, forbidden: 0, invalid: 0 };
        const parsedCount = result.totalLinesParsed || 0;
        const skippedCount = result.totalLinesSkipped || 0;
        const minSec = result.logMinSec || summary.minTimeSec || 0;
        const maxSec = result.logMaxSec || summary.maxTimeSec || 0;
        const reading = {
            parsedCount,
            skippedCount,
            skipCounts,
            // Lines that are requests, whether they were counted or excluded.
            validLines: parsedCount + skippedCount - (skipCounts.invalid || 0),
            forwardedLines: result.forwardedLines || 0,
            minTimestamp: minSec * 1000,
            maxTimestamp: maxSec * 1000,
            logSpanMinutes: minSec && maxSec ? Math.floor((maxSec - minSec) / 60) : 0,
            logStart: clock(minSec),
            logEnd: clock(maxSec),
        };
        if (warnings.length) reading.inputWarnings = warnings.slice();
        return reading;
    }

    function outcome(worker, result, warnings) {
        return {
            worker,
            summary: result.summary,
            pageResult: result.pageResult,
            data: dependency('Analyzer').analyzeFromWorkerSummary(result.summary),
            parseResult: readingOf(result, warnings),
        };
    }

    /**
     * Analyse a log.
     *
     * @param {string|Blob|ReadableStream|Array<string|Blob|ReadableStream>} input -
     *   One source, or several that make up one log (each may have its own format).
     * @param {{ skip403?: boolean, skipInternal?: boolean, clientIp?: 'remote'|'forwarded' }} [parserOptions]
     * @param {{ onProgress?: (progress: object) => void }} [hooks]
     * @returns {Promise<{ worker: object, summary: object, pageResult: object, data: object, parseResult: object }>}
     *   `worker` holds the log: pass it to filter(), rows() and append(), and
     *   call its terminate() when the analysis is no longer shown.
     */
    async function analyze(input, parserOptions = {}, hooks = {}) {
        const sources = Array.isArray(input) ? input : [input];
        const warnings = [];
        const read = async worker => {
            let result = null;
            for (let i = 0; i < sources.length; i++) {
                const stream = await open(sources[i], warnings, sources.length > 1);
                const send = dependency(i === 0 ? 'streamChunksToWorker' : 'appendStreamToWorker');
                result = await send(stream, worker, parserOptions, hooks.onProgress);
            }
            return result;
        };

        let worker = startWorker();
        const threaded = Boolean(worker);
        if (!worker) worker = await pageWorker();
        try {
            return outcome(worker, await read(worker), warnings);
        } catch (error) {
            try { worker.terminate(); } catch { /* already gone */ }
            // The browser refused to run the worker: the same engine, on the page.
            if (!threaded || !error || !error.workerUnavailable || !sources.every(canReread)) throw error;
            console.warn('The parser worker is not available, analysing on the page instead:', error);
        }
        warnings.length = 0;
        worker = await pageWorker();
        try {
            return outcome(worker, await read(worker), warnings);
        } catch (error) {
            worker.terminate();
            throw error;
        }
    }

    /**
     * Add a source to an analysis. Resolves with the analysis of the whole
     * log; the engine's filters are reset.
     */
    async function append(worker, input, parserOptions = {}, hooks = {}) {
        const warnings = [];
        const stream = await open(input, warnings, true);
        const result = await dependency('appendStreamToWorker')(stream, worker, parserOptions, hooks.onProgress);
        return outcome(worker, result, warnings);
    }

    let requests = 0;
    function ask(worker, message, isAnswer) {
        return new Promise((resolve, reject) => {
            const done = () => worker.removeEventListener('message', onMessage);
            const onMessage = event => {
                const data = event.data || {};
                if (data.type === 'error') { done(); reject(new Error(data.error || 'The log engine failed.')); }
                else if (isAnswer(data)) { done(); resolve(data); }
            };
            worker.addEventListener('message', onMessage);
            worker.postMessage(message);
        });
    }

    /**
     * The analysis of the requests that pass `filters` (see
     * DashboardFilters.forWorker). The engine keeps them for later rows().
     * @returns {Promise<{ summary: object, pageResult: object, data: object }>}
     */
    async function filter(worker, filters = {}) {
        const reqId = `filter-${++requests}`;
        const answer = await ask(worker, { action: 'filter', reqId, filters }, data => data.type === 'filter_result' && data.reqId === reqId);
        return { summary: answer.summary, pageResult: answer.pageResult, data: dependency('Analyzer').analyzeFromWorkerSummary(answer.summary) };
    }

    /**
     * A page of requests.
     * @param {{ page?: number, pageSize?: number, filters?: object, order?: 'newest'|'file' }} [request] -
     *   Without `filters`, those of the last filter() call. `order` is newest
     *   first unless 'file' asks for the order of the log.
     * @returns {Promise<{ rows: object[], totalRows: number, page: number, pageSize: number, totalPages: number }>}
     */
    async function rows(worker, request = {}) {
        const reqId = `rows-${++requests}`;
        const answer = await ask(worker, {
            action: 'get_page',
            reqId,
            pageNumber: request.page || 1,
            pageSize: request.pageSize || 50,
            filters: request.filters,
            order: request.order,
        }, data => data.type === 'page_result' && data.reqId === reqId);
        return answer.pageResult;
    }

    return { analyze, append, filter, rows, canReread, readText };
})();

if (typeof window !== 'undefined') window.LogEngine = LogEngine;
if (typeof globalThis !== 'undefined') globalThis.LogEngine = LogEngine;
if (typeof module !== 'undefined' && module.exports) module.exports = LogEngine;
