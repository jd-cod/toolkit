/**
 * The analysis engine for unit tests: the scripts the page loads, in its
 * order, and the page's own way in (LogEngine). Node has no Worker, so the
 * engine runs in the test process, as it does in a browser without workers.
 */
const js = name => require(`../../../frontend/public/js/${name}.js`);

globalThis.RequestPaths = js('request-paths');
globalThis.BotDetector = js('bot-detector');
globalThis.TrafficClassifier = js('traffic-classifier');
const LogParser = globalThis.LogParser = js('log-parser');
const { ColumnarStorage } = js('columnar-storage');
const Analyzer = globalThis.Analyzer = js('analyzer');
Object.assign(globalThis, js('stream-line-splitter'));
globalThis.createWorkerHandler = js('log-parser.worker').createWorkerHandler;
const LogEngine = js('log-engine');

const EVERYTHING = { skip403: false, skipInternal: false };

/**
 * A log analysed by the engine.
 *
 * @param {string|Blob|Array<string|Blob>} input
 * @param {object} [options] - Exclusions; none by default.
 * @returns {Promise<object>} What LogEngine.analyze gives (data, summary,
 *   parseResult, pageResult, worker), and:
 *   rows(filters, order) - every request that passes, in file order unless 'newest';
 *   filter(filters) - the analysis of the requests that pass;
 *   append(input) - the analysis after another source was added.
 */
async function analyze(input, options = EVERYTHING) {
    const result = await LogEngine.analyze(input, options);
    return {
        ...result,
        rows: async (filters = {}, order = 'file') => (await LogEngine.rows(result.worker, { filters, order, pageSize: 1000000 })).rows,
        filter: async filters => (await LogEngine.filter(result.worker, filters)).data,
        append: more => LogEngine.append(result.worker, more, options),
    };
}

/**
 * What the parser reads from each line of a text, before anything is
 * counted. The format is decided from the first lines, as the engine does.
 * @returns {{ format: string, lines: object[], requests: object[] }} `requests` are the lines that count.
 */
function readLines(text, options = EVERYTHING) {
    const lines = text.split(/\r\n|\n|\r/);
    const format = LogParser.detectFormat(lines.slice(0, 200));
    const read = lines.filter(line => line && line.trim() && line[0] !== '#').map(line => format.parseLine(line, options));
    return { format: format.type, lines: read, requests: read.filter(r => r.valid) };
}

/** A copy without typed arrays, Maps and undefined fields, for deepEqual. */
const plain = value => JSON.parse(JSON.stringify(value));

module.exports = { LogParser, ColumnarStorage, Analyzer, LogEngine, EVERYTHING, analyze, readLines, plain };
