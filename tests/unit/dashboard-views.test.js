import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

// The dashboard's markup is built without a page, so it can be checked here:
// text that comes from a log must never arrive in the page as markup.
const require = createRequire(import.meta.url);
require('../../frontend/public/js/request-paths.js');
require('../../frontend/public/js/bot-detector.js');
require('../../frontend/public/js/traffic-classifier.js');
const LogParser = require('../../frontend/public/js/log-parser.js');
globalThis.LogParser = LogParser;
const Analyzer = require('../../frontend/public/js/analyzer.js');
const DashboardFilters = require('../../frontend/public/js/dashboard-filters.js');
const Views = require('../../frontend/public/js/dashboard-views.js');

globalThis.GeoIP = { lookupIP: () => ({ country: 'Unknown', country_code: '--', asn: 0, asn_org: 'Unknown' }), lookupCountry: () => ({ country: 'Unknown', country_code: '--' }) };

const EVIL = '<img src=x onerror=alert(1)>';
const ALL = { skip403: false, skipInternal: false };
const line = (i, url, ua, referrer = '-') => `81.2.69.${1 + i} - - [27/Nov/2026:10:00:${String(i).padStart(2, '0')} +0000] "GET ${url} HTTP/1.1" 200 512 "${referrer}" "${ua}"`;

function analysed() {
    const text = [
        line(0, `/${EVIL}`, 'Mozilla/5.0 Chrome/128'),
        line(1, '/ok', `${EVIL}bot/1.0`),
        line(2, '/ok', 'Mozilla/5.0 Chrome/128', `https://${EVIL}.example/`),
        ...Array.from({ length: 12 }, (_, i) => line(3 + i, `/page/${i % 3}`, 'Mozilla/5.0 Chrome/128')),
    ].join('\n');
    const parsed = LogParser.parseIPs(text, ALL);
    Analyzer.enrichLogEntries(parsed.logEntries);
    return { parsed, data: Analyzer.analyzeEnhancedLogs(parsed.logEntries) };
}

function view(entries, over = {}) {
    return {
        activeFilters: DashboardFilters.none(), activeRpsResolution: '1', sliderStartPct: 0, sliderEndPct: 100, latestSummary: null,
        activeTimeMinutes: 0, explorerPerPage: 25, originalEnrichedEntries: entries, currentClientIp: 'auto', originalParseResult: null,
        latestPageResult: null, currentFilteredEntries: entries, uploadTotalRequests: 0, hasActiveFilters: () => false,
        getSelectedTimeRange: () => null, getGlobalTimeRange: () => null, customHoursVal: 1, currentSkipInternal: true, currentSkip403: true, currentReanalyze: null,
        ...over,
    };
}

test('text helpers', () => {
    assert.equal(Views.escapeHtml(`<a href="x" title='y'>&</a>`), '&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;');
    assert.equal(Views.escapeHtml(null), '');
    assert.equal(Views.numberWithCommas(1234567), '1,234,567');
    assert.equal(Views.numberWithCommas(undefined), '0');
    assert.equal(Views.formatSize(1536), '1.5 KB');
});

test('the status split of a path names its two most frequent responses', () => {
    const html = Views.pathStatusHtml({ count: 20, status_breakdown: [{ code: 200, count: 15 }, { code: 503, count: 4 }, { code: 0, count: 1 }] });
    assert.match(html, /title="200: 15, 503: 4, none: 1"/);
    assert.match(html, />200<\/span>.* 75%.*>503<\/span>.* 20%.*\+1/s);
    assert.equal(Views.pathStatusHtml({ count: 3, status_breakdown: [] }).includes('>-<'), true);
});

test('text from a log never becomes markup', () => {
    const { parsed, data } = analysed();
    assert.ok(data.http_metrics.top_paths.some(p => p.path.includes('<img')), 'the hostile path reached the analysis');
    const state = view(parsed.logEntries, { originalParseResult: parsed });
    const pages = [
        Views.render3ColumnIncidentMatrixHtml(data, data.total_requests),
        Views.renderFacetedFilterRibbonHtml(DashboardFilters.options(data), view(parsed.logEntries, { activeFilters: { ...DashboardFilters.none(), ipSearch: EVIL, pathSearch: EVIL, uaSearch: EVIL, statusCategory: EVIL } })),
        Views.renderLogExplorerCardHtml(view(parsed.logEntries, { activeFilters: { ...DashboardFilters.none(), ipSearch: EVIL, pathSearch: EVIL } })),
        Views.renderExclusionsHtml(parsed, state),
        Views.renderDataNoticesHtml(data, view(parsed.logEntries, { originalParseResult: { ...parsed, inputWarnings: [`${EVIL}: cut off`] } })),
        Views.renderUnifiedTelemetryCardHtml(data.request_rate, state),
    ];
    for (const html of pages) {
        assert.ok(html.length > 50);
        assert.equal(html.includes('<img'), false, html.slice(Math.max(0, html.indexOf('<img') - 80), html.indexOf('<img') + 60));
        assert.equal(/onerror=alert\(1\)>/.test(html.replace(/&gt;/g, '')), false);
    }
    assert.ok(pages[0].includes('&lt;img src=x onerror=alert(1)&gt;'), 'the path is shown, as text');
});

test('the filter bar counts the matching requests of the view it is given', () => {
    const { parsed, data } = analysed();
    const filters = { ...DashboardFilters.none(), pathSearch: '^/page' };
    const matching = DashboardFilters.apply(parsed.logEntries, filters);
    const html = Views.renderFacetedFilterRibbonHtml(DashboardFilters.options(data), view(parsed.logEntries, { activeFilters: filters, currentFilteredEntries: matching, hasActiveFilters: () => true }));
    assert.match(html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' '), /Matching 12 \/ 15 requests/);
    // After an upload the counts come from the worker's summary.
    const upload = Views.renderFacetedFilterRibbonHtml(DashboardFilters.options(data), view([], { latestSummary: { matchingCount: 7 }, uploadTotalRequests: 4000, currentFilteredEntries: [] }));
    assert.match(upload.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' '), /Matching 7 \/ 4,000 requests/);
});
