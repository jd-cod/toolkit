import { test } from 'node:test';
import assert from 'node:assert/strict';
import engine from './helpers/engine.js';
import { createRequire } from 'node:module';

// The dashboard's markup is built without a page, so it can be checked here:
// text that comes from a log must never arrive in the page as markup.
const { analyze } = engine;
const require = createRequire(import.meta.url);
const DashboardFilters = require('../../frontend/public/js/dashboard-filters.js');
const Views = require('../../frontend/public/js/dashboard-views.js');

const EVIL = '<img src=x onerror=alert(1)>';
const line = (i, url, ua, referrer = '-') => `81.2.69.${1 + i} - - [27/Nov/2026:10:00:${String(i).padStart(2, '0')} +0000] "GET ${url} HTTP/1.1" 200 512 "${referrer}" "${ua}"`;

function analysed() {
    return analyze([
        line(0, `/${EVIL}`, 'Mozilla/5.0 Chrome/128'),
        line(1, '/ok', `${EVIL}bot/1.0`),
        line(2, '/ok', 'Mozilla/5.0 Chrome/128', `https://${EVIL}.example/`),
        ...Array.from({ length: 12 }, (_, i) => line(3 + i, `/page/${i % 3}`, 'Mozilla/5.0 Chrome/128')),
    ].join('\n'));
}

// What dashboard.js hands the markup functions (see its viewState()).
function view(analysis, over = {}) {
    return {
        activeFilters: DashboardFilters.none(), activeRpsResolution: '1', sliderStartPct: 0, sliderEndPct: 100, latestSummary: analysis.summary,
        activeTimeMinutes: 0, explorerPerPage: 25, currentClientIp: 'auto', originalParseResult: analysis.parseResult,
        latestPageResult: analysis.pageResult, wholeLogRequests: analysis.data.total_requests, hasActiveFilters: () => false,
        getSelectedTimeRange: () => null, getGlobalTimeRange: () => null, customHoursVal: 1, currentSkipInternal: true, currentSkip403: true, currentSources: ['text'],
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

test('text from a log never becomes markup', async () => {
    const analysis = await analysed();
    const { data, parseResult } = analysis;
    assert.ok(data.http_metrics.top_paths.some(p => p.path.includes('<img')), 'the hostile path reached the analysis');
    const state = view(analysis);
    const pages = [
        Views.render3ColumnIncidentMatrixHtml(data, data.total_requests),
        Views.renderFacetedFilterRibbonHtml(DashboardFilters.options(data), view(analysis, { activeFilters: { ...DashboardFilters.none(), ipSearch: EVIL, pathSearch: EVIL, uaSearch: EVIL, statusCategory: EVIL } })),
        Views.renderLogExplorerCardHtml(view(analysis, { activeFilters: { ...DashboardFilters.none(), ipSearch: EVIL, pathSearch: EVIL } })),
        Views.renderExclusionsHtml(parseResult, state),
        Views.renderDataNoticesHtml(data, view(analysis, { originalParseResult: { ...parseResult, inputWarnings: [`${EVIL}: cut off`] } })),
        Views.renderUnifiedTelemetryCardHtml(data.request_rate, state),
    ];
    for (const html of pages) {
        assert.ok(html.length > 50);
        assert.equal(html.includes('<img'), false, html.slice(Math.max(0, html.indexOf('<img') - 80), html.indexOf('<img') + 60));
        assert.equal(/onerror=alert\(1\)>/.test(html.replace(/&gt;/g, '')), false);
    }
    assert.ok(pages[0].includes('&lt;img src=x onerror=alert(1)&gt;'), 'the path is shown, as text');
});

test('the filter bar counts the matching requests of the view it is given', async () => {
    const analysis = await analysed();
    const filters = { ...DashboardFilters.none(), pathSearch: '^/page' };
    const filtered = await engine.LogEngine.filter(analysis.worker, DashboardFilters.forWorker(filters));
    const text = html => html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
    const html = Views.renderFacetedFilterRibbonHtml(DashboardFilters.options(analysis.data), view(analysis, { activeFilters: filters, latestSummary: filtered.summary, hasActiveFilters: () => true }));
    assert.match(text(html), /Matching 12 \/ 15 requests/);
    const large = Views.renderFacetedFilterRibbonHtml(DashboardFilters.options(analysis.data), view(analysis, { latestSummary: { matchingCount: 7 }, wholeLogRequests: 4000 }));
    assert.match(text(large), /Matching 7 \/ 4,000 requests/);
});

test('exclusions can be switched when the log can be read again', async () => {
    const analysis = await analysed();
    assert.equal(/disabled/.test(Views.renderExclusionsHtml(analysis.parseResult, view(analysis))), false);
    const stream = Views.renderExclusionsHtml(analysis.parseResult, view(analysis, { currentSources: null }));
    assert.match(stream, /id="dash-skip-403"[^>]*disabled/);
    assert.match(stream, /These options were set before the analysis/);
});
