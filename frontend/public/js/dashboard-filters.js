/**
 * Traffic Analyzer — the dashboard's filters, without any page access.
 *
 * The filter set, which choices the dropdowns offer, and the filters in the
 * form the engine takes. The engine decides which requests pass a filter
 * (ColumnarStorage); the page state and the markup live in dashboard.js.
 */
const DashboardFilters = (() => {
    /** The filter set with nothing chosen. */
    function none() {
        return { statusCategory: 'all', method: 'all', country: 'all', asn: 'all', bot: 'all', ipSearch: '', pathSearch: '', uaSearch: '' };
    }

    /** How many of the filters narrow the view (the time window is not one of them). */
    function count(filters) {
        let active = 0;
        if (filters.method && filters.method !== 'all') active++;
        if (filters.statusCategory && filters.statusCategory !== 'all') active++;
        if (filters.country && filters.country !== 'all') active++;
        if (filters.asn && filters.asn !== 'all') active++;
        if (filters.bot && filters.bot !== 'all') active++;
        if (filters.pathSearch) active++;
        if (filters.ipSearch) active++;
        if (filters.uaSearch && filters.uaSearch.trim()) active++;
        return active;
    }

    function isActive(filters) {
        return count(filters) > 0 || Boolean(filters.uaSearch);
    }

    /**
     * The filters as the engine takes them.
     *
     * @param {object} filters - See `none()`.
     * @param {{ startMs: number, endMs: number|null, keepUntimed: boolean }|null} [timeWindow]
     *   The chosen stretch of the log, sent in seconds. `keepUntimed` lets
     *   requests without a readable time through ("last 30 minutes"); the
     *   handles of the timeline do not.
     */
    function forWorker(filters, timeWindow = null) {
        const out = Object.assign({}, filters);
        if (timeWindow) {
            out.startTimeSec = Math.floor(timeWindow.startMs / 1000);
            if (timeWindow.endMs != null) out.endTimeSec = Math.floor(timeWindow.endMs / 1000);
            if (timeWindow.keepUntimed) out.keepUntimed = true;
        }
        return out;
    }

    /** Choices for the status filter: the classes that occur, then the most frequent single codes. */
    function statusOptions(statusHits) {
        const classes = new Map();
        const codes = [];
        let other = 0;
        for (const item of statusHits || []) {
            const code = Number(item.code);
            const hits = Number(item.count) || 0;
            if (hits <= 0) continue;
            if (!(code >= 100 && code <= 599)) { other += hits; continue; }
            const cls = `${Math.floor(code / 100)}xx`;
            classes.set(cls, (classes.get(cls) || 0) + hits);
            codes.push({ value: String(code), count: hits });
        }
        return {
            classes: [...classes.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([value, hits]) => ({ value, count: hits }))
                .concat(other > 0 ? [{ value: 'other', label: 'No status', count: other }] : []),
            codes: codes.sort((a, b) => b.count - a.count || Number(a.value) - Number(b.value)).slice(0, 12),
        };
    }

    /** What the dropdowns offer, from the analysis of the whole log. */
    function options(data) {
        const asnName = asn => (/^AS/i.test(String(asn)) ? String(asn) : 'AS' + asn);
        return {
            methods: (data?.http_metrics?.method_hits || []).map(m => m.method).sort(),
            statuses: statusOptions(data?.http_metrics?.status_hits),
            countries: (data?.country_hits || []).map(c => ({ country: c.country, count: c.hits })),
            asns: (data?.asn_hits || []).map(a => ({ asn: asnName(a.asn), count: a.hits, label: `${asnName(a.asn)} - ${(a.asn_org || '').slice(0, 20)}` })),
            paths: (data?.http_metrics?.path_sections || []).slice(0, 25).map(p => ({ path: p.path, count: p.count })),
            trafficStats: {
                human: data?.human_requests || 0,
                verified: data?.verified_bots_count || 0,
                fake: data?.spoofed_bots_count || 0,
                unverified: data?.unverified_bots_count || 0,
                automated: data?.automated_count || 0,
                suspected: data?.suspected_count || 0,
            },
        };
    }

    return { none, count, isActive, forWorker, statusOptions, options };
})();

if (typeof window !== 'undefined') window.DashboardFilters = DashboardFilters;
if (typeof globalThis !== 'undefined') globalThis.DashboardFilters = DashboardFilters;
if (typeof module !== 'undefined' && module.exports) module.exports = DashboardFilters;
