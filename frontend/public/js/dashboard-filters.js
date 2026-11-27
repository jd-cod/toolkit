/**
 * Traffic Analyzer — the dashboard's filters, without any page access.
 *
 * What a filter means for a list of requests (pasted logs), which choices the
 * dropdowns offer, and the same filters in the form the upload worker takes.
 * The page state and the markup live in dashboard.js.
 *
 * Needs RequestPaths and LogParser to be loaded first.
 */
const DashboardFilters = (() => {
    const TRAFFIC_CLASSES = ['human', 'verified', 'spoofed', 'unverified', 'automated', 'suspected'];

    function dependency(name) {
        const found = typeof globalThis !== 'undefined' ? globalThis[name] : undefined;
        if (!found) throw new Error(`DashboardFilters needs ${name} to be loaded first.`);
        return found;
    }

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

    /** Traffic class of a request; entries from before the classifier carry only a bot status. */
    function trafficClassOf(entry) {
        if (entry.traffic_class) return entry.traffic_class;
        if (entry.bot_status === 'human' || (!entry.is_bot && !entry.bot_name)) return 'human';
        if (entry.bot_status === 'verified' || entry.bot_status === 'spoofed') return entry.bot_status;
        return 'unverified';
    }

    function timeOf(entry) {
        const t = entry.timestamp;
        if (t == null) return NaN;
        return t instanceof Date ? t.getTime() : (typeof t === 'number' ? t : new Date(t).getTime());
    }

    /**
     * The requests that pass the filters.
     *
     * @param {object[]} entries - Enriched log entries.
     * @param {object} filters - See `none()`.
     * @param {{ startMs: number, endMs: number|null, keepUntimed: boolean }|null} [timeWindow]
     *   The chosen stretch of the log. `keepUntimed` lets requests without a
     *   readable time through ("last 30 minutes"); the handles do not.
     */
    function apply(entries, filters, timeWindow = null) {
        let result = entries;

        if (timeWindow) {
            const { startMs, endMs, keepUntimed } = timeWindow;
            result = result.filter(e => {
                const ms = timeOf(e);
                if (!Number.isFinite(ms)) return Boolean(keepUntimed) && !e.timestamp;
                return ms >= startMs && (endMs == null || ms <= endMs);
            });
        }

        if (filters.statusCategory !== 'all') {
            const wanted = filters.statusCategory;
            const code = Number(wanted);
            result = result.filter(e => {
                const status = e.status_code || 0;
                if (/^[1-5]xx$/.test(wanted)) return Math.floor(status / 100) === Number(wanted[0]);
                // No status, or a number that is not an HTTP status.
                if (wanted === 'other') return !(status >= 100 && status <= 599);
                return code > 0 ? status === code : true;
            });
        }

        if (filters.method !== 'all') result = result.filter(e => (e.method || '').toUpperCase() === filters.method.toUpperCase());
        if (filters.country !== 'all') result = result.filter(e => e.country === filters.country);
        // Entries carry 'AS15169', the network table sends the bare number.
        if (filters.asn !== 'all') {
            const want = String(filters.asn).replace(/^AS/i, '');
            result = result.filter(e => String(e.asn ?? '').replace(/^AS/i, '') === want);
        }

        if (filters.bot !== 'all') {
            if (filters.bot === 'all_bots') result = result.filter(e => trafficClassOf(e) !== 'human');
            else if (TRAFFIC_CLASSES.includes(filters.bot)) result = result.filter(e => trafficClassOf(e) === filters.bot);
            else result = result.filter(e => e.bot_group === filters.bot);
            if (filters.botGroup) result = result.filter(e => e.bot_group === filters.botGroup);
        }

        if (filters.pathSearch) {
            const matchesPath = dependency('RequestPaths').pathMatcher(filters.pathSearch);
            result = result.filter(e => e.url && matchesPath(e.url));
        }

        if (filters.ipSearch && filters.ipSearch.trim()) {
            // A full address, the start of one, or a CIDR block.
            const matchesIp = dependency('LogParser').ipFilterMatcher(filters.ipSearch);
            result = result.filter(e => e.ip && matchesIp(e.ip));
        }

        if (filters.uaSearch && filters.uaSearch.trim()) {
            const term = filters.uaSearch.trim().toLowerCase();
            result = result.filter(e => (e.user_agent || '').toLowerCase().includes(term));
        }

        return result;
    }

    /** The filters as the upload worker takes them: the time window in seconds. */
    function forWorker(filters, timeWindow = null) {
        const out = Object.assign({}, filters);
        if (timeWindow) {
            out.startTimeSec = Math.floor(timeWindow.startMs / 1000);
            if (timeWindow.endMs != null) out.endTimeSec = Math.floor(timeWindow.endMs / 1000);
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

    /**
     * What the dropdowns offer, from the analysis of the whole log. Both
     * engines give the same analysis, so this is the one place for it.
     */
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

    return { TRAFFIC_CLASSES, none, count, isActive, trafficClassOf, apply, forWorker, statusOptions, options };
})();

if (typeof window !== 'undefined') window.DashboardFilters = DashboardFilters;
if (typeof globalThis !== 'undefined') globalThis.DashboardFilters = DashboardFilters;
if (typeof module !== 'undefined' && module.exports) module.exports = DashboardFilters;
