/**
 * Traffic Analyzer — from the engine's summary to the numbers on the page.
 *
 * The engine (log-parser.worker.js, ColumnarStorage) counts the requests of a
 * view. This turns its summary into what the dashboard and the report show:
 * countries, networks, addresses, traffic classes, statuses, paths, request
 * rate.
 *
 * Needs TrafficClassifier to be loaded first; GeoIP when it is there.
 */

const Analyzer = (() => {
    const CANDIDATE_RESOLUTIONS = [
        { seconds: 1, label: '1s' },
        { seconds: 2, label: '2s' },
        { seconds: 5, label: '5s' },
        { seconds: 10, label: '10s' },
        { seconds: 15, label: '15s' },
        { seconds: 30, label: '30s' },
        { seconds: 60, label: '1m' },
        { seconds: 120, label: '2m' },
        { seconds: 300, label: '5m' },
        { seconds: 600, label: '10m' },
        { seconds: 900, label: '15m' },
        { seconds: 1800, label: '30m' },
        { seconds: 3600, label: '1h' },
        { seconds: 7200, label: '2h' },
        { seconds: 14400, label: '4h' },
        { seconds: 21600, label: '6h' },
        { seconds: 43200, label: '12h' },
        { seconds: 86400, label: '1d' },
    ];

    // Requests per hour of the day and per weekday, in the log's own clock.
    function temporalDistribution(hourly, daily, totalRequests) {
        const share = count => (totalRequests ? (count / totalRequests * 100).toFixed(1) : 0);
        return {
            hourly: Array.from({ length: 24 }, (_, hour) => ({ hour, count: (hourly && hourly[hour]) || 0, percentage: share((hourly && hourly[hour]) || 0) })),
            daily: ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'].map((day_name, day) => ({
                day, day_name, count: (daily && daily[day]) || 0, percentage: share((daily && daily[day]) || 0),
            })),
        };
    }

    function securityMetrics(statusCategories, totalRequests) {
        const errors = statusCategories['4xx'] + statusCategories['5xx'];
        return { error_rate: errors, error_percentage: totalRequests ? (errors / totalRequests * 100).toFixed(1) : 0 };
    }

    /**
     * Requests per status class. Requests whose status is missing or is not
     * an HTTP status (0, 999) are counted under `other`, which is present
     * only when there are any, so the classes always add up to the requests
     * that have a status entry.
     * @param {Iterable<[number|string, number]>} statusCounts
     */
    function statusCategoriesOf(statusCounts) {
        const categories = { '1xx': 0, '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
        let other = 0;
        for (const [status, count] of statusCounts) {
            const cat = Math.floor(Number(status) / 100);
            if (cat >= 1 && cat <= 5) categories[`${cat}xx`] += count;
            else other += count;
        }
        if (other > 0) categories.other = other;
        return categories;
    }

    function formatBucketTime(ts, bucketSeconds, spanCrossesDays) {
        const d = new Date(ts);
        if (isNaN(d.getTime())) return '--';
        const h = String(d.getUTCHours()).padStart(2, '0');
        const m = String(d.getUTCMinutes()).padStart(2, '0');
        const s = String(d.getUTCSeconds()).padStart(2, '0');
        if (spanCrossesDays) {
            const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
            const mon = months[d.getUTCMonth()];
            const day = String(d.getUTCDate()).padStart(2, '0');
            return `${mon} ${day} ${h}:${m}${bucketSeconds < 60 ? ':' + s : ''}`;
        }
        if (bucketSeconds < 60) {
            return `${h}:${m}:${s}`;
        }
        return `${h}:${m}`;
    }

    function emptyRequestRate() {
        return {
            bucket_seconds: 1,
            bucket_label: '1s',
            total_buckets: 0,
            total_requests: 0,
            duration_seconds: 0,
            start_time: '--',
            end_time: '--',
            peak_rps: 0,
            peak_count: 0,
            peak_timestamp: 0,
            peak_time_str: '--',
            peak_index: 0,
            busiest_window_seconds: 1,
            busiest_window_label: 'second',
            busiest_count: 0,
            busiest_rps: 0,
            busiest_timestamp: 0,
            busiest_time_str: '--',
            avg_rps: 0,
            spike_ratio: 1,
            burst_severity: 'normal',
            burst_label: 'No Data',
            peak_error_rate: 0,
            available_resolutions: [],
            labels: [],
            buckets: [],
            top_spikes: [],
        };
    }

    /**
     * @param {Iterable<[string, number]>} siteHits - Requests per referring site; '' or '-' is "no referrer".
     * @returns {{ sites: {site: string, hits: number, pct: number}[], count: number, direct: number }}
     */
    function referrerSiteList(siteHits, totalRequests) {
        const sites = [];
        let direct = 0;
        for (const [site, hits] of siteHits) {
            if (!hits) continue;
            if (!site || site === '-') direct += hits;
            else sites.push({ site, hits, pct: totalRequests ? Math.round(hits / totalRequests * 1000) / 10 : 0 });
        }
        sites.sort((a, b) => b.hits - a.hits || (a.site < b.site ? -1 : 1));
        return { sites: sites.slice(0, 20), count: sites.length, direct };
    }

    /**
     * Requests per second of a log, counted by status class.
     *
     * The engine builds it from its columns (ColumnarStorage), for the whole
     * log or a filtered view; requestRateFromSeries turns it into the numbers
     * and chart buckets on the page.
     *
     * @typedef {object} RateSeries
     * @property {number} base - Seconds per slot. Chart intervals are multiples of it.
     * @property {ArrayLike<number>} times - Start of each slot that has requests, in seconds. Any order.
     * @property {ArrayLike<number>} total - Requests per slot; s2 to s5 by status class.
     * @property {number} minMs - Time of the first request, maxMs of the last.
     * @property {number} requests - Requests that have a time.
     * @property {number} [stray] - Requests left out because their date is far from the rest.
     */

    /**
     * The shortest stretch counted for a log of this length: one second up to
     * 20,000 seconds of log, then 5 s, 10 s and so on. The same steps as
     * ColumnarStorage.rateSeriesBase, which the engine stores its series in.
     */
    function busiestWindowSeconds(minSec, maxSec) {
        const slots = step => Math.floor(maxSec / step) - Math.floor(minSec / step) + 1;
        for (const step of [1, 5, 10, 30, 60, 300, 900, 3600]) {
            if (slots(step) <= 20000) return step;
        }
        return Math.ceil((maxSec - minSec + 1) / 20000 / 3600) * 3600;
    }

    // The stretch of `seconds` (aligned to the clock) with the most requests;
    // the earliest one when several tie.
    function busiestWindow(series, seconds) {
        const counts = new Map();
        for (let i = 0; i < series.times.length; i++) {
            const key = Math.floor(series.times[i] / seconds);
            counts.set(key, (counts.get(key) || 0) + series.total[i]);
        }
        let bestKey = 0;
        let best = 0;
        for (const [key, count] of counts) {
            if (count > best || (count === best && key < bestKey)) { best = count; bestKey = key; }
        }
        return { count: best, timestamp: bestKey * seconds * 1000 };
    }

    /**
     * Chart buckets, peak and average rate from a rate series.
     * @param {RateSeries|null} series
     * @param {{ resolution?: number|string }} [options] - Seconds per chart
     *   bucket; chosen from the span of the log when absent or 'auto'.
     */
    function requestRateFromSeries(series, options = {}) {
        if (!series || !(series.requests > 0)) return emptyRequestRate();
        const minTs = series.minMs;
        const maxTs = series.maxMs;
        const base = series.base > 0 ? series.base : 1;
        const strayTimestamps = series.stray || 0;
        const requests = series.requests;

        const durationSeconds = Math.max(1, Math.round((maxTs - minTs) / 1000));
        const spanCrossesDays = (new Date(minTs).toISOString().slice(0, 10) !== new Date(maxTs).toISOString().slice(0, 10));

        // Determine bucket seconds
        let bucketSeconds = 1;
        const requestedRes = options.resolution;
        // Count inclusive, epoch-aligned buckets, not just elapsed intervals.
        // Exactly 1,500 seconds can require 1,501 buckets at 1s resolution.
        const bucketCount = seconds => Math.floor(maxTs / (seconds * 1000)) - Math.floor(minTs / (seconds * 1000)) + 1;

        // A chart bucket is made of whole slots of the series.
        const usable = seconds => seconds % base === 0;
        const wholeSlots = seconds => Math.ceil(seconds / base) * base;

        if (requestedRes && requestedRes !== 'auto' && Number(requestedRes) > 0) {
            const desired = Number(requestedRes);
            if (usable(desired) && bucketCount(desired) <= 1500) {
                bucketSeconds = desired;
            } else {
                const safe = CANDIDATE_RESOLUTIONS.find(r => usable(r.seconds) && bucketCount(r.seconds) <= 1500);
                bucketSeconds = safe ? safe.seconds : wholeSlots(Math.ceil(durationSeconds / 1499));
            }
        } else {
            // Auto resolution targeting ~40 to 160 buckets
            const autoMatch = CANDIDATE_RESOLUTIONS.find(r => usable(r.seconds) && bucketCount(r.seconds) <= 160);
            bucketSeconds = autoMatch ? autoMatch.seconds : wholeSlots(Math.ceil(durationSeconds / 159));
        }

        const bucketMs = bucketSeconds * 1000;
        const startBucketTs = Math.floor(minTs / bucketMs) * bucketMs;
        const endBucketTs = Math.floor(maxTs / bucketMs) * bucketMs;
        const totalBuckets = Math.min(1500, Math.floor((endBucketTs - startBucketTs) / bucketMs) + 1);

        const buckets = new Array(totalBuckets);
        for (let i = 0; i < totalBuckets; i++) {
            const ts = startBucketTs + i * bucketMs;
            buckets[i] = {
                timestamp: ts,
                count: 0,
                status_2xx: 0,
                status_3xx: 0,
                status_4xx: 0,
                status_5xx: 0,
            };
        }

        for (let i = 0; i < series.times.length; i++) {
            const idx = Math.floor((series.times[i] * 1000 - startBucketTs) / bucketMs);
            if (idx >= 0 && idx < totalBuckets) {
                const b = buckets[idx];
                b.count += series.total[i];
                b.status_2xx += series.s2[i];
                b.status_3xx += series.s3[i];
                b.status_4xx += series.s4[i];
                b.status_5xx += series.s5[i];
            }
        }

        let peakRps = 0;
        let peakBucket = buckets[0] || null;
        let peakIndex = 0;
        const labels = new Array(totalBuckets);

        for (let i = 0; i < totalBuckets; i++) {
            const b = buckets[i];
            b.rps = Number((b.count / bucketSeconds).toFixed(2));
            b.rps_2xx = Number((b.status_2xx / bucketSeconds).toFixed(2));
            b.rps_3xx = Number((b.status_3xx / bucketSeconds).toFixed(2));
            b.rps_4xx = Number((b.status_4xx / bucketSeconds).toFixed(2));
            b.rps_5xx = Number((b.status_5xx / bucketSeconds).toFixed(2));
            b.label = formatBucketTime(b.timestamp, bucketSeconds, spanCrossesDays);
            labels[i] = b.label;

            if (b.rps > peakRps || (b.rps === peakRps && peakBucket === null)) {
                peakRps = b.rps;
                peakBucket = b;
                peakIndex = i;
            }
        }

        // Independent of the chart: the busiest second, or the shortest
        // stretch kept for a log this long.
        let windowSeconds = busiestWindowSeconds(Math.floor(minTs / 1000), Math.floor(maxTs / 1000));
        if (windowSeconds < base || windowSeconds % base !== 0) windowSeconds = wholeSlots(windowSeconds);
        const busiest = busiestWindow(series, windowSeconds);
        const windowLabel = windowSeconds === 1 ? 'second'
            : (CANDIDATE_RESOLUTIONS.find(r => r.seconds === windowSeconds)?.label || `${windowSeconds}s`);

        const avgRps = Number((requests / durationSeconds).toFixed(2));
        const spikeRatio = avgRps > 0 ? Number((peakRps / avgRps).toFixed(1)) : 1;

        let burstSeverity = 'normal';
        let burstLabel = 'Steady Traffic';
        if (spikeRatio >= 4.0 && peakRps >= 5.0) {
            burstSeverity = 'critical';
            burstLabel = `Critical Surge (${spikeRatio}x baseline)`;
        } else if (spikeRatio >= 2.0 && peakRps >= 2.0) {
            burstSeverity = 'elevated';
            burstLabel = `Elevated Burst (${spikeRatio}x baseline)`;
        }

        let peakErrorRate = 0;
        if (peakBucket && peakBucket.count > 0) {
            peakErrorRate = Number((((peakBucket.status_4xx + peakBucket.status_5xx) / peakBucket.count) * 100).toFixed(1));
        }

        const standardUIResolutions = [
            { seconds: 1, label: '1s' },
            { seconds: 5, label: '5s' },
            { seconds: 10, label: '10s' },
            { seconds: 30, label: '30s' },
            { seconds: 60, label: '1m' },
            { seconds: 300, label: '5m' },
        ];

        const availableResolutions = standardUIResolutions.map(r => ({
            seconds: r.seconds,
            label: r.label,
            enabled: usable(r.seconds) && bucketCount(r.seconds) <= 1500 && bucketCount(r.seconds) >= 2,
        }));

        const topSpikes = [...buckets]
            .filter(b => b.count > 0)
            .sort((a, b) => b.rps - a.rps)
            .slice(0, 3)
            .map(b => ({
                timestamp: b.timestamp,
                label: b.label,
                rps: b.rps,
                count: b.count,
                status_4xx: b.status_4xx,
                status_5xx: b.status_5xx,
            }));

        const bucketLabel = CANDIDATE_RESOLUTIONS.find(r => r.seconds === bucketSeconds)?.label || `${bucketSeconds}s`;

        return {
            bucket_seconds: bucketSeconds,
            bucket_label: bucketLabel,
            total_buckets: totalBuckets,
            total_requests: requests,
            stray_timestamps: strayTimestamps,
            duration_seconds: durationSeconds,
            start_time: formatBucketTime(minTs, bucketSeconds, spanCrossesDays),
            end_time: formatBucketTime(maxTs, bucketSeconds, spanCrossesDays),
            peak_rps: peakRps,
            peak_count: peakBucket ? peakBucket.count : 0,
            peak_timestamp: peakBucket ? peakBucket.timestamp : minTs,
            peak_time_str: peakBucket ? peakBucket.label : '--',
            peak_index: peakIndex,
            busiest_window_seconds: windowSeconds,
            busiest_window_label: windowLabel,
            busiest_count: busiest.count,
            busiest_rps: Number((busiest.count / windowSeconds).toFixed(2)),
            busiest_timestamp: busiest.timestamp,
            busiest_time_str: formatBucketTime(busiest.timestamp, windowSeconds, spanCrossesDays),
            avg_rps: avgRps,
            spike_ratio: spikeRatio,
            burst_severity: burstSeverity,
            burst_label: burstLabel,
            peak_error_rate: peakErrorRate,
            available_resolutions: availableResolutions,
            labels,
            buckets,
            top_spikes: topSpikes,
        };
    }

    function emptyEnhancedResult() {
        return {
            ...emptyResult(),
            http_metrics: {
                status_categories: { '1xx': 0, '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 },
                status_hits: [], method_hits: [], top_urls: [], top_paths: [],
                other_paths: { paths: 0, count: 0, percentage: '0.0' }, distinct_paths: 0, path_sections: [],
                response_size: { total: 0, average: 0, median: 0, min: 0, max: 0 },
            },
            temporal_distribution: {
                hourly: Array(24).fill(0).map((_, h) => ({ hour: h, count: 0, percentage: 0 })),
                daily: Array(7).fill(0).map((_, d) => ({
                    day: d, day_name: ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'][d], count: 0, percentage: 0,
                })),
            },
            request_rate: emptyRequestRate(),
            security_metrics: { error_rate: 0, error_percentage: 0 },
        };
    }

    function emptyResult() {
        return {
            total_requests: 0, unique_ips: 0, unique_countries: 0, unique_asns: 0,
            country_hits: [], asn_hits: [], top_ips: [], bot_groups: [], bot_hits: [], human_requests: 0,
            traffic_classes: TrafficClassifier.aggregate([]).traffic_classes,
            verified_bots_count: 0, spoofed_bots_count: 0, unverified_bots_count: 0,
            automated_count: 0, suspected_count: 0, other_bots_count: 0,
            verified_bot_ips_count: 0, spoofed_bot_ips_count: 0,
            spoofed_bot_attackers: [], spoofed_bot_ips: [], suspected_clients: [],
        };
    }

    function analyzeFromWorkerSummary(summary) {
        if (!summary) return emptyEnhancedResult();

        const totalRequests = summary.matchingCount || 0;
        const uniqueIps = summary.uniqueIps || 0;

        const noIps = { unique_ips: 0, ip_details: [] };
        const countryHits = Object.entries(summary.countryCounts || {})
            .map(([code, hits]) => {
                const known = code && code !== '-' && code !== '--';
                const ips = (summary.countryIps && summary.countryIps[code]) || noIps;
                return {
                    country: known ? ((summary.countryNames && summary.countryNames[code]) || code) : 'Unknown',
                    country_code: known ? code : '--',
                    hits,
                    unique_ips: ips.unique_ips,
                    ip_details: ips.ip_details,
                };
            })
            .sort((a, b) => b.hits - a.hits || (a.country < b.country ? -1 : (a.country > b.country ? 1 : 0)));

        const asnHits = Object.entries(summary.asnHits || {})
            .map(([key, hits]) => {
                const asn = Number(String(key).replace(/^AS/i, '')) || 0;
                const ips = (summary.asnIps && summary.asnIps[key]) || noIps;
                return {
                    asn,
                    asn_org: (summary.asnOrgMap && summary.asnOrgMap[key]) || (asn > 0 && typeof GeoIP !== 'undefined' && GeoIP.lookupASNOrg ? GeoIP.lookupASNOrg(asn) : '') || 'Unknown',
                    hits,
                    unique_ips: ips.unique_ips,
                    ip_details: ips.ip_details,
                };
            })
            .sort((a, b) => b.hits - a.hits || a.asn - b.asn);

        // Traffic classes and bot groups. The worker classifies every client
        // and sends the result as `summary.traffic`. A summary without it
        // (older worker, tests) only has bot names: those are listed as
        // unverified, and the parser's "no bot" markers are not bots at all.
        let traffic = summary.traffic;
        if (!traffic) {
            const NOT_A_BOT = new Set(['None', 'Human', '-', '']);
            const items = [];
            let named = 0;
            for (const [name, count] of Object.entries(summary.botCounts || {})) {
                if (NOT_A_BOT.has(name)) continue;
                named += count;
                items.push({
                    client: { ip: name, ua: '', cls: 'unverified', name, group: name, reason: 'Named by User-Agent only', verified: null },
                    count,
                });
            }
            items.push({
                client: { ip: '', ua: '', cls: 'human', name: null, group: null, reason: '', verified: null },
                count: Math.max(0, totalRequests - named),
            });
            traffic = TrafficClassifier.aggregate(items);
            for (const g of traffic.bot_groups) {
                g.unique_ips = 0;
                for (const sb of g.sub_bots) { sb.unique_ips = 0; sb.ip_details = []; }
            }
        }

        // HTTP Status categories
        const statusCategories = statusCategoriesOf(Object.entries(summary.statusCounts || {}));
        const statusHits = Object.entries(summary.statusCounts || {})
            .map(([codeStr, count]) => {
                const code = parseInt(codeStr, 10);
                return {
                    code,
                    count,
                    percentage: totalRequests ? ((count / totalRequests) * 100).toFixed(1) : '0.0'
                };
            })
            .sort((a, b) => b.count - a.count);

        // The worker sends requests per time slot; summaries from before it
        // did have hourly counts only.
        let reqRateObj;
        if (summary.rateSeries) {
            reqRateObj = requestRateFromSeries(summary.rateSeries);
        } else {
            const rateBuckets = Array.isArray(summary.timeBuckets)
                ? summary.timeBuckets.map(b => ({
                    timestamp: b.timestamp || (b.time ? b.time * 1000 : 0),
                    count: b.count || b.total || 0,
                    rps: b.rps || 0,
                    status_2xx: b.status_2xx || 0,
                    status_3xx: b.status_3xx || 0,
                    status_4xx: b.status_4xx || b.error || 0,
                    status_5xx: b.status_5xx || 0,
                    label: b.label || ''
                }))
                : Object.entries(summary.timeBuckets || {})
                    .sort((a, b) => Number(a[0]) - Number(b[0]))
                    .map(([secStr, count]) => {
                        const ts = Number(secStr) * 1000;
                        return {
                            timestamp: ts,
                            count: count || 0,
                            rps: Number(((count || 0) / 3600).toFixed(2)),
                            status_2xx: 0, status_3xx: 0, status_4xx: 0, status_5xx: 0,
                            label: new Date(ts).toISOString().slice(11, 16)
                        };
                    });
            reqRateObj = {
                ...emptyRequestRate(),
                buckets: rateBuckets,
                data_points: rateBuckets,
                bucket_seconds: 3600,
                bucket_label: '1h',
                total_buckets: rateBuckets.length,
                peak_rps: rateBuckets.length ? Math.max(...rateBuckets.map(b => b.rps)) : 0,
            };
        }

        const topIps = (summary.topIps || []).map(item => {
            const geo = (summary.ipGeoMap && summary.ipGeoMap[item.ip]) || {};
            return {
                ip: item.ip,
                hits: item.hits,
                country: geo.country || 'Unknown',
                country_code: geo.country_code || '--',
                asn: geo.asn || 0,
                asn_org: geo.asn_org || 'Unknown'
            };
        });

        // HTTP Methods
        const methodHits = Object.entries(summary.methodCounts || {})
            .map(([method, count]) => ({
                method,
                count,
                percentage: totalRequests ? ((count / totalRequests) * 100).toFixed(1) : '0.0'
            }))
            .sort((a, b) => b.count - a.count);

        const referrerSites = referrerSiteList(summary.referrerSites || [], totalRequests);
        const size = summary.responseSize || {};

        const workerPaths = summary.paths || { top_paths: [], other_paths: { paths: 0, count: 0, percentage: '0.0' }, distinct_paths: 0, sections: [] };

        return {
            total_requests: totalRequests,
            unique_ips: uniqueIps,
            unique_countries: countryHits.filter(c => c.country !== 'Unknown').length,
            unique_asns: asnHits.filter(a => Number(a.asn) > 0).length,
            country_hits: countryHits,
            asn_hits: asnHits,
            top_ips: topIps,
            bot_groups: traffic.bot_groups,
            bot_hits: traffic.bot_groups,
            traffic_classes: traffic.traffic_classes,
            human_requests: traffic.human_requests,
            verified_bots_count: traffic.verified_bots_count,
            spoofed_bots_count: traffic.spoofed_bots_count,
            unverified_bots_count: traffic.unverified_bots_count,
            automated_count: traffic.automated_count,
            suspected_count: traffic.suspected_count,
            other_bots_count: traffic.other_bots_count,
            verified_bot_ips_count: traffic.verified_bot_ips_count,
            spoofed_bot_ips_count: traffic.spoofed_bot_ips_count,
            spoofed_bot_attackers: traffic.spoofed_bot_attackers,
            spoofed_bot_ips: traffic.spoofed_bot_ips,
            suspected_clients: traffic.suspected_clients,
            ua_field_missing: Boolean(summary.uaFieldMissing),
            http_metrics: {
                status_categories: statusCategories,
                status_hits: statusHits,
                method_hits: methodHits,
                top_urls: workerPaths.top_paths.slice(0, 20).map(p => ({ url: p.path, count: p.count, percentage: p.percentage, status_breakdown: p.status_breakdown })),
                top_paths: workerPaths.top_paths,
                other_paths: workerPaths.other_paths,
                distinct_paths: workerPaths.distinct_paths,
                path_sections: workerPaths.sections,
                response_size: {
                    total: summary.totalBytes || 0,
                    average: totalRequests ? Math.round((summary.totalBytes || 0) / totalRequests) : 0,
                    median: size.median || 0,
                    min: size.min || 0,
                    max: size.max || 0,
                },
            },
            temporal_distribution: temporalDistribution(summary.hourly, summary.daily, totalRequests),
            request_rate: reqRateObj,
            referrer_sites: referrerSites.sites,
            referrer_site_count: summary.referrerSiteCount ?? referrerSites.count,
            direct_requests: referrerSites.direct,
            security_metrics: securityMetrics(statusCategories, totalRequests),
        };
    }

    return { analyzeFromWorkerSummary, requestRateFromSeries };
})();

if (typeof window !== 'undefined') window.Analyzer = Analyzer;
if (typeof self !== 'undefined') self.Analyzer = Analyzer;
if (typeof module !== 'undefined' && module.exports) module.exports = Analyzer;
