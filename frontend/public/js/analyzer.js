/**
 * Log Analysis Engine — Client-Side
 * 
 * Port of Python analyze_logs() function.
 * Takes parsed IPs + user agents + GeoIP lookups and produces
 * country hits, ASN hits, top IPs, bot breakdown (with sub-groups), etc.
 */

const Analyzer = (() => {
    /**
     * Analyze extracted IPs and produce security-focused metrics.
     */
    function analyzeLogs(ips, userAgents, logEntries) {
        if (!ips || ips.length === 0) return emptyResult();
        if (!userAgents) userAgents = new Array(ips.length).fill('-');

        // Count hits per IP
        const ipCounter = new Map();
        for (const ip of ips) {
            ipCounter.set(ip, (ipCounter.get(ip) || 0) + 1);
        }

        // Store raw log lines per IP for access log viewer
        const ipLogEntries = new Map();
        if (logEntries) {
            for (const entry of logEntries) {
                if (!ipLogEntries.has(entry.ip)) ipLogEntries.set(entry.ip, []);
                ipLogEntries.get(entry.ip).push(entry);
            }
        }

        // GeoIP lookups for unique IPs
        const countryCounter = new Map();
        const asnCounter = new Map();
        const countryIPs = new Map();
        const asnIPs = new Map();
        const asnOrgMap = new Map();

        for (const [ipStr, count] of ipCounter) {
            const info = GeoIP.lookupIP(ipStr);
            const countryKey = info.country;
            const asnKey = info.asn;

            countryCounter.set(countryKey, (countryCounter.get(countryKey) || 0) + count);
            asnCounter.set(asnKey, (asnCounter.get(asnKey) || 0) + count);

            if (!countryIPs.has(countryKey)) countryIPs.set(countryKey, new Set());
            countryIPs.get(countryKey).add(ipStr);

            if (!asnIPs.has(asnKey)) asnIPs.set(asnKey, new Set());
            asnIPs.get(asnKey).add(ipStr);

            asnOrgMap.set(asnKey, info.asn_org);
        }

        // Bot detection and verification with sub-grouping
        const botGroupData = new Map();  // groupName -> { requests, ips: Set, verifiedReqs: 0, spoofedReqs: 0, unverifiedReqs: 0, subBots: Map }
        const botCounter = new Map();
        const botIPs = new Map();
        const botIPHits = new Map();
        const botIPUA = new Map();
        let humanCount = 0;
        let verifiedBotsCount = 0;
        let spoofedBotsCount = 0;
        let unverifiedBotsCount = 0;
        const verifiedBotIPs = new Set();
        const spoofedBotIPs = new Set();
        const spoofedAttackersMap = new Map(); // "ip|botName" -> details

        for (let i = 0; i < ips.length; i++) {
            const ip = ips[i];
            const ua = userAgents[i];
            const botResult = BotDetector.detectBot(ua);
            if (botResult) {
                const { name, group } = botResult;
                const groupName = group || name;
                const verifyResult = BotDetector.verifyBot(name, ip);

                if (verifyResult.status === 'verified') {
                    verifiedBotsCount++;
                    verifiedBotIPs.add(ip);
                } else if (verifyResult.status === 'spoofed') {
                    spoofedBotsCount++;
                    spoofedBotIPs.add(ip);
                    const spoofKey = `${ip}|${name}`;
                    if (!spoofedAttackersMap.has(spoofKey)) {
                        const info = GeoIP.lookupIP(ip);
                        spoofedAttackersMap.set(spoofKey, {
                            ip,
                            bot_name: name,
                            group_name: groupName,
                            hits: 0,
                            country: info.country || 'Unknown',
                            country_code: info.country_code || '--',
                            asn: info.asn ? `AS${info.asn}` : 'AS0',
                            asn_org: info.asn_org || 'Unknown',
                            user_agent: ua,
                            reason: verifyResult.reason,
                        });
                    }
                    spoofedAttackersMap.get(spoofKey).hits++;
                } else {
                    unverifiedBotsCount++;
                }

                // Track per-group
                if (!botGroupData.has(groupName)) {
                    botGroupData.set(groupName, {
                        requests: 0,
                        ips: new Set(),
                        verifiedReqs: 0,
                        spoofedReqs: 0,
                        unverifiedReqs: 0,
                        subBots: new Map(),
                    });
                }
                const gd = botGroupData.get(groupName);
                gd.requests++;
                gd.ips.add(ip);
                if (verifyResult.status === 'verified') gd.verifiedReqs++;
                else if (verifyResult.status === 'spoofed') gd.spoofedReqs++;
                else gd.unverifiedReqs++;

                // Track sub-bot within group
                if (!gd.subBots.has(name)) {
                    gd.subBots.set(name, {
                        requests: 0,
                        ips: new Set(),
                        ipHits: new Map(),
                        ipUA: new Map(),
                        ipVerify: new Map(),
                        verifiedReqs: 0,
                        spoofedReqs: 0,
                        unverifiedReqs: 0,
                    });
                }
                const sb = gd.subBots.get(name);
                sb.requests++;
                sb.ips.add(ip);
                sb.ipHits.set(ip, (sb.ipHits.get(ip) || 0) + 1);
                sb.ipUA.set(ip, ua);
                sb.ipVerify.set(ip, verifyResult);
                if (verifyResult.status === 'verified') sb.verifiedReqs++;
                else if (verifyResult.status === 'spoofed') sb.spoofedReqs++;
                else sb.unverifiedReqs++;

                // Legacy flat tracking
                botCounter.set(name, (botCounter.get(name) || 0) + 1);
                if (!botIPs.has(name)) botIPs.set(name, new Set());
                botIPs.get(name).add(ip);
                if (!botIPHits.has(name)) botIPHits.set(name, new Map());
                botIPHits.get(name).set(ip, (botIPHits.get(name).get(ip) || 0) + 1);
                if (!botIPUA.has(name)) botIPUA.set(name, new Map());
                botIPUA.get(name).set(ip, ua);
            } else {
                humanCount++;
            }
        }

        // Build sorted country hits
        const countryHits = [...countryCounter.entries()]
            .sort((a, b) => b[1] - a[1])
            .map(([country, hits]) => {
                let countryCode = '--';
                const ipsInCountry = countryIPs.get(country);
                if (ipsInCountry) {
                    for (const ip of ipsInCountry) {
                        const info = GeoIP.lookupCountry(ip);
                        if (info.country_code !== '--') { countryCode = info.country_code; break; }
                    }
                }
                return {
                    country, country_code: countryCode, hits,
                    unique_ips: ipsInCountry ? ipsInCountry.size : 0,
                    ip_details: ipsInCountry ?
                        [...ipsInCountry].map(ip => ({ ip, hits: ipCounter.get(ip) || 0 }))
                            .sort((a, b) => b.hits - a.hits) : [],
                };
            });

        // Build sorted ASN hits
        const asnHits = [...asnCounter.entries()]
            .sort((a, b) => b[1] - a[1])
            .map(([asn, hits]) => ({
                asn, asn_org: asnOrgMap.get(asn) || 'Unknown', hits,
                unique_ips: asnIPs.get(asn) ? asnIPs.get(asn).size : 0,
                ip_details: asnIPs.get(asn) ?
                    [...asnIPs.get(asn)].map(ip => ({ ip, hits: ipCounter.get(ip) || 0 }))
                        .sort((a, b) => b.hits - a.hits) : [],
            }));

        // Top 50 IPs
        const topIPs = [...ipCounter.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 50)
            .map(([ipStr, hits]) => {
                const info = GeoIP.lookupIP(ipStr);
                return { ip: ipStr, hits, country: info.country, country_code: info.country_code, asn: info.asn, asn_org: info.asn_org };
            });

        // Bot hits grouped (top 20 groups) with verification statuses
        const totalRequests = ips.length;
        const botGroups = [...botGroupData.entries()]
            .sort((a, b) => b[1].requests - a[1].requests)
            .slice(0, 20)
            .map(([groupName, gd]) => {
                const subBots = [...gd.subBots.entries()]
                    .sort((a, b) => b[1].requests - a[1].requests)
                    .map(([subName, sb]) => {
                        let subStatus = 'unverified';
                        if (sb.spoofedReqs > 0 && sb.verifiedReqs > 0) subStatus = 'mixed';
                        else if (sb.spoofedReqs > 0) subStatus = 'spoofed';
                        else if (sb.verifiedReqs > 0) subStatus = 'verified';

                        return {
                            bot_name: subName,
                            requests: sb.requests,
                            unique_ips: sb.ips.size,
                            pct: totalRequests ? Math.round(sb.requests / totalRequests * 1000) / 10 : 0,
                            verified_requests: sb.verifiedReqs,
                            spoofed_requests: sb.spoofedReqs,
                            unverified_requests: sb.unverifiedReqs,
                            verification_status: subStatus,
                            ip_details: [...sb.ips].map(ip => {
                                const v = sb.ipVerify.get(ip) || { verified: null, status: 'unverified_publisher', reason: 'Unverified' };
                                return {
                                    ip,
                                    hits: sb.ipHits.get(ip) || 0,
                                    user_agent: sb.ipUA.get(ip) || '-',
                                    verified: v.verified,
                                    status: v.status,
                                    reason: v.reason,
                                };
                            }).sort((a, b) => b.hits - a.hits),
                        };
                    });

                let groupStatus = 'unverified';
                if (gd.spoofedReqs > 0 && gd.verifiedReqs > 0) groupStatus = 'mixed';
                else if (gd.spoofedReqs > 0) groupStatus = 'spoofed';
                else if (gd.verifiedReqs > 0) groupStatus = 'verified';

                return {
                    group_name: groupName,
                    requests: gd.requests,
                    unique_ips: gd.ips.size,
                    pct: totalRequests ? Math.round(gd.requests / totalRequests * 1000) / 10 : 0,
                    verified_requests: gd.verifiedReqs,
                    spoofed_requests: gd.spoofedReqs,
                    unverified_requests: gd.unverifiedReqs,
                    verification_status: groupStatus,
                    sub_bots: subBots,
                    has_sub_groups: subBots.length > 1,
                };
            });

        const spoofedAttackers = [...spoofedAttackersMap.values()].sort((a, b) => b.hits - a.hits);
        const uniqueSpoofedIPs = [...spoofedBotIPs];

        return {
            total_requests: totalRequests,
            unique_ips: ipCounter.size,
            unique_countries: countryIPs.size,
            unique_asns: asnIPs.size,
            country_hits: countryHits,
            asn_hits: asnHits,
            top_ips: topIPs,
            bot_groups: botGroups,
            bot_hits: botGroups, // backward compat alias
            human_requests: humanCount,
            verified_bots_count: verifiedBotsCount,
            spoofed_bots_count: spoofedBotsCount,
            unverified_bots_count: unverifiedBotsCount,
            verified_bot_ips_count: verifiedBotIPs.size,
            spoofed_bot_ips_count: spoofedBotIPs.size,
            spoofed_bot_attackers: spoofedAttackers,
            spoofed_bot_ips: uniqueSpoofedIPs,
            ip_log_entries: ipLogEntries, // Map<ip, logEntry[]> for access log viewer
        };
    }

    /**
     * Enhanced log analysis using full log entries with HTTP method, status, URL, etc.
     */
    function analyzeEnhancedLogs(logEntries) {
        if (!logEntries || logEntries.length === 0) return emptyEnhancedResult();

        const totalRequests = logEntries.length;
        const ips = logEntries.map(e => e.ip);
        const userAgents = logEntries.map(e => e.user_agent || '-');

        // Run basic analysis with logEntries passed for per-IP log tracking
        const basicResult = analyzeLogs(ips, userAgents, logEntries);

        // HTTP Status Code Analysis
        const statusCounter = new Map();
        const methodCounter = new Map();
        const urlCounter = new Map();
        const pathCounter = new Map();
        const urlByStatus = new Map();
        let totalResponseSize = 0;
        const responseSizes = [];
        const hourlyCounter = new Array(24).fill(0);
        const dailyCounter = new Array(7).fill(0);

        for (const entry of logEntries) {
            if (entry.status_code !== null && !isNaN(entry.status_code)) {
                statusCounter.set(entry.status_code, (statusCounter.get(entry.status_code) || 0) + 1);
            }
            if (entry.method) {
                const method = entry.method.toUpperCase();
                methodCounter.set(method, (methodCounter.get(method) || 0) + 1);
            }
            if (entry.url) {
                const simpleUrl = entry.url.split('?')[0];
                urlCounter.set(simpleUrl, (urlCounter.get(simpleUrl) || 0) + 1);
                if (entry.status_code !== null) {
                    if (!urlByStatus.has(simpleUrl)) urlByStatus.set(simpleUrl, new Map());
                    const statusMap = urlByStatus.get(simpleUrl);
                    statusMap.set(entry.status_code, (statusMap.get(entry.status_code) || 0) + 1);
                }
                // Extract path segments for Top Paths (like: /admin/, /api/, /wp-login/)
                const pathSegments = simpleUrl.match(/\/[a-zA-Z0-9_.-]+/g);
                if (pathSegments) {
                    for (const seg of pathSegments) {
                        pathCounter.set(seg, (pathCounter.get(seg) || 0) + 1);
                    }
                }
            }
            if (entry.response_size !== null && !isNaN(entry.response_size)) {
                totalResponseSize += entry.response_size;
                responseSizes.push(entry.response_size);
            }
            if (entry.timestamp) {
                const date = new Date(entry.timestamp);
                hourlyCounter[date.getUTCHours()]++;
                dailyCounter[date.getUTCDay()]++;
            }
        }

        const statusCategories = { '1xx': 0, '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
        for (const [status, count] of statusCounter.entries()) {
            const cat = Math.floor(status / 100);
            if (cat >= 1 && cat <= 5) statusCategories[`${cat}xx`] += count;
        }

        const statusHits = [...statusCounter.entries()]
            .sort((a, b) => b[1] - a[1])
            .map(([code, count]) => ({ code, count, percentage: totalRequests ? (count / totalRequests * 100).toFixed(1) : 0 }));

        const methodHits = [...methodCounter.entries()]
            .sort((a, b) => b[1] - a[1])
            .map(([method, count]) => ({ method, count, percentage: totalRequests ? (count / totalRequests * 100).toFixed(1) : 0 }));

        const topUrls = [...urlCounter.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 20)
            .map(([url, count]) => {
                const statusMap = urlByStatus.get(url) || new Map();
                return {
                    url, count,
                    percentage: totalRequests ? (count / totalRequests * 100).toFixed(1) : 0,
                    status_breakdown: [...statusMap.entries()].sort((a, b) => b[1] - a[1]).map(([code, c]) => ({ code, count: c })),
                };
            });

        // Top paths (path segments extracted like awk/grep -oE '/[a-zA-Z0-9_.-]+/')
        const topPaths = [...pathCounter.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 30)
            .map(([path, count]) => ({
                path, count,
                percentage: totalRequests ? (count / totalRequests * 100).toFixed(1) : 0,
            }));

        // Referrers Counter
        const referrerCounter = new Map();
        for (let i = 0; i < logEntries.length; i++) {
            const ref = logEntries[i].referrer || '-';
            referrerCounter.set(ref, (referrerCounter.get(ref) || 0) + 1);
        }
        const referrers = [...referrerCounter.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 20)
            .map(([referrer, hits]) => ({
                referrer,
                hits,
                pct: totalRequests ? Math.round(hits / totalRequests * 1000) / 10 : 0,
            }));

        let avgResponseSize = 0, medianResponseSize = 0;
        let minResponseSize = 0, maxResponseSize = 0;
        if (responseSizes.length > 0) {
            avgResponseSize = Math.round(totalResponseSize / responseSizes.length);
            const sorted = [...responseSizes].sort((a, b) => a - b);
            const mid = Math.floor(sorted.length / 2);
            medianResponseSize = sorted.length % 2 !== 0 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) / 2);
            minResponseSize = sorted[0];
            maxResponseSize = sorted[sorted.length - 1];
        }

        return {
            ...basicResult,
            http_metrics: {
                status_categories: statusCategories,
                status_hits: statusHits,
                method_hits: methodHits,
                top_urls: topUrls,
                top_paths: topPaths,
                response_size: {
                    total: totalResponseSize, average: avgResponseSize, median: medianResponseSize,
                    min: minResponseSize,
                    max: maxResponseSize,
                },
            },
            temporal_distribution: {
                hourly: hourlyCounter.map((count, hour) => ({ hour, count, percentage: totalRequests ? (count / totalRequests * 100).toFixed(1) : 0 })),
                daily: dailyCounter.map((count, day) => ({
                    day, day_name: ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'][day],
                    count, percentage: totalRequests ? (count / totalRequests * 100).toFixed(1) : 0,
                })),
            },
            request_rate: computeRequestRate(logEntries),
            referrers: referrers,
            security_metrics: {
                error_rate: statusCategories['4xx'] + statusCategories['5xx'],
                error_percentage: totalRequests ? ((statusCategories['4xx'] + statusCategories['5xx']) / totalRequests * 100).toFixed(1) : 0,
            },
        };
    }

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

    function computeRequestRate(logEntries, options = {}) {
        if (!logEntries || logEntries.length === 0) return emptyRequestRate();

        const validEntries = [];
        let minTs = Infinity;
        let maxTs = -Infinity;

        for (const entry of logEntries) {
            if (!entry.timestamp) continue;
            const ts = entry.timestamp instanceof Date
                ? entry.timestamp.getTime()
                : (typeof entry.timestamp === 'number' ? entry.timestamp : new Date(entry.timestamp).getTime());
            if (!isNaN(ts)) {
                validEntries.push({ ...entry, _ts: ts });
                if (ts < minTs) minTs = ts;
                if (ts > maxTs) maxTs = ts;
            }
        }

        if (validEntries.length === 0) return emptyRequestRate();

        const durationSeconds = Math.max(1, Math.round((maxTs - minTs) / 1000));
        const spanCrossesDays = (new Date(minTs).toISOString().slice(0, 10) !== new Date(maxTs).toISOString().slice(0, 10));

        // Determine bucket seconds
        let bucketSeconds = 1;
        const requestedRes = options.resolution;
        // Count inclusive, epoch-aligned buckets, not just elapsed intervals.
        // Exactly 1,500 seconds can require 1,501 buckets at 1s resolution.
        const bucketCount = seconds => Math.floor(maxTs / (seconds * 1000)) - Math.floor(minTs / (seconds * 1000)) + 1;

        if (requestedRes && requestedRes !== 'auto' && Number(requestedRes) > 0) {
            const desired = Number(requestedRes);
            if (bucketCount(desired) <= 1500) {
                bucketSeconds = desired;
            } else {
                const safe = CANDIDATE_RESOLUTIONS.find(r => bucketCount(r.seconds) <= 1500);
                bucketSeconds = safe ? safe.seconds : Math.ceil(durationSeconds / 1499);
            }
        } else {
            // Auto resolution targeting ~40 to 160 buckets
            const autoMatch = CANDIDATE_RESOLUTIONS.find(r => bucketCount(r.seconds) <= 160);
            bucketSeconds = autoMatch ? autoMatch.seconds : Math.ceil(durationSeconds / 159);
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

        for (let i = 0; i < validEntries.length; i++) {
            const entry = validEntries[i];
            const idx = Math.floor((entry._ts - startBucketTs) / bucketMs);
            if (idx >= 0 && idx < totalBuckets) {
                const b = buckets[idx];
                b.count++;
                const code = entry.status_code;
                if (code >= 200 && code < 300) b.status_2xx++;
                else if (code >= 300 && code < 400) b.status_3xx++;
                else if (code >= 400 && code < 500) b.status_4xx++;
                else if (code >= 500 && code < 600) b.status_5xx++;
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

        const avgRps = Number((validEntries.length / durationSeconds).toFixed(2));
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
            enabled: bucketCount(r.seconds) <= 1500 && bucketCount(r.seconds) >= 2,
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
            total_requests: validEntries.length,
            duration_seconds: durationSeconds,
            start_time: formatBucketTime(minTs, bucketSeconds, spanCrossesDays),
            end_time: formatBucketTime(maxTs, bucketSeconds, spanCrossesDays),
            peak_rps: peakRps,
            peak_count: peakBucket ? peakBucket.count : 0,
            peak_timestamp: peakBucket ? peakBucket.timestamp : minTs,
            peak_time_str: peakBucket ? peakBucket.label : '--',
            peak_index: peakIndex,
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
            verified_bots_count: 0, spoofed_bots_count: 0, unverified_bots_count: 0,
            verified_bot_ips_count: 0, spoofed_bot_ips_count: 0,
            spoofed_bot_attackers: [], spoofed_bot_ips: [],
            ip_log_entries: new Map(),
        };
    }

    /**
     * Enrich raw parsed log entries with GeoIP and Bot detection data upfront.
     * This avoids repeated lookups when filtering or exploring logs.
     */
    function enrichLogEntries(logEntries) {
        if (!logEntries || !Array.isArray(logEntries)) return;
        const ipGeoCache = new Map();
        const uaBotCache = new Map();
        const verifyCache = new Map();

        for (const entry of logEntries) {
            // GeoIP lookup & cache
            if (!ipGeoCache.has(entry.ip)) {
                ipGeoCache.set(entry.ip, GeoIP.lookupIP(entry.ip));
            }
            const geo = ipGeoCache.get(entry.ip);
            entry.country = geo.country || 'Unknown';
            entry.country_code = geo.country_code || '--';
            entry.asn = geo.asn ? `AS${geo.asn}` : 'AS0';
            entry.asn_num = geo.asn || 0;
            entry.asn_org = geo.asn_org || 'Unknown';

            // Bot detection & verification cache
            const ua = entry.user_agent || '-';
            if (!uaBotCache.has(ua)) {
                uaBotCache.set(ua, BotDetector.detectBot(ua));
            }
            const bot = uaBotCache.get(ua);
            if (bot) {
                const verifyKey = `${bot.name}|${entry.ip}`;
                if (!verifyCache.has(verifyKey)) {
                    verifyCache.set(verifyKey, BotDetector.verifyBot(bot.name, entry.ip));
                }
                const v = verifyCache.get(verifyKey);

                entry.is_bot = true;
                entry.bot_name = bot.name;
                entry.bot_group = bot.group || bot.name;
                entry.bot_verified = v.verified;
                entry.bot_status = v.status;
                entry.bot_reason = v.reason;
            } else {
                entry.is_bot = false;
                entry.bot_name = null;
                entry.bot_group = null;
                entry.bot_verified = null;
                entry.bot_status = 'human';
                entry.bot_reason = 'Human traffic';
            }
        }
    }

    function generateNginxDeny(ips) { return ips.map(ip => `deny ${ip};`).join('\n'); }

    function generateAwsWafRule(ips) {
        const ipSet = {
            Name: 'BlockedIPs',
            Scope: 'REGIONAL',
            IPAddressVersion: 'IPV4',
            Addresses: ips.map(ip => ip.includes(':') ? ip + '/128' : ip + '/32'),
        };
        return JSON.stringify(ipSet, null, 2);
    }

    function generateCloudflareRule(ips) {
        const expression = ips.map(ip => `ip.src eq ${ip}`).join(' or ');
        return `# Cloudflare WAF Custom Rule — Block IPs\n# Action: Block\n# Expression:\n(${expression})`;
    }

    function generateIpsetCommands(ips, setName = 'blocklist') {
        const lines = [`ipset create ${setName} hash:ip -exist`];
        for (const ip of ips) lines.push(`ipset add ${setName} ${ip} -exist`);
        return lines.join('\n');
    }

    function analyzeFromWorkerSummary(summary) {
        if (!summary) return emptyEnhancedResult();

        const totalRequests = summary.matchingCount || 0;
        const uniqueIps = summary.uniqueIps || 0;

        // Country Hits
        const countryHits = Object.entries(summary.countryCounts || {})
            .map(([country, count]) => ({
                country,
                country_code: country,
                count,
                hits: count,
                percentage: totalRequests ? ((count / totalRequests) * 100).toFixed(1) : '0.0'
            }))
            .sort((a, b) => b.hits - a.hits);

        // ASN Hits
        const asnHits = Object.entries(summary.asnHits || {})
            .map(([asn, count]) => {
                const asnOrg = (summary.asnOrgMap && summary.asnOrgMap[asn]) || (typeof GeoIP !== 'undefined' && GeoIP.lookupASNOrg ? GeoIP.lookupASNOrg(Number(asn)) : '') || `AS${asn}`;
                return {
                    asn,
                    asn_org: asnOrg,
                    count,
                    hits: count,
                    percentage: totalRequests ? ((count / totalRequests) * 100).toFixed(1) : '0.0'
                };
            })
            .sort((a, b) => b.hits - a.hits);

        // Bot Groups
        let botRequestsTotal = 0;
        const botEntries = Object.entries(summary.botCounts || {}).map(([name, count]) => {
            botRequestsTotal += count;
            return {
                group_name: name,
                requests: count,
                unique_ips: 0,
                pct: totalRequests ? Math.round((count / totalRequests) * 1000) / 10 : 0,
                verified_requests: count,
                spoofed_requests: 0,
                unverified_requests: 0,
                verification_status: 'verified',
                sub_bots: [{ name, count, verified: true, status: 'verified', reason: 'User-Agent / Signature' }],
                has_sub_groups: false
            };
        }).sort((a, b) => b.requests - a.requests);

        const humanRequests = Math.max(0, totalRequests - botRequestsTotal);

        // HTTP Status categories
        const statusCategories = { '1xx': 0, '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
        const statusHits = Object.entries(summary.statusCounts || {})
            .map(([codeStr, count]) => {
                const code = parseInt(codeStr, 10);
                const cat = Math.floor(code / 100);
                if (cat >= 1 && cat <= 5) statusCategories[`${cat}xx`] += count;
                return {
                    code,
                    count,
                    percentage: totalRequests ? ((count / totalRequests) * 100).toFixed(1) : '0.0'
                };
            })
            .sort((a, b) => b.count - a.count);

        let rateBuckets = [];
        if (Array.isArray(summary.timeBuckets)) {
            rateBuckets = summary.timeBuckets.map(b => ({
                timestamp: b.timestamp || (b.time ? b.time * 1000 : 0),
                count: b.count || b.total || 0,
                rps: b.rps || 0,
                status_2xx: b.status_2xx || 0,
                status_3xx: b.status_3xx || 0,
                status_4xx: b.status_4xx || b.error || 0,
                status_5xx: b.status_5xx || 0,
                label: b.label || ''
            }));
        } else if (summary.timeBuckets && typeof summary.timeBuckets === 'object') {
            const entries = Object.entries(summary.timeBuckets).sort((a, b) => Number(a[0]) - Number(b[0]));
            rateBuckets = entries.map(([secStr, count]) => {
                const sec = Number(secStr);
                const ts = sec * 1000;
                return {
                    timestamp: ts,
                    count: count || 0,
                    rps: Number(((count || 0) / 3600).toFixed(2)),
                    status_2xx: 0,
                    status_3xx: 0,
                    status_4xx: 0,
                    status_5xx: 0,
                    label: new Date(ts).toISOString().slice(11, 16)
                };
            });
        }

        const reqRateObj = {
            buckets: rateBuckets,
            data_points: rateBuckets,
            bucket_seconds: 3600,
            bucket_label: '1h',
            total_buckets: rateBuckets.length,
            peak_rps: rateBuckets.length ? Math.max(...rateBuckets.map(b => b.rps)) : 0,
            avg_rps: 0,
            top_spikes: []
        };

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

        return {
            total_requests: totalRequests,
            unique_ips: uniqueIps,
            unique_countries: countryHits.length,
            unique_asns: asnHits.length,
            country_hits: countryHits,
            asn_hits: asnHits,
            top_ips: topIps,
            bot_groups: botEntries,
            bot_hits: botEntries,
            human_requests: humanRequests,
            verified_bots_count: botRequestsTotal,
            spoofed_bots_count: 0,
            unverified_bots_count: 0,
            verified_bot_ips_count: 0,
            spoofed_bot_ips_count: 0,
            spoofed_bot_attackers: [],
            spoofed_bot_ips: [],
            ip_log_entries: new Map(),
            http_metrics: {
                total_bandwidth_bytes: summary.totalBytes || 0,
                response_size: {
                    total: summary.totalBytes || 0,
                    avg: totalRequests ? Math.round((summary.totalBytes || 0) / totalRequests) : 0,
                },
                avg_response_size: totalRequests ? Math.round((summary.totalBytes || 0) / totalRequests) : 0,
                status_categories: statusCategories,
                status_hits: statusHits,
                method_hits: methodHits,
                top_paths: [],
                top_referrers: [],
                request_rate: reqRateObj
            },
            request_rate: reqRateObj
        };
    }

    return { analyzeLogs, analyzeEnhancedLogs, analyzeFromWorkerSummary, computeRequestRate, enrichLogEntries, generateNginxDeny, generateAwsWafRule, generateCloudflareRule, generateIpsetCommands };
})();

if (typeof window !== 'undefined') window.Analyzer = Analyzer;
if (typeof self !== 'undefined') self.Analyzer = Analyzer;
if (typeof module !== 'undefined' && module.exports) module.exports = Analyzer;
