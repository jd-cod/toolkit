/**
 * Traffic Classifier — Client-Side
 *
 * Sorts every request of an access log into exactly one class, so the classes
 * always add up to the total:
 *
 *   human       a browser, with nothing automated about how it behaves
 *   verified    a known crawler, and the address is in its publisher's ranges
 *   unverified  a known crawler whose address cannot be checked
 *   spoofed     claims to be a known crawler from an address that is not its publisher's
 *   automated   scripts, HTTP libraries, scanners, crawlers not in the list, no User-Agent
 *   suspected   a browser User-Agent whose requests look automated
 *
 * A request is judged as part of a client (one IP address with one User-Agent),
 * because behaviour only shows across several requests. Both analysis paths
 * (in-memory and the streaming worker) use this file, so they agree.
 *
 * Depends on BotDetector (bot-detector.js) for User-Agent and address checks.
 */

const TrafficClassifier = (() => {
    const CLASSES = ['human', 'verified', 'unverified', 'spoofed', 'automated', 'suspected'];
    const CLASS_INDEX = Object.fromEntries(CLASSES.map((name, i) => [name, i]));
    const CLASS_LABELS = {
        human: 'Human',
        verified: 'Verified bots',
        unverified: 'Known bots, unverified',
        spoofed: 'Spoofed bots',
        automated: 'Other bots & tools',
        suspected: 'Suspected bots',
    };
    // `bot_status` values the dashboard and report already understand.
    const STATUS_BY_CLASS = {
        human: 'human',
        verified: 'verified',
        unverified: 'unverified_publisher',
        spoofed: 'spoofed',
        automated: 'automated',
        suspected: 'suspected',
    };
    const SUSPECTED_GROUP = 'Suspected automation';

    // A log format without a User-Agent column makes every request look like
    // it sent none. Above this share the field is treated as absent, and such
    // requests are judged by behaviour instead of being called bots.
    const UA_MISSING_SHARE = 0.9;
    const UA_MISSING_MIN_ROWS = 20;

    const ASSET_RE = /\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3|m4s)$/i;
    const AUTH_PATH_RE = /wp-login\.php|xmlrpc\.php|\/(?:login|signin|sign-in|sign_in|logon|authenticate)(?:[/.?]|$)/;
    // Paths nobody reaches by following links. One bit each in a 32-bit mask.
    const PROBE_PATHS = [
        '/.env', '/.git/', '/.aws/', '/.ssh/', '/.svn/', '/.hg/', '/.ds_store', '/.htpasswd', '/.vscode/',
        'wp-config', 'xmlrpc.php', 'wlwmanifest.xml', 'wp-login.php', 'phpmyadmin', '/pma/', 'adminer.php',
        'phpinfo', 'eval-stdin.php', '/vendor/phpunit', '/cgi-bin/', 'boaform', '/hnap1', 'setup.cgi',
        '/etc/passwd', '/actuator/', '/solr/admin', '/owa/auth', 'autodiscover.xml', '/_ignition',
        '/telescope/requests', '/manager/html',
    ];

    const THRESHOLDS = {
        probePaths: 3,          // different sensitive paths from one client
        authPostsPerMinute: 10, // POSTs to a login endpoint within one minute
        floodPerMinute: 120,    // page requests in one minute, with almost no assets or referrers
        floodHardPerMinute: 600, // page requests in one minute, with almost no assets
        enumRequests: 30,       // requests needed before an error storm counts
        enumErrorShare: 0.8,
        enumPaths: 15,
        scoreRequests: 20,      // requests needed before the weak signals are added up
        scoreSignals: 3,
        scoreBreadthPaths: 30,
    };

    function botDetector() {
        if (typeof BotDetector !== 'undefined') return BotDetector;
        if (typeof globalThis !== 'undefined' && globalThis.BotDetector) return globalThis.BotDetector;
        throw new Error('TrafficClassifier needs BotDetector (bot-detector.js) to be loaded first.');
    }

    function popcount(n) {
        n = n - ((n >>> 1) & 0x55555555);
        n = (n & 0x33333333) + ((n >>> 2) & 0x33333333);
        return (((n + (n >>> 4)) & 0x0f0f0f0f) * 0x01010101) >>> 24;
    }

    function hashPath(str) {
        let h = 2166136261;
        for (let i = 0; i < str.length; i++) {
            h ^= str.charCodeAt(i);
            h = Math.imul(h, 16777619);
        }
        return h >>> 0;
    }

    /** Estimated number of different page paths, from a 64-bit occupancy map. */
    function distinctPaths(client) {
        const bits = popcount(client.pathLo) + popcount(client.pathHi);
        if (bits >= 64) return 400;
        return Math.round(-64 * Math.log(1 - bits / 64));
    }

    function newClient(ip, ua, info) {
        return {
            ip, ua, info,
            n: 0, pages: 0, assets: 0, withRef: 0, err4: 0, heads: 0, http10: 0,
            robots: 0, probeMask: 0, probeHits: 0, pathLo: 0, pathHi: 0,
            winStart: -1, winCount: 0, peakMin: 0,
            authStart: -1, authCount: 0, authPeak: 0, authPosts: 0,
            cls: 'human', name: null, group: null, reason: 'Browser traffic', verified: null,
        };
    }

    function observe(client, row) {
        client.n++;
        const url = row.url || '';
        const q = url.indexOf('?');
        const path = q === -1 ? url : url.slice(0, q);
        const lower = path.toLowerCase();
        const t = row.timeSec > 0 ? row.timeSec : -1;

        if (ASSET_RE.test(path)) {
            client.assets++;
        } else {
            client.pages++;
            const bit = hashPath(path) & 63;
            if (bit < 32) client.pathLo |= (1 << bit);
            else client.pathHi |= (1 << (bit - 32));
            // Busiest minute: a 60-second window that opens at the first
            // request after the previous window closed. Logs are written in
            // time order, so one open window per client is enough.
            if (t >= 0) {
                if (client.winStart >= 0 && Math.abs(t - client.winStart) < 60) client.winCount++;
                else { client.winStart = t; client.winCount = 1; }
                if (client.winCount > client.peakMin) client.peakMin = client.winCount;
            }
        }

        if (row.hasReferrer) client.withRef++;
        if (row.status >= 400 && row.status < 500) client.err4++;
        if (row.httpVersion === 'HTTP/1.0') client.http10++;

        const method = row.method || '';
        if (method === 'HEAD') {
            client.heads++;
        } else if (method === 'POST' && AUTH_PATH_RE.test(lower)) {
            client.authPosts++;
            if (t >= 0) {
                if (client.authStart >= 0 && Math.abs(t - client.authStart) < 60) client.authCount++;
                else { client.authStart = t; client.authCount = 1; }
                if (client.authCount > client.authPeak) client.authPeak = client.authCount;
            }
        }

        if (lower === '/robots.txt') client.robots = 1;
        for (let i = 0; i < PROBE_PATHS.length; i++) {
            if (lower.indexOf(PROBE_PATHS[i]) !== -1) {
                client.probeMask |= (1 << i);
                client.probeHits++;
                break;
            }
        }
    }

    /**
     * Decide whether a client that looks like a browser behaves like one.
     * Strong signals decide alone; weak ones only count together.
     *
     * @returns {{ label: string, reason: string }|null} null means human.
     */
    function behaviourVerdict(c) {
        const T = THRESHOLDS;
        const probes = popcount(c.probeMask);
        if (probes >= T.probePaths) {
            return { label: 'Vulnerability probing', reason: `Requested ${probes} different sensitive paths (${c.probeHits} requests)` };
        }
        if (c.authPeak >= T.authPostsPerMinute) {
            return { label: 'Login brute force', reason: `${c.authPeak} login attempts within one minute (${c.authPosts} in total)` };
        }
        const assetShare = c.n ? c.assets / c.n : 0;
        const refShare = c.n ? c.withRef / c.n : 0;
        if ((c.peakMin >= T.floodPerMinute && assetShare <= 0.2 && refShare <= 0.2) ||
            (c.peakMin >= T.floodHardPerMinute && assetShare <= 0.1)) {
            return { label: 'Request flood', reason: `${c.peakMin} page requests within one minute, without the assets or referrers a browser sends` };
        }
        const errShare = c.n ? c.err4 / c.n : 0;
        const paths = distinctPaths(c);
        if (c.n >= T.enumRequests && errShare >= T.enumErrorShare && paths >= T.enumPaths) {
            return { label: 'Path enumeration', reason: `${Math.round(errShare * 100)}% of ${c.n} requests failed, across about ${paths} different paths` };
        }
        if (c.n >= T.scoreRequests) {
            const signals = [];
            if (c.assets === 0) signals.push('no page assets');
            if (c.withRef === 0) signals.push('no referrers');
            if (c.robots) signals.push('fetched robots.txt');
            if (c.heads / c.n >= 0.5) signals.push('mostly HEAD requests');
            if (errShare >= 0.5) signals.push(`${Math.round(errShare * 100)}% client errors`);
            if (c.http10 / c.n >= 0.9) signals.push('HTTP/1.0');
            if (paths >= T.scoreBreadthPaths && c.pages / c.n >= 0.9) signals.push(`about ${paths} different pages`);
            if (signals.length >= T.scoreSignals) {
                return { label: 'Crawler-like browsing', reason: `${c.n} requests with ${signals.join(', ')}` };
            }
        }
        return null;
    }

    const AUTOMATED_REASONS = {
        scanner: name => `Security scanner signature (${name})`,
        tool: name => `Script, HTTP library or non-browser app (${name})`,
        headless: name => `Automated browser (${name})`,
        unknown_bot: name => `Calls itself a bot (${name}); not in the known-bot list`,
        unknown_client: name => `Not a browser and not a recognised client (${name})`,
    };

    /**
     * Collects the clients of one log and classifies them.
     *
     *   const session = TrafficClassifier.createSession();
     *   const id = session.add(ip, userAgent, { timeSec, status, method, url, hasReferrer, httpVersion });
     *   session.finalize(ip => asnNumber);      // after the last add(); may be repeated
     *   session.client(id).cls                  // 'human' | 'verified' | ...
     */
    function createSession() {
        const clients = [];
        const index = new Map();
        let rows = 0;
        let noUaRows = 0;
        let uaFieldMissing = false;

        function add(ip, userAgent, row) {
            const ua = (typeof userAgent === 'string' && userAgent !== '-') ? userAgent : '';
            const key = ip + '\u0000' + ua;
            let id = index.get(key);
            if (id === undefined) {
                id = clients.length;
                clients.push(newClient(ip, ua, botDetector().classifyUserAgent(ua)));
                index.set(key, id);
            }
            const client = clients[id];
            rows++;
            if (!ua) noUaRows++;
            // Behaviour only matters for clients that could be people.
            if (client.info.kind === 'browser' || client.info.kind === 'no_ua') {
                observe(client, row || {});
            } else {
                client.n++;
            }
            return id;
        }

        function finalize(lookupAsn) {
            const detector = botDetector();
            uaFieldMissing = rows >= UA_MISSING_MIN_ROWS && noUaRows / rows >= UA_MISSING_SHARE;

            for (const c of clients) {
                const { kind, name, group } = c.info;
                if (kind === 'known_bot') {
                    const asn = typeof lookupAsn === 'function' ? (Number(lookupAsn(c.ip)) || 0) : 0;
                    const v = detector.verifyBot(name, c.ip, asn);
                    c.cls = v.status === 'verified' ? 'verified' : (v.status === 'spoofed' ? 'spoofed' : 'unverified');
                    c.name = name;
                    c.group = group || name;
                    c.reason = v.reason;
                    c.verified = v.verified;
                } else if (AUTOMATED_REASONS[kind]) {
                    c.cls = 'automated';
                    c.name = name;
                    c.group = group;
                    c.reason = AUTOMATED_REASONS[kind](name);
                    c.verified = null;
                } else if (kind === 'no_ua' && !uaFieldMissing) {
                    c.cls = 'automated';
                    c.name = name;
                    c.group = group;
                    c.reason = 'Sent no User-Agent header';
                    c.verified = null;
                } else {
                    const verdict = behaviourVerdict(c);
                    if (verdict) {
                        c.cls = 'suspected';
                        c.name = verdict.label;
                        c.group = SUSPECTED_GROUP;
                        c.reason = verdict.reason;
                    } else {
                        c.cls = 'human';
                        c.name = null;
                        c.group = null;
                        c.reason = 'Browser traffic';
                    }
                    c.verified = null;
                }
            }
        }

        return {
            add,
            finalize,
            client: id => clients[id],
            get clientCount() { return clients.length; },
            get rowCount() { return rows; },
            get uaFieldMissing() { return uaFieldMissing; },
        };
    }

    function verificationStatus(counts) {
        if (counts.spoofed > 0 && counts.verified > 0) return 'mixed';
        if (counts.spoofed > 0) return 'spoofed';
        if (counts.verified > 0) return 'verified';
        if (counts.unverified > 0) return 'unverified';
        if (counts.suspected > 0 && counts.automated === 0) return 'suspected';
        if (counts.automated > 0) return 'automated';
        return 'unverified';
    }

    function emptyCounts() {
        return { human: 0, verified: 0, unverified: 0, spoofed: 0, automated: 0, suspected: 0 };
    }

    function pct(part, total) {
        return total ? Math.round(part / total * 1000) / 10 : 0;
    }

    /**
     * Turn per-client request counts into the numbers the dashboard shows.
     *
     * @param {Iterable<{ client: object, count: number }>} items - Classified
     *   clients with the number of their requests that are in scope (for
     *   example after a filter). `client` needs ip, ua, cls, name, group,
     *   reason and verified.
     * @param {object} [options]
     * @param {(ip: string) => object} [options.geo] - Country and network of
     *   an address, for the spoofed-bot list.
     * @param {number} [options.ipDetailLimit] - Most addresses to list per bot.
     */
    function aggregate(items, options = {}) {
        const geo = typeof options.geo === 'function' ? options.geo : null;
        const ipDetailLimit = options.ipDetailLimit > 0 ? options.ipDetailLimit : Infinity;

        let total = 0;
        const classCounts = emptyCounts();
        const classIps = {};
        for (const cls of CLASSES) classIps[cls] = new Set();
        const groups = new Map();
        const spoofedAttackers = new Map();
        const suspectedClients = [];

        for (const { client, count } of items) {
            if (!count) continue;
            const cls = CLASS_INDEX[client.cls] === undefined ? 'human' : client.cls;
            total += count;
            classCounts[cls] += count;
            classIps[cls].add(client.ip);
            if (cls === 'human') continue;

            const groupName = client.group || client.name || 'Unknown';
            const botName = client.name || groupName;
            let g = groups.get(groupName);
            if (!g) {
                g = { requests: 0, ips: new Set(), counts: emptyCounts(), subBots: new Map() };
                groups.set(groupName, g);
            }
            g.requests += count;
            g.ips.add(client.ip);
            g.counts[cls] += count;

            let sb = g.subBots.get(botName);
            if (!sb) {
                sb = { requests: 0, counts: emptyCounts(), details: new Map() };
                g.subBots.set(botName, sb);
            }
            sb.requests += count;
            sb.counts[cls] += count;
            const detail = sb.details.get(client.ip);
            if (detail) {
                detail.hits += count;
            } else {
                sb.details.set(client.ip, {
                    ip: client.ip,
                    hits: count,
                    user_agent: client.ua || '-',
                    verified: client.verified,
                    status: STATUS_BY_CLASS[cls],
                    reason: client.reason,
                });
            }

            if (cls === 'spoofed') {
                const key = `${client.ip}|${botName}`;
                let att = spoofedAttackers.get(key);
                if (!att) {
                    const info = geo ? (geo(client.ip) || {}) : {};
                    att = {
                        ip: client.ip,
                        bot_name: botName,
                        group_name: groupName,
                        hits: 0,
                        country: info.country || 'Unknown',
                        country_code: info.country_code || '--',
                        asn: info.asn ? `AS${info.asn}` : 'AS0',
                        asn_org: info.asn_org || 'Unknown',
                        user_agent: client.ua || '-',
                        reason: client.reason,
                    };
                    spoofedAttackers.set(key, att);
                }
                att.hits += count;
            } else if (cls === 'suspected') {
                suspectedClients.push({
                    ip: client.ip, hits: count, label: botName, reason: client.reason, user_agent: client.ua || '-',
                });
            }
        }

        const botGroups = [...groups.entries()]
            .sort((a, b) => b[1].requests - a[1].requests)
            .map(([groupName, g]) => {
                const subBots = [...g.subBots.entries()]
                    .sort((a, b) => b[1].requests - a[1].requests)
                    .map(([botName, sb]) => ({
                        bot_name: botName,
                        requests: sb.requests,
                        unique_ips: sb.details.size,
                        pct: pct(sb.requests, total),
                        verified_requests: sb.counts.verified,
                        spoofed_requests: sb.counts.spoofed,
                        unverified_requests: sb.counts.unverified,
                        automated_requests: sb.counts.automated,
                        suspected_requests: sb.counts.suspected,
                        verification_status: verificationStatus(sb.counts),
                        ip_details: [...sb.details.values()].sort((a, b) => b.hits - a.hits).slice(0, ipDetailLimit),
                    }));
                return {
                    group_name: groupName,
                    requests: g.requests,
                    unique_ips: g.ips.size,
                    pct: pct(g.requests, total),
                    verified_requests: g.counts.verified,
                    spoofed_requests: g.counts.spoofed,
                    unverified_requests: g.counts.unverified,
                    automated_requests: g.counts.automated,
                    suspected_requests: g.counts.suspected,
                    verification_status: verificationStatus(g.counts),
                    sub_bots: subBots,
                    has_sub_groups: subBots.length > 1,
                };
            });

        const trafficClasses = CLASSES.map(cls => ({
            key: cls,
            label: CLASS_LABELS[cls],
            requests: classCounts[cls],
            unique_ips: classIps[cls].size,
            pct: pct(classCounts[cls], total),
        }));

        return {
            classified_requests: total,
            traffic_classes: trafficClasses,
            bot_groups: botGroups,
            human_requests: classCounts.human,
            verified_bots_count: classCounts.verified,
            spoofed_bots_count: classCounts.spoofed,
            unverified_bots_count: classCounts.unverified,
            automated_count: classCounts.automated,
            suspected_count: classCounts.suspected,
            other_bots_count: classCounts.unverified + classCounts.automated + classCounts.suspected,
            verified_bot_ips_count: classIps.verified.size,
            spoofed_bot_ips_count: classIps.spoofed.size,
            spoofed_bot_attackers: [...spoofedAttackers.values()].sort((a, b) => b.hits - a.hits),
            spoofed_bot_ips: [...classIps.spoofed],
            suspected_clients: suspectedClients.sort((a, b) => b.hits - a.hits).slice(0, 100),
        };
    }

    return {
        CLASSES,
        CLASS_INDEX,
        CLASS_LABELS,
        STATUS_BY_CLASS,
        SUSPECTED_GROUP,
        THRESHOLDS,
        createSession,
        aggregate,
        behaviourVerdict,
    };
})();

if (typeof window !== 'undefined') window.TrafficClassifier = TrafficClassifier;
if (typeof self !== 'undefined') self.TrafficClassifier = TrafficClassifier;
if (typeof globalThis !== 'undefined') globalThis.TrafficClassifier = TrafficClassifier;
if (typeof module !== 'undefined' && module.exports) module.exports = TrafficClassifier;
