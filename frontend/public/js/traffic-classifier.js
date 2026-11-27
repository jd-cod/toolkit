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
 * because behaviour only shows across several requests.
 *
 * Depends on BotDetector (bot-detector.js) for User-Agent and address checks
 * and on RequestPaths (request-paths.js) for what a request path means.
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

    const THRESHOLDS = {
        probePaths: 3,          // different attack-looking paths from one client
        strongProbes: 2,        // different requests that are attacks on any site
        scriptMisses: 5,        // different script files that do not exist
        authPostsPerMinute: 10, // login attempts within one minute
        authAttempts: 20,       // login attempts over the whole log ...
        authShare: 0.3,         // ... when they are this share of the client's requests
        floodPerMinute: 120,    // page requests in one minute, with almost no assets or referrers
        floodHardPerMinute: 600, // page requests in one minute, with almost no assets
        enumRequests: 30,       // requests needed before an error storm counts
        enumErrorShare: 0.8,
        enumPaths: 15,
        scrapePages: 100,       // page requests without a single asset ...
        scrapePaths: 50,        // ... across this many different pages
        scoreRequests: 20,      // requests needed before the weak signals are added up
        scoreSignals: 3,
        scoreReferrerShare: 0.8, // with referrers on this share of requests, one more signal is needed
        scoreBreadthPaths: 30,
        rotationClients: 8,     // browser clients from one address before they are judged together
        rotationRequests: 50,
        stuffingClients: 30,    // clients that did nothing but try to log in at one endpoint
    };

    // Assets served from another host never reach this log, and then "no
    // assets" says nothing about a client. Assets count as logged once this
    // many browser clients fetched one; a log with fewer than
    // ASSET_CHECK_CLIENTS returning clients is too small to tell and is
    // assumed to have them.
    const ASSET_CLIENTS = 3;
    const ASSET_CHECK_CLIENTS = 10;

    function botDetector() {
        if (typeof BotDetector !== 'undefined') return BotDetector;
        if (typeof globalThis !== 'undefined' && globalThis.BotDetector) return globalThis.BotDetector;
        throw new Error('TrafficClassifier needs BotDetector (bot-detector.js) to be loaded first.');
    }

    function requestPaths() {
        if (typeof RequestPaths !== 'undefined') return RequestPaths;
        if (typeof globalThis !== 'undefined' && globalThis.RequestPaths) return globalThis.RequestPaths;
        throw new Error('TrafficClassifier needs RequestPaths (request-paths.js) to be loaded first.');
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

    /** Estimated number of different values, from an occupancy map of `size` bits. */
    function estimate(bits, size) {
        if (bits >= size) return size * 6;
        return Math.round(-size * Math.log(1 - bits / size));
    }

    function distinctPaths(client) {
        return estimate(popcount(client.pathLo) + popcount(client.pathHi), 64);
    }

    /** Clients of one network are judged together: an IPv4 address, or an IPv6 /64. */
    function networkOf(ip) {
        if (typeof ip !== 'string' || ip.indexOf(':') === -1) return ip;
        const sides = ip.split('::');
        const left = sides[0] ? sides[0].split(':') : [];
        if (left.length >= 4 || sides.length === 1) return left.slice(0, 4).join(':') + '::/64';
        const right = sides[1] ? sides[1].split(':') : [];
        const zeros = new Array(Math.max(0, 8 - left.length - right.length)).fill('0');
        return [...left, ...zeros, ...right].slice(0, 4).join(':') + '::/64';
    }

    function newClient(ip, ua, info) {
        return {
            ip, ua, info,
            n: 0, pages: 0, assets: 0, media: 0, withRef: 0, err4: 0, heads: 0, http10: 0,
            robots: 0, probeBits: 0, probeHits: 0, strongBits: 0, scriptMissBits: 0, pathLo: 0, pathHi: 0,
            pageTimes: null, peakMin: 0,
            authTimes: null, authPeak: 0, authAttempts: 0, authPath: null,
            cls: 'human', name: null, group: null, reason: 'Browser traffic', verified: null,
        };
    }

    /** What one request is, worked out once and used for the client and its network. */
    function describe(row) {
        const paths = requestPaths();
        const url = row.url || '';
        const path = paths.normalizePath(url);
        return {
            path,
            kind: paths.resourceKind(url),
            signature: url ? paths.attackSignature(url) : null,
            auth: paths.isAuthRequest(row.method || '', url),
            script: paths.isScriptPath(url),
            hash: hashPath(path),
        };
    }

    // No rule looks past this many requests in one minute.
    const MINUTE_CAP = 5000;

    /**
     * Add a request time and return how many requests lie within the 60
     * seconds that end with it. The window moves with every request, so a
     * burst is counted whole wherever it falls on the clock. Logs are written
     * in time order (or in reverse); `window` keeps only the last minute.
     *
     * @param {{ times: number[], head: number }} window
     */
    function withinLastMinute(window, t) {
        const times = window.times;
        while (window.head < times.length && Math.abs(t - times[window.head]) >= 60) window.head++;
        times.push(t);
        if (times.length - window.head > MINUTE_CAP) window.head++;
        if (window.head >= 1024 && window.head * 2 >= times.length) {
            times.splice(0, window.head);
            window.head = 0;
        }
        return times.length - window.head;
    }

    function observe(client, row, d) {
        client.n++;
        const t = row.timeSec > 0 ? row.timeSec : -1;

        if (d.kind === 'asset') {
            client.assets++;
        } else if (d.kind === 'media') {
            client.media++;
        } else {
            client.pages++;
            const bit = d.hash & 63;
            if (bit < 32) client.pathLo |= (1 << bit);
            else client.pathHi |= (1 << (bit - 32));
            if (t >= 0) {
                if (!client.pageTimes) client.pageTimes = { times: [], head: 0 };
                const inMinute = withinLastMinute(client.pageTimes, t);
                if (inMinute > client.peakMin) client.peakMin = inMinute;
            }
        }

        if (row.hasReferrer) client.withRef++;
        if (row.status >= 400 && row.status < 500) client.err4++;
        if (row.httpVersion === 'HTTP/1.0') client.http10++;
        if (row.method === 'HEAD') client.heads++;

        if (d.auth) {
            client.authAttempts++;
            if (client.authPath === null) client.authPath = d.path;
            if (t >= 0) {
                if (!client.authTimes) client.authTimes = { times: [], head: 0 };
                const inMinute = withinLastMinute(client.authTimes, t);
                if (inMinute > client.authPeak) client.authPeak = inMinute;
            }
        }

        if (d.path === '/robots.txt') client.robots = 1;
        // A path that is an attack on any site always counts. A path that is
        // only suspicious (wp-login.php, xmlrpc.php, phpMyAdmin) counts when
        // the server did not serve it: where it exists and answers, people
        // and their browsers use it.
        const served = (row.status >= 200 && row.status < 300) || row.status === 304;
        if (d.signature && (d.signature.strong || !served)) {
            client.probeHits++;
            client.probeBits |= (1 << ((d.hash >>> 6) & 31));
            if (d.signature.strong) client.strongBits |= (1 << ((d.hash >>> 11) & 31));
        }
        if (d.script && row.status === 404) client.scriptMissBits |= (1 << ((d.hash >>> 16) & 31));
    }

    /**
     * Decide whether a client that looks like a person's program behaves like one.
     * Strong signals decide alone; weak ones only count together.
     *
     * @param {object} c - Counters of one client, or of one network.
     * @param {{ assetsLogged: boolean, app: boolean }} cal - What this log can show.
     * @returns {{ label: string, reason: string }|null} null means human.
     */
    function behaviourVerdict(c, cal) {
        const T = THRESHOLDS;
        const probes = estimate(popcount(c.probeBits), 32);
        const strong = estimate(popcount(c.strongBits), 32);
        if (strong >= T.strongProbes || probes >= T.probePaths) {
            return { label: 'Vulnerability probing', reason: `Requested ${Math.max(probes, strong)} different attack paths (${c.probeHits} requests)` };
        }
        const misses = estimate(popcount(c.scriptMissBits), 32);
        if (misses >= T.scriptMisses) {
            return { label: 'Vulnerability probing', reason: `Tried ${misses} script files that do not exist` };
        }
        if (c.authPeak >= T.authPostsPerMinute) {
            return { label: 'Login brute force', reason: `${c.authPeak} login attempts within one minute (${c.authAttempts} in total)` };
        }
        if (c.authAttempts >= T.authAttempts && c.authAttempts / c.n >= T.authShare) {
            return { label: 'Login brute force', reason: `${c.authAttempts} login attempts, ${Math.round(c.authAttempts / c.n * 100)}% of its requests` };
        }
        const assetShare = c.n ? c.assets / c.n : 0;
        const refShare = c.n ? c.withRef / c.n : 0;
        const fewAssets = cal.assetsLogged && !cal.app;
        if (c.peakMin >= T.floodHardPerMinute && (!fewAssets || assetShare <= 0.1)) {
            return { label: 'Request flood', reason: `${c.peakMin} page requests within one minute` };
        }
        if (!cal.app && c.peakMin >= T.floodPerMinute && refShare <= 0.2 && (!fewAssets || assetShare <= 0.2)) {
            return { label: 'Request flood', reason: `${c.peakMin} page requests within one minute, without the assets or referrers a browser sends` };
        }
        const errShare = c.n ? c.err4 / c.n : 0;
        const paths = distinctPaths(c);
        if (c.n >= T.enumRequests && errShare >= T.enumErrorShare && paths >= T.enumPaths && refShare <= 0.2) {
            return { label: 'Path enumeration', reason: `${Math.round(errShare * 100)}% of ${c.n} requests failed, across about ${paths} different paths` };
        }
        if (cal.app) return null;
        if (fewAssets && c.assets === 0 && c.pages >= T.scrapePages && paths >= T.scrapePaths) {
            return { label: 'Crawler-like browsing', reason: `${c.pages} page requests across about ${paths} pages without one stylesheet, script or image` };
        }
        if (c.n >= T.scoreRequests) {
            const signals = [];
            if (fewAssets && c.assets === 0) signals.push('no page assets');
            if (c.withRef === 0) signals.push('no referrers');
            if (c.robots) signals.push('fetched robots.txt');
            if (c.heads / c.n >= 0.5) signals.push('mostly HEAD requests');
            if (errShare >= 0.5) signals.push(`${Math.round(errShare * 100)}% client errors`);
            if (c.http10 / c.n >= 0.9) signals.push('HTTP/1.0');
            if (paths >= T.scoreBreadthPaths && c.pages / c.n >= 0.9) signals.push(`about ${paths} different pages`);
            if (c.info && c.info.legacy) signals.push('a browser version long out of use');
            // Requests that nearly all name the page they came from are what a
            // page's own script sends (search-as-you-type, polling an API).
            const needed = refShare >= T.scoreReferrerShare ? T.scoreSignals + 1 : T.scoreSignals;
            if (signals.length >= needed) {
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
        // Everything seen from one network, whatever User-Agent it sent.
        const networks = new Map();
        let rows = 0;
        let noUaRows = 0;
        let uaFieldMissing = false;

        function add(ip, userAgent, row) {
            const ua = (typeof userAgent === 'string' && userAgent !== '-') ? userAgent : '';
            const key = ip + '\u0000' + ua;
            let id = index.get(key);
            let isNew = false;
            if (id === undefined) {
                id = clients.length;
                clients.push(newClient(ip, ua, botDetector().classifyUserAgent(ua)));
                index.set(key, id);
                isNew = true;
            }
            const client = clients[id];
            rows++;
            if (!ua) noUaRows++;
            // Behaviour only matters for clients that could be people.
            const kind = client.info.kind;
            if (kind === 'browser' || kind === 'app' || kind === 'no_ua') {
                const r = row || {};
                const d = describe(r);
                observe(client, r, d);
                const net = networkOf(ip);
                let network = networks.get(net);
                if (!network) {
                    network = newClient(net, '', { kind: 'browser' });
                    network.members = [];
                    networks.set(net, network);
                }
                if (isNew) network.members.push(id);
                observe(network, r, d);
            } else {
                client.n++;
            }
            return id;
        }

        function suspect(c, label, reason) {
            c.cls = 'suspected';
            c.name = label;
            c.group = SUSPECTED_GROUP;
            c.reason = reason;
            c.verified = null;
        }

        function finalize(lookupAsn) {
            const detector = botDetector();
            const T = THRESHOLDS;
            uaFieldMissing = rows >= UA_MISSING_MIN_ROWS && noUaRows / rows >= UA_MISSING_SHARE;
            let withAssets = 0;
            let returning = 0;
            for (const c of clients) {
                if (c.info.kind !== 'browser') continue;
                if (c.assets > 0) withAssets++;
                if (c.n >= 5) returning++;
            }
            const assetsLogged = withAssets >= ASSET_CLIENTS || returning < ASSET_CHECK_CLIENTS;

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
                    const verdict = behaviourVerdict(c, { assetsLogged, app: kind === 'app' });
                    if (verdict) {
                        suspect(c, verdict.label, verdict.reason);
                    } else {
                        c.cls = 'human';
                        c.name = null;
                        c.group = null;
                        c.reason = kind === 'app' ? `App traffic (${name})` : 'Browser traffic';
                        c.verified = null;
                    }
                }
            }

            // One network that keeps changing its User-Agent (or its IPv6
            // address) splits into clients too small to judge. Judge them as one.
            for (const network of networks.values()) {
                if (network.members.length < T.rotationClients) continue;
                const people = network.members.map(id => clients[id]).filter(c => c.cls === 'human');
                if (people.length === 0) continue;
                const what = `${network.members.length} User-Agent and address combinations from one network`;
                const verdict = behaviourVerdict(network, { assetsLogged, app: false });
                if (verdict) {
                    for (const c of people) suspect(c, verdict.label, `${what}; together: ${verdict.reason.charAt(0).toLowerCase()}${verdict.reason.slice(1)}`);
                    continue;
                }
                const perClient = network.n / network.members.length;
                const bare = assetsLogged ? network.assets / network.n <= 0.2 : network.withRef / network.n <= 0.2;
                if (network.n >= T.rotationRequests && perClient <= 3 && bare) {
                    for (const c of people) suspect(c, 'Rotating identity', `${what}, ${network.n} requests, about ${Math.round(perClient * 10) / 10} each`);
                }
            }

            // Password guessing spread over many addresses: each client tries
            // a few times and does nothing else.
            const loginOnly = new Map();
            for (const c of clients) {
                if (c.cls !== 'human' || c.authAttempts === 0 || c.assets > 0) continue;
                if (c.authAttempts / c.n < 0.6) continue;
                let list = loginOnly.get(c.authPath);
                if (!list) { list = []; loginOnly.set(c.authPath, list); }
                list.push(c);
            }
            for (const [path, list] of loginOnly) {
                if (list.length < T.stuffingClients) continue;
                for (const c of list) suspect(c, 'Distributed login attempts', `One of ${list.length} clients that did nothing but try to log in at ${path}`);
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
