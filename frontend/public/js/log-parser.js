/**
 * Access Log Parser — Client-Side
 *
 * Turns access-log lines into requests: client address, time, method, URL,
 * status, size, referrer and User-Agent. Recognises nginx/Apache combined and
 * common, vhost-prefixed, JSON (nginx, Caddy, Traefik, Cloudflare), AWS load
 * balancer logs, and other space-separated layouts by looking at the columns.
 *
 * Needs RequestPaths (request-paths.js); uses BotDetector when it is loaded.
 */

const LogParser = (() => {
    const TS_REGEX = /\[(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]/;

    function requestPaths() {
        if (typeof RequestPaths !== 'undefined') return RequestPaths;
        return (typeof globalThis !== 'undefined' && globalThis.RequestPaths) || null;
    }

    // ─── Addresses ───

    // Numeric words allow compressed, expanded and hex-mapped forms to share
    // the same validation and network boundaries (e.g. ::ffff:c0a8:101).
    function ipv6Words(ip) {
        let address = ip.toLowerCase();
        if (address.includes('.')) {
            const split = address.lastIndexOf(':');
            const ipv4 = address.slice(split + 1);
            if (!isValidIPv4(ipv4)) return null;
            const octets = ipv4.split('.').map(Number);
            address = address.slice(0, split + 1) + ((octets[0] << 8) | octets[1]).toString(16) + ':' + ((octets[2] << 8) | octets[3]).toString(16);
        }
        const sides = address.split('::');
        if (sides.length > 2) return null;
        const left = sides[0] ? sides[0].split(':') : [];
        const right = sides[1] ? sides[1].split(':') : [];
        const groups = [...left, ...right];
        if (!groups.every(group => /^[0-9a-f]{1,4}$/.test(group))) return null;
        if (sides.length === 1 ? groups.length !== 8 : groups.length >= 8) return null;
        return [...left, ...Array(8 - groups.length).fill('0'), ...right].map(word => parseInt(word, 16));
    }

    function isValidIPv4(ip) {
        const parts = ip.split('.');
        return parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && Number(p) <= 255 && p === String(Number(p)));
    }

    function isValidIP(ip) {
        if (typeof ip !== 'string') return false;
        return ip.includes(':') ? ipv6Words(ip) !== null : isValidIPv4(ip);
    }

    /**
     * Unwrap an IPv4-mapped IPv6 address to its bare IPv4 form: nginx reports
     * the same client as `192.178.4.1` or `::ffff:192.178.4.1` depending on
     * the socket family.
     */
    function unwrapV4Mapped(ip) {
        if (typeof ip !== 'string' || !ip.includes(':')) return ip;
        const words = ipv6Words(ip);
        if (!words || !words.slice(0, 5).every(word => word === 0) || words[5] !== 0xffff) return ip;
        return [words[6] >>> 8, words[6] & 255, words[7] >>> 8, words[7] & 255].join('.');
    }

    /** One spelling per address (RFC 5952), so a client is counted once. */
    function canonicalIP(ip) {
        if (typeof ip !== 'string' || !ip.includes(':')) return ip;
        const words = ipv6Words(ip);
        if (!words) return ip;
        if (words.slice(0, 5).every(word => word === 0) && words[5] === 0xffff) {
            return [words[6] >>> 8, words[6] & 255, words[7] >>> 8, words[7] & 255].join('.');
        }
        let bestStart = -1, bestLen = 0;
        for (let i = 0; i < 8;) {
            if (words[i] !== 0) { i++; continue; }
            let j = i;
            while (j < 8 && words[j] === 0) j++;
            if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
            i = j;
        }
        const hex = words.map(word => word.toString(16));
        if (bestLen < 2) return hex.join(':');
        return hex.slice(0, bestStart).join(':') + '::' + hex.slice(bestStart + bestLen).join(':');
    }

    /**
     * Read a client address as servers write it: bare, `ip:port`,
     * `[v6]`, `[v6]:port`, or with a zone (`fe80::1%eth0`).
     * @returns {string|null} The address in canonical form, or null.
     */
    function parseClientToken(token) {
        if (typeof token !== 'string') return null;
        let t = token.trim().replace(/^["']+|["',]+$/g, '');
        const bracket = /^\[([^\]]+)\](?::\d+)?$/.exec(t);
        if (bracket) t = bracket[1];
        else if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(t)) t = t.slice(0, t.lastIndexOf(':'));
        const zone = t.indexOf('%');
        if (zone > 0) t = t.slice(0, zone);
        return isValidIP(t) ? canonicalIP(t) : null;
    }

    function isPrivateIP(ip) {
        try {
            const target = unwrapV4Mapped(ip);
            if (target.includes(':')) return isPrivateIPv6(target);
            return isPrivateIPv4(target);
        } catch {
            return true;
        }
    }

    function isPrivateIPv4(ip) {
        const parts = ip.split('.');
        if (parts.length !== 4) return true;
        const nums = parts.map(p => parseInt(p, 10));
        if (nums.some(n => isNaN(n) || n < 0 || n > 255)) return true;

        const [a, b] = nums;
        if (a === 10) return true;                              // 10.0.0.0/8
        if (a === 172 && b >= 16 && b <= 31) return true;       // 172.16.0.0/12
        if (a === 192 && b === 168) return true;                // 192.168.0.0/16
        if (a === 127) return true;                             // loopback
        if (a === 169 && b === 254) return true;                // link-local
        if (a === 100 && b >= 64 && b <= 127) return true;      // carrier-grade NAT
        if (a === 198 && (b === 18 || b === 19)) return true;   // benchmarking
        if (a === 0 || a >= 224) return true;                   // "this network", multicast, reserved
        return false;
    }

    function isPrivateIPv6(ip) {
        const words = ipv6Words(ip);
        if (!words) return true;
        const loopbackOrUnspecified = words.slice(0, 7).every(word => word === 0) && words[7] <= 1;
        return loopbackOrUnspecified ||
            (words[0] & 0xfe00) === 0xfc00 ||   // unique local
            (words[0] & 0xffc0) === 0xfe80 ||   // link-local
            (words[0] & 0xffc0) === 0xfec0 ||   // site-local (deprecated)
            (words[0] & 0xff00) === 0xff00;     // multicast
    }

    function ipv4ToInt(ip) {
        const p = ip.split('.');
        return (((+p[0]) << 24) | ((+p[1]) << 16) | ((+p[2]) << 8) | (+p[3])) >>> 0;
    }

    /**
     * Build a test for the address filter.
     *   a full address        that address only
     *   the start of one      `185.220.` or `185.220` matches 185.220.x.x, not 185.2200.x
     *   a CIDR block          IPv4 or IPv6
     * @returns {(ip: string) => boolean}
     */
    function ipFilterMatcher(term) {
        const t = String(term || '').trim().toLowerCase();
        if (!t) return () => true;
        if (t.includes('/')) {
            const [addr, bitsStr] = t.split('/');
            const bits = /^\d+$/.test(bitsStr) ? parseInt(bitsStr, 10) : NaN;
            const base = parseClientToken(addr);
            if (base && !base.includes(':') && bits >= 0 && bits <= 32) {
                const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
                const net = (ipv4ToInt(base) & mask) >>> 0;
                return ip => typeof ip === 'string' && !ip.includes(':') && ((ipv4ToInt(ip) & mask) >>> 0) === net;
            }
            if (base && base.includes(':') && bits >= 0 && bits <= 128) {
                const want = ipv6Words(base);
                return ip => {
                    if (typeof ip !== 'string' || !ip.includes(':')) return false;
                    const words = ipv6Words(ip);
                    if (!words) return false;
                    for (let i = 0, left = bits; i < 8 && left > 0; i++, left -= 16) {
                        const mask = left >= 16 ? 0xffff : (0xffff << (16 - left)) & 0xffff;
                        if ((words[i] & mask) !== (want[i] & mask)) return false;
                    }
                    return true;
                };
            }
            return () => false;
        }
        const full = parseClientToken(t);
        if (full) return ip => ip === full;
        return ip => {
            const s = String(ip || '').toLowerCase();
            if (!s.startsWith(t)) return false;
            if (s.length === t.length) return true;
            const last = t[t.length - 1];
            const next = s[t.length];
            return last === '.' || last === ':' || next === '.' || next === ':';
        };
    }

    /**
     * The client in an `X-Forwarded-For` list. Each proxy appends the address
     * it received the request from, so the right-most public entry is the last
     * one a proxy vouched for; entries to its left can be written by anyone.
     */
    function forwardedClient(list) {
        if (!list || list === '-') return null;
        const parts = String(list).split(',');
        let fallback = null;
        for (let i = parts.length - 1; i >= 0; i--) {
            const ip = parseClientToken(parts[i]);
            if (!ip) continue;
            if (!isPrivateIP(ip)) return ip;
            if (!fallback) fallback = ip;
        }
        return fallback;
    }

    function isAddressList(value) {
        if (!value || value === '-') return false;
        const parts = value.split(',');
        for (const part of parts) if (!isValidIP(part.trim())) return false;
        return true;
    }

    /**
     * Find a forwarded-address field among the extra fields a log format puts
     * after the User-Agent (stock nginx: `"$http_x_forwarded_for"`).
     * Addresses with a port are not taken: that is an upstream, not a client.
     * @returns {{ list: string, quoted: boolean }|null}
     */
    function forwardedFromTail(tail) {
        if (!tail) return null;
        const re = /"([^"]*)"|(\S+)/g;
        let m;
        for (let seen = 0; seen < 8 && (m = re.exec(tail)); seen++) {
            if (m[1] !== undefined) {
                if (isAddressList(m[1])) return { list: m[1], quoted: true };
                continue;
            }
            let value = m[2];
            if (!/^[0-9a-f:.]+,?$/i.test(value)) continue;
            // An unquoted list is written with spaces: `1.2.3.4, 5.6.7.8`.
            while (value.endsWith(',')) {
                const next = /\s*(\S+)/y;
                next.lastIndex = re.lastIndex;
                const more = next.exec(tail);
                if (!more) { value = value.slice(0, -1); break; }
                value += more[1];
                re.lastIndex = next.lastIndex;
            }
            if (isAddressList(value)) return { list: value, quoted: value.includes(',') };
        }
        return null;
    }

    // ─── Time ───

    const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

    function wallClock(y, mo, d, h, mi, s) {
        if (mo < 0 || mo > 11 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59) return null;
        const date = new Date(Date.UTC(y, mo, d, h, mi, s));
        if (date.getUTCFullYear() !== y || date.getUTCMonth() !== mo || date.getUTCDate() !== d) return null;
        return date;
    }

    // The offset is not applied, but an impossible one marks a corrupt time.
    function validOffset(hours, minutes) {
        return (hours === undefined || +hours <= 23) && (minutes === undefined || +minutes <= 59);
    }

    /**
     * Read a log timestamp.
     *
     * The result is the clock time as the server wrote it, stored as if it
     * were UTC: `13:55:36 -0700` and `13:55:36+05:30` both read 13:55:36. The
     * dashboard shows a log in its own clock, whatever the viewer's time zone.
     * Epoch numbers have no clock of their own and are read as UTC.
     *
     * @returns {Date|null}
     */
    function parseTimestamp(tsStr) {
        if (!tsStr || typeof tsStr !== 'string') return null;
        const str = tsStr.trim();

        // ISO-8601: 2026-10-01T00:00:00Z, 2026-10-01T05:30:00.123+05:30, 2026-10-01 00:00:00
        let m = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?\s*(?:Z|UTC|GMT|[+-](\d{2})(?::?(\d{2}))?)?$/i.exec(str);
        if (m) return validOffset(m[7], m[8]) ? wallClock(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) : null;

        // Common Log Format: 01/Oct/2026:00:00:00 +0000
        m = /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?(?:\s*(?:Z|UTC|GMT|[+-](\d{2}):?(\d{2})))?$/.exec(str);
        if (m) {
            const month = MONTHS[m[2].toLowerCase()];
            if (month === undefined || !validOffset(m[7], m[8])) return null;
            return wallClock(+m[3], month, +m[1], +m[4], +m[5], +m[6]);
        }

        // Epoch: seconds (with or without a fraction), milli-, micro- or nanoseconds
        m = /^(\d{10})(?:\.\d+)?$/.exec(str);
        if (m) return new Date(Number(m[1]) * 1000);
        if (/^\d{13}$/.test(str)) return new Date(Number(str));
        if (/^\d{16}$/.test(str)) return new Date(Math.floor(Number(str) / 1000));
        if (/^\d{19}$/.test(str)) return new Date(Number(str.slice(0, 13)));

        // RFC 1123: Sat, 10 Oct 2026 13:55:36 GMT
        m = /^(?:[A-Za-z]{3},\s*)?(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})/.exec(str);
        if (m) {
            const month = MONTHS[m[2].toLowerCase()];
            if (month === undefined) return null;
            return wallClock(+m[3], month, +m[1], +m[4], +m[5], +m[6]);
        }
        return null;
    }

    /**
     * First and last time of a log, ignoring stray dates (one line with a
     * wrong year would otherwise stretch the timeline over years).
     * @param {number[]} times - Milliseconds.
     * @returns {{ min: number, max: number, outliers: number }|null}
     */
    function timeBounds(times) {
        const n = times.length;
        if (n === 0) return null;
        let min = Infinity, max = -Infinity;
        for (let i = 0; i < n; i++) {
            const t = times[i];
            if (t < min) min = t;
            if (t > max) max = t;
        }
        if (n < 20 || max - min <= 2 * 86400000) return { min, max, outliers: 0 };
        const sorted = Float64Array.from(times).sort();
        const lo = sorted[Math.floor(n * 0.005)];
        const hi = sorted[Math.max(0, Math.ceil(n * 0.995) - 1)];
        const margin = Math.max(hi - lo, 86400000);
        const from = lo - margin, to = hi + margin;
        let first = 0, last = n - 1;
        while (first < n && sorted[first] < from) first++;
        while (last >= 0 && sorted[last] > to) last--;
        if (first > last) return { min, max, outliers: 0 };
        return { min: sorted[first], max: sorted[last], outliers: first + (n - 1 - last) };
    }

    /**
     * Does this User-Agent belong to a known crawler (bot or impersonator)?
     *
     * Keep the existing 403 policy's crawler exception. Internal exclusions
     * take precedence regardless of User-Agent; a health checker using cURL
     * must not bypass the internal-traffic option.
     *
     * @param {string|null} ua - Raw User-Agent string.
     * @returns {boolean} True if the UA matches a known bot pattern.
     */
    function isBotUserAgent(ua) {
        if (!ua || ua === '-') return false;
        try {
            // `detectBotName(ua)` is the UA -> name entry point.
            // `isKnownBot(name)` takes an already-resolved bot NAME and answers a
            // different question ("does this publisher publish CIDRs?"), so
            // passing it a raw UA was meaningless - it happened to return truthy
            // for some UAs only because the UA string contains a feed key as a
            // substring, and false for others. Use detectBotName and simply
            // treat "resolved to a bot name" as the answer.
            if (typeof BotDetector !== 'undefined' && BotDetector.detectBotName) {
                const name = BotDetector.detectBotName(ua);
                if (name) return true;
                // A resolvable non-bot (e.g. cURL/Wget) is still a scripted
                // client, so do not treat "not a known bot" as "human".
                return /\b(bot|crawler|spider|slurp|archiver|scraper|curl|wget|python-requests|headlesschrome)/i.test(ua);
            }
        } catch {
            // Fall through to the regex fallback below.
        }
        // Last-resort fallback for when bot-detector.js could not load at all.
        // NOTE: the leading `\b` is deliberately absent from the `bot`/`spider`
        // alternatives - `\bbot\b` cannot match inside camelCase names like
        // ClaudeBot or GPTBot, which is exactly the class of impersonator this
        // guard exists to preserve. A missing `\b` risks a false positive on
        // some word containing "bot", which only keeps a line for closer
        // inspection downstream - far cheaper than dropping a real spoof.
        return /(bot|crawler|spider|slurp|archiver|scraper|curl|wget|python-requests|headlesschrome)/i.test(ua);
    }

    const KNOWN_METHOD_RE = /^[A-Za-z][A-Za-z-]{1,19}$/;

    /**
     * Split a request line into method, target and protocol version.
     * The target is everything between the method and a trailing `HTTP/x`, so
     * a URL that contains a space stays whole. A line that is not HTTP (a TLS
     * handshake sent to the HTTP port) has no method and no URL.
     */
    function splitRequest(request) {
        const none = { method: null, url: null, httpVersion: null };
        if (typeof request !== 'string') return none;
        const req = request.trim();
        if (!req || req === '-') return none;
        const space = req.search(/\s/);
        if (space === -1) return none;
        const method = req.slice(0, space);
        const wordMethod = KNOWN_METHOD_RE.test(method);
        let rest = req.slice(space).trim();
        let httpVersion = null;
        const version = /\s+(HTTP\/\d(?:\.\d)?)$/i.exec(rest);
        if (version) {
            httpVersion = version[1].toUpperCase();
            rest = rest.slice(0, version.index);
        }
        // Without a protocol version only a word can be a method; with one,
        // whatever stood in the method position is reported as it was sent.
        if (!wordMethod && !httpVersion) return none;
        return { method: wordMethod ? method.toUpperCase() : method, url: rest || null, httpVersion };
    }

    function isLikelyUserAgent(str) {
        if (!str || str === '-') return false;
        return /(Mozilla|AppleWebKit|Chrome|Safari|Firefox|Edge|Gecko|curl|Wget|bot|spider|crawler|archiver|scraper|python|Go-http|Java|Postman)/i.test(str);
    }

    function isLikelyReferer(str) {
        if (!str || str === '-') return true;
        return /^https?:\/\//i.test(str);
    }

    function stripQuotes(str) {
        if (typeof str !== 'string') return '';
        return str.replace(/^["'\[]+|["'\]]+$/g, '');
    }

    // Apache writes a quote inside a field as \" ; nginx writes \x22.
    function unescapeField(str) {
        return str.indexOf('\\"') === -1 ? str : str.replace(/\\"/g, '"');
    }

    // Exact paths only: do not hide /healthcare or nested API resources.
    const HEALTH_CHECK_PATHS = new Set(['/health', '/healthz', '/healthcheck', '/health-check', '/health_check', '/readyz', '/livez', '/_health']);

    /**
     * A monitoring probe: a GET or HEAD to a health endpoint that was answered
     * normally. Anything else sent to that path (a POST, an error) stays in.
     */
    function isHealthCheck(method, url, statusCode) {
        if (!url) return false;
        if (method && method !== 'GET' && method !== 'HEAD') return false;
        if (statusCode >= 400) return false;
        const paths = requestPaths();
        const path = paths ? paths.normalizePath(url) : url.split(/[?#]/)[0].replace(/\/+$/, '');
        if (HEALTH_CHECK_PATHS.has(path)) return true;
        return /^\/(?:healthz|livez|readyz)\/[a-z0-9_-]+$/.test(path);
    }

    // Kept for callers that only have a URL.
    function isHealthCheckPath(url) {
        return isHealthCheck(null, url, 0);
    }

    /**
     * A blocked request that is still worth seeing: an attack path, or an
     * attempt to log in. "Ignore 403" hides ordinary refusals, not these.
     */
    function isEvidence(method, url) {
        const paths = requestPaths();
        if (!paths || !url) return false;
        return paths.attackSignature(url) !== null || paths.isAuthRequest(method, url);
    }

    function option(options, name) {
        return (options && options[name] !== undefined) ? Boolean(options[name]) : true;
    }

    /**
     * Turn the raw fields of one line into a request, applying the exclusions.
     *
     * @param {object} f - remote (canonical address or null), forwarded
     *   ({ list, quoted } or null), time (string), request (string) or
     *   method/url/httpVersion, status, bytes, referrer, userAgent.
     * @param {object} options - skip403, skipInternal, clientIp ('auto' | 'remote' | 'forwarded').
     * @param {object} [ctx] - Per-file findings: useForwarded.
     */
    function finish(f, options, ctx, line) {
        const skip403 = option(options, 'skip403');
        const skipInternal = option(options, 'skipInternal');
        const mode = (options && options.clientIp) || 'auto';

        let ip = f.remote;
        let viaForwarded = false;
        if (f.forwarded && mode !== 'remote') {
            const trusted = mode === 'forwarded' || !ip || (ctx && ctx.useForwarded) || (f.forwarded.quoted && isPrivateIP(ip));
            if (trusted) {
                const client = forwardedClient(f.forwarded.list);
                if (client) { ip = client; viaForwarded = true; }
            }
        }
        if (!ip) return { valid: false, reason: 'Invalid IP format', reasonType: 'invalid', line };

        let timestamp = null;
        let timeSec = 0;
        if (f.time) {
            timestamp = parseTimestamp(f.time);
            if (timestamp) timeSec = Math.floor(timestamp.getTime() / 1000);
        }

        const req = f.request !== undefined ? splitRequest(f.request) : { method: f.method || null, url: f.url || null, httpVersion: f.httpVersion || null };
        const status = parseInt(f.status, 10);
        const statusCode = status >= 100 && status <= 599 ? status : 0;

        if (skipInternal && isPrivateIP(ip)) {
            return { valid: false, reason: 'Private/reserved IP', reasonType: 'privateIP', timestamp, timeSec, line };
        }
        if (skipInternal && isHealthCheck(req.method, req.url, statusCode)) {
            return { valid: false, reason: 'Health-check endpoint', reasonType: 'healthCheck', timestamp, timeSec, line };
        }

        const size = Number(f.bytes);
        const responseSize = size > 0 && Number.isFinite(size) ? Math.floor(size) : 0;
        const referrer = f.referrer && f.referrer !== '-' ? f.referrer : null;
        const userAgent = f.userAgent && f.userAgent !== '-' ? f.userAgent : null;
        const isCrawler = isBotUserAgent(userAgent);

        if (skip403 && statusCode === 403 && !isCrawler && !isEvidence(req.method, req.url)) {
            return { valid: false, reason: '403 Forbidden (blocked)', reasonType: 'forbidden', timestamp, timeSec, line };
        }

        let botName = 'None';
        if (typeof BotDetector !== 'undefined' && BotDetector.detectBotName && userAgent) {
            const detected = BotDetector.detectBotName(userAgent);
            if (detected) botName = detected;
            else if (isCrawler) botName = 'Scripted/Bot';
        } else if (isCrawler) {
            botName = 'Scripted/Bot';
        }

        return {
            valid: true,
            ip,
            remoteAddr: f.remote || ip,
            viaForwarded,
            timestamp,
            timeSec,
            method: req.method,
            url: req.url,
            httpVersion: req.httpVersion,
            statusCode,
            responseSize,
            referrer,
            userAgent,
            botName,
            isCrawler,
            line
        };
    }

    // ─── Formats ───
    // Each extractor returns the raw fields of a line, or null when the line
    // is not in its format. A quoted field may contain \" (Apache).

    const Q = '"((?:[^"\\\\]|\\\\.)*)"';
    const TAIL = `(\\d{3}|-) (\\d+|-)(?: ${Q}(?: ${Q})?)?(?:\\s+(.*))?$`;
    // remote ident user [time] "request" status bytes ["referrer" ["user agent"]] [extra fields]
    // The user may contain spaces when ident is "-".
    const LOG_REGEX = new RegExp(`^(\\S+) (?:\\S+ (\\S+)|- (.+?)) \\[([^\\]]+)\\] ${Q} ${TAIL}`);
    // host[:port] remote ident user [time] ...
    const VHOST_REGEX = new RegExp(`^(\\S+)\\s+(\\S+) \\S+ (\\S+) \\[([^\\]]+)\\] ${Q} ${TAIL}`);
    // AWS load balancers: [type] time elb client:port target:port t t t elb_status target_status received sent "request" "user agent" ...
    const ALB_REGEX = new RegExp(`^(?:(?:https?|h2|grpcs?|wss?|tcp|tls) )?(\\d{4}-\\d{2}-\\d{2}T[\\d:.]+Z?) \\S+ (\\S+) \\S+ (?:-?[\\d.]+ ){3}(\\d{3}|-) (?:\\d{3}|-) \\d+ (\\d+) ${Q} ${Q}`);

    function extractStandard(line) {
        const m = LOG_REGEX.exec(line);
        if (!m) return null;
        const remote = parseClientToken(m[1]);
        if (!remote) return null;
        return {
            remote, time: m[4], request: unescapeField(m[5]), status: m[6], bytes: m[7],
            referrer: m[8] === undefined ? null : unescapeField(m[8]),
            userAgent: m[9] === undefined ? null : unescapeField(m[9]),
            forwarded: m[10] ? forwardedFromTail(m[10]) : null,
        };
    }

    function extractVhost(line) {
        const m = VHOST_REGEX.exec(line);
        if (!m) return null;
        const remote = parseClientToken(m[2]);
        if (!remote) return null;
        return {
            remote, time: m[4], request: unescapeField(m[5]), status: m[6], bytes: m[7],
            referrer: m[8] === undefined ? null : unescapeField(m[8]),
            userAgent: m[9] === undefined ? null : unescapeField(m[9]),
            forwarded: m[10] ? forwardedFromTail(m[10]) : null,
        };
    }

    function extractAlb(line) {
        const m = ALB_REGEX.exec(line);
        if (!m) return null;
        const remote = parseClientToken(m[2]);
        if (!remote) return null;
        return { remote, time: m[1], request: m[5], status: m[3], bytes: m[4], referrer: null, userAgent: m[6], forwarded: null };
    }

    function firstValue(...values) {
        for (const v of values) {
            if (v === undefined || v === null || v === '') continue;
            if (typeof v === 'string' || typeof v === 'number') return String(v);
        }
        return '';
    }

    /**
     * JSON access logs: nginx (`escape=json`), Caddy, Traefik, Cloudflare
     * Logpush, and Docker's `{"log": "<line>"}` wrapper around a text line.
     */
    function extractJson(line) {
        if (line[0] !== '{') return null;
        let obj;
        try {
            obj = JSON.parse(line);
        } catch {
            return null;
        }
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
        if (typeof obj.log === 'string' && (obj.stream !== undefined || obj.time !== undefined)) {
            return { wrapped: obj.log.trim() };
        }

        const req = (obj.request && typeof obj.request === 'object') ? obj.request : {};
        const headers = (req.headers && typeof req.headers === 'object') ? req.headers : {};
        const header = name => {
            const v = headers[name] !== undefined ? headers[name] : headers[name.toLowerCase()];
            return Array.isArray(v) ? firstValue(v[0]) : firstValue(v);
        };

        const remote = parseClientToken(firstValue(
            obj.remote_addr, obj.client_ip, obj.clientip, obj.client, obj.remote_ip, obj.ip,
            obj.ClientIP, obj.ClientHost, obj.ClientAddr, obj.c_ip, req.client_ip, req.remote_ip, req.remote_addr));
        const forwardedList = firstValue(
            obj.http_x_forwarded_for, obj.x_forwarded_for, obj.xff, obj.http_x_real_ip, obj.x_real_ip,
            obj['request_X-Forwarded-For'], header('X-Forwarded-For'));
        const forwarded = forwardedList && forwardedList !== '-' && isAddressList(forwardedList) ? { list: forwardedList, quoted: true } : null;
        if (!remote && !forwarded) return null;

        let method = firstValue(obj.request_method, obj.method, obj.RequestMethod, obj.ClientRequestMethod, req.method, obj.verb) || null;
        let url = firstValue(obj.request_uri, obj.uri, obj.path, obj.url, obj.RequestPath, obj.ClientRequestURI, req.uri) || null;
        let httpVersion = firstValue(obj.server_protocol, obj.http_version, obj.protocol, obj.RequestProtocol, obj.ClientRequestProtocol, req.proto) || null;
        if (typeof obj.request === 'string') {
            const parts = splitRequest(obj.request);
            if (parts.method) {
                method = method || parts.method;
                url = url || parts.url;
                httpVersion = httpVersion || parts.httpVersion;
            } else if (!url && obj.request.trim() !== '-' && obj.request.trim()[0] === '/') {
                url = obj.request.trim();
            }
        }
        if (method) method = KNOWN_METHOD_RE.test(method) ? method.toUpperCase() : null;

        return {
            remote,
            forwarded,
            time: firstValue(obj.time_local, obj.time_iso8601, obj.timestamp, obj.time, obj['@timestamp'], obj.date,
                obj.ts, obj.msec, obj.StartUTC, obj.StartLocal, obj.EdgeStartTimestamp, obj.start_time).replace(/^\[|\]$/g, ''),
            method, url, httpVersion,
            status: firstValue(obj.status, obj.status_code, obj.code, obj.response_status, obj.DownstreamStatus, obj.OriginStatus, obj.EdgeResponseStatus, obj.response_code),
            bytes: firstValue(obj.body_bytes_sent, obj.bytes_sent, obj.bytes, obj.response_size, obj.response_length, obj.size, obj.DownstreamContentSize, obj.EdgeResponseBytes),
            referrer: firstValue(obj.http_referer, obj.referer, obj.referrer, obj.request_Referer, obj.ClientRequestReferer, header('Referer')) || null,
            userAgent: firstValue(obj.http_user_agent, obj.user_agent, obj.agent, obj.useragent, obj['request_User-Agent'], obj.ClientRequestUserAgent, header('User-Agent')) || null,
        };
    }

    /**
     * Tokenize a line, keeping quoted and bracketed parts whole.
     */
    function tokenizeLine(line) {
        const tokens = [];
        let cur = '';
        let inQuote = false;
        let inBracket = false;
        for (let i = 0; i < line.length; i++) {
            const ch = line[i];
            if (ch === '\\' && inQuote && i + 1 < line.length) {
                cur += ch + line[++i];
            } else if (ch === '"' && !inBracket) {
                inQuote = !inQuote;
                cur += ch;
            } else if (ch === '[' && !inQuote) {
                inBracket = true;
                cur += ch;
            } else if (ch === ']' && inBracket && !inQuote) {
                inBracket = false;
                cur += ch;
            } else if ((ch === ' ' || ch === '\t') && !inQuote && !inBracket) {
                if (cur.length > 0) {
                    tokens.push(cur);
                    cur = '';
                }
            } else {
                cur += ch;
            }
        }
        if (cur.length > 0) tokens.push(cur);
        return tokens;
    }

    function tokenAddress(token) {
        const clean = stripQuotes(token || '');
        if (!clean) return null;
        return clean.includes(',') ? forwardedClient(clean) : parseClientToken(clean);
    }

    /**
     * Work out which column holds what in a space-separated layout that is
     * none of the known formats. A column is accepted when nine in ten sample
     * lines fit, so one damaged line does not decide for the whole file.
     */
    function compileDynamicSchema(candidates) {
        if (!candidates || candidates.length === 0) return null;

        const allRows = candidates.map(tokenizeLine).filter(r => r.length >= 3);
        if (allRows.length === 0) return null;
        const lengths = new Map();
        for (const r of allRows) lengths.set(r.length, (lengths.get(r.length) || 0) + 1);
        let width = 0, widthRows = 0;
        for (const [len, n] of lengths) if (n > widthRows || (n === widthRows && len > width)) { width = len; widthRows = n; }
        const rows = allRows.filter(r => r.length === width);

        const mostly = (col, test) => {
            let ok = 0;
            for (const r of rows) if (test(r[col])) ok++;
            return ok / rows.length >= 0.9;
        };
        const some = (col, test) => rows.some(r => test(r[col]));
        const quoted = v => v[0] === '"';
        const colMap = { ipCol: -1, timeCol: -1, reqCol: -1, statusCol: -1, bytesCol: -1, refCol: -1, uaCol: -1 };
        const taken = new Set();
        const firstCol = (from, test) => {
            for (let col = Math.max(0, from); col < width; col++) if (!taken.has(col) && test(col)) { taken.add(col); return col; }
            return -1;
        };

        colMap.ipCol = firstCol(0, col => mostly(col, v => tokenAddress(v) !== null));
        colMap.timeCol = firstCol(0, col => mostly(col, v => parseTimestamp(stripQuotes(v)) !== null));
        colMap.reqCol = firstCol(0, col => some(col, quoted) && mostly(col, v => {
            const clean = stripQuotes(v);
            return clean === '-' || clean[0] === '/' || splitRequest(clean).method !== null;
        }));
        // Status and size follow the request in every layout seen; looking
        // there first keeps a syslog day-of-month from being read as a size.
        const after = colMap.reqCol !== -1 ? colMap.reqCol + 1 : 0;
        colMap.statusCol = firstCol(after, col => mostly(col, v => /^[1-5]\d\d$/.test(v)));
        colMap.bytesCol = firstCol(colMap.statusCol !== -1 ? colMap.statusCol + 1 : after,
            col => mostly(col, v => /^\d+$|^-$/.test(v)) && some(col, v => /^\d+$/.test(v)));

        const quotedCols = [];
        for (let col = 0; col < width; col++) if (!taken.has(col) && some(col, quoted)) quotedCols.push(col);
        const values = col => rows.map(r => stripQuotes(r[col]));
        const isUrl = v => v.startsWith('http://') || v.startsWith('https://');
        if (quotedCols.length === 1) {
            if (values(quotedCols[0]).some(isUrl)) colMap.refCol = quotedCols[0];
            else colMap.uaCol = quotedCols[0];
        } else if (quotedCols.length >= 2) {
            const [colA, colB] = quotedCols;
            const count = (col, test) => values(col).filter(test).length;
            const aUa = count(colA, isLikelyUserAgent), bUa = count(colB, isLikelyUserAgent);
            const aRef = count(colA, isUrl), bRef = count(colB, isUrl);
            // The column with more User-Agent-like values is the User-Agent.
            const aIsUa = aUa !== bUa ? aUa > bUa : aRef < bRef;
            colMap.uaCol = aIsUa ? colA : colB;
            colMap.refCol = aIsUa ? colB : colA;
        }

        // Without a status column it is not an access log (an error log has
        // addresses and quoted requests too).
        if (colMap.ipCol === -1 || colMap.statusCol === -1 || (colMap.reqCol === -1 && colMap.timeCol === -1)) return null;
        return { type: 'dynamic', colMap, extract: createDynamicExtractor(colMap) };
    }

    function createDynamicExtractor(colMap) {
        const minCols = Math.max(colMap.ipCol, colMap.timeCol, colMap.statusCol, colMap.reqCol);
        return function extractDynamic(line) {
            const tokens = tokenizeLine(line);
            if (tokens.length <= minCols) return null;
            const remote = tokenAddress(tokens[colMap.ipCol]);
            if (!remote) return null;
            const status = colMap.statusCol !== -1 ? tokens[colMap.statusCol] : '';
            if (colMap.statusCol !== -1 && !/^(?:\d{3}|-)$/.test(status)) return null;
            const field = col => (col !== -1 && tokens[col] !== undefined) ? unescapeField(stripQuotes(tokens[col])) : null;
            return {
                remote,
                forwarded: null,
                time: field(colMap.timeCol),
                request: field(colMap.reqCol) || '',
                status,
                bytes: colMap.bytesCol !== -1 ? tokens[colMap.bytesCol] : 0,
                referrer: field(colMap.refCol),
                userAgent: field(colMap.uaCol),
            };
        };
    }

    /**
     * W3C extended format (IIS): the `#Fields:` header names the columns.
     */
    function compileW3C(fieldsLine) {
        const names = fieldsLine.trim().split(/\s+/);
        const col = name => names.indexOf(name);
        const ip = col('c-ip');
        const status = col('sc-status');
        if (ip === -1 || status === -1) return null;
        const date = col('date'), time = col('time'), method = col('cs-method'), stem = col('cs-uri-stem'), query = col('cs-uri-query');
        const bytes = col('sc-bytes'), ua = col('cs(User-Agent)'), ref = col('cs(Referer)'), version = col('cs-version');
        const forwarded = col('X-Forwarded-For');
        const text = v => (v === undefined || v === '-') ? null : v.replace(/\+/g, ' ');
        return function extractW3C(line) {
            if (line[0] === '#') return null;
            const t = line.split(' ');
            if (t.length !== names.length) return null;
            const remote = parseClientToken(t[ip]);
            if (!remote) return null;
            const q = query !== -1 && t[query] !== '-' ? '?' + t[query] : '';
            const list = forwarded !== -1 ? text(t[forwarded]) : null;
            return {
                remote,
                forwarded: list && isAddressList(list.replace(/\s/g, '')) ? { list, quoted: true } : null,
                time: date !== -1 && time !== -1 ? `${t[date]} ${t[time]}` : null,
                method: method !== -1 && KNOWN_METHOD_RE.test(t[method]) ? t[method].toUpperCase() : null,
                url: stem !== -1 && t[stem] !== '-' ? t[stem] + q : null,
                httpVersion: version !== -1 ? text(t[version]) : null,
                status: t[status],
                bytes: bytes !== -1 ? t[bytes] : 0,
                referrer: ref !== -1 ? text(t[ref]) : null,
                userAgent: ua !== -1 ? text(t[ua]) : null,
            };
        };
    }

    const EXTRACTORS = { standard: extractStandard, vhost: extractVhost, alb: extractAlb, json: extractJson };
    // Lines forwarded through syslog carry `Oct 10 13:55:36 host tag: ` (or an
    // ISO time) in front of the access-log line.
    const SYSLOG_PREFIX_RE = /^(?:<\d+>)?(?:[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+) \S+ [^\s:]+(?:\[\d+\])?: /;
    const FORMAT_ORDER = ['standard', 'vhost', 'alb', 'json'];

    /**
     * Build the parser for one file. The detected format is tried first; a
     * line in another known format is still read, so mixed files work in any
     * order. A line that fits no format is invalid: nothing is guessed from a
     * single line.
     */
    function makeLineParser(primary, ctx = {}, customExtract = null) {
        const order = [primary, ...FORMAT_ORDER.filter(type => type !== primary)];
        const parse = (rawLine, options, depth = 0) => {
            const line = rawLine ? rawLine.trim() : '';
            if (!line) return { valid: false, reason: 'Empty line', reasonType: 'invalid' };
            for (const type of order) {
                let fields = EXTRACTORS[type] ? EXTRACTORS[type](line) : (customExtract ? customExtract(line) : null);
                if (!fields) continue;
                if (fields.wrapped !== undefined) {
                    return depth === 0 ? parse(fields.wrapped, options, 1) : { valid: false, reason: 'Unparseable log format', reasonType: 'invalid', line };
                }
                if (ctx.swapRefUa && type !== 'json' && type !== 'alb') {
                    fields = { ...fields, referrer: fields.userAgent, userAgent: fields.referrer };
                }
                return finish(fields, options || {}, ctx, line);
            }
            if (depth === 0) {
                const prefix = SYSLOG_PREFIX_RE.exec(line);
                if (prefix) return parse(line.slice(prefix[0].length), options, 1);
            }
            const space = line.indexOf(' ');
            const startsWithAddress = parseClientToken(space > 0 ? line.slice(0, space) : line) !== null;
            return {
                valid: false,
                reason: startsWithAddress ? 'Unparseable log format' : 'Invalid IP format',
                reasonType: 'invalid',
                line
            };
        };
        return (rawLine, options) => parse(rawLine, options, 0);
    }

    /** Parse one line in any known format (no per-file findings). */
    const parseLine = makeLineParser('standard');

    /** Parse one JSON access-log line. */
    function parseJsonLine(rawLine, options = {}) {
        const line = rawLine ? rawLine.trim() : '';
        if (!line) return { valid: false, reason: 'Empty line', reasonType: 'invalid' };
        try {
            JSON.parse(line);
        } catch {
            return { valid: false, reason: 'Invalid JSON log line', reasonType: 'invalid', line };
        }
        return makeLineParser('json')(line, options);
    }

    const SAMPLE_LINES = 200;

    /**
     * Decide the format of a file from its first lines.
     *
     * Every known format is tried on every sample line and the one that fits
     * most lines wins, so a few damaged or foreign lines do not change the
     * choice. The sample also tells whether the server sits behind a proxy
     * that records the real client in a forwarded-address field.
     *
     * @param {string[]|string} sampleLines
     * @returns {{ type: string, parseLine: Function, useForwarded: boolean, swapRefUa: boolean, colMap?: object }}
     */
    function detectFormat(sampleLines) {
        const sample = (Array.isArray(sampleLines) ? sampleLines : String(sampleLines || '').split('\n'))
            .map(l => (l ? l.trim() : ''));
        const candidates = sample.filter(l => l.length > 0 && l[0] !== '#').slice(0, SAMPLE_LINES);

        const header = sample.slice(0, 50).find(l => /^#Fields:/i.test(l));
        const w3c = header ? compileW3C(header.replace(/^#Fields:/i, '')) : null;
        if (w3c) {
            return { type: 'w3c', parseLine: makeLineParser('w3c', { useForwarded: false, swapRefUa: false }, w3c), useForwarded: false, swapRefUa: false };
        }

        if (candidates.length === 0) {
            return { type: 'standard', parseLine, useForwarded: false, swapRefUa: false };
        }

        const hits = { standard: 0, vhost: 0, alb: 0, json: 0 };
        const fieldsOf = [];
        for (const line of candidates) {
            let found = null;
            for (const type of FORMAT_ORDER) {
                const fields = EXTRACTORS[type](line);
                if (fields) { hits[type]++; found = fields; break; }
            }
            if (!found) {
                const prefix = SYSLOG_PREFIX_RE.exec(line);
                const inner = prefix ? extractStandard(line.slice(prefix[0].length)) : null;
                if (inner) { hits.standard++; found = inner; }
            }
            fieldsOf.push(found);
        }

        let type = 'standard';
        for (const candidate of FORMAT_ORDER) if (hits[candidate] > hits[type]) type = candidate;
        const recognised = hits.standard + hits.vhost + hits.alb + hits.json;

        let dynamic = null;
        if (recognised < candidates.length / 2) {
            dynamic = compileDynamicSchema(candidates);
            if (dynamic) type = 'dynamic';
        }

        const ctx = { useForwarded: false, swapRefUa: false };
        const parsed = fieldsOf.filter(f => f && f.wrapped === undefined);

        // Behind a proxy or CDN the connecting address is the proxy. That is
        // the case when nearly every line carries a forwarded address and
        // those addresses vary more than the connecting ones do.
        if (parsed.length >= 10) {
            const remotes = new Set();
            const forwarded = new Set();
            let withForwarded = 0;
            for (const f of parsed) {
                if (f.remote) remotes.add(f.remote);
                const client = f.forwarded ? forwardedClient(f.forwarded.list) : null;
                if (client) { withForwarded++; forwarded.add(client); }
            }
            ctx.useForwarded = withForwarded / parsed.length >= 0.9 && forwarded.size > remotes.size;
        }

        // A layout that writes the User-Agent before the referrer.
        if (type === 'standard' || type === 'vhost') {
            let swapped = 0, normal = 0;
            for (const f of parsed) {
                if (isLikelyUserAgent(f.userAgent)) normal++;
                else if (f.referrer && !/^https?:\/\//i.test(f.referrer) && isLikelyUserAgent(f.referrer) && isLikelyReferer(f.userAgent)) swapped++;
            }
            ctx.swapRefUa = swapped > normal;
        }

        return {
            type,
            parseLine: makeLineParser(type, ctx, dynamic ? dynamic.extract : null),
            useForwarded: ctx.useForwarded,
            swapRefUa: ctx.swapRefUa,
            ...(dynamic ? { colMap: dynamic.colMap } : {}),
        };
    }

    /**
     * Parse access-log text.
     * @param {string} logText
     * @param {Object} [options]
     * @param {boolean} [options.skip403=true] - Leave out ordinary 403 responses.
     * @param {boolean} [options.skipInternal=true] - Leave out private addresses and health checks.
     * @param {'auto'|'remote'|'forwarded'} [options.clientIp='auto'] - Which address is the client.
     */
    function parseIPs(logText, options = {}) {
        const skip403 = options.skip403 !== false;
        const skipInternal = options.skipInternal !== false;
        const ips = [];
        const userAgents = [];
        const parsedLines = [];
        const skippedLines = [];
        const skipCounts = { privateIP: 0, healthCheck: 0, forbidden: 0, invalid: 0 };
        let validLines = 0;
        let forwardedLines = 0;
        const times = [];
        const logEntries = [];

        const lines = logText.split(/\r\n|\n|\r/);
        const format = detectFormat(lines);
        const lineParser = format.parseLine;

        for (const rawLine of lines) {
            if (!rawLine || !rawLine.trim() || rawLine[0] === '#') continue;
            const parsed = lineParser(rawLine, options);

            if (parsed.timestamp) times.push(parsed.timestamp.getTime());
            if (parsed.reasonType !== 'invalid') validLines++;

            if (!parsed.valid) {
                skippedLines.push({ reason: parsed.reason, line: rawLine.trim() });
                if (parsed.reasonType) skipCounts[parsed.reasonType]++;
                continue;
            }
            if (parsed.viaForwarded) forwardedLines++;

            logEntries.push({
                ip: parsed.ip,
                timestamp: parsed.timestamp,
                method: parsed.method,
                url: parsed.url,
                http_version: parsed.httpVersion,
                status_code: parsed.statusCode,
                response_size: parsed.responseSize,
                referrer: parsed.referrer,
                user_agent: parsed.userAgent,
                raw_line: parsed.line
            });

            ips.push(parsed.ip);
            userAgents.push(parsed.userAgent || '-');
            parsedLines.push({ ip: parsed.ip, line: parsed.line, user_agent: parsed.userAgent || '-' });
        }

        let logSpanMinutes = 0;
        let logStart = null;
        let logEnd = null;
        let minTimestamp = 0;
        let maxTimestamp = 0;
        const bounds = timeBounds(times);
        if (bounds) {
            minTimestamp = bounds.min;
            maxTimestamp = bounds.max;
            logSpanMinutes = Math.floor((maxTimestamp - minTimestamp) / 60000);
            logStart = formatTimestamp(new Date(minTimestamp));
            logEnd = formatTimestamp(new Date(maxTimestamp));
        }

        return {
            ips,
            userAgents,
            parsedLines,
            skippedLines,
            skipCounts,
            validLines,
            options: { skip403, skipInternal },
            format: format.type,
            // How many requests took their client from a forwarded-address field.
            forwardedLines,
            strayTimestamps: bounds ? bounds.outliers : 0,
            logSpanMinutes,
            logStart,
            logEnd,
            minTimestamp,
            maxTimestamp,
            logEntries,
        };
    }

    function formatTimestamp(date) {
        const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const d = String(date.getUTCDate()).padStart(2, '0');
        const m = months[date.getUTCMonth()];
        const y = date.getUTCFullYear();
        const h = String(date.getUTCHours()).padStart(2, '0');
        const min = String(date.getUTCMinutes()).padStart(2, '0');
        const sec = String(date.getUTCSeconds()).padStart(2, '0');
        return `${d}/${m}/${y} ${h}:${min}:${sec}`;
    }

    /**
     * Filter log text to only lines within last N minutes relative to latest timestamp.
     */
    function filterByTime(logText, minutes) {
        if (minutes <= 0) return logText;

        const lines = logText.split('\n');
        const timestamped = [];

        for (const line of lines) {
            const m = line.match(TS_REGEX);
            if (m) {
                const ts = parseTimestamp(m[1]);
                if (ts) timestamped.push({ ts, line });
            }
        }

        if (timestamped.length === 0) return logText;

        let maxTs = timestamped[0].ts.getTime();
        for (let i = 1; i < timestamped.length; i++) {
            const t = timestamped[i].ts.getTime();
            if (t > maxTs) maxTs = t;
        }
        const latestTs = new Date(maxTs);
        const cutoff = new Date(latestTs.getTime() - minutes * 60000);

        return timestamped
            .filter(t => t.ts >= cutoff)
            .map(t => t.line)
            .join('\n');
    }

    /**
     * Compute dynamic time filter intervals based on log span.
     */
    function computeTimeFilters(logSpanMinutes) {
        const candidates = [
            [10, '10m'], [20, '20m'], [30, '30m'],
            [60, '1h'], [120, '2h'], [180, '3h'], [240, '4h'],
            [360, '6h'], [480, '8h'], [720, '12h'], [1440, '24h'],
        ];

        const filters = [];
        for (const [mins, label] of candidates) {
            if (mins < logSpanMinutes) {
                filters.push({ minutes: mins, label });
            }
        }

        if (logSpanMinutes > 0) {
            const roundTargets = [10, 20, 30, 60, 120, 180, 240, 360, 480, 720, 1440];
            let rounded = logSpanMinutes;
            for (const target of roundTargets) {
                if (target >= logSpanMinutes && (target - logSpanMinutes) <= 5) {
                    rounded = target;
                    break;
                }
            }

            let spanLabel;
            if (rounded < 60) {
                spanLabel = `${rounded}m`;
            } else {
                const h = Math.floor(rounded / 60);
                const m = rounded % 60;
                spanLabel = m ? `${h}h${m}m` : `${h}h`;
            }

            if (filters.length > 0 && filters[filters.length - 1].label === spanLabel) {
                filters[filters.length - 1].minutes = 0;
            } else {
                filters.push({ minutes: 0, label: spanLabel });
            }
        } else {
            filters.push({ minutes: 0, label: 'All' });
        }

        return filters;
    }

    async function parseAsync(logText, options) {
        if (typeof Worker !== 'undefined') {
            try {
                return await new Promise((resolve, reject) => {
                    const worker = new Worker('/js/log-parser.worker.js?v=6.55');
                    worker.onmessage = e => {
                        worker.terminate();
                        if (e.data.type === 'success') resolve(e.data.result);
                        else reject(new Error(e.data.error || 'Worker parsing error'));
                    };
                    worker.onerror = error => { worker.terminate(); reject(error); };
                    worker.postMessage({ action: 'parse', logText, options });
                });
            } catch (error) {
                console.warn('Worker parsing failed, falling back to main thread:', error);
            }
        }
        return parseIPs(logText, options);
    }

    return {
        parseLine, parseIPs, parseAsync, filterByTime, computeTimeFilters, isValidIP, isPrivateIP, detectFormat,
        parseJsonLine, tokenizeLine, parseTimestamp, splitRequest, canonicalIP, ipFilterMatcher, forwardedClient, timeBounds,
    };
})();
if (typeof module !== 'undefined' && module.exports) module.exports = LogParser;
if (typeof window !== 'undefined') window.LogParser = LogParser;
if (typeof self !== 'undefined') self.LogParser = LogParser;
