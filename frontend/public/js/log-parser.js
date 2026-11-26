/**
 * Nginx Log Parser — Client-Side
 * 
 * Port of Python parse_ips() function.
 * Extracts IPs, user-agents, timestamps from nginx access log lines.
 * Excludes internal traffic and ordinary 403s from analysis by default.
 */

const LogParser = (() => {
    const TS_REGEX = /\[(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]/;

    /**
     * Unwrap an IPv4-mapped IPv6 address to its bare IPv4 form.
     *
     * Nginx reports `$remote_addr` in the address family the connection used,
     * so the same client legitimately appears as either `192.178.4.1` or
     * `::ffff:192.178.4.1`. Without this, a v4-mapped client matches neither
     * the IPv4 nor the IPv6 validation below and is silently discarded — the
     * parser is strict about dotted-quad and does not accept the `.` inside a
     * v4-mapped literal.
     *
     * @param {string} ip - Client IP address.
     * @returns {string} The bare IPv4 address, or `ip` unchanged.
     */
    function unwrapV4Mapped(ip) {
        if (typeof ip !== 'string' || !ip.includes(':')) return ip;
        const words = ipv6Words(ip);
        if (!words || !words.slice(0, 5).every(word => word === 0) || words[5] !== 0xffff) return ip;
        return [words[6] >>> 8, words[6] & 255, words[7] >>> 8, words[7] & 255].join('.');
    }

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
        // 10.0.0.0/8
        if (a === 10) return true;
        // 172.16.0.0/12
        if (a === 172 && b >= 16 && b <= 31) return true;
        // 192.168.0.0/16
        if (a === 192 && b === 168) return true;
        // 127.0.0.0/8
        if (a === 127) return true;
        // 169.254.0.0/16 (link-local)
        if (a === 169 && b === 254) return true;
        // 100.64.0.0/10 (carrier-grade NAT / non-public client space)
        if (a === 100 && b >= 64 && b <= 127) return true;
        // 0.0.0.0
        if (a === 0) return true;

        return false;
    }

    function isPrivateIPv6(ip) {
        const words = ipv6Words(ip);
        if (!words) return true;
        const loopbackOrUnspecified = words.slice(0, 7).every(word => word === 0) && words[7] <= 1;
        return loopbackOrUnspecified || (words[0] & 0xfe00) === 0xfc00 || (words[0] & 0xffc0) === 0xfe80;
    }

    function isValidIP(ip) {
        if (typeof ip !== 'string') return false;
        return ip.includes(':') ? ipv6Words(ip) !== null : isValidIPv4(ip);
    }

    function parseTimestamp(tsStr) {
        if (!tsStr || typeof tsStr !== 'string') return null;

        // ISO-8601 format: 2026-10-01T00:00:00Z or 2026-10-01T05:30:00+05:30 or 2026-10-01 00:00:00
        const isoMatch = tsStr.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:(Z)|([+-])(\d{2}):?(\d{2}))?$/);
        if (isoMatch) {
            const [, year, month, day, hour, min, sec, , sign, offH = '0', offM = '0'] = isoMatch;
            const y = Number(year), mo = Number(month) - 1, d = Number(day);
            const h = Number(hour), mi = Number(min), s = Number(sec);
            if (mo < 0 || mo > 11 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59) return null;
            if (Number(offH) > 23 || Number(offM) > 59) return null;
            const utc = new Date(Date.UTC(y, mo, d, h, mi, s));
            if (utc.getUTCFullYear() !== y || utc.getUTCMonth() !== mo || utc.getUTCDate() !== d) return null;
            if (sign) {
                const offsetMs = (Number(offH) * 60 + Number(offM)) * 60000;
                return new Date(utc.getTime() - (sign === '+' ? offsetMs : -offsetMs));
            }
            return utc;
        }

        // Standard Nginx wall-clock format: 01/Oct/2026:00:00:00 +0000
        const months = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
        const m = tsStr.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([+-])(\d{2})(\d{2}))?$/);
        if (!m) return null;
        const [, day, mon, year, hour, min, sec, , offsetHour = '0', offsetMinute = '0'] = m;
        if (!(mon in months)) return null;
        const wall = new Date(Date.UTC(Number(year), months[mon], Number(day), Number(hour), Number(min), Number(sec)));
        if (wall.getUTCFullYear() !== Number(year) || wall.getUTCMonth() !== months[mon] || wall.getUTCDate() !== Number(day) ||
            wall.getUTCHours() !== Number(hour) || wall.getUTCMinutes() !== Number(min) || wall.getUTCSeconds() !== Number(sec) ||
            Number(offsetHour) > 23 || Number(offsetMinute) > 59) return null;
        return wall;
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

    const KNOWN_STATUS_CODES = new Set([
        100, 101, 102, 103,
        200, 201, 202, 203, 204, 205, 206, 207, 208, 226,
        300, 301, 302, 303, 304, 305, 307, 308,
        400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 426, 428, 429, 431, 451,
        500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511
    ]);

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

    /**
     * Parse a single JSON-formatted access log line.
     */
    function parseJsonLine(rawLine, options = {}) {
        const skip403 = (options && options.skip403 !== undefined) ? Boolean(options.skip403) : true;
        const skipInternal = (options && options.skipInternal !== undefined) ? Boolean(options.skipInternal) : true;

        const line = rawLine ? rawLine.trim() : '';
        if (!line) {
            return { valid: false, reason: 'Empty line', reasonType: 'invalid' };
        }

        let obj;
        try {
            obj = JSON.parse(line);
        } catch {
            return { valid: false, reason: 'Invalid JSON log line', reasonType: 'invalid', line };
        }

        const rawIp = obj.remote_addr || obj.client_ip || obj.client || obj.remote_ip || obj.ip || obj.x_forwarded_for || '';
        let firstIp = String(rawIp).trim();
        if (firstIp.includes(',')) {
            const parts = firstIp.split(',').map(s => s.trim());
            firstIp = parts.find(p => isValidIP(p) && !isPrivateIP(p)) || parts[0];
        }

        if (!firstIp || !isValidIP(firstIp)) {
            return { valid: false, reason: 'Invalid IP format', reasonType: 'invalid', line };
        }

        const normalizedAddr = unwrapV4Mapped(firstIp);

        let timestamp = null;
        let timeSec = 0;
        const rawTime = obj.time_local || obj.time_iso8601 || obj.timestamp || obj.time || obj['@timestamp'] || obj.date;
        if (rawTime) {
            timestamp = parseTimestamp(String(rawTime).replace(/^\[|\]$/g, ''));
            if (timestamp) timeSec = Math.floor(timestamp.getTime() / 1000);
        }

        let method = obj.request_method || obj.method || null;
        let url = obj.request_uri || obj.uri || obj.path || null;
        let httpVersion = obj.server_protocol || obj.http_version || obj.protocol || null;

        if (obj.request && typeof obj.request === 'string') {
            const parts = obj.request.trim().split(/\s+/);
            if (parts.length >= 2) {
                if (!method) method = parts[0];
                if (!url) url = parts[1];
                if (!httpVersion && parts[2]) httpVersion = parts[2];
            } else if (!url) {
                url = obj.request;
            }
        }

        if (skipInternal && isPrivateIP(normalizedAddr)) {
            return { valid: false, reason: 'Private/reserved IP', reasonType: 'privateIP', timestamp, timeSec, line };
        }
        if (skipInternal && isHealthCheckPath(url)) {
            return { valid: false, reason: 'Health-check endpoint', reasonType: 'healthCheck', timestamp, timeSec, line };
        }

        const statusCode = parseInt(obj.status || obj.status_code || obj.code || obj.response_status || 0, 10) || 0;
        const rawBytes = obj.body_bytes_sent || obj.bytes_sent || obj.bytes || obj.response_size || obj.response_length || 0;
        const responseSize = rawBytes === '-' ? 0 : (parseInt(rawBytes, 10) || 0);

        const rawReferer = obj.http_referer || obj.referer || obj.referrer || '-';
        const rawUA = obj.http_user_agent || obj.user_agent || obj.agent || '-';
        const referrer = rawReferer === '-' ? null : String(rawReferer);
        const userAgent = rawUA === '-' ? null : String(rawUA);

        const isCrawler = isBotUserAgent(userAgent);

        if (skip403 && statusCode === 403 && !isCrawler) {
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
            ip: normalizedAddr,
            timestamp,
            timeSec,
            method,
            url,
            httpVersion,
            statusCode,
            responseSize,
            referrer,
            userAgent,
            botName,
            isCrawler,
            line
        };
    }

    /**
     * Tokenize a single log line preserving quoted and bracketed substrings.
     */
    function tokenizeLine(line) {
        const tokens = [];
        let cur = '';
        let inQuote = false;
        let inBracket = false;
        for (let i = 0; i < line.length; i++) {
            const ch = line[i];
            if (ch === '"' && !inBracket) {
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

    /**
     * Parse VirtualHost-prefixed Nginx access log lines.
     */
    function parseVHostLine(rawLine, options = {}, regex = null) {
        const skip403 = (options && options.skip403 !== undefined) ? Boolean(options.skip403) : true;
        const skipInternal = (options && options.skipInternal !== undefined) ? Boolean(options.skipInternal) : true;

        const line = rawLine ? rawLine.trim() : '';
        if (!line) return { valid: false, reason: 'Empty line', reasonType: 'invalid' };

        const rgx = regex || /^(\S+)\s+(\S+) \S+ (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)"(?:\s+.*)?)?$/;
        const match = line.match(rgx);
        if (!match) return { valid: false, reason: 'Unparseable log format', reasonType: 'invalid', line };

        const [, , ipToken, , , request, status, bodyBytesSent, httpReferer = '-', httpUserAgent = '-'] = match;
        if (!isValidIP(ipToken)) return { valid: false, reason: 'Invalid IP format', reasonType: 'invalid', line };

        const normalizedAddr = unwrapV4Mapped(ipToken);
        const [method = null, url = null, httpVersion = null] = request && request !== '-' ? request.split(/\s+/) : [];
        const isCrawler = isBotUserAgent(httpUserAgent);

        let timestamp = null;
        let timeSec = 0;
        const tsMatch = line.match(TS_REGEX);
        if (tsMatch) {
            timestamp = parseTimestamp(tsMatch[1]);
            if (timestamp) timeSec = Math.floor(timestamp.getTime() / 1000);
        }

        if (skipInternal && isPrivateIP(normalizedAddr)) {
            return { valid: false, reason: 'Private/reserved IP', reasonType: 'privateIP', timestamp, timeSec, line };
        }
        if (skipInternal && isHealthCheckPath(url)) {
            return { valid: false, reason: 'Health-check endpoint', reasonType: 'healthCheck', timestamp, timeSec, line };
        }

        const statusCode = parseInt(status, 10);
        const responseSize = bodyBytesSent === '-' ? 0 : parseInt(bodyBytesSent, 10);
        const referrer = httpReferer === '-' ? null : httpReferer;
        const userAgent = httpUserAgent === '-' ? null : httpUserAgent;

        if (skip403 && statusCode === 403 && !isCrawler) {
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
            ip: normalizedAddr,
            timestamp,
            timeSec,
            method,
            url,
            httpVersion,
            statusCode,
            responseSize,
            referrer,
            userAgent,
            botName,
            isCrawler,
            line
        };
    }

    /**
     * Synthesize a line parser bound to column indices discovered during sample classification.
     */
    function createDynamicLineParser(colMap) {
        return function parseDynamicLine(rawLine, options = {}) {
            const skip403 = (options && options.skip403 !== undefined) ? Boolean(options.skip403) : true;
            const skipInternal = (options && options.skipInternal !== undefined) ? Boolean(options.skipInternal) : true;

            const line = rawLine ? rawLine.trim() : '';
            if (!line) {
                return { valid: false, reason: 'Empty line', reasonType: 'invalid' };
            }

            const tokens = tokenizeLine(line);
            const minCols = Math.max(colMap.ipCol, colMap.timeCol, colMap.statusCol, colMap.reqCol);
            if (tokens.length <= minCols) {
                return { valid: false, reason: 'Unparseable log format', reasonType: 'invalid', line };
            }

            let rawIp = colMap.ipCol !== -1 ? stripQuotes(tokens[colMap.ipCol]) : '';
            if (rawIp.includes(',')) {
                const parts = rawIp.split(',').map(s => s.trim());
                rawIp = parts.find(p => isValidIP(p) && !isPrivateIP(p)) || parts[0];
            }
            if (!rawIp || !isValidIP(rawIp)) {
                return { valid: false, reason: 'Invalid IP format', reasonType: 'invalid', line };
            }
            const normalizedAddr = unwrapV4Mapped(rawIp);

            let timestamp = null;
            let timeSec = 0;
            if (colMap.timeCol !== -1 && tokens[colMap.timeCol]) {
                const rawTime = stripQuotes(tokens[colMap.timeCol]);
                timestamp = parseTimestamp(rawTime);
                if (timestamp) timeSec = Math.floor(timestamp.getTime() / 1000);
            }

            let method = null;
            let url = null;
            let httpVersion = null;
            if (colMap.reqCol !== -1 && tokens[colMap.reqCol]) {
                const reqStr = stripQuotes(tokens[colMap.reqCol]);
                if (reqStr && reqStr !== '-') {
                    const parts = reqStr.split(/\s+/);
                    method = parts[0] || null;
                    url = parts[1] || null;
                    httpVersion = parts[2] || null;
                }
            }

            if (skipInternal && isPrivateIP(normalizedAddr)) {
                return { valid: false, reason: 'Private/reserved IP', reasonType: 'privateIP', timestamp, timeSec, line };
            }
            if (skipInternal && isHealthCheckPath(url)) {
                return { valid: false, reason: 'Health-check endpoint', reasonType: 'healthCheck', timestamp, timeSec, line };
            }

            let statusCode = 0;
            if (colMap.statusCol !== -1 && tokens[colMap.statusCol]) {
                statusCode = parseInt(tokens[colMap.statusCol], 10) || 0;
            }

            let responseSize = 0;
            if (colMap.bytesCol !== -1 && tokens[colMap.bytesCol]) {
                const b = tokens[colMap.bytesCol];
                responseSize = b === '-' ? 0 : (parseInt(b, 10) || 0);
            }

            let referrer = null;
            if (colMap.refCol !== -1 && tokens[colMap.refCol]) {
                const r = stripQuotes(tokens[colMap.refCol]);
                referrer = r === '-' ? null : r;
            }

            let userAgent = null;
            if (colMap.uaCol !== -1 && tokens[colMap.uaCol]) {
                const u = stripQuotes(tokens[colMap.uaCol]);
                userAgent = u === '-' ? null : u;
            }

            const isCrawler = isBotUserAgent(userAgent);
            if (skip403 && statusCode === 403 && !isCrawler) {
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
                ip: normalizedAddr,
                timestamp,
                timeSec,
                method,
                url,
                httpVersion,
                statusCode,
                responseSize,
                referrer,
                userAgent,
                botName,
                isCrawler,
                line
            };
        };
    }

    /**
     * Inspect token positions across sample lines and compile a dynamic schema.
     */
    function compileDynamicSchema(candidates) {
        if (!candidates || candidates.length === 0) return null;

        const tokenRows = candidates.map(tokenizeLine);
        const minTokens = Math.min(...tokenRows.map(r => r.length));
        if (minTokens < 3) return null;

        const colMap = {
            ipCol: -1,
            timeCol: -1,
            reqCol: -1,
            statusCol: -1,
            bytesCol: -1,
            refCol: -1,
            uaCol: -1
        };

        const quotedCols = new Set();

        for (let col = 0; col < minTokens; col++) {
            const vals = tokenRows.map(r => r[col]);

            // Test IP: all samples must have valid IP (bare or XFF)
            if (colMap.ipCol === -1) {
                const isAllIP = vals.every(v => {
                    const clean = stripQuotes(v);
                    const first = clean.includes(',') ? clean.split(',')[0].trim() : clean;
                    return isValidIP(first);
                });
                if (isAllIP) {
                    colMap.ipCol = col;
                    continue;
                }
            }

            // Test Timestamp: all samples have bracketed or ISO timestamp
            if (colMap.timeCol === -1) {
                const isAllTime = vals.every(v => {
                    const clean = stripQuotes(v);
                    return parseTimestamp(clean) !== null;
                });
                if (isAllTime) {
                    colMap.timeCol = col;
                    continue;
                }
            }

            // Test Status Code: known HTTP status codes between 100 and 599
            if (colMap.statusCol === -1) {
                const isAllStatus = vals.every(v => KNOWN_STATUS_CODES.has(parseInt(v, 10)));
                if (isAllStatus) {
                    colMap.statusCol = col;
                    continue;
                }
            }

            // Test Request: quoted method + path or path alone
            if (colMap.reqCol === -1) {
                const isAllReq = vals.every(v => {
                    const clean = stripQuotes(v);
                    return /^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE)\s+\S+/i.test(clean) || clean.startsWith('/') || clean === '-';
                });
                if (isAllReq && vals.some(v => v.startsWith('"'))) {
                    colMap.reqCol = col;
                    continue;
                }
            }

            // Track quoted columns for User-Agent vs Referer
            if (vals.some(v => v.startsWith('"'))) {
                quotedCols.add(col);
            }
        }

        // Second pass: distinguish Bytes, Referer, and User-Agent
        for (let col = 0; col < minTokens; col++) {
            if (col === colMap.ipCol || col === colMap.timeCol || col === colMap.reqCol || col === colMap.statusCol) {
                continue;
            }
            const vals = tokenRows.map(r => r[col]);

            // Test Bytes: integer or dash (must have at least one numeric value across samples to avoid matching ident "-")
            if (colMap.bytesCol === -1 && vals.every(v => /^\d+$|^-$/.test(v)) && vals.some(v => /^\d+$/.test(v))) {
                colMap.bytesCol = col;
                continue;
            }
        }

        // Third pass: accurately distinguish Referer vs User-Agent among quoted columns
        const remainingQuoted = Array.from(quotedCols).filter(col => col !== colMap.reqCol);
        if (remainingQuoted.length === 1) {
            const vals = tokenRows.map(r => stripQuotes(r[remainingQuoted[0]]));
            if (vals.some(v => v.startsWith('http://') || v.startsWith('https://'))) {
                colMap.refCol = remainingQuoted[0];
            } else {
                colMap.uaCol = remainingQuoted[0];
            }
        } else if (remainingQuoted.length >= 2) {
            const colA = remainingQuoted[0];
            const colB = remainingQuoted[1];
            const valsA = tokenRows.map(r => stripQuotes(r[colA]));
            const valsB = tokenRows.map(r => stripQuotes(r[colB]));

            const aIsUa = valsA.some(isLikelyUserAgent);
            const bIsUa = valsB.some(isLikelyUserAgent);
            const aIsRef = valsA.some(v => v.startsWith('http://') || v.startsWith('https://'));
            const bIsRef = valsB.some(v => v.startsWith('http://') || v.startsWith('https://'));

            if (aIsUa && !bIsUa) {
                // colA is User-Agent, colB is Referer
                colMap.uaCol = colA;
                colMap.refCol = colB;
            } else if (bIsUa && !aIsUa) {
                // colB is User-Agent, colA is Referer
                colMap.uaCol = colB;
                colMap.refCol = colA;
            } else if (aIsRef && !bIsRef) {
                colMap.refCol = colA;
                colMap.uaCol = colB;
            } else if (bIsRef && !aIsRef) {
                colMap.refCol = colB;
                colMap.uaCol = colA;
            } else {
                // Standard default: first is Referer, second is User-Agent
                colMap.refCol = colA;
                colMap.uaCol = colB;
            }
        }

        if (colMap.ipCol !== -1 && (colMap.statusCol !== -1 || colMap.reqCol !== -1)) {
            return {
                type: 'dynamic',
                colMap,
                parseLine: createDynamicLineParser(colMap)
            };
        }

        return null;
    }

    /**
     * Detect log format from a set of sample lines (3-15 lines).
     * Returns a schema object { type, parseLine(line, options) }.
     */
    function detectFormat(sampleLines) {
        if (!sampleLines || sampleLines.length === 0) {
            return { type: 'standard', parseLine };
        }

        const candidates = (Array.isArray(sampleLines) ? sampleLines : sampleLines.split('\n'))
            .map(l => (l ? l.trim() : ''))
            .filter(l => l.length > 0 && !l.startsWith('#'))
            .slice(0, 15);

        if (candidates.length === 0) {
            return { type: 'standard', parseLine };
        }

        // 1. JSON format check
        const jsonCount = candidates.filter(l => l.startsWith('{') && l.endsWith('}')).length;
        if (jsonCount >= Math.ceil(candidates.length / 2)) {
            return { type: 'json', parseLine: parseJsonLine };
        }

        // 2. Standard Combined (Fast-path): 100% match on sample lines
        let standardMatches = 0;
        let uaSwapped = false;
        for (const line of candidates) {
            const spaceIdx = line.indexOf(' ');
            const first = spaceIdx > 0 ? line.substring(0, spaceIdx) : line;
            if (isValidIP(first)) {
                const match = line.match(LOG_REGEX);
                if (match) {
                    standardMatches++;
                    const refSlot = match[7];
                    const uaSlot = match[8];
                    // If slot 7 looks like a UA and slot 8 looks like a Referer URL, they are swapped!
                    if (refSlot && isLikelyUserAgent(refSlot) && (!uaSlot || isLikelyReferer(uaSlot))) {
                        uaSwapped = true;
                    }
                }
            }
        }
        if (standardMatches === candidates.length && !uaSwapped) {
            return { type: 'standard', parseLine };
        }

        // 3. VirtualHost Combined format ($host $remote_addr ... or $host:$port $remote_addr ...)
        const VHOST_REGEX = /^(\S+)\s+(\S+) \S+ (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)"(?:\s+.*)?)?$/;
        let vhostMatches = 0;
        for (const line of candidates) {
            const m = line.match(VHOST_REGEX);
            if (m && isValidIP(m[2])) {
                vhostMatches++;
            }
        }
        if (vhostMatches >= Math.ceil(candidates.length * 0.8)) {
            return {
                type: 'vhost',
                parseLine: (line, options) => parseVHostLine(line, options, VHOST_REGEX)
            };
        }

        // 4. Dynamic Token Classifier (shuffled fields)
        const dynamicSchema = compileDynamicSchema(candidates);
        if (dynamicSchema) {
            return dynamicSchema;
        }

        // Default fallback
        return { type: 'standard', parseLine };
    }

    // Common format ends after size; combined adds referrer and UA, and
    // deployments may append extra fields. A dash in the byte field means
    // no bytes sent. Keep incomplete/empty requests for error investigations.
    const LOG_REGEX = /^(\S+) \S+ (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)"(?:\s+.*)?)?$/;

    /**
     * Parse a single nginx access log line.
     * @param {string} rawLine - Raw single line text
     * @param {Object} [options] - Parsing options
     * @returns {Object} Parse result with valid boolean, error reason or extracted fields
     */
    function parseLine(rawLine, options = {}) {
        const skip403 = (options && options.skip403 !== undefined) ? Boolean(options.skip403) : true;
        const skipInternal = (options && options.skipInternal !== undefined) ? Boolean(options.skipInternal) : true;

        const line = rawLine ? rawLine.trim() : '';
        if (!line) {
            return { valid: false, reason: 'Empty line', reasonType: 'invalid' };
        }

        const spaceIdx = line.indexOf(' ');
        const firstToken = spaceIdx > 0 ? line.substring(0, spaceIdx) : line;

        if (!firstToken || !isValidIP(firstToken)) {
            if (line.startsWith('{') && line.endsWith('}')) {
                return parseJsonLine(line, options);
            }
            const fallbackFormat = detectFormat([line]);
            if (fallbackFormat && fallbackFormat.type !== 'standard') {
                return fallbackFormat.parseLine(line, options);
            }
            return { valid: false, reason: 'Invalid IP format', reasonType: 'invalid', line };
        }

        const normalizedAddr = unwrapV4Mapped(firstToken);
        const match = line.match(LOG_REGEX);

        if (!match) {
            const fallbackFormat = detectFormat([line]);
            if (fallbackFormat && fallbackFormat.type !== 'standard') {
                return fallbackFormat.parseLine(line, options);
            }
            return { valid: false, reason: 'Unparseable log format', reasonType: 'invalid', line };
        }

        const [, , , , request, status, bodyBytesSent, httpReferer = '-', httpUserAgent = '-'] = match;
        const [method = null, url = null, httpVersion = null] = request && request !== '-' ? request.split(/\s+/) : [];
        const isCrawler = isBotUserAgent(httpUserAgent);

        let timestamp = null;
        let timeSec = 0;
        const tsMatch = line.match(TS_REGEX);
        if (tsMatch) {
            timestamp = parseTimestamp(tsMatch[1]);
            if (timestamp) timeSec = Math.floor(timestamp.getTime() / 1000);
        }

        if (skipInternal && isPrivateIP(normalizedAddr)) {
            return { valid: false, reason: 'Private/reserved IP', reasonType: 'privateIP', timestamp, timeSec, line };
        }
        if (skipInternal && isHealthCheckPath(url)) {
            return { valid: false, reason: 'Health-check endpoint', reasonType: 'healthCheck', timestamp, timeSec, line };
        }

        const statusCode = parseInt(status, 10);
        const responseSize = bodyBytesSent === '-' ? 0 : parseInt(bodyBytesSent, 10);
        const referrer = httpReferer === '-' ? null : httpReferer;
        const userAgent = httpUserAgent === '-' ? null : httpUserAgent;

        if (skip403 && statusCode === 403 && !isCrawler) {
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
            ip: normalizedAddr,
            timestamp,
            timeSec,
            method,
            url,
            httpVersion,
            statusCode,
            responseSize,
            referrer,
            userAgent,
            botName,
            isCrawler,
            line
        };
    }

    /**
     * Parse nginx access log text.
     * @param {string} logText - Raw nginx access log content
     * @param {Object} [options] - Parsing options
     * @param {boolean} [options.skip403=true] - Whether to skip ordinary 403 responses
     * @param {boolean} [options.skipInternal=true] - Exclude private/local IPs and exact health-check paths
     * @returns {Object} { ips, userAgents, parsedLines, skippedLines, logSpanMinutes, logStart, logEnd, logEntries }
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
        let earliestTimestamp = Infinity;
        let latestTimestamp = -Infinity;
        const logEntries = []; // Enhanced: full structured log entries

        const lines = logText.split('\n');
        const format = detectFormat(lines);
        const lineParser = format && format.parseLine ? format.parseLine : parseLine;

        for (const rawLine of lines) {
            if (!rawLine || !rawLine.trim()) continue;
            const parsed = lineParser(rawLine, options);

            if (parsed.timestamp) {
                earliestTimestamp = Math.min(earliestTimestamp, parsed.timestamp.getTime());
                latestTimestamp = Math.max(latestTimestamp, parsed.timestamp.getTime());
            }

            if (parsed.reasonType !== 'invalid') {
                validLines++;
            }

            if (!parsed.valid) {
                skippedLines.push({ reason: parsed.reason, line: rawLine.trim() });
                if (parsed.reasonType) skipCounts[parsed.reasonType]++;
                continue;
            }

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

        // Compute log time span
        let logSpanMinutes = 0;
        let logStart = null;
        let logEnd = null;
        let minTimestamp = 0;
        let maxTimestamp = 0;
        if (Number.isFinite(earliestTimestamp)) {
            minTimestamp = earliestTimestamp;
            maxTimestamp = latestTimestamp;
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
            logSpanMinutes,
            logStart,
            logEnd,
            minTimestamp,
            maxTimestamp,
            logEntries, // Enhanced: full structured log entries
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

    // Exact, case-sensitive paths only: do not hide /healthcare, nested API
    // resources, or all Unknown-ASN clients. Ignore query strings/trailing /.
    const HEALTH_CHECK_PATHS = new Set(['/health', '/healthz', '/healthcheck', '/health-check', '/health_check', '/readyz', '/livez', '/_health']);
    function isHealthCheckPath(url) {
        if (!url) return false;
        const path = url.split(/[?#]/)[0].replace(/\/+$/, '');
        return HEALTH_CHECK_PATHS.has(path);
    }

    async function parseAsync(logText, options) {
        if (typeof Worker !== 'undefined') {
            try {
                return await new Promise((resolve, reject) => {
                    const worker = new Worker('/js/log-parser.worker.js?v=6.52');
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

    return { parseLine, parseIPs, parseAsync, filterByTime, computeTimeFilters, isValidIP, isPrivateIP, detectFormat, parseJsonLine, tokenizeLine };
})();
if (typeof module !== 'undefined' && module.exports) module.exports = LogParser;
if (typeof window !== 'undefined') window.LogParser = LogParser;
if (typeof self !== 'undefined') self.LogParser = LogParser;
