# Traffic Analyzer: parser, identification and path review

Reviewed on branch `traffic-classifier` at commit `d8eb9fb`, 2026-11-27.
This is a review only. No code was changed for it.

It continues `TRAFFIC_ANALYZER_REVIEW.md` (filters and the new traffic classifier) and covers:

- the log parser (`log-parser.js`, `log-parser.worker.js`, `stream-line-splitter.js`, `columnar-storage.js`),
- identification: which log format a file is, which address is the client, which client is a bot,
- path identification: how URLs become "paths" in tables, filters and attack detection,
- the numbers the analyzer (`analyzer.js`) derives from the parsed rows.

## 1. Summary

48 findings: 10 high, 26 medium, 12 low. 45 were reproduced on this branch; A2 is carried over from the earlier review, and A5 and A6 are read from the code.

Severity: **High** means wrong headline numbers or a lost log for common input. **Medium** means wrong numbers for realistic but specific input. **Low** means rare input or a cosmetic fault.

The ten that matter most:

| # | Finding | Effect measured |
|---|---|---|
| C1 | The proxy or CDN address is taken as the client; `X-Forwarded-For` is never read | Behind a private proxy 50 of 50 lines are dropped. Behind a CDN, 40 of 40 real Googlebot requests are shown as spoofed |
| B1 | The default "Ignore 403" removes blocked requests before bots are judged | A scanner with 300 blocked probes does not appear at all |
| B2 | Attack paths are matched as plain text in the path only | Encoded probes, payloads in the query string, traversal and injection are all counted as human |
| B3 | A client is one address with one exact User-Agent | 300 requests a minute with a new User-Agent each time: 300 "humans" |
| B4 | Password guessing is only seen at 10 or more attempts a minute | 600 login attempts at 9 a minute: human |
| U1 | "Targeted Paths" counts path segments, not paths | 210 requests show 395 hits and shares that add up to 188% |
| U2 | Card, dropdown and filter count the same path three ways | `/products`: 75 in the card, 50 in the dropdown, 83 after clicking |
| F1 | One damaged line among the first 15 changes the parser for the whole file | 96 of 96 rows get status 0, 0 bytes and no User-Agent |
| F2 | A status the parser does not know (499, 444, 520) in the sample | Every row of the file gets status 0 |
| P1 | Time zone offsets are ignored in one notation and applied in the other | The same instant is stored 8 hours apart |

## 1a. Status after the fixes (2026-11-27)

The findings below were fixed on this branch in four commits after the review. 40 are fixed, 5 are partly fixed and 3 are open. Sections 3.1 to 3.6 describe the behaviour **before** the fixes; this table says what is true now. Outputs of the same probe scripts after the fixes are in `review2/out-after/`.

| # | Now | Note |
|---|---|---|
| F1, F2, F3, F5, F6, F8 | Fixed | Format chosen by majority over 200 lines; any status 100-599; mixed files read in any order; per-file detection in upload |
| F4 | Fixed | Nothing is guessed from one line. Two lines glued together still parse as one request |
| F7 | Fixed | Added AWS ALB and classic ELB, IIS W3C, Caddy, Traefik, Cloudflare Logpush, Docker wrapper, syslog prefix. HAProxy is still not read |
| P1 | Changed | Both notations now keep the clock the server wrote (see decisions below) |
| P2 | Fixed | Fractions, epoch numbers, one-digit day, any letter case, `+02`, RFC 1123. Non-English month names are still not read |
| P3, P4, P5, P7 | Fixed | |
| P6 | Partly | 999 becomes "unknown". Unknown statuses are still listed outside the 2xx-5xx categories |
| P8 | Partly | Lone CR line endings work for pasted text and for uploads. UTF-16 files are unchanged |
| C1 | Fixed | Client read from `X-Forwarded-For` behind a private proxy or a CDN; the page says how many requests |
| C2, C3, C5, C6 | Fixed | Host names in place of addresses are still rejected |
| C4 | Partly | Benchmark, multicast, reserved and site-local ranges are internal. The three documentation ranges stay public: the repository's tests and samples use them as client addresses |
| B1 | Fixed | "Ignore 403" keeps blocked attack paths and login attempts |
| B2, B3, B4, B5, B6, B7, B9, B11, B13 | Fixed | |
| B8 | Fixed | Library names inside a browser User-Agent are ignored. Monitor and scanner names still match anywhere |
| B10 | Partly | An out-of-date browser version is one weak signal; a malformed User-Agent is not a browser. An old version alone is still human |
| B12 | Open | The one-minute window still does not slide |
| U1, U2, U3, U4, U5, U7 | Fixed | |
| U6 | Fixed | Upload has paths and sections. Referrers and the status split per path are still paste-only |
| A1, A3, A4 | Fixed | |
| A5 | Partly | A tooltip on the time span says which clock is shown |
| A2, A6 | Open | Peak rate by bucket size; referrers not grouped by site |

Decisions taken while fixing, each easy to reverse:

1. **Time zone (P1).** An existing end-to-end test requires that `[07:23:05 -0700]` is shown as 07:23:05. So the rule is "show the log's own clock", and ISO timestamps were changed to follow it instead of being converted to UTC.
2. **Which forwarded address is the client (C1).** The right-most public entry of `X-Forwarded-For`. The left-most is easier to read but can be written by the client, which would let anyone appear as a verified Googlebot.
3. **When forwarded addresses are trusted (C1).** Always when the connecting address is private. Otherwise only when at least nine in ten lines carry one and they vary more than the connecting addresses do. `clientIp: 'remote' | 'forwarded'` overrides this in the parser options; there is no control for it on the page yet.
4. **"Ignore 403" (B1).** The option stays on by default and still hides ordinary refusals, but never a request that looks like an attack or a login attempt.
5. **Apps (B9).** Native apps and media players are judged by behaviour like browsers, so their users count as human unless the app probes, floods or guesses passwords. `okhttp` stays a script library.
6. **Address filter.** A full address matches that address only; the start of one (`185.220.`) matches whole leading groups; CIDR works for IPv4 and IPv6. Text inside an address (`.3.4`) no longer matches.
7. **Countries and networks (A3).** The two counters at the top no longer count "Unknown" as a country or AS0 as a network. The tables still list them.

Upload gaps from section 3.7, now closed: path, method, address and CIDR filters work; "Matching N / M" and the entry count are right; the Skipped counts are shown; the choices in the dropdowns stay those of the whole log while a filter is on; a filter box keeps the focus while typing (both engines). The two exclusion options are switched off after an upload, with a note, because the file is not kept and there is nothing to recalculate from; they are set before the analysis. Still open for uploads: the timeline has one-hour buckets without a status split, and there are no referrers.

Existing tests whose expectations were changed, because they described the old behaviour:

| Test | Change |
|---|---|
| `tests/e2e/nginx-parser-contract.spec.ts`, ISO-8601 test | `2026-10-01T05:30:00+05:30` now reads 05:30:00 (decision 1); it read 00:00:00 UTC |
| `tests/e2e/cross-filter-rows.spec.ts`, two tests | Path rows carry `data-path="=/products"`, dropdown values are `^/products` |
| `tests/e2e/nginx-golden-analysis.spec.ts` and `tests/fixtures/nginx-release-golden.json` | `top_paths` lists whole paths (it listed segments: `/api` 4, `/login` 1, `/42` 1); `unique_countries` 4 to 3 and `unique_asns` 7 to 6 (decision 7); dropdown value `^/products`. **Not run**: the log this test reads, `tests/fixtures/nginx-release-golden.log`, is not in the repository. The new values were derived from the entries listed in the manifest |

Three things the end-to-end tests caught in the first version of the fixes, now corrected: health-check paths are case-sensitive again (`/HealthCheck` is a normal page); a request line with a protocol version reports whatever stood in the method position (`<b>`), as text; an impossible time zone offset (`+0060`) marks the time as unreadable.

## 2. How this was checked

- The browser scripts were loaded into Node and driven through both engines (paste and upload) with small logs whose correct answer is known in advance.
- The eleven parser scripts of the 2026-11-26 review were run again against this branch. Their output is unchanged except where the classifier branch changed behaviour on purpose.
- Path numbers on the page were read in a real browser (Playwright) from the build on `http://127.0.0.1:3020/nginx`.

Scripts and outputs are in `/Users/dan/work/toolkit-dev/review-evidence/traffic-analyzer/`:

| Reference | File |
|---|---|
| p1 to p8 | `review2/p1-request-lines.cjs` ... `review2/p8-more.cjs`, outputs in `review2/out/p*.txt` |
| b1 | `review2/b1-paths-page.mjs` (browser), output `review2/out/b1.txt`, screenshot `review2/out/b1-paths-page.png` |
| prev-01 to prev-11 | `parser/01-formats.cjs` ... `parser/11-ua-swap-heuristic.cjs`, run with `TK_JS=<checkout>/frontend/public/js`, outputs in `review2/out/prev-*.txt` |
| t13 | `analyzer/t13-tor-substring.cjs` |

Not checked: real production logs, gzip handling in the browser (code unchanged since the earlier review, see section 3.8), and the backend feed parser.

## 3. Findings

### 3.1 Log format identification

The format is chosen once from the first 15 non-comment lines (`detectFormat`, `log-parser.js:669-736`): JSON if half the lines look like JSON, standard only if all 15 match, vhost at 80%, otherwise a "dynamic" parser that guesses columns.

**F1 (High). One damaged line in the first 15 changes the parser for the whole file.**
A line cut inside the request at position 5 of 100 makes the file "dynamic" with no status, bytes or User-Agent column: 96 of 96 rows get status 0, 0 bytes, no User-Agent (prev-03). The same line at position 20 costs one row. Cause: standard needs 15 of 15 (`:708`). Fix: choose the format by majority over a larger sample, and let a line that fails be one invalid line.

**F2 (High). A status code the dynamic parser does not know makes it lose the status column.**
The status column must hold only codes from a fixed list (`:178-184`, `:573-579`). The list has no 499, 444, 520 or 425. One such line in the sample of a non-standard format gives status 0 for all 30 rows; with a syslog prefix the byte count becomes the day of the month (prev-10 item 1). Fix: accept any three-digit number from 100 to 599.

**F3 (Medium). Mixed files are handled differently depending on which format comes first.**
Standard lines followed by vhost or JSON lines: all 40 parsed. The other way round: 20 of 40 rejected (prev-02 B, D, E). Cause: only the standard parser retries other formats per line (`:765`, `:776`).

**F4 (Medium). The per-line retry accepts lines that are not requests.**
An nginx error-log line, a truncated line, two lines glued together, shell output that contains an address: each is counted as a request, with status 0 or 511 (prev-10 item 2). The retry builds a column guess from that single line (`compileDynamicSchema` on one sample), which fits almost anything. It is also about five times slower (129 ms against 23 ms for 20,000 lines, prev-02 M).

**F5 (Medium). The "User-Agent and referrer are swapped" guess can swap them for the whole file.**
If one sampled line has a referrer that looks like a User-Agent (`:702`), the file leaves the standard parser. With probe lines among the first 15, referrer and User-Agent are exchanged in 99 of 100 rows (prev-11 C). Every bot verdict then runs on referrers.

**F6 (Medium). Upload engine: the format is taken from the first chunk, and "Add more logs" reuses the previous file's format.**
A first chunk with two lines decides the format: 30 of 32 lines skipped (prev-02 K). A third file is parsed with the second file's format: 10 of 30 lines lost (prev-03, last line). Cause: `activeFormat` is cleared at the end of the first stream only (`log-parser.worker.js:181`, not in the append branch at `:216-241`).

**F7 (Medium). Common formats are not recognised and the only message is "No valid access-log lines found".**
Caddy JSON, Traefik JSON, Cloudflare Logpush, AWS ALB and classic ELB, IIS/W3C, and Docker's `{"log": "..."}` wrapper parse 0 lines (prev-01, prev-10 3g). The JSON parser reads flat nginx-style keys only (`:220-268`).

**F8 (Low). One JSON line can throw and stop the whole analysis.**
A line that is `null` throws "Cannot read properties of null"; `"request_uri":123` throws "url.split is not a function" (prev-10 3e, 4). Cause: no type checks after `JSON.parse` (`:215-259`).

### 3.2 Field parsing

Line numbers without a file name are in `log-parser.js`.

**P1 (High). Time zones: the offset is ignored for `[10/Oct/2026:13:55:36 -0700]` and applied for ISO timestamps.**
The same instant written both ways is stored as 13:55 and 20:55 (prev-04; p6 item 7). Logs from two servers or two formats cannot be merged, and nothing on the page says which clock is shown. Cause: `parseTimestamp` keeps the wall-clock time for the bracketed notation (`:127-135`) and converts for ISO (`:118-121`). Fix: convert both to UTC, and offer the display zone.

**P2 (Medium). Timestamps in an unknown notation are kept without a time and vanish from the timeline and time filters.**
Not understood: fractional seconds in the bracketed notation, epoch seconds and `$msec`, a one-digit day, lower-case or non-English month names, `+02`, RFC 1123 dates (prev-04). A log of 500 such rows shows 500 requests and an empty timeline (p6 item 6).

**P3 (Medium). A backslash-escaped quote breaks the line.**
Apache writes `\"`. In the URL: the row gets status 0, 0 bytes and no User-Agent. In the referrer: the referrer is cut at the quote (p1). Cause: `LOG_REGEX` (`:741`) and `tokenizeLine` (`:308-335`) do not know escapes.

**P4 (Medium). A URL with a space is cut at the space.**
`GET /my file.pdf HTTP/1.1` gives URL `/my` and HTTP version `file.pdf`. Two different files become one URL `/my` with 10 hits (p1, p2 I). Cause: the request is split on whitespace (`:784`). Fix: method is the first token, version the last token if it starts with `HTTP/`, the URL is everything between.

**P5 (Medium). Request lines that are not HTTP become "methods", and the engines disagree.**
A TLS handshake sent to the HTTP port gives method `\x16\x03\x01`. Paste shows it upper-cased as `\X16\X03\X01`; upload keeps the original. A request without a method is counted as GET in upload only: GET=10 in upload, GET=5 in paste for the same log (p2 H; `log-parser.worker.js:132`). The upload store keeps 256 distinct methods; beyond that, rows read back the wrong method (prev-09 item 2).

**P6 (Low). Status 000 and 999 are accepted; status 0 is in no category.**
20 requests, of which 5 with status 0 and 5 with 999: the status table lists them, the 2xx to 5xx categories add up to 10 (p6 item 3).

**P7 (Low). Upload engine: a response of 4 GiB or more wraps.**
4 GiB is stored as 0 and 5 GiB as 1 GiB; the total reads 9.66 GB instead of 13.96 GB (prev-09). The byte column is 32 bits.

**P8 (Low). Line handling.**
A file with lone CR line endings is one line. A UTF-16 file (PowerShell redirect) parses 0 lines. A file without any newline is buffered without limit (64 MB tested). Latin-1 bytes become U+FFFD (prev-07).

### 3.3 Which address is the client

**C1 (High). The first address on the line is always the client. `X-Forwarded-For` is never used for text formats.**
The stock nginx `main` format ends with `"$http_x_forwarded_for"`, so the real client is in most logs taken behind a proxy.

- Private proxy address first, default options: 50 of 50 lines dropped as internal, in both engines. The user sees "No valid access-log lines found" (p5).
- CDN edge address first: 100 requests from 59 real clients show as 5 addresses. 40 genuine Googlebot requests (real Google addresses in `X-Forwarded-For`) are shown as **spoofed**, because the CDN address is not Google's (p5).
- Top IPs, countries and networks then describe the CDN.
- JSON logs: `http_x_forwarded_for` is not among the keys read; `x_forwarded_for` is used only when no other address key exists (`log-parser.js:220`).

Fix: detect the case (all or most addresses private, or all in CDN networks, and a trailing quoted address list), read the client from `X-Forwarded-For` with a "trusted proxies" rule, and say on the page which field was used.

**C2 (Medium). IPv6 addresses are compared as text.**
`2001:db8::1`, the same address written in full, in upper case, and with `0:0`: four clients (p7 item 3). A client that moves inside one /64 is 600 unique addresses and 600 single-request "humans" (p7 item 2). Fix: store one canonical form; judge IPv6 clients by /64.

**C3 (Medium). Address forms that are rejected, so the line is dropped as invalid.**
`203.0.113.9:51234`, `[2001:db8::1]:443`, `fe80::1%eth0`, and host names when the server resolves them (p1, prev-06).

**C4 (Low). "Internal" misses ranges that cannot be internet clients.**
Counted as public: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4, 2001:db8::/32, fec0::/10, ff00::/8, 64:ff9b::/96 (p7 item 5; `log-parser.js:68-98`).

**C5 (Medium). Health checks are excluded by path alone, for any client and any method.**
`sqlmap` sending `POST /health` and getting 500 from a public address is dropped as a health check. `/Health`, `/api/health`, `/ping`, `/status`, `/healthz/ready` are kept (p7 item 4; `log-parser.js:1025-1030`). The exclusion is also tied to the "Ignore internal requests" checkbox, which says nothing about health checks.

**C6 (Medium). With "Ignore internal requests" off, internal monitors are reported as spoofed bots.**
`kube-probe` from 10.x, `ELB-HealthChecker` from 172.31.x, UptimeRobot on the LAN, an internal Googlebot test: 80 of 100 requests "spoofed" (p7 item 1). These probes only ever come from private addresses. Cause: any non-public address with a bot name is spoofed (`bot-detector.js:795-804`). Fix: a separate "internal" verdict.

### 3.4 Which client is a bot

**B1 (High). "Ignore 403 responses" is on by default and removes blocked requests before the classifier sees them.**
It keeps a 403 only when the User-Agent names a bot or tool (`log-parser.js:148-176`, applied at `:274`, `:378`, `:490`, `:807`). A scanner with a browser User-Agent whose 300 probes were all blocked: total 50, human 50, nothing else. With the option off: human 50, suspected 300 (p6 item 1). Requests without a User-Agent are dropped the same way. Fix: keep the rows and offer "hide blocked requests" as a view filter, or at least classify before excluding.

**B2 (High). Attack paths are found only as lower-case text inside the path.**
The query string is cut off before the check and nothing is decoded (`traffic-classifier.js:114-117`, list at `:52-58`). All of these, from a browser User-Agent, are counted as human (p3):

| Requests | Result |
|---|---|
| `/%2eenv`, `/.%67it/config`, `/wp%2dconfig.php` | human |
| `/?file=../../../../etc/passwd`, `/download?f=../.env` | human |
| `/..%2f..%2f..%2fetc%2fpasswd`, `/cgi-bin/.%2e/.%2e/bin/sh` | human |
| `?id=1'+UNION+SELECT`, `?q=<script>`, `${jndi:ldap://...}` | human |
| `/backup.sql`, `/server-status`, `/shell.php`, `/web.config`, `/id_rsa` (12 paths) | human |
| 12 different `.php` files under `/wp-content/`, all 404 | human |

Fix: decode once, look at path and query, and match families (traversal, secrets and backups, script files that return 404, injection text) instead of a list of 31 strings.

**B3 (High). A client is one address with one exact User-Agent, and nothing is judged across clients.**
(`traffic-classifier.js:230`.) One address sending 300 requests a minute with a new browser User-Agent each time is 300 clients of one request: human=300 (p3). 3,000 failed logins from 1,000 addresses in five minutes: human=3,000 (p8 item 3). 300 addresses posting twice to `/wp-login.php`: human. Fix: a second pass per address (many User-Agents, pooled behaviour) and per target (one login path hit by many clients that do nothing else).

**B4 (High). Slow password guessing is not seen.**
The rule needs 10 POSTs to a login path inside one minute (`traffic-classifier.js:60-71`, `:144-150`). 600 POSTs to `/login` at 6 or 9 a minute, answered 200 or 302: human=600 (p8 item 2). The total number of attempts is collected but not used. Login paths are a short name list; `/api/v1/auth/token` and `admin-ajax.php` are not on it and were caught only by the weaker "crawler-like" rule, with that label (p3).

**B5 (Medium). A scraper that sends a referrer is human.**
500 product pages at 100 a minute, no assets at all, a constant referrer: human=500 (p3). The flood rule needs both "few assets" and "few referrers" below 600 a minute (`traffic-classifier.js:180-181`), and a referrer is trivial to send.

**B6 (Medium). People flagged as suspected bots.**
40 PDF downloads without a referrer: suspected. 500 HLS video segments (`.ts`): suspected. 40 autocomplete lookups that return 404: "Path enumeration" (p3). Cause: `.pdf`, `.ts`, `.m3u8`, `.json`, `.xml`, `.txt`, `.wasm`, `.zip` are not assets (`traffic-classifier.js:49`), so such requests count as pages. Not flagged, correctly: a WordPress editor at work, the admin heartbeat, a page polling an API every two seconds, 200 people behind one office address (p3, p8 items 4 and 5).

**B7 (Medium). The bot name is the first pattern found anywhere in the User-Agent, which names the wrong bot and then calls it spoofed.**
(p5; table at `bot-detector.js:27-166`.)

| Real User-Agent | Named as | Verdict |
|---|---|---|
| `TelegramBot (like TwitterBot)` (Telegram) | Twitterbot | spoofed |
| `Feedly/1.0 (+http://www.feedly.com/fetcher.html; like FeedFetcher-Google)` | Feedfetcher-Google | spoofed |
| `facebookexternalhit/1.1;line-poker/1.0` (LINE) | Facebook External Hit | spoofed |
| `...adidxbot/2.0; +http://www.bing.com/bingbot.htm` | Bingbot | wrong name |
| `NotGooglebot/1.0` | Googlebot | spoofed |

Fix: match the product token at the start or after `compatible;`, ignore what follows "like", and put specific patterns before general ones.

**B8 (Medium). The generic "bot word" rule runs before the browser test.**
A complete browser User-Agent with a phone model or extension name containing Robot, Spider, Checker, Crawl or Validator, or with `(+https://...)`, becomes an "Unlisted crawler". Named patterns also match anywhere: `Python-Tutor-Extension` is a Python script, `Datadoghq-RUM-WebView` is the Datadog agent (p4; `bot-detector.js:236`, `:674-688`).

**B9 (Medium). Native apps and media players are counted as bots.**
`MyShopApp/5.2.1 (iPhone; iOS 17.1)`, `CFNetwork`, `Dalvik`, `okhttp`, `AppleCoreMedia`, `Spotify`, Outlook, and the text browsers Lynx and w3m all land in "Other bots" (p4). For a site with a mobile app, its users move from human to bot. This needs a decision: a separate "Apps" class, or a label inside human.

**B10 (Medium). Forged browser User-Agents that bots favour are human.**
Chrome 41, Firefox 3 and 9, MSIE 6, `MSIE 9.0; Trident/5.0`, two User-Agents glued together, and SQL injection text appended to a browser User-Agent are all "browser" (p4). Browser age and malformed strings are not signals.

**B11 (Low). Crawlers missing from the name list.**
360Spider, Google-PageRenderer, Cloudflare-Traffic-Manager and `yandex.com/bots` are "Unlisted crawlers": still automated, but their address is not checked (p4).

**B12 (Low). The one-minute window does not slide.**
It opens at the first request after the previous window closed (`traffic-classifier.js:127-134`), so a burst shorter than a minute can be split in two and needs up to twice the threshold.

**B13 (Low). The "no User-Agent field" note is computed on the filtered rows (introduced on this branch).**
Whole log: note off. Filter to "automated", which leaves 40 rows without a User-Agent: note on (p6 item 2; `analyzer.js:51-56`, `:175`). Paste engine only.

### 3.5 Path identification

Four places each have their own idea of a path: the analyzer's tables, the filter dropdown, the filter itself, and the classifier.

**U1 (High). "Targeted Paths" lists path segments, counted once per segment per request.**
(`analyzer.js:220-226`.)

- 10 requests to `/api/v1/users/123` give four rows, each 10 hits and 100% (p2 A).
- 10 requests to `/a/a/a` give `/a` = 30 hits, 300% (p2 C).
- The site root never appears: 10 requests to `/` give an empty card (p2 B).
- `/admin`, `/blog/admin` and `/admin/` are one row; `/Admin` is another (p2 D).
- In the browser, a shop log of 210 requests shows 395 hits and shares that add up to 188%. The rows include `/42`, `/7`, `/v1` and `/app.js` under the heading "Endpoint Path" (b1).

**U2 (High). The same path has three different counts on one page.**
`/products` in the shop log: 75 in the card, 50 in the path dropdown, 83 requests after clicking the row (b1). The card counts the segment anywhere, the dropdown counts the first segment only (`dashboard.js:1925-1936`), and the filter is a text search over the whole URL including the query string, so `/search?q=/products` matches (`dashboard.js:2034-2036`).

**U3 (Medium). The segment pattern drops characters.**
`/~alice/home` is counted as `/home`, `/caf%C3%A9/menu` as `/caf` and `/menu`, `/@vite/client` as `/client`, `/a+b/c,d` as `/a` and `/c`, `/user:42/x` as `/user` and `/x` (p2 E). The pattern allows letters, digits, `_`, `.` and `-` only.

**U4 (Medium). URLs are not normalised.**
`/index.html`, `//index.html`, `/./index.html`, `/index.html/`, `/INDEX.html` and `/index%2Ehtml` are six URLs (p2 G). `http://example.com/page` is its own URL and adds the segment `/example.com`. `/page#top` and `/page;jsessionid=1` are separate from `/page` (p2 F). Only `?` is cut (`analyzer.js:213`).

**U5 (Medium). "Security signals: N active indicators" counts harmless paths.**
It adds one for every top-path segment that contains `admin`, `.env`, `.git`, `wp-login` or `xmlrpc`, whatever the status and however few the requests (`dashboard.js:757-773`). The shop log, which has no attack in it, shows "3 active indicators": `/badminton`, `/admin-tips-for-shop-owners`, `/administration` (b1). It also counts a network as Tor when its name contains the letters "tor": 319 of 29,728 networks sampled match, among them Ford Motor and Tractor Supply, while the Tor exit operators checked do not (t13). The number does not use the classifier's results (scanners, suspected clients).

**U6 (Medium). The upload engine has no paths at all.**
Targeted Paths, top URLs and referrers are empty after an upload (p2, every case; `analyzer.js:849-850`).

**U7 (Low). The lists are cut without saying so.**
The card holds at most 30 segments and its badge then says "30 Paths"; top URLs stop at 20 with no "other" row (`analyzer.js:253-272`).

### 3.6 Numbers the analyzer derives

**A1 (Medium). One wrong date stretches the timeline.**
600 requests in ten minutes plus one line dated 2016: span 5,258,884 minutes, one bucket is 23 days, 2 of 160 buckets hold data, average 0 requests a second (p6 item 5).

**A2 (Medium). Peak rate and the burst label depend on the bucket size.**
The peak is the average of the busiest bucket, so a wider bucket gives a lower peak. The upload engine always uses one-hour buckets with no status split (`analyzer.js:764-791`). Carried over from the earlier review (ANALYZE-17, 18); code unchanged.

**A3 (Medium). Countries and networks are counted differently by the two engines.**
Three located addresses and two without location data: paste shows "Unknown" as a country and AS0 as a network (4 networks); upload shows country codes instead of names and 3 networks (p8 item 1).

**A4 (Low). Response size has different keys per engine.**
Paste: `average`, `median`, `min`, `max`. Upload: `avg` only (p6 item 4). The downloaded report reads `average` and `median` (`report.js:684-685`) and prints NaN and undefined for uploads.

**A5 (Low). Hours and days are shown in UTC of the stored time without saying so.** Together with P1 the hour-of-day chart is off by the server's offset.

**A6 (Low). Referrers.** "-" is counted as the top referrer, and full URLs are not grouped by site, so one site with many pages is many rows (`analyzer.js:275-287`). Read from the code, not run.

### 3.7 Upload engine gaps already in `TRAFFIC_ANALYZER_REVIEW.md`

At the time of the review (see section 1a for what is fixed): exclusion toggles empty the dashboard, method, path, partial-address and CIDR filters are ignored, "Matching 0 / 0", "Skipped: 0", hour-only timeline.

### 3.8 Carried over, not run again

The code is unchanged since the 2026-11-26 review (`review-evidence/traffic-analyzer/parser/FINDINGS.md` and `analyzer/FINDINGS.md`):

- A gzip file with several members is rejected and a truncated one loses everything readable; with two or more files gzip is recognised by file name (PARSE-14, 15).
- When the parser worker cannot start, the error shown is "[object Event]" (PARSE-16).
- The backend feed parser drops compressed IPv6 ranges, so IPv6 crawlers can be called spoofed (ANALYZE-10).
- GeoIP download failures block or hang the analysis (ANALYZE-07 to 09).

## 4. What works

- Chunk boundaries: chunk sizes from 1 to 65,536 bytes with multi-byte characters give the same result as one string. CRLF, a missing final newline and a UTF-8 BOM are handled (prev-07).
- IPv4-mapped IPv6 addresses are unwrapped; malformed IPv4 and IPv6 are rejected (prev-06).
- Common, combined, combined with extra fields, vhost and nginx JSON are parsed correctly when the file is clean (prev-01).
- Both engines give the same traffic classes for every case in p3, p5, p6 and p8.
- Plain probes, fast login floods, request floods, slow scrapers without referrers and rotating between three User-Agents are detected (p3).

## 5. Suggested order of work

1. **Client address and the 403 default** (C1, B1, C6). They decide what the classifier is given. Small parser change plus one option.
2. **One path function** (U1 to U4, U6, P4): a single `normalisePath()` used by the tables, the dropdown, the filter and the classifier; "Targeted Paths" lists real paths with their status split; the path filter matches a path or a prefix.
3. **Classifier** (B2 to B10): decoded path and query checks by family, a per-address and per-target pass, cumulative login attempts, a longer asset list, anchored bot names, a decision on apps.
4. **Format detection** (F1 to F6): majority vote over a larger sample, any status from 100 to 599, strict per-line checks instead of the one-line guess.
5. **Time** (P1, P2, A1): one time zone rule, more notations, a guard against stray dates.
6. **Engine parity and the rest** (U5, A2 to A4, P5 to P8, C2 to C5, F7, F8).

Each step should add the cases above as unit tests next to `tests/unit/traffic-classifier.test.js`.
