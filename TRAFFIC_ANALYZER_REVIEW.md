# Traffic Analyzer review and new traffic classifier

Date: 2026-11-27. Reviewed: `main` at `a53c7b8`. Changes: branch `traffic-classifier` (local, uncommitted, not pushed).

Line numbers in sections 2 to 4 and 7 refer to `main`. Evidence scripts and their output are in
`/Users/dan/work/toolkit-dev/review-evidence/traffic-analyzer/` (untracked); the folder is named per finding.

## 1. Summary

1. **The analyzer has two engines and they did not agree.** Pasted text, samples, remote URLs, multi-file
   uploads and shared links use an in-memory engine. A single uploaded file and cURL ingest use a streaming
   engine in a Web Worker. The second one is a reduced copy of the first, and most wrong numbers come from it.
2. **Human traffic was counted as bots on upload.** The parser stores the word `None` as the bot name of a
   human request, and the streaming engine listed `None` as a verified bot. Every uploaded log showed
   "0% human, 100% verified bots". Fixed on the branch.
3. **Filters.** In paste mode, combined filters are consistent: every card, table and the Log Explorer are
   recomputed from the same filtered rows, and all 27 combination checks gave the expected count. The
   mismatches in paste mode are the path and IP filters, which match more rows than the row you clicked
   shows. In upload mode, the method, path, traffic and partial-IP filters did not work at all. The traffic
   filter is fixed on the branch; the others are listed in section 7 with the fix for each.
4. **Bot detection misjudged 22 of 35 common user agents.** In-app browsers (Pinterest, Sogou, Viber),
   Internet Explorer and a phone model were called bots or even "spoofed bot attackers". Scanners (zgrab,
   Nikto, sqlmap, Nuclei), HTTP libraries (okhttp, axios) and requests with no user agent were called human.
   Fixed on the branch: 0 of 35 wrong.
5. **New classifier.** Every request now gets exactly one of six classes that always add up to the total,
   in both engines: human, verified bot, known bot (unverified), spoofed bot, other bots and tools, suspected
   bot. Bots outside the known list are counted and named. Browsers that behave like bots are kept apart from
   people instead of being mixed into either side.

Before and after, same logs, same data files:

| Log | Path | `main` | Branch |
| --- | --- | --- | --- |
| heavy-traffic.log (generated as 70,000 human, 30,000 bot) | paste | human 70,000 | human 70,000 |
| | upload | human 0, verified 100,000 | human 70,000, verified 5,230, spoofed 1,807, other 22,963 |
| multi-vector-attack.log (3 attack tools, 2 fake Googlebots) | paste | human 22,980 (includes the zgrab scanner), spoofed 0 | human 22,337, spoofed 1,793, tools and scanners 2,689 |
| | upload | human 0, verified 49,761 | identical to paste |
| inapp-and-scanners.log (8 people, 6 scanner requests) | paste | human 7, spoofed 5, unverified 2 | human 8, other 6 |

## 2. How the analyzer works

All analysis runs in the browser. React renders the input form; classic scripts in `frontend/public/js`
do the rest, loaded in order by `frontend/src/lib/nginx-engine.ts`.

| Input | Engine | Code path |
| --- | --- | --- |
| Paste, sample buttons, remote URL, several files, shared link `/s/[code]`, re-analysis after an exclusion toggle | In-memory | `LogParser.parseAsync` -> `Analyzer.enrichLogEntries` -> `Analyzer.analyzeEnhancedLogs`; filters in `dashboard.js` `applyFilters` (:1966) |
| One uploaded file, cURL ingest session | Streaming | `streamChunksToWorker` -> `log-parser.worker.js` + `ColumnarStorage` -> `Analyzer.analyzeFromWorkerSummary` (:774); filters in `ColumnarStorage.query` (:276) |

The engine is chosen by the type of input, not its size: a 1 kB file uploaded goes through the streaming
engine, the same text pasted goes through the in-memory one.

On a filter change the in-memory engine filters the entry list and runs the whole analysis again on the
result, so its numbers agree with each other by construction. The streaming engine sends the filter to the
worker, which scans typed-array columns and returns counters.

## 3. Filters

Tested in a real browser against a production build of `main`, with a 241-line log whose every count is
known (`filters/logs/known.log`, expected values from `filters/expect.py`, which shares no code with the
app). Full output: `filters/out/run-2026-11-27.txt`.

### 3.1 Each filter, both engines

| Filter | Paste (in-memory) | Upload (streaming) on `main` |
| --- | --- | --- |
| HTTP method | Correct (POST 47, DELETE 17, HEAD 23) | **Ignored.** Total stays 241 |
| Country | Correct. "Unknown" (68 requests) cannot be selected | Correct counts, shown as codes (`US`, `--`) |
| ASN | Correct, including AS0 | Correct, but AS0 is not offered |
| Path dropdown | **Mismatch.** Label says `/api (32)`, result is 53; `/products (23)` gives 56; `/admin (16)` gives 29 | **Ignored**, and the dropdown is empty |
| Path search box | Substring of the URL including the query string, case-insensitive. A trailing space gives 0. `café` does not match `caf%C3%A9` | **Ignored** |
| IP search box | Substring: `1.2.3.4` also returns `11.2.3.45` (34 instead of 20). IPv6 in expanded form gives 0. An invalid mask `8.8.8.8/33` is treated as a substring | Exact address only. `8.8` gives 0, any CIDR gives 0 |
| Traffic: human | Correct | **0 results** |
| Traffic: all bots, verified, spoofed, unverified | Correct | **0 results** |
| Time presets, stepper, drag | Correct | Correct. Keyboard steps on a handle stop after the first key (focus is lost on re-render) |
| Status class | No control exists, although the code supports it (`statusCategory`) | Same |
| User agent | No control exists (`uaSearch`) | Not supported: the column was not stored |

### 3.2 Several filters together

Paste: all correct. Examples: POST + United States = 28; + AS15169 = 14; + IP containing `8.8.8` = 3;
removing the method keeps the others (19); a combination that matches nothing shows a clean empty state;
Last 30 min + POST = 7; country + time window in either order gives the same number; Clear resets
everything including the time window.

Upload on `main`: wrong whenever one of the ignored filters is part of the combination. POST + US shows 135
instead of 28; POST + US + AS15169 shows 71 instead of 14; DELETE + one IP + a path that matches nothing
shows 16 instead of 0; Last 30 min + POST shows 41 instead of 7.

### 3.3 Numbers on the page that disagree with each other

| # | What you see | Why | Where |
| --- | --- | --- | --- |
| F1 | Upload: badge "Matching 0 / 0 requests" and Log Explorer header "(0 entries)" while the cards show 241 | The badge counts the in-memory entry list, which is empty in streaming mode | `dashboard.js:3069-3070` |
| F2 | Paste: clicking the IP row `1.2.3.4  20` shows 34 requests from 2 addresses | Row click sets a substring search | `dashboard.js:1449-1454`, `:2044` |
| F3 | Paste: three different numbers for one path. Table row `/api 37`, dropdown `/api (32)`, result after clicking either: 53 | The table counts every path segment, the dropdown counts the first segment, the filter matches a substring anywhere in the URL | `analyzer.js:321-327`, `dashboard.js:1915-1918`, `:2020-2023` |
| F4 | Paste: the timeline chart always shows the whole log (241) whatever is filtered. Upload: it follows the filter | The chart is deliberately drawn from the unfiltered entries in one engine only | `dashboard.js:1490-1500` |
| F5 | Upload: "Skipped: 0 lines" and all four exclusion counters 0, although 44 lines were excluded | The worker counts skipped lines but the page never reads the count | `nginx-init.js:599-610` |
| F6 | Upload: unticking "Ignore 403 responses" or "Ignore internal requests" empties the dashboard (0 requests) | The toggle re-parses the stored log text, which is empty in streaming mode | `dashboard.js:1270-1281` |
| F7 | Upload: Log Explorer shows "-" for time, status and user agent | The worker's rows use other field names than the table reads | `columnar-storage.js:455-465`, `dashboard.js:2219-2228` |
| F8 | Upload: "Targeted Paths" and "Top Referrers" are always empty; "ASNs & networks" is one lower than in paste | The worker summary has no paths or referrers and drops AS0 | `columnar-storage.js:345`, `analyzer.js:927-928` |
| F9 | Both: the traffic cards did not add up to 100%. The largest bot class (unverified) had no card | Only human, verified and spoofed had cards | `dashboard.js:1044-1061` |
| F10 | Both: the bot table is cut at 20 groups, so its rows can add up to less than the cards | `slice(0, 20)` | `analyzer.js:205` |
| F11 | Both: typing in the IP or path box at normal speed keeps only the first character | Each keystroke re-renders the whole dashboard after 150 ms and the box loses focus | `dashboard.js:2353-2364`, `:2589-2614` |
| F12 | Both: the two search boxes above the Log Explorer keep their old text after Clear | They are separate inputs writing to the same filter | `dashboard.js:1338-1357` |
| F13 | Both: the "IP logs" window ignores active filters (row says 2 hits, window lists 20) | It reads the unfiltered entries | `dashboard.js:1837` (`showIPLogs`) |

Fixed on the branch: F1 for the traffic filter only (see section 6), F7, F9, F10. The rest are open.

## 4. Bot detection on `main`

| # | Problem | Effect | Where |
| --- | --- | --- | --- |
| B1 | Humans stored as bot `None` in the streaming engine and summed into "verified bots" | Upload and cURL ingest: 0% human, 100% verified | `log-parser.js:278,382,494,811`, `analyzer.js:806-823,913` |
| B2 | The streaming engine never checks a bot's address; every bot is hard-coded as "Verified" | Fake Googlebots and `python-requests` get a green Verified pill | `analyzer.js:807-821` |
| B3 | Patterns that match people: `/Pinterest/`, `/Sogou/`, `/Viber/`, `/Yeti/`, `/Trident/`, and an unanchored `bot\|crawl\|spider\|...\|archive` | Pinterest and Sogou app users are listed as "Fake/Spoofed" attackers; Internet Explorer and a CUBOT phone are bots | `bot-detector.js:59,66,84,87,137,138` |
| B4 | Anything matching no pattern is human, including an empty user agent | zgrab, masscan, Nmap, Nikto, sqlmap, Nuclei, WPScan, okhttp, axios, node-fetch, Censys, and all requests without a user agent count as human | `bot-detector.js:536-544`, `analyzer.js:155-157` |
| B5 | Bots are found only by name. A script sending a Chrome user agent is always human | No scanner, brute-force or flood detection anywhere | - |
| B6 | A fuzzy fallback matches a bot name to an IP feed by substring in either direction | Will misfire as feeds are added | `bot-detector.js:570-575` |
| B7 | Backend: the first sync of the bot IP feeds never runs. `SUM()` comes back from MySQL as the string `"0"` and is compared with `=== 0` | On a new install Google, Bing, OpenAI and 13 other publishers have no IP ranges, so nothing claiming to be them can be verified or flagged. This is the state of the data file on this machine | `backend/src/lib/bot-ip-updater.js:728-732` |

Measured with 35 real user agents (`analyzer/t4-ua-detection.cjs`): 22 wrong on `main`, 0 wrong on the branch.

## 5. The new classifier

### 5.1 Classes

Each request belongs to one client (one IP address with one user agent) and each client gets one class.

| Class | Meaning | Card |
| --- | --- | --- |
| `human` | A browser user agent and nothing automated in the behaviour | Human traffic |
| `verified` | A known crawler, and the address is inside its publisher's IP ranges | Verified bots |
| `spoofed` | Claims to be a known crawler from an address that is not its publisher's, or from a private address | Spoofed bots |
| `unverified` | A known crawler whose address cannot be checked (no ranges published or loaded) | Other bots |
| `automated` | Not a browser: scripts and HTTP libraries, security scanners, headless browsers, crawlers that are not in the list, unrecognisable clients, no user agent | Other bots |
| `suspected` | A browser user agent whose requests look automated | Other bots |

Human + verified + spoofed + other bots = total requests, always, with or without filters.

### 5.2 Steps

1. **User agent** (`BotDetector.classifyUserAgent`, `bot-detector.js`). First match wins:
   no user agent; 111 known crawlers and services in 60 groups; 26 scanner signatures; 21 tool and library
   signatures; headless browsers; then a generic rule for anything that calls itself a bot (a product name
   ending in bot, crawler, spider, scraper, fetcher, checker, indexer, archiver, validator, or the
   `+http://` contact convention), shown under "Unlisted crawlers" with its own name; then the browser
   test (starts with `Mozilla/` or `Opera/`, names a platform and an engine); everything else is an
   "Unidentified client".
   Crawlers whose name also appears in an app's browser are matched by their crawler token only, so
   `[Pinterest/iOS]`, `SogouMobileBrowser`, `Viber/21.5`, `Trident/7.0` and `CUBOT NOTE 20` are browsers.
2. **Address check** for known crawlers (`BotDetector.verifyBot`). Private and reserved addresses are
   spoofed. Inside the publisher's ranges is verified, outside is spoofed. If the publisher's ranges are
   not loaded, the network (ASN) of the address is used for Google and Microsoft only: outside their
   networks is spoofed, inside is unverified, because cloud customers share those networks. The substring
   fallback (B6) is removed.
3. **Behaviour** for clients that look like browsers (`TrafficClassifier`, `traffic-classifier.js`).
   One strong signal is enough:

   | Signal | Threshold |
   | --- | --- |
   | Vulnerability probing | 3 or more different sensitive paths (`/.env`, `/.git/`, `wp-config`, `phpmyadmin`, 31 in total) |
   | Login brute force | 10 or more POSTs to a login endpoint within one minute |
   | Request flood | 120 page requests in one minute with at most 20% assets and 20% referrers, or 600 with at most 10% assets |
   | Distributed request flood | 20 or more clients that each sent 5 or more page requests in one minute for the same page (3 pages at most), none with an asset and at most 20% with a referrer, together 120 or more in one minute. See `PARSER_AND_IDENTIFICATION_REVIEW.md` section 1d |
   | Path enumeration | 30 or more requests, 80% of them 4xx, across about 15 or more paths |

   Weak signals count only when at least three occur together in 20 or more requests: no page assets, no
   referrers, fetched `robots.txt`, mostly HEAD, half or more 4xx, HTTP/1.0, about 30 or more different pages.
   The thresholds are in one object, `TrafficClassifier.THRESHOLDS`.
4. **Logs without a user agent column.** If 90% or more of at least 20 requests have no user agent, the
   format has no such field. Those requests are then judged by behaviour instead of being called bots, and
   the dashboard says so. Without this rule such a log would turn into 100% bots.

A client is judged once, over the whole log. Filters and time windows never change a request's class.

### 5.3 What changed in the code

| File | Change |
| --- | --- |
| `frontend/public/js/traffic-classifier.js` (new, 489 lines) | Client sessions, behaviour rules, and one `aggregate()` that both engines use to build classes, bot groups and the spoofed list |
| `frontend/public/js/bot-detector.js` | New pattern tables, `classifyUserAgent`, ASN fallback, `loadData`/`getData` so the worker gets the IP ranges from the page |
| `frontend/public/js/analyzer.js` | `enrichLogEntries` classifies through a session; `analyzeLogs` and `analyzeFromWorkerSummary` build the bot numbers with the shared `aggregate()`; adds `traffic_classes`, `automated_count`, `suspected_count`, `other_bots_count`, `suspected_clients`, `ua_field_missing` |
| `frontend/public/js/columnar-storage.js` | Client column; traffic filter by class and by bot group; per-client counts; Log Explorer rows carry time, status and user agent |
| `frontend/public/js/log-parser.worker.js`, `stream-line-splitter.js` | The worker classifies clients and returns the same structure as the in-memory engine |
| `frontend/public/js/dashboard.js` | "Other bots" card, two new traffic filter options, bot table rows for the new classes, no 20-group limit, merged logs are classified as a whole |
| `frontend/public/js/report.js` | "Other bots" card and badges for the new classes in the downloaded report and CSV |
| `frontend/src/lib/nginx-engine.ts`, `globals.css`, `signal-nginx.css` | Load the new script; 8-card layout; cache string `?v=6.54` (6.53 is taken by the `share-functionality` branch) |
| `backend/src/lib/bot-ip-updater.js` | B7: counts read as numbers, so the first feed sync runs |
| `tests/unit/traffic-classifier.test.js` (new), `tests/unit/analyzer-summary.test.js`, `tests/e2e/dashboard-structure.spec.ts`, `backend/test/bot-ip-updater.test.js` (new) | Tests |

One behaviour change to know about: "Ignore 403 responses" keeps 403s from clients that name themselves as
bots or tools. Scanners now count as such, so their blocked requests stay in the analysis
(multi-vector-attack.log: 50,000 requests instead of 49,761), and 403s from Internet Explorer are no
longer kept.

### 5.4 Checks run

| Check | Result |
| --- | --- |
| `node --test tests/unit/` | 90 of 91 pass. The one failure, `myip.test.js`, fails on `main` too (unrelated import problem). 60 of the tests are new |
| `cd backend && node --test test/bot-ip-updater.test.js` | 3 of 3 pass |
| Engine parity, 4 logs x 2 data files, in Node (`classifier/parity.cjs`) | Classes, bot groups, sub-bots, unique IPs and spoofed list identical in both engines; every traffic filter returns exactly the class count |
| Browser, paste and upload, 5 logs (`classifier/browser-check.mjs`) | All checks pass, no console errors: cards add up, bot rows match, each traffic filter, each bot-row click and its undo, traffic + country combined |
| E2E suite against the branch build (148 tests) | 135 pass, 5 skipped. 8 failed: 7 also fail on `main` (one of them intermittently); the 8th was the test that expects 7 KPI cards, now updated. The 59 analyzer tests pass after that |
| `tsc --noEmit`, `next build` | Pass |
| ESLint | 2 more `no-require-imports` errors in `log-parser.worker.js`, same pattern as the 3 already there |

Not checked: the backend fix against a live database (the unit test covers the comparison only); real
production logs (all logs here are generated); the two golden-file e2e specs, which cannot run because
their fixture logs are not in the repository. Their expected numbers will need regenerating, since tools
such as curl moved from "unverified" to "other bots".

Limits to keep in mind: behaviour rules only see what is in the log, so a slow scraper with a browser user
agent, real assets and referrers stays human; a client is one IP with one user agent, so an office behind
one address with identical browsers is one client; native apps (`okhttp`, `CFNetwork`, `Dalvik`) are
counted under "Scripts & HTTP libraries" because they are not browsers.

## 6. What is still wrong after this branch

The traffic filter and the human/bot numbers are now the same in both engines. Everything else in
section 3 that says "upload" is unchanged, because the streaming engine still lacks the data.

## 7. Open issues, in suggested order

The parser, client and bot identification, and path handling were reviewed in more depth afterwards:
see `PARSER_AND_IDENTIFICATION_REVIEW.md` (48 findings, each with a reproduction).

Severity: C critical, H high, M medium, L low. "Yesterday" means reproduced on 2026-11-26 with the script
named, not re-run today.

Status on 2026-11-27, after the fixes described in `PARSER_AND_IDENTIFICATION_REVIEW.md` section 1a:

| # | Now |
| --- | --- |
| 1 | Fixed: the exclusion options re-read the uploaded file. They are switched off, with a note, once a second source was added or the input was a stream |
| 2 | Fixed: method, path, address prefix and CIDR filters work on uploads |
| 3 | Fixed: "Matching N / M", the entry count and the Skipped counts are right on uploads |
| 4 | Fixed: uploads have paths, sections, referring sites, the status split per path and the same timeline as pasted logs (every interval, error line) |
| 5 | Fixed in both engines: the box keeps focus and caret |
| 6 | Fixed: a row click is an exact match; card, dropdown and filter count the same thing |
| 7 | Fixed: the chart shows the whole log in both engines; filters narrow the numbers and tables |
| 8 | Fixed: a status filter (class or code) and a User-Agent search box, in both engines |
| 10 | Fixed: the dashboard names the crawlers whose IP ranges are not loaded, and says when the range file could not be loaded at all |
| 12 | Fixed: one shared GeoIP load that always finishes; a database that cannot be loaded leaves "Unknown" and a notice; only bytes that parse as a database are cached |
| 13 | Fixed: Escape closes the address log window; Clear empties both pairs of search boxes (F12); the address window lists what the filters let through (F13); the path choices keep their order |
| A1 | Fixed: one engine. Every source goes through `LogEngine.analyze` into the worker and its column store; the in-memory engine is removed (see `PARSER_AND_IDENTIFICATION_REVIEW.md` section 1c) |
| A2 | Fixed: one result shape |
| A3 | Fixed: `dashboard.js` is split into state, filter logic (`dashboard-filters.js`) and markup (`dashboard-views.js`); the latter two are tested without a browser |
| A4 | Fixed: the script version is made at build time |
| A5 | Fixed: `upload-parity.spec.ts`; the golden and bot-intel specs run; sample logs are generated; CI workflow |
| A6 | Fixed: removed |
| 9 | Fixed: "Unknown" can be chosen in both engines, IPv6 is matched in any notation, `/33` matches nothing |
| 11 | Fixed (PARSE-07, PARSE-04). PARSE-08: every notation now keeps the server's clock |

### Functional

| # | Sev | Issue | Fix |
| --- | --- | --- | --- |
| 1 | C | F6: an exclusion toggle after an upload empties the analysis | Keep the uploaded `File` and re-stream it with the new options, or disable the toggles in streaming mode |
| 2 | H | Upload: method, path and partial-IP/CIDR filters ignored or 0 (3.1) | In `ColumnarStorage._parseFilters`, build a match mask over `methodDict`, `urlDict` and `ipDict` once per query and test rows against it; the client column added here makes a user-agent filter possible the same way |
| 3 | H | F1, F5: "Matching 0 / 0", "(0 entries)", "Skipped: 0" on upload | Take the numbers from `summary.matchingCount`, the unfiltered total and the worker's skip counters |
| 4 | H | F8: no paths, no referrers, hour-only timeline without status split on upload | Add path-segment and referrer dictionaries and status class per time bucket to the worker summary |
| 5 | H | F11: typing in a filter box loses focus after one character | Re-render only the result sections, not the filter ribbon; or restore focus and caret after render |
| 6 | M | F2, F3: row clicks filter by substring | Use exact match for row clicks (`ipExact`, first path segment), keep substring for typed text; count one thing in table, dropdown and filter |
| 7 | M | F4: timeline follows filters in one engine only | Decide one behaviour; if the chart should show the whole log, shade the filtered share |
| 8 | M | No status filter and no user-agent filter in the UI | Add a status class dropdown and a user-agent search box; both exist in `applyFilters` |
| 9 | M | Paste: "Unknown" country cannot be selected; IPv6 must be typed in the log's own notation; `/33` accepted | `dashboard.js:1904`, `:2027-2044` |
| 10 | M | B7 follow-up: when bot ranges are missing the dashboard does not say so | Show the number of publishers without ranges next to the bot table |
| 11 | M | Yesterday, parser (`parser/FINDINGS.md`): one truncated line among the first 15 makes every row lose status, bytes and user agent (PARSE-07); logs behind a proxy are rejected because only `$remote_addr` is read (PARSE-04); time zone offsets of common-log timestamps are discarded (PARSE-08) | See the file; each has a repro script |
| 12 | M | Yesterday, GeoIP (`analyzer/FINDINGS.md` 07 to 09): Analyze hangs forever if the GeoIP download fails while in progress; one unreachable database blocks the whole analysis; a bad download is cached | Same |
| 13 | L | F12, F13; Escape does not close the IP log window; option order in the path dropdown changes after Clear | - |

### Architecture

| # | Issue | Suggestion |
| --- | --- | --- |
| A1 | Two engines with separate parsing loops, filters and result shapes. Each feature has to be written twice and the copies drift (this review is mostly a list of such drift) | Make one engine. The columnar store can serve small inputs too; keep the in-memory path only as a fallback where Workers are missing. Until then, add a test that runs one log through both and compares every number, as `tests/unit/traffic-classifier.test.js` now does for traffic classes |
| A2 | The result object differs by engine: country names or codes, `asn` number or string, percentages as strings or numbers, keys missing | Define the shape once and build it in one function |
| A3 | `dashboard.js` is 3,182 lines in one closure with about 40 mutable variables; every filter change rebuilds the whole page with `innerHTML` | Split into state, filter logic and render; filter logic without DOM access can then be unit-tested (today it can only be tested through a browser) |
| A4 | Classic scripts share globals; the cache string `?v=` is maintained by hand in 4 files while `/js/*` is cached for 30 days | Generate the version at build time |
| A5 | Tests: almost every e2e spec pastes text, so the streaming engine had no value checks; 2 golden specs and 5 upload tests cannot run from a clean clone; no CI | Commit small fixture logs, add upload variants of the value tests, add a CI workflow |
| A6 | Dead code: `geomap.js` and its vendor files are never loaded; the mitigation functions in `dashboard.js` have no DOM; `renderLogExplorerCardHtml` is defined twice | Remove |

## 8. Try it

A production build of the branch is running at http://127.0.0.1:3020/nginx (frontend only, using the
review backend on port 4010). Stop it with `kill $(cat logs/classifier-frontend.pid)` in this folder.

The crawler IP range file of this checkout (`frontend/public/data/verified-bots.json`, not tracked) was
replaced on 2026-11-27 by one synced that day with the branch's own updater, so real Googlebot shows as
verified here. The file it replaced had no ranges for Google, Bing or OpenAI (B7).

Tests: `npm run test:unit`, `npm run test:backend` (needs `npm ci` in `backend/`), and
`E2E_BASE_URL=http://127.0.0.1:3020 npx playwright test` from this folder. The sample logs the page and
some specs need are written by `npm run samples` in `frontend/`.
