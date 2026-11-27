# Tool test suites: how they work and how to write one for a new tool

This folder holds one deep Playwright suite per tool. Each suite drives the tool in a real browser the way a
person would, and compares **every value the tool shows** with an expected value the test computes on its own.
The suites are plain code: no AI service is called at any point. A run prints only what did not go to plan and
writes a report that a person or an AI agent can read to find and fix the cause.

Give this file to an agent (or a new team member) together with the request "write the test suite for tool X".
It contains the full method.

## Contents

1. [Run the suites](#1-run-the-suites)
2. [What a run produces](#2-what-a-run-produces)
3. [Layout of this folder](#3-layout-of-this-folder)
4. [The method: eight layers every tool suite must cover](#4-the-method-eight-layers-every-tool-suite-must-cover)
5. [Oracles: where expected values come from](#5-oracles-where-expected-values-come-from)
6. [Random inputs and seeds](#6-random-inputs-and-seeds)
7. [Tools that call a server or a third party](#7-tools-that-call-a-server-or-a-third-party)
8. [Shared helpers](#8-shared-helpers)
9. [Writing rules](#9-writing-rules)
10. [Step by step: adding a suite for a new tool](#10-step-by-step-adding-a-suite-for-a-new-tool)
11. [Worked example: the Traffic Analyzer](#11-worked-example-the-traffic-analyzer)
12. [Checklist before you call a suite done](#12-checklist-before-you-call-a-suite-done)

## 1. Run the suites

The suites need a running frontend and backend. Point `E2E_BASE_URL` at the frontend.

```bash
npm ci                                   # once, in the repository root
npx playwright install chromium          # once

E2E_BASE_URL=http://localhost:3000 npm run test:tools                              # everything
E2E_BASE_URL=http://localhost:3000 npm run test:tools -- tests/e2e/tools/nginx     # one tool
E2E_BASE_URL=http://localhost:3000 npm run test:tools -- -g "country filter"       # tests by name
E2E_SEED=123456 E2E_BASE_URL=http://localhost:3000 npm run test:tools              # replay a run exactly
```

| Variable | Meaning | Default |
| --- | --- | --- |
| `E2E_BASE_URL` | Frontend under test | `http://localhost:3001` |
| `E2E_SEED` | Seed for all generated inputs | random, printed at the start of the run |
| `E2E_LIVE` | `0` skips tests tagged `@live` (they need internet access from the backend) | on |
| `E2E_RETRIES` | Retries per failed test | `0` |
| `E2E_TIMEZONE` | Browser time zone | `America/New_York` |
| `E2E_REPORT_DIR` | Where the failure report is written | `test-results/tools-report` |
| `E2E_STORAGE` | `real` makes the Traffic Analyzer share tests use the stack's own object storage instead of the in-test stand-in (section 7) | stand-in when the stack has no storage |

The browser runs in a time zone that is **not** UTC on purpose: a tool that mixes local time and UTC shows
wrong times only for users outside UTC, and the default would hide that.

## 2. What a run produces

The reporter (`_support/failure-reporter.ts`) prints nothing for a passing test. For each problem it prints
the tool, the test and the first lines of the message, then a totals line:

```
✗ [subnet] Subnet calculator — invalid input › rejects "10.0.0.0/2.5" (fractional prefix)  (failed)
    Error: "10.0.0.0/2.5" is not a valid network (fractional prefix); an error must be shown
PROBLEMS FOUND: 32 passed, 1 failed, 0 flaky, 0 skipped in 41.0s
Details: test-results/tools-report/failures.md
```

`test-results/tools-report/` is rewritten on every run:

| File | Content |
| --- | --- |
| `failures.md` | The index, grouped by tool. For each failure: test, file and line, seed, reproduce command, saved inputs, and the first four mismatches (expected and shown) |
| `<n>-<tool>-<test>/failure.md` | Every mismatch of that one failure, in full |
| `<n>-<tool>-<test>/` | Next to it: the inputs the test generated (for example the access log it pasted), a screenshot, the page structure at the moment of failure, the Playwright trace |
| `failures.json` | All of it as data, for a program or an AI agent |

To have an AI fix what a run found, give it `failures.md` and this guide. It reads the index, opens the
`failure.md` and the saved input of the entry it works on, and reruns that one test with the reproduce command.

The intended loop is: run → read `failures.md` → decide for each entry whether the **application** is wrong
(fix the application) or the **expectation** is wrong (fix the oracle, and say why in the commit) → rerun with
the same `E2E_SEED`. Never make a test pass by loosening it without understanding which side is wrong.

## 3. Layout of this folder

```
tests/e2e/tools/
  README.md                 this guide
  FINDINGS.md               defects the suites currently report, by tool; remove a line when it is fixed
  _support/                 shared helpers (section 8)
  <tool>/                   one folder per tool, named after its route
    oracle.ts               expected values, computed independently of the app
    generator.ts            random input builder (when inputs are more than a line)
    page.ts                 selectors and actions for the tool ("page object")
    *.spec.ts               the tests, one file per area when the tool is large
```

Small tools keep everything in `oracle.ts` and one spec. Large tools (the Traffic Analyzer) split specs by
area so one area can be run alone.

## 4. The method: eight layers every tool suite must cover

Work through the layers in this order. A suite is complete when each layer is either covered or explicitly
not applicable to the tool (say so in a comment at the top of the spec).

### Layer 1 — The tool is reachable

- The route answers HTTP 200 and shows the tool's `h1` (`openTool`).
- The home page directory and the sidebar link to it, and the link lands on the route (`expectToolLinkedFromHome`).
- The page title names the tool.

### Layer 2 — Nothing is visually broken

- Every control the tool needs is visible and enabled (`expectControlsUsable`).
- `expectNoUiGlitches` passes in **every state** the tool has (empty, loading where it can be held, result,
  error, each tab or mode, each open dialog) and at **desktop, laptop and mobile** widths (`VIEWPORTS`). It
  finds sideways scrolling, controls with no size, controls outside the viewport, controls covered by another
  element, controls with no readable name, cut-off button labels, leaked `undefined` / `NaN` /
  `[object Object]` / `Invalid Date`, broken images and duplicate ids.
  The audit looks at `<main>` unless told otherwise. A dialog, or anything else rendered outside `<main>`,
  needs `{ scope: '<selector>' }`; the sidebar and top bar are audited by the `workspace/` suite.
- An open dialog covers the whole page: nothing behind it can be clicked (`nginx/01-access-and-layout`).
- No JavaScript error, console error or failed request happens. The `guard` fixture checks this in every test
  automatically; a test that provokes an error on purpose declares it with `guard.allow(/pattern/)`.

### Layer 3 — Input paths

Every way to give the tool input is exercised: typing, pasting, file upload, drag and drop where offered,
sample buttons, presets, the Enter key, URL parameters. Each path must reach the same result for the same data.

### Layer 4 — Every displayed value is correct

This is the core. Generate random input, compute what the tool should show, and compare **each** number, label,
table cell, badge, percentage and timestamp. Do not sample: if the page shows it, a test checks it.

- Totals, counts, unique counts, percentages (with the page's rounding), sizes with units.
- Every table: row count, order, each column of each row, the header count badge, the "showing x of y" text.
- Every chart: read the Chart.js model (`Chart.getChart(canvas)`), then compare labels, data points, axis
  limits and tick labels with the oracle; also check that the canvas is not blank.
- Time: every displayed time against the input, in the time zone the tool promises.
- Consistency between widgets: the same quantity shown in two places must be equal (a card and its table, a
  dropdown option count and the result of choosing it).

### Layer 5 — Every control changes the result correctly

For each filter, toggle, tab, sort header, preset, slider, stepper, page-size selector and pagination button:

1. Use it.
2. Recompute the expectation for the new state with the oracle.
3. Re-run the full layer 4 comparison, not a single spot check.
4. Undo it and confirm the original result returns.

Then **combine** controls: pick random pairs and triples (filter A + filter B + time range) and compare again.
Combinations are where filters silently disagree. Include the combination that matches nothing (empty state
must show zeros and a clear message, not stale data) and "clear all".

Clicking a table row, a chart legend or a badge that applies a filter counts as a control: check the filter it
applies and the resulting data, and that a second click removes it when the tool promises that.

### Layer 6 — Everything that leaves the page

- **Copy buttons**: the clipboard text equals the expected text; the button confirms.
- **Exports and reports** (CSV, HTML, JSON): download the file, parse it, and compare every field with the
  oracle and with what the page showed. Check the file name. For an HTML report, open it in the browser and
  run the layer 4 comparison on it.
- **Share links**: create one without a password and one with a password. Open each in a **new browser
  context** (a different visitor). Without password: the shared view shows the same values as the original.
  With password: the content is hidden until the right password is entered, a wrong password is refused, the
  right one shows the same values. Check expiry options when the tool offers them.
- **Requests the tool sends**: for server-backed tools, the request body matches what the user entered.

### Layer 7 — Bad input and failure

- Invalid, empty, oversized, and boundary inputs: the tool refuses with a clear message and shows no result.
- Inputs that look valid but are not (wrong separators, out-of-range numbers, trailing text). A tool that
  accepts them and shows a confident wrong answer is the worst failure for an operator.
- Markup in input (`<img src=x onerror=...>`): shown as text, never executed.
- For server-backed tools: HTTP 400, 429, 500, a network failure and a slow response. The page must show an
  error, leave no spinner running, and recover on the next valid request.

### Layer 8 — State and navigation

- A second run replaces the first result completely (no leftovers from the previous input).
- "New", "Reset", "Clear" and "Back" return to a clean state.
- Reload, browser back and forward, and deep links behave as the tool promises.
- Settings the tool remembers (localStorage) are restored, and a cleared storage gives the defaults.

## 5. Oracles: where expected values come from

An oracle is the test's own answer to "what should the page show for this input?". Rules:

1. **Independent.** Never import the application's code to compute the expectation, and never copy its
   algorithm line by line. Write the rule from the definition (an RFC, the tool's own help text, plain
   arithmetic) and in a different style: BigInt instead of bit operators, a loop instead of a regex, a
   different library. A shared mistake is invisible; an independent one is not.
2. **Derived from the input, not from the page.** The generator knows what it put in ("340 requests from
   this address, 12 of them 404"). Expectations come from that record. Reading a number off the page and
   comparing it with another number off the page is only a consistency check (still worth having).
3. **Deterministic.** Same seed, same input, same expectation.
4. **Honest about definitions.** When the tool's meaning of a number is a product decision (for example
   "which requests count as human"), write the definition at the top of the oracle, in words, with the source
   (help text, UI label, documentation). If the page and the definition disagree, the test fails and a person
   decides which one is right.
5. **External data is pinned.** When a result depends on a data file (GeoIP database, bot IP ranges), the
   oracle reads the same file with a different reader, or the test serves a small file of its own. See the
   Traffic Analyzer suite for both techniques.

6. **Default data is unambiguous; ambiguity gets its own test.** A generator's normal output must have one
   obvious right answer for every value (no path name that is part of another path, no browser whose name
   contains "bot"). Then a red test in the main specs means a real defect, not a debatable definition. Every
   awkward input goes into an edge-case spec, in a small hand-written input with **one concern per test**, so
   its failure names exactly one cause and cannot hide the rest of the tool.
7. **Where the definition is a product decision, say so in the test name or message.** If a test encodes a
   choice the product owner could reasonably make differently (should "Unknown" be selectable as a country?),
   keep the test, word it as the expectation it is, and list it in the hand-over as a decision to confirm.

A disagreement between page and oracle has three possible causes, in this order of likelihood once a suite is
stable: the application is wrong; the application changed on purpose and the definition must be updated; the
oracle is wrong. Investigate before editing either side.

## 6. Random inputs and seeds

- Use the `rng` fixture for every random choice. Never use `Math.random()` or the current time for test data.
- Generators take an `Rng` and return both the input **and the facts about it** (the ground truth the oracle
  starts from).
- Save generated input with `evidence.save('name.ext', content)`. On failure it is copied into the report, so
  the exact log, payload or expression can be inspected and pasted into the tool by hand.
- Each test gets its own seed, derived from `E2E_SEED` and the test title. Running one test alone with the
  same `E2E_SEED` regenerates the same input.
- Make generators produce the awkward cases on purpose and often: a single row, ties in a "top N" table,
  values on a rounding boundary, the longest label, zero of something, IPv6 next to IPv4, a span that crosses
  midnight, more rows than one page.
- Tie-breaking: when the tool's order for equal values is not defined, compare as a set within the tied
  group, or generate data without ties for the ordering test and with ties for a separate test.

## 7. Tools that call a server or a third party

Results that come from DNS, WHOIS, a certificate or a reputation service cannot be predicted. Use three kinds
of test, in this proportion:

1. **Contract tests (most of the suite, always run).** Intercept the tool's API call in the browser with
   `mockApi` and answer with a randomised payload that follows the backend's real response shape (read the
   route in `backend/src/routes` to get it right, including optional and missing fields). The payload is the
   oracle: every field must appear correctly, every derived value (days remaining, grades, counts, badges)
   must match an independent recomputation. Also assert the request the page sent. Cover error responses,
   slow responses, empty results and extreme values here.
2. **Live tests (few, tagged `@live`).** Use the real backend with a stable public target. Capture the real
   response with `captureApi` and assert that the page shows exactly that response. Where a second,
   independent source exists (Node's `dns` or `tls` module), compare with it too, tolerating only what
   legitimately varies. Skip with `test.skip(process.env.E2E_LIVE === '0', ...)`.
3. **Real backend flows we own (always run).** Anything stored by our backend, such as share links, runs
   against the real API and database end to end.

Never weaken a contract test because a live service was slow; move the variable part to a live test.

**Replace only the third party, never our own logic.** When a feature needs an outside service that the test
stack does not have (object storage for traffic-analysis shares), stand in for that service alone and keep
every part we own on the real backend. `nginx/storage.ts` is the model: it keeps uploaded logs in memory and
serves them back, while the share record, the password check and the expiry still run through the real API
and database. It detects a stack that has real storage and then replaces nothing.

The backend allows 100 requests per minute per client address. Through the local Next.js proxy this limit does
not apply; when testing a deployed site behind a reverse proxy, run with `--workers=1`.

## 8. Shared helpers

Import `test` and `expect` from `_support/fixtures`, never from `@playwright/test` directly, so the guard is active.

| Helper | File | Use |
| --- | --- | --- |
| `test`, `expect` | `_support/fixtures.ts` | Test function with the fixtures below |
| `rng` fixture | `_support/rng.ts` | `int`, `pick`, `weighted`, `shuffle`, `sample`, `bool`, `string`, `fork` |
| `guard` fixture | `_support/fixtures.ts` | Fails the test on unexpected page errors; `guard.allow(/re/)` for intended ones |
| `evidence` fixture | `_support/fixtures.ts` | `evidence.save(name, content)` keeps generated input with the failure |
| `withCommas`, `parseCount`, `cleanText` | `_support/fixtures.ts` | Number formatting and reading text |
| `openTool`, `expectToolLinkedFromHome`, `waitForHydration` | `_support/navigation.ts` | Layer 1 |
| `expectNoUiGlitches`, `expectControlsUsable`, `auditUi`, `VIEWPORTS` | `_support/ui-audit.ts` | Layer 2 |
| `captureDownload` | `_support/io.ts` | Run an action, get the downloaded file's name and text |
| `readClipboard`, `clearClipboard` | `_support/io.ts` | Copy buttons |
| `mockApi`, `failApi`, `captureApi` | `_support/io.ts` | Section 7 |
| `parseCsv`, `csvToRecords` | `_support/csv.ts` | Exported CSV files |
| `scriptApi`, `deferred`, `settle` | `_support/gate.ts` | Answer each request separately, hold a response open (loading state), deliver an old answer after a newer one |
| `newVisitor`, `expectVisitorClean` | `_support/visitor.ts` | A second person opening a share link: fresh browser context with its own error watch |
| `expectNoUiGlitchesAtRest` | `_support/ui-audit.ts` | The layout audit after hover effects and fade-ins have finished |

Add a helper to `_support/` when a second tool needs it. Keep tool-specific code in the tool's folder.

Helpers that are still local to one suite and are the next candidates to move here when a new suite needs them:
an independent reader for the GeoIP `.mmdb` files (`dns/mmdb.ts`, `abuse/mmdb.ts`; `nginx/geo.ts` uses the
`maxmind` package), the statistical limits for random output (`chiSquareLimit`, `binomialRange` in
`password-generator/checks.ts`), `seedStorage` for preset localStorage (same file), and the colour-contrast and
blank-icon checks in `workspace/checks.ts`.

## 9. Writing rules

- **One behaviour per test, named as a statement of what must be true**: `'country filter shows only requests
  from that country'`, not `'test filter 3'`. The name is the first thing the failure report shows.
- **Every assertion carries a message that says what was being checked and with which input**:
  `expect.soft(cell, \`${ctx}: hits for ${ip}\`).toHaveText('340')`. A bare `expected 340, received 34` is not
  enough to act on.
- **Use `expect.soft` for comparisons of displayed values**, so one run reports every wrong number instead of
  stopping at the first. Use plain `expect` for preconditions (the dashboard appeared, the dialog opened).
- **Act like a user.** Click, type, select, drag, press keys. Do not call the application's functions from
  the test and do not set application state through `page.evaluate`. Reading state that has no DOM form (a
  chart's data model) is allowed and must be combined with a check of what is visible.
- **Wait for a condition, never for time.** No `waitForTimeout`. Wait for the element, text or request that
  proves the page is ready. If the tool debounces input, wait for the visible effect.
  When the application itself runs on a timer (a "Copied!" label that resets after two seconds), give that
  wait a generous limit (20 s): on a busy machine a page can stand still for several seconds, and a tight
  limit turns that into a false failure.
- **Selectors**: prefer role and accessible name, then stable ids, then text. Avoid selectors built on inline
  styles or deep structure. Put them in the tool's `page.ts` so a markup change is fixed in one place.
- **Each test stands alone**: it opens the tool itself and depends on no other test.
- **Known application defects stay as failing tests.** Do not skip or soften them. If a defect must be
  parked, use `test.fail()` with a comment that names the defect, so the test turns red again when it is fixed.
- **Comments explain why**, for example the definition a check relies on. They do not narrate the code.
- **Prove that a new check can fail.** Before trusting a comparison, change one expected value (or one input
  record) and see the test turn red with a message you could act on. A check that cannot fail is worse than none.

### Techniques that the existing suites rely on

- **Waiting for a re-render.** The Traffic Analyzer replaces its whole dashboard on every filter change. Mark
  an element before the action and wait for the unmarked replacement (`TrafficAnalyzer.rerender`). For React
  pages, wait for the text or element the action produces.
- **Charts.** Read the model with `Chart.getChart(canvas)` inside `page.evaluate` (labels, data points, axis
  limits, tick labels, tooltip), and check separately that the canvas has painted pixels.
- **Order with ties.** "Top N" lists are compared by their sequence of counts, and each listed entry must
  exist with that count; entries with equal counts may come in any order (`expectTopN` in `nginx/checks.ts`).
- **Percentages and sizes.** Compare a displayed, rounded value with the exact value and accept only the
  rounding the display implies (half a unit of the last shown digit). Do not re-implement the page's rounding call.
- **Time.** Pin "now" with `page.clock` when a tool shows relative or countdown values, and compute expected
  local times with an explicit `timeZone`, never with the Node process's zone.
- **Large input.** `locator.fill` with megabytes of text stalls the browser. Paste through the clipboard
  (`analysePastedWithShortcut`) or upload a file.
- **Downloads.** `captureDownload` returns the file's text. To open a downloaded HTML report, save it with an
  `.html` name first (`nginx/08-report.spec.ts`); the browser's own copy has no extension.
- **A second visitor.** Open shared links in `browser.newContext()` with the same `baseURL`, time zone and
  locale as the project, and collect its console errors yourself; the `guard` fixture only watches the first page.
- **Hydration.** `openTool` waits until React has attached its handlers. A click before that is lost and
  looks like a broken control.
- **One read, one comparison.** Read everything the page shows into a plain object in a single
  `page.evaluate`, build the expected object from the oracle, and report every difference in one soft
  failure (`readView` / `diffView` in `chmod/page.ts`, `snapshot()` / `checkDashboard` in `nginx/`). This is
  what makes typing all 4096 chmod modes or checking every explorer row affordable.
- **Time zones and clock changes.** `cron/oracle.ts` has `wallClock`, `offsetAt`, `instantOf` and
  `clockChanges` for computing local wall-clock times and finding the daylight-saving transitions of a zone.
- **Races.** For every tool that sends a request: press Enter twice while the first request runs (one request
  must be sent), and deliver the answer to an earlier lookup after the answer to a later one (the later one
  must stay on screen). `scriptApi` with `deferred()` does both without sleeping.
- **Not changed.** Before asserting that something did *not* happen, give the page the chance to do it:
  `settle(page)` waits a few animation frames and one timer turn.
- **Icon buttons.** Icon fonts put a glyph at the start of a button's accessible name. Match names with a
  pattern anchored at the end (`/Copy$/`), not with an exact string.
- **Output that is random by design** (passwords). Do not predict values. Assert that every value is possible
  for the configuration, that every possible symbol appears over many samples, and that frequencies stay
  inside a statistical limit chosen so a correct generator fails less than once in a million runs.
- **Rows the tests leave behind.** Share tests create rows in the `*_shares` tables and there is no public
  delete. Run against a test database, not production.

## 10. Step by step: adding a suite for a new tool

1. **Read the tool.** The page under `frontend/src/app/<route>/`, the libraries it imports, any classic
   scripts under `frontend/public/js/`, and its backend route under `backend/src/routes/`. Open it in a
   browser and use every control once.
2. **Write the inventory** as a comment block at the top of the main spec: inputs, controls, every displayed
   value, every output (copy, export, share), every state (empty, loading, result, error). This list is the
   coverage contract; each entry must map to a test.
3. **Write the definitions** for each displayed value in `oracle.ts`, in words first, then code (section 5).
4. **Write the generator** (`generator.ts`) returning input plus ground truth (section 6).
5. **Write `page.ts`**: locators and user actions (`pasteLogs`, `selectCountry`, `readKpis`, `readTable`).
   Readers return plain data so specs compare data with data.
6. **Write the specs layer by layer** (section 4). Start with layers 1, 2 and 4 for the default state; add
   controls, combinations, outputs, failures and state.
7. **Run it** against a local stack until every failure is understood. For each failure decide: application
   defect (keep the test, add a line to `FINDINGS.md`) or wrong expectation (fix the oracle).
8. **Run it five times with different seeds** (`for i in 1 2 3 4 5; do npm run test:tools -- tests/e2e/tools/<tool>; done`).
   A test that passes with some seeds and fails with others has found either an edge-case defect or an
   assumption in the oracle; both must be resolved, not retried.
9. **Add the tool to the table below**, and its route and category to `CATALOGUE` in `workspace/oracle.ts`
   (the home page, sidebar and search tests derive what they expect from that table). Then go through the
   checklist in section 12.

### Suites in this folder

| Tool | Route | Folder | Oracle |
| --- | --- | --- | --- |
| Traffic Analyzer | `/nginx` | `nginx/` | Generated access log with ground truth; own parser, classifier and aggregation; GeoIP read from the site's `.mmdb` files with the `maxmind` package |
| IP Info & Security Risk Lookup | `/abuse` | `abuse/` | Input grammar (RFC 3986 / RFC 4291); generated API payloads; own `.mmdb` reader |
| ASN to IPs Converter | `/asn` | `asn/` | BigInt prefix ranges, containment and aggregation; firewall rule syntax per vendor; generated API payloads |
| Chmod Calculator | `/chmod` | `chmod/` | POSIX mode arithmetic (`chmod(1)`, `ls(1)`) |
| Crontab Builder | `/cron` | `cron/` | Own cron evaluator after `crontab(5)`, evaluated in the browser's time zone |
| DNS Lookup | `/dns` | `dns/` | Generated API payloads; Node's resolver and DNS-over-HTTPS for live tests; own `.mmdb` reader |
| What Is My IP | `/myip` | `myip/` | Generated `/api/myip` payloads and the browser context the test configured |
| Password Generator | `/password-generator` | `password-generator/` | Keyspace counted with BigInt; the set of possible outputs; statistical limits for uniformity |
| SSL Certificate Checker | `/ssl` | `ssl/` | Generated certificate chains; Node's `tls` module for live tests |
| Subnet / CIDR Calculator | `/subnet` | `subnet/` | BigInt network arithmetic |
| WHOIS Lookup | `/whois` | `whois/` | Generated snapshots; WHATWG URL parser for the lookup target; registry data for live tests |
| Workspace shell (home, sidebar, search, theme, SEO) | `/` | `workspace/` | Site configuration (`/api/site/config` or a generated one) and the `CATALOGUE` table |

## 11. Worked example: the Traffic Analyzer

The Traffic Analyzer (`/nginx`) is the reference for how deep a suite goes. Its plan, in the order a person
would check the tool by hand:

1. The tool opens on `/nginx`; the four input sources, both exclusion checkboxes, the sample buttons and the
   Analyze button are visible and usable; no layout problem at any width.
2. Choose "Paste logs", paste a **freshly generated** access log, and analyse it.
3. When the dashboard appears, compare the header cards with the generated log: total requests, unique IPs,
   ASNs, countries, human share, verified and spoofed bots; then parsed and skipped line counts, the time
   span, the error percentage, the method ribbon and the data transferred.
4. Timeline chart: it is drawn; its first and last point and its axis labels match the first and last log
   time; each bucket's count equals the number of generated requests in that bucket; the chart-interval
   buttons regroup the same requests into 1 s, 5 s, 1 min and 15 min buckets; the time-range buttons, the
   stepper and both drag handles select the window they claim and everything below follows.
5. Country chart and ASN chart: labels, values and percentages match the log.
6. Filters: every method, every country, every path, every ASN, every traffic class, IP search (text and
   CIDR), path search; then random combinations of them, with and without a time range. After each one,
   every card, table, chart and the matching counter are recomputed and compared. Clearing restores the full
   data set.
7. Tables: most active IPs, targeted paths, ASNs and networks, bot intelligence, top referrers. Rows, order,
   hits and shares match the log; clicking a row applies that filter and the data follows; clicking again
   removes it.
8. Log explorer: every row of every page shows the right time, address, method, path, status, country,
   protocol and user agent; the entry count is right; page size and all pagination buttons work; its own
   search boxes filter.
9. Exclusion toggles (403 responses, internal requests): the skipped counts are right and the dashboard is
   recomputed when they change.
10. Report download: the HTML report and the CSV export contain the same numbers as the dashboard, field by field.
11. Share: a snapshot without a password and one with a password each open for another visitor and show the
    same numbers; a wrong password is refused.
12. New Analysis returns to a clean input screen and a second, different log shows only its own data.

The plan maps to the spec files in `nginx/` like this:

| Spec | Plan steps | Also covers |
| --- | --- | --- |
| `01-access-and-layout` | 1 | layout audit of the dashboard and its dialogs at three widths |
| `02-overview` | 2, 3, 5 | |
| `03-timeline` | 4 | tooltip of a bucket |
| `04-filters` | 6 | |
| `05-tables` | 7 | IP access-log dialog, AbuseIPDB scan (mocked third party) |
| `06-explorer` | 8 | |
| `07-exclusions` | 9 | |
| `08-report` | 10 | |
| `09-share` | 11 | expiry choices, a second share, the sharer's exclusion options |
| `10-inputs` | 12 | file upload (plain and gzip), drag and drop, sample data sets, "Add More Logs" |
| `11-edge-cases` | | inputs chosen to break assumptions: look-alike user agents, IPv6 notations, overlapping paths, hostile content, 15,000 lines |

Use the same depth for every tool: list what a careful operator would verify by hand, automate each item
against an oracle, then add an edge-case file with inputs chosen to break the tool's assumptions.

## 12. Checklist before you call a suite done

- [ ] The inventory at the top of the spec lists every control, displayed value, output and state, and each has a test.
- [ ] All eight layers are covered or marked not applicable with a reason.
- [ ] Every expectation comes from an oracle that does not import application code.
- [ ] Inputs are generated from `rng`; generated input is saved with `evidence.save`.
- [ ] Displayed values are compared with `expect.soft` and a message naming the value and the input.
- [ ] No `waitForTimeout`, no `Math.random()`, no dependence on test order.
- [ ] The suite was run five times with different seeds; every failure is either an application defect
      (listed in the hand-over) or was an oracle error that is now fixed.
- [ ] Layout audit passes (or its findings are reported) at desktop, laptop and mobile widths in every state.
- [ ] The suite is listed in the table in section 10.
