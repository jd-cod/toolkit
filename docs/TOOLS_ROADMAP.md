# Tools roadmap: the 2026-11 tools pack

Read this before adding, changing or reviewing a tool. It records what was
added, why, how new tools are wired, what was verified, and what is
deliberately left for later. Keep the status table current when work lands.

Branch: `feature/new-tools` (from `main` at `a53c7b8`). Built 2026-11-27.

## Why these tools

The toolkit targets sysadmins who work on Linux servers daily and on Windows
sometimes. A market review on 2026-11-27 found:

- **People pay for monitoring and alerts, not for one-off lookups.** MXToolbox
  sells blacklist and DMARC monitoring ($129 and $399 per month), UptimeRobot
  sells uptime, SSL and domain monitoring ($13 to $98 per month),
  Healthchecks.io and Cronitor sell cron heartbeat monitoring ($20 per month,
  $2 per monitor), TrackSSL and Oh Dear sell certificate and domain expiry
  monitoring (from about $15 per month).
- **Lookups are free everywhere** but they are what admins open every day, and
  they are the entry point to the paid monitors. The biggest gap in this
  project was email (the reason MXToolbox is a daily tab).
- Generic converters (base64, JWT, hash, UUID, regex) were skipped on purpose:
  IT-Tools (41k GitHub stars) gives them away and they do not differentiate.

## Product decisions (from the owner, 2026-11-27)

1. **No sign-up, no paywall for now.** Every tool is open to every visitor.
2. Build and test the tools first. Usage limits, paid access, customer login
   and subscriptions come later as a separate phase (see "Later").
3. Until customer accounts exist, monitors belong to the admin and are managed
   in `/admin`.

## Status

| Tool | Key and route | Runs | Status |
|---|---|---|---|
| SPF, DKIM & DMARC Checker | `email-auth` | server (DNS) | done |
| Blacklist (DNSBL) Check | `blacklist` | server (DNS) | done |
| Email Header Analyzer | `email-headers` | browser | done |
| SMTP Server Test | `smtp-test` | server (TCP) | done |
| HTTP Headers & Redirect Checker | `http-headers` | server (HTTP) | done |
| Open Port Checker | `port-check` | server (TCP) | done |
| Certificate & CSR Decoder | `cert-decoder` | browser | done |
| SSH Config Auditor | `sshd-audit` | browser | done |
| systemd Timer Generator | `systemd-timer` | browser | done |
| Firewall Rule Generator | `firewall-rules` | browser | done |
| rsync Command Builder | `rsync` | browser | done |
| SSH Auth Log Analyzer | `auth-log` | browser | done |
| Mail Log Analyzer (Postfix) | `mail-log` | browser | done |
| Windows Event ID Lookup | `windows-events` | browser | done |
| Windows Error Code Lookup | `windows-errors` | browser | done |
| Robocopy Command Builder | `robocopy` | browser | done |
| IPv6 in the Subnet Calculator | `subnet` (existing) | browser | done |
| IIS logs in the Traffic Analyzer | `nginx` (existing) | browser | done |
| Monitoring (admin-owned) | `/admin`, Monitors | server | done |

Every route is `/<tool_key>`. The site now has 27 tools.

## How a tool is wired

A tool has one key. Adding a tool means touching each of these, and
`tests/unit/tool-registry.test.js` fails when one is missed:

| What | Where |
|---|---|
| Registry row (label, description, icon, colour, tags, order) | a migration in `backend/migrations/` **and** `DEFAULT_TOOLS` in `backend/src/routes/public.js` |
| Route, category, sidebar icon | `frontend/src/lib/tool-catalog.ts` |
| SEO title and description | `TOOL_SEO_DEFAULTS` in `frontend/src/lib/seo.ts` |
| Side guide text (three short tips) | `GUIDES` in `frontend/src/components/ToolWorkspace.tsx` |
| Page | `frontend/src/app/<key>/page.tsx` and a two-line `layout.tsx` using `createToolLayout` |
| Logic | `frontend/src/lib/tools/<key>.ts` (browser tools) or `backend/src/lib/` plus a route in `backend/src/routes/` (server tools) |
| Tests | `tests/unit/<key>.test.js` or `backend/test/<name>.test.js`, plus the route in `tests/e2e/tool-pages.spec.ts` |

Conventions for the tools in this pack:

- **Pages** use `components/ToolPage.tsx` for the frame and the pieces in
  `components/ToolUi.tsx` (styles: `app/tool-kit.css`, `tk-` classes) instead
  of inline styles. `app/rsync/` is the reference for a browser tool,
  `app/port-check/` for a server-backed one (`hooks/useToolRequest.ts` holds
  the loading, error and deep-link logic).
- **Logic stays out of the page.** Browser tools keep parsing and command
  building in `frontend/src/lib/tools/*.ts` as plain TypeScript with no React
  or DOM use, so `node --test tests/unit/` imports them directly. Local
  imports inside those files need the `.ts` extension (Node strips types but
  does not resolve extensions; `allowImportingTsExtensions` is on). No enums
  and no `1n` BigInt literals (the frontend compiles to ES2017).
- **Generated commands are quoted** with `lib/tools/shell.ts` (`shQuote`,
  `cmdQuote`, `psQuote`). Never interpolate user input into a command raw.
  Invalid input is reported as an error and kept out of the output.
- **Destructive options** (delete, mirror, purge) are marked as dangerous and
  produce a warning next to the command.
- **Privacy claims must hold.** A tool described as client-side must not send
  its input anywhere. Private keys, configs and logs stay in the browser
  (`tests/e2e/tools-pack.spec.ts` asserts this for the certificate decoder).
- `sort_order` must stay unique across tools (`tests/e2e/tool-order.spec.ts`).
- Migrations here are numbered from 012: the unmerged `security-hardening`
  and `share-functionality` branches each already add a file numbered 011.
- Server routes answer errors as `{ error: "message" }`. Routes registered as
  plugins do not inherit the error handler in `server.js`, so each new route
  file catches its own errors (see `routes/net-tools.js`).

## Notes on individual tools

- **Blacklist check** (`backend/src/lib/dnsbl.js`). Before a list is trusted
  it must pass the self-test RFC 5782 requires: 127.0.0.2 listed, 127.0.0.1
  not listed. A list that fails (offline, answers everything, or refuses this
  server's resolver) is shown as "not checked", never as "clean". Spamhaus
  refuses queries from public resolvers, so on most hosts it is "not checked"
  until `TOOLS_DNS_SERVERS` points at a private resolver. Spamhaus PBL entries
  are shown as policy listings, not spam listings.
- **SPF** (`backend/src/lib/email-auth.js`). The lookup count walks every
  include and redirect, as receivers do; more than 10 is a permanent error.
  DKIM selectors cannot be listed from DNS, so about 40 common names are tried
  plus any the visitor enters.
- **SMTP test** (`backend/src/lib/smtp-probe.js`). Sends only EHLO, STARTTLS
  and QUIT. The EHLO greeting is hidden in the transcript because it echoes
  the address this server connects from.
- **Certificate decoder** (`frontend/src/lib/tools/der.ts`,
  `cert-decoder.ts`). A hand-written DER reader instead of an X.509 library:
  it runs in the browser, handles private keys, and stays small enough to
  audit. The tests compare it with Node's X.509 parser on certificates made by
  openssl. PFX files and encrypted keys are not opened; the page gives the
  openssl commands instead.
- **IIS logs** (`frontend/public/js/log-parser.js`). The parser reads the
  column layout from `#Fields:` and switches layout when another header goes
  by. Without a header it assumes the default IIS 8+ or IIS 7 layout.
- **Windows reference data** (`frontend/src/lib/tools/windows-errors-data.ts`,
  `windows-events.ts`). Checked on 2026-11-27 against Wine's `winerror.h` and
  `ntstatus.h` and the ReactOS bug check list: every code those sources define
  matched (182 of 195 Win32, 94 of 94 NTSTATUS, 75 of 123 HRESULT, 33 of 51
  stop codes; the rest are WinSock, WMI, Windows Update, .NET and newer stop
  codes those headers do not carry). Event IDs have no machine-readable
  source here and were reviewed by hand. The pages say they cover common
  entries, not all.
- **Auth log counting rule.** A failed attempt is a `Failed <method> for`
  line. `Invalid user` and `pam_unix` lines describe the same attempt and are
  not counted again. Addresses that also logged in successfully are never put
  in the block list.

## Server-side tools and abuse

Several new tools make this server connect to a host the visitor chooses.
That is the same risk class as the SSRF finding on `/storage/upload-external`.
Rules for every such tool:

- Destinations are checked with `backend/src/lib/net-guard.js`: loopback,
  private, link-local, CGNAT, documentation and metadata ranges are refused,
  and the check happens inside the DNS lookup the socket uses, so a name
  cannot resolve to a different address after the check.
  `ALLOW_PRIVATE_TARGETS=true` turns the guard off for self-hosters who
  inspect internal hosts.
- `net-guard.js` is copied unchanged from the `security-hardening` branch so
  the two branches merge cleanly. Do not edit it here; put new helpers in
  another file.
- Each route has its own rate limit, tighter than the global 100 per minute:
  email auth 20, blacklist 10, SMTP 6, HTTP check 15, port check 6 per minute.
- The port checker takes at most 25 ports per request, resolves the host once
  and probes only that address. The SMTP test never sends mail and makes no
  open-relay test.

Known limits, to fix before charging for anything:

- On `main` the rate-limit key trusts the client's `X-Forwarded-For`, so the
  limits above can be sidestepped until `security-hardening` is merged.
- Disabling a tool in `/admin` hides its card but does not switch off its API.

## Monitoring

Monitors re-run a check on a schedule and alert when its state changes. They
live in `/admin` under "Monitors".

| Type | Watches | Down when |
|---|---|---|
| `ssl_expiry` | a host's TLS certificate | expired, wrong host name, or unreachable (warns N days before expiry) |
| `domain_expiry` | a domain registration (RDAP/WHOIS) | expired or unregistered (warns N days before expiry) |
| `blacklist` | an IP or host on the DNS blacklists | listed on any list that answers |
| `dns_record` | one record (A, AAAA, MX, TXT, NS, CNAME) | differs from the expected value, or from the first value seen |
| `http` | a URL | error, unexpected status, or missing keyword |
| `tcp` | a host and port | port does not accept connections |
| `heartbeat` | a cron job that calls `/api/ping/<token>` | no ping within the interval plus grace period |

How it works:

- Code: `backend/src/lib/monitoring/` (`types.js` validation, `checks.js`,
  `state.js` transitions, `scheduler.js`, `alerts.js`), routes in
  `backend/src/routes/monitors.js`, tables in migration 013, UI in
  `frontend/src/components/admin/MonitorsSection.tsx`.
- The scheduler runs inside the backend process every 30 seconds. A monitor is
  claimed with an UPDATE before it runs, so two backend processes on one
  database do not run the same check twice. `MONITORING_ENABLED=false` stops
  it.
- The network checks (HTTP, TCP, SSL, DNS) need two failures in a row, one
  minute apart, before a monitor goes down. Recovery and warnings apply at
  once. Each state change is stored in `monitor_events` and sent once to every
  enabled alert channel; there are no repeat reminders.
- Alert channels: generic webhook (JSON), Slack-style webhook (`{ "text" }`,
  also Mattermost and Rocket.Chat), and email through `ALERT_SMTP_*`.
- Monitor and webhook targets are **not** run through the SSRF guard, because
  the admin enters them and watching internal hosts is a normal use. This must
  change when monitors become customer-owned.
- Not included in the admin backup and restore.

## Verified on 2026-11-27

- `cd backend && node --test test/`: 88 pass (24 before this work).
- `node --test tests/unit/`: 236 of 237 pass. The one failure,
  `myip.test.js`, fails on `main` too (an extensionless import).
- Frontend `tsc --noEmit` clean; `eslint` reports nothing in new files (19
  problems remain in files that predate this work); `next build` succeeds.
- Playwright against the production build (all specs except the two that
  need log fixtures missing from the repo): 161 of 167 pass. The six failures
  are the ones recorded on `main` the day before: `cache-headers` needs sample
  logs that are not in the repo, one mobile `timeline-accuracy` drag, and the
  four `tool-order` cases, which hardcode ports 3001/4001 (with the ports
  changed they pass 4 of 4).
- Server tools were exercised against real hosts (github.com, gmail.com MX,
  8.8.8.8), and monitoring end to end: a dead URL, a changed DNS record and a
  missed heartbeat each raised one alert on a local webhook.
- Not verified: the PowerShell and netsh output of the firewall generator and
  the robocopy command on a real Windows machine; email alert delivery through
  a real SMTP server; Spamhaus results (this machine's resolver is refused).

## Later (not in this pack)

- Customer accounts, login, subscriptions, and per-plan usage limits.
- Moving monitors from admin-owned to customer-owned (add the SSRF guard to
  monitor targets at the same time), status pages, repeat reminders.
- Merge `security-hardening` first: it fixes the rate-limit key these tools
  rely on.
- DMARC aggregate report inbox (needs inbound mail).
- A full vulnerability scanner (large, abuse and legal risk).
- Exim and Sendmail in the mail log analyzer; in-browser PFX conversion.

## Local development for this checkout

- MySQL: container `toolkit-lab-mysql` on `127.0.0.1:3316` (separate from the
  `toolkit-mysql` container other checkouts use).
- Backend on port 4100 (`backend/.env`), frontend on 3100
  (`BACKEND_API_URL=http://localhost:4100/api`, which must also be set for
  `next build` because rewrites are fixed at build time).
- Tests: `cd backend && node --test test/`, `node --test tests/unit/`,
  `E2E_BASE_URL=http://localhost:3100 npx playwright test tests/e2e/tools-pack.spec.ts tests/e2e/tool-pages.spec.ts`.
- `node scripts/dev/page-shot.mjs <url> <out.png>` saves a screenshot and
  prints console errors; `scripts/dev/page-flow.mjs` does the same after a
  list of fill and click steps.
