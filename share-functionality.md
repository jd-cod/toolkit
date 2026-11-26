# Branch `share-functionality`

Written 2026-11-26. Based on `main` at `a53c7b8` (the initial commit).

This branch gives every tool the same Share, Download HTML and Download CSV
actions, with a password and an expiry on every share link, and makes a failed
database migration visible instead of silent.

## Before this branch

- **Each tool had its own share code.** DNS, WHOIS, My IP and ASN each had
  their own share modal, their own API route and their own table
  (`dns_shares`, `whois_shares`, `myip_shares`, `asn_shares`). The Traffic
  Analyzer had a third implementation in `frontend/public/js/share.js`.
- **Five tools could not share at all:** SSL, IP Info, Subnet, Cron and chmod.
- **Download buttons differed per tool** in which ones existed, where they sat
  and how the HTML report looked.
- **Share passwords could be bypassed.** `GET /api/storage/download/:code`
  returned a Traffic Analyzer log without checking the share's password or
  expiry.
- **Share passwords were stored as unsalted SHA-256.**
- **Expired snapshot shares were never deleted**, and the cleanup job only ran
  when R2 storage was configured.
- **A failed migration was swallowed.** `backend/src/migrate.js` logged the
  failure, ran the remaining files, printed "All migrations completed" and
  exited 0.

## After this branch

### One actions bar and one share dialog

- `frontend/src/components/share/ResultActions.tsx` renders the bar. A tool
  passes it the share payload and its HTML and CSV builders.
- `frontend/src/components/share/ShareDialog.tsx` is the only share dialog. It
  asks for a title, an optional password and an expiry (1 hour, 24 hours,
  7 days, 30 days, or never, which is the default), then shows the link.
- `frontend/src/lib/report-html.ts` (`buildReportHtml`) produces every HTML
  report, `frontend/src/lib/csv-utils.ts` (`toCSV`) every CSV, and
  `frontend/src/lib/download.ts` saves the file.
- `/s/[code]` renders any shared result through the registry in
  `frontend/src/components/share/SharedSnapshot.tsx`. A shared page shows the
  downloads but no Share button.

| Tool | Share | Download HTML | Download CSV | Notes |
| --- | --- | --- | --- | --- |
| DNS, WHOIS, My IP, ASN | yes | yes | yes | moved from their own modals |
| SSL, IP Info | yes | yes | yes | sharing is new |
| Subnet, Cron, chmod | yes | yes | yes | sharing is new; the link stores the inputs and the result is recomputed |
| Traffic Analyzer | yes | yes | yes | bar is placed in the dashboard toolbar by `NginxResultActions.tsx`; the log is uploaded to R2 |
| Password Generator (bulk) | no | yes | yes | generated passwords never leave the browser |

### Backend

- `POST /api/share/snapshot` stores a JSON result for any tool in the new
  `tool_shares` table. `POST /api/share` stores a Traffic Analyzer share that
  points at an R2 object. `GET /api/share/:code` and
  `POST /api/share/:code/verify` serve both kinds.
- Passwords are hashed with bcrypt (72 byte limit). Hashes made before this
  branch still verify. Password checks are limited to 10 per minute.
- `GET /api/storage/download/:code` now enforces the password and the expiry.
- The cleanup job deletes expired snapshot shares and runs without R2.
- The admin Shares section lists and deletes shares from every tool.
- Shared helpers are in `backend/src/lib/share-utils.js`.

### Database

`backend/migrations/011_tool_shares.sql` creates `tool_shares` and **moves**
every row from `dns_shares`, `whois_shares`, `myip_shares` and `asn_shares`
into it, so existing `/s/<code>` links keep working. The four old tables are
left in place, empty. Traffic Analyzer shares stay in `shares`.

### Migration runner and health check

- `npm run migrate` stops at the first file that fails, names it and the files
  it did not attempt, and exits 1. The failed file is retried on the next run.
- The database is selected before each file, so a file without its own `USE`
  line (`002`, `005_r2_storage`, `007`) no longer fails with "No database
  selected" when the files before it are skipped as already applied.
- `GET /api/health` has a `migrations` field: `applied`, `pending` or
  `unknown` (no ledger table). With pending migrations it answers HTTP 200
  with `"status":"degraded"` and `"pending_migrations": <count>`, and the
  server logs the file names at startup.
- The Docker start command still uses `|| true`, so the API comes up after a
  failed migration and the container stays "healthy". That was the existing
  intent; change the degraded answer to 503 if a monitor should flag it.
- The logic is in `backend/src/lib/migrations.js` and
  `backend/src/routes/health.js`.

## Commits

| Commit | Change |
| --- | --- |
| `675bacc` | Shared dialog, actions bar, snapshot share API, migration 011, download password fix, bcrypt, cleanup, admin |
| `161ca8a` | DNS, WHOIS, My IP and ASN use the shared bar; old modals removed |
| `0a2b82e` | `/s/[code]` renders through one snapshot registry |
| `923bfe9` | Share and Download HTML for SSL, IP Info, Subnet, Cron, chmod; downloads for Password Generator |
| `d755035` | Traffic Analyzer uses the shared bar and dialog; `public/js/share.js` deleted |
| `50f05a3` | End-to-end spec `tests/e2e/result-actions.spec.ts` and updated specs |
| `1b6ac06` | Migration runner stops on failure; health reports pending migrations |

## Running the tests

```bash
npm run test:backend     # 45 tests, no database needed
npm run test:unit        # 52 tests
cd frontend && npx tsc --noEmit && npm run build
npx playwright test tests/e2e/result-actions.spec.ts   # needs the app running
```

## What was checked

- Backend tests 45/45 and unit tests 52/52 pass. The type check is clean and
  the production build succeeds.
- `result-actions.spec.ts` (14 tests) and the updated specs passed in Chromium
  against a local frontend, backend and MySQL 8.4, on the dev server and the
  production build.
- Migration 011 and the share API were run against a real MySQL 8.4: old rows
  moved, an old SHA-256 password still verified, expiry was stored, the verify
  rate limit applied.
- The migration runner was run against a real MySQL 8.4: fresh server, a
  pending file without `USE`, a deliberately broken file (exit 1, next file not
  run, health `degraded`), then recovery to `ok` without a restart.

## What was not checked

- **Real R2 storage.** The Traffic Analyzer upload was mocked.
- **Browsers other than Chromium**, and phones.
- `nginx-golden-analysis` and `bot-intel-gold-set` (fixture logs are not in
  the repository), `tool-order` and `cache-headers` (need the stack on `:4001`
  with sample logs).
- `cross-filter-rows` and one `internal-exclusions` test failed locally because
  fake MaxMind databases were used. Some WHOIS tests (live lookups) and one
  Password Generator passphrase test are intermittently flaky.

## Behaviour changes to know before deploying

- Migration 011 moves share rows out of the four old tables. Code older than
  this branch will not find them, so rolling back the code needs the rows
  copied back.
- Shared Traffic Analyzer links now show the download buttons.
- CSV files now quote headers and write an empty cell for a missing value.
- A log ingested from the terminal keeps the Share button, with a note that it
  is not retained.

## Not in this branch

These were found in the review at the start of the session and are untouched
here:

- SSRF in `POST /api/storage/upload-external`
- Rate-limit key taken from `X-Forwarded-For`, which a client can spoof
- Invite-only mode not enforced
- Uploads held in memory

The remote branch `security-hardening` (commit `ada6070`) was pushed separately
on the same day and changes some of the same files. A trial merge of the two
branches conflicts in `backend/src/routes/admin.js`,
`backend/src/routes/share.js`, `backend/src/routes/storage.js` and
`frontend/src/lib/nginx-engine.ts`. Whichever branch merges second needs those
resolved by hand.
