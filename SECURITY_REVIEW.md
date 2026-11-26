# Security review and fixes (2026-11-26)

Full review of the backend, frontend, dependencies and deployment config, and
the fixes made for each finding. Every fix has tests; see "Verification" at
the end.

The changes are on the local branch `security-hardening`.

## Deploying these changes

1. Run the database migration: `cd backend && npm run migrate` (the Docker
   image does this on start). It adds `admin_users.token_version`. Nobody is
   signed out by it, and the code keeps working until it has run.
2. Set these in `backend/.env` for production (see `backend/sample_production.env`):
   - `APP_URL=https://your-domain` — pins the URL in the ingest script and
     restricts CORS to your site.
   - `TRUSTED_PROXIES` — only if you are **not** behind Cloudflare
     (`none`), or have another proxy with a public IP in front.
3. Rebuild the frontend (`npm ci && npm run build`, or rebuild the image):
   Next.js and other packages changed.
4. Check that your reverse proxy forwards the visitor's address in
   `X-Forwarded-For` (Cloudflare does; nginx needs
   `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`). Without it
   the backend cannot tell visitors apart: the general rate limit is then
   skipped, as it was before, and the login and share-password limits are
   shared by all visitors.
5. Keep starting the frontend with `node server.js` (the Docker image and
   `ecosystem.config.cjs` do). The invite-only gate and the client address
   forwarding live there; `next start` and `next dev` do not run them.

## Behaviour changes to know about

- **Logout signs the admin out everywhere**, not just in the current browser.
- **New admin passwords need 12 characters** (was 6). Existing passwords keep working.
- **MySQL is published on `127.0.0.1` only** in both compose files. Set
  `MYSQL_BIND=0.0.0.0` if another machine must reach it.
- **The SSL checker and "analyze a remote URL" refuse private, loopback and
  link-local addresses.** Set `ALLOW_PRIVATE_TARGETS=true` on a private
  network where checking internal hosts is wanted.
- **Invite-only mode is now enforced.** If `invite_only_enabled` is `1` in
  your database, visitors who are not whitelisted will see the gate page after
  this deploy.
- **Rate limits now apply per real client** when requests come through the
  frontend server (they were skipped before). The general limit is still 100
  requests per minute and only counts visitors with a public address, so local
  use, LAN clients and the test suite are not throttled. Login is limited to
  10 attempts per 5 minutes and share-password checks to 20 per minute for
  everyone.
- Shares edited in the admin panel only accept `http(s)` source URLs; anything
  else is rejected with a message.
- A nginx share can only be created for the upload it came from. The existing
  share dialog already works this way.

## Findings

### Critical

| # | Finding | Fix |
|---|---------|-----|
| 1 | Next.js 16.2.2 had 5 critical remote-code-execution advisories (two in features this app uses: `next/og` and the image optimizer). | Upgraded to 16.4.6. `npm audit` reports 0 vulnerabilities. |
| 2 | `GET /ingest?session=...` put the value unescaped into the bash script users pipe into `bash`; the `Host` header reached the same script. | Session IDs and the base URL are restricted to safe characters, checked again inside the generator (`backend/src/lib/ingest-script.js`, `routes/ingest.js`). |
| 3 | `POST /api/storage/upload-external` fetched any URL without login, including internal services and cloud metadata, and made the response downloadable. | New `backend/src/lib/net-guard.js`: http/https only, public addresses only (checked at connect time, so DNS tricks do not work), every redirect re-checked, size capped while streaming. |
| 4 | Share passwords and expiry could be bypassed through `GET /api/storage/download/:code`, and `POST /api/share` accepted any storage key. | The download endpoint refuses codes that belong to a protected or expired share. A share can only point at `shares/<its own code>.log.gz`. |

### High

| # | Finding | Fix |
|---|---------|-----|
| 5 | Rate limiting trusted the client's `X-Forwarded-For` header, and requests through the frontend were exempt. | `backend/src/lib/client-ip.js` reads the header from the right and only believes trusted proxies. `frontend/server.js` appends the connecting address. Tighter limits on login, share password checks, uploads, share creation and AbuseIPDB lookups. Requests with no public client address skip the general limit (they would all share one bucket) but not the login and share-password limits. |
| 6 | `POST /api/ssl` connected to any host and port, so it could scan internal networks. | Uses the same guard as #3, validates the hostname and port. |
| 7 | Backend dependencies: Fastify 5.8.4 (authentication and validation bypass advisories), mysql2 3.20.0 (credential leak), fast-uri, @fastify/busboy. | Updated within the existing version ranges (Fastify 5.12.8, mysql2 3.24.6). `npm audit` reports 0 vulnerabilities. |
| 8 | Unauthenticated large uploads and unbounded work. | Per-client limits on upload endpoints (#5), presigned uploads over 250 MB are rejected at finalize, decompression is capped at 2 GB, `/api/abuse` checks at most 50 IPs per request. The 400/500 MB body limits themselves are unchanged because the log analyzer needs them. |

### Medium

| # | Finding | Fix |
|---|---------|-----|
| 9 | Share passwords used unsalted SHA-256, and shares created in the admin panel (bcrypt) could never be opened. | New shares use bcrypt. Verification accepts both formats, so existing shares keep working. |
| 10 | CORS allowed every origin with credentials in production. | Uses `CORS_ORIGIN` (now a comma-separated list) or the origin of `APP_URL`. With neither set it still allows all origins and logs a warning, so nothing breaks silently. |
| 11 | No security headers; CDN files loaded without integrity checks. | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` and a minimal `Content-Security-Policy` on all pages; `X-Powered-By` removed; SRI hashes on Chart.js and Bootstrap Icons. |
| 12 | Invite-only mode did nothing. | Enforced by `frontend/access-gate.js` and `GET /api/site/access-check`, following the rules shown in the admin panel. |
| 13 | Admin sessions: tokens could not be revoked, 6-character minimum password, no algorithm pin, default password in the README. | Session version (migration 011) checked on every request; logout and password change revoke; minimum 12 characters; HS256 pinned; login no longer reveals whether a username exists; README corrected. |
| 14 | Deployment: MySQL published on all interfaces, fallback root password in the healthcheck, PM2 unpinned. | MySQL bound to localhost, fallback removed, PM2 pinned to 7.1.2. |
| 15 | Wrong input types caused 500 errors with internal messages. | String inputs are type-checked on all public routes; unexpected errors return a generic message in production. |
| 16 | Tiptap 3.22.2 (paste-handling XSS in the admin editor). | Updated to 3.35.0. |

### Low

| # | Finding | Fix |
|---|---------|-----|
| 17 | JSON-LD blocks could be broken out of with `</script>` in a tool label or setting. | `serializeJsonLd()` in `frontend/src/lib/seo.ts` escapes `<`. |
| 18 | Share `source_url` and ingest `chunkId` were not validated. | Only http(s) URLs are stored, in the public and the admin share routes; chunk IDs must match the ones the server issues. |

## Not changed, and why

- **Admin-authored page HTML is rendered as written.** Admins can already add
  scripts through the `analytics_script` setting, so sanitizing page content
  would remove formatting without adding protection.
- **Password generator history in localStorage.** It is a documented feature
  and never leaves the browser.
- **HSTS.** It applies to the whole hostname, including other services on
  other ports, so it belongs on the TLS-terminating proxy.
- **Dev dependencies in the production image and the Node 22 base image.**
  Changing either risks the image build; Node 22 is supported until April 2027.
- **The backend port (4000) is still published.** Direct connections are now
  rate-limited correctly, and other tooling in this repo uses the port.

## Noticed, not security

- Request bodies over 10 MB sent through the frontend's `/api` rewrite are cut
  off by Next.js (`experimental.proxyClientMaxBodySize`), so large uploads only
  work when `/api` reaches the backend directly. This was already the case
  before these changes.
- `tests/unit/myip.test.js` cannot load under plain `node --test` (extensionless import).

## Verification

Run on 2026-11-26 against MySQL 8.4 in Docker, the backend on port 4000 and a
production build of the frontend (`npm run build`, `node server.js`).

| Check | Result |
|-------|--------|
| `npm audit` in `backend/`, `frontend/` and the repo root | 0 vulnerabilities in each |
| `cd backend && node --test test/` | 67 pass, 0 fail (24 before; 43 new tests cover the fixes) |
| `node --test tests/unit/` | 37 pass, 1 fail: `myip.test.js` cannot load, same as before the changes |
| `cd frontend && npm run build` (Next.js 16.4.6) | succeeds |
| `cd frontend && npm run lint` | 26 problems, the same 26 as before the changes |
| Playwright suite, 148 tests, against this branch and against a build of `main` | 134 pass on this branch; the 7 failures also fail on `main` (see below) |

The 7 Playwright failures that `main` shares: four `tool-order` tests are
hardcoded to ports 3001/4001, `cache-headers` expects sample logs under
`/samples/` that are not in the repository, the mobile touch-drag test in
`timeline-accuracy` does not move the handle, and one `password-generator`
test reads the password before the mode switch has rendered. Two more spec files
(`bot-intel-gold-set`, `nginx-golden-analysis`) need `tests/fixtures/*.log`
files that are not in the repository and were left out of both runs.

Checked by hand against the running servers:

- Every tool page, `robots.txt`, the sitemap and the Open Graph image load;
  no console errors or blocked resources on any page with the new headers and
  integrity hashes.
- DNS, WHOIS, ASN, IP info, AbuseIPDB, My IP and SSL lookups return results.
  The SSL checker refuses `localhost` and `127.0.0.1`.
- Admin: login, every admin section, password change (other sessions end,
  the current one continues), logout (a copied token stops working), and the
  login limit (blocked after 10 attempts).
- Invite-only mode on: visitors get the gate page, the whitelist and a
  signed-in admin get through, `/login`, `/admin`, `/api` and static files
  stay reachable. Off: everything loads.
- A password-protected DNS share can be created and opened.
- The ingest script no longer contains injected input.
- Rate limits: 150 requests in a row from this machine through the frontend
  all succeed; a public client address is limited after 100.

Not verified end to end: uploads, downloads and nginx shares that use
Cloudflare R2. R2 is not configured on the test machine, so those routes were
tested with a stubbed storage layer only.
