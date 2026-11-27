# Findings of the first full run

State of `main` at a53c7b8 on 2026-11-27: 820 tests, 648 pass, 170 fail, 2 skipped. The failing set was the
same in every run. Each line below is one or more failing tests; none is a test that fails by accident.

`test-results/tools-report/failures.md` of a fresh run has the evidence for each (input, expected, shown).
Remove a line here when the defect is fixed and its tests are green.

Items marked **(decision)** are behaviour the tests judge against a definition written in the suite's
`oracle.ts`. If the current behaviour is intended, change the definition and the test, not the application.

| Tool | Tests | Failing |
| --- | --- | --- |
| Traffic Analyzer (`nginx/`) | 134 | 43 |
| DNS Lookup (`dns/`) | 101 | 17 |
| Workspace shell (`workspace/`) | 91 | 6 |
| ASN to IPs (`asn/`) | 90 | 22 |
| Password Generator (`password-generator/`) | 77 | 12 |
| IP Info & Risk Lookup (`abuse/`) | 62 | 21 |
| What Is My IP (`myip/`) | 60 | 8 |
| WHOIS Lookup (`whois/`) | 50 | 8 |
| Crontab Builder (`cron/`) | 48 | 13 |
| SSL Checker (`ssl/`) | 41 | 10 |
| Chmod Calculator (`chmod/`) | 33 | 3 |
| Subnet Calculator (`subnet/`) | 33 | 7 |

## Found in several tools

- **A late answer replaces a newer result.** Start lookup A, then lookup B; when A's answer arrives after B's,
  the page shows A under B's input. `dns/page.tsx:58-137`, `asn/page.tsx:41-63`, `whois/page.tsx:27-37`,
  `ssl/page.tsx:21-29`.
- **Enter during a running lookup sends it again** (3 to 6 requests for one lookup). `dns/page.tsx:305`,
  `asn/page.tsx:126`, `whois/page.tsx:106`, `ssl/page.tsx:66`.
- **Share title longer than the column returns HTTP 500** (`ER_DATA_TOO_LONG`). `backend/src/routes/share.js:148,159`.
- **Dialog close buttons and Title inputs have no accessible name** (share dialogs of dns, asn, whois, myip;
  both Traffic Analyzer dialogs; the AbuseIPDB link in `/abuse`).
- **CSV export writes the text `null`** for missing values. `frontend/src/lib/csv-utils.ts:27`.
- **CSV export does not neutralise formula cells** (`=`, `+`, `-`, `@`). Tested in `nginx/`; the same writer
  serves the other tools.

## Traffic Analyzer (`/nginx`)

Input
- A single uploaded or dropped file (streaming engine) gives a different dashboard from the same text pasted:
  skipped counts 0, human share 0%, ASN count off by one, time span in another format. Filters are ignored,
  and changing an exclusion option empties the dashboard.
- All five `/samples/*.log` answer 404, so the sample buttons and the home page link "Explore a sample" do nothing.
- "Add More Logs" by paste does not update the time span or the skipped counts.
- The hours stepper keeps its value after "New Analysis".

Timeline
- The bucket tooltip can never appear: `#slider-active-window` lies on top of the chart and takes the mouse.
- **(decision)** A time range longer than the log (30m/1h/2h on a short log, or 99 typed hours) shows the
  "Clear Active Filters" pill although nothing is filtered.

Tables
- "Targeted Paths" lists path segments, not request paths; clicking a row shows a different count from the row.
- The "Most Active IPs" badge stops at 50.
- "Scan Top 20 IPs" sends 10 addresses.
- A failed AbuseIPDB lookup is shown as "0% Clean"; "Scanned" is shown when the service is unavailable or
  answers 500.
- The IP log dialog shows 100 rows without saying that there are more.
- An open dialog does not cover the sidebar, which stays clickable.

Log explorer
- All four search boxes lose focus and text after the first typed character (the dashboard is rebuilt under
  the cursor).
- URLs are cut at 40 characters and user agents are cut, with no way to read the full value.

Report and share
- The HTML report prints large numbers without thousands separators (a second, broken `n()` at the end of
  `report.js` overrides the first).
- A report downloaded while a filter is active does not say so.
- Expiry "1 Hour" is stored as never expiring (`computeExpiry` in `backend/src/routes/share.js` has no `1h`).
- A second share from the same dashboard is impossible without a reload (the button stays "Creating...").
- The shared view ignores the sharer's exclusion options and always hides 403 and internal requests.

Classification and matching
- Internet Explorer 11 ("Trident") and CUBOT phones are counted as bots.
- `TelegramBot (like TwitterBot)` is listed as Twitter/X.
- A network name with "tor" inside another word counts as a Tor indicator.
- One IPv6 address written in different notations counts as several clients.
- Clicking an IP row filters by text: 1.2.3.4 also matches 11.2.3.40 and 1.2.3.45.
- An IPv4 CIDR search matches IPv6 clients.
- The path dropdown shows a count that differs from what selecting the entry shows when paths overlap.
- **(decision)** The "Unknown" country of the chart cannot be chosen in the country filter.

## DNS Lookup (`/dns`)

- MX priority 0 is shown blank, on the page and in the HTML report. `DnsSnapshotView.tsx:300`, `lib/dns.ts:436`.
- A null MX (`example.com`) is an empty row. `backend/src/routes/dns.js:288`.
- A CNAME target is listed among the A records. `dns.js:100-107`.
- A TXT record made of several strings is joined with a space, which corrupts a DKIM key. `dns.js:305`.
- An internationalised name (`münchen.de`) is reported as "does not exist". `dns.ts:105`, `dns.js:83`.
- A pasted URL with a port, query, fragment or credentials is queried as typed. `dns.ts:105-111`.
- **(decision)** A PTR lookup for `8.8.8.8` says "does not exist".
- Deep link with `resolver=global` or `9.9.9.9`: the select shows Cloudflare while the card says otherwise.
  `page.tsx:148-155`.
- Global mode: exports and shares take domain and type from the form as it is now, not from the lookup
  (`page.tsx:207,210`); "Checked At" is the time of the share click (`:211`); TTLs never measured are shown as
  "0s" (`:216`); after sharing, Standard mode shows the global snapshot as its result (`:237,286`).

## ASN to IPs (`/asn`)

- IPv6 containment is a text comparison: an address inside a prefix gets "NO MATCH". `lib/asn.ts:306`,
  `backend/src/lib/asn-utils.js:194`.
- Text that is not an address (`10..0.1`, `1e1.0.0.1`, `2001:db8::zz`) gets "MATCH FOUND" or "NO MATCH",
  never "invalid". `asn.ts:111`, `asn-utils.js:7`.
- IPv6 rows have no range end, and "Usable IPs" shows the number of /64s. `asn.ts:172`.
- nftables, IPset and Cisco ACL output silently drops IPv6 prefixes that the header counts. `asn.ts:365,411,391`.
- Mikrotik output puts IPv6 under `/ip firewall address-list`. `asn.ts:403`.
- Apache output is not usable: deny is a `<RequireAll>` with only `Require not ip`; allow puts several
  `Require ip` in `<RequireAll>`. `asn.ts:345`.
- API: an unknown action (`reject`) returns ACCEPT rules; a "prefix" such as `10.0.0.0/8; rm -rf …` is written
  into the generated command. `asn-utils.js:249`, `routes/asn.js:357`.
- The mask chip "/32 (2)" lists 4 rows because IPv6 /32 are included. `AsnSnapshotView.tsx:81`.
- CSV of an empty filter result exports every prefix. `AsnSnapshotView.tsx:174`.
- Live data: country and registry show "13312-15359" and "IANA 16-bit … Registry" (`routes/asn.js:229-230`);
  the IPv4 total sums overlapping prefixes (AS15169: 4.26M shown, 2.64M unique; `asn-utils.js:219`); the IPv6
  list is sorted as text (`asn.js:313`); the fragments "AS" and "x" resolve to Google and Twitter
  (`asn.js:136-137`); a number above 4294967295 is sent upstream (`asn.js:71`).

## Password Generator (`/password-generator`)

- A deleted history entry stays in localStorage, returns after a reload, and reappears when another row is
  deleted. `page.tsx:246`.
- Separator `+` reverts to `-` after a reload. `settings.ts:22` against `generator.ts:53`.
- The note says a four-word passphrase is "above the 80-bit target"; it is 52 bits. `page.tsx:479`.
- Advice talks about another mode (PIN advice in Random mode, word advice in PIN mode). `entropy.ts:206-224`.
- With "at least one of each type", the entropy shown is higher than the number of possible values allows
  (4 characters: 26 bits shown, 22 real). `page.tsx:148-151`, `entropy.ts:275-277`.
- Saved settings with every character type off are accepted and produce a lowercase value. `settings.ts:49-58`.
- At 390 px the Delete button of a history row is cut off. `signal.css:364-367`.
- **(decision)** Advice calls a value solid while the label says Weak (52–59 bits).
- **(decision)** "Avoid shell-hostile symbols" still generates `$` and `&`. `generator.ts:47`.
- **(decision)** Switching "Save to history" off is not remembered. `page.tsx:133`.
- **(decision)** Any age of 24–48 hours is called "Yesterday". `page.tsx:69`.

## IP Info & Risk Lookup (`/abuse`)

All in `frontend/src/app/abuse/page.tsx` unless given.
- Zero-compressed IPv6 (`2001:4860:4860::8888`) is refused; `999.999.999.999` is looked up. `:78`
- A request count of `-5` is sent as typed. `:77`
- Level "unknown" is drawn as "Low". `:195-197`
- When only the IP-info service fails, or an address is missing from its answer, or the batch is above the
  backend limit of 100, rows show "No PTR record" and "Low" instead of an error. `:99-101, :126, :143`
- A failed AbuseIPDB request (500/429) is presented as "API key is optional". `:103-107, :250`
- Without a key, details still say Reports 0 / Never / Not TOR. `:384-386`
- "Reverse DNS" shows the AbuseIPDB `domain`, including `N/A` and `ERROR`, and counts it as a PTR. `:128`
- A `--` country code hides the GeoIP country; flag and name can come from different sources. `:130-131`
- The guide promises risk reasons in the details; they are never shown. `:378-390`
- A new lookup keeps the previous filter, and old results stay under a new error. `:80-88`
- Up to 50 addresses are accepted but `max` is not sent, so the backend checks 20. `:96`, `backend/src/routes/abuse.js:19`
- Reserved IPv6 ranges (`2001:db8::/32`, `ff00::/8`, `febf::`, full-form `::1`) are treated as public.
  `backend/src/routes/ipinfo.js:72-75`
- **(decision)** An address listed twice is counted twice in "IPs analysed".

## What Is My IP (`/myip`)

- An answer with `ip: null` crashes the page ("This page couldn't load"). `myip/page.tsx:542`
- Latitude or longitude 0 is shown as "—". `:491`
- Chrome and Firefox on iOS are shown as Safari; Samsung Internet and Edge on Android as Google Chrome. `:28-32`
- The HTML report inserts values unescaped; markup in a value runs as script. `lib/myip.ts:157-158`

## WHOIS Lookup (`/whois`)

- `https://x.com?utm=1` is sent as `x.com?utm=1`, `user:pw@x.com` as `user`. `lib/whois.ts:13-14`
- A domain that is not registered shows creation 01 Jan 1985, status ACTIVE and gTLD nameservers (the TLD's
  IANA record). `routes/whois.js:103,139`. Depends on the `whois` binary; seen on macOS, not checked on Linux.
- A name under `.invalid` shows "Registered". `whois.js:218`
- `8.8.8.8` shows "Registered"; an IPv6 address is looked up as `2001`. `whois.js:80`, `whois.ts:14`

## SSL Checker (`/ssl`)

- `host:8443` is checked on 443. `ssl/page.tsx:27`, `routes/ssl.js:22`
- A port of `abc`, `0`, `443abc`, `443.5`, `4e2` or `0x1bb` returns a certificate. `ssl/page.tsx:27`, `ssl.js:23`
- `wrong.host.badssl.com` is reported as "Hostname matches", trusted, A+. `ssl.js:240`
- `untrusted-root.badssl.com` is reported as trusted, A+; `socket.authorized` is read and not used. `ssl.js:59,76`
- An expired or wrong-host certificate with a full chain says "Missing intermediate certificates". `page.tsx:109`
- The last certificate of a chain is called Root by position, also when it is cross-signed. `page.tsx:176`
- Missing validity dates are shown as "Invalid Date". `page.tsx:36`
- 30 of wikipedia.org's 41 names are listed. `ssl.js:143`

## Crontab Builder (`/cron`)

All in `frontend/src/app/cron/page.tsx`.
- Invalid expressions are shown as Valid: `5-1`, `5x`, `1.5`, `0x10`, `5#2`, `-5`, `5-`, `a-b`, `/5`, `*/5/2`,
  `70/5`. `:26-34, :43`
- `0-20000000 * * * *` crashes the page ("Set maximum size exceeded"). `:30,33`
- `0 0 13 * 5` lists only Friday the 13th; cron runs it every Friday and every 13th. `:70-72`
- The search for next runs stops after 365 days, so the Yearly preset shows one run and 29 February none. `:69`
- "Next 10 Executions" stands over an empty table for `0 0 31 2 *` and `MON-FRI`. `:142`
- When clocks go back, the repeated hour of runs is missing. `:68,73`
- `0 9-17 * * 1-5` is described as "At NaN:00 PM on 1-5". `:57-58`
- `0 24 * * *` shows "At 12:00 PM" under the Invalid banner. `:49-63`
- After a manual edit the preset list keeps showing the old preset, so it cannot be chosen again. `:109`

## Chmod Calculator (`/chmod`)

All in `frontend/src/app/chmod/page.tsx`.
- Typing 0, 7, 5, 5, 1 gives mode 7551 with every special bit set. `:77`
- `888` shows no error while the cards and Copy still offer `chmod 755`. `:71,93`
- A mode pasted with a space (`"644 "`) is silently ignored. `:71`

## Subnet Calculator (`/subnet`)

- These are accepted as networks: `10..0.1/24`, `10.0.0.0/24/8`, `1e1.0.0.0/8`, `0x10.0.0.0/8`,
  `10.0.0.0/8abc`, `10.0.0.0/2.5`, and a netmask with a hole (`255.0.255.0`).

## Workspace shell

- The navigation loading bar never stops after Ctrl/Cmd-click on a sidebar link (`Navbar.tsx:46-57`) or after
  choosing the already open tool in the palette (`Navbar.tsx:151`).
- There is no `not-found.tsx`: the 404 page offers no way back.
- The home page meta description ignores the configured one. `layout.tsx:22-25`
- **(decision)** The palette keeps the previous query when reopened. `Navbar.tsx:29`
- **(decision)** The system light-mode preference is ignored. `ThemeProvider.tsx:17-28`, `layout.tsx:67`

## Not checked, and why

- **Object storage (R2).** The test stack has none. Traffic Analyzer share tests replace only the storage
  upload and download (`nginx/storage.ts`); one test that needs real storage is skipped. Run with
  `E2E_STORAGE=real` on a stack that has it.
- **AbuseIPDB with a key.** The backend has no key, so that path runs against generated answers only.
- **Global DNS probes** (`/api/dns/global`): not available locally; global mode runs on generated answers.
- **Expired share links** (HTTP 410): the shortest expiry is an hour or a day and tests cannot age a row; the
  page's handling of 410 is tested with a replayed answer.
- **Published content pages** (`/page/<slug>`): the site has none; that test is skipped.
- **Sample data sets**: the files are missing, so analysing a sample could not be checked beyond the 404.
