import { test, expect, type Page } from '../_support/fixtures';
import { openTool, expectToolLinkedFromHome } from '../_support/navigation';
import { expectControlsUsable, VIEWPORTS, expectNoUiGlitchesAtRest } from '../_support/ui-audit';
import { captureDownload, readClipboard, clearClipboard, mockApi, failApi, type ApiCall } from '../_support/io';
import { parseCsv } from '../_support/csv';
import { deferred, scriptApi, settle, type ScriptedReply } from '../_support/gate';
import { MARKUP, randomDomain, randomNow, randomSnapshot, richSnapshot, unregisteredSnapshot } from './generator';
import { asciiHost, completeSnapshot, csvRecord, expectedSummary, lookupTarget, sameMonthSpelling, type Snapshot } from './oracle';
import {
  API, HEADING, ROUTE, actionButton, cardValue, domainInput, emptyState, errorAlert, lookup, lookupButton, readView, statCards, submit,
} from './page';
import { expectNoMarkupExecuted, expectPageShows, expectRawShows, expectReportShows } from './checks';

/**
 * WHOIS Lookup (/whois) — contract tests. The browser's call to POST /api/whois
 * is answered by the test with a generated snapshot, so the snapshot is the
 * ground truth for everything on screen. Share links (real backend) are in
 * whois-share.spec.ts, lookups against the real registries in whois-live.spec.ts.
 *
 * INVENTORY (each entry is covered by a test here or in the two other specs)
 *
 * Inputs
 *  - Domain box (placeholder "e.g. openai.com"): bare domain, URL, upper case, port, path, IDN, surrounding spaces
 *  - Lookup button, Enter key in the box, deep link /whois?domain=...
 * Controls on a result
 *  - Share Snapshot (dialog: Title, Link Expiry, Password, Generate Share Link, Copy, Create Another Link, close, backdrop)
 *  - Copy Summary, Download HTML, JSON, CSV
 *  - Show/Hide Raw RDAP|WHOIS, Open DNS Lookup, Open SSL Checker
 *  - Shared view only: Re-run Lookup, Open Live Lookup, password box + Unlock
 * Displayed values
 *  - Cards: Domain, Registration, Registrar, Days Until Expiry (+ colour), DNSSEC (+ colour)
 *  - Source and Checked At line
 *  - Domain Status labels, or the "no status" note
 *  - Registrar & Dates: Source, Registrar, Registrar IANA ID, Abuse Email, Abuse Phone, Creation/Updated/Expiry Date, Privacy
 *  - Nameserver Comparison: registry nameservers, live DNS nameservers, Exact Match, Only In <source>, Only In DNS
 *  - Contacts: Registrant, Admin, Tech (only those with data)
 *  - Risk Signals list, or the "none" note
 *  - Raw record
 *  - Shared view: title, Created / Expires dates, banner with title and code
 * Outputs
 *  - Request body of POST /api/whois and POST /api/share/whois
 *  - Clipboard (summary, share link), HTML report, JSON file, CSV file, share link
 * States
 *  - empty, loading, result (registered, unregistered, sparse), error (HTTP 400/404/429/5xx, network), share dialog
 *    (form, creating, created, failed), shared view (locked, wrong password, unlocked, not found, expired)
 *
 * Layers: 1-8 all apply. Not applicable: recent lookups / history (the tool keeps none), settings in
 * localStorage (none), drag and drop or file input (none).
 */

const nowIso = (now: Date) => now.toISOString();

/** Opens the tool with the browser clock pinned to `now`. */
async function openPinned(page: Page, now: Date, route = ROUTE) {
  await page.clock.setFixedTime(now);
  await openTool(page, route, HEADING);
}

/** Answers every lookup with whatever `holder.answer` currently is. */
async function answerWith(page: Page, holder: { answer: unknown }): Promise<ApiCall[]> {
  return mockApi(page, API, () => holder.answer, { method: 'POST' });
}

test.describe('WHOIS — access and layout', () => {
  test('is linked from the home page and the sidebar', async ({ page }) => {
    await expectToolLinkedFromHome(page, ROUTE);
    await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
  });

  test('opens with its controls ready, an empty result area and no request sent', async ({ page }) => {
    const calls = await mockApi(page, API, {}, { method: 'POST' });
    await openTool(page, ROUTE, HEADING);
    await expect(page).toHaveTitle(/WHOIS/i);
    await expectControlsUsable(page, {
      'domain box': 'input[placeholder="e.g. openai.com"]',
      'Lookup button': '.input-card button',
    });
    await expect(domainInput(page), 'the domain box starts empty').toHaveValue('');
    await expect(lookupButton(page)).toHaveText('Lookup');
    await expect(emptyState(page).getByRole('heading', { name: 'Explore a domain’s registration' }), 'empty state before the first lookup').toBeVisible();
    await expect(statCards(page), 'no result before a lookup').toHaveCount(0);
    await expect(errorAlert(page), 'no error before a lookup').toHaveCount(0);
    await expect(page.getByText('Input accepts a bare domain or URL.'), 'input hint').toBeVisible();
    await expect(page.getByRole('complementary', { name: 'Domain registration' }), 'guide panel').toBeVisible();
    expect(calls.length, 'opening the page must not call the API').toBe(0);
  });

  for (const [name, viewport] of Object.entries(VIEWPORTS)) {
    test(`has no layout problems at ${name} size (${viewport.width}px) in every state`, async ({ page, rng, guard, evidence }) => {
      await page.setViewportSize(viewport);
      const now = randomNow(rng);
      const rich = richSnapshot(rng, now);
      const long = randomSnapshot(rng, now, { long: true, hostile: true, contacts: ['hostile', 'full', 'partial'], statuses: 6 });
      const none = unregisteredSnapshot(rng, now);
      await evidence.save('whois-layout-snapshots.json', { rich, long, none });

      const hold = deferred();
      guard.allow(/status of 500|HTTP 500/);
      await scriptApi(page, API, async (_call, index): Promise<ScriptedReply> => {
        if (index === 0) await hold.promise;
        if (index === 3) return { status: 500, body: { error: 'WHOIS lookup failed.', raw_response: '', raw_whois: '' } };
        return { body: [rich, long, none][index] };
      });

      await openPinned(page, now);
      await expectNoUiGlitchesAtRest(page, `${ROUTE} empty state @${name}`);

      await submit(page, rich.domain);
      await expect(lookupButton(page)).toHaveText('Looking up...');
      await expectNoUiGlitchesAtRest(page, `${ROUTE} while loading @${name}`);
      hold.resolve();
      await expect(cardValue(page, 'Domain')).toHaveText(rich.domain);
      await expectNoUiGlitchesAtRest(page, `${ROUTE} result with contacts @${name}`);
      await actionButton(page, /Show Raw/).click();
      await expectNoUiGlitchesAtRest(page, `${ROUTE} result with the raw record open @${name}`);

      await lookup(page, long.domain);
      await expect(cardValue(page, 'Domain')).toHaveText(long.domain);
      await actionButton(page, /Show Raw/).click();
      await expectNoUiGlitchesAtRest(page, `${ROUTE} result with very long values and markup @${name}`);

      await lookup(page, none.domain);
      await expect(cardValue(page, 'Registration')).toHaveText('Unknown / Not Found');
      await expectNoUiGlitchesAtRest(page, `${ROUTE} unregistered domain @${name}`);

      await lookup(page, rich.domain);
      await expect(errorAlert(page)).toBeVisible();
      await expectNoUiGlitchesAtRest(page, `${ROUTE} error state @${name}`);
    });
  }
});

test.describe('WHOIS — input', () => {
  test('a bare domain or a URL is reduced to its host name, sent once, and shown back in the box', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const d = randomDomain(rng);
    const cases = [
      d,
      `   ${d}  `,
      d.toUpperCase(),
      `https://${d}`,
      `http://${d}/`,
      `HTTPS://WWW.${d.toUpperCase()}/Path/Page?q=1#top`,
      `https://${d}:8443/admin`,
      `${d}/some/path?x=1`,
      `${d}:8080`,
      `deep.sub.${d}`,
      'xn--mnchen-3ya.de',
      'MÜNCHEN.de',
      'https://bücher.example/katalog',
    ];
    await evidence.save('whois-typed-inputs.json', cases);
    const calls = await mockApi(page, API, (call: ApiCall) => richSnapshot(rng, now, { domain: asciiHost((call.body as { domain?: string })?.domain) || 'unparsable.example' }), { method: 'POST' });
    await openPinned(page, now);

    for (const [i, typed] of cases.entries()) {
      const want = lookupTarget(typed);
      await lookup(page, typed, i % 2 ? 'enter' : 'button');
      expect.soft(calls.length, `typing "${typed}": number of API requests so far`).toBe(i + 1);
      const call = calls.at(-1)!;
      expect.soft(call.method, `typing "${typed}": request method`).toBe('POST');
      expect.soft(Object.keys((call.body ?? {}) as object), `typing "${typed}": fields in the request body`).toEqual(['domain']);
      expect.soft(asciiHost((call.body as { domain?: string })?.domain), `typing "${typed}": domain sent to the API (expected host "${want}")`).toBe(want);
      expect.soft(asciiHost(await domainInput(page).inputValue()), `typing "${typed}": the box shows the name that was looked up`).toBe(want);
      await expect.soft(cardValue(page, 'Domain'), `typing "${typed}": Domain card shows the domain the server answered for`).toHaveText(want);
    }
  });

  test('a URL whose host is followed directly by a query, a fragment, or preceded by credentials is reduced to its host name', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const d = randomDomain(rng);
    const cases = [`https://${d}?utm_source=mail`, `http://${d}?a=1&b=2`, `https://${d}#contact`, `https://user:secret@${d}/account`];
    await evidence.save('whois-typed-inputs.json', cases);
    const calls = await mockApi(page, API, () => richSnapshot(rng, now, { domain: d }), { method: 'POST' });
    await openPinned(page, now);

    for (const typed of cases) {
      await lookup(page, typed);
      const sent = (calls.at(-1)?.body as { domain?: string })?.domain;
      expect.soft(sent, `typing the URL "${typed}": the page says it accepts a URL, so the domain sent to the API must be its host "${d}"`).toBe(d);
    }
  });

  test('an empty or blank box does nothing: no request, no error, no result', async ({ page }) => {
    const calls = await mockApi(page, API, {}, { method: 'POST' });
    await openTool(page, ROUTE, HEADING);
    for (const typed of ['', '    ', '\t']) {
      await submit(page, typed, 'button');
      await submit(page, typed, 'enter');
    }
    await settle(page);
    expect(calls.length, 'a blank box must not call the API').toBe(0);
    await expect(errorAlert(page)).toHaveCount(0);
    await expect(statCards(page)).toHaveCount(0);
    await expect(emptyState(page)).toBeVisible();
    await expect(lookupButton(page)).toBeEnabled();
  });

  test('a deep link /whois?domain=... fills the box and runs exactly one lookup', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const snapshot = richSnapshot(rng, now);
    const param = `HTTPS://${snapshot.domain.toUpperCase()}/landing?ref=mail`;
    await evidence.save('whois-deep-link.json', { param, snapshot });
    const calls = await mockApi(page, API, snapshot, { method: 'POST' });

    await openPinned(page, now, `${ROUTE}?domain=${encodeURIComponent(param)}`);
    await expect(cardValue(page, 'Domain')).toHaveText(snapshot.domain);
    await settle(page);
    expect.soft(calls.map(call => call.body), `deep link ?domain=${param}: requests sent`).toEqual([{ domain: snapshot.domain }]);
    await expect.soft(domainInput(page), `deep link ?domain=${param}: the box shows the looked-up domain`).toHaveValue(snapshot.domain);
    await expectPageShows(page, snapshot, `deep link for ${snapshot.domain}`);

    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(cardValue(page, 'Domain'), 'reloading a deep link runs the lookup again').toHaveText(snapshot.domain);
    expect.soft(calls.length, 'requests after one reload of the deep link').toBe(2);
  });

  test('the result names the domain the server resolved, not the text that was typed (IDN to punycode)', async ({ page, rng }) => {
    const now = randomNow(rng);
    const snapshot = richSnapshot(rng, now, { domain: 'xn--mnchen-3ya.de' });
    const calls = await mockApi(page, API, snapshot, { method: 'POST' });
    await openPinned(page, now);
    await lookup(page, 'München.DE');
    expect.soft((calls[0]?.body as { domain?: string })?.domain, 'typing "München.DE": domain sent, lower-cased').toBe('münchen.de');
    await expectPageShows(page, snapshot, 'typing "München.DE"');
  });
});

test.describe('WHOIS — every displayed value equals the snapshot', () => {
  test('random snapshots: cards, colours, source line, statuses, dates, nameservers, contacts, risk signals and the raw record', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const snapshots = Array.from({ length: 10 }, () => randomSnapshot(rng, now));
    await evidence.save('whois-snapshots.json', { now: nowIso(now), snapshots });
    const holder = { answer: snapshots[0] as unknown };
    const calls = await answerWith(page, holder);
    await openPinned(page, now);

    for (const [i, snapshot] of snapshots.entries()) {
      holder.answer = snapshot;
      const ctx = `snapshot #${i} (${snapshot.domain}, ${snapshot.data_source})`;
      await lookup(page, snapshot.domain);
      await expect(cardValue(page, 'Domain'), `${ctx}: result appears`).toHaveText(snapshot.domain);
      expect.soft(calls.at(-1)?.body, `${ctx}: request body`).toEqual({ domain: snapshot.domain });
      await expectPageShows(page, snapshot, ctx);
      await expectRawShows(page, snapshot, ctx);
      await expectNoMarkupExecuted(page, ctx);
    }
    expect.soft(calls.length, 'one request per lookup').toBe(snapshots.length);
  });

  test('days until expiry: value and colour at every boundary (expired, today, 30, 31, unknown)', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const dayValues = [-rng.int(2, 2000), -1, 0, 1, 14, 15, 29, 30, 31, 32, rng.int(33, 5000), null];
    const snapshots = dayValues.map(expiryDays => randomSnapshot(rng, now, { expiryDays, hostile: false, long: false }));
    await evidence.save('whois-expiry-snapshots.json', { now: nowIso(now), snapshots });
    const holder = { answer: snapshots[0] as unknown };
    await answerWith(page, holder);
    await openPinned(page, now);

    for (const [i, snapshot] of snapshots.entries()) {
      holder.answer = snapshot;
      const ctx = `expiry ${snapshot.expiry_date || '(none)'} checked ${snapshot.checked_at_utc} (${dayValues[i]} days)`;
      expect(snapshot.days_until_expiry, `${ctx}: generator produced the intended day count`).toBe(dayValues[i]);
      await lookup(page, snapshot.domain);
      await expect(cardValue(page, 'Domain')).toHaveText(snapshot.domain);
      await expectPageShows(page, snapshot, ctx);
    }
  });

  test('DNSSEC, data source and privacy wording for every variant', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const variants: Snapshot[] = [];
    for (const source of ['rdap', 'whois'] as const) {
      for (const dnssec of ['signed', 'unsigned', 'unknown'] as const) {
        const snapshot = randomSnapshot(rng, now, { source, dnssec, hostile: false });
        variants.push(snapshot);
      }
    }
    variants.push({ ...richSnapshot(rng, now), privacy_detected: true, privacy_provider: '' });
    variants.push({ ...richSnapshot(rng, now), privacy_detected: true, privacy_provider: 'Domains By Proxy' });
    variants.push({ ...richSnapshot(rng, now), privacy_detected: false, privacy_provider: 'Ignored When Not Detected' });
    variants.push({ ...richSnapshot(rng, now, { statuses: 0 }), data_source: 'rdap' });
    variants.push({ ...richSnapshot(rng, now, { statuses: 0 }), data_source: 'whois' });
    await evidence.save('whois-variants.json', variants);
    const holder = { answer: variants[0] as unknown };
    await answerWith(page, holder);
    await openPinned(page, now);

    for (const [i, snapshot] of variants.entries()) {
      holder.answer = snapshot;
      const ctx = `variant #${i} (source ${snapshot.data_source}, dnssec ${snapshot.dnssec}, privacy ${snapshot.privacy_detected}/"${snapshot.privacy_provider}", ${snapshot.status_labels.length} statuses)`;
      await lookup(page, snapshot.domain);
      await expect(cardValue(page, 'Domain')).toHaveText(snapshot.domain);
      await expectPageShows(page, snapshot, ctx);
      await expectRawShows(page, snapshot, ctx);
    }
  });

  test('nameserver comparison for matching, differing, one-sided and empty lists', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const snapshots = (['match', 'differ', 'registry-only', 'dns-only', 'none'] as const).map(nameservers => richSnapshot(rng, now, { nameservers }));
    // The comparison can be undetermined (null) when the DNS side could not be read.
    snapshots.push({ ...richSnapshot(rng, now, { nameservers: 'registry-only' }), nameserver_match: null });
    await evidence.save('whois-nameserver-snapshots.json', snapshots);
    const holder = { answer: snapshots[0] as unknown };
    await answerWith(page, holder);
    await openPinned(page, now);

    for (const snapshot of snapshots) {
      holder.answer = snapshot;
      const ctx = `nameservers registry=[${snapshot.nameservers.join(' ')}] dns=[${snapshot.dns_nameservers.join(' ')}] match=${snapshot.nameserver_match}`;
      await lookup(page, snapshot.domain);
      await expect(cardValue(page, 'Domain')).toHaveText(snapshot.domain);
      await expectPageShows(page, snapshot, ctx);
    }
  });

  test('contacts: no section without contacts, one card per role that has data, redacted and partial contacts as received', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const kinds = [
      ['empty', 'empty', 'empty'], ['full', 'full', 'full'], ['redacted', 'redacted', 'redacted'], ['empty', 'full', 'empty'],
      ['empty', 'empty', 'partial'], ['partial', 'empty', 'redacted'], ['hostile', 'partial', 'full'],
    ] as const;
    const snapshots = kinds.map(contacts => richSnapshot(rng, now, { contacts: [...contacts] }));
    await evidence.save('whois-contact-snapshots.json', snapshots);
    const holder = { answer: snapshots[0] as unknown };
    await answerWith(page, holder);
    await openPinned(page, now);

    for (const [i, snapshot] of snapshots.entries()) {
      holder.answer = snapshot;
      const ctx = `contacts ${kinds[i].join('/')} (${snapshot.domain})`;
      await lookup(page, snapshot.domain);
      await expect(cardValue(page, 'Domain')).toHaveText(snapshot.domain);
      const shown = await expectPageShows(page, snapshot, ctx);
      expect.soft(shown.sections.includes('Contacts'), `${ctx}: Contacts section present only when a contact has data`).toBe(kinds[i].some(kind => kind !== 'empty'));
      await expectNoMarkupExecuted(page, ctx);
    }
  });

  // The backend sends ISO 8601 timestamps or an empty string; anything else it could not parse is passed through.
  test('dates are shown in UTC to the minute: midnight, last minute of a year, leap day, sub-second, with offset, and non-dates as received', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const stamps = [
      '2031-01-01T00:00:00.000Z', '2030-12-31T23:59:59.999Z', '2028-02-29T12:30:00Z', '1995-08-14T04:00:00.000Z',
      '2026-09-05T00:00:00Z', '2026-03-08T06:59:59.000Z', '2027-11-07T05:30:00+05:30', '2026-05-04T00:00:00-11:00',
      '', 'not-a-date', 'unknown',
    ];
    const base = richSnapshot(rng, now);
    const snapshots = stamps.map((stamp, i) => ({
      ...base, domain: `date${i}.${base.domain}`,
      creation_date: stamp, updated_date: stamps[(i + 1) % stamps.length], expiry_date: stamps[(i + 2) % stamps.length],
      checked_at_utc: Number.isNaN(Date.parse(stamp)) ? base.checked_at_utc : stamp,
    }));
    await evidence.save('whois-date-snapshots.json', snapshots);
    const holder = { answer: snapshots[0] as unknown };
    await answerWith(page, holder);
    await openPinned(page, now);

    for (const snapshot of snapshots) {
      holder.answer = snapshot;
      const ctx = `dates created="${snapshot.creation_date}" updated="${snapshot.updated_date}" expiry="${snapshot.expiry_date}" checked="${snapshot.checked_at_utc}"`;
      await lookup(page, snapshot.domain);
      await expect(cardValue(page, 'Domain')).toHaveText(snapshot.domain);
      await expectPageShows(page, snapshot, ctx);
    }
  });

  test('an unregistered domain shows "Unknown / Not Found" and no invented registration data', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const snapshot = unregisteredSnapshot(rng, now);
    await evidence.save('whois-unregistered.json', snapshot);
    await mockApi(page, API, snapshot, { method: 'POST' });
    await openPinned(page, now);
    await lookup(page, snapshot.domain);
    const ctx = `unregistered ${snapshot.domain}`;
    await expect(cardValue(page, 'Registration'), `${ctx}: Registration card`).toHaveText('Unknown / Not Found');
    await expectPageShows(page, snapshot, ctx);
    await expectRawShows(page, snapshot, ctx);
  });

  test('an incomplete or mistyped answer falls back to neutral values and the browser clock, without crashing', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const full = richSnapshot(rng, now);
    const keys = Object.keys(full) as (keyof Snapshot)[];
    const dropSome = () => {
      const copy: Record<string, unknown> = { ...full };
      for (const key of rng.sample(keys.filter(k => k !== 'domain'), rng.int(3, 12))) delete copy[key];
      return copy;
    };
    const answers: { why: string; answer: unknown }[] = [
      { why: 'random fields missing (1)', answer: dropSome() },
      { why: 'random fields missing (2)', answer: dropSome() },
      { why: 'only the domain', answer: { domain: full.domain } },
      { why: 'empty object', answer: {} },
      { why: 'JSON null', answer: null },
      { why: 'wrong types', answer: { ...full, status_labels: 'Active', status_codes: null, days_until_expiry: '12', nameserver_match: 'yes', nameservers: [1, 'ns1.example.net', null], contacts: null, rdap_metadata: 'x', dnssec: 'insecure', data_source: 'RDAP', registrar: 42, risk_signals: { a: 1 }, checked_at_utc: 7 } },
      { why: 'contact with missing parts', answer: { ...full, contacts: { registrant: { name: 'Only A Name' }, admin: 'nobody', tech: { email: 5, phone: '+1.5550100' } } } },
      { why: 'raw record only in raw_whois', answer: { ...full, data_source: 'whois', raw_response: undefined, raw_whois: 'Domain Name: FALLBACK.EXAMPLE\nRegistrar: Raw Only' } },
      { why: 'no raw record at all', answer: { ...full, raw_response: '', raw_whois: '' } },
    ];
    await evidence.save('whois-incomplete-answers.json', { now: nowIso(now), answers });
    const holder = { answer: answers[0].answer };
    await answerWith(page, holder);
    await openPinned(page, now);

    for (const { why, answer } of answers) {
      holder.answer = answer;
      const want = completeSnapshot(answer, nowIso(now));
      const ctx = `answer with ${why}`;
      await lookup(page, full.domain);
      await expect(statCards(page), `${ctx}: the five summary cards are shown`).toHaveCount(5);
      await expectPageShows(page, want, ctx);
      await expectRawShows(page, want, ctx);
    }
  });

  test('values with markup, quotes, commas and very long text are shown as plain text', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const base = randomSnapshot(rng, now, { hostile: true, long: true, contacts: ['hostile', 'hostile', 'hostile'], statuses: 3 });
    const snapshot: Snapshot = {
      ...base,
      registrar: `${MARKUP} "Evil, Inc." <b>bold</b> & co`,
      registrar_iana_id: '<script>alert(1)</script>',
      abuse_email: `"abuse"@example.org, <a href="javascript:alert(1)">x</a>`,
      abuse_phone: `+1.555 ${MARKUP}`,
      privacy_detected: true,
      privacy_provider: `<i>Privacy</i>, "LLC"`,
      status_labels: ['Active', `<b>Bold Status</b>`, `Status, with "quotes"`],
      nameservers: [`ns1.example.net`, `<img src=x onerror=alert(1)>.example.net`],
      risk_signals: [`Risk with ${MARKUP}`, 'Second, "quoted" risk'],
    };
    await evidence.save('whois-hostile-snapshot.json', snapshot);
    const dialogs: string[] = [];
    page.on('dialog', dialog => { dialogs.push(dialog.message()); void dialog.dismiss(); });
    await mockApi(page, API, snapshot, { method: 'POST' });
    await openPinned(page, now);
    await lookup(page, snapshot.domain);
    await expect(cardValue(page, 'Domain')).toHaveText(snapshot.domain);
    await expectPageShows(page, snapshot, 'snapshot with markup in every text field');
    await expectRawShows(page, snapshot, 'snapshot with markup in every text field');
    await expectNoMarkupExecuted(page, 'snapshot with markup in every text field');
    expect.soft(dialogs, 'no dialog may be opened by snapshot values').toEqual([]);
  });
});

test.describe('WHOIS — controls on a result', () => {
  test('the raw record toggles open and closed and starts collapsed for every new result', async ({ page, rng }) => {
    const now = randomNow(rng);
    const first = richSnapshot(rng, now, { source: 'rdap' });
    const second = richSnapshot(rng, now, { source: 'whois' });
    const holder = { answer: first as unknown };
    await answerWith(page, holder);
    await openPinned(page, now);

    await lookup(page, first.domain);
    await expectRawShows(page, first, `first result ${first.domain}`);
    await actionButton(page, 'Show Raw RDAP').click();
    await expect(page.locator('main pre')).toBeVisible();

    holder.answer = second;
    await lookup(page, second.domain);
    await expect(cardValue(page, 'Domain')).toHaveText(second.domain);
    await expect(page.locator('main pre'), 'a new result starts with the raw record collapsed').toHaveCount(0);
    await expect(actionButton(page, 'Show Raw WHOIS')).toBeVisible();
    await expectRawShows(page, second, `second result ${second.domain}`);
  });

  test('"Open SSL Checker" and "Open DNS Lookup" carry the domain to the other tool', async ({ page, rng }) => {
    const now = randomNow(rng);
    const snapshot = richSnapshot(rng, now);
    await mockApi(page, API, snapshot, { method: 'POST' });
    const sslCalls = await mockApi(page, '**/api/ssl', { error: 'stubbed by the WHOIS suite', domain: snapshot.domain }, { method: 'POST' });
    await openPinned(page, now);
    await lookup(page, snapshot.domain);

    const view = await readView(page);
    expect.soft(view.links, 'cross-tool links [text, href]').toEqual([
      ['Open DNS Lookup', `/dns?domain=${encodeURIComponent(snapshot.domain)}&types=NS`],
      ['Open SSL Checker', `/ssl?domain=${encodeURIComponent(snapshot.domain)}`],
    ]);

    await page.getByRole('link', { name: 'Open SSL Checker' }).click();
    await expect(page).toHaveURL(new RegExp(`/ssl\\?domain=${snapshot.domain.replace(/\./g, '\\.')}$`));
    await expect(page.getByRole('heading', { level: 1, name: 'SSL Certificate Checker' })).toBeVisible();
    await expect(page.getByPlaceholder('example.com'), 'the SSL checker receives the domain').toHaveValue(snapshot.domain);
    await expect.poll(() => sslCalls.length, { message: 'the SSL checker starts a check for the domain' }).toBeGreaterThan(0);
    expect.soft((sslCalls[0].body as { domain?: string }).domain, 'domain the SSL checker was asked to check').toBe(snapshot.domain);

    await page.goBack();
    await expect(page.getByRole('heading', { level: 1, name: HEADING }), 'Back returns to the WHOIS tool').toBeVisible();
  });
});

test.describe('WHOIS — copy and export', () => {
  test('Copy Summary puts the displayed values on the clipboard and confirms', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const snapshots = [richSnapshot(rng, now), randomSnapshot(rng, now, { hostile: true }), unregisteredSnapshot(rng, now)];
    await evidence.save('whois-copy-snapshots.json', snapshots);
    const holder = { answer: snapshots[0] as unknown };
    await answerWith(page, holder);
    await openPinned(page, now);

    for (const snapshot of snapshots) {
      holder.answer = snapshot;
      await lookup(page, snapshot.domain);
      await expect(cardValue(page, 'Domain')).toHaveText(snapshot.domain);
      await clearClipboard(page);
      await actionButton(page, 'Copy Summary').click();
      await expect(actionButton(page, 'Copied!'), `${snapshot.domain}: the button confirms the copy`).toBeVisible();
      const copied = sameMonthSpelling(await readClipboard(page)).split('\n');
      const want = expectedSummary(snapshot).split('\n');
      expect.soft(copied.length, `${snapshot.domain}: number of lines in the copied summary`).toBe(want.length);
      for (const [i, line] of want.entries()) {
        expect.soft(copied[i], `${snapshot.domain}: copied summary line ${i + 1} ("${line.split(':')[0]}")`).toBe(line);
      }
      await expect(actionButton(page, 'Copy Summary'), `${snapshot.domain}: the label returns after two seconds`).toBeVisible({ timeout: 6_000 });
    }
  });

  test('Download HTML saves a report whose every field equals the snapshot, with markup escaped', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const snapshots = [richSnapshot(rng, now), randomSnapshot(rng, now, { hostile: true, contacts: ['hostile', 'empty', 'empty'] }), unregisteredSnapshot(rng, now)];
    await evidence.save('whois-report-snapshots.json', snapshots);
    const holder = { answer: snapshots[0] as unknown };
    await answerWith(page, holder);
    await openPinned(page, now);

    for (const snapshot of snapshots) {
      holder.answer = snapshot;
      await lookup(page, snapshot.domain);
      await expect(cardValue(page, 'Domain')).toHaveText(snapshot.domain);
      const file = await captureDownload(page, () => actionButton(page, 'Download HTML').click());
      await evidence.save(`whois-report-${snapshot.domain}.html`, file.text);
      expect.soft(file.filename, `${snapshot.domain}: HTML report file name`).toBe(`${snapshot.domain}-whois-snapshot.html`);
      await expect(actionButton(page, 'Downloaded!'), `${snapshot.domain}: the button confirms the download`).toBeVisible();
      await expectReportShows(page, file.text, snapshot, `HTML report for ${snapshot.domain}`);
      await expect(actionButton(page, 'Download HTML'), `${snapshot.domain}: the label returns after two seconds`).toBeVisible({ timeout: 6_000 });
    }
  });

  test('JSON downloads the snapshot unchanged (and completed with defaults when the answer was incomplete)', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const full = randomSnapshot(rng, now, { hostile: true });
    const answers: unknown[] = [full, { domain: full.domain, registrar: 'Only Two Fields' }];
    await evidence.save('whois-json-answers.json', answers);
    const holder = { answer: answers[0] };
    await answerWith(page, holder);
    await openPinned(page, now);

    for (const [i, answer] of answers.entries()) {
      holder.answer = answer;
      const want = completeSnapshot(answer, nowIso(now));
      await lookup(page, full.domain);
      const file = await captureDownload(page, () => actionButton(page, 'JSON').click());
      expect.soft(file.filename, `answer #${i}: JSON file name`).toBe(`${full.domain}-whois-snapshot.json`);
      const parsed = JSON.parse(file.text) as Record<string, unknown>;
      for (const key of Object.keys(want) as (keyof Snapshot)[]) {
        expect.soft(parsed[key], `answer #${i}: field "${key}" in the JSON export`).toEqual(want[key]);
      }
      expect.soft(Object.keys(parsed).sort(), `answer #${i}: fields present in the JSON export`).toEqual(Object.keys(want).sort());
    }
  });

  test('CSV downloads one row whose cells equal the snapshot, field by field', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const snapshots = [richSnapshot(rng, now, { source: 'rdap' }), randomSnapshot(rng, now, { hostile: true, source: 'whois' }), unregisteredSnapshot(rng, now)];
    await evidence.save('whois-csv-snapshots.json', snapshots);
    const holder = { answer: snapshots[0] as unknown };
    await answerWith(page, holder);
    await openPinned(page, now);

    for (const snapshot of snapshots) {
      holder.answer = snapshot;
      await lookup(page, snapshot.domain);
      await expect(cardValue(page, 'Domain')).toHaveText(snapshot.domain);
      const file = await captureDownload(page, () => actionButton(page, 'CSV').click());
      await evidence.save(`whois-export-${snapshot.domain}.csv`, file.text);
      expect.soft(file.filename, `${snapshot.domain}: CSV file name`).toBe(`${snapshot.domain}-whois-snapshot.csv`);
      const rows = parseCsv(file.text);
      expect(rows.length, `${snapshot.domain}: the CSV has one header row and one data row`).toBe(2);
      expect.soft(rows[1].length, `${snapshot.domain}: the data row has as many cells as the header`).toBe(rows[0].length);
      const record = Object.fromEntries(rows[0].map((name, i) => [name, rows[1][i]]));
      const want = csvRecord(snapshot);
      expect.soft(Object.keys(record).sort(), `${snapshot.domain}: CSV columns`).toEqual(Object.keys(want).sort());
      for (const [column, value] of Object.entries(want)) {
        expect.soft(record[column], `${snapshot.domain}: CSV column "${column}"`).toBe(value);
      }
    }
  });
});

test.describe('WHOIS — failures', () => {
  const FAILURES: { status: number; body: unknown; contentType?: string; shows: RegExp; why: string }[] = [
    { status: 400, body: { error: 'Invalid domain name.', raw_response: '', raw_whois: '' }, shows: /^Invalid domain name\.$/, why: 'invalid name' },
    { status: 404, body: { error: 'No RDAP bootstrap entry found for example.zz.', raw_response: '', raw_whois: '' }, shows: /^No RDAP bootstrap entry found for example\.zz\.$/, why: 'not found' },
    { status: 429, body: { error: 'Rate limit exceeded, retry in 1 minute', statusCode: 429 }, shows: /^Rate limit exceeded, retry in 1 minute$/, why: 'rate limited' },
    { status: 500, body: { error: 'WHOIS lookup failed.', raw_response: '', raw_whois: '' }, shows: /^WHOIS lookup failed\.$/, why: 'server error' },
    { status: 502, body: { error: 'WHOIS server returned no data.', raw_response: '', raw_whois: '' }, shows: /^WHOIS server returned no data\.$/, why: 'upstream gave nothing' },
    { status: 504, body: { error: 'WHOIS lookup timed out.', raw_response: '', raw_whois: '' }, shows: /^WHOIS lookup timed out\.$/, why: 'timeout' },
    { status: 502, body: '<html><body><h1>502 Bad Gateway</h1></body></html>', contentType: 'text/html', shows: /502/, why: 'proxy error page instead of JSON' },
    { status: 500, body: {}, shows: /500/, why: 'error without a message' },
    { status: 500, body: { error: `Lookup of ${MARKUP} failed` }, shows: /^Lookup of <img src=x onerror="window\.__e2eXss=1"> failed$/, why: 'message containing markup' },
  ];

  test('every error answer shows its message, no result, no spinner, and the next lookup works', async ({ page, rng, guard }) => {
    const now = randomNow(rng);
    const good = richSnapshot(rng, now);
    guard.allow(/status of (400|404|429|500|502|504)|HTTP 50\d/);
    const api = await scriptApi(page, API, (_call, index): ScriptedReply => {
      // Even requests fail with the next error in the table; odd requests succeed.
      const failure = index % 2 === 0 ? FAILURES[index / 2] : undefined;
      return failure ? { status: failure.status, body: failure.body, contentType: failure.contentType } : { body: good };
    });
    await openPinned(page, now);

    for (const failure of FAILURES) {
      const ctx = `HTTP ${failure.status} (${failure.why})`;
      await lookup(page, good.domain);
      await expect.soft(errorAlert(page), `${ctx}: the error message is shown`).toHaveText(failure.shows);
      await expect.soft(statCards(page), `${ctx}: no result is shown`).toHaveCount(0);
      await expect.soft(emptyState(page), `${ctx}: the "enter a domain" hint is not shown next to an error`).toHaveCount(0);
      await expect.soft(lookupButton(page), `${ctx}: the button is usable again`).toBeEnabled();
      await expectNoMarkupExecuted(page, ctx);

      await lookup(page, good.domain);
      await expect.soft(errorAlert(page), `after ${ctx}: the error disappears on the next successful lookup`).toHaveCount(0);
      await expect.soft(cardValue(page, 'Domain'), `after ${ctx}: the next lookup shows its result`).toHaveText(good.domain);
    }
    expect.soft(api.calls.length, 'one request per lookup').toBe(FAILURES.length * 2);
  });

  test('a network failure shows an error, no result, and the tool recovers', async ({ page, rng, guard }) => {
    const now = randomNow(rng);
    const good = richSnapshot(rng, now);
    guard.allow(/ERR_FAILED|Failed to fetch/);
    await openPinned(page, now);
    await failApi(page, API);
    await lookup(page, good.domain);
    await expect(errorAlert(page), 'a failed request must be reported').toBeVisible();
    expect.soft(((await errorAlert(page).textContent()) ?? '').trim().length, 'the error has a message').toBeGreaterThan(0);
    await expect.soft(statCards(page), 'no result after a network failure').toHaveCount(0);
    await expect.soft(lookupButton(page), 'the button is usable again').toBeEnabled();

    await page.unroute(API);
    await mockApi(page, API, good, { method: 'POST' });
    await lookup(page, good.domain);
    await expect.soft(errorAlert(page), 'the error clears').toHaveCount(0);
    await expectPageShows(page, good, `recovery lookup of ${good.domain}`);
  });

  test('while a lookup runs the button is disabled and labelled, and the previous result and error are cleared', async ({ page, rng, guard }) => {
    const now = randomNow(rng);
    const first = richSnapshot(rng, now);
    const second = richSnapshot(rng, now);
    const holds = [deferred(), deferred(), deferred()];
    guard.allow(/status of 500|HTTP 500/);
    const api = await scriptApi(page, API, async (_call, index): Promise<ScriptedReply> => {
      await holds[index].promise;
      return index === 1 ? { status: 500, body: { error: 'WHOIS lookup failed.' } } : { body: index === 0 ? first : second };
    });
    await openPinned(page, now);

    const expectLoading = async (ctx: string) => {
      await expect(lookupButton(page), `${ctx}: button label while loading`).toHaveText('Looking up...');
      await expect.soft(lookupButton(page), `${ctx}: button disabled while loading`).toBeDisabled();
      await expect.soft(statCards(page), `${ctx}: no result while loading`).toHaveCount(0);
      await expect.soft(errorAlert(page), `${ctx}: no error while loading`).toHaveCount(0);
      await expect.soft(emptyState(page), `${ctx}: the empty-state hint is hidden while loading`).toHaveCount(0);
    };

    await submit(page, first.domain);
    await expectLoading('first lookup');
    holds[0].resolve();
    await expect(cardValue(page, 'Domain')).toHaveText(first.domain);

    await submit(page, 'fails.example');
    await expectLoading('second lookup (previous result on screen)');
    holds[1].resolve();
    await expect(errorAlert(page)).toHaveText('WHOIS lookup failed.');

    await submit(page, second.domain);
    await expectLoading('third lookup (previous error on screen)');
    holds[2].resolve();
    await expect(cardValue(page, 'Domain')).toHaveText(second.domain);
    await expect.soft(lookupButton(page), 'button after the last lookup').toHaveText('Lookup');
    await expect.soft(lookupButton(page)).toBeEnabled();
    expect.soft(api.calls.length, 'three lookups, three requests').toBe(3);
  });

  test('pressing Enter again while a lookup runs does not send a second request', async ({ page, rng }) => {
    const now = randomNow(rng);
    const snapshot = richSnapshot(rng, now);
    const hold = deferred();
    const api = await scriptApi(page, API, async (): Promise<ScriptedReply> => { await hold.promise; return { body: snapshot }; });
    await openPinned(page, now);

    await submit(page, snapshot.domain, 'enter');
    await expect(lookupButton(page)).toHaveText('Looking up...');
    await domainInput(page).press('Enter');
    await domainInput(page).press('Enter');
    await settle(page);
    const sent = api.calls.length;
    hold.resolve();
    await expect(cardValue(page, 'Domain')).toHaveText(snapshot.domain);
    expect(sent, `requests sent for one lookup of ${snapshot.domain} after pressing Enter three times (the button is disabled while loading; Enter must be too)`).toBe(1);
  });

  test('a slow answer to an earlier lookup never replaces the result of a later one', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const slow = richSnapshot(rng, now);
    const fast = richSnapshot(rng, now);
    await evidence.save('whois-race.json', { slowFirst: slow.domain, fastSecond: fast.domain });
    const hold = deferred();
    const api = await scriptApi(page, API, async (call): Promise<ScriptedReply> => {
      if ((call.body as { domain?: string }).domain === slow.domain) { await hold.promise; return { body: slow }; }
      return { body: fast };
    });
    await openPinned(page, now);

    await submit(page, slow.domain, 'enter');
    await expect(lookupButton(page)).toHaveText('Looking up...');
    await submit(page, fast.domain, 'enter');
    await settle(page);
    const secondWasSent = api.calls.length === 2;
    if (secondWasSent) {
      await api.delivered(1);
      await expect.soft(cardValue(page, 'Domain'), `lookup of ${fast.domain} answered while ${slow.domain} is still pending`).toHaveText(fast.domain);
    }
    hold.resolve();
    await api.delivered(0);
    await settle(page);

    // Whatever the page did with the second Enter, the result must belong to the last request it sent.
    const lastRequested = (api.calls.at(-1)!.body as { domain: string }).domain;
    const want = lastRequested === slow.domain ? slow : fast;
    await expect(statCards(page)).toHaveCount(5);
    expect((await cardValue(page, 'Domain').textContent()) ?? '',
      `requests were sent for [${api.calls.map(c => (c.body as { domain: string }).domain).join(', ')}]; the answer for ${slow.domain} arrived last. The result on screen must be for the last request (${lastRequested})`).toBe(lastRequested);
    await expectPageShows(page, want, `result after the late answer for ${slow.domain}`);
    expect.soft(asciiHost(await domainInput(page).inputValue()), 'the box and the result name the same domain').toBe(lastRequested);
  });
});

test.describe('WHOIS — state', () => {
  test('a second lookup replaces the first result completely, an error replaces a result, and a result replaces an error', async ({ page, rng, guard, evidence }) => {
    const now = randomNow(rng);
    const first = richSnapshot(rng, now, { source: 'rdap', contacts: ['full', 'full', 'full'], statuses: 5 });
    const second = unregisteredSnapshot(rng, now);
    const third = randomSnapshot(rng, now, { source: 'whois', contacts: ['empty', 'empty', 'redacted'], hostile: false });
    await evidence.save('whois-replace-snapshots.json', { first, second, third });
    guard.allow(/status of 500|HTTP 500/);
    await scriptApi(page, API, (_call, index): ScriptedReply => (
      index === 2 ? { status: 500, body: { error: 'WHOIS lookup failed.' } } : { body: [first, second, undefined, third][index] }
    ));
    await openPinned(page, now);

    await lookup(page, first.domain);
    await expectPageShows(page, first, `first result ${first.domain}`);
    await actionButton(page, 'Show Raw RDAP').click();

    await lookup(page, second.domain);
    await expect(cardValue(page, 'Domain')).toHaveText(second.domain);
    await expectPageShows(page, second, `second result ${second.domain} after ${first.domain}`);
    const text = (await page.locator('main').textContent()) ?? '';
    for (const leftover of [first.domain, first.registrar, first.contacts.registrant.name, first.nameservers[0], first.status_labels[0]]) {
      expect.soft(text.includes(leftover), `nothing of the first result ("${leftover}") may remain after looking up ${second.domain}`).toBe(false);
    }

    await lookup(page, 'fails.example');
    await expect(errorAlert(page)).toHaveText('WHOIS lookup failed.');
    await expect.soft(statCards(page), 'an error removes the previous result').toHaveCount(0);
    await expect.soft(page.locator('main .table-card'), 'an error removes every result section').toHaveCount(0);

    await lookup(page, third.domain);
    await expect.soft(errorAlert(page), 'a result removes the previous error').toHaveCount(0);
    await expectPageShows(page, third, `third result ${third.domain} after an error`);
  });

  test('reloading the page returns to the clean empty state and sends nothing', async ({ page, rng }) => {
    const now = randomNow(rng);
    const snapshot = richSnapshot(rng, now);
    const calls = await mockApi(page, API, snapshot, { method: 'POST' });
    await openPinned(page, now);
    await lookup(page, snapshot.domain);
    await expect(cardValue(page, 'Domain')).toHaveText(snapshot.domain);

    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
    await expect(emptyState(page), 'empty state after reload').toBeVisible();
    await expect(domainInput(page), 'the box is empty after reload').toHaveValue('');
    await expect(statCards(page)).toHaveCount(0);
    expect(calls.length, 'the reload itself sends no lookup').toBe(1);
  });
});
