import type { APIRequestContext } from '@playwright/test';
import { test, expect } from '../_support/fixtures';
import { captureDownload, clearClipboard, mockApi, readClipboard } from '../_support/io';
import { expectNoUiGlitches, VIEWPORTS } from '../_support/ui-audit';
import {
  describeLookup, expectCsvMatches, expectNoMarkupExecuted, expectReportMatches, expectRequestsMatch, expectViewMatches, readHtmlReport, runAndCheck,
} from './checks';
import { MARKUP_PROBES, UNKNOWN, awkwardTxtValues, randomAnswer, randomLookup } from './generator';
import {
  CSV_HEADER, GeoOracle, OFFERED_TYPES, SHARE_EXPIRIES, expectedCopyText, expectedCsvRows, expectedSnapshot, expectedView, humanTtl,
  utcStamp, utcStampsBetween, viewerDate, type ApiAnswer, type ExpectedView, type Lookup, type Reply,
} from './oracle';
import { DnsPage, SharedPage, gate, openVisitor, serveLookups } from './page';

/**
 * DNS Lookup — share links, against the REAL backend and database:
 * POST /api/share/dns, GET /api/share/:code, POST /api/share/:code/verify and
 * the shared-view page /s/<code>. The lookup that is shared is answered by the
 * test (random payload), so every value of the shared view has a known origin.
 *
 * Not covered: an expired link (HTTP 410). The shortest expiry is 24 hours and
 * the suite has no way to age a row without touching the database.
 */

const answer = (body: ApiAnswer): Reply => ({ kind: 'answer', body });

/** Every column, an empty type and a failed type, so the shared view has all section kinds. */
function shareableLookup(rng: Parameters<typeof randomLookup>[0]): Lookup {
  const lookup = randomLookup(rng, { types: ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME', 'SRV'], kind: 'records', providers: 'same' });
  (lookup.replies.TXT as { body: ApiAnswer }).body.records = rng.sample(awkwardTxtValues(rng), 6).map(data => ({ name: lookup.domain, type: 'TXT', TTL: rng.int(0, 99999), data }));
  lookup.replies.CNAME = answer(randomAnswer(rng, lookup.domain, 'CNAME', lookup.resolver, { kind: 'none' }));
  lookup.replies.SRV = answer({ error: 'DNS lookup failed with SERVFAIL.', records: [], status: 2, _type: 'SRV', dns_provider: UNKNOWN, hosting_provider: UNKNOWN });
  return lookup;
}

interface ShareMeta { share_type?: string; title?: string; has_password?: boolean; expires_at?: string | null; created_at?: string; domain?: string; checked_at_utc?: string; snapshot?: unknown }

async function shareMeta(request: APIRequestContext, code: string): Promise<{ status: number; body: ShareMeta }> {
  const response = await request.get(`/api/share/${code}`);
  return { status: response.status(), body: await response.json() };
}

/** Compares the shared page of `code` with the expected view and returns the shown view. */
async function expectSharedPageShows(shared: SharedPage, code: string, title: string, want: ExpectedView, stamp: string, counters: string[], ctx: string) {
  await shared.waitForSnapshot();
  await expect.soft(shared.title, `${ctx}: page title`).toHaveText(title);
  await expect.soft(shared.banner, `${ctx}: read-only banner`).toHaveText(`You are viewing ${title} - read-only DNS snapshot.`);
  await expect.soft(shared.main.getByText(`/s/${code}`, { exact: true }), `${ctx}: the link code is shown`).toBeVisible();
  const view = await shared.view();
  expectViewMatches(view, want, { ctx, stamps: [stamp] });
  expect.soft(view.sections.map(section => section.counter), `${ctx}: query times equal the original result`).toEqual(counters);
  return view;
}

test.describe('DNS Lookup — share dialog', () => {
  test('opens with a default title, "Never expires", no password and the time of the lookup; X and a click outside close it', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: ['A', 'NS'], kind: 'records' });
    await serveLookups(page, lookup);
    await dns.open();
    const { shown } = await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);

    await dns.shareButton.click();
    const dialog = dns.share;
    await expect(dialog.heading).toBeVisible();
    await expect.soft(dialog.title, 'default title').toHaveValue(`${lookup.domain} DNS Snapshot`);
    await expect.soft(dialog.expiry, 'default expiry').toHaveValue('never');
    const options = await dialog.expiry.locator('option').evaluateAll(list => list.map(o => ({ value: (o as HTMLOptionElement).value, label: o.textContent ?? '' })));
    expect.soft(options, 'expiry choices').toEqual(SHARE_EXPIRIES.map(e => ({ value: e.value, label: e.label })));
    await expect.soft(dialog.password, 'password starts empty').toHaveValue('');
    await expect.soft(dialog.password).toHaveAttribute('placeholder', 'Leave blank for public link');
    await expect.soft(dialog.checkedAt, 'the dialog repeats the time of the lookup').toHaveText(shown.checkedAt ?? '');
    await expect.soft(dialog.error).toHaveCount(0);

    // Change every field, close with X, reopen: the defaults are back.
    await dialog.title.fill('something else');
    await dialog.expiry.selectOption('7d');
    await dialog.password.fill('secret');
    await dialog.closeButton.click();
    await expect(dialog.heading, 'X closes the dialog').toHaveCount(0);
    await dns.shareButton.click();
    await expect.soft(dialog.title, 'title after reopening').toHaveValue(`${lookup.domain} DNS Snapshot`);
    await expect.soft(dialog.expiry, 'expiry after reopening').toHaveValue('never');
    await expect.soft(dialog.password, 'password after reopening').toHaveValue('');

    // A click on the dimmed area outside the panel closes it; a click inside does not.
    await dialog.heading.click();
    await expect(dialog.heading, 'a click inside keeps the dialog open').toBeVisible();
    await dialog.backdrop.click({ position: { x: 5, y: 5 } });
    await expect(dialog.heading, 'a click outside closes the dialog').toHaveCount(0);
    await expect.soft(dns.checkedAt, 'the result is still there after closing').toHaveText(shown.checkedAt ?? '');
  });

  test('the dialog has no layout problems at desktop, laptop and mobile size, before and after creating a link', async ({ page, rng, baseURL, evidence }) => {
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: ['MX'], kind: 'records' });
    await serveLookups(page, lookup);
    await dns.open();
    await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    // The panel is the only element with this structure: panel > header row > title row > h3.
    const scope = 'div:has(> div > div > h3)';
    for (const [name, viewport] of Object.entries(VIEWPORTS)) {
      await page.setViewportSize(viewport);
      if (!(await dns.share.heading.isVisible())) await dns.shareButton.click();
      await expect(dns.share.generate).toBeVisible();
      await page.mouse.move(0, 0);
      await expectNoUiGlitches(page, `share dialog (form) @${name}`, { scope });
      const box = await dns.share.panel.boundingBox();
      expect.soft(box && box.x >= 0 && box.x + box.width <= viewport.width, `share dialog @${name}: the panel (${JSON.stringify(box)}) fits the ${viewport.width}px viewport`).toBe(true);
    }
    await dns.share.create();
    for (const [name, viewport] of Object.entries(VIEWPORTS)) {
      await page.setViewportSize(viewport);
      await page.mouse.move(0, 0);
      await expectNoUiGlitches(page, `share dialog (link created) @${name}`, { scope });
    }
  });

  test('a failed share request shows the error in the dialog and a retry succeeds; a slow one shows progress', async ({ page, rng, evidence, guard, baseURL, request }) => {
    guard.allow(/status of 500|HTTP 500/);
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: ['NS'], kind: 'records' });
    await serveLookups(page, lookup);
    await dns.open();
    await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    await dns.shareButton.click();

    await mockApi(page, '**/api/share/dns', { success: false, error: 'Could not generate unique code. Try again.' }, { method: 'POST', status: 500 });
    await dns.share.generate.click();
    await expect(dns.share.error, 'the server message is shown in the dialog').toHaveText('Could not generate unique code. Try again.');
    await expect.soft(dns.share.created, 'no link after a failure').toHaveCount(0);
    await expect.soft(dns.share.generate, 'the form stays usable').toBeEnabled();

    // Second attempt: the real backend, held back to observe the progress state.
    await page.unroute('**/api/share/dns');
    const held = gate();
    await page.route('**/api/share/dns', async route => { await held.promise; await route.continue(); });
    await dns.share.generate.click();
    await expect(dns.share.creating, 'progress text while the link is being created').toBeVisible();
    await expect.soft(dns.share.generate, 'no second submit while waiting').toHaveCount(0);
    held.open();
    await expect(dns.share.created).toBeVisible();
    await expect.soft(dns.share.error, 'the earlier error is gone').toHaveCount(0);
    const code = ((await dns.share.link.textContent()) ?? '').split('/s/')[1];
    expect((await shareMeta(request, code)).status, `the created link /s/${code} exists`).toBe(200);
  });

  test('a title longer than the 500 characters the database keeps is refused or shortened, never an Internal Server Error', async ({ page, rng, evidence, baseURL }) => {
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: ['NS'], kind: 'records' });
    await serveLookups(page, lookup);
    await dns.open();
    await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    await dns.shareButton.click();
    const longTitle = rng.string(rng.int(501, 620), 'abcdefghij klmnopqrstuvwxyz');
    await evidence.save('long-title.txt', longTitle);
    await dns.share.title.fill(longTitle);
    const [response] = await Promise.all([
      page.waitForResponse(res => res.url().endsWith('/api/share/dns'), { timeout: 8_000 }).catch(() => null),
      dns.share.generate.click(),
    ]);
    // Either the page refuses before sending (no response), or the server answers without a 5xx.
    expect.soft(response?.status() ?? 0, `POST /api/share/dns with a ${longTitle.length}-character title must not be a server error; dialog shows: "${await dns.share.panel.innerText()}"`).toBeLessThan(500);
  });
});

test.describe('DNS Lookup — shared links for another visitor', () => {
  test('a link without a password shows another visitor exactly the result that was shared', async ({ page, rng, evidence, browser, baseURL, request }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const lookup = shareableLookup(rng);
    await serveLookups(page, lookup);
    await dns.open();
    const { want, shown, ctx } = await runAndCheck(dns, lookup, geo, evidence);

    await dns.shareButton.click();
    const title = `Snapshot ${rng.string(6)} — ${lookup.domain} ✓`;
    const startedAt = Date.now();
    const { code, url, request: sent } = await dns.share.create({ title });
    await evidence.save('share-request.json', sent);

    // What the page sent to the backend.
    expect.soft(sent.title, `${ctx}: share title sent`).toBe(title);
    expect.soft(sent.domain, `${ctx}: share domain sent`).toBe(lookup.domain);
    expect.soft(sent.expiry, `${ctx}: share expiry sent`).toBe('never');
    expect.soft(sent.password, `${ctx}: no password sent for a public link`).toBe('');
    expect.soft(utcStamp(String(sent.checked_at_utc)), `${ctx}: checked_at_utc sent equals the time shown on the page`).toBe(shown.checkedAt);
    expect.soft(sent.snapshot, `${ctx}: snapshot stored with the share (every field of every record)`)
      .toEqual(expectedSnapshot(want, { checkedAt: sent.checked_at_utc, queryTime: expect.any(Number), selectedTypes: expect.any(Array) }));
    expect.soft([...(sent.snapshot as { selected_types: string[] }).selected_types].sort(), `${ctx}: selected types stored with the share`).toEqual([...lookup.types].sort());

    // The link the dialog offers.
    expect.soft(url, `${ctx}: link shown in the dialog`).toBe(`${baseURL}/s/${code}`);
    await clearClipboard(page);
    await dns.share.copyLink.click();
    await expect.soft(dns.share.copyLink, 'the copy button confirms').toHaveText('Copied!');
    expect.soft(await readClipboard(page), `${ctx}: copied link`).toBe(`${baseURL}/s/${code}`);
    await expect.soft(dns.share.panel.getByText(`Checked at ${shown.checkedAt}.`), `${ctx}: the dialog repeats the lookup time`).toBeVisible();

    // What the backend stored.
    const meta = await shareMeta(request, code);
    expect(meta.status, `GET /api/share/${code}`).toBe(200);
    expect.soft(meta.body, `${ctx}: share metadata`).toMatchObject({ share_type: 'dns', title, has_password: false, expires_at: null, domain: lookup.domain, checked_at_utc: sent.checked_at_utc });
    expect.soft(Math.abs(new Date(String(meta.body.created_at)).getTime() - startedAt), `${ctx}: created_at (${meta.body.created_at}) is the time the link was created`).toBeLessThan(120_000);

    // Another visitor.
    const visitor = await openVisitor(browser, baseURL!);
    try {
      const shared = new SharedPage(visitor.page);
      await shared.open(code);
      await expectSharedPageShows(shared, code, title, want, shown.checkedAt ?? '', shown.sections.map(s => s.counter), `visitor of /s/${code}`);
      await expect.soft(shared.dates, 'creation date in the visitor\'s time zone, no expiry').toHaveText(`Created: ${viewerDate(String(meta.body.created_at))}`);
      await expect.soft(shared.lockHeading, 'no password prompt for a public link').toHaveCount(0);
      await expect.soft(shared.newLookupLink).toHaveAttribute('href', '/dns');
      await expectNoMarkupExecuted(visitor.page, `visitor of /s/${code}`);
      expect.soft(visitor.problems(), 'browser errors for the visitor').toEqual([]);
    } finally {
      await visitor.close();
    }
  });

  test('a password-protected link hides the snapshot until the right password is entered; a wrong or empty one is refused', async ({ page, rng, evidence, browser, baseURL, request }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const lookup = shareableLookup(rng);
    await serveLookups(page, lookup);
    await dns.open();
    const { want, shown } = await runAndCheck(dns, lookup, geo, evidence);
    await dns.shareButton.click();
    const password = `pw-${rng.string(10)} ${rng.string(4, 'ÄÖÜß!#%&')}`;
    const { code, request: sent } = await dns.share.create({ password, expiry: '7d' });
    await evidence.save('share-password.json', { code, password });
    expect.soft(sent.password, 'password sent to the backend').toBe(password);
    const title = `${lookup.domain} DNS Snapshot`;

    // The backend must not hand out the data without the password.
    const meta = await shareMeta(request, code);
    expect.soft(meta.body, 'metadata of a protected link').toMatchObject({ share_type: 'dns', title, has_password: true });
    expect.soft(Object.keys(meta.body).filter(key => ['snapshot', 'domain', 'checked_at_utc'].includes(key)), 'GET /api/share/:code of a protected link leaks no content fields').toEqual([]);
    expect.soft(JSON.stringify(meta.body), 'no record value in the metadata of a protected link').not.toContain(String((lookup.replies.NS as { body: ApiAnswer }).body.records?.[0]?.data));
    for (const attempt of [{}, { password: '' }, { password: `${password}x` }, { password: password.toUpperCase() }]) {
      const verify = await request.post(`/api/share/${code}/verify`, { data: attempt });
      expect.soft(verify.status(), `POST /api/share/${code}/verify with ${JSON.stringify(attempt)} must be refused`).toBe(401);
      expect.soft(await verify.text(), 'a refused verification returns no snapshot').not.toContain('"snapshot"');
    }

    const visitor = await openVisitor(browser, baseURL!, { allow: [/status of 401/] });
    try {
      const shared = new SharedPage(visitor.page);
      await shared.open(code);
      await expect(shared.lockHeading, 'the visitor is asked for the password').toBeVisible();
      await expect.soft(shared.title, 'the title is visible on the locked page').toHaveText(title);
      await expect.soft(shared.checkedAt, 'no snapshot on the locked page').toHaveCount(0);
      await expect.soft(shared.main.locator('.stat-card, .table-card'), 'no cards or records on the locked page').toHaveCount(0);
      await expect.soft(shared.main, 'the domain is not revealed on the locked page other than in the title').not.toContainText(String((lookup.replies.NS as { body: ApiAnswer }).body.records?.[0]?.data));

      await shared.unlock.click();
      await expect(shared.error, 'an empty password is refused with a message').toHaveText('⚠️ Password required.');
      await expect.soft(shared.lockHeading).toBeVisible();

      await shared.password.fill(`${password}x`);
      await shared.unlock.click();
      await expect(shared.error, 'a wrong password is refused with a message').toHaveText('⚠️ Incorrect password.');
      await expect.soft(shared.lockHeading, 'still locked after a wrong password').toBeVisible();
      await expect.soft(shared.checkedAt, 'still no snapshot after a wrong password').toHaveCount(0);

      await shared.password.fill(password);
      await shared.password.press('Enter');
      await expectSharedPageShows(shared, code, title, want, shown.checkedAt ?? '', shown.sections.map(s => s.counter), `visitor of protected /s/${code}`);
      await expect.soft(shared.lockHeading, 'the prompt is gone after the right password').toHaveCount(0);
      await expect.soft(shared.error, 'the earlier error is gone').toHaveCount(0);
      expect.soft(visitor.problems(), 'browser errors for the visitor').toEqual([]);
    } finally {
      await visitor.close();
    }
  });

  test('each expiry choice is sent as chosen, stored as that many hours from now, and shown to the visitor', async ({ page, rng, evidence, browser, baseURL, request }) => {
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: ['A', 'TXT'], kind: 'records' });
    await serveLookups(page, lookup);
    await dns.open();
    await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    await dns.shareButton.click();

    const visitor = await openVisitor(browser, baseURL!);
    try {
      const codes = new Set<string>();
      for (const expiry of rng.shuffle(SHARE_EXPIRIES)) {
        if (await dns.share.createAnother.isVisible()) await dns.share.createAnother.click();
        const createdAt = Date.now();
        const { code, request: sent } = await dns.share.create({ expiry: expiry.value });
        codes.add(code);
        const ctx = `expiry "${expiry.label}" (/s/${code})`;
        expect.soft(sent.expiry, `${ctx}: value sent to POST /api/share/dns`).toBe(expiry.value);

        const meta = (await shareMeta(request, code)).body;
        if (expiry.hours === null) {
          expect.soft(meta.expires_at, `${ctx}: stored expiry`).toBeNull();
        } else {
          const wanted = createdAt + expiry.hours * 3_600_000;
          expect.soft(Math.abs(new Date(String(meta.expires_at)).getTime() - wanted), `${ctx}: stored expiry ${meta.expires_at} should be ${expiry.hours}h after creation (${new Date(wanted).toISOString()})`).toBeLessThan(120_000);
        }

        const shared = new SharedPage(visitor.page);
        await shared.open(code);
        await shared.waitForSnapshot();
        const created = `Created: ${viewerDate(String(meta.created_at))}`;
        await expect.soft(shared.dates, `${ctx}: dates shown to the visitor`).toHaveText(expiry.hours === null ? created : `${created} · Expires: ${viewerDate(String(meta.expires_at))}`);
      }
      expect.soft(codes.size, '"Create Another Link" gives a new code every time').toBe(SHARE_EXPIRIES.length);
      expect.soft(visitor.problems(), 'browser errors for the visitor').toEqual([]);
    } finally {
      await visitor.close();
    }
  });

  test('the visitor can copy, export and download the shared snapshot with the same content as the original', async ({ page, rng, evidence, browser, baseURL }) => {
    const dns = new DnsPage(page);
    const lookup = shareableLookup(rng);
    await serveLookups(page, lookup);
    await dns.open();
    const { want, shown } = await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    await dns.shareButton.click();
    const { code } = await dns.share.create();
    const ctx = `visitor of /s/${code} (${describeLookup(lookup)})`;

    const visitor = await openVisitor(browser, baseURL!);
    try {
      const shared = new SharedPage(visitor.page);
      await shared.open(code);
      await shared.waitForSnapshot();

      await clearClipboard(visitor.page);
      await shared.copyAllButton.click();
      await expect(shared.copyAllButton).toHaveText('Copied!');
      expect.soft(await readClipboard(visitor.page), `${ctx}: Copy All Records`).toBe(expectedCopyText(want));

      const csv = await captureDownload(visitor.page, () => shared.exportCsvButton.click());
      expect.soft(csv.filename, `${ctx}: CSV file name`).toBe(`${lookup.domain}-dns-snapshot.csv`);
      expectCsvMatches(csv.text, CSV_HEADER, expectedCsvRows(want), ctx);

      const html = await captureDownload(visitor.page, () => shared.downloadHtmlButton.click());
      expect.soft(html.filename, `${ctx}: report file name`).toBe(`${lookup.domain}-shared-dns-snapshot.html`);
      expectReportMatches(await readHtmlReport(visitor.page, html.text), want, { ctx, stamps: [shown.checkedAt ?? ''], pageCounters: shown.sections.map(s => s.counter) });
      expect.soft(visitor.problems(), 'browser errors for the visitor').toEqual([]);
    } finally {
      await visitor.close();
    }
  });

  test('"Re-run DNS Lookup Now" and "Open Live Lookup" start a live lookup with the shared domain, resolver and types', async ({ page, rng, evidence, browser, baseURL }) => {
    const dns = new DnsPage(page);
    const geo = await GeoOracle.load(baseURL!);
    const lookup = randomLookup(rng, { types: rng.sample(OFFERED_TYPES, rng.int(2, 4)), kind: 'records', resolver: rng.pick(['8.8.8.8', '208.67.222.222']) });
    await serveLookups(page, lookup);
    await dns.open();
    const { want } = await runAndCheck(dns, lookup, geo, evidence);
    await dns.shareButton.click();
    const { code } = await dns.share.create();

    const visitor = await openVisitor(browser, baseURL!);
    try {
      const calls = await serveLookups(visitor.page, lookup);
      const shared = new SharedPage(visitor.page);
      await shared.open(code);
      await shared.waitForSnapshot();

      const href = await shared.openLiveLink.getAttribute('href');
      const link = new URL(href ?? '', baseURL);
      expect.soft(link.pathname, '"Open Live Lookup" target').toBe('/dns');
      expect.soft(link.searchParams.get('domain'), '"Open Live Lookup" domain').toBe(lookup.domain);
      expect.soft(link.searchParams.get('resolver'), '"Open Live Lookup" resolver').toBe(lookup.resolver);
      expect.soft((link.searchParams.get('types') ?? '').split(',').sort(), '"Open Live Lookup" record types').toEqual([...want.selectedTypes].sort());
      expect.soft([...link.searchParams.keys()].sort(), '"Open Live Lookup" has no other parameters').toEqual(['domain', 'resolver', 'types']);

      await shared.rerunButton.click();
      await expect(visitor.page, '"Re-run DNS Lookup Now" opens the DNS tool').toHaveURL(/\/dns\?domain=/);
      const live = new DnsPage(visitor.page);
      await live.waitForResult();
      const ctx = `re-run from /s/${code}`;
      expectRequestsMatch(calls, lookup, ctx);
      expectViewMatches(await live.view(), expectedView(lookup, geo), { ctx });
      await expect.soft(live.domain, `${ctx}: domain box`).toHaveValue(lookup.domain);
      await expect.soft(live.resolver, `${ctx}: resolver`).toHaveValue(lookup.resolver);
      expect.soft(await live.checkedTypes(), `${ctx}: ticked types`).toEqual(OFFERED_TYPES.filter(type => lookup.types.includes(type)));
      expect.soft(visitor.problems(), 'browser errors for the visitor').toEqual([]);
    } finally {
      await visitor.close();
    }
  });

  test('"Checked At" of a shared snapshot is the time of the lookup, however much later it is shared', async ({ page, rng, evidence, browser, baseURL }) => {
    await page.clock.install();
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: ['NS'], kind: 'records' });
    await serveLookups(page, lookup);
    await dns.open();
    const before = Date.now();
    const { shown } = await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    const stamps = utcStampsBetween(before - 2000, Date.now() + 2000);
    const minutesLater = rng.int(7, 55);
    await page.clock.fastForward(minutesLater * 60_000);

    await dns.shareButton.click();
    await expect.soft(dns.share.checkedAt, `share dialog ${minutesLater} minutes after the lookup`).toHaveText(shown.checkedAt ?? '');
    const { code, request: sent } = await dns.share.create();
    expect.soft(stamps, `checked_at_utc sent ${minutesLater} minutes after the lookup (${sent.checked_at_utc}) is the lookup time`).toContain(utcStamp(String(sent.checked_at_utc)));

    const visitor = await openVisitor(browser, baseURL!);
    try {
      const shared = new SharedPage(visitor.page);
      await shared.open(code);
      await shared.waitForSnapshot();
      await expect.soft(shared.checkedAt, 'visitor sees the lookup time').toHaveText(shown.checkedAt ?? '');
    } finally {
      await visitor.close();
    }
  });

  test('a title with markup, and a blank title, are stored and shown safely', async ({ page, rng, evidence, browser, baseURL }) => {
    const dns = new DnsPage(page);
    const lookup = randomLookup(rng, { types: ['NS'], kind: 'records' });
    await serveLookups(page, lookup);
    await dns.open();
    await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
    await dns.shareButton.click();
    const markupTitle = `${MARKUP_PROBES[0]} & "quotes" ${rng.string(5)}`;
    const first = await dns.share.create({ title: `  ${markupTitle}  ` });
    expect.soft(first.request.title, 'title is sent without surrounding spaces').toBe(markupTitle);
    await dns.share.createAnother.click();
    const second = await dns.share.create({ title: '   ' });
    expect.soft(second.request.title, 'a blank title falls back to the default').toBe(`${lookup.domain} DNS Snapshot`);

    const visitor = await openVisitor(browser, baseURL!);
    try {
      const shared = new SharedPage(visitor.page);
      await shared.open(first.code);
      await shared.waitForSnapshot();
      await expect.soft(shared.title, 'markup in the title is shown as text').toHaveText(markupTitle);
      await expect.soft(shared.banner).toHaveText(`You are viewing ${markupTitle} - read-only DNS snapshot.`);
      await expectNoMarkupExecuted(visitor.page, `visitor of /s/${first.code}`);
      await shared.open(second.code);
      await shared.waitForSnapshot();
      await expect.soft(shared.title, 'default title').toHaveText(`${lookup.domain} DNS Snapshot`);
    } finally {
      await visitor.close();
    }
  });

  test('an unknown link code says the share was not found', async ({ page, rng, guard }) => {
    guard.allow(/status of 404/);
    const shared = new SharedPage(page);
    const code = rng.string(8, 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
    await shared.open(code);
    await expect(shared.error).toHaveText('⚠️ Share not found.');
    await expect.soft(shared.checkedAt).toHaveCount(0);
    await expect.soft(shared.lockHeading).toHaveCount(0);
    await expect.soft(shared.main.locator('.skeleton'), 'the loading placeholder is gone').toHaveCount(0);
  });
});

test.describe('DNS Lookup — shared view of snapshots stored through the share API', () => {
  test('snapshots with random lookup times (midnight, month ends, any year) show that exact time and the stored query times', async ({ page, rng, evidence, baseURL, request }) => {
    const geo = await GeoOracle.load(baseURL!);
    const instants = [
      Date.UTC(2026, 8, rng.int(1, 30), 0, rng.int(0, 59), rng.int(0, 59)),    // September, hour 00
      Date.UTC(2027, 11, 31, 23, 59, 59),                                       // last second of a year
      Date.UTC(2028, 1, 29, 12, 0, 0),                                          // leap day
      Date.UTC(rng.int(2001, 2037), rng.int(0, 11), rng.int(1, 28), rng.int(0, 23), rng.int(0, 59), rng.int(0, 59)),
      Date.UTC(rng.int(2001, 2037), rng.int(0, 11), rng.int(1, 28), 0, 0, 0),
    ];
    const shared = new SharedPage(page);
    for (const instant of instants) {
      const lookup = randomLookup(rng, { types: rng.sample(OFFERED_TYPES, rng.int(1, 4)) });
      const want = expectedView(lookup, geo);
      const checkedAt = new Date(instant + rng.int(0, 999)).toISOString();
      const snapshot = expectedSnapshot(want, { checkedAt, queryTime: 0 }) as { results: { _queryTime: number }[] };
      const times = snapshot.results.map(() => rng.pick([0, 1, rng.int(2, 999), rng.int(1000, 30000)]));
      snapshot.results.forEach((result, i) => { result._queryTime = times[i]; });
      const title = `API snapshot ${rng.string(6)}`;
      const created = await request.post('/api/share/dns', { data: { title, domain: lookup.domain, expiry: 'never', password: '', checked_at_utc: checkedAt, snapshot } });
      expect(created.status(), 'POST /api/share/dns').toBe(200);
      const { code } = await created.json() as { code: string };
      await evidence.save(`api-snapshot-${code}.json`, { checkedAt, snapshot });

      await shared.open(code);
      const ctx = `/s/${code} (checked at ${checkedAt})`;
      await shared.waitForSnapshot();
      await expect.soft(shared.title, `${ctx}: title`).toHaveText(title);
      const view = await shared.view();
      expectViewMatches(view, want, { ctx, stamps: [utcStamp(checkedAt)] });
      expect.soft(view.sections.map(s => Number(s.counter.match(/(\d+)ms$/)?.[1])), `${ctx}: stored query times`).toEqual(times);
    }
  });

  test('a minimal snapshot (only domain, types and record values, as an older client stored it) is shown with derived totals and defaults', async ({ page, rng, evidence, request }) => {
    const domain = `${rng.string(8)}.example`;
    const checkedAt = new Date(Date.UTC(2025, rng.int(0, 11), rng.int(1, 28), rng.int(0, 23), rng.int(0, 59), rng.int(0, 59))).toISOString();
    const ttl = rng.int(61, 86399);
    const snapshot = {
      domain,
      checked_at_utc: checkedAt,
      results: [
        { _type: 'TXT', records: [{ value: 'only-a-value-field', TTL: String(ttl) }] },
        { _type: 'A', records: [{ data: '192.0.2.10', TTL: ttl }, { data: '192.0.2.11' }] },
        { _type: 'MX', records: [] },
      ],
    };
    await evidence.save('minimal-snapshot.json', snapshot);
    const created = await request.post('/api/share/dns', { data: { title: 'Minimal', domain, checked_at_utc: checkedAt, snapshot } });
    expect(created.status(), 'POST /api/share/dns').toBe(200);
    const { code } = await created.json() as { code: string };

    const shared = new SharedPage(page);
    await shared.open(code);
    await shared.waitForSnapshot();
    const view = await shared.view();
    const ctx = `minimal snapshot /s/${code}`;
    expect.soft(view.cards, `${ctx}: summary cards`).toEqual([
      { label: 'Domain', value: domain, meta: '' },
      { label: 'Records Found', value: '3', meta: '' },
      { label: 'DNS Provider', value: 'Unknown', meta: 'Low confidence · No strong DNS fingerprint' },
      { label: 'Hosting / Edge', value: 'Unknown', meta: 'Low confidence · Derived from DNS answers' },
      { label: 'Resolver', value: 'Cloudflare (1.1.1.1)', meta: '' },
    ]);
    expect.soft(view.checkedAt, `${ctx}: Checked At`).toBe(utcStamp(checkedAt));
    expect.soft(view.sections.map(s => `${s.heading} | ${s.counter} | ${s.state}`), `${ctx}: sections in display order`).toEqual([
      'A Records | 2 found · 0ms | table', 'MX Records | 0 found · 0ms | empty', 'TXT Records | 1 found · 0ms | table',
    ]);
    expect.soft(view.sections[0]?.rows.map(row => row.map(cell => cell.text)), `${ctx}: A rows (no location or provider stored)`).toEqual([
      ['192.0.2.10', '—', 'Unknown', humanTtl(ttl)], ['192.0.2.11', '—', 'Unknown', '0s'],
    ]);
    expect.soft(view.sections[1]?.note, `${ctx}: MX note`).toBe('No MX records found.');
    expect.soft(view.sections[2]?.rows.map(row => row.map(cell => cell.text)), `${ctx}: TXT row (value field, TTL stored as text)`).toEqual([['only-a-value-field', humanTtl(ttl)]]);
    const live = new URL((await shared.openLiveLink.getAttribute('href')) ?? '', 'http://x');
    expect.soft({ domain: live.searchParams.get('domain'), resolver: live.searchParams.get('resolver'), types: (live.searchParams.get('types') ?? '').split(',').sort() }, `${ctx}: "Open Live Lookup" parameters`)
      .toEqual({ domain, resolver: '1.1.1.1', types: ['A', 'MX', 'TXT'] });
  });
});

test.describe('DNS Lookup — shared view layout', () => {
  for (const [name, viewport] of Object.entries(VIEWPORTS)) {
    test(`the shared page has no layout problems at ${name} size (${viewport.width}px): password prompt, refused password, snapshot`, async ({ page, rng, evidence, browser, baseURL }) => {
      const dns = new DnsPage(page);
      const lookup = shareableLookup(rng);
      await serveLookups(page, lookup);
      await dns.open();
      await runAndCheck(dns, lookup, await GeoOracle.load(baseURL!), evidence);
      await dns.shareButton.click();
      const password = rng.string(12);
      const { code } = await dns.share.create({ password, expiry: '30d' });

      const visitor = await openVisitor(browser, baseURL!, { viewport, allow: [/status of 401/] });
      try {
        const shared = new SharedPage(visitor.page);
        await shared.open(code);
        await expect(shared.lockHeading).toBeVisible();
        await expectNoUiGlitches(visitor.page, `/s/${code} password prompt @${name}`);
        await shared.password.fill('not the password');
        await shared.password.press('Enter');
        await expect(shared.error).toBeVisible();
        await expectNoUiGlitches(visitor.page, `/s/${code} refused password @${name}`);
        await shared.password.fill(password);
        await shared.password.press('Enter');
        await shared.waitForSnapshot();
        await expect(visitor.page.locator('.table-card:has(.table-card-header)')).toHaveCount(lookup.types.length);
        await expectNoUiGlitches(visitor.page, `/s/${code} snapshot @${name}`);
        expect.soft(visitor.problems(), 'browser errors for the visitor').toEqual([]);
      } finally {
        await visitor.close();
      }
    });
  }
});
