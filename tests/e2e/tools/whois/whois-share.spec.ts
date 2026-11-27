import { test, expect, type Page } from '../_support/fixtures';
import { openTool } from '../_support/navigation';
import { VIEWPORTS, expectNoUiGlitchesAtRest } from '../_support/ui-audit';
import { captureApi, captureDownload, clearClipboard, mockApi, readClipboard } from '../_support/io';
import { deferred, scriptApi, type ScriptedReply } from '../_support/gate';
import { MARKUP, randomNow, randomSnapshot, richSnapshot } from './generator';
import { expectedSummary, expectedView, localDay, sameMonthSpelling, utcStamp, type Snapshot } from './oracle';
import {
  API, HEADING, ROUTE, SHARE_API, SHARE_DIALOG, actionButton, cardValue, expectVisitorClean, lookup, newVisitor, openShared, passwordBox,
  passwordPrompt, readView, shareClose, shareDialog, shareExpiry, shareLink, sharePassword, shareSubmit, shareTitle, sharedError,
  statCards, unlockButton, type Visitor,
} from './page';
import { expectNoMarkupExecuted, expectRawShows, expectViewEquals } from './checks';

/**
 * WHOIS Lookup — share links, against the real backend and database.
 *
 * The snapshot being shared is generated (the lookup is answered by the test),
 * so the oracle knows every value; creating the link, storing it, reading it
 * back and checking the password all run on the real API. Each link is opened
 * by a second visitor: a new browser context with nothing from the first.
 */

interface CreatedShare {
  code: string;
  link: string;
  status: number;
  request: Record<string, unknown>;
  response: Record<string, unknown>;
}

/** Looks up a generated snapshot so there is a result to share. */
async function showSnapshot(page: Page, snapshot: Snapshot, now: Date) {
  await mockApi(page, API, snapshot, { method: 'POST' });
  await page.clock.setFixedTime(now);
  await openTool(page, ROUTE, HEADING);
  await lookup(page, snapshot.domain);
  await expect(cardValue(page, 'Domain')).toHaveText(snapshot.domain);
}

async function openDialog(page: Page) {
  await actionButton(page, 'Share Snapshot').click();
  await expect(shareDialog(page), 'the share dialog opens').toBeVisible();
}

/** Fills the open dialog, presses "Generate Share Link" and returns the real exchange. */
async function generate(page: Page, options: { title?: string; expiry?: string; password?: string } = {}): Promise<CreatedShare> {
  if (options.title !== undefined) await shareTitle(page).fill(options.title);
  if (options.expiry !== undefined) await shareExpiry(page).selectOption(options.expiry);
  if (options.password !== undefined) await sharePassword(page).fill(options.password);
  const exchange = await captureApi<Record<string, unknown>>(page, '/api/share/whois', () => shareSubmit(page).click());
  expect(exchange.status, `POST /api/share/whois answered ${exchange.status}: ${JSON.stringify(exchange.response)}`).toBe(200);
  await expect(shareDialog(page).getByText('Share link created!'), 'the dialog confirms the link').toBeVisible();
  const link = ((await shareLink(page).textContent()) ?? '').trim();
  return { code: String(exchange.response.code), link, status: exchange.status, request: exchange.request as Record<string, unknown>, response: exchange.response };
}

/** The text present in `now` that was not in `before`, when one piece of text was inserted. */
function insertedText(before: string, now: string): string {
  let start = 0;
  while (start < before.length && before[start] === now[start]) start++;
  let end = 0;
  while (end < before.length - start && before[before.length - 1 - end] === now[now.length - 1 - end]) end++;
  return now.slice(start, now.length - end);
}

const header = (page: Page) => page.locator('main h1');
const dates = (page: Page) => page.locator('main p', { hasText: /^Created:/ });
const banner = (page: Page) => page.locator('main span', { hasText: 'You are viewing' });

/** The shared page must show, for another visitor, exactly what the sharer saw. */
async function expectSharedShows(visitor: Visitor, snapshot: Snapshot, original: Awaited<ReturnType<typeof readView>>, share: { code: string; title: string }, ctx: string) {
  const page = visitor.page;
  await expect(statCards(page), `${ctx}: the snapshot is shown`).toHaveCount(5);
  await expect.soft(header(page), `${ctx}: page heading is the share title`).toHaveText(share.title);
  await expect.soft(banner(page), `${ctx}: banner names the share`).toHaveText(`You are viewing ${share.title} - read-only registration data.`);
  await expect.soft(page.locator('main').getByText(`/s/${share.code}`, { exact: true }), `${ctx}: banner shows the share code`).toBeVisible();
  await expect.soft(page.getByRole('link', { name: 'Open Live Lookup' }), `${ctx}: "Open Live Lookup" target`).toHaveAttribute('href', `/whois?domain=${encodeURIComponent(snapshot.domain)}`);
  await expect.soft(actionButton(page, 'Re-run Lookup'), `${ctx}: shared view offers Re-run Lookup`).toBeVisible();
  await expect.soft(actionButton(page, 'Share Snapshot'), `${ctx}: shared view is read-only (no Share button)`).toHaveCount(0);
  const shown = await readView(page);
  expectViewEquals(shown, expectedView(snapshot), `${ctx} vs the shared snapshot`);
  expect.soft(shown, `${ctx}: the shared view shows the same values as the original result`).toEqual(original);
  await expectRawShows(page, snapshot, ctx);
  await expectNoMarkupExecuted(page, ctx);
}

test.describe('WHOIS — share links (real backend)', () => {
  test('a link without password: dialog defaults, request, copy, and another visitor sees the same snapshot', async ({ page, browser, rng, evidence }, testInfo) => {
    const now = randomNow(rng);
    const snapshot = randomSnapshot(rng, now, { hostile: true, contacts: ['hostile', 'redacted', 'partial'], statuses: 4 });
    await evidence.save('whois-shared-snapshot.json', snapshot);
    await showSnapshot(page, snapshot, now);
    const original = await readView(page);
    const defaultTitle = `${snapshot.domain} WHOIS Snapshot`;

    await openDialog(page);
    await expect.soft(shareTitle(page), 'default share title').toHaveValue(defaultTitle);
    await expect.soft(shareExpiry(page), 'default expiry').toHaveValue('never');
    expect.soft(await shareExpiry(page).locator('option').allTextContents(), 'expiry choices').toEqual(['Never expires', '24 hours', '7 days', '30 days']);
    await expect.soft(sharePassword(page), 'password starts empty').toHaveValue('');
    expect.soft(sameMonthSpelling((await shareDialog(page).getByText('Checked At:').locator('..').textContent()) ?? ''), 'check time in the dialog')
      .toBe(`Checked At: ${utcStamp(snapshot.checked_at_utc)}`);

    const startedAt = Date.now();
    const share = await generate(page);
    await evidence.save('whois-share-exchange.json', share);
    expect.soft(share.request.title, 'share request: title').toBe(defaultTitle);
    expect.soft(share.request.domain, 'share request: domain').toBe(snapshot.domain);
    expect.soft(share.request.expiry, 'share request: expiry').toBe('never');
    expect.soft(share.request.password, 'share request: password').toBe('');
    expect.soft(share.request.checked_at_utc, 'share request: check time').toBe(snapshot.checked_at_utc);
    expect.soft(share.request.snapshot, 'share request: the snapshot sent is the one on screen').toEqual(snapshot);
    expect.soft(share.response.success, 'share response: success').toBe(true);
    expect.soft(share.code, 'share response: code is 8 letters or digits').toMatch(/^[A-Za-z0-9]{8}$/);
    expect.soft(share.response.url, 'share response: url').toBe(`/s/${share.code}`);
    expect.soft(share.link, 'link shown in the dialog').toBe(`${new URL(page.url()).origin}/s/${share.code}`);
    expect.soft(sameMonthSpelling((await shareDialog(page).getByText(/^Checked at /).textContent()) ?? ''), 'check time under the link')
      .toBe(`Checked at ${utcStamp(snapshot.checked_at_utc)}.`);

    await clearClipboard(page);
    await shareDialog(page).getByRole('button', { name: 'Copy' }).click();
    await expect(shareDialog(page).getByRole('button', { name: 'Copied!' }), 'the Copy button confirms').toBeVisible();
    expect.soft(await readClipboard(page), 'copied share link').toBe(share.link);

    const visitor = await newVisitor(browser, testInfo);
    try {
      const { status, meta } = await openShared(visitor, share.code);
      expect(status, 'GET /api/share/<code> for a public link').toBe(200);
      await expect(passwordPrompt(visitor.page), 'a public link asks for no password').toHaveCount(0);
      await expectSharedShows(visitor, snapshot, original, { code: share.code, title: defaultTitle }, `public link /s/${share.code}`);
      expect.soft(meta.expires_at, 'a link that never expires has no expiry time').toBeNull();
      const created = Date.parse(String(meta.created_at));
      expect.soft(Math.abs(created - startedAt), `created_at (${meta.created_at}) is the time the link was made (${new Date(startedAt).toISOString()})`).toBeLessThan(5 * 60_000);
      await expect.soft(dates(visitor.page), 'creation date under the title, no expiry').toHaveText(`Created: ${localDay(created)}`);
      await expect.soft(visitor.page, 'title of the shared page').toHaveTitle(/Shared Report/);
      expectVisitorClean(visitor, `visitor of /s/${share.code}`);
    } finally {
      await visitor.context.close();
    }
  });

  test('a link with a password hides the snapshot until the right password is entered; empty and wrong passwords are refused', async ({ page, browser, rng, evidence }, testInfo) => {
    const now = randomNow(rng);
    const snapshot = richSnapshot(rng, now);
    const password = `pw-${rng.string(10)}`;
    const title = `Locked report ${rng.string(6)}`;
    await evidence.save('whois-locked-share.json', { snapshot, password, title });
    await showSnapshot(page, snapshot, now);
    const original = await readView(page);

    await openDialog(page);
    // Spaces around the password are not part of it.
    const share = await generate(page, { title, password: `  ${password}  ` });
    expect.soft(share.request.password, 'share request: password without the surrounding spaces').toBe(password);

    const visitor = await newVisitor(browser, testInfo);
    visitor.allow(/status of 401/);
    const vp = visitor.page;
    const expectLocked = async (ctx: string) => {
      await expect(passwordPrompt(vp), `${ctx}: the password prompt is shown`).toBeVisible();
      await expect.soft(statCards(vp), `${ctx}: no snapshot card is shown`).toHaveCount(0);
      const text = (await vp.locator('main').textContent()) ?? '';
      for (const secret of [snapshot.domain, snapshot.registrar, snapshot.nameservers[0], snapshot.contacts.registrant.email]) {
        expect.soft(text.includes(secret), `${ctx}: "${secret}" from the snapshot must not be visible`).toBe(false);
      }
    };
    try {
      const { status, meta } = await openShared(visitor, share.code);
      expect(status, 'GET /api/share/<code> for a protected link').toBe(200);
      expect.soft(Object.keys(meta).sort(), 'metadata of a protected link carries no snapshot, domain or check time')
        .toEqual(['created_at', 'expires_at', 'has_password', 'password_required', 'share_type', 'title']);
      await expect.soft(header(vp), 'the title is shown above the prompt').toHaveText(title);
      await expectLocked('before any password');

      const attempt = async (value: string, via: 'button' | 'enter') => {
        await passwordBox(vp).fill(value);
        const answered = vp.waitForResponse(res => res.url().endsWith(`/api/share/${share.code}/verify`));
        if (via === 'enter') await passwordBox(vp).press('Enter'); else await unlockButton(vp).click();
        return (await answered).status();
      };

      expect.soft(await attempt('', 'button'), 'verify with an empty password: HTTP status').toBe(401);
      await expect.soft(sharedError(vp), 'empty password: message').toHaveText('⚠️ Password required.');
      await expectLocked('after an empty password');

      for (const wrong of [`${password}x`, password.toUpperCase(), password.slice(0, -1), 'password']) {
        expect.soft(await attempt(wrong, 'enter'), `verify with the wrong password "${wrong}": HTTP status`).toBe(401);
        await expect.soft(sharedError(vp), `wrong password "${wrong}": message`).toHaveText('⚠️ Incorrect password.');
        await expectLocked(`after the wrong password "${wrong}"`);
      }

      expect.soft(await attempt(password, 'enter'), 'verify with the right password: HTTP status').toBe(200);
      await expect(passwordPrompt(vp), 'the prompt goes away after the right password').toHaveCount(0);
      await expect.soft(sharedError(vp), 'the earlier error goes away').toHaveCount(0);
      await expectSharedShows(visitor, snapshot, original, { code: share.code, title }, `protected link /s/${share.code} after unlocking`);

      await vp.reload({ waitUntil: 'domcontentloaded' });
      await expectLocked('after reloading the unlocked page (the password is not remembered)');
      expectVisitorClean(visitor, `visitor of protected /s/${share.code}`);
    } finally {
      await visitor.context.close();
    }
  });

  test('each expiry choice stores that lifetime and the shared page shows the creation and expiry dates', async ({ page, browser, rng }, testInfo) => {
    const now = randomNow(rng);
    const snapshot = richSnapshot(rng, now);
    await showSnapshot(page, snapshot, now);
    await openDialog(page);

    const choices: { value: string; label: string; ms: number }[] = [
      { value: '24h', label: '24 hours', ms: 24 * 3_600_000 },
      { value: '7d', label: '7 days', ms: 7 * 86_400_000 },
      { value: '30d', label: '30 days', ms: 30 * 86_400_000 },
    ];
    const visitor = await newVisitor(browser, testInfo);
    try {
      for (const choice of choices) {
        await shareExpiry(page).selectOption({ label: choice.label });
        const share = await generate(page);
        expect.soft(share.request.expiry, `expiry "${choice.label}": value sent`).toBe(choice.value);

        const { meta } = await openShared(visitor, share.code);
        const created = Date.parse(String(meta.created_at));
        const expires = Date.parse(String(meta.expires_at));
        expect.soft(Math.abs(expires - created - choice.ms), `expiry "${choice.label}": expires_at (${meta.expires_at}) minus created_at (${meta.created_at}) must be ${choice.ms} ms, give or take 2 s`).toBeLessThanOrEqual(2000);
        await expect.soft(dates(visitor.page), `expiry "${choice.label}": dates under the title`).toHaveText(`Created: ${localDay(created)} · Expires: ${localDay(expires)}`);
        await expect.soft(statCards(visitor.page), `expiry "${choice.label}": the snapshot opens before it expires`).toHaveCount(5);

        await shareDialog(page).getByRole('button', { name: 'Create Another Link' }).click();
        await expect(shareSubmit(page), '"Create Another Link" returns to the form').toBeVisible();
      }
      expectVisitorClean(visitor, 'visitor of links with an expiry');
    } finally {
      await visitor.context.close();
    }
  });

  test('the share title is stored as typed (markup stays text, spaces trimmed) and a blank title falls back to the default', async ({ page, browser, rng }, testInfo) => {
    const now = randomNow(rng);
    const snapshot = richSnapshot(rng, now);
    await showSnapshot(page, snapshot, now);
    await openDialog(page);
    const typed = `  ${MARKUP} "Q3" audit, ${rng.string(6)} & co  `;
    const longTitle = `${'Long-title-'.repeat(40)}${rng.string(8)}`; // 448 characters: within the 500 the database stores
    const cases = [
      { typed, title: typed.trim() },
      { typed: '    ', title: `${snapshot.domain} WHOIS Snapshot` },
      { typed: longTitle, title: longTitle },
    ];

    const visitor = await newVisitor(browser, testInfo);
    try {
      for (const { typed: value, title } of cases) {
        const share = await generate(page, { title: value });
        expect.soft(share.request.title, `title typed as "${value}": title sent`).toBe(title);
        await openShared(visitor, share.code);
        await expect.soft(header(visitor.page), `title typed as "${value}": heading of the shared page`).toHaveText(title);
        await expect.soft(banner(visitor.page), `title typed as "${value}": banner`).toHaveText(`You are viewing ${title} - read-only registration data.`);
        await expectNoMarkupExecuted(visitor.page, `shared page titled "${title}"`);
        await shareDialog(page).getByRole('button', { name: 'Create Another Link' }).click();
      }
      expectVisitorClean(visitor, 'visitor of links with custom titles');
    } finally {
      await visitor.context.close();
    }
  });

  test('a title longer than the database stores is shortened or refused with a readable message, never a server error', async ({ page, rng, guard }) => {
    const now = randomNow(rng);
    const snapshot = richSnapshot(rng, now);
    await showSnapshot(page, snapshot, now);
    await openDialog(page);
    const title = 'T'.repeat(600);
    await shareTitle(page).fill(title);
    guard.allow(/status of (400|413|422|500)|HTTP 500/);
    const exchange = await captureApi<Record<string, unknown>>(page, '/api/share/whois', () => shareSubmit(page).click());
    await expect(shareDialog(page).getByText('Creating share link...')).toHaveCount(0);
    const dialogText = ((await shareDialog(page).textContent()) ?? '').replace(title, '');
    expect.soft(exchange.status, `sharing with a 600-character title: HTTP status (answer: ${JSON.stringify(exchange.response)})`).toBeLessThan(500);
    expect.soft(dialogText, 'the dialog must not show a database error to the user').not.toMatch(/column|data too long|sql|at row/i);
  });

  test('the shared view can re-run the lookup and export the snapshot', async ({ page, browser, rng, evidence }, testInfo) => {
    const now = randomNow(rng);
    const snapshot = randomSnapshot(rng, now, { hostile: true });
    await evidence.save('whois-shared-snapshot.json', snapshot);
    await showSnapshot(page, snapshot, now);
    await openDialog(page);
    const share = await generate(page);

    const visitor = await newVisitor(browser, testInfo);
    const vp = visitor.page;
    try {
      await openShared(visitor, share.code);
      await expect(statCards(vp)).toHaveCount(5);

      await clearClipboard(vp);
      await actionButton(vp, 'Copy Summary').click();
      await expect(actionButton(vp, 'Copied!')).toBeVisible();
      expect.soft(sameMonthSpelling(await readClipboard(vp)), 'summary copied from the shared view').toBe(expectedSummary(snapshot));

      const json = await captureDownload(vp, () => actionButton(vp, 'JSON').click());
      expect.soft(json.filename, 'JSON file name from the shared view').toBe(`${snapshot.domain}-whois-snapshot.json`);
      expect.soft(JSON.parse(json.text), 'JSON exported from the shared view equals the snapshot that was shared').toEqual(snapshot);
      const csv = await captureDownload(vp, () => actionButton(vp, 'CSV').click());
      expect.soft(csv.filename, 'CSV file name from the shared view').toBe(`${snapshot.domain}-whois-snapshot.csv`);
      const html = await captureDownload(vp, () => actionButton(vp, 'Download HTML').click());
      expect.soft(html.filename, 'HTML file name from the shared view').toBe(`${snapshot.domain}-whois-snapshot.html`);

      // Re-run starts a fresh lookup of the same domain on the live tool.
      const fresh = richSnapshot(rng, now, { domain: snapshot.domain });
      const calls = await mockApi(vp, API, fresh, { method: 'POST' });
      await actionButton(vp, 'Re-run Lookup').click();
      await expect(vp, 'Re-run Lookup opens the live tool for the domain').toHaveURL(new RegExp(`/whois\\?domain=${snapshot.domain.replace(/\./g, '\\.')}$`));
      await expect(vp.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
      await expect(cardValue(vp, 'Registrar'), 'the live tool shows the fresh answer, not the stored snapshot').toHaveText(fresh.registrar);
      expect.soft(calls.map(call => call.body), 'lookup sent by Re-run Lookup').toEqual([{ domain: snapshot.domain }]);
      await expect.soft(actionButton(vp, 'Share Snapshot'), 'the live tool offers sharing again').toBeVisible();
      expectVisitorClean(visitor, `visitor of /s/${share.code}`);
    } finally {
      await visitor.context.close();
    }
  });

  test('a link that does not exist, and one that has expired, show a message and no snapshot', async ({ browser, rng }, testInfo) => {
    const visitor = await newVisitor(browser, testInfo);
    visitor.allow(/status of (404|410)/);
    const vp = visitor.page;
    try {
      const unknown = `zz${rng.string(6, 'ABCDEFGHJKLMNPQRSTUVWXYZ')}`;
      const first = await openShared(visitor, unknown);
      expect.soft(first.status, `GET /api/share/${unknown} (never created)`).toBe(404);
      await expect.soft(sharedError(vp), 'unknown link: message').toHaveText('⚠️ Share not found.');
      await expect.soft(statCards(vp), 'unknown link: no snapshot').toHaveCount(0);
      await expect.soft(passwordPrompt(vp), 'unknown link: no password prompt').toHaveCount(0);

      // The backend answers 410 once expires_at has passed; that cannot be waited for, so the answer is played back.
      const expired = `ex${rng.string(6, 'ABCDEFGHJKLMNPQRSTUVWXYZ')}`;
      await mockApi(vp, `**/api/share/${expired}`, { error: 'This share link has expired.' }, { status: 410 });
      const second = await openShared(visitor, expired);
      expect.soft(second.status).toBe(410);
      await expect.soft(sharedError(vp), 'expired link: message').toHaveText('⚠️ This share link has expired.');
      await expect.soft(statCards(vp), 'expired link: no snapshot').toHaveCount(0);
      expectVisitorClean(visitor, 'visitor of missing and expired links');
    } finally {
      await visitor.context.close();
    }
  });
});

test.describe('WHOIS — share dialog behaviour', () => {
  test('the dialog closes by its close button and by the backdrop, and reopens with fresh defaults', async ({ page, rng }) => {
    const now = randomNow(rng);
    const snapshot = richSnapshot(rng, now);
    await showSnapshot(page, snapshot, now);
    const defaultTitle = `${snapshot.domain} WHOIS Snapshot`;

    await openDialog(page);
    await shareTitle(page).fill('changed title');
    await shareExpiry(page).selectOption('7d');
    await sharePassword(page).fill('typed-password');
    await shareClose(page).click();
    await expect(shareDialog(page), 'the close button closes the dialog').toHaveCount(0);
    await expect.soft(statCards(page), 'the result is still on screen behind the dialog').toHaveCount(5);

    await openDialog(page);
    await expect.soft(shareTitle(page), 'title after reopening').toHaveValue(defaultTitle);
    await expect.soft(shareExpiry(page), 'expiry after reopening').toHaveValue('never');
    await expect.soft(sharePassword(page), 'password after reopening').toHaveValue('');

    await shareDialog(page).click({ position: { x: 6, y: 6 } });
    await expect(shareDialog(page), 'clicking the backdrop closes the dialog').toHaveCount(0);

    await openDialog(page);
    await shareDialog(page).getByRole('heading', { name: 'Share WHOIS Snapshot' }).click();
    await expect(shareDialog(page), 'clicking inside the dialog keeps it open').toBeVisible();
  });

  test('while the link is created the form is replaced by a progress note; a failure shows its message, keeps the form, and a retry works', async ({ page, rng, guard }) => {
    const now = randomNow(rng);
    const snapshot = richSnapshot(rng, now);
    await showSnapshot(page, snapshot, now);
    guard.allow(/status of (400|500|502)|HTTP 50\d|ERR_FAILED|Failed to fetch/);
    const hold = deferred();
    const failures: { reply: ScriptedReply; shows: RegExp; why: string }[] = [
      { reply: { status: 500, body: { success: false, error: 'Could not generate unique code. Try again.' } }, shows: /Could not generate unique code\. Try again\./, why: 'HTTP 500 with a message' },
      { reply: { status: 400, body: { success: false, error: 'Missing domain.' } }, shows: /Missing domain\./, why: 'HTTP 400 with a message' },
      { reply: { status: 502, body: '<html>Bad Gateway</html>', contentType: 'text/html' }, shows: /502/, why: 'HTTP 502 without JSON' },
      { reply: { abort: true }, shows: /\S/, why: 'network failure' },
    ];
    const api = await scriptApi(page, SHARE_API, async (_call, index): Promise<ScriptedReply> => {
      if (index === 0) await hold.promise;
      return failures[index]?.reply ?? { body: { success: true, code: 'Abc12345', url: '/s/Abc12345' } };
    });

    await openDialog(page);
    await shareTitle(page).fill('Kept title');
    await sharePassword(page).fill('kept-password');
    const cleanText = ((await shareDialog(page).textContent()) ?? '').trim();

    await shareSubmit(page).click();
    await expect(shareDialog(page).getByText('Creating share link...'), 'progress note while the link is created').toBeVisible();
    await expect.soft(shareSubmit(page), 'the form is hidden while the link is created').toHaveCount(0);
    hold.resolve();

    for (const [i, failure] of failures.entries()) {
      if (i > 0) await shareSubmit(page).click();
      await expect(shareSubmit(page), `${failure.why}: the form is back`).toBeVisible();
      const extra = insertedText(cleanText, ((await shareDialog(page).textContent()) ?? '').trim());
      expect.soft(extra, `${failure.why}: the message added to the dialog`).toMatch(failure.shows);
      await expect.soft(shareLink(page), `${failure.why}: no link is shown`).toHaveCount(0);
      await expect.soft(shareTitle(page), `${failure.why}: the typed title is kept`).toHaveValue('Kept title');
      await expect.soft(sharePassword(page), `${failure.why}: the typed password is kept`).toHaveValue('kept-password');
    }

    await shareSubmit(page).click();
    await expect(shareDialog(page).getByText('Share link created!')).toBeVisible();
    await expect.soft(shareLink(page), 'link after a successful retry').toHaveText(`${new URL(page.url()).origin}/s/Abc12345`);
    expect.soft(api.calls.length, 'one request per press of Generate Share Link').toBe(failures.length + 1);
    const sent = api.calls.at(-1)!.body as Record<string, unknown>;
    expect.soft([sent.title, sent.password, sent.expiry, sent.domain], 'final request: title, password, expiry, domain').toEqual(['Kept title', 'kept-password', 'never', snapshot.domain]);
  });
});

test.describe('WHOIS — share layout', () => {
  test('the share dialog has no layout problems at desktop, laptop and mobile size (form, creating, failed, created link)', async ({ page, rng, guard }) => {
    const now = randomNow(rng);
    const snapshot = richSnapshot(rng, now);
    await showSnapshot(page, snapshot, now);
    guard.allow(/status of 500|HTTP 500/);
    // Per viewport: the first press of Generate is held and then fails, the second succeeds.
    const holds = Object.keys(VIEWPORTS).map(() => deferred());
    await scriptApi(page, SHARE_API, async (_call, index): Promise<ScriptedReply> => {
      if (index % 2 === 1) return { body: { success: true, code: 'Lay0ut12', url: '/s/Lay0ut12' } };
      await holds[index / 2].promise;
      return { status: 500, body: { success: false, error: 'Could not generate unique code. Try again.' } };
    });

    for (const [i, [name, viewport]] of Object.entries(VIEWPORTS).entries()) {
      await page.setViewportSize(viewport);
      await openDialog(page);
      await expectNoUiGlitchesAtRest(page, `share dialog, form @${name}`, { scope: SHARE_DIALOG });
      await shareSubmit(page).click();
      await expect(shareDialog(page).getByText('Creating share link...')).toBeVisible();
      await expectNoUiGlitchesAtRest(page, `share dialog, creating @${name}`, { scope: SHARE_DIALOG });
      holds[i].resolve();
      await expect(shareDialog(page).getByText('Could not generate unique code. Try again.')).toBeVisible();
      await expectNoUiGlitchesAtRest(page, `share dialog, failed @${name}`, { scope: SHARE_DIALOG });
      await shareSubmit(page).click();
      await expect(shareDialog(page).getByText('Share link created!')).toBeVisible();
      await expectNoUiGlitchesAtRest(page, `share dialog, link created @${name}`, { scope: SHARE_DIALOG });
      await shareClose(page).click();
      await expect(shareDialog(page)).toHaveCount(0);
    }
  });

  test('the shared page has no layout problems at desktop, laptop and mobile size (locked, wrong password, unlocked)', async ({ page, browser, rng }, testInfo) => {
    const now = randomNow(rng);
    const snapshot = randomSnapshot(rng, now, { long: true, hostile: true, contacts: ['hostile', 'full', 'partial'], statuses: 6, registered: true });
    await showSnapshot(page, snapshot, now);
    await openDialog(page);
    const share = await generate(page, { password: 'layout-pass', expiry: '7d' });

    const visitor = await newVisitor(browser, testInfo);
    visitor.allow(/status of 401/);
    const vp = visitor.page;
    try {
      for (const [name, viewport] of Object.entries(VIEWPORTS)) {
        await vp.setViewportSize(viewport);
        await openShared(visitor, share.code);
        await expect(passwordPrompt(vp)).toBeVisible();
        await expectNoUiGlitchesAtRest(vp, `/s/<code> locked @${name}`);
        await passwordBox(vp).fill('not-the-password');
        await unlockButton(vp).click();
        await expect(sharedError(vp)).toBeVisible();
        await expectNoUiGlitchesAtRest(vp, `/s/<code> after a wrong password @${name}`);
        await passwordBox(vp).fill('layout-pass');
        await unlockButton(vp).click();
        await expect(statCards(vp)).toHaveCount(5);
        await actionButton(vp, /Show Raw/).click();
        await expectNoUiGlitchesAtRest(vp, `/s/<code> unlocked, long values, raw record open @${name}`);
      }
      expectVisitorClean(visitor, 'visitor of the shared page');
    } finally {
      await visitor.context.close();
    }
  });
});
