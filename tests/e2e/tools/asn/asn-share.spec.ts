import type { Browser, BrowserContext, Page } from '@playwright/test';
import { test, expect } from '../_support/fixtures';
import { captureApi, captureDownload, failApi, mockApi, readClipboard } from '../_support/io';
import { waitForHydration } from '../_support/navigation';
import { expectNoUiGlitches, VIEWPORTS } from '../_support/ui-audit';
import { addressCases, randomScenario, type Scenario } from './generator';
import { type ExplorerState, browserDate, containing, explorerList, maskDistribution, ruleProblems, utcDate } from './oracle';
import { DEFAULT_EXPLORER, applyExplorerState, expectExplorer, expectOverview, expectPrefixCsv, expectReport, openWith } from './checks';
import { AsnView, LOOKUP_API, SHARE_API, SHARE_DIALOG_CSS, ShareDialog, SharedPage, primary } from './page';

/**
 * Share Snapshot: the dialog on /asn, POST /api/share/asn and the shared view
 * /s/<code>. The lookup is mocked (so the snapshot is known exactly); the share
 * itself is stored and read back through the REAL backend and database, and
 * opened by a second browser context, as another visitor would.
 */

interface Visitor { context: BrowserContext; page: Page; shared: SharedPage; problems: string[] }

/** A different visitor: fresh context, same time zone and locale as the suite, with its own error watch. */
async function openVisitor(browser: Browser, allowed: RegExp[] = []): Promise<Visitor> {
  const context = await browser.newContext({
    viewport: VIEWPORTS.desktop,
    timezoneId: process.env.E2E_TIMEZONE ?? 'America/New_York',
    locale: 'en-US',
    permissions: ['clipboard-read', 'clipboard-write'],
    acceptDownloads: true,
  });
  const page = await context.newPage();
  const problems: string[] = [];
  const record = (text: string) => { if (!allowed.some(re => re.test(text))) problems.push(text); };
  page.on('pageerror', err => record(`uncaught exception: ${err.message}`));
  page.on('console', msg => { if (msg.type() === 'error') record(`console.error: ${msg.text()}`); });
  page.on('response', res => { if (res.status() >= 500) record(`HTTP ${res.status()}: ${res.url()}`); });
  return { context, page, shared: new SharedPage(page), problems };
}

async function visit(visitor: Visitor, url: string): Promise<void> {
  const response = await visitor.page.goto(url, { waitUntil: 'domcontentloaded' });
  expect(response?.status(), `${url} should answer 200`).toBe(200);
  await waitForHydration(visitor.page);
}

/** Looks `scenario` up on /asn (mocked) and creates a share for it through the real backend. */
async function createShare(page: Page, scenario: Scenario, options: Parameters<ShareDialog['create']>[0] = {}): Promise<{ url: string; code: string; view: AsnView }> {
  const { view } = await openWith(page, scenario);
  await view.shareButton().click();
  const url = await new ShareDialog(page).create(options);
  return { url, code: url.split('/s/')[1], view };
}

test.describe('ASN share — dialog', () => {
  test('proposes a title, offers four expiry options, and closes without sharing by Cancel, ✕ or a click outside', async ({ page, rng }) => {
    const scenario = randomScenario(rng, { v4Count: 4, v6Count: 1 });
    const shareCalls = await mockApi(page, SHARE_API, { success: true, code: 'Unused001', url: '/s/Unused001' }, { method: 'POST' });
    const { view } = await openWith(page, scenario);
    const dialog = new ShareDialog(page);
    await expect(dialog.heading(), 'no dialog before Share is pressed').toHaveCount(0);

    for (const close of ['Cancel', '✕', 'outside'] as const) {
      await view.shareButton().click();
      await expect(dialog.heading()).toBeVisible();
      await expect.soft(dialog.titleInput(), `opened before "${close}": proposed title`).toHaveValue(`AS${scenario.asn} - ${scenario.holder} Intelligence Snapshot`);
      await expect.soft(dialog.expirySelect(), 'default expiry').toHaveValue('never');
      await expect.soft(dialog.passwordInput(), 'password starts empty').toHaveValue('');
      await expect.soft(dialog.passwordInput(), 'password is masked').toHaveAttribute('type', 'password');
      expect.soft(await dialog.expirySelect().locator('option').allTextContents(), 'expiry options').toEqual(['Never expire', '24 Hours', '7 Days', '30 Days']);
      expect.soft(await dialog.expirySelect().locator('option').evaluateAll(options => options.map(o => (o as HTMLOptionElement).value)), 'expiry values').toEqual(['never', '24h', '7d', '30d']);

      // Leave something behind; the next opening must not show it.
      await dialog.titleInput().fill('edited title');
      await dialog.expirySelect().selectOption('7d');
      await dialog.passwordInput().fill('secret');
      if (close === 'Cancel') await dialog.cancelButton().click();
      else if (close === '✕') await dialog.xButton().click();
      else await dialog.backdrop().click({ position: { x: 5, y: 5 } });
      await expect(dialog.heading(), `"${close}" closes the dialog`).toHaveCount(0);
    }
    expect(shareCalls.length, 'closing the dialog shares nothing').toBe(0);
    await expect(view.badge(), 'the result stays on screen').toHaveText(`AS${scenario.asn}`);
  });

  test('sends title, ASN, expiry, password and the whole snapshot, then shows a link that can be copied', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: rng.int(6, 14), v6Count: rng.int(2, 5) });
    await evidence.save('asn-response.json', scenario.payload);
    const { view } = await openWith(page, scenario);
    const dialog = new ShareDialog(page);
    const title = `Incident ${rng.string(6)} — AS${scenario.asn}`;
    const password = rng.string(10);
    const expiry = rng.pick(['24h', '7d', '30d'] as const);

    await view.shareButton().click();
    await dialog.titleInput().fill(`  ${title}  `);
    await dialog.expirySelect().selectOption(expiry);
    await dialog.passwordInput().fill(`  ${password} `);
    const exchange = await captureApi<{ success: boolean; code: string; url: string }>(page, SHARE_API, () => dialog.generateButton().click());
    expect(exchange.status, 'POST /api/share/asn status').toBe(200);
    const body = exchange.request as Record<string, any>;
    expect.soft(body.title, 'request: title (trimmed)').toBe(title);
    expect.soft(body.asn, 'request: asn').toBe(scenario.asn);
    expect.soft(body.expiry, 'request: expiry').toBe(expiry);
    expect.soft(body.password, 'request: password (trimmed)').toBe(password);
    expect.soft(body.checked_at_utc, 'request: checked_at_utc of the lookup').toBe(scenario.payload.checked_at_utc);
    for (const key of ['asn', 'holder', 'name', 'description', 'country_code', 'rir', 'announced', 'abuse_emails', 'neighbours', 'ipv4_prefixes', 'ipv6_prefixes', 'aggregated_ipv4', 'stats', 'checked_at_utc']) {
      expect.soft(body.snapshot?.[key], `request: snapshot.${key} equals the lookup response`).toEqual(scenario.payload[key]);
    }

    expect.soft(exchange.response.success, 'response: success').toBe(true);
    expect.soft(exchange.response.code, 'response: code is 8 letters or digits').toMatch(/^[A-Za-z0-9]{8}$/);
    expect.soft(exchange.response.url, 'response: url').toBe(`/s/${exchange.response.code}`);
    await expect(dialog.readyHeading()).toBeVisible();
    await expect.soft(dialog.linkInput(), 'link shown in the dialog').toHaveValue(`${new URL(page.url()).origin}/s/${exchange.response.code}`);
    await expect.soft(dialog.card().getByText(`Anyone with this link can view the frozen AS${scenario.asn} snapshot.`), 'confirmation names the network').toBeVisible();

    await page.evaluate(() => navigator.clipboard.writeText('not copied yet'));
    await dialog.copyButton().click();
    await expect.soft(dialog.copyButton(), 'Copy confirms').toHaveText(/Copied!/);
    expect.soft(await readClipboard(page), 'clipboard after Copy').toBe(await dialog.linkInput().inputValue());
    await dialog.closeButton().click();
    await expect(dialog.heading()).toHaveCount(0);

    // An empty title falls back to a generic one.
    await view.shareButton().click();
    await expect.soft(dialog.readyHeading(), 'reopening starts a new share, not the old link').toHaveCount(0);
    await dialog.titleInput().fill('   ');
    const second = await captureApi(page, SHARE_API, () => dialog.generateButton().click());
    expect.soft((second.request as Record<string, any>).title, 'request: title when the box is blank').toBe(`AS${scenario.asn} Snapshot`);
    expect.soft((second.request as Record<string, any>).password, 'request: no password').toBe('');
    expect.soft((second.request as Record<string, any>).expiry, 'request: default expiry').toBe('never');
  });

  test('a failed share request shows the error in the dialog and a retry works', async ({ page, rng, guard }) => {
    guard.allow(/status of 500|HTTP 500|ERR_FAILED/);
    const scenario = randomScenario(rng, { v4Count: 3, v6Count: 1 });
    const { view } = await openWith(page, scenario);
    const dialog = new ShareDialog(page);
    await mockApi(page, SHARE_API, { success: false, error: 'Could not generate unique code. Try again.' }, { method: 'POST', status: 500 });
    await view.shareButton().click();
    await dialog.generateButton().click();
    await expect(dialog.error(), 'HTTP 500: error text in the dialog').toHaveText('Could not generate unique code. Try again.');
    await expect.soft(dialog.generateButton(), 'the button is usable again').toHaveText('Generate Share Link');
    await expect.soft(dialog.generateButton()).toBeEnabled();
    await expect.soft(dialog.readyHeading(), 'no link after a failure').toHaveCount(0);

    await page.unroute(SHARE_API);
    await failApi(page, SHARE_API);
    await dialog.generateButton().click();
    await expect(dialog.error(), 'network failure: an error is shown').toHaveText(/\S{3,}/);
    await expect.soft(dialog.readyHeading()).toHaveCount(0);

    await page.unroute(SHARE_API);
    await dialog.generateButton().click();
    await expect(dialog.readyHeading(), 'the retry reaches the real backend and succeeds').toBeVisible();
    await expect.soft(dialog.error(), 'the error is gone').toHaveCount(0);
  });

  test('has no layout problems at desktop, laptop and mobile size, as form and with the link', async ({ page, rng }) => {
    const scenario = randomScenario(rng, { v4Count: 4, v6Count: 1 });
    await mockApi(page, SHARE_API, { success: true, code: 'Layout01', url: '/s/Layout01' }, { method: 'POST' });
    const { view } = await openWith(page, scenario);
    const dialog = new ShareDialog(page);
    for (const [name, viewport] of Object.entries(VIEWPORTS)) {
      await page.setViewportSize(viewport);
      await view.shareButton().click();
      await expect(dialog.heading()).toBeVisible();
      await expectNoUiGlitches(page, `share dialog, form @${name}`, { scope: SHARE_DIALOG_CSS });
      await dialog.create({ password: 'layout' });
      await expectNoUiGlitches(page, `share dialog, link ready @${name}`, { scope: SHARE_DIALOG_CSS });
      await dialog.closeButton().click();
    }
  });
});

test.describe('ASN share — shared view for another visitor', () => {
  test('without a password the shared view shows the same network, prefix for prefix, and its own controls work', async ({ page, browser, rng, evidence }) => {
    const startedAt = new Date();
    const scenario = randomScenario(rng, { v4Count: rng.int(30, 45), v6Count: rng.int(5, 9) });
    await evidence.save('asn-response.json', scenario.payload);
    const title = `Shared ${rng.string(8)}`;
    const { url, code } = await createShare(page, scenario, { title });
    await evidence.save('share.json', { url, title });

    const visitor = await openVisitor(browser);
    await visit(visitor, url);
    const { shared } = visitor;
    const view = shared.view;
    const ctx = `shared view /s/${code}`;
    await expect(view.badge(), `${ctx}: the snapshot is shown without a password`).toHaveText(`AS${scenario.asn}`);
    await expect.soft(shared.passwordHeading(), `${ctx}: no password prompt`).toHaveCount(0);
    await expect.soft(shared.title(), `${ctx}: page title`).toHaveText(title);
    await expect.soft(shared.readOnlyBadge(), `${ctx}: read-only badge`).toBeVisible();
    expect.soft([`Created: ${browserDate(startedAt)}`, `Created: ${browserDate(new Date())}`], `${ctx}: creation date in the visitor's time zone, no expiry`)
      .toContain(((await shared.dates().textContent()) || '').trim());
    await expect.soft(view.shareCode(), `${ctx}: share code in the footer`).toHaveText(`Share Code: ${code}`);
    await expect.soft(view.shareButton(), `${ctx}: a shared snapshot cannot be shared again`).toHaveCount(0);
    await expect.soft(view.rerunButton(), `${ctx}: Run Live Lookup is offered`).toBeVisible();

    // Same numbers as the original.
    await expectOverview(view, scenario, ctx, { title });
    await expectExplorer(view, scenario, DEFAULT_EXPLORER, ctx);

    // The shared view has its own filters: use them.
    const states: ExplorerState[] = [
      { ...DEFAULT_EXPLORER, version: 'ipv6' },
      { ...DEFAULT_EXPLORER, version: 'ipv4', aggregated: true },
      { ...DEFAULT_EXPLORER, mask: rng.pick(maskDistribution(scenario.v4))[0] },
      { ...DEFAULT_EXPLORER, query: scenario.v4[rng.int(0, scenario.v4.length - 1)].text.slice(0, 5) },
      DEFAULT_EXPLORER,
    ];
    let state: ExplorerState = DEFAULT_EXPLORER;
    for (const next of states) {
      await applyExplorerState(view, state, next);
      state = next;
      await expectExplorer(view, scenario, state, ctx);
    }

    // Outputs of the shared view.
    const csv = await captureDownload(visitor.page, () => view.csvButton().click());
    expect.soft(csv.filename, `${ctx}: CSV file name`).toBe(`AS${scenario.asn}-prefixes.csv`);
    expectPrefixCsv(csv.text, scenario, explorerList(scenario.v4, scenario.aggregated, scenario.v6, DEFAULT_EXPLORER), `${ctx}: CSV`);
    await view.copySummaryButton().click();
    await expect(view.copySummaryButton()).toHaveText(/Copied!/);
    expectReport(await readClipboard(visitor.page), scenario, `${ctx}: Copy Summary`);

    await view.tab('firewall').click();
    const rules = await view.readRules();
    const selected = [...scenario.aggregated, ...scenario.v6];
    expect.soft(ruleProblems('nginx', rules, { action: 'deny', asn: scenario.asn, org: scenario.holder, prefixes: selected, dates: [utcDate(new Date()), utcDate(startedAt)] }),
      `${ctx}: default firewall rules (nginx, deny, merged IPv4 + IPv6)`).toEqual([]);

    await view.tab('tester').click();
    for (const item of addressCases(rng, scenario.v4, 4, 2)) {
      const result = await view.testAddress(item.ip);
      expect.soft(result.matched, `${ctx}: IP tester for ${item.ip} (${item.note})`).toBe(containing(scenario.v4, 4, item.value).length > 0);
    }

    await view.tab('bgp').click();
    const peers = await view.readTopPeers();
    expect.soft(peers.map(p => p.asn), `${ctx}: top neighbours`).toEqual(scenario.payload.neighbours.top_peers.map((p: any) => `AS${p.asn}`));
    await expect.soft(view.inspectButtons(), `${ctx}: no Inspect buttons on a frozen snapshot`).toHaveCount(0);
    await expect.soft(view.contactField('Network Holder / Org'), `${ctx}: holder`).toHaveText(scenario.holder);

    expect.soft(visitor.problems, `${ctx}: browser errors in the visitor's page`).toEqual([]);
    await visitor.context.close();
  });

  test('Run Live Lookup on a shared snapshot opens /asn with that ASN and looks it up', async ({ page, browser, rng }) => {
    const scenario = randomScenario(rng, { v4Count: 5, v6Count: 2 });
    const { url } = await createShare(page, scenario);
    const visitor = await openVisitor(browser);
    const calls = await mockApi(visitor.page, LOOKUP_API, scenario.payload, { method: 'POST' });
    await visit(visitor, url);
    await expect(visitor.shared.view.badge()).toHaveText(`AS${scenario.asn}`);
    await visitor.shared.view.rerunButton().click();
    await expect(visitor.page, 'Run Live Lookup navigates to the tool with the ASN in the link').toHaveURL(new RegExp(`/asn\\?asn=${scenario.asn}$`));
    const live = new AsnView(visitor.page, primary(visitor.page));
    await expect(live.badge(), 'the live lookup runs by itself').toHaveText(`AS${scenario.asn}`);
    expect.soft(calls.map(c => c.body), 'lookup request sent by the link').toEqual([{ asn: scenario.asn }]);
    await expect.soft(live.shareButton(), 'the live result can be shared again').toBeVisible();
    expect.soft(visitor.problems, 'browser errors in the visitor\'s page').toEqual([]);
    await visitor.context.close();
  });

  test('with a password the snapshot stays hidden until the right password is entered; a wrong or empty one is refused', async ({ page, browser, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: rng.int(8, 16), v6Count: rng.int(2, 5) });
    await evidence.save('asn-response.json', scenario.payload);
    const password = `pw-${rng.string(10)}`;
    const title = `Protected ${rng.string(6)}`;
    const { url, code } = await createShare(page, scenario, { title, password });
    await evidence.save('share.json', { url, title, password });

    const visitor = await openVisitor(browser, [/status of 401/]);
    const { shared } = visitor;
    const metadata = visitor.page.waitForResponse(res => res.url().endsWith(`/api/share/${code}`));
    await visit(visitor, url);
    const meta = await (await metadata).json();
    expect.soft(Object.keys(meta).sort(), 'GET /api/share/<code> of a protected share returns no snapshot data').toEqual(['created_at', 'expires_at', 'has_password', 'password_required', 'share_type', 'title']);

    const expectLocked = async (when: string) => {
      await expect(shared.passwordHeading(), `${when}: password prompt`).toBeVisible();
      await expect.soft(shared.view.table(), `${when}: no prefix table`).toHaveCount(0);
      await expect.soft(shared.view.tab('prefixes'), `${when}: no result tabs`).toHaveCount(0);
      const text = (await visitor.page.locator('main').textContent()) || '';
      for (const prefix of [...scenario.v4, ...scenario.v6].slice(0, 6)) {
        expect.soft(text.includes(prefix.text), `${when}: prefix ${prefix.text} must not be on the page`).toBe(false);
      }
      expect.soft(text.includes(scenario.holder), `${when}: the holder name must not be on the page`).toBe(false);
    };
    await expectLocked('before a password');
    await expect.soft(shared.title(), 'the title is shown above the prompt').toHaveText(title);

    for (const [wrong, message] of [[`${password}x`, 'Incorrect password.'], [password.toUpperCase(), 'Incorrect password.'], ['', 'Password required.']] as const) {
      await shared.passwordInput().fill(wrong);
      await shared.unlockButton().click();
      await expect(shared.error(), `password ${JSON.stringify(wrong)} must be refused`).toContainText(message);
      await expectLocked(`after password ${JSON.stringify(wrong)}`);
    }

    await shared.passwordInput().fill(password);
    await shared.passwordInput().press('Enter');
    const view = shared.view;
    await expect(view.badge(), 'the right password (with Enter) opens the snapshot').toHaveText(`AS${scenario.asn}`);
    await expect.soft(shared.passwordHeading(), 'the prompt is gone').toHaveCount(0);
    await expect.soft(shared.error(), 'the earlier error is gone').toHaveCount(0);
    await expectOverview(view, scenario, `protected share /s/${code}`, { title });
    await expectExplorer(view, scenario, DEFAULT_EXPLORER, `protected share /s/${code}`);
    await expect.soft(view.shareCode()).toHaveText(`Share Code: ${code}`);
    expect.soft(visitor.problems, 'browser errors in the visitor\'s page (401 answers are expected)').toEqual([]);
    await visitor.context.close();
  });

  test('the shared view shows the creation date and, for 24 hours / 7 days / 30 days, the expiry date', async ({ page, browser, rng }) => {
    const scenario = randomScenario(rng, { v4Count: 3, v6Count: 1 });
    const { view } = await openWith(page, scenario);
    const dialog = new ShareDialog(page);
    const day = 24 * 60 * 60 * 1000;
    const options: [{ expiry: 'never' | '24h' | '7d' | '30d' }, number | null][] = [[{ expiry: 'never' }, null], [{ expiry: '24h' }, 1], [{ expiry: '7d' }, 7], [{ expiry: '30d' }, 30]];
    const visitor = await openVisitor(browser);
    for (const [option, days] of options) {
      const before = new Date();
      await view.shareButton().click();
      const url = await dialog.create(option);
      const after = new Date();
      await dialog.closeButton().click();
      await visit(visitor, url);
      await expect(visitor.shared.view.badge()).toHaveText(`AS${scenario.asn}`);
      const line = (at: Date) => `Created: ${browserDate(at)}${days === null ? '' : ` · Expires: ${browserDate(new Date(at.getTime() + days * day))}`}`;
      expect.soft([line(before), line(after)], `expiry "${option.expiry}": dates under the title (visitor's time zone ${process.env.E2E_TIMEZONE ?? 'America/New_York'})`)
        .toContain(((await visitor.shared.dates().textContent()) || '').trim());
    }
    expect.soft(visitor.problems, 'browser errors in the visitor\'s page').toEqual([]);
    await visitor.context.close();
  });

  test('markup in the share title is shown as text in the shared view', async ({ page, browser, rng }) => {
    const scenario = randomScenario(rng, { v4Count: 3, v6Count: 1, holder: '<img src=x onerror=alert(1)>' });
    const title = '<img src=x onerror=alert(1)><b>bold</b>';
    const { url } = await createShare(page, scenario, { title });
    const visitor = await openVisitor(browser);
    const dialogs: string[] = [];
    visitor.page.on('dialog', dialog => { dialogs.push(dialog.message()); void dialog.dismiss(); });
    await visit(visitor, url);
    await expect(visitor.shared.view.badge()).toHaveText(`AS${scenario.asn}`);
    await expect.soft(visitor.shared.title(), 'title as text').toHaveText(title);
    await expect.soft(visitor.shared.view.heading(), 'snapshot heading as text').toHaveText(title);
    await visitor.shared.view.tab('bgp').click();
    await expect.soft(visitor.shared.view.contactField('Network Holder / Org'), 'holder as text').toHaveText(scenario.holder);
    expect.soft(await visitor.page.locator('img[src="x"], main b').count(), 'no element created from the title or the holder').toBe(0);
    expect.soft(dialogs, 'no script may run').toEqual([]);
    expect.soft(visitor.problems, 'browser errors in the visitor\'s page').toEqual([]);
    await visitor.context.close();
  });

  test('an unknown share code shows "Share not found." and no snapshot', async ({ browser, baseURL, rng }) => {
    const visitor = await openVisitor(browser, [/status of 404/]);
    await visit(visitor, `${baseURL}/s/zz${rng.string(6, 'ABCDEFGHJKLMNPQRSTUVWXYZ')}`);
    await expect(visitor.shared.error(), 'error for an unknown code').toContainText('Share not found.');
    await expect.soft(visitor.shared.view.table()).toHaveCount(0);
    await expect.soft(visitor.shared.passwordHeading()).toHaveCount(0);
    expect.soft(visitor.problems, 'browser errors in the visitor\'s page (the 404 is expected)').toEqual([]);
    await visitor.context.close();
  });

  test('has no layout problems at desktop, laptop and mobile size: password prompt, refused password, every tab', async ({ page, browser, rng }) => {
    const scenario = randomScenario(rng, { v4Count: 34, v6Count: 6 });
    const { url } = await createShare(page, scenario, { password: 'layout-pass', title: `Layout ${rng.string(5)}` });
    const visitor = await openVisitor(browser, [/status of 401/]);
    const { shared } = visitor;
    for (const [name, viewport] of Object.entries(VIEWPORTS)) {
      const at = (state: string) => `shared view, ${state} @${name}`;
      await visitor.page.setViewportSize(viewport);
      await visit(visitor, url);
      await expect(shared.passwordHeading()).toBeVisible();
      await expectNoUiGlitches(visitor.page, at('password prompt'));
      await shared.passwordInput().fill('wrong');
      await shared.unlockButton().click();
      await expect(shared.error()).toBeVisible();
      await expectNoUiGlitches(visitor.page, at('refused password'));
      await shared.passwordInput().fill('layout-pass');
      await shared.unlockButton().click();
      await expect(shared.view.badge()).toHaveText(`AS${scenario.asn}`);
      await expectNoUiGlitches(visitor.page, at('prefix explorer'));
      await shared.view.aggregateToggle().click();
      await expectNoUiGlitches(visitor.page, at('aggregated supernets'));
      for (const tab of ['firewall', 'tester', 'bgp'] as const) {
        await shared.view.tab(tab).click();
        if (tab === 'tester') await shared.view.testAddress('198.51.100.9');
        await expectNoUiGlitches(visitor.page, at(`${tab} tab`));
      }
    }
    expect.soft(visitor.problems, 'browser errors in the visitor\'s page (401 for the wrong password is expected)').toEqual([]);
    await visitor.context.close();
  });
});
