import { test, expect, type Page, type TestInfo } from '../_support/fixtures';
import type { Browser, BrowserContext } from '@playwright/test';
import { openTool } from '../_support/navigation';
import { expectNoUiGlitches, VIEWPORTS } from '../_support/ui-audit';
import { captureApi, captureDownload, clearClipboard, mockApi, readClipboard } from '../_support/io';
import { parseCsv } from '../_support/csv';
import { emptyPayload, fullPayload, generatePayload, publicIpv6 } from './generator';
import {
  DASH, expectedCsv, expectedReport, fileStem, flagOf, httpDate, networkLabel, shortDate, stackLabel, type MyIpPayload,
} from './oracle';
import {
  HEADING, ROUTE, addressCard, copyAddressButton, csvButton, generateLinkButton, htmlButton, openWith, readAddressCard,
  readSections, readSharedSections, recordMyIpResponses, rowsToRecord, shareButton, shareDialog, shareExpirySelect,
  shareLinkText, sharePasswordInput, shareTitleInput, waitForResult,
} from './page';

/**
 * /myip — everything that leaves the page: clipboard, CSV, HTML report and
 * share links (created through the real backend and opened by a second
 * visitor in a new browser context). Inventory and layer map: see myip.spec.ts.
 */

const TIME_ZONE = process.env.E2E_TIMEZONE ?? 'America/New_York';
/** The share dialog is the only plain <div> directly under the workspace shell; the audit looks at it alone. */
const DIALOG_SCOPE = '.signal-workspace > div';

interface Visitor { context: BrowserContext; page: Page; problems: string[] }

/** A second visitor: a fresh browser context with the same site, time zone and language, watched for page errors. */
async function newVisitor(browser: Browser, testInfo: TestInfo): Promise<Visitor> {
  const use = testInfo.project.use;
  const context = await browser.newContext({ baseURL: use.baseURL, timezoneId: use.timezoneId, locale: use.locale, viewport: use.viewport ?? undefined });
  const page = await context.newPage();
  const problems: string[] = [];
  page.on('pageerror', error => problems.push(`uncaught exception: ${error.message}`));
  page.on('console', message => { if (message.type() === 'error') problems.push(`console.error: ${message.text()}`); });
  return { context, page, problems };
}

interface OriginalView { device: Record<string, string>; connection: Record<string, string>; headers: Record<string, string> }

async function readOriginal(page: Page): Promise<OriginalView> {
  const sections = await readSections(page);
  return {
    device: rowsToRecord(sections['Browser & Device']),
    connection: rowsToRecord(sections['Browser-Estimated Connection']),
    headers: rowsToRecord(sections['HTTP Request Headers']),
  };
}

/** Creates a share link through the dialog and returns its code and the request the page sent. */
async function createShare(page: Page, options: { title?: string; expiry?: string; password?: string } = {}) {
  await shareButton(page).click();
  await expect(shareDialog(page)).toBeVisible();
  if (options.title !== undefined) await shareTitleInput(page).fill(options.title);
  if (options.expiry) await shareExpirySelect(page).selectOption(options.expiry);
  if (options.password !== undefined) await sharePasswordInput(page).fill(options.password);
  const exchange = await captureApi<{ success: boolean; code: string; url: string }>(page, '/api/share/myip', () => generateLinkButton(page).click());
  await expect(shareDialog(page).getByText('Share link created!')).toBeVisible();
  const link = (await shareLinkText(page).innerText()).trim();
  return { exchange, link, code: exchange.response.code };
}

/** Compares the shared view with the payload and with what the original page showed. */
async function expectSharedView(shared: Page, payload: MyIpPayload, original: OriginalView, addresses: { ipv4: string | null; ipv6: string | null }, title: string, ctx: string) {
  await expect(addressCard(shared), `${ctx}: the shared address card`).toBeVisible();
  const card = await readAddressCard(shared);
  expect.soft(card.ipv4.value, `${ctx}: shared IPv4 box`).toMatch(addresses.ipv4 ? new RegExp(`^${addresses.ipv4.replace(/\./g, '\\.')}$`) : /^Not Detected/);
  expect.soft(card.ipv6.value, `${ctx}: shared IPv6 box`).toMatch(addresses.ipv6 ? new RegExp(`^${addresses.ipv6}$`) : /^Not Detected/);
  expect.soft(card.badges, `${ctx}: shared badges (stack, network type)`).toEqual([stackLabel(addresses.ipv4, addresses.ipv6), networkLabel(payload.network_type)]);

  const sections = await readSharedSections(shared);
  const want: Record<string, Record<string, string>> = {
    Geolocation: {
      City: payload.city || DASH,
      Region: payload.region || DASH,
      Country: payload.country ? `${flagOf(payload.country_code)} ${payload.country}` : DASH,
      'Postal Code': payload.postal_code || DASH,
      Timezone: payload.timezone || DASH,
      'UTC Offset': payload.utc_offset || DASH,
    },
    Network: {
      ISP: payload.isp || DASH,
      ASN: payload.asn ? `AS${payload.asn}` : DASH,
      'Reverse DNS': payload.reverse_dns || DASH,
    },
    'Browser & Device': {
      Browser: original.device['Browser'],
      OS: original.device['Operating System'],
      Screen: original.device['Screen Resolution'],
      Language: original.device['Language'],
      Cookies: original.device['Cookies'],
      GPU: original.device['GPU / WebGL'],
    },
    'HTTP Headers': {
      'User-Agent': original.headers['User-Agent'],
      'Accept-Language': original.headers['Accept-Language'],
      'Accept-Encoding': original.headers['Accept-Encoding'],
      DNT: original.headers['DNT (Do Not Track)'],
    },
  };
  for (const [name, rows] of Object.entries(want)) {
    for (const [label, value] of Object.entries(rows)) {
      expect.soft(sections[name]?.[label], `${ctx}: shared view "${name}" → "${label}" equals the original`).toBe(value);
    }
  }
  if (Object.keys(original.connection).length) {
    const connection = sections['Connection'] ?? {};
    expect.soft(connection['Type']?.toLowerCase(), `${ctx}: shared connection type`).toBe(original.connection['Browser Connection Type'].toLowerCase());
    expect.soft(connection['Effective Type'], `${ctx}: shared effective type`).toBe(original.connection['Effective Type']);
    expect.soft(connection['Bandwidth'], `${ctx}: shared bandwidth`).toBe(original.connection['Estimated Bandwidth']);
    expect.soft(connection['RTT'], `${ctx}: shared round-trip time`).toBe(original.connection['Round-Trip Time']);
  }
  await expect.soft(shared.getByRole('heading', { level: 1 }), `${ctx}: shared page title`).toHaveText(title);
  await expect.soft(shared.getByText('Shared Analysis — Read Only'), `${ctx}: read-only marker`).toBeVisible();
  await expect.soft(shared.getByText(/^Checked at /), `${ctx}: time of the original check, in UTC`).toHaveText(`Checked at ${httpDate(payload.checked_at_utc)}`);
  expect.soft(await shared.locator('main').innerText(), `${ctx}: the shared view never prints "null" or "undefined"`).not.toMatch(/\b(null|undefined|NaN)\b/);
}

test.describe('What Is My IP — copy buttons', () => {
  test('each address box copies its own address and confirms', async ({ page, rng }) => {
    const details = generatePayload(rng, { version: 'IPv4', missing: 0 });
    const ipv6 = publicIpv6(rng);
    await openWith(page, callNumber => (callNumber === 1 ? { ...details, ip: ipv6, ip_version: 'IPv6' } : details));
    await waitForResult(page);
    for (const [version, address] of [['IPv4', details.ip], ['IPv6', ipv6]] as const) {
      await clearClipboard(page);
      await copyAddressButton(page, version).click();
      await expect(copyAddressButton(page, version), `${version} Copy button confirms`).toHaveText('Copied!');
      expect.soft(await readClipboard(page), `clipboard after copying the ${version} address`).toBe(address);
      await expect(copyAddressButton(page, version), `${version} Copy label returns after two seconds`).toHaveText('Copy', { timeout: 5_000 });
    }
  });
});

test.describe('What Is My IP — CSV and HTML report', () => {
  test('"Export CSV" holds every field of the API answer plus the detected addresses', async ({ page, rng, evidence }) => {
    for (const version of ['IPv4', 'IPv6'] as const) {
      const payload = generatePayload(rng.fork(version), { version, missing: 0.3 });
      await page.unroute('**/api/myip');
      await openWith(page, payload);
      await waitForResult(page);
      const ipv4 = version === 'IPv4' ? payload.ip : null;
      const ipv6 = version === 'IPv6' ? payload.ip : null;
      const file = await captureDownload(page, () => csvButton(page).click());
      await evidence.save(`export-${version}.csv`, file.text);
      expect.soft(file.filename, `CSV file name for ${payload.ip}`).toBe(`${fileStem(ipv4, payload.ip)}.csv`);
      const rows = parseCsv(file.text);
      expect(rows.length, 'one header row and one data row').toBe(2);
      const record = Object.fromEntries(rows[0].map((name, i) => [name, rows[1][i]]));
      const want = expectedCsv(payload, ipv4, ipv6);
      expect.soft(rows[0].slice(0, 3), 'the CSV starts with the detected addresses and the stack').toEqual(['ipv4', 'ipv6', 'ip_stack']);
      for (const [column, value] of Object.entries(want.cells)) {
        expect.soft(record[column], `CSV column "${column}" for ${payload.ip}`).toBe(value);
      }
      for (const column of want.empty) {
        expect.soft(rows[0], `CSV has a "${column}" column even when the value is unknown`).toContain(column);
      }
    }
  });

  test('the CSV leaves a cell empty when the backend knows no value: no literal "null"', async ({ page, evidence }) => {
    const payload = emptyPayload('198.51.100.24');
    await openWith(page, payload);
    await waitForResult(page);
    const file = await captureDownload(page, () => csvButton(page).click());
    await evidence.save('export.csv', file.text);
    const [header, cells] = parseCsv(file.text);
    const leaked = header.filter((_, i) => /^(null|undefined|NaN)$/.test(cells[i]));
    expect(leaked, `CSV columns whose cell is the literal text "null" (the API value is JSON null, an unknown value)`).toEqual([]);
  });

  test('"Download HTML" produces a report with the same values as the page', async ({ page, rng, evidence }) => {
    const payload = fullPayload(rng);
    await openWith(page, payload);
    await waitForResult(page);
    const original = await readOriginal(page);
    const file = await captureDownload(page, () => htmlButton(page).click());
    await evidence.save('report.html', file.text);
    expect.soft(file.filename, 'report file name').toBe(`${fileStem(payload.ip, payload.ip)}.html`);

    const report = await page.context().newPage();
    await report.setContent(file.text);
    const shown = await report.evaluate(() => {
      const clean = (text: string | null | undefined) => (text || '').replace(/\s+/g, ' ').trim();
      const sections: Record<string, Record<string, string>> = {};
      for (const card of Array.from(document.querySelectorAll('.card'))) {
        const header = card.querySelector('.card-header');
        if (!header) continue;
        sections[clean(header.textContent)] = Object.fromEntries(Array.from(card.querySelectorAll('tr')).map(tr => [clean(tr.children[0]?.textContent), clean(tr.children[1]?.textContent)]));
      }
      return {
        title: document.title,
        stack: clean(document.querySelector('.badge-stack')?.textContent),
        boxes: Array.from(document.querySelectorAll('.ip-box')).map(box => clean(box.textContent)),
        meta: clean(document.querySelector('.meta')?.textContent),
        sections,
      };
    });
    await report.close();
    const sectionNamed = (name: string) => Object.entries(shown.sections).find(([title]) => title.includes(name))?.[1] ?? {};

    expect.soft(shown.title, 'report title').toBe(`My IP Report — ${payload.ip}`);
    expect.soft(shown.stack, 'report stack badge').toBe(stackLabel(payload.ip, null));
    expect.soft(shown.boxes[0], 'report IPv4 box').toBe(`IPv4 ${payload.ip}`);
    expect.soft(shown.boxes[1], 'report IPv6 box').toMatch(/^IPv6 .*Not Detected/);
    expect.soft(shown.meta, 'report footer carries the time of the check').toBe(`Generated by SysAdmin Toolkit · ${payload.checked_at_utc}`);
    for (const [name, rows] of Object.entries(expectedReport(payload))) {
      const got = sectionNamed(name);
      for (const [label, value] of rows) {
        if (Array.isArray(value)) expect.soft(value, `report "${name}" → "${label}", shown "${got[label]}"`).toContain(got[label]);
        else expect.soft(got[label], `report "${name}" → "${label}"`).toBe(value);
      }
    }
    const device = sectionNamed('Browser & Device');
    const deviceLabels: [string, string][] = [['Browser', 'Browser'], ['OS', 'Operating System'], ['Screen', 'Screen Resolution'], ['Language', 'Language'], ['Do Not Track', 'Do Not Track'], ['Cookies', 'Cookies'], ['GPU', 'GPU / WebGL'], ['Platform', 'Platform']];
    for (const [inReport, onPage] of deviceLabels) {
      expect.soft(device[inReport], `report "Browser & Device" → "${inReport}" equals the page's "${onPage}"`).toBe(original.device[onPage]);
    }
    const connection = sectionNamed('Connection');
    for (const label of ['Browser Connection Type', 'Effective Type', 'Estimated Bandwidth', 'Round-Trip Time', 'Data Saver']) {
      expect.soft(connection[label]?.toLowerCase(), `report "Browser-Estimated Connection" → "${label}" equals the page`).toBe(original.connection[label]?.toLowerCase());
    }
  });

  test('markup in the API answer is text in the HTML report too: no element is created and no script runs', async ({ page, rng, evidence }) => {
    const base = fullPayload(rng);
    const payload: MyIpPayload = {
      ...base,
      city: '<img src=x onerror="window.__xss=1">',
      isp: 'Evil <b>Corp</b><script>window.__xss=2</script>', org: 'Evil <b>Corp</b>',
      reverse_dns: '<svg onload="window.__xss=3"></svg>.example.net',
      headers: { ...base.headers, user_agent: '<iframe srcdoc="x"></iframe>Agent' },
    };
    await openWith(page, payload);
    await waitForResult(page);
    const file = await captureDownload(page, () => htmlButton(page).click());
    await evidence.save('report.html', file.text);
    const report = await page.context().newPage();
    let dialogs = 0;
    report.on('dialog', dialog => { dialogs++; void dialog.dismiss(); });
    await report.setContent(file.text);
    const found = await report.evaluate(() => ({
      elements: Array.from(document.querySelectorAll('td img, td b, td script, td svg, td iframe')).map(el => el.tagName.toLowerCase()),
      flag: (window as unknown as { __xss?: number }).__xss ?? null,
      text: document.body.innerText,
    }));
    await report.close();
    expect.soft(found.elements, 'elements created inside report cells from values of the API answer (reverse DNS, organisation, city and User-Agent are not under the site\'s control)').toEqual([]);
    expect.soft(found.flag, 'script injected through the API answer ran in the report').toBeNull();
    expect.soft(dialogs, 'no dialog may open').toBe(0);
    expect.soft(found.text, 'the organisation name appears as the literal text the API returned').toContain(payload.isp as string);
  });
});

test.describe('What Is My IP — share dialog', () => {
  for (const [name, viewport] of Object.entries(VIEWPORTS)) {
    test(`the share dialog has no layout problems at ${name} size (${viewport.width}px): form and created link`, async ({ page, rng }) => {
      await page.setViewportSize(viewport);
      await openWith(page, fullPayload(rng));
      await waitForResult(page);
      await mockApi(page, '**/api/share/myip', { success: true, code: 'Ab12Cd34', url: '/s/Ab12Cd34' });
      await shareButton(page).click();
      await expect(shareDialog(page)).toBeVisible();
      await expectNoUiGlitches(page, `${ROUTE} share dialog, form @${name}`, { scope: DIALOG_SCOPE });
      await generateLinkButton(page).click();
      await expect(shareDialog(page).getByText('Share link created!')).toBeVisible();
      await expectNoUiGlitches(page, `${ROUTE} share dialog, link created @${name}`, { scope: DIALOG_SCOPE });
    });
  }

  test('the dialog proposes a title, sends what was entered, and "Create Another Link", the close button and the backdrop work', async ({ page, rng, evidence }) => {
    const payload = fullPayload(rng);
    await openWith(page, payload);
    await waitForResult(page);
    const original = await readOriginal(page);
    const calls = await mockApi(page, '**/api/share/myip', { success: true, code: 'Zz99Yy88', url: '/s/Zz99Yy88' });

    await shareButton(page).click();
    await expect(shareTitleInput(page), 'proposed title names the address').toHaveValue(`My IP Report — ${payload.ip}`);
    await expect(shareExpirySelect(page), 'default expiry').toHaveValue('never');
    expect.soft(await shareExpirySelect(page).locator('option').allInnerTexts(), 'expiry options').toEqual(['Never expires', '24 hours', '7 days', '30 days']);
    await expect(sharePasswordInput(page), 'password starts empty').toHaveValue('');

    const title = `  Report ${rng.string(6)} for the audit  `;
    const password = `pw-${rng.string(8)}`;
    await shareTitleInput(page).fill(title);
    await shareExpirySelect(page).selectOption('7d');
    await sharePasswordInput(page).fill(password);
    await generateLinkButton(page).click();
    await expect(shareDialog(page).getByText('Share link created!')).toBeVisible();
    const body = calls[0].body as { title: string; ip: string; expiry: string; password: string; checked_at_utc: string; snapshot: Record<string, unknown> };
    await evidence.save('share-request.json', body);
    expect.soft(body.title, 'title sent (surrounding spaces removed)').toBe(title.trim());
    expect.soft(body.ip, 'address sent').toBe(payload.ip);
    expect.soft(body.expiry, 'expiry sent').toBe('7d');
    expect.soft(body.password, 'password sent').toBe(password);
    expect.soft(body.checked_at_utc, 'time of the check sent').toBe(payload.checked_at_utc);
    for (const [key, value] of Object.entries(payload)) {
      expect.soft(body.snapshot[key], `snapshot field "${key}" equals the API answer`).toEqual(value);
    }
    expect.soft(body.snapshot.ipv4, 'snapshot IPv4 address').toBe(payload.ip);
    expect.soft(body.snapshot.ipv6, 'snapshot IPv6 address (none detected)').toBeNull();
    const client = body.snapshot.client as Record<string, string>;
    expect.soft([client.browser, client.os, client.screen, client.language, client.dnt, client.cookies, client.webgl, client.platform], 'snapshot browser details equal the "Browser & Device" card')
      .toEqual(['Browser', 'Operating System', 'Screen Resolution', 'Language', 'Do Not Track', 'Cookies', 'GPU / WebGL', 'Platform'].map(label => original.device[label]));

    const origin = new URL(page.url()).origin;
    await expect(shareLinkText(page), 'the link is this site + /s/ + the code the backend returned').toHaveText(`${origin}/s/Zz99Yy88`);
    await clearClipboard(page);
    await shareDialog(page).getByRole('button', { name: 'Copy' }).click();
    await expect(shareDialog(page).getByRole('button', { name: 'Copied!' }), 'the link Copy button confirms').toBeVisible();
    expect.soft(await readClipboard(page), 'clipboard after copying the share link').toBe(`${origin}/s/Zz99Yy88`);

    await shareDialog(page).getByRole('button', { name: 'Create Another Link' }).click();
    await expect(generateLinkButton(page), '"Create Another Link" returns to the form').toBeVisible();
    await expect(shareTitleInput(page), 'the form keeps the title that was entered').toHaveValue(title);

    // Close with the X button, reopen: the form is reset.
    await shareDialog(page).locator('button').first().click();
    await expect(page.getByRole('heading', { name: 'Share IP Report' }), 'the X button closes the dialog').toHaveCount(0);
    await shareButton(page).click();
    await expect(shareTitleInput(page), 'reopening resets the title').toHaveValue(`My IP Report — ${payload.ip}`);
    await expect(shareExpirySelect(page), 'reopening resets the expiry').toHaveValue('never');
    await expect(sharePasswordInput(page), 'reopening clears the password').toHaveValue('');

    // An empty title falls back to the proposed one.
    await shareTitleInput(page).fill('   ');
    await generateLinkButton(page).click();
    await expect(shareDialog(page).getByText('Share link created!')).toBeVisible();
    expect.soft((calls[1].body as { title: string }).title, 'a blank title is replaced by the proposed title').toBe(`My IP Report — ${payload.ip}`);
    expect.soft((calls[1].body as { password: string }).password, 'no password when the field is empty').toBe('');

    // Close by clicking the backdrop.
    await page.mouse.click(5, 5);
    await expect(page.getByRole('heading', { name: 'Share IP Report' }), 'a click outside closes the dialog').toHaveCount(0);
  });

  test('when the share cannot be created the dialog shows the error, stops the spinner and stays usable', async ({ page, rng, guard }) => {
    await openWith(page, fullPayload(rng));
    await waitForResult(page);
    guard.allow(/status of 500|HTTP 500/);
    await mockApi(page, '**/api/share/myip', { success: false, error: 'Could not generate unique code. Try again.' }, { status: 500, delayMs: 800 });
    await shareButton(page).click();
    await generateLinkButton(page).click();
    await expect(shareDialog(page).getByText('Creating share link...'), 'progress text while the share is created').toBeVisible();
    await expect(shareDialog(page).getByText('Could not generate unique code. Try again.'), 'the backend\'s error text is shown').toBeVisible();
    await expect(shareDialog(page).getByText('Creating share link...')).toHaveCount(0);
    await expect(generateLinkButton(page), 'the form is usable again').toBeEnabled();
    expect.soft(await shareLinkText(page).count(), 'no link is shown after a failure').toBe(0);

    await page.unroute('**/api/share/myip');
    await mockApi(page, '**/api/share/myip', { success: true, code: 'Ok123456', url: '/s/Ok123456' });
    await generateLinkButton(page).click();
    await expect(shareDialog(page).getByText('Share link created!'), 'the next attempt succeeds').toBeVisible();
    await expect(shareDialog(page).getByText('Could not generate unique code')).toHaveCount(0);
  });
});

test.describe('What Is My IP — share links (real backend)', () => {
  test('a link without a password shows another visitor the same values', async ({ page, browser, rng, evidence, request }, testInfo) => {
    const payload = fullPayload(rng);
    await evidence.save('payload.json', payload);
    await openWith(page, payload);
    await waitForResult(page);
    const original = await readOriginal(page);
    const title = `Audit ${rng.string(8)}`;
    const share = await createShare(page, { title });
    expect(share.exchange.status, 'POST /api/share/myip').toBe(200);
    expect(share.link, 'share link shown in the dialog').toBe(`${new URL(page.url()).origin}/s/${share.code}`);

    const meta = await (await request.get(`/api/share/${share.code}`)).json();
    expect.soft(meta, 'share metadata stored by the backend').toMatchObject({ share_type: 'myip', title, has_password: false, ip: payload.ip, expires_at: null });
    expect.soft(Math.abs(Date.now() - new Date(meta.created_at).getTime()), `created_at (${meta.created_at}) is the time the link was made`).toBeLessThan(120_000);

    const visitor = await newVisitor(browser, testInfo);
    await visitor.page.goto(`/s/${share.code}`, { waitUntil: 'domcontentloaded' });
    await expect(visitor.page.getByText('Password Protected'), 'no password prompt for a public link').toHaveCount(0);
    await expectSharedView(visitor.page, payload, original, { ipv4: payload.ip, ipv6: null }, title, 'public link');
    await expect.soft(visitor.page.getByText(/^Created: /), 'creation date in the visitor\'s time zone, no expiry').toHaveText(`Created: ${shortDate(meta.created_at, TIME_ZONE)}`);
    await expect.soft(visitor.page.getByRole('link', { name: 'Open Live Tool' }), 'link back to the live tool').toHaveAttribute('href', '/myip');
    expect.soft(visitor.problems, 'browser errors on the shared view').toEqual([]);
    await visitor.context.close();
  });

  test('a link with a password hides everything until the right password is entered; a wrong one is refused', async ({ page, browser, rng, evidence, request }, testInfo) => {
    const payload = fullPayload(rng, 'IPv6');
    await evidence.save('payload.json', payload);
    await openWith(page, payload);
    await waitForResult(page);
    const original = await readOriginal(page);
    const password = `S3cret-${rng.string(10)}`;
    const title = `Protected ${rng.string(8)}`;
    const share = await createShare(page, { title, password, expiry: '24h' });

    // What an anonymous client can read without the password.
    const meta = await (await request.get(`/api/share/${share.code}`)).json();
    expect.soft(meta, 'metadata of a protected share').toMatchObject({ share_type: 'myip', title, has_password: true });
    expect.soft(JSON.stringify(meta), `the metadata of a protected share must not contain the address ${payload.ip}`).not.toContain(payload.ip);
    expect.soft(meta.snapshot, 'no snapshot without the password').toBeUndefined();
    const refused = await request.post(`/api/share/${share.code}/verify`, { data: { password: `${password}x` } });
    expect.soft(refused.status(), 'POST /verify with a wrong password').toBe(401);
    expect.soft(JSON.stringify(await refused.json()), 'a refused verification returns no snapshot').not.toContain(payload.ip);

    const visitor = await newVisitor(browser, testInfo);
    const shared = visitor.page;
    await shared.goto(`/s/${share.code}`, { waitUntil: 'domcontentloaded' });
    await expect(shared.getByRole('heading', { name: 'Password Protected' }), 'password prompt').toBeVisible();
    expect.soft(await shared.locator('main').innerText(), 'nothing of the report is visible before the password').not.toContain(payload.ip);
    expect.soft(await addressCard(shared).count(), 'no address card before the password').toBe(0);

    await shared.getByPlaceholder('Enter password').fill(`${password}-wrong`);
    await shared.getByRole('button', { name: 'Unlock' }).click();
    await expect(shared.getByText('Incorrect password.'), 'a wrong password is refused with a message').toBeVisible();
    await expect(shared.getByRole('heading', { name: 'Password Protected' }), 'the prompt stays after a wrong password').toBeVisible();
    expect.soft(await addressCard(shared).count(), 'no address card after a wrong password').toBe(0);

    await shared.getByPlaceholder('Enter password').fill('');
    await shared.getByRole('button', { name: 'Unlock' }).click();
    await expect(shared.getByText('Password required.'), 'an empty password is refused with a message').toBeVisible();

    await shared.getByPlaceholder('Enter password').fill(password);
    await shared.getByPlaceholder('Enter password').press('Enter');
    await expect(shared.getByRole('heading', { name: 'Password Protected' }), 'the prompt disappears with the right password').toHaveCount(0);
    await expect(shared.getByText('Incorrect password.'), 'the earlier error is cleared').toHaveCount(0);
    await expectSharedView(shared, payload, original, { ipv4: null, ipv6: payload.ip }, title, 'protected link');
    await expect.soft(shared.getByText(/^Created: /), 'creation and expiry dates').toHaveText(`Created: ${shortDate(meta.created_at, TIME_ZONE)} · Expires: ${shortDate(meta.expires_at, TIME_ZONE)}`);
    expect.soft(visitor.problems.filter(problem => !/401/.test(problem)), 'browser errors on the shared view (the two refused passwords answer 401 on purpose)').toEqual([]);
    await visitor.context.close();
  });

  test('the real answer for this client survives the round trip through a share link', async ({ page, browser, rng }, testInfo) => {
    const recorder = recordMyIpResponses(page);
    await openTool(page, ROUTE, HEADING);
    await waitForResult(page);
    const payload = (await recorder.answers())[0].body as MyIpPayload;
    const original = await readOriginal(page);
    const title = `Loopback ${rng.string(8)}`;
    const share = await createShare(page, { title });
    const visitor = await newVisitor(browser, testInfo);
    await visitor.page.goto(`/s/${share.code}`, { waitUntil: 'domcontentloaded' });
    const addresses = { ipv4: payload.ip_version === 'IPv4' ? payload.ip : null, ipv6: payload.ip_version === 'IPv6' ? payload.ip : null };
    await expectSharedView(visitor.page, payload, original, addresses, title, `real answer for ${payload.ip}`);
    expect.soft(visitor.problems, 'browser errors on the shared view').toEqual([]);
    await visitor.context.close();
  });

  test('the shared view offers its own CSV and HTML downloads, with the snapshot\'s values', async ({ page, browser, rng, evidence }, testInfo) => {
    const payload = fullPayload(rng);
    await openWith(page, payload);
    await waitForResult(page);
    const share = await createShare(page, { title: `Downloads ${rng.string(6)}` });
    const visitor = await newVisitor(browser, testInfo);
    const shared = visitor.page;
    await shared.goto(`/s/${share.code}`, { waitUntil: 'domcontentloaded' });
    await expect(addressCard(shared)).toBeVisible();

    const csv = await captureDownload(shared, () => shared.getByRole('button', { name: 'Export CSV' }).click());
    await evidence.save('shared-export.csv', csv.text);
    expect.soft(csv.filename, 'CSV file name from the shared view').toBe(`${fileStem(payload.ip, payload.ip)}.csv`);
    const [header, cells] = parseCsv(csv.text);
    const record = Object.fromEntries(header.map((name, i) => [name, cells[i]]));
    const want = expectedCsv(payload, payload.ip, null).cells;
    // The snapshot view keeps the fields it displays; internal flags of the live answer are not part of it.
    for (const column of ['ipv4', 'ip_stack', 'ip', 'ip_version', 'city', 'region', 'region_code', 'country', 'country_code', 'registered_country', 'continent', 'postal_code', 'accuracy_radius', 'latitude', 'longitude', 'timezone', 'utc_offset', 'isp', 'org', 'asn', 'asn_name', 'domain', 'usage_type', 'proxy_type', 'proxy_detected', 'reverse_dns', 'network_type', 'checked_at_utc', 'headers user_agent', 'headers accept_language', 'headers accept_encoding', 'headers dnt']) {
      // Fields the answer does not know (null) are the subject of the "no literal null" test above.
      if (want[column] !== undefined) expect.soft(record[column], `shared CSV column "${column}" equals the original answer`).toBe(want[column]);
    }

    const html = await captureDownload(shared, () => shared.getByRole('button', { name: 'Download HTML' }).click());
    await evidence.save('shared-report.html', html.text);
    expect.soft(html.filename, 'HTML file name from the shared view').toBe(`${fileStem(payload.ip, payload.ip)}.html`);
    const report = await visitor.context.newPage();
    await report.setContent(html.text);
    await expect.soft(report, 'title of the report made from the snapshot').toHaveTitle(`My IP Report — ${payload.ip}`);
    await expect.soft(report.locator('.meta'), 'the report keeps the time of the original check').toHaveText(`Generated by SysAdmin Toolkit · ${payload.checked_at_utc}`);
    await expect.soft(report.locator('.ip-val').first(), 'address in the report made from the snapshot').toHaveText(payload.ip);
    for (const value of [payload.city, payload.country, payload.isp, `AS${payload.asn}`, payload.reverse_dns, payload.timezone]) {
      await expect.soft(report.locator('body'), `the report made from the snapshot contains "${value}"`).toContainText(String(value));
    }
    expect.soft(visitor.problems, 'browser errors on the shared view').toEqual([]);
    await visitor.context.close();
  });

  test('each expiry choice is stored as that duration, and "Never expires" stores none', async ({ page, rng, request }) => {
    await openWith(page, fullPayload(rng));
    await waitForResult(page);
    const durations: [string, number | null][] = [['never', null], ['24h', 24 * 3600], ['7d', 7 * 24 * 3600], ['30d', 30 * 24 * 3600]];
    for (const [expiry, seconds] of durations) {
      const share = await createShare(page, { expiry });
      const meta = await (await request.get(`/api/share/${share.code}`)).json();
      if (seconds === null) {
        expect.soft(meta.expires_at, 'expires_at for "Never expires"').toBeNull();
      } else {
        const lifetime = (new Date(meta.expires_at).getTime() - new Date(meta.created_at).getTime()) / 1000;
        expect.soft(Math.abs(lifetime - seconds), `lifetime of a "${expiry}" link is ${seconds} s (stored: created ${meta.created_at}, expires ${meta.expires_at})`).toBeLessThanOrEqual(2);
      }
      await shareDialog(page).locator('button').first().click();
      await expect(page.getByRole('heading', { name: 'Share IP Report' })).toHaveCount(0);
    }
  });

  test('a share code that does not exist says so', async ({ browser }, testInfo) => {
    const visitor = await newVisitor(browser, testInfo);
    await visitor.page.goto('/s/NoSuchCode0', { waitUntil: 'domcontentloaded' });
    await expect(visitor.page.getByText('Share not found.'), 'message for an unknown code').toBeVisible();
    expect.soft(await addressCard(visitor.page).count(), 'no report for an unknown code').toBe(0);
    await visitor.context.close();
  });
});
