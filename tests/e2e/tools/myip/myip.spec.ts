import { test, expect, type Page } from '../_support/fixtures';
import { openTool, expectToolLinkedFromHome } from '../_support/navigation';
import { expectNoUiGlitches, expectControlsUsable, VIEWPORTS } from '../_support/ui-audit';
import { mockApi } from '../_support/io';
import { emptyPayload, fullPayload, generatePayload, publicIpv6 } from './generator';
import {
  DASH, NETWORK_LABELS, NO_CITY, coordinatesText, expectedGeolocation, expectedHeaders, expectedNetwork, expectedStats,
  flagOf, isLabelSuffix, networkLabel, stackLabel, type MyIpPayload,
} from './oracle';
import {
  HEADING, MYIP_URL, ROUTE, addressCard, asnLookupLink, csvButton, dnsLookupLink, errorBox, htmlButton, loadingCard, openWith,
  readAddressCard, readSections, readStats, recordMyIpResponses, rowsToRecord, section, shareButton, waitForResult,
} from './page';

/**
 * What Is My IP (/myip) — server-backed (GET /api/myip), plus browser-side diagnostics.
 *
 * INVENTORY (the coverage contract; each entry maps to at least one test)
 *
 * Inputs
 *   - None typed by the user. The page asks GET /api/myip three times on load: once for the details and
 *     twice to detect an IPv4 and an IPv6 address (same endpoint unless the site configures others).
 *   - The browser itself: User-Agent, screen, language, Do Not Track, cookies, WebGL, platform,
 *     Network Information API.
 *   - No URL parameters, no refresh button (reload is the refresh).
 * Controls
 *   - Copy button in each address box; "Share Results" (dialog: title, expiry, password, generate, copy link,
 *     create another, close); "Download HTML"; "Export CSV"; "ASN Lookup" and "More info →" (to /asn?asn=N);
 *     "DNS Lookup" (to /dns?domain=…); two collapsible cards ("Browser & Device", "HTTP Request Headers").
 * Displayed values
 *   - Address card: IPv4 box, IPv6 box, "Detected" tags, stack badge, network-type badge.
 *   - Summary cards: Country, City, ASN Org, ASN.
 *   - Geolocation: City, State / Region, Country, Registered Country, Continent, Postal Code, Accuracy Radius,
 *     Timezone, UTC Offset, Coordinates.
 *   - GeoLite ASN & Network: ASN Organization, ASN, Domain*, Usage Type*, Proxy Type*, Reverse DNS (PTR),
 *     Estimated Network Type (* only when known).
 *   - Browser & Device: Browser, Operating System, Screen Resolution, Language, Do Not Track, Cookies,
 *     GPU / WebGL, Platform.
 *   - HTTP Request Headers: User-Agent, Accept-Language, Accept-Encoding, DNT.
 *   - Browser-Estimated Connection: Connection Type, Effective Type, Bandwidth, Round-Trip Time, Data Saver,
 *     or "Not Supported in Your Browser".
 *   - Not shown by this page (nothing to test): map or map link, local time at the IP's location, viewport
 *     size, browser time zone, device pixel ratio, colour scheme, WebRTC/local addresses.
 * Outputs
 *   - Clipboard (addresses, share link), CSV, HTML report, share link (POST /api/share/myip) and the shared
 *     view /s/<code>.
 * States
 *   - Loading, result (IPv4 only, IPv6 only, dual stack; fields known or unknown), error, share dialog
 *     (form, creating, created, error).
 *
 * LAYERS: 1, 2, 4, 5 this file; 3 not applicable beyond page load (no user input; the browser
 * configuration is the input: myip-browser.spec.ts); 6 myip-output.spec.ts; 7 myip-failures.spec.ts and
 * this file (markup, extreme values); 8 myip-failures.spec.ts (reload) and myip-output.spec.ts (dialog);
 * deep links and remembered settings: not applicable, the tool reads no URL parameter and stores nothing.
 *
 * Oracle: ./oracle.ts. Contract tests answer GET /api/myip with generated payloads (./generator.ts) in the
 * backend's shape; real-backend tests capture the real answer.
 */

/** Compares every value of the result view with the payload. */
async function expectPayloadShown(page: Page, payload: MyIpPayload, ctx: string, addresses: { ipv4: string | null; ipv6: string | null }) {
  const card = await readAddressCard(page);
  for (const [name, box, address] of [['IPv4', card.ipv4, addresses.ipv4], ['IPv6', card.ipv6, addresses.ipv6]] as const) {
    if (address) {
      expect.soft(box.value, `${ctx}: ${name} box`).toBe(address);
      expect.soft(box.tags, `${ctx}: ${name} box tags`).toEqual([name, 'Detected']);
      expect.soft(box.copyLabel, `${ctx}: ${name} box offers Copy`).toBe('Copy');
    } else {
      expect.soft(box.value, `${ctx}: ${name} box without an address`).toMatch(/^Not Detected/);
      expect.soft(box.tags, `${ctx}: ${name} box tags without an address`).toEqual([name]);
    }
  }
  expect.soft(card.badges, `${ctx}: badges under the addresses (stack, network type "${payload.network_type}")`).toEqual([stackLabel(addresses.ipv4, addresses.ipv6), networkLabel(payload.network_type)]);

  const stats = await readStats(page);
  for (const [label, value] of Object.entries(expectedStats(payload))) {
    expect.soft(stats[label], `${ctx}: summary card "${label}"`).toBe(value);
  }

  const sections = await readSections(page);
  const geo = rowsToRecord(sections['Geolocation']);
  const wantGeo = expectedGeolocation(payload);
  expect.soft(Object.keys(geo), `${ctx}: rows of the Geolocation card`).toEqual(Object.keys(wantGeo));
  for (const [label, value] of Object.entries(wantGeo)) {
    expect.soft(geo[label], `${ctx}: Geolocation "${label}"`).toBe(value);
  }

  const network = sections['GeoLite ASN & Network'] ?? [];
  const wantNetwork = expectedNetwork(payload);
  expect.soft(network.map(row => row.label), `${ctx}: rows of the network card (optional rows only when known)`).toEqual(wantNetwork.map(([label]) => label));
  for (const [label, value] of wantNetwork) {
    expect.soft(network.find(row => row.label === label)?.value, `${ctx}: network "${label}"`).toBe(value);
  }
  const asnRow = network.find(row => row.label === 'ASN');
  expect.soft(asnRow?.link ?? null, `${ctx}: "More info →" link next to the ASN`).toEqual(payload.asn ? { label: 'More info →', href: `/asn?asn=${payload.asn}` } : null);

  const headers = rowsToRecord(sections['HTTP Request Headers']);
  for (const [label, value] of Object.entries(expectedHeaders(payload))) {
    expect.soft(headers[label], `${ctx}: request header "${label}"`).toBe(value);
  }

  if (payload.asn) await expect.soft(asnLookupLink(page), `${ctx}: "ASN Lookup" link`).toHaveAttribute('href', `/asn?asn=${payload.asn}`);
  else expect.soft(await asnLookupLink(page).count(), `${ctx}: no "ASN Lookup" link without an ASN`).toBe(0);
  if (payload.reverse_dns) {
    const href = (await dnsLookupLink(page).getAttribute('href')) ?? '';
    const domain = decodeURIComponent(href.replace('/dns?domain=', ''));
    expect.soft(href.startsWith('/dns?domain='), `${ctx}: "DNS Lookup" link target (${href})`).toBe(true);
    expect.soft(isLabelSuffix(domain, payload.reverse_dns), `${ctx}: "DNS Lookup" asks for "${domain}", which must be the PTR name "${payload.reverse_dns}" or a parent domain of it`).toBe(true);
  } else {
    expect.soft(await dnsLookupLink(page).count(), `${ctx}: no "DNS Lookup" link without a PTR name`).toBe(0);
  }

  const text = await page.locator('.signal-tool-primary').innerText();
  expect.soft(text, `${ctx}: the words "null" and "undefined" never appear`).not.toMatch(/\b(null|undefined|NaN)\b/);
}

const addressesOf = (payload: MyIpPayload) => ({
  ipv4: payload.ip_version === 'IPv4' ? payload.ip : null,
  ipv6: payload.ip_version === 'IPv6' ? payload.ip : null,
});

test.describe('What Is My IP — access and layout', () => {
  test('is linked from the home page and the sidebar', async ({ page }) => {
    await expectToolLinkedFromHome(page, ROUTE);
    await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
  });

  test('opens with its title, guide panel and action buttons ready', async ({ page }) => {
    await openTool(page, ROUTE, HEADING);
    await expect(page, 'the page title names the tool').toHaveTitle(/What Is My IP/i);
    await waitForResult(page);
    await expectControlsUsable(page, {
      'Share Results button': 'button:has-text("Share Results")',
      'Download HTML button': 'button:has-text("Download HTML")',
      'Export CSV button': 'button:has-text("Export CSV")',
      'Browser & Device card header': 'details.signal-myip-collapsible >> nth=0 >> summary',
      'HTTP Request Headers card header': 'details.signal-myip-collapsible >> nth=1 >> summary',
    });
    await expect(page.getByRole('complementary', { name: 'Your connection' }), 'guide panel').toBeVisible();
    await expect(loadingCard(page), 'the loading card is gone once the result is shown').toHaveCount(0);
    await expect(errorBox(page)).toHaveCount(0);
  });

  for (const [name, viewport] of Object.entries(VIEWPORTS)) {
    test(`has no layout problems at ${name} size (${viewport.width}px): loading, full result with every card open, and error`, async ({ page, rng, guard }) => {
      await page.setViewportSize(viewport);
      // Long values on purpose: an IPv6 address, the longest city and organisation names.
      const payload = { ...fullPayload(rng, 'IPv6'), city: 'Llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch', isp: 'Very Long Autonomous System Organisation Name For Layout Testing Of The Network Card Co., Ltd.' };
      const state = { status: 200, delay: 1200 };
      await page.route('**/api/myip', async (route) => {
        await new Promise(resolve => setTimeout(resolve, state.delay));
        await route.fulfill({ status: state.status, json: state.status === 200 ? payload : { error: 'Simulated failure' } });
      });
      await page.goto(ROUTE, { waitUntil: 'domcontentloaded' });
      await expect(loadingCard(page), 'loading card while the answer is held back').toBeVisible();
      await expectNoUiGlitches(page, `${ROUTE} loading @${name}`);
      await waitForResult(page);
      await expectNoUiGlitches(page, `${ROUTE} result, cards collapsed @${name}`);
      await section(page, 'Browser & Device').locator('summary').click();
      await section(page, 'HTTP Request Headers').locator('summary').click();
      await expectNoUiGlitches(page, `${ROUTE} result, every card open @${name}`);

      guard.allow(/status of 500|HTTP 500/);
      Object.assign(state, { status: 500, delay: 0 });
      await page.reload({ waitUntil: 'domcontentloaded' });
      await expect(errorBox(page)).toBeVisible();
      await expectNoUiGlitches(page, `${ROUTE} error @${name}`);
    });

    test(`has no layout problems at ${name} size (${viewport.width}px): a result without any known detail`, async ({ page }) => {
      await page.setViewportSize(viewport);
      await openWith(page, emptyPayload());
      await waitForResult(page);
      await expectNoUiGlitches(page, `${ROUTE} result with unknown details @${name}`, { forbiddenText: ['\\bnull\\b'] });
    });
  }
});

test.describe('What Is My IP — every displayed value equals the API answer', () => {
  test('random payloads: address card, summary cards, geolocation, network, request headers and links', async ({ page, rng, evidence }) => {
    const payloads = [
      generatePayload(rng.fork('1'), { version: 'IPv4', missing: 0 }),
      generatePayload(rng.fork('2'), { version: 'IPv6', missing: 0.1 }),
      generatePayload(rng.fork('3'), { missing: 0.35 }),
      generatePayload(rng.fork('4'), { missing: 0.6 }),
      generatePayload(rng.fork('5')),
      generatePayload(rng.fork('6')),
    ];
    await evidence.save('payloads.json', payloads);
    let current = payloads[0];
    const calls = await openWith(page, () => current);
    for (const [number, payload] of payloads.entries()) {
      current = payload;
      if (number > 0) await page.reload({ waitUntil: 'domcontentloaded' });
      await waitForResult(page);
      await expectPayloadShown(page, payload, `payload ${number + 1} (${payload.ip})`, addressesOf(payload));
    }
    expect.soft(calls.every(call => call.method === 'GET'), 'the page only reads /api/myip').toBe(true);
    expect.soft(calls.every(call => !call.url.includes('?')), 'the page asks about the caller, without an ip= parameter').toBe(true);
  });

  test('a payload in which nothing is known shows dashes and explanations, never "null"', async ({ page }) => {
    const payload = emptyPayload('198.51.100.23');
    await openWith(page, payload);
    await waitForResult(page);
    await expectPayloadShown(page, payload, 'payload with every optional field null', addressesOf(payload));
    const sections = await readSections(page);
    for (const row of sections['Geolocation'] ?? []) {
      expect.soft(row.value, `Geolocation "${row.label}" when unknown`).toBe(DASH);
    }
    expect.soft(rowsToRecord(sections['GeoLite ASN & Network'])['Reverse DNS (PTR)'], 'reverse DNS when unknown').toBe('No PTR record found');
    expect.soft((await readAddressCard(page)).ipv6.value, 'IPv6 box when no IPv6 address was seen').toMatch(/^Not Detected\s*Your network does not support IPv6$/);
  });

  test('the country is known but the city is not: the City row explains it', async ({ page, rng }) => {
    const payload = { ...generatePayload(rng, { missing: 0 }), city: null };
    await openWith(page, payload);
    await waitForResult(page);
    expect.soft(rowsToRecord((await readSections(page))['Geolocation']).City, `City row for ${payload.country} without a city`).toBe(NO_CITY);
    expect.soft((await readStats(page)).City, 'City summary card without a city').toBe(DASH);
    await expectPayloadShown(page, payload, 'payload without a city', addressesOf(payload));
  });

  test('an IPv6 visitor: the IPv6 box shows the address, the IPv4 box says "Not Detected", the badge says "IPv6 Only"', async ({ page, rng }) => {
    const payload = generatePayload(rng, { version: 'IPv6', missing: 0 });
    await openWith(page, payload);
    await waitForResult(page);
    const card = await readAddressCard(page);
    expect.soft(card.ipv6.value, 'IPv6 box').toBe(payload.ip);
    expect.soft(card.ipv4.value, 'IPv4 box').toBe('Not Detected');
    expect.soft(card.badges[0], 'stack badge').toBe('IPv6 Only');
    await expectPayloadShown(page, payload, 'IPv6-only visitor', addressesOf(payload));
  });

  test('a dual-stack visitor: both boxes show an address and the badge says "Dual-Stack"', async ({ page, rng, evidence }) => {
    // The details call answers with the IPv4 view; the two detection calls see the same visitor over IPv6 and IPv4.
    const details = generatePayload(rng, { version: 'IPv4', missing: 0 });
    const ipv6 = publicIpv6(rng);
    const overV6 = { ...details, ip: ipv6, ip_version: 'IPv6' };
    await evidence.save('answers.json', { details, overV6 });
    const calls = await openWith(page, callNumber => (callNumber === 1 ? overV6 : details));
    await waitForResult(page);
    expect(calls.length, 'the page asks /api/myip three times: details, IPv6 detection, IPv4 detection').toBe(3);
    await expectPayloadShown(page, details, 'dual-stack visitor', { ipv4: details.ip, ipv6 });
  });

  test('every network type has its label, and an unexpected type is shown as "Unknown"', async ({ page, rng }) => {
    const types = [...Object.keys(NETWORK_LABELS), 'satellite', ''];
    let current = { ...generatePayload(rng, { missing: 0 }), network_type: types[0] };
    await openWith(page, () => current);
    for (const [number, type] of types.entries()) {
      current = { ...current, network_type: type };
      if (number > 0) await page.reload({ waitUntil: 'domcontentloaded' });
      await waitForResult(page);
      const card = await readAddressCard(page);
      const row = rowsToRecord((await readSections(page))['GeoLite ASN & Network'])['Estimated Network Type'];
      expect.soft(card.badges[1], `network badge for type "${type}"`).toBe(networkLabel(type));
      expect.soft(row, `"Estimated Network Type" row for type "${type}"`).toBe(networkLabel(type));
    }
  });

  test('coordinates at the limits of the globe are shown with four decimals', async ({ page }) => {
    const cases: [number, number][] = [[90, 180], [-90, -180], [89.99994, -179.99996], [-33.868821, 151.209296], [0.5, -0.1275], [64.1466, -21.9426]];
    let current: MyIpPayload = { ...emptyPayload('203.0.113.77'), country: 'Testland', country_code: 'TL', latitude: cases[0][0], longitude: cases[0][1] };
    await openWith(page, () => current);
    for (const [number, [latitude, longitude]] of cases.entries()) {
      current = { ...current, latitude, longitude };
      if (number > 0) await page.reload({ waitUntil: 'domcontentloaded' });
      await waitForResult(page);
      expect.soft(rowsToRecord((await readSections(page))['Geolocation']).Coordinates, `Coordinates for latitude ${latitude}, longitude ${longitude}`).toBe(coordinatesText(current));
    }
  });

  test('a location on the equator or on the prime meridian still has coordinates', async ({ page }) => {
    const cases: [number, number, string][] = [[0, 32.5825, 'on the equator (Uganda)'], [51.4779, 0, 'on the prime meridian (Greenwich)'], [0, 0, 'at 0°, 0°']];
    let current: MyIpPayload = { ...emptyPayload('203.0.113.78'), country: 'Testland', country_code: 'TL', latitude: cases[0][0], longitude: cases[0][1] };
    await openWith(page, () => current);
    for (const [number, [latitude, longitude, where]] of cases.entries()) {
      current = { ...current, latitude, longitude };
      if (number > 0) await page.reload({ waitUntil: 'domcontentloaded' });
      await waitForResult(page);
      expect.soft(rowsToRecord((await readSections(page))['Geolocation']).Coordinates, `Coordinates for latitude ${latitude}, longitude ${longitude} (${where}): 0 is a real coordinate, not a missing one`).toBe(coordinatesText(current));
    }
  });

  test('markup in any text field of the answer is shown as text and creates no element', async ({ page, rng }) => {
    const base = fullPayload(rng);
    const payload: MyIpPayload = {
      ...base,
      city: '<img src=x onerror="window.__xss=1">',
      region: '<b>Region</b>', country: '<u>Country</u>', registered_country: '<i>Registered</i>',
      isp: '<script>window.__xss=2</script>Evil <b>Corp</b>', org: '<script>window.__xss=2</script>Evil <b>Corp</b>',
      domain: '<a href="javascript:window.__xss=3">x</a>', usage_type: '<svg onload="window.__xss=4">',
      reverse_dns: '"><img src=x onerror="window.__xss=5">.example.net', timezone: '<marquee>tz</marquee>',
      headers: { ...base.headers, user_agent: '<img src=x onerror="window.__xss=6">', accept_language: '<b>en</b>' },
    };
    let dialogs = 0;
    page.on('dialog', dialog => { dialogs++; void dialog.dismiss(); });
    await openWith(page, payload);
    await waitForResult(page);
    await expectPayloadShown(page, payload, 'payload with markup', addressesOf(payload));
    const injected = await page.locator('.signal-tool-primary').evaluate(root => ({
      elements: root.querySelectorAll('img, script, svg, marquee, u, a[href^="javascript"]').length,
      flag: (window as unknown as { __xss?: number }).__xss ?? null,
    }));
    expect.soft(injected, 'no element may be created from the answer and no injected script may run').toEqual({ elements: 0, flag: null });
    expect.soft(dialogs, 'no dialog may open').toBe(0);
  });

  test('the backend\'s "not detected on this connection" answer (ip: null) is shown as a message, not as a crashed page', async ({ page }) => {
    // backend/src/routes/myip.js answers HTTP 200 with this body when the request host name contains
    // "ipv6" (or "ipv4") and the visitor arrived over the other protocol.
    const answer = { ip: null, ip_version: null, error: 'IPv6 not detected on this connection' };
    await mockApi(page, MYIP_URL, answer);
    await page.goto(ROUTE, { waitUntil: 'domcontentloaded' });
    await expect(loadingCard(page), 'the loading card must end').toHaveCount(0);
    await expect.soft(page.getByRole('heading', { level: 1, name: HEADING }), 'the tool must still be on screen (the page shows "This page couldn\'t load" instead)').toBeVisible({ timeout: 3_000 });
    expect.soft(await page.locator('body').innerText(), 'the visitor must be told that no address was detected').toMatch(/not detected|IPv6/i);
  });
});

test.describe('What Is My IP — controls on the result', () => {
  test('"Browser & Device" and "HTTP Request Headers" start collapsed, open on click and close again', async ({ page, rng }) => {
    await openWith(page, fullPayload(rng));
    await waitForResult(page);
    for (const title of ['Browser & Device', 'HTTP Request Headers']) {
      const card = section(page, title);
      const firstValue = card.locator('dl.signal-myip-details dd').first();
      await expect(card, `"${title}" starts collapsed`).not.toHaveAttribute('open', /.*/);
      await expect(firstValue, `rows of "${title}" are hidden while collapsed`).toBeHidden();
      await card.locator('summary').click();
      await expect(card, `"${title}" opens on click`).toHaveAttribute('open', /.*/);
      await expect(firstValue, `rows of "${title}" are visible when open`).toBeVisible();
      await card.locator('summary').click();
      await expect(firstValue, `rows of "${title}" are hidden again after a second click`).toBeHidden();
    }
    for (const title of ['Geolocation', 'GeoLite ASN & Network', 'Browser-Estimated Connection']) {
      await expect(page.locator('.signal-tool-primary .glass').filter({ hasText: title }).first(), `"${title}" is always open`).toBeVisible();
    }
  });

  test('the ASN and DNS links point at routes of this site that exist', async ({ page, rng, request }) => {
    const payload = { ...fullPayload(rng), asn: 64496 + rng.int(0, 15), reverse_dns: `host-${rng.int(1, 99)}.dsl.example.co.uk` };
    await openWith(page, payload);
    await waitForResult(page);
    await expect(asnLookupLink(page)).toHaveAttribute('href', `/asn?asn=${payload.asn}`);
    await expect(page.getByRole('link', { name: 'More info →' })).toHaveAttribute('href', `/asn?asn=${payload.asn}`);
    const dnsHref = (await dnsLookupLink(page).getAttribute('href')) ?? '';
    expect.soft(isLabelSuffix(new URL(dnsHref, 'http://x').searchParams.get('domain') ?? '', payload.reverse_dns), `"DNS Lookup" target ${dnsHref} is the PTR name or a parent domain of ${payload.reverse_dns}`).toBe(true);
    for (const href of [`/asn?asn=${payload.asn}`, dnsHref]) {
      const response = await request.get(href);
      expect.soft(response.status(), `GET ${href}`).toBe(200);
    }
    expect.soft(flagOf('GB'), 'oracle self-check: flag of GB').toBe('🇬🇧');
  });
});

test.describe('What Is My IP — real backend', () => {
  test('the page shows exactly what /api/myip returned, and the address is the one the backend sees for this client', async ({ page, request, evidence }) => {
    const recorder = recordMyIpResponses(page);
    await openTool(page, ROUTE, HEADING);
    await waitForResult(page);
    const answers = await recorder.answers();
    await evidence.save('real-answers.json', answers);
    expect(answers.length, 'three GET /api/myip calls on load').toBe(3);
    expect(answers.map(answer => answer.status), 'all three answer 200').toEqual([200, 200, 200]);
    const payload = answers[0].body as MyIpPayload;

    // The same question asked directly, outside the browser.
    const direct = await (await request.get('/api/myip')).json() as MyIpPayload;
    expect.soft(payload.ip, 'address in the page\'s answer equals the address the backend reports to a direct request from this machine').toBe(direct.ip);
    expect.soft(['127.0.0.1', '::1'], `the test client reaches the backend over loopback; it reported ${payload.ip}`).toContain(payload.ip);
    expect.soft(payload.ip_version, 'ip_version matches the address syntax').toBe(payload.ip.includes(':') ? 'IPv6' : 'IPv4');
    for (const key of ['city', 'region', 'country', 'country_code', 'continent', 'postal_code', 'latitude', 'longitude', 'timezone', 'utc_offset', 'isp', 'asn'] as const) {
      expect.soft(payload[key], `/api/myip "${key}" for a loopback address (no GeoIP record exists)`).toBeNull();
    }
    expect.soft(payload.headers.user_agent, 'the backend echoes the User-Agent the browser sent').toBe(await page.evaluate(() => navigator.userAgent));

    await expectPayloadShown(page, payload, `real answer for ${payload.ip}`, addressesOf(payload));
    await expect(asnLookupLink(page), 'no ASN link for a loopback address').toHaveCount(0);
    await expect(shareButton(page)).toBeEnabled();
    await expect(htmlButton(page)).toBeEnabled();
    await expect(csvButton(page)).toBeEnabled();
    await expect(addressCard(page)).toContainText(payload.ip);
  });
});
