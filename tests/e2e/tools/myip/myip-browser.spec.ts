import { test, expect, type Page } from '../_support/fixtures';
import { openTool } from '../_support/navigation';
import { emptyPayload, fullPayload } from './generator';
import { BROWSER_PROFILES, EMBEDDED_TOKEN_AGENTS, type MyIpPayload } from './oracle';
import { HEADING, MYIP_URL, ROUTE, openWith, readSections, recordMyIpResponses, rowsToRecord, waitForResult } from './page';

/**
 * /myip — browser diagnostics. The oracle is the browser context the test
 * configures: the page must report exactly that browser.
 * Inventory and layer map: see myip.spec.ts.
 */

/** The WebGL renderer string, read the same way any page can, independent of the tool's own code path. */
async function webglRenderer(page: Page): Promise<string | null> {
  return page.evaluate(() => {
    const gl = document.createElement('canvas').getContext('webgl');
    const info = gl?.getExtension('WEBGL_debug_renderer_info');
    return gl && info ? String(gl.getParameter(info.UNMASKED_RENDERER_WEBGL)) : null;
  });
}

async function deviceRows(page: Page): Promise<Record<string, string>> {
  return rowsToRecord((await readSections(page))['Browser & Device']);
}

for (const profile of BROWSER_PROFILES) {
  test.describe(`What Is My IP — visited with ${profile.name}`, () => {
    test.use({
      userAgent: profile.userAgent,
      viewport: profile.viewport,
      // `screen` is a context option that test.use only forwards through contextOptions.
      contextOptions: { screen: profile.screen },
      locale: profile.locale,
      timezoneId: profile.timezoneId,
      deviceScaleFactor: profile.deviceScaleFactor,
      colorScheme: profile.colorScheme,
    });

    test('reports this browser, system, screen and language, and the headers this browser really sent', async ({ page, evidence }) => {
      await page.addInitScript((platform) => {
        Object.defineProperty(Navigator.prototype, 'platform', { get: () => platform, configurable: true });
      }, profile.platform);
      const recorder = recordMyIpResponses(page);
      await openTool(page, ROUTE, HEADING);
      await waitForResult(page);

      // The context really is what the profile says (a check of the test setup, not of the tool).
      const context = await page.evaluate(() => ({
        ua: navigator.userAgent, width: window.innerWidth, height: window.innerHeight, zone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        ratio: window.devicePixelRatio, dark: window.matchMedia('(prefers-color-scheme: dark)').matches, language: navigator.language,
        screen: [window.screen.width, window.screen.height],
      }));
      expect(context, 'browser context configured as the profile describes').toEqual({
        ua: profile.userAgent, width: profile.viewport.width, height: profile.viewport.height, zone: profile.timezoneId,
        ratio: profile.deviceScaleFactor, dark: profile.colorScheme === 'dark', language: profile.locale,
        screen: [profile.screen.width, profile.screen.height],
      });

      const rows = await deviceRows(page);
      await evidence.save('browser-rows.json', rows);
      const ctx = `${profile.name} (${profile.userAgent})`;
      expect.soft(rows['Browser'], `${ctx}: Browser names the right family`).toMatch(profile.browser.family);
      expect.soft(rows['Browser'], `${ctx}: Browser carries the version from the UA string`).toContain(profile.browser.version);
      expect.soft(rows['Browser'], `${ctx}: Browser names no other browser`).not.toMatch(profile.browser.not);
      expect.soft(rows['Operating System'], `${ctx}: Operating System family`).toMatch(profile.os.family);
      expect.soft(rows['Operating System'], `${ctx}: Operating System version from the UA string`).toContain(profile.os.version);
      expect.soft(rows['Screen Resolution'], `${ctx}: Screen Resolution is the screen size, not the viewport ${profile.viewport.width}×${profile.viewport.height}`).toBe(`${profile.screen.width} × ${profile.screen.height}`);
      expect.soft(rows['Language'], `${ctx}: Language`).toBe(profile.locale);
      expect.soft(rows['Platform'], `${ctx}: Platform`).toBe(profile.platform);
      expect.soft(rows['Cookies'], `${ctx}: Cookies (enabled in this context)`).toBe('Enabled');
      expect.soft(rows['Do Not Track'], `${ctx}: Do Not Track (not set in this context)`).toBe('Disabled');
      const renderer = await webglRenderer(page);
      if (renderer) expect.soft(rows['GPU / WebGL'], `${ctx}: GPU / WebGL renderer`).toBe(renderer);
      else expect.soft(['Not available', 'Restricted'], `${ctx}: GPU / WebGL when the browser exposes no renderer, shown "${rows['GPU / WebGL']}"`).toContain(rows['GPU / WebGL']);

      // Request headers: the real backend echoes what this browser sent.
      const [details] = await recorder.answers();
      const payload = details.body as MyIpPayload;
      const headers = rowsToRecord((await readSections(page))['HTTP Request Headers']);
      expect.soft(payload.headers.user_agent, `${ctx}: User-Agent the backend received`).toBe(profile.userAgent);
      expect.soft(headers['User-Agent'], `${ctx}: User-Agent row`).toBe(profile.userAgent);
      expect.soft(headers['Accept-Language'], `${ctx}: Accept-Language row equals the backend's answer`).toBe(payload.headers.accept_language || '—');
      expect.soft(headers['Accept-Language'].startsWith(profile.locale), `${ctx}: Accept-Language "${headers['Accept-Language']}" starts with the browser language ${profile.locale}`).toBe(true);
      expect.soft(headers['Accept-Encoding'], `${ctx}: Accept-Encoding row equals the backend's answer`).toBe(payload.headers.accept_encoding || '—');
      expect.soft(headers['DNT (Do Not Track)'], `${ctx}: DNT row (no DNT header sent)`).toBe('Not set');
    });
  });
}

test.describe('What Is My IP — browser diagnostics', () => {
  test('a browser whose UA string embeds another browser\'s token is not reported as that other browser', async ({ browser, rng }, testInfo) => {
    const payload = fullPayload(rng);
    for (const agent of EMBEDDED_TOKEN_AGENTS) {
      const context = await browser.newContext({ baseURL: testInfo.project.use.baseURL, userAgent: agent.userAgent });
      const visitor = await context.newPage();
      await openWith(visitor, payload);
      await waitForResult(visitor);
      const rows = await deviceRows(visitor);
      expect.soft(rows['Browser'], `${agent.name} (${agent.userAgent}) is shown as "${rows['Browser']}"; it must not be named after the token it only embeds`).not.toMatch(agent.isNot);
      await context.close();
    }
  });

  test('Do Not Track on and cookies off are reported as the browser states them', async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(Navigator.prototype, 'doNotTrack', { get: () => '1', configurable: true });
      Object.defineProperty(Navigator.prototype, 'cookieEnabled', { get: () => false, configurable: true });
    });
    await page.setExtraHTTPHeaders({ DNT: '1' });
    const recorder = recordMyIpResponses(page);
    await openTool(page, ROUTE, HEADING);
    await waitForResult(page);
    const rows = await deviceRows(page);
    expect.soft(rows['Do Not Track'], 'Do Not Track with navigator.doNotTrack = "1"').toBe('Enabled');
    expect.soft(rows['Cookies'], 'Cookies with navigator.cookieEnabled = false').toBe('Disabled');
    const [details] = await recorder.answers();
    expect.soft((details.body as MyIpPayload).headers.dnt, 'DNT header the real backend received').toBe('1');
    expect.soft(rowsToRecord((await readSections(page))['HTTP Request Headers'])['DNT (Do Not Track)'], 'DNT row with the header sent').toBe('1');
  });

  const connections = [
    { type: 'cellular', effectiveType: '3g', downlink: 1.45, rtt: 350, saveData: true },
    { type: 'wifi', effectiveType: '4g', downlink: 10, rtt: 50, saveData: false },
    { type: 'ethernet', effectiveType: 'slow-2g', downlink: 0, rtt: 0, saveData: false },
  ];
  for (const connection of connections) {
    test(`the connection card shows what the Network Information API reports (${connection.type}, ${connection.effectiveType}, ${connection.downlink} Mbps)`, async ({ page }) => {
      await page.addInitScript((fake) => {
        Object.defineProperty(Navigator.prototype, 'connection', { get: () => fake, configurable: true });
      }, connection);
      await openWith(page, emptyPayload('203.0.113.50'));
      await waitForResult(page);
      const rows = rowsToRecord((await readSections(page))['Browser-Estimated Connection']);
      const ctx = `navigator.connection = ${JSON.stringify(connection)}`;
      expect.soft(rows['Browser Connection Type']?.toLowerCase(), `${ctx}: Browser Connection Type`).toBe(connection.type);
      expect.soft(rows['Effective Type']?.toLowerCase(), `${ctx}: Effective Type`).toBe(connection.effectiveType);
      expect.soft(rows['Estimated Bandwidth'], `${ctx}: Estimated Bandwidth`).toBe(`${connection.downlink} Mbps`);
      expect.soft(rows['Round-Trip Time'], `${ctx}: Round-Trip Time`).toBe(`${connection.rtt} ms`);
      expect.soft(rows['Data Saver'], `${ctx}: Data Saver`).toBe(connection.saveData ? 'Enabled' : 'Disabled');
    });
  }

  test('the connection card of this browser equals its own Network Information API', async ({ page }) => {
    await openWith(page, emptyPayload('203.0.113.51'));
    await waitForResult(page);
    const api = await page.evaluate(() => {
      const c = (navigator as unknown as { connection?: { type?: string; effectiveType?: string; downlink?: number; rtt?: number; saveData?: boolean } }).connection;
      return c ? { type: c.type ?? null, effectiveType: c.effectiveType ?? null, downlink: c.downlink ?? null, rtt: c.rtt ?? null, saveData: !!c.saveData } : null;
    });
    test.skip(api === null, 'this browser has no Network Information API');
    const rows = rowsToRecord((await readSections(page))['Browser-Estimated Connection']);
    expect.soft(rows['Browser Connection Type']?.toLowerCase(), 'Browser Connection Type').toBe((api!.type ?? 'unknown').toLowerCase());
    expect.soft(rows['Effective Type']?.toLowerCase(), 'Effective Type').toBe((api!.effectiveType ?? 'unknown').toLowerCase());
    expect.soft(rows['Estimated Bandwidth'], 'Estimated Bandwidth').toBe(api!.downlink === null ? '—' : `${api!.downlink} Mbps`);
    expect.soft(rows['Round-Trip Time'], 'Round-Trip Time').toBe(api!.rtt === null ? '—' : `${api!.rtt} ms`);
    expect.soft(rows['Data Saver'], 'Data Saver').toBe(api!.saveData ? 'Enabled' : 'Disabled');
  });

  test('a browser without the Network Information API gets an explanation instead of connection values', async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(Navigator.prototype, 'connection', { get: () => undefined, configurable: true });
    });
    await openWith(page, emptyPayload('203.0.113.52'));
    await waitForResult(page);
    const card = page.locator('.signal-tool-primary .glass').filter({ hasText: 'Browser-Estimated Connection' });
    await expect(card, 'explanation in the connection card').toContainText('Not Supported in Your Browser');
    await expect(card).toContainText('The Network Information API is not available in your browser.');
    expect.soft((await readSections(page))['Browser-Estimated Connection'], 'no connection rows without the API').toBeUndefined();
  });
});

test.describe('What Is My IP — request made by the page', () => {
  test('GET /api/myip is called through the site\'s own /api path with no address parameter', async ({ page }) => {
    const urls: string[] = [];
    page.on('request', request => { if (request.url().includes('/api/myip')) urls.push(`${request.method()} ${new URL(request.url()).pathname}${new URL(request.url()).search}`); });
    await page.route(MYIP_URL, route => route.fulfill({ json: emptyPayload('203.0.113.53') }));
    await page.goto(ROUTE, { waitUntil: 'domcontentloaded' });
    await waitForResult(page);
    expect(urls, 'requests for the visitor\'s address').toEqual(['GET /api/myip', 'GET /api/myip', 'GET /api/myip']);
  });
});
