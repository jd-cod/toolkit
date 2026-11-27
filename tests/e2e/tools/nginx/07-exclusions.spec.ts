import { test, expect } from './fixtures';
import { checkDashboard } from './checks';
import { analyse } from './oracle';
import { BROWSERS, UNLISTED_AGENTS, FEED_CRAWLERS, HEALTH_PATHS } from './catalog';
import { buildRequest, logFromRequests } from './generator';

/**
 * Traffic Analyzer — "Ignore 403 responses" and "Ignore internal requests".
 *
 * Both options exist on the input screen and above the results. All four
 * combinations are checked from both places, with the full dashboard compare.
 */

const COMBINATIONS = [
  { skip403: true, skipInternal: true },
  { skip403: false, skipInternal: true },
  { skip403: true, skipInternal: false },
  { skip403: false, skipInternal: false },
];

const sourceNote = (o: { skip403: boolean; skipInternal: boolean }) =>
  `Browser analysis · ${o.skip403 ? '403 exclusion enabled' : 'All response statuses included'} · ${o.skipInternal ? 'Internal requests excluded' : 'Internal requests included'}`;

test.describe('Traffic Analyzer — exclusions chosen before analysis', () => {
  for (const options of COMBINATIONS) {
    test(`ignore 403: ${options.skip403 ? 'on' : 'off'}, ignore internal: ${options.skipInternal ? 'on' : 'off'}`, async ({ analyzer, newLog }) => {
      const log = await newLog({ internalShare: 0.08, healthShare: 0.06 });
      await analyzer.analysePasted(log.text, options);
      const snap = await analyzer.snapshot();
      const want = checkDashboard(snap, log, { options }, 'input-screen options');
      expect.soft(snap.exclusions.skip403, 'dashboard checkbox "Ignore 403 responses" mirrors the choice').toBe(options.skip403);
      expect.soft(snap.exclusions.skipInternal, 'dashboard checkbox "Ignore internal requests" mirrors the choice').toBe(options.skipInternal);
      expect.soft(snap.sourceNote, 'source note names the active exclusions').toBe(sourceNote(options));
      const all = analyse(log, { skip403: false, skipInternal: false });
      expect(all.kept.length, 'sanity: the log contains lines each option would exclude').toBeGreaterThan(analyse(log).kept.length);
      expect(want.analysis.kept.length).toBeGreaterThan(0);
    });
  }
});

test.describe('Traffic Analyzer — exclusions changed on the dashboard', () => {
  test('toggling each option recalculates everything and resets the filters', async ({ analyzer, newLog }) => {
    const log = await newLog({ internalShare: 0.08, healthShare: 0.06 });
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    checkDashboard(await analyzer.snapshot(), log, {}, 'initial');

    // A filter is active when the option changes: the help text promises it is reset.
    await analyzer.selectMethod('POST');

    const steps: { id: string; options: { skip403: boolean; skipInternal: boolean } }[] = [
      { id: 'dash-skip-403', options: { skip403: false, skipInternal: true } },
      { id: 'dash-skip-internal', options: { skip403: false, skipInternal: false } },
      { id: 'dash-skip-403', options: { skip403: true, skipInternal: false } },
      { id: 'dash-skip-internal', options: { skip403: true, skipInternal: true } },
    ];
    for (const step of steps) {
      await analyzer.rerender(() => page.locator(`#${step.id}`).click());
      const snap = await analyzer.snapshot();
      checkDashboard(snap, log, { options: step.options }, `after toggling #${step.id}`);
      expect.soft(snap.sourceNote, 'source note follows the options').toBe(sourceNote(step.options));
      await expect.soft(page.locator('#dashboard-exclusions'), 'the option box is usable again after recalculating').toBeEnabled();
    }
  });

  test('the options chosen on the dashboard are kept when going back to the input screen', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 200 });
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    await analyzer.rerender(() => page.locator('#dash-skip-403').click());
    await page.locator('#dash-back-btn').click();
    await expect(page.locator('#nginx-input-section')).toBeVisible();
    await expect.soft(page.locator('#nginx-skip-403'), 'input-screen "Ignore 403 responses" follows the dashboard choice').not.toBeChecked();
    await expect.soft(page.locator('#nginx-skip-internal')).toBeChecked();
  });
});

test.describe('Traffic Analyzer — what counts as excluded', () => {
  test('every documented internal address range and health-check path is excluded, and look-alikes are kept', async ({ analyzer, geo }) => {
    const t = Date.UTC(2026, 2, 10, 9, 0, 0);
    let n = 0;
    const at = () => t + 1000 * n++;
    const human = BROWSERS[0];
    const internal = ['10.0.0.1', '10.255.255.255', '172.16.0.1', '172.31.255.254', '192.168.0.1', '192.168.255.254', '127.0.0.1', '127.255.255.254',
      '169.254.0.1', '169.254.255.254', '100.64.0.1', '100.127.255.254', 'fd12:3456:789a::1', 'fc00::1', 'fe80::abcd', '::1'];
    // One step outside each documented range: these are public and must be analysed.
    const lookAlike = ['9.255.255.255', '11.0.0.1', '172.15.255.255', '172.32.0.1', '192.167.255.255', '192.169.0.1', '126.255.255.255', '128.0.0.1',
      '169.253.255.255', '169.255.0.1', '100.63.255.255', '100.128.0.1', '2001:db8::1', 'fec0::1'];
    const healthUrls = [...HEALTH_PATHS, '/health/', '/healthz?verbose=1', '/readyz//'];
    const lookAlikeUrls = ['/healthcare', '/health/status', '/api/health', '/Health', '/healthz.php', '/livez2'];

    const requests = [
      ...internal.map(ip => ({ ...buildRequest(geo, { ip, ts: at(), agent: human }), internalAddress: true })),
      ...lookAlike.map(ip => buildRequest(geo, { ip, ts: at(), agent: human })),
      ...healthUrls.map(url => ({ ...buildRequest(geo, { ip: '8.8.4.4', ts: at(), agent: UNLISTED_AGENTS[2], url }), healthCheck: true })),
      ...lookAlikeUrls.map(url => buildRequest(geo, { ip: '8.8.4.4', ts: at(), agent: human, url })),
      // An internal address asking for a health path is counted once, as internal.
      { ...buildRequest(geo, { ip: '10.9.9.9', ts: at(), agent: human, url: '/health' }), internalAddress: true, healthCheck: true },
    ];
    const log = logFromRequests(requests);
    await analyzer.analysePasted(log.text);
    const snap = await analyzer.snapshot();
    const want = checkDashboard(snap, log, {}, 'documented exclusions');
    expect(want.analysis.skipped.internalAddress).toBe(internal.length + 1);
    expect(want.analysis.skipped.healthCheck).toBe(healthUrls.length);
    const shownIps = new Set(snap.explorer.rows.map(r => r.ip));
    expect.soft(lookAlike.filter(ip => !shownIps.has(ip)), 'public addresses next to an internal range that are missing from the analysis').toEqual([]);
  });

  test('403 responses: browsers are excluded, crawlers and scripted clients are kept', async ({ analyzer, geo }) => {
    const t = Date.UTC(2026, 2, 10, 9, 0, 0);
    const agents = [...BROWSERS, ...FEED_CRAWLERS, ...UNLISTED_AGENTS];
    const requests = agents.flatMap((agent, i) => [
      buildRequest(geo, { ip: `8.8.${i}.1`, ts: t + i * 2000, agent, status: 403 }),
      buildRequest(geo, { ip: `8.8.${i}.1`, ts: t + i * 2000 + 1000, agent, status: 200 }),
    ]);
    // Crawler user agents from addresses outside the published ranges are impersonators.
    for (const r of requests) if (r.agent.feedKey) r.trafficClass = 'spoofed';
    const log = logFromRequests(requests);
    await analyzer.analysePasted(log.text);
    const want = checkDashboard(await analyzer.snapshot(), log, {}, '403 handling');
    expect(want.analysis.skipped.forbidden, 'one 403 per browser is excluded').toBe(BROWSERS.length);

    await analyzer.rerender(() => analyzer.page.locator('#dash-skip-403').click());
    checkDashboard(await analyzer.snapshot(), log, { options: { skip403: false, skipInternal: true } }, '403 included');
  });

  test('when every request is excluded the dashboard says so and offers the options to include them', async ({ analyzer, geo }) => {
    const t = Date.UTC(2026, 2, 10, 9, 0, 0);
    const requests = Array.from({ length: 12 }, (_, i) => ({ ...buildRequest(geo, { ip: `10.0.0.${i + 1}`, ts: t + i * 1000, agent: BROWSERS[0] }), internalAddress: true }));
    const log = logFromRequests(requests);
    await analyzer.analysePasted(log.text);
    const { page } = analyzer;
    await expect.soft(page.locator('#dash-exclusion-status'), 'message when all valid requests are excluded').toHaveText('All valid requests are excluded. Adjust the options above to include them.');
    const snap = await analyzer.snapshot();
    expect.soft(snap.kpis.total, 'TOTAL REQUESTS with everything excluded').toBe('0');
    expect.soft(snap.exclusions.privateIp, 'skipped private/local IP count').toBe('12');

    await analyzer.rerender(() => page.locator('#dash-skip-internal').click());
    checkDashboard(await analyzer.snapshot(), log, { options: { skip403: true, skipInternal: false } }, 'internal requests included');
  });
});
