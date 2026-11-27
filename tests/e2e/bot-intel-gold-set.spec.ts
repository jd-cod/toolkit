import fs from 'node:fs';
import path from 'node:path';
import { test, expect, waitForEngineReady } from './fixtures/dashboard';
import type { Page } from '@playwright/test';

/**
 * Bot Intelligence Gold Set — UI render verification
 * ==================================================
 *
 * `scripts/qa_bot_intel_gold_set.mjs` proves bot-detection LOGIC is correct.
 * This spec proves the other half — that those verdicts REACH THE USER AS THE
 * RIGHT UI. A correct classifier behind a dashboard that renders the wrong
 * number or drops the alert is a silent, shipping bug.
 *
 * Ground truth comes from the manifest at runtime, never hardcoded, so
 * regenerating the fixture can't leave expectations stale.
 *
 * ── WHERE THE BOT UI ACTUALLY LIVES (read from source, not assumed) ─────
 *   KPI "VERIFIED BOTS" / "SPOOFED BOTS"      dashboard.js:263-273
 *   "2. Bot Intelligence" table                dashboard.js:1916-1964
 *   "Bot Traffic Analysis" + "Verified Genuine" report.js:746-803
 *   🚨 Fake Bot Alert banner                   report.js:754-760
 *   "Detected Spoofed Bot Attackers" table     report.js:795-801
 *   reached via #dash-download-btn (dashboard.js:533) → Report.openModal
 *   → runDownload (report.js:338), which builds an HTML file we intercept.
 *
 * NOTE: there is no `#spoofed-bot-alert-banner` and no `#spoofed-attackers-card`
 * anywhere in the repo. The on-page dashboard renders NO spoof alert banner at
 * all; that surface exists only inside the generated report. See the findings
 * section of the task report.
 *
 * ── WHY THESE ASSERTIONS CAN FAIL ───────────────────────────────────────
 * The manifest splits every case into "the classifier must return X" and "the
 * parser must accept this line at all" (`parses`). One fixture line carries a
 * syntactically impossible IP and is expected to be rejected before any bot
 * verdict exists, so `expected_counts` (all 42 cases, for the offline auditor)
 * and `ui_expected_counts` (41 parseable cases, for this spec) differ by one.
 *
 * The beforeEach hook asserts the parser discards EXACTLY the manifest's
 * unparseable set and nothing more. That is the load-bearing check: a
 * security-relevant line being dropped silently is precisely the bug class this
 * suite exists to catch, and it once hid real spoofed ClaudeBot/GPTBot traffic
 * behind a regex that could not match camelCase bot names.
 */

const FIXTURE_DIR = path.resolve(__dirname, '..', 'fixtures');
// The log is made from the crawler ranges of the day and is not kept in the
// repository: python3 scripts/generate_bot_intel_test_logs.py
const GOLD_LOG_PATH = path.join(FIXTURE_DIR, 'bot-intel-test.log');
const GOLD_LOG = fs.existsSync(GOLD_LOG_PATH) ? fs.readFileSync(GOLD_LOG_PATH, 'utf8') : '';
const MANIFEST = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'bot-intel-expected.json'), 'utf8')) as {
  expected_counts: Record<string, number>;
  ui_expected_counts: Record<string, number>;
  unparseable_ips: string[];
  cases: {
    ip: string;
    scenario: string;
    expected_status: string;
    expected_bot: string | null;
    parses: boolean;
  }[];
};

const LOG_LINES = GOLD_LOG.split('\n').filter(Boolean);

/** Replays the real log-parser in-page to report what it discarded and why. */
async function parserDiagnostics(page: Page) {
  return page.evaluate((log: string) => {
    const r = (window as any).LogParser.parseIPs(log, { skipInternal: false });
    return {
      parsed: r.logEntries.length,
      skipped: r.skippedLines.map((s: { reason: string; line: string }) => ({
        reason: s.reason,
        ip: s.line.split(' ')[0],
        line: s.line.slice(0, 90),
      })),
    };
  }, GOLD_LOG);
}

/** Intercepts the generated report and returns its HTML. */
async function reportHtml(page: Page): Promise<string> {
  await page.click('#dash-download-btn');
  await expect(page.locator('#download-modal-backdrop')).toBeVisible();
  const [download] = await Promise.all([
    page.waitForEvent('download', { timeout: 30_000 }),
    page.click('#dl-start-btn'),
  ]);
  const chunks: Buffer[] = [];
  for await (const c of await download.createReadStream()) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

const text = (page: Page, sel: string) =>
  page.evaluate((s) => document.querySelector(s)?.textContent?.trim() ?? 'MISSING', sel);

/**
 * Collapse an IPv4-mapped IPv6 literal to bare IPv4.
 *
 * `log-parser.js` normalises `::ffff:1.2.3.4` to `1.2.3.4` so a single client
 * arriving over either socket is not split into two aggregate rows. Expectation
 * builders must do the same or they count one client twice.
 */
const unmap = (ip: string) => ip.replace(/^::ffff:/, '');

/** Escape an IP for literal use inside a RegExp — `.` and `:` are both regex-significant. */
const esc = (ip: string) => ip.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** `<span class="ip-code">IP</span>` immediately followed by a verdict pill. */
const pillFor = (ip: string, emoji: string) =>
  new RegExp(`<span class="ip-code">${esc(ip)}</span>\\s*<span[^>]*>${emoji}`);

/** `<span class="ip-code">IP</span>` as a row in the attackers table. */
const attackerRowFor = (ip: string) =>
  new RegExp(`ip-code"[^>]*>${esc(ip)}</span></td>`);

/** Distinct spoofed clients, v4-mapped forms collapsed, parseable cases only. */
const spoofedClientIps = () => [
  ...new Set(
    MANIFEST.cases
      .filter((c) => c.expected_status === 'spoofed' && c.parses)
      .map((c) => unmap(c.ip)),
  ),
];

test.describe('Bot Intelligence Gold Set → UI', () => {
  test.skip(!GOLD_LOG, `fixture not present at ${GOLD_LOG_PATH}; run python3 scripts/generate_bot_intel_test_logs.py`);
  test.beforeEach(async ({ page }) => {
    await page.goto('/nginx', { waitUntil: 'load' });
    await waitForEngineReady(page);
    await page.getByRole('tab', { name: 'Paste logs' }).click();
    // Forensic opt-in: this classifier corpus deliberately includes private-IP
    // bot claims. Default exclusion behavior is tested in internal-exclusions.
    await page.locator('#nginx-skip-internal').uncheck();
    await page.fill('#nginx-logtext', GOLD_LOG);
    await page.click('#nginx-analyze-btn');
    await expect(page.locator('#nginx-dashboard')).toBeVisible({ timeout: 45_000 });
    await expect(page.locator('.kpi-micro-card').first()).toBeVisible();

    const diag = await parserDiagnostics(page);
    console.log(
      `DIAG fixtureLines=${LOG_LINES.length} parsed=${diag.parsed} discarded=${diag.skipped.length}`,
    );
    for (const s of diag.skipped) console.log(`DIAG_DISCARD [${s.reason}] ${s.ip}`);

    // The parser must discard EXACTLY the lines the manifest marks unparseable
    // (a syntactically impossible IP), and nothing else. Any other discard is a
    // real bug: it means a security-relevant request is invisible to the
    // dashboard, which is how spoofed ClaudeBot/GPTBot lines were once dropped.
    const discardedIps = diag.skipped.map((s) => s.ip).sort();
    expect(
      discardedIps,
      `Parser discarded [${discardedIps.join(', ')}] but the manifest only expects ` +
        `[${(MANIFEST.unparseable_ips || []).join(', ')}] to be unparseable.`,
    ).toEqual([...(MANIFEST.unparseable_ips || [])].sort());
  });

  // ── 1. KPI cards ───────────────────────────────────────────────────────
  // These count bot REQUESTS, not unique IPs, so they must be compared against
  // `ui_expected_counts` (parseable cases only) — the full `expected_counts`
  // includes the deliberately-malformed line the parser is supposed to reject,
  // which can never reach a bot verdict in the browser.
  test('KPI cards show the manifest verified / spoofed totals', async ({ page }) => {
    const v = await text(page, '.kpi-card-verified .stat-value');
    const vLbl = await text(page, '.kpi-card-verified .stat-label');
    const s = await text(page, '.kpi-card-spoofed .stat-value');
    const sLbl = await text(page, '.kpi-card-spoofed .stat-label');
    const exp = MANIFEST.ui_expected_counts;
    console.log(`KPI VERIFIED BOTS value="${v}" label="${vLbl}"`);
    console.log(`KPI SPOOFED BOTS  value="${s}" label="${sLbl}"`);
    console.log(`KPI EXPECTED     verified=${exp.verified} spoofed=${exp.spoofed}`);

    expect(v, `VERIFIED BOTS card. ${LOG_LINES.length} log lines, manifest expects ${exp.verified} verified bot requests.`).toBe(
      String(exp.verified),
    );
    expect(s, `SPOOFED BOTS card. ${LOG_LINES.length} log lines, manifest expects ${exp.spoofed} spoofed bot requests.`).toBe(
      String(exp.spoofed),
    );
  });

  // ── 2. Fake-bot alert banner ────────────────────────────────────────────
  // The banner states BOTH numbers, and they are different quantities:
  //   "Detected N requests"      -> spoofed_bots_count   (request count)
  //   "M unique IP(s) claim ..."  -> spoofed_bot_ips.length (unique IPs)
  // Asserting only the first is how a whole spoofed IP class can go missing
  // without the alert noticing.
  test('fake-bot alert banner is visible and names 185.220.101.5', async ({ page }) => {
    const report = await reportHtml(page);
    const banner = /🚨[^<]*/.exec(report)?.[0]?.trim() ?? '(none)';
    const subtext = /(\d+) unique IP\(s\)[^<]*/.exec(report)?.[0]?.trim() ?? '(none)';
    console.log(`ALERT BANNER: "${banner}"`);
    console.log(`ALERT SUBTEXT: "${subtext}"`);

    const spoofedCases = MANIFEST.cases.filter((c) => c.expected_status === 'spoofed' && c.parses);
    const expReqs = spoofedCases.length;
    // `::ffff:192.168.1.100` and `192.168.1.100` are ONE client, not two:
    // log-parser.js normalises the v4-mapped form to bare IPv4 precisely so a
    // single client arriving over either socket is not double-counted. Collapse
    // the mapped form here too, or the expectation over-counts by one.
    const unmap = (ip: string) => ip.replace(/^::ffff:/, '');
    const expIps = new Set(spoofedCases.map((c) => unmap(c.ip))).size;
    console.log(`ALERT EXPECTED requests=${expReqs} uniqueIps=${expIps}`);

    expect(report, 'No 🚨 Fake Bot Alert banner in the generated report.').toContain('Fake Bot Alert');
    expect(report, `Alert banner must count ${expReqs} spoofed requests.`).toContain(
      `Detected ${expReqs.toLocaleString('en-US')} requests`,
    );
    expect(report, `Alert banner must name ${expIps} unique spoofed IPs.`).toContain(
      `${expIps} unique IP(s)`,
    );
    expect(report, 'No "Detected Spoofed Bot Attackers" table.').toContain('Detected Spoofed Bot Attackers');
    expect(report, 'Attackers table does not name the Tor-exit IP 185.220.101.5.').toContain('185.220.101.5');
  });

  // ── 3. Bot Traffic Analysis badge for the real Googlebot ────────────────
  test('Bot Traffic Analysis marks real Googlebot 192.178.4.1 as genuine, never spoofed', async ({ page }) => {
    const report = await reportHtml(page);
    expect(report, 'No "Bot Traffic Analysis" section.').toContain('Bot Traffic Analysis');
    expect(report, 'Report contains no verification-status badges at all.').toMatch(
      /(Verified Genuine|Mixed|Unverified|Fake \/ Spoofed)/,
    );

    // The Google GROUP aggregates genuine + impersonated Googlebot traffic, so
    // its group status is "Mixed" by design. The per-IP verdict is what matters
    // and it lives in the expandable detail pills.
    const pill = (ip: string) => {
      const m = new RegExp(`<span class="ip-code">${esc(ip)}</span>\\s*<span[^>]*>(🟢|🔴)`).exec(report);
      return m ? m[1] : 'ABSENT';
    };
    const g1 = pill('192.178.4.1');
    const g2 = pill('192.178.4.129');
    console.log(`PILL 192.178.4.1=${g1} PILL 192.178.4.129=${g2}`);

    expect(g1, 'Real Googlebot 192.178.4.1 has no per-IP verdict pill in the report.').not.toBe('ABSENT');
    expect(g1, 'Real Googlebot 192.178.4.1 is badged 🔴 (spoofed) in the report.').not.toBe('🔴');
    expect(g1, 'Real Googlebot 192.178.4.1 is not badged 🟢 (genuine).').toBe('🟢');
    expect(g2, 'Real Googlebot 192.178.4.129 is not badged 🟢 (genuine).').toBe('🟢');
  });

  // ── 4. Humans must not be shown as bots ────────────────────────────────
  test('human traffic is not presented as a bot in the bot table or with a bot badge', async ({ page }) => {
    // IPs the manifest calls human and that NEVER serve bot traffic — the only
    // ones where a bot verdict would be unambiguously wrong.
    const humanOnly = [
      ...new Set(
        MANIFEST.cases
          .filter((c) => c.expected_status === 'human' && !MANIFEST.cases.some((o) => unmap(o.ip) === unmap(c.ip) && o.expected_status !== 'human'))
          .map((c) => unmap(c.ip)),
      ),
    ];
    console.log(`HUMAN_ONLY IPs: ${humanOnly.join(', ') || '(none)'}`);

    await expect(page.locator('.cross-filter-bot-row').first()).toBeVisible();
    const botTable = (await page.locator('.cross-filter-bot-row').allInnerTexts()).join('\n');
    for (const ip of humanOnly) {
      expect(botTable, `Human-only IP ${ip} leaked into the on-page Bot Intelligence table.`).not.toContain(ip);
    }

    const report = await reportHtml(page);
    for (const ip of humanOnly) {
      expect(
        report,
        `Human-only IP ${ip} was badged 🟢 genuine in the report.`,
      ).not.toMatch(pillFor(ip, '🟢'));
    }

    // The subnet-scan canaries share a /24 with spoofers 50-52 and must stay clean.
    for (const ip of ['203.0.113.10', '203.0.113.11', '203.0.113.12', '203.0.113.13', '203.0.113.14']) {
      expect(
        report,
        `Benign ${ip} (same /24 as spoofers 50-52) carries a bot verdict pill.`,
      ).not.toMatch(pillFor(ip, '[🟢🔴]'));
    }
  });

  // ── 5. Subnet-scan spoofers ────────────────────────────────────────────
  test('the subnet-scan spoofers 203.0.113.50-52 are each flagged as spoofed', async ({ page }) => {
    const report = await reportHtml(page);
    for (const ip of ['203.0.113.50', '203.0.113.51', '203.0.113.52']) {
      const spoofPill = pillFor(ip, '🔴');
      const attRow = attackerRowFor(ip);
      console.log(`SCAN ${ip}: pill=${spoofPill.test(report)} attackerRow=${attRow.test(report)}`);
      expect(report, `Subnet-scan spoofer ${ip} is not badged 🔴 spoofed.`).toMatch(spoofPill);
      expect(report, `Subnet-scan spoofer ${ip} is missing from "Detected Spoofed Bot Attackers".`).toMatch(attRow);
    }

    // Every manifest-spoofed client that SURVIVES PARSING must reach the
    // attackers table. Cases marked `parses: false` are rejected by
    // log-parser.js before any verdict exists, so they are legitimately
    // absent — but only those.
    const parsedIps: string[] = await page.evaluate(
      (log: string) =>
        ((window as any).LogParser.parseIPs(log, { skipInternal: false }).logEntries as { ip: string }[]).map((e) =>
          // Collapse v4-mapped form so it compares equal to the manifest's
          // `192.168.1.100` form of the same client.
          e.ip.replace(/^::ffff:/, ''),
        ),
      GOLD_LOG,
    );
    const attBlock = report.slice(report.indexOf('Detected Spoofed Bot Attackers'));
    const declaredUnparseable = new Set(MANIFEST.unparseable_ips || []);
    for (const ip of spoofedClientIps()) {
      if (!parsedIps.includes(ip)) {
        expect(
          declaredUnparseable.has(ip),
          `Spoofed IP ${ip} is parseable per the manifest but log-parser.js discarded it, ` +
            'so it is invisible to the dashboard. Only manifest-unparseable IPs may be absent.',
        ).toBe(true);
        continue;
      }
      expect(attBlock, `Spoofed IP ${ip} survives parsing but is absent from the attackers table.`).toContain(ip);
    }
  });
});
