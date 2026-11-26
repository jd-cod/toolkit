/**
 * Bot Intelligence Gold Set Auditor (offline)
 * ============================================
 * Loads the REAL `frontend/public/js/bot-detector.js` into Node and replays
 * `tests/fixtures/bot-intel-test.log` line by line, asserting each request's
 * classification against the ground truth in `bot-intel-expected.json`.
 *
 * This is deliberately offline: no browser, no dev container, no network. It
 * isolates bot-detection correctness from UI rendering so a failure here is
 * unambiguously a logic bug rather than a Playwright flake.
 *
 * Run:  node scripts/qa_bot_intel_gold_set.mjs
 */

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');

const DETECTOR_SRC = path.join(ROOT, 'frontend/public/js/bot-detector.js');
const PARSER_SRC = path.join(ROOT, 'frontend/public/js/log-parser.js');
const FEED_PATH = path.join(ROOT, 'frontend/public/data/verified-bots.json');
const LOG_PATH = path.join(ROOT, 'tests/fixtures/bot-intel-test.log');
const EXPECTED_PATH = path.join(ROOT, 'tests/fixtures/bot-intel-expected.json');

/**
 * Minimal browser shim: these scripts only need `window` plus the handful of
 * APIs they touch during init. We serve fetch from disk and deliberately leave
 * `indexedDB` undefined so `openIndexedDb()` rejects into its own `catch` and
 * the persistence layer degrades instead of hanging. (A stub that never fires
 * `onsuccess` would deadlock `init()` forever — the promise simply never
 * settles.)
 *
 * Both `bot-detector.js` and `log-parser.js` are loaded into the SAME sandbox so
 * the audit runs the real pair together, exactly as the page does. Loading only
 * the detector would hide a whole class of bug: the parser consults the detector
 * to decide which private/403 lines are security-relevant bot traffic, and a
 * detector that is absent there silently changes which lines get classified.
 */
function loadBrowserScripts() {
  const source = fs.readFileSync(DETECTOR_SRC, 'utf8');
  const parserSource = fs.readFileSync(PARSER_SRC, 'utf8');
  const feed = fs.readFileSync(FEED_PATH, 'utf8');

  const sandbox = {
    console: { log: () => {}, warn: () => {}, error: () => {} },
    fetch: async (url) => {
      if (String(url).includes('verified-bots.json')) {
        return { ok: true, json: async () => JSON.parse(feed) };
      }
      return { ok: false, json: async () => ({}) };
    },
    setTimeout,
    clearTimeout,
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;

  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: DETECTOR_SRC });
  vm.runInContext(parserSource, sandbox, { filename: PARSER_SRC });

  if (!sandbox.BotDetector) {
    throw new Error('bot-detector.js did not expose window.BotDetector');
  }
  if (!sandbox.LogParser) {
    throw new Error('log-parser.js did not expose window.LogParser');
  }
  return sandbox;
}

/** Parse one Nginx Combined Log Format line into the fields we assert on. */
function parseLogLine(line, LogParser) {
  const m = line.match(
    /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*?) HTTP\/[\d.]+" (\d{3}) (\S+) "([^"]*)" "([^"]*)"/
  );
  if (!m) return null;
  // Validate the IP exactly as the browser does. A permissive `\S+` capture
  // would happily accept `123.456.789.0`, which `log-parser.js` rejects, and
  // the audit would then assert a verdict the dashboard can never produce.
  if (LogParser && typeof LogParser.isValidIP === 'function' && !LogParser.isValidIP(m[1])) {
    return null;
  }
  return { ip: m[1], ts: m[2], method: m[3], path: m[4], status: m[5], userAgent: m[8] };
}

async function main() {
  for (const [label, file] of [
    ['bot-detector.js', DETECTOR_SRC],
    ['log-parser.js', PARSER_SRC],
    ['verified-bots.json', FEED_PATH],
    ['bot-intel-test.log', LOG_PATH],
    ['bot-intel-expected.json', EXPECTED_PATH],
  ]) {
    if (!fs.existsSync(file)) {
      console.error(`❌ Missing ${label} at ${file}`);
      process.exitCode = 1;
      return;
    }
  }

  const { BotDetector, LogParser } = loadBrowserScripts();
  const loaded = await BotDetector.init();
  if (!loaded) {
    console.error('❌ BotDetector.init() failed to load the verified-bots feed.');
    process.exitCode = 1;
    return;
  }

  const stats = BotDetector.getBotStats();
  console.log('═'.repeat(74));
  console.log('  BOT INTELLIGENCE GOLD SET AUDIT (offline, real bot-detector.js)');
  console.log('═'.repeat(74));
  console.log(`  Sources loaded : ${stats.totalSources}`);
  console.log(`  CIDRs compiled : ${stats.totalCidrs}\n`);

  const lines = fs.readFileSync(LOG_PATH, 'utf8').split('\n').filter(Boolean);
  const manifest = JSON.parse(fs.readFileSync(EXPECTED_PATH, 'utf8'));

  if (lines.length !== manifest.cases.length) {
    console.error(
      `❌ Fixture drift: log has ${lines.length} lines, manifest has ${manifest.cases.length} cases. ` +
      'Re-run: python3 scripts/generate_bot_intel_test_logs.py'
    );
    process.exitCode = 1;
    return;
  }

  const results = [];
  const unparseable = [];

  for (let i = 0; i < lines.length; i++) {
    const parsed = parseLogLine(lines[i], LogParser);
    if (!parsed) {
      // A case marked `parses: false` is SUPPOSED to be rejected here (a
      // syntactically impossible IP, say). One we expected to parse but
      // could not is a fixture bug and must not be skipped quietly.
      if (manifest.cases[i].parses !== false) {
        console.error(
          `❌ Line ${i + 1} is marked parseable in the manifest but the parser rejected it: ` +
          `${lines[i].slice(0, 80)}`
        );
        process.exitCode = 1;
      } else {
        unparseable.push({ line: i + 1, text: lines[i], expected: true });
      }
      continue;
    }

    // detectBot() returns { name, group } or null - use detectBotName() for the
    // bare string that verifyBot() expects.
    const detected = BotDetector.detectBot(parsed.userAgent);
    const botName = detected ? detected.name : null;
    const verification = BotDetector.verifyBot(botName, parsed.ip);

    results.push({
      index: i + 1,
      ip: parsed.ip,
      path: parsed.path,
      scenario: manifest.cases[i].scenario,
      detectedBot: botName,
      actualStatus: verification.status,
      expectedStatus: manifest.cases[i].expected_status,
      expectedBot: manifest.cases[i].expected_bot,
      reason: verification.reason,
      pass: verification.status === manifest.cases[i].expected_status,
    });
  }

  // ── Report ────────────────────────────────────────────────────────────
  const scenarioOrder = ['verified_bots', 'impersonators', 'edge_cases', 'subnet_scan', 'human_baseline'];
  for (const scenario of scenarioOrder) {
    const rows = results.filter((r) => r.scenario === scenario);
    const failed = rows.filter((r) => !r.pass);
    const status = failed.length === 0 ? '✅' : '❌';
    console.log(`${status} ${scenario} (${rows.length} requests, ${failed.length} mismatched)`);
    for (const r of rows) {
      const mark = r.pass ? '  ·' : '  ✗';
      console.log(
        `${mark} ${r.ip.padEnd(16)} ${String(r.detectedBot || '—').padEnd(14)} ` +
        `${r.actualStatus.padEnd(20)} exp:${r.expectedStatus}`
      );
      if (!r.pass) console.log(`      reason: ${r.reason}`);
    }
    console.log();
  }

  if (unparseable.length) {
    console.log(`❌ ${unparseable.length} log line(s) failed to parse:`);
    for (const u of unparseable) console.log(`   line ${u.line}: ${u.text}`);
    console.log();
  }

  // ── Aggregate counts ──────────────────────────────────────────────────
  // Compare against `ui_expected_counts` (parseable cases only) so the offline
  // audit reconciles with what the dashboard can actually display. Comparing
  // against the full total would report a permanent 1-case deficit that is just
  // the deliberately-malformed line the parser is supposed to reject.
  const actualCounts = {};
  for (const r of results) {
    actualCounts[r.actualStatus] = (actualCounts[r.actualStatus] || 0) + 1;
  }
  const expectedCounts = manifest.ui_expected_counts || manifest.expected_counts;
  console.log('─'.repeat(74));
  console.log('  COUNT RECONCILIATION (parseable cases — matches the dashboard)');
  console.log('─'.repeat(74));
  let countsOk = true;
  for (const key of ['verified', 'spoofed', 'unverified_publisher', 'human']) {
    const exp = expectedCounts[key] || 0;
    const act = actualCounts[key] || 0;
    if (exp !== act) countsOk = false;
    console.log(
      `  ${key.padEnd(22)} expected ${String(exp).padStart(3)}   actual ${String(act).padStart(3)}   ` +
      `${exp === act ? '✅' : '❌'}`
    );
  }
  if (unparseable.length) {
    console.log(
      `\n  ${unparseable.length} line(s) correctly rejected by the parser before ` +
      `classification (as the manifest expects): ${unparseable.map((u) => u.text.split(' ')[0]).join(', ')}`
    );
  }
  console.log();

  const mismatches = results.filter((r) => !r.pass);
  console.log('─'.repeat(74));
  if (mismatches.length === 0 && countsOk) {
    const rejected = unparseable.length ? `, ${unparseable.length} correctly rejected` : '';
    console.log(
      `🎉 ALL ${results.length + unparseable.length} GOLD SET CASES HANDLED CORRECTLY ` +
      `(${results.length} classified${rejected})`
    );
  } else {
    console.log(
      `❌ ${mismatches.length} classification mismatch(es), ` +
      `${unparseable.length} unparseable line(s), counts reconciled: ${countsOk}`
    );
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error('Auditor crashed:', err);
  process.exitCode = 1;
});
