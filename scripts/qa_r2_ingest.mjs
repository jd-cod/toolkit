/**
 * UI-FIRST QA — nginx ingest session → dashboard, on the real dev domain.
 *
 * Pass 1: load the session URL, screenshot, log console + page errors.
 * Pass 2: reload the SAME url to prove the zero-retention delete-on-first-view
 *         behaviour surfaces a user-facing expired state (not a blank page).
 *
 * Usage: node scripts/qa_r2_ingest.mjs <sessionUrl>
 */
import { chromium } from 'playwright';
import { writeFileSync } from 'fs';

const SESSION_URL = process.argv[2];
if (!SESSION_URL) {
  console.error('Usage: node scripts/qa_r2_ingest.mjs <sessionUrl>');
  process.exit(1);
}

const outDir = '/tmp/qa_r2';
const consoleLog = [];
const pageErrors = [];
const failedReqs = [];

function line(s) { console.log(s); }

async function pass(label, url) {
  line(`\n${'='.repeat(70)}\n${label}\n  ${url}\n${'='.repeat(70)}`);
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
  const page = await ctx.newPage();

  page.on('console', m => consoleLog.push(`[${label}][${m.type()}] ${m.text()}`));
  page.on('pageerror', e => pageErrors.push(`[${label}] ${e.name}: ${e.message}`));
  page.on('requestfailed', r =>
    failedReqs.push(`[${label}] ${r.url()} :: ${r.failure()?.errorText}`));
  page.on('response', r => {
    if (r.status() >= 400) failedReqs.push(`[${label}] HTTP ${r.status()} ${r.url()}`);
  });

  const resp = await page.goto(url, { waitUntil: 'networkidle', timeout: 90000 }).catch(e => {
    pageErrors.push(`[${label}] navigation: ${e.message}`);
    return null;
  });
  line(`  nav status: ${resp ? resp.status() : 'FAILED'}`);

  // Poll for the dashboard instead of a fixed sleep — a 1M-line log takes a while.
  let dashState = 'hidden';
  const t0 = Date.now();
  for (let i = 0; i < 60; i++) {
    dashState = await page.evaluate(() => {
      const el = document.querySelector('#nginx-dashboard');
      if (!el) return 'MISSING';
      const cs = getComputedStyle(el);
      return (cs.display !== 'none' && cs.visibility !== 'hidden' && el.offsetParent !== null)
        ? 'VISIBLE' : 'hidden';
    }).catch(() => 'EVALERR');
    if (dashState === 'VISIBLE' || dashState === 'MISSING') break;
    await page.waitForTimeout(2000);
  }
  line(`  ⏱  polled for ${((Date.now() - t0) / 1000).toFixed(1)}s → dashboard: ${dashState}`);

  const state = await page.evaluate(() => {
    const vis = sel => {
      const el = document.querySelector(sel);
      if (!el) return 'MISSING';
      const cs = getComputedStyle(el);
      return (cs.display !== 'none' && cs.visibility !== 'hidden' && el.offsetParent !== null)
        ? 'VISIBLE' : 'hidden';
    };
    const txt = sel => (document.querySelector(sel)?.textContent || '').trim();
    return {
      dashboard: vis('#nginx-dashboard'),
      dashboardDisplay: document.querySelector('#nginx-dashboard')?.style.display ?? '(unset)',
      uploadInput: vis('#log-input, #file-input, input[type=file]'),
      loadedScripts: window.__loadedScripts || (window.performance.getEntriesByType('resource')
        .filter(r => r.name.includes('/js/'))
        .map(r => r.name.split('/js/')[1])),
      title: document.title,
      bodyTextSample: document.body.innerText.replace(/\s+/g, ' ').slice(0, 1200),
      hitCount: (document.querySelector('#nginx-dashboard')?.innerText || '')
        .match(/([\d,]{2,})\s*(Total|total|Requests|requests|Hits|hits)/)?.[0] || 'not-found',
      lightpandaMentions: ((document.querySelector('#nginx-dashboard')?.innerText || '')
        .match(/lightpanda/gi) || []).length,
    };
  }).catch(e => ({ evalError: e.message }));

  line(`  #nginx-dashboard : ${state.dashboard}  (inline display: ${state.dashboardDisplay})`);
  line(`  file input       : ${state.uploadInput}`);
  line(`  scripts loaded   : ${JSON.stringify(state.loadedScripts)}`);
  line(`  ShareModal defined: ${await page.evaluate(() => typeof window.ShareModal)}`);
  line(`  hit count text     : ${state.hitCount}`);
  line(`  'lightpanda' hits  : ${state.lightpandaMentions} occurrences in dashboard`);
  line(`  page text        : ${state.bodyTextSample?.slice(0, 400)}`);

  await page.screenshot({ path: `${outDir}/${label}.png`, fullPage: false, timeout: 120000, animations: 'disabled' })
    .then(() => line(`  screenshot       : ${outDir}/${label}.png`))
    .catch(e => line(`  screenshot FAILED: ${e.message.split('\n')[0]}`));

  await browser.close();
  return state;
}

// ---- Pass 1: first view (should render dashboard) ----
const s1 = await pass('pass1-first-view', SESSION_URL);

// ---- Pass 2: second view of the same link (should be expired) ----
const s2 = await pass('pass2-second-view', SESSION_URL);

line(`\n${'='.repeat(70)}\nEVIDENCE\n${'='.repeat(70)}`);
line(`\n--- PAGE ERRORS (${pageErrors.length}) ---`);
pageErrors.forEach(e => line('  ' + e));
line(`\n--- FAILED REQUESTS (${failedReqs.length}) ---`);
failedReqs.slice(0, 25).forEach(e => line('  ' + e));
line(`\n--- CONSOLE (${consoleLog.length}) ---`);
consoleLog.slice(0, 40).forEach(e => line('  ' + e));

const report = { sessionUrl: SESSION_URL, s1, s2, pageErrors, failedReqs, consoleLog };
writeFileSync(`${outDir}/report.json`, JSON.stringify(report, null, 2));
line(`\nFull report: ${outDir}/report.json`);

line(`\nVERDICT: ${s1.dashboard === 'VISIBLE' ? '✅ DASHBOARD RENDERED' : '❌ DASHBOARD NOT VISIBLE'}`);
line(`VERDICT: ${pageErrors.length === 0 ? '✅ NO PAGE ERRORS' : '❌ ' + pageErrors.length + ' PAGE ERRORS'}`);
