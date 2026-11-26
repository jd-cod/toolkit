/**
 * Capture the settled nginx dashboard on the dev domain.
 * Waits for #nginx-dashboard visible AND the ingest progress modal to be gone,
 * so the screenshot shows real rendered content, not the loading overlay.
 *
 * Usage: node scripts/qa_r2_capture.mjs <sessionUrl> [outName]
 */
import { chromium } from 'playwright';
import { writeFileSync } from 'fs';

const SESSION_URL = process.argv[2];
const OUT = process.argv[3] || 'dashboard-settled';
if (!SESSION_URL) { console.error('usage: node qa_r2_capture.mjs <sessionUrl> [name]'); process.exit(1); }

const outDir = '/tmp/qa_r2';
const errors = [];
const browser = await chromium.launch({ args: ['--no-sandbox'] });
const page = await (await browser.newContext({ viewport: { width: 1600, height: 1100 } })).newPage();
page.on('pageerror', e => errors.push(`${e.name}: ${e.message}`));
page.on('console', m => { if (m.type() === 'error') errors.push(`console: ${m.text()}`); });

console.log(`  ${SESSION_URL}`);
const t0 = Date.now();
await page.goto(SESSION_URL, { waitUntil: 'domcontentloaded', timeout: 90000 });

// Wait for the dashboard AND for the progress modal to finish fading out.
let ok = false;
for (let i = 0; i < 90; i++) {
  ok = await page.evaluate(() => {
    const d = document.querySelector('#nginx-dashboard');
    if (!d) return false;
    const cs = getComputedStyle(d);
    if (cs.display === 'none' || d.offsetParent === null) return false;
    const m = document.getElementById('ingest-progress-modal');
    return !m || m.style.opacity === '0';
  }).catch(() => false);
  if (ok) break;
  await page.waitForTimeout(2000);
}
const secs = ((Date.now() - t0) / 1000).toFixed(1);
console.log(`  settled=${ok}  after ${secs}s`);
await page.waitForTimeout(2500);

const facts = await page.evaluate(() => {
  const d = document.querySelector('#nginx-dashboard');
  const t = d ? d.innerText : '';
  return {
    dashboardVisible: !!d && getComputedStyle(d).display !== 'none',
    totalRequests: t.match(/([\d,]+)\s*TOTAL REQUESTS/)?.[1] ?? 'not-found',
    uniqueIPs: t.match(/([\d,]+)\s*UNIQUE IPS/)?.[1] ?? 'not-found',
    parsed: t.match(/Parsed:\s*([\d,]+)\s*lines/)?.[1] ?? 'not-found',
    skipped: t.match(/Skipped:\s*([\d,]+)\s*lines/)?.[1] ?? 'not-found',
    lightpandaRows: (t.match(/lightpanda/gi) || []).length,
    zeroRetentionBanner: t.includes('ZERO RETENTION') || t.includes('Zero-Retention'),
    shareButton: t.includes('Share'),
  };
});

await page.screenshot({ path: `${outDir}/${OUT}.png`, fullPage: false, timeout: 120000 });
await page.screenshot({ path: `${outDir}/${OUT}-full.png`, fullPage: true, timeout: 120000 }).catch(() => {});

console.log('  FACTS:', JSON.stringify(facts, null, 4).replace(/\n/g, '\n  '));
console.log(`  errors: ${errors.length}`);
errors.forEach(e => console.log('   - ' + e));
writeFileSync(`${outDir}/${OUT}.json`, JSON.stringify({ SESSION_URL, secs, facts, errors }, null, 2));
await browser.close();
console.log(ok && facts.dashboardVisible ? '  ✅ DASHBOARD CONFIRMED VISIBLE' : '  ❌ NOT VISIBLE');
