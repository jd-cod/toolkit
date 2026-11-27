// Usage: node scripts/dev/page-flow.mjs <url> <out.png> '<json steps>' [width]
// Steps: ["fill", selector, value], ["click", selector], ["wait", ms], ["waitFor", selector], ["text", selector].
// Runs the steps, saves a full-page screenshot and prints the title and any console errors.
import { chromium } from 'playwright';
const [url, out, stepsJson = '[]', width = '1440'] = process.argv.slice(2);
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: Number(width), height: 1000 } });
const errors = [];
page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
page.on('pageerror', e => errors.push('PAGEERROR ' + e.message));
await page.goto(url, { waitUntil: 'networkidle' });
for (const [action, a, b] of JSON.parse(stepsJson)) {
  if (action === 'fill') await page.fill(a, b);
  else if (action === 'click') await page.click(a);
  else if (action === 'wait') await page.waitForTimeout(a);
  else if (action === 'waitFor') await page.waitForSelector(a, { timeout: 45000 });
  else if (action === 'text') console.log(JSON.stringify((await page.locator(a).allInnerTexts()).slice(0, 20)));
}
await page.screenshot({ path: out, fullPage: true });
console.log(JSON.stringify({ title: await page.title(), errors }));
await browser.close();
