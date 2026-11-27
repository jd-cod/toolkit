// Usage: node scripts/dev/page-shot.mjs <url> <out.png> [width] [fullPage=1]
// Loads a page, saves a screenshot and prints the page title and any console errors.
import { chromium } from 'playwright';
const [url, out, width = '1440', full = '1'] = process.argv.slice(2);
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: Number(width), height: 1000 } });
const errors = [];
page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
page.on('pageerror', e => errors.push('PAGEERROR ' + e.message));
await page.goto(url, { waitUntil: 'networkidle' });
await page.screenshot({ path: out, fullPage: full === '1' });
console.log(JSON.stringify({ title: await page.title(), errors }));
await browser.close();
