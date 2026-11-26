import { chromium } from '@playwright/test';

const TOP_100_DOMAINS = [
  // Top Global & Tech (.com, .net, .org)
  'google.com',
  'youtube.com',
  'facebook.com',
  'amazon.com',
  'apple.com',
  'microsoft.com',
  'wikipedia.org',
  'twitter.com',
  'instagram.com',
  'linkedin.com',
  'reddit.com',
  'netflix.com',
  'yahoo.com',
  'github.com',
  'cloudflare.com',
  'whatsapp.com',
  'zoom.us',
  'openai.com',
  'spotify.com',
  'ebay.com',
  'adobe.com',
  'dropbox.com',
  'salesforce.com',
  'cnn.com',
  'nytimes.com',
  'theguardian.com',
  'reuters.com',
  'bloomberg.com',
  'stackoverflow.com',
  'medium.com',
  'quora.com',
  'wordpress.org',
  'tumblr.com',
  'pinterest.com',
  'imdb.com',
  'paypal.com',
  'stripe.com',
  'shopify.com',
  'etsy.com',
  'booking.com',
  'airbnb.com',
  'uber.com',
  'lyft.com',
  'slack.com',
  'canva.com',
  'figma.com',
  'notion.so',
  'vimeo.com',
  'soundcloud.com',
  'twitch.tv',
  'craigslist.org',
  'archive.org',
  'sourceforge.net',
  'bitbucket.org',
  'gitlab.com',
  'npmjs.com',
  'docker.com',
  'vercel.com',
  'netlify.com',
  'supabase.com',
  'digitalocean.com',
  'heroku.com',
  'linode.com',
  'ovhcloud.com',
  'hetzner.com',
  'godaddy.com',
  'namecheap.com',
  'name.com',

  // ccTLDs & European / Global Registries
  'bbc.co.uk',
  'denic.de',
  'afnic.fr',
  'nic.ch',
  'nic.ru',
  'jprs.jp',
  'nominet.uk',
  'cira.ca',
  'nic.in',
  'registro.br',
  'nic.it',
  'red.es',
  'sidn.nl',
  'norid.no',
  'iis.se',
  'dns.pt',
  'nic.at',
  'nic.pl',
  'cctld.uz',

  // Standard Bodies, Open Source & Edu / Gov
  'ietf.org',
  'icann.org',
  'iana.org',
  'w3.org',
  'mozilla.org',
  'kernel.org',
  'debian.org',
  'ubuntu.com',
  'python.org',
  'rust-lang.org',
  'golang.org',
  'php.net',
  'ruby-lang.org',
  'swift.org',
  'mit.edu',
  'stanford.edu',
  'harvard.edu',
  'whitehouse.gov',
  'nasa.gov',
];

const BASE_URL = process.env.BASE_URL || 'http://localhost:3001';
const CONCURRENCY = 3;

async function testDomain(browser, domain, index = 1) {
  const context = await browser.newContext({
    extraHTTPHeaders: {
      'x-forwarded-for': `127.0.1.${(index % 200) + 1}`,
    },
  });
  const page = await context.newPage();
  const consoleErrors = [];

  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      const txt = msg.text();
      if (!txt.includes('ERR_NAME_NOT_RESOLVED') && !txt.includes('401')) {
        consoleErrors.push(txt);
      }
    }
  });

  const startTime = Date.now();
  try {
    const url = `${BASE_URL}/whois?domain=${encodeURIComponent(domain)}`;
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });

    // Wait for stat cards or error alert
    const statCardsPromise = page.locator('.stat-card').first().waitFor({ timeout: 25000 }).then(() => 'cards');
    const alertPromise = page.locator('.alert-custom').first().waitFor({ timeout: 25000 }).then(() => 'alert');
    const outcome = await Promise.race([statCardsPromise, alertPromise]);

    const duration = Date.now() - startTime;

    if (outcome === 'cards') {
      const cardTexts = await page.locator('.stat-card').allInnerTexts();
      const domainCard = cardTexts[0] || '';
      const regCard = cardTexts[1] || '';
      const registrarCard = cardTexts[2] || '';
      const expiryCard = cardTexts[3] || '';
      const dnssecCard = cardTexts[4] || '';

      let source = 'UNKNOWN';
      try {
        const sourceLocator = page.locator('strong:has-text("Source:") + span');
        if (await sourceLocator.count() > 0) {
          source = await sourceLocator.innerText();
        }
      } catch {
        // ignore
      }

      await context.close();
      return {
        domain,
        success: true,
        source,
        registered: regCard.includes('Registered'),
        registrar: registrarCard.split('\n')[0].trim(),
        days_until_expiry: expiryCard.split('\n')[0].trim(),
        dnssec: dnssecCard.split('\n')[0].trim(),
        duration,
        consoleErrors,
      };
    } else {
      const alertText = await page.locator('.alert-custom').innerText();
      await context.close();
      return {
        domain,
        success: false,
        source: 'N/A',
        error: alertText.trim(),
        duration,
        consoleErrors,
      };
    }
  } catch (err) {
    await context.close();
    return {
      domain,
      success: false,
      source: 'TIMEOUT/EXCEPTION',
      error: err.message,
      duration: Date.now() - startTime,
      consoleErrors,
    };
  }
}

async function runWorker(browser, queue, results, totalCount) {
  while (queue.length > 0) {
    const item = queue.shift();
    if (!item) break;
    const { domain, index } = item;
    const result = await testDomain(browser, domain, index);
    results.push(result);
    const statusIcon = result.success ? (result.source === 'RDAP' ? '⚡ [RDAP]' : '🛡️ [WHOIS]') : '❌ [FAIL]';
    const detail = result.success
      ? `Registrar: "${result.registrar}" | Reg: ${result.registered} | ${result.duration}ms`
      : `Error: ${result.error} | ${result.duration}ms`;
    console.log(`[${results.length}/${totalCount}] ${statusIcon} ${domain.padEnd(20)} ${detail}`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

async function main() {
  console.log(`=== Starting Real Browser WHOIS Test for 100 Top Domains ===`);
  console.log(`Target: ${BASE_URL}/whois | Concurrency: ${CONCURRENCY} workers\n`);

  const browser = await chromium.launch({ headless: true });
  const queue = TOP_100_DOMAINS.map((domain, index) => ({ domain, index: index + 1 }));
  const results = [];

  const workerPromises = Array.from({ length: CONCURRENCY }, () => runWorker(browser, queue, results, TOP_100_DOMAINS.length));
  await Promise.all(workerPromises);
  await browser.close();

  // Aggregate statistics
  const total = results.length;
  const passed = results.filter((r) => r.success).length;
  const failed = results.filter((r) => !r.success).length;
  const rdapCount = results.filter((r) => r.source === 'RDAP').length;
  const whoisCount = results.filter((r) => r.source === 'WHOIS').length;
  const avgDuration = Math.round(results.reduce((acc, r) => acc + r.duration, 0) / total);

  console.log(`\n======================================================`);
  console.log(`                 TEST SUMMARY REPORT                 `);
  console.log(`======================================================`);
  console.log(`Total Domains Tested : ${total}`);
  console.log(`Successful Lookups   : ${passed} (${((passed / total) * 100).toFixed(1)}%)`);
  console.log(`Failed Lookups       : ${failed}`);
  console.log(`RDAP Data Source     : ${rdapCount} (${((rdapCount / total) * 100).toFixed(1)}%)`);
  console.log(`WHOIS Fallback       : ${whoisCount} (${((whoisCount / total) * 100).toFixed(1)}%)`);
  console.log(`Avg Page Time        : ${avgDuration} ms`);

  if (failed > 0) {
    console.log(`\n❌ Failed Domains Details:`);
    for (const r of results.filter((r) => !r.success)) {
      console.log(`  - ${r.domain}: ${r.error} (${r.duration}ms)`);
    }
  }

  // Check console errors
  const errorsCount = results.reduce((acc, r) => acc + (r.consoleErrors?.length || 0), 0);
  console.log(`Total Console JS Err : ${errorsCount}`);

  // Write JSON report for inspection
  const fs = await import('node:fs/promises');
  await fs.writeFile('test-results/whois-100-domains-report.json', JSON.stringify({
    summary: { total, passed, failed, rdapCount, whoisCount, avgDuration, errorsCount },
    results,
  }, null, 2));
  console.log(`Detailed JSON report written to test-results/whois-100-domains-report.json`);
}

main().catch((err) => {
  console.error('Fatal runner error:', err);
  process.exit(1);
});
