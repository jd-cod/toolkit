#!/usr/bin/env node
// Writes the sample logs the Traffic Analyzer offers on its start page into
// public/samples. The files are not kept in the repository: they are made
// here, the same on every run, before a build (`npm run samples`).
//
//   node scripts/generate-samples.mjs           write the files that are missing
//   node scripts/generate-samples.mjs --force   write all of them again
//
// Four samples are made by this script. The two large ones come from the
// Python generators next to them and need python3.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../public/samples');
const FORCE = process.argv.includes('--force');

function random(seed) {
  let state = seed >>> 0;
  const next = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 4294967296;
  };
  return {
    next,
    int: (min, max) => min + Math.floor(next() * (max - min + 1)),
    pick: list => list[Math.floor(next() * list.length)],
    chance: p => next() < p,
  };
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const p2 = n => String(n).padStart(2, '0');
const START = Date.UTC(2026, 7, 15, 8, 0, 0) / 1000;
function stamp(seconds) {
  const t = new Date((START + seconds) * 1000);
  return `${p2(t.getUTCDate())}/${MONTHS[t.getUTCMonth()]}/${t.getUTCFullYear()}:${p2(t.getUTCHours())}:${p2(t.getUTCMinutes())}:${p2(t.getUTCSeconds())} +0000`;
}
const row = (at, ip, method, target, status, size, referrer, agent) =>
  ({ at, text: `${ip} - - [${stamp(at)}] "${method} ${target} HTTP/1.1" ${status} ${size} "${referrer}" "${agent}"` });
const finish = rows => rows.sort((a, b) => a.at - b.at).map(r => r.text).join('\n') + '\n';

// Access networks in several countries, for visitors.
const VISITOR_NETWORKS = ['73.162.14', '98.207.33', '24.5.118', '86.142.70', '81.151.9', '91.64.203', '84.152.61', '90.55.130', '78.193.44', '151.42.88', '83.56.201', '89.160.20', '49.36.172', '126.74.9', '189.6.25', '1.129.104', '99.230.41', '77.249.18'];
const BROWSERS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0',
];
const SITE = 'https://shop.example.com';
const PAGES = ['/', '/products', '/products/item-{n}', '/products/item-{n}', '/category/shoes', '/category/bags', '/cart', '/checkout', '/account', '/blog/summer-sale', '/search?q=sneakers', '/pricing', '/about'];
const ASSETS = ['/static/css/app.css', '/static/js/app.js', '/static/js/vendor.js', '/static/img/logo.svg', '/static/img/hero.webp', '/favicon.ico'];
const SEARCH_REFERRERS = ['https://www.google.com/', 'https://www.bing.com/', 'https://duckduckgo.com/', 'https://www.instagram.com/'];

function visitors(rnd, count) {
  return Array.from({ length: count }, () => ({ ip: `${rnd.pick(VISITOR_NETWORKS)}.${rnd.int(2, 250)}`, agent: rnd.pick(BROWSERS) }));
}

/** One visit: a page, the files it needs, then a few more pages. */
function visit(rnd, rows, visitor, at) {
  let referrer = rnd.chance(0.55) ? rnd.pick(SEARCH_REFERRERS) : '-';
  const pages = rnd.int(1, 5);
  for (let i = 0; i < pages; i++) {
    const page = rnd.pick(PAGES).replace('{n}', String(rnd.int(100, 180)));
    const status = rnd.chance(0.02) ? 404 : (page === '/account' && rnd.chance(0.3) ? 302 : 200);
    rows.push(row(at, visitor.ip, 'GET', page, status, status === 200 ? rnd.int(6000, 42000) : 320, referrer, visitor.agent));
    if (i === 0 || rnd.chance(0.3)) {
      for (const asset of ASSETS) {
        if (rnd.chance(0.7)) rows.push(row(at + rnd.int(0, 1), visitor.ip, 'GET', asset, rnd.chance(0.25) ? 304 : 200, rnd.int(800, 90000), SITE + page.split('?')[0], visitor.agent));
      }
    }
    if (page === '/cart' && rnd.chance(0.5)) rows.push(row(at + 2, visitor.ip, 'POST', '/api/cart', 200, 412, SITE + '/cart', visitor.agent));
    if (page === '/checkout' && rnd.chance(0.4)) rows.push(row(at + 3, visitor.ip, 'POST', '/api/orders', 201, 655, SITE + '/checkout', visitor.agent));
    referrer = SITE + page.split('?')[0];
    at += rnd.int(8, 90);
  }
}

function baseline(rnd, rows, people, visits, span) {
  const crowd = visitors(rnd, people);
  for (let i = 0; i < visits; i++) visit(rnd, rows, rnd.pick(crowd), rnd.int(0, span));
}

// Crawlers, each from an address range its operator publishes.
const CRAWLERS = [
  { agent: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', networks: ['66.249.64', '66.249.66', '66.249.70'], weight: 30 },
  { agent: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36', networks: ['40.77.167', '157.55.39', '207.46.13'], weight: 16 },
  { agent: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)', networks: ['20.171.206', '52.230.152'], weight: 10 },
  { agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)', networks: ['17.22.237', '17.241.75'], weight: 6 },
  { agent: 'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)', networks: ['54.36.148', '142.44.220'], weight: 12 },
  { agent: 'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)', networks: ['185.191.171', '85.208.96'], weight: 10 },
  { agent: 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)', networks: ['5.255.253', '87.250.224', '213.180.203'], weight: 6 },
  { agent: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)', networks: ['216.73.216'], weight: 8 },
];
const CRAWL_PATHS = ['/robots.txt', '/sitemap.xml', '/', '/products', '/products/item-{n}', '/products/item-{n}', '/category/shoes', '/category/bags', '/blog/summer-sale', '/blog/care-guide', '/pricing', '/about'];

function crawl(rnd, rows, crawler, ip, at, requests) {
  for (let i = 0; i < requests; i++) {
    const target = i === 0 ? '/robots.txt' : rnd.pick(CRAWL_PATHS).replace('{n}', String(rnd.int(100, 400)));
    rows.push(row(at, ip, 'GET', target, rnd.chance(0.04) ? 404 : (rnd.chance(0.1) ? 304 : 200), rnd.int(900, 38000), '-', crawler.agent));
    at += rnd.int(2, 40);
  }
}

function ecommerceNormal() {
  const rnd = random(101);
  const rows = [];
  baseline(rnd, rows, 260, 520, 6 * 3600);
  for (const crawler of CRAWLERS.slice(0, 2)) {
    for (let i = 0; i < 6; i++) crawl(rnd, rows, crawler, `${rnd.pick(crawler.networks)}.${rnd.int(1, 120)}`, rnd.int(0, 6 * 3600 - 600), rnd.int(4, 10));
  }
  return finish(rows);
}

// Hosting networks scanners are run from.
const SCANNER_NETWORKS = ['45.155.205', '193.32.162', '185.224.128', '141.98.10', '80.94.95', '194.26.135', '162.142.125', '167.94.138', '71.6.199', '89.248.165'];
const SCANNER_AGENTS = [
  'Mozilla/5.0 zgrab/0.x', 'python-requests/2.31.0', 'Go-http-client/1.1', 'curl/8.4.0', 'Nuclei - Open-source project (github.com/projectdiscovery/nuclei)',
  'sqlmap/1.8.4#stable (https://sqlmap.org)', 'masscan/1.3 (https://github.com/robertdavidgraham/masscan)', 'Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36', 'l9explore/1.2.2',
];
const PROBES = [
  ['GET', '/.env', 404], ['GET', '/.env.production', 404], ['GET', '/.git/config', 404], ['GET', '/.aws/credentials', 404], ['GET', '/wp-login.php', 404],
  ['POST', '/wp-login.php', 404], ['POST', '/xmlrpc.php', 404], ['GET', '/wp-admin/install.php', 404], ['GET', '/phpmyadmin/index.php', 404], ['GET', '/pma/', 404],
  ['GET', '/admin/config.php', 403], ['GET', '/server-status', 403], ['GET', '/actuator/env', 404], ['GET', '/actuator/health', 404], ['GET', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', 404],
  ['GET', '/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh', 400], ['GET', '/index.php?page=../../../../etc/passwd', 403], ['GET', "/products?id=1'%20OR%20'1'='1", 403],
  ['GET', '/search?q=%3Cscript%3Ealert(1)%3C/script%3E', 403], ['GET', '/backup.sql', 404], ['GET', '/config.json', 404], ['GET', '/owa/auth/logon.aspx', 404],
  ['GET', '/solr/admin/info/system', 404], ['POST', '/api/v1/auth/login', 401], ['GET', '/login.action', 404], ['GET', '/shell.php', 404],
];

function attackScanners() {
  const rnd = random(202);
  const rows = [];
  baseline(rnd, rows, 120, 190, 4 * 3600);
  for (let s = 0; s < 46; s++) {
    const ip = `${rnd.pick(SCANNER_NETWORKS)}.${rnd.int(2, 250)}`;
    const agent = rnd.pick(SCANNER_AGENTS);
    let at = rnd.int(0, 4 * 3600 - 300);
    const sweep = rnd.int(15, 70);
    for (let i = 0; i < sweep; i++) {
      const [method, target, status] = rnd.pick(PROBES);
      rows.push(row(at, ip, method, target, status, rnd.int(150, 560), '-', agent));
      at += rnd.int(0, 2);
    }
  }
  // One address guessing passwords.
  for (let i = 0; i < 180; i++) rows.push(row(7200 + i * 2, '185.224.128.17', 'POST', '/account/login', 401, 310, SITE + '/account/login', BROWSERS[0]));
  return finish(rows);
}

function ddosFlood() {
  const rnd = random(303);
  const rows = [];
  baseline(rnd, rows, 180, 330, 3600);
  // 30 addresses from a handful of networks ask for the same expensive pages for two minutes.
  const networks = ['103.152.220', '103.152.221', '45.227.254', '45.227.255', '177.54.144', '190.2.131', '41.216.186', '202.56.164', '118.99.81', '36.37.180'];
  const agents = [BROWSERS[0], 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36'];
  const botnet = Array.from({ length: 30 }, () => ({ ip: `${rnd.pick(networks)}.${rnd.int(2, 250)}`, agent: rnd.pick(agents) }));
  const floodStart = 1500;
  for (let i = 0; i < 12000; i++) {
    const at = floodStart + Math.floor(i / 12000 * 120);
    const bot = rnd.pick(botnet);
    const target = rnd.chance(0.7) ? `/search?q=${rnd.int(100000, 999999)}` : '/';
    // The server keeps up for the first seconds, then answers 503.
    const overloaded = at - floodStart > 20 && rnd.chance(0.65);
    rows.push(row(at, bot.ip, 'GET', target, overloaded ? 503 : 200, overloaded ? 197 : rnd.int(9000, 24000), '-', bot.agent));
  }
  // Ten minutes later, a second wave from 240 other addresses for three minutes.
  // Each sends about eight requests a minute: slow enough to pass for a visitor on its own.
  const swarm = Array.from({ length: 240 }, (_, i) => ({ ip: `${networks[i % networks.length]}.${rnd.int(2, 250)}`, agent: rnd.pick(agents) }));
  const swarmStart = 2220;
  for (let i = 0; i < 6000; i++) {
    const at = swarmStart + Math.floor(i / 6000 * 180);
    const bot = rnd.pick(swarm);
    const target = rnd.chance(0.7) ? `/search?q=${rnd.int(100000, 999999)}` : '/';
    const overloaded = at - swarmStart > 30 && rnd.chance(0.4);
    rows.push(row(at, bot.ip, 'GET', target, overloaded ? 503 : 200, overloaded ? 197 : rnd.int(9000, 24000), '-', bot.agent));
  }
  return finish(rows);
}

function botCrawlers() {
  const rnd = random(404);
  const rows = [];
  baseline(rnd, rows, 110, 170, 5 * 3600);
  const totalWeight = CRAWLERS.reduce((sum, c) => sum + c.weight, 0);
  for (let session = 0; session < 230; session++) {
    let roll = rnd.next() * totalWeight;
    const crawler = CRAWLERS.find(c => (roll -= c.weight) < 0) || CRAWLERS[0];
    crawl(rnd, rows, crawler, `${rnd.pick(crawler.networks)}.${rnd.int(1, 120)}`, rnd.int(0, 5 * 3600 - 600), rnd.int(5, 16));
  }
  // The same crawler names from networks their operators do not use.
  const impostors = ['185.220.101', '45.142.120', '94.23.175', '193.142.146'];
  for (let session = 0; session < 40; session++) {
    const crawler = CRAWLERS[rnd.int(0, 2)];
    const ip = `${rnd.pick(impostors)}.${rnd.int(2, 60)}`;
    let at = rnd.int(0, 5 * 3600 - 300);
    for (let i = 0; i < rnd.int(6, 20); i++) {
      const [method, target, status] = rnd.chance(0.5) ? rnd.pick(PROBES) : ['GET', `/products/item-${rnd.int(100, 400)}`, 200];
      rows.push(row(at, ip, method, target, status, rnd.int(150, 22000), '-', crawler.agent));
      at += rnd.int(0, 3);
    }
  }
  return finish(rows);
}

const SAMPLES = {
  'ecommerce-normal.log': ecommerceNormal,
  'attack-scanners.log': attackScanners,
  'ddos-flood.log': ddosFlood,
  'bot-crawlers.log': botCrawlers,
};
const PYTHON_SAMPLES = {
  'heavy-traffic.log': 'generate_heavy_traffic.py',
  'multi-vector-attack.log': 'generate_multi_vector.py',
};

mkdirSync(OUT, { recursive: true });
const wanted = name => FORCE || !existsSync(path.join(OUT, name));
const size = name => `${(statSync(path.join(OUT, name)).size / 1048576).toFixed(1)} MB`;

for (const [name, make] of Object.entries(SAMPLES)) {
  if (!wanted(name)) continue;
  writeFileSync(path.join(OUT, name), make());
  console.log(`samples: wrote ${name} (${size(name)})`);
}

let missing = 0;
for (const [name, script] of Object.entries(PYTHON_SAMPLES)) {
  if (!wanted(name)) continue;
  const run = spawnSync('python3', [path.join(OUT, script)], { stdio: ['ignore', 'ignore', 'pipe'] });
  if (run.status === 0 && existsSync(path.join(OUT, name))) {
    console.log(`samples: wrote ${name} (${size(name)})`);
  } else {
    missing++;
    console.warn(`samples: ${name} was not written (${run.error ? run.error.message : String(run.stderr || '').trim().split('\n').pop() || `python3 exited with ${run.status}`}). It needs python3: python3 public/samples/${script}`);
  }
}
if (missing && process.argv.includes('--strict')) process.exit(1);
