/**
 * Building blocks for generated access logs, with the facts the oracle needs.
 *
 * The default catalogue is UNAMBIGUOUS on purpose: every user agent has one
 * obvious classification and every path has one obvious meaning. Ambiguous
 * and adversarial inputs (a phone model called "CUBOT", nested paths, a
 * status code nginx invents) live in the edge-case specs, one concern per
 * test, so a failure there cannot hide the rest of the dashboard.
 */

/** How a request's sender should be labelled on the dashboard. */
export type TrafficClass = 'human' | 'verified' | 'spoofed' | 'unverified';

export interface Agent {
  /** Short name used in test messages. */
  id: string;
  userAgent: string;
  /** `human` for browsers; otherwise an automated client. */
  kind: 'human' | 'crawler' | 'tool';
  /** Name shown in the "Bot Classification" column. Empty for humans. */
  group: string;
  /** Name of the individual bot or client, as listed in reports. Empty for humans. */
  name?: string;
  /** Key in the verified-bot IP feed, when the publisher lists its addresses. */
  feedKey?: string;
}

export const BROWSERS: Agent[] = [
  { id: 'chrome-windows', kind: 'human', group: '', userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36' },
  { id: 'safari-mac', kind: 'human', group: '', userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15' },
  { id: 'firefox-linux', kind: 'human', group: '', userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0' },
  { id: 'safari-iphone', kind: 'human', group: '', userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1' },
  { id: 'chrome-android', kind: 'human', group: '', userAgent: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36' },
  { id: 'edge-windows', kind: 'human', group: '', userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0' },
];

/** Crawlers whose publishers list their addresses in the feed served by the test. */
export const FEED_CRAWLERS: Agent[] = [
  { id: 'googlebot', kind: 'crawler', group: 'Google', name: 'Googlebot', feedKey: 'googlebot', userAgent: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' },
  { id: 'bingbot', kind: 'crawler', group: 'Microsoft', name: 'Bingbot', feedKey: 'bingbot', userAgent: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)' },
  { id: 'gptbot', kind: 'crawler', group: 'OpenAI', name: 'GPTBot', feedKey: 'gptbot', userAgent: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)' },
];

/** Crawlers and tools with no published address list: they can only be "unverified". */
export const UNLISTED_AGENTS: Agent[] = [
  { id: 'ahrefsbot', kind: 'crawler', group: 'Ahrefs', name: 'AhrefsBot', userAgent: 'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)' },
  { id: 'semrushbot', kind: 'crawler', group: 'Semrush', name: 'SemrushBot', userAgent: 'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)' },
  { id: 'curl', kind: 'tool', group: 'Scraper / Tool', name: 'cURL / Wget', userAgent: 'curl/8.4.0' },
  { id: 'python-requests', kind: 'tool', group: 'Scraper / Tool', name: 'python-requests', userAgent: 'python-requests/2.31.0' },
  { id: 'go-http', kind: 'tool', group: 'Scraper / Tool', name: 'Go-http-client', userAgent: 'Go-http-client/2.0' },
];

/**
 * Address ranges the test publishes as the verified-bot feed
 * (`/data/verified-bots.json`). A crawler request from inside its publisher's
 * range is genuine; the same user agent from anywhere else is an impersonator.
 */
export const FEED_RANGES: Record<string, { name: string; group: string; ipv4: string[]; ipv6: string[] }> = {
  googlebot: { name: 'Googlebot', group: 'Google', ipv4: ['66.249.64.0/19'], ipv6: ['2001:4860:4801::/48'] },
  bingbot: { name: 'Bingbot', group: 'Microsoft', ipv4: ['157.55.39.0/24', '40.77.167.0/24'], ipv6: [] },
  gptbot: { name: 'GPTBot', group: 'OpenAI', ipv4: ['20.15.240.64/27'], ipv6: [] },
  // Present in the feed with no ranges: the publisher is known but cannot be verified.
  ahrefsbot: { name: 'AhrefsBot', group: 'Ahrefs', ipv4: [], ipv6: [] },
};

/** The feed file in the shape the backend compiles (backend/src/lib/bot-ip-updater.js). */
export function botFeedFile(): object {
  const bots = Object.fromEntries(Object.entries(FEED_RANGES).map(([key, entry]) => [key, {
    name: entry.name, group: entry.group, bot_key: key,
    total_cidrs: entry.ipv4.length + entry.ipv6.length,
    ipv4: entry.ipv4, ipv6: entry.ipv6,
    last_synced_at: '2026-01-01T00:00:00.000Z', last_status: 'ok',
  }]));
  const total = Object.values(FEED_RANGES).reduce((sum, e) => sum + e.ipv4.length + e.ipv6.length, 0);
  return { version: 'e2e-fixture', generated_at: '2026-01-01T00:00:00.000Z', total_sources: Object.keys(bots).length, total_cidrs: total, bots };
}

/**
 * Request paths. `first` is the first path segment; the default set is built
 * so that no first segment is contained in a URL that belongs to another
 * first segment (checked in generator.ts), which keeps the path filter's
 * meaning unambiguous for the default data.
 */
export const NESTED_URLS: string[] = [
  '/', '/index.html',
  '/products/1042', '/products/77?color=red', '/products/list?page=2',
  '/blog/2026/launch-notes', '/blog/archive',
  '/static/css/site.css', '/static/js/app.js', '/static/img/logo.png',
  '/api/v1/users', '/api/v1/orders?limit=50', '/api/v2/session',
  '/checkout', '/cart', '/search?q=shoes',
  '/account/settings', '/favicon.ico', '/robots.txt', '/sitemap.xml',
];

/** Paths probed by scanners; used for tools and impersonators. */
export const PROBE_URLS: string[] = ['/wp-login.php', '/xmlrpc.php', '/.env', '/phpmyadmin/index.php', '/.git/config'];

/** One segment, no query string: "path", "first segment" and "substring" all agree. */
export const FLAT_URLS: string[] = [
  '/home', '/pricing', '/contact', '/signup', '/logout', '/dashboard', '/reports', '/billing',
  '/wp-login.php', '/xmlrpc.php', '/.env', '/favicon.ico', '/robots.txt',
];

export const REFERRERS: string[] = [
  'https://www.google.com/', 'https://www.bing.com/search?q=toolkit', 'https://duckduckgo.com/',
  'https://news.ycombinator.com/item?id=4242', 'https://example.org/links', 'https://t.co/AbCdEf',
];

export const METHODS: { method: string; weight: number }[] = [
  { method: 'GET', weight: 68 }, { method: 'POST', weight: 16 }, { method: 'HEAD', weight: 6 },
  { method: 'PUT', weight: 4 }, { method: 'DELETE', weight: 3 }, { method: 'OPTIONS', weight: 2 }, { method: 'PATCH', weight: 1 },
];

export const STATUSES: { status: number; weight: number }[] = [
  { status: 200, weight: 58 }, { status: 201, weight: 2 }, { status: 204, weight: 2 },
  { status: 301, weight: 4 }, { status: 302, weight: 4 }, { status: 304, weight: 6 },
  { status: 400, weight: 2 }, { status: 401, weight: 3 }, { status: 403, weight: 5 }, { status: 404, weight: 8 }, { status: 429, weight: 1 },
  { status: 500, weight: 3 }, { status: 502, weight: 1 }, { status: 503, weight: 1 },
];

export const PROTOCOLS: { protocol: string; weight: number }[] = [
  { protocol: 'HTTP/1.1', weight: 68 }, { protocol: 'HTTP/2.0', weight: 27 }, { protocol: 'HTTP/1.0', weight: 5 },
];

/** Exact paths the tool documents as health checks ("What is excluded?"). */
export const HEALTH_PATHS = ['/health', '/healthz', '/healthcheck', '/health-check', '/health_check', '/readyz', '/livez', '/_health'];

/** Addresses the tool documents as internal: private, loopback, link-local, CGNAT, IPv6 unique-local. */
export const INTERNAL_ADDRESSES = [
  '10.0.0.5', '10.255.255.254', '172.16.4.9', '172.31.200.1', '192.168.1.20', '127.0.0.1',
  '169.254.10.10', '100.64.0.7', '100.127.255.1', 'fd00::1', 'fc00:abcd::9', 'fe80::1', '::1',
];

/** Lines that are plainly not access-log requests. */
export const INVALID_LINES = [
  'this is not an access log line',
  '--- log rotated ---',
];
