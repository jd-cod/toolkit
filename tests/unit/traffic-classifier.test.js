import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const BotDetector = require('../../frontend/public/js/bot-detector.js');
const TrafficClassifier = require('../../frontend/public/js/traffic-classifier.js');
const LogParser = require('../../frontend/public/js/log-parser.js');
const Analyzer = require('../../frontend/public/js/analyzer.js');
const { createWorkerHandler } = require('../../frontend/public/js/log-parser.worker.js');

const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
const SAFARI = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

// Ranges for two publishers; Bing is left without ranges on purpose.
const FEED = {
    bots: {
        googlebot: { name: 'Googlebot', group: 'Google', ipv4: ['66.249.64.0/19'], ipv6: ['2001:4860:4801::/48'] },
        applebot: { name: 'Applebot', group: 'Apple', ipv4: ['17.58.96.0/19'], ipv6: [] },
        bingbot: { name: 'Bingbot', group: 'Microsoft', ipv4: [], ipv6: [] },
    },
};

// The in-memory path looks every address up; this table stands in for the GeoIP database.
const ASN_BY_IP = { '40.77.167.10': 8075, '185.220.101.5': 60729 };
globalThis.GeoIP = {
    lookupIP: ip => ({ country: 'Unknown', country_code: '--', asn: ASN_BY_IP[ip] || 0, asn_org: 'Unknown' }),
    lookupCountry: () => ({ country: 'Unknown', country_code: '--' }),
};

let clock = Date.UTC(2026, 8, 20, 10, 0, 0) / 1000;
function line(ip, { method = 'GET', url = '/', status = 200, ref = '-', ua = CHROME, at } = {}) {
    const t = new Date((at ?? clock++) * 1000);
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const p = n => String(n).padStart(2, '0');
    const stamp = `${p(t.getUTCDate())}/${months[t.getUTCMonth()]}/${t.getUTCFullYear()}:${p(t.getUTCHours())}:${p(t.getUTCMinutes())}:${p(t.getUTCSeconds())} +0000`;
    return `${ip} - - [${stamp}] "${method} ${url} HTTP/1.1" ${status} 512 "${ref}" "${ua}"`;
}

function classify(lines) {
    const session = TrafficClassifier.createSession();
    const ids = [];
    for (const raw of lines) {
        const r = LogParser.parseLine(raw, { skip403: false, skipInternal: false });
        assert.ok(r.valid, `line should parse: ${raw}`);
        ids.push(session.add(r.ip, r.userAgent, {
            timeSec: r.timeSec, status: r.statusCode, method: r.method, url: r.url,
            hasReferrer: Boolean(r.referrer), httpVersion: r.httpVersion,
        }));
    }
    session.finalize(ip => ASN_BY_IP[ip] || 0);
    return ids.map(id => session.client(id));
}

function classOfOnlyClient(lines) {
    const classes = new Set(classify(lines).map(c => c.cls));
    assert.equal(classes.size, 1, `expected one class, got ${[...classes]}`);
    return classify(lines)[0];
}

before(() => {
    assert.equal(BotDetector.loadData(FEED), true);
});

describe('BotDetector.classifyUserAgent', () => {
    const browsers = [
        ['Chrome desktop', CHROME],
        ['Safari iPhone', SAFARI],
        ['Firefox Linux', 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0'],
        ['Internet Explorer 11', 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'],
        ['Internet Explorer 9', 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)'],
        ['Opera 12', 'Opera/9.80 (Windows NT 6.1; WOW64) Presto/2.12.388 Version/12.18'],
        ['Pinterest in-app iOS', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [Pinterest/iOS]'],
        ['Sogou mobile browser', 'Mozilla/5.0 (Linux; Android 10; MI 9) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/78.0.3904.108 Mobile Safari/537.36 SogouMSE,SogouMobileBrowser/5.31.6'],
        ['Viber in-app', 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.0.0 Mobile Safari/537.36 Viber/21.5.0.3'],
        ['Facebook in-app', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/470.0.0.31.107;FBDV/iPhone14,5]'],
        ['CUBOT phone', 'Mozilla/5.0 (Linux; Android 11; CUBOT NOTE 20) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'],
        ['Samsung browser', 'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36'],
    ];
    for (const [label, ua] of browsers) {
        test(`browser: ${label}`, () => {
            assert.equal(BotDetector.classifyUserAgent(ua).kind, 'browser');
            assert.equal(BotDetector.detectBot(ua), null);
        });
    }

    const automated = [
        ['known_bot', 'Googlebot', 'Google', GOOGLEBOT],
        ['known_bot', 'Bingbot', 'Microsoft', 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'],
        ['known_bot', 'Applebot-Extended', 'Apple', 'Mozilla/5.0 (compatible; Applebot-Extended/0.1; +http://www.apple.com/go/applebot)'],
        ['known_bot', 'Claude-User', 'Anthropic', 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)'],
        ['known_bot', 'Pinterestbot', 'Pinterest', 'Mozilla/5.0 (compatible; Pinterestbot/1.0; +http://www.pinterest.com/bot.html)'],
        ['known_bot', 'Sogou', 'Sogou', 'Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)'],
        ['known_bot', 'Meta External Fetcher', 'Facebook/Meta', 'meta-externalfetcher/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)'],
        ['scanner', 'zgrab', 'Security scanners', 'Mozilla/5.0 zgrab/0.x'],
        ['scanner', 'sqlmap', 'Security scanners', 'sqlmap/1.8.4#stable (https://sqlmap.org)'],
        ['scanner', 'Nikto', 'Security scanners', 'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)'],
        ['scanner', 'CensysInspect', 'Security scanners', 'Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)'],
        ['tool', 'cURL / Wget', 'Scripts & HTTP libraries', 'curl/8.4.0'],
        ['tool', 'python-requests', 'Scripts & HTTP libraries', 'python-requests/2.31.0'],
        ['tool', 'okhttp', 'Scripts & HTTP libraries', 'okhttp/4.12.0'],
        ['tool', 'axios', 'Scripts & HTTP libraries', 'axios/1.7.2'],
        ['headless', 'Headless Chrome / Puppeteer', 'Headless browsers', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/126.0.0.0 Safari/537.36'],
        ['unknown_bot', 'AcmeSeoBot', 'Unlisted crawlers', 'Mozilla/5.0 (compatible; AcmeSeoBot/3.1; +https://acme.example/bot)'],
        ['unknown_bot', 'my-crawler', 'Unlisted crawlers', 'my-crawler/0.4'],
        ['unknown_client', 'Mozilla/5.0', 'Unidentified clients', 'Mozilla/5.0'],
        ['unknown_client', 'InternalSync/2.0', 'Unidentified clients', 'InternalSync/2.0 (build 77)'],
        ['no_ua', 'No user agent', 'No user agent', '-'],
        ['no_ua', 'No user agent', 'No user agent', ''],
    ];
    for (const [kind, name, group, ua] of automated) {
        test(`${kind}: ${ua || '(empty)'}`, () => {
            assert.deepEqual(BotDetector.classifyUserAgent(ua), { kind, name, group });
        });
    }

    test('detectBot names declared bots and tools only', () => {
        assert.equal(BotDetector.detectBotName(GOOGLEBOT), 'Googlebot');
        assert.equal(BotDetector.detectBotName('curl/8.4.0'), 'cURL / Wget');
        assert.equal(BotDetector.detectBotName('Mozilla/5.0'), null);
        assert.equal(BotDetector.detectBotName('-'), null);
    });
});

describe('BotDetector.verifyBot', () => {
    test('address inside the published ranges is verified', () => {
        assert.equal(BotDetector.verifyBot('Googlebot', '66.249.66.1').status, 'verified');
        assert.equal(BotDetector.verifyBot('Googlebot', '2001:4860:4801:1::5').status, 'verified');
    });

    test('address outside the published ranges is spoofed', () => {
        assert.equal(BotDetector.verifyBot('Googlebot', '185.220.101.5').status, 'spoofed');
    });

    test('private address is spoofed whatever the bot', () => {
        assert.equal(BotDetector.verifyBot('SemrushBot', '10.0.0.5').status, 'spoofed');
    });

    test('publisher without ranges: outside its networks is spoofed, inside is unverified', () => {
        assert.equal(BotDetector.verifyBot('Bingbot', '185.220.101.5', 60729).status, 'spoofed');
        assert.equal(BotDetector.verifyBot('Bingbot', '40.77.167.10', 8075).status, 'unverified_publisher');
        assert.equal(BotDetector.verifyBot('Bingbot', '40.77.167.10').status, 'unverified_publisher');
    });

    test('publisher without ranges and without known networks is unverified', () => {
        assert.equal(BotDetector.verifyBot('SemrushBot', '185.220.101.5', 60729).status, 'unverified_publisher');
    });

    test('a bot name does not borrow the ranges of a similarly named feed', () => {
        // "Applebot" has ranges; an unrelated name containing it must not match them.
        assert.equal(BotDetector.verifyBot('NotApplebotAtAll', '8.8.8.8').status, 'unverified_publisher');
    });
});

describe('TrafficClassifier: one class per request', () => {
    test('browsers are human; declared bots, tools and scanners are not', () => {
        const clients = classify([
            line('82.132.214.10', { url: '/', ref: 'https://www.google.com/' }),
            line('82.132.214.10', { url: '/css/app.css', ref: 'https://shop.example/' }),
            line('66.249.66.1', { ua: GOOGLEBOT }),
            line('185.220.101.5', { ua: GOOGLEBOT }),
            line('40.77.167.10', { ua: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)' }),
            line('198.51.100.7', { ua: 'curl/8.4.0' }),
            line('198.51.100.8', { ua: 'Mozilla/5.0 zgrab/0.x' }),
            line('198.51.100.9', { ua: 'Mozilla/5.0 (compatible; AcmeSeoBot/3.1; +https://acme.example/bot)' }),
            line('198.51.100.10', { ua: '-' }),
        ]);
        assert.deepEqual(clients.map(c => c.cls), [
            'human', 'human', 'verified', 'spoofed', 'unverified', 'automated', 'automated', 'automated', 'automated',
        ]);
        assert.deepEqual(clients.slice(5).map(c => c.group), [
            'Scripts & HTTP libraries', 'Security scanners', 'Unlisted crawlers', 'No user agent',
        ]);
    });

    test('a log without a User-Agent column does not turn every visitor into a bot', () => {
        const lines = [];
        for (let i = 0; i < 40; i++) lines.push(line(`82.132.214.${i}`, { ua: '-', url: `/page-${i % 5}` }));
        const clients = classify(lines);
        assert.ok(clients.every(c => c.cls === 'human'), 'requests should stay human');
    });

    test('a few requests without a User-Agent in a normal log are automated', () => {
        const lines = [];
        for (let i = 0; i < 40; i++) lines.push(line(`82.132.214.${i}`, { url: '/', ref: 'https://shop.example/' }));
        lines.push(line('198.51.100.10', { ua: '-' }));
        const clients = classify(lines);
        assert.equal(clients.at(-1).cls, 'automated');
        assert.equal(clients.filter(c => c.cls === 'human').length, 40);
    });
});

describe('TrafficClassifier: browsers that behave like bots', () => {
    test('a person browsing pages with assets and referrers stays human', () => {
        const lines = [];
        for (let page = 0; page < 30; page++) {
            const ref = page ? `https://shop.example/products/item-${page - 1}` : 'https://www.google.com/';
            lines.push(line('82.132.214.10', { url: `/products/item-${page}`, ref }));
            for (const asset of ['/css/app.css', '/js/bundle.js', '/images/hero.webp', '/favicon.ico']) {
                lines.push(line('82.132.214.10', { url: asset, ref: `https://shop.example/products/item-${page}` }));
            }
        }
        assert.equal(classOfOnlyClient(lines).cls, 'human');
    });

    test('an administrator logging in to WordPress stays human', () => {
        const lines = [
            line('82.132.214.10', { url: '/wp-login.php' }),
            line('82.132.214.10', { method: 'POST', url: '/wp-login.php', status: 302, ref: 'https://blog.example/wp-login.php' }),
            line('82.132.214.10', { url: '/wp-admin/', ref: 'https://blog.example/wp-login.php' }),
            line('82.132.214.10', { url: '/wp-admin/load-styles.php?c=1', ref: 'https://blog.example/wp-admin/' }),
        ];
        assert.equal(classOfOnlyClient(lines).cls, 'human');
    });

    test('a page that loads hundreds of assets in one minute stays human', () => {
        const lines = [line('82.132.214.10', { url: '/gallery', at: clock })];
        for (let i = 0; i < 400; i++) lines.push(line('82.132.214.10', { url: `/images/photo-${i}.jpg`, ref: 'https://shop.example/gallery', at: clock + (i % 50) }));
        clock += 60;
        assert.equal(classOfOnlyClient(lines).cls, 'human');
    });

    test('requesting several sensitive paths is vulnerability probing', () => {
        const lines = ['/.env', '/.git/config', '/wp-config.php.bak', '/phpmyadmin/index.php'].map(url => line('203.0.113.50', { url, status: 404 }));
        const client = classOfOnlyClient(lines);
        assert.equal(client.cls, 'suspected');
        assert.equal(client.name, 'Vulnerability probing');
        assert.equal(client.group, TrafficClassifier.SUSPECTED_GROUP);
    });

    test('many login attempts within one minute is a brute force', () => {
        const start = clock;
        const lines = [];
        for (let i = 0; i < 12; i++) lines.push(line('203.0.113.51', { method: 'POST', url: '/wp-login.php', at: start + i * 4 }));
        clock += 60;
        assert.equal(classOfOnlyClient(lines).name, 'Login brute force');
    });

    test('a burst of page requests without assets or referrers is a flood', () => {
        const start = clock;
        const lines = [];
        for (let i = 0; i < 150; i++) lines.push(line('203.0.113.52', { url: `/search?q=${i}`, at: start + (i % 55) }));
        clock += 60;
        assert.equal(classOfOnlyClient(lines).name, 'Request flood');
    });

    test('mostly failed requests across many paths is path enumeration', () => {
        const lines = [];
        for (let i = 0; i < 40; i++) lines.push(line('203.0.113.53', { url: `/backup-${i}.zip`, status: 404, at: clock + i * 90 }));
        clock += 3600;
        assert.equal(classOfOnlyClient(lines).name, 'Path enumeration');
    });

    test('a single-page app polling an API quickly, with referrers, stays human', () => {
        const start = clock;
        const lines = [];
        for (let i = 0; i < 200; i++) lines.push(line('82.132.214.30', { url: `/api/widgets/${i % 12}`, ref: 'https://app.example/', at: start + (i % 58) }));
        clock += 60;
        assert.equal(classOfOnlyClient(lines).cls, 'human');
    });

    test('weak signals count only together', () => {
        const quiet = [];
        for (let i = 0; i < 25; i++) quiet.push(line('82.132.214.20', { url: `/article-${i % 4}`, at: clock + i * 120 }));
        clock += 3600;
        // No assets and no referrers alone (a CDN and a privacy extension) is not enough.
        assert.equal(classOfOnlyClient(quiet).cls, 'human');

        const crawl = [line('203.0.113.54', { url: '/robots.txt', at: clock })];
        for (let i = 0; i < 25; i++) crawl.push(line('203.0.113.54', { url: `/article-${i % 4}`, at: clock + i * 120 }));
        clock += 3600;
        const client = classOfOnlyClient(crawl);
        assert.equal(client.cls, 'suspected');
        assert.equal(client.name, 'Crawler-like browsing');
    });
});

describe('TrafficClassifier.aggregate', () => {
    test('classes add up to the total and bots are grouped by publisher', () => {
        const clients = classify([
            line('82.132.214.10', { ref: 'https://www.google.com/' }),
            line('66.249.66.1', { ua: GOOGLEBOT }),
            line('66.249.66.1', { ua: GOOGLEBOT }),
            line('185.220.101.5', { ua: GOOGLEBOT }),
            line('198.51.100.7', { ua: 'curl/8.4.0' }),
            line('198.51.100.8', { ua: 'python-requests/2.31.0' }),
        ]);
        const counts = new Map();
        for (const c of clients) counts.set(c, (counts.get(c) || 0) + 1);
        const result = TrafficClassifier.aggregate([...counts].map(([client, count]) => ({ client, count })));

        assert.equal(result.classified_requests, 6);
        assert.equal(result.traffic_classes.reduce((sum, c) => sum + c.requests, 0), 6);
        assert.equal(result.human_requests, 1);
        assert.equal(result.verified_bots_count, 2);
        assert.equal(result.spoofed_bots_count, 1);
        assert.equal(result.automated_count, 2);
        assert.equal(result.other_bots_count, 2);

        const google = result.bot_groups.find(g => g.group_name === 'Google');
        assert.equal(google.verified_requests, 2);
        assert.equal(google.spoofed_requests, 1);
        assert.equal(google.verification_status, 'mixed');
        assert.equal(google.unique_ips, 2);

        const tools = result.bot_groups.find(g => g.group_name === 'Scripts & HTTP libraries');
        assert.equal(tools.automated_requests, 2);
        assert.deepEqual(tools.sub_bots.map(b => b.bot_name).sort(), ['cURL / Wget', 'python-requests']);

        assert.deepEqual(result.spoofed_bot_ips, ['185.220.101.5']);
        assert.equal(result.spoofed_bot_attackers[0].bot_name, 'Googlebot');
    });
});

describe('Both analysis paths classify the same', () => {
    const lines = [];
    for (let i = 0; i < 30; i++) {
        lines.push(line('82.132.214.10', { url: `/products/item-${i}`, ref: 'https://shop.example/', status: i % 10 === 0 ? 404 : 200 }));
        lines.push(line('82.132.214.10', { url: '/css/app.css', ref: `https://shop.example/products/item-${i}` }));
    }
    for (let i = 0; i < 8; i++) lines.push(line('66.249.66.1', { ua: GOOGLEBOT, url: `/products/item-${i}` }));
    for (let i = 0; i < 5; i++) lines.push(line('185.220.101.5', { ua: GOOGLEBOT, url: '/admin', status: 404 }));
    for (let i = 0; i < 6; i++) lines.push(line('40.77.167.10', { ua: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)' }));
    for (let i = 0; i < 7; i++) lines.push(line('198.51.100.7', { ua: 'curl/8.4.0', method: 'POST', url: '/api/login', status: 401 }));
    for (const url of ['/.env', '/.git/config', '/phpmyadmin/', '/.aws/credentials']) lines.push(line('203.0.113.50', { url, status: 404 }));
    const text = lines.join('\n') + '\n';
    const expected = { human: 60, verified: 8, unverified: 6, spoofed: 5, automated: 7, suspected: 4 };

    function runWorker() {
        const messages = [];
        const handler = createWorkerHandler(msg => messages.push(msg));
        handler({ data: { action: 'parse_stream_chunk', chunk: new TextEncoder().encode(text), isLast: true, options: { skip403: false, skipInternal: false } } });
        const complete = messages.find(m => m.type === 'complete');
        // The page answers with the network of each address, as GeoIP enrichment does.
        const ipDict = complete.ipDict;
        handler({ data: {
            action: 'enrich_geo',
            countryIds: new Uint16Array(ipDict.length),
            asns: Uint32Array.from(ipDict, ip => ASN_BY_IP[ip] || 0),
            countryDict: ['-'],
            asnOrgMap: {},
        } });
        const enriched = messages.find(m => m.type === 'enriched');
        const filter = filters => {
            messages.length = 0;
            handler({ data: { action: 'filter', filters } });
            return messages.find(m => m.type === 'filter_result');
        };
        return { enriched, filter };
    }

    const classCounts = data => Object.fromEntries(data.traffic_classes.map(c => [c.key, c.requests]));

    test('in-memory path', () => {
        const parsed = LogParser.parseIPs(text, { skip403: false, skipInternal: false });
        Analyzer.enrichLogEntries(parsed.logEntries);
        const data = Analyzer.analyzeEnhancedLogs(parsed.logEntries);
        assert.deepEqual(classCounts(data), expected);
        assert.equal(data.human_requests, 60);
        assert.equal(data.other_bots_count, 17);

        // A filtered part of the log keeps each request in its class.
        const errors = parsed.logEntries.filter(e => e.status_code >= 400);
        assert.deepEqual(classCounts(Analyzer.analyzeEnhancedLogs(errors)), {
            human: 3, verified: 0, unverified: 0, spoofed: 5, automated: 7, suspected: 4,
        });
    });

    test('streaming worker path', () => {
        const { enriched } = runWorker();
        const data = Analyzer.analyzeFromWorkerSummary(enriched.summary);
        assert.deepEqual(classCounts(data), expected);
        assert.equal(data.total_requests, 90);
        assert.equal(data.human_requests, 60);
        assert.ok(!data.bot_groups.some(g => g.group_name === 'None'), 'humans must not be listed as a bot');
    });

    test('both paths list the same bot groups', () => {
        const parsed = LogParser.parseIPs(text, { skip403: false, skipInternal: false });
        Analyzer.enrichLogEntries(parsed.logEntries);
        const memory = Analyzer.analyzeEnhancedLogs(parsed.logEntries);
        const worker = Analyzer.analyzeFromWorkerSummary(runWorker().enriched.summary);
        const shape = data => data.bot_groups.map(g => [g.group_name, g.requests, g.unique_ips, g.verification_status, g.sub_bots.map(b => [b.bot_name, b.requests])]);
        assert.deepEqual(shape(worker), shape(memory));
        assert.deepEqual(worker.spoofed_bot_ips, memory.spoofed_bot_ips);
    });

    test('worker traffic filters return exactly the class counts', () => {
        const { filter } = runWorker();
        for (const [cls, count] of Object.entries(expected)) {
            assert.equal(filter({ bot: cls }).summary.matchingCount, count, `bot=${cls}`);
        }
        assert.equal(filter({ bot: 'all_bots' }).summary.matchingCount, 30);
        assert.equal(filter({ bot: 'verified', botGroup: 'Google' }).summary.matchingCount, 8);
        assert.equal(filter({ bot: 'spoofed', botGroup: 'Microsoft' }).summary.matchingCount, 0);
    });

    test('worker traffic filter combines with other filters', () => {
        const { filter } = runWorker();
        const res = filter({ bot: 'human', statusCategory: '4xx' });
        assert.equal(res.summary.matchingCount, 3);
        assert.equal(res.summary.traffic.human_requests, 3);
        assert.equal(res.pageResult.rows.length, 3);
        assert.ok(res.pageResult.rows.every(r => r.traffic_class === 'human' && r.status_code === 404 && r.user_agent === CHROME));

        assert.equal(filter({ bot: 'all_bots', statusCategory: '4xx' }).summary.matchingCount, 16);
    });
});
