/**
 * Bot Detector & User-Agent Spoofing Verification Engine — Client-Side
 * 
 * Capabilities:
 *  1. User-Agent Bot Detection: 35+ crawler regex patterns with grouping.
 *  2. Official CIDR Bitwise Verification: Ultra-fast 32-bit integer IPv4 masks
 *     and 128-bit IPv6 prefix matching against official bot IP ranges.
 *  3. Spoofing Detection: Flags traffic claiming to be official bots (Googlebot, Bingbot, GPTBot, etc.)
 *     originating from unverified/untrusted IP addresses.
 *  4. IndexedDB & Edge Caching: Caches /data/verified-bots.json in IndexedDB with fallback.
 */

const BotDetector = (() => {
    // ─── User-Agent Regex Patterns (85+ Comprehensive Crawlers) ───
    // Each entry: [displayName, regex, parentGroup (optional)]
    const BOT_PATTERNS = [
        // ── Google ──
        ['Googlebot', /Googlebot/i, 'Google'],
        ['AdsBot-Google', /AdsBot-Google/i, 'Google'],
        ['GoogleOther', /GoogleOther/i, 'Google'],
        ['Google-InspectionTool', /Google-InspectionTool/i, 'Google'],
        ['Storebot-Google', /Storebot-Google/i, 'Google'],
        ['Mediapartners-Google', /Mediapartners-Google/i, 'Google'],
        ['Feedfetcher-Google', /Feedfetcher-Google/i, 'Google'],
        ['APIs-Google', /APIs-Google/i, 'Google'],

        // ── Microsoft / Bing ──
        ['Bingbot', /bingbot/i, 'Microsoft'],
        ['MSNBot', /msnbot/i, 'Microsoft'],
        ['BingPreview', /BingPreview/i, 'Microsoft'],

        // ── OpenAI ──
        ['GPTBot', /GPTBot/i, 'OpenAI'],
        ['OAI-SearchBot', /OAI-SearchBot/i, 'OpenAI'],
        ['ChatGPT-User', /ChatGPT-User/i, 'OpenAI'],

        // ── Anthropic / Claude ──
        ['ClaudeBot', /ClaudeBot/i, 'Anthropic'],
        ['Claude-Web', /Claude-Web/i, 'Anthropic'],
        ['Anthropic', /anthropic/i, 'Anthropic'],

        // ── Perplexity AI ──
        ['PerplexityBot', /PerplexityBot/i, 'Perplexity'],
        ['Perplexity-User', /Perplexity-User/i, 'Perplexity'],

        // ── Apple ──
        ['Applebot', /Applebot/i, 'Apple'],
        ['Applebot-Extended', /Applebot-Extended/i, 'Apple'],

        // ── Amazon ──
        ['Amazonbot', /Amazonbot/i, 'Amazon'],

        // ── Other Major Search Engines ──
        ['DuckDuckBot', /DuckDuckBot/i, 'DuckDuckGo'],
        ['DuckAssistBot', /DuckAssistBot/i, 'DuckDuckGo'],
        ['YandexBot', /YandexBot/i, 'Yandex'],
        ['YandexImages', /YandexImages/i, 'Yandex'],
        ['Baidu Spider', /Baiduspider/i, 'Baidu'],
        ['Sogou', /Sogou/i, 'Sogou'],
        ['PetalBot', /PetalBot/i, 'Huawei'],
        ['AspiegelBot', /AspiegelBot/i, 'Huawei'],
        ['Yahoo! Slurp', /Yahoo!\s+Slurp|Slurp/i, 'Yahoo'],
        ['MojeekBot', /MojeekBot/i, 'Mojeek'],
        ['QwantBot', /Qwantify|QwantBot/i, 'Qwant'],
        ['CocCocBot', /CocCocBot/i, 'CocCoc'],
        ['Naver Yeti', /Yeti/i, 'Naver'],
        ['SeznamBot', /SeznamBot/i, 'Seznam'],
        ['ia_archiver', /ia_archiver/i, 'Internet Archive'],

        // ── Meta / Facebook ──
        ['Facebook External Hit', /facebookexternalhit/i, 'Facebook/Meta'],
        ['Facebot', /facebot/i, 'Facebook/Meta'],
        ['Meta External Agent', /meta-externalagent/i, 'Facebook/Meta'],
        ['Meta Web Indexer', /meta-webindexer/i, 'Facebook/Meta'],
        ['Meta External Ads', /meta-externalads/i, 'Facebook/Meta'],

        // ── Social & Messaging Link Preview ──
        ['Twitterbot', /Twitterbot/i, 'Twitter/X'],
        ['LinkedInBot', /LinkedInBot/i, 'LinkedIn'],
        ['TelegramBot', /TelegramBot/i, 'Telegram'],
        ['WhatsApp', /WhatsApp/i, 'WhatsApp'],
        ['Slackbot', /Slackbot|Slack-ImgProxy/i, 'Slack'],
        ['Discordbot', /Discordbot/i, 'Discord'],
        ['Pinterestbot', /Pinterestbot|Pinterest/i, 'Pinterest'],
        ['RedditBot', /RedditBot/i, 'Reddit'],
        ['SkypeUriPreview', /SkypeUriPreview/i, 'Skype'],
        ['Viber', /Viber/i, 'Viber'],
        ['VKShare', /VKShare/i, 'VKontakte'],
        ['Bluesky', /Bluesky/i, 'Bluesky'],

        // ── AI & Other Crawlers ──
        ['Bytespider', /Bytespider/i, 'ByteDance'],
        ['TikTokSpider', /TikTokSpider/i, 'ByteDance'],
        ['cohere-ai', /cohere-ai/i, 'Cohere'],
        ['Diffbot', /Diffbot/i, 'Diffbot'],
        ['YouBot', /YouBot/i, 'You.com'],
        ['DeepL_Bot', /DeepL_Bot/i, 'DeepL'],
        ['MistralBot', /MistralBot/i, 'Mistral'],

        // ── SEO & Audit Crawlers ──
        ['SemrushBot', /SemrushBot|SiteAuditBot|SplitSignalBot/i, 'Semrush'],
        ['AhrefsBot', /AhrefsBot|AhrefsSiteAudit/i, 'Ahrefs'],
        ['MJ12bot', /MJ12bot/i, 'Majestic'],
        ['DotBot', /DotBot/i, 'Moz'],
        ['Common Crawl', /CCBot/i, 'Common Crawl'],
        ['Barkrowler', /Barkrowler/i, 'Crawler'],
        ['Screaming Frog', /Screaming\s+Frog\s+SEO\s+Spider/i, 'SEO Spider'],
        ['SeoViewer', /SeoViewer/i, 'SEO'],
        ['SEOkicks', /SEOkicks/i, 'SEO'],
        ['MegaIndex', /MegaIndex/i, 'SEO'],
        ['CriteoBot', /CriteoBot/i, 'Criteo'],

        // ── Uptime & Performance Monitors ──
        ['UptimeRobot', /UptimeRobot/i, 'Monitoring'],
        ['Pingdom', /Pingdom/i, 'Monitoring'],
        ['Site24x7', /Site24x7/i, 'Monitoring'],
        ['StatusCake', /StatusCake/i, 'Monitoring'],
        ['GTmetrix', /GTmetrix/i, 'Monitoring'],
        ['Datadog Agent', /Datadog/i, 'Monitoring'],
        ['NewRelicPinger', /NewRelicPinger/i, 'Monitoring'],
        ['BetterStack', /BetterStack|Better\s+Uptime/i, 'Monitoring'],

        // ── Automated HTTP Clients & Scrapers ──
        ['Python-urllib', /Python-urllib/i, 'Scraper / Tool'],
        ['python-requests', /python-requests/i, 'Scraper / Tool'],
        ['aiohttp', /aiohttp/i, 'Scraper / Tool'],
        ['httpx', /httpx/i, 'Scraper / Tool'],
        ['Go-http-client', /Go-http-client/i, 'Scraper / Tool'],
        ['Java / HttpClient', /Java\/|Apache-HttpClient/i, 'Scraper / Tool'],
        ['libwww-perl', /libwww-perl/i, 'Scraper / Tool'],
        ['cURL / Wget', /curl\/|[wW]get/i, 'Scraper / Tool'],
        ['PostmanRuntime', /PostmanRuntime/i, 'Scraper / Tool'],
        ['Scrapy', /Scrapy/i, 'Scraper'],
        ['Headless Chrome / Puppeteer', /HeadlessChrome|Puppeteer|Playwright|Selenium/i, 'Automated Browser'],
        ['ImageSpider', /imageSpider/i, 'Scraper'],
        ['GeedoProductSearch', /GeedoProductSearch/i, 'E-Commerce'],
        ['Trident', /Trident/i, 'Generic'],
        ['Other Bot', /bot|crawl|spider|scraper|fetcher|checker|indexer|archive/i, 'Generic'],
    ];

    // Alias and normalization map to link UA bot names to verified IP feed keys
    const BOT_NAME_TO_SOURCE_KEYS = {
        'googlebot': ['googlebot', 'google_other', 'google_fetchers'],
        'adsbotgoogle': ['googlebot', 'google_other'],
        'googleother': ['google_other', 'googlebot', 'google_fetchers'],
        'googleinspectiontool': ['googlebot', 'google_other', 'google_fetchers'],
        'storebotgoogle': ['googlebot', 'google_other', 'google_fetchers'],
        'mediapartnersgoogle': ['googlebot', 'google_other', 'google_fetchers'],
        'feedfetchergoogle': ['google_fetchers', 'googlebot'],
        'apisgoogle': ['google_fetchers', 'googlebot'],
        'google': ['googlebot', 'google_other', 'google_fetchers'],
        'bingbot': ['bingbot'],
        'msnbot': ['bingbot'],
        'bingpreview': ['bingbot'],
        'microsoft': ['bingbot'],
        'gptbot': ['gptbot'],
        'oaisearchbot': ['oai_searchbot'],
        'searchbot': ['oai_searchbot'],
        'chatgptuser': ['chatgpt_user'],
        'openai': ['gptbot', 'oai_searchbot', 'chatgpt_user'],
        // Anthropic publishes one egress list for its crawlers rather than a
        // per-agent list, so every Anthropic UA pattern maps to the same source.
        'claudebot': ['claudebot'],
        'claudeweb': ['claudebot'],
        'claudeuser': ['claudebot'],
        'claudesearchbot': ['claudebot'],
        'anthropic': ['claudebot'],
        'claude': ['claudebot'],
        'duckduckbot': ['duckduckbot', 'duckassistbot'],
        'duckassistbot': ['duckassistbot', 'duckduckbot'],
        'duckduckgo': ['duckduckbot', 'duckassistbot'],
        'ahrefsbot': ['ahrefsbot'],
        'ahrefssiteaudit': ['ahrefsbot'],
        'ahrefs': ['ahrefsbot'],
        'ccbot': ['ccbot'],
        'commoncrawl': ['ccbot'],
        'perplexitybot': ['perplexity'],
        'perplexityuser': ['perplexity'],
        'perplexity': ['perplexity'],
        'amazonbot': ['amazonbot'],
        'amazon': ['amazonbot'],
        'yandexbot': ['yandexbot'],
        'yandeximages': ['yandexbot'],
        'yandex': ['yandexbot'],
        'mojeekbot': ['mojeekbot'],
        'mojeek': ['mojeekbot'],
        'qwantbot': ['qwantbot'],
        'qwant': ['qwantbot'],
        'applebot': ['applebot'],
        'applebotextended': ['applebot'],
        'apple': ['applebot'],
        'facebookexternalhit': ['facebook_meta'],
        'facebot': ['facebook_meta'],
        'metaexternalagent': ['facebook_meta'],
        'metawebindexer': ['facebook_meta'],
        'metaexternalads': ['facebook_meta'],
        'facebook': ['facebook_meta'],
        'meta': ['facebook_meta'],
        'pinterestbot': ['pinterest'],
        'pinterest': ['pinterest'],
        'telegrambot': ['telegram'],
        'telegram': ['telegram'],
        'twitterbot': ['twitter'],
        'twitter': ['twitter'],
        'linkedinbot': ['linkedin'],
        'linkedin': ['linkedin'],
        'baiduspider': ['baidu'],
        'baidu': ['baidu'],
        'sogou': ['sogou'],
        'petalbot': ['petalbot'],
        'aspiegelbot': ['petalbot'],
        'huawei': ['petalbot'],
        'semrushbot': ['semrush'],
        'semrush': ['semrush'],
        'mj12bot': ['mj12bot'],
        'majestic': ['mj12bot'],
        'dotbot': ['dotbot'],
        'moz': ['dotbot'],
        'criteobot': ['criteo'],
        'criteo': ['criteo'],
        'uptimerobot': ['uptimerobot'],
        'pingdom': ['pingdom'],
        'datadog': ['datadog'],
        'datadogagent': ['datadog'],
        'betterstack': ['betterstack'],
        'betteruptime': ['betterstack'],
        'github': ['github'],
        'stripe': ['stripe'],
    };

    // ─── IndexedDB Constants ───
    const IDB_NAME = 'sysadmin_bot_cache';
    const IDB_VERSION = 1;
    const IDB_STORE = 'bot_metadata';

    let verifiedBotsData = null;
    let compiledIndices = new Map(); // bot_key -> { ipv4Rules: [{mask, network}], ipv6Rules: [{mask, network}] }
    let verificationCache = new Map(); // "botKey|ip" -> result object
    let initPromise = null;

    // ─── Bitwise IPv4 Utilities ───

    function ipv4ToInt(ip) {
        if (!ip || typeof ip !== 'string') return null;
        const parts = ip.split('.');
        if (parts.length !== 4) return null;
        const a = parseInt(parts[0], 10);
        const b = parseInt(parts[1], 10);
        const c = parseInt(parts[2], 10);
        const d = parseInt(parts[3], 10);
        if (isNaN(a) || isNaN(b) || isNaN(c) || isNaN(d)) return null;
        if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) return null;
        return (((a << 24) | (b << 16) | (c << 8) | d) >>> 0);
    }

    function parseIpv4Cidr(cidr) {
        const parts = cidr.split('/');
        const ipInt = ipv4ToInt(parts[0]);
        if (ipInt === null) return null;
        const maskLen = parts[1] !== undefined ? parseInt(parts[1], 10) : 32;
        if (isNaN(maskLen) || maskLen < 0 || maskLen > 32) return null;
        const mask = maskLen === 0 ? 0 : ((0xFFFFFFFF << (32 - maskLen)) >>> 0);
        const network = (ipInt & mask) >>> 0;
        return { mask, network };
    }

    // ─── IPv6 Utilities ───

    function parseIpv6(ip) {
        if (!ip || typeof ip !== 'string') return null;
        let str = ip.toLowerCase().trim();
        const zoneIdx = str.indexOf('%');
        if (zoneIdx !== -1) str = str.slice(0, zoneIdx);

        const doubleColon = str.indexOf('::');
        let parts;
        if (doubleColon !== -1) {
            const head = str.slice(0, doubleColon).split(':').filter(Boolean);
            const tail = str.slice(doubleColon + 2).split(':').filter(Boolean);
            const missing = 8 - (head.length + tail.length);
            if (missing < 0) return null;
            const middle = new Array(missing).fill('0');
            parts = head.concat(middle, tail);
        } else {
            parts = str.split(':');
        }

        if (parts.length !== 8) return null;

        let high = 0n;
        let low = 0n;
        for (let i = 0; i < 4; i++) {
            const val = BigInt(parseInt(parts[i], 16) || 0);
            high = (high << 16n) | val;
        }
        for (let i = 4; i < 8; i++) {
            const val = BigInt(parseInt(parts[i], 16) || 0);
            low = (low << 16n) | val;
        }
        return (high << 64n) | low;
    }

    function parseIpv6Cidr(cidr) {
        const parts = cidr.split('/');
        const ip128 = parseIpv6(parts[0]);
        if (ip128 === null) return null;
        const maskLen = parts[1] !== undefined ? parseInt(parts[1], 10) : 128;
        if (isNaN(maskLen) || maskLen < 0 || maskLen > 128) return null;
        const mask = maskLen === 0 ? 0n : (((1n << 128n) - 1n) ^ ((1n << BigInt(128 - maskLen)) - 1n));
        const network = ip128 & mask;
        return { mask, network };
    }

    // ─── Non-Public (Reserved) Address Classification ───

    // Ranges that cannot legitimately originate from the public internet. A
    // request arriving at a public web server from one of these is spoofed at
    // the network layer, regardless of the User-Agent it claims. Masks are
    // derived from CIDR strings via the same parsers used to compile the feed,
    // so they cannot drift out of sync with `parseIpv4Cidr` / `parseIpv6Cidr`.
    // Most-specific prefix first, so the reported label is the tightest match.
    const NON_PUBLIC_V4 = [
        { cidr: '127.0.0.0/8', label: 'loopback (127.0.0.0/8)' },
        { cidr: '10.0.0.0/8', label: 'private RFC1918 (10.0.0.0/8)' },
        { cidr: '172.16.0.0/12', label: 'private RFC1918 (172.16.0.0/12)' },
        { cidr: '100.64.0.0/10', label: 'CGNAT (100.64.0.0/10)' },
        { cidr: '169.254.0.0/16', label: 'link-local (169.254.0.0/16)' },
        { cidr: '192.168.0.0/16', label: 'private RFC1918 (192.168.0.0/16)' },
    ].map(r => ({ ...parseIpv4Cidr(r.cidr), label: r.label }));
    const NON_PUBLIC_V6 = [
        { cidr: '::1/128', label: 'loopback (::1/128)' },
        { cidr: 'fc00::/7', label: 'unique local (fc00::/7)' },
        { cidr: 'fe80::/10', label: 'link-local (fe80::/10)' },
    ].map(r => ({ ...parseIpv6Cidr(r.cidr), label: r.label }));

    /**
     * Unwrap an IPv4-mapped / IPv4-compatible IPv6 address to its bare IPv4
     * form (e.g. `::ffff:192.178.4.1` -> `192.178.4.1`).
     *
     * Nginx reports `$remote_addr` in the address family the connection
     * actually used, so the same client can legitimately appear as either
     * `192.178.4.1` or `::ffff:192.178.4.1`. Left un-normalised, the mapped
     * form matches neither the IPv4 nor the IPv6 published CIDRs (a genuine
     * Googlebot would be reported as spoofed) while also slipping past the
     * reserved-range check below (a private address would look routable).
     * Both are wrong in opposite directions, so the unwrap happens once, up
     * front, for every downstream check.
     *
     * @param {string} ip - Client IP address.
     * @returns {string} The bare IPv4 address if `ip` is a v4-mapped form,
     *   otherwise `ip` unchanged.
     */
    function normalizeClientIp(ip) {
        if (typeof ip !== 'string' || !ip.includes(':')) return ip;

        const str = ip.toLowerCase().trim();
        const v4Mapped = str.match(/^::(?:ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
        if (v4Mapped) {
            // Re-validate octets: `::ffff:999.1.1.1` is not a v4-mapped address.
            const octets = v4Mapped[1].split('.');
            if (octets.every(o => Number(o) <= 255 && o !== '')) {
                return v4Mapped[1];
            }
        }
        return ip;
    }

    /**
     * Classify a client IP that cannot legitimately originate from the public
     * internet (RFC1918, loopback, link-local, CGNAT, IPv6 ULA).
     *
     * @param {string} ip - Client IP address, IPv4 or IPv6.
     * @returns {{status: string, reason: string}|null} Descriptor for the
     *   reserved range the IP falls in, or null if the IP is public (or is
     *   syntactically invalid — invalid input is left to the caller's normal
     *   verification path, which already fails closed).
     */
    function classifyNonPublicIp(ip) {
        if (typeof ip !== 'string' || !ip) return null;

        // Resolve v4-mapped forms first so `::ffff:10.0.0.1` is judged as IPv4.
        const normalized = normalizeClientIp(ip);

        if (normalized.includes(':')) {
            const ip128 = parseIpv6(normalized);
            if (ip128 === null) return null;
            for (const rule of NON_PUBLIC_V6) {
                if ((ip128 & rule.mask) === rule.network) {
                    return { status: 'spoofed', reason: `Non-routable client IP (${rule.label})` };
                }
            }
            return null;
        }

        const ipInt = ipv4ToInt(normalized);
        if (ipInt === null) return null;
        for (const rule of NON_PUBLIC_V4) {
            if (((ipInt & rule.mask) >>> 0) === rule.network) {
                return { status: 'spoofed', reason: `Non-routable client IP (${rule.label})` };
            }
        }
        return null;
    }

    // ─── IndexedDB Storage Helpers ───

    function openIndexedDb() {
        return new Promise((resolve, reject) => {
            if (typeof indexedDB === 'undefined') {
                return reject(new Error('IndexedDB not supported'));
            }
            const req = indexedDB.open(IDB_NAME, IDB_VERSION);
            req.onupgradeneeded = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains(IDB_STORE)) {
                    db.createObjectStore(IDB_STORE);
                }
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
    }

    async function getIdbData(key) {
        try {
            const db = await openIndexedDb();
            return new Promise((resolve) => {
                const tx = db.transaction(IDB_STORE, 'readonly');
                const req = tx.objectStore(IDB_STORE).get(key);
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => resolve(null);
            });
        } catch {
            return null;
        }
    }

    async function setIdbData(key, value) {
        try {
            const db = await openIndexedDb();
            return new Promise((resolve) => {
                const tx = db.transaction(IDB_STORE, 'readwrite');
                tx.objectStore(IDB_STORE).put(value, key);
                tx.oncomplete = () => resolve(true);
                tx.onerror = () => resolve(false);
            });
        } catch {
            return false;
        }
    }

    // ─── Build Bitwise Search Indices ───

    function compileIndices(data) {
        compiledIndices.clear();
        verificationCache.clear();
        if (!data || !data.bots) return;

        for (const [botKey, botObj] of Object.entries(data.bots)) {
            const ipv4Rules = [];
            const ipv6Rules = [];

            if (Array.isArray(botObj.ipv4)) {
                for (const cidr of botObj.ipv4) {
                    const rule = parseIpv4Cidr(cidr);
                    if (rule) ipv4Rules.push(rule);
                }
            }

            if (Array.isArray(botObj.ipv6)) {
                for (const cidr of botObj.ipv6) {
                    const rule = parseIpv6Cidr(cidr);
                    if (rule) ipv6Rules.push(rule);
                }
            }

            compiledIndices.set(botKey, {
                botKey,
                name: botObj.name || botKey,
                group: botObj.group || botObj.name || botKey,
                ipv4Rules,
                ipv6Rules,
                totalCidrs: ipv4Rules.length + ipv6Rules.length,
            });
        }
    }

    // ─── Initialization ───

    async function init() {
        if (initPromise) return initPromise;

        initPromise = (async () => {
            try {
                // 1. Try to fetch fresh verified-bots.json (Edge CDN cached with stale-while-revalidate)
                const res = await fetch('/data/verified-bots.json', { cache: 'default' });
                if (res.ok) {
                    const data = await res.json();
                    if (data && data.bots) {
                        verifiedBotsData = data;
                        compileIndices(data);
                        await setIdbData('verified_bots_data', data);
                        return true;
                    }
                }
            } catch (err) {
                console.warn('BotDetector: Live fetch failed, trying IndexedDB cache:', err.message);
            }

            // 2. Fallback to IndexedDB
            const cached = await getIdbData('verified_bots_data');
            if (cached && cached.bots) {
                verifiedBotsData = cached;
                compileIndices(cached);
                return true;
            }

            console.warn('BotDetector: No verified bots data available.');
            return false;
        })();

        return initPromise;
    }

    // Trigger eager background load on script load
    if (typeof window !== 'undefined') {
        init().catch(() => {});
    }

    // ─── Core Bot Detection from User-Agent ───

    /**
     * Detect bot from user-agent string.
     * @returns {{ name: string, group: string|null }} or null for human traffic
     */
    function detectBot(userAgent) {
        if (!userAgent || userAgent === '-') return null;
        for (const [name, pattern, group] of BOT_PATTERNS) {
            if (pattern.test(userAgent)) {
                return { name, group: group || null };
            }
        }
        return null;
    }

    /**
     * Legacy helper: returns bot name string or null
     */
    function detectBotName(userAgent) {
        const result = detectBot(userAgent);
        return result ? result.name : null;
    }

    // ─── Verification & Spoof Detection ───

    function normalizeBotKey(botName) {
        if (!botName) return '';
        return String(botName).toLowerCase().replace(/[^a-z0-9]/g, '');
    }

    function getSourceKeysForBot(botName) {
        const norm = normalizeBotKey(botName);
        if (BOT_NAME_TO_SOURCE_KEYS[norm]) {
            return BOT_NAME_TO_SOURCE_KEYS[norm];
        }
        // Direct match in compiledIndices
        if (compiledIndices.has(norm)) {
            return [norm];
        }
        // Partial substring match in compiledIndices
        for (const key of compiledIndices.keys()) {
            if (norm.includes(key) || key.includes(norm)) {
                return [key];
            }
        }
        return [];
    }

    /**
     * Verify if an IP claiming to be a specific bot is authentic or spoofed.
     * 
     * @param {string} botName - Detected bot name (e.g. "Googlebot", "Bingbot", "GPTBot", "YandexBot")
     * @param {string} ip - Remote client IP address
     * @returns {{
     *   verified: boolean|null,
     *   status: 'verified'|'spoofed'|'unverified_publisher'|'human',
     *   reason: string,
     *   matchedSource?: string
     * }}
     */
    function verifyBot(botName, ip) {
        if (!botName) {
            return { verified: null, status: 'human', reason: 'Human traffic' };
        }
        if (!ip || typeof ip !== 'string') {
            return { verified: null, status: 'unverified_publisher', reason: 'Invalid client IP address' };
        }

        const cacheKey = `${botName}|${ip}`;
        if (verificationCache.has(cacheKey)) {
            return verificationCache.get(cacheKey);
        }

        const sourceKeys = getSourceKeysForBot(botName);

        // A client IP from a reserved/non-routable range can never be a real
        // crawler on a public web server, whatever the User-Agent claims. This
        // is checked BEFORE the publisher-feed test below, otherwise a bot whose
        // publisher publishes no CIDR feed would mask the spoof and be reported
        // as `unverified_publisher` — the same bucket as a legitimate bot.
        const nonPublic = classifyNonPublicIp(ip);
        if (nonPublic) {
            const spoofedResult = {
                verified: false,
                status: nonPublic.status,
                reason: `Fake/Spoofed ${botName} (${nonPublic.reason})`,
            };
            verificationCache.set(cacheKey, spoofedResult);
            return spoofedResult;
        }

        // Filter for source keys that have non-empty CIDR rules
        const activeSources = sourceKeys
            .map(key => compiledIndices.get(key))
            .filter(src => src && src.totalCidrs > 0);

        // If no official verified source exists for this bot publisher
        if (activeSources.length === 0) {
            const res = {
                verified: null,
                status: 'unverified_publisher',
                reason: `Bot publisher (${botName}) does not publish official IP verification feeds`,
            };
            verificationCache.set(cacheKey, res);
            return res;
        }

        // Test IPv4 or IPv6. `clientIp` is the v4-mapped-normalised form, so a
        // client connecting over an IPv6 socket but routed as IPv4 is matched
        // against the published IPv4 ranges rather than being called spoofed.
        const clientIp = normalizeClientIp(ip);
        const isV4 = clientIp.includes('.');
        let isMatch = false;
        let matchedName = activeSources[0].name;

        if (isV4) {
            const ipInt = ipv4ToInt(clientIp);
            if (ipInt !== null) {
                for (const src of activeSources) {
                    for (let i = 0; i < src.ipv4Rules.length; i++) {
                        const rule = src.ipv4Rules[i];
                        if (((ipInt & rule.mask) >>> 0) === rule.network) {
                            isMatch = true;
                            matchedName = src.name;
                            break;
                        }
                    }
                    if (isMatch) break;
                }
            }
        } else {
            const ip128 = parseIpv6(clientIp);
            if (ip128 !== null) {
                for (const src of activeSources) {
                    for (let i = 0; i < src.ipv6Rules.length; i++) {
                        const rule = src.ipv6Rules[i];
                        if ((ip128 & rule.mask) === rule.network) {
                            isMatch = true;
                            matchedName = src.name;
                            break;
                        }
                    }
                    if (isMatch) break;
                }
            }
        }

        let result;
        if (isMatch) {
            result = {
                verified: true,
                status: 'verified',
                reason: `Official ${matchedName} IP`,
                matchedSource: matchedName,
            };
        } else {
            result = {
                verified: false,
                status: 'spoofed',
                reason: `Fake/Spoofed ${botName} (Untrusted IP)`,
            };
        }

        verificationCache.set(cacheKey, result);
        return result;
    }

    function isKnownBot(botName) {
        const sourceKeys = getSourceKeysForBot(botName);
        return sourceKeys.some(key => {
            const src = compiledIndices.get(key);
            return src && src.totalCidrs > 0;
        });
    }

    function getBotStats() {
        return {
            isLoaded: Boolean(verifiedBotsData),
            totalSources: compiledIndices.size,
            totalCidrs: Array.from(compiledIndices.values()).reduce((sum, s) => sum + s.totalCidrs, 0),
            sources: Array.from(compiledIndices.values()).map(s => ({
                key: s.botKey,
                name: s.name,
                group: s.group,
                totalCidrs: s.totalCidrs,
            })),
        };
    }

    return {
        BOT_PATTERNS,
        init,
        detectBot,
        detectBotName,
        verifyBot,
        isKnownBot,
        getBotStats,
    };
})();

// Export globally for browser scripts, and onto `self` for Web Workers.
// The Worker that parses large uploads is a *different global scope* with no
// `window`, so a `window`-only export makes BotDetector permanently undefined
// there. `log-parser.js` then silently falls back to a regex that cannot match
// camelCase bot names (ClaudeBot, GPTBot - no word boundary before "Bot"),
// which is how spoofed ClaudeBot/GPTBot lines on private or 403'd requests
// were being dropped from the analysis entirely.
if (typeof window !== 'undefined') {
    window.BotDetector = BotDetector;
}
if (typeof self !== 'undefined') {
    self.BotDetector = BotDetector;
}
if (typeof globalThis !== 'undefined') {
    globalThis.BotDetector = BotDetector;
}
