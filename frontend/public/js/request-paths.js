/**
 * Request paths — Client-Side
 *
 * The one place that decides what the "path" of a logged request is. The
 * tables, the path filter, the parser's exclusions and the traffic classifier
 * all use it, so a path is counted, filtered and judged the same way.
 */

const RequestPaths = (() => {
    const CACHE_LIMIT = 20000;

    function cached(cache, key, compute) {
        let value = cache.get(key);
        if (value === undefined) {
            value = compute(key);
            if (cache.size >= CACHE_LIMIT) cache.clear();
            cache.set(key, value);
        }
        return value;
    }

    /** Decode %XX once; bytes that are not valid UTF-8 are left as written. */
    function decodeOnce(str) {
        if (str.indexOf('%') === -1) return str;
        try {
            return decodeURIComponent(str);
        } catch {
            return str.replace(/%([0-9a-f]{2})/gi, (m, hex) => {
                const code = parseInt(hex, 16);
                return code < 0x80 ? String.fromCharCode(code) : m;
            });
        }
    }

    /**
     * Split a request target into path and query.
     * Accepts origin-form (`/a?b`), absolute-form (`http://host/a?b`), `*`
     * and `host:port` (CONNECT). A fragment is dropped.
     */
    function splitTarget(url) {
        let target = typeof url === 'string' ? url : '';
        const hash = target.indexOf('#');
        if (hash !== -1) target = target.slice(0, hash);
        const scheme = /^[a-z][a-z0-9+.-]*:\/\/[^/?]*/i.exec(target);
        if (scheme) target = target.slice(scheme[0].length) || '/';
        const q = target.indexOf('?');
        return q === -1 ? { path: target, query: '' } : { path: target.slice(0, q), query: target.slice(q + 1) };
    }

    function computePath(url) {
        let { path } = splitTarget(url);
        if (!path || path === '-') return '';
        if (path[0] !== '/') return path; // `*`, `host:port`, or not HTTP at all
        // Only characters that never change the meaning are decoded, so
        // `/a%2Fb` stays different from `/a/b`.
        path = path.replace(/%([0-9a-f]{2})/gi, (m, hex) => {
            const ch = String.fromCharCode(parseInt(hex, 16));
            return /[A-Za-z0-9._~-]/.test(ch) ? ch : '%' + hex.toUpperCase();
        });
        const out = [];
        for (let seg of path.split('/')) {
            const semi = seg.indexOf(';');
            if (semi !== -1) seg = seg.slice(0, semi); // ;jsessionid=...
            if (seg === '' || seg === '.') continue;
            if (seg === '..') { out.pop(); continue; }
            out.push(seg);
        }
        return '/' + out.join('/');
    }

    const pathCache = new Map();

    /**
     * The path of a request target in one spelling: no query, fragment or
     * `;parameters`, no host, no `//`, `/./` or `/../`, no trailing slash.
     * `//index.html`, `/./index.html` and `/index%2Ehtml` are all `/index.html`.
     * Case is kept, because paths are case-sensitive.
     */
    function normalizePath(url) {
        if (!url || typeof url !== 'string') return '';
        return cached(pathCache, url, computePath);
    }

    /** First level of a path: `/static/app.js` -> `/static`, `/` -> `/`. */
    function sectionOf(url) {
        const path = normalizePath(url);
        if (!path || path[0] !== '/') return path;
        const next = path.indexOf('/', 1);
        return next === -1 ? path : path.slice(0, next);
    }

    // What a page pulls in by itself. Requests for these show a browser at work.
    const ASSET_RE = /\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|cur|webp|avif|bmp|tiff?|heic|woff2?|ttf|otf|eot|webmanifest|wasm)$/i;
    // Downloads and media: neither a page view nor proof of a browser.
    const MEDIA_RE = /\.(?:pdf|zip|gz|tgz|tar|7z|rar|dmg|exe|msi|apk|ipa|iso|mp4|m4v|m4s|m4a|webm|mov|avi|mkv|mp3|aac|ogg|oga|wav|flac|ts|m3u8|mpd|vtt|srt|docx?|xlsx?|pptx?|csv|epub)$/i;

    /** 'asset' | 'media' | 'page' */
    function resourceKind(url) {
        const path = normalizePath(url);
        if (ASSET_RE.test(path)) return 'asset';
        if (MEDIA_RE.test(path)) return 'media';
        return 'page';
    }

    const AUTH_PATH_RE = /(?:^|\/)(?:wp-login\.php|xmlrpc\.php|login|log-in|log_in|signin|sign-in|sign_in|logon|authenticate|auth|token|session|sessions)(?:\.[a-z0-9]+)?$/i;
    const CREDENTIAL_QUERY_RE = /(?:^|&)(?:pass|passwd|password|pwd)=/i;

    /** A request that tries to log in: a login endpoint, or a password in the query. */
    function isAuthRequest(method, url) {
        if (!url) return false;
        const { query } = splitTarget(url);
        if (query && CREDENTIAL_QUERY_RE.test(query)) return true;
        return method === 'POST' && AUTH_PATH_RE.test(normalizePath(url));
    }

    // ── Attack signatures ────────────────────────────────────────────────
    // Checked against the fully decoded, lower-cased target (path and query).
    // "strong" families are requests nobody makes by following links.
    const SIGNATURES = [
        ['traversal', true, /(?:\.\.[\/\\]){2,}|\/etc\/(?:passwd|shadow|hosts)\b|\/proc\/self\/|\b(?:win|boot)\.ini\b|\/windows\/system32/],
        ['injection', true, /\bunion(?:\s|\+|\/\*.*?\*\/)+(?:all(?:\s|\+)+)?select\b|\bselect\b.{1,80}\bfrom\b.{0,40}\binformation_schema|'\s*(?:or|and)\s*'?\d|\b(?:or|and)\s+\d+\s*=\s*\d+|\b(?:sleep|benchmark|pg_sleep|load_file)\s*\(|\bwaitfor\s+delay\b|xp_cmdshell|<\s*script|<\s*(?:img|svg|iframe)\b[^>]*\bon\w+\s*=|javascript:|\$\{\s*jndi:|\$\{[^}]*\$\{|(?:;|\||&&|`|\$\()\s*(?:cat|id|wget|curl|uname|whoami|nc|bash|sh|ping)(?=\s|$|[;|&`)])|\b(?:php|file|expect|data|zip|phar):\/\/|\(\)\s*\{\s*:;\s*\}/],
        ['secrets', true, /\/\.(?:env|git|svn|hg|aws|ssh|htpasswd|htaccess|ds_store|npmrc|dockerenv|vscode|idea|bash_history|kube)(?:[\/.?]|$)|\/(?:id_rsa|id_dsa|id_ed25519|credentials|web\.config|wp-config[^\/?]*|config\.(?:php|yml|yaml|json|inc)\.[a-z~]+|local\.settings\.json|server-(?:status|info))(?:[\/?]|$)|\.(?:sql|sqlite|sqlite3|bak|old|orig|save|swp|dump|mdb)(?:\.(?:gz|zip|bz2|xz|tar))?(?:\?|$)|\/(?:backup|backups|dump|database|db|site|www|wwwroot|public_html|htdocs|html|web|archive)(?:[-_.]?\d[\d_.-]*)?\.(?:zip|tar|tar\.gz|tgz|gz|7z|rar|sql)(?:\?|$)|\.[a-z0-9]{1,5}~(?:\?|$)/],
        ['exploit', true, /eval-stdin\.php|\/vendor\/phpunit|\/_ignition\/|\/actuator\/(?:env|heapdump|gateway|jolokia|mappings|shutdown)|\/solr\/admin|\/manager\/html|\/hnap1|boaform|setup\.cgi|\/cgi-bin\/|\/owa\/auth|autodiscover\.xml|\/telescope\/requests|\/(?:shell|cmd|c99|r57|wso|alfa|webshell|backdoor|upl|mini)\d*\.(?:php|jsp|asp|aspx)|\/wp-content\/uploads\/.*\.php|\/struts|\/jmx-console|\/invoker\/|\/console\/login|\/ecp\/|\/remote\/fgt_lang|\/dana-na\/|\/geoserver\/|\/druid\/|\/nacos\//],
        ['admin-tool', false, /phpmyadmin|\/pma\/|\/myadmin\/|adminer[\w.-]*\.php|phpinfo|\/info\.php|wlwmanifest\.xml|xmlrpc\.php|wp-login\.php|\/administrator\/index\.php|\/admin\.php|\/wp-admin\/(?:install|setup-config)\.php|\/user\/register|\/\.well-known\/.*\.(?:php|bak)/],
    ];
    // Skips the full check for the bulk of ordinary requests.
    const QUICK_RE = /\.\.|%|[<'"`$|;(~]|\/\.|\/etc\/|\/proc\/|\.(?:php|aspx?|jsp|cgi|sql|sqlite3?|bak|old|orig|save|swp|dump|mdb|ini|config|xml|zip|gz|tgz|tar|7z|rar)\b|passwd|admin|cgi-bin|actuator|solr|hnap|boaform|telescope|manager|server-|phpunit|ignition|credentials|id_rsa|struts|console|invoker|\/ecp\/|fgt_lang|dana-na|geoserver|druid|nacos|register|phpinfo|\/pma\//i;

    function computeSignature(url) {
        if (!QUICK_RE.test(url)) return null;
        // Decode twice: double encoding (`%252e`) is a common way round filters.
        const text = decodeOnce(decodeOnce(url.replace(/\+/g, ' '))).toLowerCase();
        for (const [family, strong, pattern] of SIGNATURES) {
            if (pattern.test(text)) return { family, strong };
        }
        return null;
    }

    const signatureCache = new Map();

    /**
     * Does this request target look like an attack?
     * @returns {{ family: 'traversal'|'injection'|'secrets'|'exploit'|'admin-tool', strong: boolean }|null}
     *   `strong` is false for paths that are also used legitimately on some
     *   sites (the WordPress login page, phpMyAdmin).
     */
    function attackSignature(url) {
        if (!url || typeof url !== 'string') return null;
        return cached(signatureCache, url, computeSignature);
    }

    const SCRIPT_RE = /\.(?:php\d?|phtml|aspx?|ashx|jspx?|cgi|pl|cfm|do|action)$/i;

    /** A server-side script file, the kind scanners try by name. */
    function isScriptPath(url) {
        return SCRIPT_RE.test(normalizePath(url));
    }

    /**
     * Build a test for the path filter.
     *   `=/a/b`  the path is exactly /a/b
     *   `^/a`    the path is in the section /a (first level)
     *   other    the text appears anywhere in the URL, ignoring case
     * @returns {(url: string) => boolean}
     */
    function pathMatcher(filter) {
        const value = typeof filter === 'string' ? filter.trim() : '';
        if (!value) return () => true;
        if (value[0] === '=') {
            const want = normalizePath(value.slice(1)) || value.slice(1);
            return url => normalizePath(url) === want;
        }
        if (value[0] === '^') {
            const want = sectionOf(value.slice(1)) || value.slice(1);
            return url => sectionOf(url) === want;
        }
        const term = value.toLowerCase();
        return url => (url || '').toLowerCase().includes(term);
    }

    /** Path filter value as shown to the user. */
    function describeFilter(filter) {
        const value = typeof filter === 'string' ? filter : '';
        if (value[0] === '=') return value.slice(1);
        if (value[0] === '^') return value.slice(1) + '/…';
        return value;
    }

    /**
     * Count requests per path and per section.
     * @param {Iterable<[string, number, Map<number, number>?]>} urlCounts - URL, hits, hits by status.
     */
    function summarize(urlCounts, total, limits = {}) {
        const pathLimit = limits.paths || 30;
        const sectionLimit = limits.sections || 25;
        const paths = new Map();
        const sections = new Map();
        let withPath = 0;
        for (const [url, count, statuses] of urlCounts) {
            const path = normalizePath(url);
            if (!path) continue;
            withPath += count;
            let rec = paths.get(path);
            if (!rec) { rec = { count: 0, statuses: new Map() }; paths.set(path, rec); }
            rec.count += count;
            if (statuses) for (const [code, n] of statuses) rec.statuses.set(code, (rec.statuses.get(code) || 0) + n);
            const section = sectionOf(url);
            sections.set(section, (sections.get(section) || 0) + count);
        }
        const pct = n => total ? (n / total * 100).toFixed(1) : '0.0';
        const sorted = [...paths.entries()].sort((a, b) => b[1].count - a[1].count);
        const top = sorted.slice(0, pathLimit).map(([path, rec]) => ({
            path,
            count: rec.count,
            percentage: pct(rec.count),
            status_breakdown: [...rec.statuses.entries()].sort((a, b) => b[1] - a[1]).map(([code, c]) => ({ code, count: c })),
            attack: (attackSignature(path) || {}).family || null,
        }));
        const shown = top.reduce((sum, p) => sum + p.count, 0);
        return {
            top_paths: top,
            other_paths: { paths: Math.max(0, sorted.length - top.length), count: withPath - shown, percentage: pct(withPath - shown) },
            distinct_paths: sorted.length,
            sections: [...sections.entries()].sort((a, b) => b[1] - a[1]).slice(0, sectionLimit)
                .map(([path, count]) => ({ path, count, percentage: pct(count) })),
        };
    }


    /**
     * The site a referrer names, for grouping: `https://www.Example.com:443/a?b`
     * is `www.example.com`. Empty when there is no referrer ("-") or it names
     * no site (a path on its own).
     */
    function referrerSite(referrer) {
        if (!referrer || typeof referrer !== 'string') return '';
        let site = referrer.trim();
        if (!site || site === '-') return '';
        const scheme = site.indexOf('://');
        if (scheme !== -1) site = site.slice(scheme + 3);
        else if (site.startsWith('//')) site = site.slice(2);
        else if (site[0] === '/') return '';
        const end = site.search(/[/?#]/);
        if (end !== -1) site = site.slice(0, end);
        const at = site.lastIndexOf('@');
        if (at !== -1) site = site.slice(at + 1);
        if (site[0] === '[') {
            const close = site.indexOf(']');
            if (close !== -1) site = site.slice(0, close + 1);
        } else {
            const colon = site.lastIndexOf(':');
            if (colon !== -1 && /^\d*$/.test(site.slice(colon + 1))) site = site.slice(0, colon);
        }
        return site.toLowerCase().replace(/\.$/, '');
    }

    return {
        splitTarget, normalizePath, sectionOf, resourceKind, isAuthRequest, attackSignature, isScriptPath,
        pathMatcher, describeFilter, summarize, referrerSite,
    };
})();

if (typeof window !== 'undefined') window.RequestPaths = RequestPaths;
if (typeof self !== 'undefined') self.RequestPaths = RequestPaths;
if (typeof globalThis !== 'undefined') globalThis.RequestPaths = RequestPaths;
if (typeof module !== 'undefined' && module.exports) module.exports = RequestPaths;
