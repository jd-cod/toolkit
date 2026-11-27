const { test } = require('node:test');
const assert = require('node:assert/strict');

globalThis.RequestPaths = require('../../frontend/public/js/request-paths.js');
globalThis.BotDetector = require('../../frontend/public/js/bot-detector.js');
const LogParser = require('../../frontend/public/js/log-parser.js');

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36';
const ALL = { skip403: false, skipInternal: false };
const line = (req, x = {}) =>
    `${x.ip || '8.8.8.8'} - ${x.user || '-'} [${x.time || '27/Nov/2026:10:00:00 +0000'}] "${req}" ${x.status || 200} ${x.bytes ?? 123} "${x.ref || '-'}" "${x.ua || UA}"${x.tail || ''}`;
const many = (n, make) => Array.from({ length: n }, (_, i) => make(i)).join('\n');

test('request line: a URL with a space stays whole, non-HTTP bytes are not a method', () => {
    let r = LogParser.parseLine(line('GET /my file.pdf HTTP/1.1'), ALL);
    assert.deepEqual([r.method, r.url, r.httpVersion], ['GET', '/my file.pdf', 'HTTP/1.1']);
    r = LogParser.parseLine(line('get /a HTTP/1.1'), ALL);
    assert.equal(r.method, 'GET');
    r = LogParser.parseLine(line('\\x16\\x03\\x01\\x00'), ALL);
    assert.ok(r.valid);
    assert.deepEqual([r.method, r.url], [null, null]);
    r = LogParser.parseLine(line('GET /old'), ALL);
    assert.deepEqual([r.method, r.url, r.httpVersion], ['GET', '/old', null]);
    r = LogParser.parseLine(line('<b> /invalid HTTP/1.1'), ALL);
    assert.deepEqual([r.method, r.url], ['<b>', '/invalid'], 'a full request line reports its method as sent');
});

test('escaped quotes do not break the line', () => {
    let r = LogParser.parseLine(line('GET /a\\"b HTTP/1.1'), ALL);
    assert.deepEqual([r.url, r.statusCode, r.responseSize, r.userAgent], ['/a"b', 200, 123, UA]);
    r = LogParser.parseLine(line('GET /a HTTP/1.1', { ref: 'https://x.test/?q=\\"hi\\"' }), ALL);
    assert.equal(r.referrer, 'https://x.test/?q="hi"');
});

test('status outside 100-599 is unknown; sizes above 4 GiB are kept', () => {
    assert.equal(LogParser.parseLine(line('GET /a HTTP/1.1', { status: 999 }), ALL).statusCode, 0);
    assert.equal(LogParser.parseLine(line('GET /a HTTP/1.1', { status: 499 }), ALL).statusCode, 499);
    assert.equal(LogParser.parseLine(line('GET /a HTTP/1.1', { bytes: 5368709120 }), ALL).responseSize, 5368709120);
});

test('client address forms', () => {
    const ip = token => { const r = LogParser.parseLine(line('GET /a HTTP/1.1', { ip: token }), ALL); return r.valid ? r.ip : null; };
    assert.equal(ip('8.8.8.8:51234'), '8.8.8.8');
    assert.equal(ip('[2001:db8::1]:443'), '2001:db8::1');
    assert.equal(ip('::ffff:8.8.4.4'), '8.8.4.4');
    assert.equal(ip('2001:0DB8:0000:0000:0000:0000:0000:0001'), '2001:db8::1');
    assert.equal(ip('2001:db8:0:0:0:0:0:1'), '2001:db8::1');
    assert.equal(ip('host.example.com'), null);
    assert.equal(ip('08.8.8.8'), null);
});

test('addresses that cannot be internet clients are internal', () => {
    for (const ip of ['10.1.2.3', '172.16.0.1', '192.168.1.1', '127.0.0.1', '169.254.1.1', '100.64.0.1', '198.18.0.5', '224.0.0.1', '240.0.0.1',
        '::1', 'fd00::1', 'fe80::1', 'fec0::1', 'ff02::1', '::ffff:10.0.0.1']) {
        assert.ok(LogParser.isPrivateIP(ip), ip);
    }
    for (const ip of ['8.8.8.8', '172.32.0.1', '100.128.0.1', '2a00:1450::1']) assert.ok(!LogParser.isPrivateIP(ip), ip);
});

test('behind a private proxy the client comes from X-Forwarded-For', () => {
    const text = many(50, i => line(`GET /p${i} HTTP/1.1`, { ip: '10.0.0.5', tail: ` "81.2.69.${1 + i}"` }));
    const r = LogParser.parseIPs(text, { skip403: true, skipInternal: true });
    assert.equal(r.logEntries.length, 50);
    assert.equal(r.forwardedLines, 50);
    assert.equal(new Set(r.ips).size, 50);
    assert.equal(r.skipCounts.privateIP, 0);
});

test('behind a CDN the client comes from X-Forwarded-For when nearly every line has one', () => {
    const text = many(60, i => line(`GET /p${i} HTTP/1.1`, { ip: `172.70.1.${1 + (i % 5)}`, tail: ` "81.2.69.${1 + (i % 40)}"` }));
    const r = LogParser.parseIPs(text, ALL);
    assert.equal(r.forwardedLines, 60);
    assert.equal(new Set(r.ips).size, 40);
    assert.equal(LogParser.parseIPs(text, { ...ALL, clientIp: 'remote' }).forwardedLines, 0);
});

test('a forwarded header from a direct client is not trusted', () => {
    // Three of sixty visitors send their own X-Forwarded-For; the server is not behind a proxy.
    const text = many(60, i => line(`GET /p${i} HTTP/1.1`, { ip: `81.2.69.${1 + i}`, tail: i % 20 === 0 ? ' "66.249.66.1"' : ' "-"' }));
    const r = LogParser.parseIPs(text, ALL);
    assert.equal(r.forwardedLines, 0);
    assert.ok(!r.ips.includes('66.249.66.1'));
});

test('the client address can be chosen instead of left to the automatic rule', () => {
    // A direct client that sends its own forwarded header: not trusted automatically.
    const text = many(40, i => line('GET / HTTP/1.1', { ip: `81.2.69.${i + 1}`, tail: i % 2 ? ' "6.6.6.6"' : ' "-"' }));
    const auto = LogParser.parseIPs(text, ALL);
    assert.equal(auto.forwardedLines, 0);
    assert.deepEqual(auto.options, { skip403: false, skipInternal: false }, 'the automatic rule is not named in the options');

    const forwarded = LogParser.parseIPs(text, { ...ALL, clientIp: 'forwarded' });
    assert.equal(forwarded.forwardedLines, 20);
    assert.equal(forwarded.ips.filter(ip => ip === '6.6.6.6').length, 20);
    assert.deepEqual(forwarded.options, { skip403: false, skipInternal: false, clientIp: 'forwarded' });

    const remote = LogParser.parseIPs(text, { ...ALL, clientIp: 'remote' });
    assert.equal(remote.forwardedLines, 0);
    assert.deepEqual(remote.options, { skip403: false, skipInternal: false, clientIp: 'remote' });

    // Anything else is the automatic rule.
    assert.deepEqual(LogParser.parseIPs(text, { ...ALL, clientIp: 'nonsense' }).options, { skip403: false, skipInternal: false });
});

test('the right-most public address of a forwarded list is the client', () => {
    assert.equal(LogParser.forwardedClient('6.6.6.6, 81.2.69.1, 10.1.1.1'), '81.2.69.1');
    assert.equal(LogParser.forwardedClient('10.0.0.1, 192.168.1.1'), '192.168.1.1');
    assert.equal(LogParser.forwardedClient('-'), null);
    const r = LogParser.parseLine(line('GET /a HTTP/1.1', { ip: '10.0.0.5', tail: ' 10.0.0.9:8080 0.01' }), ALL);
    assert.equal(r.ip, '10.0.0.5', 'an upstream address with a port is not a client');
});

test('timestamps keep the clock the server wrote', () => {
    const iso = t => { const d = LogParser.parseTimestamp(t); return d ? d.toISOString().slice(0, 19) : null; };
    assert.equal(iso('10/Oct/2026:13:55:36 -0700'), '2026-10-10T13:55:36');
    assert.equal(iso('2026-10-10T13:55:36-07:00'), '2026-10-10T13:55:36');
    assert.equal(iso('2026-10-10T13:55:36.123456Z'), '2026-10-10T13:55:36');
    assert.equal(iso('10/Oct/2026:13:55:36.123 +0000'), '2026-10-10T13:55:36');
    assert.equal(iso('1/oct/2026:13:55:36 +0000'), '2026-10-01T13:55:36');
    assert.equal(iso('2026-10-10T13:55:36+02'), '2026-10-10T13:55:36');
    assert.equal(iso('1791640536.123'), '2026-10-10T13:55:36');
    assert.equal(iso('1791640536123'), '2026-10-10T13:55:36');
    assert.equal(iso('Sat, 10 Oct 2026 13:55:36 GMT'), '2026-10-10T13:55:36');
    assert.equal(iso('29/Feb/2026:12:00:00 +0000'), null);
    assert.equal(iso('10/Oct/2026:13:55:60 +0000'), null);
    assert.equal(iso('10/Oct/2026:13:55:36 +0060'), null, 'an impossible offset marks a corrupt time');
    assert.equal(iso('2026-10-10T13:55:36+05:75'), null);
});

test('one stray date does not stretch the log span', () => {
    const rows = Array.from({ length: 600 }, (_, i) => line(`GET /p${i} HTTP/1.1`, { time: `27/Nov/2026:10:${String(Math.floor(i / 60)).padStart(2, '0')}:${String(i % 60).padStart(2, '0')} +0000` }));
    rows.splice(300, 0, line('GET /stray HTTP/1.1', { time: '27/Nov/2016:10:05:00 +0000' }));
    const r = LogParser.parseIPs(rows.join('\n'), ALL);
    assert.equal(r.logSpanMinutes, 9);
    assert.equal(r.strayTimestamps, 1);
    assert.equal(r.logEntries.length, 601);
});

test('"Ignore 403" hides ordinary refusals but keeps attacks and login attempts', () => {
    const on = { skip403: true, skipInternal: false };
    assert.equal(LogParser.parseLine(line('GET /page HTTP/1.1', { status: 403 }), on).reasonType, 'forbidden');
    assert.ok(LogParser.parseLine(line('GET /.env HTTP/1.1', { status: 403 }), on).valid);
    assert.ok(LogParser.parseLine(line('GET /?f=../../etc/passwd HTTP/1.1', { status: 403 }), on).valid);
    assert.ok(LogParser.parseLine(line('POST /login HTTP/1.1', { status: 403 }), on).valid);
    assert.ok(LogParser.parseLine(line('GET /page HTTP/1.1', { status: 403, ua: 'curl/8.4.0' }), on).valid);
});

test('health checks: only a normal GET or HEAD to a health endpoint is left out', () => {
    const on = { skip403: false, skipInternal: true };
    const kind = (req, x) => { const r = LogParser.parseLine(line(req, x), on); return r.valid ? 'kept' : r.reasonType; };
    assert.equal(kind('GET /health HTTP/1.1'), 'healthCheck');
    assert.equal(kind('HEAD /healthz/ready HTTP/1.1'), 'healthCheck');
    assert.equal(kind('GET /HealthCheck HTTP/1.1'), 'kept', 'paths are case-sensitive');
    assert.equal(kind('GET /livez?verbose HTTP/1.1'), 'healthCheck');
    assert.equal(kind('POST /health HTTP/1.1', { status: 500, ua: 'sqlmap/1.7' }), 'kept');
    assert.equal(kind('GET /health HTTP/1.1', { status: 503 }), 'kept');
    assert.equal(kind('GET /healthcare HTTP/1.1'), 'kept');
});

test('format detection: a damaged line costs one line, not the file', () => {
    const rows = Array.from({ length: 100 }, (_, i) => line(`GET /p${i} HTTP/1.1`, { status: i % 5 ? 200 : 404 }));
    rows[5] = '8.8.8.8 - - [27/Nov/2026:10:00:00 +0000] "GET /trunc';
    const r = LogParser.parseIPs(rows.join('\n'), ALL);
    assert.equal(r.format, 'standard');
    assert.equal(r.logEntries.length, 99);
    assert.equal(r.skipCounts.invalid, 1);
    assert.ok(r.logEntries.every(e => e.status_code > 0 && e.user_agent === UA));
});

test('format detection: mixed files are read whichever format comes first', () => {
    const std = Array.from({ length: 20 }, (_, i) => line(`GET /s${i} HTTP/1.1`));
    const vhost = std.map(l => 'www.example.com:443 ' + l);
    const json = Array.from({ length: 20 }, (_, i) => JSON.stringify({ remote_addr: '8.8.4.4', request: `GET /j${i} HTTP/1.1`, status: 200, body_bytes_sent: 5 }));
    const syslog = std.map(l => 'Oct 10 13:55:36 web1 nginx: ' + l);
    for (const [a, b] of [[std, vhost], [vhost, std], [std, json], [json, std], [syslog, std], [std, syslog]]) {
        assert.equal(LogParser.parseIPs([...a, ...b].join('\n'), ALL).logEntries.length, 40);
    }
});

test('format detection: any status from 100 to 599 is a status', () => {
    const rows = Array.from({ length: 30 }, (_, i) => `web1 app ${line(`GET /p${i} HTTP/1.1`, { status: i === 3 ? 499 : 200, bytes: 1000 })}`);
    const r = LogParser.parseIPs(rows.join('\n'), ALL);
    assert.equal(r.logEntries.length, 30);
    assert.equal(r.logEntries.filter(e => e.status_code === 499).length, 1);
    assert.equal(r.logEntries.filter(e => e.status_code === 200).length, 29);
    assert.ok(r.logEntries.every(e => e.response_size === 1000));
});

test('lines that are not requests are rejected', () => {
    const rejected = [
        '2026/11/27 10:00:00 [error] 1234#0: *1 open() "/var/www/x" failed (2: No such file), client: 203.0.113.9, server: ex.com, request: "GET /x HTTP/1.1", host: "ex.com"',
        '8.8.8.8 - - [27/Nov/2026:10:00:00 +0000] "GET /trunc',
        'root@web1:~# curl -s http://203.0.113.9/x 200 3',
        'null',
        '[1,2,3]',
    ];
    for (const l of rejected) assert.equal(LogParser.parseLine(l, ALL).valid, false, l);
    assert.doesNotThrow(() => LogParser.parseLine('{"remote_addr":"8.8.8.8","request_uri":123}', ALL));
});

test('other formats: load balancer, IIS, Caddy, Traefik, Cloudflare, Docker wrapper', () => {
    const one = text => { const r = LogParser.parseIPs(text, ALL); assert.equal(r.logEntries.length, 1, text.slice(0, 60)); return r.logEntries[0]; };
    let e = one('https 2018-07-02T22:23:00.186641Z app/my-lb/50dc 81.2.69.39:2817 10.0.0.1:80 0.000 0.001 0.000 200 200 34 366 "GET https://www.example.com:443/x?y=1 HTTP/1.1" "curl/7.46.0" ECDHE TLSv1.2 arn:aws');
    assert.deepEqual([e.ip, e.method, e.status_code, e.response_size, e.user_agent], ['81.2.69.39', 'GET', 200, 366, 'curl/7.46.0']);
    e = one('#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status sc-bytes time-taken\n' +
        '2026-10-10 13:55:36 10.0.0.1 GET /default.aspx id=1 443 - 81.2.69.9 Mozilla/5.0+(Windows+NT+10.0) - 200 0 0 5120 15');
    assert.deepEqual([e.ip, e.url, e.status_code, e.response_size, e.user_agent], ['81.2.69.9', '/default.aspx?id=1', 200, 5120, 'Mozilla/5.0 (Windows NT 10.0)']);
    e = one('{"ts":1791640536.123,"request":{"remote_ip":"81.2.69.7","proto":"HTTP/2.0","method":"GET","uri":"/caddy","headers":{"User-Agent":["curl/8"]}},"size":2326,"status":200}');
    assert.deepEqual([e.ip, e.url, e.status_code, e.response_size, e.user_agent], ['81.2.69.7', '/caddy', 200, 2326, 'curl/8']);
    e = one('{"ClientHost":"81.2.69.8","DownstreamStatus":200,"DownstreamContentSize":99,"RequestMethod":"GET","RequestPath":"/t","StartUTC":"2026-10-10T13:55:36.123Z","request_User-Agent":"x"}');
    assert.deepEqual([e.ip, e.url, e.status_code, e.response_size], ['81.2.69.8', '/t', 200, 99]);
    e = one('{"ClientIP":"81.2.69.9","ClientRequestMethod":"GET","ClientRequestURI":"/cf","EdgeResponseStatus":200,"EdgeResponseBytes":10,"EdgeStartTimestamp":1791640536000000000}');
    assert.deepEqual([e.ip, e.url, e.timestamp.toISOString().slice(0, 19)], ['81.2.69.9', '/cf', '2026-10-10T13:55:36']);
    e = one(JSON.stringify({ log: line('GET /d HTTP/1.1') + '\n', stream: 'stdout', time: '2026-11-27T10:00:00Z' }));
    assert.deepEqual([e.ip, e.url], ['8.8.8.8', '/d']);
});

test('a layout that writes the User-Agent before the referrer is read the right way round', () => {
    const rows = Array.from({ length: 30 }, (_, i) => `8.8.8.${i} - - [27/Nov/2026:10:00:00 +0000] "GET /p${i} HTTP/1.1" 200 5 "${UA}" "${i % 2 ? 'https://site.test/' : '-'}"`);
    const r = LogParser.parseIPs(rows.join('\n'), ALL);
    assert.ok(r.logEntries.every(e => e.user_agent === UA));
    assert.equal(r.logEntries.filter(e => e.referrer === 'https://site.test/').length, 15);
});

test('address filter: full address, start of an address, CIDR', () => {
    const ips = ['1.2.3.4', '11.2.3.45', '1.2.3.40', '1.2.30.1', '2001:db8:1::5'];
    const hits = term => ips.filter(LogParser.ipFilterMatcher(term));
    assert.deepEqual(hits('1.2.3.4'), ['1.2.3.4']);
    assert.deepEqual(hits('1.2.3'), ['1.2.3.4', '1.2.3.40']);
    assert.deepEqual(hits('1.2.3.0/24'), ['1.2.3.4', '1.2.3.40']);
    assert.deepEqual(hits('2001:db8::/32'), ['2001:db8:1::5']);
    assert.deepEqual(hits('9.9.9.9'), []);
});

test('HAProxy HTTP logs, with and without the syslog prefix', () => {
    const rows = [
        'Feb  6 12:14:14 localhost haproxy[14389]: 81.2.69.1:33317 [06/Feb/2026:12:14:14.655] http-in static/srv1 10/0/30/69/109 200 2750 - - ---- 1/1/1/1/0 0/0 {1wt.eu} {} "GET /index.html HTTP/1.1"',
        '81.2.69.142:51234 [06/Feb/2026:12:14:15.123] fe_https~ be_app/app2 0/0/1/12/13 404 512 - - ---- 5/5/0/0/0 0/0 {shop.test|Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0|https://shop.test/} "GET /missing?x=1 HTTP/2.0"',
        '2026-02-06T12:14:16+00:00 lb1 haproxy[991]: 2001:4860:4860::8888:40000 [06/Feb/2026:12:14:16.001] fe be/<NOSRV> -1/-1/-1/-1/0 503 212 - - SC-- 1/1/0/0/0 0/0 "POST /api HTTP/1.1"',
        '81.2.69.3:40000 [06/Feb/2026:12:14:17.001] fe be/s1 0/0/0/1/+1 200 +99 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"',
        '81.2.69.4:40001 [06/Feb/2026:12:14:18.001] fe be/s1 0/0/1/-1/2 -1 0 - - CD-- 5/5/0/0/0 0/0 "<BADREQ>"',
    ];
    const r = LogParser.parseIPs(rows.join('\n'), ALL);
    assert.equal(r.format, 'haproxy');
    assert.equal(r.logEntries.length, 5);
    const view = e => [e.ip, e.method, e.url, e.status_code, e.response_size, e.user_agent, e.referrer, e.timestamp.toISOString().slice(11, 19)];
    assert.deepEqual(view(r.logEntries[0]), ['81.2.69.1', 'GET', '/index.html', 200, 2750, null, null, '12:14:14']);
    assert.deepEqual(view(r.logEntries[1]), ['81.2.69.142', 'GET', '/missing?x=1', 404, 512, 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0', 'https://shop.test/', '12:14:15']);
    assert.deepEqual(view(r.logEntries[2]).slice(0, 5), ['2001:4860:4860::8888', 'POST', '/api', 503, 212]);
    assert.deepEqual(view(r.logEntries[3]).slice(0, 5), ['81.2.69.3', 'GET', '/', 200, 99]);
    assert.deepEqual(view(r.logEntries[4]).slice(0, 5), ['81.2.69.4', null, null, 0, 0], 'a request that was never a request has no method or status');

    // An ordinary access log is not taken for HAProxy, and the other way round.
    assert.equal(LogParser.parseIPs(many(30, i => line(`GET /p${i} HTTP/1.1`)), ALL).format, 'standard');
    assert.equal(LogParser.parseIPs([...rows, line('GET /mixed HTTP/1.1')].join('\n'), ALL).logEntries.length, 6);
});

test('behind HAProxy the captured X-Forwarded-For names the client when the connecting address is private', () => {
    const rows = many(20, i => `10.0.0.1:4${1000 + i} [06/Feb/2026:12:14:${String(10 + i).padStart(2, '0')}.001] fe be/s1 0/0/0/1/1 200 99 - - ---- 1/1/0/0/0 0/0 {81.2.69.${i + 1}|curl/8.4.0} "GET /p${i} HTTP/1.1"`);
    const r = LogParser.parseIPs(rows, { skip403: false, skipInternal: true });
    assert.equal(r.logEntries.length, 20);
    assert.equal(r.forwardedLines, 20);
    assert.equal(r.logEntries[0].ip, '81.2.69.1');
    assert.equal(r.logEntries[0].user_agent, 'curl/8.4.0');
});

test('month names in other languages', () => {
    const month = t => { const d = LogParser.parseTimestamp(t); return d ? d.getUTCMonth() + 1 : null; };
    const names = {
        1: ['Jan', 'janv', 'janv.', 'ene', 'gen'], 2: ['Feb', 'févr', 'fev'], 3: ['Mar', 'Mär', 'mrz', 'mars', 'mrt'], 4: ['Apr', 'avr', 'abr'],
        5: ['May', 'Mai', 'mag', 'mei'], 6: ['Jun', 'juin', 'giu'], 7: ['Jul', 'juil', 'lug'], 8: ['Aug', 'août', 'ago'],
        9: ['Sep', 'sept', 'set'], 10: ['Oct', 'Okt', 'ott', 'out'], 11: ['Nov'], 12: ['Dec', 'Dez', 'déc', 'dic'],
    };
    for (const [number, list] of Object.entries(names)) {
        for (const name of list) assert.equal(month(`10/${name}/2026:13:55:36 +0100`), Number(number), name);
    }
    assert.equal(month('10/Foo/2026:13:55:36 +0000'), null);
    assert.equal(month('10/Octobre/2026:13:55:36 +0000'), null);
    const e = LogParser.parseIPs('81.2.69.9 - - [10/Okt/2026:13:55:36 +0200] "GET /de HTTP/1.1" 200 5 "-" "curl/8"', ALL).logEntries[0];
    assert.equal(e.timestamp.toISOString().slice(0, 19), '2026-10-10T13:55:36');
});
