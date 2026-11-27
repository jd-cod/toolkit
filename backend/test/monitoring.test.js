import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import { normalizeChannelInput, normalizeMonitorInput } from '../src/lib/monitoring/types.js';
import { applyCheckResult, evaluateHeartbeat } from '../src/lib/monitoring/state.js';
import { checkBlacklist, checkDnsRecord, checkDomainExpiry, checkHttp, checkSslExpiry, checkTcp, createCheckRunner } from '../src/lib/monitoring/checks.js';
import { buildAlert, createNotifier, deliver } from '../src/lib/monitoring/alerts.js';
import { createMonitorScheduler } from '../src/lib/monitoring/scheduler.js';

const DAY = 86400000;

test('monitor input is validated per type and given defaults', () => {
  assert.deepEqual(normalizeMonitorInput({ type: 'ssl_expiry', name: ' Site cert ', target: 'Example.com' }), {
    type: 'ssl_expiry', name: 'Site cert', target: 'example.com', interval_minutes: 720, config: { warn_days: 14 }, is_enabled: 1,
  });
  assert.equal(normalizeMonitorInput({ type: 'ssl_expiry', name: 'x', target: 'mail.example.com:465' }).target, 'mail.example.com:465');
  assert.equal(normalizeMonitorInput({ type: 'tcp', name: 'x', target: '[2001:db8::1]:5432' }).target, '[2001:db8::1]:5432');
  assert.equal(normalizeMonitorInput({ type: 'tcp', name: 'x', target: 'db-internal:5432' }).target, 'db-internal:5432');
  assert.equal(normalizeMonitorInput({ type: 'http', name: 'x', target: 'https://example.com/health', config: { keyword: 'ok' } }).config.keyword, 'ok');
  assert.deepEqual(normalizeMonitorInput({ type: 'dns_record', name: 'x', target: 'example.com', config: { record_type: 'mx', expected: '10 a.example.com, 20 b.example.com' } }).config,
    { record_type: 'MX', expected: ['10 a.example.com', '20 b.example.com'], baseline: null });
  assert.equal(normalizeMonitorInput({ type: 'heartbeat', name: 'backup', interval_minutes: 1440 }).config.grace_minutes, 5);
});

test('bad monitor input is refused with a message for the form', () => {
  const bad = [
    {}, { type: 'nope', name: 'x' }, { type: 'http', name: '', target: 'https://a.example' },
    { type: 'http', name: 'x', target: 'not a url' }, { type: 'http', name: 'x', target: 'file:///etc/passwd' },
    { type: 'http', name: 'x', target: 'https://user:pw@a.example' }, { type: 'tcp', name: 'x', target: 'host-without-port' },
    { type: 'tcp', name: 'x', target: 'example.com:99999' }, { type: 'domain_expiry', name: 'x', target: 'localhost' },
    { type: 'dns_record', name: 'x', target: 'example.com', config: { record_type: 'SRV' } },
    { type: 'http', name: 'x', target: 'https://a.example', interval_minutes: 0 },
    { type: 'ssl_expiry', name: 'x', target: 'example.com', interval_minutes: 5 },
    { type: 'ssl_expiry', name: 'x', target: 'example.com', config: { warn_days: 'soon' } },
    { type: 'blacklist', name: 'x', target: 'exa mple.com; rm -rf /' },
  ];
  for (const input of bad) assert.throws(() => normalizeMonitorInput(input), { statusCode: 400 }, JSON.stringify(input));
});

test('alert channel input', () => {
  assert.equal(normalizeChannelInput({ type: 'webhook', name: 'Ops', target: 'https://hooks.example.com/x' }).target, 'https://hooks.example.com/x');
  assert.equal(normalizeChannelInput({ type: 'email', name: 'Ops', target: 'ops@example.com' }).type, 'email');
  for (const input of [{ type: 'sms', name: 'x', target: '1' }, { type: 'webhook', name: 'x', target: 'ftp://x' }, { type: 'webhook', name: '', target: 'https://x.example' }, { type: 'email', name: 'x', target: 'a@b.c, d@e.f' }, { type: 'email', name: 'x', target: 'nope' }]) {
    assert.throws(() => normalizeChannelInput(input), { statusCode: 400 }, JSON.stringify(input));
  }
});

test('a single failure is rechecked before a network monitor goes down', () => {
  const monitor = { type: 'http', status: 'ok', status_message: 'HTTP 200', consecutive_failures: 0, interval_minutes: 5 };
  const first = applyCheckResult(monitor, { status: 'down', message: 'timeout' });
  assert.deepEqual(first, { status: 'ok', message: 'HTTP 200', consecutiveFailures: 1, changed: false, notify: false, nextCheckMinutes: 1 });

  const second = applyCheckResult({ ...monitor, consecutive_failures: 1 }, { status: 'down', message: 'timeout' });
  assert.deepEqual(second, { status: 'down', message: 'timeout', consecutiveFailures: 2, changed: true, notify: true, nextCheckMinutes: 5 });

  const still = applyCheckResult({ ...monitor, status: 'down', consecutive_failures: 2 }, { status: 'down', message: 'timeout' });
  assert.equal(still.changed, false);
  assert.equal(still.notify, false);
  assert.equal(still.consecutiveFailures, 3);
});

test('recovery, warnings and first results', () => {
  const down = { type: 'http', status: 'down', consecutive_failures: 4, interval_minutes: 5 };
  assert.deepEqual(applyCheckResult(down, { status: 'ok', message: 'HTTP 200' }), { status: 'ok', message: 'HTTP 200', consecutiveFailures: 0, changed: true, notify: true, nextCheckMinutes: 5 });

  const fresh = { type: 'ssl_expiry', status: 'pending', consecutive_failures: 0, interval_minutes: 720 };
  const firstOk = applyCheckResult(fresh, { status: 'ok', message: 'valid' });
  assert.equal(firstOk.changed, true);
  assert.equal(firstOk.notify, false, 'a new monitor that is fine should not alert');
  assert.equal(applyCheckResult(fresh, { status: 'warn', message: 'expires in 3 days' }).notify, true);

  // Blacklist and domain monitors take a listing at its word: no recheck.
  const listed = applyCheckResult({ type: 'blacklist', status: 'ok', consecutive_failures: 0, interval_minutes: 360 }, { status: 'down', message: 'listed' });
  assert.equal(listed.status, 'down');
  assert.equal(listed.notify, true);

  const warnToOk = applyCheckResult({ type: 'ssl_expiry', status: 'warn', consecutive_failures: 0, interval_minutes: 720 }, { status: 'ok', message: 'renewed' });
  assert.equal(warnToOk.notify, true);
});

test('heartbeat: pending until the first ping, down when overdue, ok when a ping returns', () => {
  const now = Date.UTC(2026, 10, 27, 12, 0, 0);
  const base = { type: 'heartbeat', interval_minutes: 60, config: { grace_minutes: 5 } };
  assert.equal(evaluateHeartbeat({ ...base, status: 'pending', last_ping_at: null }, now), null);
  assert.deepEqual(evaluateHeartbeat({ ...base, status: 'pending', last_ping_at: new Date(now - 60000) }, now), { status: 'ok', message: 'Ping received on time.' });
  assert.equal(evaluateHeartbeat({ ...base, status: 'ok', last_ping_at: new Date(now - 64 * 60000) }, now), null);
  const late = evaluateHeartbeat({ ...base, status: 'ok', last_ping_at: new Date(now - 66 * 60000) }, now);
  assert.equal(late.status, 'down');
  assert.match(late.message, /No ping for 66 minutes\. Expected every 60 minutes, plus 5 minutes grace\./);
  assert.equal(evaluateHeartbeat({ ...base, status: 'down', last_ping_at: new Date(now - 300 * 60000) }, now), null);
  assert.equal(evaluateHeartbeat({ ...base, status: 'down', last_ping_at: new Date(now - 1000) }, now).status, 'ok');
  assert.match(evaluateHeartbeat({ type: 'heartbeat', interval_minutes: 1, config: { grace_minutes: 0 }, status: 'ok', last_ping_at: new Date(now - 61000) }, now).message, /No ping for 1 minute\. Expected every 1 minute\.$/);
});

test('SSL expiry check', async () => {
  const now = () => Date.UTC(2026, 10, 27);
  const cert = days => ({ has_certificate: true, valid_to: new Date(now() + days * DAY).toUTCString(), trusted: true, trust_error: '', hostname_error: '', subject: 'example.com', issuer: 'CA', protocol: 'TLSv1.3' });
  const run = (info, config = { warn_days: 14 }) => checkSslExpiry({ target: 'example.com', config }, { now, tlsProbe: async () => info });

  assert.equal((await run(cert(90))).status, 'ok');
  assert.equal((await run(cert(10))).status, 'warn');
  assert.match((await run(cert(1))).message, /expires in 1 day\./);
  assert.equal((await run(cert(-2))).status, 'down');
  assert.equal((await run({ ...cert(90), hostname_error: 'mismatch' })).status, 'down');
  assert.equal((await run({ ...cert(90), trusted: false, trust_error: 'SELF_SIGNED' })).status, 'warn');
  assert.equal((await run({ has_certificate: false })).status, 'down');

  let probed;
  const failed = await checkSslExpiry({ target: 'mail.example.com:465', config: {} }, { now, tlsProbe: async (host, port) => { probed = [host, port]; throw new Error('ECONNREFUSED'); } });
  assert.deepEqual(probed, ['mail.example.com', 465]);
  assert.equal(failed.status, 'down');
});

test('domain expiry check', async () => {
  const run = snapshot => checkDomainExpiry({ target: 'example.com', config: { warn_days: 30 } }, { whois: async () => snapshot });
  assert.equal((await run({ registered: true, days_until_expiry: 200 })).status, 'ok');
  assert.equal((await run({ registered: true, days_until_expiry: 12 })).status, 'warn');
  assert.equal((await run({ registered: true, days_until_expiry: -1 })).status, 'down');
  assert.equal((await run({ registered: false, days_until_expiry: null })).status, 'down');
  assert.equal((await run({ registered: true, days_until_expiry: null })).status, 'warn');
  assert.equal((await checkDomainExpiry({ target: 'example.com' }, { whois: async () => { throw new Error('rate limited'); } })).status, 'warn');
});

test('blacklist check', async () => {
  const summary = (total, unavailable) => ({ total, unavailable, listed: 0, policy: 0, clean: total - unavailable });
  const dnsbl = results => ({ checkIp: async ip => ({ target: ip, results, summary: summary(3, results.filter(r => r.status === 'unavailable').length) }) });
  const dns = { a: async () => ({ status: 'ok', records: ['192.0.2.9'] }) };
  const clean = [{ name: 'A', status: 'clean' }, { name: 'B', status: 'clean' }, { name: 'C', status: 'unavailable' }];

  assert.equal((await checkBlacklist({ target: '192.0.2.9' }, { dns, dnsbl: dnsbl(clean) })).status, 'ok');
  const listed = await checkBlacklist({ target: 'mail.example.com' }, { dns, dnsbl: dnsbl([{ name: 'Spamhaus ZEN', status: 'listed' }, { name: 'B', status: 'policy' }, { name: 'C', status: 'clean' }]) });
  assert.equal(listed.status, 'down');
  assert.match(listed.message, /Listed on 1 blacklist: Spamhaus ZEN \(192\.0\.2\.9\)\./);
  const blind = await checkBlacklist({ target: '192.0.2.9' }, { dns, dnsbl: dnsbl(clean.map(r => ({ ...r, status: 'unavailable' }))) });
  assert.equal(blind.status, 'warn');
  assert.equal((await checkBlacklist({ target: 'gone.example.com' }, { dns: { a: async () => ({ status: 'nxdomain', records: [] }) }, dnsbl: dnsbl(clean) })).status, 'down');
});

test('DNS record check: baseline, expected value, change and order', async () => {
  const dns = records => ({ a: async () => ({ status: 'ok', records }), mx: async () => ({ status: 'ok', records }), txt: async () => ({ status: 'ok', records }) });
  const first = await checkDnsRecord({ target: 'example.com', config: { record_type: 'A' } }, { dns: dns(['192.0.2.2', '192.0.2.1']) });
  assert.equal(first.status, 'ok');
  assert.deepEqual(first.details.baseline, ['192.0.2.1', '192.0.2.2']);

  const same = await checkDnsRecord({ target: 'example.com', config: { record_type: 'A', baseline: ['192.0.2.1', '192.0.2.2'] } }, { dns: dns(['192.0.2.1', '192.0.2.2']) });
  assert.equal(same.status, 'ok');
  assert.equal(same.details.baseline, undefined);

  const changed = await checkDnsRecord({ target: 'example.com', config: { record_type: 'A', baseline: ['192.0.2.1'] } }, { dns: dns(['203.0.113.5']) });
  assert.equal(changed.status, 'down');
  assert.match(changed.message, /Expected 192\.0\.2\.1, found 203\.0\.113\.5/);

  const expected = await checkDnsRecord({ target: 'example.com', config: { record_type: 'A', expected: ['192.0.2.1'], baseline: ['203.0.113.5'] } }, { dns: dns(['203.0.113.5']) });
  assert.equal(expected.status, 'down', 'an explicit expected value wins over the baseline');

  const mx = await checkDnsRecord({ target: 'example.com', config: { record_type: 'MX', expected: ['10 MX1.example.com.'] } }, { dns: dns([{ priority: 10, exchange: 'mx1.example.com' }]) });
  assert.equal(mx.status, 'ok');

  const gone = await checkDnsRecord({ target: 'example.com', config: { record_type: 'A', baseline: ['192.0.2.1'] } }, { dns: dns([]) });
  assert.match(gone.message, /found no record/);
  assert.equal((await checkDnsRecord({ target: 'example.com', config: { record_type: 'A' } }, { dns: { a: async () => ({ status: 'error', records: [], error: 'ETIMEOUT' }) } })).status, 'down');
});

test('HTTP and TCP checks against a local server', async () => {
  const server = http.createServer((req, res) => {
    if (req.url === '/slow') return void setTimeout(() => res.end('late'), 1500);
    res.statusCode = req.url === '/missing' ? 404 : 200;
    res.end(req.url === '/health' ? 'status: healthy' : 'hello');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;

  assert.equal((await checkHttp({ target: `${base}/health`, config: {} })).status, 'ok');
  assert.equal((await checkHttp({ target: `${base}/health`, config: { keyword: 'healthy' } })).status, 'ok');
  assert.match((await checkHttp({ target: `${base}/health`, config: { keyword: 'degraded' } })).message, /does not contain "degraded"/);
  assert.equal((await checkHttp({ target: `${base}/missing`, config: {} })).status, 'down');
  assert.equal((await checkHttp({ target: `${base}/missing`, config: { expected_status: 404 } })).status, 'ok');
  assert.match((await checkHttp({ target: `${base}/slow`, config: { timeout_seconds: 1 } })).message, /no response within 1 second\./);
  assert.equal((await checkTcp({ target: `127.0.0.1:${port}`, config: {} })).status, 'ok');

  await new Promise(resolve => { server.closeAllConnections(); server.close(resolve); });
  assert.equal((await checkHttp({ target: `${base}/health`, config: {} })).status, 'down');
  assert.match((await checkTcp({ target: `127.0.0.1:${port}`, config: {} })).message, /refused the connection/);
});

test('the check runner never throws', async () => {
  const run = createCheckRunner({ dns: {}, dnsbl: {}, tlsProbe: async () => { throw new Error('boom'); } });
  assert.equal((await run({ type: 'ssl_expiry', target: 'example.com', config: {} })).status, 'down');
  assert.equal((await run({ type: 'mystery', target: 'x' })).status, 'warn');
  assert.equal((await run({ type: 'tcp', target: 'no-port', config: {} })).status, 'down');
});

test('alerts: payloads per channel type, and one failing channel does not stop the rest', async () => {
  const monitor = { id: 7, name: 'Shop', type: 'http', target: 'https://shop.example.com' };
  const alert = buildAlert(monitor, { status: 'down', previousStatus: 'ok', message: 'HTTP 503', at: new Date('2026-11-27T10:00:00Z') });
  assert.equal(alert.text, '[DOWN] Shop (https://shop.example.com): HTTP 503');
  assert.equal(alert.title, 'Shop is down');
  assert.equal(alert.payload.previous_status, 'ok');

  const posts = [];
  const fetchImpl = async (url, init) => { posts.push([url, JSON.parse(init.body)]); return new Response('ok', { status: url.includes('broken') ? 500 : 200 }); };
  await deliver({ type: 'webhook', target: 'https://a.example/hook' }, alert, { fetchImpl });
  await deliver({ type: 'slack', target: 'https://a.example/slack' }, alert, { fetchImpl });
  assert.equal(posts[0][1].event, 'monitor.status_changed');
  assert.deepEqual(posts[1][1], { text: alert.text });
  await assert.rejects(deliver({ type: 'webhook', target: 'https://a.example/broken' }, alert, { fetchImpl }), /HTTP 500/);

  const mails = [];
  await deliver({ type: 'email', target: 'ops@example.com' }, alert, { sendMail: async mail => mails.push(mail) });
  assert.equal(mails[0].to, 'ops@example.com');
  assert.equal(mails[0].subject, '[Monitor] Shop is down');
  await assert.rejects(deliver({ type: 'email', target: 'ops@example.com' }, alert), /not configured/);

  const updates = [];
  const pool = { execute: async (sql, params) => (sql.startsWith('SELECT') ? [[{ id: 1, name: 'bad', type: 'webhook', target: 'x' }, { id: 2, name: 'good', type: 'slack', target: 'y' }]] : (updates.push(params), [{}])) };
  const delivered = [];
  const notify = createNotifier({ pool, log: {}, deliverImpl: async channel => { if (channel.id === 1) throw new Error('unreachable'); delivered.push(channel.id); } });
  assert.equal(await notify(monitor, { status: 'down', previousStatus: 'ok', message: 'HTTP 503' }), 2);
  assert.deepEqual(delivered, [2]);
  assert.deepEqual(updates.sort((a, b) => a[2] - b[2]), [['error', 'unreachable', 1], ['ok', '', 2]]);
});

/** In-memory stand-in for the three statements the scheduler runs against `monitors`. */
function fakePool(rows) {
  const events = [];
  return {
    rows, events,
    async execute(sql, params = []) {
      if (sql.startsWith('SELECT * FROM monitors WHERE is_enabled = 1 AND type <>')) return [rows.filter(r => r.is_enabled && r.type !== 'heartbeat' && (r.next_check_at === null || r.next_check_at <= Date.now()))];
      if (sql.startsWith("SELECT * FROM monitors WHERE is_enabled = 1 AND type = 'heartbeat'")) return [rows.filter(r => r.is_enabled && r.type === 'heartbeat' && r.last_ping_at)];
      if (sql.startsWith('UPDATE monitors SET next_check_at = DATE_ADD')) {
        const row = rows.find(r => r.id === params[0]);
        if (!row || (row.next_check_at !== null && row.next_check_at > Date.now())) return [{ affectedRows: 0 }];
        row.next_check_at = Date.now() + row.interval_minutes * 60000;
        return [{ affectedRows: 1 }];
      }
      if (sql.startsWith('UPDATE monitors SET status = ?, status_message = ?, consecutive_failures')) {
        const [status, message, failures, nextMinutes, , configJson, , id] = params;
        Object.assign(rows.find(r => r.id === id), { status, status_message: message, consecutive_failures: failures, next_check_at: Date.now() + nextMinutes * 60000, config_json: configJson });
        return [{}];
      }
      if (sql.startsWith('UPDATE monitors SET status = ?, status_message = ?, status_since')) {
        Object.assign(rows.find(r => r.id === params[2]), { status: params[0], status_message: params[1] });
        return [{}];
      }
      if (sql.startsWith('INSERT INTO monitor_events')) { events.push(params); return [{}]; }
      throw new Error(`unexpected SQL: ${sql.slice(0, 60)}`);
    },
  };
}

test('scheduler: runs due monitors once, records changes, alerts, and adopts a DNS baseline', async () => {
  const pool = fakePool([
    { id: 1, type: 'http', name: 'Web', target: 'https://a.example', status: 'ok', consecutive_failures: 1, interval_minutes: 5, is_enabled: 1, next_check_at: null, config_json: '{}' },
    { id: 2, type: 'dns_record', name: 'DNS', target: 'a.example', status: 'pending', consecutive_failures: 0, interval_minutes: 30, is_enabled: 1, next_check_at: null, config_json: '{"record_type":"A","expected":[],"baseline":null}' },
    { id: 3, type: 'http', name: 'Not due', target: 'https://b.example', status: 'ok', consecutive_failures: 0, interval_minutes: 5, is_enabled: 1, next_check_at: Date.now() + 60000, config_json: '{}' },
    { id: 4, type: 'http', name: 'Paused', target: 'https://c.example', status: 'ok', consecutive_failures: 0, interval_minutes: 5, is_enabled: 0, next_check_at: null, config_json: '{}' },
    { id: 5, type: 'heartbeat', name: 'Backup', target: '', status: 'ok', consecutive_failures: 0, interval_minutes: 1, is_enabled: 1, next_check_at: null, last_ping_at: new Date(Date.now() - 10 * 60000), config_json: '{"grace_minutes":0}' },
  ]);
  const ran = [];
  const alerts = [];
  const scheduler = createMonitorScheduler({
    pool, log: {},
    runCheck: async monitor => { ran.push(monitor.id); return monitor.type === 'http' ? { status: 'down', message: 'HTTP 503', details: {} } : { status: 'ok', message: 'A record is 192.0.2.1.', details: { current: ['192.0.2.1'], baseline: ['192.0.2.1'] } }; },
    notify: async (monitor, change) => { alerts.push([monitor.id, change.status]); },
  });

  await scheduler.tick();
  assert.deepEqual(ran.sort(), [1, 2]);
  assert.equal(pool.rows[0].status, 'down');
  assert.equal(pool.rows[1].status, 'ok');
  assert.deepEqual(JSON.parse(pool.rows[1].config_json).baseline, ['192.0.2.1']);
  assert.equal(pool.rows[4].status, 'down');
  assert.deepEqual(alerts.sort(), [[1, 'down'], [5, 'down']]);
  assert.deepEqual(pool.events.map(e => [e[0], e[1], e[2]]).sort(), [[1, 'down', 'ok'], [2, 'ok', 'pending'], [5, 'down', 'ok']]);

  // Nothing is due any more, so a second tick does no work and sends no alert.
  await scheduler.tick();
  assert.equal(ran.length, 2);
  assert.equal(alerts.length, 2);
});

test('scheduler: a monitor another process already claimed is skipped', async () => {
  const pool = fakePool([{ id: 1, type: 'http', name: 'Web', target: 'https://a.example', status: 'ok', consecutive_failures: 0, interval_minutes: 5, is_enabled: 1, next_check_at: null, config_json: '{}' }]);
  const original = pool.execute.bind(pool);
  pool.execute = async (sql, params) => (sql.startsWith('UPDATE monitors SET next_check_at = DATE_ADD') ? [{ affectedRows: 0 }] : original(sql, params));
  let ran = 0;
  await createMonitorScheduler({ pool, log: {}, runCheck: async () => { ran += 1; return { status: 'ok', message: '', details: {} }; }, notify: async () => {} }).tick();
  assert.equal(ran, 0);
});

test('a TCP probe against a closed port is reported as down, not thrown', async () => {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise(resolve => server.close(resolve));
  assert.equal((await checkTcp({ target: `127.0.0.1:${port}`, config: { timeout_seconds: 1 } })).status, 'down');
});
