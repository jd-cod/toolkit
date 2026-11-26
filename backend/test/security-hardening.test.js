import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import bcrypt from 'bcrypt';
import r2Storage from '../src/lib/r2-storage.js';
import authPlugin from '../src/plugins/auth.js';
import adminRoutes from '../src/routes/admin.js';
import abuseRoutes from '../src/routes/abuse.js';
import dnsRoutes from '../src/routes/dns.js';
import ingestRoutes from '../src/routes/ingest.js';
import shareRoutes from '../src/routes/share.js';
import sslRoutes from '../src/routes/ssl.js';
import storageRoutes from '../src/routes/storage.js';
import whoisRoutes from '../src/routes/whois.js';
import publicRoutes from '../src/routes/public.js';
import { createClientIpResolver, createIpMatcher } from '../src/lib/client-ip.js';
import { generateIngestScript } from '../src/lib/ingest-script.js';
import { resolveCorsOrigin } from '../src/lib/cors-origin.js';

/** Makes the R2 client look configured and records the keys it is asked to presign. */
function stubR2(t) {
  const original = {
    enabled: r2Storage.enabled,
    generatePresignedDownloadUrl: r2Storage.generatePresignedDownloadUrl,
    headObject: r2Storage.headObject,
    deleteLog: r2Storage.deleteLog,
  };
  const calls = { presigned: [], deleted: [] };
  r2Storage.enabled = true;
  r2Storage.generatePresignedDownloadUrl = async (key) => { calls.presigned.push(key); return `https://r2.example/${key}`; };
  r2Storage.deleteLog = async (key) => { calls.deleted.push(key); };
  t.after(() => Object.assign(r2Storage, original));
  return calls;
}

// ─── Ingest script ───

test('ingest script never embeds an unsafe session ID or base URL', () => {
  for (const session of ['x"; rm -rf ~; #', '$(id)', '`id`', 'a b', 'a\nb', '../x', 'x'.repeat(65), { a: 1 }, ['x']]) {
    const script = generateIngestScript('http://localhost:3000', session);
    assert.ok(script.includes('TARGET_SESSION_ID=""'), String(session));
  }
  assert.ok(generateIngestScript('http://localhost:3000', 'abc-DEF_123').includes('TARGET_SESSION_ID="abc-DEF_123"'));

  for (const base of ['http://evil";id;"', 'http://a$(id)', 'javascript:alert(1)', 'http://a b', 'http://a`id`', '']) {
    assert.throws(() => generateIngestScript(base), /unsafe base URL/, base);
  }
  assert.ok(generateIngestScript('https://tools.example.com').includes('BASE_URL="https://tools.example.com"'));
  assert.ok(generateIngestScript('http://[::1]:3000').includes('BASE_URL="http://[::1]:3000"'));
});

test('GET /ingest drops an injected session and ignores a hostile Host header', async (t) => {
  const app = Fastify();
  t.after(() => app.close());
  await app.register(ingestRoutes);

  const injected = await app.inject({
    method: 'GET',
    url: `/ingest?session=${encodeURIComponent('x"; echo INJECTED $(id); #')}`,
    headers: { 'user-agent': 'curl/8.0.1' },
  });
  assert.equal(injected.statusCode, 200);
  assert.ok(injected.body.includes('TARGET_SESSION_ID=""'));
  assert.ok(!injected.body.includes('INJECTED'));

  const hostile = await app.inject({
    method: 'GET', url: '/ingest',
    headers: { 'user-agent': 'curl/8.0.1', host: 'evil.example";id;"', 'x-forwarded-proto': 'javascript' },
  });
  assert.equal(hostile.statusCode, 200);
  assert.ok(hostile.body.includes('BASE_URL="http://localhost:3000"'));

  const normal = await app.inject({
    method: 'GET', url: '/ingest',
    headers: { 'user-agent': 'curl/8.0.1', 'x-forwarded-host': 'tools.example.com', 'x-forwarded-proto': 'https' },
  });
  assert.ok(normal.body.includes('BASE_URL="https://tools.example.com"'));
});

// ─── Storage download / share creation ───

function shareApp(t, shares = new Map()) {
  const app = Fastify();
  t.after(() => app.close());
  app.decorate('mysql', {
    execute: async (sql, values = []) => {
      if (/^INSERT INTO shares/.test(sql)) {
        const [code, title, r2Key, sourceUrl, passwordHash, expiresAt] = values;
        if (shares.has(code)) throw Object.assign(new Error('Duplicate entry'), { code: 'ER_DUP_ENTRY' });
        shares.set(code, { code, title, r2_key: r2Key, source_url: sourceUrl, password_hash: passwordHash, expires_at: expiresAt });
        return [{ affectedRows: 1 }];
      }
      if (/FROM shares WHERE code = \?/.test(sql)) {
        const row = shares.get(values[0]);
        return [row ? [row] : []];
      }
      return [[]]; // other share tables are empty
    },
  });
  return { app, shares };
}

test('GET /storage/download/:code refuses protected or expired shares and odd codes', async (t) => {
  const calls = stubR2(t);
  const { app } = shareApp(t, new Map([
    ['Protect1', { code: 'Protect1', password_hash: 'x', expires_at: null }],
    ['Expired1', { code: 'Expired1', password_hash: null, expires_at: '2020-01-01 00:00:00' }],
    ['Public01', { code: 'Public01', password_hash: null, expires_at: null }],
  ]));
  await app.register(storageRoutes, { prefix: '/api' });

  assert.equal((await app.inject('/api/storage/download/Protect1')).statusCode, 401);
  assert.equal((await app.inject('/api/storage/download/Expired1')).statusCode, 410);
  assert.equal((await app.inject('/api/storage/download/..%2Fephemeral%2Fabc')).statusCode, 400);
  assert.equal((await app.inject('/api/storage/download/short')).statusCode, 400);
  assert.deepEqual(calls.presigned, []);

  // An open share and a fresh upload with no share record still download.
  const open = await app.inject('/api/storage/download/Public01');
  assert.equal(open.statusCode, 200);
  assert.equal(open.json().downloadUrl, 'https://r2.example/shares/Public01.log.gz');
  assert.equal((await app.inject('/api/storage/download/Fresh001')).statusCode, 200);
  assert.deepEqual(calls.presigned, ['shares/Public01.log.gz', 'shares/Fresh001.log.gz']);
});

test('POST /share only attaches a share to its own upload', async (t) => {
  const { app, shares } = shareApp(t);
  await app.register(shareRoutes, { prefix: '/api' });
  const create = (payload) => app.inject({ method: 'POST', url: '/api/share', payload });

  // The normal flow from share.js: both values from the upload response.
  const ok = await create({ title: 'T', r2_key: 'shares/Abcd1234.log.gz', shareCode: 'Abcd1234', password: 'secret', expiry: '24h', source_url: 'https://example.com/a.log' });
  assert.equal(ok.statusCode, 200);
  assert.equal(ok.json().code, 'Abcd1234');
  assert.equal(shares.get('Abcd1234').r2_key, 'shares/Abcd1234.log.gz');
  assert.equal(shares.get('Abcd1234').source_url, 'https://example.com/a.log');
  assert.ok(shares.get('Abcd1234').password_hash.startsWith('$2'));

  // shareCode alone still works and maps to its own object.
  const codeOnly = await create({ shareCode: 'Wxyz9876' });
  assert.equal(codeOnly.statusCode, 200);
  assert.equal(shares.get('Wxyz9876').r2_key, 'shares/Wxyz9876.log.gz');

  // A second, password-free share for the same object is refused.
  assert.equal((await create({ r2_key: 'shares/Abcd1234.log.gz' })).statusCode, 409);
  assert.equal((await create({ r2_key: 'shares/Abcd1234.log.gz', shareCode: 'Other123' })).statusCode, 400);

  // Keys outside shares/<code>.log.gz are refused.
  for (const key of ['ephemeral/abc.log.gz', 'shares/../ephemeral/abc.log.gz', 'backups/db.sql', 'shares/Abcd1234.log.gz.metadata.json']) {
    assert.equal((await create({ r2_key: key })).statusCode, 400, key);
  }
  assert.equal((await create({ shareCode: '../../etc' })).statusCode, 400);
  assert.equal((await create({ shareCode: { a: 1 } })).statusCode, 400);

  // A non-http source URL is dropped, not stored.
  await create({ shareCode: 'Jsurl001', source_url: 'javascript:alert(1)' });
  assert.equal(shares.get('Jsurl001').source_url, null);
});

test('POST /share/:code/verify accepts legacy SHA-256 and bcrypt hashes, rejects wrong passwords', async (t) => {
  stubR2(t);
  const legacy = createHash('sha256').update('legacy-pass').digest('hex');
  const modern = await bcrypt.hash('modern-pass', 4);
  const { app } = shareApp(t, new Map([
    ['Legacy01', { code: 'Legacy01', title: 'L', r2_key: 'shares/Legacy01.log.gz', password_hash: legacy, expires_at: null }],
    ['Modern01', { code: 'Modern01', title: 'M', r2_key: 'shares/Modern01.log.gz', password_hash: modern, expires_at: null }],
  ]));
  await app.register(shareRoutes, { prefix: '/api' });
  const verify = (code, password) => app.inject({ method: 'POST', url: `/api/share/${code}/verify`, payload: { password } });

  assert.equal((await verify('Legacy01', 'legacy-pass')).statusCode, 200);
  assert.equal((await verify('Legacy01', 'wrong')).statusCode, 401);
  assert.equal((await verify('Legacy01', legacy)).statusCode, 401); // the stored hash is not a password
  assert.equal((await verify('Modern01', 'modern-pass')).statusCode, 200);
  assert.equal((await verify('Modern01', 'wrong')).statusCode, 401);
  assert.equal((await verify('Modern01', '')).statusCode, 401);
  assert.equal((await verify('Modern01', { a: 1 })).statusCode, 401);

  // Metadata of a protected share does not include the download URL.
  const meta = (await app.inject('/api/share/Modern01')).json();
  assert.equal(meta.password_required, true);
  assert.equal(meta.download_url, undefined);
});

// ─── Ingest finalize ───

test('POST /ingest/:id/finalize rejects chunk IDs it did not issue and oversized uploads', async (t) => {
  const calls = stubR2(t);
  r2Storage.generatePresignedUploadUrl = async (key) => `https://r2.example/put/${key}`;
  t.after(() => { delete r2Storage.generatePresignedUploadUrl; });
  let size = 1024;
  r2Storage.headObject = async () => ({ size, metadata: {} });

  const app = Fastify();
  t.after(() => app.close());
  await app.register(ingestRoutes, { prefix: '/api' });

  const init = (await app.inject({ method: 'POST', url: '/api/ingest/init' })).json();
  assert.ok(init.sessionId);
  const finalize = (chunkId) => app.inject({
    method: 'POST', url: `/api/ingest/${init.sessionId}/finalize?chunkId=${encodeURIComponent(chunkId)}`,
    headers: { accept: 'application/json' },
  });

  assert.equal((await finalize('../../shares/Victim01')).statusCode, 400);
  assert.equal((await finalize('chunk-1/../x')).statusCode, 400);
  assert.equal((await finalize('chunk-1')).statusCode, 200);

  size = 300 * 1024 * 1024;
  const tooBig = await finalize('chunk-1');
  assert.equal(tooBig.statusCode, 413);
  assert.deepEqual(calls.deleted, [`ephemeral/${init.sessionId}/chunk-1.log.gz`]);
});

// ─── SSL checker ───

test('POST /ssl refuses internal destinations and invalid ports', async (t) => {
  const app = Fastify();
  t.after(() => app.close());
  await app.register(sslRoutes, { prefix: '/api' });
  const check = async (payload) => (await app.inject({ method: 'POST', url: '/api/ssl', payload })).json();

  for (const domain of ['127.0.0.1', '10.0.0.1', '169.254.169.254', '192.168.1.1']) {
    const res = await check({ domain });
    assert.match(res.error, /not a public address/, domain);
    assert.equal(res.subject, undefined);
  }
  assert.equal((await check({ domain: 'example.com', port: -1 })).error, 'Invalid port.');
  assert.equal((await check({ domain: 'example.com', port: 70000 })).error, 'Invalid port.');
  assert.equal((await check({ domain: 'example.com', port: 'abc' })).error, 'Invalid port.');
  assert.equal((await check({ domain: 'evil.com@127.0.0.1' })).error, 'Invalid domain.');
  assert.equal((await check({ domain: { a: 1 } })).error, 'Invalid domain.');

  // A name that resolves to loopback is stopped when the socket resolves it.
  const local = await check({ domain: 'localhost', port: 443 });
  assert.match(local.error, /not a public address/);
});

// ─── Input types ───

test('lookup routes answer wrong input types with a normal error, not a 500', async (t) => {
  const app = Fastify();
  t.after(() => app.close());
  await app.register(dnsRoutes, { prefix: '/api', globalDnsAccess: { capability: async () => ({ available: false }), credentials: async () => null } });
  await app.register(whoisRoutes, { prefix: '/api' });
  await app.register(abuseRoutes, { prefix: '/api' });

  for (const [url, payload] of [
    ['/api/dns', { domain: { a: 1 } }],
    ['/api/dns', { domain: ['example.com'], type: ['A'], resolver: 5 }],
    ['/api/dns/global', { domain: 42 }],
    ['/api/whois', { domain: ['example.com'] }],
    ['/api/abuse', { ips: 'not-an-array' }],
  ]) {
    const res = await app.inject({ method: 'POST', url, payload });
    assert.ok(res.statusCode < 500, `${url} ${JSON.stringify(payload)} -> ${res.statusCode}`);
  }
});

test('POST /abuse caps how many IPs one request may check', async (t) => {
  const previousKey = process.env.ABUSEIPDB_API_KEY;
  const originalFetch = globalThis.fetch;
  process.env.ABUSEIPDB_API_KEY = 'test-key';
  let lookups = 0;
  globalThis.fetch = async () => { lookups++; return { status: 200, json: async () => ({ data: {} }) }; };
  t.after(() => {
    globalThis.fetch = originalFetch;
    if (previousKey === undefined) delete process.env.ABUSEIPDB_API_KEY;
    else process.env.ABUSEIPDB_API_KEY = previousKey;
  });

  const app = Fastify();
  t.after(() => app.close());
  await app.register(abuseRoutes, { prefix: '/api' });
  const ips = Array.from({ length: 200 }, (_, i) => `198.51.100.${i % 250}`);

  await app.inject({ method: 'POST', url: '/api/abuse', payload: { ips, max: 100000 } });
  assert.equal(lookups, 50);

  lookups = 0;
  await app.inject({ method: 'POST', url: '/api/abuse', payload: { ips, max: 10 } });
  assert.equal(lookups, 10);

  lookups = 0;
  await app.inject({ method: 'POST', url: '/api/abuse', payload: { ips } });
  assert.equal(lookups, 20);
});

// ─── Admin sessions ───

async function adminApp(t, { withTokenVersion = true } = {}) {
  const previousSecret = process.env.ADMIN_JWT_SECRET;
  process.env.ADMIN_JWT_SECRET = 'test-secret-test-secret-test-secret';
  t.after(() => {
    if (previousSecret === undefined) delete process.env.ADMIN_JWT_SECRET;
    else process.env.ADMIN_JWT_SECRET = previousSecret;
  });

  const user = { id: 7, username: 'root', password_hash: await bcrypt.hash('correct horse battery', 4), token_version: 0 };
  if (!withTokenVersion) delete user.token_version;
  const missingColumn = () => Object.assign(new Error("Unknown column 'token_version'"), { code: 'ER_BAD_FIELD_ERROR' });

  const app = Fastify();
  t.after(() => app.close());
  app.decorate('mysql', {
    execute: async (sql, values = []) => {
      if (/token_version/.test(sql) && !withTokenVersion) throw missingColumn();
      if (/^SELECT token_version FROM admin_users/.test(sql)) return [values[0] === user.id ? [{ token_version: user.token_version }] : []];
      if (/^UPDATE admin_users SET token_version/.test(sql)) { user.token_version++; return [{}]; }
      if (/^UPDATE admin_users SET password_hash/.test(sql)) { user.password_hash = values[0]; return [{}]; }
      if (/^SELECT \* FROM admin_users WHERE username/.test(sql)) return [values[0] === user.username ? [{ ...user }] : []];
      if (/^SELECT \* FROM admin_users WHERE id/.test(sql)) return [values[0] === user.id ? [{ ...user }] : []];
      return [[]];
    },
  });
  await app.register(cookie);
  await app.register(authPlugin);
  await app.register(adminRoutes, { prefix: '/api' });

  const login = async (password = 'correct horse battery', username = 'root') => {
    const res = await app.inject({ method: 'POST', url: '/api/admin/login', payload: { username, password } });
    const set = res.cookies.find((c) => c.name === 'admin_token');
    return { res, token: set?.value };
  };
  const me = (token) => app.inject({ method: 'GET', url: '/api/admin/me', cookies: { admin_token: token } });
  return { app, user, login, me };
}

test('admin login rejects bad credentials and non-string input', async (t) => {
  const { app, login } = await adminApp(t);
  assert.equal((await login('wrong')).res.statusCode, 401);
  assert.equal((await login('correct horse battery', 'nobody')).res.statusCode, 401);
  assert.equal((await app.inject({ method: 'POST', url: '/api/admin/login', payload: { username: { a: 1 }, password: 'x' } })).statusCode, 400);
  assert.equal((await app.inject({ method: 'POST', url: '/api/admin/login', payload: { username: 'root', password: ['x'] } })).statusCode, 400);

  const ok = await login();
  assert.equal(ok.res.statusCode, 200);
  const set = ok.res.cookies.find((c) => c.name === 'admin_token');
  assert.equal(set.httpOnly, true);
  assert.equal(set.sameSite, 'Strict');
});

test('logout revokes the token itself, not just the cookie', async (t) => {
  const { app, login, me } = await adminApp(t);
  const { token } = await login();
  assert.equal((await me(token)).statusCode, 200);

  const out = await app.inject({ method: 'POST', url: '/api/admin/logout', cookies: { admin_token: token } });
  assert.equal(out.statusCode, 200);
  assert.equal((await me(token)).statusCode, 401);

  // Signing in again works.
  const again = await login();
  assert.equal((await me(again.token)).statusCode, 200);
});

test('password change ends other sessions, keeps this one, and enforces the minimum length', async (t) => {
  const { app, login, me } = await adminApp(t);
  const other = await login();
  const current = await login();
  const change = (payload, token) => app.inject({ method: 'PUT', url: '/api/admin/password', payload, cookies: { admin_token: token } });

  const short = await change({ current_password: 'correct horse battery', new_password: 'short1' }, current.token);
  assert.equal(short.statusCode, 400);
  assert.match(short.json().error, /at least 12 characters/);
  assert.equal((await change({ current_password: 'wrong', new_password: 'a much longer passphrase' }, current.token)).statusCode, 401);

  const changed = await change({ current_password: 'correct horse battery', new_password: 'a much longer passphrase' }, current.token);
  assert.equal(changed.statusCode, 200);
  const reissued = changed.cookies.find((c) => c.name === 'admin_token')?.value;
  assert.ok(reissued);

  assert.equal((await me(other.token)).statusCode, 401);
  assert.equal((await me(current.token)).statusCode, 401);
  assert.equal((await me(reissued)).statusCode, 200);
  assert.equal((await login('correct horse battery')).res.statusCode, 401);
  assert.equal((await login('a much longer passphrase')).res.statusCode, 200);
});

test('tokens of a deleted account and tokens signed with another algorithm are rejected', async (t) => {
  const { app, user, login, me } = await adminApp(t);
  const { token } = await login();

  const none = `${Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url')}.${token.split('.')[1]}.`;
  assert.equal((await me(none)).statusCode, 401);
  assert.equal(JSON.parse(Buffer.from(token.split('.')[0], 'base64url')).alg, 'HS256');

  user.id = 8; // the account the token was issued for no longer exists
  assert.equal((await me(token)).statusCode, 401);
});

test('auth keeps working on a database that has not run migration 011 yet', async (t) => {
  const { app, login, me } = await adminApp(t, { withTokenVersion: false });
  const { res, token } = await login();
  assert.equal(res.statusCode, 200);
  assert.equal((await me(token)).statusCode, 200);

  const changed = await app.inject({
    method: 'PUT', url: '/api/admin/password', cookies: { admin_token: token },
    payload: { current_password: 'correct horse battery', new_password: 'a much longer passphrase' },
  });
  assert.equal(changed.statusCode, 200);
  assert.equal((await me(token)).statusCode, 200);
  assert.equal((await app.inject({ method: 'POST', url: '/api/admin/logout', cookies: { admin_token: token } })).statusCode, 200);
});

test('admin shares only store http(s) source URLs', async (t) => {
  const { app, login } = await adminApp(t);
  const { token } = await login();
  const send = (method, url, source_url) => app.inject({
    method, url, cookies: { admin_token: token }, payload: { title: 'Report', r2_key: 'shares/abcd1234.log.gz', source_url },
  });

  for (const bad of ['javascript:alert(1)', 'data:text/html,x', 'example.com/access.log']) {
    assert.equal((await send('POST', '/api/admin/shares', bad)).statusCode, 400);
    assert.equal((await send('PUT', '/api/admin/shares/abcd1234', bad)).statusCode, 400);
  }
  // A valid URL passes validation; the stub database has no such share to update.
  assert.equal((await send('PUT', '/api/admin/shares/abcd1234', 'https://example.com/access.log')).statusCode, 404);
});

// ─── CORS ───

test('resolveCorsOrigin restricts production origins when configured', () => {
  assert.equal(resolveCorsOrigin({ NODE_ENV: 'development' }), true);
  assert.equal(resolveCorsOrigin({ NODE_ENV: 'production' }), true);
  assert.equal(resolveCorsOrigin({ NODE_ENV: 'production', CORS_ORIGIN: 'https://tools.example.com/' }), 'https://tools.example.com');
  assert.deepEqual(
    resolveCorsOrigin({ NODE_ENV: 'production', CORS_ORIGIN: 'https://a.example, https://b.example' }),
    ['https://a.example', 'https://b.example'],
  );
  assert.equal(resolveCorsOrigin({ NODE_ENV: 'production', APP_URL: 'https://tools.example.com/some/path' }), 'https://tools.example.com');
  assert.equal(resolveCorsOrigin({ NODE_ENV: 'production', APP_URL: 'https://x.example', CORS_ORIGIN: 'https://y.example' }), 'https://y.example');
  assert.equal(resolveCorsOrigin({ NODE_ENV: 'production', CORS_ORIGIN: '*' }), true);
  assert.equal(resolveCorsOrigin({ NODE_ENV: 'production', APP_URL: 'not a url' }), true);
});

// ─── Invite-only access ───

test('createIpMatcher understands IPs and CIDRs in any common separator', () => {
  const matcher = createIpMatcher('203.0.113.50\n10.0.0.0/8, 192.168.1.0/24;2001:db8::/32  not-an-ip 999.1.1.1/40');
  assert.equal(matcher.size, 4);
  for (const ip of ['203.0.113.50', '10.200.3.4', '192.168.1.77', '2001:db8::1', '::ffff:10.1.1.1']) {
    assert.equal(matcher.matches(ip), true, ip);
  }
  for (const ip of ['203.0.113.51', '11.0.0.1', '192.168.2.1', '2001:db9::1', '', 'garbage', undefined]) {
    assert.equal(matcher.matches(ip), false, String(ip));
  }
  assert.equal(createIpMatcher('').matches('1.2.3.4'), false);
  assert.equal(createIpMatcher(null).matches('1.2.3.4'), false);
});

async function accessApp(t, settings) {
  const previousSecret = process.env.ADMIN_JWT_SECRET;
  process.env.ADMIN_JWT_SECRET = 'test-secret-test-secret-test-secret';
  t.after(() => {
    if (previousSecret === undefined) delete process.env.ADMIN_JWT_SECRET;
    else process.env.ADMIN_JWT_SECRET = previousSecret;
  });

  const app = Fastify();
  t.after(() => app.close());
  app.decorate('mysql', {
    execute: async (sql, values = []) => {
      if (/FROM site_settings WHERE `key` IN/.test(sql)) return [Object.entries(settings).map(([key, value]) => ({ key, value }))];
      if (/^SELECT token_version FROM admin_users/.test(sql)) return [values[0] === 1 ? [{ token_version: 2 }] : []];
      return [[]];
    },
  });
  app.decorate('clientIp', createClientIpResolver());
  await app.register(cookie);
  await app.register(authPlugin);
  await app.register(publicRoutes, { prefix: '/api' });

  // As called by frontend/server.js: loopback peer, client address appended to X-Forwarded-For.
  const check = (clientAddress, { cookies, gate = true, forged } = {}) => app.inject({
    method: 'GET', url: `/api/site/access-check${gate ? '?gate=1' : ''}`, remoteAddress: '127.0.0.1',
    headers: { 'x-forwarded-for': forged ? `${forged}, ${clientAddress}` : clientAddress }, cookies,
  }).then((res) => res.json());
  return { app, check };
}

test('access-check allows everyone while invite-only mode is off', async (t) => {
  const { check } = await accessApp(t, { invite_only_enabled: '0', invite_only_whitelist_ips: '203.0.113.50' });
  const res = await check('198.51.100.1');
  assert.equal(res.invite_only, false);
  assert.equal(res.allowed, true);
  assert.equal(res.gate_html, undefined);
});

test('access-check enforces the whitelist and cannot be fooled by a forged X-Forwarded-For', async (t) => {
  const { check } = await accessApp(t, {
    invite_only_enabled: '1',
    invite_only_whitelist_ips: '203.0.113.50\n198.18.0.0/15',
    invite_only_title: 'Members <only>',
    invite_only_message: 'Ask the admin.',
  });

  assert.equal((await check('203.0.113.50')).allowed, true);
  assert.equal((await check('198.19.4.4')).allowed, true);

  const blocked = await check('198.51.100.1');
  assert.equal(blocked.invite_only, true);
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.client_ip, '198.51.100.1');
  assert.match(blocked.gate_html, /Members &lt;only&gt;/);
  assert.match(blocked.gate_html, /Ask the admin\./);
  assert.ok(!blocked.gate_html.includes('<only>'));

  // Claiming a whitelisted address in the header does not help.
  const forged = await check('198.51.100.1', { forged: '203.0.113.50' });
  assert.equal(forged.allowed, false);
  assert.equal(forged.client_ip, '198.51.100.1');

  // The HTML is only sent when asked for.
  assert.equal((await check('198.51.100.1', { gate: false })).gate_html, undefined);
});

test('access-check lets a signed-in admin through, but not a revoked or forged session', async (t) => {
  const { app, check } = await accessApp(t, { invite_only_enabled: '1', invite_only_whitelist_ips: '' });
  const valid = app.auth.createToken({ sub: 1, username: 'root', tv: 2 });
  const revoked = app.auth.createToken({ sub: 1, username: 'root', tv: 1 });
  const unknown = app.auth.createToken({ sub: 99, username: 'ghost', tv: 0 });

  assert.equal((await check('198.51.100.1', { cookies: { admin_token: valid } })).allowed, true);
  assert.equal((await check('198.51.100.1', { cookies: { admin_token: revoked } })).allowed, false);
  assert.equal((await check('198.51.100.1', { cookies: { admin_token: unknown } })).allowed, false);
  assert.equal((await check('198.51.100.1', { cookies: { admin_token: 'not-a-token' } })).allowed, false);
  assert.equal((await check('198.51.100.1')).allowed, false);
});
