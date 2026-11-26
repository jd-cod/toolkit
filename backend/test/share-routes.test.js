import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import Fastify from 'fastify';
import shareRoutes from '../src/routes/share.js';
import storageRoutes from '../src/routes/storage.js';
import adminRoutes from '../src/routes/admin.js';
import r2Storage from '../src/lib/r2-storage.js';
import { cleanupExpiredSnapshotShares } from '../src/lib/cleanup-scheduler.js';

/** In-memory stand-in for the two share tables, driven by the SQL the routes send. */
function createShareStore() {
  const shares = new Map();
  const toolShares = new Map();

  async function execute(sql, values = []) {
    if (sql.startsWith('INSERT INTO shares')) {
      const [code, title, r2_key, source_url, password_hash, expires_at, created_at] = values;
      shares.set(code, { code, title, r2_key, source_url, password_hash, expires_at, created_at });
      return [{ affectedRows: 1 }];
    }
    if (sql.startsWith('INSERT INTO tool_shares')) {
      const [code, tool_key, title, subject, password_hash, expires_at, created_at, checked_at_utc, data_json] = values;
      toolShares.set(code, { code, tool_key, title, subject, password_hash, expires_at, created_at, checked_at_utc, data_json });
      return [{ affectedRows: 1 }];
    }
    if (sql.startsWith('DELETE FROM tool_shares WHERE expires_at')) {
      let affectedRows = 0;
      for (const [code, row] of toolShares) {
        if (row.expires_at && new Date(`${row.expires_at}Z`.replace(' ', 'T')) < values[0]) { toolShares.delete(code); affectedRows++; }
      }
      return [{ affectedRows }];
    }
    if (sql.startsWith('DELETE FROM tool_shares')) return [{ affectedRows: toolShares.delete(values[0]) ? 1 : 0 }];
    if (sql.startsWith('DELETE FROM shares')) return [{ affectedRows: shares.delete(values[0]) ? 1 : 0 }];
    if (sql.includes('COUNT(*) as cnt FROM shares')) return [[{ cnt: shares.size }]];
    if (sql.includes('GROUP BY tool_key')) {
      const counts = new Map();
      for (const row of toolShares.values()) counts.set(row.tool_key, (counts.get(row.tool_key) || 0) + 1);
      return [[...counts].map(([tool_key, cnt]) => ({ tool_key, cnt }))];
    }
    if (sql.includes('FROM shares WHERE code = ? OR r2_key = ?')) {
      return [[...shares.values()].filter(row => row.code === values[0] || row.r2_key === values[1])];
    }
    if (sql.includes('FROM shares WHERE code = ?')) return [shares.has(values[0]) ? [shares.get(values[0])] : []];
    if (sql.includes('FROM tool_shares WHERE code = ?')) return [toolShares.has(values[0]) ? [toolShares.get(values[0])] : []];
    if (sql.includes('FROM tool_shares WHERE tool_key = ?')) return [[...toolShares.values()].filter(row => row.tool_key === values[0])];
    if (sql.includes('FROM tool_shares')) return [[...toolShares.values()]];
    if (sql.includes('FROM shares')) return [[...shares.values()]];
    return [[]];
  }

  return { shares, toolShares, execute };
}

async function buildApp(t, store = createShareStore()) {
  const app = Fastify();
  t.after(() => app.close());
  app.decorate('mysql', { execute: store.execute });
  app.decorate('auth', { authMiddleware: async request => { request.admin = { username: 'test' }; } });
  await app.register(shareRoutes, { prefix: '/api' });
  await app.register(storageRoutes, { prefix: '/api' });
  await app.register(adminRoutes, { prefix: '/api' });
  return { app, store };
}

function snapshotPayload(overrides = {}) {
  return {
    tool: 'ssl',
    subject: 'example.com',
    title: 'example.com certificate',
    checked_at_utc: '2026-11-26T10:00:00.000Z',
    snapshot: { domain: 'example.com', grade: 'A' },
    ...overrides,
  };
}

test('snapshot share: any registered tool can be shared and read back', async t => {
  const { app, store } = await buildApp(t);

  const created = await app.inject({ method: 'POST', url: '/api/share/snapshot', payload: snapshotPayload() });
  assert.equal(created.statusCode, 200);
  const { code, url, has_password, expires_at } = created.json();
  assert.match(code, /^[A-Za-z0-9]{8}$/);
  assert.equal(url, `/s/${code}`);
  assert.equal(has_password, false);
  assert.equal(expires_at, null);
  assert.equal(store.toolShares.get(code).tool_key, 'ssl');

  const meta = (await app.inject(`/api/share/${code}`)).json();
  assert.equal(meta.share_type, 'ssl');
  assert.equal(meta.subject, 'example.com');
  assert.equal(meta.has_password, false);

  const verified = (await app.inject({ method: 'POST', url: `/api/share/${code}/verify`, payload: {} })).json();
  assert.deepEqual(verified.snapshot, { domain: 'example.com', grade: 'A' });
  assert.equal(verified.checked_at_utc, '2026-11-26T10:00:00.000Z');
});

test('snapshot share: rejects unknown tools, missing data and unknown expiry values', async t => {
  const { app, store } = await buildApp(t);
  const post = payload => app.inject({ method: 'POST', url: '/api/share/snapshot', payload });

  assert.equal((await post(snapshotPayload({ tool: 'nginx' }))).statusCode, 400);
  assert.equal((await post(snapshotPayload({ tool: '__proto__' }))).statusCode, 400);
  assert.equal((await post(snapshotPayload({ subject: '  ' }))).statusCode, 400);
  assert.equal((await post(snapshotPayload({ snapshot: 'text' }))).statusCode, 400);
  assert.equal((await post(snapshotPayload({ password: 'x'.repeat(73) }))).statusCode, 400);

  const badExpiry = await post(snapshotPayload({ expiry: '2h' }));
  assert.equal(badExpiry.statusCode, 400);
  assert.match(badExpiry.json().error, /Invalid expiry/);
  assert.equal(store.toolShares.size, 0);
});

test('snapshot share: every offered expiry is honoured, including one hour', async t => {
  const { app, store } = await buildApp(t);
  const hours = { '1h': 1, '24h': 24, '7d': 168, '30d': 720 };

  for (const [expiry, expectedHours] of Object.entries(hours)) {
    const before = Date.now();
    const res = await app.inject({ method: 'POST', url: '/api/share/snapshot', payload: snapshotPayload({ expiry }) });
    assert.equal(res.statusCode, 200, expiry);
    const stored = store.toolShares.get(res.json().code).expires_at;
    const actualHours = (new Date(`${stored.replace(' ', 'T')}Z`).getTime() - before) / 3_600_000;
    assert.ok(Math.abs(actualHours - expectedHours) < 0.01, `${expiry} stored as ${stored}`);
  }

  const never = await app.inject({ method: 'POST', url: '/api/share/snapshot', payload: snapshotPayload({ expiry: 'never' }) });
  assert.equal(store.toolShares.get(never.json().code).expires_at, null);
});

test('password-protected share: data is withheld until the right password is given', async t => {
  const { app, store } = await buildApp(t);
  const created = await app.inject({ method: 'POST', url: '/api/share/snapshot', payload: snapshotPayload({ password: 'correct horse' }) });
  const { code, has_password } = created.json();
  assert.equal(has_password, true);

  const storedHash = store.toolShares.get(code).password_hash;
  assert.ok(storedHash.startsWith('$2'), 'password is stored as a bcrypt hash');

  const meta = (await app.inject(`/api/share/${code}`)).json();
  assert.equal(meta.password_required, true);
  assert.equal(meta.subject, undefined);
  assert.equal(meta.snapshot, undefined);

  const verify = password => app.inject({ method: 'POST', url: `/api/share/${code}/verify`, payload: { password } });
  assert.equal((await verify(undefined)).statusCode, 401);
  assert.equal((await verify('wrong')).statusCode, 401);
  const ok = await verify('correct horse');
  assert.equal(ok.statusCode, 200);
  assert.deepEqual(ok.json().snapshot, { domain: 'example.com', grade: 'A' });
});

test('shares created before bcrypt still open with their SHA-256 password', async t => {
  const { app, store } = await buildApp(t);
  store.toolShares.set('Legacy01', {
    code: 'Legacy01', tool_key: 'dns', title: 'Old share', subject: 'example.com',
    password_hash: createHash('sha256').update('old-secret').digest('hex'),
    expires_at: null, created_at: new Date(), checked_at_utc: '2026-01-01T00:00:00Z', data_json: '{"domain":"example.com"}',
  });

  const verify = password => app.inject({ method: 'POST', url: '/api/share/Legacy01/verify', payload: { password } });
  assert.equal((await verify('nope')).statusCode, 401);
  assert.equal((await verify('old-secret')).statusCode, 200);
});

test('expired share answers 410 for both metadata and data', async t => {
  const { app, store } = await buildApp(t);
  store.toolShares.set('Expired1', {
    code: 'Expired1', tool_key: 'whois', title: 'Gone', subject: 'example.com', password_hash: null,
    expires_at: new Date(Date.now() - 60_000), created_at: new Date(), checked_at_utc: 'x', data_json: '{}',
  });

  assert.equal((await app.inject('/api/share/Expired1')).statusCode, 410);
  assert.equal((await app.inject({ method: 'POST', url: '/api/share/Expired1/verify', payload: {} })).statusCode, 410);
});

test('Traffic Analyzer share: object key comes from the code and cannot be re-published', async t => {
  const { app, store } = await buildApp(t);
  const post = payload => app.inject({ method: 'POST', url: '/api/share', payload });

  assert.equal((await post({ title: 'x' })).statusCode, 400);
  assert.equal((await post({ shareCode: '../etc' })).statusCode, 400);
  assert.equal((await post({ shareCode: 'Abcd1234', r2_key: 'shares/Other999.log.gz' })).statusCode, 400);
  assert.equal((await post({ shareCode: 'Abcd1234', expiry: '1 hour' })).statusCode, 400);

  const created = await post({ shareCode: 'Abcd1234', title: 'Prod logs', expiry: '1h', password: 'pw' });
  assert.equal(created.statusCode, 200);
  assert.match(created.json().expires_at, /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/);
  const row = store.shares.get('Abcd1234');
  assert.equal(row.r2_key, 'shares/Abcd1234.log.gz');
  assert.ok(row.expires_at, 'one hour expiry is stored, not dropped');
  assert.ok(row.password_hash.startsWith('$2'));

  // A second, passwordless share for the same upload would bypass the first one's password.
  assert.equal((await post({ shareCode: 'Abcd1234', title: 'Again' })).statusCode, 409);
});

test('storage download respects the password and expiry of a published share', async t => {
  const original = { enabled: r2Storage.enabled, presign: r2Storage.generatePresignedDownloadUrl };
  r2Storage.enabled = true;
  r2Storage.generatePresignedDownloadUrl = async key => `https://r2.example/${key}`;
  t.after(() => {
    r2Storage.enabled = original.enabled;
    r2Storage.generatePresignedDownloadUrl = original.presign;
  });

  const { app, store } = await buildApp(t);
  const row = (code, extra) => store.shares.set(code, { code, title: code, r2_key: `shares/${code}.log.gz`, password_hash: null, expires_at: null, ...extra });
  row('Locked01', { password_hash: '$2b$10$abcdefghijklmnopqrstuv' });
  row('Expired1', { expires_at: new Date(Date.now() - 60_000) });
  row('Public01', {});

  assert.equal((await app.inject('/api/storage/download/Locked01')).statusCode, 403);
  assert.equal((await app.inject('/api/storage/download/Expired1')).statusCode, 410);
  assert.equal((await app.inject('/api/storage/download/bad%2Fcode')).statusCode, 404);

  const open = await app.inject('/api/storage/download/Public01');
  assert.equal(open.statusCode, 200);
  assert.equal(open.json().downloadUrl, 'https://r2.example/shares/Public01.log.gz');

  // Not published yet: the uploader's own browser fetches it by code.
  assert.equal((await app.inject('/api/storage/download/Fresh001')).statusCode, 200);
});

test('admin share list covers every tool and can delete snapshot shares', async t => {
  const { app, store } = await buildApp(t);
  store.shares.set('Nginx001', { code: 'Nginx001', title: 'Logs', r2_key: 'shares/Nginx001.log.gz', password_hash: null, expires_at: null, created_at: new Date('2026-01-03') });
  for (const [code, tool_key, created] of [['Myip0001', 'myip', '2026-01-02'], ['Asn00001', 'asn', '2026-01-01'], ['Ssl00001', 'ssl', '2026-01-04']]) {
    store.toolShares.set(code, { code, tool_key, title: code, subject: 's', password_hash: tool_key === 'asn' ? '$2b$x' : null, expires_at: null, created_at: new Date(created), checked_at_utc: 'x', data_json: '{}' });
  }

  const all = (await app.inject('/api/admin/shares?type=all')).json();
  assert.deepEqual(all.items.map(item => item.code), ['Ssl00001', 'Nginx001', 'Myip0001', 'Asn00001']);
  assert.equal(all.total, 4);
  assert.equal(all.counts.nginx, 1);
  assert.equal(all.counts.myip, 1);
  assert.equal(all.counts.asn, 1);
  assert.equal(all.counts.dns, 0);
  assert.equal(all.items.find(item => item.code === 'Asn00001').has_password, true);
  assert.equal(all.items.find(item => item.code === 'Asn00001').password_hash, undefined);

  const onlyMyip = (await app.inject('/api/admin/shares?type=myip')).json();
  assert.deepEqual(onlyMyip.items.map(item => item.code), ['Myip0001']);

  assert.equal((await app.inject('/api/admin/shares/Asn00001')).json().share_type, 'asn');
  assert.equal((await app.inject({ method: 'DELETE', url: '/api/admin/shares/Asn00001' })).statusCode, 200);
  assert.equal(store.toolShares.has('Asn00001'), false);
  assert.equal((await app.inject({ method: 'DELETE', url: '/api/admin/shares/Asn00001' })).statusCode, 404);
});

test('cleanup removes expired snapshot shares and keeps the rest', async t => {
  const store = createShareStore();
  const base = { tool_key: 'dns', title: 't', subject: 's', password_hash: null, created_at: new Date(), checked_at_utc: 'x', data_json: '{}' };
  store.toolShares.set('Old00001', { ...base, code: 'Old00001', expires_at: '2020-01-01 00:00:00' });
  store.toolShares.set('New00001', { ...base, code: 'New00001', expires_at: '2999-01-01 00:00:00' });
  store.toolShares.set('Never001', { ...base, code: 'Never001', expires_at: null });

  assert.equal(await cleanupExpiredSnapshotShares({ execute: store.execute }), 1);
  assert.deepEqual([...store.toolShares.keys()], ['New00001', 'Never001']);
});
