import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createAccessGate, isGatedRequest } = require('../../frontend/access-gate.js');

function request(url, { method = 'GET', headers = {} } = {}) {
  return { method, url, headers };
}

function gateWith(responder, options = {}) {
  const calls = [];
  const gate = createAccessGate({
    apiBase: 'http://backend.test/api/',
    log: { error() {} },
    fetchImpl: async (url, init) => {
      calls.push({ url, headers: init.headers });
      return responder(calls.length);
    },
    ...options,
  });
  return { gate, calls };
}

const json = (body, ok = true, status = 200) => ({ ok, status, json: async () => body });

test('isGatedRequest gates pages and leaves API, admin, login, ingest and assets alone', () => {
  for (const url of ['/', '/nginx', '/nginx?session=abc', '/dns', '/s/Abcd1234', '/page/about', '/opengraph-image', '/nginx.rsc', '/unknown']) {
    assert.equal(isGatedRequest('GET', url), true, url);
  }
  for (const url of [
    '/api/health', '/api', '/api/site/config', '/ingest', '/ingest?session=x',
    '/admin', '/admin/settings', '/login', '/login?next=/admin',
    '/_next/static/chunks/main.js', '/_next/image?url=x',
    '/js/dashboard.js?v=6.52', '/data/verified-bots.json', '/fonts/manrope-700.ttf',
    '/favicon.ico', '/robots.txt', '/sitemap.xml', '/og-image.png', '/samples/demo.log',
  ]) {
    assert.equal(isGatedRequest('GET', url), false, url);
  }
  // Lookalikes of the exempt prefixes are still pages.
  for (const url of ['/administrator', '/apiary', '/loginx', '/admin/../nginx', '//admin']) {
    assert.equal(isGatedRequest('GET', url), true, url);
  }
  assert.equal(isGatedRequest('HEAD', '/nginx'), true);
  assert.equal(isGatedRequest('POST', '/nginx'), false);
});

test('a public site is served normally and the answer is cached briefly', async () => {
  let time = 1000;
  const { gate, calls } = gateWith(() => json({ invite_only: false, allowed: true }), { now: () => time });

  assert.equal(await gate.check(request('/')), null);
  assert.equal(await gate.check(request('/nginx')), null);
  assert.equal(calls.length, 1);

  time += 6000;
  assert.equal(await gate.check(request('/dns')), null);
  assert.equal(calls.length, 2);
});

test('invite-only mode blocks visitors who are not allowed and passes those who are', async () => {
  const { gate, calls } = gateWith((n) => (n === 1
    ? json({ invite_only: true, allowed: false, gate_html: '<html>gate</html>' })
    : json({ invite_only: true, allowed: true })));

  const blocked = await gate.check(request('/nginx', { headers: { 'x-forwarded-for': '1.2.3.4, 203.0.113.9', cookie: 'admin_token=abc' } }));
  assert.deepEqual(blocked, { status: 403, html: '<html>gate</html>' });
  assert.equal(calls[0].url, 'http://backend.test/api/site/access-check?gate=1');
  assert.deepEqual(calls[0].headers, { 'x-forwarded-for': '1.2.3.4, 203.0.113.9', cookie: 'admin_token=abc' });

  // Every request is checked while invite-only is on (no caching of "allowed").
  assert.equal(await gate.check(request('/nginx')), null);
  assert.equal(calls.length, 2);
});

test('paths that are never gated do not call the backend', async () => {
  const { gate, calls } = gateWith(() => json({ invite_only: true, allowed: false }));
  for (const url of ['/api/dns', '/admin', '/login', '/_next/static/x.js', '/js/report.js', '/ingest']) {
    assert.equal(await gate.check(request(url)), null, url);
  }
  assert.equal(await gate.check(request('/nginx', { method: 'POST' })), null);
  assert.equal(calls.length, 0);
});

test('a blocked visitor still gets a gate page when the backend sends no HTML', async () => {
  const { gate } = gateWith(() => json({ invite_only: true, allowed: false }));
  const blocked = await gate.check(request('/'));
  assert.equal(blocked.status, 403);
  assert.match(blocked.html, /Invite Only/);
});

test('backend failure keeps a public site up but keeps an invite-only site closed', async () => {
  const failing = gateWith(() => { throw new Error('ECONNREFUSED'); });
  assert.equal(await failing.gate.check(request('/')), null);

  const { gate } = gateWith((n) => {
    if (n === 1) return json({ invite_only: true, allowed: true });
    if (n === 2) return json({ statusCode: 429 }, false, 429);
    throw new Error('ECONNREFUSED');
  });
  assert.equal(await gate.check(request('/')), null);
  assert.equal((await gate.check(request('/'))).status, 503);
  assert.equal((await gate.check(request('/'))).status, 503);
});
