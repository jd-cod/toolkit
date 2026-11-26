import test from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { createClientIpResolver, bruteForceLimit } from '../src/lib/client-ip.js';

const CLOUDFLARE_EDGE = '172.64.1.1';

function req(peer, headers = {}) {
  return { socket: { remoteAddress: peer }, ip: peer, headers };
}

test('a direct client cannot change its identity with X-Forwarded-For', () => {
  const { resolve } = createClientIpResolver();
  assert.equal(resolve(req('203.0.113.9')), '203.0.113.9');
  assert.equal(resolve(req('203.0.113.9', { 'x-forwarded-for': '1.2.3.4' })), '203.0.113.9');
  assert.equal(resolve(req('203.0.113.9', { 'x-forwarded-for': '1.2.3.4', 'x-real-ip': '5.6.7.8' })), '203.0.113.9');
});

test('behind the Next.js server the client is the address Next.js appended', () => {
  const { resolve } = createClientIpResolver();
  assert.equal(resolve(req('127.0.0.1', { 'x-forwarded-for': '203.0.113.9' })), '203.0.113.9');
  // The client sent its own header first; only the entry added by our server counts.
  assert.equal(resolve(req('127.0.0.1', { 'x-forwarded-for': '1.2.3.4, 203.0.113.9' })), '203.0.113.9');
  assert.equal(resolve(req('::ffff:127.0.0.1', { 'x-forwarded-for': '1.2.3.4,203.0.113.9' })), '203.0.113.9');
});

test('trusted proxies in the chain are skipped: reverse proxy on the host and Cloudflare', () => {
  const { resolve } = createClientIpResolver();
  // client -> nginx (docker gateway) -> Next.js -> backend
  assert.equal(resolve(req('127.0.0.1', { 'x-forwarded-for': '198.51.100.20, 172.17.0.1' })), '198.51.100.20');
  // client -> Cloudflare -> Next.js -> backend, with a forged first entry
  assert.equal(resolve(req('127.0.0.1', { 'x-forwarded-for': `9.9.9.9, 198.51.100.20, ${CLOUDFLARE_EDGE}` })), '198.51.100.20');
  // client -> Cloudflare -> nginx -> Next.js -> backend
  assert.equal(resolve(req('127.0.0.1', { 'x-forwarded-for': `198.51.100.20, ${CLOUDFLARE_EDGE}, 127.0.0.1` })), '198.51.100.20');
});

test('TRUSTED_PROXIES replaces the Cloudflare default', () => {
  const none = createClientIpResolver({ trustedProxies: 'none' });
  assert.equal(none.resolve(req('127.0.0.1', { 'x-forwarded-for': `198.51.100.20, ${CLOUDFLARE_EDGE}` })), CLOUDFLARE_EDGE);

  const custom = createClientIpResolver({ trustedProxies: '192.0.2.0/24, 2001:db8::5' });
  assert.equal(custom.resolve(req('127.0.0.1', { 'x-forwarded-for': '198.51.100.20, 192.0.2.77' })), '198.51.100.20');
  assert.equal(custom.resolve(req('127.0.0.1', { 'x-forwarded-for': '198.51.100.20, 2001:db8::5' })), '198.51.100.20');
  assert.equal(custom.resolve(req('127.0.0.1', { 'x-forwarded-for': `198.51.100.20, ${CLOUDFLARE_EDGE}` })), CLOUDFLARE_EDGE);

  const warnings = [];
  createClientIpResolver({ trustedProxies: 'cloudflare, not-an-ip', log: { warn: (m) => warnings.push(m) } });
  assert.equal(warnings.length, 1);
});

test('a malformed entry stops the walk, so nothing to its left is believed', () => {
  const { resolve } = createClientIpResolver();
  assert.equal(resolve(req('127.0.0.1', { 'x-forwarded-for': '1.2.3.4, garbage, 10.0.0.5' })), '10.0.0.5');
});

test('when every hop is trusted the leftmost address or X-Real-IP is used', () => {
  const { resolve } = createClientIpResolver();
  assert.equal(resolve(req('127.0.0.1', { 'x-forwarded-for': '192.168.1.50, 127.0.0.1' })), '192.168.1.50');
  assert.equal(resolve(req('127.0.0.1', { 'x-real-ip': '198.51.100.20' })), '198.51.100.20');
  assert.equal(resolve(req('127.0.0.1')), '127.0.0.1');
});

test('isInternal is true only for loopback requests without forwarding headers', () => {
  const { isInternal } = createClientIpResolver();
  assert.equal(isInternal(req('127.0.0.1')), true);
  assert.equal(isInternal(req('::1')), true);
  assert.equal(isInternal(req('127.0.0.1', { 'x-forwarded-for': '203.0.113.9' })), false);
  assert.equal(isInternal(req('127.0.0.1', { 'x-real-ip': '203.0.113.9' })), false);
  assert.equal(isInternal(req('203.0.113.9')), false);
  assert.equal(isInternal(req('10.0.0.5')), false);
});

async function buildLimitedApp(t) {
  const app = Fastify();
  t.after(() => app.close());
  const clientIp = createClientIpResolver();
  await app.register(rateLimit, {
    max: 3,
    timeWindow: '1 minute',
    allowList: (request) => clientIp.isLocal(request),
    keyGenerator: (request) => clientIp.resolve(request),
  });
  app.get('/ping', async () => ({ ok: true }));
  app.post('/secret', { config: { rateLimit: bruteForceLimit(2, '1 minute') } }, async () => ({ ok: true }));
  return app;
}

test('rate limit cannot be bypassed by rotating X-Forwarded-For', async (t) => {
  const app = await buildLimitedApp(t);
  const statuses = [];
  for (let i = 0; i < 6; i++) {
    const res = await app.inject({
      method: 'GET', url: '/ping', remoteAddress: '203.0.113.9',
      headers: { 'x-forwarded-for': `198.51.100.${i}` },
    });
    statuses.push(res.statusCode);
  }
  assert.deepEqual(statuses, [200, 200, 200, 429, 429, 429]);
});

test('rate limit applies to requests proxied by Next.js and keeps clients separate', async (t) => {
  const app = await buildLimitedApp(t);
  const hit = (forwarded) => app.inject({
    method: 'GET', url: '/ping', remoteAddress: '127.0.0.1', headers: { 'x-forwarded-for': forwarded },
  });

  const first = [];
  for (let i = 0; i < 5; i++) first.push((await hit(`${i}.${i}.${i}.${i}, 203.0.113.9`)).statusCode);
  assert.deepEqual(first, [200, 200, 200, 429, 429]);

  // A different client is not affected by the first one's limit.
  assert.equal((await hit('203.0.113.10')).statusCode, 200);
});

test('internal loopback requests without forwarding headers are not rate limited', async (t) => {
  const app = await buildLimitedApp(t);
  for (let i = 0; i < 10; i++) {
    const res = await app.inject({ method: 'GET', url: '/ping', remoteAddress: '127.0.0.1' });
    assert.equal(res.statusCode, 200);
  }
});

test('isLocal is true when no public client address can be identified', () => {
  const { isLocal } = createClientIpResolver();
  assert.equal(isLocal(req('127.0.0.1')), true);
  assert.equal(isLocal(req('127.0.0.1', { 'x-forwarded-for': '127.0.0.1' })), true);
  assert.equal(isLocal(req('127.0.0.1', { 'x-forwarded-for': '172.17.0.1' })), true);
  assert.equal(isLocal(req('192.168.1.50')), true);
  assert.equal(isLocal(req('203.0.113.9')), false);
  assert.equal(isLocal(req('127.0.0.1', { 'x-forwarded-for': '203.0.113.9' })), false);
  assert.equal(isLocal(req('127.0.0.1', { 'x-forwarded-for': '127.0.0.1, 203.0.113.9' })), false);
  assert.equal(isLocal(req('127.0.0.1', { 'x-real-ip': '203.0.113.9' })), false);
  // A Cloudflare edge address is a proxy, not a client, but it is not local either.
  assert.equal(isLocal(req('127.0.0.1', { 'x-forwarded-for': '173.245.48.5' })), false);
});

test('the general limit skips requests without a public client address', async (t) => {
  const app = await buildLimitedApp(t);
  // Browser on this machine, and a proxy or Docker gateway that forwards no client address.
  for (const forwarded of ['127.0.0.1', '172.17.0.1']) {
    for (let i = 0; i < 10; i++) {
      const res = await app.inject({
        method: 'GET', url: '/ping', remoteAddress: '127.0.0.1', headers: { 'x-forwarded-for': forwarded },
      });
      assert.equal(res.statusCode, 200);
    }
  }
});

test('brute-force limits still apply without a public client address', async (t) => {
  const app = await buildLimitedApp(t);
  const statuses = [];
  for (let i = 0; i < 4; i++) {
    const res = await app.inject({
      method: 'POST', url: '/secret', remoteAddress: '127.0.0.1', headers: { 'x-forwarded-for': '127.0.0.1' },
    });
    statuses.push(res.statusCode);
  }
  assert.deepEqual(statuses, [200, 200, 429, 429]);

  // Public clients are limited separately from each other.
  const publicHit = (ip) => app.inject({
    method: 'POST', url: '/secret', remoteAddress: '127.0.0.1', headers: { 'x-forwarded-for': ip },
  });
  assert.equal((await publicHit('203.0.113.9')).statusCode, 200);
  assert.equal((await publicHit('203.0.113.9')).statusCode, 200);
  assert.equal((await publicHit('203.0.113.9')).statusCode, 429);
  assert.equal((await publicHit('203.0.113.10')).statusCode, 200);
});
