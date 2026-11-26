import test from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import dnsRoutes from '../src/routes/dns.js';
import { createGlobalDnsAccess } from '../src/services/global-dns-access.js';

test('capability discovery shares in-flight work and never exposes secrets', async () => {
  let calls = 0;
  const access = createGlobalDnsAccess({ resolveCredentials: async () => { calls++; return { accessKeyId: 'test', secretAccessKey: 'test-secret' }; } });
  assert.deepEqual(await Promise.all([access.capability(), access.capability()]), [{ available: true }, { available: true }]);
  assert.equal(calls, 1);
  assert.deepEqual(await access.capability(), { available: true });
  assert.equal(calls, 1);
});

test('missing and expired credentials are unavailable; failed discovery can recover', async () => {
  let clock = 100000;
  let valid = false;
  const access = createGlobalDnsAccess({ now: () => clock, resolveCredentials: async () => valid ? { accessKeyId: 'test', secretAccessKey: 'test' } : { accessKeyId: 'test', secretAccessKey: 'test', expiration: new Date(clock - 1) } });
  assert.deepEqual(await access.capability(), { available: false });
  valid = true;
  clock += 16000;
  assert.deepEqual(await access.capability(), { available: true });
});

test('a stalled credential provider has a bounded response', async () => {
  const access = createGlobalDnsAccess({ timeoutMs: 10, resolveCredentials: () => new Promise(() => {}) });
  assert.deepEqual(await access.capability(), { available: false });
});

test('unavailable server hides capability and rejects global queries explicitly', async () => {
  const app = Fastify();
  await app.register(dnsRoutes, { prefix: '/api', globalDnsAccess: createGlobalDnsAccess({ resolveCredentials: async () => { throw new Error('private provider details'); } }) });
  try {
    const capability = await app.inject('/api/dns/global-capability');
    assert.equal(capability.statusCode, 200);
    assert.deepEqual(capability.json(), { available: false });
    const result = await app.inject({ method: 'POST', url: '/api/dns/global', payload: { domain: 'example.com', type: 'A' } });
    assert.equal(result.statusCode, 503);
    assert.match(result.json().error, /unavailable/);
    assert.doesNotMatch(result.body, /private provider/);
  } finally { await app.close(); }
});
