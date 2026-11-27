import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import Fastify from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { auditResponse, followChain, normalizeUrl } from '../src/lib/http-inspect.js';
import { parsePorts, probePort, resolvePublicAddress, describePort, MAX_PORTS_PER_REQUEST } from '../src/lib/port-probe.js';
import netToolRoutes from '../src/routes/net-tools.js';

const hop = (url, status, headers = [], extra = {}) => ({
  url, status, status_text: '', http_version: '1.1', address: '203.0.113.9', elapsed_ms: 12, headers,
  tls: url.startsWith('https:') ? { protocol: 'TLSv1.3', trusted: true, trust_error: '', subject: '', issuer: '', valid_to: '' } : null, ...extra,
});
const fakeRequest = responses => async url => {
  const response = responses[url.toString()];
  if (!response) throw new Error(`unexpected request to ${url}`);
  if (response instanceof Error) throw response;
  return structuredClone(response);
};

test('normalizeUrl adds https, and refuses other schemes and credentials', () => {
  assert.equal(normalizeUrl('example.com/a?b=1').toString(), 'https://example.com/a?b=1');
  assert.equal(normalizeUrl('HTTP://Example.com').toString(), 'http://example.com/');
  for (const bad of ['', 'ftp://example.com', 'file:///etc/passwd', 'https://user:pw@example.com', 'http://', 'x'.repeat(3000)]) {
    assert.throws(() => normalizeUrl(bad), { statusCode: 400 }, bad);
  }
});

test('followChain follows redirects hop by hop and resolves relative locations', async () => {
  const result = await followChain(new URL('http://example.com/'), {
    request: fakeRequest({
      'http://example.com/': hop('http://example.com/', 301, [['Location', 'https://example.com/']]),
      'https://example.com/': hop('https://example.com/', 302, [['location', '/home']]),
      'https://example.com/home': hop('https://example.com/home', 200, [['Content-Type', 'text/html']]),
    }),
  });
  assert.deepEqual(result.chain.map(h => h.status), [301, 302, 200]);
  assert.equal(result.chain[1].redirect_to, 'https://example.com/home');
  assert.equal(result.final.url, 'https://example.com/home');
  assert.equal(result.error, '');
});

test('followChain stops on loops, on the hop limit and on non-http targets', async () => {
  const loop = await followChain(new URL('https://a.example/'), {
    request: fakeRequest({
      'https://a.example/': hop('https://a.example/', 302, [['Location', 'https://b.example/']]),
      'https://b.example/': hop('https://b.example/', 302, [['Location', 'https://a.example/']]),
    }),
  });
  assert.equal(loop.loop, true);
  assert.equal(loop.final, null);

  let n = 0;
  const endless = await followChain(new URL('https://a.example/0'), {
    maxHops: 3,
    request: async url => { n += 1; return hop(url.toString(), 302, [['Location', `/${n}`]]); },
  });
  assert.equal(endless.truncated, true);
  assert.equal(endless.chain.length, 4);

  const scheme = await followChain(new URL('https://a.example/'), {
    request: fakeRequest({ 'https://a.example/': hop('https://a.example/', 302, [['Location', 'javascript:alert(1)']]) }),
  });
  assert.match(scheme.error, /leaves http/);
});

test('followChain refuses private destinations, including ones reached by redirect', async () => {
  let called = 0;
  const direct = await followChain(new URL('http://127.0.0.1:8080/'), { request: async () => { called += 1; } });
  assert.equal(called, 0);
  assert.equal(direct.error, 'Destination is not a public address.');

  const viaRedirect = await followChain(new URL('https://a.example/'), {
    request: fakeRequest({ 'https://a.example/': hop('https://a.example/', 302, [['Location', 'http://169.254.169.254/latest/meta-data/']]) }),
  });
  assert.equal(viaRedirect.chain.length, 2);
  assert.equal(viaRedirect.chain[1].error, 'Destination is not a public address.');
  assert.equal(viaRedirect.final, null);
});

test('auditResponse grades a fully protected response A and a bare one F', () => {
  const good = hop('https://example.com/', 200, [
    ['Strict-Transport-Security', 'max-age=31536000; includeSubDomains'],
    ['Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'"],
    ['X-Content-Type-Options', 'nosniff'], ['Referrer-Policy', 'strict-origin-when-cross-origin'],
    ['Permissions-Policy', 'camera=()'], ['Set-Cookie', 'sid=1; Secure; HttpOnly; SameSite=Lax'],
  ]);
  const a = auditResponse({ chain: [good], final: good });
  assert.equal(a.grade, 'A');
  assert.deepEqual(a.findings.map(f => f.severity), ['ok']);

  const bare = hop('https://example.com/', 200, [['Server', 'nginx/1.18.0'], ['X-Powered-By', 'PHP/7.4'], ['Set-Cookie', 'sid=1']]);
  const f = auditResponse({ chain: [bare], final: bare });
  assert.equal(f.grade, 'F');
  const titles = f.findings.map(x => x.title).join('|');
  for (const expected of ['No Strict-Transport-Security', 'No Content-Security-Policy', 'No clickjacking protection', 'nosniff', 'Cookie "sid" is missing Secure, HttpOnly, SameSite', 'Server header shows a version', 'X-Powered-By']) {
    assert.ok(titles.includes(expected), expected);
  }
});

test('auditResponse flags plain HTTP, downgrades and long chains', () => {
  const plain = hop('http://example.com/', 200, []);
  assert.equal(auditResponse({ chain: [plain], final: plain }).grade, 'F');
  assert.equal(auditResponse({ chain: [plain], final: plain }).findings[0].severity, 'critical');

  const chain = [hop('https://a.example/', 301), hop('http://a.example/x', 301), hop('https://a.example/y', 301), hop('https://a.example/z', 200)];
  const titles = auditResponse({ chain, final: chain[3] }).findings.map(f => f.title).join('|');
  assert.ok(titles.includes('downgrades from HTTPS to HTTP'));
  assert.ok(titles.includes('3 redirects'));
});

test('parsePorts accepts lists and ranges, de-duplicates, and enforces limits', () => {
  assert.deepEqual(parsePorts('443, 22 80,8000-8002,22'), [22, 80, 443, 8000, 8001, 8002]);
  assert.deepEqual(parsePorts([22, '80']), [22, 80]);
  for (const bad of ['', '0', '65536', '80-70', 'ssh', '1-100', '22;rm -rf /', Array.from({ length: MAX_PORTS_PER_REQUEST + 1 }, (_, i) => i + 1).join(',')]) {
    assert.throws(() => parsePorts(bad), { statusCode: 400 }, String(bad));
  }
});

test('probePort tells open, closed and filtered apart', async () => {
  const server = net.createServer(socket => socket.end());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const openPort = server.address().port;
  assert.equal((await probePort('127.0.0.1', openPort, 1000)).state, 'open');
  await new Promise(resolve => server.close(resolve));
  assert.equal((await probePort('127.0.0.1', openPort, 1000)).state, 'closed');

  // A socket that never connects stands in for a firewall that drops packets.
  const silent = () => new (class extends net.Socket {})();
  const filtered = await probePort('203.0.113.1', 81, 50, silent);
  assert.deepEqual(filtered, { port: 81, state: 'filtered', latency_ms: null });
});

test('resolvePublicAddress refuses private literals and names that resolve privately', async () => {
  assert.throws(() => resolvePublicAddress('10.0.0.5'), { code: 'EBLOCKEDDESTINATION' });
  assert.throws(() => resolvePublicAddress('::1'), { code: 'EBLOCKEDDESTINATION' });
  await assert.rejects(resolvePublicAddress('localhost'), { code: 'EBLOCKEDDESTINATION' });
  const picked = await resolvePublicAddress('dual.example', (host, options, cb) => cb(null, [{ address: '2001:4860:4860::8888', family: 6 }, { address: '8.8.8.8', family: 4 }]));
  assert.equal(picked.address, '8.8.8.8');
});

test('describePort names the service and warns only when a sensitive port is open', () => {
  assert.equal(describePort({ port: 3389, state: 'open', latency_ms: 5 }).service, 'RDP');
  assert.ok(describePort({ port: 3389, state: 'open', latency_ms: 5 }).warning.includes('RDP'));
  assert.equal(describePort({ port: 3389, state: 'closed', latency_ms: null }).warning, '');
  assert.equal(describePort({ port: 443, state: 'open', latency_ms: 5 }).warning, '');
});

async function buildApp(opts = {}) {
  const app = Fastify();
  await app.register(rateLimit, { max: 100, timeWindow: '1 minute' });
  await app.register(netToolRoutes, { prefix: '/api', ...opts });
  return app;
}

test('POST /api/port-check validates input and probes only the resolved address', async () => {
  const probed = [];
  const app = await buildApp({
    resolvePublicAddress: async host => ({ address: host === 'example.com' ? '203.0.113.7' : host, family: 4 }),
    probePort: async (address, port) => { probed.push([address, port]); return { port, state: port === 22 ? 'open' : 'closed', latency_ms: port === 22 ? 3 : null }; },
  });
  const ok = await app.inject({ method: 'POST', url: '/api/port-check', payload: { host: 'example.com', ports: '22,3306' } });
  assert.equal(ok.statusCode, 200);
  assert.deepEqual(probed, [['203.0.113.7', 22], ['203.0.113.7', 3306]]);
  assert.deepEqual(ok.json().summary, { open: 1, closed: 1, filtered: 0 });

  for (const payload of [{ host: '', ports: '22' }, { host: 'exa mple', ports: '22' }, { host: 'example.com', ports: '1-1000' }, { host: 'example.com' }]) {
    const res = await app.inject({ method: 'POST', url: '/api/port-check', payload });
    assert.equal(res.statusCode, 400, JSON.stringify(payload));
    assert.equal(typeof res.json().error, 'string');
  }
  await app.close();
});

test('POST /api/port-check refuses private targets with the real guard', async () => {
  const app = await buildApp();
  for (const host of ['127.0.0.1', '10.1.2.3', '169.254.169.254', '192.168.1.1', '::1']) {
    const res = await app.inject({ method: 'POST', url: '/api/port-check', payload: { host, ports: '22' } });
    assert.equal(res.statusCode, 400, host);
    assert.match(res.json().error, /not a public address/);
  }
  await app.close();
});

test('POST /api/port-check is rate limited to 6 per minute per client', async () => {
  const app = await buildApp({ resolvePublicAddress: async () => ({ address: '203.0.113.7', family: 4 }), probePort: async (a, port) => ({ port, state: 'closed', latency_ms: null }) });
  const codes = [];
  for (let i = 0; i < 8; i++) codes.push((await app.inject({ method: 'POST', url: '/api/port-check', payload: { host: 'example.com', ports: '22' }, remoteAddress: '198.51.100.20' })).statusCode);
  assert.deepEqual(codes, [200, 200, 200, 200, 200, 200, 429, 429]);
  await app.close();
});

test('POST /api/http-check returns the chain, grade and the plain-HTTP upgrade check', async () => {
  const pages = {
    'https://example.com/': hop('https://example.com/', 200, [['Strict-Transport-Security', 'max-age=31536000']]),
    'http://example.com/': hop('http://example.com/', 200, []),
  };
  const app = await buildApp({ followChain: async url => ({ chain: [pages[url.toString()]], final: pages[url.toString()], error: '', loop: false, truncated: false }) });
  const res = await app.inject({ method: 'POST', url: '/api/http-check', payload: { url: 'example.com' } });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.equal(body.final_url, 'https://example.com/');
  assert.equal(body.http_upgrade.upgrades, false);
  assert.ok(body.findings.some(f => f.title === 'Plain HTTP does not redirect to HTTPS'));

  const bad = await app.inject({ method: 'POST', url: '/api/http-check', payload: { url: 'gopher://x' } });
  assert.equal(bad.statusCode, 400);
  assert.equal(bad.json().error, 'Only http and https URLs are supported.');
  await app.close();
});
