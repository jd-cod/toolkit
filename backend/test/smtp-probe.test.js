import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Fastify from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { probeSmtp, redactGreeting, smtpFindings } from '../src/lib/smtp-probe.js';
import emailToolRoutes from '../src/routes/email-tools.js';

// The probe refuses loopback by default; these tests run a fake server there.
process.env.ALLOW_PRIVATE_TARGETS = 'true';

function selfSignedCert() {
  const dir = mkdtempSync(join(tmpdir(), 'smtp-probe-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'), '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
    return { key: readFileSync(join(dir, 'k.pem')), cert: readFileSync(join(dir, 'c.pem')) };
  } catch {
    return null;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Minimal SMTP server. Records every command it receives. */
function fakeSmtp({ extensions = ['SIZE 1000', 'PIPELINING'], banner = '220 mx.test ESMTP ready', credentials = null, secureExtensions = ['AUTH PLAIN LOGIN'] } = {}) {
  const commands = [];
  const handle = (socket, secure) => {
    let buffer = '';
    const onData = chunk => {
      buffer += chunk.toString();
      let index;
      while ((index = buffer.indexOf('\r\n')) !== -1) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 2);
        commands.push(line);
        const verb = line.split(' ')[0].toUpperCase();
        if (verb === 'EHLO') {
          const list = secure ? secureExtensions : extensions;
          socket.write(['250-mx.test greets you, [203.0.113.99]', ...list.map((ext, i) => `${i === list.length - 1 ? '250 ' : '250-'}${ext}`)].join('\r\n') + '\r\n');
        } else if (verb === 'STARTTLS' && credentials && !secure) {
          socket.write('220 go ahead\r\n');
          socket.off('data', onData);
          const upgraded = new tls.TLSSocket(socket, { isServer: true, secureContext: tls.createSecureContext(credentials) });
          handle(upgraded, true);
        } else if (verb === 'QUIT') {
          socket.end('221 bye\r\n');
        } else {
          socket.write('502 not implemented\r\n');
        }
      }
    };
    socket.on('data', onData);
    socket.on('error', () => {});
  };
  const server = net.createServer(socket => { if (banner) socket.write(`${banner}\r\n`); handle(socket, false); });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({ server, commands, port: server.address().port })));
}

const close = server => new Promise(resolve => server.close(resolve));

test('probe reads banner and extensions, and sends nothing but EHLO and QUIT', async () => {
  const { server, commands, port } = await fakeSmtp({ extensions: ['SIZE 52428800', '8BITMIME', 'AUTH LOGIN PLAIN'] });
  const probe = await probeSmtp({ host: '127.0.0.1', port, helo: 'probe.test', timeoutMs: 2000 });
  await close(server);

  assert.equal(probe.connected, true);
  assert.equal(probe.error, '');
  assert.equal(probe.banner_host, 'mx.test');
  assert.deepEqual(probe.ehlo.extensions, ['SIZE 52428800', '8BITMIME', 'AUTH LOGIN PLAIN']);
  assert.equal(probe.ehlo.size_limit, 52428800);
  assert.deepEqual(probe.ehlo.auth_mechanisms, ['LOGIN', 'PLAIN']);
  assert.equal(probe.starttls.offered, false);
  assert.deepEqual(commands, ['EHLO probe.test', 'QUIT']);

  const titles = smtpFindings(probe, { ptr: ['mx.test'] }).map(f => `${f.severity}: ${f.title}`);
  assert.ok(titles.includes('warning: STARTTLS is not offered'));
  assert.ok(titles.includes('warning: AUTH is offered before encryption'));
});

test('the EHLO greeting, which echoes the address we connect from, is hidden in the transcript', async () => {
  const { server, port } = await fakeSmtp();
  const probe = await probeSmtp({ host: '127.0.0.1', port, helo: 'probe.test', timeoutMs: 2000 });
  await close(server);
  assert.ok(!JSON.stringify(probe).includes('203.0.113.99'));
  assert.ok(probe.transcript.some(entry => entry.line === '250-mx.test [greeting hidden]'));
  assert.deepEqual(redactGreeting([{ from: 'client', line: 'EHLO a' }, { from: 'server', line: '250 host' }]).map(e => e.line), ['EHLO a', '250 host']);
});

test('STARTTLS is negotiated and the certificate is described', async t => {
  const credentials = selfSignedCert();
  if (!credentials) return t.skip('openssl is not available');
  const { server, commands, port } = await fakeSmtp({ extensions: ['STARTTLS', 'SIZE 1000'], credentials });
  const probe = await probeSmtp({ host: 'localhost', port, helo: 'probe.test', timeoutMs: 3000, lookup: (host, options, cb) => cb(null, options.all ? [{ address: '127.0.0.1', family: 4 }] : '127.0.0.1', 4) });
  await close(server);

  assert.equal(probe.error, '');
  assert.equal(probe.starttls.upgraded, true);
  assert.match(probe.tls.protocol, /^TLSv1\.[23]$/);
  assert.equal(probe.tls.trusted, false);
  assert.equal(probe.tls.certificate.subject, 'localhost');
  assert.equal(probe.tls.certificate.hostname_match, true);
  assert.deepEqual(probe.post_tls_ehlo.auth_mechanisms, ['PLAIN', 'LOGIN']);
  assert.deepEqual(commands, ['EHLO probe.test', 'STARTTLS', 'EHLO probe.test', 'QUIT']);

  const findings = smtpFindings(probe, { ptr: ['mx.test'] });
  assert.ok(findings.some(f => f.title === 'Certificate is not trusted'));
  assert.ok(!findings.some(f => f.title === 'AUTH is offered before encryption'));
});

test('a refused connection, a silent server and a non-220 banner are reported, not thrown', async () => {
  const { server, port } = await fakeSmtp();
  await close(server);
  const refused = await probeSmtp({ host: '127.0.0.1', port, timeoutMs: 1000 });
  assert.equal(refused.connected, false);
  assert.equal(refused.error_code, 'ECONNREFUSED');
  assert.equal(smtpFindings(refused)[0].severity, 'critical');

  const silent = await fakeSmtp({ banner: '' });
  const quiet = await probeSmtp({ host: '127.0.0.1', port: silent.port, timeoutMs: 300 });
  await close(silent.server);
  assert.equal(quiet.connected, true);
  assert.match(quiet.error, /Timed out/);

  const busy = await fakeSmtp({ banner: '554 no service' });
  const rejected = await probeSmtp({ host: '127.0.0.1', port: busy.port, timeoutMs: 1000 });
  await close(busy.server);
  assert.match(rejected.error, /554 instead of 220/);
});

test('private destinations are refused unless ALLOW_PRIVATE_TARGETS is set', async () => {
  delete process.env.ALLOW_PRIVATE_TARGETS;
  try {
    const probe = await probeSmtp({ host: '127.0.0.1', port: 25, timeoutMs: 500 });
    assert.equal(probe.connected, false);
    assert.equal(probe.error_code, 'EBLOCKEDDESTINATION');
    assert.equal(smtpFindings(probe)[0].title, 'Destination is not a public address');
  } finally {
    process.env.ALLOW_PRIVATE_TARGETS = 'true';
  }
});

function fakeDns(zone) {
  const answer = (type, name) => {
    const records = zone[`${type} ${name}`];
    return records ? { status: 'ok', records } : { status: 'nxdomain', records: [] };
  };
  return { txt: async n => answer('TXT', n), mx: async n => answer('MX', n), a: async n => answer('A', n), aaaa: async n => answer('AAAA', n), ptr: async n => answer('PTR', n) };
}

async function buildApp(opts) {
  const app = Fastify();
  await app.register(rateLimit, { max: 100, timeWindow: '1 minute' });
  await app.register(emailToolRoutes, { prefix: '/api', ...opts });
  return app;
}

test('POST /api/email/smtp tests the two best MX hosts, or the host itself when asked', async () => {
  const probed = [];
  const app = await buildApp({
    dns: fakeDns({
      'MX example.com': [{ exchange: 'mx3.example.com', priority: 30 }, { exchange: 'mx1.example.com', priority: 10 }, { exchange: 'mx2.example.com', priority: 20 }],
      'PTR 203.0.113.5': ['mx1.example.com'],
    }),
    probeSmtp: async ({ host, port }) => { probed.push([host, port]); return { host, port, address: '203.0.113.5', connected: true, implicit_tls: false, banner: 'x', banner_host: host, ehlo: { starttls: true, auth_mechanisms: [] }, starttls: { offered: true, upgraded: true, error: '' }, tls: { protocol: 'TLSv1.3', cipher: '', trusted: true, trust_error: '', certificate: { days_remaining: 90, hostname_match: true, names: [], subject: host, valid_to: '' } }, timings: { banner_ms: 10 }, transcript: [], error: '', error_code: '' }; },
  });

  const viaMx = (await app.inject({ method: 'POST', url: '/api/email/smtp', payload: { target: 'example.com' } })).json();
  assert.equal(viaMx.mode, 'mx');
  assert.deepEqual(probed, [['mx1.example.com', 25], ['mx2.example.com', 25]]);
  assert.deepEqual(viaMx.servers[0].ptr, ['mx1.example.com']);

  probed.length = 0;
  const direct = (await app.inject({ method: 'POST', url: '/api/email/smtp', payload: { target: 'example.com', port: 587, direct: true } })).json();
  assert.equal(direct.mode, 'host');
  assert.deepEqual(probed, [['example.com', 587]]);

  for (const payload of [{ target: 'example.com', port: 22 }, { target: 'exa mple' }, { target: '' }]) {
    assert.equal((await app.inject({ method: 'POST', url: '/api/email/smtp', payload })).statusCode, 400, JSON.stringify(payload));
  }
  await app.close();
});

test('POST /api/email/auth validates the domain and selectors', async () => {
  const app = await buildApp({ dns: fakeDns({ 'TXT example.com': ['v=spf1 -all'] }), fetchPolicy: async () => '' });
  const ok = await app.inject({ method: 'POST', url: '/api/email/auth', payload: { domain: 'https://Example.com/', selectors: 'mail, s1' } });
  assert.equal(ok.statusCode, 200);
  assert.equal(ok.json().domain, 'example.com');
  assert.equal(ok.json().spf.status, 'pass');

  for (const payload of [{ domain: 'nope' }, { domain: '' }, { domain: 'example.com', selectors: ['ok', 'bad;selector'] }, {}]) {
    const res = await app.inject({ method: 'POST', url: '/api/email/auth', payload });
    assert.equal(res.statusCode, 400, JSON.stringify(payload));
    assert.equal(typeof res.json().error, 'string');
  }
  await app.close();
});

test('POST /api/email/blacklist checks mail server and domain addresses, skips private ones', async () => {
  const checkedIps = [];
  const summary = { listed: 0, policy: 0, clean: 1, unavailable: 0, total: 1 };
  const app = await buildApp({
    dns: fakeDns({
      'A example.com': ['9.9.9.9', '10.0.0.9', '203.0.113.10'],
      'MX example.com': [{ exchange: 'mx.example.com', priority: 10 }],
      'A mx.example.com': ['8.8.8.8'],
    }),
    dnsbl: {
      checkIp: async ip => { checkedIps.push(ip); return { target: ip, kind: 'ip', results: [], summary }; },
      checkDomain: async domain => ({ target: domain, kind: 'domain', results: [], summary }),
    },
  });

  const delete_env = process.env.ALLOW_PRIVATE_TARGETS;
  delete process.env.ALLOW_PRIVATE_TARGETS;
  try {
    const res = await app.inject({ method: 'POST', url: '/api/email/blacklist', payload: { target: 'Example.com' } });
    assert.equal(res.statusCode, 200);
    const body = res.json();
    // 10.0.0.9 is private and 203.0.113.10 is a documentation range: neither is checked.
    assert.deepEqual(checkedIps, ['8.8.8.8', '9.9.9.9']);
    assert.deepEqual(body.addresses.map(a => a.role), ['Mail server', 'Domain address']);
    assert.equal(body.summary.total, 3);

    assert.equal((await app.inject({ method: 'POST', url: '/api/email/blacklist', payload: { target: '192.168.1.1' } })).statusCode, 400);
    assert.equal((await app.inject({ method: 'POST', url: '/api/email/blacklist', payload: { target: '' } })).statusCode, 400);
    checkedIps.length = 0;
    assert.equal((await app.inject({ method: 'POST', url: '/api/email/blacklist', payload: { target: '[2001:4860:4860::8888]' } })).statusCode, 200);
    assert.deepEqual(checkedIps, ['2001:4860:4860::8888']);
  } finally {
    process.env.ALLOW_PRIVATE_TARGETS = delete_env;
  }
  await app.close();
});
