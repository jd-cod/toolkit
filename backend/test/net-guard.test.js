import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  isPublicAddress,
  assertAllowedHost,
  guardedLookup,
  guardedRequest,
} from '../src/lib/net-guard.js';

function lookup(hostname) {
  return new Promise((resolve) => guardedLookup(hostname, {}, (err, address) => resolve({ err, address })));
}

async function withServer(handler, run) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    return await run(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

async function withPrivateTargetsAllowed(run) {
  const previous = process.env.ALLOW_PRIVATE_TARGETS;
  process.env.ALLOW_PRIVATE_TARGETS = 'true';
  try {
    return await run();
  } finally {
    if (previous === undefined) delete process.env.ALLOW_PRIVATE_TARGETS;
    else process.env.ALLOW_PRIVATE_TARGETS = previous;
  }
}

test('isPublicAddress rejects loopback, private, link-local and metadata addresses', () => {
  for (const address of [
    '127.0.0.1', '127.8.8.8', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1',
    '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255',
    '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '[::1]',
    '64:ff9b::7f00:1',
  ]) {
    assert.equal(isPublicAddress(address), false, address);
  }
});

test('isPublicAddress accepts public addresses and rejects non-IP input', () => {
  for (const address of ['1.1.1.1', '8.8.8.8', '172.15.0.1', '172.32.0.1', '2606:4700:4700::1111', '::ffff:8.8.8.8']) {
    assert.equal(isPublicAddress(address), true, address);
  }
  for (const value of ['example.com', '', null, undefined, '999.1.1.1']) {
    assert.equal(isPublicAddress(value), false, String(value));
  }
});

test('assertAllowedHost blocks private IP literals and leaves hostnames to the lookup', () => {
  assert.throws(() => assertAllowedHost('127.0.0.1'), /not a public address/);
  assert.throws(() => assertAllowedHost('[::1]'), /not a public address/);
  assert.throws(() => assertAllowedHost('169.254.169.254'), /not a public address/);
  assert.doesNotThrow(() => assertAllowedHost('8.8.8.8'));
  assert.doesNotThrow(() => assertAllowedHost('example.com'));
});

test('guardedLookup refuses a hostname that resolves to loopback', async () => {
  const { err } = await lookup('localhost');
  assert.ok(err);
  assert.equal(err.code, 'EBLOCKEDDESTINATION');
});

test('guardedLookup resolves the same hostname when private targets are allowed', async () => {
  await withPrivateTargetsAllowed(async () => {
    const { err, address } = await lookup('localhost');
    assert.equal(err, null);
    assert.ok(address === '127.0.0.1' || address === '::1');
  });
});

test('guardedRequest rejects non-http schemes, embedded credentials and private hosts', async () => {
  await assert.rejects(guardedRequest('file:///etc/passwd'), /Only http and https/);
  await assert.rejects(guardedRequest('gopher://example.com/'), /Only http and https/);
  await assert.rejects(guardedRequest('not a url'), /Invalid URL/);
  await assert.rejects(guardedRequest('http://user:pass@example.com/'), /credentials/);
  await assert.rejects(guardedRequest('http://127.0.0.1:1/'), /not a public address/);
  await assert.rejects(guardedRequest('http://[::1]:1/'), /not a public address/);
  await assert.rejects(guardedRequest('http://169.254.169.254/latest/meta-data/'), /not a public address/);
  await assert.rejects(guardedRequest('http://localhost:1/'), /not a public address/);
});

test('guardedRequest does not reach a local server unless private targets are allowed', async () => {
  let hits = 0;
  await withServer((req, res) => { hits++; res.end('secret'); }, async (base) => {
    await assert.rejects(guardedRequest(`${base}/`), /not a public address/);
    assert.equal(hits, 0);

    await withPrivateTargetsAllowed(async () => {
      const res = await guardedRequest(`${base}/`);
      assert.equal(res.status, 200);
      assert.equal(res.body.toString(), 'secret');
    });
    assert.equal(hits, 1);
  });
});

test('guardedRequest follows redirects, and re-validates the destination of each one', async () => {
  await withServer((req, res) => {
    if (req.url === '/start') {
      res.writeHead(302, { Location: '/final' });
      return res.end();
    }
    if (req.url === '/to-file') {
      res.writeHead(302, { Location: 'file:///etc/passwd' });
      return res.end();
    }
    if (req.url === '/loop') {
      res.writeHead(302, { Location: '/loop' });
      return res.end();
    }
    res.end('done');
  }, async (base) => {
    await withPrivateTargetsAllowed(async () => {
      const ok = await guardedRequest(`${base}/start`);
      assert.equal(ok.body.toString(), 'done');
      assert.ok(ok.url.endsWith('/final'));
      await assert.rejects(guardedRequest(`${base}/to-file`), /Only http and https/);
      await assert.rejects(guardedRequest(`${base}/loop`, { maxRedirects: 3 }), /Too many redirects/);
    });
  });
});

test('guardedRequest stops reading once the size limit is exceeded', async () => {
  await withServer((req, res) => res.end(Buffer.alloc(64 * 1024, 'a')), async (base) => {
    await withPrivateTargetsAllowed(async () => {
      await assert.rejects(guardedRequest(`${base}/`, { maxBytes: 1024 }), (err) => err.code === 'ERESPONSETOOLARGE');
      const res = await guardedRequest(`${base}/`, { maxBytes: 128 * 1024 });
      assert.equal(res.body.length, 64 * 1024);
    });
  });
});

test('guardedRequest times out a server that never answers', async () => {
  await withServer(() => { /* never respond */ }, async (base) => {
    await withPrivateTargetsAllowed(async () => {
      await assert.rejects(guardedRequest(`${base}/`, { timeoutMs: 200 }), /timed out/);
    });
  });
});
