import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { X509Certificate, createPublicKey } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  certificateFindings, chainFindings, decodeCertificate, decodePemText, fingerprint, matchesHostname,
  parsePemBlocks, resolvePublicKey, toPem,
} from '../../frontend/src/lib/tools/cert-decoder.ts';
import { DerError, parseDer } from '../../frontend/src/lib/tools/der.ts';

// Real certificates, requests and keys made by openssl; the decoder is then
// compared with Node's own X.509 parser.
const dir = mkdtempSync(join(tmpdir(), 'cert-decoder-'));
const file = name => join(dir, name);
const read = name => readFileSync(file(name), 'utf8');
const ossl = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'pipe', 'ignore'] });
let available = true;
try {
  writeFileSync(file('leaf.ext'), 'subjectAltName=DNS:example.com,DNS:*.example.com,IP:192.0.2.7,IP:2001:db8::1,email:admin@example.com\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n');
  // Root CA (RSA 2048) and an intermediate, then a leaf signed by the intermediate.
  ossl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'root.key', '-out', 'root.pem', '-days', '3650', '-subj', '/C=US/O=Test Root, Inc./CN=Test Root CA', '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:1', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-addext', 'subjectKeyIdentifier=hash');
  ossl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'inter.key', '-out', 'inter.csr', '-subj', '/C=US/O=Test/CN=Test Intermediate');
  writeFileSync(file('inter.ext'), 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n');
  ossl('x509', '-req', '-in', 'inter.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-out', 'inter.pem', '-days', '1825', '-extfile', 'inter.ext');
  ossl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/C=DE/ST=Berlin/L=Berlin/O=Example GmbH/OU=IT/CN=example.com', '-addext', 'subjectAltName=DNS:example.com,DNS:www.example.com');
  ossl('x509', '-req', '-in', 'leaf.csr', '-CA', 'inter.pem', '-CAkey', 'inter.key', '-CAcreateserial', '-out', 'leaf.pem', '-days', '90', '-extfile', 'leaf.ext');
  // Other key types and encodings.
  ossl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'ec-sec1.key');
  ossl('pkcs8', '-topk8', '-nocrypt', '-in', 'ec-sec1.key', '-out', 'ec-pkcs8.key');
  ossl('req', '-x509', '-key', 'ec-sec1.key', '-out', 'ec.pem', '-days', '30', '-subj', '/CN=ec.example.com');
  ossl('genpkey', '-algorithm', 'ed25519', '-out', 'ed.key');
  ossl('req', '-x509', '-key', 'ed.key', '-out', 'ed.pem', '-days', '30', '-subj', '/CN=ed.example.com');
  ossl('rsa', '-in', 'leaf.key', '-traditional', '-out', 'leaf-pkcs1.key');
  ossl('pkey', '-in', 'leaf.key', '-aes256', '-passout', 'pass:secret', '-out', 'leaf-enc.key');
  ossl('crl2pkcs7', '-nocrl', '-certfile', 'leaf.pem', '-certfile', 'inter.pem', '-out', 'bundle.p7b');
  ossl('req', '-x509', '-newkey', 'rsa:1024', '-nodes', '-keyout', 'weak.key', '-out', 'weak.pem', '-days', '1', '-subj', '/CN=weak.example.com', '-addext', 'basicConstraints=CA:FALSE');
} catch {
  available = false;
}
test.after(() => rmSync(dir, { recursive: true, force: true }));
const it = (name, fn) => test(name, { skip: available ? false : 'openssl is not available' }, fn);

it('certificate fields match Node\'s X.509 parser', () => {
  const [cert] = decodePemText(read('leaf.pem'));
  const node = new X509Certificate(read('leaf.pem'));
  assert.equal(cert.kind, 'certificate');
  assert.equal(cert.version, 3);
  assert.equal(cert.serialNumber.replace(/:/g, '').toUpperCase().replace(/^0+/, ''), node.serialNumber.replace(/^0+/, ''));
  assert.equal(cert.subject.commonName, 'example.com');
  assert.equal(cert.subject.organization, 'Example GmbH');
  assert.equal(cert.subject.text, 'CN=example.com, OU=IT, O=Example GmbH, L=Berlin, ST=Berlin, C=DE');
  assert.equal(cert.issuer.commonName, 'Test Intermediate');
  assert.equal(cert.notBefore.getTime(), new Date(node.validFrom).getTime());
  assert.equal(cert.notAfter.getTime(), new Date(node.validTo).getTime());
  assert.equal(cert.signatureAlgorithm, 'SHA-256 with RSA');
  assert.deepEqual(cert.publicKey.description, 'RSA 2048 bit');
  assert.deepEqual(cert.dnsNames, ['example.com', '*.example.com']);
  assert.deepEqual(cert.ipAddresses, ['192.0.2.7', '2001:db8::1']);
  assert.deepEqual(cert.emailAddresses, ['admin@example.com']);
  assert.deepEqual(cert.keyUsage, ['Digital signature', 'Key encipherment']);
  assert.deepEqual(cert.extendedKeyUsage, ['TLS server', 'TLS client']);
  assert.equal(cert.isCa, false);
  assert.equal(cert.selfSigned, false);
});

it('fingerprints match Node\'s', async () => {
  const [cert] = decodePemText(read('leaf.pem'));
  const node = new X509Certificate(read('leaf.pem'));
  assert.equal(await fingerprint(cert.der, 'SHA-256'), node.fingerprint256);
  assert.equal(await fingerprint(cert.der, 'SHA-1'), node.fingerprint);
});

it('CA certificates report basic constraints, path length and self-signing', () => {
  const [root] = decodePemText(read('root.pem'));
  assert.equal(root.isCa, true);
  assert.equal(root.pathLength, 1);
  assert.equal(root.selfSigned, true);
  assert.deepEqual(root.keyUsage, ['Certificate signing', 'CRL signing']);
  assert.equal(root.subject.organization, 'Test Root, Inc.');
  assert.equal(root.subject.text, 'CN=Test Root CA, O=Test Root\\, Inc., C=US');
  const [inter] = decodePemText(read('inter.pem'));
  assert.equal(inter.pathLength, 0);
  assert.equal(inter.authorityKeyId, root.subjectKeyId);
});

it('a CSR is decoded with its requested names', () => {
  const [csr] = decodePemText(read('leaf.csr'));
  assert.equal(csr.kind, 'csr');
  assert.equal(csr.subject.commonName, 'example.com');
  assert.deepEqual(csr.dnsNames, ['example.com', 'www.example.com']);
  assert.equal(csr.publicKey.description, 'RSA 2048 bit');
});

it('certificate, CSR and private key (PKCS#8 and PKCS#1) share one key identity; another key does not', () => {
  const [cert] = decodePemText(read('leaf.pem'));
  const [csr] = decodePemText(read('leaf.csr'));
  const [pkcs8] = decodePemText(read('leaf.key'));
  const [pkcs1] = decodePemText(read('leaf-pkcs1.key'));
  const [other] = decodePemText(read('inter.key'));
  assert.equal(pkcs8.format, 'PKCS#8');
  assert.equal(pkcs1.format, 'PKCS#1 (RSA)');
  assert.ok(cert.publicKey.id.startsWith('rsa:'));
  assert.equal(csr.publicKey.id, cert.publicKey.id);
  assert.equal(pkcs8.publicKey.id, cert.publicKey.id);
  assert.equal(pkcs1.publicKey.id, cert.publicKey.id);
  assert.notEqual(other.publicKey.id, cert.publicKey.id);
});

it('EC keys match in SEC1 and PKCS#8 form, including a key file without the public point', async () => {
  const [cert] = decodePemText(read('ec.pem'));
  assert.equal(cert.publicKey.description, 'EC P-256');
  assert.equal(cert.signatureAlgorithm, 'ECDSA with SHA-256');
  const [sec1] = decodePemText(read('ec-sec1.key'));
  const [pkcs8] = decodePemText(read('ec-pkcs8.key'));
  assert.equal(sec1.format, 'SEC1 (EC)');
  assert.equal(sec1.publicKey.id, cert.publicKey.id);
  assert.equal(pkcs8.publicKey.id, cert.publicKey.id);

  // openssl can write an EC key without the optional public point; the identity is then derived.
  ossl('ec', '-in', 'ec-sec1.key', '-no_public', '-out', 'ec-nopub.key');
  const [bare] = decodePemText(read('ec-nopub.key'));
  assert.equal(bare.publicKey.id, '');
  assert.ok(bare.derive);
  assert.equal((await resolvePublicKey(bare)).publicKey.id, cert.publicKey.id);
});

it('Ed25519 certificate and key match after deriving the public key', async () => {
  const [cert] = decodePemText(read('ed.pem'));
  assert.equal(cert.publicKey.algorithm, 'Ed25519');
  assert.equal(cert.signatureAlgorithm, 'Ed25519');
  const [key] = decodePemText(read('ed.key'));
  assert.equal(key.publicKey.id, '');
  assert.equal((await resolvePublicKey(key)).publicKey.id, cert.publicKey.id);
});

it('a public key block has the same identity as its certificate', () => {
  const [cert] = decodePemText(read('leaf.pem'));
  const pem = createPublicKey(read('leaf.pem')).export({ type: 'spki', format: 'pem' });
  const [pub] = decodePemText(pem);
  assert.equal(pub.kind, 'public-key');
  assert.equal(pub.publicKey.id, cert.publicKey.id);
});

it('encrypted and unsupported blocks are reported, never decoded or thrown', () => {
  const [enc] = decodePemText(read('leaf-enc.key'));
  assert.equal(enc.kind, 'unreadable');
  assert.match(enc.reason, /encrypted/);
  const legacy = '-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF\n\nAAAA\n-----END RSA PRIVATE KEY-----';
  assert.match(decodePemText(legacy)[0].reason, /encrypted/);
  assert.match(decodePemText('-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----')[0].reason, /OpenSSH/);
  assert.match(decodePemText('-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----')[0].reason, /not supported/);
  assert.equal(decodePemText('-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----')[0].kind, 'unreadable');
});

it('a bundle with several blocks, a PKCS#7 file and bare base64 are all read', () => {
  const bundle = decodePemText(read('leaf.pem') + '\nsome text between\n' + read('inter.pem') + read('leaf.key'));
  assert.deepEqual(bundle.map(b => b.kind), ['certificate', 'certificate', 'private-key']);

  const p7 = decodePemText(read('bundle.p7b'));
  assert.deepEqual(p7.map(c => c.subject.commonName), ['example.com', 'Test Intermediate']);

  const bare = read('leaf.pem').replace(/-----[A-Z ]+-----/g, '');
  assert.equal(decodePemText(bare)[0].subject.commonName, 'example.com');
  const bareCsr = read('leaf.csr').replace(/-----[A-Z ]+-----/g, '');
  assert.equal(decodePemText(bareCsr)[0].kind, 'csr');
});

it('chain order: correct, reversed, and missing intermediate', () => {
  const [leaf] = decodePemText(read('leaf.pem'));
  const [inter] = decodePemText(read('inter.pem'));
  const [root] = decodePemText(read('root.pem'));
  assert.deepEqual(chainFindings([leaf, inter, root]).map(f => f.severity), ['ok']);
  assert.ok(chainFindings([leaf, root, inter]).some(f => f.title.includes('not followed by its issuer')));
  assert.ok(chainFindings([leaf, root]).some(f => f.severity === 'critical' && f.title.includes('issuer of certificate 1 is missing')));
  assert.ok(chainFindings([inter, leaf]).some(f => f.title.includes('first certificate is a CA')));
  assert.deepEqual(chainFindings([leaf]), []);
});

it('findings: expiry, weak key, missing SAN, long validity', () => {
  const [leaf] = decodePemText(read('leaf.pem'));
  const now = new Date();
  assert.deepEqual(certificateFindings(leaf, now).map(f => f.severity), ['ok']);
  const later = new Date(now.getTime() + 80 * 86400000);
  assert.match(certificateFindings(leaf, later)[0].title, /expires in \d+ days/);
  const expired = new Date(now.getTime() + 100 * 86400000);
  assert.equal(certificateFindings(leaf, expired)[0].severity, 'critical');
  const early = new Date(now.getTime() - 5 * 86400000);
  assert.equal(certificateFindings(leaf, early)[0].title, 'Certificate is not valid yet');

  const [weak] = decodePemText(read('weak.pem'));
  const titles = certificateFindings(weak, now).map(f => f.title).join('|');
  assert.ok(titles.includes('Weak 1024-bit RSA key'));
  assert.ok(titles.includes('No subject alternative names'));
  assert.ok(titles.includes('Self-signed'));
});

it('hostname matching follows wildcard rules', () => {
  const [leaf] = decodePemText(read('leaf.pem'));
  for (const host of ['example.com', 'EXAMPLE.com.', 'www.example.com', 'a.example.com', '192.0.2.7', '2001:db8::1']) assert.ok(matchesHostname(leaf, host), host);
  for (const host of ['a.b.example.com', 'example.org', 'badexample.com', '', '192.0.2.8']) assert.ok(!matchesHostname(leaf, host), host);
});

it('toPem round-trips', () => {
  const [leaf] = decodePemText(read('leaf.pem'));
  assert.equal(toPem('CERTIFICATE', leaf.der).trim(), read('leaf.pem').trim());
});

test('malformed DER is rejected with DerError, never an out-of-range read or a hang', () => {
  const cases = [
    [], [0x30], [0x30, 0x05, 0x02, 0x01], [0x30, 0x80, 0x00, 0x00], [0x30, 0x85, 1, 1, 1, 1, 1], [0x30, 0x84, 0xff, 0xff, 0xff, 0xff],
    [0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00],
  ];
  for (const bytes of cases) assert.throws(() => parseDer(new Uint8Array(bytes)), DerError, JSON.stringify(bytes));
  // 40 nested sequences exceed the depth cap.
  let nested = [0x05, 0x00];
  for (let i = 0; i < 40; i++) nested = [0x30, nested.length, ...nested];
  assert.throws(() => parseDer(new Uint8Array(nested)), DerError);
  assert.throws(() => decodeCertificate(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00])), DerError);
});

test('garbage text yields no blocks or an unreadable block, and never throws', () => {
  assert.deepEqual(decodePemText(''), []);
  assert.deepEqual(decodePemText('hello world'), []);
  assert.deepEqual(parsePemBlocks('-----BEGIN CERTIFICATE-----\nabc'), []);
  assert.equal(decodePemText('-----BEGIN CERTIFICATE-----\nMAAA\n-----END CERTIFICATE-----')[0].kind, 'unreadable');
  assert.equal(decodePemText('x'.repeat(2_000_001))[0].kind, 'unreadable');
  const random = Buffer.from(Array.from({ length: 600 }, (_, i) => (i * 37 + 11) % 256));
  random[0] = 0x30;
  assert.equal(decodePemText(random.toString('base64'))[0].kind, 'unreadable');
});
