import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  analyzeDkim, analyzeDmarc, analyzeEmailAuth, analyzeMx, analyzeMtaSts, analyzeSpf,
  parseDkimKey, parseSpf, parseTagList, isSelector,
} from '../src/lib/email-auth.js';
import { normalizeHostname } from '../src/lib/dns-client.js';

/** Fake DNS client. `zone` maps "TYPE name" to records; anything else is NXDOMAIN. */
function fakeDns(zone, { failing = [] } = {}) {
  const queries = [];
  const answer = (type, name) => {
    queries.push(`${type} ${name}`);
    if (failing.includes(`${type} ${name}`)) return { status: 'error', records: [], error: 'ESERVFAIL' };
    const records = zone[`${type} ${name}`];
    return records ? { status: records.length ? 'ok' : 'nodata', records } : { status: 'nxdomain', records: [] };
  };
  return {
    queries,
    txt: async name => answer('TXT', name),
    mx: async name => answer('MX', name),
    a: async name => answer('A', name),
    aaaa: async name => answer('AAAA', name),
    ptr: async name => answer('PTR', name),
  };
}

const titles = section => section.findings.map(f => `${f.severity}: ${f.title}`);

test('normalizeHostname accepts URLs and email addresses, rejects junk', () => {
  assert.equal(normalizeHostname(' https://Example.COM/path?x=1 '), 'example.com');
  assert.equal(normalizeHostname('user@mail.example.org'), 'mail.example.org');
  assert.equal(normalizeHostname('example.com.'), 'example.com');
  assert.equal(normalizeHostname('_dmarc.example.com'), '_dmarc.example.com');
  for (const bad of ['', 'localhost', 'exa mple.com', '-bad.com', '10.0.0.1', 'a..b', 'x'.repeat(64) + '.com', '$(id).com', null, 42]) {
    assert.equal(normalizeHostname(bad), '', `expected "${bad}" to be rejected`);
  }
});

test('parseTagList keeps order and tolerates spacing', () => {
  assert.deepEqual(parseTagList('v=DMARC1;  p = reject ;rua=mailto:a@b.c;'), [['v', 'DMARC1'], ['p', 'reject'], ['rua', 'mailto:a@b.c']]);
});

test('parseSpf reads qualifiers, networks and modifiers', () => {
  const { terms, errors } = parseSpf('v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx:mail.example.com/28 include:_spf.example.net ~all');
  assert.deepEqual(errors, []);
  assert.deepEqual(terms.map(t => [t.qualifier, t.name, t.value]), [
    ['+', 'ip4', '192.0.2.0/24'], ['+', 'ip6', '2001:db8::/32'], ['+', 'a', ''],
    ['+', 'mx', 'mail.example.com/28'], ['+', 'include', '_spf.example.net'], ['~', 'all', ''],
  ]);
  assert.equal(parseSpf('v=spf1 redirect=_spf.example.com').terms[0].kind, 'modifier');
});

test('parseSpf reports unknown mechanisms and bad networks', () => {
  const { errors } = parseSpf('v=spf1 ip4:999.1.1.1 ip4:10.0.0.0/40 inlcude:x.example -all');
  assert.equal(errors.length, 3);
});

test('SPF: missing record is critical', async () => {
  const spf = await analyzeSpf('example.com', fakeDns({ 'TXT example.com': ['google-site-verification=abc'] }));
  assert.equal(spf.status, 'missing');
  assert.equal(spf.findings[0].severity, 'critical');
});

test('SPF: two records is a permanent error', async () => {
  const spf = await analyzeSpf('example.com', fakeDns({ 'TXT example.com': ['v=spf1 -all', 'v=spf1 mx -all'] }));
  assert.equal(spf.status, 'fail');
  assert.ok(titles(spf).some(t => t.includes('2 SPF records')));
});

test('SPF: lookups are counted through nested includes and the limit is enforced', async () => {
  const zone = {
    'TXT example.com': ['v=spf1 a mx include:one.example include:two.example -all'],
    'TXT one.example': ['v=spf1 include:three.example exists:%{i}.x.example ~all'],
    'TXT two.example': ['v=spf1 ip4:192.0.2.1 -all'],
    'TXT three.example': ['v=spf1 a mx ptr -all'],
  };
  const spf = await analyzeSpf('example.com', fakeDns(zone));
  // a, mx, include one, include two = 4; one: include three, exists = 2; three: a, mx, ptr = 3.
  assert.equal(spf.lookups, 9);
  assert.equal(spf.includes.find(n => n.domain === 'one.example').lookups, 5);
  assert.equal(spf.status, 'warn');

  zone['TXT two.example'] = ['v=spf1 a mx -all'];
  const over = await analyzeSpf('example.com', fakeDns(zone));
  assert.equal(over.lookups, 11);
  assert.equal(over.status, 'fail');
  assert.ok(titles(over).some(t => t.includes('needs 11 DNS lookups')));
});

test('SPF: include loops and includes without a record are critical, and the walk terminates', async () => {
  const loop = await analyzeSpf('a.example', fakeDns({
    'TXT a.example': ['v=spf1 include:b.example -all'],
    'TXT b.example': ['v=spf1 include:a.example -all'],
  }));
  assert.ok(titles(loop).some(t => t.includes('include loop')));

  const broken = await analyzeSpf('a.example', fakeDns({ 'TXT a.example': ['v=spf1 include:gone.example -all'] }));
  assert.ok(titles(broken).some(t => t.includes('gone.example has no SPF record')));
  assert.equal(broken.status, 'fail');
});

test('SPF: +all is critical, ~all is informational, clean -all passes', async () => {
  const plus = await analyzeSpf('x.example', fakeDns({ 'TXT x.example': ['v=spf1 +all'] }));
  assert.equal(plus.status, 'fail');
  const soft = await analyzeSpf('x.example', fakeDns({ 'TXT x.example': ['v=spf1 mx ~all'] }));
  assert.equal(soft.status, 'pass');
  const hard = await analyzeSpf('x.example', fakeDns({ 'TXT x.example': ['v=spf1 ip4:192.0.2.1 -all'] }));
  assert.deepEqual(titles(hard), ['ok: SPF record is valid']);
});

test('SPF: resolver failure is reported as an error, not as missing', async () => {
  const spf = await analyzeSpf('x.example', fakeDns({}, { failing: ['TXT x.example'] }));
  assert.equal(spf.status, 'error');
});

test('DMARC: missing, none, reject', async () => {
  const missing = await analyzeDmarc('example.com', fakeDns({}));
  assert.equal(missing.status, 'missing');

  const none = await analyzeDmarc('example.com', fakeDns({ 'TXT _dmarc.example.com': ['v=DMARC1; p=none; rua=mailto:d@example.com'] }));
  assert.equal(none.status, 'warn');
  assert.equal(none.policy, 'none');

  const reject = await analyzeDmarc('example.com', fakeDns({ 'TXT _dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:d@example.com'] }));
  assert.equal(reject.status, 'pass');
  assert.deepEqual(titles(reject), ['ok: DMARC record is valid']);
});

test('DMARC: a subdomain inherits the parent policy and its sp= tag', async () => {
  const dmarc = await analyzeDmarc('mail.eu.example.com', fakeDns({ 'TXT _dmarc.example.com': ['v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com'] }));
  assert.equal(dmarc.inherited, true);
  assert.equal(dmarc.source_domain, 'example.com');
  assert.equal(dmarc.policy, 'quarantine');
});

test('DMARC: invalid policy, pct below 100, missing rua, unauthorized external rua', async () => {
  const bad = await analyzeDmarc('example.com', fakeDns({ 'TXT _dmarc.example.com': ['v=DMARC1; p=block'] }));
  assert.equal(bad.status, 'fail');

  const partial = await analyzeDmarc('example.com', fakeDns({ 'TXT _dmarc.example.com': ['v=DMARC1; p=quarantine; pct=25'] }));
  assert.ok(titles(partial).some(t => t.includes('25%')));
  assert.ok(titles(partial).some(t => t.includes('No aggregate report address')));

  const zone = { 'TXT _dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:r@reports.example.net'] };
  const external = await analyzeDmarc('example.com', fakeDns(zone));
  assert.ok(titles(external).some(t => t.includes('has not authorized reports')));
  zone['TXT example.com._report._dmarc.reports.example.net'] = ['v=DMARC1'];
  const authorized = await analyzeDmarc('example.com', fakeDns(zone));
  assert.equal(authorized.status, 'pass');
});

function dkimRecord(bits) {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: bits });
  return `v=DKIM1; k=rsa; p=${publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}`;
}

test('DKIM: key size is read from the published key', async () => {
  assert.equal(parseDkimKey(dkimRecord(2048)).key_bits, 2048);
  assert.equal(parseDkimKey(dkimRecord(1024)).key_bits, 1024);
  assert.equal(parseDkimKey('v=DKIM1; p=').revoked, true);
  assert.equal(parseDkimKey('v=DKIM1; k=rsa; p=bm90IGEga2V5').invalid, true);
  assert.equal(parseDkimKey('v=spf1 -all'), null);
  assert.equal(parseDkimKey(`v=DKIM1; k=ed25519; p=${Buffer.alloc(32, 7).toString('base64')}`).key_bits, 256);
});

test('DKIM: finds common and requested selectors, flags weak keys and missing requested selectors', async () => {
  const dns = fakeDns({
    'TXT selector1._domainkey.example.com': [dkimRecord(2048)],
    'TXT mycustom._domainkey.example.com': [`${dkimRecord(1024)}; t=y`],
  });
  const dkim = await analyzeDkim('example.com', dns, ['MyCustom', 'absent', 'bad selector!']);
  assert.deepEqual(dkim.found.map(k => k.selector).sort(), ['mycustom', 'selector1']);
  assert.equal(dkim.status, 'warn');
  assert.ok(titles(dkim).some(t => t.includes('1024-bit')));
  assert.ok(titles(dkim).some(t => t.includes('test mode')));
  assert.ok(titles(dkim).some(t => t.includes('No DKIM key at selector "absent"')));
  assert.ok(!dns.queries.some(q => q.includes('bad selector')));

  const none = await analyzeDkim('example.com', fakeDns({}));
  assert.equal(none.status, 'missing');
});

test('isSelector rejects anything that is not a DNS label sequence', () => {
  assert.ok(isSelector('selector1'));
  assert.ok(isSelector('s1.sub'));
  for (const bad of ['', 'a b', 'x;y', '-lead', 'trail-', '../x', 'a'.repeat(70)]) assert.ok(!isSelector(bad), bad);
});

test('MX: null MX, missing MX, unresolvable host, provider detection', async () => {
  const nullMx = await analyzeMx('example.com', fakeDns({ 'MX example.com': [{ exchange: '', priority: 0 }] }));
  assert.equal(nullMx.null_mx, true);

  const noMx = await analyzeMx('example.com', fakeDns({ 'A example.com': ['192.0.2.1'] }));
  assert.equal(noMx.status, 'warn');

  const dead = await analyzeMx('example.com', fakeDns({ 'MX example.com': [{ exchange: 'mx.example.com', priority: 10 }] }));
  assert.equal(dead.status, 'fail');

  const google = await analyzeMx('example.com', fakeDns({
    'MX example.com': [{ exchange: 'alt1.aspmx.l.google.com', priority: 5 }, { exchange: 'aspmx.l.google.com', priority: 1 }],
    'A aspmx.l.google.com': ['192.0.2.10'], 'A alt1.aspmx.l.google.com': ['192.0.2.11'],
  }));
  assert.equal(google.provider, 'Google Workspace');
  assert.equal(google.records[0].exchange, 'aspmx.l.google.com');
  assert.equal(google.status, 'pass');
});

test('MTA-STS: record without a reachable policy file is a warning; enforce passes', async () => {
  const dns = fakeDns({ 'TXT _mta-sts.example.com': ['v=STSv1; id=20261127'] });
  const broken = await analyzeMtaSts('example.com', dns, async () => { throw new Error('HTTP 404'); });
  assert.equal(broken.status, 'warn');

  let requested = '';
  const ok = await analyzeMtaSts('example.com', dns, async url => { requested = url; return 'version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n'; });
  assert.equal(requested, 'https://mta-sts.example.com/.well-known/mta-sts.txt');
  assert.equal(ok.status, 'pass');
  assert.deepEqual(ok.policy, { version: 'STSv1', mode: 'enforce', mx: ['mx.example.com'], max_age: 604800 });
});

test('analyzeEmailAuth combines every section and counts findings', async () => {
  const result = await analyzeEmailAuth('example.com', {
    dns: fakeDns({
      'MX example.com': [{ exchange: 'mx.example.com', priority: 10 }],
      'A mx.example.com': ['192.0.2.5'],
      'TXT example.com': ['v=spf1 mx -all'],
      'TXT _dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:d@example.com'],
    }),
    fetchPolicy: async () => { throw new Error('unused'); },
  });
  assert.deepEqual(Object.keys(result).filter(k => typeof result[k] === 'object').sort(), ['bimi', 'dkim', 'dmarc', 'mta_sts', 'mx', 'spf', 'summary', 'tls_rpt']);
  assert.equal(result.spf.status, 'pass');
  assert.equal(result.dmarc.status, 'pass');
  assert.equal(result.summary.critical, 0);
  assert.ok(result.summary.info > 0);
});
