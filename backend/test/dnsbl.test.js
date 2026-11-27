import test from 'node:test';
import assert from 'node:assert/strict';
import { createDnsblChecker, reverseIp } from '../src/lib/dnsbl.js';

function fakeDns(zone, { failing = [] } = {}) {
  const queries = [];
  const answer = (type, name) => {
    queries.push(`${type} ${name}`);
    if (failing.some(suffix => name.endsWith(suffix))) return { status: 'error', records: [], error: 'ETIMEOUT' };
    const records = zone[`${type} ${name}`];
    return records ? { status: 'ok', records } : { status: 'nxdomain', records: [] };
  };
  return { queries, a: async name => answer('A', name), txt: async name => answer('TXT', name) };
}

const healthy = zone => ({ [`A 2.0.0.127.${zone}`]: ['127.0.0.2'] });
const LISTS = [
  { zone: 'good.test', name: 'Good' },
  { zone: 'codes.test', name: 'Codes', ipv6: true, codes: { '127.0.0.10': { label: 'Policy range', policy: true }, '127.0.0.2': { label: 'Spam source' } } },
];

test('reverseIp handles IPv4 and expands IPv6 to nibbles', () => {
  assert.equal(reverseIp('192.0.2.10'), '10.2.0.192');
  assert.equal(reverseIp('2001:db8::1'), '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2');
  assert.equal(reverseIp('::1').split('.').length, 32);
  assert.equal(reverseIp('not-an-ip'), '');
});

test('a healthy list reports listed and clean addresses, with the list reason', async () => {
  const dns = fakeDns({
    ...healthy('good.test'), ...healthy('codes.test'),
    'A 10.2.0.192.good.test': ['127.0.0.2'],
    'TXT 10.2.0.192.good.test': ['Listed for spam, see https://good.test/lookup'],
  });
  const checker = createDnsblChecker({ dns, ipLists: LISTS, domainLists: [] });
  const result = await checker.checkIp('192.0.2.10');
  assert.deepEqual(result.results.map(r => [r.zone, r.status]), [['good.test', 'listed'], ['codes.test', 'clean']]);
  assert.match(result.results[0].reason, /Listed for spam/);
  assert.deepEqual(result.summary, { listed: 1, policy: 0, clean: 1, unavailable: 0, total: 2 });
});

test('policy-only return codes are not counted as spam listings', async () => {
  const dns = fakeDns({ ...healthy('good.test'), ...healthy('codes.test'), 'A 10.2.0.192.codes.test': ['127.0.0.10'] });
  const result = await createDnsblChecker({ dns, ipLists: LISTS, domainLists: [] }).checkIp('192.0.2.10');
  assert.equal(result.results[1].status, 'policy');
  assert.equal(result.results[1].detail, 'Policy range');
  assert.equal(result.summary.listed, 0);

  const mixed = fakeDns({ ...healthy('good.test'), ...healthy('codes.test'), 'A 10.2.0.192.codes.test': ['127.0.0.10', '127.0.0.2'] });
  const both = await createDnsblChecker({ dns: mixed, ipLists: LISTS, domainLists: [] }).checkIp('192.0.2.10');
  assert.equal(both.results[1].status, 'listed');
});

test('a list that fails its self-test is unavailable, never clean or listed', async () => {
  // dead.test answers nothing at all; wild.test lists every address; refuse.test returns the refusal code.
  const lists = [{ zone: 'dead.test', name: 'Dead' }, { zone: 'wild.test', name: 'Wildcard' }, { zone: 'refuse.test', name: 'Refuses' }, { zone: 'down.test', name: 'Down' }];
  const dns = fakeDns({
    'A 2.0.0.127.wild.test': ['127.0.0.2'], 'A 1.0.0.127.wild.test': ['127.0.0.2'], 'A 10.2.0.192.wild.test': ['127.0.0.2'],
    'A 2.0.0.127.refuse.test': ['127.255.255.254'], 'A 1.0.0.127.refuse.test': ['127.255.255.254'], 'A 10.2.0.192.refuse.test': ['127.255.255.254'],
  }, { failing: ['down.test'] });
  const result = await createDnsblChecker({ dns, ipLists: lists, domainLists: [] }).checkIp('192.0.2.10');
  assert.deepEqual(result.results.map(r => r.status), ['unavailable', 'unavailable', 'unavailable', 'unavailable']);
  assert.match(result.results[1].detail, /every address/);
  assert.match(result.results[2].detail, /refuses queries/);
  assert.equal(result.summary.unavailable, 4);
  // The target itself is never queried on a list that failed the self-test.
  assert.ok(!dns.queries.includes('A 10.2.0.192.dead.test'));
});

test('self-test results are cached for an hour', async () => {
  let clock = 0;
  const dns = fakeDns({ ...healthy('good.test') });
  const checker = createDnsblChecker({ dns, now: () => clock, ipLists: [LISTS[0]], domainLists: [] });
  await checker.checkIp('192.0.2.10');
  await checker.checkIp('192.0.2.11');
  assert.equal(dns.queries.filter(q => q === 'A 2.0.0.127.good.test').length, 1);
  clock += 61 * 60 * 1000;
  await checker.checkIp('192.0.2.12');
  assert.equal(dns.queries.filter(q => q === 'A 2.0.0.127.good.test').length, 2);
});

test('IPv6 addresses are only checked on lists that support IPv6', async () => {
  const dns = fakeDns({ ...healthy('good.test'), ...healthy('codes.test') });
  const result = await createDnsblChecker({ dns, ipLists: LISTS, domainLists: [] }).checkIp('2001:db8::1');
  assert.deepEqual(result.results.map(r => r.zone), ['codes.test']);
});

test('domain lists use the operator test point as their self-test', async () => {
  const lists = [{ zone: 'dbl.test', name: 'DBL', test: 'testpoint.example' }, { zone: 'off.test', name: 'Off', test: 'testpoint.example' }];
  const dns = fakeDns({ 'A testpoint.example.dbl.test': ['127.0.1.2'], 'A bad.example.dbl.test': ['127.0.1.2'] });
  const checker = createDnsblChecker({ dns, ipLists: [], domainLists: lists });
  assert.deepEqual((await checker.checkDomain('bad.example')).results.map(r => r.status), ['listed', 'unavailable']);
  assert.deepEqual((await checker.checkDomain('fine.example')).results.map(r => r.status), ['clean', 'unavailable']);
});
