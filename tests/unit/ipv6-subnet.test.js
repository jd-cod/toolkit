import test from 'node:test';
import assert from 'node:assert/strict';
import { expandIpv6, formatIpv6, parseIpv6, parseIpv6Cidr, readableCount, splitIpv6 } from '../../frontend/src/lib/tools/ipv6-subnet.ts';

test('parseIpv6 accepts every valid spelling and rejects the rest', () => {
  assert.equal(parseIpv6('::'), 0n);
  assert.equal(parseIpv6('::1'), 1n);
  assert.equal(parseIpv6('2001:db8::'), 0x20010db8n << 96n);
  assert.equal(parseIpv6('2001:0DB8:0000:0000:0000:0000:0000:0001'), (0x20010db8n << 96n) | 1n);
  assert.equal(parseIpv6('::ffff:192.0.2.1'), 0xffffc0000201n);
  assert.equal(parseIpv6('fe80::1%eth0'), (0xfe80n << 112n) | 1n);
  for (const bad of ['', ':', ':::', '1::2::3', '2001:db8', '1:2:3:4:5:6:7:8:9', '12345::', 'g::1', '::ffff:300.1.1.1', '1:2:3:4:5:6:7::8', '192.0.2.1']) {
    assert.equal(parseIpv6(bad), null, bad);
  }
});

test('formatIpv6 follows RFC 5952', () => {
  const round = text => formatIpv6(parseIpv6(text));
  assert.equal(round('2001:0db8:0000:0000:0000:0000:0000:0001'), '2001:db8::1');
  assert.equal(round('2001:db8:0:1:0:0:0:1'), '2001:db8:0:1::1');
  assert.equal(round('2001:db8:0:0:1:0:0:1'), '2001:db8::1:0:0:1');
  assert.equal(round('2001:db8:0:1:1:1:1:1'), '2001:db8:0:1:1:1:1:1');
  assert.equal(round('0:0:0:0:0:0:0:0'), '::');
  assert.equal(round('1:0:0:0:0:0:0:0'), '1::');
  assert.equal(expandIpv6(parseIpv6('2001:db8::1')), '2001:0db8:0000:0000:0000:0000:0000:0001');
});

test('a /48 site allocation', () => {
  const subnet = parseIpv6Cidr('2001:db8:abcd:12::5/48');
  assert.equal(subnet.cidr, '2001:db8:abcd::/48');
  assert.equal(subnet.first, '2001:db8:abcd::');
  assert.equal(subnet.last, '2001:db8:abcd:ffff:ffff:ffff:ffff:ffff');
  assert.equal(subnet.totalAddresses, (2n ** 80n).toString());
  assert.equal(subnet.subnets64, '65,536');
  assert.equal(subnet.type, 'Documentation');
  assert.equal(subnet.reverseZone, 'd.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa');
  assert.ok(subnet.notes.some(note => note.includes('host bits')));
});

test('prefix edge cases: /0, /64, /127, /128 and a bare address', () => {
  assert.equal(parseIpv6Cidr('::/0').last, 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');
  assert.equal(parseIpv6Cidr('::/0').totalAddresses, (2n ** 128n).toString());
  const lan = parseIpv6Cidr('2a00:1450:4001:81b::/64');
  assert.equal(lan.totalAddresses, '18446744073709551616');
  assert.equal(lan.totalReadable, '18.4 quintillion');
  assert.equal(lan.subnets64, '1');
  assert.equal(lan.type, 'Global unicast');
  assert.equal(parseIpv6Cidr('2001:db8::/127').last, '2001:db8::1');
  assert.equal(parseIpv6Cidr('2001:db8::1').prefix, 128);
  assert.equal(parseIpv6Cidr('2001:db8::1').totalAddresses, '1');
  assert.equal(parseIpv6Cidr('2001:db8::/65').subnets64, '');
  assert.equal(parseIpv6Cidr('2001:db8::/45').reverseZone, '');
});

test('address types', () => {
  const type = cidr => parseIpv6Cidr(cidr).type;
  assert.equal(type('fd12:3456:789a::/48'), 'Unique local (ULA)');
  assert.equal(type('fe80::1/64'), 'Link-local');
  assert.equal(type('ff02::1'), 'Multicast');
  assert.equal(type('::1'), 'Loopback');
  assert.equal(type('2002:c000:204::/48'), '6to4');
  assert.equal(type('2606:4700::/32'), 'Global unicast');
  assert.equal(type('4000::/3'), 'Reserved');
});

test('invalid CIDR input returns null', () => {
  for (const bad of ['', '2001:db8::/129', '2001:db8::/-1', '2001:db8::/x', '10.0.0.0/8', '2001:db8::/', 'zz::/64']) assert.equal(parseIpv6Cidr(bad), null, bad);
});

test('splitIpv6 lists the first subnets and respects the parent size', () => {
  assert.deepEqual(splitIpv6('2001:db8:abcd::/48', 64, 3), ['2001:db8:abcd::/64', '2001:db8:abcd:1::/64', '2001:db8:abcd:2::/64']);
  assert.deepEqual(splitIpv6('2001:db8::/126', 127, 8), ['2001:db8::/127', '2001:db8::2/127']);
  assert.deepEqual(splitIpv6('2001:db8::/64', 48), []);
  assert.deepEqual(splitIpv6('nonsense', 64), []);
});

test('readableCount', () => {
  assert.equal(readableCount(256n), '256');
  assert.equal(readableCount(65536n), '65,536');
  assert.equal(readableCount(2n ** 32n), '4.2 billion');
  assert.equal(readableCount(2n ** 80n), '1.2 septillion');
});
