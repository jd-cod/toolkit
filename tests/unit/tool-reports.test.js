import test from 'node:test';
import assert from 'node:assert/strict';
import { buildSslReportHtml, buildSslRerunHref, normalizeSslSnapshot } from '../../frontend/src/lib/ssl.ts';
import { buildIpInfoReportHtml, ipInfoCounts, ipInfoSubject, normalizeIpInfoSnapshot } from '../../frontend/src/lib/ipinfo.ts';
import { buildSubnetReportHtml, buildSubnetSummary, normalizeSubnetSnapshot, parseCIDR, subnetDetailRows } from '../../frontend/src/lib/subnet.ts';
import { buildCronReportHtml, cronCsvRows, describeCron, getNextRuns, normalizeCronSnapshot, parseCron } from '../../frontend/src/lib/cron.ts';
import { buildChmodReportHtml, chmodCsvRows, chmodWarnings, normalizeChmodSnapshot, parseOctalMode, toSymbolic } from '../../frontend/src/lib/chmod.ts';
import { buildDnsSnapshotHtml, dnsSnapshotCsvRows } from '../../frontend/src/lib/dns.ts';
import { buildWhoisSnapshotHtml } from '../../frontend/src/lib/whois.ts';
import { asnPrefixCsvRows, buildAsnSnapshotHtml, normalizeAsnSnapshot } from '../../frontend/src/lib/asn.ts';

const HOSTILE = '<script>alert(1)</script>';
const assertSafe = (html) => assert.equal(html.includes('<script>'), false, 'report must escape hostile values');

test('shared snapshots survive missing or malformed stored data', () => {
  for (const raw of [null, undefined, 'text', 42, [], { results: 'nope' }, { chain: [null], san_names: [1, 'ok'] }]) {
    assert.doesNotThrow(() => buildSslReportHtml(normalizeSslSnapshot(raw)));
    assert.doesNotThrow(() => buildIpInfoReportHtml(normalizeIpInfoSnapshot(raw)));
    assert.doesNotThrow(() => normalizeSubnetSnapshot(raw));
    assert.doesNotThrow(() => normalizeCronSnapshot(raw));
    assert.doesNotThrow(() => normalizeChmodSnapshot(raw));
  }
  assert.deepEqual(normalizeSslSnapshot({ san_names: [1, 'ok'] }).san_names, ['ok']);
  assert.equal(normalizeChmodSnapshot({ octal: '999' }).octal, '');
  assert.equal(normalizeChmodSnapshot({ octal: '4755' }).octal, '4755');
});

test('SSL report: content, rerun link and escaping', () => {
  const snapshot = normalizeSslSnapshot({
    domain: 'example.com', port: 8443, grade: 'A+', days_remaining: 88, protocol: 'TLSv1.3', key_type: 'EC', key_size: 256,
    subject: HOSTILE, issuer: 'Test CA', is_trusted: true, hostname_match: true, san_names: ['example.com', HOSTILE],
    chain: [{ subject: 'example.com', issuer: 'Test CA' }, { subject: 'Test CA', issuer: 'Root' }],
    checked_at_utc: '2026-11-26T10:00:00.000Z',
  });
  const html = buildSslReportHtml(snapshot);
  assertSafe(html);
  assert.ok(html.includes('example.com:8443'));
  assert.ok(html.includes('A+'));
  assert.ok(html.includes('Expires in 88 days'));
  assert.ok(html.includes('Checked at 2026-11-26 10:00:00 UTC'));
  assert.equal(buildSslRerunHref(snapshot), '/ssl?domain=example.com&port=8443');
  assert.equal(buildSslRerunHref({ domain: 'example.com', port: 443 }), '/ssl?domain=example.com');
});

test('IP Info report: counts, subject and dropped junk rows', () => {
  const snapshot = normalizeIpInfoSnapshot({
    checked_at_utc: '2026-11-26T10:00:00.000Z',
    results: [
      { ip: '1.1.1.1', reverse_dns: 'one.one.one.one', risk_level: 'low', abuse_score: 0, isp: 'Cloudflare', country_code: 'US' },
      { ip: '203.0.113.9', risk_level: 'high', abuse_score: 90, total_reports: 12, isp: HOSTILE, risk_reasons: ['Listed', 7] },
      { nope: true },
      null,
    ],
  });
  assert.equal(snapshot.results.length, 2);
  assert.deepEqual(ipInfoCounts(snapshot.results), { total: 2, rdns: 1, risk: 1, abuse: 1 });
  assert.equal(ipInfoSubject(snapshot.results), '1.1.1.1 +1 more');
  assert.deepEqual(snapshot.results[1].risk_reasons, ['Listed']);
  const html = buildIpInfoReportHtml(snapshot);
  assertSafe(html);
  assert.ok(html.includes('one.one.one.one'));
  assert.ok(html.includes('90%'));
});

test('subnet: shared links recompute from the CIDR alone', () => {
  const snapshot = normalizeSubnetSnapshot({ cidr: '10.0.0.0/24', aws_mode: 1 });
  const result = parseCIDR(snapshot.cidr);
  assert.equal(result.usableHosts, 254);
  assert.equal(result.broadcastStr, '10.0.0.255');
  assert.ok(subnetDetailRows(result, true).some(([label, value]) => label === 'AWS Usable Hosts' && value === '249'));
  assert.equal(subnetDetailRows(result, false).some(([label]) => label === 'AWS Usable Hosts'), false);
  assert.ok(buildSubnetSummary(result, true).includes('AWS Usable Hosts: 249'));
  const html = buildSubnetReportHtml(result, true, '2026-11-26T10:00:00.000Z');
  assert.ok(html.includes('10.0.0.0/24'));
  assert.ok(html.includes('AWS Usable Hosts'));
  assert.equal(parseCIDR(normalizeSubnetSnapshot({ cidr: HOSTILE }).cidr), null);
});

test('cron: description, upcoming runs and exports', () => {
  assert.equal(parseCron('not a cron'), null);
  assert.equal(describeCron('0 3 * * *'), 'At 3:00 AM');
  const from = new Date(2026, 10, 26, 10, 7, 0);
  const runs = getNextRuns('*/15 * * * *', 3, from);
  assert.deepEqual(runs.map((d) => [d.getHours(), d.getMinutes()]), [[10, 15], [10, 30], [10, 45]]);
  const rows = cronCsvRows('*/15 * * * *', runs);
  assert.equal(rows.length, 3);
  assert.equal(rows[0].run, 1);
  assert.equal(rows[0].expression, '*/15 * * * *');
  const html = buildCronReportHtml('*/15 * * * *', runs, '2026-11-26T10:00:00.000Z');
  assert.ok(html.includes('Every 15 minutes'));
  assert.ok(html.includes('Next 3 Executions'));
  assertSafe(buildCronReportHtml(HOSTILE, []));
  assert.equal(normalizeCronSnapshot({ expression: '  0 0 * * *  ' }).expression, '0 0 * * *');
});

test('chmod: modes, warnings and exports', () => {
  assert.equal(parseOctalMode('75'), null);
  assert.deepEqual(parseOctalMode('4755'), { bits: [7, 5, 5], special: 4 });
  assert.equal(toSymbolic([7, 5, 5], 4), 'rwsr-xr-x');
  assert.equal(chmodWarnings([7, 7, 7], 0)[0].level, 'danger');
  assert.deepEqual(chmodWarnings([6, 4, 4], 0), []);
  const rows = chmodCsvRows('640');
  assert.deepEqual(rows.map((row) => [row.role, row.read, row.write, row.execute]), [['Owner', true, true, false], ['Group', true, false, false], ['Others', false, false, false]]);
  const html = buildChmodReportHtml('777', '2026-11-26T10:00:00.000Z');
  assert.ok(html.includes('rwxrwxrwx'));
  assert.ok(html.includes('major security risk'));
  assertSafe(buildChmodReportHtml(HOSTILE));
});

test('DNS, WHOIS and ASN reports use the shared shell and escape their data', () => {
  const provider = { name: HOSTILE, confidence: 'high', source: 'NS' };
  const dns = {
    domain: 'example.com', resolver: '1.1.1.1', resolver_name: 'Cloudflare', selected_types: ['A', 'MX'], checked_at_utc: '2026-11-26T10:00:00.000Z',
    total_records: 2, dns_provider: provider, hosting_provider: provider,
    results: [
      { _type: 'MX', _queryTime: 5, error: '', message: '', records: [{ data: 'mail.example.com', TTL: 300, priority: 10 }] },
      { _type: 'A', _queryTime: 4, error: '', message: '', records: [{ data: '192.0.2.1', TTL: 60, country: 'US', provider_label: HOSTILE }] },
      { _type: 'TXT', _queryTime: 3, error: 'SERVFAIL', message: '', records: [] },
    ],
  };
  const dnsHtml = buildDnsSnapshotHtml(dns);
  assertSafe(dnsHtml);
  assert.ok(dnsHtml.includes('Generated by SysAdmin Toolkit'));
  assert.ok(dnsHtml.indexOf('A Records') < dnsHtml.indexOf('MX Records'), 'record types keep their usual order');
  assert.ok(dnsHtml.includes('SERVFAIL'));
  const csv = dnsSnapshotCsvRows(dns);
  assert.equal(csv.length, 3);
  assert.equal(csv.find((row) => row.type === 'TXT').record, 'Error: SERVFAIL');

  const whoisHtml = buildWhoisSnapshotHtml({
    domain: 'example.com', data_source: 'rdap', checked_at_utc: '2026-11-26T10:00:00.000Z', registered: true, registrar: HOSTILE,
    days_until_expiry: 30, dnssec: 'signed', status_labels: ['ok'], nameservers: ['a.ns'], dns_nameservers: [], nameserver_match: null,
    risk_signals: [HOSTILE], raw_response: HOSTILE,
  });
  assertSafe(whoisHtml);
  assert.ok(whoisHtml.includes('RDAP Snapshot'));

  const asn = normalizeAsnSnapshot({ asn: '64500', name: HOSTILE, ipv4_prefixes: ['192.0.2.0/24'], ipv6_prefixes: ['2001:db8::/32'], checked_at_utc: '2026-11-26T10:00:00.000Z' });
  const asnHtml = buildAsnSnapshotHtml(asn);
  assertSafe(asnHtml);
  assert.ok(asnHtml.includes('192.0.2.0/24'));
  assert.ok(asnHtml.includes('2001:db8::/32'));
  assert.deepEqual(asnPrefixCsvRows(asn).map((row) => [row.prefix, row.ip_version]), [['192.0.2.0/24', 'ipv4'], ['2001:db8::/32', 'ipv6']]);
});
