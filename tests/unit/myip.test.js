import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildMyIPReportHtml,
  buildMyIPExportData,
  normalizeMyIPSnapshot,
} from '../../frontend/src/lib/myip.ts';

const mockData = {
  ip: '203.0.113.195',
  ip_version: 'IPv4',
  city: 'San Francisco',
  region: 'California',
  region_code: 'CA',
  country: 'United States',
  country_code: 'US',
  registered_country: 'United States',
  registered_country_code: 'US',
  represented_country: null,
  represented_country_code: null,
  represented_country_type: null,
  continent: 'North America',
  continent_code: 'NA',
  postal_code: '94107',
  accuracy_radius: 20,
  latitude: 37.7749,
  longitude: -122.4194,
  metro_code: 807,
  timezone: 'America/Los_Angeles',
  utc_offset: '-08:00',
  isp: 'Cloudflare, Inc.',
  org: 'Cloudflare, Inc.',
  asn: 13335,
  asn_name: 'AS13335 Cloudflare, Inc.',
  domain: 'cloudflare.com',
  usage_type: 'Data Center/Web Hosting/Transit',
  proxy_type: null,
  proxy_detected: false,
  reverse_dns: 'one.one.one.one',
  network_type: 'hosting',
  data_sources: { maxmind: 'GeoLite2' },
  headers: {
    user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    accept_language: 'en-US,en;q=0.9',
    accept_encoding: 'gzip, deflate, br',
    referer: '',
    dnt: '1',
  },
  checked_at_utc: '2026-11-25T12:00:00Z',
};

const mockClientInfo = {
  browser: 'Chrome 130.0',
  os: 'Windows 11',
  screen: '1920x1080',
  language: 'en-US',
  dnt: 'Enabled',
  cookies: 'Enabled',
  webgl: 'ANGLE (Direct3D11)',
  platform: 'Win32',
  connection: {
    type: 'wifi',
    effectiveType: '4g',
    downlink: 10,
    rtt: 50,
    saveData: false,
    supported: true,
  },
};

test('buildMyIPReportHtml includes both IPv4 and IPv6 cards when both are detected', () => {
  const html = buildMyIPReportHtml(mockData, mockClientInfo, {
    ipv4: '203.0.113.195',
    ipv6: '2001:db8::8a2e:370:7334',
  });

  assert.ok(html.includes('203.0.113.195'), 'Should contain IPv4 address');
  assert.ok(html.includes('2001:db8::8a2e:370:7334'), 'Should contain IPv6 address');
  assert.ok(html.includes('Dual-Stack (IPv4 + IPv6)'), 'Should contain dual-stack badge');
});

test('buildMyIPReportHtml shows IPv6 Not Detected card when IPv6 is null', () => {
  const html = buildMyIPReportHtml(mockData, mockClientInfo, {
    ipv4: '203.0.113.195',
    ipv6: null,
  });

  assert.ok(html.includes('203.0.113.195'), 'Should contain IPv4 address');
  assert.ok(html.includes('Not Detected'), 'Should indicate IPv6 Not Detected');
  assert.ok(html.includes('Your network does not support IPv6'), 'Should explain IPv6 is not supported');
  assert.ok(html.includes('IPv4 Only'), 'Should contain IPv4 Only badge');
});

test('buildMyIPReportHtml places Browser & Device, then HTTP Headers, then Browser-Estimated Connection', () => {
  const html = buildMyIPReportHtml(mockData, mockClientInfo, {
    ipv4: '203.0.113.195',
    ipv6: null,
  });

  const deviceIdx = html.indexOf('Browser & Device');
  const headersIdx = html.indexOf('HTTP Request Headers');
  const connectionIdx = html.indexOf('Browser-Estimated Connection');

  assert.ok(deviceIdx !== -1, 'Must include Browser & Device section');
  assert.ok(headersIdx !== -1, 'Must include HTTP Request Headers section');
  assert.ok(connectionIdx !== -1, 'Must include Browser-Estimated Connection section');

  assert.ok(deviceIdx < headersIdx, 'Browser & Device must appear before HTTP Request Headers');
  assert.ok(headersIdx < connectionIdx, 'HTTP Request Headers must appear before Browser-Estimated Connection');
});

test('buildMyIPExportData includes ipv4, ipv6, and ip_stack status in CSV payload', () => {
  const csvData = buildMyIPExportData(mockData, {
    ipv4: '203.0.113.195',
    ipv6: null,
  });

  assert.equal(csvData.ipv4, '203.0.113.195');
  assert.equal(csvData.ipv6, 'Not Detected');
  assert.equal(csvData.ip_stack, 'IPv4 Only');
});

test('normalizeMyIPSnapshot extracts ipv4 and ipv6 from snapshot payload', () => {
  const snapshot = normalizeMyIPSnapshot({
    ...mockData,
    ipv4: '203.0.113.195',
    ipv6: '2001:db8::1',
  });

  assert.equal(snapshot.ipv4, '203.0.113.195');
  assert.equal(snapshot.ipv6, '2001:db8::1');
  assert.equal(snapshot.isDualStack, true);
});

test('normalizeMyIPSnapshot falls back to d.ip when ipv4/ipv6 fields are missing from legacy share', () => {
  const snapshot = normalizeMyIPSnapshot({
    ...mockData,
    ip: '198.51.100.1',
    ip_version: 'IPv4',
  });

  assert.equal(snapshot.ipv4, '198.51.100.1');
  assert.equal(snapshot.ipv6, null);
  assert.equal(snapshot.isDualStack, false);
});
