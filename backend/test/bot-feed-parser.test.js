import test from 'node:test';
import assert from 'node:assert/strict';
import { isIP } from 'node:net';
import { mkdtempSync, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

// The module reads this when it is loaded.
process.env.GEOIP_PUBLIC_DIR = mkdtempSync(path.join(os.tmpdir(), 'bot-feed-'));
const { parseFeedContent, compileVerifiedBotsJson } = await import('../src/lib/bot-ip-updater.js');

test.describe('plain-text feed parser', () => {
  test('IPv6 in every notation is kept', () => {
    const { ipv6 } = parseFeedContent([
      '2a01:4f8:1c1a:3d53::1',
      '2a02:6b8::/29',
      '<li>2a02:6b8:c00::/40</li>',
      '2406:da14:94d:8601:9d0d:7754:bedf:e4f5',
      '2001:4860:4801:10::/64, 2001:4860:4801:12::/64.',
    ].join('\n'), 'plain_text');
    assert.deepEqual(ipv6, [
      '2001:4860:4801:10::/64', '2001:4860:4801:12::/64', '2406:da14:94d:8601:9d0d:7754:bedf:e4f5/128',
      '2a01:4f8:1c1a:3d53::1/128', '2a02:6b8::/29', '2a02:6b8:c00::/40',
    ]);
  });

  test('IPv4 addresses and ranges are kept in list, HTML, JSON and SPF notation', () => {
    const { ipv4 } = parseFeedContent('5.255.253.0/24\n<td>77.88.0.0/18</td> "ip_prefix":"52.70.240.171/32", ip4:66.249.80.0/20 3.12.251.153.', 'plain_text');
    assert.deepEqual(ipv4, ['3.12.251.153/32', '5.255.253.0/24', '52.70.240.171/32', '66.249.80.0/20', '77.88.0.0/18']);
  });

  test('numbers that are not addresses are left out', () => {
    const page = `<script src="/js/jquery-3.7.1.2.min.js"></script> <link href="https://cdn.example/lib/4.6.2.1/app.css">
      updated at 12:30:45, MAC aa:bb:cc:dd:ee:ff, std::string, a::before { }, http://10.1.2.3/path, 999.1.1.1, 1.2.3.4:8080`;
    assert.deepEqual(parseFeedContent(page, 'plain_text'), { ipv4: [], ipv6: [], total: 0 });
  });

  test('ranges that would cover most of the internet are refused', () => {
    assert.equal(parseFeedContent('0.0.0.0/0 1.0.0.0/7 ::/0 2000::/3 :: ::1', 'plain_text').total, 0);
    assert.equal(parseFeedContent(JSON.stringify({ prefixes: [{ ipv4Prefix: '0.0.0.0/0' }, { ipv6Prefix: '::/0' }] })).total, 0);
    assert.deepEqual(parseFeedContent('17.0.0.0/8 2a02:6b8::/29', 'plain_text'), { ipv4: ['17.0.0.0/8'], ipv6: ['2a02:6b8::/29'], total: 2 });
  });

  test('JSON feeds are read as before', () => {
    const google = JSON.stringify({ creationTime: '2026-11-01', prefixes: [{ ipv6Prefix: '2001:4860:4801:10::/64' }, { ipv4Prefix: '66.249.64.0/27' }] });
    assert.deepEqual(parseFeedContent(google), { ipv4: ['66.249.64.0/27'], ipv6: ['2001:4860:4801:10::/64'], total: 2 });
  });
});

test('every built-in fallback range is a complete, valid range', async () => {
  const pool = { execute: async () => [[]] }; // no synced source: the fallbacks are all there is
  const compiled = await compileVerifiedBotsJson(pool);
  const onDisk = JSON.parse(readFileSync(path.join(process.env.GEOIP_PUBLIC_DIR, 'verified-bots.json'), 'utf8'));
  assert.equal(onDisk.total_cidrs, compiled.total_cidrs);

  const problems = [];
  for (const [key, bot] of Object.entries(compiled.bots)) {
    if (bot.total_cidrs !== bot.ipv4.length + bot.ipv6.length) problems.push(`${key}: total_cidrs ${bot.total_cidrs}, listed ${bot.ipv4.length + bot.ipv6.length}`);
    for (const [family, list] of [[4, bot.ipv4], [6, bot.ipv6]]) {
      for (const cidr of list) {
        const [address, mask] = cidr.split('/');
        const max = family === 4 ? 32 : 128;
        if (isIP(address) !== family || (mask !== undefined && !(Number(mask) >= 8 && Number(mask) <= max))) problems.push(`${key}: ${cidr}`);
      }
    }
  }
  assert.deepEqual(problems, []);
  assert.ok(compiled.bots.uptimerobot.ipv6.includes('2a01:4f8:1c1a:3d53::1/128'));

  // The browser must be able to use every one of them.
  const BotDetector = createRequire(import.meta.url)('../../frontend/public/js/bot-detector.js');
  assert.equal(BotDetector.loadData(compiled), true);
  const loaded = Object.fromEntries(BotDetector.getBotStats().sources.map(s => [s.key, s.totalCidrs]));
  for (const [key, bot] of Object.entries(compiled.bots)) assert.equal(loaded[key], bot.total_cidrs, `${key}: ranges the browser could not read`);
  assert.equal(BotDetector.verifyBot('UptimeRobot', '2a01:4f8:1c1a:3d53::1').status, 'verified');
  assert.equal(BotDetector.verifyBot('UptimeRobot', '2a01:4f8:1c1a:3d53::2').status, 'spoofed');
});
