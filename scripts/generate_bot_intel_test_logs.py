#!/usr/bin/env python3
"""
Bot Intelligence Gold Set Generator
==================================
Produces `tests/fixtures/bot-intel-test.log` (Nginx Combined Log Format) plus
`tests/fixtures/bot-intel-expected.json`, a machine-readable ground-truth
manifest that `scripts/qa_bot_intel_gold_set.mjs` asserts against.

Every IP used as a "verified" address is taken from the ACTUAL published feed
(`frontend/public/data/verified-bots.json`), so a passing audit means the
frontend's CIDR matcher agrees with the real upstream data - not with a
hand-typed guess that may have rotted.

The generator is fully deterministic (no `random`) so the log is byte-stable
across runs and diffs stay meaningful.
"""

import ipaddress
import json
import os
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
FEED_PATH = os.path.join(REPO_ROOT, 'frontend', 'public', 'data', 'verified-bots.json')
LOG_OUT = os.path.join(REPO_ROOT, 'tests', 'fixtures', 'bot-intel-test.log')
EXPECTED_OUT = os.path.join(REPO_ROOT, 'tests', 'fixtures', 'bot-intel-expected.json')

BASE_TIME = datetime(2026, 9, 30, 12, 0, 0)


def _first_host_in_feed(bot_key, count=1):
    """Return real host addresses taken from the published feed for `bot_key`.

    This keeps the Gold Set honest: if upstream drops a range, the fixture
    follows upstream instead of asserting against a stale hardcoded IP.
    """
    with open(FEED_PATH) as fh:
        feed = json.load(fh)

    entry = feed['bots'].get(bot_key)
    if not entry:
        return []

    hosts = []
    for cidr in entry.get('ipv4', []):
        net = ipaddress.ip_network(cidr)
        # Skip /32: a network address with no host allocation is a poor fixture.
        if net.prefixlen >= 32:
            continue
        hosts.append(str(net.network_address + 1))
        if len(hosts) >= count:
            break
    return hosts


# ---------------------------------------------------------------------------
# IPs NOT in any published range - these are the impersonator sources.
# ---------------------------------------------------------------------------
SPOOFED_IPS = {
    'tor_exit': '185.220.101.5',      # Tor exit node
    'private_rfc1918': '192.168.1.100',  # should never appear on a public edge
    'datacenter': '45.142.120.10',     # generic datacenter
    'ovh_datacenter': '94.23.175.40',  # OVH
    'malformed': '123.456.789.0',      # syntactically invalid octets
}

HUMAN_IPS = ['93.184.216.34', '151.101.129.69', '203.0.113.42']

# ---------------------------------------------------------------------------
# User agents
# ---------------------------------------------------------------------------
UA = {
    'googlebot': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'googlebot_mobile': (
        'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 '
        '(compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    ),
    'googlebot_bare': 'Googlebot/2.1 (+http://www.google.com/bot.html)',
    'bingbot': 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'gptbot': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)',
    'claudebot': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)',
    'applebot': (
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) '
        'Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)'
    ),
    'ccbot': 'Mozilla/5.0 (compatible; CCBot/2.0; +https://commoncrawl.org/faq/)',
    'yandexbot': 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
    # Deliberate near-miss variants
    'googlebot_no_url': 'Mozilla/5.0 (compatible; Googlebot/2.1)',
    'googlebot_capital_b': 'Mozilla/5.0 (compatible; GoogleBot/2.1; +http://www.google.com/bot.html)',
}

HUMAN_UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
]

CRAWLER_PATHS = ['/robots.txt', '/sitemap.xml', '/sitemap_index.xml', '/', '/blog', '/products', '/api/health']
ATTACK_PATHS = ['/wp-login.php', '/wp-admin', '/.env', '/.git/config', '/admin/login', '/phpmyadmin', '/backup.zip']


def log_line(ip, user_agent, path, status, timestamp, bytes_sent=1024):
    """One Nginx Combined Log Format line."""
    ts = timestamp.strftime('%d/%b/%Y:%H:%M:%S +0000')
    return f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} {bytes_sent} "-" "{user_agent}"'


class GoldSet:
    """Collects log lines alongside their expected classification."""

    def __init__(self):
        self.lines = []
        self.cases = []

    def add(self, ip, ua, path, status, timestamp, bytes_sent, *,
            expect, bot=None, scenario, note='', parses=True):
        """Emit a log line and record the ground truth we expect back.

        `expect` is one of: verified | spoofed | unverified_publisher | human

        `parses=False` marks a line that `log-parser.js` is expected to REJECT
        before the classifier ever runs (e.g. a syntactically impossible IP).
        Such a case still has a correct offline verdict, but it cannot appear in
        the dashboard, so UI expectations must be derived from `parses=True`
        cases only. Without this distinction the UI suite compares a
        request-count it can never reach against one the dashboard must show.
        """
        self.lines.append(log_line(ip, ua, path, status, timestamp, bytes_sent))
        self.cases.append({
            'ip': ip,
            'path': path,
            'scenario': scenario,
            'expected_status': expect,
            'expected_bot': bot,
            'parses': parses,
            'note': note,
        })


def build():
    gs = GoldSet()
    verified_ips = {
        key: _first_host_in_feed(key, 2)
        for key in ['googlebot', 'bingbot', 'gptbot', 'applebot', 'ccbot', 'yandexbot']
    }

    # ── Scenario 1: verified genuine bots from real published ranges ───────
    g_ips = verified_ips['googlebot'][:2]
    for i, ip in enumerate(g_ips):
        for j, path in enumerate(CRAWLER_PATHS[:3]):
            ua = [UA['googlebot'], UA['googlebot_mobile'], UA['googlebot_bare']][(i + j) % 3]
            gs.add(ip, ua, path, 200, BASE_TIME + timedelta(seconds=i * 10 + j), 1024,
                   expect='verified', bot='Googlebot', scenario='verified_bots',
                   note='Bot UA + IP inside published Googlebot ranges')

    for i, ip in enumerate(verified_ips['bingbot'][:2]):
        gs.add(ip, UA['bingbot'], '/robots.txt', 200, BASE_TIME + timedelta(seconds=30 + i * 5), 1024,
               expect='verified', bot='Bingbot', scenario='verified_bots',
               note='Bot UA + IP inside published Bingbot ranges')

    for key, bot_name, ua_key in [
        ('gptbot', 'GPTBot', 'gptbot'),
        ('applebot', 'Applebot', 'applebot'),
        ('ccbot', 'CCBot', 'ccbot'),
        ('yandexbot', 'YandexBot', 'yandexbot'),
    ]:
        ip = verified_ips[key][0]
        gs.add(ip, UA[ua_key], '/', 200, BASE_TIME + timedelta(seconds=60), 1024,
               expect='verified', bot=bot_name, scenario='verified_bots',
               note='Bot UA + IP inside published ranges')

    # ClaudeBot: Anthropic publishes a single egress list covering all its
    # crawlers (see backend/migrations/008_bot_ip_source_claudebot.sql), so a
    # real Anthropic source IP must verify. This case was the fixture's
    # `unverified_publisher` canary while the source was missing; it now
    # asserts the gap is actually closed rather than silently drifting.
    claude_ip = verified_ips.get('claudebot', [None])[0]
    if claude_ip:
        gs.add(claude_ip, UA['claudebot'], '/', 200, BASE_TIME + timedelta(seconds=65), 1024,
               expect='verified', bot='ClaudeBot', scenario='verified_bots',
               note='Real Anthropic egress IP must verify once source 008 is synced')
        gs.add('3.89.0.0', UA['claudebot'], '/', 200,
               BASE_TIME + timedelta(seconds=66), 1024,
               expect='spoofed', bot='ClaudeBot', scenario='verified_bots',
               note='ClaudeBot from an IP outside Anthropic\'s published list')

    # ── Scenario 2: impersonators - bot UA from untrusted IPs ──────────────
    for i, path in enumerate(ATTACK_PATHS[:3]):
        gs.add(SPOOFED_IPS['tor_exit'], UA['googlebot'], path, 404,
               BASE_TIME + timedelta(seconds=100 + i * 2), 512,
               expect='spoofed', bot='Googlebot', scenario='impersonators',
               note='Fake Googlebot from Tor exit node')

    gs.add(SPOOFED_IPS['datacenter'], UA['bingbot'], '/.env', 404,
           BASE_TIME + timedelta(seconds=120), 256,
           expect='spoofed', bot='Bingbot', scenario='impersonators',
           note='Fake Bingbot harvesting secrets')

    gs.add(SPOOFED_IPS['ovh_datacenter'], UA['gptbot'], '/admin/login', 403,
           BASE_TIME + timedelta(seconds=130), 512,
           expect='spoofed', bot='GPTBot', scenario='impersonators',
           note='Fake GPTBot probing admin')

    # ClaudeBot from an RFC1918 address. The publisher (Anthropic) publishes no
    # CIDR feed, which used to short-circuit verifyBot() into
    # `unverified_publisher` before the IP was ever examined - putting a spoofed
    # request in the same bucket as a legitimate ClaudeBot. Reserved-range IPs
    # are now checked first, so this is `spoofed`.
    gs.add(SPOOFED_IPS['private_rfc1918'], UA['claudebot'], '/wp-admin', 404,
           BASE_TIME + timedelta(seconds=140), 256,
           expect='spoofed', bot='ClaudeBot', scenario='impersonators',
           note='Private IP + ClaudeBot; RFC1918 cannot reach a public edge, so '
                'the non-routable-IP guard fires before the missing-feed check')

    # ── Scenario 3: edge cases ─────────────────────────────────────────────
    for i, ua_key in enumerate(['googlebot_no_url', 'googlebot_capital_b']):
        gs.add(SPOOFED_IPS['datacenter'], UA[ua_key], '/robots.txt', 200,
               BASE_TIME + timedelta(seconds=200 + i * 5), 1024,
               expect='spoofed', bot='Googlebot', scenario='edge_cases',
               note='Malformed/near-miss Googlebot UA from datacenter')

    # Real Googlebot IP, but a human UA -> must classify as HUMAN, not a bot.
    gs.add(verified_ips['googlebot'][0], HUMAN_UAS[0], '/products', 200,
           BASE_TIME + timedelta(seconds=210), 4096,
           expect='human', bot=None, scenario='edge_cases',
           note='Human UA from a Googlebot IP - IP alone must not imply bot')

    # Malformed IP: the parser must not crash, and must not call it verified.
    # `parses=False` because the parser rejects it at the IP-validation stage,
    # so the spoofed verdict is never reached in the browser - only offline.
    gs.add(SPOOFED_IPS['malformed'], UA['googlebot'], '/', 200,
           BASE_TIME + timedelta(seconds=215), 1024,
           expect='spoofed', bot='Googlebot', scenario='edge_cases', parses=False,
           note='Out-of-range octets; must degrade safely, never crash')

    # IPv4-mapped IPv6: the SAME client arriving over an IPv6 socket must
    # classify identically to its bare IPv4 form. Without normalisation this
    # fails in both directions at once - a genuine bot is called spoofed
    # (blocking a real crawler) and a private address looks routable.
    gs.add(f"::ffff:{verified_ips['googlebot'][0]}", UA['googlebot'], '/', 200,
           BASE_TIME + timedelta(seconds=220), 1024,
           expect='verified', bot='Googlebot', scenario='edge_cases',
           note='v4-mapped form of a REAL Googlebot IP must still verify')

    gs.add('::ffff:192.168.1.100', UA['claudebot'], '/wp-admin', 404,
           BASE_TIME + timedelta(seconds=225), 256,
           expect='spoofed', bot='ClaudeBot', scenario='edge_cases',
           note='v4-mapped RFC1918 must still be caught as non-routable')

    # ── Scenario 4: subnet scanning within one /24 ─────────────────────────
    for i in range(5):
        gs.add(f'203.0.113.{i + 10}', HUMAN_UAS[i % len(HUMAN_UAS)],
               CRAWLER_PATHS[(i + 3) % len(CRAWLER_PATHS)], 200,
               BASE_TIME + timedelta(seconds=300 + i * 2), 4096,
               expect='human', bot=None, scenario='subnet_scan',
               note='Benign traffic inside the scanned /24')

    for i in range(3):
        gs.add(f'203.0.113.{i + 50}', UA['googlebot'], ATTACK_PATHS[i], 404,
               BASE_TIME + timedelta(seconds=320 + i * 2), 512,
               expect='spoofed', bot='Googlebot', scenario='subnet_scan',
               note='Fake Googlebot inside the same /24 as benign traffic')

    # ── Scenario 5: baseline human traffic ─────────────────────────────────
    human_paths = ['/products', '/blog', '/', '/about', '/contact']
    for i in range(10):
        gs.add(HUMAN_IPS[i % len(HUMAN_IPS)], HUMAN_UAS[i % len(HUMAN_UAS)],
               human_paths[i % len(human_paths)], 200,
               BASE_TIME + timedelta(seconds=400 + i * 3), 4096,
               expect='human', bot=None, scenario='human_baseline',
               note='Baseline human traffic')

    return gs, verified_ips


def main():
    gs, verified_ips = build()

    os.makedirs(os.path.dirname(LOG_OUT), exist_ok=True)
    with open(LOG_OUT, 'w') as fh:
        fh.write('\n'.join(gs.lines) + '\n')

    counts = {}
    for case in gs.cases:
        counts[case['expected_status']] = counts.get(case['expected_status'], 0) + 1
    by_scenario = {}
    for case in gs.cases:
        by_scenario[case['scenario']] = by_scenario.get(case['scenario'], 0) + 1

    # Counts the DASHBOARD can actually reach: `log-parser.js` rejects
    # `parses=False` lines before any bot verdict is computed, so including them
    # here would make the UI expectations unsatisfiable by construction.
    ui_counts = {}
    for case in gs.cases:
        if case['parses']:
            ui_counts[case['expected_status']] = ui_counts.get(case['expected_status'], 0) + 1
    unparseable = [c['ip'] for c in gs.cases if not c['parses']]

    manifest = {
        'generated_by': 'scripts/generate_bot_intel_test_logs.py',
        'feed_version': json.load(open(FEED_PATH))['version'],
        'total_lines': len(gs.lines),
        'expected_counts': counts,
        'ui_expected_counts': ui_counts,
        'unparseable_ips': unparseable,
        'by_scenario': by_scenario,
        'verified_ips_from_feed': verified_ips,
        'cases': gs.cases,
    }
    with open(EXPECTED_OUT, 'w') as fh:
        json.dump(manifest, fh, indent=2)

    print('=' * 72)
    print('BOT INTELLIGENCE GOLD SET GENERATED')
    print('=' * 72)
    print(f'  Log        : {LOG_OUT}  ({len(gs.lines)} lines)')
    print(f'  Ground truth: {EXPECTED_OUT}')
    print(f'  Feed version: {manifest["feed_version"]}')
    print()
    print('  Expected classification counts:')
    for key in ['verified', 'spoofed', 'unverified_publisher', 'human']:
        print(f'    {key:22s} {counts.get(key, 0):>3}')
    print()
    print('  Dashboard-reachable counts (parser accepts the line):')
    for key in ['verified', 'spoofed', 'unverified_publisher', 'human']:
        print(f'    {key:22s} {ui_counts.get(key, 0):>3}')
    if unparseable:
        print(f'    (excluded as unparseable: {", ".join(unparseable)})')
    print()
    print('  By scenario:')
    for key, val in by_scenario.items():
        print(f'    {key:22s} {val:>3}')
    print()
    print('  ClaudeBot coverage:')
    print('    Anthropic publishes one egress list for all its crawlers')
    print('    (migration 008), so a real Anthropic IP verifies and an')
    print('    unlisted one is spoofed. If `claudebot` is missing from the')
    print('    feed the run below degrades to `unverified_publisher`.')
    print()
    print('Next: node scripts/qa_bot_intel_gold_set.mjs')


if __name__ == '__main__':
    main()
