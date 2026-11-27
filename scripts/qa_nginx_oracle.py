#!/usr/bin/env python3
"""Independent golden-log auditor. No application JS is loaded.

Run with Python + maxminddb (e.g. pip install maxminddb). The standard library
parses the fixed fixture, converts timezones, counts and computes statistics.
MaxMind's Python reader checks the binary DBs independently of the browser's
MMDB decoder; ipaddress checks official bot CIDRs independently of BotDetector.
The manifest is an assertion input, never rewritten by this script.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import shlex
import statistics

import maxminddb

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures'
DATA = ROOT / 'frontend/public/data'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assert_subset(actual, expected, location='manifest'):
    if isinstance(expected, dict):
        for key, value in expected.items():
            assert key in actual, f'{location}.{key}: missing'
            assert_subset(actual[key], value, f'{location}.{key}')
    else:
        assert actual == expected, f'{location}: expected {expected!r}, got {actual!r}'


def iso(value):
    return value.isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument('--output', type=Path, help='Write independently computed evidence JSON')
    args = args.parse_args()
    manifest = json.loads((FIXTURES / 'nginx-release-golden.json').read_text())
    log_path = FIXTURES / manifest['fixture']
    feed = json.loads((DATA / 'verified-bots.json').read_text())
    country = maxminddb.open_database(str(DATA / 'GeoLite2-Country.mmdb'))
    asn = maxminddb.open_database(str(DATA / 'GeoLite2-ASN.mmdb'))

    rows = []
    # Fixture-specific contracts: ordinary browser UAs are human; cURL is a
    # script ("automated"); recognized publisher identities require a CIDR match.
    for number, raw in enumerate(log_path.read_text().splitlines(), 1):
        prefix, rest = raw.split('[', 1)
        stamp, request = rest.split(']', 1)
        ip_text = prefix.split()[0]
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            rows.append({'line_number': number, 'discard': 'Invalid IP format'})
            continue
        fields = shlex.split(request)
        method, url, protocol = fields[0].split()
        ua = fields[4]
        timestamp = datetime.strptime(stamp, '%d/%b/%Y:%H:%M:%S %z').astimezone(timezone.utc)
        private = ip in ipaddress.ip_network('10.0.0.0/8') or ip in ipaddress.ip_network('192.168.0.0/16')
        identity = next((key for key in ('googlebot', 'bingbot', 'gptbot', 'claudebot') if key in ua.lower()), None)
        verdict = 'human'
        if identity:
            networks = feed['bots'].get(identity, {}).get('ipv4', [])
            verified = any(ip in ipaddress.ip_network(cidr) for cidr in networks)
            verdict = 'verified' if verified else 'spoofed' if private or networks else 'unverified'
        elif ua.startswith('curl/'):
            verdict = 'automated'
        geo = (country.get(ip_text) or {}).get('country', {})
        network = asn.get(ip_text) or {}
        rows.append({
            'line_number': number, 'ip': ip_text, 'timestamp': iso(timestamp),
            'method': method, 'url': url, 'http_version': protocol,
            'status_code': int(fields[1]), 'response_size': int(fields[2]),
            'referrer': None if fields[3] == '-' else fields[3],
            'user_agent': ua, 'raw_line': raw, 'bot_status': verdict,
            'country': geo.get('names', {}).get('en', 'Unknown'),
            'country_code': geo.get('iso_code', '--'),
            'asn_num': network.get('autonomous_system_number', 0),
            'asn_org': network.get('autonomous_system_organization', 'Unknown'),
            'private_ip': private,
        })

    valid = [r for r in rows if 'timestamp' in r]
    result = {
        'fixture_sha256': digest(log_path),
        'line_count': len(rows),
        'bounds': {
            'min_iso': min(r['timestamp'] for r in valid),
            'max_iso': max(r['timestamp'] for r in valid),
            'span_minutes': int((datetime.fromisoformat(max(r['timestamp'] for r in valid).replace('Z', '+00:00')) -
                                 datetime.fromisoformat(min(r['timestamp'] for r in valid).replace('Z', '+00:00'))).total_seconds() / 60),
        },
        'sources': {name: digest(DATA / name) for name in ('GeoLite2-Country.mmdb', 'GeoLite2-ASN.mmdb', 'verified-bots.json')},
        'bot_feed_version': feed['version'],
    }
    for skip403, mode in ((True, 'default_skip_403'), (False, 'include_403')):
        accepted, skipped = [], Counter()
        for row in rows:
            reason = row.get('discard')
            if not reason and row['private_ip']:
                reason = 'Private/reserved IP'
            if not reason and skip403 and row['status_code'] == 403 and row['bot_status'] == 'human':
                reason = '403 Forbidden (blocked)'
            if reason:
                skipped[reason] += 1
            else:
                accepted.append(row)
        count = lambda key: dict(Counter(str(r[key]) for r in accepted))
        sizes = [r['response_size'] for r in accepted]
        statuses = {f'{n}xx': sum(r['status_code'] // 100 == n for r in accepted) for n in range(1, 6)}
        errors = statuses['4xx'] + statuses['5xx']
        stamps = [datetime.fromisoformat(r['timestamp'].replace('Z', '+00:00')) for r in accepted]
        buckets = {}
        for row, stamp in zip(accepted, stamps):
            bucket = int(stamp.timestamp()) // 120 * 120
            if bucket not in buckets:
                buckets[bucket] = {'label': datetime.fromtimestamp(bucket, timezone.utc).strftime('%H:%M'),
                                   'count': 0, **{f'status_{n}xx': 0 for n in range(2, 6)}}
            buckets[bucket]['count'] += 1
            category = f'status_{row["status_code"] // 100}xx'
            if category in buckets[bucket]:
                buckets[bucket][category] += 1
        peak = max(buckets, key=lambda b: buckets[b]['count'])
        result[mode] = {
            'parsed_lines': len(accepted), 'skipped_lines': sum(skipped.values()), 'skip_reasons': dict(skipped),
            # "Unknown" is not a country and AS0 is not a network: neither is counted.
            'total_requests': len(accepted), 'unique_ips': len(count('ip')),
            'unique_countries': len(set(r['country'] for r in accepted) - {'Unknown'}),
            'unique_asns': len(set(r['asn_num'] for r in accepted) - {0}),
            'human_requests': sum(r['bot_status'] == 'human' for r in accepted),
            'automated_requests': sum(r['bot_status'] == 'automated' for r in accepted),
            **{f'{kind}_bots': sum(r['bot_status'] == kind for r in accepted) for kind in ('verified', 'spoofed', 'unverified')},
            'status_categories': statuses, 'status_hits': count('status_code'), 'method_hits': count('method'),
            'response_size': {'total': sum(sizes), 'average': int(statistics.mean(sizes) + .5),
                              'median': int(statistics.median(sizes) + .5), 'min': min(sizes), 'max': max(sizes)},
            'error_rate': errors, 'error_percentage': f'{int(errors / len(accepted) * 1000 + .5) / 10:.1f}',
            'country_hits': count('country'), 'asn_hits': count('asn_num'), 'ip_hits': count('ip'),
            'referrers': dict(Counter(r['referrer'] or '-' for r in accepted)),
            'top_urls': dict(Counter(r['url'].split('?')[0] for r in accepted)),
            # A path is the URL without its query string, counted once per request.
            'top_paths': dict(Counter(r['url'].split('?')[0] for r in accepted)),
            'hourly_nonzero_utc': dict(Counter(str(t.hour) for t in stamps)),
            'daily_nonzero_utc': dict(Counter(str((t.weekday() + 1) % 7) for t in stamps)),
            'request_rate': {'bucket_seconds': 120, 'bucket_label': '2m', 'total_buckets': (max(buckets) - min(buckets)) // 120 + 1,
                             'total_requests': len(accepted), 'duration_seconds': int((max(stamps) - min(stamps)).total_seconds()),
                             'start_time': min(stamps).strftime('%H:%M'), 'end_time': max(stamps).strftime('%H:%M'),
                             'peak_count': buckets[peak]['count'], 'peak_timestamp_iso': iso(datetime.fromtimestamp(peak, timezone.utc)),
                             'nonzero_buckets': [buckets[b] for b in sorted(buckets)]},
            'entries': [{k: v for k, v in r.items() if k != 'private_ip'} for r in accepted],
        }
        assert_subset(result[mode], manifest[mode], mode)
    assert result['line_count'] == manifest['line_count']
    assert result['bounds'] == manifest['bounds']
    assert [[r[k] for k in manifest['entry_columns']] for r in result['default_skip_403']['entries']] == manifest['default_entries']
    country.close()
    asn.close()
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': 'PASS', 'lines': result['line_count'], 'bounds': result['bounds'],
                      'default': {k: v for k, v in result['default_skip_403'].items() if k in ('ip_hits', 'top_urls', 'top_paths', 'referrers')},
                      'bot_feed_version': feed['version'], 'output': str(args.output or '')}, indent=2))


if __name__ == '__main__':
    main()
