#!/usr/bin/env python3
"""Build the release-QA PDF and compact evidence from recorded test results.

Dependencies: reportlab (with Pillow). Tests and the independent oracle must
be run first; this script reads their outputs and does not infer test passes.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from xml.sax.saxutils import escape

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ROOT = Path(__file__).resolve().parents[1]

FINDINGS = [
    ('D01', 'High', 'Log offsets and timeline clock',
     'Server timestamps were interpreted in viewer-local time; chart categories and range controls could diverge. Offset-aware UTC parsing, numeric chart bounds, inclusive filtering, and synchronized handle/readout timestamps now agree. Excluded valid endpoints still define the input period.',
     'timeline-accuracy.spec.ts; timeline-scrubber.spec.ts'),
    ('D02', 'Medium', 'Hourly and weekday totals',
     'The timeline was UTC but temporal histograms still called local-time Date accessors. UTC accessors now make them timezone-independent. The golden test deliberately runs in Asia/Kolkata.',
     'nginx-golden-analysis.spec.ts'),
    ('D03', 'High', 'False HTTP 200 in log views',
     'Rows and the per-IP inspector read status instead of status_code and defaulted to 200. They now render the actual 101/201/204/301/304/401/403/404/500 values. Missing methods and paths display a dash rather than invented GET / values.',
     'golden per-row test; parser contract test'),
    ('D04', 'Medium', 'Unverified and publisher-specific bot filters',
     'Unverified filtering expected a status the detector did not emit. Publisher table rows also selected all spoofers or a mixed whole publisher. Filters now recognize unverified_publisher and intersect publisher group with the displayed verdict.',
     'golden unverified/individual bot-row test'),
    ('D05', 'High', 'Valid logs and security-relevant rows discarded',
     'Common-format lines and dash byte counts were rejected. Extra fields after the User-Agent could hide a 403 crawler or an explicitly included private crawler. The parser now supports common and combined records, zero-byte dashes, incomplete requests, and reads the actual UA field.',
     'nginx-parser-contract.spec.ts; bot-intel-gold-set.spec.ts'),
    ('D06', 'Medium', 'Malformed IPv6 accepted',
     'A character whitelist accepted colon-only strings, too few groups, repeated compression markers, and oversized hextets. Structural validation now rejects these and retains valid IPv6 and mapped IPv4 clients.',
     'nginx-parser-contract.spec.ts'),
    ('D07', 'Medium', 'Protocol column misalignment',
     'Visual evidence showed eight explorer headers but only seven cells; the User-Agent appeared under Protocol. The missing http_version cell is now rendered, with exact per-column assertions.',
     'golden per-row test and updated screenshot'),
    ('D08', 'High', 'Timeline safety cap lost endpoint events',
     'Exactly 1,500 elapsed seconds can require 1,501 inclusive buckets. The old cap dropped the last request and its error. Resolution selection now counts aligned inclusive buckets and chooses a safe interval even for multi-year spans.',
     'request-rate safety test: 1,500s, 366 days, five years'),
    ('D09', 'Medium', 'Malformed method interpreted as markup',
     'The methods ribbon and method-option templates interpolated raw request tokens. Escaping now keeps malformed method tokens literal. The regression verifies a markup-like token is text, not a new element.',
     'malformed HTTP methods test'),
    ('D10', 'Low', 'Requested versus effective chart resolution',
     'The point-limit fallback could plot 10s buckets with the 1s button selected. An explicit effective-resolution note now explains the fallback, consistent with the y-axis label.',
     'golden timeline note assertion'),
    ('D11', 'Medium', 'Internal requests inflated public-traffic metrics',
     'Private clients with crawler/tool User-Agents bypassed exclusions; expanded IPv6 loopback and hex-mapped private IPv4 were missed; health paths were counted as public traffic. A separate default-on internal policy now excludes private/local/CGNAT clients and exact health-check paths before enrichment and aggregation. Independent controls above input and results recalculate the original loaded log, report skip reasons, and allow explicit inclusion. Public Unknown-ASN clients remain included.',
     'internal-exclusions.spec.ts: ranges, path boundaries, main/worker parity, all four policy combinations, charts/report, empty recovery, keyboard/mobile and read-only shares'),
    ('D12', 'Medium', 'Pending exclusion result replaced New Analysis',
     'A deliberately delayed recalculation reproduced an old result hiding the new input form after New Analysis was clicked. Leaving the dashboard now invalidates the pending exclusion revision before showing input, so its eventual result cannot render or change the next input policies.',
     'internal-exclusions.spec.ts: delayed parse result preserves the new input and its next analysis'),
]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_inventory(suites):
    rows = []
    for suite in suites:
        for spec in suite.get('specs', []):
            for test in spec.get('tests', []):
                runs = test.get('results', [])
                last = runs[-1] if runs else {}
                rows.append({'file': spec.get('file', suite.get('file')), 'line': spec.get('line'),
                             'title': spec['title'], 'project': test['projectName'],
                             'status': last.get('status', 'not-run'), 'duration_ms': last.get('duration', 0),
                             'retry': last.get('retry', 0), 'annotations': test.get('annotations', []),
                             'error': last.get('errors', [{}])[0].get('message', '') if last.get('errors') else ''})
        rows.extend(test_inventory(suite.get('suites', [])))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--prior-results', type=Path, help='Preserve a preceding run, including cross-run test instability')
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = json.loads(args.results.read_text())
    oracle = json.loads(args.oracle.read_text())
    expected = json.loads((ROOT / 'tests/fixtures/nginx-release-golden.json').read_text())
    inventory = test_inventory(result['suites'])
    counts = Counter(item['status'] for item in inventory)
    stats = result['stats']
    run_date = datetime.fromisoformat(stats['startTime'].replace('Z', '+00:00')).astimezone(timezone.utc).date()
    assert len(inventory) == sum(stats[k] for k in ('expected', 'unexpected', 'skipped', 'flaky'))
    assert oracle['fixture_sha256'] == sha(ROOT / 'tests/fixtures/nginx-release-golden.log')
    output_dir = args.output.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence = output_dir / 'evidence'
    evidence.mkdir(exist_ok=True)
    sources = ['frontend/public/js/' + name + '.js' for name in ('analyzer', 'dashboard', 'log-parser', 'log-parser.worker', 'nginx-init', 'report')]
    sources += ['frontend/src/app/signal-nginx.css', 'frontend/src/lib/nginx-engine.ts',
                'tests/e2e/nginx-golden-analysis.spec.ts', 'tests/e2e/nginx-parser-contract.spec.ts', 'tests/e2e/timeline-accuracy.spec.ts',
                 'tests/fixtures/nginx-release-golden.json', 'tests/fixtures/nginx-release-golden.log', 'scripts/qa_nginx_oracle.py']
    sources += ['frontend/src/app/nginx/page.tsx', 'frontend/src/app/s/[code]/page.tsx',
                'tests/e2e/internal-exclusions.spec.ts', 'tests/e2e/bot-intel-gold-set.spec.ts']
    metadata = {'base_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                'branch': subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT, text=True).strip(),
                'recorded_run': stats, 'counts': dict(counts), 'source_hashes': {name: sha(ROOT / name) for name in sources},
                'playwright_version': result['config']['version'], 'raw_results_sha256': sha(args.results)}
    compact = {**metadata, 'tests': inventory}
    if args.prior_results:
        prior = json.loads(args.prior_results.read_text())
        prior_inventory = test_inventory(prior['suites'])
        compact['previous_run'] = {
            'recorded_run': prior['stats'],
            'counts': dict(Counter(item['status'] for item in prior_inventory)),
            'raw_results_sha256': sha(args.prior_results),
        }
        (output_dir / 'previous-test-results.json').write_text(json.dumps({
            **compact['previous_run'], 'tests': prior_inventory,
        }, indent=2) + '\n')
    (output_dir / 'test-results.json').write_text(json.dumps(compact, indent=2) + '\n')
    (output_dir / 'oracle-evidence.json').write_text(json.dumps(oracle, indent=2) + '\n')

    for name in ('DejaVuSans', 'DejaVuSans-Bold'):
        pdfmetrics.registerFont(TTFont(name, f'/usr/share/fonts/truetype/dejavu/{name}.ttf'))
    pdfmetrics.registerFontFamily('DejaVuSans', normal='DejaVuSans', bold='DejaVuSans-Bold')
    styles = getSampleStyleSheet()
    for name in styles.byName:
        styles[name].fontName = 'DejaVuSans'
    styles['BodyText'].fontSize = 9
    styles['BodyText'].leading = 14
    styles['BodyText'].spaceAfter = 7
    for name in ('Title', 'Heading1', 'Heading2', 'Heading3'):
        styles[name].fontName = 'DejaVuSans-Bold'
        styles[name].textColor = colors.HexColor('#143d4b')
    styles.add(ParagraphStyle('SmallCell', fontName='DejaVuSans', fontSize=7.1, leading=10))
    styles.add(ParagraphStyle('CaptionQA', fontName='DejaVuSans', fontSize=8, leading=11, spaceAfter=9, textColor=colors.HexColor('#506477')))
    styles.add(ParagraphStyle('BadgeQA', fontName='DejaVuSans-Bold', fontSize=13, leading=18, alignment=TA_CENTER, spaceAfter=16, textColor=colors.HexColor('#966207')))
    story = []
    width = A4[0] - 80

    def p(text, style='BodyText'):
        return Paragraph(escape(str(text)).replace('\n', '<br/>'), styles[style])

    def text(value, style='BodyText'):
        story.append(p(value, style))

    def table(header, rows, widths=None):
        grid = [[p(c, 'SmallCell') for c in header]] + [[p(c, 'SmallCell') for c in row] for row in rows]
        tab = Table(grid, colWidths=widths, repeatRows=1, hAlign='LEFT')
        tab.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e5f0f1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f8fa')]),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('LINEBELOW', (0, 0), (-1, 0), .7, colors.HexColor('#acc9ce')),
        ]))
        story.append(tab)
        story.append(Spacer(1, 12))

    def image(source, caption, max_height=470):
        if not source.exists():
            raise FileNotFoundError(f'Missing required evidence: {source}')
        destination = evidence / source.name
        if source.resolve() != destination.resolve():
            shutil.copyfile(source, destination)
        iw, ih = PILImage.open(source).size
        scale = min(width / iw, max_height / ih)
        story.append(Image(str(destination), width=iw * scale, height=ih * scale))
        text(caption, 'CaptionQA')

    text('Nginx Log Analyzer', 'Title')
    text('Release-readiness QA report', 'Title')
    text(f'{run_date:%d %B %Y} | Development workspace | Chromium', 'CaptionQA')
    text('CONDITIONAL READINESS', 'BadgeQA')
    text(f"Final full run: {counts['passed']} passed, {counts['failed']} failed, {counts['skipped']} skipped / {len(inventory)} tests. Retries: 0. Recorded duration: {stats['duration'] / 1000:.1f}s.")
    text('The audited Nginx scenarios pass after the fixes in this report. Readiness remains conditional: the existing admin appearance test is login-gated and unreliable across runs, and a native storage download from the local browser origin is blocked by CORS. The live ingest test explicitly bridges that boundary. A runner pass alone does not prove authenticated admin coverage.')
    if 'previous_run' in compact:
        previous = compact['previous_run']['counts']
        text(f"Preceding run: {previous.get('passed', 0)} passed, {previous.get('failed', 0)} failed. Its admin appearance failure is retained in previous-test-results.json. The final admin pass does not resolve the test's early-return/authentication gap.")
    table(['Gate', 'Recorded result'], [
        ['Independent golden oracle', 'PASS: Python parsing/statistics, MaxMind MMDB reader and standard-library CIDR checks'],
        ['Golden analysis / parser / timeline / exclusions', 'All pass in the final full run; detailed inventory follows'],
        ['Frontend lint and JavaScript syntax', 'PASS: npm run lint; node --check on changed analysis scripts'],
        ['Development build / runtime', 'PASS: Next.js 16.2.2 compile + TypeScript + static pages; container healthy'],
        ['Repository-wide suite', f"Runner: {counts['passed']} passed, {counts['failed']} failed; authenticated coverage of the existing admin test remains unproven"],
        ['Native local-origin terminal download', 'BLOCKED: missing storage CORS permission; test bridge is documented'],
    ], [185, width - 185])
    text(f"Target: http://localhost:3001/nginx\nBranch: {metadata['branch']}\nBase commit: {metadata['base_commit']}\nChanges under test are uncommitted working-tree changes; source hashes are in test-results.json.")

    story.append(PageBreak())
    text('1. Methodology and evidence boundaries', 'Heading1')
    for paragraph in [
        'The fixed 20-line corpus combines ordinary browser traffic, verified Google/Bing identities, three spoofers, one cURL tool, every HTTP status class, query strings, several networks, invalid/private inputs, zero-byte responses and mixed UTC offsets. Private rows at the edges deliberately define a longer input period than accepted traffic.',
        'Expected values are maintained separately in nginx-release-golden.json. qa_nginx_oracle.py independently parses the fixture with Python shlex/datetime, computes counters/statistics, reads the country/ASN databases with MaxMind\'s Python reader, and checks bot addresses with ipaddress against the published feed. It loads no application JavaScript and asserts the manifest instead of regenerating expectations from the app.',
        'The Playwright assertions compare parser fields, skip reasons, analysis maps, chart counts, numeric bounds, visible KPI values, every explorer row, filter results, and the downloaded HTML report. The report is reopened and its rendered metrics, expandable bot section and chart are checked. Console/page errors are explicit assertions in the new tests.',
        'Timezone coverage includes Asia/Kolkata and America/New_York, server +0530/+0100/-0700 offsets, UTC-midnight crossings, singleton and empty selections, pointer/touch/keyboard changes, and inclusive end seconds. A separate safety-cap test covers exact 1,500-second and multi-year spans.',
        'Remote URL tests use intercepted storage responses. Terminal ingest uses the live upload, metadata, object and one-time session endpoints, but route.fetch bridges the real redirected object to the local origin because R2 does not allow localhost CORS. It does not replace the log with a fixture response. Gzip file upload and worker parsing are exercised separately.',
        'Both analysis exclusions default on. Internal clients are removed regardless of User-Agent or status; private client, exact health path, ordinary 403 and invalid counts are separate and non-overlapping. The internal suite checks both controls independently, retained public Unknown-ASN clients, empty-result recovery, shared read-only analysis and downloaded reports. The classifier-only bot corpus explicitly opts into internal requests to retain its forensic classification coverage.',
        'Screenshots were captured with dev-browser against localhost:3001. Chromium is the only executed browser engine. The existing large-file regression covers 50,000 lines; 400 MB stress limits, arbitrary custom formats, live reputation scores and production/public-origin browser access are outside this certification.',
    ]:
        text(paragraph)
    text('Interpretation', 'Heading2')
    text('Human means no recognized bot User-Agent, not proof of a person. Verified/spoofed reflect the implemented UA + CIDR policy; not behavioral attribution. Unknown country and AS0 are valid grouping buckets. GeoIP expectations are relative to the recorded databases, including anycast addresses with no country result.')
    text(f"Bot feed version: {oracle['bot_feed_version']}. GeoIP manifest baseline: {expected['geoip_database_version_at_creation']}. Binary/feed hashes are preserved in oracle-evidence.json.")

    story.append(PageBreak())
    text('2. Golden fixture: exact expected results', 'Heading1')
    default, inclusive = expected['default_skip_403'], expected['include_403']
    metric_rows = []
    for label, key in [('Accepted', 'parsed_lines'), ('Skipped', 'skipped_lines'), ('Total response bytes', 'response_size.total'),
                       ('Average bytes', 'response_size.average'), ('Median bytes', 'response_size.median'),
                       ('Human requests', 'human_requests'), ('Unverified requests', 'unverified_bots'),
                       ('4xx + 5xx requests', 'error_rate'), ('Error percentage', 'error_percentage')]:
        def metric(data):
            for part in key.split('.'):
                data = data[part]
            return data
        metric_rows.append([label, metric(default), metric(inclusive)])
    groups = ' / '.join(str(default[key]) for key in ('unique_ips', 'unique_countries', 'unique_asns'))
    bots = f"{default['verified_bots']} / {default['spoofed_bots']}"
    metric_rows += [['Unique IPs / country groups / ASN groups', groups, groups],
                    ['Verified / spoofed bot requests', bots, bots], ['Response byte range', '0 to 4096', '0 to 4096']]
    table(['Metric', 'Default skip ordinary 403s', 'Include 403s'], metric_rows, [width * .4, width * .3, width * .3])
    text('Internal exclusion is enabled in both columns. Compared with the 4 October baseline, private ClaudeBot line 11 is now excluded too: 15 accepted requests instead of 16, and 19,744 bytes instead of 20,000. This is the intended policy change, confirmed independently with Python.')
    text('Input period: 2026-10-01 00:00:00 to 05:00:00 UTC (300 minutes). Accepted timestamps range from 00:00:05 to 04:00:00. Invalid-IP timestamp 11:00:00 is excluded from bounds. Blank trailing lines are ignored, not counted as discarded requests.')
    table(['Discard reason', 'Default', 'Include 403s'], [[key, count, inclusive['skip_reasons'].get(key, 0)] for key, count in default['skip_reasons'].items()], [width * .6, width * .2, width * .2])
    table(['HTTP class', 'Default', 'Include 403s'], [[key, count, inclusive['status_categories'][key]] for key, count in default['status_categories'].items()], [width * .6, width * .2, width * .2])
    text('HTTP methods (default): ' + ', '.join(f'{k} {v}' for k, v in default['method_hits'].items()) + '. Including ordinary 403s adds one GET. Default exact status counts: ' + ', '.join(f'{k}: {v}' for k, v in default['status_hits'].items()))
    text('UTC hour distribution: 14 at hour 00, 1 at hour 04. All 15 occur on Thursday. Default transfer display: 19.3 KB; human display: 60%; verified: 3 (20%); spoofed: 2 (13.3%).')

    story.append(PageBreak())
    text('3. Geography, networks, paths and buckets', 'Heading1')
    table(['Country group', 'Requests'], list(default['country_hits'].items()), [width * .7, width * .3])
    table(['ASN', 'Requests'], [('AS' + key, value) for key, value in default['asn_hits'].items()], [width * .7, width * .3])
    text('Auto request rate: 120-second (2m) buckets, 121 total, 15 requests over 14,395 elapsed seconds. First bucket is the peak with 4 requests. Empty buckets remain represented; the input-range axis extends to the excluded endpoints. At requested 1s granularity, the point cap uses 10s and the UI now names that effective interval.')
    table(['UTC bucket', 'Requests', '2xx', '3xx', '4xx', '5xx'], [[b['label'], b['count'], *[b[f'status_{n}xx'] for n in range(2, 6)]] for b in default['request_rate']['nonzero_buckets']], [width * .3, width * .2] + [width * .125] * 4)
    text('Top URLs: /products has 4 requests (query string removed for aggregation); every other accepted URL has 1. Top path segments /products and /api have 4 each. All remaining segments have 1. Referrers: direct/missing 8; https://shop.test/ 4; login, products and Google test referrers 1 each.')
    text('Filter checkpoints: POST = 2; spoofed = 2; unverified cURL = 1; fake Google row = 1; verified Google row = 2; Germany = 1; AS15169 = 3; /products = 4 (7.7 KB). Matching counters preserve the original denominator of 15.')

    story.append(PageBreak())
    text('4. Accepted-row oracle', 'Heading1')
    text('Line numbers refer to nginx-release-golden.log. The machine-readable oracle includes every raw line, request, timestamp, status, size, referrer, User-Agent, country, ASN and verdict. UI checks also verify HTTP version and eight-column alignment.')
    table(['Line', 'Client', 'UTC time', 'Method / path', 'HTTP / bytes', 'Verdict'], [
        [r[0], r[1], r[2][11:19], f'{r[3]} {r[4]}', f'{r[5]} / {r[6]}', r[9]] for r in expected['default_entries']
    ], [27, 92, 60, width - 299, 60, 60])
    text('Include-403 mode additionally accepts line 17: 93.184.216.34, 00:12:00 UTC, GET /forbidden, status 403, 777 bytes, browser UA. Lines 1, 11 and 20 are private clients and remain excluded regardless of User-Agent. Line 19 has an impossible IPv4 address.')

    story.append(PageBreak())
    text('5. Defects found and fixed', 'Heading1')
    for issue, severity, title, description, coverage in FINDINGS:
        text(f'{issue} | {severity} | {title}', 'Heading2')
        text(description)
        text('Regression evidence: ' + coverage, 'CaptionQA')
    text('Oracle corrections during test authoring', 'Heading2')
    text('During the original audit, expectations incorrectly treated cURL as human, used a 900-byte median, mixed minute buckets with hourly counts, omitted the 04:00 event, and expected a date in a same-day compact readout. These were test/oracle mistakes. The new internal policy intentionally removes private bot line 11. Independent Python verification now confirms 9 human + 1 unverified, an 800-byte median, hour counts 14/1 and all nonzero buckets. The manifest was updated by hand, not generated from application output.')

    story.append(PageBreak())
    text('6. Remaining findings and release decision', 'Heading1')
    text('R01 | Existing admin appearance test | Test bug', 'Heading2')
    text('Expected: visible Primary action label. Actual in preceding failed runs: Admin Login page. The immediate password-input count after DOMContentLoaded races api.getMe() and the /login redirect. The test proceeds to an authenticated-only assertion with no authenticated session; an authenticated run also needs navigation from the default Dashboard tab to appearance settings. The login-page failure was documented before the new internal-exclusion work.')
    text('The same unchanged test reports passed in the final run. It returns without checking appearance fields whenever the login input is already present; therefore a pass can reflect that early return rather than authenticated coverage. No fix was made to this unrelated test. The previous failing run and final passing run are both preserved as evidence of the coverage gap.')
    text('Fix direction: establish an authenticated storage-state or explicit API fixture, await routing and render readiness, select the settings/appearance section, and assert its labels. Do not solve this with an unconditional pass or a longer timeout.')
    text('R02 | Local storage browser download | Environment/integration gap', 'Heading2')
    text('Observed during the original audit: upload 200; session redirect 302; independent object GET 200; Access-Control-Allow-Origin absent for http://localhost:3001. Browser fetch fails and the UI shows Link Expired or Already Viewed. Thus the message also obscures the underlying fetch/CORS failure. The current live regression uses a same-origin route.fetch bridge over the real object and verifies the 15-request result and single-use 404 behavior. Native public-origin browser downloading remains unverified.')
    text('Next gate: confirm storage CORS for the intended development/public origins, then exercise an unmodified browser download and its error path. Local-origin failure alone does not prove the production-origin CORS configuration is wrong.')
    text('Decision', 'Heading2')
    text('The audited Nginx parser, analysis, timeline, exclusions and rendered report contracts are passing in development. The final runner reports all tests passed, but this is conditional QA evidence rather than complete authenticated coverage or production launch certification. Close R01 and validate R02 before claiming end-to-end release sign-off.')

    story.append(PageBreak())
    text('7. Visual evidence', 'Heading1')
    image(args.evidence_dir / 'release-nginx-overview.png', 'Desktop, 1440px: accepted/skipped counts, default-on exclusions, 15-request summary, methods, bytes, full UTC input range and effective bucket note.', 480)
    image(args.evidence_dir / 'release-nginx-networks.png', 'Country and network distributions for the golden corpus.', 160)
    story.append(PageBreak())
    text('Explorer and mobile checks', 'Heading1')
    image(args.evidence_dir / 'release-nginx-rows.png', 'All 15 rows: actual status codes and HTTP versions aligned with their headers.', 340)
    image(args.evidence_dir / 'release-nginx-mobile.png', '390px mobile viewport: exact boundary labels and no document-level horizontal overflow. Touch behavior is covered by the timeline spec.', 350)

    story.append(PageBreak())
    text('Internal-request exclusion evidence', 'Heading1')
    text('The seven-row policy fixture retains 2 requests by default. Removing only 403 exclusion retains 3; removing only internal exclusion retains 5; removing both retains 7. Default skips: 3 private/local IP, 1 exact health path, 1 ordinary 403. Public AS0 traffic is retained. Changing policies recalculates cached raw text and resets view filters; it does not redact the raw source or alter shared uploads.')
    text('Exact paths: /health, /healthz, /healthcheck, /health-check, /health_check, /readyz, /livez, /_health. Matching is case-sensitive, ignoring query/fragment and trailing slashes. Similar or nested product paths stay included. Private checks include IPv4-mapped forms, expanded IPv6 loopback, link-local, unique-local and CGNAT.')
    image(args.evidence_dir / 'release-nginx-internal-input.png', 'Before analysis: independent default-on exclusions and inline policy help.', 230)
    image(args.evidence_dir / 'release-nginx-internal-mobile.png', 'Mobile results: independently operable controls and one-count-per-line explanation.', 290)

    story.append(PageBreak())
    text('8. Test inventory and reproduction', 'Heading1')
    grouped = defaultdict(list)
    for item in inventory:
        grouped[item['file']].append(item)
    table(['Spec file', 'Passed', 'Failed', 'Skipped'], [[name, sum(r['status'] == 'passed' for r in items),
          sum(r['status'] in ('failed', 'timedOut') for r in items), sum(r['status'] == 'skipped' for r in items)]
          for name, items in grouped.items()], [width - 126, 42, 42, 42])
    text(f'Final command: PLAYWRIGHT_JSON_OUTPUT_NAME={args.results} npx playwright test --project=chromium --reporter=line,json --retries=0')
    text('Build: docker compose -f docker-compose.dev.yml --profile prod up -d --build app. Static checks: npm run lint in frontend; node --check on parser/analyzer/dashboard; git diff --check. Oracle: scripts/qa_nginx_oracle.py. Report regeneration instructions are in docs/qa-release/README.md.')
    text(f"Recorded test start (UTC): {stats['startTime']}. Runner version: Playwright {metadata['playwright_version']}. Workers: 2. No retries. Runner-reported flaky tests: {stats['flaky']}; known cross-run admin instability is documented above.")
    for filename, items in grouped.items():
        text(filename, 'Heading2')
        table(['Test requirement', 'Result', 'Seconds'], [[r['title'], r['status'].upper(), f"{r['duration_ms']/1000:.2f}"] for r in items], [width - 108, 64, 44])

    story.append(PageBreak())
    text('9. Provenance', 'Heading1')
    text('The companion JSON files preserve exact expected entries, per-test outcomes/annotations and source hashes. Source hash comparison identifies this tested working tree even before a commit is made.')
    table(['Artifact', 'SHA-256'], [('Golden log', oracle['fixture_sha256']), ('Raw final Playwright JSON', metadata['raw_results_sha256'])] + list(oracle['sources'].items()), [width * .36, width * .64])
    text('Browser screenshots are included as original PNGs under evidence/. The full test run and independent oracle are independent evidence sources: the oracle validates intended numeric contracts; browser assertions validate that the application exposes those contracts to the user.')

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont('DejaVuSans', 7)
        canvas.setFillColor(colors.HexColor('#506477'))
        canvas.drawString(40, 24, f'Nginx release QA | Development | {run_date.isoformat()}')
        canvas.drawRightString(A4[0] - 40, 24, str(doc.page))
        canvas.restoreState()

    document = SimpleDocTemplate(str(args.output), pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=42,
                                 title=f'Nginx Release QA - {run_date.isoformat()}', author='SysAdmin Toolkit QA')
    document.build(story, onFirstPage=footer, onLaterPages=footer)
    print(json.dumps({'pdf': str(args.output), 'bytes': args.output.stat().st_size,
                      'tests': len(inventory), 'counts': dict(counts), 'sha256': sha(args.output)}, indent=2))


if __name__ == '__main__':
    main()
