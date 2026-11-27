import { test, expect, type Page } from '../_support/fixtures';
import { openTool, expectToolLinkedFromHome } from '../_support/navigation';
import { expectControlsUsable, VIEWPORTS, expectNoUiGlitchesAtRest } from '../_support/ui-audit';
import { captureDownload, readClipboard, clearClipboard, mockApi, failApi, type ApiCall } from '../_support/io';
import { parseCsv } from '../_support/csv';
import { deferred, scriptApi, settle, type ScriptedReply } from '../_support/gate';
import { MARKUP, handshakeFailure, healthyAnswer, randomAnswer, randomHost, randomNow, withValidity } from './generator';
import { BAD_PORTS, csvRecord, expectedSummary, hostOf, portIn, type SslAnswer } from './oracle';
import {
  API, HEADING, ROUTE, anyError, cardValue, check, checkButton, copyButton, emptyState, errorAlert, exportButton, failureBox, hostInput,
  loadingPanel, portInput, readView, resultPanel, submit,
} from './page';
import { expectNoMarkupExecuted, expectPageShows } from './checks';

/**
 * SSL Certificate Checker (/ssl) — contract tests. The browser's call to
 * POST /api/ssl is answered by the test with a generated answer, so the answer
 * is the ground truth for everything on screen. Checks of real hosts, compared
 * with a TLS connection the test opens itself, are in ssl-live.spec.ts.
 *
 * INVENTORY (each entry is covered by a test here or in ssl-live.spec.ts)
 *
 * Inputs
 *  - Host box (placeholder "example.com"), port box (placeholder and default "443")
 *  - Check button, Enter key in the host box, deep link /ssl?domain=...&port=...
 * Controls on a result
 *  - Export CSV, Copy Summary
 * Displayed values
 *  - Validation checks (6 lines, each passed or failed): DNS address, server software, trust, expiry, hostname match, HSTS
 *  - Cards: Days Until Expiry (+ colour), Security Grade (+ colour), Protocol, Key Type and size
 *  - Certificate Details: response time, Subject, Organization, Issuer, Issuer Org, Serial Number, Valid From, Valid Until,
 *    Fingerprint (SHA-256)
 *  - Subject Alternative Names: count and every name
 *  - Certificate Chain: count; per certificate: subject, role (Server / Intermediate / Root), organisation, validity, issuer, key
 * Outputs
 *  - Request body of POST /api/ssl, CSV file, clipboard summary
 * States
 *  - empty, loading, result, error from a failed request (alert), error inside a 200 answer (handshake failed)
 *
 * Layers: 1-8 all apply. Not applicable: share links (the tool has none), history or stored settings (none),
 * file input or drag and drop (none). The answer also carries fields the page does not display (all resolved
 * addresses, security headers other than HSTS, countries, signature algorithm): they are checked in the CSV export only.
 */

type Body = { domain?: string; port?: number | null };

/** Opens the tool with the browser clock pinned to `now`. */
async function openPinned(page: Page, now: Date, route = ROUTE) {
  await page.clock.setFixedTime(now);
  await openTool(page, route, HEADING);
}

/** Answers every check with whatever `holder.answer` currently is. */
async function answerWith(page: Page, holder: { answer: unknown }): Promise<ApiCall[]> {
  return mockApi(page, API, () => holder.answer, { method: 'POST' });
}

/** Runs each answer through the page and compares everything shown with it. */
async function expectEachShown(page: Page, answers: SslAnswer[], label: (answer: SslAnswer, index: number) => string, options = {}) {
  const holder = { answer: answers[0] as unknown };
  const calls = await answerWith(page, holder);
  for (const [i, answer] of answers.entries()) {
    holder.answer = answer;
    const ctx = label(answer, i);
    await check(page, answer.domain);
    await expect(resultPanel(page), `${ctx}: the result appears`).toBeVisible();
    expect.soft(calls.at(-1)?.body, `${ctx}: request body`).toEqual({ domain: answer.domain, port: 443 });
    await expectPageShows(page, answer, ctx, options);
  }
  return calls;
}

test.describe('SSL — access and layout', () => {
  test('is linked from the home page and the sidebar', async ({ page }) => {
    await expectToolLinkedFromHome(page, ROUTE);
    await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
  });

  test('opens with its controls ready, port 443, an empty result area and no request sent', async ({ page }) => {
    const calls = await mockApi(page, API, {}, { method: 'POST' });
    await openTool(page, ROUTE, HEADING);
    await expect(page).toHaveTitle(/SSL/i);
    await expectControlsUsable(page, {
      'host box': 'input[placeholder="example.com"]',
      'port box': 'input[placeholder="443"]',
      'Check button': '.signal-query-row button',
    });
    await expect(hostInput(page), 'the host box starts empty').toHaveValue('');
    await expect(portInput(page), 'the port box starts at 443').toHaveValue('443');
    await expect(checkButton(page)).toHaveText('🔒 Check');
    await expect(emptyState(page).getByRole('heading', { name: 'Inspect a certificate' }), 'empty state before the first check').toBeVisible();
    await expect(resultPanel(page), 'no result before a check').toHaveCount(0);
    await expect(anyError(page), 'no error before a check').toHaveCount(0);
    await expect(loadingPanel(page), 'no progress panel before a check').toHaveCount(0);
    await expect(page.getByRole('complementary', { name: 'Read the certificate' }), 'guide panel').toBeVisible();
    expect(calls.length, 'opening the page must not call the API').toBe(0);
  });

  for (const [name, viewport] of Object.entries(VIEWPORTS)) {
    test(`has no layout problems at ${name} size (${viewport.width}px) in every state`, async ({ page, rng, guard, evidence }) => {
      await page.setViewportSize(viewport);
      const now = randomNow(rng);
      const healthy = healthyAnswer(rng, now);
      const worst = randomAnswer(rng, now, { days: -12, chainLength: 5, hostMatch: false, sanCount: 30, long: true, hostile: true, sparse: false, hsts: false, dnsIp: null, server: 'Unknown' });
      const failure = handshakeFailure(rng, healthy.domain, 'TLS connection error: connect ECONNREFUSED 203.0.113.9:443');
      await evidence.save('ssl-layout-answers.json', { healthy, worst, failure });

      const hold = deferred();
      guard.allow(/status of 500|HTTP 500/);
      await scriptApi(page, API, async (_call, index): Promise<ScriptedReply> => {
        if (index === 0) await hold.promise;
        if (index === 2) return { status: 500, body: { error: 'Internal server error.', statusCode: 500 } };
        return { body: [healthy, worst, undefined, failure][index] };
      });

      await openPinned(page, now);
      await expectNoUiGlitchesAtRest(page, `${ROUTE} empty state @${name}`);

      await submit(page, healthy.domain);
      await expect(loadingPanel(page)).toBeVisible();
      await expectNoUiGlitchesAtRest(page, `${ROUTE} while checking @${name}`);
      hold.resolve();
      await expect(resultPanel(page)).toBeVisible();
      await expectNoUiGlitchesAtRest(page, `${ROUTE} trusted certificate @${name}`);

      await check(page, worst.domain);
      await expect(resultPanel(page)).toBeVisible();
      await expectNoUiGlitchesAtRest(page, `${ROUTE} expired certificate, 30 long SANs, 5-certificate chain, long values and markup @${name}`);

      await check(page, healthy.domain);
      await expect(errorAlert(page)).toBeVisible();
      await expectNoUiGlitchesAtRest(page, `${ROUTE} request error @${name}`);

      await check(page, healthy.domain);
      await expect(failureBox(page)).toBeVisible();
      await expectNoUiGlitchesAtRest(page, `${ROUTE} handshake failure @${name}`);
    });
  }
});

test.describe('SSL — input', () => {
  test('the request carries the host that was typed and the port as a number; Enter and the button do the same', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const h = randomHost(rng);
    const cases: { host: string; port?: string; wantPort: number }[] = [
      { host: h, wantPort: 443 },
      { host: `   ${h}  `, wantPort: 443 },
      { host: h.toUpperCase(), wantPort: 443 },
      { host: h, port: '8443', wantPort: 8443 },
      { host: h, port: '1', wantPort: 1 },
      { host: h, port: '65535', wantPort: 65535 },
      { host: h, port: ' 993 ', wantPort: 993 },
      { host: h, port: '', wantPort: 443 },
      { host: `https://${h}/login?next=/`, port: '443', wantPort: 443 },
      { host: `HTTP://${h.toUpperCase()}`, port: '443', wantPort: 443 },
      { host: `sub.${h}`, port: '443', wantPort: 443 },
    ];
    await evidence.save('ssl-typed-inputs.json', cases);
    const calls = await mockApi(page, API, (call: ApiCall) => healthyAnswer(rng, now, { domain: hostOf(String((call.body as Body).domain)) || 'unparsable.example' }), { method: 'POST' });
    await openPinned(page, now);

    for (const [i, { host, port, wantPort }] of cases.entries()) {
      const ctx = `host "${host}", port box ${port === undefined ? '(untouched)' : `"${port}"`}`;
      await check(page, host, port, i % 2 ? 'enter' : 'button');
      expect.soft(calls.length, `${ctx}: number of API requests so far`).toBe(i + 1);
      const call = calls.at(-1)!;
      const body = (call.body ?? {}) as Body;
      expect.soft(call.method, `${ctx}: request method`).toBe('POST');
      expect.soft(Object.keys(body).sort(), `${ctx}: fields in the request body`).toEqual(['domain', 'port']);
      expect.soft(hostOf(String(body.domain)), `${ctx}: host the request asks for`).toBe(hostOf(host));
      expect.soft(body.domain, `${ctx}: the host is sent without surrounding spaces`).toBe(String(body.domain).trim());
      expect.soft(body.port === null && wantPort === 443 ? 443 : body.port, `${ctx}: port the request asks for (an empty port box means 443)`).toBe(wantPort);
      await expect.soft(resultPanel(page), `${ctx}: a result is shown`).toBeVisible();
    }
  });

  test('a deep link /ssl?domain=...&port=... fills both boxes and runs exactly one check', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const answer = healthyAnswer(rng, now);
    const port = rng.int(1024, 65000);
    await evidence.save('ssl-deep-link.json', { answer, port });
    const calls = await mockApi(page, API, answer, { method: 'POST' });

    await openPinned(page, now, `${ROUTE}?domain=${encodeURIComponent(answer.domain)}&port=${port}`);
    await expect(resultPanel(page)).toBeVisible();
    await settle(page);
    expect.soft(calls.map(call => call.body), `deep link ?domain=${answer.domain}&port=${port}: requests sent`).toEqual([{ domain: answer.domain, port }]);
    await expect.soft(hostInput(page), 'deep link: host box').toHaveValue(answer.domain);
    await expect.soft(portInput(page), 'deep link: port box').toHaveValue(String(port));
    await expectPageShows(page, answer, `deep link for ${answer.domain}:${port}`);

    await page.goto(`${ROUTE}?domain=${encodeURIComponent(answer.domain)}`, { waitUntil: 'domcontentloaded' });
    await expect(resultPanel(page)).toBeVisible();
    await settle(page);
    expect.soft(calls.at(-1)?.body, 'deep link without a port: the check uses 443').toEqual({ domain: answer.domain, port: 443 });
    await expect.soft(portInput(page), 'deep link without a port: port box').toHaveValue('443');
    expect.soft(calls.length, 'two deep links, two requests').toBe(2);
  });

  test('an empty or blank host box does nothing: no request, no error, no result', async ({ page }) => {
    const calls = await mockApi(page, API, {}, { method: 'POST' });
    await openTool(page, ROUTE, HEADING);
    for (const typed of ['', '    ', '\t']) {
      await submit(page, typed, undefined, 'button');
      await submit(page, typed, undefined, 'enter');
    }
    await settle(page);
    expect(calls.length, 'a blank host box must not call the API').toBe(0);
    await expect(anyError(page)).toHaveCount(0);
    await expect(resultPanel(page)).toHaveCount(0);
    await expect(emptyState(page)).toBeVisible();
    await expect(checkButton(page)).toBeEnabled();
  });

  test('a port written after the host (host:8443) is checked on that port or refused, never silently checked on another port', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const h = randomHost(rng);
    const cases = [`${h}:8443`, `https://${h}:9443/health`, `${h}:25`];
    await evidence.save('ssl-host-with-port.json', cases);
    const calls = await mockApi(page, API, () => healthyAnswer(rng, now, { domain: h }), { method: 'POST' });
    await openPinned(page, now);

    for (const typed of cases) {
      await submit(page, typed, '443');
      await expect(checkButton(page)).toHaveText('🔒 Check');
      await settle(page);
      const body = (calls.at(-1)?.body ?? {}) as Body;
      const refused = (await resultPanel(page).count()) === 0 && (await anyError(page).count()) > 0;
      if (refused) continue;
      // The server keeps only the host of `domain` (everything from the first colon is dropped) and connects to `port`.
      expect.soft(body.port, `typing "${typed}" with the port box at 443: the user asked for port ${portIn(typed)}, the request ${JSON.stringify(body)} makes the server check port ${body.port}, and the result is shown without saying which port was checked`).toBe(portIn(typed));
    }
  });

  test('a port box that does not hold a port number (1-65535) is refused: an error, no result', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const answer = healthyAnswer(rng, now);
    await evidence.save('ssl-bad-ports.json', BAD_PORTS);
    // The answer follows the server's handling of `port` (backend/src/routes/ssl.js: `parseInt(body.port || '443', 10)`,
    // then tls.connect): a missing, null or 0 port means 443; a number outside 0-65535 is answered with an error.
    const calls = await mockApi(page, API, (call: ApiCall) => {
      const port = (call.body as Body).port;
      if (port === null || port === undefined || port === 0) return answer;
      if (typeof port !== 'number' || !Number.isInteger(port) || port < 0 || port > 65535) {
        return { error: `Port should be >= 0 and < 65536. Received type number (${port}).`, domain: answer.domain, response_time_ms: 1 };
      }
      return answer;
    }, { method: 'POST' });
    await openPinned(page, now);

    for (const { typed, why } of BAD_PORTS) {
      const before = calls.length;
      await submit(page, answer.domain, typed);
      await expect(checkButton(page)).toHaveText('\ud83d\udd12 Check');
      await settle(page);
      const sent = calls.length > before ? JSON.stringify(calls.at(-1)!.body) : 'nothing';
      expect.soft(await resultPanel(page).count(), `port box "${typed}" (${why}): no certificate result may be shown. The page sent ${sent}; the server reads a missing or zero port as 443 and connects to whatever number it is given`).toBe(0);
      expect.soft(await anyError(page).count(), `port box "${typed}" (${why}): an error must be shown`).toBeGreaterThan(0);
    }
  });

  test('the port box keeps its value between checks and is sent again', async ({ page, rng }) => {
    const now = randomNow(rng);
    const first = healthyAnswer(rng, now);
    const second = healthyAnswer(rng, now);
    const holder = { answer: first as unknown };
    const calls = await answerWith(page, holder);
    await openPinned(page, now);
    await check(page, first.domain, '8443');
    holder.answer = second;
    await check(page, second.domain);
    await expect.soft(portInput(page), 'port box after the second check').toHaveValue('8443');
    expect.soft(calls.map(call => call.body), 'requests of two checks with the port box set once').toEqual([
      { domain: first.domain, port: 8443 }, { domain: second.domain, port: 8443 },
    ]);
  });
});

test.describe('SSL — every displayed value equals the answer', () => {
  test('random certificates: checks, cards, colours, details, dates, SAN list and chain', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const answers = Array.from({ length: 12 }, () => randomAnswer(rng, now));
    await evidence.save('ssl-answers.json', { now: now.toISOString(), answers });
    await openPinned(page, now);
    const calls = await expectEachShown(page, answers, (a, i) => `answer #${i} (${a.domain}, ${a.days_remaining} days, grade ${a.grade}, chain ${a.chain.length}, ${a.san_names.length} SANs)`);
    expect.soft(calls.length, 'one request per check').toBe(answers.length);
    await expectNoMarkupExecuted(page, 'random answers');
  });

  test('days until expiry: value, colour, and the expiry check at every boundary (expired, 0, 6, 7, 30, 31)', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const dayValues = [-rng.int(2, 900), -1, 0, 1, 6, 7, 8, 29, 30, 31, rng.int(32, 397)];
    const answers = dayValues.map(days => randomAnswer(rng, now, { days, hostile: false, long: false }));
    await evidence.save('ssl-expiry-answers.json', { now: now.toISOString(), answers });
    for (const [i, answer] of answers.entries()) {
      expect(answer.days_remaining, `generator: certificate valid until ${answer.not_after}, checked ${now.toISOString()}`).toBe(dayValues[i]);
      expect(answer.is_expired, `generator: expired flag for ${dayValues[i]} days`).toBe(dayValues[i] < 0);
    }
    await openPinned(page, now);
    await expectEachShown(page, answers, a => `valid until ${a.not_after}, checked ${now.toISOString()} (${a.days_remaining} days)`);
  });

  test('security grade: every grade A+ to F with its colour', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const recipes: { grade: string; options: Parameters<typeof randomAnswer>[2] }[] = [
      { grade: 'A+', options: { days: 120, chainLength: 3, selfSigned: false } },
      { grade: 'A', options: { days: 20, chainLength: 3, selfSigned: false } },
      { grade: 'B', options: { days: 20, chainLength: 1, selfSigned: false } },
      { grade: 'C', options: { days: 3, chainLength: 3, selfSigned: false } },
      { grade: 'D', options: { days: 3, chainLength: 1, selfSigned: false } },
      { grade: 'F', options: { days: -5, chainLength: 3, selfSigned: false } },
      { grade: 'F', options: { days: 200, selfSigned: true } },
    ];
    const answers = recipes.map(recipe => randomAnswer(rng, now, { hostile: false, long: false, ...recipe.options }));
    await evidence.save('ssl-grade-answers.json', answers);
    for (const [i, answer] of answers.entries()) expect(answer.grade, `generator: grade for recipe #${i}`).toBe(recipes[i].grade);
    await openPinned(page, now);
    await expectEachShown(page, answers, a => `grade ${a.grade} (${a.days_remaining} days, chain of ${a.chain.length}, self-signed ${a.is_self_signed})`);
  });

  test('each validation check is shown passed and failed: DNS, server, hostname, HSTS', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const answers = [
      healthyAnswer(rng, now),
      healthyAnswer(rng, now, { dnsIp: null }),
      healthyAnswer(rng, now, { server: 'Unknown' }),
      healthyAnswer(rng, now, { hostMatch: false }),
      healthyAnswer(rng, now, { hsts: false }),
      healthyAnswer(rng, now, { server: 'envoy' }),
      randomAnswer(rng, now, { dnsIp: null, server: 'Unknown', hostMatch: false, hsts: false, days: -3, selfSigned: true }),
    ];
    await evidence.save('ssl-check-answers.json', answers);
    expect(answers[3].hostname_match, 'generator: the fourth answer does not cover its host').toBe(false);
    await openPinned(page, now);
    await expectEachShown(page, answers, a => `dns ${a.dns.ip}, server ${a.server_type.server}, host match ${a.hostname_match}, hsts ${Boolean(a.security_headers.hsts)}, trusted ${a.is_trusted}`);
  });

  test('the trust check names the real reason a certificate is not trusted', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const cases: { why: string; answer: SslAnswer }[] = [
      { why: 'trusted', answer: healthyAnswer(rng, now) },
      { why: 'self-signed', answer: healthyAnswer(rng, now, { selfSigned: true }) },
      { why: 'no intermediate in the chain', answer: healthyAnswer(rng, now, { chainLength: 1 }) },
      { why: 'expired and no intermediate', answer: healthyAnswer(rng, now, { chainLength: 1, days: -9 }) },
      { why: 'expired, complete chain, host matches', answer: healthyAnswer(rng, now, { days: -30 }) },
      { why: 'valid, complete chain, issued for another host', answer: healthyAnswer(rng, now, { hostMatch: false }) },
    ];
    await evidence.save('ssl-trust-answers.json', cases);
    expect(cases[4].answer.has_intermediate && !cases[4].answer.is_trusted && cases[4].answer.is_expired, 'generator: case 5 is expired with a complete chain').toBe(true);
    expect(cases[5].answer.has_intermediate && !cases[5].answer.is_trusted && !cases[5].answer.hostname_match, 'generator: case 6 is for another host with a complete chain').toBe(true);
    await openPinned(page, now);
    await expectEachShown(page, cases.map(c => c.answer), (a, i) => `certificate that is ${cases[i].why} (has_intermediate=${a.has_intermediate}, is_self_signed=${a.is_self_signed}, is_expired=${a.is_expired}, hostname_match=${a.hostname_match})`, { trustReason: true });
  });

  test('subject alternative names: none, one, wildcards, an IP address, a list of 30, very long names', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const answers = [
      healthyAnswer(rng, now, { sanCount: 0 }),
      healthyAnswer(rng, now, { sanCount: 1 }),
      healthyAnswer(rng, now, { sanCount: 2 }),
      healthyAnswer(rng, now, { sanCount: 30 }),
      healthyAnswer(rng, now, { sanCount: 30, long: true }),
      { ...healthyAnswer(rng, now), san_names: ['*.example.org', 'example.org', 'IP Address:203.0.113.7', 'IP Address:2001:DB8:0:0:0:0:0:1', 'xn--mnchen-3ya.de'] },
    ];
    await evidence.save('ssl-san-answers.json', answers);
    await openPinned(page, now);
    await expectEachShown(page, answers, a => `${a.san_names.length} SANs [${a.san_names.slice(0, 3).join(', ')}${a.san_names.length > 3 ? ', ...' : ''}]`);
    expect.soft(answers[0].san_names.length, 'generator: first answer has no SAN').toBe(0);
  });

  test('certificate chains of 1 to 5 certificates ending in a self-issued root: every row and its role', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const answers = [
      healthyAnswer(rng, now, { selfSigned: true }),
      healthyAnswer(rng, now, { chainLength: 1 }),
      healthyAnswer(rng, now, { chainLength: 2 }),
      healthyAnswer(rng, now, { chainLength: 3 }),
      healthyAnswer(rng, now, { chainLength: 4 }),
      healthyAnswer(rng, now, { chainLength: 5, long: true }),
    ];
    await evidence.save('ssl-chain-answers.json', answers);
    await openPinned(page, now);
    await expectEachShown(page, answers, a => `chain [${a.chain.map(c => c.subject).join(' <- ')}]`);
  });

  test('a chain that stops at a certificate issued by a CA outside the chain does not call that certificate a Root', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const answers = [healthyAnswer(rng, now, { chainLength: 2, incompleteChain: true }), healthyAnswer(rng, now, { chainLength: 4, incompleteChain: true })];
    await evidence.save('ssl-incomplete-chain-answers.json', answers);
    for (const answer of answers) {
      const last = answer.chain.at(-1)!;
      expect(last.subject, 'generator: the last certificate is not self-issued').not.toBe(last.issuer);
    }
    await openPinned(page, now);
    await expectEachShown(page, answers, a => `chain [${a.chain.map(c => `${c.subject} (issuer ${c.issuer})`).join(' <- ')}]`);
  });

  test('empty optional fields: organisation as a dash, missing values as N/A, missing key as blank', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const bare: SslAnswer = {
      ...healthyAnswer(rng, now, { chainLength: 3 }),
      subject_org: '', issuer: '', issuer_org: '', serial_number: '', fingerprint_sha256: '', key_type: '', key_size: '',
    };
    bare.chain = bare.chain.map(cert => ({ ...cert, subject_org: '', key_type: '', key_size: '' }));
    const answers = [bare, randomAnswer(rng, now, { sparse: true }), randomAnswer(rng, now, { sparse: true }), randomAnswer(rng, now, { sparse: true, selfSigned: true })];
    await evidence.save('ssl-sparse-answers.json', answers);
    await openPinned(page, now);
    await expectEachShown(page, answers, (a, i) => `sparse answer #${i} (${a.domain})`);
  });

  test('validity dates are the calendar day in the browser time zone, also when UTC is already on the next day', async ({ page, rng, evidence }) => {
    const now = new Date(Date.UTC(2026, 5, 15, 12, 0, 0));
    // Each pair is one second before and exactly on a local-midnight or DST boundary of US Eastern time.
    const instants = [
      Date.UTC(2027, 0, 1, 0, 0, 0), Date.UTC(2026, 11, 31, 23, 59, 59), Date.UTC(2027, 0, 1, 4, 59, 59), Date.UTC(2027, 0, 1, 5, 0, 0),
      Date.UTC(2026, 2, 8, 6, 59, 59), Date.UTC(2026, 2, 8, 7, 0, 0), Date.UTC(2026, 10, 1, 5, 59, 59), Date.UTC(2026, 10, 1, 6, 0, 0),
      Date.UTC(2028, 1, 29, 4, 59, 59), Date.UTC(2028, 1, 29, 5, 0, 0), Date.UTC(2030, 6, 4, 3, 59, 59), Date.UTC(2030, 6, 4, 4, 0, 0),
    ];
    const base = healthyAnswer(rng, now);
    const answers = instants.map((end, i) => ({ ...withValidity(base, end - rng.int(90, 397) * 86_400_000 - rng.int(0, 86_399) * 1000, end, now), domain: `v${i}.${base.domain}` }));
    await evidence.save('ssl-validity-answers.json', answers);
    await openPinned(page, now);
    await expectEachShown(page, answers, a => `valid ${a.not_before} to ${a.not_after}`);
  });

  test('a certificate whose validity dates are missing shows no "Invalid Date"', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const answer = healthyAnswer(rng, now, { chainLength: 3 });
    // The backend sends '' when the TLS library reports no date (ssl.js: `valid_from || ''`).
    answer.not_before = '';
    answer.chain[0].not_before = '';
    answer.chain[2].not_after = '';
    await evidence.save('ssl-missing-dates-answer.json', answer);
    await mockApi(page, API, answer, { method: 'POST' });
    await openPinned(page, now);
    await check(page, answer.domain);
    const view = await readView(page);
    expect.soft(view.details.find(([label]) => label === 'Valid From')?.[1], 'Valid From when the answer has no start date').not.toBe('Invalid Date');
    expect.soft(view.chain[0]?.valid, 'validity line of the server certificate without a start date').not.toContain('Invalid Date');
    expect.soft(view.chain[2]?.valid, 'validity line of the root certificate without an end date').not.toContain('Invalid Date');
  });

  test('values with markup, quotes, commas and very long text are shown as plain text', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const base = randomAnswer(rng, now, { hostile: true, long: true, hostMatch: false, sanCount: 5, chainLength: 3, selfSigned: false, sparse: false });
    const answer: SslAnswer = {
      ...base,
      issuer: `Issuer ${MARKUP}, "CA"`,
      issuer_org: '<script>window.__e2eXss=1</script> & <b>Org</b>',
      serial_number: `0A:1B<svg onload="window.__e2eXss=1">`,
      fingerprint_sha256: `${MARKUP}`,
      protocol: 'TLS <1.3>',
      san_names: [...base.san_names, MARKUP, '"quoted", name'],
      server_type: { ...base.server_type, server: `nginx ${MARKUP}` },
      dns: { ip: `203.0.113.5 ${MARKUP}` },
    };
    await evidence.save('ssl-hostile-answer.json', answer);
    const dialogs: string[] = [];
    page.on('dialog', dialog => { dialogs.push(dialog.message()); void dialog.dismiss(); });
    await mockApi(page, API, answer, { method: 'POST' });
    await openPinned(page, now);
    await check(page, answer.domain);
    await expectPageShows(page, answer, 'answer with markup in every text field');
    await expectNoMarkupExecuted(page, 'answer with markup in every text field');
    expect.soft(dialogs, 'no dialog may be opened by answer values').toEqual([]);
  });
});

test.describe('SSL — copy and export', () => {
  test('Export CSV downloads one row whose cells equal the answer, field by field', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const answers = [healthyAnswer(rng, now), randomAnswer(rng, now, { hostile: true, dnsIp: null, server: 'Unknown', sanCount: 5 }), randomAnswer(rng, now, { sparse: true, selfSigned: true })];
    await evidence.save('ssl-csv-answers.json', answers);
    const holder = { answer: answers[0] as unknown };
    await answerWith(page, holder);
    await openPinned(page, now);

    for (const answer of answers) {
      holder.answer = answer;
      await check(page, answer.domain);
      await expect(resultPanel(page)).toBeVisible();
      const file = await captureDownload(page, () => exportButton(page).click());
      await evidence.save(`ssl-export-${answer.domain}.csv`, file.text);
      expect.soft(file.filename, `${answer.domain}: CSV file name`).toBe(`ssl-report-${answer.domain}.csv`);
      const rows = parseCsv(file.text);
      expect(rows.length, `${answer.domain}: the CSV has one header row and one data row`).toBe(2);
      expect.soft(rows[1].length, `${answer.domain}: the data row has as many cells as the header`).toBe(rows[0].length);
      const record = Object.fromEntries(rows[0].map((name, i) => [name, rows[1][i]]));
      const want = csvRecord(answer);
      expect.soft(Object.keys(record).sort(), `${answer.domain}: CSV columns`).toEqual(Object.keys(want).sort());
      for (const [column, value] of Object.entries(want)) {
        expect.soft(record[column], `${answer.domain}: CSV column "${column}"`).toBe(value);
      }
    }
  });

  test('Copy Summary puts domain, issuer, end of validity, grade and protocol on the clipboard and confirms', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const answers = [healthyAnswer(rng, now), randomAnswer(rng, now, { hostile: true }), { ...healthyAnswer(rng, now), issuer: '' }];
    await evidence.save('ssl-copy-answers.json', answers);
    const holder = { answer: answers[0] as unknown };
    await answerWith(page, holder);
    await openPinned(page, now);

    for (const answer of answers) {
      holder.answer = answer;
      await check(page, answer.domain);
      await expect(resultPanel(page)).toBeVisible();
      await clearClipboard(page);
      await copyButton(page).click();
      await expect(copyButton(page), `${answer.domain}: the button confirms the copy`).toHaveText(/Copied Details!/);
      const copied = (await readClipboard(page)).split('\n');
      const want = expectedSummary(answer).split('\n');
      expect.soft(copied.length, `${answer.domain}: number of lines in the copied summary`).toBe(want.length);
      for (const [i, line] of want.entries()) expect.soft(copied[i], `${answer.domain}: copied summary line ${i + 1}`).toBe(line);
      await expect(copyButton(page), `${answer.domain}: the label returns after two seconds`).toHaveText(/Copy Summary/, { timeout: 6_000 });
    }
  });
});

test.describe('SSL — failures', () => {
  const FAILURES: { status: number; body: unknown; contentType?: string; shows: RegExp; why: string }[] = [
    { status: 200, body: { error: 'Invalid domain.' }, shows: /^⚠️ Invalid domain\.$/, why: 'answer refusing the host' },
    { status: 200, body: { error: 'getaddrinfo ENOTFOUND nowhere.example', domain: 'nowhere.example', response_time_ms: 12 }, shows: /^⚠️ getaddrinfo ENOTFOUND nowhere\.example$/, why: 'answer with an error and no DNS data' },
    { status: 200, body: { error: 'Connection timeout (10s)', domain: 'slow.example', response_time_ms: 10004, dns: { ip: '203.0.113.9', all_ips: ['203.0.113.9'] }, server_type: { server: 'Unknown', error: 'fetch failed', security_headers: {} } }, shows: /^⚠️ Connection timeout \(10s\)$/, why: 'handshake timeout after DNS answered' },
    { status: 200, body: { error: 'TLS connection error: read ECONNRESET', domain: 'reset.example', response_time_ms: 1741, dns: { ip: null, error: 'No A record found' }, server_type: { server: 'Unknown', error: 'fetch failed', security_headers: {} } }, shows: /^⚠️ TLS connection error: read ECONNRESET$/, why: 'handshake error with DNS data that has no address' },
    { status: 400, body: { error: 'Bad Request', statusCode: 400 }, shows: /^⚠️ Bad Request$/, why: 'HTTP 400' },
    { status: 429, body: { error: 'Rate limit exceeded, retry in 1 minute', statusCode: 429 }, shows: /^⚠️ Rate limit exceeded, retry in 1 minute$/, why: 'HTTP 429' },
    { status: 500, body: { error: 'Internal server error.', statusCode: 500 }, shows: /^⚠️ Internal server error\.$/, why: 'HTTP 500' },
    { status: 502, body: '<html><body><h1>502 Bad Gateway</h1></body></html>', contentType: 'text/html', shows: /502/, why: 'proxy error page instead of JSON' },
    { status: 500, body: {}, shows: /500/, why: 'error without a message' },
    { status: 200, body: { error: `Certificate parse error: ${MARKUP}` }, shows: /^⚠️ Certificate parse error: <img src=x onerror="window\.__e2eXss=1">$/, why: 'message containing markup' },
  ];

  test('every error answer shows its message, no certificate, no progress panel, and the next check works', async ({ page, rng, guard }) => {
    const now = randomNow(rng);
    const good = healthyAnswer(rng, now);
    guard.allow(/status of (400|429|500|502)|HTTP 50\d/);
    const api = await scriptApi(page, API, (_call, index): ScriptedReply => {
      // Even requests fail with the next error in the table; odd requests succeed.
      const failure = index % 2 === 0 ? FAILURES[index / 2] : undefined;
      return failure ? { status: failure.status, body: failure.body, contentType: failure.contentType } : { body: good };
    });
    await openPinned(page, now);

    for (const failure of FAILURES) {
      const ctx = `HTTP ${failure.status} (${failure.why})`;
      await check(page, good.domain);
      await expect.soft(anyError(page), `${ctx}: exactly one error box`).toHaveCount(1);
      await expect.soft(anyError(page).first(), `${ctx}: the error message is shown`).toHaveText(failure.shows);
      await expect.soft(resultPanel(page), `${ctx}: no certificate result is shown`).toHaveCount(0);
      await expect.soft(exportButton(page), `${ctx}: no export button without a result`).toHaveCount(0);
      await expect.soft(loadingPanel(page), `${ctx}: the progress panel is gone`).toHaveCount(0);
      await expect.soft(emptyState(page), `${ctx}: the "enter a hostname" hint is not shown next to an error`).toHaveCount(0);
      await expect.soft(checkButton(page), `${ctx}: the button is usable again`).toBeEnabled();
      await expectNoMarkupExecuted(page, ctx);

      await check(page, good.domain);
      await expect.soft(anyError(page), `after ${ctx}: the error disappears on the next successful check`).toHaveCount(0);
      await expect.soft(resultPanel(page), `after ${ctx}: the next check shows its result`).toBeVisible();
    }
    expect.soft(api.calls.length, 'one request per check').toBe(FAILURES.length * 2);
  });

  test('a network failure shows an error, no result, and the tool recovers', async ({ page, rng, guard }) => {
    const now = randomNow(rng);
    const good = healthyAnswer(rng, now);
    guard.allow(/ERR_FAILED|Failed to fetch/);
    await openPinned(page, now);
    await failApi(page, API);
    await check(page, good.domain);
    await expect(anyError(page), 'a failed request must be reported').toBeVisible();
    expect.soft(((await anyError(page).first().textContent()) ?? '').replace('⚠️', '').trim().length, 'the error has a message').toBeGreaterThan(0);
    await expect.soft(resultPanel(page), 'no result after a network failure').toHaveCount(0);
    await expect.soft(loadingPanel(page), 'the progress panel is gone').toHaveCount(0);
    await expect.soft(checkButton(page), 'the button is usable again').toBeEnabled();

    await page.unroute(API);
    await mockApi(page, API, good, { method: 'POST' });
    await check(page, good.domain);
    await expect.soft(anyError(page), 'the error clears').toHaveCount(0);
    await expectPageShows(page, good, `recovery check of ${good.domain}`);
  });

  test('while a check runs: progress panel, disabled labelled button, and the previous result and error are cleared', async ({ page, rng, guard }) => {
    const now = randomNow(rng);
    const first = healthyAnswer(rng, now);
    const second = healthyAnswer(rng, now);
    const holds = [deferred(), deferred(), deferred()];
    guard.allow(/status of 500|HTTP 500/);
    const api = await scriptApi(page, API, async (_call, index): Promise<ScriptedReply> => {
      await holds[index].promise;
      return index === 1 ? { status: 500, body: { error: 'Internal server error.' } } : { body: index === 0 ? first : second };
    });
    await openPinned(page, now);

    const expectLoading = async (ctx: string) => {
      await expect(loadingPanel(page), `${ctx}: progress panel`).toBeVisible();
      await expect.soft(loadingPanel(page), `${ctx}: progress panel text`).toContainText('Checking SSL Certificate');
      await expect.soft(checkButton(page), `${ctx}: button label while checking`).toHaveText('⏳ Checking...');
      await expect.soft(checkButton(page), `${ctx}: button disabled while checking`).toBeDisabled();
      await expect.soft(resultPanel(page), `${ctx}: no result while checking`).toHaveCount(0);
      await expect.soft(anyError(page), `${ctx}: no error while checking`).toHaveCount(0);
      await expect.soft(emptyState(page), `${ctx}: the empty-state hint is hidden while checking`).toHaveCount(0);
    };

    await submit(page, first.domain);
    await expectLoading('first check');
    holds[0].resolve();
    await expect(resultPanel(page)).toBeVisible();
    await expect.soft(loadingPanel(page), 'progress panel after the answer').toHaveCount(0);

    await submit(page, 'fails.example');
    await expectLoading('second check (previous result on screen)');
    holds[1].resolve();
    await expect(errorAlert(page)).toHaveText('⚠️ Internal server error.');

    await submit(page, second.domain);
    await expectLoading('third check (previous error on screen)');
    holds[2].resolve();
    await expect(resultPanel(page)).toBeVisible();
    await expect.soft(checkButton(page), 'button after the last check').toHaveText('🔒 Check');
    await expect.soft(checkButton(page)).toBeEnabled();
    expect.soft(api.calls.length, 'three checks, three requests').toBe(3);
    await expectPageShows(page, second, `third check ${second.domain}`);
  });

  test('pressing Enter again while a check runs does not send a second request', async ({ page, rng }) => {
    const now = randomNow(rng);
    const answer = healthyAnswer(rng, now);
    const hold = deferred();
    const api = await scriptApi(page, API, async (): Promise<ScriptedReply> => { await hold.promise; return { body: answer }; });
    await openPinned(page, now);

    await submit(page, answer.domain, undefined, 'enter');
    await expect(loadingPanel(page)).toBeVisible();
    await hostInput(page).press('Enter');
    await hostInput(page).press('Enter');
    await settle(page);
    const sent = api.calls.length;
    hold.resolve();
    await expect(resultPanel(page)).toBeVisible();
    expect(sent, `requests sent for one check of ${answer.domain} after pressing Enter three times (the button is disabled while checking; Enter must be too)`).toBe(1);
  });

  test('a slow answer to an earlier check never replaces the result of a later one', async ({ page, rng, evidence }) => {
    const now = randomNow(rng);
    const slow = healthyAnswer(rng, now);
    const fast = healthyAnswer(rng, now, { days: 3, chainLength: 1 });
    await evidence.save('ssl-race.json', { slowFirst: slow.domain, fastSecond: fast.domain });
    const hold = deferred();
    const api = await scriptApi(page, API, async (call): Promise<ScriptedReply> => {
      if ((call.body as Body).domain === slow.domain) { await hold.promise; return { body: slow }; }
      return { body: fast };
    });
    await openPinned(page, now);

    await submit(page, slow.domain, undefined, 'enter');
    await expect(loadingPanel(page)).toBeVisible();
    await submit(page, fast.domain, undefined, 'enter');
    await settle(page);
    if (api.calls.length === 2) {
      await api.delivered(1);
      await expect.soft(cardValue(page, 'Security Grade'), `check of ${fast.domain} answered while ${slow.domain} is still pending`).toHaveText(fast.grade);
    }
    hold.resolve();
    await api.delivered(0);
    await settle(page);

    // Whatever the page did with the second Enter, the result must belong to the last request it sent.
    const lastRequested = String((api.calls.at(-1)!.body as Body).domain);
    const want = lastRequested === slow.domain ? slow : fast;
    await expect(resultPanel(page)).toBeVisible();
    const shown = await readView(page);
    expect(shown.checks[0]?.text,
      `requests were sent for [${api.calls.map(c => (c.body as Body).domain).join(', ')}]; the answer for ${slow.domain} arrived last. The result on screen must be for the last request (${lastRequested})`)
      .toBe(`${want.domain} resolves to ${want.dns.ip}`);
    await expectPageShows(page, want, `result after the late answer for ${slow.domain}`);
    await expect.soft(hostInput(page), 'the host box and the result name the same host').toHaveValue(lastRequested);
  });
});

test.describe('SSL — state', () => {
  test('a second check replaces the first result completely, an error replaces a result, and a result replaces an error', async ({ page, rng, guard, evidence }) => {
    const now = randomNow(rng);
    const first = healthyAnswer(rng, now, { chainLength: 5, sanCount: 30 });
    const second = randomAnswer(rng, now, { selfSigned: true, sanCount: 0, days: -40, hsts: false, dnsIp: null, server: 'Unknown', hostile: false, long: false, sparse: true });
    const third = healthyAnswer(rng, now, { chainLength: 2, sanCount: 1 });
    await evidence.save('ssl-replace-answers.json', { first, second, third });
    guard.allow(/status of 500|HTTP 500/);
    await scriptApi(page, API, (_call, index): ScriptedReply => (
      index === 2 ? { status: 500, body: { error: 'Internal server error.' } } : { body: [first, second, undefined, third][index] }
    ));
    await openPinned(page, now);

    await check(page, first.domain);
    await expectPageShows(page, first, `first result ${first.domain}`);

    await check(page, second.domain);
    await expectPageShows(page, second, `second result ${second.domain} after ${first.domain}`);
    const text = (await page.locator('.signal-tool-primary').textContent()) ?? '';
    for (const leftover of [first.fingerprint_sha256, first.serial_number, first.san_names[0], first.chain[1].subject, String(first.dns.ip)]) {
      expect.soft(text.includes(leftover), `nothing of the first result ("${leftover}") may remain after checking ${second.domain}`).toBe(false);
    }

    await check(page, 'fails.example');
    await expect(errorAlert(page)).toHaveText('⚠️ Internal server error.');
    await expect.soft(resultPanel(page), 'an error removes the previous result').toHaveCount(0);
    await expect.soft(page.locator('.signal-tool-primary .tool-tag'), 'an error removes the SAN list').toHaveCount(0);

    await check(page, third.domain);
    await expect.soft(anyError(page), 'a result removes the previous error').toHaveCount(0);
    await expectPageShows(page, third, `third result ${third.domain} after an error`);
  });

  test('reloading the page returns to the clean empty state with port 443 and sends nothing', async ({ page, rng }) => {
    const now = randomNow(rng);
    const answer = healthyAnswer(rng, now);
    const calls = await mockApi(page, API, answer, { method: 'POST' });
    await openPinned(page, now);
    await check(page, answer.domain, '8443');
    await expect(resultPanel(page)).toBeVisible();

    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
    await expect(emptyState(page), 'empty state after reload').toBeVisible();
    await expect(hostInput(page), 'the host box is empty after reload').toHaveValue('');
    await expect(portInput(page), 'the port box is back at 443 after reload').toHaveValue('443');
    await expect(resultPanel(page)).toHaveCount(0);
    expect(calls.length, 'the reload itself sends no check').toBe(1);
  });
});
