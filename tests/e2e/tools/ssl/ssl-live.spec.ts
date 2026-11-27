import { test, expect, type Page } from '../_support/fixtures';
import { openTool } from '../_support/navigation';
import { captureApi } from '../_support/io';
import { DAY_MS, grade, localDay, type SslAnswer } from './oracle';
import { HEADING, ROUTE, anyError, check, checkButton, resultPanel, submit, type SslView } from './page';
import { expectPageShows } from './checks';
import { probeTls, resolveA, sendsHsts, type TlsFacts } from './tls-probe';

/**
 * SSL Certificate Checker against the real backend and real hosts (`@live`).
 *
 * Each test checks the page twice: against the answer the API gave (the page
 * must show exactly that), and against a TLS connection the test opens itself
 * with Node's `tls` module (the answer must be true). Only what legitimately
 * differs between two connections is tolerated: which A record is listed
 * first, and a day count taken a few seconds apart.
 */

const detail = (view: SslView, label: string) => view.details.find(([name]) => name === label)?.[1] ?? `(no "${label}" row)`;
const card = (view: SslView, label: string) => view.cards.find(c => c.label === label)?.value ?? `(no "${label}" card)`;

/** Network trouble between this machine and the target host; says nothing about the application. */
const UNREACHABLE = /ECONNRESET|ETIMEDOUT|ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|socket hang up|Connection timeout/;

/**
 * Runs a real check through the page and returns the API exchange. When the
 * answer is a connection failure to the target host, the check is pressed
 * again, up to `attempts` times: some test hosts drop every second connection.
 */
async function liveCheck(page: Page, host: string, attempts = 3) {
  await openTool(page, ROUTE, HEADING);
  for (let attempt = 1; ; attempt++) {
    const before = Date.now();
    const live = await captureApi<SslAnswer & { error?: string }>(page, '/api/ssl', () => submit(page, host), 60_000);
    const after = Date.now();
    await expect(checkButton(page)).toHaveText('\ud83d\udd12 Check', { timeout: 60_000 });
    const unreachable = typeof live.response?.error === 'string' && UNREACHABLE.test(live.response.error);
    if (!unreachable || attempt >= attempts) return { live, before, after, unreachable };
  }
}

/** The test's own TLS connection, with the same patience. */
async function probe(host: string, attempts = 3) {
  let result = await probeTls(host, 443, 6_000);
  for (let attempt = 1; !result.ok && attempt < attempts; attempt++) result = await probeTls(host, 443, 6_000);
  return result;
}

/** The page against an independent TLS connection to the same host. */
function expectAgreesWithProbe(view: SslView, probe: TlsFacts, host: string, window: { before: number; after: number }) {
  const ctx = `live ${host} vs the test's own TLS connection`;
  expect(detail(view, 'Fingerprint (SHA-256)'), `${ctx}: SHA-256 fingerprint. If this differs the two connections were served different certificates and nothing below can be compared`).toBe(probe.fingerprint256);

  expect.soft(detail(view, 'Subject'), `${ctx}: subject common name`).toBe(probe.leaf.subject);
  expect.soft(detail(view, 'Organization'), `${ctx}: subject organisation`).toBe(probe.leaf.subjectOrg || '—');
  expect.soft(detail(view, 'Issuer'), `${ctx}: issuer common name`).toBe(probe.leaf.issuer);
  expect.soft(detail(view, 'Issuer Org'), `${ctx}: issuer organisation`).toBe(probe.leaf.issuerOrg || '—');
  expect.soft(detail(view, 'Serial Number'), `${ctx}: serial number`).toBe(probe.serial);
  expect.soft(detail(view, 'Valid From'), `${ctx}: Valid From (certificate notBefore ${new Date(probe.leaf.validFromMs).toISOString()})`).toBe(localDay(probe.leaf.validFromMs));
  expect.soft(detail(view, 'Valid Until'), `${ctx}: Valid Until (certificate notAfter ${new Date(probe.leaf.validToMs).toISOString()})`).toBe(localDay(probe.leaf.validToMs));
  expect.soft(card(view, 'Key Type'), `${ctx}: key type and size`).toBe(`${probe.leaf.keyType} ${probe.leaf.keyBits}`);
  expect.soft(card(view, 'Protocol'), `${ctx}: negotiated protocol`).toBe(probe.protocol);

  expect.soft(view.sans.length, `${ctx}: number of subject alternative names listed (the certificate has ${probe.sans.length})`).toBe(probe.sans.length);
  expect.soft(view.sanTitle, `${ctx}: SAN heading with its count`).toBe(`Subject Alternative Names (${probe.sans.length})`);
  expect.soft(view.sans, `${ctx}: subject alternative names, in certificate order`).toEqual(probe.sans);

  expect.soft(view.chainTitle, `${ctx}: chain heading with its count`).toBe(`Certificate Chain (${probe.chain.length})`);
  expect.soft(view.chain.map(row => row.subject), `${ctx}: chain subjects, leaf first`).toEqual(probe.chain.map(cert => cert.subject));
  expect.soft(view.chain.map(row => row.issuer), `${ctx}: chain issuers`).toEqual(probe.chain.map(cert => cert.issuer));
  expect.soft(view.chain.map(row => row.key), `${ctx}: chain keys`).toEqual(probe.chain.map(cert => `${cert.keyType} ${cert.keyBits}`));
  expect.soft(view.chain.map(row => row.valid), `${ctx}: chain validity periods`).toEqual(probe.chain.map(cert => `${localDay(cert.validFromMs)} — ${localDay(cert.validToMs)}`));
  expect.soft(view.chain[0]?.badge, `${ctx}: the first chain row is the server certificate`).toBe('Server');

  const dayCounts = [window.before, window.after].map(at => String(Math.floor((probe.leaf.validToMs - at) / DAY_MS)));
  expect.soft(dayCounts, `${ctx}: Days Until Expiry (whole days from the check to ${new Date(probe.leaf.validToMs).toISOString()})`).toContain(card(view, 'Days Until Expiry'));
  const expired = probe.leaf.validToMs < window.after;
  expect.soft(view.checks[3]?.ok, `${ctx}: expiry check passed (certificate ${expired ? 'has expired' : 'is still valid'})`).toBe(!expired);
  expect.soft(view.checks[4]?.ok, `${ctx}: hostname check (RFC 6125 match of ${host} against the certificate: ${probe.hostMatches})`).toBe(probe.hostMatches);
  expect.soft(view.checks[2]?.ok, `${ctx}: trust check. Node's verification of the same connection says authorized=${probe.authorized}${probe.authorizationError ? ` (${probe.authorizationError})` : ''}; the page says "${view.checks[2]?.text}"`).toBe(probe.authorized);

  const shownDays = Number(card(view, 'Days Until Expiry'));
  const selfSigned = probe.chain.length === 1 && probe.leaf.selfIssued;
  expect.soft(card(view, 'Security Grade'), `${ctx}: grade for ${shownDays} days, chain of ${probe.chain.length}, self-signed ${selfSigned}`).toBe(grade(shownDays, probe.chain.length > 1, selfSigned));
  if (!probe.authorized) {
    expect.soft(['A+', 'A'], `${ctx}: a certificate that clients reject (${probe.authorizationError}) must not be graded ${card(view, 'Security Grade')}`).not.toContain(card(view, 'Security Grade'));
  }
}

test.describe('SSL — real hosts @live', () => {
  test.skip(process.env.E2E_LIVE === '0', 'live tests disabled');

  const HEALTHY: { host: string; note: string }[] = [
    { host: 'example.com', note: 'EC key, two names' },
    { host: 'iana.org', note: 'RSA key, wildcard subject, HSTS' },
    { host: 'wikipedia.org', note: 'certificate with more than 30 names' },
  ];

  for (const { host, note } of HEALTHY) {
    test(`${host} (${note}): the page shows exactly what the API returned, and that agrees with the certificate the host presents`, async ({ page, evidence }) => {
      let facts = await probe(host);
      expect(facts.ok, `precondition: the test machine can open a TLS connection to ${host}:443 (${facts.ok ? '' : facts.error})`).toBe(true);

      const { live, before, after } = await liveCheck(page, host);
      await evidence.save(`ssl-live-${host}.json`, live);
      expect(live.status, `POST /api/ssl for ${host}`).toBe(200);
      expect.soft(live.request, 'request body').toEqual({ domain: host, port: 443 });
      expect(live.response.error, `the API reports no error for ${host}`).toBeUndefined();
      await expect(resultPanel(page)).toBeVisible();

      // 1. The page against the API answer. Chain roles are compared for the first row only: live chains often end in a
      //    cross-signed certificate, which the incomplete-chain contract test covers.
      const view = await expectPageShows(page, live.response, `live ${host} vs API answer`, { roles: 'first' });

      // 2. The page against the certificate itself. Hosts with several front ends can rotate certificates: look again once.
      if (facts.ok && facts.fingerprint256 !== live.response.fingerprint_sha256) facts = await probe(host);
      await evidence.save(`ssl-probe-${host}.json`, facts);
      if (!facts.ok) throw new Error(`second TLS connection to ${host} failed: ${facts.error}`);
      expectAgreesWithProbe(view, facts, host, { before, after });

      // 3. DNS and HSTS, asked directly.
      const addresses = await resolveA(host);
      const shownIp = view.checks[0]?.text.replace(`${host} resolves to `, '') ?? '';
      if (addresses.length) expect.soft(addresses, `live ${host}: the address in "${view.checks[0]?.text}" is one of the host's A records`).toContain(shownIp);
      const hsts = await sendsHsts(host);
      if (hsts !== null) expect.soft(view.checks[5]?.ok, `live ${host}: HSTS check (https://${host}/ ${hsts ? 'sends' : 'does not send'} Strict-Transport-Security)`).toBe(hsts);
    });
  }

  const BROKEN: { host: string; what: string }[] = [
    { host: 'expired.badssl.com', what: 'an expired certificate' },
    { host: 'self-signed.badssl.com', what: 'a self-signed certificate' },
    { host: 'wrong.host.badssl.com', what: 'a certificate for another host name' },
    { host: 'untrusted-root.badssl.com', what: 'a chain to a root no client trusts' },
  ];

  // badssl.com resets a large share of connections from some networks, so both sides try up to eight times.
  // A host that still cannot be reached is skipped: there is nothing to compare.
  for (const { host, what } of BROKEN) {
    test(`${host} (${what}) is reported as not trusted, and agrees with the certificate the host presents`, async ({ page, evidence }) => {
      test.setTimeout(240_000);
      const facts = await probe(host, 8);
      test.skip(!facts.ok, `${host} cannot be reached from the test machine (${facts.ok ? '' : facts.error})`);
      if (!facts.ok) return;
      expect(facts.authorized, `precondition: Node rejects the certificate of ${host}`).toBe(false);

      const { live, before, after, unreachable } = await liveCheck(page, host, 8);
      await evidence.save(`ssl-live-${host}.json`, { live, facts });
      test.skip(unreachable, `the backend could not reach ${host} in eight attempts (${live.response?.error})`);
      expect(live.response.error, `the API reports no error for ${host}`).toBeUndefined();
      await expect(resultPanel(page)).toBeVisible();
      const view = await expectPageShows(page, live.response, `live ${host} vs API answer`, { roles: 'first' });
      expectAgreesWithProbe(view, facts, host, { before, after });

      if (host.startsWith('expired.')) expect.soft(view.checks[3]?.text, `${host}: expiry check`).toBe('Certificate EXPIRED');
      if (host.startsWith('self-signed.')) expect.soft(view.checks[2]?.text, `${host}: trust check`).toBe('Self-signed certificate');
      if (host.startsWith('wrong.host.')) expect.soft(view.checks[4]?.text, `${host}: hostname check`).toBe('Hostname does NOT match');
    });
  }

  test('a URL pasted into the host box is checked as its host', async ({ page, evidence }) => {
    const { live } = await liveCheck(page, 'https://Example.com/some/path?x=1');
    await evidence.save('ssl-live-url.json', live);
    await expect(resultPanel(page)).toBeVisible();
    const view = await expectPageShows(page, live.response, 'live "https://Example.com/some/path?x=1" vs API answer', { roles: 'first' });
    expect.soft(view.checks[0]?.text, 'the result is for the host of the URL').toMatch(/^example\.com resolves to \d+\.\d+\.\d+\.\d+$/);
    const facts = await probe('example.com');
    if (facts.ok) expect.soft(detail(view, 'Fingerprint (SHA-256)'), 'fingerprint of the certificate example.com presents').toBe(facts.fingerprint256);
  });

  test('a host that does not exist shows an error and no certificate', async ({ page, rng }) => {
    // RFC 2606 reserves .invalid: the name can never resolve.
    const host = `${rng.string(12, 'abcdefghijklmnopqrstuvwxyz')}.invalid`;
    await openTool(page, ROUTE, HEADING);
    await check(page, host);
    await expect(anyError(page), `${host} does not exist; an error must be shown`).toBeVisible();
    expect.soft(((await anyError(page).first().textContent()) ?? '').replace('⚠️', '').trim().length, 'the error has a message').toBeGreaterThan(0);
    await expect.soft(resultPanel(page), `no certificate may be shown for ${host}`).toHaveCount(0);
  });
});
