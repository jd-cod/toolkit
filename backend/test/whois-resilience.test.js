import test from 'node:test';
import assert from 'node:assert/strict';
import { buildWhoisSnapshot, getRdapBootstrapStatus } from '../src/routes/whois.js';

test.describe('WHOIS Fallback & Resilience Verification', () => {
  const originalFetch = globalThis.fetch;

  test.afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test('1. RDAP upstream rate-limiting (HTTP 429) triggers clean fallback to port 43 WHOIS', async () => {
    // Intercept fetch: allow IANA bootstrap to succeed, but return 429 on RDAP domain queries
    globalThis.fetch = async (url, options) => {
      const urlStr = String(url);
      if (urlStr.includes('data.iana.org')) {
        return originalFetch(url, options);
      }
      return new Response(JSON.stringify({ error: 'Too Many Requests', code: 429 }), {
        status: 429,
        statusText: 'Too Many Requests',
        headers: { 'Content-Type': 'application/json' },
      });
    };

    const snapshot = await buildWhoisSnapshot('google.com');
    assert.equal(snapshot.domain, 'google.com');
    // Must have fallen back to WHOIS
    assert.equal(snapshot.data_source, 'whois', 'Expected data_source to be whois after RDAP 429');
    assert.equal(snapshot.registered, true);
    assert.ok(snapshot.raw_response.length > 50, 'Expected raw port 43 WHOIS response');
    assert.ok(snapshot.raw_whois.length > 50, 'Expected raw_whois to be populated');
  });

  test('2. RDAP upstream timeout / network hang triggers clean fallback to port 43 WHOIS', async () => {
    // Simulate RDAP endpoint timing out / aborting
    globalThis.fetch = async (url, options) => {
      const urlStr = String(url);
      if (urlStr.includes('data.iana.org')) {
        return originalFetch(url, options);
      }
      const abortErr = new Error('The operation was aborted due to timeout');
      abortErr.name = 'AbortError';
      throw abortErr;
    };

    const snapshot = await buildWhoisSnapshot('google.com');
    assert.equal(snapshot.domain, 'google.com');
    assert.equal(snapshot.data_source, 'whois', 'Expected data_source to be whois after timeout');
    assert.equal(snapshot.registered, true);
    assert.ok(snapshot.raw_response.includes('MarkMonitor') || snapshot.raw_response.includes('GOOGLE.COM'));
  });

  test('3. RDAP upstream 503 Service Unavailable triggers clean fallback to port 43 WHOIS', async () => {
    globalThis.fetch = async (url, options) => {
      const urlStr = String(url);
      if (urlStr.includes('data.iana.org')) {
        return originalFetch(url, options);
      }
      return new Response(JSON.stringify({ error: 'Service Unavailable', code: 503 }), {
        status: 503,
        statusText: 'Service Unavailable',
        headers: { 'Content-Type': 'application/json' },
      });
    };

    const snapshot = await buildWhoisSnapshot('google.com');
    assert.equal(snapshot.domain, 'google.com');
    assert.equal(snapshot.data_source, 'whois', 'Expected data_source to be whois after 503');
    assert.equal(snapshot.registered, true);
  });

  test('4. TLDs without RDAP bootstrap entry natively route through port 43 WHOIS', async () => {
    // .de registry (DENIC) does not serve RDAP via IANA bootstrap
    const snapshot = await buildWhoisSnapshot('denic.de');
    assert.equal(snapshot.domain, 'denic.de');
    assert.equal(snapshot.data_source, 'whois');
    assert.equal(snapshot.registered, true);
    assert.ok(snapshot.raw_response.includes('whois.denic.de'));
  });

  test('5. Internationalized Domain Names (IDN in Punycode) succeed via port 43 WHOIS', async () => {
    // Test xn--mnchen-3ya.de (münchen.de) and xn--e1afmkfd.xn--p1ai (яндекс.рф)
    const snapshot = await buildWhoisSnapshot('xn--e1afmkfd.xn--p1ai');
    assert.equal(snapshot.domain, 'xn--e1afmkfd.xn--p1ai');
    assert.equal(snapshot.data_source, 'whois');
    assert.equal(snapshot.registered, true);
    assert.equal(snapshot.registrar, 'CC-RF');
    assert.ok(snapshot.raw_response.includes('tcinet.ru') || snapshot.raw_response.includes('XN--E1AFMKFD'));
  });

  test('6. Raw Unicode IDNs (e.g. münchen.de) are normalized to Punycode and queried properly', async () => {
    const snapshot = await buildWhoisSnapshot('münchen.de');
    assert.equal(snapshot.domain, 'xn--mnchen-3ya.de');
    assert.equal(snapshot.data_source, 'whois');
    assert.equal(snapshot.registered, true);
    assert.ok(snapshot.raw_response.includes('whois.denic.de') || snapshot.raw_response.includes('xn--mnchen-3ya.de'));
  });
});
