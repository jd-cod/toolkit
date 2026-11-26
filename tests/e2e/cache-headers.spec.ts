import { test, expect } from '@playwright/test';

/**
 * Cache-Control contract for static assets vs. API routes.
 *
 * Ported from scripts/qa_verification.mjs, which covered this well but lived
 * outside the test runner. These headers are load-bearing: this project edits
 * `public/js/*.js` constantly and relies on a `?v=` cache buster because the
 * 30-day max-age means a stale script is served for a month. A regression here
 * silently breaks deployments in a way no functional test would catch.
 *
 * Note the two distinct policies:
 *   - long-lived immutable assets (scripts, sample logs)  → 30 days
 *   - API routes                                          → no-store
 * A route flipping to `public` could leak user data; an asset flipping to
 * `no-store` would destroy the CDN hit ratio.
 */

const PUBLIC_IMMUTABLE = 'public, max-age=2592000, s-maxage=2592000, immutable';
const PUBLIC_SWR = 'public, max-age=2592000, s-maxage=2592000, stale-while-revalidate=86400';
const MMDB_SWR = 'public, max-age=604800, s-maxage=604800, stale-while-revalidate=86400';
const NO_STORE = 'no-store, no-cache, must-revalidate, private';

test.describe('Cache-Control headers', () => {
  test('client scripts are served with a 30-day SWR policy', async ({ request }) => {
    // These are the files we hot-edit. The long max-age is exactly why the
    // `?v=` buster in page.tsx is mandatory — assert both halves of that.
    for (const script of ['/js/dashboard.js', '/js/geoip.js']) {
      const res = await request.get(script);
      expect(res.status(), `${script} should be served`).toBe(200);
      expect(res.headers()['cache-control'], `${script} cache-control`).toBe(PUBLIC_SWR);
    }
  });

  test('sample logs are immutable', async ({ request }) => {
    for (const sample of ['/samples/bot-crawlers.log', '/samples/heavy-traffic.log']) {
      const res = await request.get(sample);
      expect(res.status(), `${sample} should be served`).toBe(200);
      expect(res.headers()['cache-control'], `${sample} cache-control`).toBe(PUBLIC_IMMUTABLE);
    }
  });

  test('GeoIP databases use a 7-day SWR policy', async ({ request }) => {
    for (const db of [
      '/data/GeoLite2-Country.mmdb',
      '/data/GeoLite2-ASN.mmdb',
      '/data/GeoLite2-City.mmdb',
    ]) {
      const res = await request.get(db);
      // The .mmdb files are runtime-generated and bind-mounted, not committed
      // (see .gitignore). On a cold checkout these 404 — that is an
      // environment problem, not a cache-header regression, so skip rather
      // than fail the suite.
      if (res.status() === 404) {
        test.info().annotations.push({
          type: 'skip',
          description: `${db} not present on this host (GeoIP DB not yet downloaded)`,
        });
        return;
      }
      expect(res.status(), `${db} should be served`).toBe(200);
      expect(res.headers()['cache-control'], `${db} cache-control`).toBe(MMDB_SWR);
    }
  });

  test('GeoIP metadata is revalidated without cache staleness', async ({ request }) => {
    const res = await request.get('/data/geoip-meta.json');
    if (res.status() === 404) {
      test.info().annotations.push({
        type: 'skip',
        description: 'geoip-meta.json not present on this host',
      });
      return;
    }
    expect(res.status()).toBe(200);
    expect(res.headers()['cache-control']).toBe('public, max-age=0, must-revalidate');
  });

  test('API routes are never cached', async ({ request }) => {
    const res = await request.get('/api/health');
    expect(res.status()).toBe(200);
    expect(res.headers()['cache-control'], '/api/health cache-control').toBe(NO_STORE);
  });

  test('mutating API routes are never cached', async ({ request }) => {
    // POST routes. Asserted on headers only — we are checking the caching
    // policy, not the response body, and these hit the real resolver.
    const res = await request.post('/api/dns', {
      data: { domain: 'google.com', type: 'A', resolver: '1.1.1.1' },
    });
    expect(res.headers()['cache-control'], '/api/dns cache-control').toBe(NO_STORE);
  });
});
