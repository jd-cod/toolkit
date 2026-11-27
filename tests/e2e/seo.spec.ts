import { test, expect } from '@playwright/test';

const TOOLS = [
  { path: '/nginx', expectedTitle: 'Traffic Log Analyzer | SysAdmin Toolkit' },
  { path: '/dns', expectedTitle: 'DNS Lookup & Record Checker | SysAdmin Toolkit' },
  { path: '/ssl', expectedTitle: 'SSL Certificate Checker | SysAdmin Toolkit' },
  { path: '/whois', expectedTitle: 'WHOIS & Domain Registration Lookup | SysAdmin Toolkit' },
  { path: '/asn', expectedTitle: 'ASN Lookup & IP Prefix Finder | SysAdmin Toolkit' },
  { path: '/abuse', expectedTitle: 'IP Reputation & Abuse Lookup | SysAdmin Toolkit' },
  { path: '/myip', expectedTitle: 'What Is My IP? Public IP Lookup | SysAdmin Toolkit' },
  { path: '/subnet', expectedTitle: 'IPv4 & IPv6 Subnet Calculator | SysAdmin Toolkit' },
  { path: '/chmod', expectedTitle: 'Chmod Calculator for Linux Permissions | SysAdmin Toolkit' },
  { path: '/cron', expectedTitle: 'Crontab Builder & Cron Expression Generator | SysAdmin Toolkit' },
  { path: '/password-generator', expectedTitle: 'Password & Passphrase Generator | SysAdmin Toolkit' },
];

test.describe('SEO Metadata & Indexing Contract', () => {
  test('Homepage has canonical title, description, and WebSite schema', async ({ page }) => {
    const res = await page.goto('/');
    expect(res?.status()).toBe(200);

    // Title & description
    await expect(page).toHaveTitle(/SysAdmin Toolkit/);
    const desc = await page.locator('meta[name="description"]').getAttribute('content');
    expect(desc).toBeTruthy();
    expect(desc?.length).toBeGreaterThan(20);

    // Canonical link
    const canonical = await page.locator('link[rel="canonical"]').getAttribute('href');
    expect(canonical).toMatch(/https?:\/\/[^/]+\/?$/);

    // Robots meta tag
    const robots = await page.locator('meta[name="robots"]').getAttribute('content');
    expect(robots).toBe('index, follow');

    // H1 heading in initial DOM
    const h1 = page.getByRole('heading', { level: 1 }).first();
    await expect(h1).toBeVisible();

    // WebSite JSON-LD
    const jsonLdScripts = page.locator('script[type="application/ld+json"]');
    const count = await jsonLdScripts.count();
    expect(count).toBeGreaterThan(0);

    let foundWebSite = false;
    for (let i = 0; i < count; i++) {
      const text = await jsonLdScripts.nth(i).textContent();
      if (text && text.includes('"WebSite"')) {
        foundWebSite = true;
        break;
      }
    }
    expect(foundWebSite).toBe(true);
  });

  for (const { path, expectedTitle } of TOOLS) {
    test(`Tool page ${path} serves unique metadata, canonical, H1, and WebApplication schema`, async ({ page }) => {
      const res = await page.goto(path);
      expect(res?.status()).toBe(200);

      // Title must match reviewed tool name and brand suffix
      await expect(page).toHaveTitle(expectedTitle);

      // Meta description must be unique and descriptive
      const desc = await page.locator('meta[name="description"]').getAttribute('content');
      expect(desc).toBeTruthy();
      expect(desc?.length).toBeGreaterThan(20);

      // Canonical URL must point to clean tool URL without query strings
      const canonical = await page.locator('link[rel="canonical"]').getAttribute('href');
      expect(canonical).toContain(path);
      expect(canonical).not.toContain('?');

      // Robots must allow indexing for public tools
      const robots = await page.locator('meta[name="robots"]').getAttribute('content');
      expect(robots).toBe('index, follow');

      // Must render a real H1 heading identifying the tool
      const h1 = page.getByRole('heading', { level: 1 }).first();
      await expect(h1).toBeVisible();

      // OpenGraph tags
      const ogTitle = await page.locator('meta[property="og:title"]').getAttribute('content');
      expect(ogTitle).toBe(expectedTitle);
      const ogUrl = await page.locator('meta[property="og:url"]').getAttribute('content');
      expect(ogUrl).toContain(path);

      // JSON-LD schema with WebApplication
      const jsonLdScripts = page.locator('script[type="application/ld+json"]');
      const count = await jsonLdScripts.count();
      expect(count).toBeGreaterThan(0);

      let foundWebApp = false;
      for (let i = 0; i < count; i++) {
        const text = await jsonLdScripts.nth(i).textContent();
        if (text && text.includes('"WebApplication"')) {
          foundWebApp = true;
          break;
        }
      }
      expect(foundWebApp).toBe(true);
    });
  }

  test('Private routes (/admin, /login, /s/) emit noindex, nofollow', async ({ page }) => {
    // /admin
    await page.goto('/admin');
    const adminRobots = await page.locator('meta[name="robots"]').getAttribute('content');
    expect(adminRobots).toBe('noindex, nofollow');

    // /login
    await page.goto('/login');
    const loginRobots = await page.locator('meta[name="robots"]').getAttribute('content');
    expect(loginRobots).toBe('noindex, nofollow');

    // /s/test-code
    await page.goto('/s/sample-code-1234');
    const shareRobots = await page.locator('meta[name="robots"]').getAttribute('content');
    expect(shareRobots).toBe('noindex, nofollow');
  });

  test('Sensitive query parameters on /nginx receive noindex, nofollow', async ({ page }) => {
    await page.goto('/nginx?session=test-temp-session');
    const sessionRobots = await page.locator('meta[name="robots"]').getAttribute('content');
    expect(sessionRobots).toBe('noindex, nofollow');

    await page.goto('/nginx?ingest=test-temp-ingest');
    const ingestRobots = await page.locator('meta[name="robots"]').getAttribute('content');
    expect(ingestRobots).toBe('noindex, nofollow');
  });

  test('/robots.txt allows crawling public tools and references sitemap', async ({ request }) => {
    const res = await request.get('/robots.txt');
    expect(res.status()).toBe(200);
    const body = await res.text();

    expect(body).toContain('User-Agent: *');
    expect(body).toContain('Allow: /');
    expect(body).toContain('Disallow: /api/');
    expect(body).toContain('Disallow: /ingest');
    expect(body).toContain('sitemap.xml');
  });

  test('/sitemap.xml lists canonical homepage and tools, excludes private routes', async ({ request }) => {
    const res = await request.get('/sitemap.xml');
    expect(res.status()).toBe(200);
    const body = await res.text();

    expect(body).toContain('<urlset');
    expect(body).toContain('/nginx</loc>');
    expect(body).toContain('/dns</loc>');
    expect(body).toContain('/password-generator</loc>');

    // Must never list private or administrative paths
    expect(body).not.toContain('/admin');
    expect(body).not.toContain('/login');
    expect(body).not.toContain('/s/');
    expect(body).not.toContain('/api/');
  });

  test('Missing CMS page returns 404 (not soft 404)', async ({ page }) => {
    const res = await page.goto('/page/non-existent-seo-test-slug-987');
    expect(res?.status()).toBe(404);
  });
});
