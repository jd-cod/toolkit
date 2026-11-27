import { test, expect } from '../_support/fixtures';
import type { APIRequestContext } from '@playwright/test';
import { catalogueEntry, enabledTools, expectedSitemapPaths, type SiteConfig } from './oracle';
import { breadcrumbCurrent, fetchConfig, openRoute, sidebar } from './page';
import { softly } from './checks';

/**
 * What a crawler, a bookmark or a mistyped address gets: titles and
 * descriptions in the HTML the server sends, redirects, the 404 page,
 * robots.txt, sitemap.xml, content pages, and the login gate of /admin.
 *
 * The head tags are read from the raw HTML of a plain HTTP request, because
 * that is what a crawler reads; nothing here depends on JavaScript running.
 * Inventory and layer map: see home.spec.ts.
 */

function decodeEntities(text: string): string {
  return text
    .replace(/&#x([0-9a-f]+);/gi, (_, hex: string) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec: string) => String.fromCodePoint(Number(dec)))
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

function attribute(tag: string, name: string): string | null {
  const match = tag.match(new RegExp(`\\s${name}="([^"]*)"`, 'i'));
  return match ? decodeEntities(match[1]) : null;
}

interface HeadTags {
  status: number;
  titles: string[];
  description: string | null;
  canonical: string | null;
  robots: string | null;
  ogTitle: string | null;
  h1Count: number;
}

/** Head tags of `route` as served, without running any script. */
async function readHead(request: APIRequestContext, route: string): Promise<HeadTags> {
  const response = await request.get(route, { maxRedirects: 0 });
  const html = await response.text();
  const metas = html.match(/<meta\b[^>]*>/gi) || [];
  const links = html.match(/<link\b[^>]*>/gi) || [];
  const meta = (key: 'name' | 'property', value: string) => {
    const tag = metas.find(candidate => attribute(candidate, key) === value);
    return tag ? attribute(tag, 'content') : null;
  };
  const canonical = links.find(candidate => attribute(candidate, 'rel') === 'canonical');
  return {
    status: response.status(),
    titles: [...html.matchAll(/<title>([^<]*)<\/title>/gi)].map(match => decodeEntities(match[1]).trim()),
    description: meta('name', 'description'),
    canonical: canonical ? attribute(canonical, 'href') : null,
    robots: meta('name', 'robots'),
    ogTitle: meta('property', 'og:title'),
    h1Count: (html.match(/<h1[\s>]/gi) || []).length,
  };
}

const pathOf = (url: string | null) => (url ? new URL(url).pathname.replace(/\/$/, '') || '/' : null);

test.describe('Head tags a crawler reads', () => {
  test('the home page and every tool route have their own non-empty title and description, a canonical address and an h1', async ({ request, evidence }) => {
    const config = await fetchConfig(request);
    const tools = enabledTools(config);
    const routes = ['/', ...tools.map(tool => catalogueEntry(tool.tool_key).route)];
    const heads: Record<string, HeadTags> = {};
    for (const route of routes) heads[route] = await readHead(request, route);
    await evidence.save('head-tags.json', heads);

    for (const route of routes) {
      const head = heads[route];
      const tool = tools.find(candidate => catalogueEntry(candidate.tool_key).route === route);
      expect.soft(head.status, `${route}: HTTP status`).toBe(200);
      expect.soft(head.titles.length, `${route}: exactly one <title> in the served HTML (found ${JSON.stringify(head.titles)})`).toBe(1);
      expect.soft(head.titles[0] ?? '', `${route}: <title> is not empty`).not.toBe('');
      expect.soft((head.description ?? '').trim(), `${route}: meta description is not empty`).not.toBe('');
      expect.soft(pathOf(head.canonical), `${route}: canonical link (${head.canonical}) points at the route itself`).toBe(route);
      expect.soft(head.ogTitle, `${route}: og:title equals the <title>`).toBe(head.titles[0]);
      expect.soft(head.h1Count, `${route}: the served HTML contains one h1 before any script runs`).toBe(1);
      if (tool) {
        // An administrator's SEO overrides win; without them the page still must not use the site-wide text.
        if (tool.meta_title) expect.soft(head.titles[0], `${route}: <title> uses the configured meta_title`).toContain(tool.meta_title);
        if (tool.meta_description) expect.soft(head.description, `${route}: meta description is the configured meta_description`).toBe(tool.meta_description);
        expect.soft(head.robots, `${route}: robots meta for an enabled tool with seo_noindex=${tool.seo_noindex ?? 0}`)
          .toBe(tool.seo_noindex ? 'noindex, follow' : 'index, follow');
      }
    }

    // Unique across the site: two routes with the same title or description look like duplicates to a search engine.
    for (const field of ['title', 'description'] as const) {
      const seen = new Map<string, string>();
      for (const route of routes) {
        const value = field === 'title' ? heads[route].titles[0] : heads[route].description;
        if (!value) continue;
        const twin = seen.get(value);
        expect.soft(twin, `${route} has the same ${field} as ${twin}: "${value}"`).toBeUndefined();
        seen.set(value, route);
      }
    }
  });

  test('the title in the browser tab is the served title, on every tool route', async ({ page, request }) => {
    const config = await fetchConfig(request);
    for (const tool of enabledTools(config)) {
      const route = catalogueEntry(tool.tool_key).route;
      const served = await readHead(request, route);
      await openRoute(page, route);
      await softly(page, `${route}: document title in the browser`).toHaveTitle(served.titles[0]);
      expect.soft(await page.locator('title').count(), `${route}: one <title> element in the document`).toBe(1);
    }
  });

  test('the home page meta description is the "Meta Description (SEO)" setting when one is configured', async ({ request }) => {
    // Definition: the admin settings form says of this field, "Used for the homepage meta description if not
    // overridden, and as a fallback description." (frontend/src/components/admin/SettingsSection.tsx)
    const config = await fetchConfig(request);
    const configured = (config.settings.meta_description ?? '').trim();
    const head = await readHead(request, '/');
    expect.soft((head.description ?? '').trim(), 'home page: meta description is not empty').not.toBe('');
    if (configured) {
      expect.soft(
        head.description,
        `home page: the served meta description should be the configured settings.meta_description ("${configured}"); the page serves a built-in sentence instead`,
      ).toBe(configured);
    }
  });

  test('the home page carries valid structured data for the site', async ({ request }) => {
    const response = await request.get('/');
    const html = await response.text();
    const blocks = [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)].map(match => match[1]);
    expect(blocks.length, 'one JSON-LD block on the home page').toBe(1);
    let data: Record<string, unknown> = {};
    expect(() => { data = JSON.parse(blocks[0]); }, 'the JSON-LD block parses as JSON').not.toThrow();
    expect.soft(data['@context'], 'JSON-LD @context').toBe('https://schema.org');
    expect.soft(data['@type'], 'JSON-LD @type').toBe('WebSite');
    expect.soft(String(data.name ?? ''), 'JSON-LD name is not empty').not.toBe('');
    expect.soft(String(data.description ?? ''), 'JSON-LD description is not empty').not.toBe('');
  });
});

test.describe('Redirects and unknown addresses', () => {
  test('/password redirects permanently to /password-generator, keeping the visitor in the tool', async ({ page, request }) => {
    const response = await request.get('/password', { maxRedirects: 0 });
    expect.soft(response.status(), '/password: a permanent redirect (308)').toBe(308);
    expect.soft(new URL(response.headers().location ?? '', 'http://x').pathname, '/password: Location header').toBe('/password-generator');

    const config = await fetchConfig(request);
    const tool = enabledTools(config).find(candidate => candidate.tool_key === 'password');
    const landed = await page.goto('/password', { waitUntil: 'domcontentloaded' });
    expect.soft(landed?.status(), 'the redirect target answers 200').toBe(200);
    await expect(page, '/password lands on /password-generator').toHaveURL(/\/password-generator$/);
    await softly(page.getByRole('heading', { level: 1 }).first(), '/password-generator shows its h1').toBeVisible();
    if (tool) {
      await softly(breadcrumbCurrent(page), 'breadcrumb after the redirect').toHaveText(tool.label);
      await softly(sidebar(page).locator('a[aria-current="page"]'), 'sidebar after the redirect').toHaveAttribute('href', '/password-generator');
    }
  });

  test('unknown addresses answer 404 and say that the page was not found', async ({ page, request, guard, rng }) => {
    guard.allow(/status of 404/);
    const unknown = [`/no-such-tool-${rng.string(6)}`, `/page/no-such-page-${rng.string(6)}`, `/${rng.string(5)}/${rng.string(5)}`];
    for (const path of unknown) {
      const direct = await request.get(path);
      expect.soft(direct.status(), `${path}: HTTP status`).toBe(404);
      const robots = (await readHead(request, path)).robots ?? '';
      expect.soft(robots, `${path}: a missing page must not be indexed (robots meta "${robots}")`).toContain('noindex');

      const response = await page.goto(path, { waitUntil: 'domcontentloaded' });
      expect.soft(response?.status(), `${path}: HTTP status in the browser`).toBe(404);
      await softly(page.locator('body'), `${path}: the page says that it was not found`).toContainText(/not found|could not be found|404/i);
      await softly(page.getByRole('heading', { level: 1 }).first(), `${path}: the 404 page has a heading`).toBeVisible();
    }
  });

  test('the 404 page gives the visitor a way back: a link to the home page', async ({ page, guard, rng }) => {
    guard.allow(/status of 404/);
    for (const path of [`/no-such-tool-${rng.string(6)}`, `/page/no-such-page-${rng.string(6)}`]) {
      await page.goto(path, { waitUntil: 'domcontentloaded' });
      await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible();
      const home = page.locator('a[href="/"]').filter({ visible: true });
      const linkCount = await page.locator('a[href]').filter({ visible: true }).count();
      expect.soft(
        await home.count(),
        `${path}: the 404 page shows ${linkCount} link(s) and none of them leads to the home page ("/"); a visitor who mistyped an address has no way back into the workspace except editing the address bar`,
      ).toBeGreaterThan(0);
    }
  });
});

test.describe('robots.txt and sitemap.xml', () => {
  test('robots.txt allows the site, keeps crawlers out of the API, and names the sitemap', async ({ request }) => {
    const response = await request.get('/robots.txt');
    expect(response.status(), '/robots.txt answers 200').toBe(200);
    expect.soft(response.headers()['content-type'] ?? '', '/robots.txt content type').toContain('text/plain');
    const lines = (await response.text()).split('\n').map(line => line.trim()).filter(Boolean);
    const values = (field: string) => lines.filter(line => line.toLowerCase().startsWith(`${field}:`)).map(line => line.slice(field.length + 1).trim());
    expect.soft(values('user-agent'), 'robots.txt: one rule group for every crawler').toEqual(['*']);
    expect.soft(values('allow'), 'robots.txt: the site is allowed').toContain('/');
    expect.soft(values('disallow'), 'robots.txt: the API is disallowed').toContain('/api/');
    expect.soft(values('disallow'), 'robots.txt: log ingestion is disallowed').toContain('/ingest');
    expect.soft(values('disallow'), 'robots.txt: the whole site is not disallowed').not.toContain('/');
    const sitemaps = values('sitemap');
    expect.soft(sitemaps.length, 'robots.txt: one Sitemap line').toBe(1);
    expect.soft(pathOf(sitemaps[0] ?? null), 'robots.txt: the Sitemap line points at /sitemap.xml').toBe('/sitemap.xml');
  });

  test('sitemap.xml lists the home page, every enabled indexable tool route and every indexable page, once each', async ({ request, evidence }) => {
    const config = await fetchConfig(request);
    const response = await request.get('/sitemap.xml');
    expect(response.status(), '/sitemap.xml answers 200').toBe(200);
    expect.soft(response.headers()['content-type'] ?? '', '/sitemap.xml content type').toMatch(/xml/);
    const xml = await response.text();
    await evidence.save('sitemap.xml', xml);
    const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map(match => decodeEntities(match[1]));
    const paths = locs.map(loc => pathOf(loc) as string).sort();
    expect.soft(paths, 'sitemap.xml: paths listed (home, enabled tools, published pages)').toEqual(expectedSitemapPaths(config));
    for (const loc of locs) expect.soft(() => new URL(loc), `sitemap.xml: <loc>${loc}</loc> is an absolute URL`).not.toThrow();

    // One site, one address: sitemap, robots.txt and the canonical links must name the same origin.
    const origins = new Set(locs.map(loc => new URL(loc).origin));
    expect.soft([...origins].length, `sitemap.xml: every <loc> is on the same origin (${[...origins].join(', ')})`).toBe(1);
    const robots = await (await request.get('/robots.txt')).text();
    const sitemapLine = robots.split('\n').find(line => line.toLowerCase().startsWith('sitemap:'))?.slice(8).trim() ?? '';
    expect.soft(new URL(sitemapLine).origin, 'robots.txt Sitemap line and sitemap.xml use the same origin').toBe([...origins][0]);
    const canonical = (await readHead(request, catalogueEntry(enabledTools(config)[0].tool_key).route)).canonical ?? '';
    expect.soft(new URL(canonical).origin, 'canonical links and sitemap.xml use the same origin').toBe([...origins][0]);
  });
});

test.describe('Content pages and the admin area', () => {
  test('every published content page opens with its title, and the shell names it', async ({ page, request }) => {
    const config: SiteConfig = await fetchConfig(request);
    test.skip(config.pages.length === 0, 'this site has no published content pages (config.pages is empty); pages cannot be created without changing site settings');
    for (const entry of config.pages) {
      const path = `/page/${entry.slug}`;
      await openRoute(page, path);
      await softly(page.getByRole('heading', { level: 1 }), `${path}: page title`).toHaveText(entry.title);
      await softly(breadcrumbCurrent(page), `${path}: breadcrumb`).toHaveText(entry.title);
      await softly(sidebar(page).locator(`nav[aria-label="Site pages"] a[href="${path}"]`), `${path}: listed under "Site pages" in the sidebar`).toBeVisible();
      const head = await readHead(request, path);
      expect.soft(head.titles[0] ?? '', `${path}: <title> is not empty`).not.toBe('');
      expect.soft(head.robots, `${path}: robots meta for seo_noindex=${entry.seo_noindex ?? 0}`).toBe(entry.seo_noindex ? 'noindex, follow' : 'index, follow');
    }
  });

  test('/admin shows the login form to a visitor who is not signed in, and nothing of the admin area', async ({ page, guard }) => {
    guard.allow(/api\/admin\/me/); // the admin page asks who is signed in; 401 is the expected answer
    guard.allow(/status of 401/);
    await page.goto('/admin', { waitUntil: 'domcontentloaded' });
    await expect(page, '/admin sends an anonymous visitor to /login').toHaveURL(/\/login$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Admin Login' }), 'login heading').toBeVisible();
    await expect.soft(page.locator('input[type="password"]'), 'password field').toBeVisible();
    await expect.soft(page.getByRole('button', { name: /Sign In/ }), 'sign-in button').toBeVisible();
    await expect.soft(page.getByText(/Site Settings|Activity Log|Change Password/), 'no admin section is shown').toHaveCount(0);
    const robots = await page.locator('meta[name="robots"]').getAttribute('content');
    expect.soft(robots ?? '', 'the login page is not indexed').toContain('noindex');
  });
});
