import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SITE_URL,
  DEFAULT_TITLE,
  DEFAULT_DESCRIPTION,
  TOOL_SEO_DEFAULTS,
  buildToolMetadata,
  buildPageMetadata,
  buildStructuredData,
  isRouteIndexable,
  getSitemapEntries,
  serializeJsonLd,
} from '../../frontend/src/lib/seo.ts';

test('SITE_URL defaults to canonical production origin', () => {
  assert.equal(SITE_URL, 'http://localhost:3000');
});

test('TOOL_SEO_DEFAULTS defines reviewed titles and descriptions for all 11 tools', () => {
  const expectedTools = [
    'nginx', 'dns', 'ssl', 'whois', 'asn', 'abuse',
    'myip', 'cron', 'subnet', 'chmod', 'password'
  ];
  for (const toolKey of expectedTools) {
    const meta = TOOL_SEO_DEFAULTS[toolKey];
    assert.ok(meta, `Missing SEO defaults for tool: ${toolKey}`);
    assert.ok(meta.title && meta.title.length > 5, `Tool ${toolKey} has empty title`);
    assert.ok(meta.description && meta.description.length > 20, `Tool ${toolKey} has empty description`);
    assert.ok(meta.path.startsWith('/'), `Tool ${toolKey} path must start with /`);
  }
  // Verify password tool maps to /password-generator path
  assert.equal(TOOL_SEO_DEFAULTS.password.path, '/password-generator');
});

test('buildToolMetadata constructs unique title, description, and canonical URL', () => {
  const metadata = buildToolMetadata('dns');
  assert.equal(metadata.title, 'DNS Lookup & Record Checker | SysAdmin Toolkit');
  assert.equal(metadata.description, TOOL_SEO_DEFAULTS.dns.description);
  assert.equal(metadata.alternates.canonical, 'http://localhost:3000/dns');
  assert.deepEqual(metadata.robots, { index: true, follow: true });
  assert.equal(metadata.openGraph.url, 'http://localhost:3000/dns');
  assert.equal(metadata.openGraph.title, 'DNS Lookup & Record Checker | SysAdmin Toolkit');
});

test('buildToolMetadata respects admin overrides when provided', () => {
  const toolOverride = {
    meta_title: 'Custom Admin DNS Title',
    meta_description: 'Custom Admin DNS Description',
    seo_noindex: 0,
  };
  const metadata = buildToolMetadata('dns', toolOverride);
  assert.equal(metadata.title, 'Custom Admin DNS Title | SysAdmin Toolkit');
  assert.equal(metadata.description, 'Custom Admin DNS Description');
});

test('buildToolMetadata marks tool as noindex when disabled or seo_noindex is set', () => {
  const disabledMeta = buildToolMetadata('dns', { is_enabled: 0 });
  assert.deepEqual(disabledMeta.robots, { index: false, follow: true });

  const noindexMeta = buildToolMetadata('dns', { seo_noindex: 1 });
  assert.deepEqual(noindexMeta.robots, { index: false, follow: true });
});

test('buildPageMetadata locks noindex on private and system routes', () => {
  const adminMeta = buildPageMetadata({ path: '/admin', title: 'Admin' });
  assert.deepEqual(adminMeta.robots, { index: false, follow: false });

  const loginMeta = buildPageMetadata({ path: '/login', title: 'Login' });
  assert.deepEqual(loginMeta.robots, { index: false, follow: false });

  const shareMeta = buildPageMetadata({ path: '/s/abcd1234', title: 'Shared Report' });
  assert.deepEqual(shareMeta.robots, { index: false, follow: false });

  // Sensitive nginx query variants must receive noindex
  const nginxSessionMeta = buildPageMetadata({ path: '/nginx', isSensitiveQuery: true });
  assert.deepEqual(nginxSessionMeta.robots, { index: false, follow: false });
});

test('buildStructuredData generates valid WebSite and WebApplication JSON-LD', () => {
  const websiteSchema = buildStructuredData({ type: 'website' });
  assert.equal(websiteSchema['@context'], 'https://schema.org');
  assert.equal(websiteSchema['@type'], 'WebSite');
  assert.equal(websiteSchema.url, 'http://localhost:3000');

  const toolSchema = buildStructuredData({ type: 'tool', toolKey: 'dns' });
  assert.equal(toolSchema['@context'], 'https://schema.org');
  assert.equal(toolSchema['@type'], 'WebApplication');
  assert.equal(toolSchema.name, 'DNS Lookup & Record Checker');
  assert.equal(toolSchema.applicationCategory, 'NetworkingApplication');
  assert.equal(toolSchema.operatingSystem, 'Any');
  assert.equal(toolSchema.offers.price, '0');
});

test('getSitemapEntries includes only canonical indexable public pages', () => {
  const mockConfig = {
    settings: {},
    tools: [
      { id: 1, tool_key: 'dns', is_enabled: 1, sort_order: 1 },
      { id: 2, tool_key: 'nginx', is_enabled: 1, sort_order: 2 },
      { id: 3, tool_key: 'disabled_tool', is_enabled: 0, sort_order: 3 },
      { id: 4, tool_key: 'hidden_tool', is_enabled: 1, seo_noindex: 1, sort_order: 4 },
    ],
    pages: [
      { id: 10, slug: 'about', title: 'About', sort_order: 1, seo_noindex: 0 },
      { id: 11, slug: 'private-doc', title: 'Internal', sort_order: 2, seo_noindex: 1 },
    ],
    menus: { header: [], footer: [] },
    footer: {},
  };

  const entries = getSitemapEntries(mockConfig);
  const urls = entries.map(e => e.url);

  assert.ok(urls.includes('http://localhost:3000/'));
  assert.ok(urls.includes('http://localhost:3000/dns'));
  assert.ok(urls.includes('http://localhost:3000/nginx'));
  assert.ok(urls.includes('http://localhost:3000/page/about'));

  // Must NOT include disabled, noindexed, admin, or share URLs
  assert.ok(!urls.some(u => u.includes('disabled_tool')));
  assert.ok(!urls.some(u => u.includes('hidden_tool')));
  assert.ok(!urls.some(u => u.includes('private-doc')));
  assert.ok(!urls.some(u => u.includes('/admin')));
  assert.ok(!urls.some(u => u.includes('/s/')));
});

test('serializeJsonLd cannot break out of its script element', () => {
  const data = { name: 'Tool </script><script>alert(1)</script>', note: '<!-- x -->' };
  const out = serializeJsonLd(data);

  assert.ok(!out.includes('<'));
  assert.ok(!out.toLowerCase().includes('</script'));
  // Still the same data once parsed, which is what search engines read.
  assert.deepEqual(JSON.parse(out), data);
});
