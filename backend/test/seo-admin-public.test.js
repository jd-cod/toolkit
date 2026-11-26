import test from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import adminRoutes from '../src/routes/admin.js';
import publicRoutes from '../src/routes/public.js';

test('public /site/config projects safe settings allowlist and hides internal keys', async t => {
  const app = Fastify();
  t.after(() => app.close());

  const settingsStore = new Map([
    ['site_title', 'SysAdmin Toolkit'],
    ['meta_description', 'Public meta description'],
    ['palette_primary', '#6366f1'],
    ['palette_primary_light', '#4f46e5'],
    ['custom_css', 'body { margin: 0; }'],
    ['invite_only_whitelist_ips', '192.168.1.1,10.0.0.1'], // MUST NEVER LEAK
    ['internal_secret_token', 'supersecret'], // MUST NEVER LEAK
    ['seo_google_verification', 'google12345'],
  ]);

  const mockTools = [
    {
      id: 1,
      tool_key: 'nginx',
      label: 'Nginx Log Analyzer',
      description: 'Analyze logs',
      icon: 'bi-bar-chart',
      color: '#10b981',
      tags: 'nginx,logs',
      is_enabled: 1,
      sort_order: 1,
      meta_title: 'Nginx Log Analyzer SEO Title',
      meta_description: 'Custom tool description',
      seo_noindex: 0,
    },
    {
      id: 2,
      tool_key: 'disabled_tool',
      label: 'Disabled Tool',
      is_enabled: 0,
      sort_order: 2,
      meta_title: '',
      meta_description: '',
      seo_noindex: 1,
    },
  ];

  const mockPages = [
    { id: 1, slug: 'about', title: 'About Us', sort_order: 1, is_published: 1, seo_noindex: 0 },
    { id: 2, slug: 'hidden-page', title: 'Hidden Utility', sort_order: 2, is_published: 1, seo_noindex: 1 },
  ];

  app.decorate('mysql', {
    execute: async (sql, values = []) => {
      if (sql.includes('INSERT IGNORE INTO tools')) return [{ insertId: 0 }];
      if (sql.includes('FROM site_settings')) {
        return [[...settingsStore].map(([key, value]) => ({ key, value }))];
      }
      if (sql.includes('FROM tools WHERE is_enabled = 1')) {
        return [mockTools.filter(t => t.is_enabled === 1)];
      }
      if (sql.includes('FROM menus WHERE is_visible = 1')) {
        return [[]];
      }
      if (sql.includes('FROM footer_settings')) {
        return [[{ key: 'copyright_text', value: '2026' }]];
      }
      if (sql.includes('FROM pages WHERE is_published = 1')) {
        return [mockPages.filter(p => p.is_published === 1)];
      }
      return [[]];
    },
  });

  await app.register(publicRoutes, { prefix: '/api' });

  const res = await app.inject({ method: 'GET', url: '/api/site/config' });
  assert.equal(res.statusCode, 200);
  const data = res.json();

  // Internal keys MUST NOT leak
  assert.equal(data.settings.invite_only_whitelist_ips, undefined, 'invite_only_whitelist_ips must not be in public config');
  assert.equal(data.settings.internal_secret_token, undefined, 'internal_secret_token must not be in public config');

  // Allowed public keys must be present
  assert.equal(data.settings.site_title, 'SysAdmin Toolkit');
  assert.equal(data.settings.meta_description, 'Public meta description');
  assert.equal(data.settings.palette_primary, '#6366f1');
  assert.equal(data.settings.seo_google_verification, 'google12345');

  // Tools should include SEO fields
  const nginxTool = data.tools.find(t => t.tool_key === 'nginx');
  assert.ok(nginxTool);
  assert.equal(nginxTool.meta_title, 'Nginx Log Analyzer SEO Title');
  assert.equal(nginxTool.meta_description, 'Custom tool description');
  assert.equal(nginxTool.seo_noindex, 0);

  // Pages should include seo_noindex
  const aboutPage = data.pages.find(p => p.slug === 'about');
  assert.ok(aboutPage);
  assert.equal(aboutPage.seo_noindex, 0);
  const hiddenPage = data.pages.find(p => p.slug === 'hidden-page');
  assert.ok(hiddenPage);
  assert.equal(hiddenPage.seo_noindex, 1);
});

test('admin tools update supports meta_title, meta_description, and seo_noindex', async t => {
  const app = Fastify();
  t.after(() => app.close());

  let updatedSql = '';
  let updatedValues = [];

  const existingTool = {
    id: 1,
    tool_key: 'nginx',
    label: 'Nginx Log Analyzer',
    description: 'Old desc',
    icon: 'bi-bar-chart',
    color: '#10b981',
    tags: 'nginx,logs',
    is_enabled: 1,
    sort_order: 1,
    meta_title: 'Old Title',
    meta_description: 'Old Meta',
    seo_noindex: 0,
  };

  app.decorate('mysql', {
    execute: async (sql, values = []) => {
      if (sql.includes('SELECT * FROM tools WHERE id = ?')) {
        return [[existingTool]];
      }
      if (sql.includes('UPDATE tools SET')) {
        updatedSql = sql;
        updatedValues = values;
        return [{ affectedRows: 1 }];
      }
      if (sql.includes('INSERT INTO admin_activity_log')) {
        return [{ insertId: 1 }];
      }
      return [[]];
    },
  });

  app.decorate('auth', {
    authMiddleware: async request => {
      request.admin = { username: 'testadmin' };
    },
  });

  await app.register(adminRoutes, { prefix: '/api' });

  const payload = {
    label: 'Nginx Log Analyzer Updated',
    meta_title: 'New SEO Title',
    meta_description: 'New SEO Description',
    seo_noindex: 1,
  };

  const res = await app.inject({
    method: 'PUT',
    url: '/api/admin/tools/1',
    payload,
  });

  assert.equal(res.statusCode, 200);
  assert.ok(updatedSql.includes('meta_title = ?'));
  assert.ok(updatedSql.includes('meta_description = ?'));
  assert.ok(updatedSql.includes('seo_noindex = ?'));
  assert.ok(updatedValues.includes('New SEO Title'));
  assert.ok(updatedValues.includes('New SEO Description'));
  assert.ok(updatedValues.includes(1));
});

test('admin pages create and update support seo_noindex', async t => {
  const app = Fastify();
  t.after(() => app.close());

  let insertValues = [];
  let updateValues = [];

  const existingPage = {
    id: 5,
    title: 'Test Page',
    slug: 'test-page',
    content: '<p>Content</p>',
    meta_title: 'Meta Title',
    meta_description: 'Meta Desc',
    is_published: 1,
    sort_order: 0,
    seo_noindex: 0,
  };

  app.decorate('mysql', {
    execute: async (sql, values = []) => {
      if (sql.includes('INSERT INTO pages')) {
        insertValues = values;
        return [{ insertId: 10 }];
      }
      if (sql.includes('SELECT * FROM pages WHERE id = ?')) {
        return [[existingPage]];
      }
      if (sql.includes('UPDATE pages SET')) {
        updateValues = values;
        return [{ affectedRows: 1 }];
      }
      if (sql.includes('INSERT INTO admin_activity_log')) {
        return [{ insertId: 1 }];
      }
      return [[]];
    },
  });

  app.decorate('auth', {
    authMiddleware: async request => {
      request.admin = { username: 'testadmin' };
    },
  });

  await app.register(adminRoutes, { prefix: '/api' });

  // Test POST
  const postRes = await app.inject({
    method: 'POST',
    url: '/api/admin/pages',
    payload: {
      title: 'New Page',
      slug: 'new-page',
      content: '<p>New</p>',
      is_published: true,
      seo_noindex: true,
    },
  });
  assert.equal(postRes.statusCode, 200);
  assert.ok(insertValues.includes(1), 'INSERT must include seo_noindex = 1');

  // Test PUT
  const putRes = await app.inject({
    method: 'PUT',
    url: '/api/admin/pages/5',
    payload: {
      seo_noindex: 1,
    },
  });
  assert.equal(putRes.statusCode, 200);
  assert.ok(updateValues.includes(1), 'UPDATE must include seo_noindex = 1');
});
