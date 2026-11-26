import test from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import adminRoutes from '../src/routes/admin.js';
import publicRoutes from '../src/routes/public.js';

test('appearance settings round-trip through admin and public config; invalid colors do not partially save', async t => {
  const app = Fastify();
  t.after(() => app.close());
  const settings = new Map();
  app.decorate('mysql', { execute: async (sql, values = []) => {
    if (sql.startsWith('INSERT INTO site_settings')) settings.set(values[0], values[1]);
    if (sql.includes('SELECT') && sql.includes('FROM site_settings')) return [[...settings].map(([key, value]) => ({ key, value }))];
    return [[]];
  } });
  app.decorate('auth', { authMiddleware: async request => { request.admin = { username: 'test' }; } });
  await app.register(adminRoutes, { prefix: '/api' });
  await app.register(publicRoutes, { prefix: '/api' });
  const palette = { palette_primary: '#abc', palette_primary_light: '#123456', palette_bg_card: '', custom_css: '.signal-tool-heading { letter-spacing: 1px; }' };
  assert.equal((await app.inject({ method: 'PUT', url: '/api/admin/settings', payload: palette })).statusCode, 200);
  assert.deepEqual((await app.inject('/api/admin/settings')).json(), palette);
  assert.deepEqual((await app.inject('/api/site/config')).json().settings, palette);
  const invalid = await app.inject({ method: 'PUT', url: '/api/admin/settings', payload: { palette_primary: '#ffffff', palette_primary_light: 'red;display:none' } });
  assert.equal(invalid.statusCode, 400);
  assert.deepEqual((await app.inject('/api/site/config')).json().settings, palette);
});
