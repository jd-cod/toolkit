/**
 * Admin API Routes — Fastify + MySQL
 *
 * Full CRUD for: settings, pages, menus, tools, footer.
 * Plus: auth, activity log, dashboard stats, backup, password change, shares.
 *
 * Migrated from Hono/D1 to Fastify/MySQL.
 */

import { randomBytes } from 'node:crypto';
import { bruteForceLimit } from '../lib/client-ip.js';
import { httpUrl } from '../lib/input.js';
import { getGeoIpDataStatus } from '../lib/geoip-data.js';
import { getIP2LocationStatus } from '../lib/ip2location-data.js';
import { getRdapBootstrapStatus } from './whois.js';
import { syncBotSource, syncAllBotSources, compileVerifiedBotsJson } from '../lib/bot-ip-updater.js';

// Compared against when the username does not exist, so a failed login costs
// the same bcrypt work either way and response time does not reveal which
// usernames are real.
const DUMMY_PASSWORD_HASH = '$2b$10$fqk12f5xPDshl0ILTS8ome8suxV63fDjmvHWrvSDggbbJUkkzKei.';
const MIN_PASSWORD_LENGTH = 12;
const ADMIN_COOKIE_MAX_AGE = 72 * 3600;

function adminCookieOptions() {
  return {
    path: '/', httpOnly: true, sameSite: 'strict', maxAge: ADMIN_COOKIE_MAX_AGE,
    secure: process.env.NODE_ENV === 'production',
  };
}

const SHARE_CODE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

function generateShareCode(length = 8) {
  const bytes = randomBytes(length);
  return Array.from(bytes, b => SHARE_CODE_CHARS[b % SHARE_CODE_CHARS.length]).join('');
}

async function logActivity(pool, action, details, username) {
  try {
    await pool.execute(
      'INSERT INTO admin_activity_log (action, details, admin_username) VALUES (?, ?, ?)',
      [action, details || '', username || 'system']
    );
  } catch (e) {
    console.error('Activity log error:', e);
  }
}

async function createUniqueShareCode(pool) {
  for (let attempt = 0; attempt < 10; attempt++) {
    const candidate = generateShareCode(8);
    const [rows] = await pool.execute('SELECT 1 FROM shares WHERE code = ?', [candidate]);
    if (rows.length === 0) return candidate;
  }
  return null;
}

const DEFAULT_TOOLS = [
  { tool_key: 'nginx', label: 'Traffic Analyzer', description: 'Parse and analyze web access & traffic logs with rich visualizations.', icon: 'bi-filetype-log', color: '#10b981', tags: 'traffic,logs,analyzer,access,error', sort_order: 1 },
  { tool_key: 'subnet', label: 'Subnet Calculator', description: 'Calculate subnets, CIDR ranges, wildcard masks, and network details.', icon: 'bi-diagram-3-fill', color: '#6366f1', tags: 'subnet,cidr,network,ip,calculator', sort_order: 2 },
  { tool_key: 'chmod', label: 'Chmod Calculator', description: 'Interactive Unix file permission calculator with visual toggles.', icon: 'bi-shield-lock-fill', color: '#f59e0b', tags: 'chmod,permissions,unix,linux', sort_order: 3 },
  { tool_key: 'cron', label: 'Cron Expression Parser', description: 'Build and validate cron schedules with human-readable descriptions.', icon: 'bi-clock-fill', color: '#8b5cf6', tags: 'cron,schedule,timer,jobs', sort_order: 4 },
  { tool_key: 'dns', label: 'DNS Lookup', description: 'Query DNS records via multiple DoH resolvers with provider detection.', icon: 'bi-globe2', color: '#06b6d4', tags: 'dns,lookup,records,resolver', sort_order: 5 },
  { tool_key: 'ssl', label: 'SSL Certificate Checker', description: 'Inspect SSL/TLS certificates, chain details, and security grades.', icon: 'bi-lock-fill', color: '#ec4899', tags: 'ssl,tls,certificate,security', sort_order: 6 },
  { tool_key: 'asn', label: 'ASN Lookup', description: 'Look up Autonomous System Numbers with prefix and peer details.', icon: 'bi-hdd-network-fill', color: '#f97316', tags: 'asn,bgp,network,isp', sort_order: 7 },
  { tool_key: 'abuse', label: 'IP Info & Risk Lookup', description: 'Look up IP reverse DNS, network type, country, ISP, security risk factors, and AbuseIPDB scores.', icon: 'bi-info-circle-fill', color: '#f59e0b', tags: 'ip,info,rdns,abuse,security', sort_order: 8 },
  { tool_key: 'whois', label: 'WHOIS Lookup', description: 'Inspect domain registration metadata, statuses, registrar details, nameservers, DNSSEC, and expiry risk signals.', icon: 'bi-person-vcard-fill', color: '#38bdf8', tags: 'whois,domain,registrar,expiry', sort_order: 9 },
];

async function ensureDefaultTools(pool) {
  try {
    const [rows] = await pool.execute('SELECT COUNT(*) as cnt FROM tools');
    if (rows[0].cnt > 0) return;
    for (const tool of DEFAULT_TOOLS) {
      await pool.execute(
        'INSERT INTO tools (tool_key, label, description, icon, color, tags, is_enabled, sort_order) VALUES (?, ?, ?, ?, ?, ?, 1, ?)',
        [tool.tool_key, tool.label, tool.description, tool.icon, tool.color, tool.tags, tool.sort_order]
      );
    }
    console.log(`[admin] Seeded ${DEFAULT_TOOLS.length} default tools`);
  } catch (e) {
    console.error('ensureDefaultTools error:', e.message);
  }
}

export default async function adminRoutes(fastify, opts) {
  const pool = fastify.mysql;
  const auth = fastify.auth;

  // ─── PUBLIC (no auth) ───

  // GET /api/admin/init — Check if admin is set up
  fastify.get('/admin/init', async (request, reply) => {
    const [rows] = await pool.execute('SELECT COUNT(*) as cnt FROM admin_users');
    return {
      initialized: rows[0].cnt > 0,
      bootstrap_configured: Boolean(process.env.ADMIN_BOOTSTRAP_USERNAME && process.env.ADMIN_BOOTSTRAP_PASSWORD),
    };
  });

  // POST /api/admin/init — Create bootstrap admin (only if none exist)
  fastify.post('/admin/init', async (request, reply) => {
    const [rows] = await pool.execute('SELECT COUNT(*) as cnt FROM admin_users');
    if (rows[0].cnt > 0) return reply.code(400).send({ error: 'Admin already exists' });

    const username = (process.env.ADMIN_BOOTSTRAP_USERNAME || '').trim();
    const password = process.env.ADMIN_BOOTSTRAP_PASSWORD || '';

    if (!username || !password) {
      return reply.code(503).send({ error: 'Admin bootstrap is not configured. Set ADMIN_BOOTSTRAP_USERNAME and ADMIN_BOOTSTRAP_PASSWORD, then retry.' });
    }

    const hash = await auth.hashPassword(password);
    await pool.execute('INSERT INTO admin_users (username, password_hash) VALUES (?, ?)', [username, hash]);
    await logActivity(pool, 'system.init', `Bootstrap admin "${username}" created`, 'system');

    return { success: true, message: 'Admin created. Login with the configured bootstrap credentials.' };
  });

  // POST /api/admin/login
  // Password guessing is throttled per client on top of the global limit.
  fastify.post('/admin/login', { config: { rateLimit: bruteForceLimit(10, '5 minutes') } }, async (request, reply) => {
    const body = request.body || {};
    const { username, password } = body;
    if (!username || !password) return reply.code(400).send({ error: 'Username and password required' });
    if (typeof username !== 'string' || typeof password !== 'string') return reply.code(400).send({ error: 'Username and password required' });

    const [rows] = await pool.execute('SELECT * FROM admin_users WHERE username = ?', [username]);
    if (rows.length === 0) {
      await auth.verifyPassword(password, DUMMY_PASSWORD_HASH);
      return reply.code(401).send({ error: 'Invalid credentials' });
    }

    const user = rows[0];
    const valid = await auth.verifyPassword(password, user.password_hash);
    if (!valid) return reply.code(401).send({ error: 'Invalid credentials' });

    const token = auth.createToken({ sub: user.id, username: user.username, tv: Number(user.token_version) || 0 });
    await logActivity(pool, 'auth.login', `Admin "${username}" logged in`, username);

    reply.setCookie('admin_token', token, adminCookieOptions());

    return { success: true, username: user.username };
  });

  // ─── AUTH MIDDLEWARE — everything below requires login ───
  // Register all protected routes with the auth preHandler

  // POST /api/admin/logout
  fastify.post('/admin/logout', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    await logActivity(pool, 'auth.logout', `Admin "${request.admin.username}" logged out`, request.admin.username);
    // Clearing the cookie only affects this browser; revoking makes the token
    // itself useless, including any copy that was stolen.
    await auth.revokeTokens?.(request.admin.sub);
    reply.setCookie('admin_token', '', { path: '/', httpOnly: true, sameSite: 'strict', maxAge: 0 });
    return { success: true };
  });

  // GET /api/admin/me
  fastify.get('/admin/me', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    return { username: request.admin.username, id: request.admin.sub };
  });

  // ─── DASHBOARD ───
  fastify.get('/admin/dashboard', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    await ensureDefaultTools(pool);
    const [[pagesCount], [toolsCount], [menusCount], [activityCount], [enabledTools], [sharesCount]] = await Promise.all([
      pool.execute('SELECT COUNT(*) as cnt FROM pages'),
      pool.execute('SELECT COUNT(*) as cnt FROM tools'),
      pool.execute('SELECT COUNT(*) as cnt FROM menus'),
      pool.execute('SELECT COUNT(*) as cnt FROM admin_activity_log'),
      pool.execute('SELECT COUNT(*) as cnt FROM tools WHERE is_enabled = 1'),
      pool.execute('SELECT COUNT(*) as cnt FROM shares'),
    ]);

    const [recentActivity] = await pool.execute('SELECT * FROM admin_activity_log ORDER BY created_at DESC LIMIT 10');
    const [maintenance] = await pool.execute("SELECT `value` FROM site_settings WHERE `key` = 'maintenance_mode'");
    const [announcement] = await pool.execute("SELECT `value` FROM site_settings WHERE `key` = 'announcement_enabled'");
    const geoip = await getGeoIpDataStatus();
    const ip2location = await getIP2LocationStatus(pool);
    const rdap = getRdapBootstrapStatus();

    return {
      stats: {
        total_pages: pagesCount[0]?.cnt || 0,
        total_tools: toolsCount[0]?.cnt || 0,
        enabled_tools: enabledTools[0]?.cnt || 0,
        total_menus: menusCount[0]?.cnt || 0,
        total_activities: activityCount[0]?.cnt || 0,
        total_shares: sharesCount[0]?.cnt || 0,
        maintenance_mode: maintenance[0]?.value === '1',
        announcement_active: announcement[0]?.value === '1',
      },
      system_refresh: {
        rdap,
        geoip,
        ip2location,
      },
      recent_activity: recentActivity,
    };
  });

  fastify.get('/admin/system-status', { preHandler: [auth.authMiddleware] }, async () => {
    return {
      rdap: getRdapBootstrapStatus(),
      geoip: await getGeoIpDataStatus(),
      ip2location: await getIP2LocationStatus(pool),
    };
  });

  // ─── SETTINGS ───
  fastify.get('/admin/settings', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const [rows] = await pool.execute('SELECT * FROM site_settings ORDER BY `key`');
    const settings = {};
    for (const row of rows) settings[row.key] = row.value;
    return settings;
  });

  fastify.put('/admin/settings', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const body = request.body || {};
    // Validate the entire palette before any writes, including independent light-theme overrides.
    for (const [key, value] of Object.entries(body)) {
      if (/^palette_(primary|secondary|bg_primary|bg_card|text_primary|accent_green|accent_red)(_light)?$/.test(key)
        && (typeof value !== 'string' || (value !== '' && !/^#(?:[\da-f]{3}|[\da-f]{6})$/i.test(value.trim())))) {
        return reply.code(400).send({ error: `Invalid color for ${key}. Use a 3- or 6-digit hex color, or leave it empty.` });
      }
    }
    const changedKeys = [];
    for (const [key, value] of Object.entries(body)) {
      await pool.execute(
        'INSERT INTO site_settings (`key`, `value`, updated_at) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE `value` = ?, updated_at = NOW()',
        [key, String(value), String(value)]
      );
      changedKeys.push(key);
    }
    if (changedKeys.length > 0) {
      await logActivity(pool, 'settings.update', `Updated: ${changedKeys.join(', ')}`, request.admin.username);
    }
    return { success: true };
  });

  // ─── PAGES ───
  fastify.get('/admin/pages', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const [rows] = await pool.execute('SELECT * FROM pages ORDER BY sort_order ASC, created_at DESC');
    return rows;
  });

  fastify.post('/admin/pages', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const body = request.body || {};
    const { title, slug, content, meta_title, meta_description, is_published, sort_order } = body;
    if (!title || !slug) return reply.code(400).send({ error: 'Title and slug are required' });
    const cleanSlug = slug.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');

    try {
      const [result] = await pool.execute(
        'INSERT INTO pages (title, slug, content, meta_title, meta_description, is_published, sort_order, seo_noindex) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [
          title,
          cleanSlug,
          content || '',
          meta_title || '',
          meta_description || '',
          is_published !== undefined ? (is_published ? 1 : 0) : 1,
          sort_order || 0,
          body.seo_noindex !== undefined ? (body.seo_noindex ? 1 : 0) : 0,
        ]
      );
      await logActivity(pool, 'page.create', `Created page "${title}" (/${cleanSlug})`, request.admin.username);
      return { success: true, id: result.insertId, slug: cleanSlug };
    } catch (e) {
      if (e.code === 'ER_DUP_ENTRY') return reply.code(409).send({ error: 'A page with this slug already exists' });
      throw e;
    }
  });

  fastify.get('/admin/pages/:id', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const [rows] = await pool.execute('SELECT * FROM pages WHERE id = ?', [request.params.id]);
    if (rows.length === 0) return reply.code(404).send({ error: 'Page not found' });
    return rows[0];
  });

  fastify.put('/admin/pages/:id', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const id = request.params.id;
    const body = request.body || {};
    const [existing] = await pool.execute('SELECT * FROM pages WHERE id = ?', [id]);
    if (existing.length === 0) return reply.code(404).send({ error: 'Page not found' });
    const ex = existing[0];
    const cleanSlug = body.slug ? body.slug.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '') : ex.slug;

    await pool.execute(
      'UPDATE pages SET title = ?, slug = ?, content = ?, meta_title = ?, meta_description = ?, is_published = ?, sort_order = ?, seo_noindex = ?, updated_at = NOW() WHERE id = ?',
      [
        body.title || ex.title,
        cleanSlug,
        body.content !== undefined ? body.content : ex.content,
        body.meta_title !== undefined ? body.meta_title : ex.meta_title,
        body.meta_description !== undefined ? body.meta_description : ex.meta_description,
        body.is_published !== undefined ? (body.is_published ? 1 : 0) : ex.is_published,
        body.sort_order !== undefined ? body.sort_order : ex.sort_order,
        body.seo_noindex !== undefined ? (body.seo_noindex ? 1 : 0) : (ex.seo_noindex ? 1 : 0),
        id,
      ]
    );
    await logActivity(pool, 'page.update', `Updated page "${body.title || ex.title}"`, request.admin.username);
    return { success: true };
  });

  fastify.delete('/admin/pages/:id', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const [existing] = await pool.execute('SELECT title FROM pages WHERE id = ?', [request.params.id]);
    if (existing.length === 0) return reply.code(404).send({ error: 'Page not found' });
    await pool.execute('DELETE FROM pages WHERE id = ?', [request.params.id]);
    await logActivity(pool, 'page.delete', `Deleted page "${existing[0].title}"`, request.admin.username);
    return { success: true };
  });

  // ─── MENUS ───
  fastify.get('/admin/menus', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const [rows] = await pool.execute('SELECT * FROM menus ORDER BY location ASC, sort_order ASC');
    return rows;
  });

  fastify.post('/admin/menus', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const body = request.body || {};
    if (!body.location || !body.label || !body.url) return reply.code(400).send({ error: 'Location, label, and URL are required' });

    const [result] = await pool.execute(
      'INSERT INTO menus (location, label, url, icon, sort_order, is_visible, open_in_new_tab) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [body.location, body.label, body.url, body.icon || '', body.sort_order || 0, body.is_visible !== undefined ? (body.is_visible ? 1 : 0) : 1, body.open_in_new_tab ? 1 : 0]
    );
    await logActivity(pool, 'menu.create', `Added "${body.label}" to ${body.location} menu`, request.admin.username);
    return { success: true, id: result.insertId };
  });

  fastify.put('/admin/menus/reorder', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const items = request.body?.items;
    if (!items || !Array.isArray(items)) return reply.code(400).send({ error: 'Items array required' });
    if (items.length === 0) return { success: true };

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      for (const item of items) {
        await conn.execute('UPDATE menus SET sort_order = ? WHERE id = ?', [item.sort_order, item.id]);
      }
      await conn.commit();
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }

    await logActivity(pool, 'menu.reorder', `Reordered ${items.length} menu items`, request.admin.username);
    return { success: true };
  });

  fastify.put('/admin/menus/:id', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const id = request.params.id;
    const body = request.body || {};
    const [existing] = await pool.execute('SELECT * FROM menus WHERE id = ?', [id]);
    if (existing.length === 0) return reply.code(404).send({ error: 'Menu item not found' });
    const ex = existing[0];

    await pool.execute(
      'UPDATE menus SET location = ?, label = ?, url = ?, icon = ?, sort_order = ?, is_visible = ?, open_in_new_tab = ? WHERE id = ?',
      [body.location || ex.location, body.label || ex.label, body.url || ex.url, body.icon !== undefined ? body.icon : ex.icon, body.sort_order !== undefined ? body.sort_order : ex.sort_order, body.is_visible !== undefined ? (body.is_visible ? 1 : 0) : ex.is_visible, body.open_in_new_tab !== undefined ? (body.open_in_new_tab ? 1 : 0) : ex.open_in_new_tab, id]
    );
    await logActivity(pool, 'menu.update', `Updated menu item "${body.label || ex.label}"`, request.admin.username);
    return { success: true };
  });

  fastify.delete('/admin/menus/:id', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const [existing] = await pool.execute('SELECT label FROM menus WHERE id = ?', [request.params.id]);
    if (existing.length === 0) return reply.code(404).send({ error: 'Menu item not found' });
    await pool.execute('DELETE FROM menus WHERE id = ?', [request.params.id]);
    await logActivity(pool, 'menu.delete', `Deleted menu item "${existing[0].label}"`, request.admin.username);
    return { success: true };
  });

  // ─── TOOLS ───
  fastify.get('/admin/tools', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const [rows] = await pool.execute('SELECT * FROM tools ORDER BY sort_order ASC');
    return rows;
  });

  // find-my-way ranks static segments above params, so this coexists with
  // '/admin/tools/:id' regardless of registration order.
  fastify.put('/admin/tools/reorder', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const items = request.body?.items;
    if (!Array.isArray(items)) return reply.code(400).send({ error: 'Items array required' });
    if (items.length === 0) return { success: true };

    // Validate up front: a malformed id or a non-numeric sort_order inside the
    // transaction would otherwise roll back the whole batch for no clear reason.
    for (const item of items) {
      const id = Number(item?.id);
      const sortOrder = Number(item?.sort_order);
      if (!Number.isInteger(id) || id <= 0) return reply.code(400).send({ error: 'Each item needs a numeric id' });
      if (!Number.isInteger(sortOrder)) return reply.code(400).send({ error: 'Each item needs a numeric sort_order' });
      item.id = id;
      item.sort_order = sortOrder;
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      for (const item of items) {
        await conn.execute('UPDATE tools SET sort_order = ? WHERE id = ?', [item.sort_order, item.id]);
      }
      await conn.commit();
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }

    await logActivity(pool, 'tool.reorder', `Reordered ${items.length} tools`, request.admin.username);
    return { success: true };
  });

  fastify.put('/admin/tools/:id', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const id = request.params.id;
    const body = request.body || {};
    const [existing] = await pool.execute('SELECT * FROM tools WHERE id = ?', [id]);
    if (existing.length === 0) return reply.code(404).send({ error: 'Tool not found' });
    const ex = existing[0];

    await pool.execute(
      'UPDATE tools SET label = ?, description = ?, icon = ?, color = ?, tags = ?, is_enabled = ?, sort_order = ?, meta_title = ?, meta_description = ?, seo_noindex = ?, updated_at = NOW() WHERE id = ?',
      [
        body.label !== undefined ? body.label : ex.label,
        body.description !== undefined ? body.description : ex.description,
        body.icon !== undefined ? body.icon : ex.icon,
        body.color !== undefined ? body.color : ex.color,
        body.tags !== undefined ? body.tags : ex.tags,
        body.is_enabled !== undefined ? (body.is_enabled ? 1 : 0) : ex.is_enabled,
        body.sort_order !== undefined ? body.sort_order : ex.sort_order,
        body.meta_title !== undefined ? body.meta_title : (ex.meta_title || ''),
        body.meta_description !== undefined ? body.meta_description : (ex.meta_description || ''),
        body.seo_noindex !== undefined ? (body.seo_noindex ? 1 : 0) : (ex.seo_noindex ? 1 : 0),
        id,
      ]
    );
    const action = body.is_enabled !== undefined ? (body.is_enabled ? 'tool.enable' : 'tool.disable') : 'tool.update';
    await logActivity(pool, action, `Tool "${body.label || ex.label}" updated`, request.admin.username);
    return { success: true };
  });

  // ─── FOOTER ───
  fastify.get('/admin/footer', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const [rows] = await pool.execute('SELECT * FROM footer_settings ORDER BY `key`');
    const settings = {};
    for (const row of rows) settings[row.key] = row.value;
    return settings;
  });

  fastify.put('/admin/footer', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const body = request.body || {};
    for (const [key, value] of Object.entries(body)) {
      await pool.execute(
        'INSERT INTO footer_settings (`key`, `value`, updated_at) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE `value` = ?, updated_at = NOW()',
        [key, String(value), String(value)]
      );
    }
    await logActivity(pool, 'footer.update', 'Footer settings updated', request.admin.username);
    return { success: true };
  });

  // ─── ACTIVITY LOG ───
  fastify.get('/admin/activity', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    // LIMIT/OFFSET are inlined rather than bound: mysql2 sends LIMIT ? as a
    // string param, which MySQL 8 rejects with ER_WRONG_ARGUMENTS on a prepared
    // statement. So the values are interpolated — which makes the integer check
    // below a security boundary, not just tidiness. Number() (not parseInt) is
    // deliberate: parseInt('10; DROP TABLE tools') returns 10 and silently
    // discards the tail, which is exactly the mistake this guards against.
    const toInt = (v, fallback, max) => {
      const n = Number(v);
      if (!Number.isInteger(n) || n < 0) return fallback;
      return Math.min(n, max);
    };
    const limit = toInt(request.query.limit, 50, 200);
    const offset = toInt(request.query.offset, 0, 1_000_000);

    const [rows] = await pool.query(
      `SELECT * FROM admin_activity_log ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`
    );
    const [total] = await pool.execute('SELECT COUNT(*) as cnt FROM admin_activity_log');
    return { items: rows, total: total[0]?.cnt || 0, limit, offset };
  });

  // ─── PASSWORD CHANGE ───
  fastify.put('/admin/password', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const body = request.body || {};
    const { current_password, new_password } = body;
    if (!current_password || !new_password) return reply.code(400).send({ error: 'Current and new passwords required' });
    if (typeof current_password !== 'string' || typeof new_password !== 'string') return reply.code(400).send({ error: 'Current and new passwords required' });
    if (new_password.length < MIN_PASSWORD_LENGTH) return reply.code(400).send({ error: `New password must be at least ${MIN_PASSWORD_LENGTH} characters` });

    const [rows] = await pool.execute('SELECT * FROM admin_users WHERE id = ?', [request.admin.sub]);
    if (rows.length === 0) return reply.code(404).send({ error: 'Admin not found' });

    const valid = await auth.verifyPassword(current_password, rows[0].password_hash);
    if (!valid) return reply.code(401).send({ error: 'Current password is incorrect' });

    const newHash = await auth.hashPassword(new_password);
    await pool.execute('UPDATE admin_users SET password_hash = ?, updated_at = NOW() WHERE id = ?', [newHash, request.admin.sub]);
    await logActivity(pool, 'auth.password_change', 'Admin password changed', request.admin.username);

    // End every session opened with the old password, then keep this browser
    // signed in with a token for the new session version.
    const tokenVersion = await auth.revokeTokens?.(request.admin.sub);
    if (tokenVersion !== undefined) {
      const token = auth.createToken({ sub: request.admin.sub, username: request.admin.username, tv: tokenVersion });
      reply.setCookie('admin_token', token, adminCookieOptions());
    }
    return { success: true };
  });

  // ─── SHARED LINKS ───
  fastify.post('/admin/shares', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const body = request.body || {};
    const title = (body.title || '').trim();
    const r2Key = (body.r2_key || '').trim();
    const sourceUrl = (body.source_url || '').trim();
    const password = (body.password || '').trim();
    const expiresAt = body.expires_at || null;
    if (!title || !r2Key) return reply.code(400).send({ error: 'Title and R2 Key are required' });
    if (sourceUrl && !httpUrl(sourceUrl)) return reply.code(400).send({ error: 'Source URL must start with http:// or https://' });

    const code = await createUniqueShareCode(pool);
    if (!code) return reply.code(500).send({ error: 'Could not generate a unique share code' });

    const passwordHash = password ? await auth.hashPassword(password) : null;
    const createdAt = new Date().toISOString();

    await pool.execute(
      'INSERT INTO shares (code, title, r2_key, source_url, password_hash, expires_at, created_at, r2_uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [code, title, r2Key, sourceUrl || null, passwordHash, expiresAt, createdAt, createdAt]
    );
    await logActivity(pool, 'share.create', `Created share "${title}" (${code})`, request.admin.username);
    return { success: true, code, created_at: createdAt };
  });

  fastify.get('/admin/shares', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const limit = parseInt(request.query.limit || '50');
    const offset = parseInt(request.query.offset || '0');
    const shareType = (request.query.type || 'all').toLowerCase();

    let nginxItems = [], dnsItems = [], whoisItems = [], nginxTotal = 0, dnsTotal = 0, whoisTotal = 0;

    if (shareType === 'all' || shareType === 'nginx') {
      const [rows] = await pool.execute('SELECT code, title, r2_key, source_url, password_hash, expires_at, created_at, r2_uploaded_at FROM shares ORDER BY created_at DESC');
      const [total] = await pool.execute('SELECT COUNT(*) as cnt FROM shares');
      nginxItems = rows.map(r => ({ share_type: 'nginx', code: r.code, title: r.title, r2_key: r.r2_key, source_url: r.source_url || '', has_password: !!r.password_hash, expires_at: r.expires_at, created_at: r.created_at, is_expired: r.expires_at ? new Date() > new Date(r.expires_at) : false }));
      nginxTotal = total[0]?.cnt || 0;
    }

    if (shareType === 'all' || shareType === 'dns') {
      const [rows] = await pool.execute('SELECT code, title, domain, password_hash, expires_at, created_at, checked_at_utc FROM dns_shares ORDER BY created_at DESC');
      const [total] = await pool.execute('SELECT COUNT(*) as cnt FROM dns_shares');
      dnsItems = rows.map(r => ({ share_type: 'dns', code: r.code, title: r.title, domain: r.domain, checked_at_utc: r.checked_at_utc, has_password: !!r.password_hash, expires_at: r.expires_at, created_at: r.created_at, is_expired: r.expires_at ? new Date() > new Date(r.expires_at) : false }));
      dnsTotal = total[0]?.cnt || 0;
    }

    if (shareType === 'all' || shareType === 'whois') {
      const [rows] = await pool.execute('SELECT code, title, domain, password_hash, expires_at, created_at, checked_at_utc FROM whois_shares ORDER BY created_at DESC');
      const [total] = await pool.execute('SELECT COUNT(*) as cnt FROM whois_shares');
      whoisItems = rows.map(r => ({ share_type: 'whois', code: r.code, title: r.title, domain: r.domain, checked_at_utc: r.checked_at_utc, has_password: !!r.password_hash, expires_at: r.expires_at, created_at: r.created_at, is_expired: r.expires_at ? new Date() > new Date(r.expires_at) : false }));
      whoisTotal = total[0]?.cnt || 0;
    }

    const items = [...nginxItems, ...dnsItems, ...whoisItems]
      .sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0))
      .slice(offset, offset + limit);

    return { items, total: nginxTotal + dnsTotal + whoisTotal, counts: { nginx: nginxTotal, dns: dnsTotal, whois: whoisTotal }, limit, offset, type: shareType };
  });

  fastify.get('/admin/shares/:code', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const code = request.params.code;
    const [shareRows] = await pool.execute('SELECT code, title, r2_key, source_url, password_hash, expires_at, created_at, r2_uploaded_at FROM shares WHERE code = ?', [code]);
    if (shareRows.length > 0) {
      const r = shareRows[0];
      return { share_type: 'nginx', code: r.code, title: r.title, r2_key: r.r2_key, source_url: r.source_url || '', has_password: !!r.password_hash, expires_at: r.expires_at, created_at: r.created_at };
    }
    const [dnsRows] = await pool.execute('SELECT code, title, domain, password_hash, expires_at, created_at, checked_at_utc FROM dns_shares WHERE code = ?', [code]);
    if (dnsRows.length > 0) {
      const r = dnsRows[0];
      return { share_type: 'dns', code: r.code, title: r.title, domain: r.domain, has_password: !!r.password_hash, expires_at: r.expires_at, created_at: r.created_at, checked_at_utc: r.checked_at_utc };
    }
    const [whoisRows] = await pool.execute('SELECT code, title, domain, password_hash, expires_at, created_at, checked_at_utc FROM whois_shares WHERE code = ?', [code]);
    if (whoisRows.length === 0) return reply.code(404).send({ error: 'Share not found' });
    const r = whoisRows[0];
    return { share_type: 'whois', code: r.code, title: r.title, domain: r.domain, has_password: !!r.password_hash, expires_at: r.expires_at, created_at: r.created_at, checked_at_utc: r.checked_at_utc };
  });

  fastify.put('/admin/shares/:code', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const code = request.params.code;
    const body = request.body || {};
    if (body.source_url && !httpUrl(body.source_url)) {
      return reply.code(400).send({ error: 'Source URL must start with http:// or https://' });
    }
    const [existing] = await pool.execute('SELECT * FROM shares WHERE code = ?', [code]);
    if (existing.length === 0) return reply.code(404).send({ error: 'Share not found' });
    const ex = existing[0];

    await pool.execute(
      'UPDATE shares SET title = ?, r2_key = ?, source_url = ?, expires_at = ? WHERE code = ?',
      [
        body.title !== undefined ? body.title : ex.title,
        body.r2_key !== undefined ? body.r2_key : ex.r2_key,
        body.source_url !== undefined ? (body.source_url || null) : ex.source_url,
        body.expires_at !== undefined ? body.expires_at : ex.expires_at,
        code,
      ]
    );
    await logActivity(pool, 'share.update', `Updated share "${body.title || ex.title}" (${code})`, request.admin.username);
    return { success: true };
  });

  fastify.delete('/admin/shares/:code', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const code = request.params.code;
    const [shareRows] = await pool.execute('SELECT title FROM shares WHERE code = ?', [code]);
    if (shareRows.length > 0) {
      await pool.execute('DELETE FROM shares WHERE code = ?', [code]);
      await logActivity(pool, 'share.delete', `Deleted share "${shareRows[0].title}" (${code})`, request.admin.username);
      return { success: true };
    }
    const [dnsRows] = await pool.execute('SELECT title FROM dns_shares WHERE code = ?', [code]);
    if (dnsRows.length > 0) {
      await pool.execute('DELETE FROM dns_shares WHERE code = ?', [code]);
      await logActivity(pool, 'share.delete', `Deleted DNS share "${dnsRows[0].title}" (${code})`, request.admin.username);
      return { success: true };
    }
    const [whoisRows] = await pool.execute('SELECT title FROM whois_shares WHERE code = ?', [code]);
    if (whoisRows.length === 0) return reply.code(404).send({ error: 'Share not found' });
    await pool.execute('DELETE FROM whois_shares WHERE code = ?', [code]);
    await logActivity(pool, 'share.delete', `Deleted WHOIS share "${whoisRows[0].title}" (${code})`, request.admin.username);
    return { success: true };
  });

  // ─── BACKUP ───
  fastify.get('/admin/backup', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const [settings] = await pool.execute('SELECT * FROM site_settings');
    const [pages] = await pool.execute('SELECT * FROM pages');
    const [menus] = await pool.execute('SELECT * FROM menus');
    const [tools] = await pool.execute('SELECT * FROM tools');
    const [footer] = await pool.execute('SELECT * FROM footer_settings');

    await logActivity(pool, 'backup.export', 'Full backup exported', request.admin.username);

    return { exported_at: new Date().toISOString(), version: '1.0', data: { settings, pages, menus, tools, footer } };
  });

  fastify.post('/admin/backup/restore', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const body = request.body || {};
    if (!body.data) return reply.code(400).send({ error: 'Invalid backup format' });

    const { settings, pages, menus, tools, footer } = body.data;
    let ops = 0;

    if (settings && Array.isArray(settings)) {
      for (const row of settings) {
        await pool.execute('INSERT INTO site_settings (`key`, `value`, updated_at) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE `value` = ?, updated_at = NOW()', [row.key, row.value, row.value]);
        ops++;
      }
    }

    if (footer && Array.isArray(footer)) {
      for (const row of footer) {
        await pool.execute('INSERT INTO footer_settings (`key`, `value`, updated_at) VALUES (?, ?, NOW()) ON DUPLICATE KEY UPDATE `value` = ?, updated_at = NOW()', [row.key, row.value, row.value]);
        ops++;
      }
    }

    if (tools && Array.isArray(tools)) {
      for (const row of tools) {
        await pool.execute(
          'INSERT INTO tools (tool_key, label, description, icon, color, tags, is_enabled, sort_order, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE label = ?, description = ?, icon = ?, color = ?, tags = ?, is_enabled = ?, sort_order = ?, updated_at = NOW()',
          [row.tool_key, row.label, row.description, row.icon, row.color, row.tags, row.is_enabled, row.sort_order, row.label, row.description, row.icon, row.color, row.tags, row.is_enabled, row.sort_order]
        );
        ops++;
      }
    }

    if (pages && Array.isArray(pages)) {
      await pool.execute('DELETE FROM pages');
      for (const row of pages) {
        await pool.execute(
          'INSERT INTO pages (slug, title, content, meta_title, meta_description, is_published, sort_order, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
          [row.slug, row.title, row.content, row.meta_title || '', row.meta_description || '', row.is_published, row.sort_order, row.created_at, row.updated_at]
        );
        ops++;
      }
    }

    if (menus && Array.isArray(menus)) {
      await pool.execute('DELETE FROM menus');
      for (const row of menus) {
        await pool.execute(
          'INSERT INTO menus (location, label, url, icon, sort_order, is_visible, open_in_new_tab) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [row.location, row.label, row.url, row.icon || '', row.sort_order, row.is_visible, row.open_in_new_tab || 0]
        );
        ops++;
      }
    }

    await logActivity(pool, 'backup.restore', `Restored backup with ${ops} operations`, request.admin.username);
    return { success: true, operations: ops };
  });

  // ─── GeoIP Database Update ───

  fastify.post('/admin/geoip-update', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const { refreshGeoIpData } = await import('../lib/geoip-data.js');
    const force = request.body?.force === true;

    try {
      const result = await refreshGeoIpData({ force, logger: fastify.log });
      await logActivity(pool, 'geoip.update', `GeoIP databases updated to version ${result.version}`, request.admin.username);
      return { success: true, version: result.version };
    } catch (e) {
      return reply.code(e.statusCode || 500).send({ error: `GeoIP update failed: ${e.message}` });
    }
  });

  // ─── Bot IP Sources Management ───

  // GET /api/admin/bot-sources — List all bot sources
  fastify.get('/admin/bot-sources', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const [rows] = await pool.execute(
      `SELECT id, bot_key, display_name, group_name, feed_url, format, is_enabled, 
              last_synced_at, last_status, last_error, total_cidrs, created_at, updated_at 
       FROM bot_sources 
       ORDER BY group_name ASC, display_name ASC`
    );
    return { sources: rows };
  });

  // POST /api/admin/bot-sources — Add a new bot source
  fastify.post('/admin/bot-sources', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const { bot_key, display_name, group_name, feed_url, format, is_enabled } = request.body || {};
    if (!bot_key || !display_name || !feed_url) {
      return reply.code(400).send({ error: 'bot_key, display_name, and feed_url are required.' });
    }

    const validFormats = ['json_prefixes', 'json_synctoken', 'plain_text'];
    const chosenFormat = validFormats.includes(format) ? format : 'json_prefixes';
    const enabled = is_enabled === false || is_enabled === 0 ? 0 : 1;

    try {
      const [result] = await pool.execute(
        `INSERT INTO bot_sources (bot_key, display_name, group_name, feed_url, format, is_enabled, last_status) 
         VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
        [bot_key.trim().toLowerCase(), display_name.trim(), group_name?.trim() || null, feed_url.trim(), chosenFormat, enabled]
      );

      const newId = result.insertId;
      await logActivity(pool, 'bot_source.create', `Added bot source "${display_name}" (${bot_key})`, request.admin.username);

      // Attempt immediate sync for the new source
      const [insertedRows] = await pool.execute('SELECT * FROM bot_sources WHERE id = ?', [newId]);
      if (insertedRows.length > 0 && enabled) {
        await syncBotSource(insertedRows[0], pool);
        await compileVerifiedBotsJson(pool);
      }

      const [updatedRows] = await pool.execute(
        `SELECT id, bot_key, display_name, group_name, feed_url, format, is_enabled, 
                last_synced_at, last_status, last_error, total_cidrs, created_at, updated_at 
         FROM bot_sources WHERE id = ?`,
        [newId]
      );

      return { success: true, source: updatedRows[0] };
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return reply.code(400).send({ error: `Bot key "${bot_key}" already exists.` });
      }
      return reply.code(500).send({ error: `Failed to create bot source: ${err.message}` });
    }
  });

  // PUT /api/admin/bot-sources/:id — Update a bot source
  fastify.put('/admin/bot-sources/:id', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const { id } = request.params;
    const { bot_key, display_name, group_name, feed_url, format, is_enabled } = request.body || {};

    const [existing] = await pool.execute('SELECT * FROM bot_sources WHERE id = ?', [id]);
    if (existing.length === 0) {
      return reply.code(400).send({ error: 'Bot source not found.' });
    }

    const current = existing[0];
    const newBotKey = bot_key !== undefined ? bot_key.trim().toLowerCase() : current.bot_key;
    const newDisplayName = display_name !== undefined ? display_name.trim() : current.display_name;
    const newGroupName = group_name !== undefined ? (group_name?.trim() || null) : current.group_name;
    const newFeedUrl = feed_url !== undefined ? feed_url.trim() : current.feed_url;
    const newFormat = format !== undefined ? format : current.format;
    const newEnabled = is_enabled !== undefined ? (is_enabled ? 1 : 0) : current.is_enabled;

    try {
      await pool.execute(
        `UPDATE bot_sources 
         SET bot_key = ?, display_name = ?, group_name = ?, feed_url = ?, format = ?, is_enabled = ? 
         WHERE id = ?`,
        [newBotKey, newDisplayName, newGroupName, newFeedUrl, newFormat, newEnabled, id]
      );

      await logActivity(pool, 'bot_source.update', `Updated bot source "${newDisplayName}" (#${id})`, request.admin.username);

      // Recompile verified-bots.json to reflect enable/disable state
      await compileVerifiedBotsJson(pool);

      const [updatedRows] = await pool.execute(
        `SELECT id, bot_key, display_name, group_name, feed_url, format, is_enabled, 
                last_synced_at, last_status, last_error, total_cidrs, created_at, updated_at 
         FROM bot_sources WHERE id = ?`,
        [id]
      );

      return { success: true, source: updatedRows[0] };
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return reply.code(400).send({ error: `Bot key "${newBotKey}" already exists.` });
      }
      return reply.code(500).send({ error: `Failed to update bot source: ${err.message}` });
    }
  });

  // DELETE /api/admin/bot-sources/:id — Remove a bot source
  fastify.delete('/admin/bot-sources/:id', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const { id } = request.params;
    const [existing] = await pool.execute('SELECT display_name FROM bot_sources WHERE id = ?', [id]);
    if (existing.length === 0) {
      return reply.code(404).send({ error: 'Bot source not found.' });
    }

    const name = existing[0].display_name;
    await pool.execute('DELETE FROM bot_sources WHERE id = ?', [id]);
    await logActivity(pool, 'bot_source.delete', `Deleted bot source "${name}" (#${id})`, request.admin.username);

    // Recompile verified-bots.json without the deleted source
    await compileVerifiedBotsJson(pool);

    return { success: true, message: `Bot source "${name}" removed.` };
  });

  // POST /api/admin/bot-sources/sync — Manually trigger immediate fetch & JSON re-compilation
  fastify.post('/admin/bot-sources/sync', { preHandler: [auth.authMiddleware] }, async (request, reply) => {
    const { id } = request.body || {};

    try {
      if (id) {
        const [rows] = await pool.execute('SELECT * FROM bot_sources WHERE id = ?', [id]);
        if (rows.length === 0) return reply.code(404).send({ error: 'Bot source not found.' });

        const syncResult = await syncBotSource(rows[0], pool);
        await compileVerifiedBotsJson(pool);
        await logActivity(pool, 'bot_source.sync', `Synced bot source "${rows[0].display_name}"`, request.admin.username);
        return { success: true, result: syncResult };
      }

      const syncResult = await syncAllBotSources(pool);
      await logActivity(pool, 'bot_source.sync_all', `Synced all bot IP sources (${syncResult.results?.length || 0} sources)`, request.admin.username);
      return { success: true, result: syncResult };
    } catch (err) {
      return reply.code(500).send({ error: `Bot sources sync failed: ${err.message}` });
    }
  });
}
