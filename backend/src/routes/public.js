/**
 * Public Site Config API — Fastify + MySQL
 *
 * GET /api/site/config      → Full public config (settings, tools, menus, footer, pages)
 * GET /api/site/page/:slug  → Single published page
 * GET /api/site/access-check → Invite-only status
 *
 * Migrated from Hono/D1 to Fastify/MySQL.
 */

import { generateGatePage } from '../lib/gate-page.js';
import { createIpMatcher } from '../lib/client-ip.js';

const DEFAULT_TOOLS = [
  ['nginx', 'Traffic Analyzer', 'Paste web access logs and get instant security insights — country & ASN breakdown, top attacking IPs, bot detection, and visual charts. 100% client-side.', 'bi-shield-lock-fill', '#6366f1', 'Traffic,GeoIP,Charts,Offline', 1, 1],
  ['asn', 'ASN to IPs Converter', 'Enter any ASN number to discover all IPv4 and IPv6 prefixes announced by that network. Export results with one click.', 'bi-diagram-3-fill', '#06b6d4', 'BGP,Prefixes,RIPEstat', 1, 2],
  ['abuse', 'IP Info & Risk Lookup', 'Look up IP addresses for reverse DNS (PTR), network type, country, ISP, security risk factors, and AbuseIPDB scores.', 'bi-info-circle-fill', '#f59e0b', 'GeoIP,rDNS,IPInfo,Abuse', 1, 3],
  ['subnet', 'Subnet / CIDR Calculator', 'Calculate network range, usable hosts, broadcast address, and AWS-reserved IP impact for IPv4 CIDR blocks.', 'bi-hdd-network-fill', '#10b981', 'Networking,CIDR,AWS', 1, 4],
  ['cron', 'Crontab Builder', 'Build, validate, and explain cron expressions with presets and upcoming execution previews.', 'bi-clock-fill', '#a855f7', 'Scheduling,Cron,Validation', 1, 5],
  ['dns', 'DNS Lookup', 'Query A, AAAA, CNAME, MX, TXT, NS, SOA, and CAA records across selectable resolvers.', 'bi-globe2', '#22d3ee', 'DNS,Lookup,Resolvers', 1, 6],
  ['ssl', 'SSL Certificate Checker', 'Inspect certificate expiry, issuer chain, SANs, protocol details, and hostname trust signals.', 'bi-shield-lock-fill', '#ef4444', 'TLS,Certificates,Security', 1, 7],
  ['chmod', 'chmod Calculator', 'Convert between octal and symbolic permissions with an interactive Linux permission matrix.', 'bi-key-fill', '#fbbf24', 'Linux,Permissions,Calculator', 1, 8],
  ['whois', 'WHOIS Lookup', 'Inspect domain registration metadata, statuses, registrar details, nameservers, DNSSEC, and expiry risk signals.', 'bi-person-vcard-fill', '#38bdf8', 'WHOIS,Domains,Registrar,Expiry', 1, 9],
  ['password', 'Password Generator', 'Generate cryptographically secure passwords, passphrases and PINs with a live strength meter and browser-only history. 100% client-side.', 'bi-shield-lock-fill', '#6366f1', 'Passwords,Entropy,Offline', 1, 11],
];

/**
 * Seeds the tool registry on first boot. Runs on every /site/config request.
 *
 * INSERT IGNORE on purpose: /admin can edit label, description, icon, colour,
 * tags, enabled state and sort_order, so an upsert here would revert the
 * admin's changes on the next page load. Migrations own the one-off data fixes
 * instead (see 007_password_generator_tool.sql).
 */
async function ensureDefaultTools(pool) {
  for (const tool of DEFAULT_TOOLS) {
    await pool.execute(
      'INSERT IGNORE INTO tools (tool_key, label, description, icon, color, tags, is_enabled, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      tool
    );
  }
}

const PUBLIC_SETTINGS_KEYS = new Set([
  'site_title',
  'site_description',
  'site_tagline',
  'version_badge',
  'home_hero_title',
  'home_hero_subtitle',
  'meta_description',
  'brand_icon',
  'favicon_emoji',
  'maintenance_mode',
  'maintenance_message',
  'announcement_enabled',
  'announcement_text',
  'announcement_type',
  'announcement_dismissible',
  'custom_css',
  'analytics_script',
  'seo_google_verification',
  'seo_bing_verification',
  'seo_social_image',
]);

function isAllowedSettingKey(key) {
  if (PUBLIC_SETTINGS_KEYS.has(key)) return true;
  // Also allow dynamic theme palette settings
  return /^palette_(primary|secondary|bg_primary|bg_card|text_primary|accent_green|accent_red)(_light)?$/.test(key);
}

export default async function publicRoutes(fastify, opts) {
  const pool = fastify.mysql;

  // GET /api/site/config
  fastify.get('/site/config', async (request, reply) => {
    await ensureDefaultTools(pool);

    const [settingsRows] = await pool.execute('SELECT `key`, `value` FROM site_settings');
    const [toolsRows] = await pool.execute('SELECT * FROM tools WHERE is_enabled = 1 ORDER BY sort_order ASC');
    const [menusRows] = await pool.execute('SELECT * FROM menus WHERE is_visible = 1 ORDER BY location ASC, sort_order ASC');
    const [footerRows] = await pool.execute('SELECT `key`, `value` FROM footer_settings');
    const [pagesRows] = await pool.execute('SELECT id, slug, title, sort_order, seo_noindex FROM pages WHERE is_published = 1 ORDER BY sort_order ASC');

    const settingsObj = {};
    for (const row of settingsRows) {
      if (isAllowedSettingKey(row.key)) {
        settingsObj[row.key] = row.value;
      }
    }

    const footerObj = {};
    for (const row of footerRows) footerObj[row.key] = row.value;

    const headerMenus = [];
    const footerMenus = [];
    for (const item of menusRows) {
      if (item.location === 'header') headerMenus.push(item);
      else if (item.location === 'footer') footerMenus.push(item);
    }

    return {
      settings: settingsObj,
      tools: toolsRows,
      menus: { header: headerMenus, footer: footerMenus },
      footer: footerObj,
      pages: pagesRows,
    };
  });

  // GET /api/site/page/:slug
  fastify.get('/site/page/:slug', async (request, reply) => {
    const [rows] = await pool.execute('SELECT * FROM pages WHERE slug = ? AND is_published = 1', [request.params.slug]);
    if (rows.length === 0) return reply.code(404).send({ error: 'Page not found' });
    return rows[0];
  });

  // A signed-in admin always passes the invite-only gate.
  async function isAdminRequest(request) {
    const auth = fastify.auth;
    const token = request.cookies?.admin_token;
    if (!auth?.verifyToken || !token) return false;
    const payload = auth.verifyToken(token);
    if (!payload) return false;
    const version = await auth.getTokenVersion?.(payload.sub);
    return version !== null && (version === undefined || (payload.tv ?? 0) === version);
  }

  // GET /api/site/access-check
  // Decides whether this visitor may see the site while invite-only mode is on:
  // allowed for signed-in admins and for client IPs on the whitelist. The
  // frontend server (frontend/server.js) calls it with `?gate=1` for page
  // requests and serves `gate_html` instead of the page when it says no.
  // Exempt from rate limiting: it is called once per page view, and a visitor
  // must not be able to exhaust their limit to make the check fail.
  fastify.get('/site/access-check', { config: { rateLimit: false } }, async (request, reply) => {
    try {
      const [rows] = await pool.execute(
        "SELECT `key`, `value` FROM site_settings WHERE `key` IN ('invite_only_enabled', 'invite_only_whitelist_ips', 'invite_only_title', 'invite_only_message')"
      );
      const settings = {};
      for (const row of rows) settings[row.key] = row.value;

      const inviteOnly = settings.invite_only_enabled === '1';
      const clientIP = fastify.clientIp ? fastify.clientIp.resolve(request) : (request.ip || '');
      if (!inviteOnly) return { invite_only: false, client_ip: clientIP, allowed: true };

      const allowed = createIpMatcher(settings.invite_only_whitelist_ips).matches(clientIP)
        || await isAdminRequest(request);
      const result = { invite_only: true, client_ip: clientIP, allowed };
      if (!allowed && request.query?.gate) {
        result.gate_html = generateGatePage(settings.invite_only_title || 'Invite Only', settings.invite_only_message || '');
      }
      return result;
    } catch {
      return { invite_only: false, allowed: true };
    }
  });
}
