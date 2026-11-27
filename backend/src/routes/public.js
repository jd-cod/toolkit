/**
 * Public Site Config API — Fastify + MySQL
 *
 * GET /api/site/config      → Full public config (settings, tools, menus, footer, pages)
 * GET /api/site/page/:slug  → Single published page
 * GET /api/site/access-check → Invite-only status
 *
 * Migrated from Hono/D1 to Fastify/MySQL.
 */

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
  // 2026-11 tools pack (also registered by migrations/012_tools_pack.sql)
  ['email-auth', 'SPF, DKIM & DMARC Checker', "Check a domain's MX, SPF, DKIM, DMARC, MTA-STS and BIMI records and get clear findings on what to fix.", 'bi-envelope-check-fill', '#0ea5e9', 'Email,SPF,DKIM,DMARC', 1, 12],
  ['blacklist', 'Blacklist (DNSBL) Check', 'Check whether an IP address or mail server is listed on common DNS blacklists.', 'bi-slash-circle-fill', '#ef4444', 'Email,Blacklist,DNSBL,Reputation', 1, 13],
  ['email-headers', 'Email Header Analyzer', 'Paste raw email headers to trace relay hops, delays and SPF, DKIM and DMARC results. 100% client-side.', 'bi-envelope-open-fill', '#8b5cf6', 'Email,Headers,Offline', 1, 14],
  ['smtp-test', 'SMTP Server Test', 'Connect to a mail server and review its banner, extensions, STARTTLS support and certificate. No message is sent.', 'bi-send-check-fill', '#14b8a6', 'Email,SMTP,STARTTLS', 1, 15],
  ['http-headers', 'HTTP Headers & Redirect Checker', 'Inspect response headers, follow the redirect chain and audit security headers for any public URL.', 'bi-arrow-left-right', '#3b82f6', 'HTTP,Redirects,Security headers', 1, 16],
  ['port-check', 'Open Port Checker', 'Test whether TCP ports on your server or public IP are reachable from the internet.', 'bi-door-open-fill', '#f97316', 'Ports,TCP,Firewall', 1, 17],
  ['cert-decoder', 'Certificate & CSR Decoder', 'Decode PEM certificates and CSRs and check that a private key matches. 100% client-side.', 'bi-file-earmark-lock-fill', '#ec4899', 'TLS,Certificates,CSR,Offline', 1, 18],
  ['sshd-audit', 'SSH Config Auditor', 'Paste an sshd_config to find risky settings and get a hardened snippet. 100% client-side.', 'bi-terminal-fill', '#22c55e', 'SSH,Hardening,Linux,Offline', 1, 19],
  ['systemd-timer', 'systemd Timer Generator', 'Convert a cron schedule to OnCalendar and generate .timer and .service unit files.', 'bi-stopwatch-fill', '#a855f7', 'systemd,Timers,Linux', 1, 20],
  ['firewall-rules', 'Firewall Rule Generator', 'Generate one rule for ufw, firewalld, nftables, iptables and Windows Firewall.', 'bi-bricks', '#f59e0b', 'Firewall,ufw,iptables,nftables', 1, 21],
  ['rsync', 'rsync Command Builder', 'Build an rsync command from options, with every flag explained.', 'bi-arrow-repeat', '#06b6d4', 'rsync,Backup,Linux', 1, 22],
  ['auth-log', 'SSH Auth Log Analyzer', 'Find brute-force sources, targeted users and successful logins in auth.log. 100% client-side.', 'bi-person-lock', '#10b981', 'SSH,Logs,Security,Offline', 1, 23],
  ['mail-log', 'Mail Log Analyzer', 'Summarize Postfix logs: delivered, deferred and bounced mail, rejects and failed logins. 100% client-side.', 'bi-mailbox', '#6366f1', 'Postfix,Logs,Email,Offline', 1, 24],
  ['windows-events', 'Windows Event ID Lookup', 'Look up common Windows Event IDs, logon types and failure codes.', 'bi-journal-text', '#0078d4', 'Windows,Event Viewer,Security', 1, 25],
  ['windows-errors', 'Windows Error Code Lookup', 'Decode Win32, HRESULT, NTSTATUS, Windows Update and stop codes.', 'bi-bug-fill', '#2563eb', 'Windows,Errors,HRESULT', 1, 26],
  ['robocopy', 'Robocopy Command Builder', 'Build a robocopy command from options, with switches and exit codes explained.', 'bi-copy', '#0891b2', 'Windows,Robocopy,Backup', 1, 27],
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

  // GET /api/site/access-check
  fastify.get('/site/access-check', async (request, reply) => {
    try {
      const [rows] = await pool.execute(
        "SELECT `key`, `value` FROM site_settings WHERE `key` IN ('invite_only_enabled', 'invite_only_whitelist_ips')"
      );
      const settings = {};
      for (const row of rows) settings[row.key] = row.value;

      const inviteOnly = settings.invite_only_enabled === '1';
      const clientIP = request.headers['x-real-ip'] || request.headers['x-forwarded-for']?.split(',')[0]?.trim() || request.ip || '';

      return { invite_only: inviteOnly, client_ip: clientIP, allowed: !inviteOnly };
    } catch {
      return { invite_only: false, allowed: true };
    }
  });
}
