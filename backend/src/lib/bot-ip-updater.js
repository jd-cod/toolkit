import { isIP } from 'node:net';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../../..');
// Both dev and prod run the same layout: the backend lives at
// <root>/backend/src/lib, so REPO_ROOT is <root> either way. The old
// NODE_ENV branch resolved to <root>/backend/frontend/public/data, which is a
// path nothing serves — the browser fetches /frontend/public/data — so under
// NODE_ENV=production (which BOTH compose files set) every nightly sync wrote
// the rebuilt feed into an image-baked directory while the app continued to
// serve the stale bind-mounted copy. The updater's work was silently discarded
// and feed drift was invisible. GEOIP_PUBLIC_DIR still overrides for tests.
const PUBLIC_DATA_DIR = process.env.GEOIP_PUBLIC_DIR || path.join(REPO_ROOT, 'frontend/public/data');
const VERIFIED_BOTS_JSON_PATH = path.join(PUBLIC_DATA_DIR, 'verified-bots.json');
const BOT_IP_REFRESH_MS = parseInt(process.env.BOT_IP_REFRESH_MS || String(24 * 60 * 60 * 1000), 10);
const FETCH_TIMEOUT_MS = parseInt(process.env.BOT_IP_FETCH_TIMEOUT_MS || '15000', 10);

const updaterState = {
  lastAttemptedAt: '',
  lastSuccessfulAt: '',
  lastError: '',
  inflight: null,
  refreshHandle: null,
};

function formatVersion(date = new Date()) {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, '0');
  const day = String(date.getUTCDate()).padStart(2, '0');
  return `${year}.${month}.${day}`;
}

/**
 * Validate IPv4 CIDR string and normalize to "a.b.c.d/m"
 */
function normalizeIPv4CIDR(candidate) {
  if (typeof candidate !== 'string') return null;
  const trimmed = candidate.trim();
  const parts = trimmed.split('/');
  const ip = parts[0];
  const maskStr = parts[1];

  if (isIP(ip) !== 4) return null;

  let mask = 32;
  if (maskStr !== undefined) {
    mask = parseInt(maskStr, 10);
    if (isNaN(mask) || mask < 0 || mask > 32) return null;
  }

  // Ensure 4 valid octets 0-255
  const octets = ip.split('.').map(n => parseInt(n, 10));
  if (octets.length !== 4 || octets.some(o => isNaN(o) || o < 0 || o > 255)) return null;

  return `${octets.join('.')}/${mask}`;
}

/**
 * Validate IPv6 CIDR string and normalize to "ipv6/m"
 */
function normalizeIPv6CIDR(candidate) {
  if (typeof candidate !== 'string') return null;
  const trimmed = candidate.trim();
  const parts = trimmed.split('/');
  const ip = parts[0];
  const maskStr = parts[1];

  if (isIP(ip) !== 6) return null;

  let mask = 128;
  if (maskStr !== undefined) {
    mask = parseInt(maskStr, 10);
    if (isNaN(mask) || mask < 0 || mask > 128) return null;
  }

  return `${ip.toLowerCase()}/${mask}`;
}

/**
 * Parse feed content across various formats (json_prefixes, json_synctoken, plain_text)
 */
export function parseFeedContent(text, format = 'json_prefixes') {
  const ipv4Set = new Set();
  const ipv6Set = new Set();

  function addCandidate(raw) {
    if (!raw || typeof raw !== 'string') return;
    const v4 = normalizeIPv4CIDR(raw);
    if (v4) {
      ipv4Set.add(v4);
      return;
    }
    const v6 = normalizeIPv6CIDR(raw);
    if (v6) {
      ipv6Set.add(v6);
    }
  }

  if (format === 'plain_text') {
    // Unescape unicode sequences if present in HTML/JSON responses
    const unescaped = text.replace(/\\u003c/gi, '<').replace(/\\u003e/gi, '>').replace(/\\u002f/gi, '/');
    const matches = unescaped.match(/\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g) || [];
    const v6Matches = unescaped.match(/\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}(?:\/\d{1,3})?\b/gi) || [];
    for (const m of matches) addCandidate(m);
    for (const m of v6Matches) addCandidate(m);
  } else {
    // json_prefixes, json_synctoken, or generic JSON
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      throw new Error(`Invalid JSON in feed response: ${err.message}`);
    }

    function scanObject(obj) {
      if (!obj) return;
      if (typeof obj === 'string') {
        addCandidate(obj);
        return;
      }
      if (Array.isArray(obj)) {
        for (const item of obj) {
          scanObject(item);
        }
        return;
      }
      if (typeof obj === 'object') {
        // Look for common prefix fields
        if (obj.ipv4Prefix) addCandidate(obj.ipv4Prefix);
        if (obj.ipv6Prefix) addCandidate(obj.ipv6Prefix);
        if (obj.ip_prefix) addCandidate(obj.ip_prefix);
        if (obj.ipv6_prefix) addCandidate(obj.ipv6_prefix);
        if (obj.prefix) addCandidate(obj.prefix);
        if (obj.cidr) addCandidate(obj.cidr);
        if (obj.subnet) addCandidate(obj.subnet);

        // Also recursively inspect nested containers if not already matched
        if (Array.isArray(obj.prefixes)) scanObject(obj.prefixes);
        if (Array.isArray(obj.subnets)) scanObject(obj.subnets);
        if (Array.isArray(obj.ranges)) scanObject(obj.ranges);
        if (Array.isArray(obj.items)) scanObject(obj.items);
        if (Array.isArray(obj.data)) scanObject(obj.data);
      }
    }

    scanObject(parsed);
  }

  const ipv4 = Array.from(ipv4Set).sort();
  const ipv6 = Array.from(ipv6Set).sort();

  return { ipv4, ipv6, total: ipv4.length + ipv6.length };
}

/**
 * Fetch a single bot feed and update its database record
 */
export async function syncBotSource(source, pool) {
  const sourceId = source.id;
  const botKey = source.bot_key;
  const displayName = source.display_name || botKey;
  const feedUrl = source.feed_url;
  const format = source.format || 'json_prefixes';

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    const response = await fetch(feedUrl, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'SysAdminToolkit-BotUpdater/1.0 (+http://localhost:3001)',
        'Accept': format === 'plain_text' ? 'text/plain,*/*' : 'application/json,text/plain,*/*',
      },
      redirect: 'follow',
    });
    clearTimeout(timer);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }

    const text = await response.text();
    const { ipv4, ipv6, total } = parseFeedContent(text, format);

    if (total === 0) {
      throw new Error('No valid IPv4 or IPv6 prefixes found in feed');
    }

    const cidrsJson = JSON.stringify({ ipv4, ipv6 });

    await pool.execute(
      `UPDATE bot_sources 
       SET total_cidrs = ?, cidrs_json = ?, last_synced_at = NOW(), last_status = 'ok', last_error = NULL 
       WHERE id = ?`,
      [total, cidrsJson, sourceId]
    );

    return {
      id: sourceId,
      bot_key: botKey,
      display_name: displayName,
      status: 'ok',
      total_cidrs: total,
      ipv4_count: ipv4.length,
      ipv6_count: ipv6.length,
      last_synced_at: new Date().toISOString(),
    };
  } catch (err) {
    const errorMessage = err.name === 'AbortError' ? `Fetch timed out after ${FETCH_TIMEOUT_MS}ms` : err.message;
    await pool.execute(
      `UPDATE bot_sources 
       SET last_synced_at = NOW(), last_status = 'error', last_error = ? 
       WHERE id = ?`,
      [errorMessage, sourceId]
    );

    return {
      id: sourceId,
      bot_key: botKey,
      display_name: displayName,
      status: 'error',
      error: errorMessage,
      total_cidrs: source.total_cidrs || 0,
      last_synced_at: new Date().toISOString(),
    };
  }
}

/**
 * Compile verified-bots.json from enabled bot_sources in MySQL
 */
export async function compileVerifiedBotsJson(pool) {
  const [rows] = await pool.execute(
    `SELECT id, bot_key, display_name, group_name, feed_url, format, is_enabled, total_cidrs, cidrs_json, last_synced_at, last_status 
     FROM bot_sources 
     WHERE is_enabled = 1 
     ORDER BY group_name ASC, display_name ASC`
  );

  const bots = {};
  let totalCidrsCount = 0;

  for (const row of rows) {
    let cidrs = { ipv4: [], ipv6: [] };
    if (row.cidrs_json) {
      try {
        cidrs = JSON.parse(row.cidrs_json);
      } catch {}
    }

    const ipv4 = Array.isArray(cidrs.ipv4) ? cidrs.ipv4 : [];
    const ipv6 = Array.isArray(cidrs.ipv6) ? cidrs.ipv6 : [];
    const count = ipv4.length + ipv6.length;
    totalCidrsCount += count;

    bots[row.bot_key] = {
      name: row.display_name,
      group: row.group_name || row.display_name,
      bot_key: row.bot_key,
      total_cidrs: count,
      ipv4,
      ipv6,
      last_synced_at: row.last_synced_at ? new Date(row.last_synced_at).toISOString() : null,
      last_status: row.last_status || 'pending',
    };
  }

  const STATIC_FALLBACKS = {
    applebot: {
      name: 'Applebot',
      group: 'Apple',
      bot_key: 'applebot',
      total_cidrs: 10,
      ipv4: ['17.0.0.0/8', '63.92.224.0/19', '65.199.22.0/24', '139.178.64.0/18', '144.178.0.0/19', '192.35.50.0/24', '198.183.17.0/24', '205.180.12.0/24'],
      ipv6: ['2620:149::/32', '2a01:b740::/32'],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    facebook_meta: {
      name: 'Meta / Facebook',
      group: 'Facebook/Meta',
      bot_key: 'facebook_meta',
      total_cidrs: 9,
      ipv4: ['31.13.24.0/21', '31.13.64.0/18', '66.220.144.0/20', '69.63.176.0/20', '69.171.224.0/19', '157.240.0.0/16', '173.252.64.0/18', '204.15.20.0/22'],
      ipv6: ['2a03:2880::/32'],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    pinterest: {
      name: 'Pinterestbot',
      group: 'Pinterest',
      bot_key: 'pinterest',
      total_cidrs: 4,
      ipv4: ['54.236.1.0/24', '54.236.2.0/24', '54.236.3.0/24', '54.236.4.0/24'],
      ipv6: [],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    telegram: {
      name: 'TelegramBot',
      group: 'Telegram',
      bot_key: 'telegram',
      total_cidrs: 14,
      ipv4: ['91.108.4.0/22', '91.108.8.0/22', '91.108.12.0/22', '91.108.16.0/22', '91.108.20.0/22', '91.108.56.0/22', '149.154.160.0/20', '149.154.164.0/22', '149.154.168.0/22', '149.154.172.0/22', '185.76.151.0/24'],
      ipv6: ['2001:b28:f23d::/48', '2001:b28:f23f::/48', '2a0a:f280::/29'],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    twitter: {
      name: 'Twitterbot',
      group: 'Twitter/X',
      bot_key: 'twitter',
      total_cidrs: 5,
      ipv4: ['199.16.156.0/22', '199.59.148.0/22', '199.96.56.0/21', '209.237.192.0/19'],
      ipv6: ['2620:10d:c000::/40'],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    linkedin: {
      name: 'LinkedInBot',
      group: 'LinkedIn',
      bot_key: 'linkedin',
      total_cidrs: 4,
      ipv4: ['108.174.0.0/20', '144.2.0.0/19', '199.101.160.0/22'],
      ipv6: ['2620:109:c000::/40'],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    baidu: {
      name: 'Baidu Spider',
      group: 'Baidu',
      bot_key: 'baidu',
      total_cidrs: 6,
      ipv4: ['116.179.32.0/20', '180.76.0.0/16', '220.181.108.0/24', '220.181.38.0/24', '123.125.71.0/24'],
      ipv6: ['2400:da00::/32'],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    sogou: {
      name: 'Sogou',
      group: 'Sogou',
      bot_key: 'sogou',
      total_cidrs: 4,
      ipv4: ['123.126.68.0/24', '220.181.125.0/24', '220.181.68.0/24', '106.120.173.0/24'],
      ipv6: [],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    petalbot: {
      name: 'PetalBot (Huawei)',
      group: 'Huawei',
      bot_key: 'petalbot',
      total_cidrs: 3,
      ipv4: ['114.119.128.0/18', '159.138.0.0/16', '119.8.0.0/16'],
      ipv6: [],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    semrush: {
      name: 'SemrushBot',
      group: 'Semrush',
      bot_key: 'semrush',
      total_cidrs: 5,
      ipv4: ['185.191.171.0/24', '85.208.96.0/24', '46.229.168.0/24', '141.98.232.0/24', '141.98.233.0/24'],
      ipv6: [],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    mj12bot: {
      name: 'MJ12bot',
      group: 'Majestic',
      bot_key: 'mj12bot',
      total_cidrs: 5,
      ipv4: ['136.243.0.0/16', '144.76.0.0/16', '148.251.0.0/16', '176.9.0.0/16', '178.63.0.0/16'],
      ipv6: [],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    dotbot: {
      name: 'DotBot (Moz)',
      group: 'Moz',
      bot_key: 'dotbot',
      total_cidrs: 2,
      ipv4: ['216.244.66.0/24', '69.30.224.0/20'],
      ipv6: [],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    criteo: {
      name: 'CriteoBot',
      group: 'Criteo',
      bot_key: 'criteo',
      total_cidrs: 2,
      ipv4: ['178.255.152.0/21', '64.207.240.0/20'],
      ipv6: [],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    // ── Infrastructure / webhook senders ──────────────────────────────────
    // These six have no `bot_sources` row and no fetchable feed URL, so before
    // they were listed here a compile REPLACED them with nothing: the ranges
    // lived only in verified-bots.json, which is a build artefact, and any
    // recompile silently deleted all 612 CIDRs. The alias map in
    // bot-detector.js already points at these keys, so they work fine while
    // present and degrade to "does not publish official ranges" the moment
    // the feed is rebuilt. Treat them exactly like the entries above: a
    // fallback that must survive every compile.
    github: {
      name: 'GitHub Webhooks & Actions',
      group: 'GitHub',
      bot_key: 'github',
      total_cidrs: 80,
      ipv4: [
        '140.82.112.0/20', '143.55.64.0/20', '172.182.252.130/32', '172.182.252.133/32',
        '172.182.252.135/32', '172.182.252.137/32', '185.199.108.0/22', '192.30.252.0/22',
        '20.175.192.146/32', '20.175.192.147/32', '20.175.192.149/32', '20.199.39.227/32',
        '20.199.39.228/32', '20.199.39.232/32', '20.200.245.244/32', '20.200.245.245/32',
        '20.200.245.247/32', '20.200.245.248/32', '20.201.28.148/32', '20.201.28.151/32',
        '20.201.28.152/32', '20.205.243.160/32', '20.205.243.161/32', '20.205.243.166/32',
        '20.205.243.168/32', '20.207.73.81/32', '20.207.73.82/32', '20.207.73.83/32',
        '20.207.73.85/32', '20.217.135.0/32', '20.217.135.1/32', '20.217.135.4/32',
        '20.217.135.5/32', '20.233.83.145/32', '20.233.83.146/32', '20.233.83.148/32',
        '20.233.83.149/32', '20.26.156.210/32', '20.26.156.213/32', '20.26.156.214/32',
        '20.26.156.215/32', '20.27.177.113/32', '20.27.177.116/32', '20.27.177.118/32',
        '20.27.177.119/32', '20.29.134.17/32', '20.29.134.19/32', '20.29.134.22/32',
        '20.29.134.23/32', '20.87.245.0/32', '20.87.245.2/32', '20.87.245.4/32', '20.87.245.6/32',
        '4.208.26.193/32', '4.208.26.197/32', '4.208.26.198/32', '4.208.26.200/32',
        '4.225.11.194/32', '4.225.11.199/32', '4.225.11.200/32', '4.225.11.201/32',
        '4.228.31.144/32', '4.228.31.145/32', '4.228.31.149/32', '4.228.31.150/32', '4.237.22.34/32',
        '4.237.22.36/32', '4.237.22.38/32', '4.237.22.40/32', '4.249.131.163/32', '4.249.131.164/32',
        '4.249.131.166/32', '48.202.248.38/32', '48.202.248.39/32', '48.202.248.40/32',
        '48.204.201.2/32', '48.204.201.5/32', '48.204.201.6/32'
      ],
      ipv6: [
        '2606:50c0::/32', '2a0a:a440::/29'
      ],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    uptimerobot: {
      name: 'UptimeRobot',
      group: 'Uptime Monitoring',
      bot_key: 'uptimerobot',
      total_cidrs: 186,
      ipv4: [
        '128.140.106.114/32', '128.140.41.193/32', '129.212.132.140/32', '134.199.240.137/32',
        '138.197.53.117/32', '138.197.53.138/32', '138.197.54.143/32', '138.197.54.247/32',
        '138.197.63.92/32', '139.59.50.44/32', '142.132.180.39/32', '143.198.249.237/32',
        '143.198.250.89/32', '143.244.196.21/32', '143.244.196.211/32', '143.244.221.177/32',
        '144.126.251.21/32', '146.190.9.187/32', '152.42.149.135/32', '157.90.155.240/32',
        '157.90.156.63/32', '159.223.243.219/32', '159.69.158.189/32', '161.35.247.201/32',
        '167.235.143.113/32', '167.99.18.52/32', '168.119.123.75/32', '168.119.53.160/32',
        '168.119.96.239/32', '170.64.250.132/32', '170.64.250.235/32', '170.64.250.64/32',
        '178.156.181.172/32', '178.156.184.20/32', '178.156.185.127/32', '178.156.185.231/32',
        '178.156.187.238/32', '178.156.189.113/32', '178.156.189.249/32', '18.116.205.62/32',
        '18.180.208.214/32', '18.192.166.72/32', '18.193.252.127/32', '188.166.201.79/32',
        '206.189.241.133/32', '209.38.124.252/32', '209.38.49.1/32', '209.38.49.206/32',
        '209.38.49.226/32', '209.38.51.43/32', '209.38.53.7/32', '216.144.248.27/32',
        '216.144.248.28/32', '216.144.248.29/32', '24.144.78.185/32', '24.144.78.39/32',
        '3.105.133.239/32', '3.105.190.221/32', '3.12.251.153/32', '3.133.226.214/32',
        '3.149.57.90/32', '3.20.63.178/32', '3.212.128.62/32', '3.77.67.4/32', '3.79.134.69/32',
        '34.198.201.66/32', '45.55.123.175/32', '45.55.127.146/32', '49.13.130.29/32',
        '49.13.134.145/32', '49.13.164.148/32', '49.13.167.123/32', '49.13.24.81/32',
        '5.161.113.195/32', '5.161.117.52/32', '5.161.177.47/32', '5.161.194.92/32',
        '5.161.215.244/32', '5.161.61.238/32', '5.161.73.160/32', '5.161.75.7/32', '5.223.43.32/32',
        '5.223.53.147/32', '5.223.57.22/32', '52.15.147.27/32', '52.22.236.30/32', '52.28.162.93/32',
        '52.59.43.236/32', '52.87.72.16/32', '54.167.223.174/32', '54.249.170.27/32',
        '54.64.67.106/32', '54.79.28.129/32', '54.87.112.51/32', '63.178.84.147/32',
        '64.225.81.248/32', '64.225.82.147/32', '78.46.190.63/32', '78.46.215.1/32',
        '78.47.173.76/32', '78.47.98.55/32', '88.99.80.227/32', '91.99.101.207/32'
      ],
      ipv6: [
        '2400:6180:100:d0', '2400:6180:10:200', '2406:da14:94d:8601:9d0d:7754:bedf:e4f5',
        '2406:da14:94d:8601:b325:ff58:2bba:7934', '2406:da14:94d:8601:db4b:c5ac:2cbe:9a79',
        '2406:da1c:9c8:dc02:7ae1:f2ea:ab91:2fde', '2406:da1c:9c8:dc02:7db9:f38b:7b9f:402e',
        '2406:da1c:9c8:dc02:82b2:f0fd:ee96:579', '2600:1f16:775:3a00:37bf:6026:e54a:f03a',
        '2600:1f16:775:3a00:3f24:5bb0:95d7:5a6b', '2600:1f16:775:3a00:8c2c:2ba6:778f:5be5',
        '2600:1f16:775:3a00:91ac:3120:ff38:92b5', '2600:1f16:775:3a00:ac3:c5eb:7081:942e',
        '2600:1f16:775:3a00:dbbe:36b0:3c45:da32', '2600:1f18:179:f900:2406:9399:4ae6:c5d3',
        '2600:1f18:179:f900:4696:7729:7bb3:f52f', '2600:1f18:179:f900:4b7d:d1cc:2d10:211',
        '2600:1f18:179:f900:5c68:91b6:5d75:5d7', '2600:1f18:179:f900:71:af9a:ade7:d772',
        '2600:1f18:179:f900:e8dd:eed1:a6c:183b', '2604:a880:800:14:0:1:68ba:d000',
        '2604:a880:800:14:0:1:68ba:e000', '2604:a880:800:14:0:1:68bb:0',
        '2604:a880:800:14:0:1:68bb:1000', '2604:a880:800:14:0:1:68bb:3000',
        '2604:a880:800:14:0:1:68bb:4000', '2604:a880:800:14:0:1:68bb:5000',
        '2604:a880:800:14:0:1:68bb:6000', '2604:a880:800:14:0:1:68bb:7000',
        '2604:a880:800:14:0:1:68bb:a000', '2604:a880:800:14:0:1:68bb:b000',
        '2604:a880:800:14:0:1:68bb:c000', '2604:a880:800:14:0:1:68bb:d000',
        '2604:a880:800:14:0:1:68bb:e000', '2604:a880:800:14:0:1:68bb:f000', '2607:ff68:107',
        '2a01:4f8:1c1a:3d53', '2a01:4f8:1c1b:4ef4', '2a01:4f8:1c1b:5b5a', '2a01:4f8:1c1b:7ecc',
        '2a01:4f8:1c1c:11aa', '2a01:4f8:1c1c:5353', '2a01:4f8:1c1c:7240', '2a01:4f8:1c1c:a98a',
        '2a01:4f8:c012:c60e', '2a01:4f8:c013:34c0', '2a01:4f8:c013:3b0f', '2a01:4f8:c013:3c52',
        '2a01:4f8:c013:3c53', '2a01:4f8:c013:3c54', '2a01:4f8:c013:3c55', '2a01:4f8:c013:3c56',
        '2a01:4f8:c013:c18', '2a01:4f8:c0c:83fa', '2a01:4f8:c17:42e4', '2a01:4f8:c2c:9fc6',
        '2a01:4f8:c2c:beae', '2a01:4ff:2f0:193c', '2a01:4ff:2f0:27de', '2a01:4ff:2f0:3b3a',
        '2a01:4ff:f0:2219', '2a01:4ff:f0:3e03', '2a01:4ff:f0:5f80', '2a01:4ff:f0:7fad',
        '2a01:4ff:f0:9c5f', '2a01:4ff:f0:b2f2', '2a01:4ff:f0:b6f1', '2a01:4ff:f0:bfd',
        '2a01:4ff:f0:d283', '2a01:4ff:f0:d3cd', '2a01:4ff:f0:e516', '2a01:4ff:f0:e9cf',
        '2a01:4ff:f0:eccb', '2a01:4ff:f0:efd1', '2a01:4ff:f0:fdc7', '2a03:b0c0:2:f0',
        '2a05:d014:1815:3400:654f:bd37:724c:212b', '2a05:d014:1815:3400:6d:9235:c1c0:96ad',
        '2a05:d014:1815:3400:90b4:4ef9:5631:b170', '2a05:d014:1815:3400:9779:d8e9:100a:9642',
        '2a05:d014:1815:3400:af29:e95e:64ff:df81', '2a05:d014:1815:3400:c7d6:f7f3:6cc1:30d1',
        '2a05:d014:1815:3400:d784:e5dd:8e0:67cb'
      ],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    pingdom: {
      name: 'Pingdom',
      group: 'Uptime Monitoring',
      bot_key: 'pingdom',
      total_cidrs: 149,
      ipv4: [
        '103.47.211.210/32', '108.181.70.3/32', '13.232.220.164/32', '13.238.127.47/32',
        '13.238.73.96/32', '13.41.140.26/32', '13.41.156.80/32', '13.48.152.99/32',
        '13.49.128.195/32', '141.125.89.147/32', '148.72.170.233/32', '148.72.171.17/32',
        '15.157.158.165/32', '15.157.248.148/32', '151.106.52.134/32', '158.175.95.9/32',
        '162.218.67.34/32', '162.253.128.178/32', '167.17.67.101/32', '168.1.203.46/32',
        '169.44.155.138/32', '169.51.2.18/32', '169.54.70.214/32', '169.63.150.216/32',
        '172.241.112.86/32', '173.248.147.18/32', '174.34.156.130/32', '175.45.132.20/32',
        '176.34.7.155/32', '177.47.99.26/32', '177.71.158.135/32', '178.162.206.244/32',
        '179.50.12.212/32', '18.133.153.87/32', '18.159.29.185/32', '18.169.231.220/32',
        '18.176.175.170/32', '18.228.82.35/32', '18.230.158.101/32', '184.75.210.226/32',
        '184.75.210.90/32', '184.75.214.66/32', '184.75.214.98/32', '185.136.156.82/32',
        '185.152.65.167/32', '185.180.12.65/32', '185.246.208.82/32', '185.39.146.214/32',
        '185.39.146.215/32', '185.70.76.23/32', '185.93.3.65/32', '190.120.230.7/32',
        '196.240.207.18/32', '196.244.191.18/32', '196.245.151.42/32', '199.87.228.66/32',
        '200.58.101.248/32', '207.244.80.239/32', '209.58.139.193/32', '209.58.139.194/32',
        '23.106.37.99/32', '23.111.152.74/32', '23.111.159.174/32', '23.22.2.46/32',
        '23.83.129.219/32', '23.92.127.2/32', '3.10.222.182/32', '3.11.131.95/32', '3.120.200.34/32',
        '3.121.108.101/32', '3.125.198.20/32', '3.127.78.190/32', '3.219.128.11/32',
        '3.234.196.132/32', '3.66.99.59/32', '35.75.240.83/32', '35.76.210.156/32',
        '35.79.242.196/32', '35.85.117.184/32', '43.225.198.122/32', '43.229.84.12/32',
        '44.194.39.17/32', '44.226.213.159/32', '44.240.34.6/32', '46.20.45.18/32',
        '46.246.122.10/32', '50.16.153.186/32', '51.20.199.140/32', '51.21.185.148/32',
        '52.0.204.16/32', '52.13.171.123/32', '52.194.115.181/32', '52.197.224.235/32',
        '52.197.31.124/32', '52.198.25.184/32', '52.201.3.199/32', '52.209.186.226/32',
        '52.209.34.226/32', '52.21.31.140/32', '52.210.232.124/32', '52.24.42.103/32',
        '52.34.250.64/32', '52.37.65.41/32', '52.48.244.35/32', '52.5.245.15/32', '52.52.118.192/32',
        '52.52.34.158/32', '52.52.95.213/32', '52.57.132.90/32', '52.59.147.246/32',
        '52.59.46.112/32', '52.60.154.13/32', '52.60.62.239/32', '52.62.12.49/32', '52.63.142.2/32',
        '52.63.164.147/32', '52.63.167.55/32', '52.65.247.85/32', '52.67.148.55/32',
        '52.73.209.122/32', '52.89.43.70/32', '54.153.170.200/32', '54.65.106.94/32',
        '54.68.48.199/32', '54.70.202.58/32', '54.79.157.219/32', '54.79.202.123/32',
        '54.94.182.182/32', '54.94.206.111/32', '54.94.238.198/32', '54.94.28.109/32',
        '64.237.49.203/32', '64.237.55.3/32', '66.165.229.130/32', '66.165.233.234/32',
        '72.46.130.18/32', '72.46.131.10/32', '75.101.131.114/32', '76.164.234.106/32',
        '76.164.234.130/32', '82.103.136.16/32', '82.103.139.165/32', '82.103.145.126/32',
        '85.195.116.134/32', '89.163.146.247/32', '89.163.242.206/32', '94.247.174.83/32',
        '94.75.211.73/32', '94.75.211.74/32'
      ],
      ipv6: [
      ],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    datadog: {
      name: 'Datadog Synthetics',
      group: 'Monitoring',
      bot_key: 'datadog',
      total_cidrs: 148,
      ipv4: [
        '100.28.212.0/22', '107.21.25.247/32', '108.137.133.223/32', '108.137.188.57/32',
        '13.114.211.96/32', '13.115.46.213/32', '13.126.169.175/32', '13.208.126.217/32',
        '13.208.133.55/32', '13.208.142.17/32', '13.208.255.200/32', '13.209.118.42/32',
        '13.209.230.111/32', '13.234.54.8/32', '13.236.246.161/32', '13.238.14.57/32',
        '13.244.188.203/32', '13.244.85.86/32', '13.245.194.43/32', '13.245.200.254/32',
        '13.246.172.210/32', '13.247.164.9/32', '13.48.150.244/32', '13.48.239.118/32',
        '13.48.254.37/32', '13.54.169.48/32', '15.152.238.192/32', '15.161.86.71/32',
        '15.165.240.116/32', '15.168.188.85/32', '15.188.202.64/32', '15.188.240.172/32',
        '15.188.243.248/32', '16.162.136.62/32', '16.163.153.45/32', '174.129.34.172/32',
        '18.102.80.189/32', '18.130.113.168/32', '18.139.52.173/32', '18.163.21.55/32',
        '18.163.59.106/32', '18.166.19.255/32', '18.195.155.52/32', '18.200.120.237/32',
        '18.215.84.107/32', '18.229.28.50/32', '18.229.36.120/32', '18.96.130.96/29',
        '18.96.16.112/29', '18.96.227.72/29', '18.97.147.8/29', '18.98.131.24/29',
        '18.98.196.216/29', '18.98.67.176/29', '18.98.96.240/29', '18.99.147.8/29',
        '18.99.209.96/29', '18.99.224.56/29', '18.99.34.208/29', '18.99.4.112/29', '18.99.99.232/29',
        '20.62.248.141/32', '20.83.144.189/32', '23.20.198.65/32', '23.20.66.169/32',
        '23.23.216.60/32', '3.1.219.207/32', '3.1.36.99/32', '3.120.223.25/32', '3.121.24.234/32',
        '3.18.172.189/32', '3.18.188.104/32', '3.18.197.0/32', '3.208.6.150/32', '3.210.147.169/32',
        '3.220.254.141/32', '3.227.186.226/32', '3.229.242.89/32', '3.233.144.0/20', '3.35.66.96/32',
        '3.36.177.119/32', '3.40.134.72/29', '3.40.2.64/29', '3.41.0.88/29', '3.41.176.48/29',
        '3.42.136.80/29', '3.44.192.120/29', '3.45.0.40/29', '3.90.129.171/32', '3.92.150.182/32',
        '3.96.7.126/32', '34.145.82.128/29', '34.146.154.144/29', '34.159.50.128/29',
        '34.174.98.16/29', '34.196.179.210/32', '34.202.253.27/32', '34.203.1.9/32',
        '34.204.83.4/32', '34.206.151.68/32', '34.206.254.214/32', '34.208.32.189/32',
        '34.233.140.66/32', '34.234.13.225/32', '34.237.4.239/32', '34.48.76.208/29',
        '34.94.234.88/29', '35.152.76.8/32', '35.154.93.182/32', '35.172.176.208/32',
        '35.172.85.248/32', '35.176.195.46/32', '35.177.43.250/32', '40.76.107.170/32',
        '43.198.123.228/32', '43.203.72.233/32', '43.218.5.202/32', '44.192.28.0/25',
        '44.208.124.66/32', '5.60.130.112/29', '52.1.33.14/32', '52.1.61.69/32', '52.186.167.216/29',
        '52.192.175.207/32', '52.35.61.232/32', '52.44.165.215/32', '52.44.179.207/32',
        '52.55.56.26/32', '52.60.189.53/32', '52.67.95.251/32', '52.89.221.151/32', '52.9.13.199/32',
        '52.9.139.134/32', '54.152.215.16/32', '54.157.36.5/32', '54.158.196.235/32',
        '54.177.155.33/32', '54.204.118.171/32', '54.226.163.166/32', '54.243.237.18/32',
        '54.82.178.194/32', '54.87.25.183/32', '54.92.248.81/32', '63.34.100.178/32',
        '63.35.33.198/32', '99.79.87.237/32'
      ],
      ipv6: [
        '2600:1f18:24e6:b900::/56', '2607:4240:4000::/34'
      ],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    betterstack: {
      name: 'BetterStack (Better Uptime)',
      group: 'Uptime Monitoring',
      bot_key: 'betterstack',
      total_cidrs: 34,
      ipv4: [
        '162.55.165.86/32', '168.119.246.194/32', '172.105.162.156/32', '178.156.154.250/32',
        '178.156.210.11/32', '178.156.217.188/32', '192.53.169.77/32', '194.195.248.157/32',
        '45.79.236.121/32', '5.161.118.194/32', '5.161.90.230/32', '5.223.56.56/32',
        '5.223.60.188/32', '5.223.73.226/32', '5.223.75.121/32', '91.98.38.26/32',
        '91.99.189.210/32'
      ],
      ipv6: [
        '2000:2eff:fed6:8631', '2000:6fff:fe13:8fcc', '2000:d5ff:fecf:a8d3', '2000:f7ff:fe54:8db9',
        '2a01:4f8:c012:856d', '2a01:4f8:c013:3a76', '2a01:4f8:c014:24d5', '2a01:4f8:c014:2649',
        '2a01:4ff:2f0:1c39', '2a01:4ff:2f0:1f88', '2a01:4ff:2f0:258a', '2a01:4ff:2f0:3b17',
        '2a01:4ff:f0:4f11', '2a01:4ff:f0:565a', '2a01:4ff:f0:5a81', '2a01:4ff:f0:abcd',
        '2a01:4ff:f0:eec4'
      ],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
    stripe: {
      name: 'Stripe Webhooks',
      group: 'Webhooks',
      bot_key: 'stripe',
      total_cidrs: 15,
      ipv4: [
        '13.235.122.149/32', '13.235.14.237/32', '18.211.135.69/32', '3.120.168.93/32',
        '3.130.192.231/32', '3.18.12.63/32', '3.69.109.8/32', '35.154.171.200/32',
        '35.157.207.129/32', '52.15.183.38/32', '54.187.174.169/32', '54.187.205.235/32',
        '54.187.216.72/32', '54.88.130.119/32', '54.88.130.237/32'
      ],
      ipv6: [
      ],
      last_synced_at: new Date().toISOString(),
      last_status: 'ok',
    },
  };

  for (const [key, fallback] of Object.entries(STATIC_FALLBACKS)) {
    if (!bots[key] || bots[key].total_cidrs === 0) {
      bots[key] = fallback;
      totalCidrsCount += fallback.total_cidrs;
    }
  }

  const compiledData = {
    version: formatVersion(),
    generated_at: new Date().toISOString(),
    total_sources: Object.keys(bots).length,
    total_cidrs: totalCidrsCount,
    bots,
  };

  await mkdir(PUBLIC_DATA_DIR, { recursive: true });
  await writeFile(VERIFIED_BOTS_JSON_PATH, JSON.stringify(compiledData, null, 2), 'utf8');

  updaterState.lastSuccessfulAt = compiledData.generated_at;
  updaterState.lastError = '';

  return compiledData;
}

/**
 * Sync all enabled bot sources and recompile JSON
 */
export async function syncAllBotSources(pool) {
  if (updaterState.inflight) return updaterState.inflight;

  updaterState.inflight = (async () => {
    updaterState.lastAttemptedAt = new Date().toISOString();
    try {
      const [sources] = await pool.execute(
        `SELECT id, bot_key, display_name, group_name, feed_url, format, total_cidrs FROM bot_sources WHERE is_enabled = 1`
      );

      const results = [];
      for (const source of sources) {
        const res = await syncBotSource(source, pool);
        results.push(res);
      }

      const compiled = await compileVerifiedBotsJson(pool);

      return {
        success: true,
        results,
        compiled: {
          version: compiled.version,
          total_sources: compiled.total_sources,
          total_cidrs: compiled.total_cidrs,
          generated_at: compiled.generated_at,
        },
      };
    } catch (err) {
      updaterState.lastError = err.message;
      throw err;
    } finally {
      updaterState.inflight = null;
    }
  })();

  return updaterState.inflight;
}

/**
 * Initialize Bot IP Refresh cron and startup compiler
 */
export async function initBotIpRefresh(fastify) {
  const pool = fastify.mysql;
  if (!pool) return;

  try {
    // Check if any sources need initial sync
    const [rows] = await pool.execute(
      `SELECT COUNT(*) as total, SUM(CASE WHEN last_synced_at IS NOT NULL THEN 1 ELSE 0 END) as synced FROM bot_sources WHERE is_enabled = 1`
    );

    const total = rows[0]?.total || 0;
    const synced = rows[0]?.synced || 0;

    fastify.log.info(`🤖 Checking bot IP sources (total: ${total}, synced: ${synced})...`);
    if (total > 0 && synced === 0) {
      fastify.log.info('🤖 Initializing bot IP sources initial sync...');
      await syncAllBotSources(pool);
      fastify.log.info('✅ Bot IP sources initial sync complete.');
    } else {
      // Just compile existing database state to verified-bots.json
      await compileVerifiedBotsJson(pool);
      fastify.log.info('✅ Bot IP verified-bots.json compiled from database cache.');
    }
  } catch (err) {
    fastify.log.warn(`⚠️ Bot IP initial refresh warning: ${err.message}`);
  }

  // Periodic daily refresh
  if (updaterState.refreshHandle) clearInterval(updaterState.refreshHandle);
  updaterState.refreshHandle = setInterval(() => {
    fastify.log.info('🔄 Running scheduled bot IP sources refresh...');
    syncAllBotSources(pool)
      .then(() => fastify.log.info('✅ Scheduled bot IP refresh completed.'))
      .catch((err) => fastify.log.error(`❌ Scheduled bot IP refresh failed: ${err.message}`));
  }, BOT_IP_REFRESH_MS);
}
