import { spawn } from 'node:child_process';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, mkdtemp, readdir, rm } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { isIP } from 'node:net';

const IP2LOCATION_ENABLED = (process.env.IP2LOCATION_ENABLED || '').toLowerCase() === 'true';
const IP2LOCATION_DOWNLOAD_TOKEN = (
  process.env.IP2LOCATION_DOWNLOAD_TOKEN
  || process.env.IP2LOCATION_TOKEN
  || process.env.IP2Location_Key
  || ''
).trim();
const IP2LOCATION_REFRESH_MS = parseInt(process.env.IP2LOCATION_REFRESH_MS || String(24 * 60 * 60 * 1000), 10);
const IP2LOCATION_DOWNLOAD_TIMEOUT_MS = parseInt(process.env.IP2LOCATION_DOWNLOAD_TIMEOUT_MS || String(30 * 60 * 1000), 10);
const INSERT_BATCH_SIZE = parseInt(process.env.IP2LOCATION_IMPORT_BATCH_SIZE || '500', 10);

const DATASETS = [
  {
    key: 'db11_ipv4',
    label: 'IP2Location LITE DB11 IPv4',
    packageCode: process.env.IP2LOCATION_DB11_PACKAGE || 'DB11LITE',
    table: 'ip2location_db11_ipv4',
    fields: ['ip_from', 'ip_to', 'country_code', 'country_name', 'region_name', 'city_name', 'latitude', 'longitude', 'zip_code', 'time_zone'],
  },
  {
    key: 'db11_ipv6',
    label: 'IP2Location LITE DB11 IPv6',
    packageCode: process.env.IP2LOCATION_DB11_IPV6_PACKAGE || 'DB11LITEIPV6',
    table: 'ip2location_db11_ipv6',
    fields: ['ip_from', 'ip_to', 'country_code', 'country_name', 'region_name', 'city_name', 'latitude', 'longitude', 'zip_code', 'time_zone'],
  },
  {
    key: 'px7_ipv4',
    label: 'IP2Proxy LITE PX7 IPv4',
    packageCode: process.env.IP2LOCATION_PX7_PACKAGE || 'PX7LITE',
    table: 'ip2location_px7_ipv4',
    fields: ['ip_from', 'ip_to', 'proxy_type', 'country_code', 'country_name', 'region_name', 'city_name', 'isp', 'domain', 'usage_type', 'asn', 'as_name'],
  },
  {
    key: 'px7_ipv6',
    label: 'IP2Proxy LITE PX7 IPv6',
    packageCode: process.env.IP2LOCATION_PX7_IPV6_PACKAGE || 'PX7LITEIPV6',
    table: 'ip2location_px7_ipv6',
    fields: ['ip_from', 'ip_to', 'proxy_type', 'country_code', 'country_name', 'region_name', 'city_name', 'isp', 'domain', 'usage_type', 'asn', 'as_name'],
  },
  {
    key: 'asn_ipv4',
    label: 'ASN LITE IPv4',
    packageCode: process.env.IP2LOCATION_ASN_PACKAGE || 'DBASNLITE',
    table: 'ip2location_asn_ipv4',
    fields: ['ip_from', 'ip_to', 'cidr', 'asn', 'as_name'],
  },
  {
    key: 'asn_ipv6',
    label: 'ASN LITE IPv6',
    packageCode: process.env.IP2LOCATION_ASN_IPV6_PACKAGE || 'DBASNLITEIPV6',
    table: 'ip2location_asn_ipv6',
    fields: ['ip_from', 'ip_to', 'cidr', 'asn', 'as_name'],
  },
].filter((dataset) => dataset.packageCode && dataset.packageCode.toLowerCase() !== 'false');

const TABLES = new Set(DATASETS.map((dataset) => dataset.table));

const ip2LocationState = {
  lastAttemptedAt: '',
  lastSuccessfulAt: '',
  lastError: '',
  inflight: null,
  refreshHandle: null,
};

export function isIP2LocationEnabled() {
  return IP2LOCATION_ENABLED && Boolean(IP2LOCATION_DOWNLOAD_TOKEN);
}

function isConfigured() {
  return IP2LOCATION_ENABLED;
}

function isBlank(value) {
  return value === undefined || value === null || value === '' || value === '-' || value === '0';
}

function normalizeValue(value) {
  return isBlank(value) ? '' : String(value).trim();
}

function buildDownloadUrl(packageCode) {
  const url = new URL('https://www.ip2location.com/download');
  url.searchParams.set('token', IP2LOCATION_DOWNLOAD_TOKEN);
  url.searchParams.set('file', packageCode);
  return url.toString();
}

function runUnzip(archivePath, outputDir) {
  return new Promise((resolve, reject) => {
    const child = spawn('unzip', ['-o', archivePath, '-d', outputDir], { stdio: ['ignore', 'pipe', 'pipe'] });
    const stderr = [];
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(Buffer.concat(stderr).toString('utf8').trim() || `unzip failed with exit code ${code}`));
    });
  });
}

async function findCsvFiles(rootDir) {
  const files = [];
  const entries = await readdir(rootDir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(rootDir, entry.name);
    if (entry.isFile() && entry.name.toLowerCase().endsWith('.csv')) files.push(fullPath);
    if (entry.isDirectory()) files.push(...await findCsvFiles(fullPath));
  }
  return files;
}

function pickCsvFile(files, dataset) {
  const lowerKey = dataset.key.toLowerCase();
  const wantsIPv6 = lowerKey.includes('ipv6');
  const matchingVersion = files.filter((file) => {
    const base = path.basename(file).toLowerCase();
    const isIPv6 = base.includes('ipv6');
    return wantsIPv6 ? isIPv6 : !isIPv6;
  });
  return matchingVersion[0] || files[0] || '';
}

async function downloadAndExtractDataset(dataset, workspaceDir) {
  const archivePath = path.join(workspaceDir, `${dataset.packageCode}.zip`);
  const extractDir = path.join(workspaceDir, `${dataset.packageCode}-extract`);
  await mkdir(extractDir, { recursive: true });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), IP2LOCATION_DOWNLOAD_TIMEOUT_MS);

  try {
    const response = await fetch(buildDownloadUrl(dataset.packageCode), {
      headers: { Accept: 'application/zip,application/octet-stream' },
      redirect: 'follow',
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`IP2Location download failed for ${dataset.packageCode} with HTTP ${response.status}.`);
    }

    if (!response.body) throw new Error(`IP2Location download response for ${dataset.packageCode} was empty.`);
    await pipeline(response.body, createWriteStream(archivePath));
    await runUnzip(archivePath, extractDir);

    const csvFile = pickCsvFile(await findCsvFiles(extractDir), dataset);
    if (!csvFile) throw new Error(`Downloaded archive for ${dataset.packageCode} did not contain a CSV file.`);
    return csvFile;
  } finally {
    clearTimeout(timer);
  }
}

function parseCsvLine(line) {
  const values = [];
  let current = '';
  let quoted = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      if (quoted && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        quoted = !quoted;
      }
    } else if (char === ',' && !quoted) {
      values.push(current);
      current = '';
    } else {
      current += char;
    }
  }

  values.push(current);
  return values.map(normalizeValue);
}

async function flushRows(pool, dataset, rows) {
  if (rows.length === 0) return;

  const placeholders = rows
    .map(() => `(${dataset.fields.map(() => '?').join(',')})`)
    .join(',');
  const values = rows.flat();
  const columns = dataset.fields.map((field) => `\`${field}\``).join(',');
  await pool.query(`INSERT INTO \`${dataset.table}\` (${columns}) VALUES ${placeholders}`, values);
}

function normalizeRow(dataset, parsed) {
  if (parsed.length < dataset.fields.length) return null;
  const row = parsed.slice(0, dataset.fields.length);

  if (!row[0] || !row[1]) return null;
  if (!/^\d+$/.test(row[0]) || !/^\d+$/.test(row[1])) return null;

  if (dataset.key.startsWith('db11')) {
    row[6] = row[6] ? Number(row[6]) : null;
    row[7] = row[7] ? Number(row[7]) : null;
  }

  return row;
}

async function importCsv(pool, dataset, csvPath) {
  await pool.execute(`TRUNCATE TABLE \`${dataset.table}\``);

  const reader = createInterface({
    input: createReadStream(csvPath),
    crlfDelay: Infinity,
  });

  let imported = 0;
  let batch = [];

  for await (const line of reader) {
    if (!line.trim()) continue;
    const row = normalizeRow(dataset, parseCsvLine(line));
    if (!row) continue;
    batch.push(row);
    imported++;

    if (batch.length >= INSERT_BATCH_SIZE) {
      await flushRows(pool, dataset, batch);
      batch = [];
    }
  }

  await flushRows(pool, dataset, batch);
  return imported;
}

async function setState(pool, values) {
  for (const [key, value] of Object.entries(values)) {
    await pool.execute(
      'INSERT INTO ip2location_refresh_state (state_key, state_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE state_value = VALUES(state_value)',
      [key, value]
    );
  }
}

async function readState(pool) {
  try {
    const [rows] = await pool.execute('SELECT state_key, state_value FROM ip2location_refresh_state');
    return Object.fromEntries(rows.map((row) => [row.state_key, row.state_value || '']));
  } catch {
    return {};
  }
}

async function countTable(pool, table) {
  if (!TABLES.has(table)) return null;
  try {
    const [rows] = await pool.execute(`SELECT COUNT(*) AS count FROM \`${table}\``);
    return Number(rows[0]?.count || 0);
  } catch {
    return null;
  }
}

async function latestTableMtime(pool, table) {
  if (!TABLES.has(table)) return '';
  try {
    const [rows] = await pool.execute(
      `SELECT UPDATE_TIME AS updated_at FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?`,
      [table]
    );
    const value = rows[0]?.updated_at;
    return value ? new Date(value).toISOString() : '';
  } catch {
    return '';
  }
}

export async function ensureIP2LocationSchema(pool) {
  await pool.execute(`
    CREATE TABLE IF NOT EXISTS ip2location_refresh_state (
      state_key VARCHAR(64) NOT NULL PRIMARY KEY,
      state_value TEXT,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS ip2location_db11_ipv4 (
      ip_from BIGINT UNSIGNED NOT NULL,
      ip_to BIGINT UNSIGNED NOT NULL,
      country_code CHAR(2),
      country_name VARCHAR(64),
      region_name VARCHAR(128),
      city_name VARCHAR(128),
      latitude DOUBLE NULL,
      longitude DOUBLE NULL,
      zip_code VARCHAR(30),
      time_zone VARCHAR(16),
      PRIMARY KEY (ip_to)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);
  await pool.execute(`
    CREATE TABLE IF NOT EXISTS ip2location_db11_ipv6 (
      ip_from DECIMAL(39,0) NOT NULL,
      ip_to DECIMAL(39,0) NOT NULL,
      country_code CHAR(2),
      country_name VARCHAR(64),
      region_name VARCHAR(128),
      city_name VARCHAR(128),
      latitude DOUBLE NULL,
      longitude DOUBLE NULL,
      zip_code VARCHAR(30),
      time_zone VARCHAR(16),
      PRIMARY KEY (ip_to)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS ip2location_px7_ipv4 (
      ip_from BIGINT UNSIGNED NOT NULL,
      ip_to BIGINT UNSIGNED NOT NULL,
      proxy_type VARCHAR(3),
      country_code CHAR(2),
      country_name VARCHAR(64),
      region_name VARCHAR(128),
      city_name VARCHAR(128),
      isp VARCHAR(256),
      domain VARCHAR(128),
      usage_type VARCHAR(11),
      asn VARCHAR(16),
      as_name VARCHAR(256),
      PRIMARY KEY (ip_to)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);
  await pool.execute(`
    CREATE TABLE IF NOT EXISTS ip2location_px7_ipv6 (
      ip_from DECIMAL(39,0) NOT NULL,
      ip_to DECIMAL(39,0) NOT NULL,
      proxy_type VARCHAR(3),
      country_code CHAR(2),
      country_name VARCHAR(64),
      region_name VARCHAR(128),
      city_name VARCHAR(128),
      isp VARCHAR(256),
      domain VARCHAR(128),
      usage_type VARCHAR(11),
      asn VARCHAR(16),
      as_name VARCHAR(256),
      PRIMARY KEY (ip_to)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS ip2location_asn_ipv4 (
      ip_from BIGINT UNSIGNED NOT NULL,
      ip_to BIGINT UNSIGNED NOT NULL,
      cidr VARCHAR(43),
      asn VARCHAR(16),
      as_name VARCHAR(256),
      PRIMARY KEY (ip_to)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);
  await pool.execute(`
    CREATE TABLE IF NOT EXISTS ip2location_asn_ipv6 (
      ip_from DECIMAL(39,0) NOT NULL,
      ip_to DECIMAL(39,0) NOT NULL,
      cidr VARCHAR(43),
      asn VARCHAR(16),
      as_name VARCHAR(256),
      PRIMARY KEY (ip_to)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);
}

function ipv4ToDecimal(ip) {
  return ip.split('.').reduce((value, part) => (value << 8n) + BigInt(Number(part)), 0n).toString();
}

function expandIPv6(ip) {
  const normalized = ip.toLowerCase();
  const [headPart, tailPart = ''] = normalized.split('::');
  const head = headPart ? headPart.split(':') : [];
  const tail = tailPart ? tailPart.split(':') : [];
  const fill = 8 - head.length - tail.length;
  if (fill < 0) return null;
  return [...head, ...Array(fill).fill('0'), ...tail].map((part) => part || '0');
}

function ipv6ToDecimal(ip) {
  const groups = expandIPv6(ip);
  if (!groups) return '';
  let value = 0n;
  for (const group of groups) {
    value = (value << 16n) + BigInt(parseInt(group, 16));
  }
  return value.toString();
}

function ipToDecimal(ip) {
  const version = isIP(ip);
  if (version === 4) return { version, value: ipv4ToDecimal(ip) };
  if (version === 6) return { version, value: ipv6ToDecimal(ip) };
  return { version: 0, value: '' };
}

async function lookupTable(pool, table, numericIP) {
  if (!TABLES.has(table) || !numericIP) return null;
  try {
    const [rows] = await pool.execute(
      `SELECT * FROM \`${table}\` WHERE ip_from <= ? AND ip_to >= ? ORDER BY (ip_to - ip_from) ASC LIMIT 1`,
      [numericIP, numericIP]
    );
    return rows[0] || null;
  } catch {
    return null;
  }
}

export async function lookupIP2Location(pool, ip) {
  if (!isConfigured()) return { enabled: false, contributed: false };

  const { version, value } = ipToDecimal(ip);
  if (!version || !value) return { enabled: isIP2LocationEnabled(), contributed: false };

  const suffix = version === 6 ? 'ipv6' : 'ipv4';
  const [db11, px7, asn] = await Promise.all([
    lookupTable(pool, `ip2location_db11_${suffix}`, value),
    lookupTable(pool, `ip2location_px7_${suffix}`, value),
    lookupTable(pool, `ip2location_asn_${suffix}`, value),
  ]);

  return {
    enabled: isIP2LocationEnabled(),
    contributed: Boolean(db11 || px7 || asn),
    db11: db11 ? {
      city: normalizeValue(db11.city_name),
      region: normalizeValue(db11.region_name),
      country: normalizeValue(db11.country_name),
      country_code: normalizeValue(db11.country_code),
      postal_code: normalizeValue(db11.zip_code),
      latitude: db11.latitude ?? null,
      longitude: db11.longitude ?? null,
      timezone: normalizeValue(db11.time_zone),
    } : null,
    px7: px7 ? {
      proxy_type: normalizeValue(px7.proxy_type),
      country: normalizeValue(px7.country_name),
      country_code: normalizeValue(px7.country_code),
      region: normalizeValue(px7.region_name),
      city: normalizeValue(px7.city_name),
      isp: normalizeValue(px7.isp),
      domain: normalizeValue(px7.domain),
      usage_type: normalizeValue(px7.usage_type),
      asn: normalizeValue(px7.asn),
      as_name: normalizeValue(px7.as_name),
    } : null,
    asn: asn ? {
      cidr: normalizeValue(asn.cidr),
      asn: normalizeValue(asn.asn),
      as_name: normalizeValue(asn.as_name),
    } : null,
  };
}

export async function refreshIP2LocationData(options = {}) {
  const { force = false, logger, pool } = options;

  if (!pool) throw new Error('MySQL pool is required for IP2Location refresh.');
  if (!isIP2LocationEnabled()) {
    const error = new Error('IP2Location updater is disabled. Set IP2LOCATION_ENABLED=true and IP2LOCATION_DOWNLOAD_TOKEN to enable it.');
    error.statusCode = 503;
    throw error;
  }
  if (ip2LocationState.inflight && !force) return ip2LocationState.inflight;

  ip2LocationState.inflight = (async () => {
    await ensureIP2LocationSchema(pool);
    ip2LocationState.lastAttemptedAt = new Date().toISOString();
    ip2LocationState.lastError = '';
    await setState(pool, { last_attempted_at: ip2LocationState.lastAttemptedAt, last_error: '' });

    const workspaceDir = await mkdtemp(path.join(tmpdir(), 'systoolkit-ip2location-'));
    const imported = {};
    const errors = {};

    try {
      for (const dataset of DATASETS) {
        try {
          logger?.info?.(`Downloading ${dataset.label} (${dataset.packageCode})`);
          const csvFile = await downloadAndExtractDataset(dataset, workspaceDir);
          imported[dataset.key] = await importCsv(pool, dataset, csvFile);
        } catch (error) {
          imported[dataset.key] = null;
          errors[dataset.key] = error.message || `Failed to import ${dataset.label}.`;
          logger?.warn?.(`IP2Location import failed for ${dataset.label}: ${errors[dataset.key]}`);
        }
      }

      if (Object.values(imported).every((value) => value === null)) {
        throw new Error('All IP2Location package imports failed.');
      }

      ip2LocationState.lastSuccessfulAt = new Date().toISOString();
      ip2LocationState.lastError = Object.keys(errors).length > 0
        ? `Partial IP2Location import: ${Object.values(errors).join(' | ')}`
        : '';
      await setState(pool, {
        last_successful_update_at: ip2LocationState.lastSuccessfulAt,
        last_error: ip2LocationState.lastError,
        imported: JSON.stringify(imported),
      });
      return { success: true, imported, updated_at: ip2LocationState.lastSuccessfulAt };
    } catch (error) {
      ip2LocationState.lastError = error.message || 'IP2Location update failed.';
      await setState(pool, {
        last_error: ip2LocationState.lastError,
        last_attempted_at: ip2LocationState.lastAttemptedAt,
      });
      throw error;
    } finally {
      await rm(workspaceDir, { recursive: true, force: true }).catch(() => {});
      ip2LocationState.inflight = null;
    }
  })();

  return ip2LocationState.inflight;
}

export async function getIP2LocationStatus(pool) {
  const state = pool ? await readState(pool) : {};
  const packages = {};
  for (const dataset of DATASETS) {
    packages[dataset.key] = {
      label: dataset.label,
      package_code: dataset.packageCode,
      table: dataset.table,
      rows: pool ? await countTable(pool, dataset.table) : null,
      last_table_update_at: pool ? await latestTableMtime(pool, dataset.table) : '',
    };
  }

  return {
    enabled: isIP2LocationEnabled(),
    configured: isConfigured(),
    attribution_required: true,
    refresh_interval_ms: IP2LOCATION_REFRESH_MS,
    last_attempted_at: ip2LocationState.lastAttemptedAt || state.last_attempted_at || '',
    last_successful_update_at: ip2LocationState.lastSuccessfulAt || state.last_successful_update_at || '',
    last_error: ip2LocationState.lastError || state.last_error || '',
    packages,
  };
}

export async function initIP2LocationDataRefresh(fastify) {
  const pool = fastify.mysql;
  if (!isConfigured()) return;

  await ensureIP2LocationSchema(pool);
  const state = await readState(pool);
  ip2LocationState.lastAttemptedAt = state.last_attempted_at || '';
  ip2LocationState.lastSuccessfulAt = state.last_successful_update_at || '';
  ip2LocationState.lastError = state.last_error || '';

  if (!isIP2LocationEnabled()) {
    fastify.log.warn('IP2Location updater disabled: IP2LOCATION_DOWNLOAD_TOKEN is not configured.');
    return;
  }

  const latestSuccess = ip2LocationState.lastSuccessfulAt ? new Date(ip2LocationState.lastSuccessfulAt).getTime() : 0;
  const shouldRefreshOnBoot = !latestSuccess || (Date.now() - latestSuccess) >= IP2LOCATION_REFRESH_MS;
  if (shouldRefreshOnBoot) {
    void refreshIP2LocationData({ pool, logger: fastify.log }).catch((error) => {
      fastify.log.warn(`Initial IP2Location refresh failed: ${error.message}`);
    });
  }

  if (!ip2LocationState.refreshHandle) {
    ip2LocationState.refreshHandle = setInterval(() => {
      void refreshIP2LocationData({ pool, logger: fastify.log }).catch((error) => {
        fastify.log.warn(`Scheduled IP2Location refresh failed: ${error.message}`);
      });
    }, IP2LOCATION_REFRESH_MS);

    if (typeof ip2LocationState.refreshHandle.unref === 'function') {
      ip2LocationState.refreshHandle.unref();
    }
  }

  fastify.addHook('onClose', async () => {
    if (ip2LocationState.refreshHandle) {
      clearInterval(ip2LocationState.refreshHandle);
      ip2LocationState.refreshHandle = null;
    }
  });
}
