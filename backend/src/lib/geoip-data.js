import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { access, copyFile, mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pipeline } from 'node:stream/promises';
import { reloadGeoIPReaders } from './geoip-city.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../../..');
const GEOIP_PUBLIC_DIR = process.env.GEOIP_PUBLIC_DIR || path.join(REPO_ROOT, 'frontend/public/data');
const GEOIP_META_PATH = path.join(GEOIP_PUBLIC_DIR, 'geoip-meta.json');
const GEOIP_REFRESH_MS = parseInt(process.env.GEOIP_REFRESH_MS || String(24 * 60 * 60 * 1000), 10);
const GEOIP_DOWNLOAD_TIMEOUT_MS = parseInt(process.env.GEOIP_DOWNLOAD_TIMEOUT_MS || String(15 * 60 * 1000), 10);
const GEOIP_EDITIONS = (process.env.GEOIP_EDITIONS || 'GeoLite2-City,GeoLite2-Country,GeoLite2-ASN')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);
const MAXMIND_LICENSE_KEY = (process.env.MAXMIND_LICENSE_KEY || '').trim();

const DATABASE_DESCRIPTIONS = {
  'GeoLite2-Country': 'MaxMind GeoLite2 Country Database',
  'GeoLite2-ASN': 'MaxMind GeoLite2 ASN Database',
  'GeoLite2-City': 'MaxMind GeoLite2 City Database',
};

const geoIpState = {
  lastAttemptedAt: '',
  lastSuccessfulAt: '',
  lastError: '',
  inflight: null,
  refreshHandle: null,
  refreshMs: GEOIP_REFRESH_MS,
  publicDir: GEOIP_PUBLIC_DIR,
  metadataPath: GEOIP_META_PATH,
  editions: GEOIP_EDITIONS,
};

function isUpdaterEnabled() {
  return Boolean(MAXMIND_LICENSE_KEY);
}

function formatVersion(date = new Date()) {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, '0');
  const day = String(date.getUTCDate()).padStart(2, '0');
  return `${year}.${month}.${day}`;
}

function databaseFilename(editionId) {
  return `${editionId}.mmdb`;
}

function buildDownloadUrl(editionId) {
  const url = new URL('https://download.maxmind.com/app/geoip_download');
  url.searchParams.set('edition_id', editionId);
  url.searchParams.set('license_key', MAXMIND_LICENSE_KEY);
  url.searchParams.set('suffix', 'tar.gz');
  return url.toString();
}

async function pathExists(targetPath) {
  try {
    await access(targetPath);
    return true;
  } catch {
    return false;
  }
}

async function readGeoIpMetadata() {
  try {
    const raw = await readFile(GEOIP_META_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') return parsed;
  } catch {}
  return { version: '', databases: {} };
}

async function collectFileStats(filePath) {
  try {
    const info = await stat(filePath);
    return {
      size_bytes: info.size,
      file_mtime: info.mtime.toISOString(),
    };
  } catch {
    return {
      size_bytes: null,
      file_mtime: '',
    };
  }
}

async function computeFileSha256(filePath) {
  try {
    const hash = createHash('sha256');
    const stream = createReadStream(filePath);
    for await (const chunk of stream) {
      hash.update(chunk);
    }
    return hash.digest('hex');
  } catch {
    return '';
  }
}

async function inferLatestDatabaseUpdateAt() {
  let latest = '';

  for (const editionId of GEOIP_EDITIONS) {
    const stats = await collectFileStats(path.join(GEOIP_PUBLIC_DIR, databaseFilename(editionId)));
    if (stats.file_mtime && (!latest || new Date(stats.file_mtime).getTime() > new Date(latest).getTime())) {
      latest = stats.file_mtime;
    }
  }

  return latest;
}

async function allConfiguredDatabaseFilesExist() {
  for (const editionId of GEOIP_EDITIONS) {
    if (!(await pathExists(path.join(GEOIP_PUBLIC_DIR, databaseFilename(editionId))))) {
      return false;
    }
  }
  return true;
}

async function buildGeoIpStatus() {
  const metadata = await readGeoIpMetadata();
  const databases = {};

  for (const editionId of GEOIP_EDITIONS) {
    const filename = databaseFilename(editionId);
    const filePath = path.join(GEOIP_PUBLIC_DIR, filename);
    const metaEntry = metadata?.databases?.[filename] || {};
    databases[filename] = {
      name: metaEntry.name || editionId,
      description: metaEntry.description || DATABASE_DESCRIPTIONS[editionId] || '',
      edition_id: editionId,
      version: metaEntry.version || metadata.version || '',
      last_updated_at: metaEntry.last_updated_at || '',
      sha256: metaEntry.sha256 || '',
      ...await collectFileStats(filePath),
    };
  }

  return {
    updater_enabled: isUpdaterEnabled(),
    refresh_interval_ms: GEOIP_REFRESH_MS,
    public_dir: GEOIP_PUBLIC_DIR,
    metadata_path: GEOIP_META_PATH,
    version: metadata.version || '',
    last_attempted_at: geoIpState.lastAttemptedAt || metadata.last_attempted_at || '',
    last_successful_update_at: geoIpState.lastSuccessfulAt || metadata.last_successful_update_at || await inferLatestDatabaseUpdateAt(),
    last_error: geoIpState.lastError || metadata.last_error || '',
    editions: GEOIP_EDITIONS,
    databases,
  };
}

async function writeGeoIpMetadata(metadata) {
  await mkdir(GEOIP_PUBLIC_DIR, { recursive: true });
  await writeFile(GEOIP_META_PATH, `${JSON.stringify(metadata, null, 2)}\n`, 'utf8');
}

async function streamToFile(response, filePath) {
  const body = response.body;
  if (!body) throw new Error('MaxMind download response body was empty.');
  const output = createWriteStream(filePath);
  await pipeline(body, output);
}

function runTarExtract(archivePath, outputDir) {
  return new Promise((resolve, reject) => {
    const child = spawn('tar', ['-xzf', archivePath, '-C', outputDir], { stdio: ['ignore', 'pipe', 'pipe'] });
    const stderr = [];

    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(Buffer.concat(stderr).toString('utf8').trim() || `tar failed with exit code ${code}`));
    });
  });
}

async function findFileRecursive(rootDir, targetFileName) {
  const entries = await readdir(rootDir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(rootDir, entry.name);
    if (entry.isFile() && entry.name === targetFileName) return fullPath;
    if (entry.isDirectory()) {
      const nested = await findFileRecursive(fullPath, targetFileName);
      if (nested) return nested;
    }
  }
  return '';
}

async function downloadAndExtractEdition(editionId, workspaceDir) {
  const archivePath = path.join(workspaceDir, `${editionId}.tar.gz`);
  const extractDir = path.join(workspaceDir, `${editionId}-extract`);
  await mkdir(extractDir, { recursive: true });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), GEOIP_DOWNLOAD_TIMEOUT_MS);

  try {
    const response = await fetch(buildDownloadUrl(editionId), {
      headers: { Accept: 'application/octet-stream' },
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`MaxMind download failed for ${editionId} with HTTP ${response.status}.`);
    }

    await streamToFile(response, archivePath);
    await runTarExtract(archivePath, extractDir);

    const targetPath = await findFileRecursive(extractDir, databaseFilename(editionId));
    if (!targetPath) throw new Error(`Downloaded archive for ${editionId} did not contain ${databaseFilename(editionId)}.`);
    return targetPath;
  } finally {
    clearTimeout(timer);
  }
}

export async function refreshGeoIpData(options = {}) {
  const { force = false, logger } = options;

  if (!isUpdaterEnabled()) {
    const error = new Error('MaxMind updater is disabled. Set MAXMIND_LICENSE_KEY to enable it.');
    error.statusCode = 503;
    throw error;
  }

  if (geoIpState.inflight && !force) return geoIpState.inflight;

  geoIpState.inflight = (async () => {
    geoIpState.lastAttemptedAt = new Date().toISOString();
    geoIpState.lastError = '';

    const actualWorkspaceDir = await mkdtemp(path.join(tmpdir(), 'systoolkit-geoip-'));

    try {
      await mkdir(GEOIP_PUBLIC_DIR, { recursive: true });

      const metadata = await readGeoIpMetadata();
      const nextVersion = formatVersion();
      const databases = { ...(metadata.databases || {}) };

      let anyChanged = false;

      for (const editionId of GEOIP_EDITIONS) {
        const filename = databaseFilename(editionId);
        const extractedPath = await downloadAndExtractEdition(editionId, actualWorkspaceDir);
        const destinationPath = path.join(GEOIP_PUBLIC_DIR, filename);
        const destinationExists = await pathExists(destinationPath);
        const metaEntry = metadata?.databases?.[filename] || {};

        const newHash = await computeFileSha256(extractedPath);
        const existingHash = metaEntry.sha256 || (destinationExists ? await computeFileSha256(destinationPath) : '');
        const isUnchanged = !force && destinationExists && Boolean(newHash) && newHash === existingHash;

        if (isUnchanged) {
          logger?.info?.(`GeoIP ${editionId} is unchanged (SHA-256: ${newHash.slice(0, 12)}...). Preserving cache headers.`);
          const stats = await collectFileStats(destinationPath);
          databases[filename] = {
            name: metaEntry.name || editionId,
            description: metaEntry.description || DATABASE_DESCRIPTIONS[editionId] || `${editionId} Database`,
            edition_id: editionId,
            version: metaEntry.version || metadata.version || nextVersion,
            last_updated_at: metaEntry.last_updated_at || stats.file_mtime || new Date().toISOString(),
            sha256: newHash,
            ...stats,
          };
        } else {
          anyChanged = true;
          await copyFile(extractedPath, destinationPath);
          const stats = await collectFileStats(destinationPath);
          databases[filename] = {
            name: editionId,
            description: DATABASE_DESCRIPTIONS[editionId] || `${editionId} Database`,
            edition_id: editionId,
            version: nextVersion,
            last_updated_at: new Date().toISOString(),
            sha256: newHash,
            ...stats,
          };
        }
      }

      const nextMetadata = {
        version: anyChanged ? nextVersion : (metadata.version || nextVersion),
        last_attempted_at: geoIpState.lastAttemptedAt,
        last_successful_update_at: new Date().toISOString(),
        last_error: '',
        refresh_interval_ms: GEOIP_REFRESH_MS,
        updater_enabled: true,
        databases,
      };

      await writeGeoIpMetadata(nextMetadata);
      geoIpState.lastSuccessfulAt = nextMetadata.last_successful_update_at;
      geoIpState.lastError = '';

      if (anyChanged) {
        await reloadGeoIPReaders(logger);
        logger?.info?.(`MaxMind GeoIP databases updated with new data at ${geoIpState.lastSuccessfulAt}.`);
      } else {
        logger?.info?.(`MaxMind GeoIP databases checked: all databases unchanged.`);
      }

      return nextMetadata;
    } catch (error) {
      geoIpState.lastError = error.message || 'MaxMind update failed.';
      const metadata = await readGeoIpMetadata();
      await writeGeoIpMetadata({
        ...metadata,
        last_attempted_at: geoIpState.lastAttemptedAt,
        last_successful_update_at: geoIpState.lastSuccessfulAt || metadata.last_successful_update_at || '',
        last_error: geoIpState.lastError,
        refresh_interval_ms: GEOIP_REFRESH_MS,
        updater_enabled: isUpdaterEnabled(),
      });
      throw error;
    } finally {
      await rm(actualWorkspaceDir, { recursive: true, force: true }).catch(() => {});
      geoIpState.inflight = null;
    }
  })();

  return geoIpState.inflight;
}

export async function getGeoIpDataStatus() {
  return buildGeoIpStatus();
}

export async function initGeoIpDataRefresh(fastify) {
  const metadata = await readGeoIpMetadata();
  geoIpState.lastAttemptedAt = metadata.last_attempted_at || '';
  geoIpState.lastSuccessfulAt = metadata.last_successful_update_at || await inferLatestDatabaseUpdateAt();
  geoIpState.lastError = metadata.last_error || '';

  if (!isUpdaterEnabled()) {
    fastify.log.warn('MaxMind updater disabled: MAXMIND_LICENSE_KEY is not configured.');
  } else {
    const shouldRefreshOnBoot = !geoIpState.lastSuccessfulAt
      || (Date.now() - new Date(geoIpState.lastSuccessfulAt).getTime()) >= GEOIP_REFRESH_MS
      || !(await allConfiguredDatabaseFilesExist());

    if (shouldRefreshOnBoot) {
      void refreshGeoIpData({ logger: fastify.log }).catch((error) => {
        fastify.log.warn(`Initial MaxMind refresh failed: ${error.message}`);
      });
    }

    if (!geoIpState.refreshHandle) {
      geoIpState.refreshHandle = setInterval(() => {
        void refreshGeoIpData({ logger: fastify.log }).catch((error) => {
          fastify.log.warn(`Scheduled MaxMind refresh failed: ${error.message}`);
        });
      }, GEOIP_REFRESH_MS);

      if (typeof geoIpState.refreshHandle.unref === 'function') {
        geoIpState.refreshHandle.unref();
      }
    }
  }

  fastify.addHook('onClose', async () => {
    if (geoIpState.refreshHandle) {
      clearInterval(geoIpState.refreshHandle);
      geoIpState.refreshHandle = null;
    }
  });
}
