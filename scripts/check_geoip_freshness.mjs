#!/usr/bin/env node
/**
 * GeoIP staleness monitor.
 *
 * The MaxMind auto-updater (backend/src/lib/geoip-data.js) fails QUIETLY by
 * design — a failed refresh is only `log.warn`'d and stashed in `last_error`.
 * The last good .mmdb keeps being served, so nothing is visibly broken until
 * someone opens the admin panel and notices the database is weeks out of date.
 *
 * This script closes that gap. It verifies the databases are actually fresh by
 * reading the metadata over HTTP (the same bytes a client would receive) and
 * exits non-zero when anything is stale, so cron / CI / an alert wrapper can
 * catch a silent failure.
 *
 * Checks:
 *   1. Backend API is reachable and healthy
 *   2. Updater is enabled (MAXMIND_LICENSE_KEY present)
 *   3. Each .mmdb is served over HTTP (200, non-zero length)
 *   4. geoip-meta.json is served and parseable
 *   5. last_successful_update_at is newer than STALE_HOURS (default 48)
 *   6. last_error is empty
 *   7. Every expected database reports a version
 *
 * Usage:
 *   node scripts/check_geoip_freshness.mjs
 *
 * Env:
 *   GEOIP_CHECK_BASE_URL   base URL of the app        (default http://localhost:3001)
 *   GEOIP_CHECK_API_URL    backend API base URL       (default http://localhost:4001)
 *   GEOIP_CHECK_STALE_HOURS  staleness threshold      (default 48)
 *   GEOIP_CHECK_EXPECTED   comma-separated editions   (default GeoLite2-ASN,GeoLite2-Country,GeoLite2-City)
 *
 * Exit codes: 0 = fresh, 1 = stale/unhealthy, 2 = could not check.
 */

const BASE_URL = (process.env.GEOIP_CHECK_BASE_URL || 'http://localhost:3001').replace(/\/$/, '');
const API_URL = (process.env.GEOIP_CHECK_API_URL || 'http://localhost:4001').replace(/\/$/, '');
const STALE_HOURS = parseInt(process.env.GEOIP_CHECK_STALE_HOURS || '48', 10);
const EXPECTED = (process.env.GEOIP_CHECK_EXPECTED || 'GeoLite2-ASN,GeoLite2-Country,GeoLite2-City')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const failures = [];
const warnings = [];

function fail(msg) { failures.push(msg); console.log(`  FAIL  ${msg}`); }
function warn(msg) { warnings.push(msg); console.log(`  WARN  ${msg}`); }
function pass(msg) { console.log(`  ok    ${msg}`); }

function ageHours(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return NaN;
  return (Date.now() - t) / 36e5;
}

async function fetchWithTimeout(url, opts = {}, timeoutMs = 20000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ── 1. Backend reachable ────────────────────────────────────────────────
console.log(`\nGeoIP freshness check`);
console.log(`  app=${BASE_URL}  api=${API_URL}  stale_after=${STALE_HOURS}h\n`);

console.log('[1] backend health');
let health;
try {
  const res = await fetchWithTimeout(`${API_URL}/api/health`);
  if (!res.ok) {
    fail(`health endpoint returned HTTP ${res.status}`);
  } else {
    health = await res.json();
    if (health.status === 'ok') pass(`backend healthy (db=${health.database})`);
    else fail(`backend unhealthy: ${JSON.stringify(health)}`);
  }
} catch (err) {
  console.error(`\nCould not reach ${API_URL}/api/health — ${err.message}`);
  console.error('Treating this as an infrastructure problem, not a staleness verdict.');
  process.exit(2);
}

// ── 2. Updater enabled ──────────────────────────────────────────────────
console.log('\n[2] updater configuration');
let meta;
try {
  const res = await fetchWithTimeout(`${BASE_URL}/data/geoip-meta.json`);
  if (!res.ok) {
    fail(`geoip-meta.json returned HTTP ${res.status}`);
    throw new Error('meta unavailable');
  }
  meta = await res.json();
  pass(`geoip-meta.json served (version=${meta.version})`);
} catch (err) {
  if (!failures.length) fail(`could not read geoip-meta.json: ${err.message}`);
  meta = null;
}

if (meta) {
  if (meta.updater_enabled === true) {
    pass('updater enabled (MAXMIND_LICENSE_KEY present)');
  } else {
    fail('updater is DISABLED — no MAXMIND_LICENSE_KEY set, databases will silently rot');
  }
}

// ── 3. Every expected database is served ───────────────────────────────
console.log('\n[3] databases served over HTTP');
for (const edition of EXPECTED) {
  const filename = `${edition}.mmdb`;
  try {
    const res = await fetchWithTimeout(`${BASE_URL}/data/${filename}`, { method: 'HEAD' }, 30000);
    if (res.status !== 200) {
      fail(`${filename} returned HTTP ${res.status}`);
      continue;
    }
    const len = parseInt(res.headers.get('content-length') || '0', 10);
    if (!len) {
      fail(`${filename} served with zero content-length`);
      continue;
    }
    const db = meta?.databases?.[filename] || meta?.databases?.[edition];
    const version = db?.version || meta?.version || '?';
    const etag = res.headers.get('etag') ? ' etag' : ' NO-ETAG';
    pass(`${filename} ${(len / 1048576).toFixed(1)} MB version=${version}${etag}`);
  } catch (err) {
    fail(`${filename} not fetchable: ${err.message}`);
  }
}

// ── 4. Freshness ────────────────────────────────────────────────────────
console.log('\n[4] freshness');
if (meta) {
  const lastOk = meta.last_successful_update_at;
  if (!lastOk) {
    fail('last_successful_update_at is empty — never successfully updated');
  } else {
    const age = ageHours(lastOk);
    if (Number.isNaN(age)) {
      fail(`last_successful_update_at is unparseable: ${lastOk}`);
    } else if (age > STALE_HOURS) {
      fail(`last successful update was ${age.toFixed(1)}h ago (threshold ${STALE_HOURS}h) — ${lastOk}`);
    } else {
      pass(`last successful update ${age.toFixed(1)}h ago (${lastOk})`);
    }
  }
}

// ── 5. Error state ──────────────────────────────────────────────────────
console.log('\n[5] error state');
if (meta) {
  if (meta.last_error) {
    fail(`updater reported an error: ${meta.last_error}`);
  } else {
    pass('no updater error recorded');
  }
}

// ── 6. Per-database versions ────────────────────────────────────────────
console.log('\n[6] per-database versions');
if (meta?.databases) {
  for (const [filename, db] of Object.entries(meta.databases)) {
    if (!db.version) warn(`${filename} has no version reported`);
    else pass(`${filename} version=${db.version}`);
  }
}

// ── Verdict ─────────────────────────────────────────────────────────────
console.log(`\n${'='.repeat(64)}`);
if (warnings.length) {
  console.log(`${warnings.length} warning(s):`);
  warnings.forEach((w) => console.log(`  - ${w}`));
}
if (failures.length) {
  console.log(`UNHEALTHY — ${failures.length} failure(s):`);
  failures.forEach((f) => console.log(`  - ${f}`));
  console.log(`Databases are stale or the updater is broken. Check the admin`);
  console.log(`dashboard Refresh Status card, or MaxMind quota / license key.`);
  process.exit(1);
}
console.log('HEALTHY — all GeoIP databases are present and fresh.');
process.exit(0);
