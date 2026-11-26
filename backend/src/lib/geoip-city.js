/**
 * Server-side GeoIP City + ASN reader using the `maxmind` npm package.
 *
 * Reads GeoLite2-City.mmdb and GeoLite2-ASN.mmdb from the backend data directory.
 * These files are NOT served to the browser — server-only.
 *
 * Usage:
 *   import { initGeoIPReaders, lookupCity, lookupASN, isGeoIPReady } from './geoip-city.js';
 *   await initGeoIPReaders();
 *   const cityInfo = lookupCity('103.157.231.134');
 *   const asnInfo  = lookupASN('103.157.231.134');
 */

import maxmind from 'maxmind';
import { access } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../../..');

// City DB lives in backend/data (server-only), ASN DB in frontend/public/data (shared)
const CITY_DB_PATH = process.env.GEOIP_CITY_DB_PATH
  || path.join(REPO_ROOT, 'frontend/public/data/GeoLite2-City.mmdb');
const ASN_DB_PATH = process.env.GEOIP_ASN_DB_PATH
  || path.join(REPO_ROOT, 'frontend/public/data/GeoLite2-ASN.mmdb');

let cityReader = null;
let asnReader = null;

async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Initialize MMDB readers. Call once on server startup.
 * Silently skips databases that don't exist yet (they'll be downloaded by the updater).
 */
export async function initGeoIPReaders(logger) {
  // City DB
  if (await fileExists(CITY_DB_PATH)) {
    try {
      cityReader = await maxmind.open(CITY_DB_PATH);
      logger?.info?.(`GeoIP City reader loaded: ${CITY_DB_PATH}`);
    } catch (err) {
      logger?.warn?.(`Failed to open GeoIP City DB: ${err.message}`);
    }
  } else {
    logger?.warn?.(`GeoIP City DB not found at ${CITY_DB_PATH} — city lookups will be unavailable.`);
  }

  // ASN DB
  if (await fileExists(ASN_DB_PATH)) {
    try {
      asnReader = await maxmind.open(ASN_DB_PATH);
      logger?.info?.(`GeoIP ASN reader loaded: ${ASN_DB_PATH}`);
    } catch (err) {
      logger?.warn?.(`Failed to open GeoIP ASN DB: ${err.message}`);
    }
  } else {
    logger?.warn?.(`GeoIP ASN DB not found at ${ASN_DB_PATH} — ASN lookups will be unavailable.`);
  }
}

/**
 * Reload MMDB readers (called after GeoIP data refresh).
 */
export async function reloadGeoIPReaders(logger) {
  cityReader = null;
  asnReader = null;
  await initGeoIPReaders(logger);
}

/**
 * Check if the readers are initialized.
 */
export function isGeoIPReady() {
  return { city: !!cityReader, asn: !!asnReader };
}

/**
 * Lookup city-level geolocation data for an IP.
 * Returns null if City DB is not loaded or IP not found.
 */
export function lookupCity(ip) {
  if (!cityReader) return null;
  try {
    const result = cityReader.get(ip);
    if (!result) return null;

    const city = result.city?.names?.en || '';
    const region = result.subdivisions?.[0]?.names?.en || '';
    const regionCode = result.subdivisions?.[0]?.iso_code || '';
    const country = result.country?.names?.en || '';
    const countryCode = result.country?.iso_code || '';
    const registeredCountry = result.registered_country?.names?.en || '';
    const registeredCountryCode = result.registered_country?.iso_code || '';
    const representedCountry = result.represented_country?.names?.en || '';
    const representedCountryCode = result.represented_country?.iso_code || '';
    const representedCountryType = result.represented_country?.type || '';
    const continent = result.continent?.names?.en || '';
    const continentCode = result.continent?.code || '';
    const postalCode = result.postal?.code || '';
    const accuracyRadius = result.location?.accuracy_radius || null;
    const latitude = result.location?.latitude || null;
    const longitude = result.location?.longitude || null;
    const metroCode = result.location?.metro_code || null;
    const timezone = result.location?.time_zone || '';

    return {
      city,
      region,
      region_code: regionCode,
      country,
      country_code: countryCode,
      registered_country: registeredCountry,
      registered_country_code: registeredCountryCode,
      represented_country: representedCountry,
      represented_country_code: representedCountryCode,
      represented_country_type: representedCountryType,
      continent,
      continent_code: continentCode,
      postal_code: postalCode,
      accuracy_radius: accuracyRadius,
      latitude,
      longitude,
      metro_code: metroCode,
      timezone,
    };
  } catch {
    return null;
  }
}

/**
 * Lookup ASN data for an IP.
 * Returns null if ASN DB is not loaded or IP not found.
 */
export function lookupASN(ip) {
  if (!asnReader) return null;
  try {
    const result = asnReader.get(ip);
    if (!result) return null;

    return {
      asn: result.autonomous_system_number || null,
      org: result.autonomous_system_organization || '',
    };
  } catch {
    return null;
  }
}
