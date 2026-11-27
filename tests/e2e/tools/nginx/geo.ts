import { Reader, type AsnResponse, type CountryResponse } from 'maxmind';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * GeoIP oracle.
 *
 * The Traffic Analyzer resolves country and ASN in the browser with its own
 * MMDB reader (frontend/public/js/geoip.js). This file reads the SAME database
 * files, downloaded from the site under test, with the `maxmind` package in
 * Node. Two readers, one data set: if the page shows a different country or
 * network for an address than this file does, the page's reader is wrong.
 *
 * Definitions (what the page labels "Country" and "ASN"):
 *   country      = `country.names.en` of the Country database, else "Unknown"
 *   countryCode  = `country.iso_code`, else "--"
 *   asn          = `autonomous_system_number` of the ASN database, else 0
 *   asnOrg       = `autonomous_system_organization`, else "Unknown"
 */

export interface GeoFacts {
  country: string;
  countryCode: string;
  asn: number;
  asnOrg: string;
}

export interface GeoOracle {
  lookup(ip: string): GeoFacts;
}

const FILES = ['GeoLite2-Country.mmdb', 'GeoLite2-ASN.mmdb'] as const;
let cached: Promise<GeoOracle> | null = null;

async function download(baseURL: string, name: string, cacheDir: string, expectedSha?: string): Promise<Buffer> {
  const target = path.join(cacheDir, name);
  if (existsSync(target)) {
    const onDisk = readFileSync(target);
    if (!expectedSha || createHash('sha256').update(onDisk).digest('hex') === expectedSha) return onDisk;
  }
  const response = await fetch(new URL(`/data/${name}`, baseURL));
  if (!response.ok) throw new Error(`GeoIP oracle: ${name} is not served by ${baseURL} (HTTP ${response.status}). The Traffic Analyzer needs frontend/public/data/${name}.`);
  const body = Buffer.from(await response.arrayBuffer());
  writeFileSync(target, body);
  return body;
}

/** Loads (once per worker) the databases the site under test serves. */
export function loadGeoOracle(baseURL: string): Promise<GeoOracle> {
  if (cached) return cached;
  cached = (async () => {
    const cacheDir = path.join(os.tmpdir(), 'toolkit-e2e-geoip', createHash('sha1').update(baseURL).digest('hex').slice(0, 12));
    mkdirSync(cacheDir, { recursive: true });

    // The meta file carries checksums, so a refreshed database on the server
    // replaces the cached copy instead of producing stale expectations.
    let checksums: Record<string, string | undefined> = {};
    try {
      const meta = await (await fetch(new URL('/data/geoip-meta.json', baseURL), { cache: 'no-store' })).json();
      checksums = Object.fromEntries(FILES.map(name => [name, meta?.databases?.[name]?.sha256]));
    } catch { /* no meta file: always download */ }

    const [countryDb, asnDb] = await Promise.all(FILES.map(name => download(baseURL, name, cacheDir, checksums[name])));
    const countries = new Reader<CountryResponse>(countryDb);
    const networks = new Reader<AsnResponse>(asnDb);
    const memo = new Map<string, GeoFacts>();

    return {
      lookup(ip: string): GeoFacts {
        const known = memo.get(ip);
        if (known) return known;
        let country: CountryResponse | null = null;
        let network: AsnResponse | null = null;
        try { country = countries.get(ip); } catch { /* not an address */ }
        try { network = networks.get(ip); } catch { /* not an address */ }
        const facts: GeoFacts = {
          country: country?.country?.names?.en || 'Unknown',
          countryCode: country?.country?.iso_code || '--',
          asn: network?.autonomous_system_number || 0,
          asnOrg: network?.autonomous_system_organization || 'Unknown',
        };
        memo.set(ip, facts);
        return facts;
      },
    };
  })();
  return cached;
}
