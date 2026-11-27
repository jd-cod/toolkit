'use client';

import { versioned } from './asset-version';

export interface GeoIPLookupResult {
  asn?: number;
  asn_org?: string;
}

export interface GeoIPCountryResult {
  country?: string;
  country_code?: string;
}

export interface GeoIPFullResult extends GeoIPLookupResult, GeoIPCountryResult {}

export interface GeoIPRuntime {
  init: (onProgress?: (pct: number, msg: string) => void) => Promise<unknown>;
  isReady: () => boolean;
  lookupASN: (ip: string) => GeoIPLookupResult | null;
  lookupCountry: (ip: string) => GeoIPCountryResult | null;
  lookupIP: (ip: string) => GeoIPFullResult | null;
  clearCache?: () => void;
}

declare global {
  interface Window {
    GeoIP?: GeoIPRuntime;
  }
}

let geoIpScriptPromise: Promise<GeoIPRuntime | null> | null = null;
let geoIpReadyPromise: Promise<GeoIPRuntime | null> | null = null;

function injectGeoIpScript() {
  return new Promise<GeoIPRuntime | null>((resolve) => {
    if (typeof window === 'undefined') {
      resolve(null);
      return;
    }

    if (window.GeoIP) {
      resolve(window.GeoIP);
      return;
    }

    const existing = document.querySelector<HTMLScriptElement>('script[data-geoip-script="true"]');
    if (existing) {
      existing.addEventListener('load', () => resolve(window.GeoIP || null), { once: true });
      existing.addEventListener('error', () => resolve(null), { once: true });
      return;
    }

    const script = document.createElement('script');
    script.src = versioned('/js/geoip.js');
    script.async = true;
    script.dataset.geoipScript = 'true';
    script.onload = () => resolve(window.GeoIP || null);
    script.onerror = () => resolve(null);
    document.body.appendChild(script);
  });
}

export async function loadGeoIP() {
  if (typeof window === 'undefined') return null;
  if (window.GeoIP) return window.GeoIP;

  if (!geoIpScriptPromise) {
    geoIpScriptPromise = injectGeoIpScript();
  }

  return geoIpScriptPromise;
}

export async function ensureGeoIPReady() {
  const geoIp = await loadGeoIP();
  if (!geoIp) return null;
  if (geoIp.isReady()) return geoIp;

  if (!geoIpReadyPromise) {
    // init() resolves even when a database could not be loaded; lookups then
    // answer "Unknown". A later call tries the missing database again.
    geoIpReadyPromise = geoIp.init().then(() => geoIp).catch(() => null).finally(() => {
      if (!geoIp.isReady()) geoIpReadyPromise = null;
    });
  }

  return geoIpReadyPromise;
}
