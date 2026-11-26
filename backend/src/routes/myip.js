/**
 * What Is My IP — Fastify Route
 *
 * GET /api/myip — returns the caller's public IP with geolocation,
 *   ASN, reverse DNS, network type classification, and request headers.
 *
 * Uses server-side MaxMind MMDB readers (City + ASN) so the heavy
 * City database is never pushed to the browser.
 */

import { lookupCity, lookupASN } from '../lib/geoip-city.js';
import { lookupIP2Location } from '../lib/ip2location-data.js';
import { isIP } from 'node:net';

export default async function myipRoutes(fastify, opts) {
  fastify.get('/myip', async (request, reply) => {
    const ip = extractClientIP(request);
    const ipVersion = detectIPVersion(ip);

    // Host-specific stack enforcement for dual-stack self-hosted detection
    const isExplicitQuery = Boolean(request.query?.ip);
    const reqHost = (request.headers['x-forwarded-host'] || request.headers.host || request.hostname || '').toLowerCase();
    if (!isExplicitQuery) {
      if (reqHost.includes('ipv6') && ipVersion !== 6) {
        return reply.status(200).send({ ip: null, ip_version: null, error: 'IPv6 not detected on this connection' });
      }
      if (reqHost.includes('ipv4') && ipVersion !== 4) {
        return reply.status(200).send({ ip: null, ip_version: null, error: 'IPv4 not detected on this connection' });
      }
    }

    // GeoIP lookups (server-side MMDB)
    const cityInfo = lookupCity(ip);
    const asnInfo = lookupASN(ip);
    const ip2LocationInfo = await lookupIP2Location(fastify.mysql, ip);
    const mergedGeo = mergeGeolocation(cityInfo, ip2LocationInfo?.db11);
    const mergedNetwork = mergeNetwork(asnInfo, ip2LocationInfo);

    // Reverse DNS via Cloudflare DoH
    const reverseDns = await reverseDNS(ip, ipVersion === 6 ? 6 : 4);

    // Network type classification
    const networkType = classifyNetworkType(reverseDns, mergedNetwork.org || '', mergedNetwork.usage_type || '', mergedNetwork.proxy_type || '');

    // Timezone UTC offset
    const utcOffset = mergedGeo.timezone ? getTimezoneOffset(mergedGeo.timezone) : '';

    // Extract useful request headers
    const headers = {
      user_agent: request.headers['user-agent'] || '',
      accept_language: request.headers['accept-language'] || '',
      accept_encoding: request.headers['accept-encoding'] || '',
      referer: request.headers['referer'] || '',
      dnt: request.headers['dnt'] || '',
    };

    return {
      ip,
      ip_version: ipVersion === 6 ? 'IPv6' : 'IPv4',

      // Geolocation (from City DB)
      city: mergedGeo.city || null,
      region: mergedGeo.region || null,
      region_code: mergedGeo.region_code || null,
      country: mergedGeo.country || null,
      country_code: mergedGeo.country_code || null,
      registered_country: mergedGeo.registered_country || null,
      registered_country_code: mergedGeo.registered_country_code || null,
      represented_country: mergedGeo.represented_country || null,
      represented_country_code: mergedGeo.represented_country_code || null,
      represented_country_type: mergedGeo.represented_country_type || null,
      continent: mergedGeo.continent || null,
      continent_code: mergedGeo.continent_code || null,
      postal_code: mergedGeo.postal_code || null,
      accuracy_radius: mergedGeo.accuracy_radius || null,
      latitude: mergedGeo.latitude || null,
      longitude: mergedGeo.longitude || null,
      metro_code: mergedGeo.metro_code || null,
      timezone: mergedGeo.timezone || null,
      utc_offset: utcOffset || null,

      // Network
      isp: mergedNetwork.org || null,
      org: mergedNetwork.org || null,
      asn: mergedNetwork.asn || null,
      asn_name: mergedNetwork.asn && mergedNetwork.org ? `AS${mergedNetwork.asn} ${mergedNetwork.org}` : null,
      domain: mergedNetwork.domain || null,
      usage_type: mergedNetwork.usage_type || null,
      proxy_type: mergedNetwork.proxy_type || null,
      proxy_detected: Boolean(mergedNetwork.proxy_type),
      reverse_dns: reverseDns || null,
      network_type: networkType,
      ip2location_attribution_required: Boolean(ip2LocationInfo?.enabled || ip2LocationInfo?.contributed),
      data_sources: buildDataSources(cityInfo, asnInfo, ip2LocationInfo, mergedNetwork),

      // Request headers
      headers,

      // Timestamp
      checked_at_utc: new Date().toISOString(),
    };
  });
}

// ─── Helpers ───

function hasValue(value) {
  return value !== undefined && value !== null && value !== '' && value !== '-';
}

function pickValue(primary, fallback) {
  return hasValue(primary) ? primary : fallback;
}

function mergeGeolocation(maxMindInfo, ip2LocationGeo) {
  return {
    city: pickValue(maxMindInfo?.city, ip2LocationGeo?.city || ''),
    region: pickValue(maxMindInfo?.region, ip2LocationGeo?.region || ''),
    region_code: maxMindInfo?.region_code || '',
    country: pickValue(maxMindInfo?.country, ip2LocationGeo?.country || ''),
    country_code: pickValue(maxMindInfo?.country_code, ip2LocationGeo?.country_code || ''),
    registered_country: maxMindInfo?.registered_country || '',
    registered_country_code: maxMindInfo?.registered_country_code || '',
    represented_country: maxMindInfo?.represented_country || '',
    represented_country_code: maxMindInfo?.represented_country_code || '',
    represented_country_type: maxMindInfo?.represented_country_type || '',
    continent: maxMindInfo?.continent || '',
    continent_code: maxMindInfo?.continent_code || '',
    postal_code: pickValue(maxMindInfo?.postal_code, ip2LocationGeo?.postal_code || ''),
    accuracy_radius: maxMindInfo?.accuracy_radius || null,
    latitude: hasValue(maxMindInfo?.latitude) ? maxMindInfo.latitude : ip2LocationGeo?.latitude || null,
    longitude: hasValue(maxMindInfo?.longitude) ? maxMindInfo.longitude : ip2LocationGeo?.longitude || null,
    metro_code: maxMindInfo?.metro_code || null,
    timezone: pickValue(maxMindInfo?.timezone, ip2LocationGeo?.timezone || ''),
  };
}

function mergeNetwork(maxMindAsn, ip2LocationInfo) {
  const px7 = ip2LocationInfo?.px7 || {};
  const liteAsn = ip2LocationInfo?.asn || {};
  const fallbackAsn = liteAsn.asn || px7.asn || null;
  const fallbackOrg = liteAsn.as_name || px7.as_name || px7.isp || '';
  const parsedFallbackAsn = fallbackAsn && Number.isFinite(Number(fallbackAsn)) ? Number(fallbackAsn) : null;

  return {
    asn: maxMindAsn?.asn || parsedFallbackAsn,
    org: pickValue(maxMindAsn?.org, fallbackOrg),
    domain: px7.domain || '',
    usage_type: px7.usage_type || '',
    proxy_type: px7.proxy_type || '',
  };
}

function sourceFor(maxMindValue, ip2LocationValue, ip2Source = 'ip2location') {
  if (hasValue(maxMindValue)) return 'maxmind';
  if (hasValue(ip2LocationValue)) return ip2Source;
  return null;
}

function buildDataSources(maxMindGeo, maxMindAsn, ip2LocationInfo, mergedNetwork) {
  const db11 = ip2LocationInfo?.db11 || {};
  const px7 = ip2LocationInfo?.px7 || {};
  const liteAsn = ip2LocationInfo?.asn || {};

  const sources = {
    city: sourceFor(maxMindGeo?.city, db11.city),
    region: sourceFor(maxMindGeo?.region, db11.region),
    country: sourceFor(maxMindGeo?.country, db11.country),
    country_code: sourceFor(maxMindGeo?.country_code, db11.country_code),
    postal_code: sourceFor(maxMindGeo?.postal_code, db11.postal_code),
    latitude: sourceFor(maxMindGeo?.latitude, db11.latitude),
    longitude: sourceFor(maxMindGeo?.longitude, db11.longitude),
    timezone: sourceFor(maxMindGeo?.timezone, db11.timezone),
    asn: sourceFor(maxMindAsn?.asn, liteAsn.asn || px7.asn, liteAsn.asn ? 'ip2location' : 'ip2proxy'),
    org: sourceFor(maxMindAsn?.org, liteAsn.as_name || px7.as_name || px7.isp, liteAsn.as_name ? 'ip2location' : 'ip2proxy'),
    domain: hasValue(mergedNetwork.domain) ? 'ip2proxy' : null,
    usage_type: hasValue(mergedNetwork.usage_type) ? 'ip2proxy' : null,
    proxy_type: hasValue(mergedNetwork.proxy_type) ? 'ip2proxy' : null,
    connection: 'browser',
  };

  return Object.fromEntries(Object.entries(sources).filter(([, value]) => value));
}

/**
 * Extract the real client IP from proxy headers or Fastify's request.ip
 */
function extractClientIP(request) {
  const queryIP = normalizeIP(request.query?.ip);
  if (queryIP) return queryIP;

  const forwarded = request.headers['x-forwarded-for'];
  if (forwarded) {
    const first = normalizeIP(forwarded.split(',')[0]);
    if (first) return first;
  }
  const realIP = request.headers['x-real-ip'];
  const normalizedRealIP = normalizeIP(realIP);
  if (normalizedRealIP) return normalizedRealIP;
  return normalizeIP(request.ip) || '127.0.0.1';
}

function normalizeIP(value) {
  if (typeof value !== 'string') return '';
  const ip = value.trim().replace(/^\[|\]$/g, '');
  if (!ip) return '';
  if (ip.startsWith('::ffff:')) {
    const mapped = ip.slice(7);
    return isIP(mapped) ? mapped : '';
  }
  return isIP(ip) ? ip : '';
}

/**
 * Detect if the IP is v4 or v6
 */
function detectIPVersion(ip) {
  if (ip.includes(':')) return 6;
  if (ip.includes('.')) return 4;
  return 0;
}

/**
 * Reverse DNS (PTR) lookup via Cloudflare DoH — same pattern as ipinfo.js
 */
async function reverseDNS(ip, version) {
  try {
    let query;
    if (version === 4) {
      query = ip.split('.').reverse().join('.') + '.in-addr.arpa';
    } else {
      const expanded = expandIPv6(ip);
      if (!expanded) return '';
      query = expanded.replace(/:/g, '').split('').reverse().join('.') + '.ip6.arpa';
    }

    const resp = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(query)}&type=PTR`,
      {
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(2000),
      }
    );

    if (!resp.ok) return '';
    const json = await resp.json();
    const answers = json.Answer || [];
    if (answers.length === 0) return '';
    return (answers[0].data || '').replace(/\.$/, '');
  } catch {
    return '';
  }
}

function expandIPv6(ip) {
  try {
    const parts = ip.split('::');
    if (parts.length > 2) return null;
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];
    const fill = 8 - left.length - right.length;
    if (fill < 0) return null;
    const groups = [...left, ...Array(fill).fill('0'), ...right];
    return groups.map(g => g.padStart(4, '0')).join(':');
  } catch {
    return null;
  }
}

/**
 * Classify the network type based on reverse DNS patterns and ASN org name.
 * Returns: 'residential' | 'hosting' | 'business' | 'mobile' | 'education' | 'government' | 'unknown'
 */
function classifyNetworkType(rDNS, orgName, usageType = '', proxyType = '') {
  const combined = `${rDNS} ${orgName} ${usageType} ${proxyType}`.toLowerCase();

  // Hosting / Data Center
  if (/cloud|hosting|server|vps|dedicated|hetzner|digitalocean|linode|vultr|ovh|aws|amazon|google cloud|azure|microsoft corp|oracle|rackspace|contabo|scaleway/i.test(combined)) {
    return 'hosting';
  }

  // Mobile / Cellular
  if (/mobile|cellular|cell|lte|gprs|umts|4g|5g|airtel|jio|vodafone|t-mobile|verizon wireless|at&t wireless|reliance|mtnl/i.test(combined)) {
    return 'mobile';
  }

  // Education
  if (/university|college|edu\.|\.ac\.|academic|school|campus|research/i.test(combined)) {
    return 'education';
  }

  // Government
  if (/\.gov\.|government|nic\.in|national informatics/i.test(combined)) {
    return 'government';
  }

  // Business / Corporate (often has "business" in org name or rDNS patterns)
  if (/enterprise|corporate|business|office|ltd|pvt|inc\.|corp\.|limited/i.test(combined)) {
    return 'business';
  }

  // Residential ISP patterns (dynamic/static, cable, dsl, broadband, etc.)
  if (/static|dynamic|dsl|cable|broadband|fiber|fibre|bb\.|adsl|vdsl|ftth|bsnl|mtnl|airtel|jio|liberty|tata|hathway|act fibernet|excitel|tikona|isp|residential|pool|ppp|dhcp|home/i.test(combined)) {
    return 'residential';
  }

  // If we have rDNS or org info but couldn't classify, default to residential (most common)
  if (rDNS || orgName) {
    return 'residential';
  }

  return 'unknown';
}

/**
 * Get the UTC offset string for a timezone like "Asia/Kolkata" → "+05:30"
 */
function getTimezoneOffset(timezone) {
  try {
    const now = new Date();
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      timeZoneName: 'shortOffset',
    });
    const parts = formatter.formatToParts(now);
    const tzPart = parts.find(p => p.type === 'timeZoneName');
    if (!tzPart) return '';

    const val = tzPart.value; // e.g. "GMT+5:30" or "UTC"
    if (val === 'GMT' || val === 'UTC') return '+00:00';

    // Parse "GMT+5:30" → "+05:30"
    const match = val.match(/GMT([+-])(\d{1,2})(?::(\d{2}))?/);
    if (match) {
      const sign = match[1];
      const hours = match[2].padStart(2, '0');
      const minutes = (match[3] || '00').padStart(2, '0');
      return `${sign}${hours}:${minutes}`;
    }
    return val;
  } catch {
    return '';
  }
}
