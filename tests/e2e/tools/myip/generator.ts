import type { Rng } from '../_support/rng';
import type { MyIpPayload } from './oracle';

/**
 * Random GET /api/myip payloads in the backend's real shape
 * (backend/src/routes/myip.js): every key is always present, unknown values
 * are null, `headers` and `data_sources` are objects.
 */

interface Place {
  city: string; region: string; region_code: string; country: string; country_code: string;
  continent: string; continent_code: string; postal_code: string; timezone: string; utc_offset: string;
}

/** Real places, including time zones far from UTC and with quarter-hour offsets. */
const PLACES: Place[] = [
  { city: 'San Francisco', region: 'California', region_code: 'CA', country: 'United States', country_code: 'US', continent: 'North America', continent_code: 'NA', postal_code: '94107', timezone: 'America/Los_Angeles', utc_offset: '-08:00' },
  { city: 'Kathmandu', region: 'Bagmati Province', region_code: 'P3', country: 'Nepal', country_code: 'NP', continent: 'Asia', continent_code: 'AS', postal_code: '44600', timezone: 'Asia/Kathmandu', utc_offset: '+05:45' },
  { city: 'Kiritimati', region: 'Line Islands', region_code: 'L', country: 'Kiribati', country_code: 'KI', continent: 'Oceania', continent_code: 'OC', postal_code: '', timezone: 'Pacific/Kiritimati', utc_offset: '+14:00' },
  { city: 'Pago Pago', region: 'Eastern District', region_code: '', country: 'American Samoa', country_code: 'AS', continent: 'Oceania', continent_code: 'OC', postal_code: '96799', timezone: 'Pacific/Pago_Pago', utc_offset: '-11:00' },
  { city: "St. John's", region: 'Newfoundland and Labrador', region_code: 'NL', country: 'Canada', country_code: 'CA', continent: 'North America', continent_code: 'NA', postal_code: 'A1C', timezone: 'America/St_Johns', utc_offset: '-03:30' },
  { city: 'Waitangi', region: 'Chatham Islands', region_code: 'CIT', country: 'New Zealand', country_code: 'NZ', continent: 'Oceania', continent_code: 'OC', postal_code: '8942', timezone: 'Pacific/Chatham', utc_offset: '+13:45' },
  { city: 'Frankfurt am Main', region: 'Hesse', region_code: 'HE', country: 'Germany', country_code: 'DE', continent: 'Europe', continent_code: 'EU', postal_code: '60313', timezone: 'Europe/Berlin', utc_offset: '+01:00' },
  { city: 'São Paulo', region: 'São Paulo', region_code: 'SP', country: 'Brazil', country_code: 'BR', continent: 'South America', continent_code: 'SA', postal_code: '01000-000', timezone: 'America/Sao_Paulo', utc_offset: '-03:00' },
  { city: 'Reykjavík', region: 'Capital Region', region_code: '1', country: 'Iceland', country_code: 'IS', continent: 'Europe', continent_code: 'EU', postal_code: '101', timezone: 'Atlantic/Reykjavik', utc_offset: '+00:00' },
  { city: 'Llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch', region: 'Wales', region_code: 'WLS', country: 'United Kingdom', country_code: 'GB', continent: 'Europe', continent_code: 'EU', postal_code: 'LL61 5UJ', timezone: 'Europe/London', utc_offset: '+00:00' },
  { city: '東京', region: '東京都', region_code: '13', country: 'Japan', country_code: 'JP', continent: 'Asia', continent_code: 'AS', postal_code: '100-0001', timezone: 'Asia/Tokyo', utc_offset: '+09:00' },
];

const ORGANISATIONS = [
  'Example Hosting GmbH', 'Acme Cloud, Inc.', 'Telefónica Example S.A.', "O'Reilly Networks Ltd", 'AT&T Example Services',
  'Very Long Autonomous System Organisation Name For Layout Testing Of The Network Card Co., Ltd.', 'ExampleNet', '株式会社サンプル',
];
const NETWORK_TYPES = ['residential', 'hosting', 'business', 'mobile', 'education', 'government', 'unknown'];
const USAGE_TYPES = ['DCH', 'ISP', 'MOB', 'COM', 'EDU', 'GOV', 'ISP/MOB', 'CDN'];
const PROXY_TYPES = ['VPN', 'TOR', 'DCH', 'PUB', 'RES', 'WEB'];
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0',
  'curl/8.7.1',
];

export function publicIpv4(rng: Rng): string {
  const first = rng.pick([8, 23, 45, 62, 77, 81, 93, 104, 139, 151, 176, 185, 193, 212]);
  return [first, rng.int(0, 255), rng.int(0, 255), rng.int(1, 254)].join('.');
}

/** A global IPv6 address in the compressed form a server reports. */
export function publicIpv6(rng: Rng): string {
  const head = [rng.pick(['2a01', '2a02', '2600', '2607', '2400']), rng.int(1, 0xffff).toString(16), rng.int(1, 0xffff).toString(16), rng.int(1, 0xffff).toString(16)];
  return rng.bool(0.5)
    ? `${head.join(':')}::${rng.int(1, 0xffff).toString(16)}`
    : `${head.join(':')}:${Array.from({ length: 4 }, () => rng.int(1, 0xffff).toString(16)).join(':')}`;
}

/**
 * A coordinate with up to six decimals. The digits after the fourth decimal
 * never form an exact tie ("5", "50"), so rounding to four decimals has one answer.
 */
export function coordinate(rng: Rng, limit: number): number {
  const sign = rng.bool(0.5) ? -1 : 1;
  let whole = rng.int(0, limit - 1);
  const decimals = rng.pick([0, 1, 2, 4, 5, 6]);
  if (decimals === 0) return sign * whole;
  let fraction = rng.string(decimals, '0123456789');
  if (decimals > 4 && /^50*$/.test(fraction.slice(4))) fraction = `${fraction.slice(0, 4)}${decimals === 5 ? '7' : '73'}`;
  // Keep away from values that round to zero, where the sign of zero is a formatting question.
  if (whole === 0 && /^0{1,4}/.test(fraction.padEnd(4, '0').slice(0, 4)) && Number(fraction.slice(0, 4)) === 0) whole = 1;
  return Number(`${sign < 0 ? '-' : ''}${whole}.${fraction}`);
}

export interface PayloadOptions {
  version?: 'IPv4' | 'IPv6';
  /** Chance that each optional field is null. */
  missing?: number;
}

export function generatePayload(rng: Rng, options: PayloadOptions = {}): MyIpPayload {
  const version = options.version ?? rng.weighted(['IPv4', 'IPv6'] as const, [3, 1]);
  const missing = options.missing ?? 0.2;
  const keep = () => !rng.bool(missing);
  const place = rng.pick(PLACES);
  const registered = rng.bool(0.3) ? rng.pick(PLACES) : place;
  const org = rng.pick(ORGANISATIONS);
  const hasNetwork = keep();
  const asn = hasNetwork ? rng.weighted([rng.int(1, 65535), rng.int(131072, 401308)], [2, 1]) : null;
  const proxy = rng.bool(0.3) ? rng.pick(PROXY_TYPES) : null;
  const hasCountry = keep();
  const ip = version === 'IPv4' ? publicIpv4(rng) : publicIpv6(rng);
  const rdns = keep() ? `${rng.pick(['host', 'static', 'cust', 'srv'])}-${rng.int(1, 999)}.${rng.pick(['pool.example.net', 'example.com', 'dyn.isp.example.co.uk', 'example'])}` : null;
  const hasCoordinates = keep();
  return {
    ip,
    ip_version: version,
    city: hasCountry && keep() ? place.city : null,
    region: hasCountry && keep() ? place.region : null,
    region_code: hasCountry && place.region_code && keep() ? place.region_code : null,
    country: hasCountry ? place.country : null,
    country_code: hasCountry ? place.country_code : null,
    registered_country: keep() ? registered.country : null,
    registered_country_code: keep() ? registered.country_code : null,
    represented_country: null,
    represented_country_code: null,
    represented_country_type: null,
    continent: hasCountry && keep() ? place.continent : null,
    continent_code: hasCountry && keep() ? place.continent_code : null,
    postal_code: hasCountry && place.postal_code && keep() ? place.postal_code : null,
    accuracy_radius: keep() ? rng.pick([1, 5, 10, 20, 50, 100, 200, 500, 1000]) : null,
    latitude: hasCoordinates ? coordinate(rng, 90) || 12.5 : null,
    longitude: hasCoordinates ? coordinate(rng, 180) || -45.25 : null,
    metro_code: rng.bool(0.2) ? rng.int(500, 899) : null,
    timezone: hasCountry && keep() ? place.timezone : null,
    utc_offset: hasCountry && keep() ? place.utc_offset : null,
    isp: hasNetwork ? org : null,
    org: hasNetwork ? org : null,
    asn,
    asn_name: hasNetwork ? `AS${asn} ${org}` : null,
    domain: rng.bool(0.4) ? rng.pick(['example.com', 'example.net', 'isp.example']) : null,
    usage_type: rng.bool(0.4) ? rng.pick(USAGE_TYPES) : null,
    proxy_type: proxy,
    proxy_detected: Boolean(proxy) && rng.bool(0.8),
    reverse_dns: rdns,
    network_type: rng.pick(NETWORK_TYPES),
    ip2location_attribution_required: rng.bool(0.3),
    data_sources: { ...(hasCountry ? { country: 'maxmind', city: rng.pick(['maxmind', 'ip2location']) } : {}), ...(hasNetwork ? { asn: 'maxmind', org: 'maxmind' } : {}), connection: 'browser' },
    headers: {
      user_agent: rng.pick(USER_AGENTS),
      accept_language: rng.pick(['en-US,en;q=0.9', 'de-DE,de;q=0.9,en;q=0.8', '']),
      accept_encoding: rng.pick(['gzip, deflate, br, zstd', 'gzip', '']),
      referer: '',
      dnt: rng.pick(['', '', '1', '0']),
    },
    checked_at_utc: new Date(Date.UTC(2026, rng.int(0, 11), rng.int(1, 28), rng.int(0, 23), rng.int(0, 59), rng.int(0, 59), rng.int(0, 999))).toISOString(),
  };
}

/** The payload of a backend that knows nothing about the address (what the local backend returns for 127.0.0.1). */
export function emptyPayload(ip = '127.0.0.1'): MyIpPayload {
  return {
    ip, ip_version: ip.includes(':') ? 'IPv6' : 'IPv4',
    city: null, region: null, region_code: null, country: null, country_code: null,
    registered_country: null, registered_country_code: null,
    represented_country: null, represented_country_code: null, represented_country_type: null,
    continent: null, continent_code: null, postal_code: null, accuracy_radius: null,
    latitude: null, longitude: null, metro_code: null, timezone: null, utc_offset: null,
    isp: null, org: null, asn: null, asn_name: null, domain: null, usage_type: null,
    proxy_type: null, proxy_detected: false, reverse_dns: null, network_type: 'unknown',
    ip2location_attribution_required: false,
    data_sources: { connection: 'browser' },
    headers: { user_agent: '', accept_language: '', accept_encoding: '', referer: '', dnt: '' },
    checked_at_utc: '2026-11-27T11:07:26.089Z',
  };
}

/** A payload with every field filled, for tests that need each row on screen. */
export function fullPayload(rng: Rng, version: 'IPv4' | 'IPv6' = 'IPv4'): MyIpPayload {
  const payload = generatePayload(rng, { version, missing: 0 });
  return {
    ...payload,
    domain: 'example.com', usage_type: rng.pick(USAGE_TYPES), proxy_type: rng.pick(PROXY_TYPES), proxy_detected: true,
    headers: { ...payload.headers, accept_language: 'en-US,en;q=0.9', accept_encoding: 'gzip, deflate, br, zstd', dnt: '1' },
  };
}
