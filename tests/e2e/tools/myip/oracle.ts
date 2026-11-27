/**
 * Independent expectations for What Is My IP (/myip) and its shared view.
 *
 * Nothing here imports application code. The source of every value is the
 * GET /api/myip payload (contract tests: generated; real-backend tests:
 * captured) or the browser context the test configured.
 *
 * ── Definitions ──────────────────────────────────────────────────────────
 *
 * ADDRESS CARD. The IPv4 box shows the caller's IPv4 address, the IPv6 box
 * the IPv6 address; a box without an address says "Not Detected". The badge
 * under them says "Dual-Stack (IPv4 + IPv6)" when both exist, else
 * "IPv4 Only" or "IPv6 Only". A second badge names the estimated network type.
 *
 * FIELDS. Every field of the payload that the page shows is shown verbatim.
 * A field the backend does not know arrives as JSON null and is shown as an
 * em dash "—" (reverse DNS: "No PTR record found"). The words "null" and
 * "undefined" never appear.
 *   - Country / Registered Country: flag emoji (the two regional-indicator
 *     letters of the ISO code; a globe without a code), a space, the name.
 *   - State / Region: "Name (CODE)"; Continent: "Name (CODE)".
 *   - City: the city; when the country is known but the city is not, the page
 *     explains "City not available for this IP range".
 *   - Accuracy Radius: "<n> km".
 *   - Coordinates: latitude and longitude with four decimals, "lat, lon".
 *     0 is a valid latitude (equator) and a valid longitude (prime meridian).
 *   - ASN: "AS<number>", with a link to /asn?asn=<number>.
 *   - Proxy Type: the type, followed by " detected" when the backend flags it.
 *   - Estimated Network Type: the label of the backend's seven classes
 *     (backend/src/routes/myip.js, classifyNetworkType): residential →
 *     "Residential", hosting → "Hosting / Data Center", business →
 *     "Business / Corporate", mobile → "Mobile / Cellular", education →
 *     "Education", government → "Government", unknown → "Unknown".
 *   - HTTP Request Headers: the four header values the backend received; an
 *     empty header is "—", an absent DNT header "Not set".
 *
 * BROWSER & DEVICE. What the visitor's browser reports about itself:
 * browser name and version and operating system from the User-Agent string
 * (vendor documentation of the UA tokens: "Edg/" Edge, "OPR/" Opera,
 * "Firefox/" Firefox, "CriOS/" Chrome on iOS, "FxiOS/" Firefox on iOS,
 * "SamsungBrowser/" Samsung Internet, "EdgA/" Edge on Android, "Chrome/"
 * without any of those Chrome, "Version/x Safari/" Safari; "Windows NT 10.0"
 * Windows 10 or 11, "Mac OS X 10_15_7" macOS 10.15.7, "Android 14",
 * "iPhone OS 17_6_1" iOS 17.6.1, "X11; Linux" Linux), screen size
 * "W × H" from `screen`, `navigator.language`, Do Not Track, cookies,
 * the WebGL renderer and `navigator.platform`.
 *
 * SHARED VIEW (/s/<code>). A snapshot: every value it shows equals the value
 * the original page showed when the link was created.
 */

export interface MyIpPayload {
  ip: string;
  ip_version: string;
  city: string | null;
  region: string | null;
  region_code: string | null;
  country: string | null;
  country_code: string | null;
  registered_country: string | null;
  registered_country_code: string | null;
  represented_country: string | null;
  represented_country_code: string | null;
  represented_country_type: string | null;
  continent: string | null;
  continent_code: string | null;
  postal_code: string | null;
  accuracy_radius: number | null;
  latitude: number | null;
  longitude: number | null;
  metro_code: number | null;
  timezone: string | null;
  utc_offset: string | null;
  isp: string | null;
  org: string | null;
  asn: number | null;
  asn_name: string | null;
  domain: string | null;
  usage_type: string | null;
  proxy_type: string | null;
  proxy_detected: boolean;
  reverse_dns: string | null;
  network_type: string;
  ip2location_attribution_required?: boolean;
  data_sources: Record<string, string>;
  headers: { user_agent: string; accept_language: string; accept_encoding: string; referer: string; dnt: string };
  checked_at_utc: string;
}

export const DASH = '—';
export const GLOBE = '🌐';
const REGIONAL_INDICATORS = '🇦 🇧 🇨 🇩 🇪 🇫 🇬 🇭 🇮 🇯 🇰 🇱 🇲 🇳 🇴 🇵 🇶 🇷 🇸 🇹 🇺 🇻 🇼 🇽 🇾 🇿'.split(' ');

export function flagOf(code: string | null | undefined): string {
  if (!code || code.length !== 2) return GLOBE;
  const letters = [...code.toUpperCase()].map(ch => REGIONAL_INDICATORS['ABCDEFGHIJKLMNOPQRSTUVWXYZ'.indexOf(ch)]);
  return letters.every(Boolean) ? letters.join('') : GLOBE;
}

export const NETWORK_LABELS: Record<string, string> = {
  residential: 'Residential',
  hosting: 'Hosting / Data Center',
  business: 'Business / Corporate',
  mobile: 'Mobile / Cellular',
  education: 'Education',
  government: 'Government',
  unknown: 'Unknown',
};
export function networkLabel(type: string | null | undefined): string {
  return (type && NETWORK_LABELS[type]) || 'Unknown';
}

export function stackLabel(ipv4: string | null, ipv6: string | null): string {
  if (ipv4 && ipv6) return 'Dual-Stack (IPv4 + IPv6)';
  return ipv4 ? 'IPv4 Only' : 'IPv6 Only';
}

/**
 * A decimal number as text with exactly four decimals, rounded on its
 * decimal digits (integer arithmetic on the digits, no floating point).
 * The generator avoids exact ties, where binary floating point could differ.
 */
export function fourDecimals(value: number): string {
  const text = String(value);
  if (/e/i.test(text)) throw new Error(`fourDecimals: ${text} is outside the range this oracle formats`);
  const negative = text.startsWith('-');
  const [whole, fraction = ''] = text.replace('-', '').split('.');
  const digits = BigInt(whole + fraction.padEnd(5, '0').slice(0, 5));
  const rounded = (digits + 5n) / 10n;
  const padded = rounded.toString().padStart(5, '0');
  const out = `${padded.slice(0, -4)}.${padded.slice(-4)}`;
  return negative && rounded !== 0n ? `-${out}` : out;
}

export function coordinatesText(payload: MyIpPayload): string {
  if (payload.latitude === null || payload.longitude === null) return DASH;
  return `${fourDecimals(payload.latitude)}, ${fourDecimals(payload.longitude)}`;
}

function countryText(name: string | null, code: string | null): string {
  return name ? `${flagOf(code)} ${name}` : DASH;
}

function withCode(name: string | null, code: string | null): string {
  if (!name) return DASH;
  return code ? `${name} (${code})` : name;
}

export function expectedStats(p: MyIpPayload): Record<string, string> {
  return {
    Country: countryText(p.country, p.country_code),
    City: p.city || DASH,
    'ASN Org': p.isp || DASH,
    ASN: p.asn ? `AS${p.asn}` : DASH,
  };
}

export const NO_CITY = 'City not available for this IP range';

export function expectedGeolocation(p: MyIpPayload): Record<string, string> {
  return {
    City: p.city || (p.country ? NO_CITY : DASH),
    'State / Region': withCode(p.region, p.region_code),
    Country: countryText(p.country, p.country_code),
    'Registered Country': countryText(p.registered_country, p.registered_country_code),
    Continent: withCode(p.continent, p.continent_code),
    'Postal Code': p.postal_code || DASH,
    'Accuracy Radius': p.accuracy_radius === null ? DASH : `${p.accuracy_radius} km`,
    Timezone: p.timezone || DASH,
    'UTC Offset': p.utc_offset || DASH,
    Coordinates: coordinatesText(p),
  };
}

export function proxyText(p: MyIpPayload): string {
  return `${p.proxy_type}${p.proxy_detected ? ' detected' : ''}`;
}

/** Rows of the "GeoLite ASN & Network" card, in order. Optional rows exist only when the backend knows the value. */
export function expectedNetwork(p: MyIpPayload): [string, string][] {
  const rows: [string, string][] = [
    ['ASN Organization', p.isp || DASH],
    ['ASN', p.asn ? `AS${p.asn}` : DASH],
  ];
  if (p.domain) rows.push(['Domain', p.domain]);
  if (p.usage_type) rows.push(['Usage Type', p.usage_type]);
  if (p.proxy_type) rows.push(['Proxy Type', proxyText(p)]);
  rows.push(['Reverse DNS (PTR)', p.reverse_dns || 'No PTR record found']);
  rows.push(['Estimated Network Type', networkLabel(p.network_type)]);
  return rows;
}

export function expectedHeaders(p: MyIpPayload): Record<string, string> {
  return {
    'User-Agent': p.headers.user_agent || DASH,
    'Accept-Language': p.headers.accept_language || DASH,
    'Accept-Encoding': p.headers.accept_encoding || DASH,
    'DNT (Do Not Track)': p.headers.dnt || 'Not set',
  };
}

/** A whole-label suffix of `name` (the page links the PTR's parent domain to the DNS tool). */
export function isLabelSuffix(candidate: string, name: string): boolean {
  return candidate.length > 0 && (name === candidate || name.endsWith(`.${candidate}`));
}

// ─── Browser profiles ───────────────────────────────────────────────────

export interface BrowserProfile {
  name: string;
  userAgent: string;
  /** Browser family the label must name, and families it must not name. */
  browser: { family: RegExp; version: string; not: RegExp };
  os: { family: RegExp; version: string };
  platform: string;
  locale: string;
  timezoneId: string;
  viewport: { width: number; height: number };
  screen: { width: number; height: number };
  deviceScaleFactor: number;
  colorScheme: 'light' | 'dark';
}

export const BROWSER_PROFILES: BrowserProfile[] = [
  {
    name: 'Chrome on Windows',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36',
    browser: { family: /Chrome/, version: '131.0.6778.86', not: /Safari|Edge|Opera|Firefox/ },
    os: { family: /Windows/, version: '10' },
    platform: 'Win32', locale: 'de-DE', timezoneId: 'Europe/Berlin',
    viewport: { width: 1366, height: 768 }, screen: { width: 1920, height: 1080 }, deviceScaleFactor: 1, colorScheme: 'dark',
  },
  {
    name: 'Safari on macOS',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
    browser: { family: /Safari/, version: '17.6', not: /Chrome|Edge|Opera|Firefox/ },
    os: { family: /mac ?OS/i, version: '10.15.7' },
    platform: 'MacIntel', locale: 'fr-FR', timezoneId: 'Europe/Paris',
    viewport: { width: 1280, height: 800 }, screen: { width: 1512, height: 982 }, deviceScaleFactor: 2, colorScheme: 'light',
  },
  {
    name: 'Firefox on Linux',
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0',
    browser: { family: /Firefox/, version: '133.0', not: /Chrome|Safari|Edge|Opera/ },
    os: { family: /Linux/, version: '' },
    platform: 'Linux x86_64', locale: 'pt-BR', timezoneId: 'America/Sao_Paulo',
    viewport: { width: 1600, height: 900 }, screen: { width: 2560, height: 1440 }, deviceScaleFactor: 1, colorScheme: 'dark',
  },
  {
    name: 'Chrome on Android',
    userAgent: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.81 Mobile Safari/537.36',
    browser: { family: /Chrome/, version: '131.0.6778.81', not: /Safari|Edge|Opera|Firefox/ },
    os: { family: /Android/, version: '14' },
    platform: 'Linux armv81', locale: 'ja-JP', timezoneId: 'Asia/Tokyo',
    viewport: { width: 412, height: 915 }, screen: { width: 412, height: 915 }, deviceScaleFactor: 2.625, colorScheme: 'light',
  },
  {
    name: 'Safari on iPhone',
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1',
    browser: { family: /Safari/, version: '17.6', not: /Chrome|Edge|Opera|Firefox/ },
    os: { family: /iOS/, version: '17.6.1' },
    platform: 'iPhone', locale: 'en-GB', timezoneId: 'Europe/London',
    viewport: { width: 390, height: 844 }, screen: { width: 390, height: 844 }, deviceScaleFactor: 3, colorScheme: 'dark',
  },
  {
    name: 'Edge on Windows',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.70',
    browser: { family: /Edge/, version: '131.0.2903.70', not: /Chrome|Safari|Opera|Firefox/ },
    os: { family: /Windows/, version: '10' },
    platform: 'Win32', locale: 'es-ES', timezoneId: 'Europe/Madrid',
    viewport: { width: 1440, height: 900 }, screen: { width: 2560, height: 1600 }, deviceScaleFactor: 1.5, colorScheme: 'light',
  },
];

/** Browsers whose UA string contains another browser's token. The token that identifies them comes first. */
export const EMBEDDED_TOKEN_AGENTS: { name: string; userAgent: string; is: RegExp; isNot: RegExp }[] = [
  {
    name: 'Chrome on iPhone (CriOS)',
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1',
    is: /Chrome/, isNot: /^Safari/,
  },
  {
    name: 'Firefox on iPhone (FxiOS)',
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/133.0 Mobile/15E148 Safari/605.1.15',
    is: /Firefox/, isNot: /^Safari/,
  },
  {
    name: 'Samsung Internet on Android',
    userAgent: 'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36',
    is: /Samsung/, isNot: /^Google Chrome/,
  },
  {
    name: 'Edge on Android (EdgA)',
    userAgent: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 EdgA/131.0.2903.87',
    is: /Edge/, isNot: /^Google Chrome/,
  },
];

// ─── Dates ──────────────────────────────────────────────────────────────

const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const two = (n: number) => String(n).padStart(2, '0');

/** RFC 7231 date in UTC, e.g. "Fri, 27 Nov 2026 11:07:26 GMT" (how the shared view prints "Checked at"). */
export function httpDate(iso: string): string {
  const d = new Date(iso);
  return `${WEEKDAYS[d.getUTCDay()]}, ${two(d.getUTCDate())} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()} ${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())} GMT`;
}

/** "Nov 27, 2026" for an instant, in the given time zone (the shared view's "Created" and "Expires"). */
export function shortDate(iso: string, timeZone: string): string {
  return new Intl.DateTimeFormat('en-US', { timeZone, year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(iso));
}

// ─── Exports ────────────────────────────────────────────────────────────

/** Column → text for every payload field that has a value; fields that are null are listed in `empty`. */
export function expectedCsv(p: MyIpPayload, ipv4: string | null, ipv6: string | null): { cells: Record<string, string>; empty: string[] } {
  const cells: Record<string, string> = {
    ipv4: ipv4 ?? 'Not Detected',
    ipv6: ipv6 ?? 'Not Detected',
    ip_stack: stackLabel(ipv4, ipv6),
  };
  const empty: string[] = [];
  const walk = (value: unknown, path: string) => {
    if (value === null || value === undefined) empty.push(path);
    else if (typeof value === 'object') for (const [key, inner] of Object.entries(value)) walk(inner, path ? `${path} ${key}` : key);
    else cells[path] = String(value);
  };
  walk(p, '');
  return { cells, empty };
}

export function fileStem(ipv4: string | null, ip: string): string {
  return `my-ip-report-${(ipv4 || ip).split('').map(ch => (ch === '.' || ch === ':' ? '-' : ch)).join('')}`;
}

/** Rows the downloaded HTML report must contain, per section, derived from the payload. */
export function expectedReport(p: MyIpPayload): Record<string, [string, string | string[]][]> {
  const geo = expectedGeolocation(p);
  const network: [string, string | string[]][] = [
    ['ASN Organization', p.isp || DASH],
    ['ASN', p.asn ? `AS${p.asn}` : DASH],
  ];
  if (p.domain) network.push(['Domain', p.domain]);
  if (p.usage_type) network.push(['Usage Type', p.usage_type]);
  if (p.proxy_type) network.push(['Proxy Type', proxyText(p)]);
  network.push(['Reverse DNS', p.reverse_dns || DASH], ['Estimated Network Type', networkLabel(p.network_type)]);
  return {
    Geolocation: [
      ['City', geo.City],
      ['Region', p.region || DASH],
      // Without a country the report may show the globe alone or a dash.
      ['Country', p.country ? geo.Country : [DASH, GLOBE]],
      ['Registered Country', geo['Registered Country']],
      ['Continent', p.continent ? `${p.continent} (${p.continent_code || DASH})` : DASH],
      ['Postal Code', geo['Postal Code']],
      ['Accuracy Radius', geo['Accuracy Radius']],
      ['Timezone', geo.Timezone],
      ['UTC Offset', geo['UTC Offset']],
    ],
    Network: network,
    'HTTP Request Headers': [
      ['User-Agent', p.headers.user_agent || DASH],
      ['Accept-Language', p.headers.accept_language || DASH],
      ['Accept-Encoding', p.headers.accept_encoding || DASH],
      ['DNT', p.headers.dnt || 'Not set'],
    ],
  };
}
