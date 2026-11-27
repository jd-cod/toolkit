/**
 * HTTP response inspection for the HTTP Headers & Redirect Checker.
 *
 * Follows redirects one hop at a time so every hop can be shown and every
 * destination is checked by the SSRF guard. Only response headers are read;
 * the body is dropped as soon as the headers arrive.
 */

import http from 'node:http';
import https from 'node:https';
import { assertAllowedHost, guardedLookup } from './net-guard.js';

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);
const USER_AGENT = 'SysAdminToolkit/1.0 (HTTP headers check)';

function clientError(message) {
  return Object.assign(new Error(message), { statusCode: 400 });
}

/** Accepts `example.com/path` as well as a full URL. Throws a 400 error when unusable. */
export function normalizeUrl(input) {
  let value = String(input || '').trim();
  if (!value || value.length > 2048) throw clientError('Enter a URL.');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = `https://${value}`;
  let url;
  try {
    url = new URL(value);
  } catch {
    throw clientError('That is not a valid URL.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw clientError('Only http and https URLs are supported.');
  if (url.username || url.password) throw clientError('URLs with a user name or password are not supported.');
  if (!url.hostname) throw clientError('That is not a valid URL.');
  return url;
}

function requestHop(url, { timeoutMs, lookup }) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const transport = url.protocol === 'https:' ? https : http;
    const req = transport.request(url, {
      method: 'GET',
      agent: false,
      lookup,
      rejectUnauthorized: false,
      timeout: timeoutMs,
      headers: { 'User-Agent': USER_AGENT, Accept: '*/*', 'Accept-Encoding': 'gzip, deflate, br' },
    }, res => {
      const socket = res.socket;
      const headers = [];
      for (let i = 0; i < res.rawHeaders.length && headers.length < 100; i += 2) {
        headers.push([res.rawHeaders[i], String(res.rawHeaders[i + 1]).slice(0, 4000)]);
      }
      let tlsInfo = null;
      if (url.protocol === 'https:' && typeof socket.getPeerCertificate === 'function') {
        const cert = socket.getPeerCertificate();
        tlsInfo = {
          protocol: socket.getProtocol() || '',
          trusted: socket.authorized === true,
          trust_error: socket.authorized ? '' : String(socket.authorizationError || ''),
          subject: cert?.subject?.CN || '',
          issuer: cert?.issuer?.O || cert?.issuer?.CN || '',
          valid_to: cert?.valid_to || '',
        };
      }
      const hop = {
        url: url.toString(),
        status: res.statusCode || 0,
        status_text: res.statusMessage || '',
        http_version: res.httpVersion,
        address: socket.remoteAddress || '',
        elapsed_ms: Date.now() - started,
        headers,
        tls: tlsInfo,
      };
      res.destroy();
      resolve(hop);
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('The server did not answer in time.'), { code: 'ETIMEDOUT' })));
    req.on('error', reject);
    req.end();
  });
}

export function headerValues(hop, name) {
  const wanted = name.toLowerCase();
  return hop.headers.filter(([key]) => key.toLowerCase() === wanted).map(([, value]) => value);
}

function header(hop, name) {
  return headerValues(hop, name)[0] ?? '';
}

/**
 * @returns {Promise<{ chain: object[], final: object | null, error: string, loop: boolean, truncated: boolean }>}
 */
export async function followChain(startUrl, { maxHops = 10, timeoutMs = 8000, lookup = guardedLookup, request = requestHop } = {}) {
  const chain = [];
  const seen = new Set();
  let url = startUrl;

  for (let hop = 0; hop <= maxHops; hop++) {
    if (seen.has(url.toString())) return { chain, final: null, error: 'Redirect loop: this URL was already visited.', loop: true, truncated: false };
    seen.add(url.toString());

    let result;
    try {
      assertAllowedHost(url.hostname);
      result = await request(url, { timeoutMs, lookup });
    } catch (err) {
      const blocked = err?.code === 'EBLOCKEDDESTINATION';
      chain.push({ url: url.toString(), status: 0, status_text: '', http_version: '', address: '', elapsed_ms: 0, headers: [], tls: null, error: blocked ? 'Destination is not a public address.' : (err?.message || 'Request failed.') });
      return { chain, final: null, error: chain[chain.length - 1].error, loop: false, truncated: false };
    }
    chain.push(result);

    const location = header(result, 'location');
    if (!REDIRECT_CODES.has(result.status) || !location) return { chain, final: result, error: '', loop: false, truncated: false };

    let next;
    try {
      next = new URL(location, url);
    } catch {
      return { chain, final: null, error: `Redirect to an invalid URL: ${location.slice(0, 200)}`, loop: false, truncated: false };
    }
    if (next.protocol !== 'http:' && next.protocol !== 'https:') {
      return { chain, final: result, error: `Redirect leaves http(s): ${next.protocol}`, loop: false, truncated: false };
    }
    result.redirect_to = next.toString();
    url = next;
  }
  return { chain, final: null, error: `Stopped after ${maxHops} redirects.`, loop: false, truncated: true };
}

const finding = (severity, title, detail = '') => ({ severity, title, detail });

function parseCookie(line) {
  const [pair, ...attributes] = line.split(';');
  const flags = attributes.map(attribute => attribute.trim().toLowerCase());
  return {
    name: pair.split('=')[0].trim().slice(0, 80),
    secure: flags.includes('secure'),
    httpOnly: flags.includes('httponly'),
    sameSite: flags.find(flag => flag.startsWith('samesite='))?.slice(9) || '',
  };
}

/** Security review of the final response plus the path that led to it. */
export function auditResponse({ chain, final }) {
  const findings = [];
  if (!final) return { findings, grade: '', score: 0, checks: [] };

  const isHttps = final.url.startsWith('https:');
  const checks = [];
  const check = (name, present, detail) => checks.push({ name, present, detail });

  if (!isHttps) {
    findings.push(finding('critical', 'The final page is served over plain HTTP', 'Traffic can be read and changed in transit. Serve the site over HTTPS and redirect HTTP to it.'));
  } else if (final.tls && !final.tls.trusted) {
    findings.push(finding('critical', 'The TLS certificate is not trusted', final.tls.trust_error || 'Browsers will show a warning.'));
  }
  for (let i = 1; i < chain.length; i++) {
    if (chain[i - 1].url.startsWith('https:') && chain[i].url.startsWith('http:')) {
      findings.push(finding('warning', 'A redirect downgrades from HTTPS to HTTP', `${chain[i - 1].url} redirects to ${chain[i].url}.`));
    }
  }
  const redirects = chain.length - 1;
  if (redirects >= 3) findings.push(finding('warning', `${redirects} redirects before the final page`, 'Each redirect adds a round trip. Point links and the first redirect straight at the final URL.'));
  if (chain.some(hop => hop.status === 302 || hop.status === 307) && chain[0].url.startsWith('http:') && isHttps) {
    findings.push(finding('info', 'HTTP to HTTPS uses a temporary redirect', 'Use 301 or 308 so browsers and search engines remember it.'));
  }

  const hsts = header(final, 'strict-transport-security');
  if (isHttps) {
    const maxAge = Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts)?.[1] ?? NaN);
    check('Strict-Transport-Security', Boolean(hsts) && maxAge > 0, hsts);
    if (!hsts) findings.push(finding('warning', 'No Strict-Transport-Security header', 'Without HSTS a visitor\'s first request can be downgraded to HTTP. Send "Strict-Transport-Security: max-age=31536000; includeSubDomains".'));
    else if (!(maxAge > 0)) findings.push(finding('warning', 'HSTS is switched off (max-age=0)', 'max-age=0 tells browsers to forget the HSTS policy.'));
    else if (maxAge < 15552000) findings.push(finding('info', `HSTS max-age is short (${maxAge} seconds)`, 'Six months (15552000) or more is recommended.'));
  }

  const csp = header(final, 'content-security-policy');
  const cspReportOnly = header(final, 'content-security-policy-report-only');
  check('Content-Security-Policy', Boolean(csp), csp || cspReportOnly);
  if (!csp) findings.push(finding(cspReportOnly ? 'info' : 'warning', cspReportOnly ? 'Content-Security-Policy is report-only' : 'No Content-Security-Policy header', cspReportOnly ? 'The policy is not enforced yet.' : 'A CSP limits where scripts and other content may load from and is the main defence against cross-site scripting.'));
  else {
    if (/'unsafe-inline'/.test(csp) && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(csp)) findings.push(finding('info', "CSP allows 'unsafe-inline'", 'Inline scripts are allowed, which weakens the protection against cross-site scripting.'));
    if (/'unsafe-eval'/.test(csp)) findings.push(finding('info', "CSP allows 'unsafe-eval'", ''));
  }

  const xfo = header(final, 'x-frame-options');
  const frameAncestors = /frame-ancestors/i.test(csp);
  check('X-Frame-Options', Boolean(xfo) || frameAncestors, xfo || (frameAncestors ? 'CSP frame-ancestors' : ''));
  if (!xfo && !frameAncestors) findings.push(finding('warning', 'No clickjacking protection', 'Send "X-Frame-Options: SAMEORIGIN" or a CSP frame-ancestors directive so other sites cannot embed this page in a frame.'));

  const nosniff = header(final, 'x-content-type-options');
  check('X-Content-Type-Options', nosniff.toLowerCase() === 'nosniff', nosniff);
  if (nosniff.toLowerCase() !== 'nosniff') findings.push(finding('warning', 'No X-Content-Type-Options: nosniff', 'Without it browsers may guess a content type and run a file as script.'));

  const referrer = header(final, 'referrer-policy');
  check('Referrer-Policy', Boolean(referrer), referrer);
  if (!referrer) findings.push(finding('info', 'No Referrer-Policy header', 'Browsers default to strict-origin-when-cross-origin. Set it explicitly to control what other sites learn about your URLs.'));
  else if (/unsafe-url|no-referrer-when-downgrade/i.test(referrer)) findings.push(finding('warning', `Referrer-Policy is ${referrer}`, 'Full URLs, including query strings, are sent to other sites.'));

  const permissions = header(final, 'permissions-policy');
  check('Permissions-Policy', Boolean(permissions), permissions);
  if (!permissions) findings.push(finding('info', 'No Permissions-Policy header', 'Optional. It switches off browser features such as camera and geolocation that the site does not use.'));

  for (const cookie of headerValues(final, 'set-cookie').slice(0, 20).map(parseCookie)) {
    const missing = [];
    if (isHttps && !cookie.secure) missing.push('Secure');
    if (!cookie.httpOnly) missing.push('HttpOnly');
    if (!cookie.sameSite) missing.push('SameSite');
    if (missing.length > 0) findings.push(finding(missing.includes('Secure') ? 'warning' : 'info', `Cookie "${cookie.name}" is missing ${missing.join(', ')}`, 'HttpOnly is not needed for cookies that scripts must read, but session cookies should have all three.'));
  }

  const acao = header(final, 'access-control-allow-origin');
  if (acao === '*' && header(final, 'access-control-allow-credentials').toLowerCase() === 'true') {
    findings.push(finding('warning', 'CORS allows any origin with credentials', 'Browsers reject this combination; the configuration is likely not what was intended.'));
  }

  const server = header(final, 'server');
  const poweredBy = header(final, 'x-powered-by');
  if (/\d+\.\d+/.test(server)) findings.push(finding('info', `Server header shows a version (${server.slice(0, 80)})`, 'Version numbers help attackers pick exploits. Hide them (nginx: server_tokens off; Apache: ServerTokens Prod).'));
  if (poweredBy) findings.push(finding('info', `X-Powered-By is sent (${poweredBy.slice(0, 80)})`, 'It reveals the application stack. Remove it.'));

  const score = checks.filter(item => item.present).length;
  const total = checks.length;
  const ratio = total ? score / total : 0;
  let grade = ratio === 1 ? 'A' : ratio >= 0.8 ? 'B' : ratio >= 0.6 ? 'C' : ratio >= 0.4 ? 'D' : ratio >= 0.2 ? 'E' : 'F';
  if (!isHttps) grade = 'F';
  if (findings.length === 0) findings.push(finding('ok', 'All checked security headers are present', ''));

  return { findings, grade, score, total, checks };
}

/** Notable non-security headers, for the summary panel. */
export function describeDelivery(final) {
  if (!final) return {};
  return {
    server: header(final, 'server'),
    content_type: header(final, 'content-type'),
    content_encoding: header(final, 'content-encoding'),
    cache_control: header(final, 'cache-control'),
    age: header(final, 'age'),
    etag: header(final, 'etag'),
    last_modified: header(final, 'last-modified'),
    via: header(final, 'via'),
    cache_status: header(final, 'cf-cache-status') || header(final, 'x-cache') || header(final, 'x-cache-status') || header(final, 'x-vercel-cache') || header(final, 'cache-status'),
    alt_svc: header(final, 'alt-svc'),
  };
}
