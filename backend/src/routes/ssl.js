/**
 * SSL Certificate Checker — Fastify (Node.js tls)
 *
 * POST /api/ssl
 * Body: { domain: string, port?: number }
 *
 * MAJOR REWRITE from CF Workers version:
 * - Replaced cloudflare:sockets raw TCP + manual DER X.509 parser
 *   with Node.js native tls.connect() which provides parsed certificates directly.
 * - Deleted ~300 lines of ASN.1 parsing code.
 * - Kept: resolveDNS (DoH), detectServer, computeGrade, checkHostname.
 */

import tls from 'node:tls';
import { createHash } from 'node:crypto';
import { domainToASCII } from 'node:url';
import { assertAllowedHost, guardedLookup, guardedRequest } from '../lib/net-guard.js';
import { str } from '../lib/input.js';

const HOSTNAME = /^[a-z0-9_]([a-z0-9._-]*[a-z0-9_])?$/;

export default async function sslRoutes(fastify, opts) {
  fastify.post('/ssl', async (request, reply) => {
    const body = request.body || {};
    let domain = str(body.domain).trim().toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '').replace(/:.*$/, '');
    // Internationalized names are checked in their ASCII (punycode) form.
    domain = domainToASCII(domain) || domain;
    const port = parseInt(body.port || '443', 10);

    if (!domain || domain.length > 253 || !HOSTNAME.test(domain)) return { error: 'Invalid domain.' };
    if (!Number.isInteger(port) || port < 1 || port > 65535) return { error: 'Invalid port.' };
    // This tool connects to whatever host the visitor names, so internal and
    // loopback destinations are refused (see lib/net-guard.js).
    try {
      assertAllowedHost(domain);
    } catch (e) {
      return { error: e.message, domain };
    }

    const start = Date.now();
    try {
      const [dnsResult, serverInfo, cert] = await Promise.all([
        resolveDNS(domain),
        detectServer(domain),
        checkCertificate(domain, port),
      ]);

      const ms = Date.now() - start;
      if (cert.error) return { error: cert.error, domain, response_time_ms: ms, dns: dnsResult, server_type: serverInfo };

      const days = cert.not_after ? Math.floor((new Date(cert.not_after).getTime() - Date.now()) / 86400000) : -1;
      const hostMatch = checkHostname(domain, cert.san_names || [], cert.subject || '');
      const isExpired = days < 0;
      const hasIntermediate = (cert.chain || []).length > 1;
      const isSelfSigned = (cert.chain || []).length === 1 && cert.subject === cert.issuer;

      return {
        domain, valid: !isExpired,
        subject: cert.subject, subject_org: cert.subject_org || '', subject_country: cert.subject_country || '',
        issuer: cert.issuer, issuer_org: cert.issuer_org || '', issuer_country: cert.issuer_country || '',
        serial_number: cert.serial_number,
        signature_algorithm: cert.signature_algorithm || '',
        key_type: cert.key_type || '', key_size: cert.key_size || '',
        not_before: cert.not_before, not_after: cert.not_after, days_remaining: days,
        san_names: cert.san_names, protocol: cert.protocol || 'TLS 1.2',
        fingerprint_sha256: cert.fingerprint, chain: cert.chain,
        grade: computeGrade(days, hasIntermediate, isSelfSigned, cert.signature_algorithm),
        response_time_ms: ms,
        dns: dnsResult, server_type: serverInfo,
        hostname_match: hostMatch, is_expired: isExpired,
        has_intermediate: hasIntermediate, is_self_signed: isSelfSigned,
        is_trusted: !isExpired && hasIntermediate && hostMatch && !isSelfSigned,
        security_headers: serverInfo.security_headers || {},
      };
    } catch (e) {
      return { error: e.message, domain, response_time_ms: Date.now() - start };
    }
  });
}

// ── TLS Certificate Check (Node.js native) ──────────────
function checkCertificate(domain, port = 443) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(port, domain, { servername: domain, rejectUnauthorized: false, lookup: guardedLookup }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const authorized = socket.authorized;

        if (!cert || !cert.subject) {
          socket.end();
          return resolve({ error: 'No certificate returned by server.' });
        }

        // Build chain by traversing cert.issuerCertificate
        const chain = [];
        let current = cert;
        const seen = new Set();
        while (current && !seen.has(current.fingerprint256)) {
          seen.add(current.fingerprint256);

          // Determine key type and size
          let keyType = '';
          let keySize = current.bits || '';
          if (current.asn1Curve) {
            keyType = 'EC';
            // Map common curves to bit sizes
            const curveMap = { 'prime256v1': 256, 'secp384r1': 384, 'secp521r1': 521 };
            keySize = curveMap[current.asn1Curve] || keySize;
          } else if (current.modulus) {
            keyType = 'RSA';
            keySize = current.modulus.length * 4; // hex chars * 4 = bits
          }

          chain.push({
            subject: current.subject?.CN || '',
            subject_org: current.subject?.O || '',
            subject_country: current.subject?.C || '',
            issuer: current.issuer?.CN || '',
            issuer_org: current.issuer?.O || '',
            issuer_country: current.issuer?.C || '',
            serial_number: current.serialNumber || '',
            not_before: current.valid_from || '',
            not_after: current.valid_to || '',
            san_names: current.subjectaltname
              ? current.subjectaltname.split(', ').map(s => s.replace('DNS:', '')).slice(0, 30)
              : [],
            signature_algorithm: '', // Not directly available from Node.js tls
            key_type: keyType,
            key_size: keySize,
            is_leaf: chain.length === 0,
          });

          current = current.issuerCertificate;
        }

        // Compute SHA-256 fingerprint
        const fingerprint = cert.fingerprint256 || '';

        socket.end();
        resolve({
          subject: cert.subject?.CN || domain,
          issuer: cert.issuer?.CN || '',
          subject_org: cert.subject?.O || '',
          issuer_org: cert.issuer?.O || '',
          subject_country: cert.subject?.C || '',
          issuer_country: cert.issuer?.C || '',
          serial_number: cert.serialNumber || '',
          signature_algorithm: '', // Not directly available
          key_type: chain[0]?.key_type || '',
          key_size: chain[0]?.key_size || '',
          not_before: cert.valid_from || '',
          not_after: cert.valid_to || '',
          san_names: cert.subjectaltname
            ? cert.subjectaltname.split(', ').map(s => s.replace('DNS:', '')).slice(0, 30)
            : [],
          fingerprint: fingerprint,
          protocol: protocol ? protocol.replace('v', ' ') : 'TLS 1.2',
          cipher: cipher?.standardName || cipher?.name || '',
          chain,
          authorized,
        });
      } catch (e) {
        socket.end();
        resolve({ error: `Certificate parse error: ${e.message}` });
      }
    });

    socket.setTimeout(10000, () => {
      socket.destroy();
      resolve({ error: 'Connection timeout (10s)' });
    });

    socket.on('error', (err) => {
      resolve({ error: `TLS connection error: ${err.message}` });
    });
  });
}

// ── DNS Resolution (DoH) ────────────────────────────────
async function resolveDNS(domain) {
  try {
    const resp = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`, {
      headers: { 'Accept': 'application/dns-json' },
    });
    const data = await resp.json();
    if (data.Answer?.length) {
      const ips = data.Answer.filter(a => a.type === 1).map(a => a.data);
      return { ip: ips[0] || null, all_ips: ips.slice(0, 5) };
    }
    return { ip: null, error: 'No A record found' };
  } catch (e) { return { ip: null, error: e.message }; }
}

// ── Server Type + Security Headers Detection ────────────
async function detectServer(domain) {
  try {
    const response = await guardedRequest(`https://${domain}`, {
      method: 'HEAD',
      headers: { 'User-Agent': 'Mozilla/5.0 SSL-Checker/2.0' },
      timeoutMs: 5000,
      maxBytes: 1024 * 1024,
    });
    const header = (name) => {
      const value = response.headers[name];
      return Array.isArray(value) ? value.join(', ') : (value || null);
    };
    const resp = { headers: { get: header } };

    const server = resp.headers.get('server') || '';
    const via = resp.headers.get('via') || '';
    const poweredBy = resp.headers.get('x-powered-by') || '';
    const sl = server.toLowerCase(), vl = via.toLowerCase();

    let type = server || 'Unknown';
    if (vl.includes('cloudfront'))     type = 'CloudFront';
    else if (sl.includes('cloudflare')) type = 'Cloudflare';
    else if (sl.includes('nginx'))      type = 'Nginx';
    else if (sl.includes('apache'))     type = 'Apache';
    else if (sl.includes('litespeed'))  type = 'LiteSpeed';
    else if (sl.includes('iis'))        type = 'Microsoft IIS';
    else if (sl.includes('openresty'))  type = 'OpenResty';
    else if (sl.includes('caddy'))      type = 'Caddy';
    else if (sl.includes('gws'))        type = 'Google Web Server';
    else if (vl.includes('varnish'))    type = 'Varnish';

    const securityHeaders = {};
    const hsts = resp.headers.get('strict-transport-security');
    if (hsts) securityHeaders.hsts = hsts;
    const csp = resp.headers.get('content-security-policy');
    if (csp) securityHeaders.csp = csp.length > 200 ? csp.substring(0, 200) + '…' : csp;
    const xfo = resp.headers.get('x-frame-options');
    if (xfo) securityHeaders.x_frame_options = xfo;
    const xcto = resp.headers.get('x-content-type-options');
    if (xcto) securityHeaders.x_content_type_options = xcto;
    const xxss = resp.headers.get('x-xss-protection');
    if (xxss) securityHeaders.x_xss_protection = xxss;
    const rp = resp.headers.get('referrer-policy');
    if (rp) securityHeaders.referrer_policy = rp;
    const pp = resp.headers.get('permissions-policy');
    if (pp) securityHeaders.permissions_policy = pp.length > 200 ? pp.substring(0, 200) + '…' : pp;

    return { server: type, raw_server: server, powered_by: poweredBy, security_headers: securityHeaders };
  } catch (e) { return { server: 'Unknown', error: e.message, security_headers: {} }; }
}

// ── Hostname Verification ───────────────────────────────
function checkHostname(domain, sans, subject) {
  const matches = d => {
    if (!d) return false;
    d = d.toLowerCase();
    if (d === domain) return true;
    if (d.startsWith('*.')) {
      const w = d.slice(2);
      if (domain === w || domain.endsWith('.' + w)) return true;
    }
    return false;
  };
  return sans.some(matches) || matches(subject);
}

// ── Security Grade ──────────────────────────────────────
function computeGrade(days, hasIntermediate, isSelfSigned, sigAlg) {
  if (days < 0 || isSelfSigned) return 'F';
  let score = 100;
  if (days < 7) score -= 40;
  else if (days <= 30) score -= 15;
  if (!hasIntermediate) score -= 20;
  if (sigAlg && sigAlg.toLowerCase().includes('sha1')) score -= 30;
  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 65) return 'B';
  if (score >= 50) return 'C';
  return 'D';
}
