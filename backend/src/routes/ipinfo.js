/**
 * IP Intelligence Route — Fastify
 *
 * POST /api/ipinfo
 * Body: { ips: string[] } — up to 100 IPs
 *
 * Migrated from Hono/CF Workers. Only syntax changes.
 * Reverse DNS still uses Cloudflare DoH (works in Node.js via fetch).
 */

export default async function ipinfoRoutes(fastify, opts) {
  fastify.post('/ipinfo', async (request, reply) => {
    const body = request.body || {};
    const rawIPs = Array.isArray(body.ips) ? body.ips : [];
    if (rawIPs.length === 0) return reply.code(400).send({ error: 'No IPs provided.' });
    if (rawIPs.length > 100) return reply.code(400).send({ error: 'Maximum 100 IPs per request.' });

    const BATCH = 10;
    const allResults = [];

    for (let i = 0; i < rawIPs.length; i += BATCH) {
      const batch = rawIPs.slice(i, i + BATCH);
      const batchResults = await Promise.all(
        batch.map(async (rawIP) => {
          const ip = (rawIP || '').trim();
          const version = detectIPVersion(ip);
          const isValid = version === 4 ? isValidIPv4(ip) : version === 6 ? isValidIPv6(ip) : false;

          if (!isValid) {
            return { ip, is_valid: false, is_private: false, ip_version: '', reverse_dns: '', risk_level: 'unknown', risk_reasons: ['Invalid IP address format'] };
          }

          const privateIP = isPrivate(ip, version);
          if (privateIP) {
            return { ip, is_valid: true, is_private: true, ip_version: `IPv${version}`, reverse_dns: '', risk_level: 'safe', risk_reasons: ['Private/reserved IP address'] };
          }

          const rDNS = await reverseDNS(ip, version);
          const info = { ip, is_valid: true, is_private: false, ip_version: `IPv${version}`, reverse_dns: rDNS, asn_available: null };
          const risk = assessRisk(info);

          return { ip, is_valid: true, is_private: false, ip_version: `IPv${version}`, reverse_dns: rDNS, risk_level: risk.level, risk_reasons: risk.reasons };
        })
      );
      allResults.push(...batchResults);
    }

    return { results: allResults };
  });
}

function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 0) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 192 && b === 0 && parts[2] === 0) return true;
  if (a === 192 && b === 0 && parts[2] === 2) return true;
  if (a === 198 && b === 51 && parts[2] === 100) return true;
  if (a === 203 && b === 0 && parts[2] === 113) return true;
  if (a >= 224) return true;
  return false;
}

function isPrivateIPv6(ip) {
  const lower = ip.toLowerCase();
  return lower === '::1' || lower === '::' || lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('::ffff:');
}

function detectIPVersion(ip) {
  if (ip.includes(':')) return 6;
  if (ip.includes('.')) return 4;
  return 0;
}

function isValidIPv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => { const n = parseInt(p, 10); return !isNaN(n) && n >= 0 && n <= 255 && p === String(n); });
}

function isValidIPv6(ip) {
  return /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':');
}

function isPrivate(ip, version) {
  if (version === 4) return isPrivateIPv4(ip);
  if (version === 6) return isPrivateIPv6(ip);
  return true;
}

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
    const resp = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(query)}&type=PTR`, { headers: { 'Accept': 'application/dns-json' } });
    if (!resp.ok) return '';
    const json = await resp.json();
    const answers = json.Answer || [];
    if (answers.length === 0) return '';
    return (answers[0].data || '').replace(/\.$/, '');
  } catch { return ''; }
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
  } catch { return null; }
}

function assessRisk(info) {
  const reasons = [];
  let score = 0;
  if (!info.reverse_dns) { reasons.push('No reverse DNS record'); score += 1; }
  if (info.asn_available === false) { reasons.push('Unknown ASN organization'); score += 1; }
  if (info.reverse_dns && /static|broad|dhcp|pool|dyn|ppp|client|cust/i.test(info.reverse_dns)) {
    reasons.push('Reverse DNS suggests dynamic/consumer IP'); score += 1;
  }
  if (score >= 3) return { level: 'high', reasons };
  if (score >= 1) return { level: 'medium', reasons };
  return { level: 'low', reasons };
}
