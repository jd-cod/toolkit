/**
 * Email tools — Fastify
 *
 * POST /api/email/auth       { domain, selectors? }  MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI
 * POST /api/email/blacklist  { target }              DNSBL check for an IP or a domain's servers
 * POST /api/email/smtp       { target, port?, direct? }  SMTP banner / EHLO / STARTTLS test
 *
 * See docs/TOOLS_ROADMAP.md ("Server-side tools and abuse") for the limits
 * these routes work under.
 */

import net from 'node:net';
import { createDnsClient, mapLimit, normalizeHostname } from '../lib/dns-client.js';
import { analyzeEmailAuth, isSelector } from '../lib/email-auth.js';
import { createDnsblChecker } from '../lib/dnsbl.js';
import { probeSmtp, smtpFindings, SMTP_PORTS } from '../lib/smtp-probe.js';
import { guardedRequest, isPublicAddress, allowPrivateTargets } from '../lib/net-guard.js';

const MAX_BLACKLIST_ADDRESSES = 6;
const MAX_SMTP_SERVERS = 2;

function badRequest(reply, message) {
  return reply.code(400).send({ error: message });
}

async function fetchMtaStsPolicy(url) {
  const res = await guardedRequest(url, { timeoutMs: 5000, maxBytes: 64 * 1024, maxRedirects: 0 });
  if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
  return res.body.toString('utf8');
}

export default async function emailToolRoutes(fastify, opts) {
  const dns = opts.dns || createDnsClient();
  const dnsbl = opts.dnsbl || createDnsblChecker({ dns });
  const smtpProbe = opts.probeSmtp || probeSmtp;
  const fetchPolicy = opts.fetchPolicy || fetchMtaStsPolicy;

  fastify.post('/email/auth', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (request, reply) => {
    const body = request.body || {};
    const domain = normalizeHostname(body.domain);
    if (!domain) return badRequest(reply, 'Enter a valid domain name, for example example.com.');

    const selectors = Array.isArray(body.selectors) ? body.selectors : String(body.selectors || '').split(/[\s,]+/);
    const cleanSelectors = selectors.map(value => String(value).trim().toLowerCase()).filter(Boolean);
    const invalid = cleanSelectors.find(value => !isSelector(value));
    if (invalid) return badRequest(reply, `"${invalid.slice(0, 40)}" is not a valid DKIM selector.`);

    return analyzeEmailAuth(domain, { dns, selectors: cleanSelectors, fetchPolicy });
  });

  fastify.post('/email/blacklist', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (request, reply) => {
    const raw = String((request.body || {}).target || '').trim().replace(/^\[|\]$/g, '');
    if (!raw) return badRequest(reply, 'Enter an IP address or a domain name.');

    const addresses = [];
    let domain = '';
    if (net.isIP(raw)) {
      if (!isPublicAddress(raw) && !allowPrivateTargets()) return badRequest(reply, 'Private and reserved addresses are not on any blacklist. Enter a public IP address.');
      addresses.push({ ip: raw, role: 'Address', host: '' });
    } else {
      domain = normalizeHostname(raw);
      if (!domain) return badRequest(reply, 'Enter a valid IP address or domain name.');

      const [a, mx] = await Promise.all([dns.a(domain), dns.mx(domain)]);
      const mxHosts = [...mx.records]
        .sort((x, y) => x.priority - y.priority)
        .map(record => record.exchange.toLowerCase().replace(/\.$/, ''))
        .filter(host => host && host !== '.')
        .slice(0, 4);
      const mxAddresses = await mapLimit(mxHosts, 4, async host => ({ host, records: (await dns.a(host)).records }));
      for (const { host, records } of mxAddresses) for (const ip of records.slice(0, 2)) addresses.push({ ip, role: 'Mail server', host });
      for (const ip of a.records.slice(0, 2)) addresses.push({ ip, role: 'Domain address', host: domain });
    }

    const unique = [];
    for (const entry of addresses) {
      if (!isPublicAddress(entry.ip) && !allowPrivateTargets()) continue;
      const existing = unique.find(item => item.ip === entry.ip);
      if (existing) { if (!existing.role.includes(entry.role)) existing.role += `, ${entry.role.toLowerCase()}`; continue; }
      if (unique.length < MAX_BLACKLIST_ADDRESSES) unique.push({ ...entry });
    }
    if (unique.length === 0 && !domain) return badRequest(reply, 'Nothing to check.');

    const checked = await mapLimit(unique, 3, async entry => ({ ...entry, ...(await dnsbl.checkIp(entry.ip)) }));
    const domainResult = domain ? await dnsbl.checkDomain(domain) : null;

    const all = [...checked, ...(domainResult ? [domainResult] : [])];
    const summary = { listed: 0, policy: 0, clean: 0, unavailable: 0, total: 0 };
    for (const item of all) for (const key of Object.keys(summary)) summary[key] += item.summary[key];

    return {
      target: domain || raw,
      kind: domain ? 'domain' : 'ip',
      checked_at_utc: new Date().toISOString(),
      addresses: checked,
      domain: domainResult,
      summary,
      note: domain && unique.length === 0 ? 'The domain has no public A or MX addresses, so only the domain lists were checked.' : '',
    };
  });

  fastify.post('/email/smtp', { config: { rateLimit: { max: 6, timeWindow: '1 minute' } } }, async (request, reply) => {
    const body = request.body || {};
    const port = Number(body.port ?? 25);
    if (!SMTP_PORTS.includes(port)) return badRequest(reply, `Port must be one of ${SMTP_PORTS.join(', ')}.`);

    const raw = String(body.target || '').trim().replace(/^\[|\]$/g, '');
    let servers = [];
    let mode = 'host';
    if (net.isIP(raw)) {
      servers = [{ host: raw, priority: null }];
    } else {
      const hostname = normalizeHostname(raw);
      if (!hostname) return badRequest(reply, 'Enter a domain, a mail server name or an IP address.');
      servers = [{ host: hostname, priority: null }];
      if (!body.direct) {
        const mx = await dns.mx(hostname);
        const hosts = [...mx.records]
          .sort((x, y) => x.priority - y.priority)
          .map(record => ({ host: record.exchange.toLowerCase().replace(/\.$/, ''), priority: record.priority }))
          .filter(record => record.host && record.host !== '.' && (net.isIP(record.host) || normalizeHostname(record.host)));
        if (hosts.length > 0) { servers = hosts.slice(0, MAX_SMTP_SERVERS); mode = 'mx'; }
      }
    }

    const results = await mapLimit(servers, MAX_SMTP_SERVERS, async server => {
      const probe = await smtpProbe({ host: server.host, port });
      const ptr = probe.address ? (await dns.ptr(probe.address)).records : [];
      return { ...server, ...probe, ptr, findings: smtpFindings(probe, { ptr }) };
    });

    return { target: raw, port, mode, checked_at_utc: new Date().toISOString(), servers: results };
  });
}
