/**
 * Network tools — Fastify
 *
 * POST /api/http-check  { url }          response headers, redirect chain, security header audit
 * POST /api/port-check  { host, ports }  TCP reachability of up to 25 ports on one public host
 *
 * Both connect to a visitor-chosen host, so both go through lib/net-guard.js
 * and carry their own rate limits. See docs/TOOLS_ROADMAP.md.
 */

import net from 'node:net';
import { mapLimit, normalizeHostname } from '../lib/dns-client.js';
import { auditResponse, describeDelivery, followChain, headerValues, normalizeUrl } from '../lib/http-inspect.js';
import { describePort, parsePorts, probePort, resolvePublicAddress } from '../lib/port-probe.js';

const REDIRECTS = new Set([301, 302, 303, 307, 308]);

// Routes registered as plugins do not inherit the error handler set in
// server.js, so a thrown error would reach the client as "Bad Request" with
// the reason in a field the frontend does not read. Answer in the
// { error } shape every other tool uses.
function sendError(reply, err, log) {
  const status = err?.statusCode >= 400 && err.statusCode < 500 ? err.statusCode : 502;
  if (status === 502) log.warn({ err }, 'network tool failed');
  return reply.code(status).send({ error: status === 502 ? 'The check could not be completed. Try again.' : err.message });
}

export default async function netToolRoutes(fastify, opts) {
  const follow = opts.followChain || followChain;
  const probe = opts.probePort || probePort;
  const resolveAddress = opts.resolvePublicAddress || resolvePublicAddress;

  fastify.post('/http-check', { config: { rateLimit: { max: 15, timeWindow: '1 minute' } } }, async (request, reply) => {
    let url;
    try {
      url = normalizeUrl((request.body || {}).url);
    } catch (err) {
      return sendError(reply, err, request.log);
    }
    const result = await follow(url);
    const audit = auditResponse(result);

    // A site reached over HTTPS should also send plain-HTTP visitors there.
    let httpUpgrade = null;
    if (result.final && url.protocol === 'https:' && !url.port) {
      const plain = await follow(new URL(`http://${url.host}/`), { maxHops: 0, timeoutMs: 5000 });
      const first = plain.chain[0];
      if (first && !first.error) {
        const location = headerValues(first, 'location')[0] || '';
        const upgrades = REDIRECTS.has(first.status) && /^https:/i.test(new URL(location || '/', first.url).toString());
        httpUpgrade = { status: first.status, location, upgrades };
        if (!upgrades) {
          audit.findings.push({
            severity: 'warning',
            title: 'Plain HTTP does not redirect to HTTPS',
            detail: `http://${url.host}/ answers with ${first.status} and no redirect to https. Visitors who type the address without https stay on an unencrypted connection.`,
          });
        }
      }
    }

    return {
      requested_url: url.toString(),
      checked_at_utc: new Date().toISOString(),
      chain: result.chain,
      final_url: result.final?.url || '',
      error: result.error,
      redirects: Math.max(result.chain.length - 1, 0),
      total_ms: result.chain.reduce((sum, hop) => sum + (hop.elapsed_ms || 0), 0),
      http_upgrade: httpUpgrade,
      delivery: describeDelivery(result.final),
      ...audit,
    };
  });

  fastify.post('/port-check', { config: { rateLimit: { max: 6, timeWindow: '1 minute' } } }, async (request, reply) => {
    const body = request.body || {};
    const raw = String(body.host || '').trim().replace(/^\[|\]$/g, '');
    const host = net.isIP(raw) ? raw : normalizeHostname(raw);
    if (!host) return reply.code(400).send({ error: 'Enter a host name or a public IP address.' });

    let ports;
    let target;
    try {
      ports = parsePorts(body.ports);
      target = await resolveAddress(host);
    } catch (err) {
      return sendError(reply, err, request.log);
    }
    const results = await mapLimit(ports, 10, port => probe(target.address, port));
    const described = results.map(describePort);

    return {
      host,
      address: target.address,
      checked_at_utc: new Date().toISOString(),
      results: described,
      summary: {
        open: described.filter(item => item.state === 'open').length,
        closed: described.filter(item => item.state === 'closed').length,
        filtered: described.filter(item => item.state === 'filtered').length,
      },
    };
  });
}
