/**
 * AbuseIPDB Proxy Route — Fastify
 *
 * POST /api/abuse
 * Body: { ips: [{ip, hits}], max?: number }
 *
 * Migrated from Hono/CF Workers. Only syntax changes.
 */

import { str } from '../lib/input.js';

const MAX_IPS_PER_REQUEST = 50;

export default async function abuseRoutes(fastify, opts) {
  fastify.post('/abuse', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (request, reply) => {
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    if (!apiKey) {
      return { abusive: [], non_abusive: [], api_available: false, checked_count: 0 };
    }

    const body = request.body || {};
    const ips = Array.isArray(body.ips) ? body.ips : [];
    // Every checked IP spends AbuseIPDB quota, so the caller cannot raise the cap.
    const requestedMax = Number.isInteger(body.max) && body.max > 0 ? body.max : 20;
    const max = Math.min(requestedMax, MAX_IPS_PER_REQUEST);

    const toCheck = ips.slice(0, max);
    const results = [];

    const batchSize = 5;
    for (let i = 0; i < toCheck.length; i += batchSize) {
      const batch = toCheck.slice(i, i + batchSize);
      const batchResults = await Promise.all(
        batch.map(async (ipInfo) => {
          const ip = typeof ipInfo === 'string' ? ipInfo : str(ipInfo?.ip);
          const hits = typeof ipInfo === 'string' ? 0 : (ipInfo?.hits || 0);

          try {
            const resp = await fetch(
              `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
              { headers: { 'Key': apiKey, 'Accept': 'application/json' } }
            );

            if (resp.status !== 200) {
              return { ip, hits, domain: 'API_ERROR', abuse_score: 0, country: 'Unknown', error: `HTTP ${resp.status}` };
            }

            const json = await resp.json();
            const data = json.data || {};

            return {
              ip, hits,
              domain: data.domain || 'N/A',
              abuse_score: data.abuseConfidenceScore || 0,
              country: data.countryName || 'Unknown',
              country_code: data.countryCode || '--',
              isp: data.isp || '',
              usage_type: data.usageType || '',
              total_reports: data.totalReports || 0,
              is_tor: data.isTor || false,
              is_whitelisted: data.isWhitelisted || false,
              num_distinct_users: data.numDistinctUsers || 0,
              last_reported_at: data.lastReportedAt || '',
            };
          } catch (e) {
            return { ip, hits, domain: 'ERROR', abuse_score: 0, country: 'Unknown', error: e.message };
          }
        })
      );
      results.push(...batchResults);
    }

    const abusive = results.filter(r => (r.abuse_score || 0) > 0).sort((a, b) => b.hits - a.hits);
    const non_abusive = results.filter(r => (r.abuse_score || 0) === 0).sort((a, b) => b.hits - a.hits);

    return { abusive, non_abusive, api_available: true, checked_count: results.length };
  });
}
