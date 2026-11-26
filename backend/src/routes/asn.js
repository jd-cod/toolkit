/**
 * ASN to IPs Converter & Intelligence Route — Fastify
 *
 * Endpoints:
 * - POST /api/asn                 → Full ASN prefix discovery, calculations & intelligence
 * - POST /api/asn/match-ip        → Test if an IP belongs to the ASN
 * - POST /api/asn/generate-rules  → Generate firewall & ACL configs (Nginx, iptables, UFW, etc.)
 * - POST /api/asn/search          → Search ASNs by organization name or keyword
 */

import dns from 'node:dns/promises';
import {
  parseIpv4Cidr,
  parseIpv6Cidr,
  aggregateIpv4Cidrs,
  matchIpInPrefixes,
  calculateSubnetDistribution,
  generateFirewallRules,
} from '../lib/asn-utils.js';

const RIPESTAT_API = 'https://stat.ripe.net/data';

// Known popular ASNs for fast search matching & quick chips
const POPULAR_ASNS = [
  { asn: '13335', name: 'Cloudflare', holder: 'CLOUDFLARENET', country: 'US', description: 'Cloudflare, Inc. Content Delivery & Security Network' },
  { asn: '15169', name: 'Google', holder: 'GOOGLE', country: 'US', description: 'Google LLC Global Infrastructure' },
  { asn: '16509', name: 'Amazon AWS', holder: 'AMAZON-02', country: 'US', description: 'Amazon.com, Inc. / AWS Infrastructure' },
  { asn: '8075', name: 'Microsoft', holder: 'MICROSOFT-CORP-MSN-AS-BLOCK', country: 'US', description: 'Microsoft Corporation / Azure' },
  { asn: '24940', name: 'Hetzner', holder: 'HETZNER-AS', country: 'DE', description: 'Hetzner Online GmbH Dedicated & Cloud Hosting' },
  { asn: '16276', name: 'OVHcloud', holder: 'OVH', country: 'FR', description: 'OVH SAS Global Cloud & Dedicated Server Provider' },
  { asn: '54113', name: 'Fastly', holder: 'FASTLY', country: 'US', description: 'Fastly, Inc. Edge Cloud Platform' },
  { asn: '14061', name: 'DigitalOcean', holder: 'DIGITALOCEAN-ASN', country: 'US', description: 'DigitalOcean, LLC Cloud VPS Infrastructure' },
  { asn: '20940', name: 'Akamai', holder: 'AKAMAI-ASN1', country: 'US', description: 'Akamai Technologies CDN & Edge Security' },
  { asn: '32934', name: 'Meta', holder: 'FACEBOOK', country: 'US', description: 'Meta Platforms, Inc. / Facebook Network' },
  { asn: '36459', name: 'GitHub', holder: 'GITHUB', country: 'US', description: 'GitHub, Inc. Code Hosting Infrastructure' },
  { asn: '31898', name: 'Oracle Cloud', holder: 'ORACLE-BMC-31898', country: 'US', description: 'Oracle Corporation / Oracle Cloud Infrastructure' },
  { asn: '63949', name: 'Linode / Akamai', holder: 'LINODE-AP', country: 'US', description: 'Linode Cloud Hosting' },
  { asn: '46484', name: 'Vultr / Choopa', holder: 'CHOOPA', country: 'US', description: 'The Constant Company / Vultr Cloud' },
  { asn: '13414', name: 'Twitter / X', holder: 'TWITTER', country: 'US', description: 'X Corp. Infrastructure' },
  { asn: '714', name: 'Apple', holder: 'APPLE-ENGINEERING', country: 'US', description: 'Apple Inc. Network' },
];

function formatIpCount(num) {
  if (num >= 1_000_000_000) return `${(num / 1_000_000_000).toFixed(2)}B`;
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(2)}M`;
  if (num >= 1_000) return `${(num / 1_000).toFixed(1)}K`;
  return num.toLocaleString();
}

async function fetchWithTimeout(url, timeoutMs = 8000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      signal: controller.signal,
      headers: { 'Accept': 'application/json', 'User-Agent': 'SysAdminToolkit/2.0' },
    });
    return resp;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Resolves input that might be an IP or a domain into an ASN number.
 */
async function resolveInputToAsn(input) {
  const clean = input.trim();

  // 1. Direct ASN format: "13335" or "AS13335"
  if (/^(AS)?\d+$/i.test(clean)) {
    return { asn: clean.toUpperCase().replace('AS', ''), resolved_from: null };
  }

  // 2. IPv4 format: e.g. 1.1.1.1
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(clean);
  // 3. IPv6 format
  const isIpv6 = clean.includes(':') && /^[0-9a-fA-F:]+$/.test(clean);

  let targetIp = '';
  let resolvedDomain = '';

  if (isIpv4 || isIpv6) {
    targetIp = clean;
  } else if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(clean)) {
    // Domain format
    try {
      const addresses = await dns.resolve4(clean);
      if (addresses && addresses.length > 0) {
        targetIp = addresses[0];
        resolvedDomain = clean;
      }
    } catch {
      try {
        const v6Addresses = await dns.resolve6(clean);
        if (v6Addresses && v6Addresses.length > 0) {
          targetIp = v6Addresses[0];
          resolvedDomain = clean;
        }
      } catch {
        // Could not resolve domain
      }
    }
  }

  if (targetIp) {
    // Query RIPEstat network-info for this IP
    try {
      const resp = await fetchWithTimeout(`${RIPESTAT_API}/network-info/data.json?resource=${encodeURIComponent(targetIp)}`);
      if (resp.ok) {
        const json = await resp.json();
        const asns = (json.data && json.data.asns) || [];
        if (asns.length > 0) {
          return {
            asn: asns[0].toString().replace('AS', ''),
            resolved_from: {
              input: clean,
              type: resolvedDomain ? 'domain' : 'ip',
              ip: targetIp,
              domain: resolvedDomain || null,
              matched_prefix: json.data?.prefix || null,
            },
          };
        }
      }
    } catch {
      // Fallback
    }
  }

  // 4. Check popular ASN name match (case-insensitive substring)
  const lower = clean.toLowerCase();
  const matchedPopular = POPULAR_ASNS.find(p =>
    p.name.toLowerCase() === lower ||
    p.holder.toLowerCase() === lower ||
    p.name.toLowerCase().includes(lower) ||
    p.description.toLowerCase().includes(lower)
  );

  if (matchedPopular) {
    return {
      asn: matchedPopular.asn,
      resolved_from: {
        input: clean,
        type: 'org_search',
        matched_org: matchedPopular.name,
      },
    };
  }

  return { asn: null, resolved_from: null };
}

export default async function asnRoutes(fastify, opts) {
  // ─── POST /api/asn: Main ASN Lookup & Intelligence ───
  fastify.post('/asn', async (request, reply) => {
    const body = request.body || {};
    const rawInput = (body.asn || '').toString().trim();

    if (!rawInput) {
      return reply.code(400).send({ error: 'Please enter an ASN number, IP address, domain, or organization name.' });
    }

    const { asn, resolved_from } = await resolveInputToAsn(rawInput);

    if (!asn || !/^\d+$/.test(asn)) {
      return reply.code(400).send({
        error: `Could not resolve "${rawInput}" to a valid ASN. Please enter an ASN number (e.g. AS13335), IP, or domain.`,
      });
    }

    const result = {
      asn,
      asn_formatted: `AS${asn}`,
      name: '',
      holder: '',
      description: '',
      country_code: '',
      rir: '',
      announced: false,
      abuse_emails: [],
      resolved_from,
      neighbours: {
        upstreams_count: 0,
        downstreams_count: 0,
        peers_count: 0,
        top_peers: [],
      },
      ipv4_prefixes: [],
      ipv6_prefixes: [],
      aggregated_ipv4: {
        original_count: 0,
        aggregated_count: 0,
        saved_rules: 0,
        reduction_percent: 0,
        prefixes: [],
      },
      stats: {
        total_ipv4_prefixes: 0,
        total_ipv6_prefixes: 0,
        total_ipv4_ips: 0,
        total_ipv4_ips_formatted: '0',
        v4_distribution: {},
        v6_distribution: {},
      },
      checked_at_utc: new Date().toISOString(),
      error: null,
    };

    // Parallel external fetches to RIPEstat APIs for speed
    const [overviewRes, prefixesRes, neighboursRes, abuseRes] = await Promise.allSettled([
      fetchWithTimeout(`${RIPESTAT_API}/as-overview/data.json?resource=AS${asn}`),
      fetchWithTimeout(`${RIPESTAT_API}/announced-prefixes/data.json?resource=AS${asn}`),
      fetchWithTimeout(`${RIPESTAT_API}/asn-neighbours/data.json?resource=AS${asn}`),
      fetchWithTimeout(`${RIPESTAT_API}/abuse-contact-finder/data.json?resource=AS${asn}`),
    ]);

    // 1. Process Overview Data
    if (overviewRes.status === 'fulfilled' && overviewRes.value.ok) {
      try {
        const json = await overviewRes.value.json();
        const data = json.data || {};
        result.holder = data.holder || '';
        result.name = data.holder || `AS${asn}`;
        result.description = data.type || '';
        result.announced = !!data.announced;
        const block = data.block || {};
        if (typeof block === 'object') {
          result.country_code = block.resource || '';
          result.rir = block.name || '';
        }
      } catch { /* continue */ }
    }

    // 2. Process Neighbours Data
    if (neighboursRes.status === 'fulfilled' && neighboursRes.value.ok) {
      try {
        const json = await neighboursRes.value.json();
        const neighbours = (json.data && json.data.neighbours) || [];
        let upstreams = 0, downstreams = 0, peers = 0;
        const topPeersList = [];

        for (const n of neighbours) {
          if (n.type === 'left' || n.type === 'upstream') upstreams++;
          else if (n.type === 'right' || n.type === 'downstream') downstreams++;
          else peers++;

          if (topPeersList.length < 8) {
            topPeersList.push({
              asn: n.asn,
              asn_formatted: `AS${n.asn}`,
              type: n.type || 'peer',
              v4_peers: n.v4_peers || 0,
              v6_peers: n.v6_peers || 0,
            });
          }
        }

        result.neighbours = {
          upstreams_count: upstreams,
          downstreams_count: downstreams,
          peers_count: peers || neighbours.length,
          top_peers: topPeersList,
        };
      } catch { /* continue */ }
    }

    // 3. Process Abuse Contact Data
    if (abuseRes.status === 'fulfilled' && abuseRes.value.ok) {
      try {
        const json = await abuseRes.value.json();
        const contacts = (json.data && json.data.authorities) || [];
        const emails = new Set();
        for (const auth of contacts) {
          if (auth.abuse_contacts) {
            auth.abuse_contacts.forEach(e => emails.add(e));
          }
        }
        result.abuse_emails = Array.from(emails);
      } catch { /* continue */ }
    }

    // 4. Process Announced Prefixes
    if (prefixesRes.status === 'fulfilled' && prefixesRes.value.ok) {
      try {
        const json = await prefixesRes.value.json();
        if (json.status !== 'ok') {
          result.error = `ASN ${asn} not found or no data available.`;
          return result;
        }

        const rawPrefixes = (json.data || {}).prefixes || [];
        if (rawPrefixes.length === 0) {
          result.error = `No prefixes found for AS${asn}. The ASN may not announce any BGP routes.`;
          return result;
        }

        for (const p of rawPrefixes) {
          const prefixStr = p.prefix || '';
          if (!prefixStr) continue;

          if (prefixStr.includes(':')) {
            const parsedV6 = parseIpv6Cidr(prefixStr);
            if (parsedV6) result.ipv6_prefixes.push(parsedV6);
          } else {
            const parsedV4 = parseIpv4Cidr(prefixStr);
            if (parsedV4) result.ipv4_prefixes.push(parsedV4);
          }
        }

        // Sort IPv4 and IPv6 prefixes
        result.ipv4_prefixes.sort((a, b) => a.start_long - b.start_long || a.mask - b.mask);
        result.ipv6_prefixes.sort((a, b) => a.prefix.localeCompare(b.prefix));

        // Subnet distribution & IP calculation
        const distribution = calculateSubnetDistribution(result.ipv4_prefixes, result.ipv6_prefixes);
        result.stats = {
          total_ipv4_prefixes: result.ipv4_prefixes.length,
          total_ipv6_prefixes: result.ipv6_prefixes.length,
          total_ipv4_ips: distribution.total_ipv4_addresses,
          total_ipv4_ips_formatted: formatIpCount(distribution.total_ipv4_addresses),
          v4_distribution: distribution.v4_distribution,
          v6_distribution: distribution.v6_distribution,
        };

        // Compute Aggregated CIDRs (Supernetting)
        result.aggregated_ipv4 = aggregateIpv4Cidrs(result.ipv4_prefixes);
      } catch (e) {
        result.error = `Failed parsing prefixes: ${e.message}`;
      }
    } else {
      result.error = `RIPEstat API error for AS${asn}. Please verify the ASN and try again.`;
    }

    return result;
  });

  // ─── POST /api/asn/match-ip: Test if IP is in ASN prefixes ───
  fastify.post('/asn/match-ip', async (request, reply) => {
    const body = request.body || {};
    const candidateIp = (body.ip || '').trim();
    const prefixes = body.prefixes || [];

    if (!candidateIp) {
      return reply.code(400).send({ error: 'Missing IP address to test.' });
    }

    if (!Array.isArray(prefixes) || prefixes.length === 0) {
      return reply.code(400).send({ error: 'No prefix list provided for testing.' });
    }

    const matchResult = matchIpInPrefixes(candidateIp, prefixes);
    return matchResult;
  });

  // ─── POST /api/asn/generate-rules: Firewall / ACL Generator ───
  fastify.post('/asn/generate-rules', async (request, reply) => {
    const body = request.body || {};
    const format = body.format || 'nginx';
    const action = body.action || 'deny';
    const asn = body.asn || '';
    const orgName = body.orgName || '';
    const prefixes = body.prefixes || [];

    const rules = generateFirewallRules({
      format,
      action,
      asn,
      orgName,
      prefixes,
    });

    return { rules, total_prefixes: prefixes.length, format, action };
  });

  // ─── POST /api/asn/search: Search ASNs by Org / Keyword ───
  fastify.post('/asn/search', async (request, reply) => {
    const body = request.body || {};
    const query = (body.query || '').trim().toLowerCase();

    if (!query) {
      return { results: POPULAR_ASNS.slice(0, 10) };
    }

    const matches = POPULAR_ASNS.filter(p =>
      p.asn.includes(query) ||
      p.name.toLowerCase().includes(query) ||
      p.holder.toLowerCase().includes(query) ||
      p.description.toLowerCase().includes(query)
    );

    return { results: matches };
  });
}
