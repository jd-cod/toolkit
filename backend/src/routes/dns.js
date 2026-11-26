/**
 * DNS Lookup Route — Fastify
 *
 * POST /api/dns
 * Body: { domain: string, type: string, resolver: string }
 *
 * Proxies DNS queries via DNS-over-HTTPS (DoH).
 * Migrated from Hono/CF Workers. All logic preserved.
 */
import dnsPacket from 'dns-packet';
import { createGlobalDnsAccess } from '../services/global-dns-access.js';
import { AwsClient } from 'aws4fetch';

const DOH_ENDPOINTS = {
  '1.1.1.1': 'https://cloudflare-dns.com/dns-query',
  '8.8.8.8': 'https://dns.google/dns-query',
  '208.67.222.222': 'https://doh.opendns.com/dns-query',
};

const GLOBAL_DNS_LAMBDAS = {
  'us-east-1': 'https://flvmgqbeare2arnjrij5u5cyiq0hxhbb.lambda-url.us-east-1.on.aws/',
  'us-east-2': 'https://3nqzuuhnqvhtyqibuhqk3hbwhu0ktwys.lambda-url.us-east-2.on.aws/',
  'us-west-1': 'https://xmjgjdgu7nbgsgmi3tkw3rnaoa0bydjt.lambda-url.us-west-1.on.aws/',
  'us-west-2': 'https://wqallyme3rovdv5ppe7bd2ahga0ybxjw.lambda-url.us-west-2.on.aws/',
  'eu-west-1': 'https://3nu7n2l6pboobfjkxad2qr32pe0bowql.lambda-url.eu-west-1.on.aws/',
  'eu-west-2': 'https://xukaujtbussuypfecicru6mwwi0xvzqf.lambda-url.eu-west-2.on.aws/',
  'eu-central-1': 'https://ypwmkmdmggwvv6bypnblatwfaq0iffge.lambda-url.eu-central-1.on.aws/',
  'eu-north-1': 'https://gjqv5q5dvtplbmcrynmsbz3jk40mctds.lambda-url.eu-north-1.on.aws/',
  'ap-south-1': 'https://6agsywvzsv4vylpweempo6mofa0zxqrn.lambda-url.ap-south-1.on.aws/',
  'ap-northeast-1': 'https://wgp6vjy7a54tjiqib7en2adjpq0vjzxp.lambda-url.ap-northeast-1.on.aws/',
  'ap-northeast-2': 'https://4yv7h4fs4lkcm6klsvnbpdgawi0pbvde.lambda-url.ap-northeast-2.on.aws/',
  'ap-southeast-1': 'https://itr2oduaqefxtmflixnlpf7wma0kniqp.lambda-url.ap-southeast-1.on.aws/',
  'ap-southeast-2': 'https://5nnrnudwtnvqwimcsshgb56iry0ysoqk.lambda-url.ap-southeast-2.on.aws/',
  'ca-central-1': 'https://a2r7guo6gu5gtis6mxxslvp6bm0oavvt.lambda-url.ca-central-1.on.aws/',
  'sa-east-1': 'https://xi5jptv3tnvqqwjzu4tzspeh3i0gqnev.lambda-url.sa-east-1.on.aws/'
};

const VALID_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA', 'PTR', 'SRV', 'CAA'];
const DNS_STATUS_LABELS = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };

const DNS_PROVIDER_RULES = [
  { slug: 'cloudflare-dns', name: 'Cloudflare DNS', confidence: 'high', hints: [{ type: 'NS', value: 'ns.cloudflare.com', confidence: 'high' }] },
  { slug: 'aws-route53', name: 'AWS Route 53', confidence: 'high', hints: [{ type: 'NS', value: 'awsdns-', confidence: 'high' }] },
  { slug: 'sucuri-dns', name: 'Sucuri DNS', confidence: 'high', hints: [{ type: 'NS', value: 'sucuri.net', confidence: 'high' }, { type: 'NS', value: 'dns.sucuri.net', confidence: 'high' }] },
  { slug: 'godaddy-dns', name: 'GoDaddy DNS', confidence: 'high', hints: [{ type: 'NS', value: 'domaincontrol.com', confidence: 'high' }] },
  { slug: 'namecheap-dns', name: 'Namecheap DNS', confidence: 'high', hints: [{ type: 'NS', value: 'registrar-servers.com', confidence: 'high' }] },
  { slug: 'google-cloud-dns', name: 'Google Cloud DNS', confidence: 'high', hints: [{ type: 'NS', value: 'googledomains.com', confidence: 'medium' }, { type: 'NS', value: 'googledomains', confidence: 'medium' }] },
  { slug: 'azure-dns', name: 'Azure DNS', confidence: 'high', hints: [{ type: 'NS', value: 'azure-dns', confidence: 'high' }] },
  { slug: 'vercel-dns', name: 'Vercel DNS', confidence: 'high', hints: [{ type: 'NS', value: 'vercel-dns.com', confidence: 'high' }] },
  { slug: 'digitalocean-dns', name: 'DigitalOcean DNS', confidence: 'high', hints: [{ type: 'NS', value: 'digitalocean.com', confidence: 'high' }] },
  { slug: 'wordpress-dns', name: 'WordPress.com DNS', confidence: 'high', hints: [{ type: 'NS', value: 'wordpress.com', confidence: 'high' }] },
  { slug: 'wix-dns', name: 'Wix DNS', confidence: 'high', hints: [{ type: 'NS', value: 'wixdns.net', confidence: 'high' }] },
  { slug: 'dnsmadeeasy', name: 'DNS Made Easy', confidence: 'high', hints: [{ type: 'NS', value: 'dnsmadeeasy.com', confidence: 'high' }] },
  { slug: 'network-solutions', name: 'Network Solutions DNS', confidence: 'high', hints: [{ type: 'NS', value: 'worldnic.com', confidence: 'high' }] },
  { slug: 'akamai-dns', name: 'Akamai DNS', confidence: 'high', hints: [{ type: 'NS', value: 'akam.net', confidence: 'high' }] },
];

const HOSTING_PROVIDER_RULES = [
  { slug: 'sucuri', name: 'Sucuri', confidence: 'high', hints: [{ type: 'CNAME', value: 'sucuri.net', confidence: 'high' }] },
  { slug: 'cloudflare', name: 'Cloudflare', confidence: 'high', hints: [{ type: 'CNAME', value: 'cdn.cloudflare.net', confidence: 'high' }, { type: 'CNAME', value: 'cloudflare.net', confidence: 'medium' }] },
  { slug: 'aws-cloudfront', name: 'AWS CloudFront', confidence: 'high', hints: [{ type: 'CNAME', value: 'cloudfront.net', confidence: 'high' }] },
  { slug: 'aws-elb', name: 'AWS ELB', confidence: 'high', hints: [{ type: 'CNAME', value: 'elb.amazonaws.com', confidence: 'high' }] },
  { slug: 'fastly', name: 'Fastly', confidence: 'high', hints: [{ type: 'CNAME', value: 'fastly.net', confidence: 'high' }, { type: 'CNAME', value: 'fastlylb.net', confidence: 'high' }, { type: 'CNAME', value: 'map.fastly.net', confidence: 'medium' }] },
  { slug: 'akamai', name: 'Akamai', confidence: 'high', hints: [{ type: 'CNAME', value: 'akamaiedge.net', confidence: 'high' }, { type: 'CNAME', value: 'akamaihd.net', confidence: 'high' }, { type: 'CNAME', value: 'edgesuite.net', confidence: 'high' }, { type: 'CNAME', value: 'edgekey.net', confidence: 'high' }] },
  { slug: 'google-cloud', name: 'Google Cloud', confidence: 'high', hints: [{ type: 'CNAME', value: 'ghs.googlehosted.com', confidence: 'high' }, { type: 'CNAME', value: 'googlehosted.com', confidence: 'high' }] },
  { slug: 'azure', name: 'Microsoft Azure', confidence: 'high', hints: [{ type: 'CNAME', value: 'azurefd.net', confidence: 'high' }, { type: 'CNAME', value: 'trafficmanager.net', confidence: 'high' }, { type: 'CNAME', value: 'azurewebsites.net', confidence: 'high' }, { type: 'CNAME', value: 'cloudapp.azure.com', confidence: 'medium' }] },
  { slug: 'netlify', name: 'Netlify', confidence: 'high', hints: [{ type: 'CNAME', value: 'netlify.app', confidence: 'high' }, { type: 'CNAME', value: 'netlifyglobalcdn.com', confidence: 'high' }] },
  { slug: 'vercel', name: 'Vercel', confidence: 'high', hints: [{ type: 'CNAME', value: 'vercel.app', confidence: 'medium' }] },
  { slug: 'shopify', name: 'Shopify', confidence: 'high', hints: [{ type: 'CNAME', value: 'myshopify.com', confidence: 'high' }, { type: 'CNAME', value: 'shops.myshopify.com', confidence: 'high' }] },
  { slug: 'github-pages', name: 'GitHub Pages', confidence: 'high', hints: [{ type: 'CNAME', value: 'github.io', confidence: 'high' }] },
  { slug: 'pantheon', name: 'Pantheon', confidence: 'high', hints: [{ type: 'CNAME', value: 'pantheonsite.io', confidence: 'high' }] },
  { slug: 'cloudways', name: 'Cloudways', confidence: 'high', hints: [{ type: 'CNAME', value: 'cloudwaysapps.com', confidence: 'high' }] },
  { slug: 'digitalocean', name: 'DigitalOcean', confidence: 'high', hints: [{ type: 'CNAME', value: 'ondigitalocean.app', confidence: 'high' }] },
  { slug: 'oracle-cloud', name: 'Oracle Cloud', confidence: 'high', hints: [{ type: 'CNAME', value: 'oraclecloud.com', confidence: 'high' }] },
  { slug: 'ibm-cloud', name: 'IBM Cloud', confidence: 'high', hints: [{ type: 'CNAME', value: 'mybluemix.net', confidence: 'high' }, { type: 'CNAME', value: 'appdomain.cloud', confidence: 'medium' }] },
];

export default async function dnsRoutes(fastify, opts) {
  const globalAccess = opts.globalDnsAccess || createGlobalDnsAccess();
  fastify.get('/dns/global-capability', async () => globalAccess.capability());
  fastify.post('/dns', async (request, reply) => {
    const body = request.body || {};
    const domain = (body.domain || '').trim().toLowerCase();
    const type = (body.type || 'A').trim().toUpperCase();
    const resolver = (body.resolver || '1.1.1.1').trim();

    if (!domain || domain.length > 253) return { error: 'Invalid domain name.', records: [] };
    if (!VALID_TYPES.includes(type)) return { error: `Invalid record type: ${type}`, records: [] };

    const endpoint = DOH_ENDPOINTS[resolver] || DOH_ENDPOINTS['1.1.1.1'];

    try {
      const resp = await queryDns(endpoint, domain, type);
      if (!resp.ok) return { error: `DNS resolver returned HTTP ${resp.status}`, records: [], _type: type };

      const arrayBuffer = await resp.arrayBuffer();
      const packet = dnsPacket.decode(Buffer.from(arrayBuffer));
      const status = rcodeToStatus(packet.rcode);
      
      const records = (packet.answers || [])
        .map(a => ({ ...a, data: formatDnsData(a) }))
        .filter(hasUsableAnswer)
        .map(a => ({
          name: a.name, type: a.type, TTL: a.ttl || 0,
          data: a.data.trim(),
          ...(type === 'MX' && a.data ? parseMX(a.data) : {}),
        }));

      const providers = await detectProviders(endpoint, domain, type, records, status);

      if (records.length === 0) {
        const noRecordsReason = describeNoRecords(domain, type, status);
        if (noRecordsReason) {
          return { domain, type, resolver, records: [], status, _type: type, noRecords: true, message: noRecordsReason, ...providers };
        }
        return { error: `DNS lookup failed with ${DNS_STATUS_LABELS[status] || `status ${status}`}.`, records: [], status, _type: type, ...providers };
      }

      return { domain, type, resolver, records, status, _type: type, ...providers };
    } catch (e) {
      return { error: `DNS query failed: ${e.message}`, records: [], _type: type, dns_provider: unknownProvider(), hosting_provider: unknownProvider() };
    }
  });

  fastify.post('/dns/global', {
    config: {
      rateLimit: { max: 5, timeWindow: '1 minute' }
    }
  }, async (request, reply) => {
    const body = request.body || {};
    const domain = (body.domain || '').trim().toLowerCase();
    const type = (body.type || 'A').trim().toUpperCase();

    if (!domain || domain.length > 253) return { error: 'Invalid domain name.', results: [] };
    if (!VALID_TYPES.includes(type)) return { error: `Invalid record type: ${type}`, results: [] };

    // Retrieve AWS credentials locally (uses ~/.aws/credentials or env vars)
    let awsClient;
    try {
      const credentials = await globalAccess.credentials();
      if (!credentials) return reply.code(503).send({ error: 'Global propagation is unavailable on this server. Use a standard DNS query.', results: [] });
      awsClient = new AwsClient({
        accessKeyId: credentials.accessKeyId,
        secretAccessKey: credentials.secretAccessKey,
        sessionToken: credentials.sessionToken,
        retries: 0
      });
    } catch {
      return reply.code(503).send({ error: 'Global propagation is unavailable on this server. Use a standard DNS query.', results: [] });
    }

    const promises = Object.entries(GLOBAL_DNS_LAMBDAS).map(async ([regionCode, url]) => {
      const REGION_NAMES = {
        'us-east-1': 'N. Virginia (US)',
        'us-east-2': 'Ohio (US)',
        'us-west-1': 'N. California (US)',
        'us-west-2': 'Oregon (US)',
        'eu-west-1': 'Ireland (Europe)',
        'eu-west-2': 'London (UK)',
        'eu-central-1': 'Frankfurt (Germany)',
        'eu-north-1': 'Stockholm (Sweden)',
        'ap-south-1': 'Mumbai (India)',
        'ap-northeast-1': 'Tokyo (Japan)',
        'ap-northeast-2': 'Seoul (South Korea)',
        'ap-southeast-1': 'Singapore (Asia)',
        'ap-southeast-2': 'Sydney (Australia)',
        'ca-central-1': 'Central (Canada)',
        'sa-east-1': 'São Paulo (Brazil)'
      };
      const region = REGION_NAMES[regionCode] || regionCode;

      try {
        const fullUrl = `${url}?domain=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`;
        
        const res = await awsClient.fetch(fullUrl, {
          method: 'GET',
          service: 'lambda',
          region: regionCode,
          signal: AbortSignal.timeout(8000)
        });
        
        if (!res.ok) {
          const errText = await res.text().catch(() => '');
          throw new Error(`HTTP ${res.status} ${errText}`);
        }
        const data = await res.json();
        return { region, status: 'success', data };
      } catch (err) {
        return { region, status: 'error', error: err.message };
      }
    });

    const results = await Promise.all(promises);
    return { domain, type, results };
  });
}

async function queryDns(endpoint, domain, type) {
  const buf = dnsPacket.encode({
    type: 'query',
    id: 0,
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ type, name: domain }]
  });

  return fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Length': String(buf.length),
      'Content-Type': 'application/dns-message',
      'Accept': 'application/dns-message'
    },
    body: buf
  });
}

async function detectProviders(endpoint, domain, requestedType, requestedRecords, requestedStatus) {
  const lookups = buildProviderLookupMap(requestedType, requestedRecords, requestedStatus);
  const requiredTypes = ['NS', 'SOA', 'CNAME', 'A', 'AAAA', 'MX', 'TXT'];
  const missingTypes = requiredTypes.filter(type => !(type in lookups));

  if (missingTypes.length > 0) {
    const fetched = await Promise.all(missingTypes.map(async (type) => {
      try {
        const resp = await queryDns(endpoint, domain, type);
        if (!resp.ok) return [type, []];
        const arrayBuffer = await resp.arrayBuffer();
        const packet = dnsPacket.decode(Buffer.from(arrayBuffer));
        const answers = (packet.answers || []).map(a => ({ ...a, data: formatDnsData(a) }));
        return [type, normalizeAnswers(type, answers)];
      } catch { return [type, []]; }
    }));
    for (const [type, values] of fetched) lookups[type] = values;
  }

  return {
    dns_provider: findProviderMatch(lookups, DNS_PROVIDER_RULES, ['NS', 'SOA']) || unknownProvider(),
    hosting_provider: findProviderMatch(lookups, HOSTING_PROVIDER_RULES, ['CNAME', 'A', 'AAAA', 'TXT']) || unknownProvider(),
  };
}

function buildProviderLookupMap(requestedType, requestedRecords, requestedStatus) {
  const lookups = {};
  lookups[requestedType] = requestedStatus === 0 || requestedStatus === 3
    ? normalizeRecords(requestedType, requestedRecords) : [];
  return lookups;
}

function normalizeAnswers(type, answers) {
  return answers.filter(hasUsableAnswer).map(answer => normalizeRecordValue(type, answer.data));
}

function normalizeRecords(type, records) {
  return (records || []).map(record => normalizeRecordValue(type, record?.data ?? record?.value ?? '')).filter(Boolean);
}

function normalizeRecordValue(type, value) {
  if (value == null) return '';
  let normalized = String(value).trim().toLowerCase();
  if (!normalized) return '';
  if (type !== 'TXT') normalized = normalized.replace(/\.$/, '');
  return normalized;
}

function findProviderMatch(lookups, rules, preferredSources = []) {
  let bestMatch = null;
  for (const provider of rules) {
    for (const hint of provider.hints) {
      const values = lookups[hint.type] || [];
      const matchedValue = values.find(value => value.includes(hint.value));
      if (!matchedValue) continue;
      const candidate = { slug: provider.slug, name: provider.name, confidence: hint.confidence || provider.confidence || 'medium', source: hint.type, matched_on: matchedValue };
      if (!bestMatch || rankConfidence(candidate.confidence) > rankConfidence(bestMatch.confidence)) bestMatch = candidate;
      if (candidate.confidence === 'high' && preferredSources.includes(hint.type)) return candidate;
    }
  }
  return bestMatch;
}

function rankConfidence(c) { return c === 'high' ? 3 : c === 'medium' ? 2 : 1; }
function unknownProvider() { return { slug: 'unknown', name: 'Unknown', confidence: 'low', source: '', matched_on: '' }; }
function hasUsableAnswer(answer) { if (!answer || answer.data == null) return false; return typeof answer.data === 'string' ? answer.data.trim().length > 0 : true; }
function describeNoRecords(domain, type, status) {
  if (status === 3) return `No ${type} records found. ${domain} does not exist.`;
  if (status === 0) return `No ${type} records found for ${domain}.`;
  return '';
}
function parseMX(data) {
  const parts = data.split(/\s+/);
  if (parts.length >= 2) return { priority: parseInt(parts[0], 10), value: parts.slice(1).join(' ').replace(/\.$/, ''), data: parts.slice(1).join(' ').replace(/\.$/, '') };
  return {};
}

function rcodeToStatus(rcode) {
  const map = { 'NOERROR': 0, 'FORMERR': 1, 'SERVFAIL': 2, 'NXDOMAIN': 3, 'NOTIMP': 4, 'REFUSED': 5 };
  return map[rcode] ?? 2;
}

function formatDnsData(a) {
  if (!a || a.data == null) return '';
  switch (a.type) {
    case 'MX': return `${a.data.preference} ${a.data.exchange}`;
    case 'SOA': return `${a.data.mname} ${a.data.rname} ${a.data.serial} ${a.data.refresh} ${a.data.retry} ${a.data.expire} ${a.data.minimum}`;
    case 'TXT': 
      if (Array.isArray(a.data)) return a.data.map(b => b.toString('utf8')).join(' ');
      if (Buffer.isBuffer(a.data)) return a.data.toString('utf8');
      return String(a.data);
    case 'CAA': return `${a.data.flags || 0} ${a.data.tag} "${a.data.value}"`;
    case 'SRV': return `${a.data.priority} ${a.data.weight} ${a.data.port} ${a.data.target}`;
    default: return typeof a.data === 'string' ? a.data : String(a.data);
  }
}
