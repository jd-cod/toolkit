import { spawn } from 'node:child_process';
import { Resolver } from 'node:dns/promises';
import { domainToASCII } from 'node:url';

const WHOIS_PATH = process.env.WHOIS_BIN || '/usr/bin/whois';
const WHOIS_TIMEOUT_MS = parseInt(process.env.WHOIS_TIMEOUT_MS || '15000', 10);
const WHOIS_OUTPUT_LIMIT_BYTES = parseInt(process.env.WHOIS_OUTPUT_LIMIT_BYTES || String(1024 * 1024), 10);

const RDAP_BOOTSTRAP_URL = process.env.RDAP_BOOTSTRAP_URL || 'https://data.iana.org/rdap/dns.json';
const RDAP_BOOTSTRAP_REFRESH_MS = parseInt(process.env.RDAP_BOOTSTRAP_REFRESH_MS || String(24 * 60 * 60 * 1000), 10);
const RDAP_REQUEST_TIMEOUT_MS = parseInt(process.env.RDAP_REQUEST_TIMEOUT_MS || '10000', 10);

const rdapBootstrapCache = {
  services: new Map(),
  fetchedAt: 0,
  expiresAt: 0,
  inflight: null,
  refreshHandle: null,
};

const FIELD_ALIASES = {
  registrar: ['Registrar', 'Sponsoring Registrar', 'Registrar Name'],
  registrar_iana_id: ['Registrar IANA ID', 'Sponsoring Registrar IANA ID'],
  abuse_email: ['Registrar Abuse Contact Email', 'Abuse Contact Email'],
  abuse_phone: ['Registrar Abuse Contact Phone', 'Abuse Contact Phone'],
  creation_date: ['Creation Date', 'Created On', 'Created Date', 'Registration Time', 'Domain Registration Date', 'Domain Record Activated', 'Created', '[Created on]'],
  updated_date: ['Updated Date', 'Last Updated On', 'Last Modified', 'Changed', 'Modified', 'Domain Record Last Updated', 'Last Update', '[Last Updated]'],
  expiry_date: ['Registry Expiry Date', 'Registrar Registration Expiration Date', 'Expiration Date', 'Expiry Date', 'Paid-till', 'Expires On', 'Domain Expires', 'Expire Date', 'Expires', '[Expires on]'],
  registrant_name: ['Registrant Name', 'Registrant Organization', 'Registrant'],
  registrant_email: ['Registrant Email'],
  registrant_phone: ['Registrant Phone'],
  admin_name: ['Admin Name', 'Administrative Contact Name'],
  admin_email: ['Admin Email', 'Administrative Contact Email'],
  admin_phone: ['Admin Phone', 'Administrative Contact Phone'],
  tech_name: ['Tech Name', 'Technical Contact Name'],
  tech_email: ['Tech Email', 'Technical Contact Email'],
  tech_phone: ['Tech Phone', 'Technical Contact Phone'],
  dnssec: ['DNSSEC', 'dnssec', 'DNSSEC DS RR'],
};

const STATUS_LABELS = [
  { match: /clienttransferprohibited/i, label: 'Transfer Locked' },
  { match: /servertransferprohibited/i, label: 'Registry Transfer Locked' },
  { match: /clientdeleteprohibited/i, label: 'Delete Locked' },
  { match: /serverdeleteprohibited/i, label: 'Registry Delete Locked' },
  { match: /clientupdateprohibited/i, label: 'Update Locked' },
  { match: /serverupdateprohibited/i, label: 'Registry Update Locked' },
  { match: /pendingdelete/i, label: 'Pending Delete' },
  { match: /pendingtransfer/i, label: 'Pending Transfer' },
  { match: /pendingrenew/i, label: 'Pending Renewal' },
  { match: /hold/i, label: 'On Hold' },
  { match: /ok/i, label: 'Active' },
];

const PRIVACY_HINTS = [
  'whois privacy',
  'redacted for privacy',
  'privacy service',
  'contact privacy',
  'domains by proxy',
  'privacyguardian',
  'privacy protect',
  'data protected',
  'redacted',
];

function normalizeDomain(input) {
  const raw = (input || '').trim().toLowerCase();
  const stripped = raw
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:.*$/, '');
  try {
    return domainToASCII(stripped) || stripped;
  } catch {
    return stripped;
  }
}

function isValidDomain(domain) {
  if (!domain || domain.length > 253) return false;
  if (domain.includes('..')) return false;
  return /^[a-z0-9.-]+$/.test(domain)
    && domain.includes('.')
    && domain.split('.').every((part) => part.length > 0 && part.length <= 63 && !part.startsWith('-') && !part.endsWith('-'));
}

function parseWhoisDate(value) {
  if (!value) return '';
  const sanitized = String(value).replace(/\s+/g, ' ').trim();
  const date = new Date(sanitized);
  if (!Number.isNaN(date.getTime())) return date.toISOString();

  const match = sanitized.match(/^(\d{2})-(\w{3})-(\d{4})$/i);
  if (match) {
    const retry = new Date(`${match[1]} ${match[2]} ${match[3]} UTC`);
    if (!Number.isNaN(retry.getTime())) return retry.toISOString();
  }

  return '';
}

function pickFirst(fields, aliases) {
  for (const alias of aliases) {
    const values = fields.get(alias.toLowerCase());
    if (values?.length) return values[0];
  }
  return '';
}

function collectAll(fields, aliases) {
  const output = [];
  for (const alias of aliases) {
    const values = fields.get(alias.toLowerCase()) || [];
    for (const value of values) {
      if (!output.includes(value)) output.push(value);
    }
  }
  return output;
}

function titleCase(value) {
  return value.replace(/\b\w/g, (char) => char.toUpperCase());
}

function normalizeStatusCode(value) {
  return String(value || '').trim();
}

function toStatusLabel(code) {
  const normalized = normalizeStatusCode(code);
  if (!normalized) return '';
  const compact = normalized.replace(/[\s_-]+/g, '');
  const matched = STATUS_LABELS.find((entry) => entry.match.test(compact));
  if (matched) return matched.label;
  return titleCase(normalized.replace(/[_-]+/g, ' '));
}

function parseWhoisFields(rawWhois) {
  const lines = rawWhois.split(/\r?\n/);
  const fields = new Map();

  for (const line of lines) {
    const match = line.match(/^([^:#\n][^:]{1,80}):\s*(.+)$/);
    if (!match) continue;
    const key = match[1].trim().toLowerCase();
    const value = match[2].trim();
    if (!value) continue;
    if (!fields.has(key)) fields.set(key, []);
    fields.get(key).push(value);
  }

  const nameservers = [
    ...collectAll(fields, ['Name Server', 'Nameserver', 'Nserver']),
    ...collectAll(fields, ['Name Servers']).flatMap((value) => value.split(/\s+/).filter(Boolean)),
  ]
    .map(normalizeHostname)
    .filter((value) => value.includes('.'));

  const statusCodes = collectAll(fields, ['Domain Status', 'Status', 'Domain status'])
    .map((value) => value.split(/\s+/)[0].trim())
    .filter(Boolean);

  const uniqueStatusCodes = [...new Set(statusCodes)];
  const statusLabels = [...new Set(uniqueStatusCodes.map(toStatusLabel).filter(Boolean))];

  return {
    registered: inferRegistration(rawWhois),
    status_codes: uniqueStatusCodes,
    status_labels: statusLabels,
    registrar: pickFirst(fields, FIELD_ALIASES.registrar),
    registrar_iana_id: pickFirst(fields, FIELD_ALIASES.registrar_iana_id),
    abuse_email: pickFirst(fields, FIELD_ALIASES.abuse_email),
    abuse_phone: pickFirst(fields, FIELD_ALIASES.abuse_phone),
    creation_date: parseWhoisDate(pickFirst(fields, FIELD_ALIASES.creation_date)),
    updated_date: parseWhoisDate(pickFirst(fields, FIELD_ALIASES.updated_date)),
    expiry_date: parseWhoisDate(pickFirst(fields, FIELD_ALIASES.expiry_date)),
    dnssec: pickFirst(fields, FIELD_ALIASES.dnssec),
    nameservers: [...new Set(nameservers)],
    contacts: {
      registrant: {
        name: pickFirst(fields, FIELD_ALIASES.registrant_name),
        email: pickFirst(fields, FIELD_ALIASES.registrant_email),
        phone: pickFirst(fields, FIELD_ALIASES.registrant_phone),
      },
      admin: {
        name: pickFirst(fields, FIELD_ALIASES.admin_name),
        email: pickFirst(fields, FIELD_ALIASES.admin_email),
        phone: pickFirst(fields, FIELD_ALIASES.admin_phone),
      },
      tech: {
        name: pickFirst(fields, FIELD_ALIASES.tech_name),
        email: pickFirst(fields, FIELD_ALIASES.tech_email),
        phone: pickFirst(fields, FIELD_ALIASES.tech_phone),
      },
    },
    rdap_metadata: null,
  };
}

function detectPrivacy(snapshot) {
  const joined = [
    snapshot.registrar,
    snapshot.contacts.registrant.name,
    snapshot.contacts.admin.name,
    snapshot.contacts.tech.name,
    snapshot.raw_response || snapshot.raw_whois || '',
  ].join('\n').toLowerCase();

  const provider = PRIVACY_HINTS.find((hint) => joined.includes(hint)) || '';
  return {
    privacy_detected: Boolean(provider),
    privacy_provider: provider ? titleCase(provider) : '',
  };
}

function inferRegistration(rawWhois) {
  return !/no match for|not found|no entries found|status:\s+available|domain not found/i.test(rawWhois);
}

function getDaysUntil(dateString) {
  if (!dateString) return null;
  const timestamp = new Date(dateString).getTime();
  if (Number.isNaN(timestamp)) return null;
  return Math.ceil((timestamp - Date.now()) / 86400000);
}

function buildRiskSignals(snapshot) {
  const signals = [];

  if (typeof snapshot.days_until_expiry === 'number') {
    if (snapshot.days_until_expiry < 0) signals.push('Domain appears expired.');
    else if (snapshot.days_until_expiry <= 14) signals.push('Domain expires within 14 days.');
    else if (snapshot.days_until_expiry <= 30) signals.push('Domain expires within 30 days.');
  }

  if (snapshot.creation_date) {
    const daysSinceCreation = Math.floor((Date.now() - new Date(snapshot.creation_date).getTime()) / 86400000);
    if (daysSinceCreation >= 0 && daysSinceCreation <= 30) {
      signals.push('Domain was registered within the last 30 days.');
    }
  }

  if (snapshot.privacy_detected) signals.push('Registration data privacy or redaction is enabled.');
  if (snapshot.nameserver_match === false) signals.push(`${snapshot.data_source === 'rdap' ? 'RDAP' : 'WHOIS'} nameservers differ from live DNS NS records.`);
  if (snapshot.dnssec === 'unsigned') signals.push('No live DNSSEC DS record detected.');
  if (snapshot.dnssec === 'unknown') signals.push('Could not determine live DNSSEC state.');
  if (snapshot.status_codes.some((code) => /hold/i.test(code))) signals.push('Domain status indicates hold or suspension.');
  if (snapshot.status_codes.some((code) => /pendingdelete/i.test(code.replace(/\s+/g, '')))) signals.push('Domain is pending delete.');
  if (snapshot.status_codes.some((code) => /transferprohibited/i.test(code.replace(/\s+/g, '')))) signals.push('Domain transfer is restricted.');

  return [...new Set(signals)];
}

function execWhois(domain) {
  return new Promise((resolve, reject) => {
    const child = spawn(WHOIS_PATH, ['--', domain], { stdio: ['ignore', 'pipe', 'pipe'] });
    const stdoutChunks = [];
    const stderrChunks = [];
    let totalBytes = 0;
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill('SIGKILL');
        const error = new Error('WHOIS lookup timed out.');
        error.statusCode = 504;
        reject(error);
      }
    }, WHOIS_TIMEOUT_MS);

    const onData = (bucket) => (chunk) => {
      if (settled) return;
      totalBytes += chunk.length;
      if (totalBytes > WHOIS_OUTPUT_LIMIT_BYTES) {
        settled = true;
        child.kill('SIGKILL');
        const error = new Error('WHOIS response exceeded the output limit.');
        error.statusCode = 413;
        reject(error);
        return;
      }
      bucket.push(chunk);
    };

    child.stdout.on('data', onData(stdoutChunks));
    child.stderr.on('data', onData(stderrChunks));
    child.on('error', (error) => {
      clearTimeout(timer);
      if (settled) return;
      settled = true;
      reject(error);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (settled) return;
      settled = true;

      const stdout = Buffer.concat(stdoutChunks).toString('utf8').trim();
      const stderr = Buffer.concat(stderrChunks).toString('utf8').trim();
      if (code !== 0 && !stdout) {
        const error = new Error(stderr || `WHOIS command failed with exit code ${code}.`);
        error.statusCode = 502;
        reject(error);
        return;
      }
      resolve({ raw: stdout || stderr });
    });
  });
}

async function lookupDnsContext(domain) {
  const resolver = new Resolver();
  const result = {
    dns_nameservers: [],
    nameserver_match: null,
    nameserver_only_in_whois: [],
    nameserver_only_in_dns: [],
    dnssec: 'unknown',
  };

  try {
    const nameservers = await resolver.resolveNs(domain);
    result.dns_nameservers = [...new Set(nameservers.map(normalizeHostname).filter(Boolean))].sort();
  } catch {
    result.dns_nameservers = [];
  }

  try {
    const dsRecords = await resolver.resolve(domain, 'DS');
    result.dnssec = Array.isArray(dsRecords) && dsRecords.length > 0 ? 'signed' : 'unsigned';
  } catch (error) {
    if (error?.code === 'ENODATA' || error?.code === 'ENOTFOUND' || error?.code === 'ENODOMAIN' || error?.code === 'SERVFAIL') result.dnssec = 'unsigned';
    else result.dnssec = 'unknown';
  }

  return result;
}

function compareNameservers(registrationNameservers, dnsNameservers) {
  const registrationSet = new Set(registrationNameservers.map((value) => value.toLowerCase()));
  const dnsSet = new Set(dnsNameservers.map((value) => value.toLowerCase()));
  const nameserverOnlyInRegistration = [...registrationSet].filter((value) => !dnsSet.has(value)).sort();
  const nameserverOnlyInDns = [...dnsSet].filter((value) => !registrationSet.has(value)).sort();
  return {
    nameserver_match: nameserverOnlyInRegistration.length === 0 && nameserverOnlyInDns.length === 0,
    nameserver_only_in_whois: nameserverOnlyInRegistration,
    nameserver_only_in_dns: nameserverOnlyInDns,
  };
}

function normalizeHostname(value) {
  return String(value || '').trim().toLowerCase().replace(/\.$/, '');
}

async function fetchJsonWithTimeout(url, timeoutMs, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function normalizeBootstrapServices(payload) {
  const services = new Map();
  const entries = Array.isArray(payload?.services) ? payload.services : [];

  for (const entry of entries) {
    if (!Array.isArray(entry) || entry.length < 2) continue;
    const [tlds, baseUrls] = entry;
    if (!Array.isArray(tlds) || !Array.isArray(baseUrls) || baseUrls.length === 0) continue;

    const normalizedUrls = [...new Set(baseUrls
      .filter((value) => typeof value === 'string' && /^https?:\/\//i.test(value))
      .map((value) => value.replace(/\/+$/, '')))];

    if (normalizedUrls.length === 0) continue;

    for (const tld of tlds) {
      const normalizedTld = String(tld || '').trim().toLowerCase();
      if (!normalizedTld) continue;
      const existing = services.get(normalizedTld) || [];
      services.set(normalizedTld, [...new Set([...existing, ...normalizedUrls])]);
    }
  }

  return services;
}

async function ensureRdapBootstrap(options = {}) {
  const { force = false, logger } = options;
  const now = Date.now();
  if (!force && rdapBootstrapCache.services.size > 0 && now < rdapBootstrapCache.expiresAt) {
    return rdapBootstrapCache.services;
  }

  if (rdapBootstrapCache.inflight) return rdapBootstrapCache.inflight;

  rdapBootstrapCache.inflight = (async () => {
    const response = await fetchJsonWithTimeout(RDAP_BOOTSTRAP_URL, RDAP_REQUEST_TIMEOUT_MS, {
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const error = new Error(`RDAP bootstrap request failed with HTTP ${response.status}.`);
      error.statusCode = 502;
      throw error;
    }

    const payload = await response.json();
    const services = normalizeBootstrapServices(payload);
    if (services.size === 0) {
      const error = new Error('RDAP bootstrap payload did not contain usable services.');
      error.statusCode = 502;
      throw error;
    }

    rdapBootstrapCache.services = services;
    rdapBootstrapCache.fetchedAt = now;
    rdapBootstrapCache.expiresAt = now + RDAP_BOOTSTRAP_REFRESH_MS;
    logger?.info?.(`RDAP bootstrap refreshed with ${services.size} TLD mappings.`);
    return services;
  })().finally(() => {
    rdapBootstrapCache.inflight = null;
  });

  return rdapBootstrapCache.inflight;
}

function getRdapBaseUrls(domain) {
  const tld = domain.split('.').pop()?.toLowerCase() || '';
  return rdapBootstrapCache.services.get(tld) || [];
}

export function getRdapBootstrapStatus() {
  return {
    bootstrap_url: RDAP_BOOTSTRAP_URL,
    refresh_interval_ms: RDAP_BOOTSTRAP_REFRESH_MS,
    mappings_count: rdapBootstrapCache.services.size,
    last_refreshed_at: rdapBootstrapCache.fetchedAt ? new Date(rdapBootstrapCache.fetchedAt).toISOString() : '',
    next_refresh_at: rdapBootstrapCache.expiresAt ? new Date(rdapBootstrapCache.expiresAt).toISOString() : '',
  };
}

function collectEntities(entities, bucket = []) {
  for (const entity of Array.isArray(entities) ? entities : []) {
    bucket.push(entity);
    if (Array.isArray(entity?.entities) && entity.entities.length > 0) {
      collectEntities(entity.entities, bucket);
    }
  }
  return bucket;
}

function parseVcard(entity) {
  const cards = Array.isArray(entity?.vcardArray?.[1]) ? entity.vcardArray[1] : [];
  const output = {};

  for (const card of cards) {
    if (!Array.isArray(card) || card.length < 4) continue;
    const [name, , , rawValue] = card;
    const key = String(name || '').toLowerCase();
    if (!key) continue;

    if (Array.isArray(rawValue)) {
      const joined = rawValue.filter((value) => value != null).join(' ').trim();
      if (joined && !output[key]) output[key] = joined;
      continue;
    }

    const value = String(rawValue || '').trim();
    if (!value || output[key]) continue;
    output[key] = value.replace(/^mailto:/i, '').replace(/^tel:/i, '');
  }

  return output;
}

function extractContact(entity) {
  const vcard = parseVcard(entity);
  return {
    name: vcard.fn || vcard.org || entity?.handle || '',
    email: vcard.email || '',
    phone: vcard.tel || '',
  };
}

function findEntityByRoles(entities, roles) {
  const roleSet = new Set(roles.map((value) => value.toLowerCase()));
  return entities.find((entity) => Array.isArray(entity?.roles) && entity.roles.some((role) => roleSet.has(String(role).toLowerCase())));
}

function extractRegistrarIanaId(entity) {
  const publicIds = Array.isArray(entity?.publicIds) ? entity.publicIds : [];
  for (const item of publicIds) {
    const type = String(item?.type || '').toLowerCase();
    const identifier = String(item?.identifier || '').trim();
    if (identifier && (type.includes('iana') || type.includes('registrar id'))) return identifier;
  }
  return '';
}

function extractRdapDates(events) {
  const output = {
    creation_date: '',
    updated_date: '',
    expiry_date: '',
  };

  for (const event of Array.isArray(events) ? events : []) {
    const action = String(event?.eventAction || '').toLowerCase();
    const value = parseWhoisDate(event?.eventDate || '');
    if (!value) continue;
    if (!output.creation_date && action === 'registration') output.creation_date = value;
    if (!output.expiry_date && action === 'expiration') output.expiry_date = value;
    if (!output.updated_date && (action === 'last changed' || action === 'last update of rdap database')) output.updated_date = value;
  }

  return output;
}

function parseRdapPayload(domain, payload, baseUrl) {
  const allEntities = collectEntities(payload?.entities);
  const registrarEntity = findEntityByRoles(allEntities, ['registrar']);
  const registrantEntity = findEntityByRoles(allEntities, ['registrant']);
  const adminEntity = findEntityByRoles(allEntities, ['administrative', 'admin']);
  const techEntity = findEntityByRoles(allEntities, ['technical', 'tech']);
  const abuseEntity = findEntityByRoles(allEntities, ['abuse']);
  const dates = extractRdapDates(payload?.events);

  const statusCodes = [...new Set((Array.isArray(payload?.status) ? payload.status : [])
    .map(normalizeStatusCode)
    .filter(Boolean))];

  const nameservers = [...new Set((Array.isArray(payload?.nameservers) ? payload.nameservers : [])
    .map((entry) => normalizeHostname(entry?.ldhName || entry?.unicodeName || entry))
    .filter((value) => value.includes('.')))];

  const registrarContact = extractContact(registrarEntity);
  const abuseContact = extractContact(abuseEntity);

  return {
    registered: true,
    status_codes: statusCodes,
    status_labels: [...new Set(statusCodes.map(toStatusLabel).filter(Boolean))],
    registrar: registrarContact.name || payload?.port43 || '',
    registrar_iana_id: extractRegistrarIanaId(registrarEntity),
    abuse_email: abuseContact.email || registrarContact.email || '',
    abuse_phone: abuseContact.phone || registrarContact.phone || '',
    creation_date: dates.creation_date,
    updated_date: dates.updated_date,
    expiry_date: dates.expiry_date,
    dnssec: typeof payload?.secureDNS?.delegationSigned === 'boolean' ? (payload.secureDNS.delegationSigned ? 'signed' : 'unsigned') : '',
    nameservers,
    contacts: {
      registrant: extractContact(registrantEntity),
      admin: extractContact(adminEntity),
      tech: extractContact(techEntity),
    },
    rdap_metadata: {
      base_url: baseUrl,
      handle: typeof payload?.handle === 'string' ? payload.handle : '',
    },
  };
}

async function lookupRdap(domain) {
  await ensureRdapBootstrap();
  const baseUrls = getRdapBaseUrls(domain);
  if (baseUrls.length === 0) {
    const error = new Error(`No RDAP bootstrap entry found for ${domain}.`);
    error.statusCode = 404;
    throw error;
  }

  let lastError = null;

  for (const baseUrl of baseUrls) {
    const url = `${baseUrl}/domain/${encodeURIComponent(domain)}`;

    try {
      const response = await fetchJsonWithTimeout(url, RDAP_REQUEST_TIMEOUT_MS, {
        headers: { Accept: 'application/rdap+json, application/json' },
      });

      if (response.status === 404) {
        lastError = new Error(`RDAP domain record not found at ${baseUrl}.`);
        continue;
      }

      if (!response.ok) {
        lastError = new Error(`RDAP server returned HTTP ${response.status} for ${baseUrl}.`);
        continue;
      }

      const payload = await response.json();
      if (payload?.errorCode === 404) {
        lastError = new Error(`RDAP domain record not found at ${baseUrl}.`);
        continue;
      }

      if (payload?.objectClassName !== 'domain' && !payload?.ldhName && !payload?.unicodeName) {
        lastError = new Error(`RDAP server returned an unexpected payload for ${domain}.`);
        continue;
      }

      return {
        raw: JSON.stringify(payload, null, 2),
        parsed: parseRdapPayload(domain, payload, baseUrl),
      };
    } catch (error) {
      lastError = error;
    }
  }

  const fallbackError = lastError || new Error('RDAP lookup failed.');
  fallbackError.statusCode = fallbackError.statusCode || 502;
  throw fallbackError;
}

async function buildRegistrationSnapshot(domain, lookupResult, dataSource) {
  const checkedAtUtc = new Date().toISOString();
  const dnsContext = await lookupDnsContext(domain);
  const nameserverComparison = compareNameservers(lookupResult.parsed.nameservers, dnsContext.dns_nameservers);

  let dnssec = dnsContext.dnssec;
  if (dnssec === 'unknown' && lookupResult.parsed.dnssec) {
    const rawVal = String(lookupResult.parsed.dnssec).toLowerCase();
    if (rawVal.includes('unsigned')) dnssec = 'unsigned';
    else if (rawVal.includes('signed')) dnssec = 'signed';
  }

  const snapshot = {
    domain,
    query_domain: domain,
    data_source: dataSource,
    registered: lookupResult.parsed.registered,
    status_labels: lookupResult.parsed.status_labels,
    status_codes: lookupResult.parsed.status_codes,
    registrar: lookupResult.parsed.registrar,
    registrar_iana_id: lookupResult.parsed.registrar_iana_id,
    abuse_email: lookupResult.parsed.abuse_email,
    abuse_phone: lookupResult.parsed.abuse_phone,
    creation_date: lookupResult.parsed.creation_date,
    updated_date: lookupResult.parsed.updated_date,
    expiry_date: lookupResult.parsed.expiry_date,
    days_until_expiry: getDaysUntil(lookupResult.parsed.expiry_date),
    nameservers: lookupResult.parsed.nameservers,
    dns_nameservers: dnsContext.dns_nameservers,
    nameserver_match: nameserverComparison.nameserver_match,
    nameserver_only_in_whois: nameserverComparison.nameserver_only_in_whois,
    nameserver_only_in_dns: nameserverComparison.nameserver_only_in_dns,
    dnssec,
    privacy_detected: false,
    privacy_provider: '',
    contacts: lookupResult.parsed.contacts,
    risk_signals: [],
    raw_response: lookupResult.raw,
    raw_whois: dataSource === 'whois' ? lookupResult.raw : '',
    rdap_metadata: lookupResult.parsed.rdap_metadata,
    checked_at_utc: checkedAtUtc,
  };

  const privacy = detectPrivacy(snapshot);
  snapshot.privacy_detected = privacy.privacy_detected;
  snapshot.privacy_provider = privacy.privacy_provider;
  snapshot.risk_signals = buildRiskSignals(snapshot);

  if (!snapshot.registered && snapshot.risk_signals.length === 0) {
    snapshot.risk_signals.push('Domain appears unregistered or registration data did not return an active record.');
  }

  return snapshot;
}

export async function buildWhoisSnapshot(inputDomain, options = {}) {
  const domain = normalizeDomain(inputDomain);
  if (!isValidDomain(domain)) {
    const error = new Error('Invalid domain name.');
    error.statusCode = 400;
    throw error;
  }

  const logger = options.logger;

  try {
    const rdapResult = await lookupRdap(domain);
    return await buildRegistrationSnapshot(domain, rdapResult, 'rdap');
  } catch (rdapError) {
    logger?.debug?.(`RDAP lookup failed for ${domain}; falling back to WHOIS. ${rdapError.message}`);
  }

  const whoisResponse = await execWhois(domain);
  const rawWhois = whoisResponse.raw || '';
  if (!rawWhois) {
    const error = new Error('WHOIS server returned no data.');
    error.statusCode = 502;
    throw error;
  }

  const parsed = parseWhoisFields(rawWhois);
  return buildRegistrationSnapshot(domain, { raw: rawWhois, parsed }, 'whois');
}

export default async function whoisRoutes(fastify) {
  try {
    await ensureRdapBootstrap({ logger: fastify.log });
  } catch (error) {
    fastify.log.warn(`Initial RDAP bootstrap refresh failed: ${error.message}`);
  }

  if (!rdapBootstrapCache.refreshHandle) {
    rdapBootstrapCache.refreshHandle = setInterval(() => {
      void ensureRdapBootstrap({ force: true, logger: fastify.log }).catch((error) => {
        fastify.log.warn(`Scheduled RDAP bootstrap refresh failed: ${error.message}`);
      });
    }, RDAP_BOOTSTRAP_REFRESH_MS);

    if (typeof rdapBootstrapCache.refreshHandle.unref === 'function') {
      rdapBootstrapCache.refreshHandle.unref();
    }
  }

  fastify.addHook('onClose', async () => {
    if (rdapBootstrapCache.refreshHandle) {
      clearInterval(rdapBootstrapCache.refreshHandle);
      rdapBootstrapCache.refreshHandle = null;
    }
  });

  fastify.post('/whois', async (request, reply) => {
    try {
      return await buildWhoisSnapshot(request.body?.domain || '', { logger: fastify.log });
    } catch (error) {
      return reply.code(error.statusCode || 500).send({
        error: error.message || 'WHOIS lookup failed.',
        raw_response: '',
        raw_whois: '',
      });
    }
  });
}
