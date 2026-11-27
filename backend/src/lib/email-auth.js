/**
 * Email authentication analysis: MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI.
 *
 * Everything here takes a `dns` client (see dns-client.js) so tests can pass a
 * fake one. Each section returns `{ status, findings, ... }` where status is
 * pass | warn | fail | missing | error, and findings use the same shape the
 * frontend renders: { severity: critical | warning | info | ok, title, detail }.
 */

import net from 'node:net';
import { createPublicKey } from 'node:crypto';
import { mapLimit } from './dns-client.js';

export const SPF_LOOKUP_LIMIT = 10;

// Tried when the visitor does not know the selector. DKIM selectors cannot be
// listed from DNS, so this is a best-effort guess at the common ones.
export const COMMON_DKIM_SELECTORS = [
  'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2',
  'dkim', 'mail', 'smtp', 'key1', 'key2', 'mandrill', 'mxvault', 'sig1',
  'fm1', 'fm2', 'fm3', 'protonmail', 'protonmail2', 'protonmail3', 'zoho',
  'zmail', 'amazonses', 'pm', 'krs', 'mailjet', 'cm', 'mta', 'selector', 'dk',
  'email', 'x', 'm1', 'smtpapi', 'everlytickey1', 'everlytickey2', 'turbo-smtp',
];

const MX_PROVIDERS = [
  ['google.com', 'Google Workspace'], ['googlemail.com', 'Google Workspace'],
  ['outlook.com', 'Microsoft 365'], ['protection.outlook.com', 'Microsoft 365'],
  ['protonmail.ch', 'Proton Mail'], ['zoho.com', 'Zoho Mail'], ['zoho.eu', 'Zoho Mail'],
  ['mimecast.com', 'Mimecast'], ['pphosted.com', 'Proofpoint'], ['ppe-hosted.com', 'Proofpoint Essentials'],
  ['barracudanetworks.com', 'Barracuda'], ['mailgun.org', 'Mailgun'], ['sendgrid.net', 'SendGrid'],
  ['amazonaws.com', 'Amazon SES'], ['secureserver.net', 'GoDaddy'], ['yandex.net', 'Yandex'],
  ['messagingengine.com', 'Fastmail'], ['icloud.com', 'iCloud Mail'], ['mx.cloudflare.net', 'Cloudflare Email Routing'],
  ['emailsrvr.com', 'Rackspace Email'], ['ovh.net', 'OVH'], ['gandi.net', 'Gandi'], ['migadu.com', 'Migadu'],
];

const finding = (severity, title, detail = '') => ({ severity, title, detail });

function worstStatus(findings, fallback = 'pass') {
  if (findings.some(f => f.severity === 'critical')) return 'fail';
  if (findings.some(f => f.severity === 'warning')) return 'warn';
  return fallback;
}

/** Splits `k=v; k2=v2` records (DMARC, DKIM, MTA-STS, TLS-RPT, BIMI) into an ordered list of [key, value]. */
export function parseTagList(record) {
  return String(record)
    .split(';')
    .map(part => part.trim())
    .filter(Boolean)
    .map(part => {
      const eq = part.indexOf('=');
      return eq === -1 ? [part.toLowerCase(), ''] : [part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).trim()];
    });
}

// ─── MX ──────────────────────────────────────────────────

export async function analyzeMx(domain, dns) {
  const answer = await dns.mx(domain);
  const findings = [];
  if (answer.status === 'error') {
    return { status: 'error', records: [], provider: '', null_mx: false, findings: [finding('warning', 'MX lookup failed', `The resolver returned ${answer.error}.`)] };
  }

  const sorted = [...answer.records].sort((a, b) => a.priority - b.priority || a.exchange.localeCompare(b.exchange));
  const nullMx = sorted.length === 1 && (sorted[0].exchange === '' || sorted[0].exchange === '.');
  if (nullMx) {
    return {
      status: 'warn', records: [], provider: '', null_mx: true,
      findings: [finding('info', 'Domain does not accept email', 'A null MX record (priority 0, target ".") says this domain receives no mail.')],
    };
  }

  if (sorted.length === 0) {
    const fallback = await dns.a(domain);
    findings.push(fallback.status === 'ok'
      ? finding('warning', 'No MX records', 'Mail servers will fall back to the domain\'s A record. Publish MX records, or a null MX if the domain should not receive mail.')
      : finding('critical', 'No MX records and no A record', 'This domain cannot receive email.'));
    return { status: worstStatus(findings), records: [], provider: '', null_mx: false, findings };
  }

  const records = await mapLimit(sorted.slice(0, 8), 4, async record => {
    const exchange = record.exchange.toLowerCase().replace(/\.$/, '');
    if (net.isIP(exchange)) return { exchange, priority: record.priority, addresses: [exchange], ip_literal: true };
    const [v4, v6] = await Promise.all([dns.a(exchange), dns.aaaa(exchange)]);
    return { exchange, priority: record.priority, addresses: [...v4.records, ...v6.records].slice(0, 6), resolves: v4.status === 'ok' || v6.status === 'ok' };
  });

  for (const record of records) {
    if (record.ip_literal) findings.push(finding('critical', `MX points to an IP address (${record.exchange})`, 'An MX target must be a hostname. Many servers refuse to deliver to an IP literal.'));
    else if (!record.resolves) findings.push(finding('critical', `MX host ${record.exchange} does not resolve`, 'Mail sent to this host will fail or fall through to the next MX.'));
  }
  if (records.length === 1) findings.push(finding('info', 'Single MX record', 'There is no backup mail server. That is fine when the provider handles redundancy behind one name.'));

  const provider = MX_PROVIDERS.find(([suffix]) => records.some(r => r.exchange === suffix || r.exchange.endsWith(`.${suffix}`)))?.[1] || '';
  if (findings.every(f => f.severity === 'info')) findings.unshift(finding('ok', `${records.length} MX record${records.length === 1 ? '' : 's'} found`, provider ? `Mail is handled by ${provider}.` : ''));
  return { status: worstStatus(findings), records, provider, null_mx: false, findings };
}

// ─── SPF ─────────────────────────────────────────────────

const SPF_MECHANISMS = new Set(['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists']);
const SPF_LOOKUP_TERMS = new Set(['include', 'a', 'mx', 'ptr', 'exists', 'redirect']);
const QUALIFIER_NAMES = { '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' };

export function isSpfRecord(txt) {
  return /^v=spf1(\s|$)/i.test(String(txt).trim());
}

/** Parses one SPF record into terms. Does no DNS. */
export function parseSpf(record) {
  const terms = [];
  const errors = [];
  const parts = String(record).trim().split(/\s+/).slice(1);

  for (const raw of parts) {
    const modifier = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(raw);
    if (modifier) {
      terms.push({ raw, kind: 'modifier', name: modifier[1].toLowerCase(), value: modifier[2], qualifier: '' });
      continue;
    }
    const match = /^([+\-~?]?)([a-z0-9]+)(?:([:/])(.*))?$/i.exec(raw);
    if (!match) {
      errors.push(`"${raw}" is not a valid SPF term.`);
      continue;
    }
    const name = match[2].toLowerCase();
    const value = match[3] === '/' ? `/${match[4]}` : (match[4] ?? '');
    if (!SPF_MECHANISMS.has(name)) {
      errors.push(`"${raw}" uses an unknown mechanism "${name}".`);
      continue;
    }
    if (name === 'ip4' || name === 'ip6') {
      const [address, prefix] = value.split('/');
      const family = name === 'ip4' ? 4 : 6;
      const max = family === 4 ? 32 : 128;
      const badPrefix = prefix !== undefined && !(/^\d+$/.test(prefix) && Number(prefix) <= max);
      if (net.isIP(address) !== family || badPrefix) errors.push(`"${raw}" is not a valid ${name} network.`);
    }
    if ((name === 'include' || name === 'exists') && !value) errors.push(`"${raw}" needs a domain.`);
    terms.push({ raw, kind: 'mechanism', name, value, qualifier: match[1] || '+' });
  }
  return { terms, errors };
}

async function fetchSpfRecords(domain, dns) {
  const answer = await dns.txt(domain);
  return { answer, records: answer.records.filter(isSpfRecord) };
}

/**
 * Fetches the domain's SPF record and walks every include and redirect to
 * count DNS lookups the way a receiving server does (RFC 7208 section 4.6.4:
 * at most 10, or the result is a permanent error for every message).
 */
export async function analyzeSpf(domain, dns, { maxFetches = 40 } = {}) {
  const findings = [];
  const { answer, records } = await fetchSpfRecords(domain, dns);

  if (answer.status === 'error') {
    return { status: 'error', record: '', records: [], lookups: 0, lookup_limit: SPF_LOOKUP_LIMIT, all: '', terms: [], includes: [], findings: [finding('warning', 'SPF lookup failed', `The resolver returned ${answer.error}.`)] };
  }
  if (records.length === 0) {
    return {
      status: 'missing', record: '', records: [], lookups: 0, lookup_limit: SPF_LOOKUP_LIMIT, all: '', terms: [], includes: [],
      findings: [finding('critical', 'No SPF record', 'Publish a TXT record starting with v=spf1 that lists the servers allowed to send mail for this domain. Without it, anyone can use the domain as a sender and receivers have nothing to check.')],
    };
  }
  if (records.length > 1) {
    findings.push(finding('critical', `${records.length} SPF records found`, 'A domain must have exactly one SPF record. With more than one, receivers return a permanent error and SPF fails. Merge them into a single record.'));
  }

  const record = records[0];
  const { terms, errors } = parseSpf(record);
  for (const message of errors) findings.push(finding('critical', 'SPF syntax error', message));

  let lookups = 0;
  let fetches = 0;
  let truncated = false;
  const visited = new Set([domain]);

  async function walk(parentTerms, depth) {
    const children = [];
    for (const term of parentTerms) {
      if (!SPF_LOOKUP_TERMS.has(term.name)) continue;
      lookups += 1;
      if (term.name !== 'include' && term.name !== 'redirect') continue;

      const target = term.value.toLowerCase().replace(/\.$/, '');
      const node = { type: term.name, domain: target, record: '', lookups: 0, children: [], error: '' };
      children.push(node);
      if (!target) continue;
      if (target.includes('%')) { node.error = 'Uses a macro, not expanded here.'; continue; }
      if (visited.has(target)) { node.error = 'Loop: this domain is already included.'; findings.push(finding('critical', `SPF include loop at ${target}`, 'The record includes itself, directly or through another record.')); continue; }
      if (depth >= 10 || fetches >= maxFetches) { truncated = true; node.error = 'Not followed (too deep).'; continue; }

      visited.add(target);
      fetches += 1;
      const before = lookups;
      const fetched = await fetchSpfRecords(target, dns);
      if (fetched.answer.status === 'error') {
        node.error = `Lookup failed (${fetched.answer.error}).`;
        findings.push(finding('warning', `Could not read the SPF record of ${target}`, 'Its DNS lookups are not counted, so the total may be higher.'));
        continue;
      }
      if (fetched.records.length === 0) {
        node.error = 'No SPF record.';
        findings.push(finding('critical', `${term.name === 'include' ? 'Included' : 'Redirect'} domain ${target} has no SPF record`, 'Receivers treat this as a permanent error, so SPF fails for every message. Remove the term or fix the target.'));
        continue;
      }
      node.record = fetched.records[0];
      node.children = await walk(parseSpf(node.record).terms, depth + 1);
      node.lookups = lookups - before;
    }
    return children;
  }

  const includes = await walk(terms, 0);

  if (lookups > SPF_LOOKUP_LIMIT) {
    findings.push(finding('critical', `SPF needs ${lookups} DNS lookups, the limit is ${SPF_LOOKUP_LIMIT}`, 'Receivers stop at 10 lookups and return a permanent error, so SPF fails for every message. Remove unused includes or replace them with ip4/ip6 ranges.'));
  } else if (lookups >= 8) {
    findings.push(finding('warning', `SPF uses ${lookups} of ${SPF_LOOKUP_LIMIT} DNS lookups`, 'One more include from a provider can push it over the limit.'));
  }
  if (truncated) findings.push(finding('warning', 'Not every include was followed', 'The include tree is very deep. The lookup count shown is a minimum.'));

  const allTerms = terms.filter(term => term.name === 'all');
  const redirect = terms.find(term => term.name === 'redirect');
  const all = allTerms[0]?.qualifier || '';
  if (all === '+') findings.push(finding('critical', 'SPF ends with +all', 'This authorizes every server on the internet to send as this domain. Use -all or ~all.'));
  else if (all === '?') findings.push(finding('warning', 'SPF ends with ?all (neutral)', 'Receivers get no instruction for unlisted servers. Use ~all while testing, then -all.'));
  else if (all === '~') findings.push(finding('info', 'SPF ends with ~all (soft fail)', 'Mail from unlisted servers is accepted but marked. Move to -all once every sender is listed.'));
  else if (!all && !redirect) findings.push(finding('warning', 'SPF has no "all" term', 'Without it the result for unlisted servers is neutral. End the record with -all or ~all.'));

  const allIndex = terms.findIndex(term => term.name === 'all');
  if (allIndex !== -1 && terms.slice(allIndex + 1).some(term => term.kind === 'mechanism')) {
    findings.push(finding('warning', 'Terms after "all" are ignored', 'Evaluation stops at the all mechanism. Move it to the end.'));
  }
  if (all && redirect) findings.push(finding('info', 'redirect= is ignored because the record has an "all" term', ''));
  if (terms.some(term => term.name === 'ptr')) findings.push(finding('warning', 'SPF uses the ptr mechanism', 'ptr is slow, unreliable and deprecated by RFC 7208. Replace it with ip4, ip6 or a.'));
  if (record.length > 450) findings.push(finding('info', `SPF record is ${record.length} characters long`, 'Long records can exceed the size of a UDP DNS reply. Keep it short where possible.'));

  const status = worstStatus(findings);
  if (status === 'pass') findings.unshift(finding('ok', 'SPF record is valid', `${lookups} of ${SPF_LOOKUP_LIMIT} DNS lookups used${all ? `, unlisted servers get ${QUALIFIER_NAMES[all]}` : ''}.`));
  return { status, record, records, lookups, lookup_limit: SPF_LOOKUP_LIMIT, all, terms, includes, findings };
}

// ─── DMARC ───────────────────────────────────────────────

export function isDmarcRecord(txt) {
  return /^v\s*=\s*DMARC1\s*(;|$)/i.test(String(txt).trim());
}

function mailtoDomains(value) {
  return String(value || '')
    .split(',')
    .map(uri => /^mailto:[^@\s]+@([^!\s]+)/i.exec(uri.trim())?.[1]?.toLowerCase())
    .filter(Boolean);
}

export async function analyzeDmarc(domain, dns) {
  const findings = [];
  // A subdomain without its own record inherits the policy of a parent, so
  // walk up until one is found. Stops at two labels: a public-suffix list is
  // not available here, and two labels is the organizational domain for the
  // common cases.
  const labels = domain.split('.');
  const candidates = [];
  for (let i = 0; i <= labels.length - 2 && candidates.length < 5; i++) candidates.push(labels.slice(i).join('.'));

  let record = '';
  let sourceDomain = '';
  let lookupError = '';
  let multiple = 0;
  for (const candidate of candidates) {
    const answer = await dns.txt(`_dmarc.${candidate}`);
    if (answer.status === 'error') { lookupError = answer.error; continue; }
    const matches = answer.records.filter(isDmarcRecord);
    if (matches.length > 0) { record = matches[0]; sourceDomain = candidate; multiple = matches.length; break; }
  }

  if (!record) {
    if (lookupError) return { status: 'error', record: '', source_domain: '', inherited: false, tags: {}, policy: '', findings: [finding('warning', 'DMARC lookup failed', `The resolver returned ${lookupError}.`)] };
    return {
      status: 'missing', record: '', source_domain: '', inherited: false, tags: {}, policy: '',
      findings: [finding('critical', 'No DMARC record', `Publish a TXT record at _dmarc.${domain}. Start with "v=DMARC1; p=none; rua=mailto:you@${domain}" to collect reports, then move to quarantine and reject. Gmail and Yahoo require DMARC from bulk senders.`)],
    };
  }

  const inherited = sourceDomain !== domain;
  if (multiple > 1) findings.push(finding('critical', `${multiple} DMARC records found`, 'Receivers ignore DMARC when more than one record exists. Keep exactly one.'));

  const tags = Object.fromEntries(parseTagList(record));
  const policy = (tags.p || '').toLowerCase();
  const subPolicy = (tags.sp || '').toLowerCase();
  const effective = inherited ? (subPolicy || policy) : policy;
  const valid = ['none', 'quarantine', 'reject'];

  if (inherited) findings.push(finding('info', `Policy inherited from ${sourceDomain}`, `${domain} has no DMARC record of its own, so the ${subPolicy ? 'sp=' : 'p='} policy of ${sourceDomain} applies.`));

  if (!valid.includes(policy)) {
    findings.push(finding('critical', policy ? `Invalid DMARC policy "${tags.p}"` : 'DMARC record has no p= tag', 'p must be none, quarantine or reject.'));
  } else if (effective === 'none') {
    findings.push(finding('warning', 'DMARC policy is none (monitoring only)', 'Receivers report failures but still deliver spoofed mail. Move to quarantine, then reject, once the reports show your real senders passing.'));
  } else if (effective === 'quarantine') {
    findings.push(finding('info', 'DMARC policy is quarantine', 'Failing mail goes to spam. reject is the strongest setting.'));
  }
  if (subPolicy && !valid.includes(subPolicy)) findings.push(finding('critical', `Invalid subdomain policy "${tags.sp}"`, 'sp must be none, quarantine or reject.'));
  if (!inherited && valid.includes(policy) && policy !== 'none' && subPolicy === 'none') {
    findings.push(finding('warning', 'Subdomains are not protected (sp=none)', 'Attackers can spoof any subdomain. Remove sp=none unless you need it.'));
  }

  if (tags.pct !== undefined) {
    const pct = Number(tags.pct);
    if (!/^\d+$/.test(tags.pct) || pct > 100) findings.push(finding('critical', `Invalid pct value "${tags.pct}"`, 'pct must be a number from 0 to 100.'));
    else if (pct < 100 && effective !== 'none') findings.push(finding('warning', `Policy applies to ${pct}% of failing mail`, 'The rest is treated one level more leniently. Raise pct to 100 when you are confident.'));
  }

  if (!tags.rua) {
    findings.push(finding('warning', 'No aggregate report address (rua)', 'Without rua you receive no reports and cannot see who sends mail as your domain.'));
  } else {
    const external = [...new Set(mailtoDomains(tags.rua))].filter(d => d !== sourceDomain && !d.endsWith(`.${sourceDomain}`) && !sourceDomain.endsWith(`.${d}`));
    for (const reportDomain of external.slice(0, 3)) {
      const auth = await dns.txt(`${sourceDomain}._report._dmarc.${reportDomain}`);
      if (auth.status !== 'error' && !auth.records.some(isDmarcRecord)) {
        findings.push(finding('warning', `${reportDomain} has not authorized reports for ${sourceDomain}`, `Reports sent to another domain need a TXT record "v=DMARC1" at ${sourceDomain}._report._dmarc.${reportDomain}. Without it many receivers do not send them.`));
      }
    }
    if (mailtoDomains(tags.rua).length === 0) findings.push(finding('warning', 'rua has no valid mailto: address', 'Use rua=mailto:address@example.com.'));
  }
  for (const key of ['adkim', 'aspf']) {
    if (tags[key] !== undefined && !['r', 's'].includes(tags[key].toLowerCase())) findings.push(finding('critical', `Invalid ${key} value "${tags[key]}"`, `${key} must be r (relaxed) or s (strict).`));
  }

  const status = worstStatus(findings);
  if (status === 'pass') findings.unshift(finding('ok', 'DMARC record is valid', `Policy is ${effective}: receivers are told to act on mail that fails SPF and DKIM alignment.`));
  return { status, record, source_domain: sourceDomain, inherited, tags, policy: effective, findings };
}

// ─── DKIM ────────────────────────────────────────────────

export function isSelector(value) {
  return typeof value === 'string' && /^[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?$/i.test(value);
}

/** Parses a DKIM key record. Returns null when the TXT value is not a DKIM key. */
export function parseDkimKey(record) {
  const tags = Object.fromEntries(parseTagList(record));
  if (tags.p === undefined) return null;
  if (tags.v !== undefined && tags.v.toUpperCase() !== 'DKIM1') return null;

  const keyType = (tags.k || 'rsa').toLowerCase();
  const publicKey = tags.p.replace(/\s+/g, '');
  const flags = (tags.t || '').toLowerCase().split(':').map(flag => flag.trim()).filter(Boolean);
  let bits = 0;
  let invalid = false;

  if (publicKey) {
    const der = Buffer.from(publicKey, 'base64');
    if (keyType === 'ed25519') {
      bits = der.length === 32 ? 256 : 0;
      invalid = der.length !== 32;
    } else {
      try {
        bits = createPublicKey({ key: der, format: 'der', type: 'spki' }).asymmetricKeyDetails?.modulusLength || 0;
      } catch {
        invalid = true;
      }
    }
  }
  return { key_type: keyType, key_bits: bits, revoked: publicKey === '', invalid, testing: flags.includes('y'), flags };
}

export async function analyzeDkim(domain, dns, extraSelectors = []) {
  const requested = [...new Set(extraSelectors.map(s => String(s).trim().toLowerCase()).filter(isSelector))].slice(0, 10);
  const selectors = [...new Set([...requested, ...COMMON_DKIM_SELECTORS])];
  const findings = [];
  let errors = 0;

  const results = await mapLimit(selectors, 12, async selector => {
    const answer = await dns.txt(`${selector}._domainkey.${domain}`);
    if (answer.status === 'error') { errors += 1; return null; }
    for (const txt of answer.records) {
      const key = parseDkimKey(txt);
      if (key) return { selector, ...key, record: txt.length > 120 ? `${txt.slice(0, 117)}...` : txt };
    }
    return null;
  });
  const found = results.filter(Boolean);

  for (const key of found) {
    const name = `Selector "${key.selector}"`;
    if (key.revoked) findings.push(finding('info', `${name} is revoked`, 'The key record has an empty p= value, which tells receivers this key is no longer valid.'));
    else if (key.invalid) findings.push(finding('critical', `${name} has an unreadable public key`, 'The p= value is not a valid key. Signatures made with this selector fail.'));
    else if (key.key_type === 'rsa' && key.key_bits < 1024) findings.push(finding('critical', `${name} uses a ${key.key_bits}-bit RSA key`, 'Keys under 1024 bits are rejected by receivers. Rotate to 2048 bits.'));
    else if (key.key_type === 'rsa' && key.key_bits < 2048) findings.push(finding('warning', `${name} uses a ${key.key_bits}-bit RSA key`, '1024-bit keys still work but 2048 bits is the current recommendation.'));
    else findings.push(finding('ok', `${name} has a valid ${key.key_type === 'rsa' ? `${key.key_bits}-bit RSA` : 'Ed25519'} key`, ''));
    if (key.testing && !key.revoked) findings.push(finding('warning', `${name} is in test mode (t=y)`, 'Receivers may ignore failures for this key. Remove t=y when DKIM is working.'));
  }

  for (const selector of requested) {
    if (!found.some(key => key.selector === selector)) findings.push(finding('warning', `No DKIM key at selector "${selector}"`, `Nothing was found at ${selector}._domainkey.${domain}.`));
  }

  if (found.length === 0) {
    findings.push(finding('info', 'No DKIM key found at the common selectors', `Selectors cannot be listed from DNS and ${selectors.length} common names were tried. Find yours in the DKIM-Signature header of a sent message (the s= value) and enter it above.`));
    if (errors === selectors.length) return { status: 'error', selectors_checked: selectors.length, found, findings: [finding('warning', 'DKIM lookups failed', 'The resolver did not answer.')] };
    return { status: 'missing', selectors_checked: selectors.length, found, findings };
  }
  return { status: worstStatus(findings), selectors_checked: selectors.length, found, findings };
}

// ─── MTA-STS, TLS-RPT, BIMI ──────────────────────────────

export function parseMtaStsPolicy(text) {
  const policy = { version: '', mode: '', mx: [], max_age: null };
  for (const line of String(text).split(/\r?\n/)) {
    const match = /^\s*([a-z_]+)\s*:\s*(.*?)\s*$/i.exec(line);
    if (!match) continue;
    const key = match[1].toLowerCase();
    if (key === 'version') policy.version = match[2];
    else if (key === 'mode') policy.mode = match[2].toLowerCase();
    else if (key === 'mx') policy.mx.push(match[2].toLowerCase());
    else if (key === 'max_age' && /^\d+$/.test(match[2])) policy.max_age = Number(match[2]);
  }
  return policy;
}

/** `fetchPolicy(url)` resolves to the policy file text, or throws. */
export async function analyzeMtaSts(domain, dns, fetchPolicy) {
  const answer = await dns.txt(`_mta-sts.${domain}`);
  if (answer.status === 'error') return { status: 'error', record: '', policy: null, findings: [finding('info', 'MTA-STS lookup failed', `The resolver returned ${answer.error}.`)] };
  const record = answer.records.find(txt => /^v=STSv1\s*(;|$)/i.test(txt.trim())) || '';
  if (!record) {
    return { status: 'missing', record: '', policy: null, findings: [finding('info', 'No MTA-STS policy', 'Optional. MTA-STS makes sending servers require TLS when they deliver to you, which stops downgrade attacks.')] };
  }

  const findings = [];
  let policy = null;
  if (!Object.fromEntries(parseTagList(record)).id) findings.push(finding('warning', 'MTA-STS record has no id', 'Senders use the id to notice a changed policy.'));
  try {
    policy = parseMtaStsPolicy(await fetchPolicy(`https://mta-sts.${domain}/.well-known/mta-sts.txt`));
    if (policy.version !== 'STSv1') findings.push(finding('warning', 'MTA-STS policy file is missing "version: STSv1"', ''));
    if (!['enforce', 'testing', 'none'].includes(policy.mode)) findings.push(finding('warning', `MTA-STS policy has an invalid mode "${policy.mode || 'missing'}"`, 'mode must be enforce, testing or none.'));
    else if (policy.mode !== 'enforce') findings.push(finding('info', `MTA-STS mode is ${policy.mode}`, 'Senders do not require TLS yet. Switch to enforce when the reports are clean.'));
    if (policy.mx.length === 0 && policy.mode !== 'none') findings.push(finding('warning', 'MTA-STS policy lists no mx hosts', 'Senders in enforce mode would refuse every mail server.'));
  } catch (err) {
    findings.push(finding('warning', 'MTA-STS policy file could not be fetched', `The TXT record exists but https://mta-sts.${domain}/.well-known/mta-sts.txt did not load (${err?.message || 'request failed'}). Senders ignore MTA-STS until it does.`));
  }
  const status = worstStatus(findings);
  if (status === 'pass' && policy?.mode === 'enforce') findings.unshift(finding('ok', 'MTA-STS is enforced', `Policy covers ${policy.mx.join(', ')}.`));
  return { status, record, policy, findings };
}

export async function analyzeTlsRpt(domain, dns) {
  const answer = await dns.txt(`_smtp._tls.${domain}`);
  if (answer.status === 'error') return { status: 'error', record: '', findings: [finding('info', 'TLS-RPT lookup failed', `The resolver returned ${answer.error}.`)] };
  const record = answer.records.find(txt => /^v=TLSRPTv1\s*(;|$)/i.test(txt.trim())) || '';
  if (!record) return { status: 'missing', record: '', findings: [finding('info', 'No TLS reporting record', 'Optional. A TLS-RPT record gets you reports when senders cannot deliver over TLS.')] };
  const rua = Object.fromEntries(parseTagList(record)).rua || '';
  if (!/^(mailto:|https:)/i.test(rua)) return { status: 'warn', record, findings: [finding('warning', 'TLS-RPT record has no valid rua', 'rua must be a mailto: or https: address.')] };
  return { status: 'pass', record, findings: [finding('ok', 'TLS reporting is set up', `Reports go to ${rua}.`)] };
}

export async function analyzeBimi(domain, dns, dmarcPolicy) {
  const answer = await dns.txt(`default._bimi.${domain}`);
  if (answer.status === 'error') return { status: 'error', record: '', findings: [finding('info', 'BIMI lookup failed', `The resolver returned ${answer.error}.`)] };
  const record = answer.records.find(txt => /^v=BIMI1\s*(;|$)/i.test(txt.trim())) || '';
  if (!record) return { status: 'missing', record: '', findings: [finding('info', 'No BIMI record', 'Optional. BIMI shows your logo next to messages in supporting mail clients.')] };

  const tags = Object.fromEntries(parseTagList(record));
  const findings = [];
  if (!tags.l) findings.push(finding('warning', 'BIMI record has no logo (l=)', 'l must be an https URL to an SVG Tiny PS file.'));
  else if (!/^https:\/\//i.test(tags.l)) findings.push(finding('warning', 'BIMI logo URL is not https', ''));
  if (!tags.a) findings.push(finding('info', 'BIMI record has no certificate (a=)', 'Gmail and Apple Mail only show the logo with a verified mark certificate.'));
  if (dmarcPolicy !== 'quarantine' && dmarcPolicy !== 'reject') findings.push(finding('warning', 'BIMI needs an enforced DMARC policy', 'Mail clients ignore BIMI unless DMARC is quarantine or reject.'));
  const status = worstStatus(findings);
  if (status === 'pass') findings.unshift(finding('ok', 'BIMI record found', ''));
  return { status, record, findings };
}

// ─── Combined ────────────────────────────────────────────

export async function analyzeEmailAuth(domain, { dns, selectors = [], fetchPolicy }) {
  const [mx, spf, dmarc, dkim, mtaSts, tlsRpt] = await Promise.all([
    analyzeMx(domain, dns),
    analyzeSpf(domain, dns),
    analyzeDmarc(domain, dns),
    analyzeDkim(domain, dns, selectors),
    analyzeMtaSts(domain, dns, fetchPolicy),
    analyzeTlsRpt(domain, dns),
  ]);
  const bimi = await analyzeBimi(domain, dns, dmarc.policy);

  const sections = { mx, spf, dkim, dmarc, mta_sts: mtaSts, tls_rpt: tlsRpt, bimi };
  const summary = { critical: 0, warning: 0, info: 0, ok: 0 };
  for (const section of Object.values(sections)) for (const item of section.findings) summary[item.severity] += 1;

  return { domain, checked_at_utc: new Date().toISOString(), ...sections, summary };
}
