/**
 * DNS blacklist (DNSBL) checks.
 *
 * A DNSBL is queried by reversing the IP and appending the list's zone:
 * 192.0.2.10 on zen.spamhaus.org is 10.2.0.192.zen.spamhaus.org. An A record
 * in 127.0.0.0/8 means "listed"; NXDOMAIN means "not listed".
 *
 * Lists die, start answering everything, or refuse queries from shared
 * resolvers, and each of those would produce a wrong answer. So before a list
 * is trusted it has to pass the self-test RFC 5782 requires of every list:
 * 127.0.0.2 must be listed and 127.0.0.1 must not be. A list that fails is
 * reported as "not checked", never as "clean".
 */

import net from 'node:net';
import { mapLimit } from './dns-client.js';

/**
 * `codes` maps a return address to what it means. `policy: true` marks
 * entries that are not spam listings (for example ranges an ISP says should
 * not send mail directly).
 */
export const IP_LISTS = [
  {
    zone: 'zen.spamhaus.org', name: 'Spamhaus ZEN', ipv6: true, url: 'https://check.spamhaus.org/',
    codes: {
      '127.0.0.2': { label: 'SBL (spam source)' }, '127.0.0.3': { label: 'SBL CSS (spam source)' },
      '127.0.0.4': { label: 'XBL (infected or hijacked host)' }, '127.0.0.9': { label: 'DROP (hijacked network)' },
      '127.0.0.10': { label: 'PBL (ISP says this range should not send mail directly)', policy: true },
      '127.0.0.11': { label: 'PBL (range should not send mail directly)', policy: true },
    },
  },
  { zone: 'bl.spamcop.net', name: 'SpamCop', url: 'https://www.spamcop.net/bl.shtml' },
  { zone: 'b.barracudacentral.org', name: 'Barracuda', url: 'https://www.barracudacentral.org/lookups' },
  { zone: 'psbl.surriel.com', name: 'PSBL', url: 'https://psbl.org/' },
  { zone: 'bl.mailspike.net', name: 'Mailspike BL', url: 'https://www.mailspike.org/' },
  { zone: 'dnsbl-1.uceprotect.net', name: 'UCEPROTECT Level 1', url: 'https://www.uceprotect.net/en/rblcheck.php' },
  { zone: 'dnsbl.dronebl.org', name: 'DroneBL', url: 'https://dronebl.org/lookup' },
  { zone: 'bl.blocklist.de', name: 'blocklist.de', url: 'https://www.blocklist.de/en/search.html' },
  { zone: 'all.s5h.net', name: 's5h.net' },
  { zone: 'rbl.interserver.net', name: 'InterServer RBL' },
  { zone: 'bl.0spam.org', name: '0spam' },
  { zone: 'spam.spamrats.com', name: 'SpamRATS Spam' },
  { zone: 'dyna.spamrats.com', name: 'SpamRATS Dyna', policyList: true },
  { zone: 'noptr.spamrats.com', name: 'SpamRATS NoPtr', policyList: true },
  { zone: 'truncate.gbudb.net', name: 'GBUdb Truncate' },
  { zone: 'dnsbl.spfbl.net', name: 'SPFBL' },
  { zone: 'ips.backscatterer.org', name: 'Backscatterer' },
  { zone: 'bl.nordspam.com', name: 'NordSpam' },
  { zone: 'spam.dnsbl.anonmails.de', name: 'anonmails.de' },
];

/** Domain lists. `test` is a name the operator guarantees is listed. */
export const DOMAIN_LISTS = [
  { zone: 'dbl.spamhaus.org', name: 'Spamhaus DBL', test: 'dbltest.com', url: 'https://check.spamhaus.org/' },
  { zone: 'multi.surbl.org', name: 'SURBL', test: 'surbl-org-permanent-test-point.com', url: 'https://surbl.org/surbl-analysis' },
  { zone: 'multi.uribl.com', name: 'URIBL', test: 'test.uribl.com', url: 'https://admin.uribl.com/' },
];

const HEALTH_TTL_MS = 60 * 60 * 1000;

export function reverseIp(ip) {
  if (net.isIPv4(ip)) return ip.split('.').reverse().join('.');
  if (!net.isIPv6(ip)) return '';
  // Expand to 32 hex digits, then reverse nibble by nibble.
  const [head, tail = ''] = ip.split('::');
  const headGroups = head ? head.split(':') : [];
  const tailGroups = tail ? tail.split(':') : [];
  const missing = ip.includes('::') ? 8 - headGroups.length - tailGroups.length : 0;
  const groups = [...headGroups, ...Array(Math.max(missing, 0)).fill('0'), ...tailGroups];
  if (groups.length !== 8 || groups.some(group => !/^[0-9a-f]{1,4}$/i.test(group))) return '';
  return groups.map(group => group.padStart(4, '0')).join('').toLowerCase().split('').reverse().join('.');
}

// 127.255.255.0/24 is how Spamhaus and others signal "query refused" (public
// resolver, rate limit, bad query). It is never a listing.
function isErrorCode(address) {
  return address.startsWith('127.255.255.');
}

function isListingAddress(address) {
  return address.startsWith('127.') && !isErrorCode(address);
}

export function createDnsblChecker({ dns, now = () => Date.now(), ipLists = IP_LISTS, domainLists = DOMAIN_LISTS } = {}) {
  const health = new Map();

  /** @returns {Promise<{ ok: boolean, reason: string }>} */
  async function listHealth(list, kind) {
    const cached = health.get(list.zone);
    if (cached && cached.expires > now()) return cached.value;

    let value;
    if (kind === 'ip') {
      const [listed, clean] = await Promise.all([dns.a(`2.0.0.127.${list.zone}`), dns.a(`1.0.0.127.${list.zone}`)]);
      if (listed.status === 'error' || clean.status === 'error') value = { ok: false, reason: 'The list did not answer.' };
      else if (listed.records.some(isErrorCode) || clean.records.some(isErrorCode)) value = { ok: false, reason: 'The list refuses queries from this server\'s DNS resolver.' };
      else if (clean.status === 'ok') value = { ok: false, reason: 'The list answers "listed" for every address, so its results cannot be trusted.' };
      else if (!listed.records.some(isListingAddress)) value = { ok: false, reason: 'The list failed its self-test and may be offline.' };
      else value = { ok: true, reason: '' };
    } else {
      const listed = await dns.a(`${list.test}.${list.zone}`);
      if (listed.status === 'error') value = { ok: false, reason: 'The list did not answer.' };
      else if (listed.records.some(isErrorCode)) value = { ok: false, reason: 'The list refuses queries from this server\'s DNS resolver.' };
      else if (!listed.records.some(isListingAddress)) value = { ok: false, reason: 'The list failed its self-test and may be offline.' };
      else value = { ok: true, reason: '' };
    }
    health.set(list.zone, { value, expires: now() + HEALTH_TTL_MS });
    return value;
  }

  async function queryList(list, kind, name) {
    const base = { zone: list.zone, name: list.name, url: list.url || '' };
    const state = await listHealth(list, kind);
    if (!state.ok) return { ...base, status: 'unavailable', detail: state.reason, codes: [] };

    const answer = await dns.a(`${name}.${list.zone}`);
    if (answer.status === 'error') return { ...base, status: 'unavailable', detail: 'The list did not answer.', codes: [] };
    if (answer.records.some(isErrorCode)) return { ...base, status: 'unavailable', detail: 'The list refused the query.', codes: [] };

    const codes = answer.records.filter(isListingAddress);
    if (codes.length === 0) return { ...base, status: 'clean', detail: '', codes: [] };

    const meanings = codes.map(code => list.codes?.[code]);
    const policyOnly = list.policyList || (meanings.length > 0 && meanings.every(meaning => meaning?.policy));
    const reason = await dns.txt(`${name}.${list.zone}`);
    return {
      ...base,
      status: policyOnly ? 'policy' : 'listed',
      detail: meanings.map(meaning => meaning?.label).filter(Boolean).join('; '),
      reason: (reason.records[0] || '').slice(0, 300),
      codes,
    };
  }

  function summarize(results) {
    return {
      listed: results.filter(r => r.status === 'listed').length,
      policy: results.filter(r => r.status === 'policy').length,
      clean: results.filter(r => r.status === 'clean').length,
      unavailable: results.filter(r => r.status === 'unavailable').length,
      total: results.length,
    };
  }

  async function checkIp(ip) {
    const reversed = reverseIp(ip);
    const lists = net.isIPv6(ip) ? ipLists.filter(list => list.ipv6) : ipLists;
    const results = await mapLimit(lists, 10, list => queryList(list, 'ip', reversed));
    return { target: ip, kind: 'ip', results, summary: summarize(results) };
  }

  async function checkDomain(domain) {
    const results = await mapLimit(domainLists, 5, list => queryList(list, 'domain', domain));
    return { target: domain, kind: 'domain', results, summary: summarize(results) };
  }

  return { checkIp, checkDomain };
}
