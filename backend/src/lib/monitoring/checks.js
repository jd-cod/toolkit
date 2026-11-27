/**
 * The checks monitors run. Each returns { status, message, details } with
 * status ok | warn | down and never throws: a check that cannot complete is
 * itself a result ("down: connection timed out").
 *
 * Dependencies are passed in so tests can replace the network.
 */

import net from 'node:net';
import tls from 'node:tls';
import { createDnsClient } from '../dns-client.js';
import { createDnsblChecker } from '../dnsbl.js';
import { probePort } from '../port-probe.js';
import { buildWhoisSnapshot } from '../../routes/whois.js';
import { parseTargetPort } from './types.js';

const result = (status, message, details = {}) => ({ status, message: String(message).slice(0, 1000), details });
const plural = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;

/** Connects with TLS and describes the certificate. Rejects on connection failure. */
export function probeTls(host, port, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      const info = {
        has_certificate: Boolean(cert && Object.keys(cert).length),
        valid_to: cert?.valid_to || '',
        subject: cert?.subject?.CN || '',
        issuer: cert?.issuer?.O || cert?.issuer?.CN || '',
        trusted: socket.authorized === true,
        trust_error: socket.authorized ? '' : String(socket.authorizationError || ''),
        hostname_error: cert && Object.keys(cert).length && !net.isIP(host) ? (tls.checkServerIdentity(host, cert)?.message || '') : '',
        protocol: socket.getProtocol() || '',
      };
      socket.end();
      resolve(info);
    });
    socket.setTimeout(timeoutMs, () => socket.destroy(new Error('Connection timed out')));
    socket.on('error', reject);
  });
}

export async function checkSslExpiry(monitor, { tlsProbe = probeTls, now = () => Date.now() } = {}) {
  const { host, port } = parseTargetPort(monitor.target, 443);
  const warnDays = monitor.config?.warn_days ?? 14;
  let info;
  try {
    info = await tlsProbe(host, port);
  } catch (err) {
    return result('down', `Could not connect to ${host}:${port}: ${err.message}`);
  }
  if (!info.has_certificate) return result('down', 'The server presented no certificate.', info);

  const expires = new Date(info.valid_to).getTime();
  if (Number.isNaN(expires)) return result('warn', 'The certificate expiry date could not be read.', info);
  const days = Math.floor((expires - now()) / 86400000);
  const details = { ...info, days_remaining: days };

  if (days < 0) return result('down', `Certificate expired ${plural(-days, 'day')} ago.`, details);
  if (info.hostname_error) return result('down', `Certificate does not match ${host}.`, details);
  if (days <= warnDays) return result('warn', `Certificate expires in ${plural(days, 'day')}.`, details);
  if (!info.trusted) return result('warn', `Certificate chain is not trusted (${info.trust_error || 'verification failed'}). Expires in ${plural(days, 'day')}.`, details);
  return result('ok', `Certificate is valid for ${plural(days, 'day')}.`, details);
}

export async function checkDomainExpiry(monitor, { whois = buildWhoisSnapshot } = {}) {
  const warnDays = monitor.config?.warn_days ?? 30;
  let snapshot;
  try {
    snapshot = await whois(monitor.target);
  } catch (err) {
    return result('warn', `Registration data could not be read: ${err.message}`);
  }
  const details = { registrar: snapshot.registrar || '', expiry_date: snapshot.expiry_date || '', days_until_expiry: snapshot.days_until_expiry ?? null, data_source: snapshot.data_source || '' };
  if (snapshot.registered === false) return result('down', 'The domain is not registered.', details);
  const days = snapshot.days_until_expiry;
  if (days === null || days === undefined) return result('warn', 'The registry did not publish an expiry date for this domain.', details);
  if (days < 0) return result('down', `Domain expired ${plural(-days, 'day')} ago.`, details);
  if (days <= warnDays) return result('warn', `Domain expires in ${plural(days, 'day')}.`, details);
  return result('ok', `Domain is registered for ${plural(days, 'day')} more.`, details);
}

export async function checkBlacklist(monitor, { dns, dnsbl } = {}) {
  let addresses = [];
  if (net.isIP(monitor.target)) {
    addresses = [monitor.target];
  } else {
    const answer = await dns.a(monitor.target);
    if (answer.status === 'error') return result('warn', `DNS lookup for ${monitor.target} failed (${answer.error}).`);
    addresses = answer.records.slice(0, 3);
    if (addresses.length === 0) return result('down', `${monitor.target} has no A record.`);
  }

  const listed = [];
  let answered = 0;
  let total = 0;
  for (const address of addresses) {
    const check = await dnsbl.checkIp(address);
    total += check.summary.total;
    answered += check.summary.total - check.summary.unavailable;
    for (const entry of check.results) if (entry.status === 'listed') listed.push(`${entry.name} (${address})`);
  }
  const details = { addresses, listed, lists_answered: answered, lists_total: total };
  if (listed.length > 0) return result('down', `Listed on ${plural(listed.length, 'blacklist')}: ${listed.slice(0, 6).join(', ')}${listed.length > 6 ? ', and more' : ''}.`, details);
  if (answered === 0) return result('warn', 'No blacklist could be queried from this server.', details);
  return result('ok', `Not listed on ${plural(answered, 'blacklist')} that answered.`, details);
}

function normalizeRecords(type, records) {
  const values = records.map(record => {
    if (type === 'MX') return `${record.priority} ${String(record.exchange).toLowerCase().replace(/\.$/, '')}`;
    if (type === 'TXT') return String(record);
    return String(record).toLowerCase().replace(/\.$/, '');
  });
  return [...new Set(values)].sort();
}

const sameSet = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);

/**
 * Compares the record with what is expected. With no expected value, the
 * first answer becomes the baseline (returned in `details.baseline` for the
 * caller to store) and later answers are compared with it.
 */
export async function checkDnsRecord(monitor, { dns } = {}) {
  const type = monitor.config?.record_type || 'A';
  const lookup = { A: dns.a, AAAA: dns.aaaa, MX: dns.mx, TXT: dns.txt, NS: dns.ns, CNAME: dns.cname }[type];
  const answer = await lookup(monitor.target);
  if (answer.status === 'error') return result('down', `DNS lookup failed (${answer.error}).`);

  const current = normalizeRecords(type, answer.records);
  const expected = normalizeRecords(type === 'MX' ? 'A' : type, monitor.config?.expected || []);
  const baseline = Array.isArray(monitor.config?.baseline) ? [...monitor.config.baseline].sort() : null;
  const reference = expected.length > 0 ? expected : baseline;
  const show = values => (values.length ? values.join(', ') : 'no record');

  if (!reference) return result(current.length ? 'ok' : 'warn', `${type} record is ${show(current)}. Stored as the baseline.`, { current, baseline: current });
  if (sameSet(current, reference)) return result('ok', `${type} record is unchanged: ${show(current)}.`, { current });
  return result('down', `${type} record changed. Expected ${show(reference)}, found ${show(current)}.`, { current, expected: reference });
}

export async function checkHttp(monitor, { fetchImpl = fetch } = {}) {
  const { expected_status: expectedStatus = 0, keyword = '', timeout_seconds: timeoutSeconds = 10 } = monitor.config || {};
  const started = Date.now();
  let response;
  try {
    response = await fetchImpl(monitor.target, {
      redirect: 'follow',
      signal: AbortSignal.timeout(timeoutSeconds * 1000),
      headers: { 'User-Agent': 'SysAdminToolkit-Monitor/1.0' },
    });
  } catch (err) {
    const reason = err?.name === 'TimeoutError' ? `no response within ${plural(timeoutSeconds, 'second')}` : (err?.cause?.code || err?.cause?.message || err?.message || 'request failed');
    return result('down', `Request failed: ${reason}.`, { response_ms: Date.now() - started });
  }

  const details = { status: response.status, response_ms: Date.now() - started };
  const statusOk = expectedStatus ? response.status === expectedStatus : response.status >= 200 && response.status < 400;
  if (!statusOk) {
    await response.body?.cancel().catch(() => {});
    return result('down', `Responded with HTTP ${response.status}${expectedStatus ? `, expected ${expectedStatus}` : ''}.`, details);
  }
  if (keyword) {
    // Read at most 512 KB: enough for a health page, bounded for a download.
    let body = '';
    try {
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      while (reader && body.length < 512 * 1024) {
        const { done, value } = await reader.read();
        if (done) break;
        body += decoder.decode(value, { stream: true });
      }
      await reader?.cancel().catch(() => {});
    } catch (err) {
      return result('down', `The response body could not be read: ${err.message}.`, details);
    }
    if (!body.includes(keyword)) return result('down', `HTTP ${response.status}, but the page does not contain "${keyword}".`, details);
  } else {
    await response.body?.cancel().catch(() => {});
  }
  return result('ok', `HTTP ${response.status} in ${details.response_ms} ms.`, details);
}

export async function checkTcp(monitor, { tcpProbe = probePort } = {}) {
  const { host, port } = parseTargetPort(monitor.target, 0);
  const probe = await tcpProbe(host, port, (monitor.config?.timeout_seconds ?? 5) * 1000);
  if (probe.state === 'open') return result('ok', `Port ${port} is open (${probe.latency_ms} ms).`, probe);
  return result('down', probe.state === 'closed' ? `Port ${port} refused the connection.` : `Port ${port} did not answer.`, probe);
}

export function createCheckRunner(overrides = {}) {
  const dns = overrides.dns || createDnsClient();
  const deps = { dns, dnsbl: overrides.dnsbl || createDnsblChecker({ dns }), ...overrides };
  const checks = { ssl_expiry: checkSslExpiry, domain_expiry: checkDomainExpiry, blacklist: checkBlacklist, dns_record: checkDnsRecord, http: checkHttp, tcp: checkTcp };

  return async function runCheck(monitor) {
    const check = checks[monitor.type];
    if (!check) return result('warn', `Unknown monitor type "${monitor.type}".`);
    try {
      return await check(monitor, deps);
    } catch (err) {
      return result('down', `The check failed: ${err?.message || 'unknown error'}`);
    }
  };
}
