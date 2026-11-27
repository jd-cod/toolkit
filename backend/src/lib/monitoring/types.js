/**
 * Monitor types: what each one watches, its options and how input is validated.
 *
 * Monitors are created by the admin, so targets are NOT run through the SSRF
 * guard: watching internal hosts is a normal use. That changes when monitors
 * become customer-owned (docs/TOOLS_ROADMAP.md, "Later").
 */

import net from 'node:net';
import { normalizeHostname } from '../dns-client.js';

export const STATUSES = ['pending', 'ok', 'warn', 'down'];
export const DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'];

export const MONITOR_TYPES = {
  ssl_expiry: { label: 'SSL certificate expiry', minInterval: 60, defaultInterval: 720, confirmAfter: 2 },
  domain_expiry: { label: 'Domain expiry', minInterval: 360, defaultInterval: 1440, confirmAfter: 1 },
  blacklist: { label: 'Blacklist listing', minInterval: 60, defaultInterval: 360, confirmAfter: 1 },
  dns_record: { label: 'DNS record change', minInterval: 5, defaultInterval: 30, confirmAfter: 2 },
  http: { label: 'HTTP(S) uptime', minInterval: 1, defaultInterval: 5, confirmAfter: 2 },
  tcp: { label: 'TCP port', minInterval: 1, defaultInterval: 5, confirmAfter: 2 },
  heartbeat: { label: 'Cron job heartbeat', minInterval: 1, defaultInterval: 60, confirmAfter: 1 },
};

function fail(message) {
  throw Object.assign(new Error(message), { statusCode: 400 });
}

function integer(value, fallback, min, max, label) {
  if (value === undefined || value === null || value === '') return fallback;
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) fail(`${label} must be a whole number from ${min} to ${max}.`);
  return number;
}

function hostOrIp(value, label = 'Target') {
  const raw = String(value || '').trim().replace(/^\[|\]$/g, '');
  if (net.isIP(raw)) return raw;
  // Single-label names (intranet hosts) are fine for an admin-owned monitor.
  if (/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(raw)) return raw.toLowerCase();
  const host = normalizeHostname(raw);
  if (!host) fail(`${label} must be a host name or an IP address.`);
  return host;
}

function hostAndPort(value, defaultPort) {
  const raw = String(value || '').trim();
  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(raw);
  const plain = /^([^:]+)(?::(\d+))?$/.exec(raw);
  const match = bracketed || plain || (net.isIPv6(raw) ? [raw, raw, undefined] : null);
  if (!match) fail('Target must be host or host:port.');
  const host = hostOrIp(match[1]);
  const port = integer(match[2], defaultPort, 1, 65535, 'Port');
  if (!port) fail('Target must include a port, for example db.example.com:5432.');
  return { host, port };
}

/**
 * Validates what the admin submitted and returns the row fields to store.
 * Throws an error with statusCode 400 and a message fit to show in the form.
 */
export function normalizeMonitorInput(input) {
  const type = String(input?.type || '');
  const spec = MONITOR_TYPES[type];
  if (!spec) fail('Choose a monitor type.');

  const name = String(input.name || '').trim().slice(0, 255);
  if (!name) fail('Give the monitor a name.');

  const interval = integer(input.interval_minutes, spec.defaultInterval, spec.minInterval, 10080, 'Interval');
  const raw = input.config && typeof input.config === 'object' ? input.config : {};
  let target = '';
  let config = {};

  if (type === 'ssl_expiry') {
    const { host, port } = hostAndPort(input.target, 443);
    target = port === 443 ? host : `${host}:${port}`;
    config = { warn_days: integer(raw.warn_days, 14, 1, 365, 'Warning threshold') };
  } else if (type === 'domain_expiry') {
    target = normalizeHostname(input.target);
    if (!target) fail('Target must be a domain name, for example example.com.');
    config = { warn_days: integer(raw.warn_days, 30, 1, 365, 'Warning threshold') };
  } else if (type === 'blacklist') {
    target = hostOrIp(input.target);
  } else if (type === 'dns_record') {
    target = normalizeHostname(input.target);
    if (!target) fail('Target must be a DNS name, for example www.example.com.');
    const recordType = String(raw.record_type || 'A').toUpperCase();
    if (!DNS_RECORD_TYPES.includes(recordType)) fail(`Record type must be one of ${DNS_RECORD_TYPES.join(', ')}.`);
    const expected = String(raw.expected || '').split(/[\n,]+/).map(value => value.trim()).filter(Boolean).slice(0, 20);
    // `baseline` is what the record looked like when it was last accepted; it is kept across edits.
    config = { record_type: recordType, expected, baseline: Array.isArray(raw.baseline) ? raw.baseline.map(String).slice(0, 50) : null };
  } else if (type === 'http') {
    let url;
    try {
      url = new URL(String(input.target || '').trim());
    } catch {
      fail('Target must be a full URL, for example https://example.com/health.');
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') fail('Target must be an http or https URL.');
    if (url.username || url.password) fail('Do not put credentials in the URL.');
    target = url.toString();
    config = {
      expected_status: integer(raw.expected_status, 0, 100, 599, 'Expected status'),
      keyword: String(raw.keyword || '').slice(0, 200),
      timeout_seconds: integer(raw.timeout_seconds, 10, 1, 60, 'Timeout'),
    };
  } else if (type === 'tcp') {
    const { host, port } = hostAndPort(input.target, 0);
    target = net.isIPv6(host) ? `[${host}]:${port}` : `${host}:${port}`;
    config = { timeout_seconds: integer(raw.timeout_seconds, 5, 1, 30, 'Timeout') };
  } else if (type === 'heartbeat') {
    target = '';
    config = { grace_minutes: integer(raw.grace_minutes, 5, 0, 1440, 'Grace period') };
  }

  return { type, name, target, interval_minutes: interval, config, is_enabled: input.is_enabled === undefined ? 1 : (input.is_enabled ? 1 : 0) };
}

export function parseTargetPort(target, defaultPort) {
  return hostAndPort(target, defaultPort);
}

export function normalizeChannelInput(input) {
  const type = String(input?.type || '');
  if (!['webhook', 'slack', 'email'].includes(type)) fail('Choose a channel type.');
  const name = String(input.name || '').trim().slice(0, 255);
  if (!name) fail('Give the channel a name.');
  const target = String(input.target || '').trim();
  if (type === 'email') {
    if (!/^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+$/.test(target) || target.length > 320) fail('Enter one email address.');
  } else {
    let url;
    try {
      url = new URL(target);
    } catch {
      fail('Enter a full webhook URL.');
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') fail('The webhook URL must be http or https.');
    if (target.length > 1000) fail('The webhook URL is too long.');
  }
  return { type, name, target, is_enabled: input.is_enabled === undefined ? 1 : (input.is_enabled ? 1 : 0) };
}
