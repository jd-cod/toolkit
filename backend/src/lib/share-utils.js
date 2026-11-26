/**
 * Shared helpers for share links: expiry, passwords, codes and the snapshot
 * tool registry. Used by the public share routes, the admin share routes, the
 * storage download route and the cleanup scheduler so they agree on the rules.
 */

import { createHash, randomInt, timingSafeEqual } from 'node:crypto';
import bcrypt from 'bcrypt';

/** Tools whose results are stored as a JSON snapshot in `tool_shares`. */
export const SNAPSHOT_TOOLS = Object.freeze({
  dns: 'DNS',
  whois: 'WHOIS',
  myip: 'My IP',
  asn: 'ASN',
  ssl: 'SSL Certificate',
  abuse: 'IP Info',
  subnet: 'Subnet',
  cron: 'Cron',
  chmod: 'chmod',
});

const HOUR_MS = 60 * 60 * 1000;
const EXPIRY_MS = Object.freeze({
  '1h': HOUR_MS,
  '24h': 24 * HOUR_MS,
  '7d': 7 * 24 * HOUR_MS,
  '30d': 30 * 24 * HOUR_MS,
});

export const SHARE_EXPIRY_VALUES = Object.freeze([...Object.keys(EXPIRY_MS), 'never']);

// bcrypt silently ignores everything past 72 bytes, so longer passwords are rejected.
export const MAX_SHARE_PASSWORD_BYTES = 72;
const BCRYPT_ROUNDS = 10;

const CODE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
export const SHARE_CODE_RE = /^[A-Za-z0-9]{6,20}$/;

export function generateShareCode(length = 8) {
  let code = '';
  for (let i = 0; i < length; i++) code += CODE_CHARS[randomInt(CODE_CHARS.length)];
  return code;
}

/** Format a Date as MySQL-compatible 'YYYY-MM-DD HH:MM:SS' in UTC. */
export function toMySQLDatetime(date) {
  return date.toISOString().slice(0, 19).replace('T', ' ');
}

/**
 * Turn an expiry option into a MySQL datetime.
 * A missing value means "never"; an unrecognised one is an error rather than a
 * link that silently never expires.
 */
export function resolveExpiry(expiry, now = new Date()) {
  if (expiry === undefined || expiry === null || expiry === '' || expiry === 'never') {
    return { ok: true, expiresAt: null, expiresAtIso: null };
  }
  const ms = typeof expiry === 'string' && Object.hasOwn(EXPIRY_MS, expiry) ? EXPIRY_MS[expiry] : null;
  if (ms === null) {
    return { ok: false, error: `Invalid expiry. Use one of: ${SHARE_EXPIRY_VALUES.join(', ')}.` };
  }
  const date = new Date(now.getTime() + ms);
  return { ok: true, expiresAt: toMySQLDatetime(date), expiresAtIso: date.toISOString() };
}

export function isExpired(expiresAt, now = new Date()) {
  if (!expiresAt) return false;
  return now > new Date(expiresAt);
}

/** Normalise a submitted share password. Returns '' when none was given. */
export function readSharePassword(value) {
  if (value === undefined || value === null) return { ok: true, password: '' };
  if (typeof value !== 'string') return { ok: false, error: 'Password must be text.' };
  const password = value.trim();
  if (Buffer.byteLength(password, 'utf8') > MAX_SHARE_PASSWORD_BYTES) {
    return { ok: false, error: `Password is too long (maximum ${MAX_SHARE_PASSWORD_BYTES} bytes).` };
  }
  return { ok: true, password };
}

export async function hashSharePassword(password) {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

/**
 * Check a password against a stored hash. Shares created before bcrypt was
 * adopted hold an unsalted SHA-256 hex digest, which is still accepted.
 */
export async function verifySharePassword(password, storedHash) {
  if (!storedHash || typeof password !== 'string') return false;
  if (storedHash.startsWith('$2')) return bcrypt.compare(password, storedHash);

  const submitted = Buffer.from(createHash('sha256').update(password).digest('hex'));
  const expected = Buffer.from(String(storedHash).toLowerCase());
  return submitted.length === expected.length && timingSafeEqual(submitted, expected);
}
