/**
 * Share-link options shared by every tool. The values must match what the
 * backend accepts (backend/src/lib/share-utils.js); tests/unit/share.test.js
 * fails if the two drift apart.
 */

export const SHARE_EXPIRY_OPTIONS = [
  { value: '1h', label: '1 hour' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
  { value: 'never', label: 'Never expires' },
] as const;

export type ShareExpiry = (typeof SHARE_EXPIRY_OPTIONS)[number]['value'];

export const DEFAULT_SHARE_EXPIRY: ShareExpiry = 'never';

export const MAX_SHARE_PASSWORD_BYTES = 72;

/** Tools that share a JSON snapshot of their result. */
export const SNAPSHOT_TOOLS = ['dns', 'whois', 'myip', 'asn', 'ssl', 'abuse', 'subnet', 'cron', 'chmod'] as const;

export type SnapshotTool = (typeof SNAPSHOT_TOOLS)[number];

/** Display names for every kind of share, including Traffic Analyzer log shares. */
export const SHARE_TYPE_LABELS: Record<SnapshotTool | 'nginx', string> = {
  nginx: 'Traffic Log',
  dns: 'DNS',
  whois: 'WHOIS',
  myip: 'My IP',
  asn: 'ASN',
  ssl: 'SSL',
  abuse: 'IP Info',
  subnet: 'Subnet',
  cron: 'Cron',
  chmod: 'chmod',
};

export function isSnapshotTool(value: unknown): value is SnapshotTool {
  return typeof value === 'string' && (SNAPSHOT_TOOLS as readonly string[]).includes(value);
}

/** What the user chooses in the share dialog. */
export interface ShareOptions {
  title: string;
  expiry: ShareExpiry;
  password: string;
}

export interface CreatedShare {
  code: string;
}

export function shareLink(origin: string, code: string) {
  return `${origin.replace(/\/+$/, '')}/s/${encodeURIComponent(code)}`;
}

/** Returns an error message for a password the backend would reject, or '' if it is fine. */
export function sharePasswordError(password: string) {
  const bytes = new TextEncoder().encode(password.trim()).length;
  return bytes > MAX_SHARE_PASSWORD_BYTES ? `Password is too long (maximum ${MAX_SHARE_PASSWORD_BYTES} bytes).` : '';
}

/** One-line summary of a created link, e.g. "Expires in 7 days · Password protected". */
export function describeShare(expiry: ShareExpiry, hasPassword: boolean) {
  const option = SHARE_EXPIRY_OPTIONS.find((item) => item.value === expiry);
  const expiryText = !option || expiry === 'never' ? 'Never expires' : `Expires in ${option.label}`;
  return `${expiryText} · ${hasPassword ? 'Password protected' : 'Anyone with the link can view'}`;
}
