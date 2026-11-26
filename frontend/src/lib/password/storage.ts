/**
 * localStorage-backed password history.
 *
 * This is the only persistence in the tool, and it never leaves the browser.
 * Three things follow from that and are handled here:
 *
 *  1. SSR safety — localStorage is read inside useEffect on the client, never
 *     during render, or React's hydration will mismatch.
 *  2. Untrusted input — the key is writable by any script on the origin (an
 *     XSS payload, a rogue extension, the user in devtools). Every field is
 *     re-validated on read and anything malformed is dropped rather than
 *     rendered, so a poisoned entry cannot inject markup into the table.
 *  3. Bounded growth — capped and FIFO-pruned, so this can never become an
 *     unbounded disk write.
 */

import type { PasswordMode } from './generator';
import type { StrengthLevel } from './entropy';

export const STORAGE_KEY = 'sysadmin_toolkit.pwgen.history.v1';
export const HISTORY_LIMIT = 25;

export interface HistoryEntry {
  id: string;
  password: string;
  mode: PasswordMode;
  bits: number;
  level: StrengthLevel;
  createdAt: number;
}

const MODES: PasswordMode[] = ['password', 'passphrase', 'pin'];
const LEVELS: StrengthLevel[] = ['very-weak', 'weak', 'fair', 'strong', 'very-strong'];

function isEntry(value: unknown): value is HistoryEntry {
  if (typeof value !== 'object' || value === null) return false;
  const e = value as Record<string, unknown>;
  return (
    typeof e.id === 'string' &&
    typeof e.password === 'string' &&
    e.password.length > 0 &&
    e.password.length <= 256 &&
    typeof e.createdAt === 'number' &&
    Number.isFinite(e.createdAt) &&
    e.createdAt > 0 &&
    typeof e.bits === 'number' &&
    Number.isFinite(e.bits) &&
    e.bits >= 0 &&
    typeof e.mode === 'string' &&
    MODES.includes(e.mode as PasswordMode) &&
    typeof e.level === 'string' &&
    LEVELS.includes(e.level as StrengthLevel)
  );
}

export function readHistory(): HistoryEntry[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isEntry).slice(0, HISTORY_LIMIT);
  } catch {
    // Corrupt JSON, quota exceeded, or storage disabled (private mode, blocked
    // third-party context). History is a convenience; losing it must never
    // break the generator.
    return [];
  }
}

/** Prepends the entry and drops the oldest overflow. Returns the stored list. */
export function appendHistory(entry: HistoryEntry, existing?: HistoryEntry[]): HistoryEntry[] {
  const base = existing ?? readHistory();
  const next = [entry, ...base.filter((e) => e.id !== entry.id)].slice(0, HISTORY_LIMIT);
  writeHistory(next);
  return next;
}

export function writeHistory(entries: HistoryEntry[]): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(entries.slice(0, HISTORY_LIMIT)));
  } catch {
    /* quota exceeded or storage disabled — history is best-effort by design */
  }
}

export function clearHistory(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

/** Collision-resistant id — getRandomValues rather than Math.random or a counter. */
export function newId(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
