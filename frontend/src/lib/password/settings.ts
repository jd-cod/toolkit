/**
 * localStorage-backed generator SETTINGS (mode + all options).
 *
 * History lives in storage.ts; this holds the user's configuration so a
 * refresh does not reset it. Same untrusted-input discipline as history:
 * every field is re-validated on read and anything malformed falls back to the
 * caller-supplied defaults rather than being rendered blindly.
 */

import type { PasswordMode, PasswordOptions, PassphraseOptions } from './generator';

export const SETTINGS_KEY = 'sysadmin_toolkit.pwgen.settings.v1';

export interface PersistedSettings {
  mode: PasswordMode;
  options: PasswordOptions;
  passphrase: PassphraseOptions;
  pinLength: number;
}

const MODES: PasswordMode[] = ['password', 'passphrase', 'pin'];
const SEPARATORS = ['-', '_', '.', ' ', ''];

export function writeSettings(s: PersistedSettings): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
  } catch {
    /* quota exceeded or storage disabled — settings are best-effort */
  }
}

/** Returns null when nothing valid is stored; callers apply defaults. */
export function readSettings(): PersistedSettings | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(SETTINGS_KEY);
    if (!raw) return null;
    const p = JSON.parse(raw) as Record<string, unknown>;
    if (typeof p !== 'object' || p === null) return null;

    const bool = (v: unknown) => (typeof v === 'boolean' ? v : undefined);
    const intBetween = (v: unknown, lo: number, hi: number) =>
      typeof v === 'number' && Number.isInteger(v) && v >= lo && v <= hi ? v : undefined;

    const opts = (p.options as Record<string, unknown> | undefined) ?? {};
    const ph = (p.passphrase as Record<string, unknown> | undefined) ?? {};

    const options: PasswordOptions = {
      length: intBetween(opts.length, 4, 128) ?? 20,
      uppercase: bool(opts.uppercase) ?? true,
      lowercase: bool(opts.lowercase) ?? true,
      numbers: bool(opts.numbers) ?? true,
      symbols: bool(opts.symbols) ?? true,
      excludeAmbiguous: bool(opts.excludeAmbiguous) ?? false,
      excludeSimilar: bool(opts.excludeSimilar) ?? false,
      requireEachClass: bool(opts.requireEachClass) ?? true,
    };

    const sepRaw = ph.separator;
    const passphrase: PassphraseOptions = {
      wordCount: intBetween(ph.wordCount, 3, 10) ?? 4,
      separator: typeof sepRaw === 'string' && SEPARATORS.includes(sepRaw) ? sepRaw : '-',
      capitalize: bool(ph.capitalize) ?? true,
      appendNumber: bool(ph.appendNumber) ?? false,
    };

    return {
      mode: MODES.includes(p.mode as PasswordMode) ? (p.mode as PasswordMode) : 'password',
      options,
      passphrase,
      pinLength: intBetween(p.pinLength, 4, 16) ?? 6,
    };
  } catch {
    return null;
  }
}