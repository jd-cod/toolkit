/**
 * Password generation — cryptographic core.
 *
 * Every value here comes from `crypto.getRandomValues`. There is no `Math.random`
 * anywhere in this file, deliberately: `Math.random()` is a seeded PRNG whose
 * internal state is recoverable from observed output, so a password built from it
 * is not merely "less random", it is reconstructable by anyone who sees enough
 * of the passwords we hand out.
 *
 * Everything in this module is pure and browser-only; the page calls it on the
 * client and never ships a password across the network.
 */

import { WORDLIST } from './wordlist';

export type PasswordMode = 'password' | 'passphrase' | 'pin';

export interface PasswordOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  /** Strip glyphs that are easy to confuse when read aloud or retyped (0/O/o/1/l/I/|/\). */
  excludeAmbiguous: boolean;
  /** Strip shell-hostile and easily-mangled punctuation (quotes, backslash, brackets, whitespace). */
  excludeSimilar: boolean;
  /** Force at least one character from every enabled class. Ignored if too short. */
  requireEachClass: boolean;
}

export interface PassphraseOptions {
  wordCount: number;
  separator: string;
  capitalize: boolean;
  appendNumber: boolean;
}

export const CHARSETS = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{}<>?/~',
} as const;

export const AMBIGUOUS_CHARS = '0Oo1lI|/\\';
export const SIMILAR_CHARS = '\'"`.,:;<>()[]{}~\\ ';

export const LENGTH_PRESETS = [8, 12, 16, 20, 32, 64];
export const WORD_COUNT_PRESETS = [3, 4, 5, 6, 7];
export const PIN_PRESETS = [4, 6, 8];

export const SEPARATORS = ['-', '.', '_', ' ', '+'] as const;

/**
 * Uniform integer in [0, maxExclusive) via rejection sampling.
 *
 * The obvious `byte % n` is biased: with n=94 (our full symbol set) the first 28
 * of 256 residues are reachable twice and the rest once, so those characters
 * come out ~29% more often than their share. Rejecting out-of-range draws and
 * resampling removes the bias entirely — the cost is a handful of extra bytes
 * in the vanishingly rare case n does not divide 2^32.
 */
export function randomInt(maxExclusive: number): number {
  if (maxExclusive <= 1) return 0;
  const SPACE = 0x100000000;
  const limit = SPACE - (SPACE % maxExclusive);
  const buffer = new Uint32Array(8);
  for (;;) {
    crypto.getRandomValues(buffer);
    for (let i = 0; i < buffer.length; i++) {
      if (buffer[i] < limit) return buffer[i] % maxExclusive;
    }
  }
}

function pick(pool: string): string {
  return pool[randomInt(pool.length)];
}

/** Cryptographic Fisher–Yates. Unbiased only if `getIndex` is, hence randomInt. */
export function shuffle<T>(items: T[]): T[] {
  for (let i = items.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [items[i], items[j]] = [items[j], items[i]];
  }
  return items;
}

/** The character pool each option resolves to, in the order we display them. */
export function activeSets(opts: PasswordOptions): { label: string; chars: string }[] {
  const sets: { label: string; chars: string }[] = [];
  if (opts.uppercase) sets.push({ label: 'A-Z', chars: CHARSETS.uppercase });
  if (opts.lowercase) sets.push({ label: 'a-z', chars: CHARSETS.lowercase });
  if (opts.numbers) sets.push({ label: '0-9', chars: CHARSETS.numbers });
  if (opts.symbols) sets.push({ label: 'Symbols', chars: CHARSETS.symbols });
  return sets;
}

/** Total reachable characters — the `N` in the entropy formula H = L · log2(N). */
export function poolSize(sets: { chars: string }[], excludeAmbiguous: boolean, excludeSimilar: boolean): number {
  const banned = new Set<string>();
  if (excludeAmbiguous) for (const c of AMBIGUOUS_CHARS) banned.add(c);
  if (excludeSimilar) for (const c of SIMILAR_CHARS) banned.add(c);
  return sets.reduce((n, s) => n + [...s.chars].filter((c) => !banned.has(c)).length, 0);
}

function strip(chars: string, excludeAmbiguous: boolean, excludeSimilar: string): string {
  let out = chars;
  if (excludeAmbiguous) {
    const banned = new Set(AMBIGUOUS_CHARS);
    out = [...out].filter((c) => !banned.has(c)).join('');
  }
  if (excludeSimilar) {
    const banned = new Set(excludeSimilar);
    out = [...out].filter((c) => !banned.has(c)).join('');
  }
  return out;
}

/**
 * Random-mode password.
 *
 * When `requireEachClass` is on, one character is drawn from each enabled class
 * and the rest from the union — then shuffled. Without the shuffle, "first char
 * is always uppercase" is a structural leak that survives even when each
 * character is individually uniform.
 */
export function generatePassword(opts: PasswordOptions): string {
  const sets = activeSets(opts).map((s) => ({
    label: s.label,
    chars: strip(s.chars, opts.excludeAmbiguous, opts.excludeSimilar ? SIMILAR_CHARS : ''),
  }));
  const usable = sets.filter((s) => s.chars.length > 0);

  // Every class filtered itself away (e.g. PIN-like config with symbols only) —
  // fall back to lowercase rather than emit an empty string.
  if (usable.length === 0) {
    return Array.from({ length: opts.length }, () => pick(CHARSETS.lowercase)).join('');
  }

  const length = Math.max(1, Math.floor(opts.length));
  const chars: string[] = [];

  if (opts.requireEachClass && length >= usable.length) {
    for (const set of usable) chars.push(pick(set.chars));
  }

  const union = usable.map((s) => s.chars).join('');
  while (chars.length < length) chars.push(pick(union));

  return shuffle(chars).join('');
}

export function generatePassphrase(opts: PassphraseOptions): string {
  const words = Array.from({ length: opts.wordCount }, () => {
    const w = WORDLIST[randomInt(WORDLIST.length)];
    return opts.capitalize ? w.charAt(0).toUpperCase() + w.slice(1) : w;
  });
  let out = words.join(opts.separator);
  if (opts.appendNumber) out += String(randomInt(100));
  return out;
}

export function generatePin(length: number): string {
  return Array.from({ length: Math.max(1, Math.floor(length)) }, () => pick(CHARSETS.numbers)).join('');
}

/** Uniformly-chosen-character mode. Used by the bulk generator and by history replay. */
export function generateForMode(mode: PasswordMode, p: PasswordOptions, ph: PassphraseOptions, pinLength: number): string {
  if (mode === 'passphrase') return generatePassphrase(ph);
  if (mode === 'pin') return generatePin(pinLength);
  return generatePassword(p);
}
