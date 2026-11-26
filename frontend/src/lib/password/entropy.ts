/**
 * Strength scoring — Shannon entropy, plus the deductions that make the number honest.
 *
 * The headline figure is H = L · log2(N): how many bits of entropy a uniformly
 * random password of this length, drawn from this pool, would carry. That is the
 * correct number for *generated* passwords and the only number that means anything.
 *
 * But the same formula applied to `password123!` would report 60 bits and be
 * wrong by many orders of magnitude, because it assumes the attacker brute-forces
 * a flat keyspace. So we subtract for the ways a human's output leaks: repeated
 * characters, low run diversity, a sequential run like `abcdef`, or a word that
 * appears verbatim in the EFF wordlist. What survives is what an attacker who
 * knows your password style would actually face.
 */

import { CHARSETS, SIMILAR_CHARS } from './generator';
import { BITS_PER_WORD, WORDLIST } from './wordlist';

export type StrengthLevel = 'very-weak' | 'weak' | 'fair' | 'strong' | 'very-strong';

export interface StrengthResult {
  /**
   * The honest figure: bits of entropy after pattern penalties.
   *
   * For a *generated* value this is exact — a uniform draw from a pool of N
   * carries L·log2(N) bits regardless of which characters happened to land, and
   * pattern-matching its output would only manufacture a penalty. For a *human's*
   * password it is an estimate, and the lower of the two defensible numbers.
   */
  bits: number;
  /** 0–4, index into LEVELS. */
  score: number;
  level: StrengthLevel;
  label: string;
  color: string;
  /** 0–100, width of the meter fill. */
  percent: number;
  /** Naive H = L·log2(N) before penalties, so the UI can show what we subtracted. */
  rawBits: number;
  /** Human-readable offline brute-force time. */
  crackTime: string;
  tips: string[];
  /**
   * True when `bits` is the exact entropy of a generated value rather than an
   * estimate made by pattern-matching a string. The UI shows "estimated" only
   * when this is false, so users are never shown a false precision.
   */
  exact: boolean;
}

/**
 * Guesses per second for an attacker with a rack of GPUs against a fast hash
 * (MD5/NTLM). Deliberately pessimistic: bcrypt/argon2 are ~5 orders of magnitude
 * slower, so every number here is a floor, not a ceiling.
 */
const ATTACKER_GUESSES_PER_SECOND = 1e10;

/** Above this, "centuries" is the most honest unit we can print. */
const CENTURY_SECONDS = 100 * 365.25 * 24 * 3600;

export const LEVELS: Record<StrengthLevel, { label: string; color: string; percent: number }> = {
  'very-weak': { label: 'Very Weak', color: 'var(--accent-red)', percent: 12 },
  weak: { label: 'Weak', color: '#f97316', percent: 32 },
  fair: { label: 'Fair', color: 'var(--accent-amber)', percent: 55 },
  strong: { label: 'Strong', color: 'var(--accent-green)', percent: 80 },
  'very-strong': { label: 'Very Strong', color: 'var(--accent-cyan)', percent: 100 },
};

export const LEVEL_ORDER: StrengthLevel[] = ['very-weak', 'weak', 'fair', 'strong', 'very-strong'];

export function levelForBits(bits: number): StrengthLevel {
  if (bits < 36) return 'very-weak';
  if (bits < 60) return 'weak';
  if (bits < 80) return 'fair';
  if (bits < 100) return 'strong';
  return 'very-strong';
}

/**
 * Size of the pool a password *could* have been drawn from. Distinct characters
 * present, plus a bonus when several character classes appear — because
 * `aB3$` genuinely resists attacks that a single-class pool of the same length
 * would not. Floored at 2 so a single-character password does not divide by zero.
 */
function effectivePoolSize(password: string): number {
  const distinct = new Set(password).size;
  const classes =
    (/[a-z]/.test(password) ? 1 : 0) +
    (/[A-Z]/.test(password) ? 1 : 0) +
    (/[0-9]/.test(password) ? 1 : 0) +
    (/[^a-zA-Z0-9]/.test(password) ? 1 : 0);
  return Math.max(2, distinct + (classes - 1) * 4);
}

/** Shannon entropy of the character distribution, in bits per character. */
function characterEntropy(password: string): number {
  const counts = new Map<string, number>();
  for (const c of password) counts.set(c, (counts.get(c) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / password.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Longest run of identical characters, e.g. the `aaa` in `Xaaa9!`. */
function longestRun(password: string): number {
  let best = 1;
  let run = 1;
  for (let i = 1; i < password.length; i++) {
    run = password[i] === password[i - 1] ? run + 1 : 1;
    if (run > best) best = run;
  }
  return password.length ? best : 0;
}

/** Ascending or descending sequential runs of 3+, e.g. `abcd`, `4321`, `789`. */
function hasSequentialRun(password: string): boolean {
  const delta = (i: number) => password.charCodeAt(i) - password.charCodeAt(i - 1);
  let up = 1;
  let down = 1;
  for (let i = 1; i < password.length; i++) {
    const d = delta(i);
    up = d === 1 ? up + 1 : 1;
    down = d === -1 ? down + 1 : 1;
    if (up >= 3 || down >= 3) return true;
  }
  return false;
}

/** Any alphabetic run of 4+ that is a verbatim dictionary word (`summer`, `dragon`). */
function hasDictionaryWord(password: string): boolean {
  const words = new Set(WORDLIST);
  for (let start = 0; start < password.length; start++) {
    for (let len = 4; len <= 10 && start + len <= password.length; len++) {
      if (words.has(password.slice(start, start + len).toLowerCase())) return true;
    }
  }
  return false;
}

/**
 * Bits an attacker saves from knowing the structure of this particular password.
 * These are estimates, not proofs — the intent is to be directionally honest
 * rather than to reproduce zxcvbn's matching engine.
 *
 * Only meaningful for a human-authored string. A 20-character draw from an
 * 89-symbol pool is *expected* to contain a 4-letter word from a 7,776-word list
 * and to repeat a character; neither leaks anything when the keyspace is the
 * pool itself rather than the pattern. `assessStrength` therefore skips this
 * entirely whenever the caller supplied the true pool.
 */
function penaltyBits(password: string, distinctCount: number): number {
  let penalty = 0;
  const run = longestRun(password);
  if (run >= 2) penalty += Math.min(30, 2 * (run - 1));
  if (distinctCount < password.length) penalty += 5;
  if (hasSequentialRun(password)) penalty += 12;
  if (hasDictionaryWord(password)) penalty += 15;
  if (password.length < 8) penalty += 10;
  return penalty;
}

/**
 * Human-readable time for a naive attacker running at ATTACKER_GUESSES_PER_SECOND.
 * Expects half the keyspace on average, so this is the *median* crack time.
 */
export function formatCrackTime(seconds: number): string {
  if (seconds < 1) return 'Instantly';
  if (seconds < 60) return `${Math.round(seconds)} second${Math.round(seconds) === 1 ? '' : 's'}`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} minute${Math.round(seconds / 60) === 1 ? '' : 's'}`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hour${Math.round(seconds / 3600) === 1 ? '' : 's'}`;
  if (seconds < 31557600) return `${Math.round(seconds / 86400)} day${Math.round(seconds / 86400) === 1 ? '' : 's'}`;

  const years = seconds / 31557600;
  if (years < 1000) return `${Math.round(years).toLocaleString()} years`;
  if (years < 1e6) return `${Math.round(years / 1e3).toLocaleString()} thousand years`;
  if (years < 1e9) return `${Math.round(years / 1e6).toLocaleString()} million years`;
  if (years < 1e12) return `${Math.round(years / 1e9).toLocaleString()} billion years`;
  if (seconds < CENTURY_SECONDS * 1e6) return `${Math.round(years / 1e12).toLocaleString()} trillion years`;
  return 'Longer than the age of the universe';
}

export function crackSeconds(bits: number): number {
  return Math.pow(2, Math.max(0, bits - 1)) / ATTACKER_GUESSES_PER_SECOND;
}

/** Bits a passphrase of `wordCount` words carries if each word is uniform over the list. */
export function passphraseBits(wordCount: number): number {
  return wordCount * BITS_PER_WORD;
}

/** The character classes present, for the syntax-highlighted display. */
export function characterClass(ch: string): 'lower' | 'upper' | 'digit' | 'symbol' {
  if (ch >= '0' && ch <= '9') return 'digit';
  if (ch >= 'a' && ch <= 'z') return 'lower';
  if (ch >= 'A' && ch <= 'Z') return 'upper';
  return 'symbol';
}

function buildTips(password: string, bits: number, generated: boolean): string[] {
  // A generated value is already as strong as the settings allow, so every
  // tip here would be telling the user to change a setting that is not the
  // problem. Confirm and stop.
  if (generated) {
    if (bits >= 128) {
      return ['High entropy for resistance to offline guessing.'];
    }
    if (bits < 40) {
      // A PIN is never going to be strong, and no amount of clicking changes
      // that. Say so rather than implying the slider is the problem.
      return [
        'A PIN this short is only safe against casual shoulder-surfing — it can be brute-forced in seconds offline.',
        'Use a password or passphrase for anything a real attacker would target.',
      ];
    }
    // Words and digits are counted differently, so name the lever that applies.
    const advice = bits < 52
      ? 'More words is the lever here: 5+ words clears 60 bits, 7 clears 90.'
      : bits < 80
        ? 'Solid for most services. Add a word or two for accounts that hold something worth stealing.'
        : 'Strong. Add a word or two if you want it future-proof against offline cracking.';
    return [advice];
  }

  const tips: string[] = [];

  if (password.length < 16) tips.push('Go longer — 16+ characters is the single biggest win available.');
  if (!/[0-9]/.test(password)) tips.push('Add digits (0-9) to widen the character pool.');
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password)) tips.push('Mix upper and lower case.');
  if (!/[^a-zA-Z0-9]/.test(password)) tips.push('Add symbols (!@#$) — they add more entropy per character than letters do.');
  if (new Set(password).size < password.length / 2) tips.push('Too many repeated characters — reuse collapses the effective keyspace.');
  if (hasDictionaryWord(password)) tips.push('Contains a real word. Attackers try dictionary words first.');
  if (hasSequentialRun(password)) tips.push('Contains a sequential run like abc or 4321 — these are in every cracking ruleset.');
  if (bits >= 100) tips.push('Excellent. This resists offline cracking even with a GPU cluster.');
  else if (bits >= 80) tips.push('Strong. Safe for nearly everything short of a nation-state.');

  return tips.length ? tips.slice(0, 3) : ['Solid password. Nothing obvious for an attacker to exploit.'];
}

/**
 * Score a password.
 *
 * `poolSize` is the caller's *configured* pool — the `N` in L·log2(N). When it is
 * supplied we know the value is a uniform draw from that pool, so H = L·log2(N)
 * is exact and no pattern deduction applies. This is the path every generated
 * password takes, and it matters: a naive "spot the dictionary word" pass would
 * dock a perfectly uniform 20-character random string for containing `idle`,
 * which is an artefact of the EFF list, not a weakness.
 *
 * Pass undefined to infer the pool from the string itself and apply the pattern
 * deductions. That is the honest path for anything a human typed, and for
 * history entries replayed without their original settings.
 *
 * `knownBits` overrides the L·log2(N) calculation for modes whose entropy is not
 * a function of their character pool — a passphrase is counted in *words*
 * (wordCount · log2(7776) ≈ 12.9 bits each), not characters. Without it a
 * 4-word passphrase is scored by its ~40 characters of letters and reports
 * 120 bits, more than double the ~52 it actually carries.
 */
export function assessStrength(password: string, poolSize?: number, knownBits?: number): StrengthResult {
  if (!password) {
    return {
      bits: 0, score: 0, level: 'very-weak', label: LEVELS['very-weak'].label,
      color: LEVELS['very-weak'].color, percent: 0, rawBits: 0,
      crackTime: 'Instantly', exact: true, tips: ['Generate a password to see its strength.'],
    };
  }

  // A known bit count is as authoritative as a known pool — both mean "we
  // generated this, stop guessing at it".
  const generated = (!!poolSize && poolSize > 1) || knownBits !== undefined;
  const pool = poolSize && poolSize > 1 ? poolSize : effectivePoolSize(password);
  const rawBits = knownBits !== undefined
    ? knownBits
    : password.length * Math.log2(pool);
  const distinct = new Set(password).size;

  // Entropy above the naive formula, which we cap against in the estimate path.
  // Shannon entropy of the observed character distribution is never above
  // L·log2(distinct) — that inequality is what makes a uniform random string
  // *look* weak here — so there is nothing to average in.
  const distributionBits = characterEntropy(password) * password.length;

  const base = generated
    ? rawBits
    : Math.min(rawBits, Math.max(distributionBits, password.length * Math.log2(distinct)));

  const bits = Math.max(0, Math.round(base - (generated ? 0 : penaltyBits(password, distinct))));

  const level = levelForBits(bits);
  const meta = LEVELS[level];

  return {
    bits,
    score: LEVEL_ORDER.indexOf(level),
    level,
    label: meta.label,
    color: meta.color,
    percent: meta.percent,
    rawBits: Math.round(rawBits),
    crackTime: formatCrackTime(crackSeconds(bits)),
    exact: generated,
    tips: buildTips(password, bits, generated),
  };
}

/** Which of the four standard classes the string contains — used for table badges. */
export function describeComposition(password: string): string {
  const parts: string[] = [];
  if (/[a-z]/.test(password)) parts.push('lower');
  if (/[A-Z]/.test(password)) parts.push('upper');
  if (/[0-9]/.test(password)) parts.push('digit');
  if (/[^a-zA-Z0-9]/.test(password)) parts.push('symbol');
  return parts.join(' + ') || 'none';
}

export const CLASS_HINTS = {
  lower: CHARSETS.lowercase,
  upper: CHARSETS.uppercase,
  digit: CHARSETS.numbers,
  symbol: CHARSETS.symbols,
} as const;

/** Characters that trip copy/paste or shell quoting when used in a credential. */
export const RISKY_CHARS = SIMILAR_CHARS;
