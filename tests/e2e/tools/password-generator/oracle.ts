import { readFileSync } from 'node:fs';
import path from 'node:path';
import type { Rng } from '../_support/rng';

/**
 * Independent expectations for the Password Generator.
 *
 * The generator's output is random by design, so the oracle does not predict
 * values. It states which values are POSSIBLE for a configuration (length,
 * pool, required classes, word list, separators) and what every derived number
 * on the page must be. The page computes entropy with floating point
 * `length * Math.log2(pool)`; this file counts the keyspace with BigInt and
 * takes the bit count from that, so a shared mistake cannot hide.
 *
 * DEFINITIONS (in words, with their source)
 *
 * Character classes — "Character types" buttons: Uppercase A–Z (26), Lowercase
 *   a–z (26), Numbers 0–9 (10), Symbols (23: the punctuation set below; the
 *   button shows the sample "!@#$%"; the full set is a product decision recorded
 *   from frontend/src/lib/password/generator.ts CHARSETS.symbols and verified
 *   behaviourally: the characters observed over thousands of generated
 *   characters must be exactly this pool and "Character pool: N" must equal it).
 * Avoid look-alike characters — hint on the page: "Drops 0 O o 1 l I | / \".
 * Avoid shell-hostile symbols — hint on the page: "Drops quotes, backslash,
 *   brackets and spaces". The tool additionally drops ~ . , : ; (only ~ is in the
 *   pool). Recorded as the page's definition. Separately, POSIX (Shell Command
 *   Language 2.2 "Quoting") lists the characters a shell always treats
 *   specially: | & ; < > ( ) $ ` \ " ' space tab newline. See POSIX_SHELL_SPECIAL.
 * Include at least one of each selected type — every value contains a
 *   character of each selected class.
 * Entropy — bits = log2(number of equally likely values), shown as a whole
 *   number (rounded to nearest):
 *     random:     pool ^ length        ("Character pool" x "Entropy per character")
 *     passphrase: 7776 ^ words, x100 when a number 0–99 is appended
 *     PIN:        10 ^ digits
 * Strength label — from the displayed bits: below 36 Very Weak, below 60 Weak,
 *   below 80 Fair, below 100 Strong, otherwise Very Strong (product decision,
 *   frontend/src/lib/password/entropy.ts levelForBits; the page does not print
 *   the thresholds).
 * Crack time — median time for an offline attacker making 10^10 guesses per
 *   second: half the keyspace, 2^(bits-1) guesses (entropy.ts
 *   ATTACKER_GUESSES_PER_SECOND / crackSeconds). Printed in the largest unit
 *   that is at least 1 (seconds, minutes, hours, days, Julian years, then
 *   thousand / million / billion years), rounded to nearest; below one second
 *   "Instantly"; from 10^12 years "Longer than the age of the universe".
 * History "Contains" — which of lower / upper / digit / symbol occur, in that order.
 * History "Generated" — age of the entry: under a minute "Just now", then
 *   "Nm ago", "Nh ago", "Yesterday", "Nd ago" (under a week), then the date.
 */

export type Mode = 'password' | 'passphrase' | 'pin';
export type ClassKey = 'uppercase' | 'lowercase' | 'numbers' | 'symbols';

export const CLASS_KEYS: ClassKey[] = ['uppercase', 'lowercase', 'numbers', 'symbols'];

const range = (from: string, count: number) =>
  Array.from({ length: count }, (_, i) => String.fromCharCode(from.charCodeAt(0) + i)).join('');

export const CLASS_CHARS: Record<ClassKey, string> = {
  uppercase: range('A', 26),
  lowercase: range('a', 26),
  numbers: range('0', 10),
  symbols: '!@#$%^&*()-_=+[]{}<>?/~',
};

/** Named on the page next to "Avoid look-alike characters". */
export const LOOK_ALIKE = ['0', 'O', 'o', '1', 'l', 'I', '|', '/', '\\'];

/** Named on the page next to "Avoid shell-hostile symbols": quotes, backslash, brackets, spaces. */
export const SHELL_HOSTILE_DOCUMENTED = ['\'', '"', '`', '\\', '(', ')', '[', ']', '{', '}', '<', '>', ' '];
/** Also dropped by the tool, not named in the hint. */
export const SHELL_HOSTILE_EXTRA = ['~', '.', ',', ':', ';'];

/** POSIX Shell Command Language 2.2: characters that must be quoted to represent themselves. */
export const POSIX_SHELL_SPECIAL = ['|', '&', ';', '<', '>', '(', ')', '$', '`', '\\', '"', '\'', ' ', '\t', '\n'];

export interface RandomConfig {
  length: number;
  classes: ClassKey[];
  requireEach: boolean;
  avoidLookAlike: boolean;
  avoidShellHostile: boolean;
}

export const RANDOM_DEFAULTS: RandomConfig = {
  length: 20,
  classes: [...CLASS_KEYS],
  requireEach: true,
  avoidLookAlike: false,
  avoidShellHostile: false,
};

export const RANDOM_LENGTH = { min: 4, max: 128, presets: [8, 12, 16, 20, 32, 64] };
export const WORD_COUNT = { min: 3, max: 10, presets: [3, 4, 5, 6, 7] };
export const PIN_LENGTH = { min: 4, max: 16, presets: [4, 6, 8] };
export const BULK_COUNTS = [5, 10, 25, 50];
export const HISTORY_LIMIT = 25;

/** Characters of one class that survive the two "avoid" options. */
export function classPool(key: ClassKey, config: Pick<RandomConfig, 'avoidLookAlike' | 'avoidShellHostile'>): string[] {
  const dropped = new Set<string>();
  if (config.avoidLookAlike) LOOK_ALIKE.forEach(c => dropped.add(c));
  if (config.avoidShellHostile) [...SHELL_HOSTILE_DOCUMENTED, ...SHELL_HOSTILE_EXTRA].forEach(c => dropped.add(c));
  return [...CLASS_CHARS[key]].filter(c => !dropped.has(c));
}

/** Every character a value may contain for this configuration. */
export function poolFor(config: RandomConfig): string[] {
  return CLASS_KEYS.filter(k => config.classes.includes(k)).flatMap(k => classPool(k, config));
}

export function classOf(ch: string): ClassKey {
  if (ch >= 'A' && ch <= 'Z') return 'uppercase';
  if (ch >= 'a' && ch <= 'z') return 'lowercase';
  if (ch >= '0' && ch <= '9') return 'numbers';
  return 'symbols';
}

/** Reasons a value is not a possible output of `config`. Empty when it is. */
export function randomValueProblems(value: string, config: RandomConfig): string[] {
  const problems: string[] = [];
  const pool = new Set(poolFor(config));
  if (value.length !== config.length) problems.push(`length ${value.length}, expected ${config.length}`);
  const foreign = [...new Set([...value].filter(c => !pool.has(c)))];
  if (foreign.length) problems.push(`characters outside the selected pool: ${foreign.map(c => JSON.stringify(c)).join(' ')}`);
  if (config.requireEach) {
    for (const key of config.classes) {
      if (![...value].some(c => classOf(c) === key)) problems.push(`no ${key} character although "at least one of each selected type" is on`);
    }
  }
  return problems;
}

// ---------------------------------------------------------------------------
// Entropy, label, crack time

/** Whole bits for a keyspace of `count` equally likely values: round(log2(count)), exactly. */
export function bitsForKeyspace(count: bigint): number {
  if (count <= 1n) return 0;
  // round(log2 K) = b  <=>  2^(2b-1) <= K^2 < 2^(2b+1)  <=>  b = ceil(floor(log2 K^2) / 2)
  const floorLog2OfSquare = (count * count).toString(2).length - 1;
  return Math.ceil(floorLog2OfSquare / 2);
}

export function randomKeyspace(config: RandomConfig): bigint {
  return BigInt(poolFor(config).length) ** BigInt(config.length);
}

/**
 * Number of values of `config.length` characters that contain at least one
 * character of every selected class (inclusion–exclusion over the classes left
 * out). This is the largest keyspace "at least one of each selected type" can have.
 */
export function keyspaceWithEveryClass(config: RandomConfig): bigint {
  const sizes = CLASS_KEYS.filter(k => config.classes.includes(k)).map(k => BigInt(classPool(k, config).length));
  let total = 0n;
  for (let mask = 0; mask < 2 ** sizes.length; mask++) {
    let pool = 0n;
    let left = 0;
    sizes.forEach((size, i) => { if (Math.floor(mask / 2 ** i) % 2 === 1) left++; else pool += size; });
    const term = pool ** BigInt(config.length);
    total += left % 2 === 1 ? -term : term;
  }
  return total;
}

export interface PassphraseConfig {
  words: number;
  separator: string;
  capitalise: boolean;
  appendNumber: boolean;
}

export const PASSPHRASE_DEFAULTS: PassphraseConfig = { words: 4, separator: '-', capitalise: true, appendNumber: false };

/** Separator buttons in page order; the space is drawn as an open box. */
export const SEPARATORS: { value: string; button: string }[] = [
  { value: '-', button: '-' },
  { value: '.', button: '.' },
  { value: '_', button: '_' },
  { value: ' ', button: '␣' },
  { value: '+', button: '+' },
];

export const WORDLIST_SIZE = 7776;

export function passphraseKeyspace(config: Pick<PassphraseConfig, 'words' | 'appendNumber'>): bigint {
  return BigInt(WORDLIST_SIZE) ** BigInt(config.words) * (config.appendNumber ? 100n : 1n);
}

export function pinKeyspace(digits: number): bigint {
  return 10n ** BigInt(digits);
}

export type StrengthLabel = 'Very Weak' | 'Weak' | 'Fair' | 'Strong' | 'Very Strong';
export const STRENGTH_ORDER: StrengthLabel[] = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];

export function labelForBits(bits: number): StrengthLabel {
  const floors: [number, StrengthLabel][] = [[100, 'Very Strong'], [80, 'Strong'], [60, 'Fair'], [36, 'Weak']];
  for (const [floor, label] of floors) if (bits >= floor) return label;
  return 'Very Weak';
}

const GUESSES_PER_SECOND = 10n ** 10n;
const JULIAN_YEAR_SECONDS = 31_557_600n;

function grouped(value: bigint): string {
  return value.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/** round(numerator / denominator), halves up, for positive values. */
function roundedRatio(numerator: bigint, denominator: bigint): bigint {
  return (2n * numerator + denominator) / (2n * denominator);
}

/** Median offline crack time for `bits` of entropy, as the page words it. */
export function crackTimeText(bits: number): string {
  const guesses = 2n ** BigInt(Math.max(0, bits - 1));
  // seconds = guesses / GUESSES_PER_SECOND, kept as a fraction.
  const atLeast = (seconds: bigint) => guesses >= seconds * GUESSES_PER_SECOND;
  if (!atLeast(1n)) return 'Instantly';
  const small: [bigint, string][] = [[86_400n, 'day'], [3_600n, 'hour'], [60n, 'minute'], [1n, 'second']];
  if (!atLeast(JULIAN_YEAR_SECONDS)) {
    for (const [unitSeconds, unit] of small) {
      if (!atLeast(unitSeconds)) continue;
      const n = roundedRatio(guesses, unitSeconds * GUESSES_PER_SECOND);
      return `${grouped(n)} ${unit}${n === 1n ? '' : 's'}`;
    }
  }
  const years = (scale: bigint) => roundedRatio(guesses, JULIAN_YEAR_SECONDS * GUESSES_PER_SECOND * scale);
  const yearsAtLeast = (y: bigint) => atLeast(JULIAN_YEAR_SECONDS * y);
  if (!yearsAtLeast(1_000n)) return `${grouped(years(1n))} years`;
  if (!yearsAtLeast(10n ** 6n)) return `${grouped(years(10n ** 3n))} thousand years`;
  if (!yearsAtLeast(10n ** 9n)) return `${grouped(years(10n ** 6n))} million years`;
  if (!yearsAtLeast(10n ** 12n)) return `${grouped(years(10n ** 9n))} billion years`;
  return 'Longer than the age of the universe';
}

export interface StrengthExpectation {
  bits: number;
  label: StrengthLabel;
  /** Text of the right-hand part of the strength line. */
  detail: string;
}

export function expectedStrength(keyspace: bigint): StrengthExpectation {
  const bits = bitsForKeyspace(keyspace);
  return { bits, label: labelForBits(bits), detail: `${bits} bits · ~${crackTimeText(bits)}` };
}

/** `log2(n)` to two decimals, as "Entropy per character" and "bits per word" print it. */
export function log2Fixed2(n: number): string {
  if (n <= 0) return '0.00';
  // Bisection on 2^x = n instead of Math.log2, to stay independent of the page.
  let lo = 0;
  let hi = 64;
  for (let i = 0; i < 80; i++) {
    const mid = (lo + hi) / 2;
    if (2 ** mid < n) lo = mid; else hi = mid;
  }
  return ((lo + hi) / 2).toFixed(2);
}

// ---------------------------------------------------------------------------
// Word list (read as data from the tool's own list; membership only)

let cachedWords: string[] | null = null;

/** The tool's word list, read from its source file as plain text. */
export function wordList(): string[] {
  if (cachedWords) return cachedWords;
  const file = path.resolve(__dirname, '../../../../frontend/src/lib/password/wordlist.ts');
  const fragments: string[] = [];
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    const match = line.match(/^\s+'([^']*)'\s*(\+|;)\s*$/);
    if (match) fragments.push(match[1]);
  }
  cachedWords = fragments.join('').split(' ').filter(Boolean);
  return cachedWords;
}

export interface ParsedPassphrase {
  words: string[];
  number: string | null;
}

/**
 * Splits a passphrase into list words for `config`, or explains why it cannot
 * be one. Some list words contain a hyphen ("yo-yo"), so the split tries every
 * separator position instead of a plain `split`.
 */
export function parsePassphrase(value: string, config: PassphraseConfig, list: Set<string>): ParsedPassphrase | string {
  let body = value;
  let number: string | null = null;
  const trailingDigits = value.match(/[0-9]+$/)?.[0] ?? '';
  if (config.appendNumber) {
    if (trailingDigits === '') return 'no number at the end although "Append a random number (0–99)" is on';
    if (trailingDigits.length > 2) return `number "${trailingDigits}" is outside 0–99`;
    if (trailingDigits.length === 2 && trailingDigits[0] === '0') return `number "${trailingDigits}" has a leading zero`;
    number = trailingDigits;
    body = value.slice(0, value.length - trailingDigits.length);
  } else if (trailingDigits !== '') {
    return `ends with digits "${trailingDigits}" although no number was requested`;
  }

  const isWord = (piece: string): boolean => {
    if (piece === '') return false;
    if (!config.capitalise) return list.has(piece);
    const first = piece[0];
    return first === first.toUpperCase() && first !== first.toLowerCase() && list.has(first.toLowerCase() + piece.slice(1));
  };

  const split = (rest: string, wordsLeft: number): string[] | null => {
    if (wordsLeft === 1) return isWord(rest) ? [rest] : null;
    for (let at = rest.indexOf(config.separator); at !== -1; at = rest.indexOf(config.separator, at + 1)) {
      const head = rest.slice(0, at);
      if (!isWord(head)) continue;
      const tail = split(rest.slice(at + config.separator.length), wordsLeft - 1);
      if (tail) return [head, ...tail];
    }
    return null;
  };

  const words = split(body, config.words);
  if (!words) {
    return `is not ${config.words} word-list words joined by ${JSON.stringify(config.separator)}`
      + `${config.capitalise ? ', each capitalised' : ', all lower case'}`;
  }
  return { words: words.map(w => w.toLowerCase()), number };
}

export function pinProblems(value: string, digits: number): string[] {
  const problems: string[] = [];
  if (value.length !== digits) problems.push(`length ${value.length}, expected ${digits}`);
  if (!/^[0-9]*$/.test(value)) problems.push('contains something other than digits');
  return problems;
}

// ---------------------------------------------------------------------------
// Statistics: bounds chosen so a correct generator fails with probability < 1e-9

export const FALSE_FAILURE = 1e-9;

/**
 * Upper bound for Pearson's chi-square statistic with `df` degrees of freedom
 * that a uniform source exceeds with probability below `falseFailure`
 * (Laurent–Massart: P(X - df >= 2*sqrt(df*x) + 2x) <= e^-x).
 */
export function chiSquareLimit(df: number, falseFailure = FALSE_FAILURE): number {
  const x = Math.log(1 / falseFailure);
  return df + 2 * Math.sqrt(df * x) + 2 * x;
}

/** Pearson's statistic for observed counts against equal expected counts. */
export function chiSquareUniform(counts: number[]): number {
  const total = counts.reduce((a, b) => a + b, 0);
  const expected = total / counts.length;
  return counts.reduce((sum, c) => sum + (c - expected) ** 2 / expected, 0);
}

/**
 * Range a Binomial(n, p) count stays inside with probability above
 * 1 - falseFailure (Hoeffding: P(|X - np| >= t) <= 2 e^(-2 t^2 / n)).
 */
export function binomialRange(n: number, p: number, falseFailure = FALSE_FAILURE): { min: number; max: number } {
  const t = Math.sqrt((n * Math.log(2 / falseFailure)) / 2);
  return { min: Math.max(0, Math.floor(n * p - t)), max: Math.min(n, Math.ceil(n * p + t)) };
}

/**
 * Smallest count m such that, drawing `draws` times uniformly from `choices`
 * values, the chance that any single value comes up m or more times is below
 * `falseFailure` (union bound: choices * C(draws, m) / choices^m).
 */
export function repeatLimit(draws: number, choices: number, falseFailure = FALSE_FAILURE): number {
  for (let m = 2; m <= draws; m++) {
    // log of choices * C(draws, m) * choices^-m
    let logBound = Math.log(choices) - m * Math.log(choices);
    for (let i = 0; i < m; i++) logBound += Math.log(draws - i) - Math.log(i + 1);
    if (logBound < Math.log(falseFailure)) return m;
  }
  return draws + 1;
}

// ---------------------------------------------------------------------------
// History table

export function containsText(value: string): string {
  const present = new Set([...value].map(classOf));
  const names: [ClassKey, string][] = [['lowercase', 'lower'], ['uppercase', 'upper'], ['numbers', 'digit'], ['symbols', 'symbol']];
  return names.filter(([key]) => present.has(key)).map(([, name]) => name).join(' + ') || 'none';
}

export const TIMEZONE = process.env.E2E_TIMEZONE ?? 'America/New_York';

function zoneParts(ts: number): Record<string, string> {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: TIMEZONE, year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true,
  }).formatToParts(new Date(ts));
  return Object.fromEntries(parts.map(p => [p.type, p.value]));
}

/** Full timestamp used in a history row's tooltip and button names: "Nov 27, 2026, 06:09:40 AM". */
export function fullTimestamp(ts: number): string {
  const p = zoneParts(ts);
  return `${p.month} ${p.day}, ${p.year}, ${p.hour}:${p.minute}:${p.second} ${p.dayPeriod}`;
}

/** Calendar day number (days since 1970-01-01) of `ts` in the browser's time zone. */
export function calendarDay(ts: number): number {
  const p = new Intl.DateTimeFormat('en-CA', { timeZone: TIMEZONE, year: 'numeric', month: '2-digit', day: '2-digit' })
    .formatToParts(new Date(ts));
  const get = (type: string) => Number(p.find(x => x.type === type)?.value);
  return Math.round(Date.UTC(get('year'), get('month') - 1, get('day')) / 86_400_000);
}

/** The "Generated" column for an entry made at `ts`, seen at `now`. */
export function relativeTimeText(ts: number, now: number): string {
  const age = now - ts;
  const MIN = 60_000;
  const HOUR = 60 * MIN;
  const DAY = 24 * HOUR;
  if (age < MIN) return 'Just now';
  if (age < HOUR) return `${Math.floor(age / MIN)}m ago`;
  if (age < DAY) return `${Math.floor(age / HOUR)}h ago`;
  if (age < 2 * DAY) return 'Yesterday';
  if (age < 7 * DAY) return `${Math.floor(age / DAY)}d ago`;
  const p = zoneParts(ts);
  return `${p.month} ${p.day}`;
}

/** Collapses the narrow no-break space some ICU versions put before AM/PM. */
export function normaliseSpaces(text: string): string {
  return text.replace(/[\u00a0\u202f]/g, ' ');
}

// ---------------------------------------------------------------------------
// Random configurations

export function randomRandomConfig(rng: Rng, overrides: Partial<RandomConfig> = {}): RandomConfig {
  const classes = CLASS_KEYS.filter(() => rng.bool(0.6));
  if (classes.length === 0) classes.push(rng.pick(CLASS_KEYS));
  return {
    length: rng.weighted([RANDOM_LENGTH.min, RANDOM_LENGTH.max, rng.int(5, 24), rng.int(25, 127)], [1, 1, 5, 3]),
    classes,
    requireEach: rng.bool(),
    avoidLookAlike: rng.bool(0.4),
    avoidShellHostile: rng.bool(0.4),
    ...overrides,
  };
}

export function randomPassphraseConfig(rng: Rng, overrides: Partial<PassphraseConfig> = {}): PassphraseConfig {
  return {
    words: rng.int(WORD_COUNT.min, WORD_COUNT.max),
    separator: rng.pick(SEPARATORS).value,
    capitalise: rng.bool(),
    appendNumber: rng.bool(),
    ...overrides,
  };
}

export function describeRandom(config: RandomConfig): string {
  return `random ${config.length} chars, ${config.classes.join('+')}`
    + `${config.requireEach ? ', one of each' : ''}${config.avoidLookAlike ? ', no look-alikes' : ''}${config.avoidShellHostile ? ', no shell-hostile' : ''}`;
}

export function describePassphrase(config: PassphraseConfig): string {
  return `passphrase ${config.words} words, separator ${JSON.stringify(config.separator)}`
    + `${config.capitalise ? ', capitalised' : ''}${config.appendNumber ? ', with number' : ''}`;
}
