import type { Rng } from '../_support/rng';

/**
 * Independent chmod arithmetic, written from the POSIX definition of a file
 * mode (chmod(1), ls(1)), not from the page.
 *
 * Definitions
 * -----------
 *  - A mode is three permission sets (owner, group, others), each with a read,
 *    a write and an execute flag, plus three special flags: setuid, setgid and
 *    sticky.
 *  - Octal notation: one digit per set, the sum of read = 4, write = 2 and
 *    execute = 1 (the page's own guide states the same). The special flags form
 *    an optional leading digit: setuid = 4, setgid = 2, sticky = 1. The tool
 *    writes three digits when no special flag is set and four otherwise.
 *  - Symbolic notation (`ls -l`): `r`, `w`, `x` or `-` for each flag in the
 *    order owner, group, others. The execute position changes with a special
 *    flag: setuid turns the owner's `x` into `s` and `-` into `S`; setgid does
 *    the same for the group; sticky turns the others' `x` into `t` and `-`
 *    into `T`.
 *  - `ls -la` output for a regular file is `-` followed by the symbolic form.
 *  - The octal field accepts exactly three or four characters, each 0–7.
 *    Anything else is a draft: the result on screen must not change.
 *
 * The page works with bit operators on numbers. Everything here is done with
 * lookup tables on characters, so the two cannot share an arithmetic mistake.
 */

export const ROLES = ['Owner', 'Group', 'Others'] as const;
export const PERMS = ['Read', 'Write', 'Execute'] as const;
export const SPECIALS = ['Setuid', 'Setgid', 'Sticky'] as const;
export type Role = (typeof ROLES)[number];
export type Perm = (typeof PERMS)[number];
export type Special = (typeof SPECIALS)[number];

/** Labels of the three special-bit checkboxes, as the tool names them. */
export const SPECIAL_LABELS: Record<Special, string> = {
  Setuid: 'Setuid (4xxx)',
  Setgid: 'Setgid (2xxx)',
  Sticky: 'Sticky (1xxx)',
};

/** One permission set in `ls` letters, for example `r-x`. */
type Triad = string;

export interface Mode {
  Owner: Triad;
  Group: Triad;
  Others: Triad;
  Setuid: boolean;
  Setgid: boolean;
  Sticky: boolean;
}

const OCTAL_DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7'] as const;

/** Octal digit → permission letters. The whole of "read 4, write 2, execute 1". */
const TRIAD_OF_DIGIT: Record<string, Triad> = {
  '0': '---', '1': '--x', '2': '-w-', '3': '-wx',
  '4': 'r--', '5': 'r-x', '6': 'rw-', '7': 'rwx',
};

/** Leading octal digit → special flags (setuid 4, setgid 2, sticky 1). */
const SPECIAL_OF_DIGIT: Record<string, Special[]> = {
  '0': [], '1': ['Sticky'], '2': ['Setgid'], '3': ['Setgid', 'Sticky'],
  '4': ['Setuid'], '5': ['Setuid', 'Sticky'], '6': ['Setuid', 'Setgid'], '7': ['Setuid', 'Setgid', 'Sticky'],
};

/** What the execute position shows when the set's special flag is on. */
const EXECUTE_WITH_SPECIAL: Record<Special, Record<string, string>> = {
  Setuid: { x: 's', '-': 'S' },
  Setgid: { x: 's', '-': 'S' },
  Sticky: { x: 't', '-': 'T' },
};

const SPECIAL_OF_ROLE: Record<Role, Special> = { Owner: 'Setuid', Group: 'Setgid', Others: 'Sticky' };

/** The sentence the Explanation box uses for each permission set. */
const SENTENCE_OF_TRIAD: Record<Triad, string> = {
  '---': 'has no permissions',
  '--x': 'can execute',
  '-w-': 'can write',
  '-wx': 'can write and execute',
  'r--': 'can read',
  'r-x': 'can read and execute',
  'rw-': 'can read and write',
  'rwx': 'can read, write, and execute',
};

export const WARNING_777 = '🔴 777 gives full access to everyone — major security risk!';
export const WARNING_WORLD_WRITABLE = '🟡 World-writable — other users can modify this file.';
export const WARNING_SETUID = '🟡 Setuid — file executes as the owning user.';
export const WARNING_SETGID = '🟡 Setgid — file executes as the owning group.';

function digitOfTriad(triad: Triad): string {
  const digit = OCTAL_DIGITS.find(d => TRIAD_OF_DIGIT[d] === triad);
  if (digit === undefined) throw new Error(`oracle: "${triad}" is not a permission set`);
  return digit;
}

function specialDigit(mode: Mode): string {
  const wanted = SPECIALS.filter(s => mode[s]).join('+');
  const digit = OCTAL_DIGITS.find(d => SPECIAL_OF_DIGIT[d].join('+') === wanted);
  if (digit === undefined) throw new Error('oracle: impossible special flags');
  return digit;
}

/**
 * Reads what a user typed into the octal field. `null` means "not a mode":
 * the page must keep showing the previous result.
 */
export function parseOctal(text: string): Mode | null {
  const chars = Array.from(text);
  if (chars.length !== 3 && chars.length !== 4) return null;
  if (!chars.every(c => c in TRIAD_OF_DIGIT)) return null;
  const lead = chars.length === 4 ? chars[0] : '0';
  const [owner, group, others] = chars.slice(-3);
  const flags = SPECIAL_OF_DIGIT[lead];
  return {
    Owner: TRIAD_OF_DIGIT[owner],
    Group: TRIAD_OF_DIGIT[group],
    Others: TRIAD_OF_DIGIT[others],
    Setuid: flags.includes('Setuid'),
    Setgid: flags.includes('Setgid'),
    Sticky: flags.includes('Sticky'),
  };
}

/** Builds a mode from octal text that is known to be valid. */
export function modeOf(octal: string): Mode {
  const mode = parseOctal(octal);
  if (!mode) throw new Error(`oracle: "${octal}" is not an octal mode`);
  return mode;
}

/** The mode the tool starts with (the input placeholder and first render: 755). */
export const DEFAULT_MODE: Mode = modeOf('755');

/** Three digits without special flags, four with: the form the tool displays. */
export function octalOf(mode: Mode): string {
  const body = ROLES.map(role => digitOfTriad(mode[role])).join('');
  const lead = specialDigit(mode);
  return lead === '0' ? body : lead + body;
}

/** Always four digits, the other spelling a user may type (`0755`). */
export function fourDigitOctalOf(mode: Mode): string {
  return specialDigit(mode) + ROLES.map(role => digitOfTriad(mode[role])).join('');
}

export function symbolicOf(mode: Mode): string {
  return ROLES.map(role => {
    const triad = mode[role];
    const special = SPECIAL_OF_ROLE[role];
    if (!mode[special]) return triad;
    return triad.slice(0, 2) + EXECUTE_WITH_SPECIAL[special][triad[2]];
  }).join('');
}

export function sentenceOf(mode: Mode, role: Role): string {
  return `${role} ${SENTENCE_OF_TRIAD[mode[role]]}`;
}

/**
 * Warnings, in display order. Rules (from the tool's warning texts):
 *  - every one of the nine permissions granted → the "777" warning;
 *  - otherwise, others may write → the world-writable warning;
 *  - setuid set → setuid warning; setgid set → setgid warning.
 * Sticky restricts deletion and is not a risk: it never produces a warning.
 */
export function warningsOf(mode: Mode): string[] {
  const out: string[] = [];
  const everything = ROLES.every(role => mode[role] === 'rwx');
  if (everything) out.push(WARNING_777);
  else if (mode.Others[1] === 'w') out.push(WARNING_WORLD_WRITABLE);
  if (mode.Setuid) out.push(WARNING_SETUID);
  if (mode.Setgid) out.push(WARNING_SETGID);
  return out;
}

export function isGranted(mode: Mode, role: Role, perm: Perm): boolean {
  return mode[role][PERMS.indexOf(perm)] !== '-';
}

/** The mode after a user clicks one cell of the permission grid. */
export function toggleCell(mode: Mode, role: Role, perm: Perm): Mode {
  const index = PERMS.indexOf(perm);
  const letter = 'rwx'[index];
  const triad = mode[role];
  const next = triad.slice(0, index) + (triad[index] === '-' ? letter : '-') + triad.slice(index + 1);
  return { ...mode, [role]: next };
}

/** The mode after a user clicks one special-bit checkbox. */
export function toggleSpecial(mode: Mode, special: Special): Mode {
  return { ...mode, [special]: !mode[special] };
}

/** Everything the page shows for a mode. */
export interface ExpectedView {
  octal: string;
  symbolic: string;
  ls: string;
  command: string;
  explanation: string[];
  warnings: string[];
  /** `Owner Read` → pressed?, for all nine grid buttons. */
  pressed: Record<string, boolean>;
  /** Checkbox label → checked?, for the three special bits. */
  checked: Record<string, boolean>;
}

export function expectedView(mode: Mode): ExpectedView {
  const octal = octalOf(mode);
  const symbolic = symbolicOf(mode);
  const pressed: Record<string, boolean> = {};
  for (const role of ROLES) for (const perm of PERMS) pressed[`${role} ${perm}`] = isGranted(mode, role, perm);
  const checked: Record<string, boolean> = {};
  for (const special of SPECIALS) checked[SPECIAL_LABELS[special]] = mode[special];
  return {
    octal,
    symbolic,
    ls: `-${symbolic}`,
    command: `chmod ${octal} filename`,
    explanation: ROLES.map(role => sentenceOf(mode, role)),
    warnings: warningsOf(mode),
    pressed,
    checked,
  };
}

/** All 4096 modes as four-digit octal text, `0000` … `7777`. */
export function allFourDigitOctals(): string[] {
  const out: string[] = [];
  for (const s of OCTAL_DIGITS) for (const o of OCTAL_DIGITS) for (const g of OCTAL_DIGITS) for (const w of OCTAL_DIGITS) out.push(s + o + g + w);
  return out;
}

export function randomMode(rng: Rng): Mode {
  // Special flags are rare in real use but are where the letters change, so draw them often.
  const lead = rng.bool(0.5) ? rng.pick(OCTAL_DIGITS) : '0';
  return modeOf(lead + rng.pick(OCTAL_DIGITS) + rng.pick(OCTAL_DIGITS) + rng.pick(OCTAL_DIGITS));
}

/**
 * The eight presets the dropdown offers: what each is for, and the mode that
 * purpose needs. `claim` is checked against the mode with the oracle, so a
 * preset whose number does not do what its label says is caught.
 */
export const PRESETS: { label: string; octal: string; desc: string; claim: (mode: Mode) => boolean }[] = [
  { label: 'Standard File', octal: '644', desc: 'Owner read/write, others read-only',
    claim: m => m.Owner === 'rw-' && m.Group === 'r--' && m.Others === 'r--' },
  { label: 'Executable Script', octal: '755', desc: 'Owner full, others read/execute',
    claim: m => m.Owner === 'rwx' && m.Group === 'r-x' && m.Others === 'r-x' },
  { label: 'Private File', octal: '600', desc: 'Owner read/write only',
    claim: m => m.Owner === 'rw-' && m.Group === '---' && m.Others === '---' },
  { label: 'SSH Private Key', octal: '400', desc: 'Owner read-only',
    claim: m => m.Owner === 'r--' && m.Group === '---' && m.Others === '---' },
  { label: 'Shared Directory', octal: '775', desc: 'Group write access',
    claim: m => m.Owner === 'rwx' && m.Group === 'rwx' && m.Others === 'r-x' },
  { label: 'World Writable', octal: '777', desc: '⚠️ Full access for everyone',
    claim: m => ROLES.every(r => m[r] === 'rwx') && !m.Setuid && !m.Setgid && !m.Sticky },
  { label: 'Setuid Binary', octal: '4755', desc: 'Runs as file owner',
    claim: m => m.Setuid && !m.Setgid && !m.Sticky && m.Owner === 'rwx' && m.Others[2] === 'x' },
  { label: 'Sticky /tmp', octal: '1777', desc: 'Users can only delete own files',
    claim: m => m.Sticky && !m.Setuid && !m.Setgid && ROLES.every(r => m[r] === 'rwx') },
];

/**
 * Text a user could leave in the octal field that is not a mode. For each of
 * them the result on screen must stay as it was.
 */
export const INVALID_DRAFTS: { text: string; why: string }[] = [
  { text: '', why: 'empty field' },
  { text: '7', why: 'one digit' },
  { text: '75', why: 'two digits' },
  { text: '12345', why: 'five digits' },
  { text: '07555', why: 'five digits with a leading zero' },
  { text: '888', why: '8 is not an octal digit' },
  { text: '759', why: '9 is not an octal digit' },
  { text: '8755', why: 'special digit above 7' },
  { text: 'abc', why: 'letters' },
  { text: 'rwx', why: 'symbolic letters' },
  { text: 'rwxr-xr-x', why: 'symbolic notation' },
  { text: 'u+x', why: 'symbolic chmod operand' },
  { text: '7 5 5', why: 'digits separated by spaces' },
  { text: '75a', why: 'letter in place of a digit' },
  { text: '-755', why: 'negative number' },
  { text: '+755', why: 'plus sign' },
  { text: '7.5', why: 'decimal point' },
  { text: '0o755', why: 'octal literal prefix' },
  { text: '0x1ed', why: 'hexadecimal' },
  { text: '7e2', why: 'exponent notation' },
  { text: '７５５', why: 'full-width digits' },
  { text: '٧٥٥', why: 'Arabic-Indic digits' },
];
