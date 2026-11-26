import { buildReportHtml } from './report-html';

export function toSymbolic(bits: number[], special: number): string {
  const chars = ['r', 'w', 'x'];
  let s = '';
  for (let r = 0; r < 3; r++) for (let p = 0; p < 3; p++) s += (bits[r] & (4 >> p)) ? chars[p] : '-';
  if (special & 4) s = s.slice(0, 2) + (s[2] === 'x' ? 's' : 'S') + s.slice(3);
  if (special & 2) s = s.slice(0, 5) + (s[5] === 'x' ? 's' : 'S') + s.slice(6);
  if (special & 1) s = s.slice(0, 8) + (s[8] === 'x' ? 't' : 'T');
  return s;
}

export function describePerms(bits: number, role: string): string {
  const names = [];
  if (bits & 4) names.push('read');
  if (bits & 2) names.push('write');
  if (bits & 1) names.push('execute');
  if (names.length === 0) return `${role} has no permissions`;
  if (names.length === 3) return `${role} can read, write, and execute`;
  return `${role} can ${names.join(' and ')}`;
}

export const CHMOD_ROLES = ['Owner', 'Group', 'Others'] as const;

/** Splits a 3- or 4-digit octal mode into per-role bits and the special-bits digit. */
export function parseOctalMode(octal: string): { bits: number[]; special: number } | null {
  if (!/^[0-7]{3,4}$/.test(octal)) return null;
  const digits = octal.length === 4 ? octal.slice(1) : octal;
  return { bits: digits.split('').map(Number), special: octal.length === 4 ? Number(octal[0]) : 0 };
}

/** Security notes for a mode, most serious first. */
export function chmodWarnings(bits: number[], special: number): { level: 'danger' | 'warning'; text: string }[] {
  const warnings: { level: 'danger' | 'warning'; text: string }[] = [];
  const is777 = bits[0] === 7 && bits[1] === 7 && bits[2] === 7;
  if (is777) warnings.push({ level: 'danger', text: '777 gives full access to everyone — major security risk!' });
  else if (bits[2] & 2) warnings.push({ level: 'warning', text: 'World-writable — other users can modify this file.' });
  if (special & 4) warnings.push({ level: 'warning', text: 'Setuid — file executes as the owning user.' });
  if (special & 2) warnings.push({ level: 'warning', text: 'Setgid — file executes as the owning group.' });
  return warnings;
}

/** A permission mode as it is shared; everything else is derived from it. */
export interface ChmodSnapshot {
  octal: string;
  checked_at_utc: string;
}

export function normalizeChmodSnapshot(raw: unknown): ChmodSnapshot {
  const d = (raw ?? {}) as Partial<ChmodSnapshot>;
  return {
    octal: typeof d.octal === 'string' && parseOctalMode(d.octal) ? d.octal : '',
    checked_at_utc: typeof d.checked_at_utc === 'string' ? d.checked_at_utc : new Date().toISOString(),
  };
}

/** One CSV row per role. */
export function chmodCsvRows(octal: string) {
  const mode = parseOctalMode(octal);
  if (!mode) return [];
  const symbolic = toSymbolic(mode.bits, mode.special);
  return CHMOD_ROLES.map((role, i) => ({
    octal,
    symbolic,
    role,
    digit: mode.bits[i],
    read: Boolean(mode.bits[i] & 4),
    write: Boolean(mode.bits[i] & 2),
    execute: Boolean(mode.bits[i] & 1),
    setuid: Boolean(mode.special & 4),
    setgid: Boolean(mode.special & 2),
    sticky: Boolean(mode.special & 1),
  }));
}

export function buildChmodReportHtml(octal: string, checkedAt?: string) {
  const mode = parseOctalMode(octal);
  if (!mode) {
    return buildReportHtml({ title: 'chmod Report', subject: octal, checkedAt, sections: [{ title: 'Validation', note: 'This is not a valid octal permission mode.' }] });
  }
  const symbolic = toSymbolic(mode.bits, mode.special);
  const yesNo = (on: number) => (on ? 'Yes' : 'No');

  return buildReportHtml({
    title: 'chmod Report',
    subject: octal,
    subtitle: `chmod ${octal} filename`,
    checkedAt,
    timeLabel: 'Generated at',
    cards: [
      { label: 'Octal', value: octal, mono: true },
      { label: 'Symbolic', value: symbolic, mono: true },
      { label: 'ls -la Output', value: `-${symbolic}`, mono: true },
    ],
    sections: [
      {
        title: 'Permissions',
        table: {
          columns: ['Role', 'Read', 'Write', 'Execute', 'Digit'],
          alignRight: [4],
          rows: CHMOD_ROLES.map((role, i) => [role, yesNo(mode.bits[i] & 4), yesNo(mode.bits[i] & 2), yesNo(mode.bits[i] & 1), mode.bits[i]]),
        },
      },
      {
        title: 'Special Bits',
        rows: [['Setuid', yesNo(mode.special & 4)], ['Setgid', yesNo(mode.special & 2)], ['Sticky', yesNo(mode.special & 1)]],
      },
      { title: 'Explanation', list: CHMOD_ROLES.map((role, i) => describePerms(mode.bits[i], role)) },
      { title: 'Warnings', list: chmodWarnings(mode.bits, mode.special).map((w) => w.text), empty: 'No security warnings for this mode.' },
      { title: 'Command', text: `chmod ${octal} filename` },
    ],
  });
}
