/**
 * Quoting helpers for generated commands. Tool libraries under lib/tools are
 * plain TypeScript with no React or DOM use, so `node --test tests/unit/`
 * can import them directly (local imports need the `.ts` extension).
 */

const SAFE_POSIX = /^[A-Za-z0-9_@%+=:,./~-]+$/;

/** Quote one argument for a POSIX shell. Leaves plain words untouched. */
export function shQuote(value: string): string {
  if (value === '') return "''";
  if (SAFE_POSIX.test(value)) return value;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

const SAFE_CMD = /^[A-Za-z0-9_@%+=:,./\\~-]+$/;

/** Quote one argument for cmd.exe / robocopy. A trailing backslash would escape the closing quote, so it is doubled. */
export function cmdQuote(value: string): string {
  if (value === '') return '""';
  if (SAFE_CMD.test(value)) return value;
  const escaped = value.replace(/"/g, '\\"').replace(/\\+$/, match => match + match);
  return `"${escaped}"`;
}

/** Quote a string literal for PowerShell (single quotes, doubled to escape). */
export function psQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}
