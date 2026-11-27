import {
  BUG_CHECKS,
  EXCEPTION_CODES,
  HRESULTS,
  HRESULT_FACILITIES,
  NTSTATUS_CODES,
  NTSTATUS_FACILITIES,
  WIN32_ERRORS,
  type CodeEntry,
} from './windows-errors-data.ts';

export { BUG_CHECKS, EXCEPTION_CODES, HRESULTS, HRESULT_FACILITIES, NTSTATUS_CODES, NTSTATUS_FACILITIES, WIN32_ERRORS };
export type { CodeEntry };

export type ErrorKind = 'win32' | 'hresult' | 'ntstatus' | 'exception' | 'bugcheck';

export const KIND_LABELS: Record<ErrorKind, string> = {
  win32: 'Win32 error',
  hresult: 'HRESULT',
  ntstatus: 'NTSTATUS',
  exception: 'Exception code',
  bugcheck: 'Stop code',
};

export interface BreakdownField {
  field: string;
  value: string;
  meaning: string;
}

/** A code carried inside another one: the Win32 error in 0x8007xxxx, or the NTSTATUS behind the N bit. */
export interface WrappedCode {
  kind: 'win32' | 'ntstatus';
  code: number;
  display: string;
  known: boolean;
  name: string;
  meaning: string;
}

export interface LookupCommand {
  label: string;
  command: string;
}

export interface Interpretation {
  kind: ErrorKind;
  label: string;
  /** The code as an unsigned 32-bit number. */
  value: number;
  /** 0x followed by eight hex digits. */
  hex: string;
  /** How the code is normally written for its kind, see displayCode. */
  display: string;
  decimal: string;
  /** The value as a signed 32-bit number, as many tools and logs print it. */
  signed: string;
  /** How the input was read to get this value. */
  readAs: 'decimal' | 'hex';
  known: boolean;
  name: string;
  meaning: string;
  check: string;
  note: string;
  fields: BreakdownField[];
  wraps: WrappedCode | null;
  commands: LookupCommand[];
}

export interface DecodeResult {
  input: string;
  /** `code`: the input is a number and was decoded. `text`: not a number, use searchErrors. */
  kind: 'empty' | 'code' | 'text' | 'invalid';
  message: string;
  interpretations: Interpretation[];
}

function index(entries: CodeEntry[]): Map<number, CodeEntry> {
  return new Map(entries.map(entry => [entry.code, entry]));
}

const WIN32 = index(WIN32_ERRORS);
const HRESULT = index(HRESULTS);
const NTSTATUS = index(NTSTATUS_CODES);
const EXCEPTION = index(EXCEPTION_CODES);
const BUGCHECK = index(BUG_CHECKS);

const NOT_IN_REFERENCE = 'This code is not in the reference, which covers common codes only. The field breakdown still applies.';

export function toHex(value: number, digits = 8): string {
  return `0x${(value >>> 0).toString(16).toUpperCase().padStart(digits, '0')}`;
}

/** How a code is normally written for its kind: decimal for Win32, short hex for stop codes, eight hex digits otherwise. */
export function displayCode(kind: ErrorKind, value: number): string {
  if (kind === 'win32') return String(value);
  if (kind === 'bugcheck' && value <= 0xffff) return toHex(value, 2);
  return toHex(value);
}

function bit(value: number, position: number): number {
  return (value >>> position) & 1;
}

function base(kind: ErrorKind, value: number, readAs: 'decimal' | 'hex', entry: CodeEntry | undefined): Interpretation {
  return {
    kind,
    label: KIND_LABELS[kind],
    value,
    hex: toHex(value),
    display: toHex(value),
    decimal: String(value),
    signed: String(value | 0),
    readAs,
    known: Boolean(entry),
    name: entry?.name ?? '',
    meaning: entry?.meaning ?? '',
    check: entry?.check ?? '',
    note: '',
    fields: [],
    wraps: null,
    commands: [],
  };
}

function wrapWin32(code: number): WrappedCode {
  const entry = WIN32.get(code);
  return { kind: 'win32', code, display: String(code), known: Boolean(entry), name: entry?.name ?? '', meaning: entry?.meaning ?? '' };
}

function wrapNtstatus(code: number): WrappedCode {
  const entry = NTSTATUS.get(code);
  return { kind: 'ntstatus', code, display: toHex(code), known: Boolean(entry), name: entry?.name ?? '', meaning: entry?.meaning ?? '' };
}

function win32Commands(code: number): LookupCommand[] {
  return [
    { label: 'Command prompt', command: `net helpmsg ${code}` },
    { label: 'certutil', command: `certutil -error ${code}` },
    { label: 'PowerShell', command: `[ComponentModel.Win32Exception]::new(${code}).Message` },
  ];
}

function asWin32(value: number, readAs: 'decimal' | 'hex'): Interpretation {
  const result = base('win32', value, readAs, WIN32.get(value));
  result.display = String(value);
  result.fields = [
    { field: 'Decimal', value: String(value), meaning: 'The form used by net helpmsg, GetLastError and most exit codes.' },
    { field: 'Hex', value: toHex(value, 4), meaning: 'The low 16 bits of an HRESULT that wraps this error.' },
  ];
  if (value !== 0) result.fields.push({ field: 'As an HRESULT', value: toHex((0x80070000 | value) >>> 0), meaning: 'The same error as COM, .NET and Windows Update report it (facility WIN32).' });
  result.commands = win32Commands(value);
  return result;
}

function asHresult(value: number, readAs: 'decimal' | 'hex'): Interpretation {
  const result = base('hresult', value, readAs, HRESULT.get(value));
  const severity = bit(value, 31);
  const customer = bit(value, 29);
  const nt = bit(value, 28);
  const facility = (value >>> 16) & 0x7ff;
  const code = value & 0xffff;
  const facilityName = HRESULT_FACILITIES[facility];

  if (nt) result.wraps = wrapNtstatus((value & ~0x10000000) >>> 0);
  else if (severity && facility === 7) result.wraps = wrapWin32(code);

  let codeMeaning = 'The error number within the facility.';
  if (result.wraps?.kind === 'win32') codeMeaning = result.wraps.known ? `Win32 error ${code}: ${result.wraps.name}.` : `Win32 error ${code}.`;
  else if (!nt && facility === 25 && code >= 100 && code <= 599) codeMeaning = `HTTP status ${code}.`;

  result.fields = [
    { field: 'Severity (bit 31)', value: String(severity), meaning: severity ? 'Failure.' : 'Success.' },
    { field: 'Customer (bit 29)', value: String(customer), meaning: customer ? 'Defined by an application or vendor, not by Microsoft.' : 'Defined by Microsoft.' },
    { field: 'N (bit 28)', value: String(nt), meaning: nt ? `Wraps an NTSTATUS: ${toHex((value & ~0x10000000) >>> 0)}.` : 'Not a wrapped NTSTATUS.' },
    { field: 'Facility (bits 16 to 26)', value: `${facility} (${toHex(facility, 3)})`, meaning: nt ? 'Part of the wrapped NTSTATUS.' : facilityName ? `FACILITY_${facilityName}.` : 'A facility that is not in the reference.' },
    { field: 'Code (bits 0 to 15)', value: `${code} (${toHex(code, 4)})`, meaning: codeMeaning },
  ];

  // A wrapped code that is known gives the name when the HRESULT has none of its own.
  if (!result.known && result.wraps?.known) {
    result.known = true;
    result.name = result.wraps.kind === 'win32' ? `HRESULT_FROM_WIN32(${result.wraps.name})` : `HRESULT_FROM_NT(${result.wraps.name})`;
    result.meaning = result.wraps.meaning;
    const wrapped = result.wraps.kind === 'win32' ? WIN32.get(result.wraps.code) : NTSTATUS.get(result.wraps.code);
    result.check = wrapped?.check ?? '';
  }
  if (!result.known && !nt && facility === 25 && code >= 100 && code <= 599) {
    result.note = `Facility HTTP carries an HTTP status in the code field: this is HTTP ${code}.`;
  }

  result.commands = [{ label: 'certutil', command: `certutil -error ${result.hex}` }];
  if (result.wraps?.kind === 'win32') {
    result.commands.unshift({ label: 'Command prompt', command: `net helpmsg ${code}` });
    result.commands.push({ label: 'PowerShell', command: `[ComponentModel.Win32Exception]::new(${code}).Message` });
  }
  return result;
}

const NT_SEVERITY = ['Success', 'Informational', 'Warning', 'Error'];

function asNtstatus(value: number, readAs: 'decimal' | 'hex'): Interpretation {
  const result = base('ntstatus', value, readAs, NTSTATUS.get(value));
  const severity = value >>> 30;
  const customer = bit(value, 29);
  const facility = (value >>> 16) & 0xfff;
  const code = value & 0xffff;
  const facilityName = NTSTATUS_FACILITIES[facility];
  // NTSTATUS_FROM_WIN32 builds 0xC007xxxx: error severity, facility NTWIN32, the Win32 error as the code.
  if (severity === 3 && !customer && facility === 7) result.wraps = wrapWin32(code);

  result.fields = [
    { field: 'Severity (bits 30 and 31)', value: String(severity), meaning: `${NT_SEVERITY[severity]}.` },
    { field: 'Customer (bit 29)', value: String(customer), meaning: customer ? 'Defined by an application or vendor, not by Microsoft.' : 'Defined by Microsoft.' },
    { field: 'Facility (bits 16 to 27)', value: `${facility} (${toHex(facility, 3)})`, meaning: facilityName ? `Facility ${facilityName}.` : 'A facility that is not in the reference.' },
    { field: 'Code (bits 0 to 15)', value: `${code} (${toHex(code, 4)})`, meaning: result.wraps ? (result.wraps.known ? `Win32 error ${code}: ${result.wraps.name}.` : `Win32 error ${code}.`) : 'The status number within the facility.' },
  ];

  if (!result.known && result.wraps?.known) {
    result.known = true;
    result.name = `NTSTATUS_FROM_WIN32(${result.wraps.name})`;
    result.meaning = result.wraps.meaning;
    result.check = WIN32.get(result.wraps.code)?.check ?? '';
  }
  result.commands = [{ label: 'certutil', command: `certutil -error ${result.hex}` }];
  return result;
}

function asException(value: number, readAs: 'decimal' | 'hex'): Interpretation {
  const result = base('exception', value, readAs, EXCEPTION.get(value));
  result.note = 'An exception code raised by a language runtime, not a system status code. It appears as the exception code in crash events and as a process exit code.';
  return result;
}

function asBugCheck(value: number, readAs: 'decimal' | 'hex'): Interpretation {
  const result = base('bugcheck', value, readAs, BUGCHECK.get(value));
  result.display = displayCode('bugcheck', value);
  result.note = 'Stop codes are shown on the blue screen and in System event 1001. The four parameters next to the code and the memory dump narrow down the cause.';
  return result;
}

/** Every plausible reading of one 32-bit value, most likely first. */
function interpretValue(value: number, readAs: 'decimal' | 'hex', writtenAsHex: boolean): Interpretation[] {
  const bugCheck = BUGCHECK.has(value) ? asBugCheck(value, readAs) : null;

  if (value <= 0xffff) {
    const list: Interpretation[] = [asWin32(value, readAs)];
    if (HRESULT.has(value)) list.push(asHresult(value, readAs));
    if (NTSTATUS.has(value)) list.push(asNtstatus(value, readAs));
    // Written in hex, a small value such as 0x7B is far more likely a stop code than Win32 error 123.
    if (bugCheck) { if (writtenAsHex) list.unshift(bugCheck); else list.push(bugCheck); }
    return list;
  }

  const list: Interpretation[] = [];
  if (EXCEPTION.has(value)) list.push(asException(value, readAs));
  const top = value >>> 30;
  if (top === 3 || top === 1) list.push(asNtstatus(value, readAs), asHresult(value, readAs));
  else list.push(asHresult(value, readAs), asNtstatus(value, readAs));
  if (bugCheck) list.push(bugCheck);

  // When a name is known, readings without one are noise. When nothing is known, keep the structural readings.
  const known = list.filter(item => item.known);
  if (known.length) return known;
  return top === 3 ? list : list.filter(item => item.kind === (top === 1 ? 'ntstatus' : 'hresult'));
}

interface ParsedCode {
  value: number;
  readAs: 'decimal' | 'hex';
  writtenAsHex: boolean;
}

/**
 * Read the input as one or more 32-bit values.
 * - `0x` prefix, or a-f letters: hex.
 * - Digits only: decimal. Eight digits starting with 8 (80070005) are offered as hex first, then decimal.
 * - Negative decimal (-2147024891): the signed form of a 32-bit code.
 * - Letters only without `0x` ("bad", "dead") are text, unless one or two or exactly eight characters long.
 */
function parseCode(text: string): ParsedCode[] | 'text' | 'range' {
  const prefixed = /^0x([0-9a-f]+)$/i.exec(text);
  if (prefixed) {
    return prefixed[1].length > 8 && !/^0+[0-9a-f]{8}$/i.test(prefixed[1]) ? 'range' : [{ value: parseInt(prefixed[1], 16), readAs: 'hex', writtenAsHex: true }];
  }
  if (/^-\d+$/.test(text)) {
    const number = Number(text);
    return number < -0x80000000 ? 'range' : [{ value: number >>> 0, readAs: 'decimal', writtenAsHex: false }];
  }
  if (/^\d+$/.test(text)) {
    const number = Number(text);
    const decimal: ParsedCode[] = number <= 0xffffffff ? [{ value: number, readAs: 'decimal', writtenAsHex: false }] : [];
    if (text.length === 8 && text[0] === '8') return [{ value: parseInt(text, 16), readAs: 'hex', writtenAsHex: true }, ...decimal];
    return decimal.length ? decimal : 'range';
  }
  if (/^[0-9a-f]{1,8}$/i.test(text)) {
    const lettersOnly = /^[a-f]+$/i.test(text);
    if (lettersOnly && text.length > 2 && text.length < 8) return 'text';
    return [{ value: parseInt(text, 16), readAs: 'hex', writtenAsHex: true }];
  }
  return 'text';
}

/**
 * Decode a Windows error code into every plausible interpretation: Win32,
 * HRESULT, NTSTATUS, exception code and stop code, each with its bit fields.
 * Input that is not a number comes back as kind `text`.
 */
export function decodeErrorCode(input: string): DecodeResult {
  const text = input.trim().replace(/^[([]\s*|\s*[)\].,;]+$/g, '');
  if (!text) return { input, kind: 'empty', message: '', interpretations: [] };

  const parsed = parseCode(text);
  if (parsed === 'text') return { input, kind: 'text', message: '', interpretations: [] };
  if (parsed === 'range') return { input, kind: 'invalid', message: 'Windows error codes are 32-bit values: up to 0xFFFFFFFF, or down to -2147483648 in signed form.', interpretations: [] };

  const interpretations = parsed.flatMap(code => interpretValue(code.value, code.readAs, code.writtenAsHex));

  // Stop codes are written in hex, so plain digits such as 133 may also mean stop code 0x133.
  if (parsed.length === 1 && !parsed[0].writtenAsHex && /^\d{1,8}$/.test(text)) {
    const asHex = parseInt(text, 16);
    if (asHex !== parsed[0].value && BUGCHECK.has(asHex)) {
      const extra = asBugCheck(asHex, 'hex');
      extra.note = `Stop codes are written in hex, so ${text} is read here as ${toHex(asHex)}. ${extra.note}`;
      interpretations.push(extra);
    }
  }

  const message = parsed.length > 1 ? `${text} can be read as hex (${toHex(parsed[0].value)}) or as a decimal number. Both are shown, hex first.` : '';
  return { input, kind: 'code', message, interpretations };
}

export { NOT_IN_REFERENCE };

export interface ErrorMatch {
  kind: ErrorKind;
  label: string;
  code: number;
  /** The code as displayCode writes it. Feed it back to decodeErrorCode. */
  display: string;
  name: string;
  meaning: string;
}

const DATASETS: Array<{ kind: ErrorKind; entries: CodeEntry[] }> = [
  { kind: 'win32', entries: WIN32_ERRORS },
  { kind: 'hresult', entries: HRESULTS },
  { kind: 'ntstatus', entries: NTSTATUS_CODES },
  { kind: 'exception', entries: EXCEPTION_CODES },
  { kind: 'bugcheck', entries: BUG_CHECKS },
];

function normalize(text: string): string {
  return text.toLowerCase().replace(/[_\s]+/g, ' ').trim();
}

/**
 * Search names and meanings. Every word must occur; underscores and spaces
 * are interchangeable, so `ACCESS_DENIED` and `access denied` find the same
 * entries. Matches in the name come first, the whole phrase before single words.
 */
export function searchErrors(query: string): ErrorMatch[] {
  const phrase = normalize(query);
  const words = phrase.split(' ').filter(Boolean);
  if (!words.length) return [];
  const scored: Array<{ match: ErrorMatch; score: number }> = [];
  for (const { kind, entries } of DATASETS) {
    for (const entry of entries) {
      const name = normalize(entry.name);
      const meaning = normalize(entry.meaning);
      let score = 0;
      for (const word of words) {
        if (name.includes(word)) score += 2;
        else if (meaning.includes(word)) score += 1;
        else { score = 0; break; }
      }
      if (score > 0) {
        // The words in the same order in the name (ERROR_ACCESS_DENIED for "access denied") rank first.
        if (name.includes(phrase)) score += 2;
        scored.push({ match: { kind, label: KIND_LABELS[kind], code: entry.code, display: displayCode(kind, entry.code), name: entry.name, meaning: entry.meaning }, score });
      }
    }
  }
  return scored.sort((a, b) => b.score - a.score).map(item => item.match);
}

/** Number of entries in each dataset, for the page to say what the reference covers. */
export function referenceCounts(): Record<ErrorKind, number> {
  return {
    win32: WIN32_ERRORS.length,
    hresult: HRESULTS.length,
    ntstatus: NTSTATUS_CODES.length,
    exception: EXCEPTION_CODES.length,
    bugcheck: BUG_CHECKS.length,
  };
}
