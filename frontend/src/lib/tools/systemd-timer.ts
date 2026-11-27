import { shQuote } from './shell.ts';

/**
 * Cron to systemd timer conversion. Calendar expressions use the normalized
 * form from systemd.time(7): `[DayOfWeek ]Year-Month-Day Hour:Minute:Second`.
 */

interface FieldDef {
  label: string;
  min: number;
  max: number;
  names: string[] | null;
  /** Number that the first name stands for. */
  nameBase: number;
}

interface ParsedField {
  /** The field starts with `*`. This is what cron checks to pick AND or OR for the two day fields. */
  star: boolean;
  /** Sorted values the field matches. Day of week is 0 (Sunday) to 6. */
  values: number[];
  /** systemd form of the field: `*` when unrestricted, an empty string for an unrestricted weekday. */
  calendar: string;
}

const MONTH_NAMES = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
const DAY_NAMES = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
/** systemd lists weekdays from Monday. */
const SYSTEMD_DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

const FIELDS: FieldDef[] = [
  { label: 'Minute', min: 0, max: 59, names: null, nameBase: 0 },
  { label: 'Hour', min: 0, max: 23, names: null, nameBase: 0 },
  { label: 'Day of month', min: 1, max: 31, names: null, nameBase: 0 },
  { label: 'Month', min: 1, max: 12, names: MONTH_NAMES, nameBase: 1 },
  { label: 'Day of week', min: 0, max: 7, names: DAY_NAMES, nameBase: 0 },
];
const DAY_OF_WEEK = 4;

const MACROS: Record<string, string> = {
  '@hourly': '0 * * * *',
  '@daily': '0 0 * * *',
  '@midnight': '0 0 * * *',
  '@weekly': '0 0 * * 0',
  '@monthly': '0 0 1 * *',
  '@yearly': '0 0 1 1 *',
  '@annually': '0 0 1 1 *',
};

const pad = (value: number) => String(value).padStart(2, '0');

function toNumber(token: string, def: FieldDef): number | null {
  if (/^\d{1,2}$/.test(token)) return Number(token);
  const index = def.names ? def.names.indexOf(token.toLowerCase()) : -1;
  return index === -1 ? null : index + def.nameBase;
}

/** Weekday set (cron numbering, 0 is Sunday) in systemd form: runs of three or more days become a range. */
function formatWeekdays(days: Set<number>): string {
  if (days.size === 7) return '';
  const on = SYSTEMD_DAYS.map((_, index) => days.has((index + 1) % 7));
  const out: string[] = [];
  for (let start = 0; start < 7; start++) {
    if (!on[start]) continue;
    let end = start;
    while (end + 1 < 7 && on[end + 1]) end++;
    if (end - start >= 2) out.push(`${SYSTEMD_DAYS[start]}..${SYSTEMD_DAYS[end]}`);
    else for (let day = start; day <= end; day++) out.push(SYSTEMD_DAYS[day]);
    start = end;
  }
  return out.join(',');
}

function parseField(text: string, def: FieldDef, isDayOfWeek: boolean): ParsedField | string {
  const values = new Set<number>();
  const pieces: string[] = [];
  let wildcard = false;

  for (const part of text.split(',')) {
    const match = /^(\*|[A-Za-z0-9]+)(?:-([A-Za-z0-9]+))?(?:\/(\d{1,3}))?$/.exec(part);
    if (!match || (match[1] === '*' && match[2] !== undefined)) return `${def.label}: "${part}" is not valid.`;
    const step = match[3] === undefined ? 1 : Number(match[3]);
    if (step < 1) return `${def.label}: the step in "${part}" must be 1 or more.`;

    let from = def.min;
    let to = def.max;
    const isStar = match[1] === '*';
    if (!isStar) {
      const first = toNumber(match[1], def);
      if (first === null) return `${def.label}: "${match[1]}" is not valid.`;
      const last = match[2] === undefined ? first : toNumber(match[2], def);
      if (last === null) return `${def.label}: "${match[2]}" is not valid.`;
      for (const value of [first, last]) {
        if (value < def.min || value > def.max) return `${def.label}: ${value} is out of range (${def.min} to ${def.max}).`;
      }
      if (match[2] === undefined && match[3] !== undefined) {
        return `${def.label}: "${part}" needs a range before the step, such as ${first}-${def.max}/${step}.`;
      }
      if (last < first) return `${def.label}: the range "${part}" runs backwards.`;
      from = first;
      to = last;
    }

    const matched: number[] = [];
    for (let value = from; value <= to; value += step) matched.push(value);
    for (const value of matched) values.add(isDayOfWeek ? value % 7 : value);

    if (isStar && step === 1) wildcard = true;
    else if (matched.length === 1) pieces.push(pad(from));
    else if (isStar) pieces.push(`${def.min}/${step}`);
    else if (step === 1) pieces.push(`${pad(from)}..${pad(to)}`);
    else pieces.push(`${pad(from)}..${pad(to)}/${step}`);
  }

  const sorted = [...values].sort((a, b) => a - b);
  const star = text.startsWith('*');
  if (isDayOfWeek) return { star, values: sorted, calendar: formatWeekdays(values) };
  return { star, values: sorted, calendar: wildcard ? '*' : [...new Set(pieces)].join(',') };
}

interface ParsedCron {
  errors: string[];
  reboot: boolean;
  /** The macro that was expanded, if any. */
  macro: string;
  /** Five-field expression after macro expansion. */
  cron: string;
  /** minute, hour, day of month, month, day of week. Empty when there are errors or for @reboot. */
  fields: ParsedField[];
}

function parseCron(expr: string): ParsedCron {
  const result: ParsedCron = { errors: [], reboot: false, macro: '', cron: '', fields: [] };
  let text = String(expr ?? '').trim().replace(/\s+/g, ' ');
  if (!text) {
    result.errors.push('Enter a cron expression.');
    return result;
  }
  if (text.startsWith('@')) {
    const macro = text.toLowerCase();
    if (macro === '@reboot') {
      result.reboot = true;
      result.macro = macro;
      return result;
    }
    // Keys all start with @, so this cannot hit an inherited property.
    const expanded = MACROS[macro];
    if (!expanded) {
      result.errors.push('Unknown macro. Use @hourly, @daily, @weekly, @monthly, @yearly or @reboot.');
      return result;
    }
    result.macro = macro;
    text = expanded;
  }

  const parts = text.split(' ');
  if (parts.length !== 5) {
    result.errors.push(`Expected 5 fields (minute hour day month weekday), got ${parts.length}. Leave out the command.`);
    return result;
  }
  const fields: ParsedField[] = [];
  parts.forEach((part, index) => {
    const parsed = parseField(part, FIELDS[index], index === DAY_OF_WEEK);
    if (typeof parsed === 'string') result.errors.push(parsed);
    else fields.push(parsed);
  });
  if (result.errors.length === 0) {
    result.cron = text;
    result.fields = fields;
  }
  return result;
}

const TIME_SPAN_TOKEN = /\d+(?:\.\d+)?\s*(?:usec|us|msec|ms|seconds?|sec|s|minutes?|min|m|hours?|hr|h|days?|d|weeks?|w|months?|M|years?|y)?(?![A-Za-z.])/g;

/** Returns the tidied systemd time span (`90`, `5min`, `1h 30min`, `1h30min`), or null when it is not one. */
export function normalizeTimeSpan(value: string): string | null {
  const text = String(value ?? '').trim().replace(/\s+/g, ' ');
  if (!text || text.length > 40 || !/^\d/.test(text)) return null;
  return text.replace(TIME_SPAN_TOKEN, '').trim() === '' ? text : null;
}

export interface CalendarConversion {
  valid: boolean;
  /** The five-field expression after macro expansion. Empty for @reboot and invalid input. */
  cron: string;
  /** One line per OnCalendar= entry. */
  onCalendar: string[];
  /** Set instead of onCalendar for @reboot. */
  onBootSec: string;
  notes: string[];
  errors: string[];
}

/** Convert a five-field cron expression or an @macro to systemd timer settings. */
export function cronToOnCalendar(expr: string, bootDelay = '1min'): CalendarConversion {
  const parsed = parseCron(expr);
  const out: CalendarConversion = { valid: false, cron: parsed.cron, onCalendar: [], onBootSec: '', notes: [], errors: [...parsed.errors] };
  if (out.errors.length > 0) return out;

  if (parsed.reboot) {
    const delay = normalizeTimeSpan(bootDelay);
    if (delay === null) {
      out.errors.push('Delay after boot must be a time span such as 30s, 1min or 5min.');
      return out;
    }
    out.valid = true;
    out.onBootSec = delay;
    out.notes.push(`@reboot has no calendar form. OnBootSec=${delay} starts the job ${delay} after boot.`);
    return out;
  }

  const [minute, hour, dom, month, dow] = parsed.fields;
  const time = `${hour.calendar}:${minute.calendar}:00`;
  const line = (weekdays: string, day: string) => `${weekdays ? `${weekdays} ` : ''}*-${month.calendar}-${day} ${time}`;

  if (parsed.macro) out.notes.push(`${parsed.macro} is the same as ${parsed.cron}.`);

  if (dom.star || dow.star) {
    // cron requires both day fields to match when either starts with *.
    out.onCalendar.push(line(dow.calendar, dom.calendar));
  } else if (dow.values.length === 7 || dom.values.length === 31) {
    out.onCalendar.push(line('', '*'));
    out.notes.push('Day of month and day of week are both set, and cron runs when either one matches. One of them matches every day, so the job runs every day.');
  } else {
    out.onCalendar.push(line(dow.calendar, '*'), line('', dom.calendar));
    out.notes.push('Day of month and day of week are both set. cron runs when either one matches, but one OnCalendar line needs both to match, so the timer gets two lines.');
  }
  out.valid = true;
  return out;
}

/** Longest gap between two matches is leap day to leap day across a skipped leap year (8 years). */
const MAX_DAYS_AHEAD = 366 * 8 + 2;

/**
 * The next `count` run times after `from`, in the local time zone of the runtime.
 * Returns fewer (or none) when the expression does not match within 8 years.
 */
export function nextRuns(expr: string, count: number, from: Date): Date[] {
  const parsed = parseCron(expr);
  const runs: Date[] = [];
  if (parsed.errors.length > 0 || parsed.reboot || !(count > 0) || Number.isNaN(from.getTime())) return runs;

  const [minute, hour, dom, month, dow] = parsed.fields;
  const bothMustMatch = dom.star || dow.star;
  const months = new Set(month.values);
  const doms = new Set(dom.values);
  const dows = new Set(dow.values);
  const year = from.getFullYear();
  const monthIndex = from.getMonth();
  const date = from.getDate();

  for (let offset = 0; offset < MAX_DAYS_AHEAD && runs.length < count; offset++) {
    const day = new Date(year, monthIndex, date + offset, 12);
    if (!months.has(day.getMonth() + 1)) continue;
    const domOk = doms.has(day.getDate());
    const dowOk = dows.has(day.getDay());
    if (bothMustMatch ? !(domOk && dowOk) : !(domOk || dowOk)) continue;

    for (const h of hour.values) {
      for (const m of minute.values) {
        if (runs.length >= count) break;
        const run = new Date(day.getFullYear(), day.getMonth(), day.getDate(), h, m);
        // A time skipped by a daylight saving change comes back shifted. Leave it out.
        if (run.getHours() !== h || run.getMinutes() !== m) continue;
        if (run.getTime() > from.getTime()) runs.push(run);
      }
    }
  }
  return runs;
}

export type TimerScope = 'system' | 'user';

export interface UnitOptions {
  /** Unit name without .timer or .service. */
  name: string;
  description: string;
  command: string;
  /** Account to run as. System scope only. */
  user: string;
  workingDirectory: string;
  scope: TimerScope;
  /** OnCalendar expressions, from cronToOnCalendar. */
  onCalendar: string[];
  /** Delay after boot, used instead of onCalendar for @reboot. */
  onBootSec: string;
  /** Persistent=true: run a missed job after the next boot. */
  persistent: boolean;
  randomizedDelaySec: string;
  accuracySec: string;
}

export const UNIT_DEFAULTS: UnitOptions = {
  name: 'nightly-backup',
  description: 'Nightly backup',
  command: '/usr/local/bin/backup.sh',
  user: '',
  workingDirectory: '',
  scope: 'system',
  onCalendar: [],
  onBootSec: '',
  persistent: true,
  randomizedDelaySec: '',
  accuracySec: '',
};

export interface BuiltUnits {
  timerUnit: string;
  serviceUnit: string;
  timerPath: string;
  servicePath: string;
  /** Shell commands that write both files, enable the timer and check it. */
  installCommands: string[];
  notes: string[];
  warnings: string[];
  errors: string[];
}

const NAME_PATTERN = /^[A-Za-z0-9:_.-]+$/;
const USER_PATTERN = /^(?:[A-Za-z_][A-Za-z0-9_.-]{0,30}\$?|\d{1,10})$/;
const CALENDAR_PATTERN = /^[A-Za-z0-9*,./:~ -]{1,200}$/;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;
const SHELL_SYNTAX = /[|&;<>()$`\\*?[\]{}]|(?:^|\s)~/;

/** In unit files % starts a specifier, so a literal one is doubled. */
const escapePercent = (value: string) => value.replace(/%/g, '%%');

/** systemd does not run ExecStart through a shell. True when the command only works in one. */
function needsShell(command: string): boolean {
  if (SHELL_SYNTAX.test(command)) return true;
  if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(command)) return true;
  // systemd understands quotes that wrap a whole word. Anything else is left to the shell.
  return /["']/.test(command.replace(/(^|\s)(?:"[^"]*"|'[^']*')(?=\s|$)/g, '$1'));
}

/**
 * Quote one argument the way systemd.syntax(7) reads it: C-style escapes are
 * processed inside quotes, so backslashes are doubled and a quote is `\'`.
 * A POSIX `'\''` would not survive a backslash elsewhere in the command.
 */
function unitQuote(value: string): string {
  return `'${value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

export function buildUnits(options: UnitOptions): BuiltUnits {
  const errors: string[] = [];
  const warnings: string[] = [];
  const notes: string[] = [];
  const user = options.scope === 'user';

  let name = String(options.name ?? '').trim();
  if (!name) {
    errors.push('Enter a unit name.');
  } else if (/\.(?:timer|service)$/i.test(name)) {
    errors.push('Enter the unit name without .timer or .service.');
  } else if (!NAME_PATTERN.test(name) || !/^[A-Za-z0-9]/.test(name) || name.length > 200) {
    errors.push('Unit name must start with a letter or digit and use only letters, digits, and : _ . -');
  }
  if (errors.length > 0) name = 'UNIT_NAME';

  const description = String(options.description ?? '').replace(/[\u0000-\u001f\u007f\s]+/g, ' ').trim().replace(/[\s\\]+$/, '') || `Scheduled job ${name}`;

  let command = String(options.command ?? '').trim();
  let execStart = '/path/to/command';
  if (!command) {
    errors.push('Enter the command to run.');
  } else if (CONTROL_CHARS.test(command)) {
    errors.push('The command must be a single line.');
    command = '';
  } else if (needsShell(command)) {
    execStart = `/bin/sh -c ${unitQuote(command).replace(/\$/g, '$$$$')}`;
    notes.push(`The command uses shell syntax, so it runs through /bin/sh -c. systemd does not start ExecStart in a shell.${command.includes('$') ? ' In the unit file $ is written as $$.' : ''}`);
  } else {
    execStart = command;
    // systemd reads - @ : + ! before the path as its own prefixes, so they are not part of the path.
    const firstWord = command.split(/\s+/)[0].replace(/^[-@:+!]*["']?/, '');
    if (!firstWord.startsWith('/')) {
      warnings.push(`ExecStart needs an absolute path. Replace "${firstWord}" with its full path, which "command -v ${firstWord}" prints.`);
    }
  }
  if (command.includes('%')) notes.push('A literal % is written as %% in unit files, because % starts a specifier.');

  const serviceLines = ['[Unit]', `Description=${escapePercent(description)}`, '', '[Service]', 'Type=oneshot'];

  const account = String(options.user ?? '').trim();
  if (account) {
    if (user) warnings.push('User= only works in system units. A user timer always runs as the account that owns it, so the user is left out.');
    else if (!USER_PATTERN.test(account)) errors.push('User must be an account name or a numeric ID.');
    else serviceLines.push(`User=${account}`);
  }

  const directory = String(options.workingDirectory ?? '').trim();
  if (directory) {
    if (!directory.startsWith('/') || CONTROL_CHARS.test(directory) || directory.endsWith('\\')) {
      errors.push('Working directory must be an absolute path.');
    } else {
      serviceLines.push(`WorkingDirectory=${escapePercent(directory)}`);
    }
  }
  serviceLines.push(`ExecStart=${escapePercent(execStart)}`);

  const timerLines = ['[Unit]', `Description=Run ${name}.service on a schedule`, '', '[Timer]'];
  const calendars: string[] = [];
  const bootDelay = String(options.onBootSec ?? '').trim();
  if (bootDelay) {
    const delay = normalizeTimeSpan(bootDelay);
    if (delay === null) errors.push('Delay after boot must be a time span such as 30s, 1min or 5min.');
    else timerLines.push(`OnBootSec=${delay}`);
    if (user) notes.push('In a user timer the boot delay is counted from boot, but the timer only starts with your user session unless lingering is on.');
  } else {
    const entries = (options.onCalendar ?? []).map(entry => String(entry ?? '').trim());
    if (entries.length === 0) errors.push('There is no schedule. Enter a valid cron expression.');
    else if (entries.every(entry => CALENDAR_PATTERN.test(entry))) calendars.push(...entries);
    else errors.push('The schedule is not a valid OnCalendar expression.');
    for (const expression of calendars) timerLines.push(`OnCalendar=${expression}`);
    if (options.persistent && calendars.length > 0) timerLines.push('Persistent=true');
  }

  const spans: Array<[string, string, string]> = [
    ['RandomizedDelaySec', options.randomizedDelaySec, 'Random delay'],
    ['AccuracySec', options.accuracySec, 'Accuracy'],
  ];
  for (const [key, raw, label] of spans) {
    const text = String(raw ?? '').trim();
    if (!text) continue;
    const span = normalizeTimeSpan(text);
    if (span === null) errors.push(`${label} must be a time span such as 30s, 5min or 1h.`);
    else timerLines.push(`${key}=${span}`);
  }
  timerLines.push('', '[Install]', 'WantedBy=timers.target');

  const timerUnit = `${timerLines.join('\n')}\n`;
  const serviceUnit = `${serviceLines.join('\n')}\n`;
  const directoryPath = user ? '~/.config/systemd/user' : '/etc/systemd/system';
  const timerPath = `${directoryPath}/${name}.timer`;
  const servicePath = `${directoryPath}/${name}.service`;

  const systemctl = user ? 'systemctl --user' : 'sudo systemctl';
  const write = (path: string, body: string) => (user ? `cat > ${path} <<'EOF'\n${body}EOF` : `sudo tee ${path} > /dev/null <<'EOF'\n${body}EOF`);
  const installCommands = [
    ...(user ? [`mkdir -p ${directoryPath}`] : []),
    write(servicePath, serviceUnit),
    write(timerPath, timerUnit),
    `${systemctl} daemon-reload`,
    `${systemctl} enable --now ${name}.timer`,
    `systemctl${user ? ' --user' : ''} list-timers ${name}.timer`,
    user ? `journalctl --user-unit ${name}.service` : `journalctl -u ${name}.service`,
    ...calendars.map(expression => `systemd-analyze calendar ${shQuote(expression)}`),
  ];
  if (user) notes.push('User timers stop when you log out. Run "loginctl enable-linger" once so they also run without a login session.');

  return { timerUnit, serviceUnit, timerPath, servicePath, installCommands, notes, warnings, errors };
}
