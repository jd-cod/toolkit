/**
 * Independent cron evaluator for the Crontab Builder suite.
 *
 * Definitions
 * -----------
 * Source: POSIX crontab(1) and the Vixie/cronie crontab(5) manual page, the
 * format the tool's guide describes ("Minute · hour · day of month · month ·
 * day of week", `*`, `/`, `-`, commas).
 *
 *  - An expression is five fields separated by blanks (spaces or tabs):
 *    minute 0–59, hour 0–23, day of month 1–31, month 1–12, day of week 0–7
 *    where both 0 and 7 mean Sunday.
 *  - A field is a comma-separated list of items. An item is `*`, a number, a
 *    range `a-b` with a <= b, or `*` or a range followed by `/step` with
 *    step >= 1. Numbers are decimal digits only. Every number must lie inside
 *    the field's limits. An empty item is an error.
 *  - Day rule: when the day-of-month field and the day-of-week field are both
 *    restricted (neither starts with `*`), a day matches when EITHER field
 *    matches it. Otherwise both must match (the unrestricted one always does).
 *  - A job runs at every minute whose local wall-clock time (minute, hour, day,
 *    month, weekday) matches. "Next executions" are the first such minutes
 *    after the current minute.
 *  - Clock changes: a wall-clock time that is skipped does not occur, and one
 *    that occurs twice is listed twice. Cron implementations all behave this
 *    way for jobs with `*` in the hour field; for jobs with a fixed hour inside
 *    the changed interval they differ, so `nextRuns` reports such a result as
 *    `dstAmbiguous` and the specs do not assert it.
 *  - Forms that implementations disagree on are "unspecified" here and are not
 *    asserted either: month and weekday names, `N/step`, a step larger than the
 *    field, `@daily`-style macros, `*`-steps in one day field while the other
 *    is restricted.
 *
 * Display rules (the tool's own, from its table and help text)
 *  - Date `Mon D, YYYY`, time `hh:mm AM|PM` (12-hour, two-digit hour), full
 *    weekday name, all in the browser's time zone.
 *  - Relative time from whole minutes remaining (rounded down): under one
 *    minute `now`; under an hour `in Xm`; under a day `in Xh Ym`; else `in Xd Yh`.
 *
 * The page walks forward one minute at a time with `Date` local getters. This
 * file filters local calendar days first and converts wall-clock times to
 * instants through `Intl.DateTimeFormat` with an explicit time zone, so the
 * two share neither algorithm nor the process time zone.
 */

export const ZONE = process.env.E2E_TIMEZONE ?? 'America/New_York';

export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;

export const FIELD_RULES = [
  { name: 'minute', caption: 'Minute', min: 0, max: 59 },
  { name: 'hour', caption: 'Hour', min: 0, max: 23 },
  { name: 'day of month', caption: 'Day(M)', min: 1, max: 31 },
  { name: 'month', caption: 'Month', min: 1, max: 12 },
  { name: 'day of week', caption: 'Day(W)', min: 0, max: 7 },
] as const;
export type FieldRule = (typeof FIELD_RULES)[number];

export const DEFAULT_EXPRESSION = '*/15 * * * *';

const MONTH_SHORT = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const WEEKDAY_SHORT = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const WEEKDAY_LONG = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

/** Hour of the day → the tool's clock label. Written out so no arithmetic can be shared with the page. */
const CLOCK = [
  '12:00 AM', '1:00 AM', '2:00 AM', '3:00 AM', '4:00 AM', '5:00 AM', '6:00 AM', '7:00 AM', '8:00 AM', '9:00 AM', '10:00 AM', '11:00 AM',
  '12:00 PM', '1:00 PM', '2:00 PM', '3:00 PM', '4:00 PM', '5:00 PM', '6:00 PM', '7:00 PM', '8:00 PM', '9:00 PM', '10:00 PM', '11:00 PM',
];

/* ------------------------------------------------------------------ */
/* Parsing                                                             */
/* ------------------------------------------------------------------ */

/** The meaning of an expression: which values each field allows. */
export interface Schedule {
  minutes: number[];
  hours: number[];
  daysOfMonth: number[];
  months: number[];
  /** 0 = Sunday … 6 = Saturday (7 is folded into 0). */
  weekdays: number[];
  domRestricted: boolean;
  dowRestricted: boolean;
}

export type Verdict =
  | { kind: 'valid'; fields: string[]; schedule: Schedule }
  | { kind: 'invalid'; reason: string }
  | { kind: 'unspecified'; reason: string };

type ItemResult = { values: number[] } | { invalid: string } | { unspecified: string };

function toNumber(digits: string): number {
  // Longer than any limit: out of range without converting (keeps huge inputs harmless).
  return digits.length > 6 ? Number.POSITIVE_INFINITY : Number(digits);
}

function readItem(item: string, rule: FieldRule): ItemResult {
  if (item === '') return { invalid: `empty list item in the ${rule.name} field` };
  const shape = /^(\*|\d+|\d+-\d+)(?:\/(\d+))?$/.exec(item);
  if (!shape) {
    const named = /^[A-Za-z]{3}(-[A-Za-z]{3})?$/.test(item) && (rule.name === 'month' || rule.name === 'day of week');
    if (named) return { unspecified: `"${item}": names are an extension` };
    return { invalid: `"${item}" in the ${rule.name} field is not *, a number, a range or a step` };
  }
  const [, base, stepText] = shape;
  const inside = (n: number) => n >= rule.min && n <= rule.max;

  let from: number, to: number;
  let single = false;
  if (base === '*') {
    from = rule.min; to = rule.max;
  } else if (base.includes('-')) {
    const [a, b] = base.split('-').map(toNumber);
    if (!inside(a) || !inside(b)) return { invalid: `"${item}": ${rule.name} must be ${rule.min}–${rule.max}` };
    if (a > b) return { invalid: `"${item}": the range runs backwards` };
    from = a; to = b;
  } else {
    const n = toNumber(base);
    if (!inside(n)) return { invalid: `"${item}": ${rule.name} must be ${rule.min}–${rule.max}` };
    from = n; to = n; single = true;
  }

  let step = 1;
  if (stepText !== undefined) {
    step = toNumber(stepText);
    if (step === 0) return { invalid: `"${item}": a step of 0 never advances` };
    if (single) return { unspecified: `"${item}": number/step is a cronie extension` };
    if (step > rule.max) return { unspecified: `"${item}": step larger than the field` };
  }
  const values: number[] = [];
  for (let v = from; v <= to; v += step) values.push(v);
  return { values };
}

function readField(text: string, rule: FieldRule): ItemResult {
  const all = new Set<number>();
  let unspecified: string | null = null;
  for (const item of text.split(',')) {
    const result = readItem(item, rule);
    if ('invalid' in result) return result;
    if ('unspecified' in result) { unspecified = unspecified ?? result.unspecified; continue; }
    result.values.forEach(v => all.add(v));
  }
  if (unspecified) return { unspecified };
  return { values: [...all].sort((a, b) => a - b) };
}

/** Splits an expression into its blank-separated fields. */
export function fieldsOf(expression: string): string[] {
  return expression.split(/[ \t]+/).filter(part => part !== '');
}

/** Decides whether an expression is a valid schedule, and what it means. */
export function judge(expression: string): Verdict {
  if (/[^\S \t]/.test(expression)) return { kind: 'unspecified', reason: 'whitespace other than space or tab' };
  const fields = fieldsOf(expression);
  if (fields.length === 1 && fields[0].startsWith('@')) return { kind: 'unspecified', reason: '@-macros are an extension' };
  if (fields.length !== 5) return { kind: 'invalid', reason: `${fields.length} field${fields.length === 1 ? '' : 's'} instead of 5` };

  const sets: number[][] = [];
  let unspecified: string | null = null;
  for (let i = 0; i < 5; i++) {
    const result = readField(fields[i], FIELD_RULES[i]);
    if ('invalid' in result) return { kind: 'invalid', reason: result.invalid };
    if ('unspecified' in result) { unspecified = unspecified ?? result.unspecified; sets.push([]); continue; }
    sets.push(result.values);
  }
  if (unspecified) return { kind: 'unspecified', reason: unspecified };

  const domStar = fields[2].startsWith('*'), dowStar = fields[4].startsWith('*');
  if ((domStar && fields[2] !== '*' && !dowStar) || (dowStar && fields[4] !== '*' && !domStar)) {
    return { kind: 'unspecified', reason: 'a *-step in one day field while the other is restricted' };
  }
  return {
    kind: 'valid',
    fields,
    schedule: {
      minutes: sets[0],
      hours: sets[1],
      daysOfMonth: sets[2],
      months: sets[3],
      weekdays: [...new Set(sets[4].map(day => (day === 7 ? 0 : day)))].sort((a, b) => a - b),
      domRestricted: !domStar,
      dowRestricted: !dowStar,
    },
  };
}

/** The schedule of an expression the caller knows to be valid. */
export function scheduleOf(expression: string): Schedule {
  const verdict = judge(expression);
  if (verdict.kind !== 'valid') throw new Error(`oracle: "${expression}" is ${verdict.kind}: ${verdict.reason}`);
  return verdict.schedule;
}

/* ------------------------------------------------------------------ */
/* Time zone arithmetic                                                */
/* ------------------------------------------------------------------ */

export interface WallClock { year: number; month: number; day: number; hour: number; minute: number; second: number }

const formatters = new Map<string, Intl.DateTimeFormat>();

/** The wall-clock reading in `zone` at an instant. */
export function wallClock(instant: number, zone: string = ZONE): WallClock {
  let formatter = formatters.get(zone);
  if (!formatter) {
    formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: zone, hourCycle: 'h23',
      year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric',
    });
    formatters.set(zone, formatter);
  }
  const parts: Record<string, number> = {};
  for (const part of formatter.formatToParts(new Date(instant))) {
    if (part.type !== 'literal') parts[part.type] = Number(part.value);
  }
  return { year: parts.year, month: parts.month, day: parts.day, hour: parts.hour % 24, minute: parts.minute, second: parts.second };
}

/** Milliseconds the zone is ahead of UTC at an instant. */
export function offsetAt(instant: number, zone: string = ZONE): number {
  const w = wallClock(instant, zone);
  return Date.UTC(w.year, w.month - 1, w.day, w.hour, w.minute, w.second) - Math.floor(instant / 1000) * 1000;
}

export interface CivilDate { year: number; month: number; day: number }

const MONTH_LENGTHS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

export function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

export function daysInMonth(year: number, month: number): number {
  return month === 2 && isLeapYear(year) ? 29 : MONTH_LENGTHS[month - 1];
}

function dayAfter(date: CivilDate): CivilDate {
  if (date.day < daysInMonth(date.year, date.month)) return { ...date, day: date.day + 1 };
  if (date.month < 12) return { year: date.year, month: date.month + 1, day: 1 };
  return { year: date.year + 1, month: 1, day: 1 };
}

/** 0 = Sunday. Counted from 1 January 1970, a Thursday. */
export function weekdayOf(date: CivilDate): number {
  const daysSinceEpoch = Math.round(Date.UTC(date.year, date.month - 1, date.day) / DAY);
  return (((daysSinceEpoch + 4) % 7) + 7) % 7;
}

interface LocalMinute { instant: number; hour: number; minute: number }
type LocalDay = { regular: true; start: number } | { regular: false; minutes: LocalMinute[] };

const localDays = new Map<string, LocalDay>();

/**
 * The real minutes that make up one local calendar day.
 * A regular day starts at local midnight and has 1440 minutes in clock order.
 * Any other day (a clock change) is listed minute by minute as it really runs.
 */
function localDay(date: CivilDate, zone: string): LocalDay {
  const key = `${zone}|${date.year}-${date.month}-${date.day}`;
  const known = localDays.get(key);
  if (known) return known;

  const sameDate = (w: WallClock) => w.year === date.year && w.month === date.month && w.day === date.day;
  const asUtc = Date.UTC(date.year, date.month - 1, date.day);
  const start = asUtc - offsetAt(asUtc, zone);
  const first = wallClock(start, zone), last = wallClock(start + DAY - MINUTE, zone), before = wallClock(start - MINUTE, zone);
  let result: LocalDay;
  if (sameDate(first) && first.hour === 0 && first.minute === 0 && sameDate(last) && last.hour === 23 && last.minute === 59 && !sameDate(before)) {
    result = { regular: true, start };
  } else {
    // Every zone is within 14 hours of UTC, so the local day lies inside this window.
    const minutes: LocalMinute[] = [];
    for (let instant = asUtc - 15 * HOUR; instant < asUtc + 40 * HOUR; instant += MINUTE) {
      const w = wallClock(instant, zone);
      if (sameDate(w)) minutes.push({ instant, hour: w.hour, minute: w.minute });
    }
    result = { regular: false, minutes };
  }
  localDays.set(key, result);
  return result;
}

/** The first instant at which the zone's clock shows the given wall-clock time (or the next existing minute). */
export function instantOf(date: CivilDate, hour: number, minute: number, zone: string = ZONE): number {
  const day = localDay(date, zone);
  if (day.regular) return day.start + (hour * 60 + minute) * MINUTE;
  const hit = day.minutes.find(m => m.hour * 60 + m.minute >= hour * 60 + minute) ?? day.minutes[day.minutes.length - 1];
  return hit.instant;
}

export interface ClockChange {
  /** First instant with the new offset. */
  instant: number;
  /** Milliseconds the clock moved: positive in spring (an hour is skipped), negative in autumn (an hour repeats). */
  shift: number;
}

/** The clock changes of one calendar year in `zone` (empty for zones without daylight saving time). */
export function clockChanges(year: number, zone: string = ZONE): ClockChange[] {
  const out: ClockChange[] = [];
  const end = Date.UTC(year + 1, 0, 1);
  for (let t = Date.UTC(year, 0, 1); t < end; t += DAY) {
    const a = offsetAt(t, zone), b = offsetAt(t + DAY, zone);
    if (a === b) continue;
    let low = t, high = t + DAY;
    while (high - low > MINUTE) {
      const mid = low + Math.floor((high - low) / 2 / MINUTE) * MINUTE;
      if (offsetAt(mid, zone) === a) low = mid; else high = mid;
    }
    out.push({ instant: high, shift: b - a });
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Next executions                                                     */
/* ------------------------------------------------------------------ */

export interface Run {
  instant: number;
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  weekday: number;
}

export interface RunList {
  runs: Run[];
  /** True when a matching wall-clock time was skipped or repeated by a clock change on a day that was looked at. */
  dstAmbiguous: boolean;
}

function dayMatches(schedule: Schedule, date: CivilDate): boolean {
  if (!schedule.months.includes(date.month)) return false;
  const byDate = schedule.daysOfMonth.includes(date.day);
  const byWeekday = schedule.weekdays.includes(weekdayOf(date));
  return schedule.domRestricted && schedule.dowRestricted ? byDate || byWeekday : byDate && byWeekday;
}

/** Days to look ahead. Ten leap days need forty years. */
const HORIZON_DAYS = 366 * 60;

/** The first `count` executions after `now`, in `zone`. Fewer when the schedule stops matching (31 February). */
export function nextRuns(schedule: Schedule, now: number, count = 10, zone: string = ZONE): RunList {
  const runs: Run[] = [];
  let dstAmbiguous = false;
  const today = wallClock(now, zone);
  let date: CivilDate = { year: today.year, month: today.month, day: today.day };
  for (let looked = 0; looked < HORIZON_DAYS && runs.length < count; looked++, date = dayAfter(date)) {
    if (!dayMatches(schedule, date)) continue;
    const weekday = weekdayOf(date);
    const add = (instant: number, hour: number, minute: number) => {
      if (instant > now && runs.length < count) runs.push({ instant, ...date, hour, minute, weekday });
    };
    const day = localDay(date, zone);
    if (day.regular) {
      for (const hour of schedule.hours) for (const minute of schedule.minutes) add(day.start + (hour * 60 + minute) * MINUTE, hour, minute);
      continue;
    }
    const occurrences = new Map<number, number>();
    for (const m of day.minutes) {
      if (!schedule.hours.includes(m.hour) || !schedule.minutes.includes(m.minute)) continue;
      occurrences.set(m.hour * 60 + m.minute, (occurrences.get(m.hour * 60 + m.minute) ?? 0) + 1);
      add(m.instant, m.hour, m.minute);
    }
    for (const hour of schedule.hours) for (const minute of schedule.minutes) {
      if (occurrences.get(hour * 60 + minute) !== 1) dstAmbiguous = true;
    }
  }
  return { runs, dstAmbiguous };
}

/* ------------------------------------------------------------------ */
/* Display                                                             */
/* ------------------------------------------------------------------ */

const two = (n: number) => (n < 10 ? `0${n}` : String(n));

export function relativeText(runInstant: number, now: number): string {
  const total = Math.floor((runInstant - now) / MINUTE);
  if (total < 1) return 'now';
  const days = Math.trunc(total / 1440);
  const hours = Math.trunc((total - days * 1440) / 60);
  const minutes = total - days * 1440 - hours * 60;
  if (total < 60) return `in ${minutes}m`;
  if (total < 1440) return `in ${hours}h ${minutes}m`;
  return `in ${days}d ${hours}h`;
}

export interface ExpectedRow { index: string; date: string; time: string; day: string; relative: string }

export function expectedRows(runs: Run[], now: number): ExpectedRow[] {
  return runs.map((run, i) => {
    const hour12 = run.hour % 12 === 0 ? 12 : run.hour % 12;
    return {
      index: String(i + 1),
      date: `${MONTH_SHORT[run.month - 1]} ${run.day}, ${run.year}`,
      time: `${two(hour12)}:${two(run.minute)} ${run.hour < 12 ? 'AM' : 'PM'}`,
      day: WEEKDAY_LONG[run.weekday],
      relative: relativeText(run.instant, now),
    };
  });
}

/** Everything the page shows for an expression at a given moment. `null` means "not checked". */
export interface ExpectedView {
  input: string | null;
  banner: 'Valid Expression' | 'Invalid Expression' | null;
  description: string | null | undefined;
  fields: { caption: string; value: string }[];
  /** `undefined` leaves the run table (heading and rows) unchecked. */
  header: string | null | undefined;
  rows: ExpectedRow[];
  buttons: string[];
}

/** The view of a valid expression. `description: undefined` leaves the sentence unchecked. */
export function validView(expression: string, runs: Run[], now: number, description?: string | null): ExpectedView {
  const fields = fieldsOf(expression);
  return {
    input: expression,
    banner: 'Valid Expression',
    description: description ?? undefined,
    fields: FIELD_RULES.map((rule, i) => ({ caption: rule.caption, value: fields[i] })),
    header: `Next ${runs.length} Executions`,
    rows: expectedRows(runs, now),
    buttons: ['Copy Expression', 'Copy Description'],
  };
}

/** The view of an invalid expression: the banner, and nothing that looks like a result. */
export function invalidView(expression: string): ExpectedView {
  return { input: expression, banner: 'Invalid Expression', description: undefined, fields: [], header: null, rows: [], buttons: [] };
}

/** The view of an empty field: no banner and no result. */
export function emptyView(expression: string): ExpectedView {
  return { input: expression, banner: null, description: null, fields: [], header: null, rows: [], buttons: [] };
}

/* ------------------------------------------------------------------ */
/* Human description                                                   */
/* ------------------------------------------------------------------ */

/**
 * The sentence for the common forms the tool describes in words:
 *   minute  `*`, `*\/n`, or a number
 *   hour    `*`, `*\/n`, a number, or a list of numbers
 *   day     `*`, a number, a list of numbers or a range (echoed as typed)
 *   month   `*`, a number or a list of numbers (named)
 *   weekday `*`, a number or a list of numbers (named; 7 is Sunday)
 * Returns `null` for anything else; the specs then only check that the
 * sentence contains no broken value.
 *
 * Wording, from the meaning of each part:
 *   every minute ................ "Every minute"
 *   every n minutes ............. "Every n minutes"
 *   minute M of each hour ....... "At minute M of every hour"
 *   on the hour H ............... "At <H o'clock>"
 *   <minutes> within hour H ..... "<minute part> past <H o'clock>"
 *   <minutes> every k hours ..... "<minute part> every k hours"
 *   <minutes> in several hours .. "<minute part> at <H1> and <H2> …"
 *   then "on day D of the month", "in Jan, Feb", "on Mon, Wed".
 */
export function describeCommon(expression: string): string | null {
  const fields = fieldsOf(expression);
  if (fields.length !== 5) return null;
  const [minute, hour, day, month, weekday] = fields;
  const plain = (text: string) => /^(0|[1-9]\d?)$/.test(text);
  const plainList = (text: string) => text.split(',').every(plain);
  // A step of 1 is "every minute" under another spelling; the tool has no wording of its own for it.
  const stepOf = (text: string) => (/^\*\/([2-9]|[1-9]\d)$/.exec(text) || [])[1];

  let minutePart: string;
  if (minute === '*') minutePart = 'Every minute';
  else if (stepOf(minute)) minutePart = `Every ${stepOf(minute)} minutes`;
  else if (plain(minute)) minutePart = `At minute ${minute}`;
  else return null;

  const words: string[] = [];
  if (hour === '*') words.push(plain(minute) ? `${minutePart} of every hour` : minutePart);
  else if (stepOf(hour)) words.push(`${minutePart} every ${stepOf(hour)} hours`);
  else if (plain(hour)) words.push(minute === '0' ? `At ${CLOCK[Number(hour)]}` : `${minutePart} past ${CLOCK[Number(hour)]}`);
  else if (plainList(hour)) words.push(`${minutePart} at ${hour.split(',').map(h => CLOCK[Number(h)]).join(' and ')}`);
  else return null;

  if (day !== '*') {
    if (!plainList(day) && !/^[1-9]\d?-[1-9]\d?$/.test(day)) return null;
    words.push(`on day ${day} of the month`);
  }
  if (month !== '*') {
    if (!plainList(month)) return null;
    words.push(`in ${month.split(',').map(m => MONTH_SHORT[Number(m) - 1]).join(', ')}`);
  }
  if (weekday !== '*') {
    if (!plainList(weekday)) return null;
    words.push(`on ${weekday.split(',').map(d => WEEKDAY_SHORT[Number(d) === 7 ? 0 : Number(d)]).join(', ')}`);
  }
  return words.join(' ');
}

/* ------------------------------------------------------------------ */
/* Presets                                                             */
/* ------------------------------------------------------------------ */

const apart = (runs: Run[], minutes: number) => runs.slice(1).every((run, i) => run.instant - runs[i].instant === minutes * MINUTE);
const allAt = (runs: Run[], hour: number, minute: number) => runs.every(run => run.hour === hour && run.minute === minute);

/**
 * The ten presets and what each label promises. `holds` is evaluated on the
 * oracle's runs for the preset's expression at a time without a clock change,
 * so a preset whose expression does not do what its label says is caught.
 */
export const PRESETS: { label: string; expr: string; holds: (runs: Run[]) => boolean }[] = [
  { label: 'Every minute', expr: '* * * * *', holds: runs => apart(runs, 1) },
  { label: 'Every 5 minutes', expr: '*/5 * * * *', holds: runs => apart(runs, 5) && runs.every(r => r.minute % 5 === 0) },
  { label: 'Every 15 minutes', expr: '*/15 * * * *', holds: runs => apart(runs, 15) && runs.every(r => r.minute % 15 === 0) },
  { label: 'Every hour', expr: '0 * * * *', holds: runs => apart(runs, 60) && runs.every(r => r.minute === 0) },
  { label: 'Daily at midnight', expr: '0 0 * * *', holds: runs => allAt(runs, 0, 0) && runs.slice(1).every((r, i) => r.day !== runs[i].day) },
  { label: 'Daily at 3 AM', expr: '0 3 * * *', holds: runs => allAt(runs, 3, 0) && runs.slice(1).every((r, i) => r.day !== runs[i].day) },
  { label: 'Weekdays at 9 AM', expr: '0 9 * * 1-5', holds: runs => allAt(runs, 9, 0) && runs.every(r => r.weekday >= 1 && r.weekday <= 5) && new Set(runs.map(r => r.weekday)).size === 5 },
  { label: 'Weekly (Sunday)', expr: '0 0 * * 0', holds: runs => allAt(runs, 0, 0) && runs.every(r => r.weekday === 0) },
  { label: 'Monthly (1st)', expr: '0 0 1 * *', holds: runs => allAt(runs, 0, 0) && runs.every(r => r.day === 1) && new Set(runs.map(r => `${r.year}-${r.month}`)).size === runs.length },
  { label: 'Yearly (Jan 1)', expr: '0 0 1 1 *', holds: runs => allAt(runs, 0, 0) && runs.every(r => r.day === 1 && r.month === 1) && new Set(runs.map(r => r.year)).size === runs.length },
];
