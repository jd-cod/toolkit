import type { Rng } from '../_support/rng';
import {
  DAY, FIELD_RULES, HOUR, MINUTE, ZONE, clockChanges, daysInMonth, instantOf, isLeapYear, nextRuns,
  type FieldRule, type Run, type Schedule,
} from './oracle';

/**
 * Random cron expressions and random "now" instants.
 *
 * Every generator returns the text to type together with the facts about it:
 * a valid expression comes with the value sets it was built from (the ground
 * truth the run-time oracle starts from, independent of the oracle's parser),
 * an invalid one with the rule it breaks.
 */

export interface GeneratedExpression {
  expr: string;
  fields: string[];
  /** What the expression means, recorded while building it. */
  truth: Schedule;
}

interface Piece { text: string; values: number[] }

const [MINUTE_RULE, HOUR_RULE, DOM_RULE, MONTH_RULE, DOW_RULE] = FIELD_RULES;

function span(from: number, to: number, step = 1): number[] {
  const out: number[] = [];
  for (let v = from; v <= to; v += step) out.push(v);
  return out;
}

const star = (rule: FieldRule): Piece => ({ text: '*', values: span(rule.min, rule.max) });

function numberPiece(rng: Rng, rule: FieldRule, leadingZero = false): Piece {
  const value = rng.int(rule.min, rule.max);
  return { text: leadingZero && value < 10 ? `0${value}` : String(value), values: [value] };
}

function rangePiece(rng: Rng, rule: FieldRule): Piece {
  const from = rng.int(rule.min, rule.max);
  const to = rng.bool(0.1) ? from : rng.int(from, rule.max);
  return { text: `${from}-${to}`, values: span(from, to) };
}

function starStepPiece(rng: Rng, rule: FieldRule): Piece {
  const step = rng.int(2, Math.max(2, Math.floor((rule.max - rule.min) / 2)));
  return { text: `*/${step}`, values: span(rule.min, rule.max, step) };
}

function rangeStepPiece(rng: Rng, rule: FieldRule): Piece {
  const from = rng.int(rule.min, rule.max - 1);
  const to = rng.int(from + 1, rule.max);
  const step = rng.int(1, Math.max(1, to - from));
  return { text: `${from}-${to}/${step}`, values: span(from, to, step) };
}

function listPiece(rng: Rng, rule: FieldRule): Piece {
  const items = Array.from({ length: rng.int(2, 4) }, () =>
    rng.weighted([numberPiece, rangePiece, rangeStepPiece], [6, 2, 1])(rng, rule));
  return { text: items.map(i => i.text).join(','), values: items.flatMap(i => i.values) };
}

/** A restricted field in one of the standard notations. */
function restricted(rng: Rng, rule: FieldRule, allowStarStep = true): Piece {
  const makers = [numberPiece, rangePiece, listPiece, rangeStepPiece, starStepPiece];
  const weights = [5, 3, 4, 1, allowStarStep ? 3 : 0];
  if (rng.bool(0.06)) return numberPiece(rng, rule, true);
  return rng.weighted(makers, weights)(rng, rule);
}

const unique = (values: number[]) => [...new Set(values)].sort((a, b) => a - b);

function assemble(pieces: Piece[]): GeneratedExpression {
  const fields = pieces.map(p => p.text);
  return {
    expr: fields.join(' '),
    fields,
    truth: {
      minutes: unique(pieces[0].values),
      hours: unique(pieces[1].values),
      daysOfMonth: unique(pieces[2].values),
      months: unique(pieces[3].values),
      weekdays: unique(pieces[4].values.map(day => (day === 7 ? 0 : day))),
      domRestricted: !fields[2].startsWith('*'),
      dowRestricted: !fields[4].startsWith('*'),
    },
  };
}

/**
 * A random valid expression using numbers, ranges, lists, steps and mixtures.
 * At most one of the two day fields is restricted here; expressions that
 * restrict both follow the either-day rule and come from `bothDaysExpression`.
 */
export function validExpression(rng: Rng): GeneratedExpression {
  const shape = rng.weighted(['minutes', 'hours', 'daily', 'weekly', 'monthly', 'anything'] as const, [4, 3, 3, 2, 2, 3]);
  const fixedMinute = () => numberPiece(rng, MINUTE_RULE);
  const fixedHour = () => numberPiece(rng, HOUR_RULE);
  let pieces: Piece[];
  if (shape === 'minutes') {
    pieces = [restricted(rng, MINUTE_RULE), rng.bool(0.6) ? star(HOUR_RULE) : restricted(rng, HOUR_RULE), star(DOM_RULE), star(MONTH_RULE), star(DOW_RULE)];
    if (rng.bool(0.15)) pieces[0] = star(MINUTE_RULE);
  } else if (shape === 'hours') {
    pieces = [rng.bool(0.7) ? fixedMinute() : listPiece(rng, MINUTE_RULE), restricted(rng, HOUR_RULE), star(DOM_RULE), star(MONTH_RULE), star(DOW_RULE)];
  } else if (shape === 'daily') {
    pieces = [fixedMinute(), rng.bool(0.7) ? fixedHour() : listPiece(rng, HOUR_RULE), star(DOM_RULE), rng.bool(0.8) ? star(MONTH_RULE) : restricted(rng, MONTH_RULE), star(DOW_RULE)];
  } else if (shape === 'weekly') {
    pieces = [fixedMinute(), fixedHour(), star(DOM_RULE), star(MONTH_RULE), restricted(rng, DOW_RULE)];
  } else if (shape === 'monthly') {
    pieces = [fixedMinute(), fixedHour(), restricted(rng, DOM_RULE), rng.bool(0.7) ? star(MONTH_RULE) : restricted(rng, MONTH_RULE), star(DOW_RULE)];
  } else {
    const dayField = rng.pick(['dom', 'dow', 'none'] as const);
    pieces = [
      rng.bool(0.2) ? star(MINUTE_RULE) : restricted(rng, MINUTE_RULE),
      rng.bool(0.3) ? star(HOUR_RULE) : restricted(rng, HOUR_RULE),
      dayField === 'dom' ? restricted(rng, DOM_RULE) : star(DOM_RULE),
      rng.bool(0.6) ? star(MONTH_RULE) : restricted(rng, MONTH_RULE),
      dayField === 'dow' ? restricted(rng, DOW_RULE) : star(DOW_RULE),
    ];
  }
  return assemble(pieces);
}

/** Day of month AND day of week restricted (no `*`-steps): the either-day rule applies. */
export function bothDaysExpression(rng: Rng): GeneratedExpression {
  return assemble([
    numberPiece(rng, MINUTE_RULE),
    numberPiece(rng, HOUR_RULE),
    rng.bool(0.6) ? numberPiece(rng, DOM_RULE) : listPiece(rng, DOM_RULE),
    star(MONTH_RULE),
    rng.weighted([numberPiece, rangePiece, listPiece], [3, 1, 1])(rng, DOW_RULE),
  ]);
}

/**
 * An expression in the common forms the tool describes in words (see
 * `describeCommon` in the oracle): canonical numbers, `*\/n` with n >= 2,
 * lists of hours, months and weekdays.
 */
export function commonFormExpression(rng: Rng): string {
  const numbers = (rule: FieldRule, count: number) => rng.sample(span(rule.min, rule.max), count).join(',');
  const minute = rng.weighted(['*', `*/${rng.int(2, 30)}`, '0', String(rng.int(0, 59))], [2, 3, 3, 4]);
  const hour = rng.weighted(['*', `*/${rng.int(2, 12)}`, String(rng.int(0, 23)), numbers(HOUR_RULE, rng.int(2, 4))], [3, 2, 5, 2]);
  const day = rng.weighted(['*', String(rng.int(1, 31)), numbers(DOM_RULE, 2), `${rng.int(1, 10)}-${rng.int(11, 31)}`], [6, 2, 1, 1]);
  const month = rng.weighted(['*', String(rng.int(1, 12)), numbers(MONTH_RULE, rng.int(2, 4))], [6, 2, 2]);
  const weekday = rng.weighted(['*', String(rng.int(0, 7)), numbers(DOW_RULE, rng.int(2, 3))], [6, 2, 2]);
  return [minute, hour, day, month, weekday].join(' ');
}

/* ------------------------------------------------------------------ */
/* Invalid expressions                                                 */
/* ------------------------------------------------------------------ */

export type InvalidKind =
  | 'field-count' | 'out-of-range' | 'zero-step' | 'empty-item' | 'not-a-number'
  | 'reversed-range' | 'trailing-characters' | 'negative' | 'broken-range' | 'broken-step';

export interface InvalidExpression { expr: string; why: string }

/** A simple valid field, used around the one broken field. */
function filler(rng: Rng, rule: FieldRule): string {
  return rng.bool(0.6) ? '*' : String(rng.int(rule.min, rule.max));
}

/** Five valid fields with field `index` replaced by `bad`. */
function withField(rng: Rng, index: number, bad: string): string {
  return FIELD_RULES.map((rule, i) => (i === index ? bad : filler(rng, rule))).join(' ');
}

/** Expressions that every cron implementation rejects, by the rule they break. Fixed cases first, then random ones. */
export function invalidExpressions(rng: Rng, kind: InvalidKind, randomCount = 10): InvalidExpression[] {
  const out: InvalidExpression[] = [];
  const add = (expr: string, why: string) => out.push({ expr, why });
  const anyField = () => rng.int(0, 4);
  const name = (i: number) => FIELD_RULES[i].name;
  const inRange = (i: number) => rng.int(FIELD_RULES[i].min, FIELD_RULES[i].max);

  if (kind === 'field-count') {
    add('*', 'one field');
    add('* *', 'two fields');
    add('* * *', 'three fields');
    add('* * * *', 'four fields');
    add('* * * * * *', 'six fields (a seconds or year column is not standard cron)');
    add('0 0 1 1 * 2030', 'six fields');
    add('*/15****', 'no blanks between the fields');
    add('0,0,1,1,*', 'commas instead of blanks');
    for (let n = 0; n < randomCount; n++) {
      const count = rng.pick([1, 2, 3, 4, 6, 7, 8]);
      add(Array.from({ length: count }, (_, i) => filler(rng, FIELD_RULES[i % 5])).join(' '), `${count} fields`);
    }
  } else if (kind === 'out-of-range') {
    add('60 * * * *', 'minute 60');
    add('* 24 * * *', 'hour 24');
    add('* * 0 * *', 'day of month 0');
    add('* * 32 * *', 'day of month 32');
    add('* * * 0 *', 'month 0');
    add('* * * 13 *', 'month 13');
    add('* * * * 8', 'day of week 8');
    add('0-60 * * * *', 'minute range ending at 60');
    add('* 20-24 * * *', 'hour range ending at 24');
    add('* * 0-5 * *', 'day-of-month range starting at 0');
    add('* * * 10-13 *', 'month range ending at 13');
    add('* * * * 5-8', 'day-of-week range ending at 8');
    add('5,61 * * * *', 'minute list containing 61');
    add('0 0 1,32 * *', 'day-of-month list containing 32');
    add('0-99/5 * * * *', 'stepped minute range ending at 99');
    for (let n = 0; n < randomCount; n++) {
      const i = anyField();
      const rule = FIELD_RULES[i];
      const value = rule.min > 0 && rng.bool(0.25) ? 0 : rng.pick([rule.max + 1, rule.max + rng.int(2, 40), rng.int(100, 9999)]);
      const form = rng.pick(['number', 'range', 'list'] as const);
      const bad = form === 'number' ? String(value) : form === 'range' && value > rule.max ? `${inRange(i)}-${value}` : `${inRange(i)},${value}`;
      add(withField(rng, i, bad), `${name(i)} ${value} is outside ${rule.min}–${rule.max}`);
    }
  } else if (kind === 'zero-step') {
    add('*/0 * * * *', 'minute step 0');
    add('0 */0 * * *', 'hour step 0');
    add('0 0 */0 * *', 'day step 0');
    add('0 0 1 */0 *', 'month step 0');
    add('0 0 * * */0', 'weekday step 0');
    add('10-20/0 * * * *', 'range with step 0');
    add('*/00 * * * *', 'step 00');
    add('*/ * * * *', 'step sign without a number');
    add('5-10/ * * * *', 'range step sign without a number');
    for (let n = 0; n < randomCount; n++) {
      const i = anyField();
      const rule = FIELD_RULES[i];
      const from = rng.int(rule.min, rule.max - 1);
      add(withField(rng, i, rng.bool() ? '*/0' : `${from}-${rng.int(from + 1, rule.max)}/0`), `${name(i)} step 0`);
    }
  } else if (kind === 'empty-item') {
    add('1,,2 * * * *', 'empty item in the middle of a list');
    add(',1 * * * *', 'list starting with a comma');
    add('1, * * * *', 'list ending with a comma');
    add(', * * * *', 'a comma alone');
    add('0 9,,17 * * *', 'empty item in the hour list');
    add('0 0 * * 1,', 'weekday list ending with a comma');
    for (let n = 0; n < randomCount; n++) {
      const i = anyField();
      const a = inRange(i), b = inRange(i);
      add(withField(rng, i, rng.pick([`${a},,${b}`, `,${a}`, `${a},`, `${a},${b},`])), `empty item in the ${name(i)} list`);
    }
  } else if (kind === 'not-a-number') {
    add('abc * * * *', 'letters as minute');
    add('* noon * * *', 'a word as hour');
    add('* * first * *', 'a word as day');
    add('x * * * *', 'a letter as minute');
    add('** * * * *', 'two asterisks');
    add('? * * * *', 'question mark (Quartz syntax)');
    add('0 0 L * *', 'L (Quartz syntax)');
    add('*5 * * * *', 'asterisk followed by a number');
    add('every 5 minutes please now', 'five words');
    add('$ % ^ & !', 'five symbols');
    for (let n = 0; n < randomCount; n++) {
      // Words of four or more letters, so month and weekday names (an extension) are not hit by chance.
      const i = anyField();
      const word = rng.pick([rng.string(rng.int(4, 8), 'abcdefghijklmnopqrstuvwxyz'), rng.pick(['?', '#', '$', '~', '**', '*?', '_', '=', '½', '①'])]);
      add(withField(rng, i, word), `"${word}" as ${name(i)}`);
    }
  } else if (kind === 'reversed-range') {
    add('5-1 * * * *', 'minute range 5-1');
    add('0 17-9 * * *', 'hour range 17-9');
    add('0 0 20-10 * *', 'day range 20-10');
    add('0 0 1 12-1 *', 'month range 12-1');
    add('0 9 * * 5-1', 'weekday range 5-1');
    add('30-10/5 * * * *', 'stepped minute range 30-10');
    add('0,45-15 * * * *', 'list containing the range 45-15');
    for (let n = 0; n < randomCount; n++) {
      const i = anyField();
      const rule = FIELD_RULES[i];
      const low = rng.int(rule.min, rule.max - 1), high = rng.int(low + 1, rule.max);
      add(withField(rng, i, rng.bool(0.8) ? `${high}-${low}` : `${high}-${low}/${rng.int(1, 3)}`), `${name(i)} range ${high}-${low} runs backwards`);
    }
  } else if (kind === 'trailing-characters') {
    add('5x * * * *', 'minute "5x"');
    add('0 9am * * *', 'hour "9am"');
    add('1.5 * * * *', 'minute "1.5"');
    add('1e1 * * * *', 'minute "1e1"');
    add('0x10 * * * *', 'minute "0x10"');
    add('0 0 1st * *', 'day "1st"');
    add('0 0 1 2nd *', 'month "2nd"');
    add('0 0 * * 1!', 'weekday "1!"');
    add('0 0 * * 5#2', 'weekday "5#2" (Quartz syntax for the second Friday)');
    add('0 0 15W * *', 'day "15W" (Quartz syntax for the nearest weekday)');
    add('*/5x * * * *', 'step "5x"');
    add('*/1.5 * * * *', 'step "1.5"');
    add('10-20/5m * * * *', 'range step "5m"');
    add('5,10x * * * *', 'list item "10x"');
    for (let n = 0; n < randomCount; n++) {
      const i = anyField();
      const tail = rng.pick(['x', 'm', 'h', '.5', '!', '%', '_', 'th', ';', ')']);
      const value = inRange(i);
      add(withField(rng, i, rng.bool(0.75) ? `${value}${tail}` : `*/${rng.int(2, 5)}${tail}`), `${name(i)} has "${tail}" after a number`);
    }
  } else if (kind === 'negative') {
    add('-5 * * * *', 'minute -5');
    add('0 -1 * * *', 'hour -1');
    add('0 0 -1 * *', 'day -1');
    add('0 0 1 -1 *', 'month -1');
    add('0 0 * * -1', 'weekday -1');
    add('+5 * * * *', 'minute +5');
    add('*/-5 * * * *', 'step -5');
    add('0,-10 * * * *', 'list item -10');
    for (let n = 0; n < randomCount; n++) {
      const i = anyField();
      const value = rng.int(1, FIELD_RULES[i].max);
      add(withField(rng, i, `-${value}`), `${name(i)} -${value}`);
    }
  } else if (kind === 'broken-range') {
    add('5- * * * *', 'range without an end');
    add('- * * * *', 'a dash alone');
    add('1--5 * * * *', 'two dashes');
    add('1-2-3 * * * *', 'three numbers in one range');
    add('a-b * * * *', 'letters around a dash');
    add('*-5 * * * *', 'asterisk as the start of a range');
    add('1-x * * * *', 'letter as the end of a range');
    add('0 9-17- * * *', 'hour range with a dash at the end');
    add('0 0 * * 1-', 'weekday range without an end');
    add('0 9 * * 1-5-', 'weekday range with a dash at the end');
    for (let n = 0; n < randomCount; n++) {
      const i = anyField();
      const a = inRange(i);
      add(withField(rng, i, rng.pick([`${a}-`, `${a}--${a}`, `${a}-x`, `x-${a}`, `*-${a}`, `${a}-*`])), `malformed ${name(i)} range`);
    }
  } else {
    add('/5 * * * *', 'step without a start');
    add('*/5/2 * * * *', 'two steps');
    add('70/5 * * * *', 'step starting at minute 70');
    add('0 30/2 * * *', 'step starting at hour 30');
    add('*/x * * * *', 'letter as step');
    add('*//5 * * * *', 'two step signs');
    add('0-30/5/5 * * * *', 'two steps after a range');
    add('0 0 /2 * *', 'day step without a start');
    for (let n = 0; n < randomCount; n++) {
      const i = anyField();
      const rule = FIELD_RULES[i];
      const step = rng.int(2, 6);
      add(withField(rng, i, rng.pick([`/${step}`, `*/${step}/${rng.int(2, 4)}`, `${rule.max + rng.int(1, 30)}/${step}`, `*//${step}`])), `malformed ${name(i)} step`);
    }
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Instants                                                            */
/* ------------------------------------------------------------------ */

export interface PinnedInstant { instant: number; label: string }

const FIRST_YEAR = 2025, LAST_YEAR = 2034;

function jitter(rng: Rng): number {
  return rng.int(0, 59) * 1000 + rng.int(0, 999);
}

/** Any moment in the next years, with seconds and milliseconds. */
export function randomInstant(rng: Rng): PinnedInstant {
  const from = Date.UTC(FIRST_YEAR, 0, 1), to = Date.UTC(LAST_YEAR, 11, 31);
  return { instant: from + Math.floor(rng.next() * (to - from)), label: 'random moment' };
}

/** Moments where calendars go wrong: month ends, leap day, year end, and the days around a clock change. */
export function edgeInstant(rng: Rng, zone: string = ZONE): PinnedInstant {
  const year = rng.int(FIRST_YEAR, LAST_YEAR);
  const lateEvening = () => ({ hour: 23, minute: rng.int(30, 59) });
  const kind = rng.pick(['month-end', 'leap-day', 'february-end', 'year-end', 'new-year', 'clock-change'] as const);
  if (kind === 'month-end') {
    const month = rng.int(1, 12);
    const { hour, minute } = lateEvening();
    return { instant: instantOf({ year, month, day: daysInMonth(year, month) }, hour, minute, zone) + jitter(rng), label: `last evening of month ${month}/${year}` };
  }
  if (kind === 'leap-day') {
    const leap = rng.pick([2028, 2032]);
    const day = rng.pick([28, 29]);
    return { instant: instantOf({ year: leap, month: 2, day }, rng.int(0, 23), rng.int(0, 59), zone) + jitter(rng), label: `${day} February of leap year ${leap}` };
  }
  if (kind === 'february-end') {
    const plain = isLeapYear(year) ? year + 1 : year;
    const { hour, minute } = lateEvening();
    return { instant: instantOf({ year: plain, month: 2, day: 28 }, hour, minute, zone) + jitter(rng), label: `28 February ${plain} (not a leap year), late evening` };
  }
  if (kind === 'year-end') {
    const { hour, minute } = lateEvening();
    return { instant: instantOf({ year, month: 12, day: 31 }, hour, minute, zone) + jitter(rng), label: `New Year's Eve ${year}` };
  }
  if (kind === 'new-year') {
    return { instant: instantOf({ year, month: 1, day: 1 }, 0, rng.int(0, 5), zone) + jitter(rng), label: `first minutes of ${year}` };
  }
  const changes = clockChanges(year, zone);
  if (changes.length === 0) return randomInstant(rng);
  const change = rng.pick(changes);
  const instant = change.instant + rng.int(-4 * 24, 2 * 24) * HOUR + rng.int(0, 59) * MINUTE + jitter(rng);
  return { instant, label: `around the clock change of ${new Date(change.instant).toISOString()}` };
}

/** Half ordinary moments, half calendar edges. */
export function pinnedInstant(rng: Rng, zone: string = ZONE): PinnedInstant {
  return rng.bool(0.5) ? randomInstant(rng) : edgeInstant(rng, zone);
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

export interface ScheduleCase {
  expr: string;
  schedule: Schedule;
  now: number;
  nowLabel: string;
  /** The ten executions the oracle expects after `now`. */
  runs: Run[];
}

/**
 * How far ahead the tenth run may lie for the general tests: ten monthly runs
 * span at most 306 days, so everything from "every minute" to "monthly" is in.
 * Schedules that run less often (yearly, quarterly, the 31st, leap day) are
 * checked by the test for sparse schedules, which fails on the page's
 * one-year look-ahead limit; keeping them out of the general tests keeps one
 * defect in one test.
 */
export const DENSE_WITHIN_DAYS = 320;

/**
 * Draws expressions and moments until the pair gives ten runs within
 * `withinDays` and no matching time falls into a clock change (the one
 * situation cron implementations handle differently; it has its own tests).
 */
export function denseCase(
  rng: Rng,
  makeExpression: () => { expr: string; schedule: Schedule },
  makeInstant: () => PinnedInstant = () => pinnedInstant(rng, zone),
  zone: string = ZONE,
  withinDays: number = DENSE_WITHIN_DAYS,
): ScheduleCase {
  for (let attempt = 0; attempt < 500; attempt++) {
    const { expr, schedule } = makeExpression();
    const now = makeInstant();
    const { runs, dstAmbiguous } = nextRuns(schedule, now.instant, 10, zone);
    if (dstAmbiguous || runs.length < 10) continue;
    if (runs[9].instant - now.instant > withinDays * DAY) continue;
    return { expr, schedule, now: now.instant, nowLabel: `${now.label}, ${new Date(now.instant).toISOString()}`, runs };
  }
  throw new Error('generator: no dense, unambiguous case found in 500 attempts');
}

/** Text form of a case for the evidence file. */
export function caseLine(c: ScheduleCase): string {
  return `${c.expr}    @ ${new Date(c.now).toISOString()} (${c.nowLabel})`;
}
