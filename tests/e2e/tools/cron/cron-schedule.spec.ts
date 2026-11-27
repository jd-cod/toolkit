import { test, expect, type Page } from '../_support/fixtures';
import { openTool } from '../_support/navigation';
import type { Rng } from '../_support/rng';
import {
  DAY, HOUR, MINUTE, ZONE, clockChanges, describeCommon, judge, nextRuns, scheduleOf, validView, wallClock,
} from './oracle';
import {
  bothDaysExpression, caseLine, commonFormExpression, denseCase, pinnedInstant, randomInstant, validExpression, type ScheduleCase,
} from './generator';
import { HEADING, ROUTE, expectView, freezeClock, readView, showAt, summarize } from './page';

/**
 * Crontab Builder — layer 4: what the tool says a schedule means.
 * See cron.spec.ts for the inventory. Every test freezes the browser clock at a
 * generated moment and compares the validity banner, the five field cards, the
 * table heading and all ten rows (number, date, time, weekday, relative time)
 * with ./oracle.ts.
 */

const open = (page: Page) => openTool(page, ROUTE, HEADING);

const generalCase = (rng: Rng) => denseCase(rng, () => { const g = validExpression(rng); return { expr: g.expr, schedule: g.truth }; });

/** Shows a case and compares the whole page. `description: undefined` skips the sentence. */
async function expectCase(page: Page, c: ScheduleCase, context = ''): Promise<boolean> {
  await showAt(page, c.expr, c.now);
  return expectView(page, validView(c.expr, c.runs, c.now, describeCommon(c.expr)), `"${c.expr}" at ${c.nowLabel}${context ? ` — ${context}` : ''}`);
}

/** The first clock change of the wanted direction in a random year, or `undefined` in a zone without daylight saving time. */
function clockChange(rng: Rng, direction: 'forward' | 'back') {
  const year = rng.int(2025, 2034);
  return clockChanges(year).find(change => (direction === 'forward' ? change.shift > 0 : change.shift < 0));
}

test.describe('Crontab Builder — next executions', () => {
  test('random expressions (numbers, ranges, lists, steps, mixtures) at random moments: validity, field cards and all ten runs', async ({ page, rng, evidence }) => {
    const cases = Array.from({ length: 140 }, () => generalCase(rng));
    await evidence.save('cases.txt', cases.map(caseLine).join('\n'));
    await freezeClock(page, cases[0].now);
    await open(page);
    let wrong = 0;
    for (const c of cases) {
      const verdict = judge(c.expr);
      expect(verdict.kind === 'valid' && JSON.stringify(verdict.schedule) === JSON.stringify(c.schedule),
        `oracle self-check: the parser reads "${c.expr}" as the generator built it`).toBe(true);
      if (!await expectCase(page, c)) wrong++;
      expect(wrong, 'stopped after 6 wrong schedules; see the mismatches above').toBeLessThan(6);
    }
  });

  test('common schedules at calendar edges: month ends, 28/29 February, New Year, days around a clock change', async ({ page, rng, evidence }) => {
    const expressions = [
      '* * * * *', '*/10 * * * *', '0 * * * *', '45 23 * * *', '0 0 * * *', '30 0 * * *', '0 0 1 * *', '0 0 28-31 * *',
      '59 23 28-31 * *', '0 0 * * 0', '0 12 * * 1-5', '0 0 1,15 * *', '5 0 29,30,31 * *', '0 0 * * 6,0', '*/30 22-23 * * *', '0 0-2 1 * *',
    ];
    const cases = Array.from({ length: 60 }, () =>
      denseCase(rng, () => { const expr = rng.pick(expressions); return { expr, schedule: scheduleOf(expr) }; }, () => pinnedInstant(rng)));
    await evidence.save('cases.txt', cases.map(caseLine).join('\n'));
    await freezeClock(page, cases[0].now);
    await open(page);
    let wrong = 0;
    for (const c of cases) {
      if (!await expectCase(page, c)) wrong++;
      expect(wrong, 'stopped after 6 wrong schedules; see the mismatches above').toBeLessThan(6);
    }
  });

  test('relative times at their boundaries: "now", minutes, hours and minutes, days and hours', async ({ page, rng, evidence }) => {
    // A daily job at wall-clock time T, looked at from `lead` minutes (and a few seconds) before T.
    // Row 1 covers "now", "in Xm" and "in Xh Ym"; the following rows cover "in Xd Yh".
    const leads = [0, 1, 2, 59, 60, 61, 119, 120, 121, 599, 600, 1380, 1439];
    const seconds = [{ s: 0, ms: 0 }, { s: 0, ms: 1 }, { s: 1, ms: 0 }, { s: 30, ms: 500 }, { s: 59, ms: 999 }];
    const cases: ScheduleCase[] = [];
    for (const lead of leads) {
      const offset = rng.pick(seconds);
      cases.push(denseCase(rng, () => {
        const target = Math.floor(randomInstant(rng).instant / MINUTE) * MINUTE;
        const w = wallClock(target);
        const expr = rng.bool(0.7) ? `${w.minute} ${w.hour} * * *` : `${w.minute} * * * *`;
        return { expr, schedule: scheduleOf(expr) };
      }));
      // Re-pin the moment relative to the job's time of day.
      const c = cases[cases.length - 1];
      const first = c.runs[0].instant;
      const now = first - lead * MINUTE - offset.s * 1000 - offset.ms;
      const runs = nextRuns(c.schedule, now);
      if (runs.dstAmbiguous) { cases.pop(); continue; }
      cases[cases.length - 1] = { ...c, now, nowLabel: `${lead} min ${offset.s}.${String(offset.ms).padStart(3, '0')} s before a run, ${new Date(now).toISOString()}`, runs: runs.runs };
    }
    await evidence.save('cases.txt', cases.map(caseLine).join('\n'));
    await freezeClock(page, cases[0].now);
    await open(page);
    for (const c of cases) await expectCase(page, c);
  });

  test('different spellings of the same schedule give the same runs: 7 and 0 for Sunday, leading zeros, full ranges, lists and steps', async ({ page, rng, evidence }) => {
    const pairs: [string, string][] = [
      ['0 0 * * 7', '0 0 * * 0'],
      ['0 0 * * 5-7', '0 0 * * 0,5,6'],
      ['0 0 * * 0-7', '0 0 * * *'],
      ['05 09 * * *', '5 9 * * *'],
      ['0-59 * * * *', '* * * * *'],
      ['*/1 * * * *', '* * * * *'],
      ['0,15,30,45 * * * *', '*/15 * * * *'],
      ['0-59/15 * * * *', '*/15 * * * *'],
      ['0 0,12 * * *', '0 */12 * * *'],
      ['0 0 * * 1,2,3,4,5', '0 0 * * 1-5'],
      ['0 0 1-31 * *', '0 0 * * *'],
      ['0 0 * 1-12 *', '0 0 * * *'],
      ['3,3,3 * * * *', '3 * * * *'],
      ['10-20/5 * * * *', '10,15,20 * * * *'],
      ['30 6 * */2 *', '30 6 * 1,3,5,7,9,11 *'],
      ['0 */8 * * *', '0 0,8,16 * * *'],
      ['7-7 * * * *', '7 * * * *'],
    ];
    const cases = pairs.map(([a, b]) => ({ a, b, c: denseCase(rng, () => ({ expr: a, schedule: scheduleOf(a) })) }));
    await evidence.save('cases.txt', cases.map(x => `${x.a}  ==  ${x.b}  @ ${new Date(x.c.now).toISOString()}`).join('\n'));
    await freezeClock(page, cases[0].c.now);
    await open(page);
    for (const { a, b, c } of cases) {
      expect(JSON.stringify(nextRuns(scheduleOf(b), c.now).runs), `oracle self-check: "${a}" and "${b}" are the same schedule`).toBe(JSON.stringify(c.runs));
      await expectCase(page, c, `spelling "${a}"`);
      const rowsA = (await readView(page)).rows;
      await expectCase(page, { ...c, expr: b }, `spelling "${b}" of "${a}"`);
      const rowsB = (await readView(page)).rows;
      expect.soft(rowsB, `"${b}" and "${a}" are the same schedule and must list the same runs`).toEqual(rowsA);
    }
  });

  test('a schedule restricted by day of month AND day of week runs on days matching either one (standard cron rule)', async ({ page, rng, evidence }) => {
    // POSIX crontab: "if either the month or day of month is specified as an element or list, and
    // the day of week is also specified as an element or list, then any day matching either the
    // month and day of month, or the day of week, shall be matched." So `0 0 13 * 5` runs every
    // Friday and on every 13th, not only on Friday the 13th.
    const fixed = ['0 0 13 * 5', '0 12 1,15 * 1', '30 8 1 * 1-5', '0 0 31 * 0'];
    const cases = [
      ...fixed.map(expr => denseCase(rng, () => ({ expr, schedule: scheduleOf(expr) }))),
      ...Array.from({ length: 8 }, () => denseCase(rng, () => { const g = bothDaysExpression(rng); return { expr: g.expr, schedule: g.truth }; })),
    ];
    await evidence.save('cases.txt', cases.map(caseLine).join('\n'));
    await freezeClock(page, cases[0].now);
    await open(page);
    for (const c of cases) {
      await expectCase(page, c, 'day of month and day of week are both restricted, so a day matching EITHER must be listed; '
        + 'a page that lists only days matching both hides most of the real executions');
    }
  });

  test('schedules that run a few times a year (yearly, quarterly, the 31st, leap day) still list the next ten runs', async ({ page, rng, evidence }) => {
    const expressions = ['0 0 1 1 *', '0 0 29 2 *', '0 0 1 */3 *', '0 0 31 * *', '30 6 1 1,7 *', '0 12 25 12 *', '15 3 29 2 *'];
    const cases = expressions.map(expr => denseCase(rng, () => ({ expr, schedule: scheduleOf(expr) }), () => randomInstant(rng), ZONE, Number.POSITIVE_INFINITY));
    await evidence.save('cases.txt', cases.map(caseLine).join('\n'));
    await freezeClock(page, cases[0].now);
    await open(page);
    for (const c of cases) {
      const last = c.runs[9];
      await expectCase(page, c, `the table is headed "Next 10 Executions" and the tenth run is on ${last.month}/${last.day}/${last.year}; `
        + 'a page that stops looking after one year shows fewer runs (or none) without saying so');
    }
  });

  test('the table heading never announces more executions than the table lists (31 February, weekday names)', async ({ page, rng }) => {
    await freezeClock(page, randomInstant(rng).instant);
    await open(page);
    const never = 'matches no calendar date, so it never runs; the page must say so instead of promising executions';
    // Weekday names are an extension: a tool either reads MON-FRI as Monday to Friday (ten runs)
    // or refuses it (Invalid). "Valid" above an empty list is wrong under both readings.
    const names = 'uses weekday names; the page must either list the Monday-to-Friday runs or report the expression invalid';
    const cases: [string, string][] = [
      ['0 0 31 2 *', never], ['0 0 30 2 *', never], ['0 0 31 4,6,9,11 *', never],
      ['0 9 * * MON-FRI', names], ['0 0 1 JAN-MAR *', names.replace(/weekday/, 'month').replace('Monday-to-Friday', 'January-to-March')],
    ];
    for (const [expr, why] of cases) {
      const verdict = judge(expr);
      if (verdict.kind === 'valid') expect(nextRuns(verdict.schedule, Date.UTC(2030, 0, 1)).runs.length, `oracle: "${expr}" matches no date at all`).toBe(0);
      await showAt(page, expr, randomInstant(rng).instant);
      const view = await readView(page);
      const announced = view.header === null ? null : Number((/Next (\d+) Executions/.exec(view.header) || [])[1]);
      expect.soft(announced === null || announced === view.rows.length,
        `"${expr}" ${why}. The page shows the heading ${JSON.stringify(view.header)} above ${view.rows.length} rows (${summarize(view)})`).toBe(true);
    }
  });
});

test.describe('Crontab Builder — clock changes', () => {
  test('spring forward: jobs with * in the hour field skip the missing hour and continue', async ({ page, rng, evidence }) => {
    const change = clockChange(rng, 'forward');
    test.skip(!change, `${ZONE} has no daylight saving time`);
    const before = change!.instant;
    const expressions = ['*/15 * * * *', '0 * * * *', '*/20 * * * *', '7,37 * * * *', '30 * * * *', `${rng.int(0, 59)},${rng.int(0, 59)} * * * *`];
    const cases: ScheduleCase[] = expressions.map(expr => {
      const now = before - rng.int(1, 150) * MINUTE - rng.int(0, 59_999);
      return { expr, schedule: scheduleOf(expr), now, nowLabel: `${Math.round((before - now) / MINUTE)} min before the clocks go forward, ${new Date(now).toISOString()}`, runs: nextRuns(scheduleOf(expr), now).runs };
    });
    const lastMinutes = before - rng.int(1, 8) * MINUTE - rng.int(0, 59_999);
    cases.push({ expr: '* * * * *', schedule: scheduleOf('* * * * *'), now: lastMinutes, nowLabel: `minutes before the clocks go forward, ${new Date(lastMinutes).toISOString()}`, runs: nextRuns(scheduleOf('* * * * *'), lastMinutes).runs });
    await evidence.save('cases.txt', cases.map(caseLine).join('\n'));
    await freezeClock(page, cases[0].now);
    await open(page);
    for (const c of cases) await expectCase(page, c, 'the hour that does not exist is skipped; real time between runs stays even');
  });

  test('fall back: jobs with * in the hour field also run during the repeated hour', async ({ page, rng, evidence }) => {
    const change = clockChange(rng, 'back');
    test.skip(!change, `${ZONE} has no daylight saving time`);
    // `change.instant` is the second time the clock shows the repeated hour. A job with `*` in the
    // hour field runs by real time, so it runs in the first and in the second pass of that hour
    // (cron, cronie, systemd timers and busybox all agree on this).
    const second = change!.instant;
    const repeated = Math.abs(change!.shift);
    const expressions = ['*/15 * * * *', '0 * * * *', '*/20 * * * *', '7,37 * * * *', '30 * * * *', `${rng.int(0, 59)} * * * *`];
    const cases: ScheduleCase[] = expressions.map(expr => {
      const now = second - rng.int(5, Math.round(repeated / MINUTE) - 5) * MINUTE - rng.int(0, 59_999);
      return { expr, schedule: scheduleOf(expr), now, nowLabel: `during the first pass of the repeated hour, ${new Date(now).toISOString()}`, runs: nextRuns(scheduleOf(expr), now).runs };
    });
    const justBefore = second - rng.int(1, 8) * MINUTE - rng.int(0, 59_999);
    cases.push({ expr: '* * * * *', schedule: scheduleOf('* * * * *'), now: justBefore, nowLabel: `minutes before the clocks go back, ${new Date(justBefore).toISOString()}`, runs: nextRuns(scheduleOf('* * * * *'), justBefore).runs });
    const evening = second - repeated - rng.int(10, 90) * MINUTE - rng.int(0, 59_999);
    cases.push({ expr: '*/15 * * * *', schedule: scheduleOf('*/15 * * * *'), now: evening, nowLabel: `before the repeated hour starts, ${new Date(evening).toISOString()}`, runs: nextRuns(scheduleOf('*/15 * * * *'), evening).runs });
    await evidence.save('cases.txt', cases.map(caseLine).join('\n'));
    await freezeClock(page, cases[0].now);
    await open(page);
    for (const c of cases) {
      await expectCase(page, c, 'the clock shows this hour twice and the job runs in both passes; '
        + 'a page that jumps from the first pass straight to the next hour leaves out an hour of real executions (the relative times show the gap)');
    }
  });

  test('jobs at a fixed time outside the changed hour keep their wall-clock time across a clock change, with the real time remaining', async ({ page, rng, evidence }) => {
    const year = rng.int(2025, 2034);
    const changes = clockChanges(year);
    test.skip(changes.length === 0, `${ZONE} has no daylight saving time`);
    const cases = Array.from({ length: 16 }, () => {
      const change = rng.pick(changes);
      return denseCase(rng, () => {
        const expr = `${rng.int(0, 59)} ${rng.int(0, 23)} * * ${rng.bool(0.6) ? '*' : rng.int(0, 6)}`;
        return { expr, schedule: scheduleOf(expr) };
      }, () => {
        const instant = change.instant - rng.int(2, 60) * HOUR - rng.int(0, 59_999);
        return { instant, label: `${Math.round((change.instant - instant) / HOUR)} h before the clock change of ${new Date(change.instant).toISOString()}` };
      });
    });
    await evidence.save('cases.txt', cases.map(caseLine).join('\n'));
    // Every case must really cross the change, otherwise the test proves nothing.
    for (const c of cases) expect(c.runs[9].instant - c.now, `case "${c.expr}" spans the clock change`).toBeGreaterThan(2 * DAY);
    await freezeClock(page, cases[0].now);
    await open(page);
    for (const c of cases) await expectCase(page, c, 'a day with a clock change has 23 or 25 hours; the relative time must count real hours');
  });
});

test.describe('Crontab Builder — description', () => {
  test('the sentence for common schedules says what the expression means', async ({ page, rng, evidence }) => {
    const fixed: [string, string][] = [
      ['* * * * *', 'Every minute'],
      ['*/5 * * * *', 'Every 5 minutes'],
      ['0 * * * *', 'At minute 0 of every hour'],
      ['30 * * * *', 'At minute 30 of every hour'],
      ['0 0 * * *', 'At 12:00 AM'],
      ['0 12 * * *', 'At 12:00 PM'],
      ['0 3 * * *', 'At 3:00 AM'],
      ['0 23 * * *', 'At 11:00 PM'],
      ['15 14 * * *', 'At minute 15 past 2:00 PM'],
      ['0 */2 * * *', 'At minute 0 every 2 hours'],
      ['0 9,17 * * *', 'At minute 0 at 9:00 AM and 5:00 PM'],
      ['0 0 1 * *', 'At 12:00 AM on day 1 of the month'],
      ['0 0 1 1 *', 'At 12:00 AM on day 1 of the month in Jan'],
      ['0 0 * * 0', 'At 12:00 AM on Sun'],
      ['0 0 * * 7', 'At 12:00 AM on Sun'],
      ['0 8 * * 1,3,5', 'At 8:00 AM on Mon, Wed, Fri'],
      ['0 6 * 6,12 *', 'At 6:00 AM in Jun, Dec'],
      ['0 0 * 2 6', 'At 12:00 AM in Feb on Sat'],
    ];
    const random = Array.from({ length: 80 }, () => commonFormExpression(rng));
    await evidence.save('expressions.json', random);
    await open(page);
    for (const [expr, sentence] of fixed) {
      expect(describeCommon(expr), `oracle self-check: hand-written sentence for "${expr}"`).toBe(sentence);
    }
    for (const expr of [...fixed.map(f => f[0]), ...random]) {
      const sentence = describeCommon(expr);
      expect(sentence, `oracle self-check: "${expr}" is a common form`).not.toBeNull();
      await showAt(page, expr, Date.UTC(2030, 5, 15, 12));
      const view = await readView(page);
      expect.soft(view.banner, `"${expr}" is valid`).toBe('Valid Expression');
      expect.soft(view.description, `description of "${expr}"`).toBe(sentence);
    }
  });

  test('the sentence for an hour range, a stepped hour range or an hour list with a range names real times, never "NaN"', async ({ page, rng, evidence }) => {
    const fixed = ['0 9-17 * * 1-5', '30 8-18 * * *', '0 9-11,17 * * *', '0 0-23/2 * * *', '*/10 6-22 * * *', '0 8-12,14-18 * * 1-5'];
    const random = Array.from({ length: 10 }, () => {
      const from = rng.int(0, 20), to = rng.int(from + 1, 23);
      const hour = rng.pick([`${from}-${to}`, `${from}-${to}/2`, `${from}-${to},${rng.int(0, 23)}`]);
      return `${rng.pick(['0', '*', '*/15', String(rng.int(1, 59))])} ${hour} * * *`;
    });
    await evidence.save('expressions.json', [...fixed, ...random]);
    await open(page);
    for (const expr of [...fixed, ...random]) {
      expect(judge(expr).kind, `oracle self-check: "${expr}" is valid`).toBe('valid');
      await showAt(page, expr, Date.UTC(2030, 5, 15, 12));
      const view = await readView(page);
      expect.soft(view.banner, `"${expr}" is valid`).toBe('Valid Expression');
      expect.soft(view.description ?? '', `description of the valid expression "${expr}": the hour part "${expr.split(' ')[1]}" must be put into words (or echoed), not shown as a broken number`)
        .not.toMatch(/NaN|undefined|null|\[object/);
    }
  });

  test('the sentence of any valid expression is never empty and carries no broken value (hour ranges are covered separately)', async ({ page, rng, evidence }) => {
    // Random expressions in every notation; hour fields holding a range are left to the test above.
    const cases: ScheduleCase[] = [];
    while (cases.length < 60) {
      const c = generalCase(rng);
      if (!c.expr.split(' ')[1].includes('-')) cases.push(c);
    }
    await evidence.save('cases.txt', cases.map(caseLine).join('\n'));
    await open(page);
    for (const c of cases) {
      await showAt(page, c.expr, c.now);
      const view = await readView(page);
      expect.soft((view.description ?? '').length, `description of "${c.expr}" must not be empty`).toBeGreaterThan(0);
      expect.soft(view.description ?? '', `description of "${c.expr}"`).not.toMatch(/NaN|undefined|null|\[object/);
    }
  });
});
