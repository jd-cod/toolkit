import { test, expect, type Page } from '../_support/fixtures';
import { openTool, expectToolLinkedFromHome, waitForHydration } from '../_support/navigation';
import { expectNoUiGlitches, expectControlsUsable, VIEWPORTS } from '../_support/ui-audit';
import { readClipboard, clearClipboard } from '../_support/io';
import {
  DAY, DEFAULT_EXPRESSION, PRESETS, describeCommon, emptyView, expectedRows, invalidView, judge, nextRuns, scheduleOf, validView,
} from './oracle';
import { DENSE_WITHIN_DAYS, caseLine, commonFormExpression, denseCase, invalidExpressions, validExpression, type ScheduleCase } from './generator';
import {
  HEADING, ROUTE, banner, copyButtons, enterExpression, expectView, expressionInput, fieldCards, freezeClock, guide,
  presetSelect, readView, runRows, showAt,
} from './page';

/**
 * Crontab Builder (/cron) — runs entirely in the browser, no server call.
 *
 * Oracle: ./oracle.ts is an independent cron evaluator (POSIX / Vixie rules)
 * that works in the browser's time zone through Intl; the browser clock is
 * frozen with Playwright's clock API so every "next execution" and every
 * relative time is predictable.
 *
 * INVENTORY (each entry is covered by a test in one of the three spec files)
 *  Inputs
 *    - expression text field (default `*\/15 * * * *`)
 *    - preset dropdown: 10 presets
 *  Displayed values
 *    - validity banner: icon + "Valid Expression" / "Invalid Expression"
 *    - human description under the banner (also shown for invalid input)
 *    - five field cards: Minute, Hour, Day(M), Month, Day(W)
 *    - "Next N Executions" heading and table: #, date, time, weekday, relative time (10 rows)
 *    - guide panel "Schedule reference" (three entries)
 *  Outputs
 *    - Copy Expression, Copy Description: clipboard text and confirmation label
 *  States
 *    - empty field (nothing below the input), valid, invalid, copied
 *
 * FILES
 *  cron.spec.ts ........... layers 1, 2, 3, 5 (presets), 6, 8 and time zones
 *  cron-schedule.spec.ts .. layer 4: runs, relative times, calendar edges, clock changes, day rule, descriptions
 *  cron-invalid.spec.ts ... layer 7: every class of invalid expression, markup, oversized input
 *  Server failures, exports and share links do not apply: the tool has no server call, file or link.
 */

const open = (page: Page) => openTool(page, ROUTE, HEADING);

const randomCase = (rng: Parameters<typeof validExpression>[0]) =>
  denseCase(rng, () => { const g = validExpression(rng); return { expr: g.expr, schedule: g.truth }; });

/** A moment at which the default expression (and any given ones) can be predicted without a clock-change caveat. */
const caseFor = (rng: Parameters<typeof validExpression>[0], expr: string): ScheduleCase =>
  denseCase(rng, () => ({ expr, schedule: scheduleOf(expr) }));

const LONG_EXPRESSION = '0,5,10,15,20,25,30,35,40,45,50,55 8,9,10,11,12,13,14,15,16,17,18 1-7,15-21 1,2,3,4,5,6,7,8,9,10,11,12 *';

test.describe('Crontab Builder — access and layout', () => {
  test('is linked from the home page and the sidebar', async ({ page }) => {
    await expectToolLinkedFromHome(page, ROUTE);
    await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
  });

  test('opens on the default expression with its schedule, controls and guide panel', async ({ page, rng }) => {
    const start = caseFor(rng, DEFAULT_EXPRESSION);
    await freezeClock(page, start.now);
    await open(page);
    await expect(page).toHaveTitle(/cron/i);
    await expectControlsUsable(page, {
      'expression field': '.signal-tool-primary input[type="text"]',
      'preset list': '.signal-tool-primary select',
      'Copy Expression button': '.signal-tool-primary button.btn-secondary >> nth=0',
      'Copy Description button': '.signal-tool-primary button.btn-secondary >> nth=1',
    });
    await expect(runRows(page), 'the run table fills in once the page is interactive').toHaveCount(10);
    await expectView(page, validView(DEFAULT_EXPRESSION, start.runs, start.now, 'Every 15 minutes'), `first visit at ${start.nowLabel}`);
    await expect.soft(presetSelect(page), 'the preset list starts on its placeholder').toHaveValue('');
    await expect.soft(banner(page), 'validity banner').toBeVisible();
    await expect.soft(fieldCards(page), 'five field cards').toHaveCount(5);

    const panel = guide(page);
    await expect(panel, 'guide panel "Schedule reference"').toBeVisible();
    await expect.soft(panel.getByRole('heading', { name: 'Schedule reference' })).toBeVisible();
    await expect.soft(panel.locator('dt'), 'guide entries').toHaveText(['Five fields', 'Common operators', 'Execution preview']);
    await expect.soft(panel.locator('dd').nth(0), 'guide names the field order the cards use').toHaveText('Minute · hour · day of month · month · day of week.');
    await expect.soft(panel.locator('dd').nth(1), 'guide names the operators').toContainText('* matches every value, / adds a step, - defines a range, and commas join values.');
    await expect.soft(panel.locator('dd').nth(2), 'guide promises local time').toContainText(/Upcoming runs use your browser.s local time/);
  });

  test('with the real clock, the table lists the ten runs after the present moment', async ({ page, rng }) => {
    // No frozen clock here: guards against a suite that only ever sees a fake time.
    await open(page);
    const expr = `${rng.int(0, 59)} ${rng.int(0, 23)} * * *`;
    const before = await page.evaluate(() => Date.now());
    await enterExpression(page, expr);
    await expect(runRows(page)).toHaveCount(10);
    const view = await readView(page);
    const after = await page.evaluate(() => Date.now());
    const candidates = [before, after].map(now => expectedRows(nextRuns(scheduleOf(expr), now).runs, now));
    const shown = JSON.stringify(view.rows);
    expect.soft(candidates.map(rows => JSON.stringify(rows)).includes(shown),
      `"${expr}" at the real time ${new Date(before).toISOString()}: page rows ${shown} must equal the runs after that moment ${JSON.stringify(candidates[0])}`).toBe(true);
  });

  for (const [name, viewport] of Object.entries(VIEWPORTS)) {
    test(`has no layout problems at ${name} size (${viewport.width}px) in every state`, async ({ page, rng }) => {
      await page.setViewportSize(viewport);
      await freezeClock(page, caseFor(rng, DEFAULT_EXPRESSION).now);
      await open(page);
      await expect(runRows(page)).toHaveCount(10);
      await expectNoUiGlitches(page, `${ROUTE} default expression @${name}`);

      await enterExpression(page, LONG_EXPRESSION);
      await expect(banner(page)).toHaveText('Valid Expression');
      await expectNoUiGlitches(page, `${ROUTE} long valid expression "${LONG_EXPRESSION}" @${name}`);

      await enterExpression(page, '61 25 * * * and some more text that is not cron');
      await expect(banner(page)).toHaveText('Invalid Expression');
      await expectNoUiGlitches(page, `${ROUTE} invalid expression @${name}`);

      await enterExpression(page, '');
      await expect(banner(page)).toHaveCount(0);
      await expectNoUiGlitches(page, `${ROUTE} empty field @${name}`);

      await presetSelect(page).selectOption('0 9 * * 1-5');
      await expect(runRows(page)).toHaveCount(10);
      await expectNoUiGlitches(page, `${ROUTE} preset "Weekdays at 9 AM" @${name}`);

      await copyButtons(page).nth(1).click();
      await expect(copyButtons(page).nth(1)).toHaveText('Copied Description!');
      await expectNoUiGlitches(page, `${ROUTE} right after copying @${name}`);
    });
  }
});

test.describe('Crontab Builder — presets', () => {
  test('the dropdown offers the ten presets, and each label matches what its expression does', async ({ page, rng }) => {
    await open(page);
    const options = await presetSelect(page).locator('option').evaluateAll(list =>
      list.map(o => ({ value: (o as HTMLOptionElement).value, text: (o.textContent || '').replace(/\s+/g, ' ').trim() })));
    expect(options[0], 'first entry is the placeholder').toEqual({ value: '', text: 'Load a preset...' });
    expect.soft(options.slice(1).map(o => o.text), 'preset labels in order').toEqual(PRESETS.map(p => `${p.label} — ${p.expr}`));
    expect.soft(options.slice(1).map(o => o.value), 'preset values in order').toEqual(PRESETS.map(p => p.expr));
    for (const preset of PRESETS) {
      const verdict = judge(preset.expr);
      expect.soft(verdict.kind, `preset "${preset.label}" (${preset.expr}) must be a valid expression`).toBe('valid');
      // The label's promise, checked on the oracle's runs at a moment without a clock change.
      const sample = denseCase(rng, () => ({ expr: preset.expr, schedule: scheduleOf(preset.expr) }), undefined, undefined, Number.POSITIVE_INFINITY);
      expect.soft(preset.holds(sample.runs), `preset "${preset.label}": the expression ${preset.expr} must do what the label says (checked at ${sample.nowLabel})`).toBe(true);
    }
  });

  test('choosing a preset loads its expression with the right validity, description, field cards and runs', async ({ page, rng, evidence }) => {
    // One moment for all presets, without a clock change inside any of their run lists.
    let now = 0;
    for (let attempt = 0; attempt < 200; attempt++) {
      now = caseFor(rng, DEFAULT_EXPRESSION).now;
      if (PRESETS.every(p => !nextRuns(scheduleOf(p.expr), now).dstAmbiguous)) break;
    }
    await evidence.save('moment.txt', new Date(now).toISOString());
    await freezeClock(page, now);
    await open(page);
    for (const preset of rng.shuffle(PRESETS)) {
      await presetSelect(page).selectOption(preset.expr);
      const { runs } = nextRuns(scheduleOf(preset.expr), now);
      const want = validView(preset.expr, runs, now, describeCommon(preset.expr));
      // Presets that run a few times a year are compared in "sparse schedules" (cron-schedule.spec.ts).
      if (runs[9].instant - now > DENSE_WITHIN_DAYS * DAY) want.header = undefined;
      await expectView(page, want, `preset "${preset.label}" at ${new Date(now).toISOString()}`);
      await expect.soft(presetSelect(page), `the list shows the chosen preset "${preset.label}"`).toHaveValue(preset.expr);
    }
  });

  test('after the expression is edited by hand, the preset list no longer shows the old preset', async ({ page, rng }) => {
    await open(page);
    const preset = rng.pick(PRESETS);
    await presetSelect(page).selectOption(preset.expr);
    await expect(expressionInput(page)).toHaveValue(preset.expr);
    const typed = caseFor(rng, `${rng.int(1, 59)} ${rng.int(1, 23)} * * *`).expr;
    await enterExpression(page, typed);
    await expect(expressionInput(page)).toHaveValue(typed);
    const view = await readView(page);
    // A list that still shows the preset states something untrue about the field, and the
    // preset cannot be picked again: choosing the entry that is already selected changes nothing.
    expect.soft(view.presetValue === '' || view.presetValue === view.input.trim(),
      `preset "${preset.label}" was chosen, then "${typed}" was typed: the preset list still shows "${view.presetValue}" while the expression is "${view.input}". `
      + 'It must return to "Load a preset..." (or follow the field), otherwise the same preset cannot be chosen again').toBe(true);
  });
});

test.describe('Crontab Builder — input paths', () => {
  test('typing key by key ends in the same result as pasting, and reports "need 5 fields" on the way', async ({ page, rng, evidence }) => {
    // A common-form expression (so the sentence is known) with both day fields open,
    // so the day rule (tested elsewhere) plays no role.
    const c = denseCase(rng, () => {
      const [minute, hour, , month] = commonFormExpression(rng).split(' ');
      const text = [minute, hour, '*', month, '*'].join(' ');
      return { expr: text, schedule: scheduleOf(text) };
    });
    const expr = c.expr;
    await evidence.save('case.txt', caseLine(c));
    await freezeClock(page, c.now);
    await open(page);
    await expressionInput(page).fill('');
    let typed = '';
    for (const key of expr) {
      await expressionInput(page).press(key === ' ' ? 'Space' : key);
      typed += key;
      if (typed.trim().split(/ +/).length < 5) {
        const view = await readView(page);
        expect.soft(view.banner, `after typing "${typed}" (fewer than five fields)`).toBe('Invalid Expression');
        expect.soft(view.description, `message after typing "${typed}"`).toBe('❌ Invalid: need 5 fields');
        expect.soft(view.rows.length + view.fields.length + view.buttons.length, `no result parts after typing "${typed}"`).toBe(0);
      }
    }
    const want = validView(expr, c.runs, c.now, describeCommon(expr));
    await expectView(page, want, `"${expr}" typed key by key at ${c.nowLabel}`);

    await enterExpression(page, '');
    await expectView(page, emptyView(''), 'field emptied');
    await page.evaluate(text => navigator.clipboard.writeText(text), expr);
    await expressionInput(page).focus();
    await page.keyboard.press('ControlOrMeta+V');
    await expectView(page, want, `"${expr}" pasted from the clipboard at ${c.nowLabel}`);
  });

  test('blanks around and between the fields (spaces or tabs) do not change the schedule', async ({ page, rng, evidence }) => {
    const c = randomCase(rng);
    const blank = () => rng.pick([' ', '  ', '\t', ' \t ', '   ']);
    const fields = c.expr.split(' ');
    const variants = [
      `  ${c.expr}`, `${c.expr}   `, `\t${c.expr}\t`,
      fields.join('  '), fields.join('\t'),
      rng.pick(['', ' ', '\t']) + fields.map((f, i) => (i ? blank() : '') + f).join('') + rng.pick(['', ' ', '\t']),
    ];
    await evidence.save('variants.json', { expression: c.expr, moment: new Date(c.now).toISOString(), variants });
    await freezeClock(page, c.now);
    await open(page);
    for (const variant of variants) {
      expect(judge(variant).kind, `oracle self-check: ${JSON.stringify(variant)} is valid`).toBe('valid');
      await showAt(page, variant, c.now);
      await expectView(page, validView(variant, c.runs, c.now, describeCommon(variant)), `${JSON.stringify(variant)} (same as "${c.expr}") at ${c.nowLabel}`);
    }
  });
});

test.describe('Crontab Builder — copy', () => {
  test('Copy Expression and Copy Description put exactly the shown texts on the clipboard and confirm', async ({ page, rng, evidence }) => {
    await open(page);
    const expressions = [DEFAULT_EXPRESSION, ...Array.from({ length: 4 }, () => commonFormExpression(rng))];
    await evidence.save('expressions.json', expressions);
    for (const expr of expressions) {
      await enterExpression(page, expr);
      await expect(banner(page), `"${expr}" is valid`).toHaveText('Valid Expression');
      const description = describeCommon(expr) as string;

      await clearClipboard(page);
      await copyButtons(page).nth(0).click();
      await expect(copyButtons(page).nth(0), `Copy Expression confirms for "${expr}"`).toHaveText('Copied Expression!');
      expect.soft(await readClipboard(page), `clipboard after Copy Expression for "${expr}"`).toBe(expr);

      await clearClipboard(page);
      await copyButtons(page).nth(1).click();
      await expect(copyButtons(page).nth(1), `Copy Description confirms for "${expr}"`).toHaveText('Copied Description!');
      const copied = await readClipboard(page);
      expect.soft(copied, `clipboard after Copy Description for "${expr}"`).toBe(description);
      expect.soft(copied, `clipboard equals the description on screen for "${expr}"`).toBe((await readView(page)).description);
    }
    await expect(copyButtons(page).nth(1), 'the label returns after two seconds').toHaveText('Copy Description', { timeout: 6_000 });
    await expect(copyButtons(page).nth(0), 'the label returns after two seconds').toHaveText('Copy Expression', { timeout: 6_000 });
  });

  test('Copy Expression copies a random list, range and step expression character for character', async ({ page, rng, evidence }) => {
    await open(page);
    const cases = Array.from({ length: 6 }, () => validExpression(rng).expr);
    await evidence.save('expressions.json', cases);
    for (const expr of cases) {
      await enterExpression(page, expr);
      await expect(banner(page), `"${expr}" is valid`).toHaveText('Valid Expression');
      await clearClipboard(page);
      await copyButtons(page).nth(0).click();
      await expect(copyButtons(page).nth(0)).toHaveText('Copied Expression!');
      expect.soft(await readClipboard(page), `clipboard after Copy Expression for "${expr}"`).toBe(expr);
    }
    // Typed with blanks around it: the copied text must still be the same expression.
    const padded = `  ${cases[0]}  `;
    await enterExpression(page, padded);
    await clearClipboard(page);
    await copyButtons(page).nth(0).click();
    await expect(copyButtons(page).nth(0)).toHaveText('Copied Expression!');
    expect.soft((await readClipboard(page)).trim(), `clipboard after Copy Expression for ${JSON.stringify(padded)}`).toBe(cases[0]);
  });

  test('there is nothing to copy while the field is empty or invalid', async ({ page }) => {
    await open(page);
    for (const text of ['', '   ', '* * * *', '60 * * * *']) {
      await enterExpression(page, text);
      await expect.soft(copyButtons(page), `copy buttons for ${JSON.stringify(text)}`).toHaveCount(0);
    }
    await enterExpression(page, '0 0 * * *');
    await expect.soft(copyButtons(page), 'copy buttons return with a valid expression').toHaveText(['Copy Expression', 'Copy Description']);
  });
});

test.describe('Crontab Builder — state', () => {
  test('each entry replaces the previous result completely: valid, invalid and empty in random order', async ({ page, rng, evidence }) => {
    const first = randomCase(rng);
    await freezeClock(page, first.now);
    await open(page);
    // Invalid input comes only from the classes the page already rejects, so this test is about state, not validation.
    const invalid = (['field-count', 'out-of-range', 'zero-step', 'empty-item', 'not-a-number'] as const)
      .flatMap(kind => invalidExpressions(rng, kind, 3));
    const log: string[] = [];
    let wrong = 0;
    for (let step = 1; step <= 40 && wrong < 5; step++) {
      const kind = rng.weighted(['valid', 'invalid', 'empty'] as const, [5, 3, 2]);
      let ok: boolean;
      if (kind === 'valid') {
        const c = randomCase(rng);
        log.push(`${step}. valid ${caseLine(c)}`);
        await showAt(page, c.expr, c.now);
        ok = await expectView(page, validView(c.expr, c.runs, c.now, describeCommon(c.expr)), `step ${step}: "${c.expr}" at ${c.nowLabel} (previous: ${log[log.length - 2] ?? 'default'})`);
      } else if (kind === 'invalid') {
        const bad = rng.pick(invalid);
        log.push(`${step}. invalid ${bad.expr} (${bad.why})`);
        await enterExpression(page, bad.expr);
        ok = await expectView(page, invalidView(bad.expr), `step ${step}: invalid "${bad.expr}" (${bad.why}) must leave no schedule (previous: ${log[log.length - 2] ?? 'default'})`);
      } else {
        const blank = rng.pick(['', ' ', '    ', '\t']);
        log.push(`${step}. empty ${JSON.stringify(blank)}`);
        await enterExpression(page, blank);
        ok = await expectView(page, emptyView(blank), `step ${step}: empty field ${JSON.stringify(blank)} must show nothing below the input (previous: ${log[log.length - 2] ?? 'default'})`);
      }
      if (!ok) wrong++;
    }
    await evidence.save('steps.txt', log.join('\n'));
  });

  test('a reload returns to the default expression and an untouched preset list', async ({ page, rng }) => {
    const c = randomCase(rng);
    const start = caseFor(rng, DEFAULT_EXPRESSION);
    await freezeClock(page, c.now);
    await open(page);
    await presetSelect(page).selectOption(rng.pick(PRESETS).expr);
    await enterExpression(page, c.expr);
    await expectView(page, validView(c.expr, c.runs, c.now, describeCommon(c.expr)), `"${c.expr}" before the reload`);
    expect.soft(new URL(page.url()).pathname + new URL(page.url()).search, 'the expression is not kept in the address').toBe(ROUTE);

    await freezeClock(page, start.now);
    await page.reload();
    await waitForHydration(page);
    await expect(runRows(page)).toHaveCount(10);
    await expectView(page, validView(DEFAULT_EXPRESSION, start.runs, start.now, 'Every 15 minutes'), `reload after "${c.expr}"`);
    await expect.soft(presetSelect(page), 'preset list after a reload').toHaveValue('');
  });

  test('leaving the tool and coming back with the browser Back button starts from the default again', async ({ page, rng }) => {
    const start = caseFor(rng, DEFAULT_EXPRESSION);
    await freezeClock(page, start.now);
    await open(page);
    await enterExpression(page, '5 4 * * *');
    await page.locator('aside.signal-sidebar a[href="/chmod"]').first().click();
    await expect(page.getByRole('heading', { level: 1, name: 'chmod Calculator' })).toBeVisible();
    await page.goBack();
    await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
    await expect(runRows(page)).toHaveCount(10);
    await expectView(page, validView(DEFAULT_EXPRESSION, start.runs, start.now, 'Every 15 minutes'), 'after Back from another tool');
    await page.goForward();
    await expect(page.getByRole('heading', { level: 1, name: 'chmod Calculator' })).toBeVisible();
  });
});

// The guide promises "Upcoming runs use your browser's local time". The other tests run in
// E2E_TIMEZONE; these repeat the comparison for visitors elsewhere, including a zone that is
// not a whole number of hours from UTC.
for (const zone of ['Asia/Kolkata', 'Europe/London', 'Pacific/Auckland']) {
  test.describe(`Crontab Builder — visitor in ${zone}`, () => {
    test.use({ timezoneId: zone });

    test(`runs are listed in ${zone} local time`, async ({ page, rng, evidence }) => {
      const cases = Array.from({ length: 12 }, () =>
        denseCase(rng, () => { const g = validExpression(rng); return { expr: g.expr, schedule: g.truth }; }, undefined, zone));
      await evidence.save('cases.txt', cases.map(caseLine).join('\n'));
      await freezeClock(page, cases[0].now);
      await open(page);
      for (const c of cases) {
        await showAt(page, c.expr, c.now);
        await expectView(page, validView(c.expr, c.runs, c.now), `"${c.expr}" at ${c.nowLabel} for a visitor in ${zone}`);
      }
    });
  });
}
