import { test, expect, type Page } from '../_support/fixtures';
import { openTool } from '../_support/navigation';
import { emptyView, invalidView, judge, scheduleOf, validView } from './oracle';
import { denseCase, invalidExpressions, randomInstant, type InvalidKind } from './generator';
import { HEADING, ROUTE, enterExpression, expectView, freezeClock, readView, settleView, showAt, summarize } from './page';

/**
 * Crontab Builder — layer 7: input that is not a cron expression.
 * See cron.spec.ts for the inventory.
 *
 * An operator pastes the expression into a crontab. If the tool says "Valid"
 * for something cron refuses, or lists runs for something that means nothing,
 * the mistake is found in production. So for every invalid expression the page
 * must show "Invalid Expression" and no field cards, run table or copy button.
 *
 * Each test covers one rule: the fixed cases first, then random ones in a
 * random field. The oracle confirms for every case that it is invalid under
 * the definition in ./oracle.ts before the page is asked.
 */

const open = (page: Page) => openTool(page, ROUTE, HEADING);

const RULES: { kind: InvalidKind; title: string }[] = [
  { kind: 'field-count', title: 'an expression with fewer or more than five fields is invalid' },
  { kind: 'out-of-range', title: 'a value outside its field (minute 60, hour 24, day 0 or 32, month 0 or 13, weekday 8) is invalid' },
  { kind: 'zero-step', title: 'a step of zero or a missing step is invalid' },
  { kind: 'empty-item', title: 'an empty list item ("1,,2", ",1", "1,") is invalid' },
  { kind: 'not-a-number', title: 'words and symbols in place of a number are invalid' },
  { kind: 'reversed-range', title: 'a range that runs backwards ("5-1") is invalid' },
  { kind: 'trailing-characters', title: 'a number followed by other characters ("5x", "1.5", "0x10", "*/5x") is invalid' },
  { kind: 'negative', title: 'negative and signed numbers ("-5", "+5") are invalid' },
  { kind: 'broken-range', title: 'a malformed range ("5-", "1--5", "a-b", "*-5", "1-2-3") is invalid' },
  { kind: 'broken-step', title: 'a malformed step ("/5", "*/5/2", "70/5") is invalid' },
];

test.describe('Crontab Builder — invalid expressions', () => {
  for (const { kind, title } of RULES) {
    test(title, async ({ page, rng, evidence }) => {
      const cases = invalidExpressions(rng, kind, 12);
      await evidence.save(`invalid-${kind}.json`, cases);
      await freezeClock(page, randomInstant(rng).instant);
      await open(page);
      for (const { expr, why } of cases) {
        const verdict = judge(expr);
        expect(verdict.kind, `oracle self-check: "${expr}" (${why}) is invalid by definition`).toBe('invalid');
        await enterExpression(page, expr);
        // The page renders within the input event; a short wait is enough to tell "wrong" from "late".
        const diffs = await settleView(page, invalidView(expr), 300);
        const view = await readView(page);
        expect.soft(diffs, `"${expr}" is not a cron expression (${why}; ${verdict.kind === 'invalid' ? verdict.reason : ''}). `
          + `The page must show "Invalid Expression" with no field cards, run table or copy buttons, but shows: ${summarize(view)}\n  ${diffs.join('\n  ')}\n`).toEqual([]);
      }
    });
  }

  test('an invalid expression is not described as if it were a schedule', async ({ page }) => {
    await open(page);
    // The banner says "Invalid Expression"; the line under it must not then state a schedule
    // ("At 12:00 PM" for hour 24). For a wrong field count the page already says "Invalid: need 5 fields".
    const cases = ['0 24 * * *', '61 * * * *', '0 0 32 * *', '0 0 * 13 *', '*/0 * * * *', '0 0 * * 8', 'abc * * * *'];
    for (const expr of cases) {
      expect(judge(expr).kind, `oracle self-check: "${expr}" is invalid`).toBe('invalid');
      await enterExpression(page, expr);
      const view = await readView(page);
      expect(view.banner, `"${expr}" must be reported invalid`).toBe('Invalid Expression');
      expect.soft(view.description ?? '', `"${expr}" is invalid, yet the line under "Invalid Expression" reads ${JSON.stringify(view.description)}, a schedule that does not exist. `
        + 'It must say what is wrong (or stay empty), not start like a schedule').not.toMatch(/^(At|Every)\b/);
    }
  });

  test('a very large range is rejected without taking the page down', async ({ page, guard }) => {
    await open(page);
    // 20 million is beyond what the page can hold in a set of values; a typo with a few
    // extra digits must end in "Invalid Expression", not in a dead page.
    const expr = '0-20000000 * * * *';
    await enterExpression(page, expr).catch(() => { /* the page may already be gone; reported below */ });
    const alive = await page.getByRole('heading', { level: 1, name: HEADING }).isVisible();
    const body = alive ? '' : ((await page.locator('body').innerText().catch(() => '')) || '').replace(/\s+/g, ' ').slice(0, 160);
    expect.soft(alive, `after entering "${expr}" the tool is gone; the browser shows: "${body}" (${guard.problems().join('; ') || 'no browser error recorded'}). `
      + 'The range must be refused by comparing its end with the field limit (59), not by building every value').toBe(true);
    await expectView(page, invalidView(expr), `"${expr}" (minute range far outside 0–59)`, 300);
  });

  test('markup in the expression is shown as text and never runs', async ({ page }) => {
    await open(page);
    const payload = '<img/src=x/onerror=window.__cronXss=1> <script>window.__cronXss=2</script> <b>*</b> * *';
    await enterExpression(page, payload);
    await expectView(page, invalidView(payload), 'markup as an expression');
    expect(await page.evaluate(() => (window as unknown as { __cronXss?: number }).__cronXss), 'the markup must not run').toBeUndefined();
    await expect(page.locator('main img, main script, .signal-tool-primary b'), 'no element may be created from the typed text').toHaveCount(0);
    const view = await readView(page);
    expect.soft(view.description ?? '', 'the typed markup appears as plain text, if at all').not.toMatch(/\[object|undefined/);
  });

  test('an empty field or blanks only show neither a verdict nor a result', async ({ page, rng }) => {
    const expr = '*/5 * * * *';
    const c = denseCase(rng, () => ({ expr, schedule: scheduleOf(expr) }));
    await freezeClock(page, c.now);
    await open(page);
    for (const blank of ['', ' ', '     ', '\t', ' \t ']) {
      await enterExpression(page, blank);
      await expectView(page, emptyView(blank), `field holding ${JSON.stringify(blank)}`);
    }
    // And the tool recovers: the next valid expression is evaluated normally.
    await showAt(page, expr, c.now);
    await expectView(page, validView(expr, c.runs, c.now, 'Every 5 minutes'), `"${expr}" after an empty field, at ${c.nowLabel}`);
  });

  test('a very long expression is handled: 5,000 list items are valid, 5,000 fields are not', async ({ page, rng }) => {
    await open(page);
    const minutes = Array.from({ length: 5000 }, () => rng.int(0, 59)).join(',');
    const long = `${minutes} * * * *`;
    await enterExpression(page, long);
    const view = await readView(page);
    expect.soft(view.banner, 'a list of 5,000 minutes (all 0–59) is a valid field').toBe('Valid Expression');
    expect.soft(view.rows.length, 'ten runs for the long list').toBe(10);
    const many = Array.from({ length: 5000 }, () => '*').join(' ');
    await enterExpression(page, many);
    await expectView(page, invalidView(many), '5,000 fields');
  });
});
