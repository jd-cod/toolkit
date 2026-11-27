import { test, expect } from '../_support/fixtures';
import { openTool } from '../_support/navigation';
import { allFourDigitOctals, expectedView, modeOf, octalOf, type Mode } from './oracle';
import { HEADING, ROUTE, enterOctal, settleView } from './page';

/**
 * chmod Calculator — layer 4 for the whole input space: all 4096 modes.
 * See chmod.spec.ts for the inventory.
 *
 * Each mode is typed into the octal field and every value on the page is
 * compared with ./oracle.ts: the field itself, the three cards, the command
 * line, the three explanation sentences, the warning lines, the nine grid
 * buttons (pressed state and check mark) and the three checkboxes.
 */

// 4096 fills in a row: recording a trace snapshot for each one triples the run time and adds
// nothing, because every mismatch is reported in full by the comparison itself.
test.use({ trace: 'off' });

const open = (page: Parameters<typeof openTool>[0]) => openTool(page, ROUTE, HEADING);

/** The spellings of a mode that the octal field may show after the mode was entered as `typed`. */
const spellings = (typed: string, mode: Mode) => [typed, octalOf(mode)];

test.describe('chmod Calculator — all 4096 modes', () => {
  // Four slices, so both workers share the work and no slice comes near the test timeout.
  for (const leads of ['01', '23', '45', '67']) {
    test(`typing each mode shows the right octal, symbolic, ls, sentences, warnings, grid and checkboxes — special digit ${leads[0]} and ${leads[1]} (1024 modes)`, async ({ page, rng, evidence }) => {
      test.setTimeout(240_000);
      await open(page);
      // Random order, so each mode is also reached from an unrelated previous one.
      const modes = rng.shuffle(allFourDigitOctals().filter(text => leads.includes(text[0])));
      // Without special bits both spellings are legal input: `755` and `0755`.
      const typedList = modes.map(four => (four[0] === '0' && rng.bool(0.5) ? four.slice(1) : four));
      await evidence.save('typed-modes.txt', typedList.join('\n'));

      let wrong = 0;
      for (const typed of typedList) {
        const mode = modeOf(typed);
        await enterOctal(page, typed);
        const diffs = await settleView(page, expectedView(mode), spellings(typed, mode));
        if (diffs.length === 0) continue;
        expect.soft(diffs, `typed "${typed}": every value on the page must follow from the mode\n  ${diffs.join('\n  ')}\n`).toEqual([]);
        if (++wrong >= 12) break;
      }
      expect(wrong, `modes (of ${typedList.length}) for which the page showed a wrong value; the sweep stops at 12`).toBe(0);
    });
  }
});

