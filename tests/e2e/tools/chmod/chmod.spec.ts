import { test, expect } from '../_support/fixtures';
import { openTool, expectToolLinkedFromHome, waitForHydration } from '../_support/navigation';
import { expectNoUiGlitches, expectControlsUsable, VIEWPORTS } from '../_support/ui-audit';
import { readClipboard, clearClipboard } from '../_support/io';
import {
  DEFAULT_MODE, INVALID_DRAFTS, PERMS, PRESETS, ROLES, SPECIALS, SPECIAL_LABELS,
  WARNING_777, WARNING_SETGID, WARNING_SETUID, WARNING_WORLD_WRITABLE,
  expectedView, fourDigitOctalOf, modeOf, octalOf, parseOctal, randomMode,
  toggleCell, toggleSpecial, type Mode,
} from './oracle';
import {
  HEADING, ROUTE, card, cell, choosePreset, commandLine, copyButton, enterOctal, expectView, guide,
  invalidFieldIsFlagged, octalInput, presetSelect, readView, specialBox, typeOctal,
} from './page';

/**
 * chmod Calculator (/chmod) — runs entirely in the browser, no server call.
 *
 * Oracle: ./oracle.ts converts between octal, symbolic and words with lookup
 * tables written from the POSIX definition of a file mode.
 *
 * INVENTORY (each entry is covered by a test below)
 *  Inputs
 *    - octal text field (3 or 4 octal digits; anything else is a draft)
 *    - preset dropdown: 8 presets, returns to "Load a preset..." after use
 *    - permission grid: 9 toggle buttons "Owner|Group|Others Read|Write|Execute" (aria-pressed + check mark)
 *    - special bits: 3 checkboxes Setuid (4xxx), Setgid (2xxx), Sticky (1xxx)
 *  Displayed values
 *    - octal field content (follows grid, checkboxes and presets)
 *    - Octal card, Symbolic card, "ls -la Output" card
 *    - warnings box: 777, world-writable, setuid, setgid lines; absent when none applies
 *    - Explanation: one sentence each for Owner, Group, Others
 *    - Command line `chmod <octal> filename`
 *    - guide panel "Permission reference" (three entries)
 *  Outputs
 *    - Copy button: clipboard text and "Copied!" confirmation
 *  States
 *    - default (755), any of 4096 modes, with and without warnings, draft in the field, copied
 *
 * LAYERS
 *  1 reachable .......... "access and layout"
 *  2 layout ............. "access and layout" (desktop, laptop, mobile; five states each)
 *  3 input paths ........ fill, key-by-key typing, presets, grid clicks, checkbox and label clicks, keyboard
 *  4 displayed values ... chmod-all-modes.spec.ts (every value for each of the 4096 modes), "notation and warnings"
 *  5 controls ........... "grid and special bits", "presets"
 *  6 outputs ............ "command and copy"
 *  7 bad input .......... "drafts and invalid input"
 *  8 state .............. "state"
 *  Server failures, exports and share links do not apply: the tool has no server call, file or link.
 */

const open = (page: Parameters<typeof openTool>[0]) => openTool(page, ROUTE, HEADING);

test.describe('chmod Calculator — access and layout', () => {
  test('is linked from the home page and the sidebar', async ({ page }) => {
    await expectToolLinkedFromHome(page, ROUTE);
    await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
  });

  test('opens on mode 755 with every control ready and the guide panel shown', async ({ page }) => {
    await open(page);
    await expect(page).toHaveTitle(/chmod/i);
    await expectControlsUsable(page, {
      'octal field': '.signal-tool-primary input[placeholder="755"]',
      'preset list': '.signal-tool-primary select',
      'Copy button': '.signal-tool-primary button.btn-secondary',
      ...Object.fromEntries(ROLES.flatMap(role => PERMS.map(perm => [`${role} ${perm} button`, `button[aria-label="${role} ${perm}"]`]))),
    });
    for (const special of SPECIALS) {
      await expect.soft(specialBox(page, special), `${SPECIAL_LABELS[special]} checkbox should be visible`).toBeVisible();
      await expect.soft(specialBox(page, special), `${SPECIAL_LABELS[special]} checkbox should be enabled`).toBeEnabled();
    }
    await expectView(page, expectedView(DEFAULT_MODE), '755', 'first visit');
    await expect.soft(presetSelect(page), 'the preset list starts on its placeholder').toHaveValue('');
    await expect.soft(copyButton(page), 'Copy button label before copying').toHaveText('Copy');

    // The same values through the accessibility tree, as a user finds them.
    await expect.soft(card(page, 'Octal'), 'Octal card on first visit').toHaveText('755');
    await expect.soft(card(page, 'Symbolic'), 'Symbolic card on first visit').toHaveText('rwxr-xr-x');
    await expect.soft(card(page, 'ls -la Output'), 'ls -la Output card on first visit').toHaveText('-rwxr-xr-x');
    await expect.soft(cell(page, 'Group', 'Write'), 'Group Write is off in 755').toHaveAttribute('aria-pressed', 'false');
    await expect.soft(cell(page, 'Owner', 'Write'), 'Owner Write is on in 755').toHaveAttribute('aria-pressed', 'true');

    const panel = guide(page);
    await expect(panel, 'guide panel "Permission reference"').toBeVisible();
    await expect.soft(panel.getByRole('heading', { name: 'Permission reference' })).toBeVisible();
    await expect.soft(panel.locator('dt'), 'guide entries').toHaveText(['Read · write · execute', 'Three roles', 'Special bits']);
    // The guide's own rule is the definition the oracle is built on.
    await expect.soft(panel.locator('dd').first(), 'guide states the digit values').toContainText('Read = 4, write = 2, execute = 1');
    await expect.soft(panel.locator('dd').nth(2), 'guide explains the leading digit').toContainText('leading octal digit');
  });

  for (const [name, viewport] of Object.entries(VIEWPORTS)) {
    test(`has no layout problems at ${name} size (${viewport.width}px) in every state`, async ({ page }) => {
      await page.setViewportSize(viewport);
      await open(page);
      await expectNoUiGlitches(page, `${ROUTE} default 755 @${name}`);

      await enterOctal(page, '6777');
      await expect(card(page, 'Octal')).toHaveText('6777');
      await expectNoUiGlitches(page, `${ROUTE} mode 6777 with three warnings @${name}`);

      await enterOctal(page, '000');
      await expect(card(page, 'Octal')).toHaveText('000');
      await expectNoUiGlitches(page, `${ROUTE} mode 000 (nothing pressed) @${name}`);

      await enterOctal(page, 'rwxr-xr-x is not octal');
      await expectNoUiGlitches(page, `${ROUTE} with a long invalid draft in the octal field @${name}`);

      await enterOctal(page, '1777');
      await copyButton(page).click();
      await expect(copyButton(page)).toHaveText('Copied!');
      await expectNoUiGlitches(page, `${ROUTE} right after copying @${name}`);

      // The grid must stay operable at this width.
      await cell(page, 'Others', 'Write').click();
      await expectView(page, expectedView(modeOf('1775')), '1775', `grid click at ${name} size`);
    });
  }
});

test.describe('chmod Calculator — notation and warnings', () => {
  test('a leading zero is accepted and means "no special bits"', async ({ page, rng, evidence }) => {
    await open(page);
    const bodies = ['000', '777', '007', '070', '700', '644', '755', ...Array.from({ length: 25 }, () => octalOf({ ...randomMode(rng), Setuid: false, Setgid: false, Sticky: false }))];
    await evidence.save('leading-zero-inputs.json', bodies.map(b => `0${b}`));
    for (const body of bodies) {
      // Start from a mode with every special bit set, so a zero that is ignored would show.
      await enterOctal(page, '7000');
      await expectView(page, expectedView(modeOf('7000')), '7000', 'typed "7000"');
      await enterOctal(page, `0${body}`);
      await expectView(page, expectedView(modeOf(body)), [`0${body}`, body], `typed "0${body}"`);
    }
  });

  test('warnings appear exactly for 777, world-writable, setuid and setgid modes', async ({ page }) => {
    await open(page);
    // Written out by hand as a second, table-free statement of the warning rules.
    const cases: [string, string[]][] = [
      ['755', []],
      ['000', []],
      ['775', []],
      ['770', []],
      ['1755', []],
      ['1000', []],
      ['777', [WARNING_777]],
      ['0777', [WARNING_777]],
      ['1777', [WARNING_777]],
      ['776', [WARNING_WORLD_WRITABLE]],
      ['773', [WARNING_WORLD_WRITABLE]],
      ['772', [WARNING_WORLD_WRITABLE]],
      ['767', [WARNING_WORLD_WRITABLE]],
      ['677', [WARNING_WORLD_WRITABLE]],
      ['666', [WARNING_WORLD_WRITABLE]],
      ['002', [WARNING_WORLD_WRITABLE]],
      ['1772', [WARNING_WORLD_WRITABLE]],
      ['4755', [WARNING_SETUID]],
      ['4000', [WARNING_SETUID]],
      ['2755', [WARNING_SETGID]],
      ['2000', [WARNING_SETGID]],
      ['6755', [WARNING_SETUID, WARNING_SETGID]],
      ['3755', [WARNING_SETGID]],
      ['5755', [WARNING_SETUID]],
      ['4777', [WARNING_777, WARNING_SETUID]],
      ['7777', [WARNING_777, WARNING_SETUID, WARNING_SETGID]],
      ['6666', [WARNING_WORLD_WRITABLE, WARNING_SETUID, WARNING_SETGID]],
      ['2002', [WARNING_WORLD_WRITABLE, WARNING_SETGID]],
    ];
    for (const [typed, warnings] of cases) {
      await enterOctal(page, typed);
      await expect(card(page, 'Octal'), `Octal card after typing "${typed}"`).toHaveText(octalOf(modeOf(typed)));
      const view = await readView(page);
      expect.soft(view.warnings, `warnings for mode ${typed}`).toEqual(warnings);
      expect.soft(expectedView(modeOf(typed)).warnings, `oracle and hand-written table agree for ${typed}`).toEqual(warnings);
      for (const line of warnings) await expect.soft(page.getByText(line, { exact: true }), `warning "${line}" for mode ${typed} is visible`).toBeVisible();
      if (warnings.length === 0) {
        await expect.soft(page.locator('.signal-tool-primary').getByText(/^(🔴|🟡)/), `mode ${typed} needs no warning`).toHaveCount(0);
      }
    }
  });

  test('special bits change the execute letter: s/S for setuid and setgid, t/T for sticky', async ({ page }) => {
    await open(page);
    // The eight combinations a reader of `ls -l` must be able to tell apart, as literals.
    const cases: [string, string][] = [
      ['4755', 'rwsr-xr-x'], ['4655', 'rwSr-xr-x'],
      ['2755', 'rwxr-sr-x'], ['2745', 'rwxr-Sr-x'],
      ['1777', 'rwxrwxrwt'], ['1776', 'rwxrwxrwT'],
      ['7777', 'rwsrwsrwt'], ['7000', '--S--S--T'],
      ['7666', 'rwSrwSrwT'], ['7111', '--s--s--t'],
      ['5701', 'rws-----t'], ['3070', '---rws--T'], ['3060', '---rwS--T'],
    ];
    for (const [typed, symbolic] of cases) {
      await enterOctal(page, typed);
      await expect.soft(card(page, 'Symbolic'), `Symbolic card for mode ${typed}`).toHaveText(symbolic);
      await expect.soft(card(page, 'ls -la Output'), `ls -la Output card for mode ${typed}`).toHaveText(`-${symbolic}`);
      expect.soft(expectedView(modeOf(typed)).symbolic, `oracle and hand-written table agree for ${typed}`).toBe(symbolic);
    }
  });
});

test.describe('chmod Calculator — grid and special bits', () => {
  test('each grid button switches exactly its own permission, and a second click switches it back', async ({ page, rng, evidence }) => {
    await open(page);
    const starts = ['000', '777', octalOf(randomMode(rng)), octalOf(randomMode(rng))];
    await evidence.save('start-modes.json', starts);
    for (const start of starts) {
      await enterOctal(page, start);
      const before = modeOf(start);
      await expectView(page, expectedView(before), start, `start mode ${start}`);
      for (const role of ROLES) {
        for (const perm of PERMS) {
          const after = toggleCell(before, role, perm);
          await cell(page, role, perm).click();
          await expectView(page, expectedView(after), octalOf(after), `mode ${start}, clicked "${role} ${perm}"`);
          await cell(page, role, perm).click();
          await expectView(page, expectedView(before), start, `mode ${start}, clicked "${role} ${perm}" twice`);
        }
      }
    }
  });

  test('each special-bit checkbox switches its own bit, by the box and by its label', async ({ page, rng, evidence }) => {
    await open(page);
    const starts = ['000', '777', '755', '644', octalOf({ ...randomMode(rng), Setuid: false, Setgid: false, Sticky: false })];
    await evidence.save('start-modes.json', starts);
    for (const start of starts) {
      await enterOctal(page, start);
      let mode = modeOf(start);
      for (const special of rng.shuffle(SPECIALS)) {
        mode = toggleSpecial(mode, special);
        await specialBox(page, special).click();
        await expectView(page, expectedView(mode), octalOf(mode), `from ${start}: ticked ${special} (now ${octalOf(mode)})`);
      }
      for (const special of rng.shuffle(SPECIALS)) {
        mode = toggleSpecial(mode, special);
        await page.locator('.signal-tool-primary label', { hasText: SPECIAL_LABELS[special] }).click();
        await expectView(page, expectedView(mode), octalOf(mode), `from ${start}: clicked the label of ${special} (now ${octalOf(mode)})`);
      }
      expect(octalOf(mode), 'all three bits were switched on and off again').toBe(start);
    }
  });

  test('a long random series of clicks, ticks, presets and typed modes always matches a model of the mode', async ({ page, rng, evidence }) => {
    await open(page);
    let mode: Mode = DEFAULT_MODE;
    /** Exact text expected in the octal field; a draft stays until another control is used. */
    let field = octalOf(mode);
    const log: string[] = [];
    let wrong = 0;

    for (let step = 1; step <= 260; step++) {
      const action = rng.weighted(['cell', 'special', 'preset', 'type', 'draft'] as const, [10, 4, 1, 2, 1]);
      let what: string;
      if (action === 'cell') {
        const role = rng.pick(ROLES), perm = rng.pick(PERMS);
        mode = toggleCell(mode, role, perm);
        field = octalOf(mode);
        what = `click "${role} ${perm}"`;
        await cell(page, role, perm).click();
      } else if (action === 'special') {
        const special = rng.pick(SPECIALS);
        mode = toggleSpecial(mode, special);
        field = octalOf(mode);
        what = `tick "${SPECIAL_LABELS[special]}"`;
        await specialBox(page, special).click();
      } else if (action === 'preset') {
        const preset = rng.pick(PRESETS);
        mode = modeOf(preset.octal);
        field = preset.octal;
        what = `preset "${preset.label}"`;
        await choosePreset(page, preset.octal);
      } else if (action === 'type') {
        mode = randomMode(rng);
        field = octalOf(mode);
        what = `type "${field}"`;
        await enterOctal(page, field);
      } else {
        field = rng.pick(INVALID_DRAFTS).text;
        what = `type the draft ${JSON.stringify(field)}`;
        await enterOctal(page, field);
      }
      log.push(`${step}. ${what} -> ${octalOf(mode)}`);
      if (!await expectView(page, expectedView(mode), field, `step ${step} (${what}); last steps: ${log.slice(-6).join(' | ')}`)) wrong++;
      if (wrong >= 8) break;
    }
    await evidence.save('actions.txt', log.join('\n'));
    expect(wrong, 'steps where the page and the model disagreed').toBe(0);
  });

  test('grid buttons and checkboxes work from the keyboard, in reading order', async ({ page }) => {
    await open(page);
    await octalInput(page).focus();
    const focused = () => page.evaluate(() => {
      const el = document.activeElement as HTMLElement | null;
      if (!el) return '(nothing)';
      if (el instanceof HTMLInputElement && el.type === 'checkbox') return (el.closest('label')?.textContent || '').trim();
      return el.getAttribute('aria-label') || el.getAttribute('placeholder') || el.tagName.toLowerCase() + ':' + (el.textContent || '').trim().slice(0, 20);
    });

    let mode: Mode = DEFAULT_MODE;
    await page.keyboard.press('Tab');
    expect.soft(await focused(), 'Tab from the octal field reaches the preset list').toMatch(/^select:/);
    for (const role of ROLES) {
      for (const perm of PERMS) {
        await page.keyboard.press('Tab');
        expect.soft(await focused(), `Tab order reaches "${role} ${perm}"`).toBe(`${role} ${perm}`);
        // Space on one pass, Enter on the next, to cover both activation keys.
        await page.keyboard.press(perm === 'Write' ? 'Enter' : 'Space');
        mode = toggleCell(mode, role, perm);
        await expectView(page, expectedView(mode), octalOf(mode), `keyboard toggle of "${role} ${perm}"`);
      }
    }
    for (const special of SPECIALS) {
      await page.keyboard.press('Tab');
      expect.soft(await focused(), `Tab order reaches the ${special} checkbox`).toBe(SPECIAL_LABELS[special]);
      await page.keyboard.press('Space');
      mode = toggleSpecial(mode, special);
      await expectView(page, expectedView(mode), octalOf(mode), `keyboard toggle of ${special}`);
    }
    await page.keyboard.press('Tab');
    expect.soft(await focused(), 'Tab order ends on the Copy button').toMatch(/Copy/);
  });
});

test.describe('chmod Calculator — presets', () => {
  test('the dropdown offers the eight presets, and each label matches the mode it names', async ({ page }) => {
    await open(page);
    const options = await presetSelect(page).locator('option').evaluateAll(list =>
      list.map(o => ({ value: (o as HTMLOptionElement).value, text: (o.textContent || '').replace(/\s+/g, ' ').trim() })));
    expect(options[0], 'first entry is the placeholder').toEqual({ value: '', text: 'Load a preset...' });
    expect.soft(options.slice(1).map(o => o.text), 'preset labels in order').toEqual(PRESETS.map(p => `${p.label} (${p.octal}) — ${p.desc}`));
    expect.soft(options.slice(1).map(o => o.value), 'preset values in order').toEqual(PRESETS.map(p => p.octal));
    for (const preset of PRESETS) {
      expect.soft(preset.claim(modeOf(preset.octal)), `preset "${preset.label}" (${preset.octal}): the mode must do what the label says (${preset.desc})`).toBe(true);
    }
  });

  test('choosing a preset applies its mode everywhere and the list returns to its placeholder', async ({ page, rng }) => {
    await open(page);
    for (const preset of rng.shuffle(PRESETS)) {
      // Leave an unrelated mode first so nothing of it may survive the preset.
      const before = randomMode(rng);
      await enterOctal(page, octalOf(before));
      await choosePreset(page, preset.octal);
      await expectView(page, expectedView(modeOf(preset.octal)), preset.octal, `preset "${preset.label}" after mode ${octalOf(before)}`);
      await expect.soft(presetSelect(page), `preset list after choosing "${preset.label}"`).toHaveValue('');
    }
  });

  test('the same preset can be chosen again after the mode was changed', async ({ page, rng }) => {
    await open(page);
    const preset = rng.pick(PRESETS);
    await choosePreset(page, preset.octal);
    const changed = toggleCell(modeOf(preset.octal), rng.pick(ROLES), rng.pick(PERMS));
    await enterOctal(page, octalOf(changed));
    await expectView(page, expectedView(changed), octalOf(changed), `preset "${preset.label}" then mode ${octalOf(changed)}`);
    // Keyboard selection, as a user who reopens the list does; the list is back on its placeholder.
    await presetSelect(page).focus();
    await presetSelect(page).selectOption({ label: `${preset.label} (${preset.octal}) — ${preset.desc}` });
    await expectView(page, expectedView(modeOf(preset.octal)), preset.octal, `preset "${preset.label}" chosen a second time`);
  });
});

test.describe('chmod Calculator — drafts and invalid input', () => {
  test('text that is not a 3 or 4 digit octal mode leaves the result untouched and stays in the field', async ({ page, rng, evidence }) => {
    await open(page);
    const random = Array.from({ length: 20 }, () => {
      const kind = rng.pick(['short', 'long', 'bad-digit', 'letters'] as const);
      if (kind === 'short') return rng.string(rng.int(1, 2), '01234567');
      if (kind === 'long') return rng.string(rng.int(5, 9), '01234567');
      if (kind === 'bad-digit') return rng.shuffle([...rng.string(rng.int(2, 3), '01234567'), rng.pick(['8', '9'])]).join('');
      return rng.string(rng.int(3, 4), 'abcdefrwxstugo+-=,');
    }).map(text => ({ text, why: 'random' }));
    const drafts = [...INVALID_DRAFTS, ...random];
    await evidence.save('drafts.json', drafts);
    for (const { text, why } of drafts) {
      expect(parseOctal(text), `oracle self-check: ${JSON.stringify(text)} is not a mode`).toBeNull();
      const mode = randomMode(rng);
      await enterOctal(page, octalOf(mode));
      await enterOctal(page, text);
      await expectView(page, expectedView(mode), text, `mode ${octalOf(mode)}, then the draft ${JSON.stringify(text)} (${why})`);
    }
  });

  test('typing key by key: the result follows the field only while it holds a complete mode', async ({ page, rng, evidence }) => {
    await open(page);
    await octalInput(page).fill('');
    let mode: Mode = DEFAULT_MODE;
    let text = '';
    const keys: string[] = [];
    let wrong = 0;
    for (let step = 1; step <= 220 && wrong < 8; step++) {
      let key: string;
      let next: string;
      // A four-digit entry with a leading zero is normalised by the page (0755 -> 755);
      // that case has its own tests below, so this walk steps around it.
      do {
        key = text.length >= 5 && rng.bool(0.7)
          ? 'Backspace'
          : rng.weighted(['digit', '8', '9', 'x', ' ', 'Backspace'] as const, [14, 1, 1, 1, 1, 5]);
        if (key === 'digit') key = rng.pick(['0', '1', '2', '3', '4', '5', '6', '7']);
        next = key === 'Backspace' ? text.slice(0, -1) : text + key;
      } while (/^0[0-7]{3}$/.test(next));
      text = next;
      keys.push(key === ' ' ? 'Space' : key);
      await octalInput(page).press(key === ' ' ? 'Space' : key);
      mode = parseOctal(text) ?? mode;
      if (!await expectView(page, expectedView(mode), text, `key ${step} (${keys.slice(-8).join(' ')}), field should read ${JSON.stringify(text)}`)) wrong++;
    }
    await evidence.save('keys.txt', keys.join(' '));
    expect(wrong, 'keystrokes after which the page and the model disagreed').toBe(0);
  });

  test('typing a mode key by key gives the same result as pasting it', async ({ page, rng, evidence }) => {
    await open(page);
    const modes = Array.from({ length: 12 }, () => randomMode(rng));
    await evidence.save('modes.json', modes.map(octalOf));
    for (const mode of modes) {
      const text = octalOf(mode);
      await enterOctal(page, '000');
      await typeOctal(page, text);
      await expectView(page, expectedView(mode), text, `"${text}" typed key by key`);
      await enterOctal(page, '000');
      await enterOctal(page, text);
      await expectView(page, expectedView(mode), text, `"${text}" pasted`);
    }
  });

  test('using the grid, a checkbox or a preset while a draft is in the field replaces the draft with the new mode', async ({ page, rng }) => {
    await open(page);
    for (const control of ['grid', 'checkbox', 'preset'] as const) {
      let mode = randomMode(rng);
      const draft = rng.pick(INVALID_DRAFTS.filter(d => d.text !== '')).text;
      await enterOctal(page, octalOf(mode));
      await enterOctal(page, draft);
      await expectView(page, expectedView(mode), draft, `mode ${octalOf(mode)} with the draft ${JSON.stringify(draft)}`);
      if (control === 'grid') {
        const role = rng.pick(ROLES), perm = rng.pick(PERMS);
        mode = toggleCell(mode, role, perm);
        await cell(page, role, perm).click();
      } else if (control === 'checkbox') {
        const special = rng.pick(SPECIALS);
        mode = toggleSpecial(mode, special);
        await specialBox(page, special).click();
      } else {
        const preset = rng.pick(PRESETS);
        mode = modeOf(preset.octal);
        await choosePreset(page, preset.octal);
      }
      await expectView(page, expectedView(mode), octalOf(mode), `draft ${JSON.stringify(draft)}, then the ${control} was used`);
    }
  });

  test('a fifth digit typed after a four-digit mode does not change the result', async ({ page, rng, evidence }) => {
    await open(page);
    const cases = Array.from({ length: 10 }, () => ({
      four: rng.pick(['1', '2', '3', '4', '5', '6', '7']) + rng.string(3, '01234567'),
      extra: rng.pick(['0', '1', '2', '3', '4', '5', '6', '7']),
    }));
    await evidence.save('cases.json', cases);
    for (const { four, extra } of cases) {
      await typeOctal(page, four);
      await expectView(page, expectedView(modeOf(four)), four, `typed "${four}" key by key`);
      await octalInput(page).press(extra);
      await expectView(page, expectedView(modeOf(four)), four + extra, `typed "${four}" and then "${extra}" (five digits are not a mode)`);
    }
  });

  test('a fifth digit typed after a mode with a leading zero ("0755" then "1") does not turn into a different mode', async ({ page }) => {
    await open(page);
    await typeOctal(page, '0755');
    await expectView(page, expectedView(modeOf('755')), ['0755', '755'], 'typed "0755" key by key');
    await octalInput(page).press('1');
    // The user has typed 0,7,5,5,1. Five digits are not a mode, so the result must stay 755
    // (as it stays 4755 after 4,7,5,5,1). Dropping the typed zero turns the entry into 7551.
    const view = await readView(page);
    expect.soft(view.octal, 'Octal card after typing the five keys 0 7 5 5 1: the entry "07551" is not a mode, so the last valid mode 755 must remain '
      + `(the field now reads ${JSON.stringify(view.input)}, the command line reads ${JSON.stringify(view.command)})`).toBe('755');
    expect.soft(view.checked, 'special bits after typing 0 7 5 5 1: none was asked for').toEqual({ 'Setuid (4xxx)': false, 'Setgid (2xxx)': false, 'Sticky (1xxx)': false });
    expect.soft(view.input, 'octal field after typing the five keys 0 7 5 5 1 must hold what was typed').toBe('07551');
  });

  test('an octal field that holds something other than a mode is flagged, not silently ignored', async ({ page }) => {
    await open(page);
    // While such text is in the field, the cards and the command still show the previous
    // mode. Without any sign that the entry was refused, a user copies `chmod 755` believing
    // it is what they typed.
    for (const text of ['888', '12345', 'rwx']) {
      await enterOctal(page, '755');
      await enterOctal(page, text);
      const view = await readView(page);
      expect(view.octal, `the refused entry ${JSON.stringify(text)} must not change the mode`).toBe('755');
      expect.soft(await invalidFieldIsFlagged(page),
        `octal field holds ${JSON.stringify(text)} (not a mode) while the page still shows mode ${view.octal} and offers to copy "${view.command}": `
        + 'the page must say the entry is invalid (aria-invalid on the field, an error message, or a disabled Copy button); it shows none of these').toBe(true);
    }
  });

  test('a mode pasted with a space before or after it is applied or flagged, never silently dropped', async ({ page }) => {
    await open(page);
    for (const text of ['644 ', ' 644', ' 4755 ', '\t600']) {
      await enterOctal(page, '755');
      await enterOctal(page, text);
      const view = await readView(page);
      const applied = view.octal === text.trim();
      const flagged = await invalidFieldIsFlagged(page);
      expect.soft(applied || flagged,
        `pasted ${JSON.stringify(text)}: the field reads ${JSON.stringify(view.input)} (the space cannot be seen) but the page still shows mode ${view.octal} `
        + `and the command "${view.command}", with no sign that the entry was refused. Expected mode ${text.trim()} to be applied, or the field to be flagged`).toBe(true);
    }
  });

  test('markup typed into the octal field is kept as text and never runs', async ({ page }) => {
    await open(page);
    await enterOctal(page, '640');
    const payload = '<img src=x onerror="window.__chmodXss=1"><script>window.__chmodXss=2</script>';
    await enterOctal(page, payload);
    await expectView(page, expectedView(modeOf('640')), payload, 'markup in the octal field');
    expect(await page.evaluate(() => (window as unknown as { __chmodXss?: number }).__chmodXss), 'the markup must not run').toBeUndefined();
    await expect(page.locator('main img, main script'), 'no element may be created from the typed text').toHaveCount(0);

    const long = '7'.repeat(20_000);
    await enterOctal(page, long);
    await expectView(page, expectedView(modeOf('640')), long, 'a 20,000 character entry');
  });
});

test.describe('chmod Calculator — command and copy', () => {
  test('Copy puts exactly the displayed command on the clipboard and confirms', async ({ page, rng, evidence }) => {
    await open(page);
    const modes = [modeOf('755'), modeOf('4755'), modeOf('000'), ...Array.from({ length: 4 }, () => randomMode(rng))];
    await evidence.save('modes.json', modes.map(octalOf));
    for (const mode of modes) {
      const octal = octalOf(mode);
      await enterOctal(page, octal);
      await expect(commandLine(page), `command line for mode ${octal}`).toHaveText(`chmod ${octal} filename`);
      await clearClipboard(page);
      await copyButton(page).click();
      await expect(copyButton(page), `Copy button confirms for mode ${octal}`).toHaveText('Copied!');
      expect.soft(await readClipboard(page), `clipboard after Copy for mode ${octal}`).toBe(`chmod ${octal} filename`);
    }
    await expect(copyButton(page), 'the label returns to "Copy" after two seconds').toHaveText('Copy', { timeout: 6_000 });
  });

  test('Copy after grid and checkbox changes copies the new command, with the four-digit form when a special bit is set', async ({ page, rng }) => {
    await open(page);
    let mode: Mode = DEFAULT_MODE;
    for (let i = 0; i < 6; i++) {
      const role = rng.pick(ROLES), perm = rng.pick(PERMS);
      mode = toggleCell(mode, role, perm);
      await cell(page, role, perm).click();
    }
    const special = rng.pick(SPECIALS);
    mode = toggleSpecial(mode, special);
    await specialBox(page, special).click();
    await expectView(page, expectedView(mode), octalOf(mode), 'after six grid clicks and one special bit');
    expect(octalOf(mode), 'a special bit gives a four-digit mode').toBe(fourDigitOctalOf(mode));
    await clearClipboard(page);
    await copyButton(page).click();
    await expect(copyButton(page)).toHaveText('Copied!');
    expect.soft(await readClipboard(page), `clipboard for mode ${octalOf(mode)}`).toBe(`chmod ${octalOf(mode)} filename`);
  });

  test('with a draft in the field, Copy copies the command that is on screen', async ({ page, rng }) => {
    await open(page);
    const mode = randomMode(rng);
    await enterOctal(page, octalOf(mode));
    await enterOctal(page, '9');
    await clearClipboard(page);
    await copyButton(page).click();
    await expect(copyButton(page)).toHaveText('Copied!');
    const shown = (await commandLine(page).textContent()) ?? '';
    expect.soft(shown, `command line with the draft "9" after mode ${octalOf(mode)}`).toBe(`chmod ${octalOf(mode)} filename`);
    expect.soft(await readClipboard(page), 'clipboard equals the command line on screen').toBe(shown);
  });
});

test.describe('chmod Calculator — state', () => {
  test('a reload returns to mode 755 with no special bits and no draft', async ({ page, rng }) => {
    await open(page);
    const mode = { ...randomMode(rng), Sticky: true };
    await enterOctal(page, octalOf(mode));
    await expectView(page, expectedView(mode), octalOf(mode), `mode ${octalOf(mode)} before the reload`);
    expect.soft(new URL(page.url()).pathname + new URL(page.url()).search, 'the mode is not kept in the address').toBe(ROUTE);
    await page.reload();
    await waitForHydration(page);
    await expectView(page, expectedView(DEFAULT_MODE), '755', `reload after mode ${octalOf(mode)}`);

    await enterOctal(page, 'draft');
    await page.reload();
    await waitForHydration(page);
    await expectView(page, expectedView(DEFAULT_MODE), '755', 'reload with a draft in the field');
    await expect.soft(presetSelect(page)).toHaveValue('');
  });

  test('leaving the tool and coming back with the browser Back button starts from 755 again', async ({ page, rng }) => {
    await open(page);
    const drawn = octalOf(randomMode(rng));
    await enterOctal(page, drawn === '755' ? '640' : drawn);
    await page.locator('aside.signal-sidebar a[href="/cron"]').first().click();
    await expect(page.getByRole('heading', { level: 1, name: 'Crontab Builder' })).toBeVisible();
    await page.goBack();
    await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
    await expectView(page, expectedView(DEFAULT_MODE), '755', 'after Back from another tool');
    await page.goForward();
    await expect(page.getByRole('heading', { level: 1, name: 'Crontab Builder' })).toBeVisible();
  });
});
