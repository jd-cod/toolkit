import { test, expect } from '../_support/fixtures';
import { expectToolLinkedFromHome } from '../_support/navigation';
import { expectNoUiGlitches, expectControlsUsable, VIEWPORTS } from '../_support/ui-audit';
import {
  RANDOM_DEFAULTS, RANDOM_LENGTH, WORD_COUNT, PIN_LENGTH, BULK_COUNTS, HISTORY_LIMIT, PASSPHRASE_DEFAULTS,
  randomKeyspace, passphraseKeyspace, pinKeyspace, randomValueProblems, parsePassphrase, pinProblems,
  poolFor, log2Fixed2, wordList, type Mode,
} from './oracle';
import { PasswordGenerator, ROUTE, HEADING } from './page';
import { expectStrength, expectMainValuePossible } from './checks';

/**
 * Password Generator (/password-generator, legacy /password) — runs entirely in the browser.
 *
 * INVENTORY (coverage contract; the spec file that covers each entry is named in brackets)
 *
 * Modes (buttons with aria-pressed): Random, Passphrase, PIN. Each has its own hint line and its own
 *   remembered length. [this file]
 * Value display (#pw-value): generated on load and after every settings change; Hide/Show button
 *   (bullets instead of the value); Regenerate; Copy Password ("Copied!" for two seconds). [outputs]
 * Strength (#pw-strength): label (Very Weak … Very Strong), "N bits · ~crack time", meter fill, advice
 *   lines. [random, passphrase-pin]
 * Length: one slider per mode (Random 4–128 characters, Passphrase 3–10 words, PIN 4–16 digits), a
 *   readout ("20 characters"), preset buttons (8 12 16 20 32 64 / 3 4 5 6 7 / 4 6 8). There is no
 *   number field: out-of-range and non-numeric lengths can only arrive from saved settings. [random,
 *   passphrase-pin, state]
 * Random mode: four character-type toggles (Uppercase, Lowercase, Numbers, Symbols; the last one
 *   selected cannot be switched off), "Include at least one of each selected type", "Avoid look-alike
 *   characters", "Avoid shell-hostile symbols", "Character pool: N distinct characters", "Entropy per
 *   character: X bits". No custom symbol field. [random]
 * Passphrase mode: separator buttons (- . _ space +), "Capitalise each word", "Append a random number
 *   (0–99)", help text (word-list size, bits per word, a claim about four words). [passphrase-pin]
 * PIN mode: warning with bits per digit and the bits of the current PIN. [passphrase-pin]
 * Bulk generate: count (5 / 10 / 25 / 50), Generate, numbered list, per-row copy, Copy All, Export CSV
 *   (generated-passwords.csv), Clear. Promise: "These are not saved to history." [outputs, history]
 * History ("Recent passwords n/25"): a value is recorded once it has been on screen for about a
 *   second; "Save to history" checkbox; rows with hidden value + reveal, Length, Contains, Strength
 *   (label + bits), Generated (relative time, full timestamp as tooltip), copy, delete; Clear all;
 *   empty state; 25-entry limit; kept in localStorage. [history]
 * Remembered settings (localStorage): mode, all Random options, all Passphrase options, PIN length.
 *   There is no "reset to defaults" control; clearing the browser storage gives the defaults. [state]
 * Security properties: values come from crypto.getRandomValues, never Math.random; values never
 *   appear in a request, the URL, a cookie or sessionStorage; the server-rendered page holds no value.
 *   [state]
 * Guide panel ("Generation settings") and the privacy note. [this file]
 * States: loading placeholder before the browser takes over, value shown, value hidden, bulk list
 *   open, history empty / with rows / row revealed. There is no error state: nothing can be typed.
 *
 * LAYERS: 1 access (this file) · 2 layout (this file) · 3 input paths: slider by fill, keyboard and
 * mouse, presets, toggles, labels (random, passphrase-pin); the tool reads no URL parameters and
 * accepts no typed, pasted or uploaded input · 4 displayed values (random, passphrase-pin, history) ·
 * 5 controls and combinations (random, passphrase-pin) · 6 copy / CSV (outputs); no share feature and
 * no server requests · 7 bad input: only reachable through tampered storage (state) · 8 state (state,
 * history); the tool keeps nothing in the URL, so back/forward and deep links do not apply.
 */

const MODE_FACTS: Record<Mode, { button: string; hint: string; heading: string; unit: string; range: { min: number; max: number; presets: number[] }; initial: number }> = {
  password: { button: 'Random', hint: 'Full-entropy random string', heading: 'Password length', unit: 'characters', range: RANDOM_LENGTH, initial: 20 },
  passphrase: { button: 'Passphrase', hint: 'Memorable words you can retype', heading: 'Number of words', unit: 'words', range: WORD_COUNT, initial: 4 },
  pin: { button: 'PIN', hint: 'Digits only — lockers, doors, MFA backup', heading: 'PIN length', unit: 'digits', range: PIN_LENGTH, initial: 6 },
};

test.describe('Password generator — access', () => {
  test('is linked from the home page and the sidebar', async ({ page }) => {
    await expectToolLinkedFromHome(page, ROUTE);
    await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
    await new PasswordGenerator(page).waitForValue();
  });

  test('the legacy /password address redirects permanently to the tool', async ({ page, request }) => {
    const response = await request.get('/password', { maxRedirects: 0 });
    expect([301, 308], `/password should answer with a permanent redirect, got HTTP ${response.status()}`).toContain(response.status());
    expect(response.headers().location, 'redirect target of /password').toMatch(/\/password-generator$/);

    const gen = new PasswordGenerator(page);
    await page.goto('/password');
    await expect(page, 'the browser should end up on the tool').toHaveURL(new RegExp(`${ROUTE}$`));
    await expect(page.getByRole('heading', { level: 1, name: HEADING })).toBeVisible();
    await gen.waitForValue();
  });

  test('opens in Random mode with the documented defaults and every control ready', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    await expect(page).toHaveTitle(/Password/i);
    await expect.soft(page.getByText('Create a random password, memorable passphrase, or numeric PIN.')).toBeVisible();
    await expect.soft(page.getByText('Everything happens inside your browser')).toBeVisible();
    await expect.soft(page.getByText('Nothing is uploaded or stored on our servers.')).toBeVisible();

    await expectControlsUsable(page, {
      'mode buttons': '.signal-tool-primary button[aria-pressed]',
      'Hide password button': 'button[aria-label="Hide password"]',
      'Regenerate button': 'button[title="Generate a new one"]',
      'length slider': 'input.pw-slider',
      'length presets': 'input.pw-slider + div button',
      'option checkboxes': '.signal-tool-primary label input[type="checkbox"]',
      'bulk count': 'select[aria-label="How many passwords to generate"]',
    });
    for (const control of [gen.copyButton, gen.bulkGenerate, gen.saveToHistory]) {
      await expect.soft(control).toBeVisible();
      await expect.soft(control).toBeEnabled();
    }

    for (const mode of Object.keys(MODE_FACTS) as Mode[]) {
      await expect.soft(gen.modeButton(mode), `${mode} mode button pressed state`).toHaveAttribute('aria-pressed', String(mode === 'password'));
    }
    await expect.soft(gen.modeHint, 'mode hint').toHaveText(MODE_FACTS.password.hint);

    await expectMainValuePossible(gen, v => randomValueProblems(v, RANDOM_DEFAULTS), 'default settings');
    await expectStrength(gen, randomKeyspace(RANDOM_DEFAULTS), 'default settings (20 characters, all four types)');
    await expect.soft(gen.tips, 'at least one line of advice under the meter').not.toHaveCount(0);

    await expect.soft(gen.slider, 'slider value').toHaveValue('20');
    await expect.soft(gen.slider, 'slider minimum').toHaveAttribute('min', String(RANDOM_LENGTH.min));
    await expect.soft(gen.slider, 'slider maximum').toHaveAttribute('max', String(RANDOM_LENGTH.max));
    await expect.soft(gen.lengthHeading).toHaveText('Password length');
    await expect.soft(gen.lengthReadout).toHaveText('20 characters');
    await expect.soft(gen.presets, 'length presets').toHaveText(RANDOM_LENGTH.presets.map(String));
    await expect.soft(gen.preset(20), 'the preset equal to the current length is highlighted').toHaveClass(/btn-primary/);

    const samples = { uppercase: 'A–Z', lowercase: 'a–z', numbers: '0–9', symbols: '!@#$%' } as const;
    for (const [key, sample] of Object.entries(samples) as [keyof typeof samples, string][]) {
      await expect.soft(gen.classButton(key), `${key} is selected by default`).toHaveAttribute('aria-pressed', 'true');
      await expect.soft(gen.classButton(key), `${key} shows its sample`).toContainText(sample);
    }
    await expect.soft(gen.option('requireEach'), '"at least one of each" default').toBeChecked();
    await expect.soft(gen.option('avoidLookAlike'), '"avoid look-alike" default').not.toBeChecked();
    await expect.soft(gen.option('avoidShellHostile'), '"avoid shell-hostile" default').not.toBeChecked();
    const pool = poolFor(RANDOM_DEFAULTS).length;
    await expect.soft(gen.poolSize, 'character pool for all four types').toHaveText(String(pool));
    await expect.soft(gen.entropyPerChar, `entropy per character for a pool of ${pool}`).toHaveText(`${log2Fixed2(pool)} bits`);

    await expect.soft(gen.bulkCount, 'bulk count default').toHaveValue('10');
    await expect.soft(gen.bulkCount.locator('option'), 'bulk count choices').toHaveText(BULK_COUNTS.map(n => `${n} passwords`));
    await expect.soft(gen.bulkRowButtons, 'no bulk list before Generate is pressed').toHaveCount(0);
    await expect.soft(gen.bulkCopyAll, 'no Copy All before a bulk list exists').toHaveCount(0);
    await expect.soft(gen.bulkCard).toContainText('These are not saved to history.');

    await expect.soft(gen.saveToHistory, '"Save to history" default').toBeChecked();
    await expect.soft(gen.historyCount, 'history counter names the limit').toHaveText(new RegExp(`^[01]/${HISTORY_LIMIT}$`));
    await expect.soft(gen.historyCard).toContainText(`History stays in this browser (up to ${HISTORY_LIMIT} entries) & clearing browser data erases history.`);

    const guide = page.getByRole('complementary', { name: 'Generation settings' });
    await expect.soft(guide, 'guide panel').toBeVisible();
    await expect.soft(guide.locator('dt'), 'guide steps').toHaveText(['Choose a mode', 'Match your policy', 'Generate a batch']);
  });

  test('the page sent by the server contains a loading placeholder and no generated value', async ({ request }) => {
    const response = await request.get(ROUTE);
    expect(response.status(), `${ROUTE} should answer 200`).toBe(200);
    const html = await response.text();
    expect.soft(html, 'server HTML announces the browser-only generator').toContain('Loading your browser-only generator');
    expect.soft(html.includes('id="pw-value"'), 'server HTML must not contain the value display (values are created in the browser only)').toBe(false);
  });
});

test.describe('Password generator — layout', () => {
  for (const [name, viewport] of Object.entries(VIEWPORTS)) {
    test(`has no layout problems at ${name} size (${viewport.width}px) in any mode or state`, async ({ page }) => {
      await page.setViewportSize(viewport);
      const gen = new PasswordGenerator(page);
      await gen.open();
      await expectNoUiGlitches(page, `${ROUTE} Random mode, defaults @${name}`);

      await gen.setLength(RANDOM_LENGTH.max);
      await expectMainValuePossible(gen, v => randomValueProblems(v, { ...RANDOM_DEFAULTS, length: RANDOM_LENGTH.max }), 'longest value');
      await expectNoUiGlitches(page, `${ROUTE} Random mode, 128 characters @${name}`);

      await gen.hideButton().click();
      await expect(gen.showButton()).toBeVisible();
      await expectNoUiGlitches(page, `${ROUTE} value hidden @${name}`);
      await gen.showButton().click();

      await gen.generateBulk(50);
      await expectNoUiGlitches(page, `${ROUTE} bulk list of 50 long values @${name}`);
      await gen.bulkClear.click();

      await gen.configurePassphrase({ words: WORD_COUNT.max, separator: ' ', capitalise: true, appendNumber: true });
      await gen.generateBulk(10);
      await expectNoUiGlitches(page, `${ROUTE} Passphrase mode, 10 words, bulk list @${name}`);

      await gen.configurePin(PIN_LENGTH.max);
      await expectNoUiGlitches(page, `${ROUTE} PIN mode @${name}`);

      await expect(gen.historyRows.first(), 'the value on screen is recorded in the history').toBeVisible();
      await gen.historyRows.first().getByRole('button', { name: /^Reveal password/ }).click();
      await expectNoUiGlitches(page, `${ROUTE} history with a revealed row @${name}`);

      await gen.clearAll.click();
      await expect(gen.historyEmpty).toBeVisible();
      await expectNoUiGlitches(page, `${ROUTE} history empty @${name}`);
    });
  }
});

test.describe('Password generator — history table layout', () => {
  test('the buttons of a history row are fully visible at every width, not cut off by the table edge', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    for (const [name, viewport] of Object.entries(VIEWPORTS)) {
      await page.setViewportSize(viewport);
      await gen.open();
      await expect(gen.historyRows.first(), 'the value on screen is recorded in the history').toBeVisible();
      const frame = await gen.historyCard.locator('.signal-password-history-wrap').boundingBox();
      expect(frame, 'history table area').toBeTruthy();
      for (const action of ['Reveal', 'Copy', 'Delete']) {
        const box = await gen.historyRows.first().getByRole('button', { name: new RegExp(`^${action} password from`) }).boundingBox();
        expect(box, `${action} button of the first history row @${name}`).toBeTruthy();
        expect.soft(
          box!.x >= frame!.x - 1 && box!.x + box!.width <= frame!.x + frame!.width + 1,
          `@${name} (${viewport.width}px): the ${action} button spans x=${Math.round(box!.x)}..${Math.round(box!.x + box!.width)} `
          + `but the visible table area is x=${Math.round(frame!.x)}..${Math.round(frame!.x + frame!.width)}`,
        ).toBe(true);
      }
      await gen.clearAll.click();
    }
  });
});

test.describe('Password generator — modes', () => {
  test('each mode shows its own hint, length control, presets and options, and a value of its own kind', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const words = new Set(wordList());
    const possible: Record<Mode, (value: string) => string[]> = {
      password: v => randomValueProblems(v, RANDOM_DEFAULTS),
      passphrase: v => { const parsed = parsePassphrase(v, PASSPHRASE_DEFAULTS, words); return typeof parsed === 'string' ? [parsed] : []; },
      pin: v => pinProblems(v, MODE_FACTS.pin.initial),
    };
    const keyspace: Record<Mode, bigint> = {
      password: randomKeyspace(RANDOM_DEFAULTS),
      passphrase: passphraseKeyspace(PASSPHRASE_DEFAULTS),
      pin: pinKeyspace(MODE_FACTS.pin.initial),
    };

    // Ends on Random again: going back must restore the first mode's view.
    for (const mode of ['passphrase', 'pin', 'password', 'pin', 'passphrase', 'password'] as Mode[]) {
      const facts = MODE_FACTS[mode];
      const ctx = `${facts.button} mode`;
      await gen.selectMode(mode);
      for (const other of Object.keys(MODE_FACTS) as Mode[]) {
        await expect.soft(gen.modeButton(other), `${ctx}: ${other} button pressed state`).toHaveAttribute('aria-pressed', String(other === mode));
      }
      await expect.soft(gen.modeHint, `${ctx}: hint line`).toHaveText(facts.hint);
      await expect.soft(gen.lengthHeading, `${ctx}: length heading`).toHaveText(facts.heading);
      await expect.soft(page.getByRole('slider', { name: facts.heading }), `${ctx}: the slider is named after what it sets`).toBeVisible();
      await expect.soft(gen.slider, `${ctx}: slider minimum`).toHaveAttribute('min', String(facts.range.min));
      await expect.soft(gen.slider, `${ctx}: slider maximum`).toHaveAttribute('max', String(facts.range.max));
      await expect.soft(gen.slider, `${ctx}: default length`).toHaveValue(String(facts.initial));
      await expect.soft(gen.lengthReadout, `${ctx}: length readout`).toHaveText(`${facts.initial} ${facts.unit}`);
      await expect.soft(gen.presets, `${ctx}: presets`).toHaveText(facts.range.presets.map(String));

      await expect.soft(gen.primary.getByText('Character types'), `${ctx}: character types panel`).toHaveCount(mode === 'password' ? 1 : 0);
      await expect.soft(gen.poolSize, `${ctx}: character pool readout`).toHaveCount(mode === 'password' ? 1 : 0);
      await expect.soft(gen.separatorButtons, `${ctx}: separator buttons`).toHaveCount(mode === 'passphrase' ? 5 : 0);
      await expect.soft(gen.passphraseHelp, `${ctx}: word-list note`).toHaveCount(mode === 'passphrase' ? 1 : 0);
      await expect.soft(gen.pinWarning, `${ctx}: PIN warning`).toHaveCount(mode === 'pin' ? 1 : 0);

      await expectMainValuePossible(gen, possible[mode], ctx);
      await expectStrength(gen, keyspace[mode], ctx);
    }
  });

  test('each mode remembers its own length while the others are used', async ({ page, rng, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const lengths: Record<Mode, number> = {
      password: rng.int(RANDOM_LENGTH.min, RANDOM_LENGTH.max),
      passphrase: rng.int(WORD_COUNT.min, WORD_COUNT.max),
      pin: rng.int(PIN_LENGTH.min, PIN_LENGTH.max),
    };
    await evidence.save('lengths.json', lengths);
    for (const mode of rng.shuffle(Object.keys(lengths) as Mode[])) {
      await gen.selectMode(mode);
      await gen.setLength(lengths[mode]);
    }
    for (const mode of rng.shuffle([...Object.keys(lengths), ...Object.keys(lengths)] as Mode[])) {
      await gen.selectMode(mode);
      await expect.soft(gen.slider, `${mode}: slider after visiting other modes`).toHaveValue(String(lengths[mode]));
      await expect.soft(gen.lengthReadout, `${mode}: readout after visiting other modes`).toHaveText(`${lengths[mode]} ${MODE_FACTS[mode].unit}`);
    }
  });
});
