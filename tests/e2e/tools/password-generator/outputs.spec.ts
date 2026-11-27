import { test, expect } from '../_support/fixtures';
import { captureDownload, readClipboard, clearClipboard } from '../_support/io';
import { parseCsv } from '../_support/csv';
import {
  BULK_COUNTS, RANDOM_DEFAULTS, PIN_LENGTH, WORD_COUNT,
  wordList, parsePassphrase, pinProblems, randomValueProblems, randomRandomConfig, randomPassphraseConfig,
  randomKeyspace, describeRandom, describePassphrase, type Mode,
} from './oracle';
import { PasswordGenerator } from './page';
import { expectAllPossible, expectMainValuePossible, expectStrength } from './checks';

/**
 * Everything that leaves the page: the clipboard and the CSV file. Also the
 * Hide/Show switch, because what is copied must not depend on it.
 */

const WORDS = new Set(wordList());

interface Setup {
  mode: Mode;
  label: string;
  apply: (gen: PasswordGenerator) => Promise<void>;
  problems: (value: string) => string[];
}

/** One randomised configuration per mode, with the rule its values must obey. */
function setups(rng: import('../_support/rng').Rng): Setup[] {
  const random = randomRandomConfig(rng, { length: rng.int(16, 48), classes: ['uppercase', 'lowercase', 'numbers', 'symbols'] });
  const phrase = randomPassphraseConfig(rng, { separator: ' ', words: rng.int(4, WORD_COUNT.max) });
  const digits = rng.int(PIN_LENGTH.min, PIN_LENGTH.max);
  return [
    { mode: 'password', label: describeRandom(random), apply: gen => gen.configureRandom(random), problems: v => randomValueProblems(v, random) },
    {
      mode: 'passphrase', label: describePassphrase(phrase), apply: gen => gen.configurePassphrase(phrase),
      problems: v => { const parsed = parsePassphrase(v, phrase, WORDS); return typeof parsed === 'string' ? [parsed] : []; },
    },
    { mode: 'pin', label: `${digits}-digit PIN`, apply: gen => gen.configurePin(digits), problems: v => pinProblems(v, digits) },
  ];
}

/**
 * Presses "Copy Password" and returns the value that was on screen. A settings
 * change regenerates the value a moment later, so the comparison is repeated
 * until the value did not change around the click.
 */
async function copyMainValue(gen: PasswordGenerator, ctx: string): Promise<string> {
  let copied = '';
  await expect(async () => {
    await clearClipboard(gen.page);
    const before = await gen.read();
    await gen.copyButton.click();
    const clipboard = await readClipboard(gen.page);
    expect(await gen.read(), `${ctx}: the value should not change while it is copied`).toBe(before);
    expect(clipboard, `${ctx}: clipboard after "Copy Password"`).toBe(before);
    copied = before;
  }).toPass({ timeout: 15_000 });
  return copied;
}

test.describe('Copy and Hide/Show', () => {
  test('Copy Password puts exactly the displayed value on the clipboard in every mode, and confirms', async ({ page, rng, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const all = setups(rng);
    await evidence.save('configurations.json', all.map(s => s.label));
    for (const setup of all) {
      await setup.apply(gen);
      await expectMainValuePossible(gen, setup.problems, setup.label);
      const copied = await copyMainValue(gen, setup.label);
      expect.soft(setup.problems(copied), `${setup.label}: the copied value "${copied}" is a possible value`).toEqual([]);
      await expect.soft(gen.primary.getByRole('button', { name: /Copied!$/ }).first(), `${setup.label}: button confirms the copy`).toBeVisible();
      await expect.soft(gen.primary.getByRole('button', { name: /Copy Password$/ }), `${setup.label}: label returns after about two seconds`).toBeVisible({ timeout: 20_000 });
    }
  });

  test('Hide replaces the value with dots, Copy still copies the real value, Show brings the same value back', async ({ page, rng }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    for (const setup of setups(rng)) {
      const ctx = setup.label;
      await setup.apply(gen);
      await expectMainValuePossible(gen, setup.problems, ctx);
      const value = await copyMainValue(gen, ctx);
      const strength = await gen.strengthDetail.textContent();

      await gen.hideButton().click();
      await expect(gen.showButton(), `${ctx}: the button now offers "Show password"`).toBeVisible();
      await expect.soft(gen.value, `${ctx}: hidden value shows only dots`).toHaveText(/^•+$/);
      await expect.soft(gen.value, `${ctx}: hidden value must not contain the value`).not.toContainText(value);
      await expect.soft(gen.strengthDetail, `${ctx}: strength is unchanged while hidden`).toHaveText(strength ?? '');

      await clearClipboard(page);
      await gen.copyButton.click();
      await expect.poll(() => readClipboard(page), { message: `${ctx}: Copy while hidden copies the real value` }).toBe(value);

      await gen.showButton().click();
      await expect(gen.hideButton(), `${ctx}: the button offers "Hide password" again`).toBeVisible();
      await expect.soft(gen.value, `${ctx}: Show brings back the same value, not a new one`).toHaveText(value);

      // Regenerating while hidden changes the value without revealing it.
      await gen.hideButton().click();
      await gen.regenerateButton.click();
      await expect.soft(gen.value, `${ctx}: still hidden after Regenerate`).toHaveText(/^•+$/);
      await clearClipboard(page);
      await gen.copyButton.click();
      await expect.poll(() => readClipboard(page), { message: `${ctx}: Copy while hidden puts a value on the clipboard` }).not.toBe('');
      const fresh = await readClipboard(page);
      expect.soft(setup.problems(fresh), `${ctx}: value generated while hidden ("${fresh}") is a possible value`).toEqual([]);
      await gen.showButton().click();
      await expect.soft(gen.value, `${ctx}: Show reveals the value that was copied while hidden`).toHaveText(fresh);
    }
  });
});

test.describe('Bulk generation', () => {
  test('every count (5, 10, 25, 50) lists exactly that many numbered values for the current settings, in every mode', async ({ page, rng, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const all = setups(rng);
    await evidence.save('configurations.json', all.map(s => s.label));
    for (const setup of all) {
      await setup.apply(gen);
      for (const count of rng.shuffle(BULK_COUNTS)) {
        const ctx = `${setup.label}, ${count} values`;
        const values = await gen.generateBulk(count);
        expect.soft(values.length, `${ctx}: rows in the list`).toBe(count);
        expect.soft(await gen.bulkIndexes(), `${ctx}: row numbers`).toEqual(Array.from({ length: count }, (_, i) => String(i + 1).padStart(2, '0')));
        expectAllPossible(values, setup.problems, ctx);
        await expect.soft(gen.bulkCopyAll, `${ctx}: Copy All offered`).toBeVisible();
        await expect.soft(gen.bulkExport, `${ctx}: Export CSV offered`).toBeVisible();
        await expect.soft(gen.bulkClear, `${ctx}: Clear offered`).toBeVisible();
      }
    }
  });

  test('a new batch replaces the previous one, and the single value above is left alone', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const main = await expectMainValuePossible(gen, v => randomValueProblems(v, RANDOM_DEFAULTS), 'defaults');
    const first = await gen.generateBulk(25);
    const second = await gen.generateBulk(10);
    expect.soft(second.length, 'second batch size').toBe(10);
    expect.soft(second.filter(v => first.includes(v)), 'values of the first batch still listed after the second').toEqual([]);
    await expect.soft(gen.value, 'the single value is not touched by bulk generation').toHaveText(main);
    await expectStrength(gen, randomKeyspace(RANDOM_DEFAULTS), 'after bulk generation');
  });

  test('Copy All copies the list one value per line, and each row button copies its own value', async ({ page, rng, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    for (const setup of setups(rng)) {
      await setup.apply(gen);
      const count = rng.pick(BULK_COUNTS);
      const values = await gen.generateBulk(count);
      await evidence.save(`bulk-${setup.mode}.txt`, values.join('\n'));

      await clearClipboard(page);
      await gen.bulkCopyAll.click();
      await expect.soft(gen.bulkCard.getByRole('button', { name: /Copied!$/ }), `${setup.label}: Copy All confirms`).toBeVisible();
      expect.soft(await readClipboard(page), `${setup.label}: clipboard after Copy All (${count} values, one per line)`).toBe(values.join('\n'));

      for (const index of rng.sample(values.map((_, i) => i), 3)) {
        await clearClipboard(page);
        const button = gen.bulkCard.getByRole('button', { name: `Copy password ${index + 1}`, exact: true });
        await button.click();
        await expect.soft(button.locator('i.bi-check-lg'), `${setup.label}: row ${index + 1} shows a check mark after copying`).toBeVisible();
        expect.soft(await readClipboard(page), `${setup.label}: clipboard after copying row ${index + 1}`).toBe(values[index]);
      }
    }
  });

  test('Export CSV downloads generated-passwords.csv with the same values, numbered, in the same order', async ({ page, rng, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    for (const setup of setups(rng)) {
      await setup.apply(gen);
      const count = rng.pick(BULK_COUNTS);
      const values = await gen.generateBulk(count);
      const file = await captureDownload(page, () => gen.bulkExport.click());
      await evidence.save(`export-${setup.mode}.csv`, file.text);
      const ctx = `${setup.label}, ${count} values`;
      expect.soft(file.filename, `${ctx}: file name`).toBe('generated-passwords.csv');
      const rows = parseCsv(file.text);
      expect.soft(rows[0], `${ctx}: header row`).toEqual(['index', 'password']);
      expect.soft(rows.length - 1, `${ctx}: data rows`).toBe(count);
      expect.soft(rows.slice(1).map(r => r[0]), `${ctx}: index column`).toEqual(values.map((_, i) => String(i + 1)));
      expect.soft(rows.slice(1).map(r => r[1]), `${ctx}: password column equals the list on the page`).toEqual(values);
      expect.soft(rows.slice(1).filter(r => r.length !== 2), `${ctx}: rows that do not have exactly two cells`).toEqual([]);
    }
  });

  test('Clear removes the list and its buttons, and a new batch can be generated afterwards', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    await gen.generateBulk(5);
    await gen.bulkClear.click();
    await expect.soft(gen.bulkRowButtons, 'rows after Clear').toHaveCount(0);
    await expect.soft(gen.bulkCopyAll, 'Copy All after Clear').toHaveCount(0);
    await expect.soft(gen.bulkExport, 'Export CSV after Clear').toHaveCount(0);
    await expect.soft(gen.bulkClear, 'Clear after Clear').toHaveCount(0);
    await expect.soft(gen.bulkCount, 'the chosen count is kept').toHaveValue('5');
    const again = await gen.generateBulk();
    expect.soft(again.length, 'batch generated after Clear').toBe(5);
    expectAllPossible(again, v => randomValueProblems(v, RANDOM_DEFAULTS), 'batch after Clear');
  });
});
