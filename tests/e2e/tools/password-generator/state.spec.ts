import { test, expect, type Page } from '../_support/fixtures';
import { captureDownload } from '../_support/io';
import type { Rng } from '../_support/rng';
import {
  CLASS_KEYS, RANDOM_DEFAULTS, PASSPHRASE_DEFAULTS, SEPARATORS, RANDOM_LENGTH, WORD_COUNT, PIN_LENGTH,
  wordList, parsePassphrase, pinProblems, randomValueProblems, randomRandomConfig, randomPassphraseConfig,
  randomKeyspace, passphraseKeyspace, pinKeyspace, poolFor, classOf, describeRandom, describePassphrase,
  type Mode, type PassphraseConfig, type RandomConfig,
} from './oracle';
import { PasswordGenerator, ROUTE, SETTINGS_KEY, HISTORY_KEY } from './page';
import { expectStrength, expectMainValuePossible, expectAllPossible, seedStorage, encodings, waitUntilRecorded } from './checks';

/**
 * Where the randomness comes from, where generated values may and may not go,
 * and what the tool remembers between visits.
 */

const WORDS = new Set(wordList());
const phraseProblems = (config: PassphraseConfig) => (value: string) => {
  const parsed = parsePassphrase(value, config, WORDS);
  return typeof parsed === 'string' ? [parsed] : [];
};

interface RngProbe {
  mathCalls: number;
  mathStacks: string[];
  cryptoCalls: number;
}

/** Counts calls to Math.random and crypto.getRandomValues, and can pin either source to a constant. */
async function installRngProbe(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const probe = { mathCalls: 0, mathStacks: [] as string[], cryptoCalls: 0, freezeCrypto: false, freezeMath: false };
    (window as unknown as { __rngProbe: typeof probe }).__rngProbe = probe;
    const realRandom = Math.random.bind(Math);
    Math.random = () => {
      probe.mathCalls++;
      if (probe.mathStacks.length < 5) probe.mathStacks.push((new Error().stack ?? '').split('\n').slice(2, 6).join(' <- '));
      return probe.freezeMath ? 0.5 : realRandom();
    };
    const realValues = crypto.getRandomValues.bind(crypto);
    crypto.getRandomValues = (<T extends ArrayBufferView | null>(array: T): T => {
      probe.cryptoCalls++;
      if (probe.freezeCrypto && array) {
        new Uint8Array(array.buffer, array.byteOffset, array.byteLength).fill(0);
        return array;
      }
      return realValues(array as never) as T;
    }) as typeof crypto.getRandomValues;
  });
}

const resetProbe = (page: Page) => page.evaluate(() => {
  const probe = (window as unknown as { __rngProbe: RngProbe }).__rngProbe;
  probe.mathCalls = 0; probe.mathStacks = []; probe.cryptoCalls = 0;
});
const readProbe = (page: Page) => page.evaluate(() => {
  const probe = (window as unknown as { __rngProbe: RngProbe }).__rngProbe;
  return { mathCalls: probe.mathCalls, mathStacks: probe.mathStacks, cryptoCalls: probe.cryptoCalls };
});
const freeze = (page: Page, which: 'freezeCrypto' | 'freezeMath', on: boolean) => page.evaluate(([key, value]) => {
  (window as unknown as { __rngProbe: Record<string, boolean> }).__rngProbe[key as string] = value as boolean;
}, [which, on] as const);

const MODES: { mode: Mode; name: string }[] = [
  { mode: 'password', name: 'Random' },
  { mode: 'passphrase', name: 'Passphrase' },
  { mode: 'pin', name: 'PIN' },
];

test.describe('Source of randomness', () => {
  test('generation uses crypto.getRandomValues and never calls Math.random, in every mode, single and bulk', async ({ page }) => {
    await installRngProbe(page);
    const gen = new PasswordGenerator(page);
    await gen.open();
    for (const { mode, name } of MODES) {
      await gen.selectMode(mode);
      await gen.regenerateButton.click();
      await resetProbe(page);
      for (let i = 0; i < 10; i++) await gen.regenerateButton.click();
      await gen.generateBulk(50);
      const probe = await readProbe(page);
      expect.soft(
        probe.mathCalls,
        `${name} mode: Math.random was called ${probe.mathCalls} times while generating 10 single values and 50 bulk values; first callers:\n${probe.mathStacks.join('\n')}`,
      ).toBe(0);
      expect.soft(probe.cryptoCalls, `${name} mode: crypto.getRandomValues calls while generating 60 values`).toBeGreaterThan(0);
    }
  });

  test('values depend on crypto.getRandomValues alone: pinning it pins the output, pinning Math.random changes nothing', async ({ page }) => {
    await installRngProbe(page);
    const gen = new PasswordGenerator(page);
    await gen.open();
    for (const { mode, name } of MODES) {
      await gen.selectMode(mode);
      if (mode !== 'password') await gen.setLength(mode === 'pin' ? PIN_LENGTH.max : 6);

      // Math.random constant: values must keep changing.
      await freeze(page, 'freezeMath', true);
      const free: string[] = [];
      for (let i = 0; i < 6; i++) free.push(await gen.regenerate());
      expect.soft(new Set(free).size, `${name} mode with Math.random pinned to 0.5: 6 regenerated values should all differ (${free.join(' | ')})`).toBe(free.length);
      await freeze(page, 'freezeMath', false);

      // crypto.getRandomValues constant: no other source of variation may remain.
      await freeze(page, 'freezeCrypto', true);
      const before = (await readProbe(page)).cryptoCalls;
      const pinned: string[] = [];
      for (let i = 0; i < 6; i++) pinned.push(await gen.regenerate());
      expect.soft((await readProbe(page)).cryptoCalls, `${name} mode: Regenerate should ask crypto.getRandomValues for new values`).toBeGreaterThan(before);
      expect.soft(
        new Set(pinned).size,
        `${name} mode with crypto.getRandomValues pinned to zeros: every regenerated value should be identical, got ${[...new Set(pinned)].join(' | ')}`,
      ).toBe(1);
      await gen.bulkCount.selectOption('10');
      await gen.bulkGenerate.click();
      await expect(gen.bulkRowButtons).toHaveCount(10);
      expect.soft(new Set(await gen.bulkValues()).size, `${name} mode with crypto.getRandomValues pinned: all 10 bulk values should be identical`).toBe(1);
      await gen.bulkClear.click();
      await freeze(page, 'freezeCrypto', false);
    }
  });
});

test.describe('Where generated values go', () => {
  test('no generated value appears in a network request, the address bar, a cookie or sessionStorage', async ({ page, rng, evidence }) => {
    const requests: string[] = [];
    page.on('request', request => requests.push(`${request.method()} ${request.url()}\n${request.postData() ?? ''}`));
    const gen = new PasswordGenerator(page);
    await gen.open();

    const random = randomRandomConfig(rng, { length: rng.int(20, 40), classes: [...CLASS_KEYS] });
    const phrase = randomPassphraseConfig(rng, { words: rng.int(4, 8) });
    const secrets: string[] = [await expectMainValuePossible(gen, v => randomValueProblems(v, RANDOM_DEFAULTS), 'defaults')];
    const use = async (problems: (v: string) => string[], ctx: string) => {
      secrets.push(await expectMainValuePossible(gen, problems, ctx));
      for (let i = 0; i < 3; i++) secrets.push(await gen.regenerate());
      secrets.push(...await gen.generateBulk(10));
      await gen.copyButton.click();
      await gen.bulkCopyAll.click();
      await captureDownload(page, () => gen.bulkExport.click());
      await gen.hideButton().click();
      await gen.showButton().click();
      // Long enough on screen to be written to the history as well.
      secrets.push(await waitUntilRecorded(gen));
    };
    await gen.configureRandom(random);
    await use(v => randomValueProblems(v, random), describeRandom(random));
    await gen.configurePassphrase(phrase);
    await use(phraseProblems(phrase), describePassphrase(phrase));
    // A long PIN, so that a match with digits in an unrelated address cannot happen by chance.
    await gen.configurePin(PIN_LENGTH.max);
    await use(v => pinProblems(v, PIN_LENGTH.max), '16-digit PIN');
    await page.reload();
    await gen.waitForValue();
    secrets.push(await gen.read());

    const unique = [...new Set(secrets)].filter(v => v.length >= 12);
    await evidence.save('generated-values.json', unique);
    await evidence.save('requests.txt', requests.join('\n---\n'));
    const cookies = (await page.context().cookies()).map(c => `${c.name}=${c.value}`).join('; ');
    const session = await page.evaluate(() => Object.keys(window.sessionStorage).map(k => `${k}=${window.sessionStorage.getItem(k)}`).join('\n'));
    const settings = (await page.evaluate(key => window.localStorage.getItem(key), SETTINGS_KEY)) ?? '';
    const leaks: string[] = [];
    for (const value of unique) {
      for (const form of encodings(value)) {
        for (const request of requests) if (request.includes(form)) leaks.push(`"${value}" in request ${request.split('\n')[0]}`);
        if (page.url().includes(form)) leaks.push(`"${value}" in the address bar ${page.url()}`);
        if (cookies.includes(form)) leaks.push(`"${value}" in a cookie`);
        if (session.includes(form)) leaks.push(`"${value}" in sessionStorage`);
        if (settings.includes(form)) leaks.push(`"${value}" in the saved settings`);
      }
    }
    expect.soft(leaks, `${unique.length} generated values checked against ${requests.length} requests`).toEqual([]);
    expect.soft(new URL(page.url()).pathname + new URL(page.url()).search + new URL(page.url()).hash, 'the address stays the plain tool address').toBe(ROUTE);
    expect.soft(requests.filter(r => !r.startsWith('GET ')).map(r => r.split('\n')[0]), 'the tool sends nothing: requests other than GET').toEqual([]);
  });
});

// ---------------------------------------------------------------------------

interface Remembered {
  mode: Mode;
  random: RandomConfig;
  phrase: PassphraseConfig;
  pin: number;
}

function randomRemembered(rng: Rng, mode: Mode): Remembered {
  return {
    mode,
    random: randomRandomConfig(rng),
    // "+" is covered by its own test below.
    phrase: randomPassphraseConfig(rng, { separator: rng.pick(SEPARATORS.filter(s => s.value !== '+')).value }),
    pin: rng.int(PIN_LENGTH.min, PIN_LENGTH.max),
  };
}

const DEFAULTS: Remembered = { mode: 'password', random: RANDOM_DEFAULTS, phrase: PASSPHRASE_DEFAULTS, pin: 6 };

async function applyAll(gen: PasswordGenerator, state: Remembered) {
  await gen.configureRandom(state.random);
  await gen.configurePassphrase(state.phrase);
  await gen.configurePin(state.pin);
  await gen.selectMode(state.mode);
  // The tool saves on every change; wait for the last one before the page is left.
  await expect.poll(
    async () => JSON.parse((await gen.page.evaluate(key => window.localStorage.getItem(key), SETTINGS_KEY)) ?? '{}').mode,
    { message: `the selected mode (${state.mode}) should be saved in the browser` },
  ).toBe(state.mode);
}

/** Checks every remembered control in all three modes, then returns to the mode the page opened in. */
async function expectControls(gen: PasswordGenerator, state: Remembered, ctx: string) {
  for (const { mode } of MODES) {
    await expect.soft(gen.modeButton(mode), `${ctx}: ${mode} mode selected`).toHaveAttribute('aria-pressed', String(mode === state.mode));
  }
  await gen.selectMode('password');
  const random = await gen.controls();
  expect.soft(
    { length: random.length, classes: random.classes, requireEach: random.requireEach, avoidLookAlike: random.avoidLookAlike, avoidShellHostile: random.avoidShellHostile },
    `${ctx}: Random-mode controls (length slider, character types, three options)`,
  ).toEqual({
    length: state.random.length, classes: CLASS_KEYS.filter(key => state.random.classes.includes(key)), requireEach: state.random.requireEach,
    avoidLookAlike: state.random.avoidLookAlike, avoidShellHostile: state.random.avoidShellHostile,
  });
  await expect.soft(gen.poolSize, `${ctx}: character pool`).toHaveText(String(poolFor(state.random).length));
  await expectMainValuePossible(gen, v => randomValueProblems(v, state.random), `${ctx}: Random mode`);
  await expectStrength(gen, randomKeyspace(state.random), `${ctx}: Random mode`);

  await gen.selectMode('passphrase');
  const phrase = await gen.controls();
  expect.soft(
    { words: phrase.length, separator: SEPARATORS[phrase.separatorIndex]?.value, capitalise: phrase.capitalise, appendNumber: phrase.appendNumber },
    `${ctx}: Passphrase-mode controls (word slider, highlighted separator, two options)`,
  ).toEqual({ words: state.phrase.words, separator: state.phrase.separator, capitalise: state.phrase.capitalise, appendNumber: state.phrase.appendNumber });
  await expectMainValuePossible(gen, phraseProblems(state.phrase), `${ctx}: Passphrase mode`);
  await expectStrength(gen, passphraseKeyspace(state.phrase), `${ctx}: Passphrase mode`);

  await gen.selectMode('pin');
  expect.soft((await gen.controls()).length, `${ctx}: PIN length slider`).toBe(state.pin);
  await expectMainValuePossible(gen, v => pinProblems(v, state.pin), `${ctx}: PIN mode`);
  await expectStrength(gen, pinKeyspace(state.pin), `${ctx}: PIN mode`);

  await gen.selectMode(state.mode);
}

test.describe('Remembered settings', () => {
  test('the mode and every option of every mode are restored after a reload', async ({ page, rng, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const states = rng.shuffle(MODES).map(({ mode }) => randomRemembered(rng, mode));
    await evidence.save('settings.json', states);
    for (const state of states) {
      const ctx = `after reload, saved in ${state.mode} mode`;
      await applyAll(gen, state);
      await page.reload();
      await gen.waitForValue();
      await expectControls(gen, state, ctx);
    }
  });

  test('every separator choice is remembered after a reload', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    for (const { value, button } of SEPARATORS) {
      const config = { ...PASSPHRASE_DEFAULTS, separator: value };
      await gen.configurePassphrase(config);
      await expectMainValuePossible(gen, phraseProblems(config), `separator "${button}" before the reload`);
      await page.reload();
      await gen.waitForValue();
      await expect(gen.modeButton('passphrase'), 'Passphrase mode is restored').toHaveAttribute('aria-pressed', 'true');
      await expect.soft(gen.separatorButton(value), `separator "${button}" should still be selected after a reload`).toHaveClass(/btn-primary/, { timeout: 3_000 });
      const shown = await gen.read();
      expect.soft(phraseProblems(config)(shown), `value after the reload ("${shown}") should use separator "${button}"`).toEqual([]);
    }
  });

  test('what is not a setting starts fresh after a reload: bulk list, hidden state', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const first = await gen.read();
    await gen.generateBulk(25);
    await gen.hideButton().click();
    await page.reload();
    await gen.waitForValue();
    await expect.soft(gen.bulkRowButtons, 'bulk list after a reload').toHaveCount(0);
    await expect.soft(gen.hideButton(), 'the value is visible again after a reload').toBeVisible();
    expect.soft(await gen.read(), 'a reload generates a new value').not.toBe(first);
    await expectMainValuePossible(gen, v => randomValueProblems(v, RANDOM_DEFAULTS), 'after reload');
  });

  test('clearing the browser storage brings back the defaults in every mode', async ({ page, rng, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const state = randomRemembered(rng, rng.pick(MODES).mode);
    await evidence.save('settings.json', state);
    await applyAll(gen, state);
    await page.evaluate(() => { window.localStorage.clear(); window.sessionStorage.clear(); });
    const clearedAt = Date.now();
    await page.reload();
    await gen.waitForValue();
    await expectControls(gen, DEFAULTS, 'after clearing storage');
    await gen.selectMode('password');
    await waitUntilRecorded(gen);
    const stored = await gen.storedHistory();
    expect.soft(stored.filter(e => e.createdAt < clearedAt - 2_000), 'history entries of the earlier visit that survived clearing the storage').toEqual([]);
    await expect.soft(gen.historyRows, 'rows equal the entries recorded since').toHaveCount(stored.length);
  });
});

test.describe('Tampered or damaged storage', () => {
  const GARBAGE: { name: string; settings?: string; history?: string }[] = [
    { name: 'settings: cut-off JSON', settings: '{"mode":"pin","options":{' },
    { name: 'settings: null', settings: 'null' },
    { name: 'settings: a number', settings: '42' },
    { name: 'settings: a string', settings: '"passphrase"' },
    { name: 'settings: an array', settings: '[1,2,3]' },
    { name: 'settings: wrong types everywhere', settings: '{"mode":7,"options":"all","passphrase":[],"pinLength":"six"}' },
    { name: 'history: cut-off JSON', history: '[{"id":"a","password":"x' },
    { name: 'history: an object instead of a list', history: '{"password":"hunter2"}' },
    { name: 'history: entries of the wrong shape', history: '[1,"two",null,{"password":5},{"id":"a","password":"","mode":"pin","bits":1,"level":"weak","createdAt":1},{"id":"b","password":"abc","mode":"nope","bits":1,"level":"weak","createdAt":1},{"id":"c","password":"abc","mode":"pin","bits":-1,"level":"weak","createdAt":1},{"id":"d","password":"abc","mode":"pin","bits":1,"level":"mighty","createdAt":1}]' },
    { name: 'both keys: plain text', settings: 'not json at all', history: 'not json at all' },
  ];

  for (const item of GARBAGE) {
    test(`${item.name}: the tool opens with defaults and an empty history`, async ({ page }) => {
      const seeded: Record<string, string> = {};
      if (item.settings !== undefined) seeded[SETTINGS_KEY] = item.settings;
      if (item.history !== undefined) seeded[HISTORY_KEY] = item.history;
      await seedStorage(page, seeded);
      const startedAt = Date.now();
      const gen = new PasswordGenerator(page);
      await gen.open();
      await expectControls(gen, DEFAULTS, item.name);
      // The tool keeps working: the value on screen is recorded, and it is the only row.
      await waitUntilRecorded(gen);
      const stored = await gen.storedHistory();
      expect.soft(stored.filter(e => e.createdAt < startedAt - 2_000), `${item.name}: stored entries that were not recorded during this visit`).toEqual([]);
      await expect.soft(gen.historyRows, `${item.name}: rows equal the entries recorded during this visit`).toHaveCount(stored.length);
    });
  }

  test('saved numbers outside the allowed ranges and unknown choices fall back to the defaults', async ({ page, rng, evidence }) => {
    const badNumber = () => rng.pick<unknown>([0, -5, 3.5, 1e9, 129, '20', null, true, NaN]);
    const saved = {
      mode: 'pin',
      options: {
        length: rng.pick<unknown>([RANDOM_LENGTH.min - 1, RANDOM_LENGTH.max + 1, badNumber()]),
        uppercase: 'yes', lowercase: 1, numbers: null, symbols: 'false',
        excludeAmbiguous: 'true', excludeSimilar: 1, requireEachClass: 0,
      },
      passphrase: {
        wordCount: rng.pick<unknown>([WORD_COUNT.min - 1, WORD_COUNT.max + 1, badNumber()]),
        separator: rng.pick(['<b>', '--', '/', 'x', 5, null]),
        capitalize: 'no', appendNumber: 'yes',
      },
      pinLength: rng.pick<unknown>([PIN_LENGTH.min - 1, PIN_LENGTH.max + 1, badNumber()]),
    };
    const text = JSON.stringify(saved);
    await evidence.save('saved-settings.json', text);
    await seedStorage(page, { [SETTINGS_KEY]: text });
    const gen = new PasswordGenerator(page);
    await gen.open();
    // The mode is a valid choice and is kept; every other field is unusable.
    await expectControls(gen, { ...DEFAULTS, mode: 'pin' }, `saved settings ${text}`);
  });

  test('saved settings with every character type off are not accepted (the page itself never allows that state)', async ({ page, rng }) => {
    const length = rng.int(8, 30);
    const saved = {
      mode: 'password',
      options: { length, uppercase: false, lowercase: false, numbers: false, symbols: false, excludeAmbiguous: false, excludeSimilar: false, requireEachClass: true },
      passphrase: { wordCount: 4, separator: '-', capitalize: true, appendNumber: false },
      pinLength: 6,
    };
    await seedStorage(page, { [SETTINGS_KEY]: JSON.stringify(saved) });
    const gen = new PasswordGenerator(page);
    await gen.open();
    const states = await gen.classStates();
    const selected = CLASS_KEYS.filter(key => states[key]);
    const value = await gen.read();
    expect.soft(selected.length, 'at least one character type must be shown as selected').toBeGreaterThan(0);
    expect.soft(
      [...new Set([...value].map(classOf))].filter(key => !selected.includes(key)),
      `the value "${value}" contains character types that are not selected (selected: ${selected.join(', ') || 'none'})`,
    ).toEqual([]);
    await expect.soft(gen.poolSize, `a ${value.length}-character value is on screen, so the character pool cannot be 0`).not.toHaveText('0', { timeout: 3_000 });
    await expect.soft(gen.strengthDetail, 'a generated value is never marked "est."').not.toContainText('est.', { timeout: 3_000 });
  });

  test('markup stored in the history is shown as text and never runs', async ({ page }) => {
    const payload = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>';
    const entry = { id: 'x"><svg onload=window.__pwned=1>', password: payload, mode: 'password', bits: 50, level: 'weak', createdAt: Date.now() - 60_000 };
    await seedStorage(page, {
      [HISTORY_KEY]: JSON.stringify([entry]),
      [SETTINGS_KEY]: JSON.stringify({ mode: 'passphrase', passphrase: { wordCount: 4, separator: '<img src=x onerror="window.__pwned=1">', capitalize: true, appendNumber: false } }),
    });
    const gen = new PasswordGenerator(page);
    await gen.open();
    await expect(gen.historyRows).toHaveCount(1);
    const row = gen.historyRows.first();
    await row.getByRole('button', { name: /^Reveal password/ }).click();
    await expect.soft(row.locator('code'), 'the stored text is shown literally').toHaveText(payload);
    await expect.soft(gen.primary.locator('img, script, svg'), 'no element may be created from stored text').toHaveCount(0);
    expect.soft(await page.evaluate(() => (window as unknown as { __pwned?: number }).__pwned), 'stored markup must not execute').toBeUndefined();
    await expectMainValuePossible(gen, phraseProblems(PASSPHRASE_DEFAULTS), 'separator with markup is replaced by the default');
    expectAllPossible(await gen.generateBulk(5), phraseProblems(PASSPHRASE_DEFAULTS), 'bulk values after loading tampered settings');
  });
});
