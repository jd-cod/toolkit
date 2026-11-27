import { test, expect, withCommas } from '../_support/fixtures';
import {
  PASSPHRASE_DEFAULTS, SEPARATORS, WORD_COUNT, PIN_LENGTH, WORDLIST_SIZE, RANDOM_DEFAULTS, FALSE_FAILURE,
  wordList, parsePassphrase, passphraseKeyspace, pinKeyspace, pinProblems, randomKeyspace, bitsForKeyspace, labelForBits,
  log2Fixed2, chiSquareLimit, chiSquareUniform, repeatLimit, randomPassphraseConfig, describePassphrase,
  type PassphraseConfig,
} from './oracle';
import { PasswordGenerator } from './page';
import { expectStrength, expectAllPossible, expectMainValuePossible, tipTexts, displayedBits } from './checks';

/**
 * Passphrase and PIN modes, and the advice text all three modes share.
 */

const WORDS = new Set(wordList());

function passphraseProblems(config: PassphraseConfig) {
  return (value: string) => {
    const parsed = parsePassphrase(value, config, WORDS);
    return typeof parsed === 'string' ? [parsed] : [];
  };
}

async function expectSeparatorHighlight(gen: PasswordGenerator, separator: string, ctx: string) {
  for (const { value, button } of SEPARATORS) {
    await expect.soft(gen.separatorButton(value), `${ctx}: highlight of separator button "${button}"`)
      .toHaveClass(value === separator ? /btn-primary/ : /btn-secondary/);
  }
}

test.describe('Passphrase mode', () => {
  test('the word list the oracle reads holds the 7,776 distinct words the page announces', async ({ page }) => {
    expect(wordList().length, 'words in frontend/src/lib/password/wordlist.ts').toBe(WORDLIST_SIZE);
    expect(WORDS.size, 'distinct words (a repeated word would lower the real entropy per word)').toBe(WORDLIST_SIZE);
    const gen = new PasswordGenerator(page);
    await gen.open();
    await gen.selectMode('passphrase');
    await expect.soft(gen.passphraseHelp, 'word-list size in the note').toContainText(`${withCommas(WORDLIST_SIZE)}-word list`);
    await expect.soft(gen.passphraseHelp, `bits per word = log2(${WORDLIST_SIZE})`).toContainText(`${log2Fixed2(WORDLIST_SIZE)} bits per word`);
  });

  test('defaults, every word count 3–10 and every preset give that many list words, with the right entropy', async ({ page, rng }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    await gen.selectMode('passphrase');

    await expect.soft(gen.slider, 'default number of words').toHaveValue(String(PASSPHRASE_DEFAULTS.words));
    await expect.soft(gen.separatorButtons, 'separator choices').toHaveText(SEPARATORS.map(s => s.button));
    await expectSeparatorHighlight(gen, PASSPHRASE_DEFAULTS.separator, 'defaults');
    await expect.soft(gen.capitalise, '"Capitalise each word" default').toBeChecked();
    await expect.soft(gen.appendNumber, '"Append a random number" default').not.toBeChecked();
    await expectMainValuePossible(gen, passphraseProblems(PASSPHRASE_DEFAULTS), 'default passphrase');

    const counts = Array.from({ length: WORD_COUNT.max - WORD_COUNT.min + 1 }, (_, i) => WORD_COUNT.min + i);
    for (const words of rng.shuffle(counts)) {
      const config = { ...PASSPHRASE_DEFAULTS, words };
      const ctx = describePassphrase(config);
      await gen.setLength(words);
      await expect.soft(gen.lengthReadout, `${ctx}: readout`).toHaveText(`${words} words`);
      expectAllPossible(await gen.generateBulk(50), passphraseProblems(config), ctx);
      await expectMainValuePossible(gen, passphraseProblems(config), ctx);
      await expectStrength(gen, passphraseKeyspace(config), ctx);
    }

    for (const words of rng.shuffle(WORD_COUNT.presets)) {
      const config = { ...PASSPHRASE_DEFAULTS, words };
      await gen.preset(words).click();
      await expect.soft(gen.slider, `preset ${words}: slider`).toHaveValue(String(words));
      await expect.soft(gen.lengthReadout, `preset ${words}: readout`).toHaveText(`${words} words`);
      for (const other of WORD_COUNT.presets) {
        await expect.soft(gen.preset(other), `preset ${words} pressed: highlight of preset ${other}`)
          .toHaveClass(other === words ? /btn-primary/ : /btn-secondary/);
      }
      await expectMainValuePossible(gen, passphraseProblems(config), `preset ${words}`);
      await expectStrength(gen, passphraseKeyspace(config), `preset ${words}`);
    }

    await gen.slider.focus();
    await page.keyboard.press('Home');
    await expect.soft(gen.lengthReadout, 'Home key: fewest words').toHaveText(`${WORD_COUNT.min} words`);
    await page.keyboard.press('End');
    await expect.soft(gen.lengthReadout, 'End key: most words').toHaveText(`${WORD_COUNT.max} words`);
    await expectMainValuePossible(gen, passphraseProblems({ ...PASSPHRASE_DEFAULTS, words: WORD_COUNT.max }), 'End key');
  });

  test('every separator, with random capitalisation, number and word count, shapes hundreds of values correctly', async ({ page, rng, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const configs = [
      ...rng.shuffle(SEPARATORS).map(s => randomPassphraseConfig(rng, { separator: s.value })),
      { words: WORD_COUNT.min, separator: '-', capitalise: false, appendNumber: true },
      { words: WORD_COUNT.max, separator: ' ', capitalise: true, appendNumber: true },
      ...Array.from({ length: 3 }, () => randomPassphraseConfig(rng)),
    ];
    await evidence.save('passphrase-configurations.json', configs);
    const samples: Record<string, string[]> = {};
    for (const config of configs) {
      const ctx = describePassphrase(config);
      await gen.configurePassphrase(config);
      await expectSeparatorHighlight(gen, config.separator, ctx);
      const values = await gen.collect(200);
      samples[ctx] = values.slice(0, 10);
      expectAllPossible(values, passphraseProblems(config), ctx);
      await expectMainValuePossible(gen, passphraseProblems(config), ctx);
      await expectStrength(gen, passphraseKeyspace(config), ctx);
      expect.soft(new Set(values).size, `${ctx}: 200 values of ${bitsForKeyspace(passphraseKeyspace(config))} bits should all differ`).toBe(values.length);
    }
    await evidence.save('passphrase-samples.json', samples);
  });

  test('the option labels can be clicked, and switching an option off again restores the plain form', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    await gen.selectMode('passphrase');
    const lower = { ...PASSPHRASE_DEFAULTS, capitalise: false };
    const numbered = { ...lower, appendNumber: true };

    await gen.primary.getByText('Capitalise each word').click();
    await expect.soft(gen.capitalise, 'clicking the label switches capitalisation off').not.toBeChecked();
    await expectMainValuePossible(gen, passphraseProblems(lower), 'capitalisation off');
    await expectStrength(gen, passphraseKeyspace(lower), 'capitalisation off (same entropy)');

    await gen.primary.getByText('Append a random number (0–99)').click();
    await expect.soft(gen.appendNumber, 'clicking the label switches the number on').toBeChecked();
    await expectMainValuePossible(gen, passphraseProblems(numbered), 'number on');
    await expectStrength(gen, passphraseKeyspace(numbered), 'number on (100 times more values)');

    await gen.primary.getByText('Append a random number (0–99)').click();
    await gen.primary.getByText('Capitalise each word').click();
    await expectMainValuePossible(gen, passphraseProblems(PASSPHRASE_DEFAULTS), 'both options back to default');
    await expectStrength(gen, passphraseKeyspace(PASSPHRASE_DEFAULTS), 'both options back to default');
  });

  test('words are drawn from the whole list about equally, and no word keeps coming back', async ({ page, rng, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const config = randomPassphraseConfig(rng, { words: WORD_COUNT.max, appendNumber: false });
    await gen.configurePassphrase(config);
    const values = await gen.collect(400);
    expectAllPossible(values, passphraseProblems(config), describePassphrase(config));

    const index = new Map(wordList().map((word, i) => [word, i]));
    const drawn = values.flatMap(value => {
      const parsed = parsePassphrase(value, config, WORDS);
      return typeof parsed === 'string' ? [] : parsed.words;
    });
    // 16 equal slices of the alphabetical list: a generator that only reaches part of it leaves slices empty.
    const buckets = new Array(16).fill(0);
    for (const word of drawn) buckets[Math.floor(((index.get(word) ?? 0) * 16) / WORDLIST_SIZE)]++;
    const statistic = chiSquareUniform(buckets);
    const limit = chiSquareLimit(buckets.length - 1);
    await evidence.save('word-buckets.json', { words: drawn.length, buckets });
    expect.soft(
      statistic,
      `${drawn.length} words spread over 16 equal slices of the list as ${JSON.stringify(buckets)}: chi-square ${statistic.toFixed(1)}, `
      + `a uniform source stays below ${limit.toFixed(1)} with probability 1 - ${FALSE_FAILURE}`,
    ).toBeLessThan(limit);

    const tally = new Map<string, number>();
    for (const word of drawn) tally.set(word, (tally.get(word) ?? 0) + 1);
    const [topWord, topCount] = [...tally.entries()].sort((a, b) => b[1] - a[1])[0];
    const allowed = repeatLimit(drawn.length, WORDLIST_SIZE);
    expect.soft(topCount, `most frequent word "${topWord}" appears ${topCount} times in ${drawn.length} draws (limit ${allowed})`).toBeLessThan(allowed);

    // Every position of the phrase is drawn independently: no position is stuck on one word.
    for (let position = 0; position < config.words; position++) {
      const atPosition = new Set(values.map(v => (parsePassphrase(v, config, WORDS) as { words: string[] }).words?.[position]));
      expect.soft(atPosition.size, `distinct words at position ${position + 1} over ${values.length} passphrases`).toBeGreaterThan(values.length / 2);
    }
  });

  test('the appended number is a whole number 0–99 spread over the full range', async ({ page, rng, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const config = randomPassphraseConfig(rng, { words: WORD_COUNT.min, appendNumber: true });
    await gen.configurePassphrase(config);
    const values = await gen.collect(700);
    expectAllPossible(values, passphraseProblems(config), describePassphrase(config));
    const numbers = values.map(v => Number(v.match(/[0-9]+$/)?.[0] ?? NaN));
    const tens = new Array(10).fill(0);
    for (const n of numbers) if (n >= 0 && n <= 99) tens[Math.floor(n / 10)]++;
    await evidence.save('appended-numbers.json', { tens, numbers });
    const statistic = chiSquareUniform(tens);
    const limit = chiSquareLimit(9);
    expect.soft(
      statistic,
      `${numbers.length} appended numbers by tens (0–9, 10–19, …): ${JSON.stringify(tens)}; chi-square ${statistic.toFixed(1)}, limit ${limit.toFixed(1)}`,
    ).toBeLessThan(limit);
    await expectStrength(gen, passphraseKeyspace(config), describePassphrase(config));
  });

  test('the note under the options makes a true statement about a four-word passphrase', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    await gen.selectMode('passphrase');
    const note = (await gen.passphraseHelp.textContent()) ?? '';
    const claim = note.match(/(Three|Four|Five|Six|Seven) words is comfortably above the (\d+)-bit target/);
    expect(claim, `the note should state how a word count compares with a bit target; it reads: "${note}"`).toBeTruthy();
    const words = ['Three', 'Four', 'Five', 'Six', 'Seven'].indexOf(claim![1]) + 3;
    const target = Number(claim![2]);
    const bits = bitsForKeyspace(passphraseKeyspace({ words, appendNumber: false }));
    expect.soft(
      bits,
      `the note says "${claim![0]}", but ${words} words from a ${withCommas(WORDLIST_SIZE)}-word list carry ${bits} bits `
      + `(the page's own meter shows ${bits} bits, "${labelForBits(bits)}", for ${words} words)`,
    ).toBeGreaterThan(target);
  });
});

test.describe('PIN mode', () => {
  test('every PIN length 4–16 and every preset gives digits only, with the right entropy and warning', async ({ page, rng }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    await gen.selectMode('pin');
    const lengths = Array.from({ length: PIN_LENGTH.max - PIN_LENGTH.min + 1 }, (_, i) => PIN_LENGTH.min + i);

    const check = async (digits: number, ctx: string) => {
      await expect.soft(gen.slider, `${ctx}: slider`).toHaveValue(String(digits));
      await expect.soft(gen.lengthReadout, `${ctx}: readout`).toHaveText(`${digits} digits`);
      await expectMainValuePossible(gen, v => pinProblems(v, digits), ctx);
      const want = await expectStrength(gen, pinKeyspace(digits), ctx);
      await expect.soft(gen.pinWarning, `${ctx}: warning names bits per digit and the bits of this PIN`)
        .toContainText(`Only ${log2Fixed2(10)} bits per digit — a ${digits}-digit PIN has ${want.bits} bits`);
    };

    for (const digits of rng.shuffle(lengths)) {
      await gen.setLength(digits);
      await gen.awaitLength(digits);
      expectAllPossible(await gen.generateBulk(50), v => pinProblems(v, digits), `${digits}-digit PIN`);
      await check(digits, `${digits}-digit PIN`);
    }
    for (const digits of rng.shuffle(PIN_LENGTH.presets)) {
      await gen.preset(digits).click();
      for (const other of PIN_LENGTH.presets) {
        await expect.soft(gen.preset(other), `preset ${digits} pressed: highlight of preset ${other}`)
          .toHaveClass(other === digits ? /btn-primary/ : /btn-secondary/);
      }
      await check(digits, `PIN preset ${digits}`);
    }
    await gen.slider.focus();
    await page.keyboard.press('Home');
    await check(PIN_LENGTH.min, 'Home key (shortest PIN)');
    await page.keyboard.press('End');
    await check(PIN_LENGTH.max, 'End key (longest PIN)');
  });

  test('digits are used about equally often, and a PIN may start with 0 without losing a digit', async ({ page, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    await gen.configurePin(PIN_LENGTH.max);
    const long = await gen.collect(200);
    expectAllPossible(long, v => pinProblems(v, PIN_LENGTH.max), '16-digit PINs');
    const text = long.join('');
    const counts = Array.from({ length: 10 }, (_, d) => text.split(String(d)).length - 1);
    const statistic = chiSquareUniform(counts);
    const limit = chiSquareLimit(9);
    await evidence.save('digit-counts.json', counts);
    expect.soft(
      statistic,
      `digit counts over ${text.length} digits ${JSON.stringify(counts)}: chi-square ${statistic.toFixed(1)}, a uniform source stays below ${limit.toFixed(1)}`,
    ).toBeLessThan(limit);

    await gen.configurePin(PIN_LENGTH.min);
    const short = await gen.collect(300);
    expectAllPossible(short, v => pinProblems(v, PIN_LENGTH.min), '4-digit PINs');
    // 300 uniform PINs with none starting with 0 has probability 0.9^300 < 1e-13.
    expect.soft(short.filter(v => v.startsWith('0')).length, '4-digit PINs starting with 0 among 300').toBeGreaterThan(0);
  });
});

test.describe('Advice under the strength meter', () => {
  test('advice never talks about a different mode than the one selected', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const findings: string[] = [];
    const scan = async (ctx: string, forbidden: RegExp, why: string) => {
      const tips = await tipTexts(gen);
      expect.soft(tips.length, `${ctx}: at least one line of advice`).toBeGreaterThan(0);
      const bits = await displayedBits(gen);
      for (const tip of tips) if (forbidden.test(tip)) findings.push(`${ctx} (${bits} bits) ${why}: "${tip}"`);
    };

    await gen.selectMode('password');
    for (const length of [4, 6, 8, 12, 16, 20, 32]) {
      await gen.setLength(length);
      await gen.awaitLength(length);
      await scan(`Random mode, ${length} characters`, /\bPIN\b|\bwords?\b/i, 'is told about PINs or words');
    }
    await gen.selectMode('passphrase');
    for (let words = WORD_COUNT.min; words <= WORD_COUNT.max; words++) {
      await gen.setLength(words);
      await scan(`Passphrase mode, ${words} words`, /\bPIN\b/, 'is told about PINs');
    }
    await gen.selectMode('pin');
    for (let digits = PIN_LENGTH.min; digits <= PIN_LENGTH.max; digits++) {
      await gen.setLength(digits);
      await gen.awaitLength(digits);
      await scan(`PIN mode, ${digits} digits`, /\bwords?\b/i, 'is told to add words');
    }
    expect.soft(findings, 'advice lines that describe another mode').toEqual([]);
  });

  test('advice never calls a value solid or strong while the label next to it says Weak', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const findings: string[] = [];
    const scan = async (ctx: string) => {
      const label = (await gen.strengthLabel.textContent()) ?? '';
      const bits = await displayedBits(gen);
      for (const tip of await tipTexts(gen)) {
        if (/^(Solid|Strong)\b/.test(tip) && /Weak/.test(label)) findings.push(`${ctx}: label "${label}" (${bits} bits) next to advice "${tip}"`);
      }
    };
    await gen.selectMode('passphrase');
    for (const appendNumber of [false, true]) {
      await gen.appendNumber.setChecked(appendNumber);
      for (let words = WORD_COUNT.min; words <= WORD_COUNT.max; words++) {
        await gen.setLength(words);
        await scan(`passphrase, ${words} words${appendNumber ? ' + number' : ''}`);
      }
    }
    await gen.selectMode('pin');
    for (let digits = PIN_LENGTH.min; digits <= PIN_LENGTH.max; digits++) {
      await gen.setLength(digits);
      await gen.awaitLength(digits);
      await scan(`PIN, ${digits} digits`);
    }
    expect.soft(findings, 'advice that contradicts the strength label').toEqual([]);
  });

  test('word counts quoted in the advice clear the bit levels they are said to clear', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    // Three words plus a number is 45 bits, where the advice quotes word counts.
    const config = { ...PASSPHRASE_DEFAULTS, words: 3, appendNumber: true };
    await gen.configurePassphrase(config);
    await expectStrength(gen, passphraseKeyspace(config), describePassphrase(config));
    const advice = (await tipTexts(gen)).join(' ');
    const claim = advice.match(/(\d+)\+ words clears (\d+) bits, (\d+) clears (\d+)/);
    expect(claim, `advice for 3 words + number should quote word counts; it reads: "${advice}"`).toBeTruthy();
    for (const [words, level] of [[Number(claim![1]), Number(claim![2])], [Number(claim![3]), Number(claim![4])]]) {
      const bits = bitsForKeyspace(passphraseKeyspace({ words, appendNumber: false }));
      expect.soft(bits, `advice says ${words} words clears ${level} bits; ${words} words carry ${bits} bits`).toBeGreaterThanOrEqual(level);
    }
  });

  test('a full-strength default password is described as high entropy and nothing else', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    await expectStrength(gen, randomKeyspace(RANDOM_DEFAULTS), 'defaults');
    expect.soft(await tipTexts(gen), 'advice for the default 20-character password').toEqual(['High entropy for resistance to offline guessing.']);
  });
});
