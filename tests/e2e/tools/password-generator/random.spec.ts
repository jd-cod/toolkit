import { test, expect } from '../_support/fixtures';
import {
  CLASS_KEYS, CLASS_CHARS, LOOK_ALIKE, SHELL_HOSTILE_DOCUMENTED, POSIX_SHELL_SPECIAL, RANDOM_DEFAULTS, RANDOM_LENGTH,
  STRENGTH_ORDER, FALSE_FAILURE,
  poolFor, classPool, classOf, randomValueProblems, randomKeyspace, keyspaceWithEveryClass, bitsForKeyspace,
  labelForBits, expectedStrength, log2Fixed2, chiSquareLimit, chiSquareUniform, binomialRange,
  randomRandomConfig, describeRandom, type ClassKey, type RandomConfig,
} from './oracle';
import { PasswordGenerator } from './page';
import { expectStrength, expectAllPossible, expectMainValuePossible, displayedBits } from './checks';

/**
 * Random mode: every generated value must be a possible value for the selected
 * settings, the pool and entropy figures must follow from the settings, and the
 * values must behave like uniform draws.
 */

async function expectPoolReadout(gen: PasswordGenerator, config: RandomConfig, ctx: string) {
  const pool = poolFor(config).length;
  await expect.soft(gen.poolSize, `${ctx}: "Character pool"`).toHaveText(String(pool));
  await expect.soft(gen.entropyPerChar, `${ctx}: "Entropy per character" for a pool of ${pool}`).toHaveText(`${log2Fixed2(pool)} bits`);
}

test.describe('Random mode — length', () => {
  test('every length preset sets the slider, the readout and the length of the value', async ({ page, rng }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    for (const n of rng.shuffle(RANDOM_LENGTH.presets)) {
      const config = { ...RANDOM_DEFAULTS, length: n };
      await gen.preset(n).click();
      await expect.soft(gen.slider, `preset ${n}: slider`).toHaveValue(String(n));
      await expect.soft(gen.lengthReadout, `preset ${n}: readout`).toHaveText(`${n} characters`);
      for (const other of RANDOM_LENGTH.presets) {
        await expect.soft(gen.preset(other), `preset ${n} pressed: highlight of preset ${other}`)
          .toHaveClass(other === n ? /btn-primary/ : /btn-secondary/);
      }
      await expectMainValuePossible(gen, v => randomValueProblems(v, config), `preset ${n}`);
      await expectStrength(gen, randomKeyspace(config), `preset ${n}`);
    }
    // A length that is not a preset highlights none of them.
    await gen.setLength(21);
    for (const other of RANDOM_LENGTH.presets) {
      await expect.soft(gen.preset(other), `length 21: preset ${other} must not be highlighted`).toHaveClass(/btn-secondary/);
    }
  });

  test('the slider stops at 4 and 128 and follows the keyboard and the mouse', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const expectLength = async (n: number, how: string) => {
      await expect.soft(gen.slider, `${how}: slider value`).toHaveValue(String(n));
      await expect.soft(gen.lengthReadout, `${how}: readout`).toHaveText(`${n} characters`);
      await expectMainValuePossible(gen, v => randomValueProblems(v, { ...RANDOM_DEFAULTS, length: n }), how);
    };

    await gen.slider.focus();
    await page.keyboard.press('ArrowRight');
    await expectLength(21, 'ArrowRight from 20');
    await page.keyboard.press('ArrowLeft');
    await page.keyboard.press('ArrowLeft');
    await expectLength(19, 'ArrowLeft twice from 21');
    await page.keyboard.press('Home');
    await expectLength(RANDOM_LENGTH.min, 'Home key (shortest value)');
    await page.keyboard.press('ArrowLeft');
    await expectLength(RANDOM_LENGTH.min, 'ArrowLeft at the minimum');
    await page.keyboard.press('End');
    await expectLength(RANDOM_LENGTH.max, 'End key (longest value)');
    await page.keyboard.press('ArrowRight');
    await expectLength(RANDOM_LENGTH.max, 'ArrowRight at the maximum');

    const box = await gen.slider.boundingBox();
    expect(box, 'slider should have a size').toBeTruthy();
    // The track is a thin pill; aim a few pixels inside its ends.
    await gen.slider.click({ position: { x: 6, y: box!.height / 2 } });
    await expectLength(RANDOM_LENGTH.min, 'mouse click at the left end of the slider');
    await gen.slider.click({ position: { x: box!.width - 6, y: box!.height / 2 } });
    await expectLength(RANDOM_LENGTH.max, 'mouse click at the right end of the slider');
  });
});

test.describe('Random mode — strength figures', () => {
  test('bits, label, crack time and meter are right for every length 4–128, for a small and a random pool', async ({ page, rng, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    // Digits only moves 3.3 bits per step, so every crack-time unit and every label is reached.
    const digitsOnly: RandomConfig = { length: 4, classes: ['numbers'], requireEach: false, avoidLookAlike: false, avoidShellHostile: false };
    const other = randomRandomConfig(rng, { requireEach: false });
    await evidence.save('pools.json', { digitsOnly, other });
    const fills = new Map<string, Set<string>>();

    for (const base of [digitsOnly, other]) {
      await gen.configureRandom(base);
      const lengths = base === digitsOnly
        ? Array.from({ length: RANDOM_LENGTH.max - RANDOM_LENGTH.min + 1 }, (_, i) => RANDOM_LENGTH.min + i)
        : [RANDOM_LENGTH.min, RANDOM_LENGTH.max, ...Array.from({ length: 40 }, () => rng.int(RANDOM_LENGTH.min, RANDOM_LENGTH.max))];
      const mismatches: string[] = [];
      for (const length of lengths) {
        const config = { ...base, length };
        await gen.slider.fill(String(length));
        const want = expectedStrength(randomKeyspace(config));
        // The value and the figures computed from it follow the slider one frame later.
        let shot = await gen.strengthSnapshot();
        await expect.poll(async () => {
          shot = await gen.strengthSnapshot();
          return shot.value.length;
        }, { message: `length ${length}: the displayed value should have ${length} characters` }).toBe(length);
        const ctx = describeRandom(config);
        if (shot.readout !== `${length} characters`) mismatches.push(`${ctx}: readout "${shot.readout}", expected "${length} characters"`);
        if (shot.detail !== want.detail) mismatches.push(`${ctx}: shows "${shot.detail}", expected "${want.detail}"`);
        if (shot.label !== want.label) mismatches.push(`${ctx}: label "${shot.label}", expected "${want.label}" for ${want.bits} bits`);
        if (shot.tips.length === 0) mismatches.push(`${ctx}: no advice line under the meter`);
        if (!fills.has(shot.label)) fills.set(shot.label, new Set());
        fills.get(shot.label)!.add(shot.fill);
      }
      expect.soft(mismatches, `strength line for pool of ${poolFor(base).length} characters (${base.classes.join('+')})`).toEqual([]);
    }

    // The meter: one fill width per label, growing with the label, full only for Very Strong.
    const widths = STRENGTH_ORDER.map(label => ({ label, widths: [...(fills.get(label) ?? [])] }));
    await evidence.save('meter-fill.json', widths);
    for (const { label, widths: seen } of widths) {
      expect.soft(seen.length, `meter fill for "${label}" should be one fixed width, saw ${JSON.stringify(seen)}`).toBe(1);
    }
    const numbers = widths.map(w => parseFloat(w.widths[0]));
    expect.soft(numbers, 'meter fill should grow from Very Weak to Very Strong').toEqual([...numbers].sort((a, b) => a - b));
    expect.soft(new Set(numbers).size, 'each label should have its own meter fill').toBe(STRENGTH_ORDER.length);
    expect.soft(numbers[numbers.length - 1], 'meter is full for Very Strong').toBe(100);
  });

  test('pool size and entropy per character are right for every combination of character types and avoid options', async ({ page, rng }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const length = rng.int(RANDOM_LENGTH.min, 40);
    const combos: RandomConfig[] = [];
    // Gray-code order: each step switches one character type, as a user clicking through them would.
    for (const [avoidLookAlike, avoidShellHostile] of rng.shuffle([[false, false], [true, false], [false, true], [true, true]])) {
      for (let step = 1; step < 16; step++) {
        const mask = step ^ (step >> 1);
        combos.push({
          length, requireEach: false, avoidLookAlike, avoidShellHostile,
          classes: CLASS_KEYS.filter((_, i) => Math.floor(mask / 2 ** i) % 2 === 1),
        });
      }
    }
    for (const config of combos) {
      const ctx = describeRandom(config);
      await gen.configureRandom(config);
      await expectPoolReadout(gen, config, ctx);
      await expectStrength(gen, randomKeyspace(config), ctx);
    }
    // Back to everything on: the original figures return.
    await gen.configureRandom({ ...RANDOM_DEFAULTS, length });
    await expectPoolReadout(gen, RANDOM_DEFAULTS, 'all types on again');
  });

  test('with "at least one of each selected type" on, the entropy shown does not exceed what the number of possible values allows', async ({ page, evidence }) => {
    // Requiring one character of every type removes values (four characters from four types can only
    // be one of each: 26*26*10*23*4! = 3,731,520 values, not 85^4). Entropy is log2 of the number of
    // possible values, so the figure and the label must come from that count.
    const gen = new PasswordGenerator(page);
    await gen.open();
    const cases: RandomConfig[] = [
      { ...RANDOM_DEFAULTS, length: 4 },
      { ...RANDOM_DEFAULTS, length: 6 },
      { ...RANDOM_DEFAULTS, length: 8 },
      { ...RANDOM_DEFAULTS, length: 12 },
      { ...RANDOM_DEFAULTS, length: 6, avoidLookAlike: true, avoidShellHostile: true },
      { ...RANDOM_DEFAULTS, length: 5, classes: ['uppercase', 'lowercase', 'numbers'] },
    ];
    const report: object[] = [];
    for (const config of cases) {
      await gen.configureRandom(config);
      const possible = keyspaceWithEveryClass(config);
      const bound = bitsForKeyspace(possible);
      const shown = await displayedBits(gen);
      const label = await gen.strengthLabel.textContent();
      report.push({ config: describeRandom(config), possibleValues: possible.toString(), bitsAllowed: bound, bitsShown: shown, labelShown: label, labelAllowed: labelForBits(bound) });
      expect.soft(
        shown,
        `${describeRandom(config)}: only ${possible.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',')} values are possible (${bound} bits), `
        + `but the page shows ${shown} bits (pool ^ length = ${bitsForKeyspace(randomKeyspace(config))} bits, which counts values the option forbids)`,
      ).toBeLessThanOrEqual(bound);
      expect.soft(label, `${describeRandom(config)}: strength label for ${bound} bits of real keyspace`).toBe(labelForBits(bound));
    }
    await evidence.save('entropy-with-required-types.json', report);
  });
});

test.describe('Random mode — generated values', () => {
  test('hundreds of values per configuration are all possible values for the selected settings', async ({ page, rng, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const singleClass = CLASS_KEYS.map(key => randomRandomConfig(rng, { classes: [key], length: rng.int(RANDOM_LENGTH.min, 40) }));
    const configs: RandomConfig[] = [
      ...singleClass,
      { ...RANDOM_DEFAULTS, length: RANDOM_LENGTH.min },                       // as short as the number of required types
      { ...RANDOM_DEFAULTS, length: RANDOM_LENGTH.max, avoidLookAlike: true, avoidShellHostile: true },
      { ...RANDOM_DEFAULTS, requireEach: false },
      ...Array.from({ length: 8 }, () => randomRandomConfig(rng)),
    ];
    await evidence.save('random-configurations.json', configs);
    const samples: Record<string, string[]> = {};

    for (const config of configs) {
      const ctx = describeRandom(config);
      await gen.configureRandom(config);
      const values = await gen.collect(200);
      samples[ctx] = values.slice(0, 20);
      expectAllPossible(values, v => randomValueProblems(v, config), ctx);

      const seen = new Set([...values.join('')].map(classOf));
      for (const key of config.classes) {
        expect.soft(seen.has(key), `${ctx}: ${key} characters should occur somewhere in ${values.length} values`).toBe(true);
      }
      await expectMainValuePossible(gen, v => randomValueProblems(v, config), ctx);
      await expectPoolReadout(gen, config, ctx);
      await expectStrength(gen, randomKeyspace(config), ctx);
    }
    await evidence.save('value-samples.json', samples);
  });

  test('"at least one of each selected type" is what guarantees every type, also at the shortest length', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const strict: RandomConfig = { ...RANDOM_DEFAULTS, length: RANDOM_LENGTH.min, requireEach: true };
    const loose: RandomConfig = { ...strict, requireEach: false };
    const lacksAType = (value: string) => CLASS_KEYS.some(key => ![...value].some(c => classOf(c) === key));

    await gen.configureRandom(strict);
    const guaranteed = await gen.collect(300);
    expectAllPossible(guaranteed, v => randomValueProblems(v, strict), 'option on, 4 characters, 4 types');

    // Without the option a 4-character value holds all four types only about 7% of the time,
    // so 300 values that all do would mean the option is not really off.
    await gen.configureRandom(loose);
    const free = await gen.collect(300);
    expectAllPossible(free, v => randomValueProblems(v, loose), 'option off, 4 characters, 4 types');
    expect.soft(free.filter(lacksAType).length, 'option off: some 4-character values should lack a type').toBeGreaterThan(0);

    await gen.configureRandom(strict);
    expectAllPossible(await gen.collect(100), v => randomValueProblems(v, strict), 'option on again');
  });

  test('the two "avoid" options drop exactly the characters their hints name, and the pool count matches what is generated', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();

    const hint = await gen.primary.locator('label', { hasText: 'Avoid look-alike characters' }).textContent();
    const named = (hint?.match(/Drops (.+?) —/)?.[1] ?? '').split(' ');
    expect.soft(named, 'characters named in the "Avoid look-alike characters" hint').toEqual(LOOK_ALIKE);
    await expect.soft(gen.primary.locator('label', { hasText: 'Avoid shell-hostile symbols' }), 'shell-hostile hint')
      .toContainText('Drops quotes, backslash, brackets and spaces');

    for (const [avoidLookAlike, avoidShellHostile] of [[false, false], [true, false], [false, true], [true, true]]) {
      const config: RandomConfig = { length: RANDOM_LENGTH.max, classes: [...CLASS_KEYS], requireEach: false, avoidLookAlike, avoidShellHostile };
      const ctx = describeRandom(config);
      await gen.configureRandom(config);
      // 6,400 characters: a pool character missing by chance has probability below 1e-30.
      const seen = new Set((await gen.collect(50)).join(''));
      const pool = poolFor(config);
      expect.soft(pool.filter(c => !seen.has(c)), `${ctx}: pool characters that never appear in 6,400 generated characters`).toEqual([]);
      expect.soft([...seen].filter(c => !pool.includes(c)), `${ctx}: generated characters outside the pool`).toEqual([]);
      if (avoidLookAlike) expect.soft(LOOK_ALIKE.filter(c => seen.has(c)), `${ctx}: look-alike characters that still appear`).toEqual([]);
      if (avoidShellHostile) expect.soft(SHELL_HOSTILE_DOCUMENTED.filter(c => seen.has(c)), `${ctx}: quotes, backslash, brackets or spaces that still appear`).toEqual([]);
      await expect.soft(gen.poolSize, `${ctx}: "Character pool" should equal the ${seen.size} distinct characters actually generated`).toHaveText(String(seen.size));
      await expectPoolReadout(gen, config, ctx);
    }
  });

  test('with "Avoid shell-hostile symbols" on, no value contains a character the shell treats specially', async ({ page }) => {
    // POSIX Shell Command Language 2.2: | & ; < > ( ) $ ` \ " ' space tab newline must be quoted
    // to stand for themselves. A password holding one of them breaks an unquoted command line.
    const gen = new PasswordGenerator(page);
    await gen.open();
    const config: RandomConfig = { length: RANDOM_LENGTH.max, classes: [...CLASS_KEYS], requireEach: false, avoidLookAlike: false, avoidShellHostile: true };
    await gen.configureRandom(config);
    const seen = new Set((await gen.collect(50)).join(''));
    expect.soft(
      POSIX_SHELL_SPECIAL.filter(c => seen.has(c)),
      'shell-special characters found in values generated with "Avoid shell-hostile symbols" on',
    ).toEqual([]);
  });

  test('the last selected character type cannot be switched off', async ({ page, rng }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    for (const key of rng.shuffle(CLASS_KEYS) as ClassKey[]) {
      const config: RandomConfig = { length: rng.int(8, 24), classes: [key], requireEach: rng.bool(), avoidLookAlike: false, avoidShellHostile: false };
      const ctx = `only ${key} selected`;
      await gen.configureRandom(config);
      await gen.classButton(key).click();
      await expect.soft(gen.classButton(key), `${ctx}: pressing it again must leave it selected`).toHaveAttribute('aria-pressed', 'true');
      await expect.soft(gen.poolSize, `${ctx}: pool`).toHaveText(String(CLASS_CHARS[key].length));
      expectAllPossible(await gen.generateBulk(25), v => randomValueProblems(v, config), ctx);
      await expectMainValuePossible(gen, v => randomValueProblems(v, config), ctx);
      await expectStrength(gen, randomKeyspace(config), ctx);
    }
  });

  test('Regenerate produces a new value every time, each valid for the settings', async ({ page, rng, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const config = randomRandomConfig(rng, { length: rng.int(16, 64) });
    await evidence.save('configuration.json', config);
    await gen.configureRandom(config);
    const values = [await expectMainValuePossible(gen, v => randomValueProblems(v, config), 'before Regenerate')];
    for (let i = 0; i < 30; i++) values.push(await gen.regenerate());
    expectAllPossible(values, v => randomValueProblems(v, config), describeRandom(config));
    expect.soft(new Set(values).size, `31 consecutive values should all differ (${describeRandom(config)})`).toBe(values.length);
    await expectStrength(gen, randomKeyspace(config), 'after 30 regenerations');
  });
});

test.describe('Random mode — randomness quality', () => {
  test('every pool character is used about equally often (chi-square over tens of thousands of characters)', async ({ page, rng, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    // Without "at least one of each" every character is an independent uniform draw from the pool.
    const configs = [
      { ...RANDOM_DEFAULTS, length: RANDOM_LENGTH.max, requireEach: false },
      randomRandomConfig(rng, { length: RANDOM_LENGTH.max, requireEach: false }),
    ];
    await evidence.save('configurations.json', configs);
    for (const config of configs) {
      const ctx = describeRandom(config);
      await gen.configureRandom(config);
      const text = (await gen.collect(300)).join('');
      const pool = poolFor(config);
      const counts = pool.map(c => text.split(c).length - 1);
      const statistic = chiSquareUniform(counts);
      const limit = chiSquareLimit(pool.length - 1);
      await evidence.save(`counts-${pool.length}.json`, Object.fromEntries(pool.map((c, i) => [c, counts[i]])));
      expect.soft(counts.reduce((a, b) => a + b, 0), `${ctx}: every generated character belongs to the pool`).toBe(text.length);
      expect.soft(pool.filter((_, i) => counts[i] === 0), `${ctx}: pool characters never generated in ${text.length} characters`).toEqual([]);
      expect.soft(
        statistic,
        `${ctx}: chi-square of character counts over ${text.length} characters is ${statistic.toFixed(1)}; `
        + `a uniform source stays below ${limit.toFixed(1)} with probability 1 - ${FALSE_FAILURE} (expected count per character ${(text.length / pool.length).toFixed(0)}, `
        + `min ${Math.min(...counts)}, max ${Math.max(...counts)})`,
      ).toBeLessThan(limit);
    }
  });

  test('required character types land in every position (no fixed layout such as "first character is a capital")', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const config: RandomConfig = { ...RANDOM_DEFAULTS, length: 4 };
    await gen.configureRandom(config);
    const values = await gen.collect(1000);
    // With 4 characters and 4 required types each position holds each type a quarter of the time.
    const range = binomialRange(values.length, 0.25, FALSE_FAILURE / 16);
    for (let position = 0; position < 4; position++) {
      for (const key of CLASS_KEYS) {
        const count = values.filter(v => classOf(v[position] ?? '') === key).length;
        expect.soft(
          count >= range.min && count <= range.max,
          `position ${position + 1} holds a ${key} character in ${count} of ${values.length} values; expected about ${values.length / 4} (allowed ${range.min}–${range.max})`,
        ).toBe(true);
      }
    }
    // Within a type the characters must vary too.
    for (const key of CLASS_KEYS) {
      const used = new Set(values.flatMap(v => [...v].filter(c => classOf(c) === key)));
      const pool = classPool(key, config);
      expect.soft(used.size, `${key}: distinct characters used in ${values.length} values (pool of ${pool.length})`).toBe(pool.length);
    }
  });

  test('a bulk batch of strong values contains no duplicate, and two batches share nothing', async ({ page, rng }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const config = randomRandomConfig(rng, { length: rng.int(16, 40) });
    await gen.configureRandom(config);
    const first = await gen.generateBulk(50);
    const second = await gen.generateBulk(50);
    const all = [...first, ...second];
    expect.soft(new Set(all).size, `${describeRandom(config)}: 100 values of ${bitsForKeyspace(randomKeyspace(config))} bits should all differ`).toBe(all.length);
  });
});
