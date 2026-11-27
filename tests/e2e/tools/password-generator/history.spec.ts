import { test, expect, type Page } from '../_support/fixtures';
import { readClipboard, clearClipboard } from '../_support/io';
import type { Rng } from '../_support/rng';
import {
  HISTORY_LIMIT, RANDOM_DEFAULTS, PIN_LENGTH,
  containsText, expectedStrength, randomKeyspace, passphraseKeyspace, pinKeyspace, labelForBits,
  randomRandomConfig, randomPassphraseConfig, describeRandom, describePassphrase,
  fullTimestamp, relativeTimeText, calendarDay, normaliseSpaces, type Mode, type StrengthExpectation,
} from './oracle';
import { PasswordGenerator, HISTORY_KEY, type HistoryRow } from './page';
import { seedStorage, waitUntilRecorded } from './checks';

/**
 * "Recent passwords": what is recorded, what each row shows, and that removing
 * entries really removes them. The page promises: "History stays in this
 * browser (up to 25 entries)" and, for bulk values, "These are not saved to history."
 */

interface StoredEntry {
  id: string;
  password: string;
  mode: Mode;
  bits: number;
  level: string;
  createdAt: number;
}

const levelSlug = (label: string) => label.toLowerCase().replace(' ', '-');
const MASK = /^•+$/;

/** Stored entries as an earlier visit would have left them; each has its own length so rows can be told apart while hidden. */
function makeEntries(rng: Rng, count: number, now: number, ages?: number[]): StoredEntry[] {
  return Array.from({ length: count }, (_, i) => {
    const bits = rng.int(10, 200);
    return {
      id: rng.string(16, '0123456789abcdef'),
      password: rng.string(30 + i, 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#%^*-_=+?'),
      mode: rng.pick(['password', 'passphrase', 'pin'] as Mode[]),
      bits,
      level: levelSlug(labelForBits(bits)),
      createdAt: now - (ages ? ages[i] : (i + 1) * 90_000),
    };
  });
}

function rowByLength(rows: HistoryRow[], password: string): HistoryRow | undefined {
  return rows.find(row => row.length === String(password.length));
}

/** Advances the page clock until the history counter reads `count`. */
async function advanceUntilCount(page: Page, gen: PasswordGenerator, count: number): Promise<void> {
  await expect(async () => {
    await page.clock.fastForward(2_000);
    await expect(gen.historyCount).toHaveText(`${count}/${HISTORY_LIMIT}`, { timeout: 1_000 });
  }, `history counter should reach ${count}/${HISTORY_LIMIT}`).toPass({ timeout: 20_000 });
}

test.describe('History — recording', () => {
  test('the first value is recorded with its length, composition, strength and time, and can be revealed and hidden', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    const openedAt = Date.now();
    await gen.open();
    const value = await waitUntilRecorded(gen);
    await expect(gen.historyCount, 'counter').toHaveText(`1/${HISTORY_LIMIT}`);
    const want = expectedStrength(randomKeyspace(RANDOM_DEFAULTS));
    const [stored] = await gen.storedHistory();
    const [row] = await gen.readHistory();

    expect.soft(row.shown, 'the value is hidden in the table until revealed').toMatch(MASK);
    expect.soft(row.length, `Length column for "${value}"`).toBe(String(value.length));
    expect.soft(row.contains, `Contains column for "${value}"`).toBe(containsText(value));
    expect.soft(row.label, 'Strength label').toBe(want.label);
    expect.soft(row.bits, 'Strength bits').toBe(`${want.bits}b`);
    expect.soft(row.generated, 'Generated column').toBe('Just now');
    expect.soft(stored.createdAt, 'recorded time lies between opening the page and now').toBeGreaterThanOrEqual(openedAt - 2_000);
    expect.soft(stored.createdAt, 'recorded time lies between opening the page and now').toBeLessThanOrEqual(Date.now() + 2_000);
    const stamp = fullTimestamp(stored.createdAt);
    expect.soft(normaliseSpaces(row.generatedTitle), 'tooltip of the Generated column').toBe(stamp);
    expect.soft(normaliseSpaces(row.revealName), 'name of the reveal button').toBe(`Reveal password from ${stamp}`);
    expect.soft(normaliseSpaces(row.copyName), 'name of the copy button').toBe(`Copy password from ${stamp}`);
    expect.soft(normaliseSpaces(row.deleteName), 'name of the delete button').toBe(`Delete password from ${stamp}`);
    expect.soft({ mode: stored.mode, bits: stored.bits, level: stored.level }, 'stored entry').toEqual({ mode: 'password', bits: want.bits, level: levelSlug(want.label) });

    const first = gen.historyRows.first();
    await first.getByRole('button', { name: /^Reveal password/ }).click();
    await expect.soft(first.locator('code'), 'revealed value').toHaveText(value);
    await first.getByRole('button', { name: /^Hide password from/ }).click();
    await expect.soft(first.locator('code'), 'hidden again with the eye button').toHaveText(MASK);
    await first.locator('code').click();
    await expect.soft(first.locator('code'), 'clicking the dots reveals the value too').toHaveText(value);
    await first.locator('code').click();
    await expect.soft(first.locator('code'), 'clicking the value hides it').toHaveText(MASK);
  });

  test('values from all three modes are listed newest first, each with the strength of the settings that made it', async ({ page, rng, evidence }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const random = randomRandomConfig(rng, { length: rng.int(8, 40) });
    const phrase = randomPassphraseConfig(rng);
    const digits = rng.int(PIN_LENGTH.min, PIN_LENGTH.max);
    const steps: { label: string; mode: Mode; apply: () => Promise<void>; want: StrengthExpectation }[] = rng.shuffle([
      { label: describeRandom(random), mode: 'password' as Mode, apply: () => gen.configureRandom(random), want: expectedStrength(randomKeyspace(random)) },
      { label: describePassphrase(phrase), mode: 'passphrase' as Mode, apply: () => gen.configurePassphrase(phrase), want: expectedStrength(passphraseKeyspace(phrase)) },
      { label: `${digits}-digit PIN`, mode: 'pin' as Mode, apply: () => gen.configurePin(digits), want: expectedStrength(pinKeyspace(digits)) },
    ]);
    await evidence.save('steps.json', steps.map(s => s.label));

    const known = new Map<string, { label: string; mode: Mode; want: StrengthExpectation }>();
    known.set(await waitUntilRecorded(gen), { label: 'default settings', mode: 'password', want: expectedStrength(randomKeyspace(RANDOM_DEFAULTS)) });
    for (const step of steps) {
      await step.apply();
      known.set(await waitUntilRecorded(gen), step);
    }

    const stored = await gen.storedHistory();
    await evidence.save('stored-history.json', stored);
    await expect(gen.historyCount, 'counter equals the number of stored entries').toHaveText(`${stored.length}/${HISTORY_LIMIT}`);
    for (let i = 0; i < stored.length; i++) {
      await gen.historyRows.nth(i).getByRole('button', { name: /^Reveal password/ }).click();
    }
    const rows = await gen.readHistory();
    expect.soft(rows.map(r => r.shown), 'rows, newest first, equal the stored entries').toEqual(stored.map(e => e.password));
    expect.soft([...known.keys()].reverse().filter(v => !stored.some(e => e.password === v)), 'values that stayed on screen but were not recorded').toEqual([]);

    for (const [value, { label, mode, want }] of known) {
      const row = rows.find(r => r.shown === value);
      const entry = stored.find(e => e.password === value);
      if (!row || !entry) continue;
      expect.soft(row.length, `${label}: Length column`).toBe(String(value.length));
      expect.soft(row.contains, `${label}: Contains column for "${value}"`).toBe(containsText(value));
      expect.soft(row.label, `${label}: Strength label`).toBe(want.label);
      expect.soft(row.bits, `${label}: Strength bits`).toBe(`${want.bits}b`);
      expect.soft(row.generated, `${label}: Generated column`).toBe('Just now');
      expect.soft(entry.mode, `${label}: stored mode`).toBe(mode);
    }
  });

  test('with "Save to history" off nothing is recorded; switching it on records the value then on screen', async ({ page }) => {
    await page.clock.install();
    const gen = new PasswordGenerator(page);
    await gen.open();
    await advanceUntilCount(page, gen, 1);
    const before = await gen.storedHistory();

    await gen.saveToHistory.uncheck();
    const unseen: string[] = [];
    for (let i = 0; i < 4; i++) {
      unseen.push(await gen.regenerate());
      await page.clock.fastForward(5_000);
    }
    await gen.setLength(33);
    await gen.awaitLength(33);
    unseen.push(await gen.read());
    await page.clock.fastForward(10_000);

    await expect.soft(gen.historyCount, 'counter while saving is off').toHaveText(`1/${HISTORY_LIMIT}`);
    const dump = await gen.browserStorageDump();
    expect.soft(unseen.filter(v => dump.includes(v)), 'values generated while "Save to history" was off that are in browser storage').toEqual([]);
    expect.soft(await gen.storedHistory(), 'stored history while saving is off').toEqual(before);
    await expect.soft(gen.historyRows, 'entries recorded earlier stay listed').toHaveCount(1);

    await gen.saveToHistory.check();
    await advanceUntilCount(page, gen, 2);
    const stored = await gen.storedHistory();
    expect.soft(stored[0].password, 'switching it on records the value on screen').toBe(await gen.read());
    expect.soft(stored.map(e => e.password).filter(v => unseen.slice(0, -1).includes(v)), 'earlier unsaved values must not appear afterwards').toEqual([]);
  });

  test('bulk values are not saved to history, as the bulk card says', async ({ page }) => {
    await page.clock.install();
    const gen = new PasswordGenerator(page);
    await gen.open();
    await advanceUntilCount(page, gen, 1);
    const bulk = [...await gen.generateBulk(50), ...await gen.generateBulk(25)];
    await page.clock.fastForward(10_000);
    await expect.soft(gen.historyCount, 'counter after two bulk batches').toHaveText(`1/${HISTORY_LIMIT}`);
    const dump = await gen.browserStorageDump();
    expect.soft(bulk.filter(v => dump.includes(v)), 'bulk values found in browser storage').toEqual([]);
  });

  test('the history keeps the newest 25 entries and drops the oldest', async ({ page, rng, evidence }) => {
    const entries = makeEntries(rng, HISTORY_LIMIT, Date.now());
    await evidence.save('stored-before.json', entries);
    await seedStorage(page, { [HISTORY_KEY]: JSON.stringify(entries) });
    const gen = new PasswordGenerator(page);
    await gen.open();
    await expect(gen.historyRows, 'a full history is listed completely').toHaveCount(HISTORY_LIMIT);
    const value = await waitUntilRecorded(gen);

    await expect.soft(gen.historyCount, 'counter at the limit').toHaveText(`${HISTORY_LIMIT}/${HISTORY_LIMIT}`);
    await expect.soft(gen.historyRows, 'rows at the limit').toHaveCount(HISTORY_LIMIT);
    const rows = await gen.readHistory();
    expect.soft(rows.map(r => r.length), 'lengths of the rows: the new value, then the 24 newest earlier entries in order')
      .toEqual([String(value.length), ...entries.slice(0, HISTORY_LIMIT - 1).map(e => String(e.password.length))]);
    const stored = await gen.storedHistory();
    expect.soft(stored.map(e => e.password), 'stored entries').toEqual([value, ...entries.slice(0, HISTORY_LIMIT - 1).map(e => e.password)]);
  });
});

test.describe('History — rows of an earlier visit', () => {
  test('entries survive a reload unchanged and hidden again', async ({ page }) => {
    const gen = new PasswordGenerator(page);
    await gen.open();
    const values = [await waitUntilRecorded(gen)];
    for (let i = 0; i < 2; i++) {
      await gen.regenerateButton.click();
      values.unshift(await waitUntilRecorded(gen));
    }
    await gen.historyRows.first().getByRole('button', { name: /^Reveal password/ }).click();
    const before = await gen.storedHistory();

    await page.reload();
    await gen.waitForValue();
    const fresh = await waitUntilRecorded(gen);
    const after = await gen.storedHistory();
    expect.soft(after.slice(1), 'entries of the first visit after the reload').toEqual(before);
    expect.soft(after[0].password, 'the value generated after the reload is added on top').toBe(fresh);
    await expect.soft(gen.historyCount, 'counter after the reload').toHaveText(`${values.length + 1}/${HISTORY_LIMIT}`);
    const rows = await gen.readHistory();
    expect.soft(rows.every(r => MASK.test(r.shown)), 'every row is hidden again after a reload').toBe(true);
    for (let i = 0; i < values.length; i++) {
      await gen.historyRows.nth(i + 1).getByRole('button', { name: /^Reveal password/ }).click();
      await expect.soft(gen.historyRows.nth(i + 1).locator('code'), `row ${i + 2} after the reload`).toHaveText(values[i]);
    }
  });

  test('every column of stored entries of every age is shown correctly', async ({ page, rng, evidence }) => {
    // A fixed "now" makes the age boundaries exact (59.999 s is "Just now", 60 s is "1m ago").
    const now = Date.UTC(2026, rng.int(0, 11), rng.int(1, 28), 20, rng.int(0, 59), rng.int(0, 59));
    await page.clock.setFixedTime(now);
    const SEC = 1_000, MIN = 60 * SEC, HOUR = 60 * MIN, DAY = 24 * HOUR;
    const ages = [
      20 * SEC, MIN - 1, MIN, 5 * MIN + 30 * SEC, HOUR - 1, HOUR, 3 * HOUR + 10 * MIN, DAY - 1,
      DAY, 30 * HOUR, 2 * DAY, 3 * DAY + 12 * HOUR, 7 * DAY - 1, 7 * DAY, 10 * DAY, 400 * DAY,
    // "Yesterday" is checked here only for entries that really are from the previous calendar day.
    ].filter(age => age < DAY || age >= 2 * DAY || calendarDay(now) - calendarDay(now - age) === 1);
    const entries = makeEntries(rng, ages.length, now, ages);
    await evidence.save('stored-history.json', { now, nowText: fullTimestamp(now), entries });
    await seedStorage(page, { [HISTORY_KEY]: JSON.stringify(entries) });

    const gen = new PasswordGenerator(page);
    await gen.open();
    await waitUntilRecorded(gen);
    await expect(gen.historyCount).toHaveText(`${entries.length + 1}/${HISTORY_LIMIT}`);
    const rows = (await gen.readHistory()).slice(1);
    expect(rows.length, 'one row per stored entry').toBe(entries.length);

    entries.forEach((entry, i) => {
      const row = rows[i];
      const ctx = `entry made ${fullTimestamp(entry.createdAt)} (${Math.round(ages[i] / 1000)} s before ${fullTimestamp(now)})`;
      const stamp = fullTimestamp(entry.createdAt);
      expect.soft(row.shown, `${ctx}: hidden`).toMatch(MASK);
      expect.soft(row.length, `${ctx}: Length`).toBe(String(entry.password.length));
      expect.soft(row.contains, `${ctx}: Contains for "${entry.password}"`).toBe(containsText(entry.password));
      expect.soft(row.label, `${ctx}: Strength label for stored level ${entry.level}`).toBe(labelForBits(entry.bits));
      expect.soft(row.bits, `${ctx}: Strength bits`).toBe(`${entry.bits}b`);
      expect.soft(row.generated, `${ctx}: Generated`).toBe(relativeTimeText(entry.createdAt, now));
      expect.soft(normaliseSpaces(row.generatedTitle), `${ctx}: tooltip`).toBe(stamp);
      expect.soft(normaliseSpaces(row.revealName), `${ctx}: reveal button name`).toBe(`Reveal password from ${stamp}`);
      expect.soft(normaliseSpaces(row.copyName), `${ctx}: copy button name`).toBe(`Copy password from ${stamp}`);
      expect.soft(normaliseSpaces(row.deleteName), `${ctx}: delete button name`).toBe(`Delete password from ${stamp}`);
    });
  });

  test('an entry is called "Yesterday" only when it was made on the previous calendar day', async ({ page, rng }) => {
    // Pick a moment early in the day, so that 47 hours earlier is two calendar days back.
    const base = Date.UTC(2026, rng.int(0, 11), rng.int(1, 28));
    const age = 47 * 3_600_000;
    const now = Array.from({ length: 24 }, (_, h) => base + h * 3_600_000).find(t => calendarDay(t) - calendarDay(t - age) === 2);
    expect(now, 'a moment at which 47 hours ago is two calendar days ago').toBeTruthy();
    await page.clock.setFixedTime(now!);
    const [entry] = makeEntries(rng, 1, now!, [age]);
    await seedStorage(page, { [HISTORY_KEY]: JSON.stringify([entry]) });

    const gen = new PasswordGenerator(page);
    await gen.open();
    await expect(gen.historyRows.first()).toBeVisible();
    const row = rowByLength(await gen.readHistory(), entry.password);
    expect(row, 'the stored entry should be listed').toBeTruthy();
    expect.soft(
      row!.generated,
      `entry made ${fullTimestamp(entry.createdAt)}, viewed ${fullTimestamp(now!)} (two calendar days later) must not be labelled "Yesterday"`,
    ).not.toBe('Yesterday');
  });

  test('the copy button of a row copies that row\'s value without revealing it', async ({ page, rng }) => {
    const entries = makeEntries(rng, 5, Date.now());
    await seedStorage(page, { [HISTORY_KEY]: JSON.stringify(entries) });
    const gen = new PasswordGenerator(page);
    await gen.open();
    await expect(gen.historyRows).toHaveCount(entries.length);
    for (const index of rng.sample([0, 1, 2, 3, 4], 3)) {
      const row = gen.historyRows.nth(index);
      await clearClipboard(page);
      await row.getByRole('button', { name: /^Copy password from/ }).click();
      await expect.soft(row.locator('button i.bi-check-lg'), `row ${index + 1}: check mark after copying`).toBeVisible();
      expect.soft(await readClipboard(page), `row ${index + 1}: clipboard`).toBe(entries[index].password);
      await expect.soft(row.locator('code'), `row ${index + 1}: stays hidden`).toHaveText(MASK);
    }
  });
});

test.describe('History — removing entries', () => {
  test('deleting a row erases the entry from the browser, so it does not come back after a reload', async ({ page, rng, evidence }) => {
    const entries = makeEntries(rng, 4, Date.now());
    await evidence.save('stored-history.json', entries);
    await seedStorage(page, { [HISTORY_KEY]: JSON.stringify(entries) });
    const gen = new PasswordGenerator(page);
    await gen.open();
    await waitUntilRecorded(gen);
    await expect(gen.historyRows).toHaveCount(entries.length + 1);

    const victim = entries[rng.int(0, entries.length - 1)];
    await gen.historyRows.filter({ has: page.locator('td', { hasText: new RegExp(`^${victim.password.length}$`) }) })
      .getByRole('button', { name: /^Delete password from/ }).click();
    await expect.soft(gen.historyRows, 'rows after deleting one').toHaveCount(entries.length);
    await expect.soft(gen.historyCount, 'counter after deleting one').toHaveText(`${entries.length}/${HISTORY_LIMIT}`, { timeout: 3_000 });
    expect.soft(rowByLength(await gen.readHistory(), victim.password), 'the deleted row is no longer listed').toBeUndefined();
    expect.soft(
      (await gen.storedHistory()).some(e => e.password === victim.password),
      `the deleted password "${victim.password}" must be gone from localStorage ("${HISTORY_KEY}")`,
    ).toBe(false);

    await page.reload();
    await gen.waitForValue();
    await expect(gen.historyRows.first()).toBeVisible();
    expect.soft(rowByLength(await gen.readHistory(), victim.password), 'after a reload the deleted entry must not be listed again').toBeUndefined();
  });

  test('deleting a second row does not bring the first deleted row back', async ({ page, rng, evidence }) => {
    const entries = makeEntries(rng, 5, Date.now());
    await evidence.save('stored-history.json', entries);
    await seedStorage(page, { [HISTORY_KEY]: JSON.stringify(entries) });
    const gen = new PasswordGenerator(page);
    await gen.open();
    await waitUntilRecorded(gen);
    await expect(gen.historyRows).toHaveCount(entries.length + 1);

    const [first, second] = rng.sample(entries, 2);
    const deleteRow = (entry: StoredEntry) => gen.historyRows
      .filter({ has: page.locator('td', { hasText: new RegExp(`^${entry.password.length}$`) }) })
      .getByRole('button', { name: /^Delete password from/ }).click();
    await deleteRow(first);
    await expect(gen.historyRows, 'rows after the first delete').toHaveCount(entries.length);
    await deleteRow(second);

    const lengths = (await gen.readHistory()).map(r => r.length);
    expect.soft(lengths.includes(String(second.password.length)), 'the second deleted row is gone').toBe(false);
    expect.soft(lengths.includes(String(first.password.length)), 'the first deleted row must stay gone after deleting another row').toBe(false);
    await expect.soft(gen.historyCount, 'counter after deleting two of six').toHaveText(`${entries.length - 1}/${HISTORY_LIMIT}`, { timeout: 3_000 });
  });

  test('Clear all empties the list and the browser storage for good', async ({ page, rng }) => {
    const entries = makeEntries(rng, 6, Date.now());
    await seedStorage(page, { [HISTORY_KEY]: JSON.stringify(entries) });
    const gen = new PasswordGenerator(page);
    await gen.open();
    const current = await waitUntilRecorded(gen);
    await expect(gen.historyRows).toHaveCount(entries.length + 1);

    await gen.clearAll.click();
    await expect.soft(gen.historyRows, 'rows after Clear all').toHaveCount(0);
    await expect.soft(gen.historyEmpty, 'empty state').toBeVisible();
    await expect.soft(gen.historyCount, 'counter after Clear all').toHaveText(`0/${HISTORY_LIMIT}`);
    await expect.soft(gen.clearAll, 'Clear all is offered only when there is something to clear').toHaveCount(0);
    const dump = await gen.browserStorageDump();
    expect.soft([current, ...entries.map(e => e.password)].filter(v => dump.includes(v)), 'passwords still in browser storage after Clear all').toEqual([]);
    await expect.soft(gen.value, 'the value on screen is not touched').toHaveText(current);

    await page.reload();
    await gen.waitForValue();
    const fresh = await waitUntilRecorded(gen);
    expect.soft((await gen.storedHistory()).map(e => e.password), 'after a reload only the newly generated value is in the history').toEqual([fresh]);
    await expect.soft(gen.historyRows, 'rows after the reload').toHaveCount(1);
  });

  test('switching "Save to history" off is remembered, so a later visit does not start storing passwords again', async ({ page }) => {
    await page.clock.install();
    const gen = new PasswordGenerator(page);
    await gen.open();
    await gen.saveToHistory.uncheck();
    await gen.regenerateButton.click();
    await page.clock.fastForward(5_000);

    await page.reload();
    await gen.waitForValue();
    await expect.soft(gen.saveToHistory, '"Save to history" after a reload, having been switched off').not.toBeChecked({ timeout: 3_000 });
    const value = await gen.read();
    await page.clock.fastForward(10_000);
    const dump = await gen.browserStorageDump();
    expect.soft(dump.includes(value), `the value generated after the reload ("${value}") was written to browser storage although saving had been switched off`).toBe(false);
  });
});
