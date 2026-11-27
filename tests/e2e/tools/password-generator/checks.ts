import { expect, type Page } from '../_support/fixtures';
import { expectedStrength, type StrengthExpectation } from './oracle';
import type { PasswordGenerator } from './page';

/**
 * Assertions shared by the Password Generator specs.
 */

/** Strength label, bits and crack time for a keyspace of equally likely values. */
export async function expectStrength(gen: PasswordGenerator, keyspace: bigint, ctx: string): Promise<StrengthExpectation> {
  const want = expectedStrength(keyspace);
  await expect.soft(gen.strengthDetail, `${ctx}: entropy and crack time (a generated value is exact, never "est.")`).toHaveText(want.detail);
  await expect.soft(gen.strengthLabel, `${ctx}: strength label for ${want.bits} bits`).toHaveText(want.label);
  return want;
}

/**
 * Soft assertion over a batch of generated values: none may have a problem.
 * Reports the first few offenders with the reason, not hundreds of lines.
 */
export function expectAllPossible(values: string[], problems: (value: string) => string[], ctx: string): void {
  const bad = values
    .map(value => ({ value, problems: problems(value) }))
    .filter(entry => entry.problems.length > 0);
  expect.soft(
    bad.slice(0, 5),
    `${ctx}: ${bad.length} of ${values.length} generated values are not possible for these settings`,
  ).toEqual([]);
}

/** Waits until the main display shows a value that is possible for the current settings. */
export async function expectMainValuePossible(gen: PasswordGenerator, problems: (value: string) => string[], ctx: string): Promise<string> {
  let value = '';
  await expect.poll(async () => {
    value = await gen.read();
    return problems(value);
  }, { message: `${ctx}: the displayed value should be possible for these settings` }).toEqual([]);
  return value;
}

/** Waits until the value on screen is the newest entry of the stored history, and returns it. */
export async function waitUntilRecorded(gen: PasswordGenerator): Promise<string> {
  let value = '';
  await expect.poll(async () => {
    value = await gen.read();
    return (await gen.storedHistory())[0]?.password === value;
  }, { message: 'the value on screen should be recorded in the history about a second after it appears', timeout: 20_000 }).toBe(true);
  return value;
}

/** Bits printed in the strength line, or NaN. */
export async function displayedBits(gen: PasswordGenerator): Promise<number> {
  const text = (await gen.strengthDetail.textContent()) ?? '';
  const match = text.match(/^(\d+) bits/);
  return match ? Number(match[1]) : NaN;
}

export async function tipTexts(gen: PasswordGenerator): Promise<string[]> {
  return (await gen.tips.allTextContents()).map(t => t.replace(/\s+/g, ' ').trim());
}

/** Puts values into localStorage before the tool's code runs, as a returning visitor would have them. */
export async function seedStorage(page: Page, items: Record<string, string>): Promise<void> {
  // Any same-origin document that does not run the generator.
  await page.goto('/api/site/config');
  await page.evaluate(entries => {
    for (const [key, value] of Object.entries(entries)) window.localStorage.setItem(key, value);
  }, items);
}

/** Variants of a value that could carry it in a URL or a request body. */
export function encodings(value: string): string[] {
  return [...new Set([value, encodeURIComponent(value), encodeURI(value), Buffer.from(value, 'utf8').toString('base64'), JSON.stringify(value).slice(1, -1)])];
}
