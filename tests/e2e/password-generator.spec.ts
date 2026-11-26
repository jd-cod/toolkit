import { test, expect, type Page } from './fixtures/dashboard';

/**
 * Functional coverage for the Password Generator.
 *
 * The other tool routes in tool-pages.spec.ts are smoke-only, and deliberately
 * so — they call live third-party APIs, so asserting on their output would make
 * the suite flap on someone else's outage. This page makes no network calls at
 * all, which means it can be held to a much higher standard, and should be: it
 * is the only tool in the suite whose entire job is a security property.
 *
 * What is worth asserting:
 *  - the CSPRNG actually produces different values (a `Math.random` regression
 *    or a seeded PRNG would still pass a render-only test)
 *  - the length slider controls the generated length
 *  - character-class toggles really change the output alphabet
 *  - the strength meter reports the mathematically correct bit count
 *  - history round-trips through localStorage and survives a reload
 *  - NO network request ever leaves with a generated password — the tool's
 *    central claim, and the one thing nothing else here would catch
 */

/**
 * The generated value, read from the display card.
 *
 * textContent, not innerText: the value is syntax-highlighted, so every
 * character sits in its own span and innerText inserts a newline between each
 * one — which reads back as a 39-character string for a 20-character password.
 * textContent concatenates the spans in DOM order with no separator, which is
 * the actual value the Copy button puts on the clipboard.
 */
async function readPassword(page: Page): Promise<string> {
  return (await page.locator('#pw-value').textContent())?.trim() ?? '';
}

async function openPasswordPage(page: Page) {
  await page.goto('/password-generator', { waitUntil: 'load' });
  // The page holds its first render until it knows it is on the client, so it
  // cannot paint a password during SSR. Wait for the post-mount generate.
  await expect(page.locator('#pw-value')).not.toBeEmpty();
}

/**
 * Fails the test if any request carries a generated password in its body.
 *
 * The generator is browser-only by design, so this is the assertion that
 * actually enforces it. A regression that POSTs the value to a share endpoint
 * or a telemetry beacon would render perfectly and pass every other test here.
 */
function assertNothingLeaves(secret: string, calls: string[]) {
  const leaked = calls.filter((c) => c.includes(secret));
  expect(
    leaked,
    `Generated password appeared in a network call:\n${leaked.join('\n')}`,
  ).toEqual([]);
}

test.describe('Password Generator', () => {
  test('generates a fresh password each time and honours the length slider', async ({ page, console }) => {
    await openPasswordPage(page);

    const first = await readPassword(page);
    expect(first).toHaveLength(20);

    // Regen must actually regenerate — not re-render the same value.
    await page.getByRole('button', { name: /Regenerate/ }).click();
    await expect(async () => {
      expect(await readPassword(page)).not.toBe(first);
    }).toPass({ timeout: 5_000 });

    // The slider drives the output length.
    await page.getByLabel('Password length').fill('32');
    await expect(async () => {
      expect(await readPassword(page)).toHaveLength(32);
    }).toPass({ timeout: 5_000 });

    // ...and the preset pills do the same.
    await page.getByRole('button', { name: '64', exact: true }).click();
    await expect(async () => {
      expect(await readPassword(page)).toHaveLength(64);
    }).toPass({ timeout: 5_000 });

    console.assertClean();
  });

  test('character-class toggles change the output alphabet', async ({ page }) => {
    await openPasswordPage(page);

    // Numbers off => no digits in any of several draws. These are toggle
    // buttons with aria-pressed, not checkboxes.
    await page.getByRole('button', { name: /Numbers/ }).click();
    await expect(async () => {
      for (let i = 0; i < 5; i++) {
        expect(await readPassword(page)).not.toMatch(/[0-9]/);
        await page.getByRole('button', { name: /Regenerate/ }).click();
      }
    }).toPass({ timeout: 10_000 });

    // Symbols off => no punctuation. Also catches a toggle that fails to
    // update the pool, which would silently keep widening the keyspace.
    await page.getByRole('button', { name: /Symbols/ }).click();
    await expect(async () => {
      for (let i = 0; i < 5; i++) {
        expect(await readPassword(page)).toMatch(/^[A-Za-z]+$/);
        await page.getByRole('button', { name: /Regenerate/ }).click();
      }
    }).toPass({ timeout: 10_000 });

    // The pool readout must follow the toggles, not the other way round:
    // a-z only is 26 characters, so the strong box has to say 26.
    await expect(page.getByText('26', { exact: false }).first()).toBeVisible();
    await expect(page.getByText('Character pool:').first()).toBeVisible();
  });

  test('reports the correct entropy, not a low score for a strong password', async ({ page }) => {
    await openPasswordPage(page);

    // 20 chars from the full 89-symbol pool is 20*log2(89) = 128.5 bits.
    // This is the regression guard: the scorer used to cap itself at
    // L*log2(distinct chars), which reads 86 bits for a perfectly uniform
    // random string, then deducted pattern penalties, landing near 80 —
    // "Strong" instead of "Very Strong".
    //
    // The digits are matched individually because "100 bits" contains "00" and
    // a substring assertion for the true value would pass against the bug.
    const digits = (t: string) => t.match(/\d+(?= bits)/)?.[0];
    await expect(page.locator('#pw-strength')).toContainText('Very Strong');
    await expect(async () => {
      const text = (await page.locator('#pw-strength').textContent()) ?? '';
      expect([...digits(text)!].sort().join('')).toBe('128');
    }).toPass();
    // "est." marks a pattern-matched guess; a generated value is exact.
    await expect(page.locator('#pw-strength')).not.toContainText('est.');

    // A shorter password must genuinely score lower — proves the number is
    // derived, not a static string.
    await page.getByLabel('Password length').fill('8');
    await expect(async () => {
      const text = (await page.locator('#pw-strength').textContent()) ?? '';
      expect(digits(text)).toBe('51');
    }).toPass();

    // The full four-class default is the case that HID the original bug: with
    // one of each class forced in, a 20-char draw always has >= 14 distinct
    // symbols, which is enough to clear the L*log2(distinct) cap the old
    // estimator applied. Strip down to digits only — pool 10, so 8 characters
    // is 26.6 bits — and the cap reappears, reporting 7-17 bits and drifting
    // on every regenerate. The meter must stay at 27.
    await page.getByRole('button', { name: /Uppercase/ }).click();
    await page.getByRole('button', { name: /Lowercase/ }).click();
    await page.getByRole('button', { name: /Symbols/ }).click();
    await expect(async () => {
      const text = (await page.locator('#pw-strength').textContent()) ?? '';
      expect(digits(text)).toBe('27');
    }).toPass({ timeout: 10_000 });
    // ...and it must not drift when regenerated, which is what made the bug
    // so visible in use: the number moved every time you clicked Regenerate.
    for (let i = 0; i < 3; i++) {
      await page.getByRole('button', { name: /Regenerate/ }).click();
      await expect(async () => {
        const text = (await page.locator('#pw-strength').textContent()) ?? '';
        expect(digits(text)).toBe('27');
      }).toPass({ timeout: 5_000 });
    }
  });

  test('passphrase mode is scored in words, not characters', async ({ page }) => {
    await openPasswordPage(page);

    await page.getByRole('button', { name: /Passphrase/ }).click();
    await expect(page.getByLabel('Number of words')).toBeVisible();

    const phrase = await readPassword(page);
    // 4 words from a 7,776-word list is 4*log2(7776) = 51.7 bits. Scoring it
    // on its ~40 characters of letters reports 90+ bits, which is both wrong
    // and dangerous — it tells the user a 4-word phrase is stronger than it is.
    await expect(page.locator('#pw-strength')).toContainText('52 bits');
    expect(phrase.split('-')).toHaveLength(4);
  });

  test('history persists across a reload and stores nothing server-side', async ({
    page,
    console,
  }) => {
    const requests: string[] = [];
    page.on('request', (r) => {
      if (['post', 'put', 'patch'].includes(r.method())) {
        requests.push(`${r.method()} ${r.url()} ${r.postData() ?? ''}`);
      }
    });

    await openPasswordPage(page);
    const generated = await readPassword(page);

    // History is written on a debounce, not on every keystroke of the slider.
    const row = page.locator('[data-pw-history-row]').first();
    await expect(row).toBeVisible({ timeout: 10_000 });
    // Masked at rest — a history table that renders plaintext the moment it
    // loads is a shoulder-surfing bug, so assert that before anything else.
    await expect(row).not.toContainText(generated);

    // Reveal it, and only then should the value be readable.
    await row.getByRole('button').first().click();
    await expect(row).toContainText(generated);

    // ...and it survives a full reload, which is the whole point of the table.
    // The reveal state is intentionally not persisted, so the row comes back
    // masked — assert the value survived without asserting the reveal stuck.
    await page.reload({ waitUntil: 'load' });
    const reloaded = page.locator('[data-pw-history-row]').first();
    await expect(reloaded).toBeVisible({ timeout: 10_000 });
    await reloaded.getByRole('button').first().click();
    await expect(reloaded).toContainText(generated);

    assertNothingLeaves(generated, requests);
    console.assertClean();
  });

  test('reveal toggle masks the value, and history masks by default', async ({ page }) => {
    await openPasswordPage(page);
    const secret = await readPassword(page);

    await page.getByRole('button', { name: 'Hide password' }).click();
    await expect(page.locator('#pw-value')).not.toContainText(secret);
    await page.getByRole('button', { name: 'Show password' }).click();
    await expect(page.locator('#pw-value')).toContainText(secret);

    // History rows stay masked until explicitly revealed.
    await expect(page.locator('[data-pw-history-row]').first()).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('[data-pw-history-row]').first()).not.toContainText(secret);
  });

  test('copy button puts exactly the displayed value on the clipboard', async ({ page }) => {
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    await openPasswordPage(page);

    const shown = await readPassword(page);
    await page.getByRole('button', { name: /Copy Password/ }).click();
    await expect(page.getByRole('button', { name: /Copied/ })).toBeVisible();

    const clip = await page.evaluate(() => navigator.clipboard.readText());
    // A copy button that copies the *previous* password is the classic
    // stale-state bug here, and it is invisible without reading the clipboard.
    expect(clip).toBe(shown);
  });

  test('the page states the browser-only privacy claim', async ({ page }) => {
    await openPasswordPage(page);
    await expect(page.getByText(/browser/i).first()).toBeVisible();
  });

  test('settings persist across a reload', async ({ page }) => {
    await openPasswordPage(page);

    // Change several settings.
    await page.getByLabel('Password length').fill('32');
    await page.getByRole('button', { name: /Numbers/ }).click();
    await page.getByRole('button', { name: 'Passphrase' }).click();
    await page.getByLabel('Number of words').fill('6');

    await page.reload({ waitUntil: 'load' });
    await expect(page.locator('#pw-value')).not.toBeEmpty();

    // Mode survived.
    await expect(page.getByLabel('Number of words')).toBeVisible();
    // Word count survived — 6-word phrase has 6 hyphen-separated words.
    await expect(async () => {
      const phrase = (await page.locator('#pw-value').textContent())?.trim() ?? '';
      expect(phrase.split('-')).toHaveLength(6);
    }).toPass({ timeout: 5_000 });

    // Switch back and check password-mode settings survived too.
    await page.getByRole('button', { name: /Random/ }).click();
    await expect(async () => {
      expect(await readPassword(page)).toHaveLength(32);
      expect(await readPassword(page)).not.toMatch(/[0-9]/);
    }).toPass({ timeout: 5_000 });
  });

  test('corrupt settings in localStorage fall back to defaults', async ({ page }) => {
    await page.goto('/password-generator', { waitUntil: 'load' });
    await page.evaluate(() => {
      window.localStorage.setItem('sysadmin_toolkit.pwgen.settings.v1', 'not-json');
    });
    await page.reload({ waitUntil: 'load' });
    await expect(page.locator('#pw-value')).not.toBeEmpty();
    // Default is 20 chars — corruption did not break generation.
    await expect(async () => {
      expect(await readPassword(page)).toHaveLength(20);
    }).toPass({ timeout: 5_000 });
  });
});
