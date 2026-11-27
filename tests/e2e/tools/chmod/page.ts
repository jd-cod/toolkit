import { expect, type Locator, type Page } from '@playwright/test';
import { PERMS, ROLES, SPECIALS, SPECIAL_LABELS, type ExpectedView, type Perm, type Role, type Special } from './oracle';

/**
 * Selectors, user actions and readers for the chmod Calculator (/chmod).
 * A markup change in the tool is fixed here, not in the specs.
 */

export const ROUTE = '/chmod';
export const HEADING = 'chmod Calculator';

const primary = (page: Page) => page.locator('.signal-tool-primary');

export const octalInput = (page: Page) => primary(page).getByPlaceholder('755');
export const presetSelect = (page: Page) => primary(page).locator('select');
export const cell = (page: Page, role: Role, perm: Perm) => primary(page).getByRole('button', { name: `${role} ${perm}`, exact: true });
export const specialBox = (page: Page, special: Special) => primary(page).getByRole('checkbox', { name: SPECIAL_LABELS[special] });
export const commandLine = (page: Page) => primary(page).locator('code');
export const copyButton = (page: Page) => primary(page).locator('button.btn-secondary');
export const guide = (page: Page) => page.getByRole('complementary', { name: 'Permission reference' });

/** Value of an output card (`Octal`, `Symbolic`, `ls -la Output`), found by its caption. */
export function card(page: Page, caption: string): Locator {
  return primary(page).locator('div.glass')
    .filter({ has: page.locator('div', { hasText: new RegExp(`^${caption}$`) }) })
    .locator('div').first();
}

/** Replaces the content of the octal field in one go, as a paste does. */
export async function enterOctal(page: Page, text: string): Promise<void> {
  await octalInput(page).fill(text);
}

/**
 * True when the page tells the user that the octal field is not usable as it
 * stands: the field is marked invalid, an error message is on screen, or the
 * Copy button is disabled. Any one of them counts.
 */
export async function invalidFieldIsFlagged(page: Page): Promise<boolean> {
  return page.evaluate(() => {
    const root = document.querySelector('.signal-tool-primary') as HTMLElement;
    const field = root.querySelector('input[type="text"]');
    const marked = field?.getAttribute('aria-invalid') === 'true' || (field as HTMLInputElement | null)?.validity.valid === false;
    const alert = root.querySelector('[role="alert"], [aria-live="assertive"]');
    const message = /invalid|not (a )?valid|must be|octal digits|digits 0\s*(-|–|to)\s*7/i.test(root.innerText);
    const copy = root.querySelector('button.btn-secondary') as HTMLButtonElement | null;
    return marked || (alert !== null && (alert.textContent || '').trim() !== '') || message || copy?.disabled === true;
  });
}

/** Types into the emptied octal field one key at a time. */
export async function typeOctal(page: Page, text: string): Promise<void> {
  await octalInput(page).fill('');
  await octalInput(page).pressSequentially(text);
}

export async function choosePreset(page: Page, octal: string): Promise<void> {
  await presetSelect(page).selectOption(octal);
}

/** Everything the tool shows, read in one pass so a comparison sees one consistent state. */
export interface ChmodView {
  input: string;
  presetValue: string;
  octal: string | null;
  symbolic: string | null;
  ls: string | null;
  command: string | null;
  explanation: string[];
  warnings: string[];
  pressed: Record<string, boolean | null>;
  /** Whether the cell shows its check mark; must agree with `pressed`. */
  ticked: Record<string, boolean | null>;
  checked: Record<string, boolean | null>;
  copyLabel: string | null;
  /** Names of parts that exist but are not visible. */
  hidden: string[];
}

export async function readView(page: Page): Promise<ChmodView> {
  return page.evaluate(({ roles, perms, specialLabels }) => {
    const root = document.querySelector('.signal-tool-primary') as HTMLElement;
    const text = (el: Element | null | undefined) => (el ? (el.textContent || '').replace(/\s+/g, ' ').trim() : null);
    const hidden: string[] = [];
    const seen = (name: string, el: Element | null | undefined) => {
      if (el && !(el as HTMLElement).checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) hidden.push(name);
      return el;
    };

    const cardValue = (caption: string) => {
      const box = Array.from(root.querySelectorAll('div.glass'))
        .find(glass => Array.from(glass.children).some(child => text(child) === caption));
      return text(seen(`${caption} card`, box?.children[0]));
    };

    const pressed: Record<string, boolean | null> = {};
    const ticked: Record<string, boolean | null> = {};
    for (const role of roles) {
      for (const perm of perms) {
        const name = `${role} ${perm}`;
        const button = seen(`${name} button`, root.querySelector(`button[aria-label="${name}"]`));
        const state = button?.getAttribute('aria-pressed');
        pressed[name] = state === 'true' ? true : state === 'false' ? false : null;
        ticked[name] = button ? button.querySelector('i.bi-check-lg') !== null : null;
      }
    }

    const checked: Record<string, boolean | null> = {};
    for (const label of specialLabels) {
      const holder = Array.from(root.querySelectorAll('label')).find(l => text(l) === label);
      const box = seen(`${label} checkbox`, holder?.querySelector('input[type="checkbox"]')) as HTMLInputElement | null | undefined;
      checked[label] = box ? box.checked : null;
    }

    const explanationBox = Array.from(root.querySelectorAll('div.glass'))
      .find(glass => text(glass.children[0]) === 'Explanation');
    const warnings = Array.from(root.querySelectorAll('div'))
      .filter(div => div.children.length === 0 && /^(\u{1F534}|\u{1F7E1})/u.test(text(div) || ''))
      .map(div => text(seen('warning line', div)) as string);

    const input = root.querySelector('input[type="text"]') as HTMLInputElement | null;
    const select = root.querySelector('select') as HTMLSelectElement | null;
    return {
      input: input ? input.value : '(no octal field)',
      presetValue: select ? select.value : '(no preset list)',
      octal: cardValue('Octal'),
      symbolic: cardValue('Symbolic'),
      ls: cardValue('ls -la Output'),
      command: text(seen('command line', root.querySelector('code'))),
      explanation: explanationBox ? Array.from(explanationBox.querySelectorAll('p')).map(p => text(seen('explanation line', p)) as string) : [],
      warnings,
      pressed,
      ticked,
      checked,
      copyLabel: text(root.querySelector('button.btn-secondary')),
      hidden,
    };
  }, { roles: [...ROLES], perms: [...PERMS], specialLabels: SPECIALS.map(s => SPECIAL_LABELS[s]) });
}

/**
 * What the octal field must contain: one exact text, any of several spellings
 * of the same mode (`0755` may stay or become `755`), or `null` when the
 * caller checks the field itself.
 */
export type FieldExpectation = string | readonly string[] | null;

/** One line per value that differs from the expectation; empty when the view is right. */
export function diffView(got: ChmodView, want: ExpectedView, wantInput: FieldExpectation): string[] {
  const out: string[] = [];
  const check = (name: string, shown: unknown, expected: unknown) => {
    if (JSON.stringify(shown) !== JSON.stringify(expected)) out.push(`${name}: page shows ${JSON.stringify(shown)}, expected ${JSON.stringify(expected)}`);
  };
  if (typeof wantInput === 'string') check('octal field', got.input, wantInput);
  else if (wantInput !== null && !wantInput.includes(got.input)) {
    out.push(`octal field: page shows ${JSON.stringify(got.input)}, expected one of ${JSON.stringify(wantInput)}`);
  }
  check('Octal card', got.octal, want.octal);
  check('Symbolic card', got.symbolic, want.symbolic);
  check('ls -la Output card', got.ls, want.ls);
  check('command line', got.command, want.command);
  check('Explanation sentences', got.explanation, want.explanation);
  check('warnings', got.warnings, want.warnings);
  for (const [name, expected] of Object.entries(want.pressed)) {
    check(`grid button "${name}" pressed`, got.pressed[name], expected);
    check(`grid button "${name}" check mark`, got.ticked[name], expected);
  }
  for (const [name, expected] of Object.entries(want.checked)) check(`checkbox "${name}" checked`, got.checked[name], expected);
  check('parts that are not visible', got.hidden, []);
  return out;
}

/**
 * Reads the page until it shows `want` (React renders within the same task as
 * the event, so the first read normally matches) and returns what still differs.
 */
export async function settleView(page: Page, want: ExpectedView, wantInput: FieldExpectation): Promise<string[]> {
  let diffs = diffView(await readView(page), want, wantInput);
  if (diffs.length === 0) return diffs;
  try {
    await expect.poll(async () => (diffs = diffView(await readView(page), want, wantInput)).length, { timeout: 1500 }).toBe(0);
  } catch { /* the caller reports the remaining differences */ }
  return diffs;
}

/** Soft comparison of the whole page with the oracle. Returns true when everything matched. */
export async function expectView(page: Page, want: ExpectedView, wantInput: FieldExpectation, context: string): Promise<boolean> {
  const diffs = await settleView(page, want, wantInput);
  expect.soft(diffs, `${context}: every value on the page must follow from the mode\n  ${diffs.join('\n  ')}\n`).toEqual([]);
  return diffs.length === 0;
}
