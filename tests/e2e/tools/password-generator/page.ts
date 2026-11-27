import type { Locator } from '@playwright/test';
import { expect, type Page } from '../_support/fixtures';
import { openTool } from '../_support/navigation';
import {
  CLASS_KEYS, SEPARATORS, RANDOM_DEFAULTS, PASSPHRASE_DEFAULTS,
  type ClassKey, type Mode, type PassphraseConfig, type RandomConfig,
} from './oracle';

/**
 * Selectors and user actions for the Password Generator.
 *
 * Buttons carry a Bootstrap icon whose glyph becomes part of the accessible
 * name, so names are matched with a pattern anchored at the end of the label.
 */

export const ROUTE = '/password-generator';
export const HEADING = 'Password Generator';
export const SETTINGS_KEY = 'sysadmin_toolkit.pwgen.settings.v1';
export const HISTORY_KEY = 'sysadmin_toolkit.pwgen.history.v1';

const MODE_NAMES: Record<Mode, RegExp> = { password: /Random$/, passphrase: /Passphrase$/, pin: /PIN$/ };
const CLASS_NAMES: Record<ClassKey, RegExp> = { uppercase: /^Uppercase/, lowercase: /^Lowercase/, numbers: /^Numbers/, symbols: /^Symbols/ };

export interface ControlSnapshot {
  mode: Mode | null;
  /** Slider value: characters, words or digits. */
  length: number;
  classes: ClassKey[];
  requireEach: boolean | null;
  avoidLookAlike: boolean | null;
  avoidShellHostile: boolean | null;
  /** Index of the highlighted separator button, -1 outside Passphrase mode. */
  separatorIndex: number;
  capitalise: boolean | null;
  appendNumber: boolean | null;
}

export interface HistoryRow {
  /** Text in the password cell: bullets while hidden, the value once revealed. */
  shown: string;
  length: string;
  contains: string;
  label: string;
  bits: string;
  generated: string;
  /** Tooltip of the "Generated" cell (full timestamp). */
  generatedTitle: string;
  revealName: string;
  copyName: string;
  deleteName: string;
}

export class PasswordGenerator {
  readonly primary: Locator;
  readonly value: Locator;
  readonly strengthLabel: Locator;
  readonly strengthDetail: Locator;
  readonly meterFill: Locator;
  readonly tips: Locator;
  readonly modeHint: Locator;
  readonly regenerateButton: Locator;
  readonly copyButton: Locator;
  readonly slider: Locator;
  readonly lengthHeading: Locator;
  readonly lengthReadout: Locator;
  readonly presets: Locator;
  readonly poolSize: Locator;
  readonly entropyPerChar: Locator;
  readonly separatorButtons: Locator;
  readonly capitalise: Locator;
  readonly appendNumber: Locator;
  readonly passphraseHelp: Locator;
  readonly pinWarning: Locator;
  readonly bulkCard: Locator;
  readonly bulkCount: Locator;
  readonly bulkGenerate: Locator;
  readonly bulkCopyAll: Locator;
  readonly bulkExport: Locator;
  readonly bulkClear: Locator;
  readonly bulkRowButtons: Locator;
  readonly historyCard: Locator;
  readonly historyCount: Locator;
  readonly saveToHistory: Locator;
  readonly clearAll: Locator;
  readonly historyRows: Locator;
  readonly historyEmpty: Locator;

  constructor(readonly page: Page) {
    this.primary = page.locator('.signal-tool-primary');
    this.value = page.locator('#pw-value');
    this.strengthLabel = page.locator('#pw-strength > span').nth(0);
    this.strengthDetail = page.locator('#pw-strength > span').nth(1);
    this.meterFill = page.locator('#pw-strength + div > div');
    this.tips = page.locator('#pw-strength ~ ul > li');
    this.modeHint = this.primary.locator('.glass').first().locator('span').first();
    this.regenerateButton = this.primary.getByRole('button', { name: /Regenerate$/ });
    this.copyButton = this.primary.getByRole('button', { name: /(Copy Password|Copied!)$/ }).first();
    this.slider = this.primary.getByRole('slider');
    this.lengthHeading = this.primary.locator('input.pw-slider').locator('xpath=preceding-sibling::div[1]/span[1]');
    this.lengthReadout = this.primary.locator('input.pw-slider').locator('xpath=preceding-sibling::div[1]/span[2]');
    this.presets = this.primary.locator('input.pw-slider + div').getByRole('button');
    this.poolSize = this.primary.locator('span', { hasText: 'Character pool:' }).locator('strong');
    this.entropyPerChar = this.primary.locator('span', { hasText: 'Entropy per character:' }).locator('strong');
    this.separatorButtons = this.primary.locator('span', { hasText: /^Separator$/ }).locator('xpath=following-sibling::div[1]').getByRole('button');
    this.capitalise = this.primary.getByRole('checkbox', { name: 'Capitalise each word' });
    this.appendNumber = this.primary.getByRole('checkbox', { name: /Append a random number/ });
    this.passphraseHelp = this.primary.locator('div', { hasText: /^Drawn from the EFF/ }).last();
    this.pinWarning = this.primary.locator('span', { hasText: /^Only .* bits per digit/ });
    this.bulkCard = this.primary.locator('.glass').filter({ hasText: 'Bulk generate' });
    this.bulkCount = this.primary.getByLabel('How many passwords to generate');
    this.bulkGenerate = this.bulkCard.getByRole('button', { name: /^\W*Generate$/ });
    this.bulkCopyAll = this.bulkCard.getByRole('button', { name: /(Copy All|Copied!)$/ });
    this.bulkExport = this.bulkCard.getByRole('button', { name: /Export CSV$/ });
    this.bulkClear = this.bulkCard.getByRole('button', { name: /Clear$/ });
    this.bulkRowButtons = this.bulkCard.locator('button[aria-label^="Copy password "]');
    this.historyCard = this.primary.locator('.glass').filter({ hasText: 'Recent passwords' });
    this.historyCount = this.historyCard.locator('span', { hasText: /^\d+\/\d+$/ });
    this.saveToHistory = this.historyCard.getByRole('checkbox', { name: 'Save to history' });
    this.clearAll = this.historyCard.getByRole('button', { name: /Clear all$/ });
    this.historyRows = this.historyCard.locator('tr[data-pw-history-row]');
    this.historyEmpty = this.historyCard.getByText('Nothing here yet');
  }

  /** Opens the tool and waits for the first generated value. */
  async open(route = ROUTE): Promise<void> {
    await openTool(this.page, route, HEADING);
    await this.waitForValue();
  }

  async waitForValue(): Promise<void> {
    await expect(this.value, 'a value should be generated as soon as the tool is ready').not.toHaveText(/^(Generating…)?$/);
  }

  /** The generated value exactly as displayed. */
  async read(): Promise<string> {
    return (await this.value.textContent()) ?? '';
  }

  modeButton(mode: Mode): Locator {
    return this.primary.getByRole('button', { name: MODE_NAMES[mode] }).first();
  }

  classButton(key: ClassKey): Locator {
    return this.primary.getByRole('button', { name: CLASS_NAMES[key] });
  }

  option(name: 'requireEach' | 'avoidLookAlike' | 'avoidShellHostile'): Locator {
    const labels = {
      requireEach: /Include at least one of each selected type/,
      avoidLookAlike: /Avoid look-alike characters/,
      avoidShellHostile: /Avoid shell-hostile symbols/,
    };
    return this.primary.getByRole('checkbox', { name: labels[name] });
  }

  preset(n: number): Locator {
    return this.presets.filter({ hasText: new RegExp(`^${n}$`) });
  }

  separatorButton(value: string): Locator {
    const index = SEPARATORS.findIndex(s => s.value === value);
    return this.separatorButtons.nth(index);
  }

  hideButton(): Locator { return this.primary.getByRole('button', { name: 'Hide password' }); }
  showButton(): Locator { return this.primary.getByRole('button', { name: 'Show password' }); }

  async selectMode(mode: Mode): Promise<void> {
    await this.modeButton(mode).click();
    await expect(this.modeButton(mode), `${mode} mode button should be pressed`).toHaveAttribute('aria-pressed', 'true');
  }

  /** Moves the length slider (characters, words or digits, depending on the mode). */
  async setLength(n: number): Promise<void> {
    await this.slider.fill(String(n));
    await expect(this.slider, `slider should be at ${n}`).toHaveValue(String(n));
  }

  /**
   * Waits until the displayed value has `n` characters. The value (and the
   * strength figures, which are computed from it) follows a length change one
   * animation frame later, so readers must not look before this.
   */
  async awaitLength(n: number): Promise<void> {
    await expect.poll(async () => (await this.read()).length, { message: `the displayed value should have ${n} characters` }).toBe(n);
  }

  /** State of every settings control of the mode on screen, read in one go. */
  async controls(): Promise<ControlSnapshot> {
    return this.primary.evaluate(root => {
      const text = (el: Element | null | undefined) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();
      const toggles = Array.from(root.querySelectorAll('button[aria-pressed]'));
      const pressed = (el: Element) => el.getAttribute('aria-pressed') === 'true';
      const modeNames: Record<string, string> = { Random: 'password', Passphrase: 'passphrase', PIN: 'pin' };
      const modeButton = toggles.slice(0, 3).find(pressed);
      const checkbox = (label: string): boolean | null => {
        const holder = Array.from(root.querySelectorAll('label')).find(l => text(l).includes(label));
        const input = holder?.querySelector('input');
        return input ? (input as HTMLInputElement).checked : null;
      };
      const separatorHeading = Array.from(root.querySelectorAll('span')).find(el => text(el) === 'Separator');
      const separators = Array.from(separatorHeading?.nextElementSibling?.querySelectorAll('button') ?? []);
      const classNames = ['Uppercase', 'Lowercase', 'Numbers', 'Symbols'];
      const classKeys = ['uppercase', 'lowercase', 'numbers', 'symbols'];
      const slider = root.querySelector('input.pw-slider') as HTMLInputElement | null;
      return {
        mode: modeNames[text(modeButton)] ?? null,
        length: slider ? Number(slider.value) : NaN,
        classes: toggles.slice(3).filter(pressed).map(el => classKeys[classNames.findIndex(name => text(el).startsWith(name))]),
        requireEach: checkbox('Include at least one of each selected type'),
        avoidLookAlike: checkbox('Avoid look-alike characters'),
        avoidShellHostile: checkbox('Avoid shell-hostile symbols'),
        separatorIndex: separators.findIndex(el => el.classList.contains('btn-primary')),
        capitalise: checkbox('Capitalise each word'),
        appendNumber: checkbox('Append a random number'),
      };
    }) as Promise<ControlSnapshot>;
  }

  async classStates(): Promise<Record<ClassKey, boolean>> {
    const { classes } = await this.controls();
    return Object.fromEntries(CLASS_KEYS.map(key => [key, classes.includes(key)])) as Record<ClassKey, boolean>;
  }

  /** Applies a Random-mode configuration through the controls, touching only what differs. */
  async configureRandom(config: RandomConfig): Promise<void> {
    await this.selectMode('password');
    const now = await this.controls();
    // Turn wanted classes on first: the tool refuses to switch the last one off.
    for (const key of CLASS_KEYS) if (config.classes.includes(key) && !now.classes.includes(key)) await this.classButton(key).click();
    for (const key of CLASS_KEYS) if (!config.classes.includes(key) && now.classes.includes(key)) await this.classButton(key).click();
    for (const name of ['requireEach', 'avoidLookAlike', 'avoidShellHostile'] as const) {
      if (now[name] !== config[name]) await this.option(name).click();
    }
    if (now.length !== config.length) await this.slider.fill(String(config.length));
    await expect.poll(async () => {
      const state = await this.controls();
      return {
        length: state.length, classes: state.classes, requireEach: state.requireEach,
        avoidLookAlike: state.avoidLookAlike, avoidShellHostile: state.avoidShellHostile,
      };
    }, { message: 'Random-mode controls should show the requested configuration' }).toEqual({
      length: config.length, classes: CLASS_KEYS.filter(key => config.classes.includes(key)), requireEach: config.requireEach,
      avoidLookAlike: config.avoidLookAlike, avoidShellHostile: config.avoidShellHostile,
    });
    await this.awaitLength(config.length);
  }

  async configurePassphrase(config: PassphraseConfig): Promise<void> {
    await this.selectMode('passphrase');
    const now = await this.controls();
    const index = SEPARATORS.findIndex(s => s.value === config.separator);
    if (now.separatorIndex !== index) await this.separatorButton(config.separator).click();
    if (now.capitalise !== config.capitalise) await this.capitalise.click();
    if (now.appendNumber !== config.appendNumber) await this.appendNumber.click();
    if (now.length !== config.words) await this.slider.fill(String(config.words));
    await expect.poll(async () => {
      const state = await this.controls();
      return { words: state.length, separatorIndex: state.separatorIndex, capitalise: state.capitalise, appendNumber: state.appendNumber };
    }, { message: 'Passphrase-mode controls should show the requested configuration' }).toEqual({
      words: config.words, separatorIndex: index, capitalise: config.capitalise, appendNumber: config.appendNumber,
    });
  }

  async configurePin(digits: number): Promise<void> {
    await this.selectMode('pin');
    await this.setLength(digits);
    await this.awaitLength(digits);
  }

  /** Label, figures, meter fill and advice of the strength block, plus the value they describe. */
  async strengthSnapshot(): Promise<{ value: string; label: string; detail: string; fill: string; readout: string; tips: string[] }> {
    return this.primary.evaluate(root => {
      const text = (el: Element | null | undefined) => el?.textContent ?? '';
      const strength = root.querySelector('#pw-strength');
      const slider = root.querySelector('input.pw-slider');
      return {
        value: text(root.querySelector('#pw-value')),
        label: text(strength?.children[0]),
        detail: text(strength?.children[1]),
        fill: (strength?.nextElementSibling?.firstElementChild as HTMLElement | null)?.style.width ?? '',
        readout: text(slider?.previousElementSibling?.children[1]),
        tips: Array.from(strength?.parentElement?.querySelectorAll('ul > li') ?? []).map(li => text(li).replace(/\s+/g, ' ').trim()),
      };
    });
  }

  /** Values of the bulk list, in display order. */
  async bulkValues(): Promise<string[]> {
    return this.bulkRowButtons.locator('xpath=preceding-sibling::span[1]').allTextContents();
  }

  async bulkIndexes(): Promise<string[]> {
    return this.bulkRowButtons.locator('xpath=preceding-sibling::span[2]').allTextContents();
  }

  /**
   * Presses "Generate" in the bulk card and returns the new list. Waits for
   * the list to be replaced (a list of several values repeating exactly is
   * not a realistic outcome for any mode).
   */
  async generateBulk(count?: number): Promise<string[]> {
    if (count !== undefined) await this.bulkCount.selectOption(String(count));
    const size = Number(await this.bulkCount.inputValue());
    const before = await this.bulkValues();
    await this.bulkGenerate.click();
    let values: string[] = [];
    await expect.poll(async () => {
      values = await this.bulkValues();
      return values.length === size && values.join('\n') !== before.join('\n');
    }, { message: `bulk list should show ${size} new values` }).toBe(true);
    return values;
  }

  /** Collects at least `total` values with the bulk generator (50 per press). */
  async collect(total: number): Promise<string[]> {
    const out: string[] = [];
    await this.bulkCount.selectOption('50');
    while (out.length < total) out.push(...await this.generateBulk());
    return out;
  }

  /** Presses "Regenerate" and returns the value shown afterwards. */
  async regenerate(): Promise<string> {
    await this.regenerateButton.click();
    return this.read();
  }

  async readHistory(): Promise<HistoryRow[]> {
    return this.historyRows.evaluateAll(rows => rows.map(row => {
      const cells = Array.from(row.querySelectorAll('td'));
      const text = (el: Element | null | undefined) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();
      const buttons = Array.from(row.querySelectorAll('button')).map(b => b.getAttribute('aria-label') ?? '');
      const strength = Array.from(cells[3]?.querySelectorAll('span') ?? []);
      return {
        shown: row.querySelector('code')?.textContent ?? '',
        length: text(cells[1]),
        contains: text(cells[2]),
        label: text(strength[0]),
        bits: text(strength[1]),
        generated: text(cells[4]),
        generatedTitle: cells[4]?.getAttribute('title') ?? '',
        revealName: buttons[0] ?? '',
        copyName: buttons[1] ?? '',
        deleteName: buttons[2] ?? '',
      };
    }));
  }

  /** Stored history entries (what a later visit to the page will load). */
  async storedHistory(): Promise<{ password: string; mode: string; bits: number; level: string; createdAt: number }[]> {
    const raw = await this.page.evaluate(key => window.localStorage.getItem(key), HISTORY_KEY);
    try {
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed.filter(entry => entry && typeof entry === 'object') : [];
    } catch {
      return []; // damaged storage holds no usable entry
    }
  }

  /** Everything this origin keeps in the browser, as one searchable text. */
  async browserStorageDump(): Promise<string> {
    return this.page.evaluate(() => {
      const dump = (store: Storage) => Object.keys(store).map(k => `${k}=${store.getItem(k)}`).join('\n');
      return `localStorage:\n${dump(window.localStorage)}\nsessionStorage:\n${dump(window.sessionStorage)}\ncookie:\n${document.cookie}`;
    });
  }
}

export { RANDOM_DEFAULTS, PASSPHRASE_DEFAULTS };
