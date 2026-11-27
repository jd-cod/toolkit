import { expect, type Page } from '@playwright/test';
import type { ExpectedView } from './oracle';

/**
 * Selectors, user actions and readers for the Crontab Builder (/cron).
 * A markup change in the tool is fixed here, not in the specs.
 */

export const ROUTE = '/cron';
export const HEADING = 'Crontab Builder';

const primary = (page: Page) => page.locator('.signal-tool-primary');

export const expressionInput = (page: Page) => primary(page).getByPlaceholder('*/5 * * * *');
export const presetSelect = (page: Page) => primary(page).locator('select');
export const banner = (page: Page) => primary(page).getByText(/^(Valid|Invalid) Expression$/);
export const runsTable = (page: Page) => primary(page).locator('table.signal-cron-runs-table');
export const runRows = (page: Page) => runsTable(page).locator('tbody tr');
export const fieldCards = (page: Page) => primary(page).locator('.signal-cron-fields .glass');
/** The two copy buttons, in order: expression, description. Their labels change after a copy. */
export const copyButtons = (page: Page) => primary(page).locator('button.btn-secondary');
export const guide = (page: Page) => page.getByRole('complementary', { name: 'Schedule reference' });

/** Opens the tool with the browser clock frozen at `instant`, so "next executions" are predictable. */
export async function freezeClock(page: Page, instant: number): Promise<void> {
  await page.clock.setFixedTime(new Date(instant));
}

/** Replaces the expression in one go, as a paste does. */
export async function enterExpression(page: Page, expression: string): Promise<void> {
  await expressionInput(page).fill(expression);
}

/**
 * Shows `expression` as computed at `instant`. The page computes the run list
 * when the expression changes, so the field is emptied first: the list is then
 * always built for the new moment, also when the expression stays the same.
 */
export async function showAt(page: Page, expression: string, instant: number): Promise<void> {
  await freezeClock(page, instant);
  await expressionInput(page).fill('');
  await expressionInput(page).fill(expression);
}

export interface CronRow { index: string; date: string; time: string; day: string; relative: string }

/** Everything the tool shows, read in one pass so a comparison sees one consistent state. */
export interface CronView {
  input: string;
  presetValue: string;
  banner: string | null;
  bannerIcon: string | null;
  description: string | null;
  fields: { caption: string; value: string }[];
  header: string | null;
  columns: string[];
  rows: CronRow[];
  buttons: string[];
}

export async function readView(page: Page): Promise<CronView> {
  return page.evaluate(() => {
    const root = document.querySelector('.signal-tool-primary') as HTMLElement | null;
    // Chrome separates the time and AM/PM with a narrow no-break space; compare with plain spaces.
    const text = (node: Node | null | undefined) => (node ? (node.textContent || '').replace(/\s+/g, ' ').trim() : '');
    if (!root) {
      return { input: '(tool not on the page)', presetValue: '', banner: null, bannerIcon: null, description: null, fields: [], header: null, columns: [], rows: [], buttons: [] };
    }
    const input = root.querySelector('input[type="text"]') as HTMLInputElement | null;
    const select = root.querySelector('select') as HTMLSelectElement | null;

    const bannerLabel = Array.from(root.querySelectorAll('span')).find(span => /^(Valid|Invalid) Expression$/.test(text(span)));
    const bannerBox = bannerLabel?.parentElement?.parentElement;
    const descriptionNode = bannerBox?.querySelector('p');

    const table = root.querySelector('table.signal-cron-runs-table');
    const rows = Array.from(table?.querySelectorAll('tbody tr') ?? []).map(tr => {
      const cells = Array.from(tr.querySelectorAll('td'));
      const time = cells[1]?.querySelector('span');
      const date = Array.from(cells[1]?.childNodes ?? []).filter(node => node !== time).map(node => text(node)).join(' ').trim();
      return { index: text(cells[0]), date, time: text(time), day: text(cells[2]), relative: text(cells[3]) };
    });

    return {
      input: input ? input.value : '(no expression field)',
      presetValue: select ? select.value : '(no preset list)',
      banner: bannerLabel ? text(bannerLabel) : null,
      bannerIcon: bannerLabel ? text(bannerLabel.previousElementSibling) : null,
      description: descriptionNode ? text(descriptionNode) : null,
      fields: Array.from(root.querySelectorAll('.signal-cron-fields .glass')).map(box => ({ caption: text(box.children[0]), value: text(box.children[1]) })),
      header: table ? text(table.closest('.glass')?.firstElementChild) : null,
      columns: Array.from(table?.querySelectorAll('thead th') ?? []).map(th => text(th)),
      rows,
      buttons: Array.from(root.querySelectorAll('button')).map(button => text(button)),
    };
  });
}

/** One line per value that differs from the expectation; empty when the view is right. */
export function diffView(got: CronView, want: ExpectedView): string[] {
  const out: string[] = [];
  const check = (name: string, shown: unknown, expected: unknown) => {
    if (JSON.stringify(shown) !== JSON.stringify(expected)) out.push(`${name}: page shows ${JSON.stringify(shown)}, expected ${JSON.stringify(expected)}`);
  };
  if (want.input !== null) check('expression field', got.input, want.input);
  check('validity banner', got.banner, want.banner);
  if (want.banner !== null) check('banner icon', got.bannerIcon, want.banner === 'Valid Expression' ? '✅' : '❌');
  if (want.description !== undefined) check('description', got.description, want.description);
  check('field cards', got.fields.map(f => `${f.caption}=${f.value}`), want.fields.map(f => `${f.caption}=${f.value}`));
  check('copy buttons', got.buttons, want.buttons);
  if (want.header === undefined) return out;
  check('run table heading', got.header, want.header);
  if (want.header !== null) check('run table columns', got.columns, ['#', 'Date & Time', 'Day', 'Relative']);
  check('number of run rows', got.rows.length, want.rows.length);
  want.rows.forEach((row, i) => {
    const shown = got.rows[i];
    if (!shown) return;
    for (const column of ['index', 'date', 'time', 'day', 'relative'] as const) {
      if (shown[column] !== row[column]) {
        out.push(`run ${i + 1} ${column}: page shows ${JSON.stringify(shown[column])}, expected ${JSON.stringify(row[column])}`
          + (column === 'index' ? '' : ` (page row: ${shown.date} ${shown.time}, ${shown.day}, ${shown.relative}; expected row: ${row.date} ${row.time}, ${row.day}, ${row.relative})`));
      }
    }
  });
  return out;
}

/** Reads the page until it shows `want` and returns what still differs (React renders within the event, so the first read normally matches). */
export async function settleView(page: Page, want: ExpectedView, patience = 1500): Promise<string[]> {
  let diffs = diffView(await readView(page), want);
  if (diffs.length === 0) return diffs;
  try {
    await expect.poll(async () => (diffs = diffView(await readView(page), want)).length, { timeout: patience }).toBe(0);
  } catch { /* the caller reports the remaining differences */ }
  return diffs;
}

/** Soft comparison of the whole page with the oracle. Returns true when everything matched. */
export async function expectView(page: Page, want: ExpectedView, context: string, patience = 1500): Promise<boolean> {
  const diffs = await settleView(page, want, patience);
  expect.soft(diffs, `${context}\n  ${diffs.join('\n  ')}\n`).toEqual([]);
  return diffs.length === 0;
}

/** A short account of what the page shows, for failure messages. */
export function summarize(view: CronView): string {
  const rows = view.rows.length ? `${view.rows.length} run rows (first: ${view.rows[0].date} ${view.rows[0].time})` : 'no run rows';
  return `banner ${JSON.stringify(view.banner)}, description ${JSON.stringify(view.description)}, heading ${JSON.stringify(view.header)}, ${rows}`;
}
