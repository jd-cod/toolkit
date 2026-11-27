import { test, expect } from './fixtures';
import { checkDashboard } from './checks';
import { analyse, summarise } from './oracle';

/**
 * Traffic Analyzer — the dashboard right after analysing a pasted log.
 *
 * Every card, ribbon, chart, table and the first explorer page is compared
 * with the oracle, for a fresh random log on every run.
 */

test.describe('Traffic Analyzer — overview of a pasted log', () => {
  test('every value on the dashboard matches a random log', async ({ analyzer, newLog }) => {
    const log = await newLog();
    await analyzer.analysePasted(log.text);
    checkDashboard(await analyzer.snapshot(), log, {}, 'after analysis');
  });

  test('a second, different random log (single-segment paths) also matches, including the Targeted Paths table', async ({ analyzer, newLog }) => {
    const log = await newLog({ urls: 'flat' });
    await analyzer.analysePasted(log.text);
    checkDashboard(await analyzer.snapshot(), log, {}, 'flat-path log');
  });

  test('source line describes the input and the active exclusions', async ({ analyzer, newLog }) => {
    const log = await newLog({ requests: 120 });
    await analyzer.analysePasted(log.text);
    const snap = await analyzer.snapshot();
    expect.soft(snap.sourceLabel, 'source label for pasted input').toBe('Pasted logs');
    expect.soft(snap.sourceNote, 'source note').toBe('Browser analysis · 403 exclusion enabled · Internal requests excluded');
    expect.soft(snap.exclusions.skip403, '"Ignore 403 responses" is on by default').toBe(true);
    expect.soft(snap.exclusions.skipInternal, '"Ignore internal requests" is on by default').toBe(true);
    await expect.soft(analyzer.page.locator('#dash-source-badge'), 'node badge').toHaveText('1 node');
    const kept = analyse(log).kept;
    expect(summarise(kept).total, 'sanity: the generated log has requests left after exclusions').toBeGreaterThan(0);
  });
});
