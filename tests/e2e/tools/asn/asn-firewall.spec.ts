import { test, expect } from '../_support/fixtures';
import { captureDownload, readClipboard } from '../_support/io';
import { randomScenario, type Scenario } from './generator';
import { type Cidr, type RuleAction, type RuleRequest, RULE_FORMATS, ruleFileName, ruleProblems, utcDate } from './oracle';
import { openWith } from './checks';
import type { AsnView } from './page';

/**
 * Firewall & ACL Generator tab of /asn, and the backend endpoint
 * POST /api/asn/generate-rules (our own code; the page does not call it, it
 * builds the rules in the browser with a second copy of the same generator).
 *
 * Every output is checked by `ruleProblems` in ./oracle.ts against the
 * selected prefixes: one rule per prefix, the platform's syntax for the
 * prefix's address family, the chosen action.
 */

type Scope = 'both' | 'ipv4' | 'ipv6';

/** The prefixes a scope and the merge option select, in output order: IPv4 first, then IPv6. */
function selection(scenario: Scenario, scope: Scope, merge: boolean): Cidr[] {
  const v4 = merge ? scenario.aggregated : scenario.v4;
  if (scope === 'ipv4') return v4;
  if (scope === 'ipv6') return scenario.v6;
  return [...v4, ...scenario.v6];
}

function request(scenario: Scenario, action: RuleAction, prefixes: Cidr[], startedAt: Date): RuleRequest {
  return { action, asn: scenario.asn, org: scenario.holder, prefixes, dates: [...new Set([utcDate(new Date()), utcDate(startedAt)])] };
}

async function openGenerator(page: import('@playwright/test').Page, scenario: Scenario): Promise<AsnView> {
  const { view } = await openWith(page, scenario);
  await view.tab('firewall').click();
  await expect(view.rulesOutput()).toBeVisible();
  return view;
}

test.describe('ASN firewall generator — controls', () => {
  test('starts on Nginx, deny, both versions, merged; offers 13 formats; settings survive a visit to another tab', async ({ page, rng, evidence }) => {
    const startedAt = new Date();
    const scenario = randomScenario(rng, { v4Count: rng.int(12, 30), v6Count: rng.int(3, 8) });
    await evidence.save('asn-response.json', scenario.payload);
    const view = await openGenerator(page, scenario);

    await expect.soft(view.formatSelect(), 'default format').toHaveValue('nginx');
    await expect.soft(view.scopeSelect(), 'default scope').toHaveValue('both');
    await expect.soft(view.mergeCheckbox(), 'merge is on by default').toBeChecked();
    expect.soft(await view.formatSelect().locator('option').allTextContents(), 'format options, in order').toEqual(RULE_FORMATS.map(f => f.label));
    expect.soft(await view.formatSelect().locator('option').evaluateAll(options => options.map(o => (o as HTMLOptionElement).value)), 'format option values')
      .toEqual(RULE_FORMATS.map(f => f.value));
    expect.soft(await view.scopeSelect().locator('option').allTextContents(), 'scope options').toEqual(['IPv4 + IPv6 (Both)', 'IPv4 Only', 'IPv6 Only']);

    const output = await view.readRules();
    await evidence.save('rules-default.txt', output);
    expect.soft(ruleProblems('nginx', output, request(scenario, 'deny', selection(scenario, 'both', true), startedAt)),
      'default output: nginx deny rules for the merged IPv4 prefixes and the IPv6 prefixes').toEqual([]);
    await expect.soft(view.linesLabel(), 'line counter').toHaveText(`${output.split('\n').length} lines generated`);

    await view.setRules({ format: 'ufw', action: 'allow', scope: 'ipv4', merge: false });
    const changed = await view.readRules();
    expect.soft(ruleProblems('ufw', changed, request(scenario, 'allow', selection(scenario, 'ipv4', false), startedAt)), 'ufw allow, IPv4, not merged').toEqual([]);
    await view.tab('bgp').click();
    await view.tab('firewall').click();
    await expect.soft(view.formatSelect(), 'format after visiting another tab').toHaveValue('ufw');
    await expect.soft(view.scopeSelect(), 'scope after visiting another tab').toHaveValue('ipv4');
    await expect.soft(view.mergeCheckbox(), 'merge after visiting another tab').not.toBeChecked();
    expect.soft(await view.readRules(), 'rules after visiting another tab').toBe(changed);
  });
});

test.describe('ASN firewall generator — every format', () => {
  for (const { value: format, label } of RULE_FORMATS) {
    test(`${label}: one correct rule per selected prefix for every action, scope and merge setting`, async ({ page, rng, evidence }) => {
      const startedAt = new Date();
      const scenario = randomScenario(rng, { v4Count: rng.int(10, 18), v6Count: rng.int(3, 6) });
      await evidence.save('asn-response.json', scenario.payload);
      const view = await openGenerator(page, scenario);
      await view.setRules({ format });

      const combos: { action: RuleAction; scope: Scope; merge: boolean }[] = [];
      for (const scope of ['ipv4', 'both', 'ipv6'] as const) {
        for (const action of ['deny', 'allow'] as const) {
          for (const merge of scope === 'ipv6' ? [true] : [true, false]) combos.push({ action, scope, merge });
        }
      }
      for (const combo of combos) {
        await view.setRules(combo);
        const output = await view.readRules();
        const prefixes = selection(scenario, combo.scope, combo.merge);
        const where = `${format}, action ${combo.action}, scope ${combo.scope}, merge ${combo.merge ? 'on' : 'off'} (${prefixes.length} prefixes selected)`;
        const problems = ruleProblems(format, output, request(scenario, combo.action, prefixes, startedAt));
        if (problems.length) await evidence.save(`rules-${format}-${combo.action}-${combo.scope}-${combo.merge ? 'merged' : 'raw'}.txt`, output);
        expect.soft(problems, `${where}:\n  ${problems.join('\n  ')}\n`).toEqual([]);
        await expect.soft(view.linesLabel(), `${where}: line counter`).toHaveText(`${output.split('\n').length} lines generated`);
      }

      // What leaves the page is the text that is shown.
      const combo = rng.pick(combos);
      await view.setRules(combo);
      const shown = await view.readRules();
      await page.evaluate(() => navigator.clipboard.writeText('not copied yet'));
      await view.copyRulesButton().click();
      await expect.soft(view.copyRulesButton(), `${format}: Copy Rules confirms`).toHaveText(/Copied Rules!/);
      expect.soft(await readClipboard(page), `${format} ${combo.action} ${combo.scope}: clipboard after Copy Rules`).toBe(shown);
      const file = await captureDownload(page, () => view.saveFileButton().click());
      expect.soft(file.filename, `${format} ${combo.action}: saved file name`).toBe(ruleFileName(scenario.asn, format, combo.action));
      expect.soft(file.text, `${format} ${combo.action} ${combo.scope}: saved file content`).toBe(shown);
    });
  }
});

test.describe('ASN firewall rules API (POST /api/asn/generate-rules, real backend)', () => {
  type Page = import('@playwright/test').Page;
  const generate = (page: Page, data: Record<string, unknown>) => page.request.post('/api/asn/generate-rules', { data });
  /** Rule lines only: the first line (header) and everything that is not a comment. */
  const significant = (text: string) => text.split('\n').filter((line, i) => i === 0 || !line.startsWith('#'));

  test('returns, for the same prefixes and options, the rules the page shows', async ({ page, rng, evidence }) => {
    const scenario = randomScenario(rng, { v4Count: rng.int(8, 14), v6Count: rng.int(2, 5) });
    await evidence.save('asn-response.json', scenario.payload);
    const view = await openGenerator(page, scenario);
    await view.setRules({ merge: false, scope: 'both' });
    const prefixes = selection(scenario, 'both', false);
    for (const { value: format } of RULE_FORMATS) {
      const action: RuleAction = rng.pick(['deny', 'allow']);
      await view.setRules({ format, action });
      const shown = await view.readRules();
      const response = await generate(page, { format, action, asn: scenario.asn, orgName: scenario.holder, prefixes: prefixes.map(p => ({ prefix: p.text })) });
      expect(response.status(), `${format} ${action}: API status`).toBe(200);
      const body = await response.json();
      expect.soft(body.total_prefixes, `${format}: total_prefixes in the API answer`).toBe(prefixes.length);
      expect.soft([body.format, body.action], `${format}: format and action echoed by the API`).toEqual([format, action]);
      if (format === 'json') {
        // The page lists its full prefix records, the API echoes what it was sent: compare the prefixes.
        expect.soft(JSON.parse(body.rules).map((p: { prefix: string }) => p.prefix), `${format}: prefixes from the API`).toEqual(JSON.parse(shown).map((p: { prefix: string }) => p.prefix));
      } else {
        expect.soft(significant(body.rules), `${format} ${action}: rule lines from the API and from the page`).toEqual(significant(shown));
      }
    }
  });

  test('uses nginx and deny when format and action are left out', async ({ page, rng }) => {
    const startedAt = new Date();
    const scenario = randomScenario(rng, { v4Count: 5, v6Count: 2 });
    const prefixes = selection(scenario, 'both', false);
    const response = await generate(page, { asn: scenario.asn, orgName: scenario.holder, prefixes: prefixes.map(p => ({ prefix: p.text })) });
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect.soft([body.format, body.action], 'defaults reported').toEqual(['nginx', 'deny']);
    expect.soft(ruleProblems('nginx', body.rules, request(scenario, 'deny', prefixes, startedAt)), 'default rules are nginx deny rules').toEqual([]);
  });

  test('refuses a format or an action it does not know instead of guessing', async ({ page, rng }) => {
    const scenario = randomScenario(rng, { v4Count: 3, v6Count: 1 });
    const prefixes = scenario.v4.map(p => ({ prefix: p.text }));
    for (const action of ['reject', 'DENY', 'blacklist']) {
      const response = await generate(page, { format: 'iptables', action, asn: scenario.asn, orgName: scenario.holder, prefixes });
      const text = await response.text();
      expect.soft(response.status(), `action "${action}" is neither "deny" nor "allow"; the API answered ${response.status()} with ${text.includes('-j ACCEPT') ? 'ACCEPT (allow) rules' : 'rules'}: ${text.slice(0, 160)}`).toBe(400);
    }
    for (const format of ['nginxx', 'IPTABLES', '']) {
      const response = await generate(page, { format, action: 'deny', asn: scenario.asn, orgName: scenario.holder, prefixes });
      if (format === '') { expect.soft(response.status(), 'an empty format falls back to the default').toBe(200); continue; }
      expect.soft(response.status(), `format "${format}" does not exist; the API answered ${response.status()}: ${(await response.text()).slice(0, 160)}`).toBe(400);
    }
  });

  test('refuses prefixes that are not CIDR blocks instead of writing them into commands', async ({ page, rng }) => {
    const scenario = randomScenario(rng, { v4Count: 2, v6Count: 0 });
    const hostile = ['10.0.0.0/8; rm -rf /tmp/x', '$(reboot)', '10.0.0.0/33', 'not-a-prefix'];
    for (const prefix of hostile) {
      const response = await generate(page, { format: 'iptables', action: 'deny', asn: scenario.asn, orgName: scenario.holder, prefixes: [{ prefix: scenario.v4[0].text }, { prefix }] });
      const text = await response.text();
      const written = response.status() === 200 && JSON.parse(text).rules.includes(prefix);
      expect.soft(written, `prefix ${JSON.stringify(prefix)} is not a CIDR block; the API answered ${response.status()} and wrote it into a shell command: ${written ? JSON.parse(text).rules.split('\n').pop() : ''}`).toBe(false);
    }
  });
});
