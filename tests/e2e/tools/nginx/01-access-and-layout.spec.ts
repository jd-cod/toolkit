import { test, expect } from './fixtures';
import { expectToolLinkedFromHome } from '../_support/navigation';
import { expectNoUiGlitches, expectControlsUsable, VIEWPORTS } from '../_support/ui-audit';
import { readClipboard, clearClipboard } from '../_support/io';
import { ROUTE } from './page';

/**
 * Traffic Analyzer (/nginx) — INVENTORY (each item is covered by the spec named in brackets)
 *
 * Inputs
 *   - Upload file(s): file chooser, drag and drop, .log/.txt/.gz, one or many      [10-inputs]
 *   - cURL ingest: two commands with copy buttons                                   [01]
 *   - Paste logs: textarea; global paste shortcut                                   [02, 10-inputs]
 *   - Remote URL: URL field with validation; server-side fetch                      [01, 10-inputs]
 *   - Sample datasets: five buttons                                                 [10-inputs]
 *   - Exclusions: "Ignore 403 responses", "Ignore internal requests" (+ help)       [07-exclusions]
 * Dashboard values
 *   - Toolbar: Parsed, Skipped, Span; source line; error share; exclusion counts    [02, 07]
 *   - Cards: total, unique IPs, ASNs, countries, human %, verified, spoofed         [02, 04]
 *   - Methods ribbon, data egress                                                   [02, 04]
 *   - Timeline chart: buckets, axis, intervals, time range, stepper, handles        [03-timeline]
 *   - Country chart + legend, ASN chart                                             [02, 04]
 *   - Tables: active IPs, bot intelligence, targeted paths, abusive IPs, ASNs,
 *     referrers; row clicks; IP log dialog; AbuseIPDB scan                          [05-tables]
 *   - Log Explorer: rows, counts, page size, pagination, search boxes               [06-explorer]
 * Controls
 *   - Filters: method, country, path, ASN, traffic class, IP search, path search,
 *     matching counter, clear pill, and combinations                                [04-filters]
 * Outputs
 *   - Download Report (HTML, compact option) and CSV                                [08-report]
 *   - Share Snapshot (with and without password), shared view /s/<code>             [09-share]
 * States
 *   - Input screen, analysing, dashboard, empty result, error dialog, New Analysis,
 *     Add More Logs dialog                                                          [01, 10-inputs, 11-edge-cases]
 */

test.describe('Traffic Analyzer — access', () => {
  test('is linked from the home page and the sidebar', async ({ page }) => {
    await expectToolLinkedFromHome(page, ROUTE);
    await expect(page.getByRole('heading', { level: 1, name: 'Traffic Log Analyzer' })).toBeVisible();
  });

  test('opens with its title, the three workflow steps and the analysis engine loaded', async ({ analyzer }) => {
    const { page } = analyzer;
    await expect(page).toHaveTitle(/Traffic|Log/i);
    await expect(page.getByRole('heading', { level: 1, name: 'Traffic Log Analyzer' })).toBeVisible();
    await expect(page.getByRole('list', { name: 'Analysis workflow' }).getByRole('listitem')).toHaveText(['1 Add your logs', '2 Analyze locally', '3 Explore insights']);
    for (const name of ['LogParser', 'Analyzer', 'Dashboard', 'GeoIP', 'BotDetector', 'Chart']) {
      expect.soft(await page.evaluate(n => typeof (window as unknown as Record<string, unknown>)[n] !== 'undefined', name), `engine part "${name}" should be loaded`).toBe(true);
    }
    await expect(page.locator('#nginx-dashboard'), 'no dashboard before any analysis').toBeHidden();
  });
});

test.describe('Traffic Analyzer — input screen', () => {
  test('all four sources, the exclusion options and the samples are present and usable', async ({ analyzer }) => {
    const { page } = analyzer;
    await expectControlsUsable(page, {
      'Upload file tab': '#nginx-tab-upload',
      'cURL ingest tab': '#nginx-tab-server',
      'Paste logs tab': '#nginx-tab-paste',
      'Remote URL tab': '#nginx-tab-url',
      'Ignore 403 checkbox': '#nginx-skip-403',
      'Ignore internal checkbox': '#nginx-skip-internal',
      'Choose files label': 'label[for="nginx-logfile"]',
    });
    await expect(page.locator('#nginx-tab-upload'), 'upload is the default source').toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#nginx-skip-403')).toBeChecked();
    await expect(page.locator('#nginx-skip-internal')).toBeChecked();
    await expect(page.locator('.btn-sample')).toHaveCount(5);
    await expect(page.locator('#nginx-analyze-btn'), 'nothing to analyse yet').toBeDisabled();
    await expect(page.locator('#nginx-input-status')).toHaveText('Choose a file to start your analysis.');
    await expect(page.locator('#nginx-logfile')).toHaveAttribute('accept', '.log,.txt,.gz');
  });

  test('each source tab shows its own panel and status, by mouse and by arrow keys', async ({ analyzer }) => {
    const { page } = analyzer;
    const expectOnly = async (mode: string) => {
      for (const m of ['upload', 'server', 'paste', 'url']) {
        await expect(page.locator(`#nginx-panel-${m}`), `panel "${m}" while "${mode}" is selected`).toBeVisible({ visible: m === mode });
        await expect(page.locator(`#nginx-tab-${m}`)).toHaveAttribute('aria-selected', String(m === mode));
      }
    };
    await analyzer.chooseSource('paste');
    await expectOnly('paste');
    await expect(page.locator('#nginx-input-status')).toHaveText('Paste log lines to start your analysis.');
    await expect(page.locator('#nginx-analyze-btn')).toBeDisabled();

    await analyzer.chooseSource('url');
    await expectOnly('url');
    await expect(page.locator('#nginx-input-status')).toHaveText('Enter a public HTTP(S) log URL to start.');

    await analyzer.chooseSource('server');
    await expectOnly('server');
    await expect(page.locator('#nginx-analyze-btn'), 'cURL ingest has no Analyze button').toBeHidden();
    await expect(page.locator('fieldset.signal-nginx-options'), 'exclusion options do not apply to cURL ingest').toBeHidden();
    await expect(page.locator('#nginx-input-status')).toHaveText('Run the command above, then open the link it prints.');

    await analyzer.chooseSource('upload');
    await expectOnly('upload');
    await page.locator('#nginx-tab-upload').focus();
    await page.keyboard.press('ArrowRight');
    await expectOnly('server');
    await page.keyboard.press('End');
    await expectOnly('url');
    await page.keyboard.press('ArrowRight');
    await expectOnly('upload');
    await page.keyboard.press('ArrowLeft');
    await expectOnly('url');
    await page.keyboard.press('Home');
    await expectOnly('upload');
  });

  test('Analyze is enabled only when the chosen source has usable input', async ({ analyzer }) => {
    const { page } = analyzer;
    const button = page.locator('#nginx-analyze-btn');
    const status = page.locator('#nginx-input-status');

    await analyzer.chooseSource('paste');
    await page.locator('#nginx-logtext').fill('   \n  ');
    await expect(button, 'whitespace is not input').toBeDisabled();
    await page.locator('#nginx-logtext').fill('1.2.3.4 - - [01/Jun/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8.4.0"');
    await expect(button).toBeEnabled();
    await expect(status).toHaveText('Ready to analyze the selected source.');
    await page.locator('#nginx-logtext').fill('');
    await expect(button).toBeDisabled();

    await analyzer.chooseSource('url');
    const url = page.locator('#nginx-gist-url');
    const cases: [string, string][] = [
      ['not a url', 'Enter a valid HTTP(S) URL.'],
      ['ftp://example.com/access.log', 'Use an HTTP(S) URL without embedded credentials.'],
      ['https://user:secret@example.com/access.log', 'Use an HTTP(S) URL without embedded credentials.'],
      ['file:///etc/passwd', 'Use an HTTP(S) URL without embedded credentials.'],
    ];
    for (const [value, message] of cases) {
      await url.fill(value);
      await expect.soft(status, `status for URL "${value}"`).toHaveText(message);
      await expect.soft(button, `Analyze must stay disabled for URL "${value}"`).toBeDisabled();
    }
    await url.fill('https://example.com/access.log.gz');
    await expect(status).toHaveText('Ready to analyze the selected source.');
    await expect(button).toBeEnabled();

    await analyzer.chooseSource('upload');
    await page.locator('#nginx-logfile').setInputFiles({ name: 'notes.pdf', mimeType: 'application/pdf', buffer: Buffer.from('x') });
    await expect.soft(status, 'a file that is not .log/.txt/.gz is refused').toHaveText('Choose .log, .txt, or gzip (.gz) files.');
    await expect.soft(button).toBeDisabled();
    await page.locator('#nginx-logfile').setInputFiles({ name: 'access.log', mimeType: 'text/plain', buffer: Buffer.from('x') });
    await expect(button).toBeEnabled();
    await expect(page.locator('#nginx-dropzone-filename'), 'the chosen file is named').toContainText('access.log');
  });

  test('cURL ingest commands point at this site and their Copy buttons copy them', async ({ analyzer, baseURL }) => {
    const { page } = analyzer;
    const origin = new URL(baseURL as string).origin;
    await analyzer.chooseSource('server');
    const recommended = `gzip -c /var/log/nginx/access.log | bash <(curl -fsSL ${origin}/ingest)`;
    const latest = `tail -n 50000 /var/log/nginx/access.log | gzip -c | curl -sS -F "file=@-" ${origin}/ingest`;

    const first = page.locator('#nginx-panel-server .cli-snippet').first();
    await expect(first.locator('code'), 'recommended command').toHaveText(recommended);
    await clearClipboard(page);
    await first.getByRole('button', { name: 'Copy recommended cURL command' }).click();
    await expect(first.getByRole('button')).toContainText('Copied!');
    expect(await readClipboard(page), 'clipboard after copying the recommended command').toBe(recommended);

    await page.locator('#nginx-panel-server summary').click();
    const second = page.locator('#nginx-panel-server details .cli-snippet');
    await expect(second.locator('code'), '"latest 50,000 requests" command').toHaveText(latest);
    await clearClipboard(page);
    await second.getByRole('button', { name: 'Copy complete cURL command' }).click();
    expect(await readClipboard(page), 'clipboard after copying the second command').toBe(latest);
  });

  test('"What is excluded?" explains both options', async ({ analyzer }) => {
    const { page } = analyzer;
    await analyzer.chooseSource('paste');
    const help = page.locator('#nginx-input-section details.signal-nginx-option-help');
    await help.locator('summary').click();
    await expect(help).toContainText('private, loopback, link-local, CGNAT and IPv6 unique-local IPs');
    await expect(help).toContainText('/health, /healthz, /healthcheck, /health-check, /health_check, /readyz, /livez and /_health');
    await expect(help).toContainText('recognized crawlers are retained for bot analysis');
  });
});

test.describe('Traffic Analyzer — layout', () => {
  for (const [name, viewport] of Object.entries(VIEWPORTS)) {
    test(`input screen has no layout problems at ${name} size (${viewport.width}px), for every source`, async ({ analyzer }) => {
      const { page } = analyzer;
      await page.setViewportSize(viewport);
      for (const mode of ['upload', 'server', 'paste', 'url'] as const) {
        await analyzer.chooseSource(mode);
        await expectNoUiGlitches(page, `${ROUTE} input screen, "${mode}" source @${name}`);
      }
    });

    test(`dashboard has no layout problems at ${name} size (${viewport.width}px)`, async ({ analyzer, newLog }) => {
      const { page } = analyzer;
      await page.setViewportSize(viewport);
      const log = await newLog({ requests: 400 });
      await analyzer.analysePasted(log.text);
      // The explorer table scrolls sideways inside its own box by design; wide log rows live there.
      await expectNoUiGlitches(page, `${ROUTE} dashboard @${name}`);
      await analyzer.selectMethod('GET');
      await expectNoUiGlitches(page, `${ROUTE} dashboard with a filter active @${name}`);
    });
  }

  test('dashboard dialogs have no layout problems and cover the whole page while open', async ({ analyzer, newLog }) => {
    const { page } = analyzer;
    const log = await newLog({ requests: 200 });
    await analyzer.analysePasted(log.text);
    // A modal dialog must sit above everything: a click on the sidebar or the
    // top bar while it is open must land on the dialog's backdrop, not navigate away.
    const expectCovers = async (name: string, backdropSelector: string) => {
      const uncovered = await page.evaluate((selector) => {
        const backdrop = document.querySelector(selector);
        const points: [string, number, number][] = [['sidebar', 40, 300], ['top bar', window.innerWidth - 40, 20], ['page centre', window.innerWidth / 2, window.innerHeight - 20]];
        return points.filter(([, x, y]) => {
          const hit = document.elementFromPoint(x, y);
          return !(hit && backdrop && (hit === backdrop || backdrop.contains(hit)));
        }).map(([area]) => area);
      }, backdropSelector);
      expect.soft(uncovered, `${name}: areas of the page still clickable behind the open dialog`).toEqual([]);
    };

    await page.locator('.btn-inspect-ip-logs').first().click();
    await expect(page.locator('#ip-log-modal')).toBeVisible();
    await expectNoUiGlitches(page, 'IP access-log dialog', { scope: '#ip-log-modal' });
    await expectCovers('IP access-log dialog', '#ip-log-modal');
    await page.locator('#ip-log-modal-close').click();
    await expect(page.locator('#ip-log-modal')).toBeHidden();

    await page.locator('#dash-download-btn').click();
    await expect(page.locator('#download-modal')).toBeVisible();
    await expectNoUiGlitches(page, 'Download Report dialog', { scope: '#download-modal-backdrop' });
    await expectCovers('Download Report dialog', '#download-modal-backdrop');
    await page.locator('#dl-modal-close').click();

    await page.locator('#dash-share-btn').click();
    await expect(page.locator('#share-modal')).toBeVisible();
    await expectNoUiGlitches(page, 'Share Analysis dialog', { scope: '#share-modal-backdrop' });
    await expectCovers('Share Analysis dialog', '#share-modal-backdrop');
    await page.locator('#share-close-btn').click();

    await page.locator('#dash-add-logs-btn').click();
    await expect(page.locator('#add-logs-modal')).toBeVisible();
    await expectNoUiGlitches(page, 'Add More Logs dialog', { scope: '#add-logs-modal' });
    await expectCovers('Add More Logs dialog', '#add-logs-modal');
  });
});
