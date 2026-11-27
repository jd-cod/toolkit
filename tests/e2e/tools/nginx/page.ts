import { expect, type Page } from '@playwright/test';
import { botFeedFile } from './catalog';

/**
 * Page object for the Traffic Analyzer (/nginx).
 *
 * Actions do what a user does (click, type, select, drag). Readers return
 * plain data taken from what is on screen, so specs compare data with data.
 * Chart values are read from the Chart.js model of each canvas, together
 * with a check that the canvas has actually been painted.
 */

export const ROUTE = '/nginx';

export interface ChartPoint { x: number; y: number }

export interface DashboardSnapshot {
  parsedLines: string;
  skippedLines: string;
  spanText: string | null;
  sourceLabel: string;
  sourceNote: string;
  errorText: string;
  exclusions: { privateIp: string; healthCheck: string; forbidden: string; invalid: string; skip403: boolean; skipInternal: boolean };
  filters: {
    method: { value: string; options: { value: string; label: string }[] };
    country: { value: string; options: { value: string; label: string }[] };
    path: { value: string; options: { value: string; label: string }[] };
    asn: { value: string; options: { value: string; label: string }[] };
    traffic: { value: string; options: { value: string; label: string }[] };
    ipSearch: string;
    pathSearch: string;
    matching: string;
  };
  kpis: { total: string; uniqueIps: string; asns: string; countries: string; human: string; verified: string; verifiedLabel: string; spoofed: string; spoofedLabel: string };
  methods: { method: string; count: string; pct: string }[];
  egress: string;
  timeline: {
    activeInterval: string | null;
    note: string;
    activeRange: string[];
    stepper: string;
    readout: { start: string; end: string; startIso: string; endIso: string; pill: string } | null;
    handles: Record<'start' | 'end', { now: number; min: number; max: number; text: string; label: string; disabled: string | null }>;
    chart: null | {
      datasets: { label: string; points: ChartPoint[]; hidden: boolean }[];
      xMin: number; xMax: number;
      ticks: { value: number; label: string }[];
      yTitle: string;
    };
    painted: boolean;
  };
  countryChart: { badge: string; labels: string[]; data: number[]; legend: { country: string; pct: string }[]; painted: boolean };
  asnChart: { badge: string; labels: string[]; data: number[]; painted: boolean };
  signalsHeading: string;
  tables: {
    ips: { badge: string; rows: { ip: string; hits: string }[] };
    bots: { badge: string; rows: { label: string; hits: string; status: string; filter: string; group: string }[]; empty: string | null };
    paths: { badge: string; rows: { path: string; hits: string; share: string }[] };
    abuse: { rows: { ip: string; confidence: string; domain: string; country: string }[] };
    asns: { badge: string; rows: { asn: string; code: string; org: string; hits: string; share: string }[] };
    referrers: { badge: string; rows: { referrer: string; hits: string; share: string }[] };
  };
  explorer: {
    count: string;
    perPage: string;
    ipSearch: string;
    pathSearch: string;
    rows: { time: string; ip: string; method: string; path: string; status: string; countryCode: string; country: string; protocol: string; userAgent: string }[];
    emptyMessage: string | null;
    pageText: string;
    pageButtons: { page: string; active: boolean }[];
    firstDisabled: boolean; prevDisabled: boolean; nextDisabled: boolean; lastDisabled: boolean;
  };
  clearPill: { visible: boolean; text: string };
}

export class TrafficAnalyzer {
  constructor(readonly page: Page) {}

  /**
   * Opens the tool with the verified-bot address feed pinned to the ranges in
   * catalog.ts, so "verified" and "spoofed" are predictable.
   */
  async open(): Promise<void> {
    await this.page.route('**/data/verified-bots.json*', route =>
      route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(botFeedFile()) }));
    const response = await this.page.goto(ROUTE, { waitUntil: 'domcontentloaded' });
    expect(response?.status(), `${ROUTE} should answer 200`).toBe(200);
    await this.waitForEngine();
  }

  /** The analysis scripts load one after another; the button is marked when they are bound. */
  async waitForEngine(): Promise<void> {
    await expect(this.page.locator('#nginx-analyze-btn'), 'the analysis engine should finish loading').toHaveAttribute('data-engine-ready', 'true', { timeout: 60_000 });
  }

  async chooseSource(mode: 'upload' | 'server' | 'paste' | 'url'): Promise<void> {
    await this.page.locator(`#nginx-tab-${mode}`).click();
    await expect(this.page.locator(`#nginx-panel-${mode}`)).toBeVisible();
  }

  async setInputExclusions(options: { skip403?: boolean; skipInternal?: boolean }): Promise<void> {
    if (options.skip403 !== undefined) await this.page.locator('#nginx-skip-403').setChecked(options.skip403);
    if (options.skipInternal !== undefined) await this.page.locator('#nginx-skip-internal').setChecked(options.skipInternal);
  }

  /** Paste a log and analyse it; resolves when the dashboard is on screen. */
  async analysePasted(text: string, options: { skip403?: boolean; skipInternal?: boolean } = {}): Promise<void> {
    await this.chooseSource('paste');
    await this.page.locator('#nginx-logtext').fill(text);
    await this.setInputExclusions(options);
    await this.page.locator('#nginx-analyze-btn').click();
    await this.waitForDashboard();
  }

  /**
   * Paste a log with the keyboard shortcut (Ctrl/Cmd+V on the page) and analyse it.
   * This is how a person pastes a large log; typing megabytes into the box is not.
   */
  async analysePastedWithShortcut(text: string): Promise<void> {
    await this.page.evaluate(value => navigator.clipboard.writeText(value), text);
    await this.page.locator('h1').first().click();
    await this.page.keyboard.press('ControlOrMeta+V');
    await expect(this.page.locator('#nginx-tab-paste')).toHaveAttribute('aria-selected', 'true');
    await expect.poll(() => this.page.locator('#nginx-logtext').evaluate(el => (el as HTMLTextAreaElement).value.length), { message: 'the pasted text should arrive in the paste box' }).toBe(text.length);
    await this.page.locator('#nginx-analyze-btn').click();
    await this.waitForDashboard();
  }

  /** Upload one or more files through the file chooser; resolves when the dashboard is on screen. */
  async analyseUploaded(files: { name: string; mimeType: string; buffer: Buffer }[], options: { skip403?: boolean; skipInternal?: boolean } = {}): Promise<void> {
    await this.chooseSource('upload');
    await this.setInputExclusions(options);
    await this.page.locator('#nginx-logfile').setInputFiles(files);
    const analyse = this.page.locator('#nginx-analyze-btn');
    // Some builds start on file selection; click only if the button is still waiting.
    if (await analyse.isVisible() && await analyse.isEnabled()) await analyse.click().catch(() => undefined);
    await this.waitForDashboard();
  }

  async waitForDashboard(): Promise<void> {
    await expect(this.page.locator('#nginx-dashboard'), 'the dashboard should appear after analysis').toBeVisible({ timeout: 90_000 });
    await expect(this.page.locator('#signal-overview .kpi-micro-card').first()).toBeVisible({ timeout: 90_000 });
    await expect(this.page.locator('#explorer-pagination-wrap')).toContainText(/Page \d+ of \d+/);
  }

  /**
   * Runs an action that makes the dashboard re-render and waits for the new
   * render. The dashboard replaces its content on every filter change, so the
   * marked element disappearing is the signal.
   */
  async rerender(action: () => Promise<unknown>): Promise<void> {
    await this.page.locator('#signal-overview').evaluate(el => el.setAttribute('data-e2e-old', '1'));
    await action();
    await expect(this.page.locator('#signal-overview:not([data-e2e-old])'), 'the dashboard should re-render after the action').toBeVisible({ timeout: 30_000 });
    await expect(this.page.locator('#explorer-pagination-wrap')).toContainText(/Page \d+ of \d+/);
  }

  // ── Filters ──
  selectMethod(value: string) { return this.rerender(() => this.page.locator('#filter-method').selectOption(value)); }
  selectCountry(value: string) { return this.rerender(() => this.page.locator('#filter-country').selectOption(value)); }
  selectPath(value: string) { return this.rerender(() => this.page.locator('#filter-path-select').selectOption(value)); }
  selectAsn(value: string) { return this.rerender(() => this.page.locator('#filter-asn').selectOption(value)); }
  selectTraffic(value: string) { return this.rerender(() => this.page.locator('#filter-bot').selectOption(value)); }
  searchIp(text: string) { return this.rerender(() => this.page.locator('#filter-ip').fill(text)); }
  searchPath(text: string) { return this.rerender(() => this.page.locator('#filter-path').fill(text)); }
  explorerSearchIp(text: string) { return this.rerender(() => this.page.locator('#log-table-ip-subnet-search').fill(text)); }
  explorerSearchPath(text: string) { return this.rerender(() => this.page.locator('#log-table-path-search').fill(text)); }
  clearFilters() { return this.rerender(() => this.page.locator('#floating-clear-filters-btn').click()); }

  /** Applies several ribbon filters, one after another. */
  async applyFilters(filters: { method?: string; country?: string; asn?: number; traffic?: string; ipSearch?: string; pathSearch?: string }): Promise<void> {
    if (filters.method) await this.selectMethod(filters.method);
    if (filters.country) await this.selectCountry(filters.country);
    if (filters.asn !== undefined) await this.selectAsn(`AS${filters.asn}`);
    if (filters.traffic) await this.selectTraffic(filters.traffic);
    if (filters.ipSearch) await this.searchIp(filters.ipSearch);
    if (filters.pathSearch) await this.searchPath(filters.pathSearch);
  }

  // ── Time range ──
  lastMinutes(minutes: 30 | 60 | 120) { return this.rerender(() => this.page.locator(`.shortcut-btn[data-mins="${minutes}"]`).click()); }
  allTime() { return this.rerender(() => this.page.locator('#btn-all-time').click()); }
  stepHours(direction: 'plus' | 'minus') { return this.rerender(() => this.page.locator(`#stepper-${direction}`).click()); }

  /** Press a key on a timeline handle (ArrowLeft/Right move one second; with Shift one minute). */
  async pressOnHandle(side: 'start' | 'end', key: string): Promise<void> {
    await this.page.locator(`#handle-${side}`).focus();
    await this.rerender(() => this.page.keyboard.press(key));
  }

  /** Drag a timeline handle to a fraction (0..1) of the track, with the mouse. */
  async dragHandle(side: 'start' | 'end', fraction: number): Promise<void> {
    const handle = this.page.locator(`#handle-${side}`);
    const track = this.page.locator('#slider-scrubber-track');
    await handle.scrollIntoViewIfNeeded();
    const hb = await handle.boundingBox();
    const tb = await track.boundingBox();
    if (!hb || !tb) throw new Error('timeline handle or track is not on screen');
    const fromX = hb.x + hb.width / 2;
    const y = hb.y + hb.height / 2;
    const toX = tb.x + tb.width * fraction;
    await this.rerender(async () => {
      await this.page.mouse.move(fromX, y);
      await this.page.mouse.down();
      await this.page.mouse.move((fromX + toX) / 2, y, { steps: 4 });
      await this.page.mouse.move(toX, y, { steps: 4 });
      await this.page.mouse.up();
    });
  }

  /** Chart interval buttons redraw only the chart. */
  async chooseInterval(seconds: 1 | 5 | 60 | 900): Promise<void> {
    const button = this.page.locator(`.rps-res-btn[data-res="${seconds}"]`);
    await button.click();
    await expect(button, `the ${seconds}s interval button should become the active one`).toHaveClass(/active/);
  }

  // ── Explorer ──
  async setPerPage(size: 10 | 25 | 50 | 100): Promise<void> {
    await this.page.locator('#explorer-per-page').selectOption(String(size));
    await expect(this.page.locator('#explorer-pagination-wrap')).toContainText(/Page 1 of/);
  }

  async goToPage(button: 'first' | 'prev' | 'next' | 'last' | number): Promise<void> {
    const before = await this.page.locator('#explorer-pagination-wrap > span').first().textContent();
    const locator = typeof button === 'number'
      ? this.page.locator(`.exp-page-btn[data-page="${button}"]`)
      : this.page.locator(`#exp-${button}-btn`);
    await locator.click();
    await expect(this.page.locator('#explorer-pagination-wrap > span').first(), 'the page indicator should change').not.toHaveText(before || '');
  }

  /** Everything the dashboard shows, read in one pass. */
  async snapshot(): Promise<DashboardSnapshot> {
    return this.page.evaluate(() => {
      const text = (el: Element | null | undefined) => (el?.textContent || '').replace(/\s+/g, ' ').trim();
      const q = (sel: string, root: ParentNode = document) => root.querySelector(sel);
      const qa = (sel: string, root: ParentNode = document) => Array.from(root.querySelectorAll(sel));
      const dash = document.getElementById('nginx-dashboard') as HTMLElement;

      const toolbarSpans = qa('.signal-dashboard-toolbar > div:last-child > span', dash).map(text);
      const find = (prefix: string) => toolbarSpans.find(s => s.startsWith(prefix)) || '';
      const counts = qa('#exclusion-counts strong', dash).map(text);

      const select = (id: string) => {
        const el = document.getElementById(id) as HTMLSelectElement | null;
        return { value: el?.value ?? '', options: el ? Array.from(el.options).map(o => ({ value: o.value, label: text(o) })) : [] };
      };
      const input = (id: string) => (document.getElementById(id) as HTMLInputElement | null)?.value ?? '';
      const kpi = (cls: string) => ({ value: text(q(`.${cls} .stat-value`, dash)), label: text(q(`.${cls} .stat-label`, dash)) });

      const painted = (id: string) => {
        const canvas = document.getElementById(id) as HTMLCanvasElement | null;
        if (!canvas || !canvas.width || !canvas.height) return false;
        const data = canvas.getContext('2d')!.getImageData(0, 0, canvas.width, canvas.height).data;
        let inked = 0;
        for (let i = 3; i < data.length; i += 4) if (data[i] !== 0) inked++;
        return inked > 200;
      };
      const chartOf = (id: string) => {
        const canvas = document.getElementById(id) as HTMLCanvasElement | null;
        const lib = (window as unknown as { Chart?: { getChart(c: HTMLCanvasElement): any } }).Chart;
        return canvas && lib ? lib.getChart(canvas) : null;
      };

      const rps = chartOf('rps-chart');
      const handle = (side: 'start' | 'end') => {
        const el = document.getElementById(`handle-${side}`);
        return {
          now: Number(el?.getAttribute('aria-valuenow')), min: Number(el?.getAttribute('aria-valuemin')), max: Number(el?.getAttribute('aria-valuemax')),
          text: el?.getAttribute('aria-valuetext') || '', label: text(q('time', el || undefined)), disabled: el?.getAttribute('aria-disabled') ?? null,
        };
      };
      const readoutTimes = qa('#time-window-readout time', dash) as HTMLTimeElement[];

      const card = (title: string) => qa('.card-table-wrap', dash).find(c => text(q('.table-header > span', c)).includes(title)) as HTMLElement | undefined;
      const cells = (row: Element) => Array.from(row.children).map(text);
      const bodyRows = (c?: HTMLElement) => (c ? qa('tbody tr', c) : []);
      const badge = (c?: HTMLElement) => text(c ? q('.table-header .pill', c) : null);

      const ipCard = card('Most Active IPs');
      const botCard = card('Bot Intelligence');
      const pathCard = card('Targeted Paths');
      const abuseCard = card('Abusive IPs');
      const asnCard = card('ASNs & Networks');
      const refCard = card('Top Referrers');

      const explorerRows = qa('#explorer-rows-body tr', dash);
      const emptyRow = explorerRows.length === 1 && explorerRows[0].children.length === 1 ? text(explorerRows[0]) : null;
      const country = q('#country-chart', dash)?.closest('.chart-card');
      const asn = q('#asn-chart', dash)?.closest('.chart-card');
      const countryModel = chartOf('country-chart');
      const asnModel = chartOf('asn-chart');
      const pill = document.getElementById('floating-clear-filters-btn');
      const disabled = (id: string) => (document.getElementById(id) as HTMLButtonElement | null)?.disabled ?? true;

      return {
        parsedLines: find('Parsed:'),
        skippedLines: find('Skipped:'),
        spanText: toolbarSpans.find(s => s.startsWith('Span:')) || null,
        sourceLabel: text(q('.signal-dashboard-source strong', dash)),
        sourceNote: text(q('.signal-dashboard-source > div > span', dash)),
        errorText: text(q('.signal-dashboard-errors', dash)),
        exclusions: {
          privateIp: counts[0] || '', healthCheck: counts[1] || '', forbidden: counts[2] || '', invalid: counts[3] || '',
          skip403: (document.getElementById('dash-skip-403') as HTMLInputElement | null)?.checked ?? false,
          skipInternal: (document.getElementById('dash-skip-internal') as HTMLInputElement | null)?.checked ?? false,
        },
        filters: {
          method: select('filter-method'), country: select('filter-country'), path: select('filter-path-select'),
          asn: select('filter-asn'), traffic: select('filter-bot'),
          ipSearch: input('filter-ip'), pathSearch: input('filter-path'),
          matching: text(document.getElementById('filter-matching-badge')),
        },
        kpis: {
          total: kpi('kpi-card-total').value, uniqueIps: kpi('kpi-card-ips').value, asns: kpi('kpi-card-asns').value,
          countries: kpi('kpi-card-countries').value, human: kpi('kpi-card-human').value,
          verified: kpi('kpi-card-verified').value, verifiedLabel: kpi('kpi-card-verified').label,
          spoofed: kpi('kpi-card-spoofed').value, spoofedLabel: kpi('kpi-card-spoofed').label,
        },
        methods: qa('.methods-bandwidth-ribbon > div:first-child > span', dash).slice(1).map(span => {
          const parts = Array.from(span.children).map(text);
          return { method: parts[0] || '', count: parts[1] || '', pct: parts[2] || '' };
        }),
        egress: text(q('.methods-bandwidth-ribbon .pill', dash)),
        timeline: {
          activeInterval: (q('.rps-res-btn.active', dash) as HTMLElement | null)?.dataset.res ?? null,
          note: text(document.getElementById('rps-resolution-note')),
          activeRange: qa('.shortcut-btn.active', dash).map(text),
          stepper: input('stepper-val'),
          readout: readoutTimes.length === 2 ? {
            start: text(readoutTimes[0]), end: text(readoutTimes[1]),
            startIso: readoutTimes[0].dateTime, endIso: readoutTimes[1].dateTime,
            pill: text(q('#time-window-readout .time-span-pill', dash)),
          } : null,
          handles: { start: handle('start'), end: handle('end') },
          chart: rps ? {
            datasets: rps.data.datasets.map((d: any, i: number) => ({
              label: d.label, hidden: !rps.isDatasetVisible(i),
              points: d.data.map((p: any) => ({ x: p.x, y: p.y })),
            })),
            xMin: rps.scales.x.min, xMax: rps.scales.x.max,
            ticks: rps.scales.x.ticks.map((t: any) => ({ value: t.value, label: Array.isArray(t.label) ? t.label.join(' ') : String(t.label) })),
            yTitle: rps.options.scales.y.title.text,
          } : null,
          painted: painted('rps-chart'),
        },
        countryChart: {
          badge: text(country ? q('.chart-card-header > span', country) : null),
          labels: countryModel ? [...countryModel.data.labels] : [],
          data: countryModel ? [...countryModel.data.datasets[0].data] : [],
          legend: qa('#country-chart-legend .legend-item', dash).map(item => ({
            country: text(item.children[1]).replace(/:$/, ''), pct: text(item.children[2]),
          })),
          painted: painted('country-chart'),
        },
        asnChart: {
          badge: text(asn ? q('.chart-card-header > span', asn) : null),
          labels: asnModel ? [...asnModel.data.labels] : [],
          data: asnModel ? [...asnModel.data.datasets[0].data] : [],
          painted: painted('asn-chart'),
        },
        signalsHeading: text(q('.signal-panel-heading', dash)),
        tables: {
          ips: {
            badge: badge(ipCard),
            rows: bodyRows(ipCard).filter(r => r.classList.contains('cross-filter-ip-row')).map(r => ({ ip: cells(r)[0], hits: cells(r)[1] })),
          },
          bots: {
            badge: badge(botCard),
            rows: bodyRows(botCard).filter(r => r.classList.contains('cross-filter-bot-row')).map(r => ({
              label: cells(r)[0], hits: cells(r)[1], status: cells(r)[2],
              filter: (r as HTMLElement).dataset.bot || '', group: (r as HTMLElement).dataset.botGroup || '',
            })),
            empty: bodyRows(botCard).some(r => r.classList.contains('cross-filter-bot-row')) ? null : text(q('tbody', botCard)),
          },
          paths: {
            badge: badge(pathCard),
            rows: bodyRows(pathCard).filter(r => r.classList.contains('cross-filter-path-row')).map(r => ({ path: cells(r)[0], hits: cells(r)[1], share: cells(r)[2] })),
          },
          abuse: { rows: bodyRows(abuseCard).map(r => ({ ip: cells(r)[0], confidence: cells(r)[1], domain: cells(r)[2], country: cells(r)[3] })) },
          asns: {
            badge: badge(asnCard),
            rows: bodyRows(asnCard).filter(r => r.classList.contains('cross-filter-asn-row')).map(r => ({
              asn: (r as HTMLElement).dataset.asn || '', code: text(q('.asn-code', r)),
              org: text(r.children[0].children[1]), hits: cells(r)[1], share: cells(r)[2],
            })),
          },
          referrers: {
            badge: badge(refCard),
            rows: bodyRows(refCard).filter(r => r.children.length === 3).map(r => ({ referrer: cells(r)[0], hits: cells(r)[1], share: cells(r)[2] })),
          },
        },
        explorer: {
          count: text(q('.log-explorer-header h5 + span', dash)),
          perPage: (document.getElementById('explorer-per-page') as HTMLSelectElement | null)?.value ?? '',
          ipSearch: input('log-table-ip-subnet-search'),
          pathSearch: input('log-table-path-search'),
          rows: emptyRow !== null ? [] : explorerRows.map(r => {
            const c = Array.from(r.children);
            const code = text(q('.country-flag', c[5]));
            return {
              time: text(c[0]), ip: text(c[1]), method: text(c[2]), path: text(c[3]), status: text(c[4]),
              countryCode: code, country: text(c[5]).slice(code.length).trim(), protocol: text(c[6]), userAgent: text(c[7]),
            };
          }),
          emptyMessage: emptyRow,
          pageText: text(q('#explorer-pagination-wrap > span', dash)),
          pageButtons: qa('.exp-page-btn', dash).map(b => ({ page: text(b), active: (b as HTMLElement).style.fontWeight === '700' })),
          firstDisabled: disabled('exp-first-btn'), prevDisabled: disabled('exp-prev-btn'),
          nextDisabled: disabled('exp-next-btn'), lastDisabled: disabled('exp-last-btn'),
        },
        clearPill: { visible: !!pill && getComputedStyle(pill).display !== 'none', text: text(pill) },
      };
    });
  }
}
