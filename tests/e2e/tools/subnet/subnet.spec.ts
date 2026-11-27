import { test, expect, type Page } from '../_support/fixtures';
import { openTool, expectToolLinkedFromHome } from '../_support/navigation';
import { expectNoUiGlitches, expectControlsUsable, VIEWPORTS } from '../_support/ui-audit';
import { captureDownload, readClipboard, clearClipboard } from '../_support/io';
import { parseCsv } from '../_support/csv';
import { expectedSubnet, grouped, randomIp, maskForPrefix, bigToIp, INVALID_INPUTS, type SubnetExpectation } from './oracle';

/**
 * Subnet / CIDR Calculator (/subnet) — runs entirely in the browser.
 *
 * Oracle: ./oracle.ts recomputes every value with BigInt arithmetic.
 * Inputs: random addresses for every prefix length, each run.
 */

const ROUTE = '/subnet';

const input = (page: Page) => page.getByPlaceholder('10.0.0.0/24 or 192.168.1.0 255.255.255.0');
const calculateButton = (page: Page) => page.getByRole('button', { name: 'Calculate' });
const awsToggle = (page: Page) => page.getByRole('checkbox', { name: 'AWS Mode' });
const errorBanner = (page: Page) => page.locator('.signal-tool-primary').getByText(/Invalid CIDR/);
const detailsTable = (page: Page) => page.locator('.signal-tool-primary table');

/** Value shown in one of the four summary cards, found by its caption. */
function card(page: Page, caption: string) {
  return page.locator('.signal-tool-primary div.glass')
    .filter({ has: page.locator('div', { hasText: new RegExp(`^${caption}$`) }) })
    .locator('div').first();
}

/** Value cell of a "Subnet Details" row, found by its label. */
function detail(page: Page, label: string) {
  return detailsTable(page).locator('tr')
    .filter({ has: page.locator('td', { hasText: new RegExp(`^${label}$`) }) })
    .locator('td').nth(1);
}

async function calculate(page: Page, value: string) {
  await input(page).fill(value);
  await calculateButton(page).click();
}

/** Compares every value on the page with the oracle. Soft: reports all mismatches. */
async function expectResult(page: Page, typed: string, want: SubnetExpectation, aws = false) {
  const ctx = `input "${typed}"`;
  await expect.soft(card(page, 'Network CIDR'), `${ctx}: Network CIDR card`).toHaveText(want.cidr);
  await expect.soft(card(page, aws ? 'AWS Usable Hosts' : 'Usable Hosts'), `${ctx}: usable hosts card`)
    .toHaveText(grouped(aws ? want.awsUsableHosts : want.usableHosts));
  await expect.soft(card(page, 'Total Addresses'), `${ctx}: Total Addresses card`).toHaveText(grouped(want.totalAddresses));
  await expect.soft(card(page, 'Prefix Length'), `${ctx}: Prefix Length card`).toHaveText(`/${want.prefix}`);

  const rows: [string, string][] = [
    ['Network Address', want.network],
    ['Broadcast Address', want.broadcast],
    ['First Usable Host', want.firstHost],
    ['Last Usable Host', want.lastHost],
    ['Subnet Mask', want.mask],
    ['Wildcard Mask', want.wildcard],
    ['Total Addresses', grouped(want.totalAddresses)],
    ['Usable Hosts', grouped(want.usableHosts)],
    ['CIDR Notation', want.cidr],
    ['IP Class', want.ipClass],
  ];
  for (const [label, value] of rows) {
    await expect.soft(detail(page, label), `${ctx}: "${label}" row`).toHaveText(value);
  }
  await expect.soft(detail(page, 'IP Type'), `${ctx}: "IP Type" row`).toContainText(want.ipType);
  if (aws) {
    await expect.soft(detail(page, 'AWS Usable Hosts'), `${ctx}: "AWS Usable Hosts" row`).toHaveText(grouped(want.awsUsableHosts));
  } else {
    await expect.soft(detailsTable(page).getByText('AWS Usable Hosts'), `${ctx}: no AWS row outside AWS mode`).toHaveCount(0);
  }
}

test.describe('Subnet calculator — access and layout', () => {
  test('is linked from the home page and the sidebar', async ({ page }) => {
    await expectToolLinkedFromHome(page, ROUTE);
    await expect(page.getByRole('heading', { level: 1, name: 'Subnet / CIDR Calculator' })).toBeVisible();
  });

  test('opens with its controls ready and an empty result area', async ({ page }) => {
    await openTool(page, ROUTE, 'Subnet / CIDR Calculator');
    await expect(page).toHaveTitle(/Subnet/i);
    await expectControlsUsable(page, {
      'address input': 'input[placeholder^="10.0.0.0/24"]',
      'AWS Mode checkbox': 'input[type="checkbox"]',
      'Calculate button': 'button.btn-primary',
    });
    await expect(input(page), 'the input starts with an example network').toHaveValue('192.168.1.0/24');
    await expect(awsToggle(page)).not.toBeChecked();
    await expect(page.getByRole('heading', { name: 'Size a subnet' }), 'empty state before the first calculation').toBeVisible();
    await expect(detailsTable(page), 'no result table before calculating').toHaveCount(0);
    await expect(page.getByRole('complementary', { name: 'Plan your network' }), 'guide panel').toBeVisible();
  });

  for (const [name, viewport] of Object.entries(VIEWPORTS)) {
    test(`has no layout problems at ${name} size (${viewport.width}px), before and after a result`, async ({ page }) => {
      await page.setViewportSize(viewport);
      await openTool(page, ROUTE, 'Subnet / CIDR Calculator');
      await expectNoUiGlitches(page, `${ROUTE} empty state @${name}`);
      await awsToggle(page).check();
      await calculate(page, '10.20.30.40/19');
      await expect(detailsTable(page)).toBeVisible();
      await expectNoUiGlitches(page, `${ROUTE} with result @${name}`);
      await calculate(page, 'nonsense');
      await expect(errorBanner(page)).toBeVisible();
      await expectNoUiGlitches(page, `${ROUTE} error state @${name}`);
    });
  }
});

test.describe('Subnet calculator — results match independent arithmetic', () => {
  test('every prefix length /0–/32 with a random address', async ({ page, rng, evidence }) => {
    await openTool(page, ROUTE, 'Subnet / CIDR Calculator');
    const cases = Array.from({ length: 33 }, (_, prefix) => ({ ip: randomIp(rng), prefix }));
    await evidence.save('subnet-inputs.json', cases);
    for (const { ip, prefix } of cases) {
      const typed = `${ip}/${prefix}`;
      await calculate(page, typed);
      await expectResult(page, typed, expectedSubnet(ip, prefix));
    }
  });

  test('"address netmask" notation gives the same result as CIDR notation', async ({ page, rng, evidence }) => {
    await openTool(page, ROUTE, 'Subnet / CIDR Calculator');
    const cases = rng.sample(Array.from({ length: 33 }, (_, p) => p), 10).map(prefix => ({ ip: randomIp(rng), prefix }));
    await evidence.save('subnet-netmask-inputs.json', cases);
    for (const { ip, prefix } of cases) {
      const typed = `${ip} ${bigToIp(maskForPrefix(prefix))}`;
      await calculate(page, typed);
      await expectResult(page, typed, expectedSubnet(ip, prefix));
    }
  });

  test('a bare address is treated as a single host (/32)', async ({ page, rng }) => {
    await openTool(page, ROUTE, 'Subnet / CIDR Calculator');
    const ip = randomIp(rng);
    await calculate(page, ip);
    await expectResult(page, ip, expectedSubnet(ip, 32));
  });

  test('surrounding spaces are ignored and Enter runs the calculation', async ({ page, rng }) => {
    await openTool(page, ROUTE, 'Subnet / CIDR Calculator');
    const ip = randomIp(rng);
    const prefix = rng.int(8, 30);
    await input(page).fill(`   ${ip}/${prefix}  `);
    await input(page).press('Enter');
    await expectResult(page, `${ip}/${prefix} (with spaces, Enter)`, expectedSubnet(ip, prefix));
  });

  test('address class and type at every boundary', async ({ page }) => {
    await openTool(page, ROUTE, 'Subnet / CIDR Calculator');
    const boundaries = [
      '0.0.0.0/8', '9.255.255.255/32', '10.0.0.0/8', '10.255.255.255/32', '11.0.0.0/8',
      '126.255.255.255/32', '127.0.0.1/8', '127.255.255.255/32', '128.0.0.0/16',
      '169.253.255.255/32', '169.254.0.0/16', '169.254.255.255/32', '169.255.0.0/16',
      '172.15.255.255/32', '172.16.0.0/12', '172.31.255.255/32', '172.32.0.0/16',
      '191.255.255.255/32', '192.0.0.0/24', '192.167.255.255/32', '192.168.0.0/16', '192.168.255.255/32', '192.169.0.0/16',
      '223.255.255.255/32', '224.0.0.0/4', '239.255.255.255/32', '240.0.0.0/4', '255.255.255.255/32',
    ];
    for (const typed of boundaries) {
      const [ip, prefix] = typed.split('/');
      await calculate(page, typed);
      await expectResult(page, typed, expectedSubnet(ip, Number(prefix)));
    }
  });
});

test.describe('Subnet calculator — AWS mode', () => {
  test('subtracts the five reserved addresses and never goes below zero', async ({ page, rng }) => {
    await openTool(page, ROUTE, 'Subnet / CIDR Calculator');
    await awsToggle(page).check();
    // Small subnets are where the subtraction can go wrong: include all of them.
    const prefixes = [32, 31, 30, 29, 28, ...rng.sample([27, 26, 25, 24, 22, 20, 16, 12, 8, 1, 0], 5)];
    for (const prefix of prefixes) {
      const ip = randomIp(rng);
      const typed = `${ip}/${prefix}`;
      await calculate(page, typed);
      await expectResult(page, `${typed} (AWS mode)`, expectedSubnet(ip, prefix), true);
    }
    await expect(page.getByText('AWS reservations: Network, Gateway, DNS, Future, Broadcast (−5 IPs)')).toBeVisible();
  });

  test('switching AWS mode on and off updates an existing result without recalculating', async ({ page, rng }) => {
    await openTool(page, ROUTE, 'Subnet / CIDR Calculator');
    const ip = randomIp(rng);
    const prefix = rng.int(16, 28);
    const typed = `${ip}/${prefix}`;
    const want = expectedSubnet(ip, prefix);
    await calculate(page, typed);
    await expectResult(page, typed, want, false);
    await awsToggle(page).check();
    await expectResult(page, `${typed} after enabling AWS mode`, want, true);
    await awsToggle(page).uncheck();
    await expectResult(page, `${typed} after disabling AWS mode`, want, false);
    await expect(page.getByText(/AWS reservations/)).toHaveCount(0);
  });
});

test.describe('Subnet calculator — invalid input', () => {
  for (const { input: typed, why } of INVALID_INPUTS) {
    test(`rejects "${typed}" (${why})`, async ({ page }) => {
      await openTool(page, ROUTE, 'Subnet / CIDR Calculator');
      await calculate(page, typed);
      await expect(errorBanner(page), `"${typed}" is not a valid network (${why}); an error must be shown`).toBeVisible();
      await expect(detailsTable(page), `no result may be shown for "${typed}"`).toHaveCount(0);
    });
  }

  test('an empty input does nothing: no result and no error', async ({ page }) => {
    await openTool(page, ROUTE, 'Subnet / CIDR Calculator');
    await calculate(page, '   ');
    await expect(errorBanner(page)).toHaveCount(0);
    await expect(detailsTable(page)).toHaveCount(0);
    await expect(page.getByRole('heading', { name: 'Size a subnet' })).toBeVisible();
  });

  test('an error replaces the previous result, and a valid input clears the error', async ({ page, rng }) => {
    await openTool(page, ROUTE, 'Subnet / CIDR Calculator');
    const ip = randomIp(rng);
    await calculate(page, `${ip}/24`);
    await expect(detailsTable(page)).toBeVisible();
    await calculate(page, '999.1.1.1/24');
    await expect(errorBanner(page)).toBeVisible();
    await expect(detailsTable(page), 'the stale result must disappear').toHaveCount(0);
    await calculate(page, `${ip}/20`);
    await expect(errorBanner(page), 'the error must clear').toHaveCount(0);
    await expectResult(page, `${ip}/20`, expectedSubnet(ip, 20));
  });
});

test.describe('Subnet calculator — export and copy', () => {
  test('Export CSV downloads a file whose values equal the oracle', async ({ page, rng, evidence }) => {
    await openTool(page, ROUTE, 'Subnet / CIDR Calculator');
    const ip = randomIp(rng);
    const prefix = rng.int(1, 30);
    const want = expectedSubnet(ip, prefix);
    await calculate(page, `${ip}/${prefix}`);
    await expect(detailsTable(page)).toBeVisible();

    const file = await captureDownload(page, () => page.getByRole('button', { name: 'Export CSV' }).click());
    await evidence.save('subnet-export.csv', file.text);
    expect(file.filename, 'file name carries the network').toBe(`subnet-report-${want.network}-${prefix}.csv`);

    const rows = parseCsv(file.text);
    expect(rows.length, 'one header row and one data row').toBe(2);
    const record = Object.fromEntries(rows[0].map((name, i) => [name, rows[1][i]]));
    const expected: Record<string, string> = {
      cidr: want.cidr,
      prefix: String(prefix),
      networkStr: want.network,
      broadcastStr: want.broadcast,
      firstHostStr: want.firstHost,
      lastHostStr: want.lastHost,
      maskStr: want.mask,
      wildcardStr: want.wildcard,
      totalHosts: want.totalAddresses.toString(),
      usableHosts: want.usableHosts.toString(),
      ipClass: want.ipClass,
    };
    for (const [column, value] of Object.entries(expected)) {
      expect.soft(record[column], `CSV column "${column}"`).toBe(value);
    }
    expect.soft(record.ipType, 'CSV column "ipType"').toContain(want.ipType);
  });

  test('Copy Summary puts the displayed values on the clipboard and confirms', async ({ page, rng }) => {
    await openTool(page, ROUTE, 'Subnet / CIDR Calculator');
    const ip = randomIp(rng);
    const prefix = rng.int(1, 30);
    const want = expectedSubnet(ip, prefix);
    await calculate(page, `${ip}/${prefix}`);
    await clearClipboard(page);

    await page.getByRole('button', { name: 'Copy Summary' }).click();
    await expect(page.getByRole('button', { name: 'Copied Details!' }), 'button confirms the copy').toBeVisible();
    expect(await readClipboard(page)).toBe([
      `CIDR: ${want.cidr}`,
      `Netmask: ${want.mask}`,
      `Wildcard: ${want.wildcard}`,
      `Network: ${want.network}`,
      `Broadcast: ${want.broadcast}`,
      `Usable Range: ${want.firstHost} - ${want.lastHost}`,
      `Total Hosts: ${want.totalAddresses}`,
      `Usable Hosts: ${want.usableHosts}`,
    ].join('\n'));
    await expect(page.getByRole('button', { name: 'Copy Summary' }), 'label returns after two seconds').toBeVisible({ timeout: 5_000 });
  });
});
