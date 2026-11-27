import { test, expect } from '../_support/fixtures';
import { openTool } from '../_support/navigation';
import { captureApi } from '../_support/io';
import {
  NOT_DOMAINS, compareNameservers, completeSnapshot, daysUntil, riskSignals, sameMonthSpelling, statusLabel, utcStamp, type Snapshot,
} from './oracle';
import { HEADING, ROUTE, cardValue, emptyState, errorAlert, lookup, readView, statCards, submit } from './page';
import { expectPageShows, expectRawShows } from './checks';
import { liveNameservers, registryRecord } from './registry';

/**
 * WHOIS Lookup against the real backend.
 *
 *  - Name validation needs no network: the backend refuses these names itself.
 *  - `@live` tests look up real domains. The page must show exactly what the
 *    API returned, and that must agree with a second source the test queries
 *    on its own: the registry's RDAP server and DNS.
 */

const row = (rows: [string, string][], label: string) => rows.find(([name]) => name === label)?.[1] ?? `(no "${label}" row)`;

test.describe('WHOIS — name validation by the real backend', () => {
  test('names that are not valid domain names are refused with a message and no result', async ({ page, guard }) => {
    guard.allow(/status of 400/);
    await openTool(page, ROUTE, HEADING);
    for (const { input, why } of NOT_DOMAINS) {
      await lookup(page, input);
      await expect.soft(errorAlert(page), `"${input}" is not a domain name (${why}); an error must be shown`).toHaveText('Invalid domain name.');
      await expect.soft(statCards(page), `no result may be shown for "${input}"`).toHaveCount(0);
      await expect.soft(emptyState(page), `no "enter a domain" hint next to the error for "${input}"`).toHaveCount(0);
    }
  });

  test('a name written with a trailing dot (the DNS root) is looked up as the same name or refused with a message', async ({ page, guard }) => {
    guard.allow(/status of 400/);
    await openTool(page, ROUTE, HEADING);
    // The name is under the reserved .invalid TLD, so whichever way the backend decides, no registry is asked for long.
    const typed = 'trailing-dot-check.invalid.';
    await lookup(page, typed);
    if (await statCards(page).count()) {
      await expect.soft(cardValue(page, 'Domain'), `"${typed}" accepted: the result is for the name without the dot`).toHaveText('trailing-dot-check.invalid');
    } else {
      await expect.soft(errorAlert(page), `"${typed}" refused: a message says why`).toHaveText(/\S/);
      await expect.soft(emptyState(page), `no "enter a domain" hint next to the error for "${typed}"`).toHaveCount(0);
    }
  });
});

test.describe('WHOIS — real registries @live', () => {
  test.skip(process.env.E2E_LIVE === '0', 'live tests disabled');

  for (const domain of ['example.com', 'iana.org']) {
    test(`${domain}: the page shows exactly what the API returned, and that agrees with the registry's RDAP record and with DNS`, async ({ page, evidence }) => {
      await openTool(page, ROUTE, HEADING);
      const before = Date.now();
      const live = await captureApi<Snapshot>(page, '/api/whois', () => submit(page, domain), 60_000);
      await evidence.save(`whois-live-${domain}.json`, live);
      expect(live.status, `POST /api/whois for ${domain}`).toBe(200);
      expect.soft(live.request, 'request body').toEqual({ domain });
      await expect(cardValue(page, 'Domain')).toHaveText(domain);

      // 1. The page against the API answer.
      const snapshot = completeSnapshot(live.response, live.response.checked_at_utc);
      const shown = await expectPageShows(page, snapshot, `live ${domain} vs API answer`);
      await expectRawShows(page, snapshot, `live ${domain} vs API answer`);

      // 2. The page against the registry and DNS, asked directly.
      const record = await registryRecord(domain);
      const dns = await liveNameservers(domain);
      await evidence.save(`whois-registry-${domain}.json`, { record, dns });
      expect(record.found, `${record.url} must know ${domain}`).toBe(true);
      const ctx = `live ${domain} vs registry (${record.url})`;

      expect.soft(shown.source, `${ctx}: the registry offers RDAP, so the source is RDAP`).toBe('RDAP');
      expect.soft(row(shown.cards, 'Registration'), `${ctx}: Registration card`).toBe('Registered');
      if (record.registrar) expect.soft(row(shown.cards, 'Registrar'), `${ctx}: Registrar card`).toBe(record.registrar);
      if (record.ianaId) expect.soft(row(shown.registrar, 'Registrar IANA ID'), `${ctx}: Registrar IANA ID`).toBe(record.ianaId);
      expect.soft(sameMonthSpelling(row(shown.registrar, 'Creation Date')), `${ctx}: Creation Date (registration event ${record.registration})`).toBe(utcStamp(record.registration));
      expect.soft(sameMonthSpelling(row(shown.registrar, 'Expiry Date')), `${ctx}: Expiry Date (expiration event ${record.expiration})`).toBe(utcStamp(record.expiration));
      if (record.lastChanged) {
        expect.soft(sameMonthSpelling(row(shown.registrar, 'Updated Date')), `${ctx}: Updated Date (last changed event ${record.lastChanged})`).toBe(utcStamp(record.lastChanged));
      }

      const checkedAt = Date.parse(snapshot.checked_at_utc);
      expect.soft(checkedAt >= before - 120_000 && checkedAt <= Date.now() + 120_000, `${ctx}: "Checked At" (${snapshot.checked_at_utc}) is the time of this lookup`).toBe(true);
      expect.soft(row(shown.cards, 'Days Until Expiry'), `${ctx}: days from the check time to the registry's expiration ${record.expiration}`)
        .toBe(String(daysUntil(record.expiration, snapshot.checked_at_utc)));
      if (record.signed !== null) {
        expect.soft(row(shown.cards, 'DNSSEC'), `${ctx}: DNSSEC (registry says delegationSigned=${record.signed})`).toBe(record.signed ? 'signed' : 'unsigned');
      }

      const registryList = row(shown.nameservers, 'RDAP Nameservers').split(', ').sort();
      expect.soft(registryList, `${ctx}: registry nameservers`).toEqual([...record.nameservers].sort());
      const dnsList = row(shown.nameservers, 'Live DNS Nameservers').split(', ').sort();
      expect.soft(dnsList, `${ctx}: live DNS nameservers (NS query from the test machine)`).toEqual(dns);
      const comparison = compareNameservers(record.nameservers, dns);
      expect.soft(row(shown.nameservers, 'Exact Match'), `${ctx}: Exact Match for registry [${record.nameservers}] vs DNS [${dns}]`).toBe(comparison.match ? 'Yes' : 'No');
      expect.soft(row(shown.nameservers, 'Only In RDAP'), `${ctx}: Only In RDAP`).toBe(comparison.onlyRegistry.join(', ') || 'None');
      expect.soft(row(shown.nameservers, 'Only In DNS'), `${ctx}: Only In DNS`).toBe(comparison.onlyDns.join(', ') || 'None');

      for (const code of record.status) {
        const label = statusLabel(code);
        if (label) expect.soft(shown.statusPills, `${ctx}: status "${code}" is shown as "${label}"`).toContain(label);
      }
      expect.soft(shown.statusPills.length, `${ctx}: no more status labels than the registry has status codes (${record.status.join(', ')})`).toBeLessThanOrEqual(record.status.length);

      // 3. Risk sentences follow from the other values on the page.
      const { risk_signals: _shownRisks, ...facts } = snapshot;
      expect.soft(shown.riskItems, `${ctx}: risk signals implied by the snapshot's own fields`).toEqual(riskSignals(facts, snapshot.checked_at_utc));
    });
  }

  test('a domain that is not registered shows "Unknown / Not Found" and no registrar, dates, status or nameservers', async ({ page, rng, evidence }) => {
    const domain = `e2e-${rng.string(18, 'abcdefghijklmnopqrstuvwxyz0123456789')}-unregistered.com`;
    const record = await registryRecord(domain);
    const dns = await liveNameservers(domain);
    expect(record.found, `precondition: the .com registry (${record.url}) has no record of ${domain}`).toBe(false);
    expect(dns, `precondition: ${domain} has no NS records`).toEqual([]);

    await openTool(page, ROUTE, HEADING);
    const live = await captureApi<Snapshot>(page, '/api/whois', () => submit(page, domain), 60_000);
    await evidence.save('whois-live-unregistered.json', live);
    expect(live.status, `POST /api/whois for ${domain}`).toBe(200);
    await expect(cardValue(page, 'Domain')).toHaveText(domain);
    const shown = await expectPageShows(page, completeSnapshot(live.response, live.response.checked_at_utc), `live ${domain} vs API answer`);

    const ctx = `${domain} is not registered (registry RDAP: 404, DNS: no NS)`;
    expect.soft(row(shown.cards, 'Registration'), `${ctx}: Registration card`).toBe('Unknown / Not Found');
    expect.soft(row(shown.cards, 'Registrar'), `${ctx}: Registrar card`).toBe('Unknown');
    expect.soft(row(shown.cards, 'Days Until Expiry'), `${ctx}: Days Until Expiry card`).toBe('Unknown');
    expect.soft(row(shown.registrar, 'Creation Date'), `${ctx}: Creation Date (an unregistered name has none)`).toBe('Unknown');
    expect.soft(row(shown.registrar, 'Updated Date'), `${ctx}: Updated Date (an unregistered name has none)`).toBe('Unknown');
    expect.soft(row(shown.registrar, 'Expiry Date'), `${ctx}: Expiry Date (an unregistered name has none)`).toBe('Unknown');
    expect.soft(shown.statusPills, `${ctx}: Domain Status (an unregistered name has none)`).toEqual([]);
    expect.soft(row(shown.nameservers, 'WHOIS Nameservers'), `${ctx}: registry nameservers (an unregistered name has none)`).toBe('None');
    expect.soft(row(shown.nameservers, 'Live DNS Nameservers'), `${ctx}: live DNS nameservers`).toBe('None');
  });

  test('a name under the reserved .invalid top-level domain is never reported as registered', async ({ page, rng, evidence, guard }) => {
    // RFC 2606 reserves .invalid: it is not delegated, so nothing under it can be registered.
    const domain = `${rng.string(10, 'abcdefghijklmnopqrstuvwxyz')}.invalid`;
    guard.allow(/status of (400|404|502)|HTTP 502/);
    await openTool(page, ROUTE, HEADING);
    const live = await captureApi<Snapshot>(page, '/api/whois', () => submit(page, domain), 60_000);
    await evidence.save('whois-live-invalid-tld.json', live);
    await expect(page.locator('main .stat-card, .signal-tool-primary .alert-custom').first()).toBeVisible();
    if (await statCards(page).count()) {
      await expect(cardValue(page, 'Registration'), `${domain} cannot be registered (.invalid is reserved); the Registration card must not say "Registered"`).toHaveText('Unknown / Not Found');
    } else {
      await expect(errorAlert(page), `${domain}: an error is an acceptable answer`).toBeVisible();
    }
  });

  test('an IP address is refused: it is not a domain name and has no domain registration', async ({ page, evidence, guard }) => {
    guard.allow(/status of (400|404|502)|HTTP 502/);
    await openTool(page, ROUTE, HEADING);
    const outcomes: Record<string, unknown> = {};
    for (const address of ['8.8.8.8', '192.0.2.1', '2001:4860:4860::8888']) {
      const live = await captureApi<Snapshot>(page, '/api/whois', () => submit(page, address), 60_000);
      await expect(page.locator('main .stat-card, .signal-tool-primary .alert-custom').first()).toBeVisible();
      const cards = (await statCards(page).count()) ? (await readView(page)).cards : [];
      outcomes[address] = { request: live.request, status: live.status, cards };
      expect.soft(cards, `typing the IP address ${address}: the tool must show an error, not a domain registration (it looked up "${JSON.stringify(live.request)}")`).toEqual([]);
    }
    await evidence.save('whois-live-ip-addresses.json', outcomes);
  });
});
