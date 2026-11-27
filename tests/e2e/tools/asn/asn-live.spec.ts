import { test, expect, type Page } from '../_support/fixtures';
import { captureApi, type LiveExchange } from '../_support/io';
import type { Scenario } from './generator';
import { type Cidr, aggregate, compactCount, compareCidr, compactRange, grouped, pageCount, parseCidr, showingText, unionSize } from './oracle';
import { DEFAULT_EXPLORER, expectExplorer, expectOverview } from './checks';
import { AsnView, LOOKUP_API, errorBanner, openAsn, primary, searchInput, submitLookup } from './page';

/**
 * @live tests: the real backend and, behind it, RIPEstat. The response is
 * captured and the page must show exactly that; values the backend derives
 * (supernets, address totals) are recomputed from the prefixes in the response.
 * Skipped with E2E_LIVE=0.
 */

type AsnResponse = Record<string, any>;

/** Looks `text` up on the real backend; asks again (at most twice) when RIPEstat itself did not answer. */
async function liveLookup(page: Page, text: string): Promise<LiveExchange<AsnResponse>> {
  let exchange: LiveExchange<AsnResponse> | null = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    exchange = await captureApi<AsnResponse>(page, LOOKUP_API, () => submitLookup(page, text), 60_000);
    if (!/RIPEstat API error/.test(String(exchange.response?.error || ''))) break;
  }
  return exchange as LiveExchange<AsnResponse>;
}

/** The captured response as a scenario: prefixes from the response, supernets from the oracle. */
function fromResponse(response: AsnResponse): Scenario {
  const read = (list: { prefix: string }[]): Cidr[] => list.map(p => {
    const cidr = parseCidr(p.prefix);
    if (!cidr) throw new Error(`the backend returned "${p.prefix}", which is not a CIDR block`);
    return { ...cidr, text: p.prefix };
  });
  const v4 = read(response.ipv4_prefixes);
  return { asn: String(response.asn), holder: response.holder || response.name, payload: response, v4, v6: read(response.ipv6_prefixes), aggregated: aggregate(v4, 4) };
}

test.describe('ASN lookup — live data @live', () => {
  test.skip(process.env.E2E_LIVE === '0', 'live tests disabled');

  test('AS112: the page shows exactly what the backend returned @live', async ({ page, evidence }) => {
    await openAsn(page);
    const exchange = await liveLookup(page, 'AS112');
    await evidence.save('as112-response.json', exchange.response);
    expect(exchange.status, 'POST /api/asn status').toBe(200);
    expect(exchange.request, 'request body').toEqual({ asn: 'AS112' });
    expect(exchange.response.error, 'the backend found AS112').toBeNull();
    const scenario = fromResponse(exchange.response);
    const view = new AsnView(page, primary(page));
    await expect(view.badge()).toHaveText('AS112');
    expect.soft(exchange.response.stats.total_ipv4_prefixes, 'stats.total_ipv4_prefixes equals the number of IPv4 prefixes in the response').toBe(scenario.v4.length);
    expect.soft(exchange.response.stats.total_ipv6_prefixes, 'stats.total_ipv6_prefixes equals the number of IPv6 prefixes in the response').toBe(scenario.v6.length);
    await expectOverview(view, scenario, 'live AS112');
    await expectExplorer(view, scenario, DEFAULT_EXPLORER, 'live AS112');
    await view.tab('bgp').click();
    expect.soft((await view.readTopPeers()).map(p => p.asn), 'live AS112: top neighbours').toEqual(exchange.response.neighbours.top_peers.map((p: any) => `AS${p.asn}`));
  });

  test('"112", "as112" and " AS112 " find the same network as "AS112" @live', async ({ page }) => {
    await openAsn(page);
    const view = new AsnView(page, primary(page));
    let holder: string | null = null;
    for (const text of ['112', 'as112', '  AS112  ']) {
      const exchange = await liveLookup(page, text);
      expect.soft(exchange.request, `"${text}": request body`).toEqual({ asn: text.trim() });
      expect.soft(exchange.response.asn, `"${text}": ASN in the response`).toBe('112');
      await expect.soft(view.badge(), `"${text}": badge`).toHaveText('AS112');
      holder = holder ?? exchange.response.holder;
      await expect.soft(view.heading(), `"${text}": holder`).toHaveText(String(holder));
    }
  });

  test('AS15169: prefix counts, pages and supernets equal an independent computation from the response @live', async ({ page, evidence }) => {
    await openAsn(page);
    const exchange = await liveLookup(page, 'AS15169');
    expect(exchange.response.error, 'the backend found AS15169').toBeNull();
    const scenario = fromResponse(exchange.response);
    await evidence.save('as15169-prefixes.json', { v4: scenario.v4.map(p => p.text), v6: scenario.v6.map(p => p.text) });
    const view = new AsnView(page, primary(page));
    await expect(view.badge()).toHaveText('AS15169');
    await expectOverview(view, scenario, 'live AS15169');
    const total = scenario.v4.length + scenario.v6.length;
    expect.soft(await view.tabCount(), 'live AS15169: tab count').toBe(total);
    await expect.soft(view.showing(), 'live AS15169: "Showing" line').toHaveText(showingText(total, 1));
    await expect.soft(view.pageLabel(), 'live AS15169: page label').toHaveText(`Page 1 of ${pageCount(total)}`);

    const agg = exchange.response.aggregated_ipv4;
    expect.soft(agg.prefixes.map((p: { prefix: string }) => p.prefix), 'live AS15169: supernets computed by the backend equal the minimal cover of its IPv4 prefixes')
      .toEqual(scenario.aggregated.map(p => p.text));
    expect.soft([agg.original_count, agg.aggregated_count, agg.saved_rules], 'live AS15169: aggregate counters')
      .toEqual([scenario.v4.length, scenario.aggregated.length, scenario.v4.length - scenario.aggregated.length]);
    await view.versionButton('ipv4').click();
    await view.aggregateToggle().click();
    await expectExplorer(view, scenario, { ...DEFAULT_EXPLORER, version: 'ipv4', aggregated: true }, 'live AS15169 aggregated');
    await view.aggregateToggle().click();
    await view.versionButton('ipv6').click();
    await expectExplorer(view, scenario, { ...DEFAULT_EXPLORER, version: 'ipv6' }, 'live AS15169 IPv6');
  });

  test('AS15169: prefixes are listed in numeric order of network address, then prefix length @live', async ({ page }) => {
    // The backend sorts both lists before answering (routes/asn.js "Sort IPv4 and IPv6 prefixes"); the page keeps that order.
    await openAsn(page);
    const exchange = await liveLookup(page, 'AS15169');
    expect(exchange.response.error, 'the backend found AS15169').toBeNull();
    const scenario = fromResponse(exchange.response);
    const view = new AsnView(page, primary(page));
    await expect(view.badge()).toHaveText('AS15169');
    for (const [family, list] of [['IPv4', scenario.v4], ['IPv6', scenario.v6]] as const) {
      const misplaced: string[] = [];
      for (let i = 1; i < list.length; i++) {
        if (compareCidr(list[i - 1], list[i]) > 0) misplaced.push(`${list[i - 1].text} is listed before ${list[i].text}`);
      }
      expect.soft(misplaced.slice(0, 6), `${family}: ${misplaced.length} neighbouring prefixes of ${list.length} are out of numeric order (sorted as text instead?)`).toEqual([]);
    }
    await view.versionButton('ipv6').click();
    expect.soft((await view.readRows()).map(r => r.prefix), 'the page lists IPv6 prefixes in the order of the response').toEqual(scenario.v6.slice(0, 25).map(p => p.text));
  });

  test('AS0 is answered with an error, not with a network @live', async ({ page }) => {
    await openAsn(page);
    const exchange = await liveLookup(page, 'AS0');
    await expect(errorBanner(page), 'AS0 is reserved (RFC 7607) and announces nothing').toBeVisible();
    expect.soft(String(exchange.response.error || ''), 'error text from the backend').not.toBe('');
    await expect.soft(errorBanner(page)).toHaveText(String(exchange.response.error));
    expect.soft(await new AsnView(page, primary(page)).tab('prefixes').count(), 'no result for AS0').toBe(0);
  });

  test('AS15169: the IPv4 address total counts each announced address once @live', async ({ page }) => {
    await openAsn(page);
    const exchange = await liveLookup(page, 'AS15169');
    expect(exchange.response.error, 'the backend found AS15169').toBeNull();
    const scenario = fromResponse(exchange.response);
    const view = new AsnView(page, primary(page));
    await expect(view.badge()).toHaveText('AS15169');
    const shown = ((await view.readCards())['IPv4 Prefixes']?.sub || '').replace(/ IPs$/, '');
    const unique = unionSize(scenario.v4);
    const sum = scenario.v4.reduce((acc, p) => acc + 2n ** BigInt(32 - p.length), 0n);
    const range = compactRange(shown);
    expect(range !== null && unique >= range.low && unique <= range.high,
      `the IPv4 card says "${shown} IPs". The ${scenario.v4.length} announced prefixes cover ${grouped(unique)} different addresses (${compactCount(unique)}); `
      + `adding up the size of every prefix, with more-specifics counted again inside their covering block, gives ${grouped(sum)} (${compactCount(sum)})`).toBe(true);
  });

  test('AS15169: country and registry are a country code and an Internet registry @live', async ({ page }) => {
    await openAsn(page);
    const exchange = await liveLookup(page, 'AS15169');
    expect(exchange.response.error, 'the backend found AS15169').toBeNull();
    const view = new AsnView(page, primary(page));
    await expect(view.badge()).toHaveText('AS15169');
    const header = await view.readHeader();
    await view.tab('bgp').click();
    const country = ((await view.contactField('Country Jurisdiction').textContent()) || '').trim();
    const registry = ((await view.contactField('Regional Internet Registry (RIR)').textContent()) || '').trim();
    expect.soft(country, `"Country Jurisdiction" (and the pin chip "${header.country}") must be a two-letter country code or "Unknown"; Google's AS15169 is registered in the US`)
      .toMatch(/^([A-Z]{2}|Unknown)$/);
    expect.soft(registry, `"Regional Internet Registry (RIR)" (and the chip "${header.registry}") must name a registry; AS15169 is assigned by ARIN`)
      .toMatch(/^(ARIN|RIPE( NCC)?|APNIC|LACNIC|AFRINIC|Unknown)$/i);
  });

  test('a number above 4294967295 is refused as not being an ASN @live', async ({ page, guard }) => {
    guard.allow(/status of 400/);
    await openAsn(page);
    const view = new AsnView(page, primary(page));
    for (const text of ['AS4294967296', '99999999999']) {
      const exchange = await liveLookup(page, text);
      await expect(errorBanner(page).or(view.badge()).first()).toBeVisible();
      expect.soft(await view.tab('prefixes').count(), `"${text}": no result may be shown`).toBe(0);
      const message = await errorBanner(page).count() ? ((await errorBanner(page).textContent()) || '').trim() : '(no error)';
      expect.soft(exchange.status, `"${text}" is larger than the largest AS number (32 bits); the backend answered HTTP ${exchange.status} and the page says "${message}"`).toBe(400);
      expect.soft(message, `"${text}": the error must say the input is not a valid ASN`).toMatch(/valid ASN|invalid|out of range/i);
    }
  });

  test('a fragment such as "AS" or "x" is refused, not resolved to some organisation @live', async ({ page, guard }) => {
    guard.allow(/status of 400/);
    await openAsn(page);
    const view = new AsnView(page, primary(page));
    for (const text of ['AS', 'x']) {
      const exchange = await liveLookup(page, text);
      await expect(errorBanner(page).or(view.badge()).first()).toBeVisible();
      const shown = await view.tab('prefixes').count() ? `${(await view.readHeader()).badge} ${(await view.readHeader()).title} (${(await view.readHeader()).resolvedFrom})` : 'an error';
      expect.soft(exchange.status, `"${text}" is not an ASN, an address, a domain or an organisation's name; the backend answered HTTP ${exchange.status} and the page shows ${shown}`).toBe(400);
      expect.soft(await view.tab('prefixes').count(), `"${text}": no network may be shown`).toBe(0);
    }
  });

  test('an organisation name and an IP address resolve to their network and the page says how @live', async ({ page }) => {
    await openAsn(page);
    const view = new AsnView(page, primary(page));

    const byName = await liveLookup(page, 'GitHub');
    expect(byName.response.error, 'the backend found GitHub').toBeNull();
    await expect(view.badge(), '"GitHub" is AS36459').toHaveText('AS36459');
    expect.soft((await view.readHeader()).resolvedFrom, '"GitHub": note').toBe('Resolved from Organization "GitHub"');
    await expect.soft(searchInput(page)).toHaveValue('GitHub');
    await expectOverview(view, fromResponse(byName.response), 'live "GitHub"');

    const byIp = await liveLookup(page, '192.175.48.1');
    expect(byIp.response.error, 'the backend resolved 192.175.48.1').toBeNull();
    await expect(view.badge(), '192.175.48.1 belongs to AS112').toHaveText('AS112');
    expect.soft((await view.readHeader()).resolvedFrom, '"192.175.48.1": note').toBe('Resolved from IP "192.175.48.1"');
    await expectOverview(view, fromResponse(byIp.response), 'live "192.175.48.1"');
  });
});
