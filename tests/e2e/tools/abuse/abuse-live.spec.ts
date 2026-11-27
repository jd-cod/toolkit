import { reverse } from 'node:dns/promises';
import { test, expect } from '../_support/fixtures';
import { openTool } from '../_support/navigation';
import { captureApi, type LiveExchange } from '../_support/io';
import { expectResults } from './checks';
import { MmdbReader, geoFacts } from './mmdb';
import { RISK_LABELS, expectedRows, isSpecialPurpose, type AbuseResponse, type BatchEntry, type IpInfoRecord } from './oracle';
import { HEADING, ROUTE, errorBanner, lookupButton, readTable, resultsPanel, submit } from './page';

/**
 * /abuse against the real backend (@live: /api/ipinfo asks Cloudflare's DNS
 * for PTR records). The page must show exactly what the API returned, the
 * GeoIP columns must equal an independent read of the database files the
 * frontend serves, and PTR names must agree with this machine's resolver.
 */

test.describe('IP Info lookup — real backend @live', () => {
  test.skip(process.env.E2E_LIVE === '0', 'live tests disabled');

  async function liveLookup(page: import('@playwright/test').Page, text: string) {
    let abuse: LiveExchange<AbuseResponse> | undefined;
    const ipinfo = await captureApi<{ results: IpInfoRecord[] }>(page, '/api/ipinfo', async () => {
      abuse = await captureApi<AbuseResponse>(page, '/api/abuse', () => submit(page, text));
    });
    await expect(resultsPanel(page).or(errorBanner(page)).first()).toBeVisible({ timeout: 45_000 });
    await expect(lookupButton(page)).toBeEnabled();
    return { ipinfo, abuse: abuse as LiveExchange<AbuseResponse> };
  }

  test('well-known addresses: the page shows exactly the API answer, the GeoIP files and the real PTR names', async ({ page, request, evidence }) => {
    // Written in full: the page does not accept the "::" form (see the IPv6 input test in abuse.spec.ts).
    const publicDns: Record<string, string> = {
      '8.8.8.8': 'dns.google',
      '1.1.1.1': 'one.one.one.one',
      '208.67.222.222': 'resolver1.opendns.com',
      '2001:4860:4860:0:0:0:0:8888': 'dns.google',
    };
    const entries: BatchEntry[] = [
      { ip: '8.8.8.8', hits: 120 }, { ip: '1.1.1.1', hits: 1 }, { ip: '2001:4860:4860:0:0:0:0:8888', hits: 7 },
      { ip: '208.67.222.222', hits: 1 }, { ip: '10.20.30.40', hits: 3 }, { ip: '192.0.2.5', hits: 1 },
    ];
    const text = entries.map(entry => (entry.hits > 1 ? `${entry.ip} ${entry.hits}` : entry.ip)).join('\n');
    const [countryFile, asnFile] = await Promise.all([request.get('/data/GeoLite2-Country.mmdb'), request.get('/data/GeoLite2-ASN.mmdb')]);
    const countries = new MmdbReader(await countryFile.body());
    const networks = new MmdbReader(await asnFile.body());
    const geo = Object.fromEntries(entries.map(({ ip }) => [ip, geoFacts(countries, networks, ip)]));

    await openTool(page, ROUTE, HEADING);
    const live = await liveLookup(page, text);
    await evidence.save('real-answers.json', { ...live, geo });
    expect(live.ipinfo.status, 'POST /api/ipinfo').toBe(200);
    expect(live.abuse.status, 'POST /api/abuse').toBe(200);
    expect.soft(live.ipinfo.request, 'request sent to /api/ipinfo').toEqual({ ips: entries.map(entry => entry.ip) });
    expect.soft(live.abuse.request, 'request sent to /api/abuse').toEqual({ ips: entries });

    const rows = expectedRows(entries, { ipinfo: live.ipinfo.response.results, abuse: live.abuse.response, geo });
    const shown = await expectResults(page, rows, 'real backend, well-known addresses');

    // Independent facts about these addresses.
    expect.soft(geo['8.8.8.8'], 'GeoLite2 knows 8.8.8.8 as Google in the US (sanity check of the database read)').toMatchObject({ country_code: 'US', asn: 15169 });
    expect.soft(shown.table.find(row => row.ip === '8.8.8.8')?.asn, 'AS number shown for 8.8.8.8').toBe('AS15169');
    expect.soft(shown.table.find(row => row.ip === '1.1.1.1')?.asn, 'AS number shown for 1.1.1.1').toBe('AS13335');
    for (const { ip } of entries) {
      const record = live.ipinfo.response.results.find(item => item.ip === ip);
      const row = shown.table.find(item => item.ip === ip);
      expect.soft(record?.is_private, `/api/ipinfo is_private for ${ip} (IANA special-purpose registry)`).toBe(isSpecialPurpose(ip));
      if (isSpecialPurpose(ip)) {
        expect.soft(row?.badge, `risk badge for the private/reserved address ${ip}`).toBe(RISK_LABELS.safe);
        expect.soft(row?.ptr, `PTR for the private/reserved address ${ip}`).toBe('No PTR record');
      }
    }
    for (const [ip, name] of Object.entries(publicDns)) {
      const row = shown.table.find(item => item.ip === ip);
      // Second source: this machine's resolver. When it cannot answer, only the well-known name is checked.
      const local = await reverse(ip.includes(':') ? '2001:4860:4860::8888' : ip).catch(() => null);
      if (local && local.length) expect.soft(local, `PTR shown for ${ip} ("${row?.ptr}") is one of the names this machine resolves`).toContain(row?.ptr);
      expect.soft(row?.ptr, `PTR shown for ${ip}`).toBe(name);
    }
  });

  test('reserved IPv4 and IPv6 ranges are classified as private/reserved and shown as Safe, not looked up as public hosts', async ({ page, evidence }) => {
    const reserved: [string, string][] = [
      ['100.64.0.1', 'shared address space 100.64.0.0/10 (RFC 6598)'],
      ['198.18.0.1', 'benchmarking 198.18.0.0/15 (RFC 2544)'],
      ['240.0.0.1', 'reserved 240.0.0.0/4'],
      ['255.255.255.255', 'limited broadcast'],
      ['0.0.0.0', 'this network 0.0.0.0/8'],
      ['fd12:3456:789a:1:0:0:0:1', 'unique local fc00::/7 (RFC 4193)'],
      ['fe80:0:0:0:1:2:3:4', 'link-local fe80::/10'],
      ['febf:0:0:0:1:2:3:4', 'link-local fe80::/10 (upper end of the block)'],
      ['0:0:0:0:0:0:0:1', 'loopback ::1 written in full'],
      ['2001:db8:0:0:0:0:0:1', 'documentation 2001:db8::/32 (RFC 3849)'],
      ['ff02:0:0:0:0:0:0:1', 'multicast ff00::/8'],
    ];
    await openTool(page, ROUTE, HEADING);
    const live = await liveLookup(page, reserved.map(([ip]) => ip).join('\n'));
    await evidence.save('real-answers.json', live);
    const shown = await readTable(page);
    reserved.forEach(([ip, range], i) => {
      expect(isSpecialPurpose(ip), `${ip} is in ${range} (test data check)`).toBe(true);
      const record = live.ipinfo.response.results.find(item => item.ip === ip);
      expect.soft(record?.is_private, `/api/ipinfo is_private for ${ip}, ${range}`).toBe(true);
      expect.soft(shown[i]?.badge, `risk badge for ${ip}, ${range} (the API says risk_level "${record?.risk_level}", reasons ${JSON.stringify(record?.risk_reasons)})`).toBe(RISK_LABELS.safe);
    });
  });
});
