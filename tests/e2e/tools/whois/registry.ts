import { Resolver } from 'node:dns/promises';

/**
 * A second, independent source for live WHOIS checks: the registry's own RDAP
 * server (found through the IANA bootstrap file, RFC 9224) and a DNS query,
 * both made from the test process. Nothing here goes through the application.
 */

export interface RegistryRecord {
  /** false when the registry answered "no such domain" (HTTP 404). */
  found: boolean;
  url: string;
  registration: string;
  expiration: string;
  lastChanged: string;
  nameservers: string[];
  status: string[];
  registrar: string;
  ianaId: string;
  /** secureDNS.delegationSigned; null when the registry does not say. */
  signed: boolean | null;
}

async function getJson(url: string): Promise<{ status: number; json: unknown }> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const response = await fetch(url, { headers: { Accept: 'application/rdap+json, application/json' }, signal: AbortSignal.timeout(15_000) });
      const body = await response.text();
      let json: unknown = null;
      try { json = JSON.parse(body); } catch { json = null; }
      if (response.status >= 500 || response.status === 429) { lastError = new Error(`HTTP ${response.status} from ${url}`); continue; }
      return { status: response.status, json };
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

type Json = Record<string, unknown>;
const asList = (value: unknown): Json[] => (Array.isArray(value) ? value as Json[] : []);

function vcardValue(entity: Json | undefined, field: string): string {
  const card = Array.isArray(entity?.vcardArray) ? (entity!.vcardArray as unknown[])[1] : [];
  for (const item of Array.isArray(card) ? card as unknown[][] : []) {
    if (item[0] === field && typeof item[3] === 'string') return item[3];
  }
  return '';
}

/** Reads the registry's RDAP record for `domain`. Throws when the registry cannot be reached. */
export async function registryRecord(domain: string): Promise<RegistryRecord> {
  const tld = domain.split('.').pop()!.toLowerCase();
  const bootstrap = await getJson('https://data.iana.org/rdap/dns.json');
  const service = asList((bootstrap.json as Json)?.services as unknown).map(entry => entry as unknown as [string[], string[]])
    .find(([tlds]) => tlds.map(t => t.toLowerCase()).includes(tld));
  if (!service) throw new Error(`the IANA RDAP bootstrap file lists no server for .${tld}`);
  const base = service[1][0].replace(/\/+$/, '');
  const url = `${base}/domain/${encodeURIComponent(domain)}`;
  const { status, json } = await getJson(url);
  const empty: RegistryRecord = { found: false, url, registration: '', expiration: '', lastChanged: '', nameservers: [], status: [], registrar: '', ianaId: '', signed: null };
  if (status === 404) return empty;
  if (status !== 200 || !json) throw new Error(`unexpected RDAP answer HTTP ${status} from ${url}`);

  const record = json as Json;
  const event = (action: string) => {
    const hit = asList(record.events).find(e => String(e.eventAction).toLowerCase() === action);
    return hit ? String(hit.eventDate) : '';
  };
  const registrar = asList(record.entities).find(e => Array.isArray(e.roles) && (e.roles as string[]).includes('registrar'));
  const iana = asList(registrar?.publicIds).find(id => /iana/i.test(String(id.type)));
  const secure = record.secureDNS as Json | undefined;
  return {
    found: true,
    url,
    registration: event('registration'),
    expiration: event('expiration'),
    lastChanged: event('last changed'),
    nameservers: asList(record.nameservers).map(ns => String(ns.ldhName ?? '').toLowerCase().replace(/\.$/, '')).filter(Boolean),
    status: Array.isArray(record.status) ? (record.status as unknown[]).map(String) : [],
    registrar: vcardValue(registrar, 'fn'),
    ianaId: iana ? String(iana.identifier) : '',
    signed: typeof secure?.delegationSigned === 'boolean' ? secure.delegationSigned as boolean : null,
  };
}

/** NS records of `domain` as the test machine's resolver sees them: lower case, sorted. Empty when there are none. */
export async function liveNameservers(domain: string): Promise<string[]> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const names = await new Resolver().resolveNs(domain);
      return [...new Set(names.map(name => name.toLowerCase().replace(/\.$/, '')))].sort();
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (code === 'ENOTFOUND' || code === 'ENODATA') return [];
      lastError = error;
    }
  }
  throw lastError;
}
