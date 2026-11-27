import type { Rng } from '../_support/rng';
import { DAY_MS, compareNameservers, daysUntil, riskSignals, statusLabel, type Contact, type Snapshot } from './oracle';

/**
 * Random WHOIS snapshots in the shape POST /api/whois returns
 * (backend/src/routes/whois.js, buildRegistrationSnapshot).
 *
 * A snapshot is internally consistent the way a real one is: the day count
 * follows from the expiry date and the check time, the nameserver comparison
 * follows from the two lists, risk sentences follow from the other fields.
 * Awkward values are produced on purpose: expired and about-to-expire
 * domains, midnight timestamps, empty lists, very long values, and values
 * containing markup, commas and quotes.
 */

/** Marker a browser would set if any generated markup were executed. */
export const XSS_FLAG = '__e2eXss';
export const MARKUP = `<img src=x onerror="window.${XSS_FLAG}=1">`;
export const SCRIPT_MARKUP = `<script>window.${XSS_FLAG}=1</script>`;

const TLDS = ['com', 'net', 'org', 'io', 'dev', 'de', 'co.uk', 'info', 'xyz', 'app'];

const REGISTRARS = [
  'MarkMonitor Inc.', 'GoDaddy.com, LLC', 'NameCheap, Inc.', 'Gandi SAS', 'CSC Corporate Domains, Inc.',
  'Tucows Domains Inc.', 'Registrar "Quoted" & Sons, Ltd.', 'Société Française du Domaine — 株式会社',
];

const RDAP_STATUS = [
  'client transfer prohibited', 'client delete prohibited', 'client update prohibited', 'server transfer prohibited',
  'server delete prohibited', 'server update prohibited', 'active', 'client hold', 'server hold', 'pending delete',
  'pending transfer', 'redemption period', 'auto renew period', 'inactive',
];
const WHOIS_STATUS = [
  'clientTransferProhibited', 'clientDeleteProhibited', 'clientUpdateProhibited', 'serverTransferProhibited',
  'serverDeleteProhibited', 'serverUpdateProhibited', 'ok', 'clientHold', 'serverHold', 'pendingDelete',
  'pendingTransfer', 'redemptionPeriod', 'autoRenewPeriod', 'inactive',
];

const PRIVACY_PROVIDERS = ['Redacted For Privacy', 'Domains By Proxy', 'Whois Privacy', 'Contact Privacy', ''];

export function randomDomain(rng: Rng): string {
  const head = rng.string(rng.int(1, 6), 'abcdefghijklmnopqrstuvwxyz');
  const tail = rng.string(rng.int(2, 9), 'abcdefghijklmnopqrstuvwxyz0123456789');
  const middle = rng.bool(0.25) ? '-' : '';
  return `${head}${middle}${tail}.${rng.pick(TLDS)}`;
}

/** A moment between 2025 and 2031, to the millisecond. */
export function randomNow(rng: Rng): Date {
  return new Date(Date.UTC(2025, 0, 1) + rng.int(0, 6 * 365) * DAY_MS + rng.int(0, DAY_MS - 1));
}

function titleWords(text: string): string {
  return text.replace(/[_-]+/g, ' ').replace(/\b[a-z]/g, ch => ch.toUpperCase());
}

function randomContact(rng: Rng, kind: 'empty' | 'redacted' | 'full' | 'partial' | 'hostile'): Contact {
  const handle = rng.string(6, 'abcdefghijklmnopqrstuvwxyz');
  if (kind === 'empty') return { name: '', email: '', phone: '' };
  if (kind === 'redacted') return { name: 'REDACTED FOR PRIVACY', email: '', phone: '' };
  if (kind === 'partial') {
    return rng.pick([
      { name: '', email: `${handle}@example.net`, phone: '' },
      { name: '', email: '', phone: `+1.${rng.int(2000000000, 9999999999)}` },
      { name: `Org ${handle}`, email: '', phone: `+44.${rng.int(1000000000, 9999999999)}` },
    ]);
  }
  if (kind === 'hostile') {
    return { name: `${MARKUP} O'Neil, "Bobby" <b>Tables</b>`, email: `"${handle}"@example.org`, phone: '+1.5550100 ext. 12, line 2' };
  }
  return { name: `${titleWords(handle)} Hostmaster`, email: `hostmaster@${handle}.example`, phone: `+${rng.int(1, 99)}.${rng.int(100000000, 999999999)}` };
}

function isoAt(ms: number): string {
  return new Date(ms).toISOString();
}

export interface SnapshotOptions {
  domain?: string;
  source?: 'rdap' | 'whois';
  /** Value the day counter must have; `null` for a snapshot without an expiry date. */
  expiryDays?: number | null;
  registered?: boolean;
  /** Include markup, quotes and commas in text fields. */
  hostile?: boolean;
  /** Include very long values. */
  long?: boolean;
  contacts?: ('empty' | 'redacted' | 'full' | 'partial' | 'hostile')[];
  nameservers?: 'match' | 'differ' | 'none' | 'registry-only' | 'dns-only';
  dnssec?: Snapshot['dnssec'];
  statuses?: number;
}

/** Builds one snapshot as checked at `now`. */
export function randomSnapshot(rng: Rng, now: Date, options: SnapshotOptions = {}): Snapshot {
  const nowMs = now.getTime();
  const source = options.source ?? rng.pick(['rdap', 'whois'] as const);
  const domain = options.domain ?? randomDomain(rng);
  const hostile = options.hostile ?? rng.bool(0.25);
  const long = options.long ?? rng.bool(0.15);
  const registered = options.registered ?? rng.bool(0.9);

  // Day counter first, then an expiry date that yields exactly that counter.
  const expiryDays = options.expiryDays !== undefined
    ? options.expiryDays
    : rng.weighted<number | null>([null, -rng.int(1, 900), 0, 1, rng.int(2, 14), rng.int(15, 30), 31, rng.int(32, 4000)], [1, 2, 1, 1, 1, 1, 1, 4]);
  let expiry = '';
  if (expiryDays !== null) {
    // ceil(x) = d for d-1 < x <= d: sit somewhere in the last day before the boundary, or exactly on it.
    const backOff = rng.bool(0.3) ? 0 : rng.int(1, DAY_MS - 1);
    expiry = isoAt(nowMs + expiryDays * DAY_MS - backOff);
  }

  // Registry dates are very often exactly midnight UTC; make that common.
  const midnight = (ms: number) => ms - (ms % DAY_MS);
  const ageDays = rng.weighted([rng.int(0, 30), rng.int(31, 400), rng.int(400, 12000)], [1, 2, 5]);
  const createdMs = rng.bool(0.4) ? midnight(nowMs - ageDays * DAY_MS) : nowMs - ageDays * DAY_MS - rng.int(0, DAY_MS - 1);
  const creation = rng.bool(0.9) ? isoAt(createdMs) : '';
  const updatedMs = createdMs + Math.floor(rng.next() * Math.max(0, nowMs - createdMs));
  const updated = rng.bool(0.8) ? isoAt(rng.bool(0.3) ? midnight(updatedMs) : updatedMs) : '';

  const pool = source === 'rdap' ? RDAP_STATUS : WHOIS_STATUS;
  const statusCodes = rng.sample(pool, options.statuses ?? rng.weighted([0, 1, 3, 6], [1, 2, 4, 1]));
  const statusLabels = [...new Set(statusCodes.map(code => statusLabel(code) ?? titleWords(code)))];

  const nsBase = rng.string(rng.int(3, 10), 'abcdefghijklmnopqrstuvwxyz');
  const nsMode = options.nameservers ?? rng.weighted(['match', 'differ', 'none', 'registry-only', 'dns-only'] as const, [5, 2, 1, 1, 1]);
  const nsCount = long ? 13 : rng.int(1, 5);
  const servers = Array.from({ length: nsCount }, (_, i) => `ns${i + 1}.${nsBase}.${rng.pick(['net', 'com', 'org'])}`);
  let registryNs: string[] = [];
  let dnsNs: string[] = [];
  if (nsMode === 'match') { registryNs = rng.shuffle(servers); dnsNs = servers.slice().sort(); }
  else if (nsMode === 'registry-only') registryNs = servers;
  else if (nsMode === 'dns-only') dnsNs = servers.slice().sort();
  else if (nsMode === 'differ') {
    registryNs = servers;
    dnsNs = [...servers.slice(1), `ns9.${rng.string(5, 'abcdefghijklmnopqrstuvwxyz')}.net`].sort();
  }
  const comparison = compareNameservers(registryNs, dnsNs);

  const contactKinds = options.contacts ?? [
    rng.weighted(['empty', 'redacted', 'full', 'partial', hostile ? 'hostile' : 'full'] as const, [3, 2, 2, 2, 1]),
    rng.weighted(['empty', 'redacted', 'full', 'partial'] as const, [4, 2, 2, 2]),
    rng.weighted(['empty', 'redacted', 'full', 'partial'] as const, [4, 2, 2, 2]),
  ];
  const contacts = {
    registrant: randomContact(rng, contactKinds[0] ?? 'empty'),
    admin: randomContact(rng, contactKinds[1] ?? 'empty'),
    tech: randomContact(rng, contactKinds[2] ?? 'empty'),
  };

  const privacyDetected = contactKinds.includes('redacted') || rng.bool(0.15);
  const longText = `${'Very-Long-Registrar-Name-Without-Spaces-'.repeat(4)}${rng.string(8)}`;
  const registrar = !registered && rng.bool(0.7) ? ''
    : hostile ? `${rng.pick(REGISTRARS)} ${MARKUP}`
      : long ? longText
        : rng.weighted([rng.pick(REGISTRARS), ''], [9, 1]);

  const rawLines = [
    `Domain Name: ${domain.toUpperCase()}`,
    `Registrar: ${registrar}`,
    `Creation Date: ${creation}`,
    `Registry Expiry Date: ${expiry}`,
    ...statusCodes.map(code => `Domain Status: ${code} https://icann.org/epp#${code}`),
    ...registryNs.map(ns => `Name Server: ${ns.toUpperCase()}`),
    `Remarks: ${SCRIPT_MARKUP} & "quotes", commas`,
    `>>> Last update of whois database: ${isoAt(nowMs)} <<<`,
    long ? `Notice: ${'lorem-ipsum-dolor-sit-amet-'.repeat(40)}` : '',
  ].filter(line => line !== '');
  const raw = source === 'rdap'
    ? JSON.stringify({
      objectClassName: 'domain', ldhName: domain.toUpperCase(), status: statusCodes,
      nameservers: registryNs.map(ns => ({ objectClassName: 'nameserver', ldhName: ns.toUpperCase() })),
      remarks: [{ description: [`${SCRIPT_MARKUP} & "quotes"`] }],
      events: [{ eventAction: 'registration', eventDate: creation }, { eventAction: 'expiration', eventDate: expiry }],
    }, null, 2)
    : rawLines.join('\n');

  const partial: Omit<Snapshot, 'risk_signals'> = {
    domain,
    query_domain: domain,
    data_source: source,
    registered,
    status_labels: statusLabels,
    status_codes: statusCodes,
    registrar,
    registrar_iana_id: registrar && rng.bool(0.8) ? String(rng.int(1, 4000)) : '',
    abuse_email: rng.bool(0.6) ? `abuse@${nsBase}.example` : '',
    abuse_phone: rng.bool(0.5) ? `+1.${rng.int(2000000000, 9999999999)}` : '',
    creation_date: creation,
    updated_date: updated,
    expiry_date: expiry,
    days_until_expiry: daysUntil(expiry, isoAt(nowMs)),
    nameservers: registryNs,
    dns_nameservers: dnsNs,
    nameserver_match: comparison.match,
    nameserver_only_in_whois: comparison.onlyRegistry,
    nameserver_only_in_dns: comparison.onlyDns,
    dnssec: options.dnssec ?? rng.pick(['signed', 'unsigned', 'unknown'] as const),
    privacy_detected: privacyDetected,
    privacy_provider: privacyDetected ? rng.pick(PRIVACY_PROVIDERS) : '',
    contacts,
    raw_response: raw,
    raw_whois: source === 'whois' ? raw : '',
    rdap_metadata: source === 'rdap' ? { base_url: `https://rdap.${nsBase}.example/v1`, handle: rng.bool(0.7) ? `${rng.int(1000, 99999999)}_DOMAIN-${nsBase.toUpperCase()}` : '' } : null,
    checked_at_utc: isoAt(nowMs),
  };
  return { ...partial, risk_signals: riskSignals(partial, isoAt(nowMs)) };
}

/** A registered domain with every optional part present: three contacts, statuses, both nameserver lists. */
export function richSnapshot(rng: Rng, now: Date, options: SnapshotOptions = {}): Snapshot {
  const snapshot = randomSnapshot(rng, now, {
    registered: true, statuses: 4, contacts: ['full', 'redacted', 'partial'], nameservers: 'differ',
    expiryDays: rng.int(40, 900), hostile: false, long: false, ...options,
  });
  return snapshot.registrar ? snapshot : { ...snapshot, registrar: `${rng.string(7, 'abcdefghijklmnopqrstuvwxyz')} Registrar, Inc.` };
}

/** What the backend returns for a name with no registration: almost every field empty. */
export function unregisteredSnapshot(rng: Rng, now: Date, domain = randomDomain(rng)): Snapshot {
  const raw = `No match for domain "${domain.toUpperCase()}".\n>>> Last update of whois database: ${now.toISOString()} <<<`;
  const partial: Omit<Snapshot, 'risk_signals'> = {
    domain, query_domain: domain, data_source: 'whois', registered: false,
    status_labels: [], status_codes: [], registrar: '', registrar_iana_id: '', abuse_email: '', abuse_phone: '',
    creation_date: '', updated_date: '', expiry_date: '', days_until_expiry: null,
    nameservers: [], dns_nameservers: [], nameserver_match: true, nameserver_only_in_whois: [], nameserver_only_in_dns: [],
    dnssec: 'unknown', privacy_detected: false, privacy_provider: '',
    contacts: { registrant: randomContact(rng, 'empty'), admin: randomContact(rng, 'empty'), tech: randomContact(rng, 'empty') },
    raw_response: raw, raw_whois: raw, rdap_metadata: null, checked_at_utc: now.toISOString(),
  };
  return { ...partial, risk_signals: riskSignals(partial, now.toISOString()) };
}
