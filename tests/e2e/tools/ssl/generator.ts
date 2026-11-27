import type { Rng } from '../_support/rng';
import { DAY_MS, certTime, daysRemaining, grade, nameCovers, type ChainCert, type SslAnswer } from './oracle';

/**
 * Random answers in the shape POST /api/ssl returns (backend/src/routes/ssl.js).
 *
 * An answer is consistent the way a real one is: the day count follows from
 * the end of validity and the check time, the flags (expired, self-signed,
 * intermediate, hostname match, trusted) follow from the certificate and the
 * chain, the grade follows from the flags. Awkward values are produced on
 * purpose: expired and about-to-expire certificates, validity times a few
 * minutes either side of midnight UTC (the local date differs from the UTC
 * date), long SAN lists, wildcards, empty optional fields, very long values,
 * and values containing markup, commas and quotes.
 */

export const XSS_FLAG = '__e2eXss';
export const MARKUP = `<img src=x onerror="window.${XSS_FLAG}=1">`;

const HEX = '0123456789ABCDEF';
const LETTERS = 'abcdefghijklmnopqrstuvwxyz';
const TLDS = ['com', 'net', 'org', 'io', 'dev', 'de', 'co.uk', 'app'];

const ISSUERS: { cn: string; org: string; root: string; rootOrg: string }[] = [
  { cn: 'R11', org: "Let's Encrypt", root: 'ISRG Root X1', rootOrg: 'Internet Security Research Group' },
  { cn: 'WE1', org: 'Google Trust Services', root: 'GTS Root R4', rootOrg: 'Google Trust Services LLC' },
  { cn: 'Sectigo Public Server Authentication CA DV R36', org: 'Sectigo Limited', root: 'Sectigo Public Server Authentication Root R46', rootOrg: 'Sectigo Limited' },
  { cn: 'DigiCert Global G2 TLS RSA SHA256 2020 CA1', org: 'DigiCert Inc', root: 'DigiCert Global Root G2', rootOrg: 'DigiCert Inc' },
  { cn: 'Amazon RSA 2048 M02', org: 'Amazon', root: 'Amazon Root CA 1', rootOrg: 'Amazon' },
];

const SERVERS = ['Nginx', 'Apache', 'Cloudflare', 'CloudFront', 'LiteSpeed', 'Microsoft IIS', 'Caddy', 'Google Web Server', 'Varnish', 'envoy', 'Unknown'];
const PROTOCOLS = ['TLS 1.3', 'TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1'];
const KEYS: [string, number][] = [['RSA', 2048], ['RSA', 3072], ['RSA', 4096], ['EC', 256], ['EC', 384], ['EC', 521]];

export function randomHost(rng: Rng): string {
  const sub = rng.bool(0.3) ? `${rng.pick(['www', 'api', 'mail', 'shop'])}.` : '';
  return `${sub}${rng.string(rng.int(3, 10), LETTERS)}${rng.bool(0.2) ? '-' + rng.string(3) : ''}.${rng.pick(TLDS)}`;
}

/** A moment between 2025 and 2031, to the millisecond. */
export function randomNow(rng: Rng): Date {
  return new Date(Date.UTC(2025, 0, 1) + rng.int(0, 6 * 365) * DAY_MS + rng.int(0, DAY_MS - 1));
}

const hexPairs = (rng: Rng, bytes: number) => Array.from({ length: bytes }, () => rng.string(2, HEX)).join(':');
const ipv4 = (rng: Rng) => [rng.int(1, 223), rng.int(0, 255), rng.int(0, 255), rng.int(1, 254)].join('.');

export interface AnswerOptions {
  domain?: string;
  /** Value the day counter must have (negative: expired). */
  days?: number;
  /** Number of certificates in the chain. 1 with `selfSigned` gives a self-signed certificate. */
  chainLength?: number;
  selfSigned?: boolean;
  hostMatch?: boolean;
  sanCount?: number;
  hsts?: boolean;
  dnsIp?: string | null;
  server?: string;
  /** Leave optional text fields empty. */
  sparse?: boolean;
  /** Put markup, quotes and commas into text fields. */
  hostile?: boolean;
  /** Very long names. */
  long?: boolean;
  /** Stop the chain at a certificate whose issuer is not part of it (no self-issued root at the end). */
  incompleteChain?: boolean;
}

/** Builds one answer as checked at `now`. */
export function randomAnswer(rng: Rng, now: Date, options: AnswerOptions = {}): SslAnswer {
  const nowMs = now.getTime();
  const domain = options.domain ?? randomHost(rng);
  const sparse = options.sparse ?? rng.bool(0.15);
  const hostile = options.hostile ?? rng.bool(0.15);
  const long = options.long ?? rng.bool(0.1);
  const selfSigned = options.selfSigned ?? rng.bool(0.1);
  const chainLength = selfSigned ? 1 : options.chainLength ?? rng.weighted([1, 2, 3, 4, 5], [1, 2, 5, 2, 1]);
  const hostMatch = options.hostMatch ?? rng.bool(0.85);

  // Day counter first, then an end of validity that yields exactly that counter (floor).
  const days = options.days ?? rng.weighted([-rng.int(1, 800), 0, rng.int(1, 6), 7, rng.int(8, 30), 31, rng.int(32, 397)], [2, 1, 1, 1, 2, 1, 6]);
  // Certificate times have whole seconds; stay clear of the day boundary by more than a second.
  const nearMidnight = rng.bool(0.4);
  let notAfterMs = nowMs + days * DAY_MS + rng.int(2_000, DAY_MS - 2_000);
  if (nearMidnight) {
    // Move to within a few minutes of midnight UTC without leaving the same day-count window.
    const midnight = Math.ceil(notAfterMs / DAY_MS) * DAY_MS;
    const candidate = midnight + rng.pick([-1, 1]) * rng.int(1, 300) * 1000;
    if (Math.floor((candidate - nowMs) / DAY_MS) === days && candidate - (nowMs + days * DAY_MS) > 2_000) notAfterMs = candidate;
  }
  notAfterMs = Math.floor(notAfterMs / 1000) * 1000;
  const lifetimeDays = rng.pick([90, 90, 199, 365, 397]);
  const notBeforeMs = notAfterMs - lifetimeDays * DAY_MS + (rng.bool(0.5) ? 0 : rng.int(1, 86_399) * 1000);

  // Names on the certificate.
  const apex = domain.split('.').slice(-2).join('.');
  const sanCount = options.sanCount ?? rng.weighted([0, 1, 2, 5, 30], [1, 3, 4, 2, 1]);
  const covering = rng.bool(0.5) ? domain : `*.${domain.split('.').slice(1).join('.')}`;
  const filler = (i: number) => (long
    ? `${'very-long-label-'.repeat(3)}${i}.${'sub.'.repeat(6)}${apex}`
    : rng.pick([`alt${i}.${apex}`, `*.s${i}.${apex}`, `${rng.string(6, LETTERS)}${i}.example.net`]));
  let sans = Array.from({ length: sanCount }, (_, i) => filler(i));
  if (sanCount > 2 && rng.bool(0.3)) sans[sanCount - 1] = `IP Address:${ipv4(rng)}`;
  if (hostMatch && sanCount > 0) sans[rng.int(0, sanCount - 1)] = covering;
  sans = [...new Set(sans)];
  const subject = hostMatch ? rng.pick([domain, covering])
    : hostile ? `${MARKUP} "other", host` : `unrelated-${rng.string(5, LETTERS)}.example.org`;
  const covered = [...sans, subject].some(name => nameCovers(name, domain));

  const issuer = rng.pick(ISSUERS);
  const [keyType, keySize] = sparse && rng.bool(0.5) ? ['', ''] as [string, string] : rng.pick(KEYS);
  const subjectOrg = sparse ? '' : hostile ? `Evil "Corp", ${MARKUP} & Sons` : long ? `${'Extremely Long Organisation Name '.repeat(5)}Ltd` : rng.pick(['', 'Example Org, Inc.', 'Société Générale d\'Exemple', 'ACME GmbH']);

  // Chain: leaf first, then the certificates that issued it, in order. A complete chain ends with a
  // self-issued root; an incomplete one stops at a certificate whose issuer is not included.
  const incomplete = options.incompleteChain ?? false;
  const endsWithRoot = chainLength >= 2 && !incomplete;
  const names = Array.from({ length: chainLength }, (_, i) => (
    i === 0 ? subject : i === chainLength - 1 && endsWithRoot ? issuer.root : i === 1 ? issuer.cn : `${issuer.cn} Cross ${i}`
  ));
  const orgs = names.map((_, i) => (i === 0 ? subjectOrg : i === chainLength - 1 && endsWithRoot ? issuer.rootOrg : issuer.org));
  const issuedBy = (i: number): [string, string] => {
    if (i + 1 < chainLength) return [names[i + 1], orgs[i + 1]];
    if (selfSigned || endsWithRoot) return [names[i], orgs[i]];
    return chainLength === 1 ? [issuer.cn, issuer.org] : [issuer.root, issuer.rootOrg];
  };
  const chain: ChainCert[] = names.map((name, i) => {
    const isLeaf = i === 0;
    const caStart = nowMs - rng.int(400, 4000) * DAY_MS;
    const [caKeyType, caKeySize] = rng.pick(KEYS);
    const [issuerName, issuerOrg] = issuedBy(i);
    return {
      subject: name,
      subject_org: orgs[i],
      subject_country: isLeaf && sparse ? '' : 'US',
      issuer: issuerName,
      issuer_org: issuerOrg,
      issuer_country: 'US',
      serial_number: rng.string(rng.pick([16, 32, 36]), HEX),
      not_before: certTime(isLeaf ? notBeforeMs : Math.floor(caStart / 1000) * 1000),
      not_after: certTime(isLeaf ? notAfterMs : Math.floor((caStart + rng.int(3000, 9000) * DAY_MS) / 1000) * 1000),
      san_names: isLeaf ? sans : [],
      signature_algorithm: '',
      key_type: isLeaf ? keyType : caKeyType,
      key_size: isLeaf ? keySize : caKeySize,
      is_leaf: isLeaf,
    };
  });

  const leaf = chain[0];
  const expired = days < 0;
  const hasIntermediate = chain.length > 1;
  const isSelfSigned = chain.length === 1 && leaf.subject === leaf.issuer;
  const hsts = options.hsts ?? rng.bool(0.6);
  const server = options.server ?? rng.pick(SERVERS);
  const headers: Record<string, string> = {};
  if (hsts) headers.hsts = rng.pick(['max-age=31536000', 'max-age=63072000; includeSubDomains; preload', 'max-age=0']);
  if (rng.bool(0.4)) headers.x_frame_options = rng.pick(['DENY', 'SAMEORIGIN']);
  if (rng.bool(0.4)) headers.x_content_type_options = 'nosniff';
  if (rng.bool(0.3)) headers.csp = `default-src 'self'; img-src *, "quoted"`;
  const ip = options.dnsIp !== undefined ? options.dnsIp : rng.bool(0.9) ? ipv4(rng) : null;

  const answer: SslAnswer = {
    domain,
    valid: !expired,
    subject: leaf.subject,
    subject_org: leaf.subject_org,
    subject_country: leaf.subject_country ?? '',
    issuer: leaf.issuer,
    issuer_org: sparse ? '' : leaf.issuer_org,
    issuer_country: 'US',
    serial_number: leaf.serial_number ?? '',
    signature_algorithm: '',
    key_type: keyType,
    key_size: keySize,
    not_before: leaf.not_before,
    not_after: leaf.not_after,
    days_remaining: daysRemaining(leaf.not_after, nowMs),
    san_names: sans,
    protocol: rng.pick(PROTOCOLS),
    fingerprint_sha256: hexPairs(rng, 32),
    chain,
    grade: grade(days, hasIntermediate, isSelfSigned),
    response_time_ms: rng.weighted([rng.int(1, 99), rng.int(100, 2500), rng.int(2501, 10000)], [2, 5, 1]),
    dns: ip ? { ip, all_ips: [ip, ...(rng.bool(0.4) ? [ipv4(rng)] : [])] } : { ip: null, error: 'No A record found' },
    server_type: server === 'Unknown'
      ? { server: 'Unknown', error: 'fetch failed', security_headers: {} }
      : { server, raw_server: server.toLowerCase(), powered_by: rng.bool(0.2) ? 'PHP/8.3' : '', security_headers: headers },
    hostname_match: covered,
    is_expired: expired,
    has_intermediate: hasIntermediate,
    is_self_signed: isSelfSigned,
    is_trusted: !expired && hasIntermediate && covered && !isSelfSigned,
    security_headers: server === 'Unknown' ? {} : headers,
  };
  return answer;
}

/** A trusted certificate with every optional part present: organisation, SANs, a three-certificate chain, HSTS. */
export function healthyAnswer(rng: Rng, now: Date, options: AnswerOptions = {}): SslAnswer {
  return randomAnswer(rng, now, {
    days: rng.int(40, 390), chainLength: 3, selfSigned: false, hostMatch: true, sanCount: 3, hsts: true,
    dnsIp: ipv4(rng), server: 'Nginx', sparse: false, hostile: false, long: false, ...options,
  });
}

/** What the backend answers when the TLS handshake fails but DNS was resolved. */
export function handshakeFailure(rng: Rng, domain: string, message = 'TLS connection error: connect ECONNREFUSED') {
  return {
    error: message, domain, response_time_ms: rng.int(5, 9000),
    dns: { ip: ipv4(rng), all_ips: [ipv4(rng)] },
    server_type: { server: 'Unknown', error: 'fetch failed', security_headers: {} },
  };
}

/** The same answer with another validity period; everything that follows from it is recomputed for `now`. */
export function withValidity(answer: SslAnswer, notBeforeMs: number, notAfterMs: number, now: Date): SslAnswer {
  const notBefore = certTime(notBeforeMs);
  const notAfter = certTime(notAfterMs);
  const days = daysRemaining(notAfter, now.getTime());
  const expired = days < 0;
  return {
    ...answer,
    not_before: notBefore,
    not_after: notAfter,
    chain: answer.chain.map((cert, i) => (i === 0 ? { ...cert, not_before: notBefore, not_after: notAfter } : cert)),
    days_remaining: days,
    valid: !expired,
    is_expired: expired,
    grade: grade(days, answer.has_intermediate, answer.is_self_signed),
    is_trusted: !expired && answer.has_intermediate && answer.hostname_match && !answer.is_self_signed,
  };
}
