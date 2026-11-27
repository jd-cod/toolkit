/**
 * Email header analysis: unfolding, Received hops and delays, authentication
 * results and findings. Plain TypeScript, no React or DOM, runs in the browser
 * and in `node --test`. Nothing here talks to the network.
 */

export interface Finding {
  severity: 'critical' | 'warning' | 'info' | 'ok';
  title: string;
  detail?: string;
}

export interface Header {
  name: string;
  value: string;
}

export interface Hop {
  /** 1-based position in travel order. */
  index: number;
  from: string;
  by: string;
  with: string;
  id: string;
  for: string;
  /** Timestamp text as written after the last `;`. */
  date: string;
  /** Parsed timestamp in epoch milliseconds, or null when it cannot be read. */
  timestamp: number | null;
  /** Seconds since the previous hop that has a readable timestamp. Null for the first hop or unreadable dates. */
  delaySeconds: number | null;
  /** True when this hop's clock is behind the previous hop's (delay clamped to 0). */
  clockSkew: boolean;
  raw: string;
}

export interface AuthResult {
  /** `spf`, `dkim`, `dmarc`, `arc`, `compauth`... lower case. */
  method: string;
  /** `pass`, `fail`, `softfail`, `none`... lower case. */
  result: string;
  /** Properties such as `smtp.mailfrom`, `header.d`, `header.i`, `header.from`, `header.s` (keys lower case). */
  props: Record<string, string>;
  comment: string;
  /** The server that wrote the header (authserv-id). */
  authservId: string;
  /** Index of the source header among headers of the same name, 0 is the top one. */
  headerIndex: number;
}

export interface ReceivedSpf {
  result: string;
  comment: string;
  props: Record<string, string>;
}

export interface DkimSignature {
  d: string;
  s: string;
  a: string;
}

export interface EmailSummary {
  from: string;
  to: string;
  cc: string;
  subject: string;
  date: string;
  messageId: string;
  returnPath: string;
  replyTo: string;
  mailer: string;
}

export interface EmailAuth {
  /** Overall result per method from Authentication-Results (SPF falls back to Received-SPF). Null when absent. */
  spf: string | null;
  dkim: string | null;
  dmarc: string | null;
  hasAuthenticationResults: boolean;
  results: AuthResult[];
  arcResults: AuthResult[];
  receivedSpf: ReceivedSpf[];
  dkimSignatures: DkimSignature[];
}

export interface EmailAnalysis {
  headers: Header[];
  /** True when the input had more headers than MAX_HEADERS and the rest was skipped. */
  truncated: boolean;
  summary: EmailSummary;
  hops: Hop[];
  totalTransitSeconds: number | null;
  auth: EmailAuth;
  findings: Finding[];
}

export const MAX_HEADERS = 1000;
export const SLOW_HOP_SECONDS = 300;

const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/;

/** Split raw text into unfolded headers. Stops at the first blank line after the headers start. */
export function splitHeaders(raw: string): { headers: Header[]; truncated: boolean } {
  const text = typeof raw === 'string' ? raw.replace(/^\uFEFF/, '') : '';
  const lines = text.split(/\r\n|\n|\r/);
  const collected: Array<{ name: string; parts: string[] }> = [];
  let truncated = false;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const trimmed = line.trim();
    if (trimmed === '') {
      if (collected.length > 0) break; // body starts here
      continue;
    }
    const current = collected[collected.length - 1];
    const first = line.charCodeAt(0);
    if (first === 32 || first === 9) {
      if (current) current.parts.push(trimmed);
      continue;
    }
    if (collected.length === 0 && line.startsWith('From ')) continue; // mbox separator line
    const colon = line.indexOf(':');
    const name = colon > 0 ? line.slice(0, colon).trimEnd() : '';
    if (name && HEADER_NAME.test(name)) {
      if (collected.length >= MAX_HEADERS) {
        truncated = true;
        break;
      }
      collected.push({ name, parts: [line.slice(colon + 1).trim()] });
    } else if (current) {
      // Some mail clients drop the leading whitespace of folded lines when copying.
      current.parts.push(trimmed);
    }
  }

  const headers = collected.map(item => ({ name: item.name, value: item.parts.filter(Boolean).join(' ') }));
  return { headers, truncated };
}

/** Remove RFC 5322 comments (text in parentheses, nesting allowed). */
export function stripComments(text: string): string {
  let depth = 0;
  let out = '';
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (char === '(') depth += 1;
    else if (char === ')' && depth > 0) depth -= 1;
    else if (depth === 0) out += char;
  }
  return out;
}

function firstComment(text: string): string {
  const start = text.indexOf('(');
  if (start < 0) return '';
  let depth = 0;
  for (let index = start; index < text.length; index += 1) {
    if (text[index] === '(') depth += 1;
    else if (text[index] === ')') {
      depth -= 1;
      if (depth === 0) return collapse(text.slice(start + 1, index));
    }
  }
  return collapse(text.slice(start + 1));
}

function collapse(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

/** Split on a separator that is outside comments and quoted strings. */
function splitTopLevel(text: string, separator: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quoted = false;
  let start = 0;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (char === '"' && depth === 0) quoted = !quoted;
    else if (quoted) continue;
    else if (char === '(') depth += 1;
    else if (char === ')' && depth > 0) depth -= 1;
    else if (char === separator && depth === 0) {
      parts.push(text.slice(start, index));
      start = index + 1;
    }
  }
  parts.push(text.slice(start));
  return parts;
}

function unquote(value: string): string {
  return value.length >= 2 && value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value;
}

// ---------- RFC 2047 encoded words ----------

function decodeBytes(bytes: number[], charset: string): string {
  const label = charset.split('*')[0].trim().toLowerCase() || 'utf-8';
  const data = Uint8Array.from(bytes);
  try {
    return new TextDecoder(label).decode(data);
  } catch {
    try {
      return new TextDecoder('utf-8').decode(data);
    } catch {
      return bytes.map(byte => String.fromCharCode(byte)).join('');
    }
  }
}

function encodedWordBytes(encoding: string, payload: string): number[] | null {
  const bytes: number[] = [];
  if (encoding.toLowerCase() === 'b') {
    let binary: string;
    try {
      binary = atob(payload.replace(/[-_]/g, char => (char === '-' ? '+' : '/')));
    } catch {
      return null;
    }
    for (let index = 0; index < binary.length; index += 1) bytes.push(binary.charCodeAt(index));
    return bytes;
  }
  for (let index = 0; index < payload.length; index += 1) {
    const char = payload[index];
    const hex = payload.slice(index + 1, index + 3);
    if (char === '_') bytes.push(32);
    else if (char === '=' && /^[0-9A-Fa-f]{2}$/.test(hex)) {
      bytes.push(parseInt(hex, 16));
      index += 2;
    } else bytes.push(char.charCodeAt(0) & 0xff);
  }
  return bytes;
}

/** Decode `=?charset?B?...?=` and `=?charset?Q?...?=` words. Text that is not an encoded word is kept as is. */
export function decodeEncodedWords(value: string): string {
  if (!value.includes('=?')) return value;
  const pattern = /=\?([^?\s]+)\?([bBqQ])\?([^?\s]*)\?=/g;
  let out = '';
  let cursor = 0;
  // Consecutive encoded words (only whitespace between them) that share a charset are
  // collected into one run and decoded together, since some senders split multi-byte characters.
  let runCharset = '';
  let runBytes: number[] | null = null;

  for (let match = pattern.exec(value); match !== null; match = pattern.exec(value)) {
    const bytes = encodedWordBytes(match[2], match[3]);
    if (bytes === null) continue; // leave a broken word in place as plain text
    const gap = value.slice(cursor, match.index);
    const charset = match[1].toLowerCase();
    const adjacent = runBytes !== null && gap.trim() === '';
    if (runBytes !== null && adjacent && runCharset === charset) {
      for (const byte of bytes) runBytes.push(byte);
    } else {
      if (runBytes !== null) out += decodeBytes(runBytes, runCharset);
      if (!adjacent) out += gap; // whitespace between two encoded words is not part of the text
      runCharset = charset;
      runBytes = bytes;
    }
    cursor = match.index + match[0].length;
  }
  if (runBytes !== null) out += decodeBytes(runBytes, runCharset);
  return out + value.slice(cursor);
}

// ---------- Dates ----------

const MONTHS: Record<string, number> = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
const ZONES: Record<string, number> = { ut: 0, utc: 0, gmt: 0, z: 0, est: -300, edt: -240, cst: -360, cdt: -300, mst: -420, mdt: -360, pst: -480, pdt: -420 };
const MAIL_DATE = /(\d{1,2})\s+([A-Za-z]{3})[A-Za-z]*,?\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?\s*([+-]\d{4}|[A-Za-z]{1,5})?/;

/** Parse an RFC 5322 date (`Tue, 1 Dec 2026 10:00:00 +0100 (CET)`) to epoch milliseconds, or null. */
export function parseMailDate(text: string): number | null {
  const cleaned = collapse(stripComments(text));
  if (!cleaned) return null;
  const match = MAIL_DATE.exec(cleaned);
  if (match) {
    const month = MONTHS[match[2].toLowerCase()];
    const day = Number(match[1]);
    let year = Number(match[3]);
    if (match[3].length <= 2) year += year < 50 ? 2000 : 1900;
    const hour = Number(match[4]);
    const minute = Number(match[5]);
    const second = match[6] ? Number(match[6]) : 0;
    if (month === undefined || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60) return null;
    let offset = 0;
    const zone = match[7];
    if (zone && /^[+-]\d{4}$/.test(zone)) {
      offset = (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(3, 5))) * (zone[0] === '-' ? -1 : 1);
    } else if (zone) {
      offset = ZONES[zone.toLowerCase()] ?? 0;
    }
    const stamp = Date.UTC(year, month, day, hour, minute, second) - offset * 60000;
    return Number.isFinite(stamp) ? stamp : null;
  }
  if (cleaned.length > 80) return null;
  const fallback = Date.parse(cleaned);
  return Number.isFinite(fallback) ? fallback : null;
}

// ---------- Received ----------

const RECEIVED_KEYWORDS = new Set(['from', 'by', 'via', 'with', 'id', 'for']);

export function parseReceived(value: string): Pick<Hop, 'from' | 'by' | 'with' | 'id' | 'for' | 'date' | 'raw'> {
  const semicolon = value.lastIndexOf(';');
  const head = semicolon >= 0 ? value.slice(0, semicolon) : value;
  const date = semicolon >= 0 ? collapse(value.slice(semicolon + 1)) : '';

  // Find the clause keywords that sit outside comments.
  const marks: Array<{ key: string; start: number; end: number }> = [];
  let index = 0;
  while (index < head.length) {
    while (index < head.length && /\s/.test(head[index])) index += 1;
    const start = index;
    let depth = 0;
    while (index < head.length && (depth > 0 || !/\s/.test(head[index]))) {
      if (head[index] === '(') depth += 1;
      else if (head[index] === ')' && depth > 0) depth -= 1;
      index += 1;
    }
    const word = head.slice(start, index).toLowerCase();
    if (RECEIVED_KEYWORDS.has(word)) marks.push({ key: word, start, end: index });
  }

  const clause: Record<string, string> = {};
  marks.forEach((mark, position) => {
    if (clause[mark.key] !== undefined) return;
    const next = marks[position + 1];
    clause[mark.key] = head.slice(mark.end, next ? next.start : head.length);
  });
  const plain = (text: string | undefined) => collapse(stripComments(text ?? ''));

  return {
    from: collapse(clause.from ?? ''),
    by: collapse(clause.by ?? ''),
    with: plain(clause.with),
    id: plain(clause.id),
    for: plain(clause.for).replace(/^<|>$/g, ''),
    date,
    raw: value,
  };
}

function buildHops(headers: Header[]): { hops: Hop[]; totalTransitSeconds: number | null } {
  const received = headers.filter(header => header.name.toLowerCase() === 'received').map(header => parseReceived(header.value));
  received.reverse(); // the bottom-most Received header is the first hop

  const hops: Hop[] = [];
  const stamps: number[] = [];
  for (const item of received) {
    const timestamp = parseMailDate(item.date);
    let delaySeconds: number | null = null;
    let clockSkew = false;
    if (timestamp !== null) {
      if (stamps.length > 0) {
        delaySeconds = Math.round((timestamp - stamps[stamps.length - 1]) / 1000);
        if (delaySeconds < 0) {
          delaySeconds = 0;
          clockSkew = true;
        }
      }
      stamps.push(timestamp);
    }
    hops.push({ index: hops.length + 1, ...item, timestamp, delaySeconds, clockSkew });
  }

  // First to last readable timestamp. Hops with unreadable dates are skipped.
  const totalTransitSeconds = stamps.length >= 2 ? Math.max(0, Math.round((stamps[stamps.length - 1] - stamps[0]) / 1000)) : null;
  return { hops, totalTransitSeconds };
}

// ---------- Authentication ----------

const PROP_KEY = /^[A-Za-z0-9_.-]+$/;

function parseProps(text: string): Record<string, string> {
  const props: Record<string, string> = {};
  for (const token of text.split(/[\s;]+/)) {
    const equals = token.indexOf('=');
    if (equals <= 0) continue;
    const key = token.slice(0, equals);
    if (!PROP_KEY.test(key)) continue;
    const lower = key.toLowerCase();
    if (props[lower] === undefined) props[lower] = unquote(token.slice(equals + 1));
  }
  return props;
}

/** Parse one Authentication-Results (or ARC-Authentication-Results) header value. */
export function parseAuthenticationResults(value: string, headerIndex = 0): AuthResult[] {
  const results: AuthResult[] = [];
  let authservId = '';
  splitTopLevel(value, ';').forEach((segment, position) => {
    const text = collapse(stripComments(segment));
    if (!text) return;
    const match = /^([A-Za-z][A-Za-z0-9-]*)\s*=\s*([A-Za-z0-9_-]+)([\s\S]*)$/.exec(text);
    if (!match) {
      if (!authservId && results.length === 0 && position <= 1) authservId = text;
      return;
    }
    const method = match[1].toLowerCase();
    if (method === 'i' && /^\d+$/.test(match[2])) return; // ARC instance tag
    results.push({
      method,
      result: match[2].toLowerCase(),
      props: parseProps(match[3]),
      comment: firstComment(segment),
      authservId: '',
      headerIndex,
    });
  });
  return results.map(result => ({ ...result, authservId }));
}

export function parseReceivedSpf(value: string): ReceivedSpf {
  const plain = collapse(stripComments(value));
  const match = /^([A-Za-z]+)([\s\S]*)$/.exec(plain);
  return {
    result: match ? match[1].toLowerCase() : '',
    comment: firstComment(value),
    props: parseProps(match ? match[2] : ''),
  };
}

export function parseDkimSignature(value: string): DkimSignature {
  const tags: Record<string, string> = {};
  for (const part of value.split(';')) {
    const equals = part.indexOf('=');
    if (equals <= 0) continue;
    const key = part.slice(0, equals).trim().toLowerCase();
    if (key && tags[key] === undefined) tags[key] = part.slice(equals + 1).replace(/\s+/g, '');
  }
  return { d: (tags.d ?? '').toLowerCase(), s: tags.s ?? '', a: tags.a ?? '' };
}

/** The overall result for one method: taken from the top-most header that reports it; `pass` if any entry there passes. */
function overallResult(results: AuthResult[], method: string): string | null {
  const matching = results.filter(result => result.method === method);
  if (matching.length === 0) return null;
  const top = matching.filter(result => result.headerIndex === matching[0].headerIndex);
  return top.some(result => result.result === 'pass') ? 'pass' : top[0].result;
}

// ---------- Domains ----------

/** Signing domain of a dkim result: `header.d`, or the domain part of `header.i` (`@example.com`, `user@example.com`). */
function dkimResultDomain(result: AuthResult): string {
  const identity = result.props['header.i'] ?? '';
  const domain = result.props['header.d'] || identity.slice(identity.lastIndexOf('@') + 1);
  return domain.replace(/\.+$/, '').toLowerCase();
}

/** First address in a header value such as `"Name" <user@example.com>`. Lower-cased domain, or '' when none. */
export function addressDomain(value: string): string {
  const withoutQuotes = value.replace(/"[^"]*"/g, ' ');
  const angle = /<([^<>\s]*@[^<>\s]+)>/.exec(withoutQuotes);
  const bare = angle ? null : /[^\s<>()",;:@]+@([^\s<>()",;:@]+)/.exec(withoutQuotes);
  const address = angle ? angle[1] : bare ? bare[0] : '';
  const at = address.lastIndexOf('@');
  if (at < 0) return '';
  return address.slice(at + 1).replace(/\.+$/, '').toLowerCase();
}

const TWO_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.za', 'co.jp', 'ne.jp', 'or.jp',
  'co.in', 'co.kr', 'co.il', 'com.br', 'com.mx', 'com.ar', 'com.tr', 'com.cn', 'com.hk', 'com.sg', 'com.tw', 'com.ua', 'com.pl',
]);

/**
 * Approximate organizational domain: the last two labels, or three for a few
 * common two-label suffixes. Not a full public suffix list.
 */
export function organizationalDomain(domain: string): string {
  const labels = domain.toLowerCase().replace(/\.+$/, '').split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  return TWO_LABEL_SUFFIXES.has(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
}

function sameOrganization(a: string, b: string): boolean {
  return organizationalDomain(a) === organizationalDomain(b);
}

// ---------- Formatting ----------

/** `45 s`, `3 min 20 s`, `2 h 5 min`, `1 d 3 h`. */
export function formatDuration(seconds: number): string {
  const total = Math.max(0, Math.round(seconds));
  if (total < 60) return `${total} s`;
  if (total < 3600) return total % 60 ? `${Math.floor(total / 60)} min ${total % 60} s` : `${total / 60} min`;
  if (total < 86400) {
    const minutes = Math.floor((total % 3600) / 60);
    return minutes ? `${Math.floor(total / 3600)} h ${minutes} min` : `${Math.floor(total / 3600)} h`;
  }
  const hours = Math.floor((total % 86400) / 3600);
  return hours ? `${Math.floor(total / 86400)} d ${hours} h` : `${Math.floor(total / 86400)} d`;
}

// ---------- Findings ----------

const APPROXIMATE = 'Domains are compared by their last two labels, so this is approximate.';
const SEVERITY_ORDER: Record<Finding['severity'], number> = { critical: 0, warning: 1, info: 2, ok: 3 };

function resultSeverity(result: string): Finding['severity'] {
  if (result === 'pass') return 'ok';
  if (result === 'fail' || result === 'hardfail') return 'critical';
  if (result === 'bestguesspass') return 'info';
  return 'warning';
}

function resultTitle(label: string, result: string): string {
  if (result === 'pass') return `${label} passed`;
  if (result === 'fail' || result === 'hardfail') return `${label} failed`;
  return `${label} result: ${result}`;
}

function buildFindings(headers: Header[], summary: EmailSummary, hops: Hop[], auth: EmailAuth): Finding[] {
  const findings: Finding[] = [];
  const all = (name: string) => headers.filter(header => header.name.toLowerCase() === name);
  const fromDomain = addressDomain(summary.from);

  if (!auth.hasAuthenticationResults) {
    findings.push({
      severity: 'warning',
      title: 'No Authentication-Results header',
      detail: 'The receiving server did not record SPF, DKIM or DMARC results, or the headers were copied before final delivery.',
    });
  }

  if (auth.spf !== null) {
    const entry = auth.results.find(result => result.method === 'spf');
    const sender = entry?.props['smtp.mailfrom'] ?? auth.receivedSpf[0]?.props['envelope-from'] ?? '';
    const explain: Record<string, string> = {
      fail: 'The sending server is not allowed to send mail for the envelope sender domain.',
      hardfail: 'The sending server is not allowed to send mail for the envelope sender domain.',
      softfail: 'The sending server is not listed for the envelope sender domain, which asks receivers to accept but mark such mail.',
      none: 'The envelope sender domain publishes no SPF record.',
      neutral: 'The envelope sender domain makes no statement about this server.',
    };
    const detail = [explain[auth.spf], sender ? `Envelope sender: ${sender}.` : '', entry ? '' : 'Taken from the Received-SPF header.'].filter(Boolean).join(' ');
    findings.push({ severity: resultSeverity(auth.spf), title: resultTitle('SPF', auth.spf), detail: detail || undefined });
  }

  if (auth.dkim !== null) {
    const entries = auth.results.filter(result => result.method === 'dkim');
    const top = entries.filter(result => result.headerIndex === entries[0].headerIndex);
    const list = top.map(result => `${dkimResultDomain(result) || 'unknown domain'} (${result.result})`).join(', ');
    const explain = auth.dkim === 'fail' ? 'The signature did not verify: the message changed after signing, or the key does not match. ' : '';
    findings.push({ severity: resultSeverity(auth.dkim), title: resultTitle('DKIM', auth.dkim), detail: `${explain}Signatures: ${list}.` });
  }

  if (auth.dmarc !== null) {
    const entry = auth.results.find(result => result.method === 'dmarc');
    const domain = entry?.props['header.from'] ?? '';
    const explain: Record<string, string> = {
      fail: 'Neither SPF nor DKIM passed with a domain aligned to the From address.',
      none: 'The From domain publishes no DMARC policy.',
      bestguesspass: 'The From domain publishes no DMARC policy, but the message would have passed one.',
    };
    const detail = [explain[auth.dmarc], domain ? `From domain: ${domain}.` : '', entry?.comment ? `Policy: ${entry.comment}.` : ''].filter(Boolean).join(' ');
    findings.push({ severity: resultSeverity(auth.dmarc), title: resultTitle('DMARC', auth.dmarc), detail: detail || undefined });
  }

  const returnDomain = addressDomain(summary.returnPath);
  if (fromDomain && returnDomain && !sameOrganization(fromDomain, returnDomain)) {
    findings.push({
      severity: auth.dmarc === 'pass' ? 'info' : 'warning',
      title: 'From domain differs from Return-Path domain',
      detail: `From uses ${fromDomain}, bounces go to ${returnDomain}. Normal for mailing services, and also seen in spoofed mail. SPF checks the Return-Path domain, not the From address. ${APPROXIMATE}`,
    });
  }

  // DKIM alignment: prefer domains that verified; fall back to the signatures themselves.
  const verified = auth.results.filter(result => result.method === 'dkim' && result.result === 'pass').map(dkimResultDomain).filter(Boolean);
  const signed = auth.dkimSignatures.map(signature => signature.d).filter(Boolean);
  const dkimDomains = [...new Set((verified.length ? verified : signed).map(domain => domain.toLowerCase()))];
  if (fromDomain && dkimDomains.length > 0) {
    if (dkimDomains.some(domain => sameOrganization(domain, fromDomain))) {
      findings.push({ severity: 'ok', title: 'DKIM signing domain is aligned with the From domain', detail: `Signed by ${dkimDomains.join(', ')}, From is ${fromDomain}. ${APPROXIMATE}` });
    } else {
      findings.push({
        severity: 'warning',
        title: 'DKIM signing domain is not aligned with the From domain',
        detail: `Signed by ${dkimDomains.join(', ')}, From is ${fromDomain}. The signature proves the signer handled the message, not that the From domain sent it. ${APPROXIMATE}`,
      });
    }
  }

  const replyDomain = addressDomain(summary.replyTo);
  if (fromDomain && replyDomain && !sameOrganization(fromDomain, replyDomain)) {
    findings.push({
      severity: 'warning',
      title: 'Reply-To domain differs from From domain',
      detail: `Replies go to ${replyDomain}, not ${fromDomain}. Used by some services, and common in phishing. ${APPROXIMATE}`,
    });
  }

  const slow = hops.filter(hop => hop.delaySeconds !== null && hop.delaySeconds > SLOW_HOP_SECONDS);
  for (const hop of slow.slice(0, 10)) {
    findings.push({
      severity: 'warning',
      title: `Hop ${hop.index} took ${formatDuration(hop.delaySeconds ?? 0)}`,
      detail: `The message waited before it reached ${stripComments(hop.by).trim() || 'this server'}${hop.from ? ` from ${stripComments(hop.from).trim()}` : ''}.`,
    });
  }
  if (slow.length > 10) findings.push({ severity: 'warning', title: `${slow.length - 10} more hops took over 5 minutes` });

  const skewed = hops.filter(hop => hop.clockSkew);
  if (skewed.length > 0) {
    findings.push({
      severity: 'info',
      title: 'Clock difference between servers',
      detail: `Hop ${skewed.map(hop => hop.index).join(', ')} has a timestamp earlier than the hop before it. Its delay is shown as 0.`,
    });
  }

  const spamParts = ['x-spam-status', 'x-spam-score', 'x-spam-flag'].flatMap(name => all(name).slice(0, 1)).map(header => `${header.name}: ${header.value.length > 160 ? `${header.value.slice(0, 160)}...` : header.value}`);
  if (spamParts.length > 0) {
    const flagged = /^\s*yes\b/i.test(all('x-spam-flag')[0]?.value ?? '') || /^\s*yes\b/i.test(all('x-spam-status')[0]?.value ?? '');
    findings.push({
      severity: flagged ? 'warning' : 'info',
      title: flagged ? 'A spam filter marked this message as spam' : 'Spam filter headers present',
      detail: spamParts.join(' | '),
    });
  }

  const originating = all('x-originating-ip')[0];
  if (originating) {
    findings.push({
      severity: 'info',
      title: 'X-Originating-IP present',
      detail: `${originating.value.slice(0, 80)} is the address of the client that submitted the message, as recorded by the sending mail service.`,
    });
  }

  return findings
    .map((finding, position) => ({ finding, position }))
    .sort((a, b) => SEVERITY_ORDER[a.finding.severity] - SEVERITY_ORDER[b.finding.severity] || a.position - b.position)
    .map(item => item.finding);
}

// ---------- Entry point ----------

export function parseEmailHeaders(raw: string): EmailAnalysis {
  const { headers, truncated } = splitHeaders(raw);
  const first = (name: string) => headers.find(header => header.name.toLowerCase() === name)?.value ?? '';
  const all = (name: string) => headers.filter(header => header.name.toLowerCase() === name);
  const decoded = (name: string) => decodeEncodedWords(first(name));

  const summary: EmailSummary = {
    from: decoded('from'),
    to: decoded('to'),
    cc: decoded('cc'),
    subject: decoded('subject'),
    date: first('date'),
    messageId: first('message-id'),
    returnPath: first('return-path'),
    replyTo: decoded('reply-to'),
    mailer: first('x-mailer') || first('user-agent'),
  };

  const { hops, totalTransitSeconds } = buildHops(headers);

  const authHeaders = all('authentication-results');
  const results = authHeaders.flatMap((header, index) => parseAuthenticationResults(header.value, index));
  const arcResults = all('arc-authentication-results').flatMap((header, index) => parseAuthenticationResults(header.value, index));
  const receivedSpf = all('received-spf').map(header => parseReceivedSpf(header.value));
  const dkimSignatures = all('dkim-signature').map(header => parseDkimSignature(header.value));
  const auth: EmailAuth = {
    spf: overallResult(results, 'spf') ?? (receivedSpf[0]?.result || null),
    dkim: overallResult(results, 'dkim'),
    dmarc: overallResult(results, 'dmarc'),
    hasAuthenticationResults: authHeaders.length > 0,
    results,
    arcResults,
    receivedSpf,
    dkimSignatures,
  };

  const findings = headers.length > 0 ? buildFindings(headers, summary, hops, auth) : [];
  return { headers, truncated, summary, hops, totalTransitSeconds, auth, findings };
}

/** A realistic message with five hops, used by the page's "Load sample" button and the tests. */
export const EMAIL_HEADERS_SAMPLE = `Delivered-To: maria.keller@example.org
Received: by 2002:a05:6402:3546:b0:5c9:4f3a:1d2e with SMTP id f6csp1284213edd;
        Tue, 24 Nov 2026 09:21:44 -0800 (PST)
ARC-Authentication-Results: i=1; mx.example.org;
       dkim=pass header.i=@northwind-billing.com header.s=nw2026 header.b=Qm9x1L2k;
       spf=pass (example.org: domain of bounces+48211-ab12@mail.northwind-billing.com designates 198.51.100.24 as permitted sender) smtp.mailfrom="bounces+48211-ab12@mail.northwind-billing.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=northwind-billing.com
Return-Path: <bounces+48211-ab12@mail.northwind-billing.com>
Received: from out-24.relay.mailcarrier.example (out-24.relay.mailcarrier.example. [198.51.100.24])
        by mx.example.org with ESMTPS id d9443c01a7336-212ab4f5c6fsi48211355ad.211.2026.11.24.09.21.43
        for <maria.keller@example.org>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Nov 2026 09:21:43 -0800 (PST)
Received-SPF: pass (example.org: domain of bounces+48211-ab12@mail.northwind-billing.com designates 198.51.100.24 as permitted sender) client-ip=198.51.100.24;
Authentication-Results: mx.example.org;
       dkim=pass header.i=@northwind-billing.com header.s=nw2026 header.b=Qm9x1L2k;
       dkim=pass header.i=@mailcarrier.example header.s=mc1 header.b=Zk31pQ8a;
       spf=pass (example.org: domain of bounces+48211-ab12@mail.northwind-billing.com designates 198.51.100.24 as permitted sender) smtp.mailfrom="bounces+48211-ab12@mail.northwind-billing.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=northwind-billing.com
Received: from queue-7.int.mailcarrier.example (queue-7.int.mailcarrier.example [10.20.7.14])
        by out-24.relay.mailcarrier.example (Postfix) with ESMTPS id 4XyQ2k5Wn1z1Bv
        for <maria.keller@example.org>; Tue, 24 Nov 2026 17:21:41 +0000 (UTC)
Received: from api-ingest-3.int.mailcarrier.example (api-ingest-3.int.mailcarrier.example [10.20.3.8])
        by queue-7.int.mailcarrier.example (Postfix) with ESMTP id 3F0A21C0093
        for <maria.keller@example.org>; Tue, 24 Nov 2026 17:14:52 +0000 (UTC)
Received: from app-02.northwind-billing.com (app-02.northwind-billing.com [203.0.113.57])
        by api-ingest-3.int.mailcarrier.example (Postfix) with ESMTPSA id 9C1D4A00F2
        for <maria.keller@example.org>; Tue, 24 Nov 2026 17:14:50 +0000 (UTC)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=northwind-billing.com;
        s=nw2026; t=1795540490;
        h=from:to:subject:date:message-id:reply-to:mime-version;
        bh=Jq0m2Vq3X1kz0c8n7mF3w0u8o4yT5d1bY6s9a2e4r7I=;
        b=Qm9x1L2kT8dV3nS5cR7pX0aB4eF6gH8jK1lM3oP5qR7sT9uV1wX3yZ5aB7cD9eF1gH3j
         K5lM7nO9pQ1rS3tU5vW7xY9zA1bC3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9=
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=mailcarrier.example; s=mc1;
        h=from:to:subject:date:message-id; bh=Jq0m2Vq3X1kz0c8n7mF3w0u8o4yT5d1bY6s9a2e4r7I=;
        b=Zk31pQ8aV2nR5tY7uI9oP1aS3dF5gH7jK9lZ1xC3vB5nM7qW9eR1tY3uI5oP7aS9dF1g
Date: Tue, 24 Nov 2026 17:14:49 +0000
From: =?UTF-8?B?Tm9ydGh3aW5kIEJpbGxpbmcg4oCTIEludm9pY2Vz?= <invoices@northwind-billing.com>
Reply-To: Northwind Accounts <accounts@northwind-billing.com>
To: Maria Keller <maria.keller@example.org>
Message-ID: <20261124171449.9c1d4a00f2@app-02.northwind-billing.com>
Subject: =?UTF-8?Q?Invoice_INV-20418_for_November_=E2=80=93_due_8_December?=
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="b1_5f8a2c9e7d"
X-Mailer: NorthwindMailer 4.2
X-Spam-Status: No, score=-1.9 required=5.0 tests=DKIM_SIGNED,DKIM_VALID,DKIM_VALID_AU,SPF_PASS
X-Spam-Score: -1.9

This part is the message body and is ignored.
`;
