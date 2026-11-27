import { cleanIp, createSyslogReader, createTimelineCounter, forEachLine, sortFindings } from './syslog.ts';
import type { LogFinding, Timeline } from './syslog.ts';

/**
 * Postfix mail log analyzer for /var/log/mail.log and /var/log/maillog.
 * Runs in the browser: one pass over the lines, everything aggregated into
 * Maps, nothing sent anywhere. Only Postfix lines are understood; Dovecot,
 * Exim and Sendmail lines are skipped.
 *
 * What the numbers mean:
 * - Queued is the number of messages qmgr put in the active queue. A message
 *   that is retried is logged again and is counted once, as long as its
 *   queue ID is still open.
 * - Sent, deferred and bounced count delivery attempts per recipient (one
 *   `to=<...> status=...` line each), so a message that is deferred three
 *   times adds three to deferred.
 * - Rejected counts `reject:` and `milter-reject:` lines, mail that was
 *   refused before or while it was received.
 */

export interface MailLogOptions {
  /** Reference time for syslog lines without a year. Defaults to the current time. */
  now?: Date | number;
  /** Rows kept in each list. Default 25. */
  limit?: number;
}

export interface MailLogTotals {
  lines: number;
  recognized: number;
  queued: number;
  delivered: number;
  deferred: number;
  bounced: number;
  expired: number;
  rejected: number;
  saslFailures: number;
  bytesQueued: number;
  connections: number;
  /** Non-delivery notifications created by the bounce service. */
  bounceNotifications: number;
  postscreenDnsbl: number;
  postscreenPregreet: number;
}

export interface SenderRow {
  sender: string;
  messages: number;
  bytes: number;
  sent: number;
  deferred: number;
  bounced: number;
}

export interface RecipientRow {
  name: string;
  sent: number;
  deferred: number;
  bounced: number;
  total: number;
}

export interface ReasonRow {
  reason: string;
  count: number;
  /** One reason as written in the log. */
  example: string;
}

export interface RejectRow {
  code: string;
  category: string;
  count: number;
  example: string;
}

export interface ClientRow {
  ip: string;
  host: string;
  count: number;
}

export interface SaslRow {
  ip: string;
  host: string;
  failures: number;
  /** Connections lost or cut off during AUTH. */
  aborted: number;
}

export interface MailLogResult {
  totals: MailLogTotals;
  firstSeen: number | null;
  lastSeen: number | null;
  /** Seconds from queueing to delivery for status=sent lines. */
  delay: { count: number; average: number; max: number };
  topSenders: SenderRow[];
  senderTotal: number;
  topRecipients: RecipientRow[];
  recipientTotal: number;
  topDomains: RecipientRow[];
  domainTotal: number;
  deferredReasons: ReasonRow[];
  deferredReasonTotal: number;
  bouncedReasons: ReasonRow[];
  bouncedReasonTotal: number;
  rejectReasons: RejectRow[];
  rejectReasonTotal: number;
  topRejectedClients: ClientRow[];
  rejectedClientTotal: number;
  saslClients: SaslRow[];
  saslClientTotal: number;
  /** Series: 0 sent, 1 deferred, 2 bounced, 3 rejected. */
  timeline: Timeline;
  findings: LogFinding[];
}

interface SenderRecord {
  messages: number;
  bytes: number;
  sent: number;
  deferred: number;
  bounced: number;
}

interface StatusRecord {
  sent: number;
  deferred: number;
  bounced: number;
}

interface ReasonRecord {
  count: number;
  example: string;
}

// Queue IDs are hex ("4F9D21A0C2") or, with enable_long_queue_ids, longer base 52 strings ("3Pt2mN2VXxznjll").
const QUEUE_ID = /^([0-9A-Za-z]{5,20}): /;
const QUEUE_FROM = /^from=<([^>]*)>, size=(\d+), nrcpt=\d+/;
const QUEUE_EXPIRED = /^from=<[^>]*>, status=(?:force-)?expired/;
const DELIVERY = /^to=<([^>]*)>, (.*?)status=([A-Za-z-]+)(?: \((.*?)\)?)?\s*$/;
const DELAY_FIELD = /(?:^|, )delay=(\d+(?:\.\d+)?)/;
// "NOQUEUE: reject: RCPT from host[ip]: 554 5.7.1 text; from=<..> to=<..> proto=ESMTP helo=<..>".
// postscreen writes "[ip]:port" with no host name, and a milter reject may carry only the enhanced status code.
const REJECT = /^[0-9A-Za-z]{5,20}: (?:milter-)?reject: \S+ from ([^\s[]*)\[([0-9A-Fa-f.:]+)\](?::\d+)?: (?:(\d{3}) )?(?:(\d\.\d{1,3}\.\d{1,3}) )?(.*)$/;
const REJECT_FIELDS = /; (?:from|to|proto|helo)=/;
const SASL_FAILURE = /^warning: ([^\s[]*)\[([^\]]+)\]: SASL \S+ authentication failed/;
const LOST_CONNECTION = /^(?:lost connection|too many errors|timeout) after (\S+) (?:\([^)]*\) )?from ([^\s[]*)\[([^\]]+)\]/;
const POSTSCREEN_DNSBL = /^DNSBL rank \d+ for \[[^\]]+\]/;
const POSTSCREEN_PREGREET = /^PREGREET \d+ after \S+ from \[[^\]]+\]/;

const MAX_REASON = 500;
const MAX_GROUPS = 2000;
const OTHER_REASONS = 'Other reasons';

// The host and address patterns start with "start of text or a character that cannot be part of the name".
// That makes the engine try each name once instead of once per character, so long tokens stay cheap.
const HOST_WITH_IP = /(^|[^A-Za-z0-9._-])[A-Za-z0-9._-]+\[[0-9A-Fa-f.:]+\](?::\d+)?/g;
const BRACKET_IP = /\[[0-9A-Fa-f.:]+\](?::\d+)?/g;
const ANGLE_ADDRESS = /<[^<>\s]*@[^<>\s]*>/g;
const BARE_ADDRESS = /(^|[^A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+/g;
const NAME_FIELD = /\bname=\S+/g;
const QUOTED = /"[^"]{1,80}"/g;
const IPV4_ANYWHERE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const ID_TOKEN = /\b(?:[0-9A-F]{8,}|(?=[0-9A-Za-z]*\d)(?=[0-9A-Za-z]*[A-Za-z])[0-9A-Za-z]{12,})\b/g;
const LONG_NUMBER = /\d{5,}/g;
const SPACES = /\s+/g;

/**
 * Makes similar delivery reasons equal so they group: host names with their
 * address, mail addresses, IP addresses, queue IDs, session tokens and long
 * numbers are replaced by placeholders.
 */
export function normalizeReason(reason: string): string {
  if (typeof reason !== 'string') return '';
  const text = reason.length > MAX_REASON ? reason.slice(0, MAX_REASON) : reason;
  return text
    .replace(HOST_WITH_IP, '$1<host>')
    .replace(BRACKET_IP, '[<ip>]')
    .replace(ANGLE_ADDRESS, '<address>')
    .replace(BARE_ADDRESS, '$1<address>')
    .replace(NAME_FIELD, 'name=<name>')
    .replace(QUOTED, '"..."')
    .replace(IPV4_ANYWHERE, '<ip>')
    .replace(ID_TOKEN, '<id>')
    .replace(LONG_NUMBER, '<n>')
    .replace(SPACES, ' ')
    .trim()
    .slice(0, 200);
}

const DNSBL_NAME = /blocked using ([A-Za-z0-9.-]+)/;

/** The short category a reject reason belongs to. */
export function rejectCategory(text: string): string {
  if (typeof text !== 'string') return 'Other';
  if (/greylist/i.test(text)) return 'Greylisted';
  const dnsbl = DNSBL_NAME.exec(text);
  if (dnsbl) return `Blocked using ${dnsbl[1].replace(/\.+$/, '').toLowerCase()}`;
  if (text.indexOf('Relay access denied') !== -1) return 'Relay access denied';
  if (text.indexOf('Recipient address rejected: User unknown') !== -1) return 'Recipient address rejected: User unknown';
  if (text.indexOf('Recipient address rejected') !== -1) return 'Recipient address rejected';
  if (text.indexOf('Client host rejected') !== -1) return 'Client host rejected';
  if (text.indexOf('Sender address rejected') !== -1) return 'Sender address rejected';
  if (text.indexOf('Helo command rejected') !== -1) return 'Helo command rejected';
  return 'Other';
}

// Wording remote servers use when they refuse mail because of the sending server's address or reputation.
const REPUTATION = /blocked using|black ?list|block ?list|\breputation\b|spamhaus|spamcop|barracuda|sorbs|uceprotect|\bdnsbl\b|\brbl\b|listed (?:in|on|at|by)\b|\bS31[45]0\b|5\.7\.606|5\.7\.511|banned sending ip|\bip(?: address)?\b[^;]{0,40}\b(?:blocked|banned|blacklisted)\b/i;

/** True when a remote server's answer says the sending server is blocked, listed or has a bad reputation. */
export function isReputationReason(reason: string): boolean {
  if (typeof reason !== 'string') return false;
  if (reason.indexOf(' said: ') === -1 && reason.indexOf('refused to talk to me') === -1) return false;
  return REPUTATION.test(reason.length > MAX_REASON ? reason.slice(0, MAX_REASON) : reason);
}

const SASL_BRUTE_FORCE = 10;
const SENDER_MIN_MESSAGES = 20;
const SENDER_MIN_SHARE = 0.4;
const SENDER_MIN_BOUNCES = 10;
const SENDER_MIN_BOUNCE_RATE = 0.1;
const DEFERRED_SHARE = 0.1;

function orNull(ts: number): number | null {
  return Number.isFinite(ts) ? ts : null;
}

function count(value: number): string {
  return value.toLocaleString('en-US');
}

function percent(part: number, whole: number): string {
  return whole > 0 ? `${Math.round((part / whole) * 100)}%` : '0%';
}

function bump(groups: Map<string, ReasonRecord>, key: string, example: string): void {
  let record = groups.get(key);
  if (!record) {
    if (groups.size >= MAX_GROUPS) {
      record = groups.get(OTHER_REASONS);
      if (!record) {
        record = { count: 0, example };
        groups.set(OTHER_REASONS, record);
      }
    } else {
      record = { count: 0, example };
      groups.set(key, record);
    }
  }
  record.count += 1;
}

function reasonRows(groups: Map<string, ReasonRecord>, limit: number): ReasonRow[] {
  return Array.from(groups, ([reason, record]) => ({ reason, count: record.count, example: record.example }))
    .sort((a, b) => b.count - a.count || (a.reason < b.reason ? -1 : 1))
    .slice(0, limit);
}

function statusRows(map: Map<string, StatusRecord>, limit: number): RecipientRow[] {
  return Array.from(map, ([name, record]) => ({ name, sent: record.sent, deferred: record.deferred, bounced: record.bounced, total: record.sent + record.deferred + record.bounced }))
    .sort((a, b) => b.total - a.total || (a.name < b.name ? -1 : 1))
    .slice(0, limit);
}

export function analyzeMailLog(text: string, options: MailLogOptions = {}): MailLogResult {
  const input = typeof text === 'string' ? text : '';
  const limit = options.limit && options.limit > 0 ? Math.floor(options.limit) : 25;
  const reader = createSyslogReader(options.now);
  const timeline = createTimelineCounter(4);

  // Queue ID to sender for messages that are still in the queue. Entries are dropped on "removed".
  const open = new Map<string, string>();
  const senders = new Map<string, SenderRecord>();
  const recipients = new Map<string, StatusRecord>();
  const domains = new Map<string, StatusRecord>();
  const deferredGroups = new Map<string, ReasonRecord>();
  const bouncedGroups = new Map<string, ReasonRecord>();
  const rejectGroups = new Map<string, { code: string; category: string; count: number; example: string }>();
  const rejectedClients = new Map<string, { host: string; count: number }>();
  const saslClients = new Map<string, { host: string; failures: number; aborted: number }>();

  let recognized = 0;
  let queued = 0;
  let bytesQueued = 0;
  let delivered = 0;
  let deferred = 0;
  let bounced = 0;
  let expired = 0;
  let rejected = 0;
  let relayDenied = 0;
  let saslFailures = 0;
  let connections = 0;
  let bounceNotifications = 0;
  let postscreenDnsbl = 0;
  let postscreenPregreet = 0;
  let delayCount = 0;
  let delaySum = 0;
  let delayMax = 0;
  let reputationBounced = 0;
  let reputationDeferred = 0;
  let reputationExample = '';
  let firstSeen = Infinity;
  let lastSeen = -Infinity;

  function senderRecord(sender: string): SenderRecord {
    let record = senders.get(sender);
    if (!record) {
      record = { messages: 0, bytes: 0, sent: 0, deferred: 0, bounced: 0 };
      senders.set(sender, record);
    }
    return record;
  }

  function statusRecord(map: Map<string, StatusRecord>, key: string): StatusRecord {
    let record = map.get(key);
    if (!record) {
      record = { sent: 0, deferred: 0, bounced: 0 };
      map.set(key, record);
    }
    return record;
  }

  function saslRecord(rawIp: string, host: string) {
    const ip = cleanIp(rawIp);
    if (ip === '') return null;
    let record = saslClients.get(ip);
    if (!record) {
      record = { host, failures: 0, aborted: 0 };
      saslClients.set(ip, record);
    }
    return record;
  }

  function handleReject(match: RegExpExecArray, ts: number): void {
    rejected += 1;
    timeline.add(ts, 3);
    const code = match[3] || match[4] || 'none';
    const cut = match[5].search(REJECT_FIELDS);
    const reason = (cut === -1 ? match[5] : match[5].slice(0, cut)).slice(0, MAX_REASON);
    const category = rejectCategory(reason);
    if (category === 'Relay access denied') relayDenied += 1;

    const key = `${code} ${category}`;
    let group = rejectGroups.get(key);
    if (!group && rejectGroups.size < MAX_GROUPS) {
      group = { code, category, count: 0, example: reason };
      rejectGroups.set(key, group);
    }
    if (group) group.count += 1;

    const ip = cleanIp(match[2]);
    if (ip !== '') {
      const client = rejectedClients.get(ip);
      if (client) client.count += 1;
      else rejectedClients.set(ip, { host: match[1] || 'unknown', count: 1 });
    }
  }

  function handleDelivery(queueId: string, match: RegExpExecArray, ts: number): boolean {
    const status = match[3];
    const series = status === 'sent' ? 0 : status === 'deferred' ? 1 : status === 'bounced' ? 2 : -1;
    if (series === -1) {
      if (status !== 'expired') return false;
      expired += 1;
      return true;
    }

    const recipient = match[1].toLowerCase() || '<>';
    const at = recipient.lastIndexOf('@');
    const domain = at === -1 ? '(local)' : recipient.slice(at + 1);
    const reason = match[4] || '';
    const who = statusRecord(recipients, recipient);
    const where = statusRecord(domains, domain);
    const sender = open.get(queueId);
    const from = sender === undefined ? null : senderRecord(sender);

    if (series === 0) {
      delivered += 1;
      who.sent += 1;
      where.sent += 1;
      if (from) from.sent += 1;
      const delay = DELAY_FIELD.exec(match[2]);
      if (delay) {
        const seconds = Number(delay[1]);
        delayCount += 1;
        delaySum += seconds;
        if (seconds > delayMax) delayMax = seconds;
      }
    } else if (series === 1) {
      deferred += 1;
      who.deferred += 1;
      where.deferred += 1;
      if (from) from.deferred += 1;
      bump(deferredGroups, normalizeReason(reason) || 'No reason given', reason.slice(0, MAX_REASON));
      if (isReputationReason(reason)) {
        reputationDeferred += 1;
        if (!reputationExample) reputationExample = reason.slice(0, MAX_REASON);
      }
    } else {
      bounced += 1;
      who.bounced += 1;
      where.bounced += 1;
      if (from) from.bounced += 1;
      bump(bouncedGroups, normalizeReason(reason) || 'No reason given', reason.slice(0, MAX_REASON));
      if (isReputationReason(reason)) {
        if (reputationBounced === 0) reputationExample = reason.slice(0, MAX_REASON);
        reputationBounced += 1;
      }
    }
    timeline.add(ts, series);
    return true;
  }

  function handleQueueLine(queueId: string, rest: string, ts: number): boolean {
    let match: RegExpExecArray | null;
    if (rest.startsWith('to=<')) {
      match = DELIVERY.exec(rest);
      return match ? handleDelivery(queueId, match, ts) : false;
    }
    if (rest.startsWith('from=<')) {
      if ((match = QUEUE_FROM.exec(rest))) {
        // qmgr logs this line again every time a deferred message is retried. Count the message once.
        if (!open.has(queueId)) {
          const sender = match[1].toLowerCase() || '<>';
          const size = Number(match[2]);
          open.set(queueId, sender);
          queued += 1;
          bytesQueued += size;
          const record = senderRecord(sender);
          record.messages += 1;
          record.bytes += size;
        }
        return true;
      }
      if (QUEUE_EXPIRED.test(rest)) {
        expired += 1;
        return true;
      }
      return false;
    }
    if (rest === 'removed') {
      open.delete(queueId);
      return true;
    }
    if (rest.startsWith('sender non-delivery notification')) {
      bounceNotifications += 1;
      return true;
    }
    return rest.startsWith('message-id=') || rest.startsWith('client=') || rest.startsWith('uid=') || rest.startsWith('sender delivery status notification') || rest.startsWith('postmaster non-delivery notification');
  }

  function handlePostfix(service: string, message: string, ts: number): boolean {
    let match: RegExpExecArray | null;

    if (message.startsWith('connect from ')) {
      connections += 1;
      return true;
    }
    if (message.startsWith('disconnect from ')) return true;

    if (message.startsWith('warning: ')) {
      if (!(match = SASL_FAILURE.exec(message))) return false;
      saslFailures += 1;
      const record = saslRecord(match[2], match[1] || 'unknown');
      if (record) record.failures += 1;
      return true;
    }

    if ((message.startsWith('lost connection after ') || message.startsWith('too many errors after ') || message.startsWith('timeout after ')) && (match = LOST_CONNECTION.exec(message))) {
      if (match[1] === 'AUTH') {
        const record = saslRecord(match[3], match[2] || 'unknown');
        if (record) record.aborted += 1;
      }
      return true;
    }

    if (service === 'postscreen') {
      if (message.startsWith('DNSBL rank ') && POSTSCREEN_DNSBL.test(message)) {
        postscreenDnsbl += 1;
        return true;
      }
      if (message.startsWith('PREGREET ') && POSTSCREEN_PREGREET.test(message)) {
        postscreenPregreet += 1;
        return true;
      }
    }

    const queue = QUEUE_ID.exec(message);
    if (!queue) return false;
    const rest = message.slice(queue[0].length);
    if (rest.startsWith('reject: ') || rest.startsWith('milter-reject: ')) {
      if (!(match = REJECT.exec(message))) return false;
      handleReject(match, ts);
      return true;
    }
    if (queue[1] === 'NOQUEUE') return false;
    return handleQueueLine(queue[1], rest, ts);
  }

  const lines = forEachLine(input, line => {
    const entry = reader.parse(line);
    const program = entry.program;
    // "postfix/smtpd", another instance name ("postfix-out/smtp") or a named service ("postfix/submission/smtpd").
    if (!program.startsWith('postfix')) return;
    const slash = program.lastIndexOf('/');
    if (slash === -1) return;
    if (handlePostfix(program.slice(slash + 1), entry.message, entry.ts)) {
      recognized += 1;
      if (entry.ts < firstSeen) firstSeen = entry.ts;
      if (entry.ts > lastSeen) lastSeen = entry.ts;
    }
  });

  /* ---------- Lists ---------- */

  const senderRows: SenderRow[] = Array.from(senders, ([sender, record]) => ({ sender, ...record }))
    .sort((a, b) => b.messages - a.messages || b.bounced - a.bounced || (a.sender < b.sender ? -1 : 1));

  const rejectRows: RejectRow[] = Array.from(rejectGroups.values())
    .sort((a, b) => b.count - a.count || (a.category < b.category ? -1 : 1));

  const clientRows: ClientRow[] = Array.from(rejectedClients, ([ip, record]) => ({ ip, host: record.host, count: record.count }))
    .sort((a, b) => b.count - a.count || (a.ip < b.ip ? -1 : 1));

  const saslRows: SaslRow[] = Array.from(saslClients, ([ip, record]) => ({ ip, host: record.host, failures: record.failures, aborted: record.aborted }))
    .sort((a, b) => b.failures - a.failures || b.aborted - a.aborted || (a.ip < b.ip ? -1 : 1));

  const deferredReasons = reasonRows(deferredGroups, limit);
  const bouncedReasons = reasonRows(bouncedGroups, limit);

  /* ---------- Findings ---------- */

  const findings: LogFinding[] = [];
  const attempts = delivered + deferred + bounced;

  if (reputationBounced > 0) {
    findings.push({
      severity: 'critical',
      title: `${count(reputationBounced)} ${reputationBounced === 1 ? 'bounce says' : 'bounces say'} your server is blocked or has a poor reputation`,
      detail: `Remote servers refused mail and named a block list or the reputation of the sending address${reputationDeferred > 0 ? ` (${count(reputationDeferred)} more were deferred for the same kind of reason)` : ''}. Your server may be blacklisted. Check its address on the blacklist tool at /blacklist. Example: ${reputationExample}`,
      link: { href: '/blacklist', label: 'Open the blacklist check' },
    });
  } else if (reputationDeferred > 0) {
    findings.push({
      severity: 'warning',
      title: `${count(reputationDeferred)} ${reputationDeferred === 1 ? 'delivery was' : 'deliveries were'} deferred for block list or reputation reasons`,
      detail: `Remote servers are slowing down or refusing your mail for now. Check your server's address on the blacklist tool at /blacklist. Example: ${reputationExample}`,
      link: { href: '/blacklist', label: 'Open the blacklist check' },
    });
  }

  const topSasl = saslRows[0];
  if (topSasl && topSasl.failures >= SASL_BRUTE_FORCE) {
    findings.push({
      severity: 'warning',
      title: `${count(topSasl.failures)} failed SMTP logins from ${topSasl.ip}`,
      detail: `This is password guessing against your mail accounts. ${count(saslFailures)} SASL logins failed in total, from ${count(saslRows.filter(row => row.failures > 0).length)} addresses. The postfix-sasl jail of fail2ban blocks these sources.`,
    });
  }

  const heavy = senderRows.find(row => row.sender !== '<>' && row.messages >= SENDER_MIN_MESSAGES && row.messages / queued >= SENDER_MIN_SHARE && row.bounced >= SENDER_MIN_BOUNCES && row.bounced / Math.max(1, row.sent + row.deferred + row.bounced) >= SENDER_MIN_BOUNCE_RATE);
  if (heavy) {
    findings.push({
      severity: 'warning',
      title: `${heavy.sender} sent ${percent(heavy.messages, queued)} of all queued mail, with ${count(heavy.bounced)} bounces`,
      detail: `${count(heavy.messages)} of ${count(queued)} messages came from this sender and ${percent(heavy.bounced, heavy.sent + heavy.deferred + heavy.bounced)} of its deliveries bounced. That pattern fits a compromised account or a script sending to a bad list. Check where these messages are submitted from.`,
    });
  }

  if (attempts > 0 && deferred / attempts > DEFERRED_SHARE) {
    const top = deferredReasons[0];
    findings.push({
      severity: 'warning',
      title: `${percent(deferred, attempts)} of delivery attempts were deferred`,
      detail: `${count(deferred)} of ${count(attempts)} attempts will be retried later.${top ? ` Most common reason (${count(top.count)} times): ${top.example}` : ''}`,
    });
  }

  if (relayDenied > 0) {
    findings.push({
      severity: 'info',
      title: `${count(relayDenied)} relay ${relayDenied === 1 ? 'attempt was' : 'attempts were'} refused`,
      detail: 'Other hosts tried to send mail through your server to outside addresses. "Relay access denied" is your server refusing them correctly. Nothing to fix.',
    });
  }

  if (lines > 0 && recognized === 0) {
    findings.push({
      severity: 'info',
      title: 'No Postfix lines were recognized',
      detail: 'Check that this is mail.log or maillog written by Postfix. Exim, Sendmail and Dovecot logs are not understood.',
    });
  } else if (recognized > 0 && findings.length === 0) {
    findings.push({ severity: 'ok', title: 'Nothing stands out in this log' });
  }

  return {
    totals: {
      lines,
      recognized,
      queued,
      delivered,
      deferred,
      bounced,
      expired,
      rejected,
      saslFailures,
      bytesQueued,
      connections,
      bounceNotifications,
      postscreenDnsbl,
      postscreenPregreet,
    },
    firstSeen: orNull(firstSeen),
    lastSeen: orNull(lastSeen),
    delay: { count: delayCount, average: delayCount > 0 ? delaySum / delayCount : 0, max: delayMax },
    topSenders: senderRows.slice(0, limit),
    senderTotal: senderRows.length,
    topRecipients: statusRows(recipients, limit),
    recipientTotal: recipients.size,
    topDomains: statusRows(domains, limit),
    domainTotal: domains.size,
    deferredReasons,
    deferredReasonTotal: deferredGroups.size,
    bouncedReasons,
    bouncedReasonTotal: bouncedGroups.size,
    rejectReasons: rejectRows.slice(0, limit),
    rejectReasonTotal: rejectRows.length,
    topRejectedClients: clientRows.slice(0, limit),
    rejectedClientTotal: clientRows.length,
    saslClients: saslRows.slice(0, limit),
    saslClientTotal: saslRows.length,
    timeline: timeline.build(),
    findings: sortFindings(findings),
  };
}
