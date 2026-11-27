import { cleanIp, createSyslogReader, createTimelineCounter, forEachLine, ipVersion, isLocalAddress, sortFindings } from './syslog.ts';
import type { LogFinding, Timeline } from './syslog.ts';

/**
 * SSH auth log analyzer for /var/log/auth.log (Debian, Ubuntu),
 * /var/log/secure (RHEL family) and `journalctl -u ssh` output.
 * Runs in the browser: one pass over the lines, everything aggregated into
 * Maps, nothing sent anywhere.
 *
 * Counting rule: a failed attempt is a `Failed <method> for ...` line, times
 * its repeat count when rsyslog wrote `message repeated N times: [ ... ]`.
 * `Invalid user ...`, `pam_unix(sshd:auth): authentication failure` and
 * `maximum authentication attempts exceeded` lines describe the same attempt
 * again, so they only add usernames and addresses and are never counted as
 * attempts. Connections closed before login and scanner probes are counted
 * separately as "other events".
 */

export interface AuthLogOptions {
  /** Reference time for syslog lines without a year. Defaults to the current time. */
  now?: Date | number;
  /** More failed attempts than this adds the brute-force note. Default 50. */
  bruteForceNote?: number;
  /** Rows kept in each list. Default 25. */
  limit?: number;
}

export interface AuthLogTotals {
  lines: number;
  recognized: number;
  failedAttempts: number;
  /** Distinct source addresses with at least one failed attempt. */
  failedIps: number;
  usernamesTried: number;
  invalidUsernames: number;
  acceptedLogins: number;
  scannerProbes: number;
  /** Connections closed or reset before login, with a user name in the line. */
  preauthDisconnects: number;
}

export interface AuthIpRow {
  ip: string;
  version: 4 | 6;
  failed: number;
  /** Connections closed before login, scanner probes and "maximum attempts" lines. */
  other: number;
  /** Distinct usernames tried from this address. */
  users: number;
  firstSeen: number | null;
  lastSeen: number | null;
  /** The same address also had an accepted login. */
  accepted: boolean;
}

export interface AuthUserRow {
  user: string;
  failed: number;
  other: number;
  /** sshd reported the name as an invalid (nonexistent) user. */
  invalid: boolean;
}

export interface AcceptedLogin {
  ts: number | null;
  user: string;
  ip: string;
  method: string;
}

export interface Offender {
  ip: string;
  failed: number;
  accepted: boolean;
}

export interface SudoUserRow {
  user: string;
  commands: number;
  authFailures: number;
  notInSudoers: number;
  lastCommand: string;
}

export interface SudoSummary {
  commands: number;
  authFailures: number;
  incorrectPasswordAttempts: number;
  notInSudoers: number;
  denied: number;
  users: SudoUserRow[];
  userTotal: number;
}

export interface AuthLogResult {
  totals: AuthLogTotals;
  firstSeen: number | null;
  lastSeen: number | null;
  /** Failed attempts per method (password, publickey, ...), most used first. */
  failedByMethod: Array<{ method: string; count: number }>;
  topIps: AuthIpRow[];
  ipTotal: number;
  topUsers: AuthUserRow[];
  userTotal: number;
  /** Newest first. */
  accepted: AcceptedLogin[];
  acceptedTotal: number;
  /** Series 0 is failed attempts, series 1 is accepted logins. */
  timeline: Timeline;
  sudo: SudoSummary;
  findings: LogFinding[];
  /** Every valid address with at least one failed attempt, most failures first. Input for buildBlockList. */
  offenders: Offender[];
}

interface IpRecord {
  ip: string;
  version: 4 | 6;
  failed: number;
  other: number;
  accepted: number;
  users: Set<string>;
  acceptedUsers: Set<string>;
  first: number;
  last: number;
}

interface UserRecord {
  failed: number;
  other: number;
  invalid: boolean;
}

interface SudoRecord {
  commands: number;
  authFailures: number;
  notInSudoers: number;
  lastCommand: string;
}

// OpenSSH auth.c: "%s %s%s%s for %s%.100s from %.200s port %d ssh2%s%s". The user name is chosen by the
// client and may contain spaces or " from ", so it is matched greedily and the address is taken from the end.
const FAILED = /^Failed (\S+) for (invalid user )?(.*) from (\S+) port \d+/;
const ACCEPTED = /^Accepted (\S+) for (.*) from (\S+) port \d+/;
const INVALID_USER = /^Invalid user (.*) from (\S+)(?: port \d+)?\s*$/;
const CLOSED = /^(?:Connection (?:closed|reset) by|Disconnected from) (authenticating|invalid) user (.*) (\S+) port \d+/;
const MAX_ATTEMPTS = /^error: maximum authentication attempts exceeded for (invalid user )?(.*) from (\S+) port \d+/;
const PAM_FAILURE = /^pam_unix\(sshd:auth\): authentication failure;.*\brhost=(\S+)(?:\s+user=(\S+))?/;
const NO_IDENTIFICATION = /^Did not receive identification string from (\S+)/;
const NO_NEGOTIATION = /^Unable to negotiate with (\S+) port \d+: no matching /;
const BANNER = /^banner exchange: Connection from (\S+) port \d+: /;
const BAD_VERSION = /^Bad protocol version identification .* from (\S+) port \d+\s*$/;
const REPEATED = /^message repeated (\d+) times: \[ ?(.*?)\]?\s*$/;

const SUDO_EVENT = /^\s*(\S+) : (.*)$/;
const SUDO_PAM_FAILURE = /^pam_unix\(sudo(?:-i)?:auth\): authentication failure;(.*)$/;
const SUDO_INCORRECT = /^(\d+) incorrect password attempts?/;
const SUDO_RUSER = /\bruser=(\S+)/;
const SUDO_LOGNAME = /\blogname=(\S+)/;
const SUDO_USER = /\buser=(\S+)/;

const MAX_REPEAT = 1000000;
const MAX_NAME = 64;
const SUCCESS_AFTER_FAILURES = 5;

function userName(raw: string): string {
  if (raw === '') return '(empty)';
  return raw.length > MAX_NAME ? `${raw.slice(0, MAX_NAME)}...` : raw;
}

function orNull(ts: number): number | null {
  return Number.isFinite(ts) ? ts : null;
}

function plural(count: number, one: string, many: string): string {
  return `${count.toLocaleString('en-US')} ${count === 1 ? one : many}`;
}

function listSome(items: string[], max = 3): string {
  if (items.length <= max) return items.join(', ');
  return `${items.slice(0, max).join(', ')} and ${items.length - max} more`;
}

export function analyzeAuthLog(text: string, options: AuthLogOptions = {}): AuthLogResult {
  const input = typeof text === 'string' ? text : '';
  const limit = options.limit && options.limit > 0 ? Math.floor(options.limit) : 25;
  const bruteForceNote = options.bruteForceNote !== undefined && options.bruteForceNote >= 0 ? options.bruteForceNote : 50;
  const reader = createSyslogReader(options.now);
  const timeline = createTimelineCounter(2);

  const ips = new Map<string, IpRecord>();
  const users = new Map<string, UserRecord>();
  const methods = new Map<string, number>();
  const sudoUsers = new Map<string, SudoRecord>();
  let recent: AcceptedLogin[] = [];

  let recognized = 0;
  let failedAttempts = 0;
  let acceptedLogins = 0;
  let scannerProbes = 0;
  let preauthDisconnects = 0;
  let acceptedRoot = 0;
  let acceptedPassword = 0;
  const rootSources = new Set<string>();
  const passwordUsers = new Set<string>();
  let firstSeen = Infinity;
  let lastSeen = -Infinity;

  let sudoCommands = 0;
  let sudoAuthFailures = 0;
  let sudoIncorrect = 0;
  let sudoNotInSudoers = 0;
  let sudoDenied = 0;

  function seen(ts: number): void {
    if (ts < firstSeen) firstSeen = ts;
    if (ts > lastSeen) lastSeen = ts;
  }

  /** Returns the record for a valid address, or null when the source is not an IP address. */
  function ipRecord(raw: string, ts: number): IpRecord | null {
    const ip = cleanIp(raw);
    if (ip === '') return null;
    let record = ips.get(ip);
    if (!record) {
      record = { ip, version: ipVersion(ip) === 6 ? 6 : 4, failed: 0, other: 0, accepted: 0, users: new Set(), acceptedUsers: new Set(), first: Infinity, last: -Infinity };
      ips.set(ip, record);
    }
    if (ts < record.first) record.first = ts;
    if (ts > record.last) record.last = ts;
    return record;
  }

  function userRecord(name: string): UserRecord {
    let record = users.get(name);
    if (!record) {
      record = { failed: 0, other: 0, invalid: false };
      users.set(name, record);
    }
    return record;
  }

  function sudoRecord(name: string): SudoRecord {
    let record = sudoUsers.get(name);
    if (!record) {
      record = { commands: 0, authFailures: 0, notInSudoers: 0, lastCommand: '' };
      sudoUsers.set(name, record);
    }
    return record;
  }

  function probe(rawIp: string, times: number, ts: number): void {
    scannerProbes += times;
    const ip = ipRecord(rawIp, ts);
    if (ip) ip.other += times;
  }

  function handleSshd(message: string, times: number, ts: number): boolean {
    let match: RegExpExecArray | null;

    if (message.startsWith('Failed ') && (match = FAILED.exec(message))) {
      const name = userName(match[3]);
      failedAttempts += times;
      methods.set(match[1], (methods.get(match[1]) || 0) + times);
      const user = userRecord(name);
      user.failed += times;
      if (match[2]) user.invalid = true;
      const ip = ipRecord(match[4], ts);
      if (ip) {
        ip.failed += times;
        ip.users.add(name);
      }
      timeline.add(ts, 0, times);
      return true;
    }

    if (message.startsWith('Accepted ') && (match = ACCEPTED.exec(message))) {
      const name = userName(match[2]);
      const method = match[1];
      acceptedLogins += times;
      const ip = ipRecord(match[3], ts);
      if (ip) {
        ip.accepted += times;
        ip.acceptedUsers.add(name);
      }
      const source = ip ? ip.ip : match[3].slice(0, MAX_NAME);
      if (name === 'root') {
        acceptedRoot += times;
        rootSources.add(source);
      }
      if (method === 'password') {
        acceptedPassword += times;
        passwordUsers.add(name);
      }
      recent.push({ ts: orNull(ts), user: name, ip: source, method });
      if (recent.length > limit * 4) recent = recent.slice(-limit * 2);
      timeline.add(ts, 1, times);
      return true;
    }

    if (message.startsWith('Invalid user ') && (match = INVALID_USER.exec(message))) {
      const name = userName(match[1]);
      userRecord(name).invalid = true;
      const ip = ipRecord(match[2], ts);
      if (ip) ip.users.add(name);
      return true;
    }

    if ((message.startsWith('Connection ') || message.startsWith('Disconnected ')) && (match = CLOSED.exec(message))) {
      const name = userName(match[2]);
      preauthDisconnects += times;
      const user = userRecord(name);
      user.other += times;
      if (match[1] === 'invalid') user.invalid = true;
      const ip = ipRecord(match[3], ts);
      if (ip) {
        ip.other += times;
        ip.users.add(name);
      }
      return true;
    }

    if (message.startsWith('error: maximum ') && (match = MAX_ATTEMPTS.exec(message))) {
      const name = userName(match[2]);
      const user = userRecord(name);
      user.other += times;
      if (match[1]) user.invalid = true;
      const ip = ipRecord(match[3], ts);
      if (ip) {
        ip.other += times;
        ip.users.add(name);
      }
      return true;
    }

    if (message.startsWith('pam_unix(sshd:auth)') && (match = PAM_FAILURE.exec(message))) {
      const ip = ipRecord(match[1], ts);
      if (match[2]) {
        const name = userName(match[2]);
        userRecord(name);
        if (ip) ip.users.add(name);
      }
      return true;
    }

    if (message.startsWith('Did not ') && (match = NO_IDENTIFICATION.exec(message))) {
      probe(match[1], times, ts);
      return true;
    }
    if (message.startsWith('Unable to ') && (match = NO_NEGOTIATION.exec(message))) {
      probe(match[1], times, ts);
      return true;
    }
    if (message.startsWith('banner exchange: ') && (match = BANNER.exec(message))) {
      probe(match[1], times, ts);
      return true;
    }
    if (message.startsWith('Bad protocol ') && (match = BAD_VERSION.exec(message))) {
      probe(match[1], times, ts);
      return true;
    }
    return false;
  }

  function handleSudo(message: string): boolean {
    let match = SUDO_PAM_FAILURE.exec(message);
    if (match) {
      const fields = match[1];
      const who = SUDO_RUSER.exec(fields) || SUDO_LOGNAME.exec(fields) || SUDO_USER.exec(fields);
      sudoAuthFailures += 1;
      if (who) sudoRecord(userName(who[1])).authFailures += 1;
      return true;
    }

    match = SUDO_EVENT.exec(message);
    if (!match) return false;
    const name = userName(match[1]);
    const rest = match[2];

    if (rest.startsWith('user NOT in sudoers')) {
      sudoNotInSudoers += 1;
      sudoRecord(name).notInSudoers += 1;
      return true;
    }
    const incorrect = SUDO_INCORRECT.exec(rest);
    if (incorrect) {
      // The PAM line already counted this failure for the user, so only the total is kept here.
      sudoIncorrect += Math.min(Number(incorrect[1]), MAX_REPEAT);
      sudoRecord(name);
      return true;
    }
    if (rest.startsWith('command not allowed') || rest.startsWith('user NOT authorized on host')) {
      sudoDenied += 1;
      sudoRecord(name);
      return true;
    }
    const command = rest.indexOf('COMMAND=');
    if (command !== -1 && !rest.startsWith('(command continued)')) {
      sudoCommands += 1;
      const record = sudoRecord(name);
      record.commands += 1;
      record.lastCommand = rest.slice(command + 8, command + 8 + 200);
      return true;
    }
    return false;
  }

  const lines = forEachLine(input, line => {
    const entry = reader.parse(line);
    const program = entry.program;
    let matched = false;

    if (program === 'sudo') {
      matched = handleSudo(entry.message);
    } else if (program === '' || program.startsWith('sshd')) {
      // sshd, and sshd-session / sshd-auth since OpenSSH 9.8. Lines without a tag (journalctl -o cat) are tried too.
      let message = entry.message;
      let times = 1;
      if (message.startsWith('message repeated ')) {
        const repeated = REPEATED.exec(message);
        if (repeated) {
          times = Math.min(Math.max(Number(repeated[1]), 1), MAX_REPEAT);
          message = repeated[2];
        }
      }
      matched = handleSshd(message, times, entry.ts);
    }

    if (matched) {
      recognized += 1;
      if (!Number.isNaN(entry.ts)) seen(entry.ts);
    }
  });

  /* ---------- Lists ---------- */

  const hostile: IpRecord[] = [];
  const offenders: Offender[] = [];
  let failedIps = 0;
  for (const record of ips.values()) {
    if (record.failed > 0 || record.other > 0) hostile.push(record);
    if (record.failed > 0) {
      failedIps += 1;
      offenders.push({ ip: record.ip, failed: record.failed, accepted: record.accepted > 0 });
    }
  }
  hostile.sort((a, b) => b.failed - a.failed || b.other - a.other || b.users.size - a.users.size || (a.ip < b.ip ? -1 : 1));
  offenders.sort((a, b) => b.failed - a.failed || (a.ip < b.ip ? -1 : 1));

  const topIps: AuthIpRow[] = hostile.slice(0, limit).map(record => ({
    ip: record.ip,
    version: record.version,
    failed: record.failed,
    other: record.other,
    users: record.users.size,
    firstSeen: orNull(record.first),
    lastSeen: orNull(record.last),
    accepted: record.accepted > 0,
  }));

  const userRows: AuthUserRow[] = [];
  let invalidUsernames = 0;
  for (const [user, record] of users) {
    if (record.invalid) invalidUsernames += 1;
    userRows.push({ user, failed: record.failed, other: record.other, invalid: record.invalid });
  }
  userRows.sort((a, b) => b.failed - a.failed || b.other - a.other || (a.user < b.user ? -1 : 1));

  // The log is in time order, so the newest logins are at the end. The sort is stable and keeps lines without a time last.
  const accepted = recent.slice().reverse().sort((a, b) => {
    if (a.ts === b.ts) return 0;
    if (a.ts === null) return 1;
    if (b.ts === null) return -1;
    return b.ts - a.ts;
  }).slice(0, limit);

  const sudoRows: SudoUserRow[] = [];
  for (const [user, record] of sudoUsers) sudoRows.push({ user, ...record });
  sudoRows.sort((a, b) => b.commands - a.commands || b.notInSudoers - a.notInSudoers || b.authFailures - a.authFailures || (a.user < b.user ? -1 : 1));

  const failedByMethod = Array.from(methods, ([method, count]) => ({ method, count })).sort((a, b) => b.count - a.count);

  /* ---------- Findings ---------- */

  const findings: LogFinding[] = [];

  const compromised = hostile.filter(record => record.accepted > 0 && record.failed >= SUCCESS_AFTER_FAILURES);
  for (const record of compromised.slice(0, 5)) {
    const names = Array.from(record.acceptedUsers);
    findings.push({
      severity: 'critical',
      title: `Accepted login from ${record.ip}, which also had ${plural(record.failed, 'failed attempt', 'failed attempts')}`,
      detail: `${record.ip} logged in as ${listSome(names)} and also failed ${record.failed.toLocaleString('en-US')} times. If this is not a user who mistyped a password, treat the account as compromised: change its password, check its authorized_keys and review what the session did.`,
    });
  }
  if (compromised.length > 5) {
    findings.push({
      severity: 'critical',
      title: `${compromised.length - 5} more addresses logged in after ${SUCCESS_AFTER_FAILURES} or more failed attempts`,
      detail: 'They are marked in the source address table.',
    });
  }

  if (acceptedRoot > 0) {
    findings.push({
      severity: 'warning',
      title: `${plural(acceptedRoot, 'accepted root login', 'accepted root logins')}`,
      detail: `root logged in directly from ${listSome(Array.from(rootSources))}. Log in as a normal user and use sudo, and set PermitRootLogin no (or prohibit-password) in sshd_config.`,
    });
  }

  if (acceptedPassword > 0) {
    findings.push({
      severity: 'warning',
      title: `${plural(acceptedPassword, 'login', 'logins')} accepted with a password`,
      detail: `Password logins for ${listSome(Array.from(passwordUsers))}. Passwords can be guessed. Switch these accounts to SSH keys and set PasswordAuthentication no.`,
    });
  }

  if (sudoNotInSudoers > 0) {
    const names = sudoRows.filter(row => row.notInSudoers > 0).map(row => row.user);
    findings.push({
      severity: 'warning',
      title: `${plural(sudoNotInSudoers, 'sudo attempt', 'sudo attempts')} by a user who is not in sudoers`,
      detail: `${listSome(names)} tried to run sudo without permission. Check whether that was expected.`,
    });
  }

  if (failedAttempts > bruteForceNote) {
    findings.push({
      severity: 'info',
      title: `${failedAttempts.toLocaleString('en-US')} failed login attempts from ${plural(failedIps, 'address', 'addresses')}`,
      detail: 'This is brute-force guessing, which every SSH server on a public address receives. fail2ban or key-only authentication stops it from mattering.',
    });
  }

  if (failedAttempts === 0 && preauthDisconnects >= 20) {
    findings.push({
      severity: 'info',
      title: `${preauthDisconnects.toLocaleString('en-US')} connections were closed before login`,
      detail: 'No failed password lines were found. A server that only accepts keys logs guessing attempts this way. They are listed as other events and are not counted as failed attempts.',
    });
  }

  if (lines > 0 && recognized === 0) {
    findings.push({
      severity: 'info',
      title: 'No sshd or sudo lines were recognized',
      detail: 'Check that this is auth.log, secure or journalctl output for the ssh unit.',
    });
  } else if (recognized > 0 && findings.length === 0) {
    findings.push({ severity: 'ok', title: 'Nothing stands out in this log' });
  }

  return {
    totals: {
      lines,
      recognized,
      failedAttempts,
      failedIps,
      usernamesTried: users.size,
      invalidUsernames,
      acceptedLogins,
      scannerProbes,
      preauthDisconnects,
    },
    firstSeen: orNull(firstSeen),
    lastSeen: orNull(lastSeen),
    failedByMethod,
    topIps,
    ipTotal: hostile.length,
    topUsers: userRows.slice(0, limit),
    userTotal: userRows.length,
    accepted,
    acceptedTotal: acceptedLogins,
    timeline: timeline.build(),
    sudo: {
      commands: sudoCommands,
      authFailures: sudoAuthFailures,
      incorrectPasswordAttempts: sudoIncorrect,
      notInSudoers: sudoNotInSudoers,
      denied: sudoDenied,
      users: sudoRows.slice(0, limit),
      userTotal: sudoRows.length,
    },
    findings: sortFindings(findings),
    offenders,
  };
}

/* ---------- Block list ---------- */

export type BlockFormat = 'plain' | 'ufw' | 'iptables' | 'nftables' | 'fail2ban' | 'hosts-deny';

export const BLOCK_FORMATS: Array<{ key: BlockFormat; label: string }> = [
  { key: 'plain', label: 'Plain list' },
  { key: 'ufw', label: 'ufw' },
  { key: 'iptables', label: 'iptables' },
  { key: 'nftables', label: 'nftables set' },
  { key: 'fail2ban', label: 'fail2ban' },
  { key: 'hosts-deny', label: 'hosts.deny' },
];

export const DEFAULT_BLOCK_THRESHOLD = 5;

export interface BlockListOptions {
  /** Minimum failed attempts for an address to be listed. Default 5. */
  threshold?: number;
  format?: BlockFormat;
}

export interface BlockList {
  threshold: number;
  /** Addresses to block, most failures first. */
  ips: string[];
  /** Addresses over the threshold that are left out on purpose. */
  review: Array<{ ip: string; failed: number; reason: 'accepted login' | 'private or loopback address' }>;
  /** The block list in the chosen format. Empty when no address qualifies. */
  text: string;
}

function formatBlockList(ips: string[], format: BlockFormat): string {
  if (ips.length === 0) return '';
  const v4 = ips.filter(ip => ipVersion(ip) === 4);
  const v6 = ips.filter(ip => ipVersion(ip) === 6);
  switch (format) {
    case 'ufw':
      return [
        '# ufw uses the first rule that matches. If SSH is already allowed,',
        '# use "ufw prepend deny from ADDRESS" (ufw 0.36 or later) instead.',
        ...ips.map(ip => `ufw deny from ${ip}`),
      ].join('\n');
    case 'iptables':
      return [
        '# -A adds the rule at the end. Use -I INPUT 1 if an earlier rule already accepts SSH.',
        ...v4.map(ip => `iptables -A INPUT -s ${ip} -j DROP`),
        ...v6.map(ip => `ip6tables -A INPUT -s ${ip} -j DROP`),
      ].join('\n');
    case 'nftables': {
      const out = ['# Put the sets in your inet table in /etc/nftables.conf.'];
      if (v4.length) out.push('set ssh_block_v4 {', '    type ipv4_addr', `    elements = { ${v4.join(', ')} }`, '}');
      if (v6.length) out.push('set ssh_block_v6 {', '    type ipv6_addr', `    elements = { ${v6.join(', ')} }`, '}');
      out.push('# Then drop them at the top of the input chain:');
      if (v4.length) out.push('#   ip saddr @ssh_block_v4 drop');
      if (v6.length) out.push('#   ip6 saddr @ssh_block_v6 drop');
      return out.join('\n');
    }
    case 'fail2ban':
      return ips.map(ip => `fail2ban-client set sshd banip ${ip}`).join('\n');
    case 'hosts-deny':
      return [
        '# /etc/hosts.deny. Only works where sshd is built with TCP wrappers',
        '# (Debian and Ubuntu). RHEL 8 and later ignore this file.',
        ...v4.map(ip => `sshd: ${ip}`),
        ...v6.map(ip => `sshd: [${ip}]`),
      ].join('\n');
    default:
      return ips.join('\n');
  }
}

/**
 * Addresses with at least `threshold` failed attempts and no accepted login.
 * An address that also logged in successfully is never suggested for blocking
 * (that could lock out a real user); it goes to `review`, as do private and
 * loopback addresses. Every address is validated again here, so the output
 * only ever contains IPv4 or IPv6 addresses.
 */
export function buildBlockList(offenders: Offender[], options: BlockListOptions = {}): BlockList {
  const requested = Number(options.threshold);
  const threshold = Number.isFinite(requested) && requested >= 1 ? Math.floor(requested) : DEFAULT_BLOCK_THRESHOLD;
  const format = BLOCK_FORMATS.some(item => item.key === options.format) ? (options.format as BlockFormat) : 'plain';

  const ips: string[] = [];
  const review: BlockList['review'] = [];
  const listed = new Set<string>();
  const sorted = (Array.isArray(offenders) ? offenders : [])
    .filter(offender => Boolean(offender) && offender.failed >= threshold)
    .sort((a, b) => b.failed - a.failed);
  for (const offender of sorted) {
    const ip = cleanIp(offender.ip);
    if (ip === '' || listed.has(ip)) continue;
    listed.add(ip);
    if (offender.accepted) review.push({ ip, failed: offender.failed, reason: 'accepted login' });
    else if (isLocalAddress(ip)) review.push({ ip, failed: offender.failed, reason: 'private or loopback address' });
    else ips.push(ip);
  }
  return { threshold, ips, review, text: formatBlockList(ips, format) };
}
