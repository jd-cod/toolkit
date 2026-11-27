/**
 * sshd_config audit. Parses an sshd_config file or `sshd -T` output and reports
 * risky settings against OpenSSH defaults. Plain TypeScript, no React or DOM,
 * runs in the browser and in `node --test`. Nothing here talks to the network.
 */

export type Severity = 'critical' | 'warning' | 'info' | 'ok';

export interface SshdDirective {
  /** Keyword as written. */
  keyword: string;
  /** Keyword in lower case, used for lookups. */
  key: string;
  /** Arguments joined with single spaces, quotes removed. */
  value: string;
  /** 1-based line number in the input. */
  line: number;
}

export interface SshdFinding {
  severity: Severity;
  directive: string;
  /** Value in effect in the pasted text, or "not set". */
  current: string;
  /** What to set instead, or "no change". */
  recommended: string;
  why: string;
  /** Short headline, for example "PermitRootLogin yes" or "X is not set, default is Y". */
  title: string;
  /** `why` plus the recommendation, ready for display. */
  detail: string;
  /** Line for the hardened snippet, when the fix is a plain config line. */
  fix?: string;
  /** Match criteria when the finding applies only inside a Match block. */
  scope?: string;
}

export interface MatchOverride {
  directive: string;
  value: string;
  line: number;
  flagged: boolean;
}

export interface MatchBlock {
  criteria: string;
  line: number;
  directives: MatchOverride[];
}

export interface SshdAudit {
  /** Directives of the global section, in order (Match and Include lines excluded). */
  directives: SshdDirective[];
  matchBlocks: MatchBlock[];
  includes: string[];
  /** Number of lines that use a keyword this tool knows. 0 means the text does not look like an sshd config. */
  recognized: number;
  findings: SshdFinding[];
  counts: Record<Severity, number>;
  /** Only the directives that should change, with recommended values. Empty when nothing needs to change. */
  hardenedSnippet: string;
}

/** Display names for the keywords this tool audits or lists. */
const NAMES: Record<string, string> = {
  allowagentforwarding: 'AllowAgentForwarding',
  allowgroups: 'AllowGroups',
  allowtcpforwarding: 'AllowTcpForwarding',
  allowusers: 'AllowUsers',
  challengeresponseauthentication: 'ChallengeResponseAuthentication',
  chrootdirectory: 'ChrootDirectory',
  ciphers: 'Ciphers',
  clientalivecountmax: 'ClientAliveCountMax',
  clientaliveinterval: 'ClientAliveInterval',
  denygroups: 'DenyGroups',
  denyusers: 'DenyUsers',
  forcecommand: 'ForceCommand',
  gatewayports: 'GatewayPorts',
  hostbasedauthentication: 'HostbasedAuthentication',
  hostkey: 'HostKey',
  hostkeyalgorithms: 'HostKeyAlgorithms',
  ignorerhosts: 'IgnoreRhosts',
  include: 'Include',
  kbdinteractiveauthentication: 'KbdInteractiveAuthentication',
  kexalgorithms: 'KexAlgorithms',
  listenaddress: 'ListenAddress',
  logingracetime: 'LoginGraceTime',
  loglevel: 'LogLevel',
  macs: 'MACs',
  match: 'Match',
  maxauthtries: 'MaxAuthTries',
  maxsessions: 'MaxSessions',
  maxstartups: 'MaxStartups',
  passwordauthentication: 'PasswordAuthentication',
  permitemptypasswords: 'PermitEmptyPasswords',
  permitrootlogin: 'PermitRootLogin',
  permittunnel: 'PermitTunnel',
  permituserenvironment: 'PermitUserEnvironment',
  port: 'Port',
  protocol: 'Protocol',
  pubkeyacceptedalgorithms: 'PubkeyAcceptedAlgorithms',
  pubkeyacceptedkeytypes: 'PubkeyAcceptedKeyTypes',
  pubkeyauthentication: 'PubkeyAuthentication',
  strictmodes: 'StrictModes',
  subsystem: 'Subsystem',
  usedns: 'UseDNS',
  usepam: 'UsePAM',
  x11forwarding: 'X11Forwarding',
  authorizedkeysfile: 'AuthorizedKeysFile',
  acceptenv: 'AcceptEnv',
  banner: 'Banner',
  printmotd: 'PrintMotd',
  syslogfacility: 'SyslogFacility',
  tcpkeepalive: 'TCPKeepAlive',
  authenticationmethods: 'AuthenticationMethods',
  addressfamily: 'AddressFamily',
  compression: 'Compression',
  permittty: 'PermitTTY',
  disableforwarding: 'DisableForwarding',
};

/** Single-value keywords this tool checks. For these sshd uses the first value it reads, so repeats are reported. */
const FIRST_WINS = [
  'permitrootlogin', 'passwordauthentication', 'permitemptypasswords', 'pubkeyauthentication', 'kbdinteractiveauthentication',
  'challengeresponseauthentication', 'x11forwarding', 'maxauthtries', 'logingracetime', 'clientaliveinterval', 'permituserenvironment',
  'hostbasedauthentication', 'ignorerhosts', 'strictmodes', 'gatewayports', 'allowtcpforwarding', 'allowagentforwarding', 'permittunnel',
  'loglevel', 'usepam', 'ciphers', 'macs', 'kexalgorithms', 'hostkeyalgorithms', 'pubkeyacceptedalgorithms', 'pubkeyacceptedkeytypes',
];

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, warning: 1, info: 2, ok: 3 };
const MAX_LISTED = 20;

// ---------- Parsing ----------

function isBlank(char: string): boolean {
  return char === ' ' || char === '\t';
}

/** Split arguments on whitespace. Double quotes group words, an unquoted `#` at the start of a word begins a comment. */
function tokenize(rest: string): string[] {
  const args: string[] = [];
  let index = 0;
  while (index < rest.length) {
    while (index < rest.length && isBlank(rest[index])) index += 1;
    if (index >= rest.length || rest[index] === '#') break;
    let token = '';
    while (index < rest.length && !isBlank(rest[index])) {
      if (rest[index] === '"') {
        const end = rest.indexOf('"', index + 1);
        token += end < 0 ? rest.slice(index + 1) : rest.slice(index + 1, end);
        index = end < 0 ? rest.length : end + 1;
      } else {
        token += rest[index];
        index += 1;
      }
    }
    args.push(token);
  }
  return args;
}

export interface ParsedSshdConfig {
  directives: SshdDirective[];
  matchBlocks: Array<{ criteria: string; line: number; directives: SshdDirective[] }>;
  includes: string[];
}

/** Parse `Keyword value`, `Keyword=value` and `sshd -T` style `keyword value` lines. */
export function parseSshdConfig(text: string): ParsedSshdConfig {
  const parsed: ParsedSshdConfig = { directives: [], matchBlocks: [], includes: [] };
  if (typeof text !== 'string') return parsed;
  const lines = text.split(/\r\n|\n|\r/);
  let block: ParsedSshdConfig['matchBlocks'][number] | null = null;

  for (let index = 0; index < lines.length; index += 1) {
    const trimmed = lines[index].trim();
    if (trimmed === '' || trimmed[0] === '#') continue;
    let end = 0;
    while (end < trimmed.length && !isBlank(trimmed[end]) && trimmed[end] !== '=') end += 1;
    if (end === 0) continue;
    const keyword = trimmed.slice(0, end);
    const key = keyword.toLowerCase();
    const value = tokenize(trimmed.slice(end).replace(/^[ \t]*=?/, '')).join(' ');
    const directive: SshdDirective = { keyword, key, value, line: index + 1 };

    if (key === 'match') {
      block = { criteria: value, line: index + 1, directives: [] };
      parsed.matchBlocks.push(block);
    } else if (key === 'include') {
      parsed.includes.push(value);
    } else if (block) {
      block.directives.push(directive);
    } else {
      parsed.directives.push(directive);
    }
  }
  return parsed;
}

/** sshd time format: seconds, or a sequence such as `2m`, `1h30m`, `90s`. Null when it cannot be read. */
export function parseSshdTime(value: string): number | null {
  const units: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };
  const text = value.trim().toLowerCase();
  if (text === '' || text.length > 40) return null;
  let total = 0;
  let index = 0;
  while (index < text.length) {
    const start = index;
    while (index < text.length && text[index] >= '0' && text[index] <= '9') index += 1;
    if (index === start) return null;
    const amount = Number(text.slice(start, index));
    const unit = index < text.length ? units[text[index]] : 1;
    if (unit === undefined) return null;
    if (index < text.length) index += 1;
    total += amount * unit;
  }
  return Number.isFinite(total) ? total : null;
}

// ---------- Algorithm lists ----------

interface AlgorithmList {
  /** '' replaces the defaults, '+' appends, '-' removes, '^' puts first. */
  prefix: '' | '+' | '-' | '^';
  items: string[];
}

export function parseAlgorithmList(value: string): AlgorithmList {
  const compact = value.replace(/\s+/g, '');
  const first = compact[0];
  const prefix = first === '+' || first === '-' || first === '^' ? first : '';
  const items = compact.slice(prefix.length).split(',').map(item => item.toLowerCase()).filter(Boolean);
  return { prefix, items };
}

function weakCipher(name: string): boolean {
  return name === '3des-cbc' || name === 'blowfish-cbc' || name === 'cast128-cbc' || name === 'rijndael-cbc@lysator.liu.se'
    || name.startsWith('arcfour') || (name.startsWith('aes') && name.endsWith('-cbc'));
}

function weakMac(name: string): boolean {
  return name.startsWith('hmac-md5') || name.startsWith('hmac-sha1') || name.startsWith('umac-64') || name.startsWith('hmac-ripemd160');
}

function weakKex(name: string): boolean {
  return name === 'diffie-hellman-group1-sha1' || name === 'diffie-hellman-group14-sha1' || name === 'diffie-hellman-group-exchange-sha1';
}

function dsaKeyAlgorithm(name: string): boolean {
  return name === 'ssh-dss' || name.startsWith('ssh-dss-cert-');
}

function sha1RsaKeyAlgorithm(name: string): boolean {
  return name === 'ssh-rsa' || name.startsWith('ssh-rsa-cert-');
}

const ETM_MACS = 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com';

// ---------- Audit ----------

interface FindingInput {
  severity: Severity;
  directive: string;
  /** Value in effect; leave out when the directive is not set. */
  value?: string;
  /** OpenSSH default, used in the title when the directive is not set. */
  fallback?: string;
  title?: string;
  recommended?: string;
  why: string;
  fix?: string;
  scope?: string;
}

function makeFinding(input: FindingInput): SshdFinding {
  const set = input.value !== undefined;
  const title = input.title ?? (set ? `${input.directive} ${input.value}` : `${input.directive} is not set, default is ${input.fallback}`);
  const recommended = input.recommended ?? input.fix ?? 'no change';
  const detail = recommended === 'no change' ? input.why : `${input.why} Recommended: ${recommended}.`;
  return {
    severity: input.severity,
    directive: input.directive,
    current: set ? (input.value as string) : 'not set',
    recommended,
    why: input.why,
    title,
    detail,
    ...(input.fix ? { fix: input.fix } : {}),
    ...(input.scope ? { scope: input.scope } : {}),
  };
}

/** Overrides worth flagging inside a Match block: keyword, risky values, reason. */
const MATCH_RISKS: Record<string, { values: string[]; reason: string }> = {
  permitrootlogin: { values: ['yes'], reason: 'Root can log in with a password for these connections.' },
  passwordauthentication: { values: ['yes'], reason: 'Password logins are allowed for these connections.' },
  permitemptypasswords: { values: ['yes'], reason: 'Accounts with an empty password can log in for these connections.' },
  hostbasedauthentication: { values: ['yes'], reason: 'Host-based authentication is allowed for these connections.' },
  x11forwarding: { values: ['yes'], reason: 'X11 forwarding is allowed for these connections.' },
  gatewayports: { values: ['yes', 'clientspecified'], reason: 'Remote port forwards can listen on all interfaces for these connections.' },
};

export function auditSshdConfig(text: string): SshdAudit {
  const parsed = parseSshdConfig(text);
  const findings: SshdFinding[] = [];
  const add = (input: FindingInput) => findings.push(makeFinding(input));

  // First occurrence of each keyword in the global section, plus every occurrence for duplicate and list checks.
  const byKey = new Map<string, SshdDirective[]>();
  for (const directive of parsed.directives) {
    const list = byKey.get(directive.key);
    if (list) list.push(directive);
    else byKey.set(directive.key, [directive]);
  }
  const first = (key: string): SshdDirective | undefined => byKey.get(key)?.[0];
  const raw = (key: string): string | undefined => first(key)?.value;
  const flag = (key: string): string | undefined => raw(key)?.toLowerCase();

  let recognized = parsed.matchBlocks.length + parsed.includes.length;
  for (const directive of parsed.directives) if (NAMES[directive.key]) recognized += 1;
  for (const block of parsed.matchBlocks) for (const directive of block.directives) if (NAMES[directive.key]) recognized += 1;

  if (typeof text === 'string' && text.trim() !== '' && recognized === 0) {
    add({
      severity: 'warning',
      directive: 'Input',
      value: 'not recognised',
      title: 'No sshd settings recognised',
      why: 'The text does not look like an sshd_config or sshd -T output. The other findings reflect OpenSSH defaults only.',
      recommended: 'paste the file /etc/ssh/sshd_config or the output of sudo sshd -T',
    });
  }

  // --- Root login ---
  const root = flag('permitrootlogin');
  if (root === undefined) {
    add({ severity: 'ok', directive: 'PermitRootLogin', fallback: 'prohibit-password', why: 'Root can log in with a key but not with a password. This is the default since OpenSSH 7.0; older versions default to yes.' });
  } else if (root === 'yes') {
    add({
      severity: 'critical',
      directive: 'PermitRootLogin',
      value: raw('permitrootlogin'),
      why: 'Root can log in directly with a password. Root exists on every system and is the first account attackers try.',
      recommended: 'PermitRootLogin no, or prohibit-password if root needs key login',
      fix: 'PermitRootLogin no',
    });
  } else if (root === 'prohibit-password' || root === 'without-password') {
    add({ severity: 'ok', directive: 'PermitRootLogin', value: raw('permitrootlogin'), why: 'Root can log in with a key but not with a password. Set it to no if root never needs to log in directly.' });
  } else if (root === 'forced-commands-only') {
    add({ severity: 'ok', directive: 'PermitRootLogin', value: raw('permitrootlogin'), why: 'Root can log in with a key only to run the command tied to that key.' });
  } else if (root === 'no') {
    add({ severity: 'ok', directive: 'PermitRootLogin', value: raw('permitrootlogin'), why: 'Root cannot log in over SSH.' });
  }

  // --- Authentication methods ---
  const password = flag('passwordauthentication');
  if (password === undefined || password === 'yes') {
    add({
      severity: 'warning',
      directive: 'PasswordAuthentication',
      value: raw('passwordauthentication'),
      fallback: 'yes',
      why: 'Password logins can be guessed or phished. Keys cannot be brute-forced in practice.',
      fix: 'PasswordAuthentication no',
    });
  } else if (password === 'no') {
    add({ severity: 'ok', directive: 'PasswordAuthentication', value: raw('passwordauthentication'), why: 'Password logins are off.' });
  }

  if (flag('permitemptypasswords') === 'yes') {
    add({
      severity: 'critical',
      directive: 'PermitEmptyPasswords',
      value: raw('permitemptypasswords'),
      why: 'Accounts with an empty password can log in when password authentication is on.',
      fix: 'PermitEmptyPasswords no',
    });
  }

  if (flag('pubkeyauthentication') === 'no') {
    add({
      severity: 'warning',
      directive: 'PubkeyAuthentication',
      value: raw('pubkeyauthentication'),
      why: 'Key login is off, which leaves only weaker methods such as passwords.',
      fix: 'PubkeyAuthentication yes',
    });
  }

  // KbdInteractiveAuthentication and ChallengeResponseAuthentication are the same option; the first line wins.
  const kbd = [first('kbdinteractiveauthentication'), first('challengeresponseauthentication')]
    .filter((item): item is SshdDirective => item !== undefined)
    .sort((a, b) => a.line - b.line)[0];
  if (kbd === undefined || kbd.value.toLowerCase() === 'yes') {
    add({
      severity: 'info',
      directive: kbd ? (NAMES[kbd.key] ?? kbd.keyword) : 'KbdInteractiveAuthentication',
      value: kbd?.value,
      fallback: 'yes',
      why: 'Keyboard-interactive login can still ask for a password through PAM when UsePAM is yes, even with PasswordAuthentication no.',
      recommended: 'KbdInteractiveAuthentication no, unless you use it for one-time codes',
    });
  }

  if (flag('hostbasedauthentication') === 'yes') {
    add({
      severity: 'warning',
      directive: 'HostbasedAuthentication',
      value: raw('hostbasedauthentication'),
      why: 'Host-based authentication trusts the client machine to vouch for the user. A compromised trusted host gives access without a key or password.',
      fix: 'HostbasedAuthentication no',
    });
  }

  if (flag('ignorerhosts') === 'no') {
    add({
      severity: 'warning',
      directive: 'IgnoreRhosts',
      value: raw('ignorerhosts'),
      why: 'Per-user .rhosts and .shosts files are honoured for host-based authentication, so users can add trusted hosts themselves.',
      fix: 'IgnoreRhosts yes',
    });
  }

  const userEnvironment = flag('permituserenvironment');
  if (userEnvironment !== undefined && userEnvironment !== 'no') {
    add({
      severity: 'warning',
      directive: 'PermitUserEnvironment',
      value: raw('permituserenvironment'),
      why: 'Users can set environment variables such as LD_PRELOAD for their sessions, which can bypass access restrictions.',
      fix: 'PermitUserEnvironment no',
    });
  }

  if (flag('strictmodes') === 'no') {
    add({
      severity: 'warning',
      directive: 'StrictModes',
      value: raw('strictmodes'),
      why: 'sshd skips the ownership and permission checks on home directories and key files, so keys in files that others can write are accepted.',
      fix: 'StrictModes yes',
    });
  }

  if (flag('usepam') === 'no') {
    add({
      severity: 'info',
      directive: 'UsePAM',
      value: raw('usepam'),
      why: 'PAM account and session processing is skipped, so PAM-based controls such as access rules, limits and two-factor modules do not apply.',
      recommended: 'UsePAM yes on systems that rely on PAM',
    });
  }

  // --- Protocol ---
  const protocol = raw('protocol');
  if (protocol !== undefined && protocol.split(/[\s,]+/).includes('1')) {
    add({
      severity: 'critical',
      directive: 'Protocol',
      value: protocol,
      why: 'SSH protocol 1 has known cryptographic flaws. OpenSSH 7.4 and later support only protocol 2; older servers accept protocol 1 with this setting.',
      recommended: 'Protocol 2, or remove the line on OpenSSH 7.4 and later',
      fix: 'Protocol 2',
    });
  }

  // --- Limits and timeouts ---
  const tries = raw('maxauthtries');
  const triesNumber = tries === undefined ? 6 : /^\d{1,9}$/.test(tries) ? Number(tries) : null;
  if (triesNumber !== null && triesNumber > 4) {
    add({
      severity: 'info',
      directive: 'MaxAuthTries',
      value: tries,
      fallback: '6',
      why: `Each connection gets ${triesNumber} authentication attempts before it is dropped. A lower value slows password guessing.`,
      fix: 'MaxAuthTries 4',
    });
  }

  const grace = raw('logingracetime');
  const graceSeconds = grace === undefined ? 120 : parseSshdTime(grace);
  if (graceSeconds !== null && (graceSeconds === 0 || graceSeconds > 60)) {
    add({
      severity: 'info',
      directive: 'LoginGraceTime',
      value: grace,
      fallback: '120 seconds',
      why: graceSeconds === 0
        ? 'Connections that never log in are kept open with no time limit, which can use up connection slots.'
        : `Connections that have not logged in are kept open for ${graceSeconds} seconds, which makes it easier to use up connection slots.`,
      fix: 'LoginGraceTime 60',
    });
  }

  const alive = raw('clientaliveinterval');
  const aliveSeconds = alive === undefined ? 0 : parseSshdTime(alive);
  if (aliveSeconds === 0) {
    add({
      severity: 'info',
      directive: 'ClientAliveInterval',
      value: alive,
      fallback: '0',
      why: 'sshd does not check whether clients are still there, so dead connections can stay open.',
      fix: 'ClientAliveInterval 300',
    });
  }

  if (!['allowusers', 'allowgroups', 'denyusers', 'denygroups'].some(key => byKey.has(key))) {
    add({
      severity: 'info',
      directive: 'AllowUsers',
      title: 'No AllowUsers, AllowGroups or DenyUsers',
      why: 'Every account with valid credentials can log in over SSH. An allow list limits SSH to the accounts that need it.',
      recommended: 'AllowGroups with a dedicated group, or AllowUsers with the account names',
    });
  }

  // --- Forwarding ---
  if (flag('x11forwarding') === 'yes') {
    add({
      severity: 'warning',
      directive: 'X11Forwarding',
      value: raw('x11forwarding'),
      why: 'X11 forwarding adds attack surface and can expose the X display of connecting clients. Servers rarely need it.',
      fix: 'X11Forwarding no',
    });
  }

  const gateway = flag('gatewayports');
  if (gateway === 'yes' || gateway === 'clientspecified') {
    add({
      severity: 'warning',
      directive: 'GatewayPorts',
      value: raw('gatewayports'),
      why: 'Remote port forwards can listen on all interfaces instead of loopback only, which can expose forwarded services to the network.',
      fix: 'GatewayPorts no',
    });
  }

  const tcpForwarding = flag('allowtcpforwarding');
  if (tcpForwarding === undefined || ['yes', 'all', 'local', 'remote'].includes(tcpForwarding)) {
    add({
      severity: 'info',
      directive: 'AllowTcpForwarding',
      value: raw('allowtcpforwarding'),
      fallback: 'yes',
      why: 'Users can tunnel TCP connections through this server, which can get around firewall rules. Turning it off matters most for accounts without a shell; jump hosts need it on.',
      recommended: 'AllowTcpForwarding no if nobody needs tunnels',
    });
  }

  const agentForwarding = flag('allowagentforwarding');
  if (agentForwarding === undefined || agentForwarding === 'yes') {
    add({
      severity: 'info',
      directive: 'AllowAgentForwarding',
      value: raw('allowagentforwarding'),
      fallback: 'yes',
      why: 'Users may forward their SSH agent. While they are connected, anyone with root on this server can use the forwarded keys.',
      recommended: 'AllowAgentForwarding no if nobody needs it',
    });
  }

  const tunnel = flag('permittunnel');
  if (tunnel !== undefined && tunnel !== 'no') {
    add({
      severity: 'info',
      directive: 'PermitTunnel',
      value: raw('permittunnel'),
      why: 'Clients may set up tun device forwarding, which works like a VPN through this server.',
      recommended: 'PermitTunnel no unless you use it',
    });
  }

  // --- Logging ---
  const logLevel = raw('loglevel')?.toUpperCase();
  if (logLevel === 'QUIET' || logLevel === 'FATAL' || logLevel === 'ERROR') {
    add({
      severity: 'warning',
      directive: 'LogLevel',
      value: raw('loglevel'),
      why: 'Successful and failed logins are not logged at this level, so there is no record of who connected.',
      fix: 'LogLevel VERBOSE',
    });
  } else if (logLevel === undefined || logLevel === 'INFO') {
    add({
      severity: 'info',
      directive: 'LogLevel',
      value: raw('loglevel'),
      fallback: 'INFO',
      why: 'VERBOSE also logs the fingerprint of the key used for each login, which helps when several people share an account.',
      fix: 'LogLevel VERBOSE',
    });
  } else if (logLevel.startsWith('DEBUG')) {
    add({
      severity: 'info',
      directive: 'LogLevel',
      value: raw('loglevel'),
      why: 'Debug logging is meant for troubleshooting. The sshd manual says it violates the privacy of users and is not recommended.',
      fix: 'LogLevel VERBOSE',
    });
  }

  // --- Port ---
  const ports = (byKey.get('port') ?? []).map(directive => directive.value).filter(value => value !== '');
  if (ports.some(port => port !== '22')) {
    add({
      severity: 'info',
      directive: 'Port',
      value: ports.join(', '),
      why: 'A non-standard port cuts down scan noise in the logs. It does not replace key-only login or a firewall.',
    });
  }

  // --- Algorithms ---
  const algorithmCheck = (key: string, kind: 'cipher' | 'mac' | 'kex' | 'key') => {
    const directive = first(key);
    if (!directive) return;
    const name = NAMES[key];
    const list = parseAlgorithmList(directive.value);
    if (list.items.length === 0) return;
    if (list.prefix === '-') {
      add({ severity: 'ok', directive: name, value: directive.value, title: `${name} removes algorithms from the defaults`, why: `The listed algorithms are taken out of the default set: ${list.items.join(', ')}.` });
      return;
    }

    const dsa = kind === 'key' ? list.items.filter(dsaKeyAlgorithm) : [];
    const weak = list.items.filter(kind === 'cipher' ? weakCipher : kind === 'mac' ? weakMac : kind === 'kex' ? weakKex : item => dsaKeyAlgorithm(item) || sha1RsaKeyAlgorithm(item));
    const verb = list.prefix === '+' ? 'adds' : list.prefix === '^' ? 'prefers' : 'allows';
    const reasons: Record<typeof kind, string> = {
      cipher: 'CBC-mode ciphers, RC4 (arcfour), 3DES, Blowfish and CAST have known weaknesses and are not in the OpenSSH defaults.',
      mac: 'MACs based on MD5, SHA-1 or RIPEMD-160 and UMAC with 64-bit tags are considered weak.',
      kex: 'These key exchange methods rely on SHA-1, and diffie-hellman-group1-sha1 also uses a 1024-bit group.',
      key: dsa.length > 0
        ? 'DSA (ssh-dss) keys are limited to 1024 bits with SHA-1 and are off by default since OpenSSH 7.0. ssh-rsa signatures use SHA-1 and are off by default since OpenSSH 8.8.'
        : 'ssh-rsa signatures use SHA-1 and are off by default since OpenSSH 8.8. RSA keys keep working through rsa-sha2-256 and rsa-sha2-512.',
    };

    if (weak.length > 0) {
      const kept = list.items.filter(item => !weak.includes(item));
      let fix: string;
      let recommended: string;
      if (kept.length > 0) {
        fix = `${name} ${list.prefix}${kept.join(',')}`;
        recommended = fix;
      } else if (kind === 'mac' && list.prefix === '') {
        fix = `MACs ${ETM_MACS}`;
        recommended = fix;
      } else {
        fix = `# Remove this line to use the OpenSSH defaults: ${name} ${directive.value}`;
        recommended = `remove the ${name} line to use the OpenSSH defaults`;
      }
      add({
        severity: dsa.length > 0 ? 'critical' : 'warning',
        directive: name,
        value: directive.value,
        title: `${name} ${verb} weak algorithms: ${weak.join(', ')}`,
        why: reasons[kind],
        recommended,
        fix,
      });
    }

    const plainMacs = kind === 'mac' ? list.items.filter(item => !weakMac(item) && !item.includes('-etm@')) : [];
    if (plainMacs.length > 0) {
      add({
        severity: 'info',
        directive: name,
        value: directive.value,
        title: `${name} ${verb} MACs without encrypt-then-MAC: ${plainMacs.join(', ')}`,
        why: 'These are not broken, but the -etm variants authenticate the encrypted packet and are the safer construction.',
        recommended: `prefer ${ETM_MACS}`,
      });
    }

    if (weak.length === 0 && plainMacs.length === 0) {
      add({ severity: 'ok', directive: name, value: directive.value, title: `${name} lists no weak algorithms`, why: 'None of the listed algorithms is on the weak list this tool checks.' });
    }
  };

  algorithmCheck('ciphers', 'cipher');
  algorithmCheck('macs', 'mac');
  algorithmCheck('kexalgorithms', 'kex');
  algorithmCheck('hostkeyalgorithms', 'key');
  algorithmCheck('pubkeyacceptedalgorithms', 'key');
  algorithmCheck('pubkeyacceptedkeytypes', 'key');

  if (!byKey.has('macs')) {
    add({
      severity: 'info',
      directive: 'MACs',
      title: 'MACs is not set, the default list still offers hmac-sha1 and umac-64',
      why: 'The OpenSSH default MAC list includes SHA-1 based and 64-bit UMAC algorithms for compatibility. Modern clients do not need them.',
      fix: `MACs ${ETM_MACS}`,
    });
  }
  if (!byKey.has('ciphers') && !byKey.has('kexalgorithms')) {
    add({
      severity: 'info',
      directive: 'Ciphers',
      title: 'Ciphers and KexAlgorithms are not set',
      why: 'The defaults depend on the OpenSSH version. Current versions have safe defaults; old versions still offer CBC ciphers and SHA-1 key exchange.',
      recommended: 'paste the output of sudo sshd -T to check the lists in effect',
    });
  }

  // --- Duplicates: the first value wins ---
  for (const key of FIRST_WINS) {
    const all = byKey.get(key);
    if (!all || all.length < 2) continue;
    const lines = all.slice(0, 5).map(directive => directive.line).join(', ');
    const differs = all.some(directive => directive.value.toLowerCase() !== all[0].value.toLowerCase());
    add({
      severity: 'info',
      directive: NAMES[key],
      value: all[0].value,
      title: `${NAMES[key]} is set ${all.length} times`,
      why: `sshd uses the first value it reads (${all[0].value}, line ${all[0].line}) and ignores the later ones${differs ? ', which differ' : ''}. Lines: ${lines}${all.length > 5 ? ' and more' : ''}.`,
      recommended: 'keep one line',
    });
  }

  // --- Include ---
  parsed.includes.slice(0, MAX_LISTED).forEach(path => {
    add({
      severity: 'info',
      directive: 'Include',
      value: path,
      why: 'Included files are not seen by this tool. Because sshd uses the first value it reads, a file included above a directive overrides it.',
      recommended: 'paste the output of sudo sshd -T to audit the settings in effect',
    });
  });

  // --- Match blocks ---
  let flaggedOverrides = 0;
  const matchBlocks: MatchBlock[] = parsed.matchBlocks.map(block => {
    const everyone = block.criteria.trim().toLowerCase() === 'all';
    const directives = block.directives.map((directive): MatchOverride => {
      const risk = MATCH_RISKS[directive.key];
      const flagged = risk !== undefined && risk.values.includes(directive.value.toLowerCase());
      const name = NAMES[directive.key] ?? directive.keyword;
      if (flagged && flaggedOverrides < MAX_LISTED) {
        add({
          severity: 'warning',
          directive: name,
          value: directive.value,
          title: `Match ${block.criteria}: ${name} ${directive.value}`,
          why: everyone
            ? `${risk.reason} Match all applies to every connection and overrides the global section.`
            : `${risk.reason} This applies only to connections that match "${block.criteria}" and overrides the global section for them.`,
          recommended: 'keep the match as narrow as possible, or remove the override',
          scope: block.criteria,
        });
      }
      if (flagged) flaggedOverrides += 1;
      return { directive: name, value: directive.value, line: directive.line, flagged };
    });
    return { criteria: block.criteria, line: block.line, directives };
  });

  const sorted = findings
    .map((finding, position) => ({ finding, position }))
    .sort((a, b) => SEVERITY_ORDER[a.finding.severity] - SEVERITY_ORDER[b.finding.severity] || a.position - b.position)
    .map(item => item.finding);

  const counts: Record<Severity, number> = { critical: 0, warning: 0, info: 0, ok: 0 };
  for (const finding of sorted) counts[finding.severity] += 1;

  const fixes: string[] = [];
  for (const finding of sorted) if (finding.fix && !fixes.includes(finding.fix)) fixes.push(finding.fix);

  return {
    directives: parsed.directives,
    matchBlocks,
    includes: parsed.includes,
    recognized,
    findings: sorted,
    counts,
    hardenedSnippet: fixes.join('\n'),
  };
}

/** A deliberately weak config for the page's "Load sample" button and the tests. */
export const SSHD_SAMPLE = `# /etc/ssh/sshd_config - sample with deliberate weaknesses
Include /etc/ssh/sshd_config.d/*.conf

Port 22
Protocol 2,1
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 2m
PermitRootLogin yes
StrictModes no
MaxAuthTries 10
MaxSessions 10

PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords yes
KbdInteractiveAuthentication yes
UsePAM yes

X11Forwarding yes
AllowTcpForwarding yes
AllowAgentForwarding yes
GatewayPorts yes
PermitUserEnvironment yes
ClientAliveInterval 0

Ciphers aes256-ctr,aes128-ctr,aes128-cbc,3des-cbc
MACs hmac-sha2-256,hmac-sha1,hmac-md5
KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
HostKeyAlgorithms +ssh-rsa,ssh-dss

# This later line is ignored: the first PasswordAuthentication wins.
PasswordAuthentication no

Subsystem sftp /usr/lib/openssh/sftp-server

Match User deploy
    PasswordAuthentication yes
    AllowTcpForwarding no

Match Group sftponly
    ChrootDirectory /srv/sftp/%u
    ForceCommand internal-sftp
    X11Forwarding no
`;
