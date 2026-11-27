import test from 'node:test';
import assert from 'node:assert/strict';
import { auditSshdConfig, parseSshdConfig, parseSshdTime, parseAlgorithmList, SSHD_SAMPLE } from '../../frontend/src/lib/tools/sshd-audit.ts';

/** First finding for a directive, optionally narrowed by text in the title. */
const finding = (audit, directive, titleText = '') => audit.findings.find(item => item.directive === directive && !item.scope && item.title.includes(titleText));
const snippetLines = audit => audit.hardenedSnippet.split('\n').filter(Boolean);

test('empty input is audited against OpenSSH defaults', () => {
  const audit = auditSshdConfig('');
  assert.equal(audit.directives.length, 0);
  assert.equal(audit.recognized, 0);

  const root = finding(audit, 'PermitRootLogin');
  assert.equal(root.severity, 'ok');
  assert.equal(root.current, 'not set');
  assert.equal(root.title, 'PermitRootLogin is not set, default is prohibit-password');

  const password = finding(audit, 'PasswordAuthentication');
  assert.equal(password.severity, 'warning');
  assert.equal(password.title, 'PasswordAuthentication is not set, default is yes');
  assert.equal(password.recommended, 'PasswordAuthentication no');
  assert.ok(password.why.length > 0);

  assert.equal(finding(audit, 'MaxAuthTries').title, 'MaxAuthTries is not set, default is 6');
  assert.equal(finding(audit, 'LoginGraceTime').title, 'LoginGraceTime is not set, default is 120 seconds');
  assert.equal(finding(audit, 'ClientAliveInterval').severity, 'info');
  assert.equal(finding(audit, 'KbdInteractiveAuthentication').severity, 'info');
  assert.equal(finding(audit, 'AllowTcpForwarding').severity, 'info');
  assert.equal(finding(audit, 'AllowAgentForwarding').severity, 'info');
  assert.equal(finding(audit, 'LogLevel').severity, 'info');
  assert.equal(finding(audit, 'AllowUsers').severity, 'info');

  // Defaults that are safe produce no finding.
  for (const directive of ['PermitEmptyPasswords', 'X11Forwarding', 'Protocol', 'StrictModes', 'IgnoreRhosts', 'GatewayPorts', 'Port', 'UsePAM']) {
    assert.equal(finding(audit, directive), undefined, directive);
  }
  assert.equal(audit.counts.critical, 0);
  assert.equal(audit.counts.warning, 1);
  assert.equal(audit.counts.critical + audit.counts.warning + audit.counts.info + audit.counts.ok, audit.findings.length);
  // No "not recognised" warning for empty input.
  assert.equal(finding(audit, 'Input'), undefined);
});

test('garbage and odd input do not throw', () => {
  for (const input of ['hello world\nthis is not a config', '=====\n"""\n\t\t', '\u0000\u0001', 'PermitRootLogin', 'Ciphers ,,,', 'Match', '= =', null, undefined, 42]) {
    const audit = auditSshdConfig(input);
    assert.ok(Array.isArray(audit.findings));
    assert.equal(typeof audit.hardenedSnippet, 'string');
  }
  const garbage = auditSshdConfig('hello world\nthis is not a config');
  assert.equal(garbage.recognized, 0);
  assert.equal(finding(garbage, 'Input').severity, 'warning');
});

test('very large input is handled quickly', () => {
  const started = Date.now();
  const big = auditSshdConfig(`${'# comment line\nPasswordAuthentication yes\nfoo bar baz\n'.repeat(60000)}Match User a\n${'PermitRootLogin yes\n'.repeat(60000)}`);
  assert.equal(finding(big, 'PasswordAuthentication', 'is set 60000 times').severity, 'info');
  assert.ok(big.findings.length < 100);
  assert.equal(auditSshdConfig(`MaxAuthTries ${'1'.repeat(200000)}x\nLoginGraceTime ${'1'.repeat(200000)}x`).counts.critical, 0);
  assert.ok(Date.now() - started < 5000);
});

test('root login: yes is critical, key-only and no are ok', () => {
  const yes = finding(auditSshdConfig('PermitRootLogin yes'), 'PermitRootLogin');
  assert.equal(yes.severity, 'critical');
  assert.equal(yes.current, 'yes');
  assert.equal(yes.fix, 'PermitRootLogin no');
  assert.match(yes.recommended, /PermitRootLogin no/);
  for (const value of ['prohibit-password', 'without-password', 'forced-commands-only', 'no', 'No']) {
    const item = finding(auditSshdConfig(`PermitRootLogin ${value}`), 'PermitRootLogin');
    assert.equal(item.severity, 'ok', value);
    assert.equal(item.current, value);
    assert.equal(item.fix, undefined);
  }
});

test('keywords are case-insensitive, and = and quotes are accepted', () => {
  const audit = auditSshdConfig('PERMITROOTLOGIN=yes\npasswordauthentication = "no"\n  X11Forwarding\tyes  # trailing comment\n#PermitEmptyPasswords yes\nBanner "/etc/issue net"\n');
  assert.equal(finding(audit, 'PermitRootLogin').severity, 'critical');
  assert.equal(finding(audit, 'PasswordAuthentication').severity, 'ok');
  assert.equal(finding(audit, 'X11Forwarding').current, 'yes');
  assert.equal(finding(audit, 'PermitEmptyPasswords'), undefined);
  assert.deepEqual(audit.directives.map(directive => [directive.key, directive.value, directive.line]), [
    ['permitrootlogin', 'yes', 1],
    ['passwordauthentication', 'no', 2],
    ['x11forwarding', 'yes', 3],
    ['banner', '/etc/issue net', 5],
  ]);
});

test('the first occurrence wins and duplicates are reported', () => {
  const audit = auditSshdConfig('PasswordAuthentication no\nPermitRootLogin no\nPasswordAuthentication yes\nPermitRootLogin yes\n');
  assert.equal(finding(audit, 'PasswordAuthentication', 'PasswordAuthentication no').severity, 'ok');
  assert.equal(finding(audit, 'PermitRootLogin', 'PermitRootLogin no').severity, 'ok');
  assert.equal(audit.counts.critical + audit.counts.warning, 0);
  const duplicate = finding(audit, 'PasswordAuthentication', 'is set 2 times');
  assert.equal(duplicate.severity, 'info');
  assert.match(duplicate.why, /first value it reads \(no, line 1\)/);
  assert.match(duplicate.why, /Lines: 1, 3/);

  // Repeatable keywords are not reported as duplicates.
  const repeatable = auditSshdConfig('Port 22\nPort 2222\nHostKey /a\nHostKey /b\nAllowUsers alice\nAllowUsers bob\nAcceptEnv LANG\nAcceptEnv LC_*\n');
  assert.ok(!repeatable.findings.some(item => item.title.includes('times')));
  assert.equal(finding(repeatable, 'AllowUsers'), undefined);
  assert.equal(finding(repeatable, 'Port').severity, 'info');
  assert.equal(finding(repeatable, 'Port').current, '22, 2222');
});

test('port 22 alone is not a finding', () => {
  assert.equal(finding(auditSshdConfig('Port 22'), 'Port'), undefined);
});

test('Match blocks are kept out of the global audit and risky overrides are flagged', () => {
  const audit = auditSshdConfig([
    'PasswordAuthentication no',
    'PermitRootLogin no',
    'Match User backup Address 10.0.0.0/8',
    '  PasswordAuthentication yes',
    '  PermitRootLogin yes',
    '  X11Forwarding no',
    'Match Group sftponly',
    '  ForceCommand internal-sftp',
    '  AllowTcpForwarding no',
  ].join('\n'));

  // Global section is unaffected by the overrides.
  assert.equal(finding(audit, 'PasswordAuthentication').severity, 'ok');
  assert.equal(finding(audit, 'PermitRootLogin').severity, 'ok');
  assert.equal(audit.counts.critical, 0);
  assert.equal(audit.directives.length, 2);
  // AllowTcpForwarding inside a Match block does not count as a global setting.
  assert.equal(finding(audit, 'AllowTcpForwarding').current, 'not set');

  assert.equal(audit.matchBlocks.length, 2);
  assert.equal(audit.matchBlocks[0].criteria, 'User backup Address 10.0.0.0/8');
  assert.deepEqual(audit.matchBlocks[0].directives.map(item => [item.directive, item.value, item.flagged]), [
    ['PasswordAuthentication', 'yes', true],
    ['PermitRootLogin', 'yes', true],
    ['X11Forwarding', 'no', false],
  ]);
  assert.deepEqual(audit.matchBlocks[1].directives.map(item => item.flagged), [false, false]);

  const scoped = audit.findings.filter(item => item.scope);
  assert.equal(scoped.length, 2);
  for (const item of scoped) {
    assert.equal(item.severity, 'warning');
    assert.equal(item.scope, 'User backup Address 10.0.0.0/8');
    assert.match(item.why, /applies only to connections that match/);
    assert.equal(item.fix, undefined);
  }
  assert.ok(!audit.hardenedSnippet.includes('PermitRootLogin'));
});

test('Include lines are reported because included files are not seen', () => {
  const audit = auditSshdConfig('Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n');
  assert.deepEqual(audit.includes, ['/etc/ssh/sshd_config.d/*.conf']);
  const include = finding(audit, 'Include');
  assert.equal(include.severity, 'info');
  assert.equal(include.current, '/etc/ssh/sshd_config.d/*.conf');
  assert.match(include.why, /not seen/);
});

test('weak ciphers, MACs and key exchange methods are found in plain lists', () => {
  const audit = auditSshdConfig([
    'Ciphers aes256-gcm@openssh.com,aes128-cbc,3des-cbc,arcfour256,blowfish-cbc,cast128-cbc,aes256-ctr',
    'MACs hmac-sha2-512-etm@openssh.com,hmac-md5,hmac-sha1-96,umac-64@openssh.com,hmac-ripemd160,hmac-sha2-256',
    'KexAlgorithms curve25519-sha256,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256',
  ].join('\n'));

  const ciphers = finding(audit, 'Ciphers');
  assert.equal(ciphers.severity, 'warning');
  assert.equal(ciphers.title, 'Ciphers allows weak algorithms: aes128-cbc, 3des-cbc, arcfour256, blowfish-cbc, cast128-cbc');
  assert.equal(ciphers.fix, 'Ciphers aes256-gcm@openssh.com,aes256-ctr');

  const macs = finding(audit, 'MACs', 'weak');
  assert.equal(macs.severity, 'warning');
  assert.match(macs.title, /hmac-md5, hmac-sha1-96, umac-64@openssh\.com, hmac-ripemd160$/);
  assert.equal(macs.fix, 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256');
  const plain = finding(audit, 'MACs', 'without encrypt-then-MAC');
  assert.equal(plain.severity, 'info');
  assert.match(plain.title, /hmac-sha2-256$/);

  const kex = finding(audit, 'KexAlgorithms');
  assert.equal(kex.severity, 'warning');
  assert.equal(kex.fix, 'KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256');
});

test('strong algorithm lists are ok and a list of only weak entries falls back to the defaults', () => {
  const strong = auditSshdConfig('Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\nMACs hmac-sha2-512-etm@openssh.com\nKexAlgorithms curve25519-sha256\n');
  for (const directive of ['Ciphers', 'MACs', 'KexAlgorithms']) assert.equal(finding(strong, directive).severity, 'ok', directive);
  assert.ok(!strong.hardenedSnippet.includes('Ciphers'));

  const weak = auditSshdConfig('Ciphers aes128-cbc\nMACs hmac-md5\n');
  assert.match(finding(weak, 'Ciphers').fix, /^# Remove this line to use the OpenSSH defaults: Ciphers aes128-cbc$/);
  assert.match(finding(weak, 'MACs').fix, /^MACs hmac-sha2-512-etm@openssh\.com,/);
});

test('algorithm lists with +, - and ^ prefixes', () => {
  assert.deepEqual(parseAlgorithmList('+aes128-cbc,AES256-CBC'), { prefix: '+', items: ['aes128-cbc', 'aes256-cbc'] });
  assert.deepEqual(parseAlgorithmList('-*cbc'), { prefix: '-', items: ['*cbc'] });
  assert.deepEqual(parseAlgorithmList('^a,b'), { prefix: '^', items: ['a', 'b'] });
  assert.deepEqual(parseAlgorithmList('a'), { prefix: '', items: ['a'] });

  const added = auditSshdConfig('Ciphers +aes128-cbc,aes256-gcm@openssh.com\nKexAlgorithms +diffie-hellman-group1-sha1\n');
  assert.equal(finding(added, 'Ciphers').severity, 'warning');
  assert.equal(finding(added, 'Ciphers').title, 'Ciphers adds weak algorithms: aes128-cbc');
  assert.equal(finding(added, 'Ciphers').fix, 'Ciphers +aes256-gcm@openssh.com');
  assert.match(finding(added, 'KexAlgorithms').fix, /^# Remove this line/);

  // Removing weak algorithms from the defaults is good.
  const removed = auditSshdConfig('Ciphers -aes128-cbc,3des-cbc\nMACs -hmac-sha1,hmac-md5\nKexAlgorithms -diffie-hellman-group14-sha1\nHostKeyAlgorithms -ssh-rsa\n');
  for (const directive of ['Ciphers', 'MACs', 'KexAlgorithms', 'HostKeyAlgorithms']) {
    assert.equal(finding(removed, directive).severity, 'ok', directive);
    assert.match(finding(removed, directive).title, /removes algorithms/);
  }
  assert.equal(removed.findings.filter(item => ['Ciphers', 'MACs', 'KexAlgorithms', 'HostKeyAlgorithms'].includes(item.directive) && item.severity !== 'ok').length, 0);

  const preferred = auditSshdConfig('MACs ^hmac-sha1');
  assert.equal(finding(preferred, 'MACs').title, 'MACs prefers weak algorithms: hmac-sha1');
});

test('ssh-dss is critical and ssh-rsa a warning in key algorithm lists', () => {
  const audit = auditSshdConfig('HostKeyAlgorithms ssh-ed25519,ssh-rsa,ssh-dss\nPubkeyAcceptedAlgorithms +ssh-rsa\nPubkeyAcceptedKeyTypes rsa-sha2-512,ssh-ed25519\n');
  const hostKey = finding(audit, 'HostKeyAlgorithms');
  assert.equal(hostKey.severity, 'critical');
  assert.match(hostKey.title, /ssh-rsa, ssh-dss/);
  assert.equal(hostKey.fix, 'HostKeyAlgorithms ssh-ed25519');
  const pubkey = finding(audit, 'PubkeyAcceptedAlgorithms');
  assert.equal(pubkey.severity, 'warning');
  assert.match(pubkey.title, /adds weak algorithms: ssh-rsa$/);
  // rsa-sha2-512 is not ssh-rsa.
  assert.equal(finding(audit, 'PubkeyAcceptedKeyTypes').severity, 'ok');
});

test('individual checks and their severities', () => {
  const cases = [
    ['PermitEmptyPasswords yes', 'PermitEmptyPasswords', 'critical'],
    ['Protocol 2,1', 'Protocol', 'critical'],
    ['Protocol 1', 'Protocol', 'critical'],
    ['PubkeyAuthentication no', 'PubkeyAuthentication', 'warning'],
    ['X11Forwarding yes', 'X11Forwarding', 'warning'],
    ['PermitUserEnvironment yes', 'PermitUserEnvironment', 'warning'],
    ['HostbasedAuthentication yes', 'HostbasedAuthentication', 'warning'],
    ['IgnoreRhosts no', 'IgnoreRhosts', 'warning'],
    ['StrictModes no', 'StrictModes', 'warning'],
    ['GatewayPorts yes', 'GatewayPorts', 'warning'],
    ['GatewayPorts clientspecified', 'GatewayPorts', 'warning'],
    ['LogLevel QUIET', 'LogLevel', 'warning'],
    ['LogLevel INFO', 'LogLevel', 'info'],
    ['ChallengeResponseAuthentication yes', 'ChallengeResponseAuthentication', 'info'],
    ['KbdInteractiveAuthentication yes', 'KbdInteractiveAuthentication', 'info'],
    ['MaxAuthTries 5', 'MaxAuthTries', 'info'],
    ['LoginGraceTime 2m', 'LoginGraceTime', 'info'],
    ['LoginGraceTime 0', 'LoginGraceTime', 'info'],
    ['ClientAliveInterval 0', 'ClientAliveInterval', 'info'],
    ['AllowTcpForwarding yes', 'AllowTcpForwarding', 'info'],
    ['AllowAgentForwarding yes', 'AllowAgentForwarding', 'info'],
    ['PermitTunnel yes', 'PermitTunnel', 'info'],
    ['UsePAM no', 'UsePAM', 'info'],
  ];
  for (const [line, directive, severity] of cases) {
    const item = finding(auditSshdConfig(line), directive);
    assert.ok(item, line);
    assert.equal(item.severity, severity, line);
    assert.equal(item.current, line.slice(line.indexOf(' ') + 1), line);
    assert.ok(item.recommended && item.why, line);
  }

  const quiet = [
    ['Protocol 2', 'Protocol'],
    ['MaxAuthTries 4', 'MaxAuthTries'],
    ['LoginGraceTime 60', 'LoginGraceTime'],
    ['LoginGraceTime 1m', 'LoginGraceTime'],
    ['ClientAliveInterval 300', 'ClientAliveInterval'],
    ['KbdInteractiveAuthentication no', 'KbdInteractiveAuthentication'],
    ['ChallengeResponseAuthentication no', 'KbdInteractiveAuthentication'],
    ['AllowTcpForwarding no', 'AllowTcpForwarding'],
    ['AllowAgentForwarding no', 'AllowAgentForwarding'],
    ['LogLevel VERBOSE', 'LogLevel'],
    ['UsePAM yes', 'UsePAM'],
    ['X11Forwarding no', 'X11Forwarding'],
    ['AllowGroups ssh-users', 'AllowUsers'],
    ['DenyUsers guest', 'AllowUsers'],
  ];
  for (const [line, directive] of quiet) assert.equal(finding(auditSshdConfig(line), directive), undefined, line);
});

test('sshd time values', () => {
  assert.equal(parseSshdTime('120'), 120);
  assert.equal(parseSshdTime('2m'), 120);
  assert.equal(parseSshdTime('1h30m'), 5400);
  assert.equal(parseSshdTime('90S'), 90);
  assert.equal(parseSshdTime('1d'), 86400);
  assert.equal(parseSshdTime('soon'), null);
  assert.equal(parseSshdTime(''), null);
  assert.equal(parseSshdTime('5x'), null);
});

test('sshd -T output (lower-case keywords, repeated hostkey lines) is audited', () => {
  const audit = auditSshdConfig([
    'port 22',
    'addressfamily any',
    'listenaddress [::]:22',
    'listenaddress 0.0.0.0:22',
    'usepam yes',
    'logingracetime 120',
    'x11forwarding yes',
    'maxauthtries 6',
    'clientaliveinterval 0',
    'permitrootlogin without-password',
    'passwordauthentication yes',
    'kbdinteractiveauthentication no',
    'permitemptypasswords no',
    'strictmodes yes',
    'gatewayports no',
    'allowtcpforwarding yes',
    'allowagentforwarding yes',
    'loglevel INFO',
    'ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com',
    'macs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1',
    'kexalgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256',
    'hostkeyalgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256',
    'hostkey /etc/ssh/ssh_host_rsa_key',
    'hostkey /etc/ssh/ssh_host_ed25519_key',
    'subsystem sftp /usr/lib/openssh/sftp-server',
  ].join('\n'));

  assert.ok(audit.recognized >= 20);
  assert.equal(audit.counts.critical, 0);
  assert.equal(finding(audit, 'PermitRootLogin').severity, 'ok');
  assert.equal(finding(audit, 'PasswordAuthentication').severity, 'warning');
  assert.equal(finding(audit, 'PasswordAuthentication').current, 'yes');
  assert.equal(finding(audit, 'X11Forwarding').severity, 'warning');
  assert.equal(finding(audit, 'MaxAuthTries').current, '6');
  assert.equal(finding(audit, 'Ciphers').severity, 'ok');
  assert.equal(finding(audit, 'KexAlgorithms').severity, 'ok');
  assert.equal(finding(audit, 'HostKeyAlgorithms').severity, 'ok');
  assert.equal(finding(audit, 'MACs', 'weak').title, 'MACs allows weak algorithms: umac-64-etm@openssh.com, hmac-sha1-etm@openssh.com, umac-64@openssh.com, hmac-sha1');
  assert.equal(finding(audit, 'MACs', 'weak').fix, 'MACs umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512');
  assert.equal(finding(audit, 'KbdInteractiveAuthentication'), undefined);
  assert.ok(!audit.findings.some(item => item.title.includes('times')));
  assert.ok(!audit.findings.some(item => item.title.includes('is not set, default')));
});

test('the hardened snippet holds only what should change, most severe first', () => {
  const audit = auditSshdConfig('PermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding yes\nPubkeyAuthentication yes\nStrictModes yes\nMaxAuthTries 3\nLoginGraceTime 30\nClientAliveInterval 300\nLogLevel VERBOSE\nMACs hmac-sha2-512-etm@openssh.com\n');
  assert.deepEqual(snippetLines(audit), ['PermitRootLogin no', 'PasswordAuthentication no', 'X11Forwarding no']);

  const clean = auditSshdConfig('PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nMaxAuthTries 3\nLoginGraceTime 30\nClientAliveInterval 300\nLogLevel VERBOSE\nAllowGroups ssh-users\nAllowTcpForwarding no\nAllowAgentForwarding no\nCiphers aes256-gcm@openssh.com\nMACs hmac-sha2-512-etm@openssh.com\nKexAlgorithms curve25519-sha256\n');
  assert.equal(clean.hardenedSnippet, '');
  assert.equal(clean.counts.critical + clean.counts.warning + clean.counts.info, 0);
});

test('the weak sample produces findings of every severity and a full snippet', () => {
  const audit = auditSshdConfig(SSHD_SAMPLE);
  assert.ok(audit.counts.critical >= 4);
  assert.ok(audit.counts.warning >= 8);
  assert.ok(audit.counts.info >= 5);
  assert.equal(finding(audit, 'PermitRootLogin').severity, 'critical');
  assert.equal(finding(audit, 'PermitEmptyPasswords').severity, 'critical');
  assert.equal(finding(audit, 'Protocol').severity, 'critical');
  assert.equal(finding(audit, 'HostKeyAlgorithms').severity, 'critical');
  // The later "PasswordAuthentication no" is ignored.
  assert.equal(finding(audit, 'PasswordAuthentication').severity, 'warning');
  assert.ok(finding(audit, 'PasswordAuthentication', 'is set 2 times'));
  assert.equal(audit.matchBlocks.length, 2);
  assert.equal(audit.findings.filter(item => item.scope === 'User deploy').length, 1);
  assert.equal(audit.includes.length, 1);

  const lines = snippetLines(audit);
  for (const expected of [
    'PermitRootLogin no', 'PermitEmptyPasswords no', 'Protocol 2', 'PasswordAuthentication no', 'StrictModes yes', 'X11Forwarding no',
    'GatewayPorts no', 'PermitUserEnvironment no', 'MaxAuthTries 4', 'LoginGraceTime 60', 'ClientAliveInterval 300', 'LogLevel VERBOSE',
    'Ciphers aes256-ctr,aes128-ctr', 'MACs hmac-sha2-256', 'KexAlgorithms curve25519-sha256',
  ]) assert.ok(lines.includes(expected), expected);
  assert.ok(lines.some(line => line.startsWith('# Remove this line to use the OpenSSH defaults: HostKeyAlgorithms +ssh-rsa,ssh-dss')));
  assert.equal(new Set(lines).size, lines.length);
  assert.equal(lines[0], 'PermitRootLogin no');
});
