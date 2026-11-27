import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeAuthLog, buildBlockList, BLOCK_FORMATS } from '../../frontend/src/lib/tools/auth-log.ts';
import { buildAuthLogSample } from '../../frontend/src/lib/tools/auth-log-sample.ts';
import { cleanIp, createSyslogReader, createTimelineCounter, forEachLine, formatLogTime, ipVersion, isLocalAddress } from '../../frontend/src/lib/tools/syslog.ts';

// Local noon on 27 November 2026. Syslog lines without a year are dated against this.
const NOW = new Date(2026, 10, 27, 12, 0, 0);
const sshd = (message, time = '10:15:01') => `Nov 27 ${time} web01 sshd[1234]: ${message}`;
const analyze = (lines, options = {}) => analyzeAuthLog(Array.isArray(lines) ? lines.join('\n') : lines, { now: NOW, ...options });
const ipRow = (result, ip) => result.topIps.find(row => row.ip === ip);
const userRow = (result, user) => result.topUsers.find(row => row.user === user);

test('failed password lines count attempts, users and addresses', () => {
  const result = analyze([
    sshd('Failed password for root from 203.0.113.45 port 51122 ssh2'),
    sshd('Failed password for invalid user admin from 203.0.113.45 port 51123 ssh2'),
    sshd('Failed password for root from 198.51.100.23 port 40000 ssh2'),
  ]);
  assert.equal(result.totals.lines, 3);
  assert.equal(result.totals.recognized, 3);
  assert.equal(result.totals.failedAttempts, 3);
  assert.equal(result.totals.failedIps, 2);
  assert.equal(result.totals.usernamesTried, 2);
  assert.equal(result.totals.invalidUsernames, 1);
  assert.deepEqual(result.topIps.map(row => [row.ip, row.failed, row.users]), [['203.0.113.45', 2, 2], ['198.51.100.23', 1, 1]]);
  assert.deepEqual(userRow(result, 'root'), { user: 'root', failed: 2, other: 0, invalid: false });
  assert.deepEqual(userRow(result, 'admin'), { user: 'admin', failed: 1, other: 0, invalid: true });
});

test('other failed methods are counted and reported by method', () => {
  const result = analyze([
    sshd('Failed publickey for git from 203.0.113.45 port 51122 ssh2: RSA SHA256:abcDEF123'),
    sshd('Failed keyboard-interactive/pam for invalid user test from 203.0.113.45 port 51122 ssh2'),
    sshd('Failed none for invalid user guest from 203.0.113.45 port 51122 ssh2'),
    sshd('Failed password for root from 203.0.113.45 port 51122 ssh2'),
    sshd('Failed password for root from 203.0.113.45 port 51122 ssh2'),
  ]);
  assert.equal(result.totals.failedAttempts, 5);
  assert.deepEqual(result.failedByMethod[0], { method: 'password', count: 2 });
  assert.deepEqual(result.failedByMethod.map(item => item.method).sort(), ['keyboard-interactive/pam', 'none', 'password', 'publickey']);
});

test('accepted logins are listed newest first with user, address and method', () => {
  const result = analyze([
    sshd('Accepted password for deploy from 192.0.2.77 port 44391 ssh2', '08:00:00'),
    sshd('Accepted publickey for alice from 198.51.100.200 port 50222 ssh2: ED25519 SHA256:3fPq8nB2xk0V', '09:00:00'),
    sshd('Accepted keyboard-interactive/pam for bob from 2001:db8::10 port 50223 ssh2', '09:30:00'),
    sshd('Accepted gssapi-with-mic for carol from 192.0.2.78 port 50224 ssh2', '10:00:00'),
  ]);
  assert.equal(result.totals.acceptedLogins, 4);
  assert.equal(result.acceptedTotal, 4);
  assert.deepEqual(result.accepted.map(row => [formatLogTime(row.ts), row.user, row.ip, row.method]), [
    ['2026-11-27 10:00:00', 'carol', '192.0.2.78', 'gssapi-with-mic'],
    ['2026-11-27 09:30:00', 'bob', '2001:db8::10', 'keyboard-interactive/pam'],
    ['2026-11-27 09:00:00', 'alice', '198.51.100.200', 'publickey'],
    ['2026-11-27 08:00:00', 'deploy', '192.0.2.77', 'password'],
  ]);
  assert.equal(result.totals.failedAttempts, 0);
  assert.equal(result.ipTotal, 0, 'addresses that only logged in are not listed as sources of failures');
});

test('the accepted list is capped and keeps the total', () => {
  const lines = [];
  for (let index = 0; index < 300; index += 1) {
    const minute = String(Math.floor(index / 60)).padStart(2, '0');
    const second = String(index % 60).padStart(2, '0');
    lines.push(sshd(`Accepted publickey for user${index} from 198.51.100.200 port 50222 ssh2`, `10:${minute}:${second}`));
  }
  const result = analyze(lines);
  assert.equal(result.acceptedTotal, 300);
  assert.equal(result.accepted.length, 25);
  assert.equal(result.accepted[0].user, 'user299');
  assert.equal(result.accepted[24].user, 'user275');
});

test('invalid user and pam_unix lines add users and addresses but are not counted as attempts', () => {
  const result = analyze([
    sshd('Invalid user admin from 203.0.113.45 port 51122'),
    sshd('pam_unix(sshd:auth): check pass; user unknown'),
    sshd('pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.45'),
    sshd('Failed password for invalid user admin from 203.0.113.45 port 51122 ssh2'),
    sshd('Connection closed by invalid user admin 203.0.113.45 port 51122 [preauth]'),
  ]);
  assert.equal(result.totals.failedAttempts, 1, 'five lines describe one attempt');
  assert.equal(result.totals.recognized, 4);
  assert.equal(result.totals.usernamesTried, 1);
  assert.equal(result.totals.invalidUsernames, 1);
  assert.equal(result.totals.preauthDisconnects, 1);
  assert.deepEqual(ipRow(result, '203.0.113.45'), {
    ip: '203.0.113.45', version: 4, failed: 1, other: 1, users: 1,
    firstSeen: Date.UTC(2026, 10, 27, 10, 15, 1), lastSeen: Date.UTC(2026, 10, 27, 10, 15, 1), accepted: false,
  });
});

test('lines without a failed attempt still record the user and the address', () => {
  const result = analyze([
    sshd('Invalid user oracle from 203.0.113.50'),
    sshd('Invalid user  from 203.0.113.51 port 4000'),
    sshd('pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.52  user=root'),
  ]);
  assert.equal(result.totals.failedAttempts, 0);
  assert.equal(result.totals.failedIps, 0);
  assert.equal(result.totals.usernamesTried, 3);
  assert.equal(result.totals.invalidUsernames, 2);
  assert.ok(userRow(result, 'oracle').invalid);
  assert.ok(userRow(result, '(empty)').invalid);
  assert.equal(userRow(result, 'root').invalid, false);
  assert.deepEqual(result.offenders, []);
});

test('connections closed before login are other events, with the kind of user', () => {
  const result = analyze([
    sshd('Connection closed by authenticating user root 203.0.113.45 port 51122 [preauth]'),
    sshd('Connection closed by invalid user admin 203.0.113.45 port 51123 [preauth]'),
    sshd('Disconnected from authenticating user root 203.0.113.46 port 51124 [preauth]'),
    sshd('Disconnected from invalid user pi 203.0.113.46 port 51125 [preauth]'),
    sshd('Connection reset by authenticating user root 203.0.113.46 port 51126 [preauth]'),
  ]);
  assert.equal(result.totals.recognized, 5);
  assert.equal(result.totals.failedAttempts, 0);
  assert.equal(result.totals.preauthDisconnects, 5);
  assert.equal(ipRow(result, '203.0.113.45').other, 2);
  assert.equal(ipRow(result, '203.0.113.46').other, 3);
  assert.deepEqual(userRow(result, 'root'), { user: 'root', failed: 0, other: 3, invalid: false });
  assert.ok(userRow(result, 'admin').invalid);
  assert.ok(userRow(result, 'pi').invalid);
});

test('maximum authentication attempts lines are recognized without adding attempts', () => {
  const result = analyze([
    sshd('Failed password for root from 203.0.113.45 port 51122 ssh2'),
    sshd('error: maximum authentication attempts exceeded for root from 203.0.113.45 port 51122 ssh2 [preauth]'),
    sshd('error: maximum authentication attempts exceeded for invalid user admin from 203.0.113.45 port 51123 ssh2 [preauth]'),
  ]);
  assert.equal(result.totals.recognized, 3);
  assert.equal(result.totals.failedAttempts, 1);
  assert.equal(ipRow(result, '203.0.113.45').other, 2);
  assert.ok(userRow(result, 'admin').invalid);
});

test('scanner probes are counted per address', () => {
  const result = analyze([
    sshd('Did not receive identification string from 192.0.2.150 port 40112'),
    sshd('Did not receive identification string from 192.0.2.150'),
    sshd('Unable to negotiate with 203.0.113.99 port 33812: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1 [preauth]'),
    sshd('Unable to negotiate with 203.0.113.99 port 33813: no matching host key type found. Their offer: ssh-dss [preauth]'),
    sshd('banner exchange: Connection from 192.0.2.151 port 51000: invalid format'),
    sshd("Bad protocol version identification 'GET / HTTP/1.1' from 192.0.2.152 port 51001"),
  ]);
  assert.equal(result.totals.scannerProbes, 6);
  assert.equal(result.totals.recognized, 6);
  assert.equal(result.totals.failedAttempts, 0);
  assert.equal(ipRow(result, '192.0.2.150').other, 2);
  assert.equal(ipRow(result, '203.0.113.99').other, 2);
  assert.equal(ipRow(result, '192.0.2.151').other, 1);
  assert.equal(ipRow(result, '192.0.2.152').other, 1);
});

test('message repeated N times counts N attempts', () => {
  const result = analyze([
    sshd('Failed password for root from 198.51.100.23 port 51820 ssh2'),
    sshd('message repeated 2 times: [ Failed password for root from 198.51.100.23 port 51820 ssh2]'),
    sshd('message repeated 5 times: [ Failed password for invalid user admin from 198.51.100.24 port 51821 ssh2]'),
    sshd('message repeated 3 times: [ Connection closed by authenticating user root 198.51.100.23 port 51822 [preauth]]'),
  ]);
  assert.equal(result.totals.recognized, 4);
  assert.equal(result.totals.failedAttempts, 8);
  assert.equal(ipRow(result, '198.51.100.23').failed, 3);
  assert.equal(ipRow(result, '198.51.100.23').other, 3);
  assert.equal(ipRow(result, '198.51.100.24').failed, 5);
  assert.equal(userRow(result, 'admin').failed, 5);
  assert.equal(result.timeline.buckets[0].counts[0], 8);
});

test('sudo commands, failures and NOT in sudoers are summarized per user', () => {
  const sudo = message => `Nov 27 09:06:11 web01 sudo: ${message}`;
  const result = analyze([
    sudo('   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl status nginx'),
    sudo('   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update'),
    sudo('pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)'),
    sudo('pam_unix(sudo:auth): authentication failure; logname=bob uid=1002 euid=0 tty=/dev/pts/2 ruser=bob rhost=  user=bob'),
    sudo('     bob : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/su'),
    sudo('  deploy : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash'),
    sudo('   carol : command not allowed ; TTY=pts/3 ; PWD=/home/carol ; USER=root ; COMMAND=/bin/cat /etc/shadow'),
  ]);
  assert.equal(result.totals.recognized, 6, 'the session line is not counted');
  assert.equal(result.sudo.commands, 2);
  assert.equal(result.sudo.authFailures, 1);
  assert.equal(result.sudo.incorrectPasswordAttempts, 3);
  assert.equal(result.sudo.notInSudoers, 1);
  assert.equal(result.sudo.denied, 1);
  assert.equal(result.sudo.userTotal, 4);
  assert.deepEqual(result.sudo.users[0], { user: 'alice', commands: 2, authFailures: 0, notInSudoers: 0, lastCommand: '/usr/bin/apt update' });
  assert.equal(result.sudo.users.find(row => row.user === 'bob').authFailures, 1);
  assert.equal(result.sudo.users.find(row => row.user === 'deploy').notInSudoers, 1);
  const finding = result.findings.find(item => item.title.includes('not in sudoers'));
  assert.equal(finding.severity, 'warning');
  assert.ok(finding.detail.includes('deploy'));
});

test('an accepted login from an address with five or more failures is critical', () => {
  const lines = [];
  for (let index = 0; index < 5; index += 1) lines.push(sshd('Failed password for deploy from 192.0.2.77 port 44310 ssh2'));
  lines.push(sshd('Accepted password for deploy from 192.0.2.77 port 44391 ssh2'));
  const result = analyze(lines);
  const critical = result.findings.filter(item => item.severity === 'critical');
  assert.equal(critical.length, 1);
  assert.ok(critical[0].title.includes('192.0.2.77'));
  assert.ok(critical[0].detail.includes('deploy'));
  assert.equal(result.findings[0].severity, 'critical', 'most severe first');
  assert.equal(ipRow(result, '192.0.2.77').accepted, true);

  const fewer = analyze(lines.slice(1));
  assert.equal(fewer.findings.filter(item => item.severity === 'critical').length, 0, 'four failures are a typo, not a finding');
});

test('root logins, password logins and many failures are reported', () => {
  const lines = [
    sshd('Accepted publickey for root from 192.0.2.10 port 61022 ssh2: RSA SHA256:Zk1vQ0h2'),
    sshd('Accepted password for alice from 198.51.100.200 port 50222 ssh2'),
  ];
  for (let index = 0; index < 60; index += 1) lines.push(sshd(`Failed password for root from 203.0.113.${index % 3} port 4000 ssh2`));
  const result = analyze(lines);
  const titles = result.findings.map(item => `${item.severity}: ${item.title}`);
  assert.ok(titles.includes('warning: 1 accepted root login'));
  assert.ok(titles.includes('warning: 1 login accepted with a password'));
  assert.ok(titles.includes('info: 60 failed login attempts from 3 addresses'));
  assert.ok(result.findings.find(item => item.title.includes('password')).detail.includes('SSH keys'));

  const quiet = analyze(lines, { bruteForceNote: 60 });
  assert.ok(!quiet.findings.some(item => item.severity === 'info'));
});

test('a clean log and an unrecognized log get their own finding', () => {
  const clean = analyze([sshd('Accepted publickey for alice from 198.51.100.200 port 50222 ssh2')]);
  assert.deepEqual(clean.findings, [{ severity: 'ok', title: 'Nothing stands out in this log' }]);
  const other = analyze(['Nov 27 10:00:00 web01 CRON[99]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)']);
  assert.equal(other.totals.recognized, 0);
  assert.equal(other.findings[0].title, 'No sshd or sudo lines were recognized');
});

test('key-only servers get a note about connections closed before login', () => {
  const lines = [];
  for (let index = 0; index < 20; index += 1) {
    lines.push(sshd(`Invalid user u${index} from 203.0.113.45 port 4000`));
    lines.push(sshd(`Connection closed by invalid user u${index} 203.0.113.45 port 4000 [preauth]`));
  }
  const result = analyze(lines);
  assert.equal(result.totals.failedAttempts, 0);
  assert.equal(result.totals.preauthDisconnects, 20);
  assert.equal(result.findings[0].title, '20 connections were closed before login');
  assert.equal(result.topIps[0].other, 20);
  assert.equal(result.topIps[0].users, 20);
});

test('block list respects the threshold and never lists an address that logged in', () => {
  const lines = [];
  const fail = (ip, times) => { for (let index = 0; index < times; index += 1) lines.push(sshd(`Failed password for root from ${ip} port 4000 ssh2`)); };
  fail('203.0.113.45', 12);
  fail('198.51.100.23', 5);
  fail('203.0.113.61', 4);
  fail('192.0.2.77', 9);
  fail('2001:db8:5a::c4', 6);
  fail('10.0.0.8', 7);
  fail('127.0.0.1', 7);
  lines.push(sshd('Accepted password for deploy from 192.0.2.77 port 44391 ssh2'));
  const result = analyze(lines);

  const list = buildBlockList(result.offenders);
  assert.equal(list.threshold, 5);
  assert.deepEqual(list.ips, ['203.0.113.45', '2001:db8:5a::c4', '198.51.100.23']);
  assert.equal(list.text, '203.0.113.45\n2001:db8:5a::c4\n198.51.100.23');
  assert.deepEqual(list.review, [
    { ip: '192.0.2.77', failed: 9, reason: 'accepted login' },
    { ip: '10.0.0.8', failed: 7, reason: 'private or loopback address' },
    { ip: '127.0.0.1', failed: 7, reason: 'private or loopback address' },
  ]);

  assert.deepEqual(buildBlockList(result.offenders, { threshold: 4 }).ips, ['203.0.113.45', '2001:db8:5a::c4', '198.51.100.23', '203.0.113.61']);
  assert.deepEqual(buildBlockList(result.offenders, { threshold: 10 }).ips, ['203.0.113.45']);
  assert.deepEqual(buildBlockList(result.offenders, { threshold: 10 }).review, []);
  assert.deepEqual(buildBlockList(result.offenders, { threshold: 13 }).ips, []);
  assert.equal(buildBlockList(result.offenders, { threshold: 13 }).text, '');
  assert.equal(buildBlockList(result.offenders, { threshold: 'abc' }).threshold, 5);
  assert.equal(buildBlockList(result.offenders, { threshold: 0 }).threshold, 5);

  for (const { key } of BLOCK_FORMATS) {
    const text = buildBlockList(result.offenders, { format: key }).text;
    assert.ok(!text.includes('192.0.2.77'), `${key} must not block an address that logged in`);
    assert.ok(!text.includes('127.0.0.1') && !text.includes('10.0.0.8'), `${key} must not block local addresses`);
    assert.ok(!text.includes('203.0.113.61'), `${key} must respect the threshold`);
  }
});

test('block list formats', () => {
  const offenders = [
    { ip: '203.0.113.45', failed: 12, accepted: false },
    { ip: '2001:db8:5a::c4', failed: 6, accepted: false },
  ];
  const commands = format => buildBlockList(offenders, { format }).text.split('\n').filter(line => !line.startsWith('#'));
  assert.deepEqual(commands('plain'), ['203.0.113.45', '2001:db8:5a::c4']);
  assert.deepEqual(commands('ufw'), ['ufw deny from 203.0.113.45', 'ufw deny from 2001:db8:5a::c4']);
  assert.deepEqual(commands('iptables'), ['iptables -A INPUT -s 203.0.113.45 -j DROP', 'ip6tables -A INPUT -s 2001:db8:5a::c4 -j DROP']);
  assert.deepEqual(commands('fail2ban'), ['fail2ban-client set sshd banip 203.0.113.45', 'fail2ban-client set sshd banip 2001:db8:5a::c4']);
  assert.deepEqual(commands('hosts-deny'), ['sshd: 203.0.113.45', 'sshd: [2001:db8:5a::c4]']);
  assert.deepEqual(commands('nftables'), [
    'set ssh_block_v4 {', '    type ipv4_addr', '    elements = { 203.0.113.45 }', '}',
    'set ssh_block_v6 {', '    type ipv6_addr', '    elements = { 2001:db8:5a::c4 }', '}',
  ]);
  assert.equal(buildBlockList(offenders, { format: 'nope' }).text, '203.0.113.45\n2001:db8:5a::c4');
  const onlyV4 = buildBlockList(offenders.slice(0, 1), { format: 'nftables' }).text;
  assert.ok(!onlyV4.includes('ipv6_addr') && !onlyV4.includes('ip6 saddr'));
});

test('only validated addresses can reach the block list', () => {
  const hostile = [
    { ip: '203.0.113.45; rm -rf /', failed: 99, accepted: false },
    { ip: '$(reboot)', failed: 99, accepted: false },
    { ip: 'evil.example.com', failed: 99, accepted: false },
    { ip: '203.0.113.45/8', failed: 99, accepted: false },
    { ip: '999.1.1.1', failed: 99, accepted: false },
    { ip: '203.0.113.9', failed: 99, accepted: false },
    { ip: '203.0.113.9', failed: 50, accepted: false },
    null,
  ];
  for (const { key } of BLOCK_FORMATS) {
    const list = buildBlockList(hostile, { format: key });
    assert.deepEqual(list.ips, ['203.0.113.9']);
    assert.ok(!/rm -rf|reboot|evil|999/.test(list.text));
  }
  assert.deepEqual(buildBlockList(undefined).ips, []);

  // A user name chosen by the attacker cannot move the address: the real one is at the end of the line.
  const lines = [];
  for (let index = 0; index < 6; index += 1) lines.push(sshd('Failed password for invalid user x from 192.0.2.1 port 22 ssh2 from 203.0.113.45 port 51122 ssh2'));
  // With UseDNS a host name can appear in place of the address. It is counted but never listed.
  for (let index = 0; index < 6; index += 1) lines.push(sshd('Failed password for root from evil.example.com port 51122 ssh2'));
  const result = analyze(lines);
  assert.equal(result.totals.failedAttempts, 12);
  assert.deepEqual(result.offenders, [{ ip: '203.0.113.45', failed: 6, accepted: false }]);
  assert.deepEqual(buildBlockList(result.offenders).ips, ['203.0.113.45']);
});

test('IPv6 sources are tracked, validated and normalized', () => {
  const result = analyze([
    sshd('Failed password for root from 2001:DB8:5a::C4 port 38800 ssh2'),
    sshd('Failed password for root from 2001:db8:5a::c4 port 38801 ssh2'),
    sshd('Invalid user admin from fe80::1%eth0 port 38802'),
    sshd('Accepted publickey for alice from ::ffff:198.51.100.200 port 50222 ssh2'),
  ]);
  assert.deepEqual(ipRow(result, '2001:db8:5a::c4').failed, 2);
  assert.equal(ipRow(result, '2001:db8:5a::c4').version, 6);
  assert.equal(result.totals.failedIps, 1);
  assert.equal(result.accepted[0].ip, '::ffff:198.51.100.200');

  assert.equal(ipVersion('192.0.2.1'), 4);
  assert.equal(ipVersion('2001:db8::1'), 6);
  assert.equal(ipVersion('::1'), 6);
  assert.equal(ipVersion('::'), 6);
  assert.equal(ipVersion('2001:db8:0:0:0:0:0:1'), 6);
  assert.equal(ipVersion('::ffff:192.0.2.1'), 6);
  for (const bad of ['', '1.2.3', '1.2.3.4.5', '256.1.1.1', '01.2.3.4', '1.2.3.4 ', '2001:db8::1::2', '2001:db8', ':::', '1:2:3:4:5:6:7:8:9', '2001:db8::g', '12345::1', 'example.com', '1.2.3.4/24', '::ffff:999.1.1.1']) {
    assert.equal(ipVersion(bad), 0, `${bad} is not an address`);
  }
  assert.equal(cleanIp('FE80::1%eth0'), 'fe80::1');
  assert.equal(cleanIp('host.example'), '');
  assert.ok(isLocalAddress('127.0.0.1') && isLocalAddress('10.1.2.3') && isLocalAddress('192.168.1.1') && isLocalAddress('172.20.0.1') && isLocalAddress('::1') && isLocalAddress('fe80::1') && isLocalAddress('fd00::1') && isLocalAddress('::ffff:10.0.0.1'));
  assert.ok(!isLocalAddress('203.0.113.45') && !isLocalAddress('172.32.0.1') && !isLocalAddress('2001:db8::1'));
});

test('traditional syslog timestamps get the current year, or the previous one when that would be in the future', () => {
  const result = analyze([
    'Dec 30 23:59:59 web01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2',
    'Jan  5 03:04:05 web01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2',
    'Nov 27 10:15:01 web01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2',
  ]);
  assert.equal(result.totals.failedAttempts, 3);
  assert.equal(formatLogTime(result.firstSeen), '2025-12-30 23:59:59');
  assert.equal(formatLogTime(result.lastSeen), '2026-11-27 10:15:01');
  assert.equal(formatLogTime(ipRow(result, '203.0.113.45').firstSeen), '2025-12-30 23:59:59');

  const reader = createSyslogReader(NOW);
  assert.equal(formatLogTime(reader.parse('Jan  5 03:04:05 web01 sshd[1]: x').ts), '2026-01-05 03:04:05');
  assert.equal(formatLogTime(reader.parse('Feb 29 01:00:00 web01 sshd[1]: x').ts), '2024-02-29 01:00:00');
  assert.equal(formatLogTime(reader.parse('Nov 27 10:15:01.123456 web01 sshd[1]: x').ts), '2026-11-27 10:15:01');
  assert.deepEqual(reader.parse('Nov 27 10:15:01 web01 sshd[1234]: Failed password'), { ts: Date.UTC(2026, 10, 27, 10, 15, 1), host: 'web01', program: 'sshd', message: 'Failed password' });
  assert.equal(reader.parse('Nov 27 10:15:01 web01 sudo:    alice : TTY=pts/0').program, 'sudo');
  assert.ok(Number.isNaN(reader.parse('Foo 27 10:15:01 web01 sshd[1]: x').ts));
  assert.ok(Number.isNaN(reader.parse('Nov 27 25:15:01 web01 sshd[1]: x').ts));
});

test('ISO 8601 timestamps from rsyslog and journalctl are read as written', () => {
  const result = analyze([
    '2026-11-27T10:15:01.123456+00:00 web01 sshd[1234]: Failed password for root from 203.0.113.45 port 51122 ssh2',
    '2026-11-27T11:20:02+0100 web01 sshd[1235]: Accepted publickey for alice from 198.51.100.200 port 50222 ssh2: ED25519 SHA256:abc',
    '2026-11-27T12:30:03Z web01 sshd-session[1236]: Failed password for root from 203.0.113.45 port 51123 ssh2',
  ]);
  assert.equal(result.totals.recognized, 3);
  assert.equal(result.totals.failedAttempts, 2, 'sshd-session lines (OpenSSH 9.8 and later) are read too');
  assert.equal(formatLogTime(result.firstSeen), '2026-11-27 10:15:01');
  assert.equal(formatLogTime(result.accepted[0].ts), '2026-11-27 11:20:02');
  assert.equal(formatLogTime(result.lastSeen), '2026-11-27 12:30:03');
  assert.deepEqual(result.timeline.buckets.map(bucket => [bucket.label, bucket.counts]), [
    ['2026-11-27 10:00', [1, 0]],
    ['2026-11-27 11:00', [0, 1]],
    ['2026-11-27 12:00', [1, 0]],
  ]);
});

test('lines without a syslog header are still matched, without a time', () => {
  const result = analyze([
    'Failed password for root from 203.0.113.45 port 51122 ssh2',
    'Accepted publickey for alice from 198.51.100.200 port 50222 ssh2',
  ]);
  assert.equal(result.totals.failedAttempts, 1);
  assert.equal(result.totals.acceptedLogins, 1);
  assert.equal(result.firstSeen, null);
  assert.equal(result.accepted[0].ts, null);
  assert.equal(ipRow(result, '203.0.113.45').firstSeen, null);
  assert.deepEqual(result.timeline.buckets, []);
});

test('the timeline is hourly with gaps filled, and daily for long logs', () => {
  const hourly = analyze([
    sshd('Failed password for root from 203.0.113.45 port 1 ssh2', '01:10:00'),
    sshd('Failed password for root from 203.0.113.45 port 1 ssh2', '01:50:00'),
    sshd('Accepted publickey for alice from 198.51.100.200 port 2 ssh2', '04:00:00'),
  ]).timeline;
  assert.equal(hourly.unit, 'hour');
  assert.equal(hourly.max, 2);
  assert.deepEqual(hourly.buckets.map(bucket => bucket.counts), [[2, 0], [0, 0], [0, 0], [0, 1]]);

  const counter = createTimelineCounter(1);
  counter.add(Date.UTC(2026, 0, 1, 5), 0);
  counter.add(Date.UTC(2026, 0, 1, 9), 0);
  counter.add(Date.UTC(2026, 1, 20, 9), 0, 4);
  counter.add(NaN, 0);
  const daily = counter.build();
  assert.equal(daily.unit, 'day');
  assert.equal(daily.buckets.length, 51);
  assert.deepEqual([daily.buckets[0].label, daily.buckets[0].counts], ['2026-01-01', [2]]);
  assert.deepEqual([daily.buckets[50].label, daily.buckets[50].counts], ['2026-02-20', [4]]);
  assert.equal(daily.truncated, false);
  assert.equal(counter.build(336, 10).buckets.length, 10);
  assert.equal(counter.build(336, 10).truncated, true);
});

test('other programs and near misses are not recognized', () => {
  const result = analyze([
    'Nov 27 10:00:00 web01 su[77]: Failed password for root from 203.0.113.45 port 1 ssh2',
    'Nov 27 10:00:00 web01 vsftpd[78]: Invalid user admin from 203.0.113.45',
    sshd('Failed password for root'),
    sshd('Accepted password for root from 203.0.113.45'),
    sshd('pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)'),
    sshd('Received disconnect from 203.0.113.45 port 51122:11: Bye Bye [preauth]'),
    sshd('Server listening on 0.0.0.0 port 22.'),
  ]);
  assert.equal(result.totals.lines, 7);
  assert.equal(result.totals.recognized, 0);
  assert.equal(result.totals.failedAttempts, 0);
});

test('garbage and empty input do not throw', () => {
  for (const input of ['', '\n\n\r\n', '   ', undefined, null, 42, {}, '\u0000\u0001\u0002', ':::::', 'Nov 27', 'Nov 27 10:15:01', 'Nov 27 10:15:01 web01', 'Nov 27 10:15:01 web01 sshd[1]:', 'Failed  for  from  port ', 'message repeated 99999999999999999999 times: [ Failed password for root from 203.0.113.45 port 1 ssh2]', 'sudo:', 'Nov 27 10:15:01 web01 sudo:  : ', '🙂'.repeat(5000), 'a'.repeat(100000), `${'Failed password for '.repeat(400)}x`]) {
    const result = analyzeAuthLog(input, { now: NOW });
    assert.ok(result.totals.lines >= 0);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(buildBlockList(result.offenders).ips));
  }
  assert.equal(analyzeAuthLog('').totals.lines, 0);
  assert.deepEqual(analyzeAuthLog('').findings, []);
  assert.equal(analyzeAuthLog('a\r\nb\n\nc').totals.lines, 3);
  assert.equal(forEachLine('x'.repeat(10000), line => assert.equal(line.length, 4096)), 1);
  assert.doesNotThrow(() => analyzeAuthLog('Nov 27 10:15:01 web01 sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2', { now: 'not a date' }));
});

test('the sample log shows every kind of finding', () => {
  const sample = buildAuthLogSample();
  assert.equal(sample, buildAuthLogSample(), 'the sample is the same every time');
  const result = analyze(sample);
  assert.ok(result.totals.recognized > 100);
  assert.ok(result.totals.failedAttempts > 50);
  assert.ok(result.totals.scannerProbes > 0);
  const severities = result.findings.map(item => item.severity);
  assert.ok(severities.includes('critical') && severities.includes('warning') && severities.includes('info'));
  assert.ok(result.findings[0].title.includes('192.0.2.77'));
  const list = buildBlockList(result.offenders);
  assert.ok(list.ips.includes('2001:db8:5a::c4'));
  assert.ok(!list.ips.includes('192.0.2.77'));
  assert.deepEqual(list.review.map(item => item.ip), ['192.0.2.77']);
  assert.ok(result.sudo.commands > 0 && result.sudo.notInSudoers === 1);
});

test('200,000 lines are analyzed in a few seconds', () => {
  const users = ['root', 'admin', 'test', 'oracle', 'ubuntu', 'postgres', 'git', 'pi', 'deploy', 'www-data'];
  const lines = [];
  let expectedFailed = 0;
  let expectedAccepted = 0;
  for (let index = 0; index < 200000; index += 1) {
    const hour = String(Math.floor(index / 8400) % 24).padStart(2, '0');
    const minute = String(Math.floor(index / 140) % 60).padStart(2, '0');
    const second = String(index % 60).padStart(2, '0');
    const head = `Nov 26 ${hour}:${minute}:${second} web01 sshd[${1000 + (index % 30000)}]: `;
    const ip = index % 7 === 0 ? `2001:db8:${(index % 900).toString(16)}::${(index % 50).toString(16)}` : `203.${index % 200}.${(index >> 3) % 250}.${(index * 7) % 250}`;
    const user = users[index % users.length] + (index % 13 === 0 ? index % 5000 : '');
    switch (index % 6) {
      case 0:
      case 1:
        lines.push(`${head}Failed password for ${index % 4 === 0 ? 'invalid user ' : ''}${user} from ${ip} port ${1024 + (index % 60000)} ssh2`);
        expectedFailed += 1;
        break;
      case 2:
        lines.push(`${head}Invalid user ${user} from ${ip} port ${1024 + (index % 60000)}`);
        break;
      case 3:
        lines.push(`${head}Connection closed by authenticating user ${user} ${ip} port ${1024 + (index % 60000)} [preauth]`);
        break;
      case 4:
        if (index % 100 === 4) {
          lines.push(`${head}Accepted publickey for alice from 198.51.100.200 port 50222 ssh2: ED25519 SHA256:abcdef`);
          expectedAccepted += 1;
        } else {
          lines.push(`${head}pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=${ip}  user=root`);
        }
        break;
      default:
        lines.push(`Nov 26 ${hour}:${minute}:${second} web01 kernel: [${index}.123456] audit: type=1400 apparmor="DENIED" operation="open" from nowhere port ${index}`);
    }
  }
  const text = lines.join('\n');
  const started = performance.now();
  const result = analyzeAuthLog(text, { now: NOW });
  const elapsed = performance.now() - started;

  assert.equal(result.totals.lines, 200000);
  assert.equal(result.totals.failedAttempts, expectedFailed);
  assert.equal(result.totals.acceptedLogins, expectedAccepted);
  assert.equal(result.topIps.length, 25);
  assert.equal(result.topUsers.length, 25);
  assert.equal(result.accepted.length, 25);
  assert.ok(result.ipTotal > 1000);
  assert.ok(result.timeline.buckets.length <= 336);
  const list = buildBlockList(result.offenders, { threshold: 2, format: 'nftables' });
  assert.ok(list.ips.every(ip => ipVersion(ip) !== 0));
  assert.ok(elapsed < 5000, `took ${Math.round(elapsed)} ms`);
});
