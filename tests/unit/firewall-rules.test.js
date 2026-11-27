import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFirewallRules, FIREWALL_DEFAULTS } from '../../frontend/src/lib/tools/firewall-rules.ts';

const base = { ...FIREWALL_DEFAULTS, action: 'allow', direction: 'in', protocol: 'tcp', ports: '22', source: '203.0.113.0/24', iface: '', comment: 'office ssh' };
const build = overrides => buildFirewallRules({ ...base, ...overrides });
const commands = (overrides, key) => {
  const result = build(overrides);
  assert.deepEqual(result.errors, []);
  return result.outputs.find(output => output.key === key).commands;
};

test('every tool gets an output with a persistence note', () => {
  const result = build({});
  assert.deepEqual(result.outputs.map(output => output.key), ['ufw', 'firewalld', 'nftables', 'iptables', 'powershell', 'netsh']);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.warnings, []);
  for (const output of result.outputs) assert.ok(output.persistence.length > 10, output.key);
});

test('ufw', () => {
  assert.deepEqual(commands({}, 'ufw'), ["sudo ufw allow from 203.0.113.0/24 to any port 22 proto tcp comment 'office ssh'"]);
  assert.deepEqual(commands({ source: '', comment: '' }, 'ufw'), ['sudo ufw allow to any port 22 proto tcp']);
  assert.deepEqual(commands({ iface: 'eth0', comment: '' }, 'ufw'), ['sudo ufw allow in on eth0 from 203.0.113.0/24 to any port 22 proto tcp']);
  assert.deepEqual(commands({ direction: 'out', protocol: 'udp', ports: '53', source: '9.9.9.9', comment: '' }, 'ufw'), ['sudo ufw allow out to 9.9.9.9 port 53 proto udp']);
  assert.deepEqual(commands({ direction: 'out', action: 'deny', ports: '25', source: '', iface: 'eth0', comment: '' }, 'ufw'), ['sudo ufw deny out on eth0 to any port 25 proto tcp']);
  assert.deepEqual(commands({ action: 'deny', protocol: 'any', ports: '', source: '198.51.100.23', comment: '' }, 'ufw'), ['sudo ufw deny from 198.51.100.23']);
  assert.deepEqual(commands({ action: 'reject', protocol: 'any', ports: '', source: '', comment: '' }, 'ufw'), ['sudo ufw reject from any']);
  assert.ok(build({}).outputs[0].persistence.includes('ufw saves rules itself'));
});

test('firewalld', () => {
  assert.deepEqual(commands({}, 'firewalld'), [
    `sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="203.0.113.0/24" port port="22" protocol="tcp" accept'`,
    'sudo firewall-cmd --reload',
  ]);
  assert.deepEqual(commands({ source: '', ports: '80,443,8000-8100' }, 'firewalld'), [
    'sudo firewall-cmd --permanent --add-port=80/tcp',
    'sudo firewall-cmd --permanent --add-port=443/tcp',
    'sudo firewall-cmd --permanent --add-port=8000-8100/tcp',
    'sudo firewall-cmd --reload',
  ]);
  assert.deepEqual(commands({ action: 'deny', source: '', ports: '23' }, 'firewalld')[0], `sudo firewall-cmd --permanent --add-rich-rule='rule port port="23" protocol="tcp" drop'`);
  assert.deepEqual(commands({ action: 'reject', ports: '8000-8100' }, 'firewalld')[0], `sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="203.0.113.0/24" port port="8000-8100" protocol="tcp" reject'`);
  assert.deepEqual(commands({ action: 'deny', protocol: 'any', ports: '', source: '198.51.100.23' }, 'firewalld')[0], `sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="198.51.100.23" drop'`);

  const outbound = build({ direction: 'out' }).outputs.find(output => output.key === 'firewalld');
  assert.deepEqual(outbound.commands, []);
  assert.ok(outbound.notes[0].includes('Outbound filtering needs a policy or direct rules'));
  const everything = build({ action: 'deny', protocol: 'any', ports: '', source: '' }).outputs.find(output => output.key === 'firewalld');
  assert.deepEqual(everything.commands, []);
  assert.ok(build({ iface: 'eth0' }).outputs[1].notes.some(note => note.includes('--get-zone-of-interface=eth0')));
});

test('nftables', () => {
  assert.deepEqual(commands({ comment: '' }, 'nftables'), ['sudo nft add rule inet filter input ip saddr 203.0.113.0/24 tcp dport 22 accept']);
  assert.deepEqual(commands({}, 'nftables'), [`sudo nft 'add rule inet filter input ip saddr 203.0.113.0/24 tcp dport 22 accept comment "office ssh"'`]);
  assert.deepEqual(commands({ source: '', ports: '80,443,8000-8100', comment: '' }, 'nftables'), ["sudo nft 'add rule inet filter input tcp dport { 80, 443, 8000-8100 } accept'"]);
  assert.deepEqual(commands({ action: 'deny', iface: 'eth0', comment: '' }, 'nftables'), [`sudo nft 'add rule inet filter input iifname "eth0" ip saddr 203.0.113.0/24 tcp dport 22 drop'`]);
  assert.deepEqual(commands({ action: 'reject', protocol: 'udp', ports: '8000-8100', source: '', comment: '' }, 'nftables'), ['sudo nft add rule inet filter input udp dport 8000-8100 reject']);
  assert.deepEqual(commands({ direction: 'out', iface: 'eth0', ports: '443', source: '198.51.100.7', comment: '' }, 'nftables'), [`sudo nft 'add rule inet filter output oifname "eth0" ip daddr 198.51.100.7 tcp dport 443 accept'`]);
  assert.deepEqual(commands({ protocol: 'tcp', ports: '', comment: '' }, 'nftables'), ['sudo nft add rule inet filter input ip saddr 203.0.113.0/24 meta l4proto tcp accept']);
  assert.deepEqual(commands({ action: 'deny', protocol: 'any', ports: '', source: '198.51.100.23', comment: '' }, 'nftables'), ['sudo nft add rule inet filter input ip saddr 198.51.100.23 drop']);
  const output = build({ direction: 'out' }).outputs.find(item => item.key === 'nftables');
  assert.ok(output.persistence.includes('sudo nft list ruleset | sudo tee /etc/nftables.conf'));
  assert.ok(output.notes.some(note => note.includes('inet table named filter')));
  assert.ok(output.notes.some(note => note.includes('daddr')));
});

test('iptables', () => {
  assert.deepEqual(commands({ comment: '' }, 'iptables'), ['sudo iptables -A INPUT -p tcp -s 203.0.113.0/24 --dport 22 -j ACCEPT']);
  assert.deepEqual(commands({ iface: 'eth0' }, 'iptables'), ["sudo iptables -A INPUT -i eth0 -p tcp -s 203.0.113.0/24 --dport 22 -m comment --comment 'office ssh' -j ACCEPT"]);
  assert.deepEqual(commands({ ports: '80,443,8000-8100', comment: '' }, 'iptables'), ['sudo iptables -A INPUT -p tcp -s 203.0.113.0/24 -m multiport --dports 80,443,8000:8100 -j ACCEPT']);
  assert.deepEqual(commands({ action: 'deny', ports: '8000-8100', comment: '' }, 'iptables'), ['sudo iptables -A INPUT -p tcp -s 203.0.113.0/24 --dport 8000:8100 -j DROP']);
  assert.deepEqual(commands({ action: 'reject', direction: 'out', iface: 'eth0', ports: '25', source: '', comment: '' }, 'iptables'), [
    'sudo iptables -A OUTPUT -o eth0 -p tcp --dport 25 -j REJECT',
    'sudo ip6tables -A OUTPUT -o eth0 -p tcp --dport 25 -j REJECT',
  ]);
  assert.deepEqual(commands({ direction: 'out', ports: '443', source: '198.51.100.7', comment: '' }, 'iptables'), ['sudo iptables -A OUTPUT -p tcp -d 198.51.100.7 --dport 443 -j ACCEPT']);
  assert.deepEqual(commands({ action: 'deny', protocol: 'any', ports: '', source: '198.51.100.23', comment: '' }, 'iptables'), ['sudo iptables -A INPUT -s 198.51.100.23 -j DROP']);
  const output = build({}).outputs.find(item => item.key === 'iptables');
  assert.ok(output.persistence.includes('netfilter-persistent save'));
  assert.ok(output.persistence.includes('service iptables save'));
  assert.ok(output.notes.some(note => note.includes('-A appends')));
});

test('Windows Firewall: PowerShell and netsh', () => {
  assert.deepEqual(commands({ ports: '80,443', comment: 'Web' }, 'powershell'), ["New-NetFirewallRule -DisplayName 'Web' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80,443 -RemoteAddress 203.0.113.0/24"]);
  assert.deepEqual(commands({ ports: '80,443', comment: 'Web' }, 'netsh'), ['netsh advfirewall firewall add rule name="Web" dir=in action=allow protocol=TCP localport=80,443 remoteip=203.0.113.0/24']);
  // Ranges use a dash, deny and reject both block, outbound rules match the remote port.
  assert.deepEqual(commands({ action: 'deny', direction: 'out', protocol: 'udp', ports: '8000-8100', source: '', comment: '' }, 'powershell'), ["New-NetFirewallRule -DisplayName 'Block UDP 8000-8100 outbound' -Direction Outbound -Action Block -Protocol UDP -RemotePort 8000-8100"]);
  assert.deepEqual(commands({ action: 'reject', direction: 'out', protocol: 'udp', ports: '8000-8100', source: '', comment: '' }, 'netsh'), ['netsh advfirewall firewall add rule name="Block UDP 8000-8100 outbound" dir=out action=block protocol=UDP remoteport=8000-8100']);
  assert.deepEqual(commands({ action: 'deny', protocol: 'any', ports: '', source: '198.51.100.23', comment: '' }, 'powershell'), ["New-NetFirewallRule -DisplayName 'Block inbound from 198.51.100.23' -Direction Inbound -Action Block -RemoteAddress 198.51.100.23"]);

  const reject = build({ action: 'reject', iface: 'eth0' }).outputs.find(output => output.key === 'powershell');
  assert.ok(reject.notes.some(note => note.includes('no reject action')));
  assert.ok(reject.notes.some(note => note.includes('-InterfaceAlias')));
  assert.ok(!reject.commands[0].includes('eth0'));
  const netsh = build({ iface: 'eth0' }).outputs.find(output => output.key === 'netsh');
  assert.ok(netsh.notes.some(note => note.includes('The interface eth0 is left out')));
  assert.ok(!netsh.commands[0].includes('eth0'));
});

test('an IPv6 source switches family in every tool', () => {
  const overrides = { source: '2001:db8::/32', comment: '' };
  assert.deepEqual(commands(overrides, 'ufw'), ['sudo ufw allow from 2001:db8::/32 to any port 22 proto tcp']);
  assert.deepEqual(commands(overrides, 'firewalld')[0], `sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv6" source address="2001:db8::/32" port port="22" protocol="tcp" accept'`);
  assert.deepEqual(commands(overrides, 'nftables'), ['sudo nft add rule inet filter input ip6 saddr 2001:db8::/32 tcp dport 22 accept']);
  assert.deepEqual(commands(overrides, 'iptables'), ['sudo ip6tables -A INPUT -p tcp -s 2001:db8::/32 --dport 22 -j ACCEPT']);
  assert.ok(commands(overrides, 'powershell')[0].endsWith("-LocalPort 22 -RemoteAddress '2001:db8::/32'"));
  assert.ok(commands(overrides, 'netsh')[0].endsWith('localport=22 remoteip=2001:db8::/32'));
  // A single address, upper case and long forms are accepted and tidied.
  assert.deepEqual(commands({ source: '2001:0DB8:0:0:0:0:0:1', comment: '' }, 'iptables'), ['sudo ip6tables -A INPUT -p tcp -s 2001:db8::1 --dport 22 -j ACCEPT']);
  assert.deepEqual(commands({ source: '::1', comment: '' }, 'nftables'), ['sudo nft add rule inet filter input ip6 saddr ::1 tcp dport 22 accept']);
});

test('without a source iptables gets an IPv4 and an IPv6 line', () => {
  assert.deepEqual(commands({ source: '', comment: '' }, 'iptables'), [
    'sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT',
    'sudo ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT',
  ]);
});

test('port lists are validated, sorted, de-duplicated and merged', () => {
  assert.deepEqual(commands({ ports: ' 443, 80 ,80, 8000 - 8100,8050 8090-8200', comment: '' }, 'iptables'), ['sudo iptables -A INPUT -p tcp -s 203.0.113.0/24 -m multiport --dports 80,443,8000:8200 -j ACCEPT']);
  assert.deepEqual(commands({ ports: '8000:8100', comment: '' }, 'ufw'), ['sudo ufw allow from 203.0.113.0/24 to any port 8000:8100 proto tcp']);
  assert.deepEqual(commands({ ports: '5000-5000', comment: '' }, 'nftables'), ['sudo nft add rule inet filter input ip saddr 203.0.113.0/24 tcp dport 5000 accept']);
});

test('more than 15 ports are split into several multiport rules', () => {
  const ports = `${Array.from({ length: 14 }, (_, index) => 1001 + index * 2).join(',')},3000-3010,4000,4002`;
  const list = ports.split(',');
  assert.equal(list.length, 17);
  // 14 single ports (14) plus one range (2) would be 16, so the range starts the second rule.
  const iptables = commands({ ports, source: '192.0.2.7', comment: '' }, 'iptables');
  assert.equal(iptables.length, 2);
  assert.equal(iptables[0], `sudo iptables -A INPUT -p tcp -s 192.0.2.7 -m multiport --dports ${list.slice(0, 14).join(',')} -j ACCEPT`);
  assert.equal(iptables[1], 'sudo iptables -A INPUT -p tcp -s 192.0.2.7 -m multiport --dports 3000:3010,4000,4002 -j ACCEPT');
  const ufw = commands({ ports, source: '192.0.2.7', comment: '' }, 'ufw');
  assert.deepEqual(ufw, [
    `sudo ufw allow from 192.0.2.7 to any port ${list.slice(0, 14).join(',')} proto tcp`,
    'sudo ufw allow from 192.0.2.7 to any port 3000:3010,4000,4002 proto tcp',
  ]);
  // Tools without the limit keep one rule.
  assert.equal(commands({ ports, source: '192.0.2.7', comment: '' }, 'nftables').length, 1);
  assert.equal(commands({ ports, source: '192.0.2.7', comment: '' }, 'powershell').length, 1);
  // Exactly 15 fits in one rule.
  const fifteen = Array.from({ length: 15 }, (_, index) => 2000 + index * 2).join(',');
  assert.equal(commands({ ports: fifteen, comment: '' }, 'iptables').length, 1);
});

test('both protocols', () => {
  // ufw applies a single port to TCP and UDP when proto is left out.
  assert.deepEqual(commands({ protocol: 'both', ports: '53', source: '', comment: '' }, 'ufw'), ['sudo ufw allow to any port 53']);
  // Lists and ranges need a proto in ufw, so there is one line per protocol.
  assert.deepEqual(commands({ protocol: 'both', ports: '80,443', source: '', comment: '' }, 'ufw'), ['sudo ufw allow to any port 80,443 proto tcp', 'sudo ufw allow to any port 80,443 proto udp']);
  assert.deepEqual(commands({ protocol: 'both', ports: '8000-8100', source: '', comment: '' }, 'ufw'), ['sudo ufw allow to any port 8000:8100 proto tcp', 'sudo ufw allow to any port 8000:8100 proto udp']);
  assert.deepEqual(commands({ protocol: 'both', ports: '53', source: '', comment: '' }, 'firewalld'), ['sudo firewall-cmd --permanent --add-port=53/tcp', 'sudo firewall-cmd --permanent --add-port=53/udp', 'sudo firewall-cmd --reload']);
  assert.deepEqual(commands({ protocol: 'both', ports: '53', comment: '' }, 'nftables'), [
    'sudo nft add rule inet filter input ip saddr 203.0.113.0/24 tcp dport 53 accept',
    'sudo nft add rule inet filter input ip saddr 203.0.113.0/24 udp dport 53 accept',
  ]);
  assert.deepEqual(commands({ protocol: 'both', ports: '53', source: '', comment: '' }, 'iptables'), [
    'sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT',
    'sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT',
    'sudo ip6tables -A INPUT -p tcp --dport 53 -j ACCEPT',
    'sudo ip6tables -A INPUT -p udp --dport 53 -j ACCEPT',
  ]);
  assert.deepEqual(commands({ protocol: 'both', ports: '53', source: '', comment: 'DNS' }, 'powershell'), [
    "New-NetFirewallRule -DisplayName 'DNS (TCP)' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 53",
    "New-NetFirewallRule -DisplayName 'DNS (UDP)' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 53",
  ]);
  assert.equal(commands({ protocol: 'both', ports: '53', source: '', comment: 'DNS' }, 'netsh').length, 2);
});

test('invalid ports are rejected and nothing is generated', () => {
  for (const ports of ['0', '65536', '99999999', '90-80', 'ssh', '22;reboot', '22 $(id)', '80,,x', '1-2-3', '-5']) {
    const result = build({ ports });
    assert.ok(result.errors.length >= 1, ports);
    assert.deepEqual(result.outputs, [], ports);
  }
  assert.ok(build({ ports: '70000' }).errors[0].includes('out of range'));
  assert.ok(build({ ports: '90-80' }).errors[0].includes('runs backwards'));
  const any = build({ protocol: 'any', ports: '22' });
  assert.ok(any.errors[0].includes('cannot be combined with ports'));
  assert.deepEqual(any.outputs, []);
});

test('invalid addresses, interfaces and enum values are rejected', () => {
  for (const source of ['300.1.1.1', '10.0.0.0/33', '10.0.0/24', '10.0.0.1/', '10.0.0.1/-1', '01.2.3.4', 'example.com', '2001:db8::/129', '2001:db8::1::2', '1:2:3:4:5:6:7:8:9', 'fe80::1%eth0', '10.0.0.1; rm -rf /', '$(id)']) {
    const result = build({ source });
    assert.equal(result.errors.length, 1, source);
    assert.deepEqual(result.outputs, [], source);
  }
  for (const iface of ['eth0; reboot', 'this-name-is-too-long', 'eth 0', '$(id)']) {
    const result = build({ iface });
    assert.ok(result.errors[0].startsWith('Interface must be'), iface);
    assert.deepEqual(result.outputs, []);
  }
  assert.deepEqual(build({ iface: 'eth0.100' }).errors, []);
  assert.deepEqual(build({ iface: 'br-lan@if2' }).errors, []);
  assert.equal(build({ action: 'permit' }).errors.length, 1);
  assert.equal(build({ direction: 'sideways' }).errors.length, 1);
  assert.equal(build({ protocol: 'icmp' }).errors.length, 1);
});

test('a CIDR with host bits set is replaced by its network address, with a warning', () => {
  const v4 = build({ source: '203.0.113.77/24', comment: '' });
  assert.ok(v4.warnings[0].includes('The rules use 203.0.113.0/24'));
  assert.equal(v4.outputs.find(output => output.key === 'iptables').commands[0], 'sudo iptables -A INPUT -p tcp -s 203.0.113.0/24 --dport 22 -j ACCEPT');
  const v6 = build({ source: '2001:db8:abcd:1234::1/44', comment: '' });
  assert.ok(v6.warnings[0].includes('The rules use 2001:db8:abc0::/44'));
  assert.deepEqual(build({ source: '10.1.2.3/32' }).warnings, []);
  assert.deepEqual(build({ source: '10.0.0.0/8' }).warnings, []);
});

test('lockout warnings for blocking SSH or RDP from any source', () => {
  const ssh = build({ action: 'deny', source: '' });
  assert.ok(ssh.warnings.some(warning => warning.includes('lock you out of SSH')));
  const rdp = build({ action: 'reject', ports: '3000-4000', source: '' });
  assert.ok(rdp.warnings.some(warning => warning.includes('lock you out of RDP')));
  const everything = build({ action: 'deny', protocol: 'any', ports: '', source: '0.0.0.0/0' });
  assert.ok(everything.warnings.some(warning => warning.includes('SSH')));
  assert.ok(everything.warnings.some(warning => warning.includes('RDP')));
  // Not for a single source, for outbound rules, for UDP or for allow rules.
  assert.deepEqual(build({ action: 'deny' }).warnings, []);
  assert.deepEqual(build({ action: 'deny', source: '', direction: 'out' }).warnings, []);
  assert.deepEqual(build({ action: 'deny', source: '', protocol: 'udp' }).warnings, []);
  assert.deepEqual(build({ source: '' }).warnings, []);
});

test('exposure warnings for allowing database, cache and telnet ports from any source', () => {
  const mysql = build({ ports: '3306', source: '' });
  assert.deepEqual(mysql.warnings, ['Port 3306 (MySQL) is open to any source. That exposes a database to the internet. Restrict the source address.']);
  const several = build({ ports: '5432,6379,27017,2375', source: '' });
  assert.equal(several.warnings.length, 4);
  assert.ok(several.warnings.some(warning => warning.includes('Redis') && warning.includes('a cache')));
  assert.ok(build({ ports: '9000-9300', source: '' }).warnings.some(warning => warning.includes('Elasticsearch')));
  assert.ok(build({ ports: '23', source: '' }).warnings.some(warning => warning.includes('Telnet')));
  // A restricted source or a deny rule is fine.
  assert.deepEqual(build({ ports: '3306', source: '10.0.0.5' }).warnings, []);
  assert.deepEqual(build({ ports: '3306', source: '', action: 'deny' }).warnings, []);
});

test('no ports with a protocol means all ports, and says so', () => {
  assert.deepEqual(build({ ports: '' }).warnings, ['No ports are set, so the rule covers all TCP ports from 203.0.113.0/24.']);
  assert.deepEqual(build({ ports: '', protocol: 'both', direction: 'out', source: '' }).warnings, ['No ports are set, so the rule covers all TCP and UDP ports.']);
  assert.deepEqual(commands({ ports: '', protocol: 'both', comment: '' }, 'ufw'), ['sudo ufw allow from 203.0.113.0/24 proto tcp', 'sudo ufw allow from 203.0.113.0/24 proto udp']);
});

test('a comment with a single quote is quoted for each tool', () => {
  const comment = "Bob's office";
  assert.deepEqual(commands({ comment }, 'iptables'), ["sudo iptables -A INPUT -p tcp -s 203.0.113.0/24 --dport 22 -m comment --comment 'Bob'\\''s office' -j ACCEPT"]);
  assert.deepEqual(commands({ comment }, 'nftables'), [`sudo nft 'add rule inet filter input ip saddr 203.0.113.0/24 tcp dport 22 accept comment "Bob'\\''s office"'`]);
  assert.ok(commands({ comment }, 'powershell')[0].startsWith("New-NetFirewallRule -DisplayName 'Bob''s office' "));
  assert.ok(commands({ comment }, 'netsh')[0].includes(`name="Bob's office"`));
  // ufw refuses single quotes in comments, so it is dropped there and explained.
  assert.deepEqual(commands({ comment }, 'ufw'), ["sudo ufw allow from 203.0.113.0/24 to any port 22 proto tcp comment 'Bobs office'"]);
  assert.ok(build({ comment }).outputs[0].notes.some(note => note.includes('single quote')));
  // Shell metacharacters stay inside the quotes.
  assert.deepEqual(commands({ comment: 'web; (prod) & more #1' }, 'ufw'), ["sudo ufw allow from 203.0.113.0/24 to any port 22 proto tcp comment 'web; (prod) & more #1'"]);
});

test('comments that some tool cannot carry are rejected', () => {
  for (const comment of ['say "hi"', 'back\\slash', '100%', 'a|b', 'cost $HOME', 'tick `id`', 'line\nbreak', 'caf\u00e9', 'x'.repeat(101)]) {
    const result = build({ comment });
    assert.equal(result.errors.length, 1, comment);
    assert.deepEqual(result.outputs, []);
  }
});
