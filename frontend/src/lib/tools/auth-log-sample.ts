/**
 * Builds the sample log for the SSH Auth Log Analyzer. The addresses are from
 * the documentation ranges (RFC 5737, RFC 3849). The same text every time.
 */

interface SampleLine {
  at: number;
  text: string;
}

function pad2(value: number): string {
  return value < 10 ? `0${value}` : String(value);
}

export function buildAuthLogSample(): string {
  const out: SampleLine[] = [];
  let order = 0;
  let pid = 20110;
  // `at` is seconds since midnight. A tiny step keeps lines of one connection in the order they were added.
  const add = (at: number, tag: string, message: string) => {
    order += 1;
    out.push({ at: at + order / 100000, text: `${tag}: ${message}` });
  };

  // A password guessing run with made-up user names.
  const guesses = ['admin', 'test', 'oracle', 'ubuntu', 'postgres', 'git', 'ftpuser', 'pi', 'user', 'guest', 'jenkins', 'minecraft', 'www', 'backup', 'support', 'admin', 'test', 'ubuntu'];
  guesses.forEach((name, index) => {
    const at = 1 * 3600 + 420 + index * 437;
    const port = 40112 + index * 613;
    const tag = `sshd[${(pid += 7)}]`;
    add(at, tag, `Invalid user ${name} from 203.0.113.45 port ${port}`);
    add(at, tag, 'pam_unix(sshd:auth): check pass; user unknown');
    add(at, tag, 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.45');
    add(at + 2, tag, `Failed password for invalid user ${name} from 203.0.113.45 port ${port} ssh2`);
    add(at + 3, tag, `Connection closed by invalid user ${name} 203.0.113.45 port ${port} [preauth]`);
  });

  // Bursts against root, with the lines rsyslog folds into "message repeated".
  for (let burst = 0; burst < 6; burst += 1) {
    const at = 3 * 3600 + 95 + burst * 1260;
    const port = 51820 + burst * 97;
    const tag = `sshd[${(pid += 11)}]`;
    add(at, tag, 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.23  user=root');
    add(at + 2, tag, `Failed password for root from 198.51.100.23 port ${port} ssh2`);
    add(at + 7, tag, `message repeated 2 times: [ Failed password for root from 198.51.100.23 port ${port} ssh2]`);
    add(at + 8, tag, `error: maximum authentication attempts exceeded for root from 198.51.100.23 port ${port} ssh2 [preauth]`);
    add(at + 8, tag, `Disconnecting authenticating user root 198.51.100.23 port ${port}: Too many authentication failures [preauth]`);
  }

  // The same thing over IPv6.
  ['root', 'admin', 'root', 'ubuntu', 'root', 'deploy', 'root'].forEach((name, index) => {
    const at = 5 * 3600 + 1310 + index * 505;
    const port = 38800 + index * 211;
    const tag = `sshd[${(pid += 5)}]`;
    const valid = name === 'root' || name === 'deploy';
    if (!valid) add(at, tag, `Invalid user ${name} from 2001:db8:5a::c4 port ${port}`);
    add(at + 2, tag, `Failed password for ${valid ? '' : 'invalid user '}${name} from 2001:db8:5a::c4 port ${port} ssh2`);
    add(at + 3, tag, `Connection closed by ${valid ? 'authenticating' : 'invalid'} user ${name} 2001:db8:5a::c4 port ${port} [preauth]`);
  });

  // Two sources that stay under the block threshold.
  add(2 * 3600 + 2710, `sshd[${(pid += 3)}]`, 'Failed password for root from 203.0.113.61 port 47120 ssh2');
  add(2 * 3600 + 2716, `sshd[${pid}]`, 'Failed password for root from 203.0.113.61 port 47120 ssh2');
  add(7 * 3600 + 133, `sshd[${(pid += 3)}]`, 'Invalid user nagios from 203.0.113.62 port 60214');
  add(7 * 3600 + 135, `sshd[${pid}]`, 'Failed password for invalid user nagios from 203.0.113.62 port 60214 ssh2');

  // Scanners that never try to log in.
  add(1 * 3600 + 1502, `sshd[${(pid += 3)}]`, 'Did not receive identification string from 192.0.2.150 port 40112');
  add(4 * 3600 + 211, `sshd[${(pid += 3)}]`, 'Unable to negotiate with 203.0.113.99 port 33812: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1,diffie-hellman-group14-sha1 [preauth]');
  add(4 * 3600 + 215, `sshd[${(pid += 3)}]`, 'Unable to negotiate with 203.0.113.99 port 33960: no matching host key type found. Their offer: ssh-dss [preauth]');
  add(6 * 3600 + 3020, `sshd[${(pid += 3)}]`, 'banner exchange: Connection from 192.0.2.151 port 51000: invalid format');

  // Seven wrong passwords for a real account, then a login from the same address.
  const deployTag = `sshd[${(pid += 9)}]`;
  for (let attempt = 0; attempt < 7; attempt += 1) {
    add(8 * 3600 + 1200 + attempt * 9, deployTag, `Failed password for deploy from 192.0.2.77 port ${44310 + attempt} ssh2`);
  }
  const deployLogin = `sshd[${(pid += 2)}]`;
  add(8 * 3600 + 1290, deployLogin, 'Accepted password for deploy from 192.0.2.77 port 44391 ssh2');
  add(8 * 3600 + 1290, deployLogin, 'pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)');
  add(8 * 3600 + 1345, 'sudo', '   deploy : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash');

  // Normal use.
  const aliceTag = `sshd[${(pid += 4)}]`;
  add(9 * 3600 + 312, aliceTag, 'Accepted publickey for alice from 198.51.100.200 port 50222 ssh2: ED25519 SHA256:3fPq8nB2xk0V1wYt7uJmQe5sZc9RdLhGa4oTiNyXvKM');
  add(9 * 3600 + 312, aliceTag, 'pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)');
  add(9 * 3600 + 371, 'sudo', '    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl status nginx');
  add(9 * 3600 + 371, 'sudo', 'pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)');
  add(9 * 3600 + 420, 'sudo', '    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/journalctl -u nginx -n 200');
  add(9 * 3600 + 502, 'sudo', '    alice : TTY=pts/0 ; PWD=/etc/nginx ; USER=root ; COMMAND=/usr/bin/systemctl reload nginx');
  add(10 * 3600 + 95, 'sudo', 'pam_unix(sudo:auth): authentication failure; logname=bob uid=1002 euid=0 tty=/dev/pts/2 ruser=bob rhost=  user=bob');
  add(10 * 3600 + 101, 'sudo', '      bob : TTY=pts/2 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt update');
  const rootTag = `sshd[${(pid += 4)}]`;
  add(10 * 3600 + 1502, rootTag, 'Accepted publickey for root from 192.0.2.10 port 61022 ssh2: RSA SHA256:Zk1vQ0h2cX9uTjR3bUxwYzZkRWg4a1NmVG9BeUJqMnM');
  add(10 * 3600 + 1502, rootTag, 'pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)');
  const laterTag = `sshd[${(pid += 4)}]`;
  add(11 * 3600 + 840, laterTag, 'Accepted publickey for alice from 198.51.100.200 port 50871 ssh2: ED25519 SHA256:3fPq8nB2xk0V1wYt7uJmQe5sZc9RdLhGa4oTiNyXvKM');

  return out
    .sort((a, b) => a.at - b.at)
    .map(line => {
      const second = Math.floor(line.at);
      return `Nov 26 ${pad2(Math.floor(second / 3600))}:${pad2(Math.floor((second % 3600) / 60))}:${pad2(second % 60)} web01 ${line.text}`;
    })
    .join('\n');
}
