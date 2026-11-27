import test from 'node:test';
import assert from 'node:assert/strict';
import { buildRsyncCommand, RSYNC_DEFAULTS } from '../../frontend/src/lib/tools/rsync.ts';
import { shQuote, cmdQuote, psQuote } from '../../frontend/src/lib/tools/shell.ts';

const base = { ...RSYNC_DEFAULTS, dryRun: false, source: '/var/www/', destination: '/backup/www/' };

test('default local copy uses archive, verbose, compress and readable sizes', () => {
  const built = buildRsyncCommand(base);
  assert.equal(built.command, 'rsync -a -v -z -h /var/www/ /backup/www/');
  assert.deepEqual(built.errors, []);
  assert.deepEqual(built.warnings, []);
  assert.equal(built.parts.length, 4);
});

test('ssh port and key become a single quoted -e argument', () => {
  const built = buildRsyncCommand({ ...base, destination: 'root@host:/srv/', sshPort: '2222', sshKey: '~/.ssh/id_ed25519' });
  assert.match(built.command, /-e 'ssh -p 2222 -i ~\/\.ssh\/id_ed25519' \/var\/www\/ root@host:\/srv\/$/);
});

test('paths and exclude patterns with spaces or quotes are shell-quoted', () => {
  const built = buildRsyncCommand({ ...base, source: "/data/my files/", excludes: ['*.log', "it's here/", '  '] });
  assert.match(built.command, /--exclude='\*\.log'/);
  assert.match(built.command, /--exclude='it'\\''s here\/'/);
  assert.match(built.command, /'\/data\/my files\/' \/backup\/www\/$/);
});

test('destructive options warn unless a dry run is on', () => {
  const live = buildRsyncCommand({ ...base, delete: true });
  assert.ok(live.warnings.some(w => w.includes('--delete removes files')));
  const dry = buildRsyncCommand({ ...base, delete: true, dryRun: true });
  assert.ok(!dry.warnings.some(w => w.includes('--delete removes files')));
  assert.ok(dry.command.includes('--dry-run'));
});

test('invalid input is reported as errors, not put in the command', () => {
  const built = buildRsyncCommand({ ...base, source: '', sshPort: '99999', bwLimit: 'fast' });
  assert.equal(built.errors.length, 3);
  assert.ok(!built.command.includes('99999'));
  assert.ok(!built.command.includes('fast'));
});

test('two remote paths are rejected and a missing trailing slash is explained', () => {
  assert.ok(buildRsyncCommand({ ...base, source: 'a@h1:/x/', destination: 'b@h2:/y/' }).errors[0].includes('two remote hosts'));
  assert.ok(buildRsyncCommand({ ...base, source: '/var/www' }).warnings[0].includes('trailing slash'));
});

test('quoting helpers', () => {
  assert.equal(shQuote('plain-word_1.txt'), 'plain-word_1.txt');
  assert.equal(shQuote(''), "''");
  assert.equal(shQuote('a b'), "'a b'");
  assert.equal(shQuote('$(rm -rf /)'), "'$(rm -rf /)'");
  assert.equal(cmdQuote('C:\\Data'), 'C:\\Data');
  assert.equal(cmdQuote('C:\\My Data\\'), '"C:\\My Data\\\\"');
  assert.equal(psQuote("it's"), "'it''s'");
});
