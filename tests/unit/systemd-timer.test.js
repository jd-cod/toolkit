import test from 'node:test';
import assert from 'node:assert/strict';
import { buildUnits, cronToOnCalendar, nextRuns, normalizeTimeSpan, UNIT_DEFAULTS } from '../../frontend/src/lib/tools/systemd-timer.ts';

const calendar = expr => cronToOnCalendar(expr).onCalendar;
const base = { ...UNIT_DEFAULTS, name: 'backup', description: 'Backup', command: '/usr/local/bin/backup.sh', onCalendar: ['*-*-* 03:00:00'] };
const stamp = date => `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;

test('cron expressions convert to normalized OnCalendar expressions', () => {
  const cases = {
    '*/15 * * * *': '*-*-* *:0/15:00',
    '0 3 * * *': '*-*-* 03:00:00',
    '0 9 * * 1-5': 'Mon..Fri *-*-* 09:00:00',
    '0 0 1 * *': '*-*-01 00:00:00',
    '30 2 1,15 * *': '*-*-01,15 02:30:00',
    '0 0 1 1 *': '*-01-01 00:00:00',
    '*/5 9-17 * * *': '*-*-* 09..17:0/5:00',
    '* * * * *': '*-*-* *:*:00',
    '0 */6 * * *': '*-*-* 0/6:00:00',
    '0 8-18/2 * * *': '*-*-* 08..18/2:00:00',
    '0 0 */2 * *': '*-*-1/2 00:00:00',
    '15 4 * */3 *': '*-1/3-* 04:15:00',
    '0 0 * jan,jul *': '*-01,07-* 00:00:00',
  };
  for (const [cron, expected] of Object.entries(cases)) {
    const result = cronToOnCalendar(cron);
    assert.deepEqual(result.onCalendar, [expected], cron);
    assert.equal(result.valid, true);
    assert.deepEqual(result.errors, []);
  }
});

test('day of week uses names, treats 0 and 7 as Sunday and expands steps', () => {
  assert.deepEqual(calendar('0 0 * * 6,0'), ['Sat,Sun *-*-* 00:00:00']);
  assert.deepEqual(calendar('0 0 * * 7'), ['Sun *-*-* 00:00:00']);
  assert.deepEqual(calendar('0 0 * * 0'), ['Sun *-*-* 00:00:00']);
  assert.deepEqual(calendar('0 0 * * mon,WED,fri'), ['Mon,Wed,Fri *-*-* 00:00:00']);
  assert.deepEqual(calendar('0 0 * * 1-5/2'), ['Mon,Wed,Fri *-*-* 00:00:00']);
  assert.deepEqual(calendar('0 0 * * */2'), ['Tue,Thu,Sat,Sun *-*-* 00:00:00']);
  assert.deepEqual(calendar('0 0 * * 5-7'), ['Fri..Sun *-*-* 00:00:00']);
  assert.deepEqual(calendar('0 0 * * 0-6'), ['*-*-* 00:00:00']);
});

test('day of month and day of week together give two lines and a note', () => {
  const result = cronToOnCalendar('0 4 13 * 5');
  assert.deepEqual(result.onCalendar, ['Fri *-*-* 04:00:00', '*-*-13 04:00:00']);
  assert.ok(result.notes.some(note => note.includes('either one matches')));
  // A day field that starts with * does not trigger the OR rule in cron.
  assert.deepEqual(calendar('0 4 */2 * 1'), ['Mon *-*-1/2 04:00:00']);
  assert.deepEqual(calendar('0 4 1 6 mon'), ['Mon *-06-* 04:00:00', '*-06-01 04:00:00']);
});

test('macros map to their cron equivalents and @reboot to OnBootSec', () => {
  assert.deepEqual(calendar('@hourly'), ['*-*-* *:00:00']);
  assert.deepEqual(calendar('@daily'), ['*-*-* 00:00:00']);
  assert.deepEqual(calendar('@midnight'), ['*-*-* 00:00:00']);
  assert.deepEqual(calendar('@weekly'), ['Sun *-*-* 00:00:00']);
  assert.deepEqual(calendar('@monthly'), ['*-*-01 00:00:00']);
  assert.deepEqual(calendar('@yearly'), ['*-01-01 00:00:00']);
  assert.deepEqual(calendar('@Annually'), ['*-01-01 00:00:00']);
  assert.equal(cronToOnCalendar('@weekly').cron, '0 0 * * 0');

  const reboot = cronToOnCalendar('@reboot');
  assert.equal(reboot.valid, true);
  assert.deepEqual(reboot.onCalendar, []);
  assert.equal(reboot.onBootSec, '1min');
  assert.equal(cronToOnCalendar('@reboot', '90s').onBootSec, '90s');
  assert.equal(cronToOnCalendar('@reboot', 'soon; reboot').valid, false);
  assert.equal(cronToOnCalendar('@fortnightly').valid, false);
});

test('invalid cron expressions return clear errors and no output', () => {
  const bad = {
    '': 'Enter a cron expression',
    '0 3 * *': 'Expected 5 fields',
    '0 3 * * * /bin/true': 'Expected 5 fields',
    '60 * * * *': 'Minute: 60 is out of range (0 to 59)',
    '0 24 * * *': 'Hour: 24 is out of range (0 to 23)',
    '0 0 0 * *': 'Day of month: 0 is out of range (1 to 31)',
    '0 0 * 13 *': 'Month: 13 is out of range (1 to 12)',
    '0 0 * * 8': 'Day of week: 8 is out of range (0 to 7)',
    '0 0 * * funday': 'Day of week: "funday" is not valid',
    '0 17-9 * * *': 'runs backwards',
    '*/0 * * * *': 'step',
    '5/15 * * * *': 'needs a range before the step',
    '0 0 * * 1;reboot': 'is not valid',
  };
  for (const [cron, message] of Object.entries(bad)) {
    const result = cronToOnCalendar(cron);
    assert.equal(result.valid, false, cron);
    assert.deepEqual(result.onCalendar, [], cron);
    assert.ok(result.errors.some(error => error.includes(message)), `${cron}: ${result.errors.join(' | ')}`);
  }
});

test('next runs are computed from a fixed start in local time', () => {
  const from = new Date(2026, 0, 1, 10, 7, 30);
  assert.deepEqual(nextRuns('*/15 * * * *', 3, from).map(stamp), ['2026-01-01 10:15', '2026-01-01 10:30', '2026-01-01 10:45']);
  assert.deepEqual(nextRuns('0 3 * * *', 2, from).map(stamp), ['2026-01-02 03:00', '2026-01-03 03:00']);
  // 2026-01-01 is a Thursday.
  assert.deepEqual(nextRuns('0 9 * * 1-5', 3, from).map(stamp), ['2026-01-02 09:00', '2026-01-05 09:00', '2026-01-06 09:00']);
  assert.deepEqual(nextRuns('@monthly', 2, from).map(stamp), ['2026-02-01 00:00', '2026-03-01 00:00']);
  assert.deepEqual(nextRuns('0 0 29 2 *', 2, from).map(stamp), ['2028-02-29 00:00', '2032-02-29 00:00']);
  // The start minute itself is not a next run.
  assert.deepEqual(nextRuns('0 10 * * *', 1, new Date(2026, 0, 1, 10, 0, 0)).map(stamp), ['2026-01-02 10:00']);
});

test('next runs follow cron day matching: either day field, or both when one starts with *', () => {
  const from = new Date(2026, 0, 1, 0, 0, 0);
  // The 13th or any Friday.
  assert.deepEqual(nextRuns('0 4 13 * 5', 4, from).map(stamp), ['2026-01-02 04:00', '2026-01-09 04:00', '2026-01-13 04:00', '2026-01-16 04:00']);
  // Odd days that are also Mondays.
  assert.deepEqual(nextRuns('0 4 */2 * 1', 3, from).map(stamp), ['2026-01-05 04:00', '2026-01-19 04:00', '2026-02-09 04:00']);
});

test('next runs stop for expressions that never match or are not schedules', () => {
  const from = new Date(2026, 0, 1, 0, 0, 0);
  assert.deepEqual(nextRuns('0 0 31 2 *', 5, from), []);
  assert.deepEqual(nextRuns('0 0 31 4,6,9,11 *', 5, from), []);
  assert.deepEqual(nextRuns('@reboot', 5, from), []);
  assert.deepEqual(nextRuns('not cron', 5, from), []);
  assert.deepEqual(nextRuns('* * * * *', 0, from), []);
});

test('system scope writes a oneshot service and a timer under /etc/systemd/system', () => {
  const built = buildUnits({ ...base, user: 'backup', workingDirectory: '/srv/app', randomizedDelaySec: '5min', accuracySec: '1s' });
  assert.deepEqual(built.errors, []);
  assert.deepEqual(built.warnings, []);
  assert.equal(built.timerPath, '/etc/systemd/system/backup.timer');
  assert.equal(built.servicePath, '/etc/systemd/system/backup.service');
  assert.equal(built.serviceUnit, '[Unit]\nDescription=Backup\n\n[Service]\nType=oneshot\nUser=backup\nWorkingDirectory=/srv/app\nExecStart=/usr/local/bin/backup.sh\n');
  assert.equal(built.timerUnit, '[Unit]\nDescription=Run backup.service on a schedule\n\n[Timer]\nOnCalendar=*-*-* 03:00:00\nPersistent=true\nRandomizedDelaySec=5min\nAccuracySec=1s\n\n[Install]\nWantedBy=timers.target\n');

  const commands = built.installCommands;
  assert.ok(commands[0].startsWith("sudo tee /etc/systemd/system/backup.service > /dev/null <<'EOF'\n[Unit]"));
  assert.ok(commands[0].endsWith('\nEOF'));
  assert.ok(commands[1].startsWith("sudo tee /etc/systemd/system/backup.timer > /dev/null <<'EOF'\n"));
  assert.deepEqual(commands.slice(2), [
    'sudo systemctl daemon-reload',
    'sudo systemctl enable --now backup.timer',
    'systemctl list-timers backup.timer',
    'journalctl -u backup.service',
    "systemd-analyze calendar '*-*-* 03:00:00'",
  ]);
});

test('user scope uses ~/.config/systemd/user, no sudo, no User= and mentions lingering', () => {
  const built = buildUnits({ ...base, scope: 'user', user: 'backup' });
  assert.equal(built.timerPath, '~/.config/systemd/user/backup.timer');
  assert.equal(built.servicePath, '~/.config/systemd/user/backup.service');
  assert.ok(!built.serviceUnit.includes('User='));
  assert.ok(built.warnings.some(warning => warning.includes('User= only works in system units')));
  assert.ok(built.notes.some(note => note.includes('loginctl enable-linger')));
  const script = built.installCommands.join('\n');
  assert.ok(!script.includes('sudo'));
  assert.ok(script.includes('mkdir -p ~/.config/systemd/user'));
  assert.ok(script.includes("cat > ~/.config/systemd/user/backup.timer <<'EOF'"));
  assert.ok(script.includes('systemctl --user daemon-reload'));
  assert.ok(script.includes('systemctl --user enable --now backup.timer'));
  assert.ok(script.includes('systemctl --user list-timers backup.timer'));
  assert.ok(script.includes('journalctl --user-unit backup.service'));
});

test('two OnCalendar lines are both written and both verified', () => {
  const built = buildUnits({ ...base, onCalendar: cronToOnCalendar('0 4 13 * 5').onCalendar });
  assert.ok(built.timerUnit.includes('OnCalendar=Fri *-*-* 04:00:00\nOnCalendar=*-*-13 04:00:00\nPersistent=true\n'));
  assert.ok(built.installCommands.includes("systemd-analyze calendar 'Fri *-*-* 04:00:00'"));
  assert.ok(built.installCommands.includes("systemd-analyze calendar '*-*-13 04:00:00'"));
});

test('@reboot timers use OnBootSec without Persistent', () => {
  const built = buildUnits({ ...base, onCalendar: [], onBootSec: '2min' });
  assert.deepEqual(built.errors, []);
  assert.ok(built.timerUnit.includes('[Timer]\nOnBootSec=2min\n\n[Install]'));
  assert.ok(!built.timerUnit.includes('Persistent'));
  assert.ok(!built.installCommands.some(command => command.startsWith('systemd-analyze')));
});

test('unit names are validated and kept out of the output', () => {
  for (const name of ['', 'my job', 'backup.timer', 'backup.service', '../etc/passwd', 'a;reboot', '-rf', 'x\n[Service]']) {
    const built = buildUnits({ ...base, name });
    assert.equal(built.errors.length, 1, JSON.stringify(name));
    assert.equal(built.timerPath, '/etc/systemd/system/UNIT_NAME.timer');
    if (name) assert.ok(!built.installCommands.join('\n').includes(name), JSON.stringify(name));
  }
  for (const name of ['backup', 'db-backup_2', 'app.cleanup', 'a:b']) {
    assert.deepEqual(buildUnits({ ...base, name }).errors, [], name);
  }
});

test('commands are validated and plain commands are passed through', () => {
  assert.ok(buildUnits({ ...base, command: '  ' }).errors.includes('Enter the command to run.'));
  const multiline = buildUnits({ ...base, command: '/bin/true\nExecStartPost=/bin/evil' });
  assert.ok(multiline.errors.includes('The command must be a single line.'));
  assert.ok(!multiline.serviceUnit.includes('evil'));

  const plain = buildUnits({ ...base, command: '/usr/bin/rsync -a "/srv/my data/" /backup/' });
  assert.ok(plain.serviceUnit.includes('ExecStart=/usr/bin/rsync -a "/srv/my data/" /backup/\n'));
  assert.deepEqual(plain.warnings, []);
  assert.deepEqual(plain.notes, []);

  const relative = buildUnits({ ...base, command: 'backup.sh --all' });
  assert.ok(relative.serviceUnit.includes('ExecStart=backup.sh --all\n'));
  assert.ok(relative.warnings.some(warning => warning.includes('ExecStart needs an absolute path')));
  // A systemd prefix such as - (ignore failure) is not part of the path.
  assert.deepEqual(buildUnits({ ...base, command: '-/usr/bin/flaky --once' }).warnings, []);
});

test('shell syntax is wrapped in /bin/sh -c with systemd quoting', () => {
  const exec = command => /^ExecStart=(.*)$/m.exec(buildUnits({ ...base, command }).serviceUnit)[1];
  assert.equal(exec('/usr/bin/pg_dumpall | gzip > /backup/all.sql.gz'), "/bin/sh -c '/usr/bin/pg_dumpall | gzip > /backup/all.sql.gz'");
  assert.equal(exec('cd /srv/app && ./run.sh'), "/bin/sh -c 'cd /srv/app && ./run.sh'");
  assert.equal(exec('/bin/a; /bin/b'), "/bin/sh -c '/bin/a; /bin/b'");
  assert.equal(exec('/bin/rm -f /tmp/cache/*.tmp'), "/bin/sh -c '/bin/rm -f /tmp/cache/*.tmp'");
  assert.equal(exec('/bin/echo `hostname`'), "/bin/sh -c '/bin/echo `hostname`'");
  assert.equal(exec('PATH=/opt/bin /opt/bin/job'), "/bin/sh -c 'PATH=/opt/bin /opt/bin/job'");
  // $ is doubled for systemd, quotes and backslashes use C-style escapes.
  assert.equal(exec('/bin/echo $(date) > "$HOME/last run"'), `/bin/sh -c '/bin/echo $$(date) > "$$HOME/last run"'`);
  assert.equal(exec("/bin/echo 'it works' >> /tmp/log"), "/bin/sh -c '/bin/echo \\'it works\\' >> /tmp/log'");
  assert.equal(exec("/bin/sed -i 's/\\.old$//' /etc/app.conf"), "/bin/sh -c '/bin/sed -i \\'s/\\\\.old$$//\\' /etc/app.conf'");

  const built = buildUnits({ ...base, command: 'backup | gzip' });
  assert.ok(built.notes.some(note => note.includes('/bin/sh -c')));
  assert.deepEqual(built.warnings, []);
});

test('a literal percent sign is doubled in unit files', () => {
  const built = buildUnits({ ...base, description: '100% backup', workingDirectory: '/srv/50%', command: '/usr/bin/backup --name db-%Y-%m-%d' });
  assert.ok(built.serviceUnit.includes('Description=100%% backup\n'));
  assert.ok(built.serviceUnit.includes('WorkingDirectory=/srv/50%%\n'));
  assert.ok(built.serviceUnit.includes('ExecStart=/usr/bin/backup --name db-%%Y-%%m-%%d\n'));
  assert.ok(built.notes.some(note => note.includes('%%')));
  const wrapped = buildUnits({ ...base, command: '/bin/date +%F > /tmp/stamp' });
  assert.ok(wrapped.serviceUnit.includes("ExecStart=/bin/sh -c '/bin/date +%%F > /tmp/stamp'\n"));
});

test('other fields are validated', () => {
  assert.ok(buildUnits({ ...base, user: 'bad user' }).errors.includes('User must be an account name or a numeric ID.'));
  assert.ok(buildUnits({ ...base, workingDirectory: 'relative/dir' }).errors.includes('Working directory must be an absolute path.'));
  assert.ok(buildUnits({ ...base, randomizedDelaySec: 'a while' }).errors[0].startsWith('Random delay must be a time span'));
  assert.ok(buildUnits({ ...base, accuracySec: '1s\nExecStart=/bin/evil' }).errors[0].startsWith('Accuracy must be a time span'));
  assert.ok(buildUnits({ ...base, onCalendar: [] }).errors.includes('There is no schedule. Enter a valid cron expression.'));
  const injected = buildUnits({ ...base, onCalendar: ['daily\nUnit=evil.service'] });
  assert.ok(injected.errors.includes('The schedule is not a valid OnCalendar expression.'));
  assert.ok(!injected.timerUnit.includes('evil'));
  const described = buildUnits({ ...base, description: 'Line one\nExecStart=/bin/evil \\' });
  assert.ok(described.serviceUnit.includes('Description=Line one ExecStart=/bin/evil\n'));
  assert.equal(buildUnits({ ...base, description: '' }).serviceUnit.split('\n')[1], 'Description=Scheduled job backup');
});

test('time spans', () => {
  for (const span of ['90', '30s', '5min', '1h 30min', '1h30min', '1.5h', '2 weeks']) assert.equal(normalizeTimeSpan(span), span, span);
  for (const span of ['', 'soon', '5 parsecs', '-5min', '5min;', '$(id)']) assert.equal(normalizeTimeSpan(span), null, span);
});
