import test from 'node:test';
import assert from 'node:assert/strict';
import {
  applyRobocopyPreset,
  buildRobocopyCommand,
  decodeRobocopyExitCode,
  ROBOCOPY_BATCH_SNIPPET,
  ROBOCOPY_DEFAULTS,
  ROBOCOPY_POWERSHELL_SNIPPET,
  ROBOCOPY_PRESETS,
  robocopyScript,
} from '../../frontend/src/lib/tools/robocopy.ts';

const base = { ...ROBOCOPY_DEFAULTS, source: 'C:\\Data', destination: 'D:\\Backup\\Data' };

test('default command copies subdirectories with short retries', () => {
  const built = buildRobocopyCommand(base);
  assert.equal(built.command, 'robocopy C:\\Data D:\\Backup\\Data /E /R:3 /W:5');
  assert.deepEqual(built.errors, []);
  assert.deepEqual(built.warnings, []);
  assert.deepEqual(built.parts.map(part => part.flag), ['/E', '/R:3', '/W:5']);
});

test('mirror warns about deletion unless it is a test run', () => {
  const live = buildRobocopyCommand({ ...base, mode: 'mir' });
  assert.ok(live.command.includes(' /MIR '));
  assert.ok(!live.command.includes('/E'));
  assert.ok(live.warnings.some(w => w.includes('/MIR deletes destination files that are not in the source, run with /L first')));
  const dry = buildRobocopyCommand({ ...base, mode: 'mir', listOnly: true });
  assert.ok(dry.command.includes('/L'));
  assert.ok(!dry.warnings.some(w => w.includes('deletes destination files')));
  assert.ok(dry.warnings.some(w => w.includes('test run')));
});

test('purge is separate from the copy mode and is implied by mirror', () => {
  const purge = buildRobocopyCommand({ ...base, purge: true });
  assert.ok(purge.command.includes('/E /PURGE'));
  assert.ok(purge.warnings.some(w => w.startsWith('/PURGE deletes destination files')));
  const both = buildRobocopyCommand({ ...base, mode: 'mir', purge: true });
  assert.ok(!both.command.includes('/PURGE'));
});

test('mirror into a drive root or the parent of the source is flagged', () => {
  const root = buildRobocopyCommand({ ...base, mode: 'mir', destination: 'E:\\' });
  assert.ok(root.warnings.some(w => w.includes('drive or share root')));
  const share = buildRobocopyCommand({ ...base, mode: 'mir', destination: '\\\\nas\\backup' });
  assert.ok(share.warnings.some(w => w.includes('drive or share root')));
  const parent = buildRobocopyCommand({ ...base, mode: 'mir', source: 'C:\\Data\\Projects', destination: 'C:\\Data' });
  assert.ok(parent.warnings.some(w => w.includes('source is inside the destination')));
});

test('paths with spaces are quoted and a trailing backslash is doubled inside quotes', () => {
  const built = buildRobocopyCommand({ ...base, source: 'C:\\My Data\\', destination: '\\\\nas\\share\\My Backup', files: ['*.docx', 'year end.xlsx', ' '] });
  assert.equal(built.command, 'robocopy "C:\\My Data\\\\" "\\\\nas\\share\\My Backup" "*.docx" "year end.xlsx" /E /R:3 /W:5');
  // Without spaces nothing is quoted, and the trailing backslash stays single.
  assert.ok(buildRobocopyCommand({ ...base, source: 'C:\\Data\\' }).command.startsWith('robocopy C:\\Data\\ D:'));
});

test('exclusion lists are quoted item by item', () => {
  const built = buildRobocopyCommand({ ...base, excludeFiles: ['*.tmp', 'Thumbs.db', ''], excludeDirs: ['System Volume Information', 'node_modules'] });
  assert.ok(built.command.endsWith('/XF "*.tmp" Thumbs.db /XD "System Volume Information" node_modules'));
  assert.equal(built.parts.filter(part => part.flag.startsWith('/X')).length, 2);
});

test('/MT with /IPG warns, and both are validated', () => {
  const built = buildRobocopyCommand({ ...base, threads: '16', ipg: '50' });
  assert.ok(built.command.includes('/MT:16 /IPG:50'));
  assert.ok(built.warnings.some(w => w.includes('/MT cannot be combined with /IPG')));
  assert.deepEqual(buildRobocopyCommand({ ...base, threads: '16' }).warnings, []);
  const bad = buildRobocopyCommand({ ...base, threads: '200', ipg: 'slow', retries: '-1', wait: 'x' });
  assert.equal(bad.errors.length, 4);
  assert.ok(!bad.command.includes('200') && !bad.command.includes('slow'));
});

test('source equals destination, and destination inside source', () => {
  const same = buildRobocopyCommand({ ...base, source: 'C:\\Data\\', destination: 'c:/data' });
  assert.ok(same.warnings.some(w => w.includes('same folder')));
  const inside = buildRobocopyCommand({ ...base, destination: 'C:\\Data\\Backup' });
  assert.ok(inside.warnings.some(w => w.includes('destination is inside the source')));
  // A sibling with the same prefix is not inside.
  assert.deepEqual(buildRobocopyCommand({ ...base, destination: 'C:\\Data2' }).warnings, []);
});

test('move, copy and backup switches', () => {
  const mov = buildRobocopyCommand({ ...base, moveFiles: true });
  assert.ok(mov.command.includes('/MOV '));
  assert.ok(mov.warnings.some(w => w.includes('/MOV deletes the source files')));
  const move = buildRobocopyCommand({ ...base, moveFiles: true, moveAll: true });
  assert.ok(move.command.includes('/MOVE') && !/\/MOV(\s|$)/.test(move.command));

  assert.ok(buildRobocopyCommand({ ...base, copyFlags: 'sdat' }).command.includes('/COPY:DATS'));
  assert.ok(!buildRobocopyCommand({ ...base, copyFlags: 'TAD' }).command.includes('/COPY'));
  assert.equal(buildRobocopyCommand({ ...base, copyFlags: '' }).errors.length, 1);

  const all = buildRobocopyCommand({ ...base, copyAll: true, sec: true, dcopy: true, restartable: true, backup: true });
  assert.ok(all.command.includes('/COPYALL /DCOPY:DAT /ZB'));
  assert.ok(!all.command.includes('/SEC'));
  assert.ok(all.warnings.some(w => w === '/COPYALL and /ZB need an elevated prompt (Run as administrator).'));
  assert.ok(buildRobocopyCommand({ ...base, sec: true }).warnings.some(w => w.startsWith('/SEC needs an elevated prompt')));
  assert.ok(buildRobocopyCommand({ ...base, backup: true }).command.includes('/B '));
});

test('logging switches and missing paths', () => {
  const built = buildRobocopyCommand({ ...base, logFile: 'C:\\Logs\\my copy.log', logAppend: true, tee: true, noProgress: true });
  assert.ok(built.command.endsWith('/LOG+:"C:\\Logs\\my copy.log" /TEE /NP'));
  assert.ok(buildRobocopyCommand({ ...base, logFile: 'copy.log' }).command.endsWith('/LOG:copy.log'));
  const empty = buildRobocopyCommand({ ...base, source: ' ', destination: '' });
  assert.equal(empty.errors.length, 2);
  assert.ok(empty.command.startsWith('robocopy SOURCE DESTINATION'));
  assert.ok(buildRobocopyCommand({ ...base, retries: '', wait: '' }).warnings.some(w => w.includes('one million times')));
});

test('presets keep the paths', () => {
  const current = { ...base, source: 'E:\\Share', logFile: 'x.log' };
  const mirror = applyRobocopyPreset(current, 'mirror');
  assert.equal(mirror.mode, 'mir');
  assert.equal(mirror.source, 'E:\\Share');
  assert.equal(mirror.logFile, 'x.log');
  const test = applyRobocopyPreset(mirror, 'test');
  assert.equal(test.mode, 'mir');
  assert.equal(test.listOnly, true);
  assert.equal(applyRobocopyPreset(current, 'unknown'), current);
  for (const preset of ROBOCOPY_PRESETS) assert.deepEqual(buildRobocopyCommand(applyRobocopyPreset(base, preset.key)).errors, []);
});

test('exit codes are decoded as bit flags', () => {
  const zero = decodeRobocopyExitCode(0);
  assert.equal(zero.failure, false);
  assert.deepEqual(zero.flags, []);
  assert.match(zero.summary, /nothing needed copying/);

  const one = decodeRobocopyExitCode(1);
  assert.deepEqual(one.flags.map(flag => flag.bit), [1]);
  assert.equal(one.failure, false);

  const three = decodeRobocopyExitCode(3);
  assert.deepEqual(three.flags.map(flag => flag.bit), [1, 2]);
  assert.equal(three.failure, false);
  assert.equal(three.summary, 'Success: files copied, extra files.');

  assert.equal(decodeRobocopyExitCode(7).failure, false);

  const eight = decodeRobocopyExitCode(8);
  assert.deepEqual(eight.flags.map(flag => flag.bit), [8]);
  assert.equal(eight.failure, true);

  const sixteen = decodeRobocopyExitCode(16);
  assert.deepEqual(sixteen.flags.map(flag => flag.bit), [16]);
  assert.equal(sixteen.failure, true);

  const combined = decodeRobocopyExitCode(11);
  assert.deepEqual(combined.flags.map(flag => flag.bit), [1, 2, 8]);
  assert.equal(combined.failure, true);
  assert.match(combined.summary, /^Failure: files copied, extra files, copy failures\.$/);

  for (const bad of [-1, 32, 1.5, NaN]) assert.equal(decodeRobocopyExitCode(bad).valid, false);
});

test('script snippets map codes below 8 to success', () => {
  assert.equal(ROBOCOPY_BATCH_SNIPPET, 'if %ERRORLEVEL% GEQ 8 exit /b %ERRORLEVEL%\nexit /b 0');
  assert.equal(ROBOCOPY_POWERSHELL_SNIPPET, 'if ($LASTEXITCODE -ge 8) { exit $LASTEXITCODE } else { exit 0 }');
  assert.equal(robocopyScript('robocopy A B', 'batch').split('\n').length, 3);
  assert.ok(robocopyScript('robocopy A B', 'powershell').startsWith('robocopy A B\nif ($LASTEXITCODE'));
});
