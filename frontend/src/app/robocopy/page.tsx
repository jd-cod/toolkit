'use client';

import { useState } from 'react';
import ToolPage from '@/components/ToolPage';
import { Badge, CodeBlock, DataTable, Field, FindingList, Panel, Select, TextArea, TextInput, Toggle, type Finding } from '@/components/ToolUi';
import {
  applyRobocopyPreset,
  buildRobocopyCommand,
  COPY_FLAGS,
  decodeRobocopyExitCode,
  ROBOCOPY_DEFAULTS,
  ROBOCOPY_EXIT_FLAGS,
  ROBOCOPY_PRESETS,
  robocopyScript,
  type RobocopyMode,
  type RobocopyOptions,
} from '@/lib/tools/robocopy';

type FlagKey = {
  [K in keyof RobocopyOptions]: RobocopyOptions[K] extends boolean ? K : never;
}[keyof RobocopyOptions];

interface Flag { key: FlagKey; label: string; hint: string; danger?: boolean }

const MODES: Array<{ value: RobocopyMode; label: string }> = [
  { value: 'e', label: 'Subdirectories, including empty ones (/E)' },
  { value: 's', label: 'Subdirectories, without empty ones (/S)' },
  { value: 'mir', label: 'Mirror, deletes extra destination files (/MIR)' },
  { value: 'none', label: 'Top level only' },
];

const MODE_FLAGS: Flag[] = [
  { key: 'purge', label: 'Purge (/PURGE)', hint: 'Delete destination files that are not in the source', danger: true },
  { key: 'moveFiles', label: 'Move files (/MOV)', hint: 'Delete source files after copying', danger: true },
  { key: 'moveAll', label: 'Move files and directories (/MOVE)', hint: 'Delete source files and directories after copying', danger: true },
];

const COPY_OPTIONS: Flag[] = [
  { key: 'copyAll', label: 'Everything (/COPYALL)', hint: 'Data, attributes, times, permissions, owner and auditing' },
  { key: 'sec', label: 'With permissions (/SEC)', hint: 'Data, attributes, times and NTFS permissions' },
  { key: 'dcopy', label: 'Directory timestamps (/DCOPY:DAT)', hint: 'Keep the times of directories too' },
];

const RELIABILITY_FLAGS: Flag[] = [
  { key: 'restartable', label: 'Restartable (/Z)', hint: 'Resume an interrupted file, slower' },
  { key: 'backup', label: 'Backup mode (/B)', hint: 'Copy files regardless of their permissions, needs elevation' },
  { key: 'unbuffered', label: 'Unbuffered I/O (/J)', hint: 'For very large files' },
  { key: 'fft', label: 'Two-second times (/FFT)', hint: 'For NAS and Samba targets' },
  { key: 'excludeJunctions', label: 'Skip junctions (/XJ)', hint: 'Recommended for user profiles' },
  { key: 'excludeOlder', label: 'Skip older (/XO)', hint: 'Keep files that are newer on the destination' },
];

const LOG_FLAGS: Flag[] = [
  { key: 'listOnly', label: 'Test run (/L)', hint: 'List only, change nothing' },
  { key: 'logAppend', label: 'Append to log (/LOG+)', hint: 'Keep earlier runs in the log file' },
  { key: 'tee', label: 'Console and log (/TEE)', hint: 'Also print the output to the console' },
  { key: 'noProgress', label: 'No progress (/NP)', hint: 'No percentage lines, keeps logs small' },
  { key: 'noFileList', label: 'No file list (/NFL)', hint: 'Do not log file names' },
  { key: 'noDirList', label: 'No directory list (/NDL)', hint: 'Do not log directory names' },
  { key: 'verbose', label: 'Verbose (/V)', hint: 'Also list skipped files' },
  { key: 'eta', label: 'Estimated time (/ETA)', hint: 'Show when each file should finish' },
];

const lines = (text: string) => text.split(/[\n,]/);

export default function RobocopyPage() {
  const [options, setOptions] = useState<RobocopyOptions>(ROBOCOPY_DEFAULTS);
  const [filesText, setFilesText] = useState('');
  const [excludeFilesText, setExcludeFilesText] = useState('');
  const [excludeDirsText, setExcludeDirsText] = useState('');
  const [exitCode, setExitCode] = useState('3');
  const set = <K extends keyof RobocopyOptions>(key: K, value: RobocopyOptions[K]) => setOptions(current => ({ ...current, [key]: value }));

  const toggleCopyFlag = (flag: string) => setOptions(current => ({
    ...current,
    copyFlags: current.copyFlags.includes(flag) ? current.copyFlags.replace(flag, '') : current.copyFlags + flag,
  }));

  const built = buildRobocopyCommand({ ...options, files: lines(filesText), excludeFiles: lines(excludeFilesText), excludeDirs: lines(excludeDirsText) });
  const findings: Finding[] = [
    ...built.errors.map(title => ({ severity: 'critical' as const, title })),
    ...built.warnings.map(title => ({ severity: 'warning' as const, title })),
  ];

  const decoded = decodeRobocopyExitCode(exitCode.trim() === '' ? NaN : Number(exitCode));
  const exitFinding: Finding = {
    severity: !decoded.valid ? 'info' : decoded.failure ? 'critical' : decoded.code >= 4 ? 'warning' : 'ok',
    title: decoded.valid ? `Exit code ${decoded.code}` : 'Not a robocopy exit code',
    detail: decoded.summary,
  };

  const toggles = (flags: Flag[]) => (
    <div className="tk-toggle-grid">
      {flags.map(flag => (
        <Toggle key={flag.key} label={flag.label} hint={flag.hint} danger={flag.danger} checked={options[flag.key]} onChange={next => set(flag.key, next)} />
      ))}
    </div>
  );

  return (
    <ToolPage tool="robocopy" title="Robocopy Command Builder" icon="bi-copy" lead="Pick the options you need and copy a command with every switch explained.">
      <Panel title="Presets" icon="bi-lightning">
        <div className="tk-chip-row">
          {ROBOCOPY_PRESETS.map(preset => (
            <button key={preset.key} type="button" className="tk-chip" title={preset.hint} onClick={() => setOptions(current => applyRobocopyPreset(current, preset.key))}>
              {preset.label}
            </button>
          ))}
        </div>
      </Panel>

      <Panel title="Paths" icon="bi-folder2-open">
        <div className="tk-form-grid">
          <Field label="Source" hint="A folder, not a file. UNC paths such as \\server\share\folder work too.">
            <TextInput mono value={options.source} onChange={event => set('source', event.target.value)} placeholder="C:\Data" />
          </Field>
          <Field label="Destination" hint="Created when it does not exist.">
            <TextInput mono value={options.destination} onChange={event => set('destination', event.target.value)} placeholder="D:\Backup\Data" />
          </Field>
          <Field label="Files" hint="Names or patterns separated by commas. Leave empty for all files.">
            <TextInput mono value={filesText} onChange={event => setFilesText(event.target.value)} placeholder="*.docx, *.xlsx" />
          </Field>
        </div>
      </Panel>

      <Panel title="Copy mode" icon="bi-diagram-2">
        <div className="tk-form-grid" style={{ marginBottom: '1rem' }}>
          <Field label="Subdirectories">
            <Select value={options.mode} onChange={event => set('mode', event.target.value as RobocopyMode)}>
              {MODES.map(mode => <option key={mode.value} value={mode.value}>{mode.label}</option>)}
            </Select>
          </Field>
        </div>
        {toggles(MODE_FLAGS)}
      </Panel>

      <Panel title="What to copy" icon="bi-file-earmark-check">
        <p className="tk-note">File properties for /COPY. Robocopy copies data, attributes and timestamps by default. /COPYALL and /SEC replace this selection.</p>
        <div className="tk-chip-row" role="group" aria-label="File properties to copy" style={{ marginBottom: '1rem' }}>
          {COPY_FLAGS.map(item => (
            <button key={item.flag} type="button" className="tk-chip" aria-pressed={options.copyFlags.includes(item.flag)} onClick={() => toggleCopyFlag(item.flag)}>
              {item.flag} · {item.label}
            </button>
          ))}
        </div>
        {toggles(COPY_OPTIONS)}
      </Panel>

      <Panel title="Reliability and filters" icon="bi-shield-check">
        <p className="tk-note">Robocopy on its own retries a failed file one million times and waits 30 seconds each time, which looks like a hang. This builder uses 3 retries and 5 seconds.</p>
        <div className="tk-form-grid" style={{ marginBottom: '1rem' }}>
          <Field label="Retries (/R)">
            <TextInput mono inputMode="numeric" value={options.retries} onChange={event => set('retries', event.target.value)} placeholder="1000000" />
          </Field>
          <Field label="Wait in seconds (/W)">
            <TextInput mono inputMode="numeric" value={options.wait} onChange={event => set('wait', event.target.value)} placeholder="30" />
          </Field>
          <Field label="Threads (/MT)" hint="1 to 128. Leave empty for a single thread.">
            <TextInput mono inputMode="numeric" value={options.threads} onChange={event => set('threads', event.target.value)} placeholder="Off" />
          </Field>
          <Field label="Throttle in ms (/IPG)" hint="Gap between packets. Not with /MT.">
            <TextInput mono inputMode="numeric" value={options.ipg} onChange={event => set('ipg', event.target.value)} placeholder="Off" />
          </Field>
        </div>
        {toggles(RELIABILITY_FLAGS)}
        <div className="tk-form-grid" style={{ marginTop: '1rem' }}>
          <Field label="Exclude files (/XF)" hint="One name or pattern per line.">
            <TextArea value={excludeFilesText} onChange={event => setExcludeFilesText(event.target.value)} placeholder={'*.tmp\nThumbs.db'} style={{ minHeight: 84 }} />
          </Field>
          <Field label="Exclude directories (/XD)" hint="One name or path per line.">
            <TextArea value={excludeDirsText} onChange={event => setExcludeDirsText(event.target.value)} placeholder={'node_modules\nSystem Volume Information'} style={{ minHeight: 84 }} />
          </Field>
        </div>
      </Panel>

      <Panel title="Logging" icon="bi-journal-text">
        <div className="tk-form-grid" style={{ marginBottom: '1rem' }}>
          <Field label="Log file (/LOG)" hint="Leave empty to print to the console only.">
            <TextInput mono value={options.logFile} onChange={event => set('logFile', event.target.value)} placeholder="C:\Logs\robocopy.log" />
          </Field>
        </div>
        {toggles(LOG_FLAGS)}
      </Panel>

      <Panel title="Command" icon="bi-terminal">
        <FindingList findings={findings} />
        <div style={{ marginTop: findings.length ? '1rem' : 0 }}>
          <CodeBlock label="robocopy" code={built.command} />
        </div>
      </Panel>

      <Panel title="What each switch does" icon="bi-list-check" flush>
        <DataTable
          head={['Switch', 'Meaning']}
          rows={built.parts.map(part => [<code key="flag" className="tk-mono" style={{ overflowWrap: 'normal', wordBreak: 'normal' }}>{part.flag}</code>, <div key="meaning" style={{ minWidth: '14rem' }}>{part.meaning}</div>])}
          empty="No switches: only the files in the top level of the source are copied."
        />
      </Panel>

      <Panel title="Exit codes" icon="bi-123">
        <p className="tk-note">Robocopy exit codes are bit flags that add up. Any value below 8 is a success, 8 or higher means at least one failure. Schedulers and CI tools treat 1 as a failure, so scripts should map the code.</p>
        <div className="tk-form-grid" style={{ marginBottom: '1rem' }}>
          <Field label="Exit code to decode" hint="The value of %ERRORLEVEL% or $LASTEXITCODE after the run.">
            <TextInput mono type="number" min={0} max={31} value={exitCode} onChange={event => setExitCode(event.target.value)} />
          </Field>
        </div>
        <FindingList findings={[exitFinding]} />
        <div style={{ margin: '1rem 0' }}>
          <DataTable
            head={['Value', 'Flag', 'Meaning', 'In this code']}
            rows={ROBOCOPY_EXIT_FLAGS.map(flag => {
              const on = decoded.flags.some(item => item.bit === flag.bit);
              return [<code key="bit" className="tk-mono">{flag.bit}</code>, <span key="label" style={{ whiteSpace: 'nowrap' }}>{flag.label}</span>, <div key="meaning" style={{ minWidth: '14rem' }}>{flag.meaning}</div>, <Badge key="set" tone={on ? (flag.bit >= 8 ? 'bad' : 'ok') : 'muted'}>{on ? 'Set' : 'Not set'}</Badge>];
            })}
          />
        </div>
        <CodeBlock label="Batch file" code={robocopyScript(built.command, 'batch')} />
        <CodeBlock label="PowerShell" code={robocopyScript(built.command, 'powershell')} />
      </Panel>
    </ToolPage>
  );
}
