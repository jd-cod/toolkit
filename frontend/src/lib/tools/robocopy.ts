import { cmdQuote } from './shell.ts';

export type RobocopyMode = 'none' | 'e' | 's' | 'mir';

export interface RobocopyOptions {
  source: string;
  destination: string;
  /** File names or wildcard patterns. Empty means all files. */
  files: string[];
  mode: RobocopyMode;
  purge: boolean;
  moveFiles: boolean;
  moveAll: boolean;
  /** Letters for /COPY: out of D A T S O U. */
  copyFlags: string;
  copyAll: boolean;
  sec: boolean;
  dcopy: boolean;
  restartable: boolean;
  backup: boolean;
  unbuffered: boolean;
  retries: string;
  wait: string;
  threads: string;
  ipg: string;
  fft: boolean;
  excludeJunctions: boolean;
  excludeOlder: boolean;
  excludeFiles: string[];
  excludeDirs: string[];
  listOnly: boolean;
  logFile: string;
  logAppend: boolean;
  tee: boolean;
  noProgress: boolean;
  noFileList: boolean;
  noDirList: boolean;
  verbose: boolean;
  eta: boolean;
}

export const ROBOCOPY_DEFAULTS: RobocopyOptions = {
  source: 'C:\\Data',
  destination: 'D:\\Backup\\Data',
  files: [],
  mode: 'e',
  purge: false,
  moveFiles: false,
  moveAll: false,
  copyFlags: 'DAT',
  copyAll: false,
  sec: false,
  dcopy: false,
  restartable: false,
  backup: false,
  unbuffered: false,
  retries: '3',
  wait: '5',
  threads: '',
  ipg: '',
  fft: false,
  excludeJunctions: false,
  excludeOlder: false,
  excludeFiles: [],
  excludeDirs: [],
  listOnly: false,
  logFile: '',
  logAppend: false,
  tee: false,
  noProgress: false,
  noFileList: false,
  noDirList: false,
  verbose: false,
  eta: false,
};

export interface CommandPart {
  flag: string;
  meaning: string;
}

export interface BuiltCommand {
  command: string;
  parts: CommandPart[];
  warnings: string[];
  errors: string[];
}

/** The file properties /COPY: can name, in the order robocopy documents them. */
export const COPY_FLAGS: Array<{ flag: string; label: string }> = [
  { flag: 'D', label: 'Data' },
  { flag: 'A', label: 'Attributes' },
  { flag: 'T', label: 'Timestamps' },
  { flag: 'S', label: 'NTFS permissions' },
  { flag: 'O', label: 'Owner' },
  { flag: 'U', label: 'Auditing information' },
];

export interface RobocopyPreset {
  key: string;
  label: string;
  hint: string;
  /** Applied on top of the defaults, or on top of the current options when `keep` is set. */
  options: Partial<RobocopyOptions>;
  keep?: boolean;
}

export const ROBOCOPY_PRESETS: RobocopyPreset[] = [
  { key: 'mirror', label: 'Mirror backup', hint: 'Make the destination an exact copy, deleting what is gone from the source.', options: { mode: 'mir', dcopy: true, excludeJunctions: true, noProgress: true } },
  { key: 'network', label: 'Resumable copy over a network', hint: 'Restartable mode with a few more retries.', options: { mode: 'e', restartable: true, retries: '5', wait: '10', noProgress: true } },
  { key: 'move', label: 'Move files', hint: 'Copy, then delete the source files.', options: { mode: 'e', moveFiles: true } },
  { key: 'permissions', label: 'Copy with NTFS permissions', hint: 'Keep ACLs, owner, auditing and directory timestamps.', options: { mode: 'e', copyAll: true, dcopy: true, restartable: true, backup: true } },
  { key: 'test', label: 'Test run', hint: 'Add /L to the current options so nothing is changed.', options: { listOnly: true }, keep: true },
];

/** Apply a preset. Paths, file patterns, exclusions and the log file are kept. */
export function applyRobocopyPreset(current: RobocopyOptions, key: string): RobocopyOptions {
  const preset = ROBOCOPY_PRESETS.find(item => item.key === key);
  if (!preset) return current;
  if (preset.keep) return { ...current, ...preset.options };
  return {
    ...ROBOCOPY_DEFAULTS,
    source: current.source,
    destination: current.destination,
    files: current.files,
    excludeFiles: current.excludeFiles,
    excludeDirs: current.excludeDirs,
    logFile: current.logFile,
    logAppend: current.logAppend,
    ...preset.options,
  };
}

function clean(list: string[]): string[] {
  return list.map(item => item.trim()).filter(Boolean);
}

/** Lower case, backslashes only, no trailing backslash: for comparing two paths. */
function normalizePath(path: string): string {
  return path.trim().replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase();
}

/** A drive root (C: or C:\) or the root of a share (\\server\share). */
function isRoot(path: string): boolean {
  const normal = normalizePath(path);
  return /^[a-z]:$/.test(normal) || /^\\\\[^\\]+\\[^\\]+$/.test(normal);
}

function wholeNumber(value: string, min: number, max: number): number | null {
  if (!/^\d+$/.test(value)) return null;
  const number = Number(value);
  return number >= min && number <= max ? number : null;
}

export function buildRobocopyCommand(input: RobocopyOptions): BuiltCommand {
  const o = { ...input, source: input.source.trim(), destination: input.destination.trim() };
  const args: string[] = [];
  const parts: CommandPart[] = [];
  const warnings: string[] = [];
  const errors: string[] = [];
  const add = (flag: string, meaning: string) => { args.push(flag); parts.push({ flag, meaning }); };

  if (!o.source) errors.push('Enter a source folder.');
  if (!o.destination) errors.push('Enter a destination folder.');

  const files = clean(o.files);
  const mirror = o.mode === 'mir';
  const purges = mirror || o.purge;

  // Copy mode
  if (o.mode === 'e') add('/E', 'Copy subdirectories, including empty ones.');
  if (o.mode === 's') add('/S', 'Copy subdirectories, but not empty ones.');
  if (mirror) add('/MIR', 'Mirror the tree: the same as /E with /PURGE. Deletes destination files and directories that are not in the source.');
  if (o.purge && !mirror) add('/PURGE', 'Delete destination files and directories that are not in the source.');
  if (o.moveAll) add('/MOVE', 'Move files and directories: delete them from the source after they are copied.');
  else if (o.moveFiles) add('/MOV', 'Move files: delete each source file after it is copied. Source directories stay.');

  // What to copy
  const copyFlags = COPY_FLAGS.map(item => item.flag).filter(flag => o.copyFlags.toUpperCase().includes(flag)).join('');
  if (o.copyAll) {
    add('/COPYALL', 'Copy all file information: data, attributes, timestamps, NTFS permissions, owner and auditing information. The same as /COPY:DATSOU.');
  } else if (o.sec) {
    add('/SEC', 'Copy files with their NTFS permissions. The same as /COPY:DATS.');
  } else if (!copyFlags) {
    errors.push('Pick at least one file property to copy.');
  } else if (copyFlags !== 'DAT') {
    const names = COPY_FLAGS.filter(item => copyFlags.includes(item.flag)).map(item => `${item.flag} ${item.label.toLowerCase()}`).join(', ');
    add(`/COPY:${copyFlags}`, `Copy these file properties: ${names}. Robocopy's default is DAT.`);
  }
  if (o.dcopy) add('/DCOPY:DAT', 'Copy directory data, attributes and timestamps. The default (DA) gives new directories the current time. Windows 7 and Server 2008 R2 only accept /DCOPY:T.');

  // Reliability
  if (o.restartable && o.backup) add('/ZB', 'Restartable mode, switching to backup mode when access is denied.');
  else if (o.restartable) add('/Z', 'Restartable mode: an interrupted file resumes where it stopped. Slower than a normal copy.');
  else if (o.backup) add('/B', 'Backup mode: read and write files with the backup and restore privileges, regardless of their permissions.');
  if (o.unbuffered) add('/J', 'Unbuffered I/O, recommended for very large files.');

  const retries = o.retries.trim();
  const wait = o.wait.trim();
  if (retries) {
    if (wholeNumber(retries, 0, 1000000) === null) errors.push('Retries must be a whole number.');
    else add(`/R:${retries}`, `Retry a failed copy ${retries} times. Robocopy's own default is 1,000,000.`);
  }
  if (wait) {
    if (wholeNumber(wait, 0, 1000000) === null) errors.push('Wait time must be a whole number of seconds.');
    else add(`/W:${wait}`, `Wait ${wait} seconds between retries. Robocopy's own default is 30.`);
  }
  if (!retries) warnings.push('Without /R robocopy retries a failed file one million times, 30 seconds apart by default, which looks like a hang.');

  const threads = o.threads.trim();
  const ipg = o.ipg.trim();
  let multithreaded = false;
  if (threads) {
    if (wholeNumber(threads, 1, 128) === null) errors.push('Threads must be between 1 and 128.');
    else { multithreaded = true; add(`/MT:${threads}`, `Copy with ${threads} threads (1 to 128, 8 when no number is given). Cannot be combined with /IPG.`); }
  }
  if (ipg) {
    if (wholeNumber(ipg, 1, 1000000) === null) errors.push('Inter-packet gap must be a whole number of milliseconds.');
    else {
      add(`/IPG:${ipg}`, `Wait ${ipg} milliseconds between packets to leave bandwidth free on slow links.`);
      if (multithreaded) warnings.push('/MT cannot be combined with /IPG. Remove one of them.');
    }
  }
  if (o.fft) add('/FFT', 'Assume FAT file times with two-second precision. Use it when one side is a NAS or Samba share, so unchanged files are not copied again.');
  if (o.excludeJunctions) add('/XJ', 'Exclude junction points and symbolic links, which robocopy follows by default. Prevents endless loops in user profiles.');
  if (o.excludeOlder) add('/XO', 'Exclude older files: skip a source file when the destination copy is newer.');

  const excludeFiles = clean(o.excludeFiles);
  const excludeDirs = clean(o.excludeDirs);
  if (excludeFiles.length) add(`/XF ${excludeFiles.map(cmdQuote).join(' ')}`, 'Exclude files that match these names or patterns.');
  if (excludeDirs.length) add(`/XD ${excludeDirs.map(cmdQuote).join(' ')}`, 'Exclude directories that match these names or paths.');

  // Logging
  if (o.listOnly) add('/L', 'List only: show what would be copied or deleted without changing anything.');
  const log = o.logFile.trim();
  if (log) {
    if (o.logAppend) add(`/LOG+:${cmdQuote(log)}`, `Append the output to ${log}.`);
    else add(`/LOG:${cmdQuote(log)}`, `Write the output to ${log}, replacing the file.`);
  }
  if (o.tee) add('/TEE', 'Write the output to the console as well as the log file.');
  if (o.noProgress) add('/NP', 'No progress: do not print the percentage copied. Keeps log files small.');
  if (o.noFileList) add('/NFL', 'No file list: do not log file names.');
  if (o.noDirList) add('/NDL', 'No directory list: do not log directory names.');
  if (o.verbose) add('/V', 'Verbose output, including skipped files.');
  if (o.eta) add('/ETA', 'Show the estimated time of arrival for each file.');

  // Warnings
  const deleteSwitch = mirror ? '/MIR' : '/PURGE';
  if (purges && !o.listOnly) warnings.push(`${deleteSwitch} deletes destination files that are not in the source, run with /L first.`);
  if (o.purge && mirror) warnings.push('/MIR already includes /PURGE, so /PURGE is left out.');
  if (o.moveFiles && o.moveAll) warnings.push('/MOVE already includes /MOV, so /MOV is left out.');
  if ((o.moveFiles || o.moveAll) && !o.listOnly) {
    warnings.push(`${o.moveAll ? '/MOVE deletes the source files and directories' : '/MOV deletes the source files'} after copying. Run with /L first.`);
  }

  const source = normalizePath(o.source);
  const destination = normalizePath(o.destination);
  if (source && destination) {
    if (source === destination) {
      warnings.push('Source and destination are the same folder.');
    } else if (destination.startsWith(`${source}\\`)) {
      warnings.push('The destination is inside the source, so robocopy would copy the folder into itself. Exclude it with /XD or pick another destination.');
    } else if (source.startsWith(`${destination}\\`) && purges) {
      warnings.push(`The source is inside the destination. ${deleteSwitch} would delete everything else there, and can delete the source folder itself.`);
    }
  }
  if (purges && o.destination && isRoot(o.destination)) {
    warnings.push(`The destination is a drive or share root. ${deleteSwitch} deletes everything there that is not in the source. Use a dedicated folder that holds no other data.`);
  }
  if (/^[a-z]:$/.test(source)) {
    warnings.push('The source is a drive root. Exclude "System Volume Information" and $RECYCLE.BIN with /XD. The destination folder can end up hidden, clear that with attrib -s -h.');
  }

  const elevated = [o.copyAll ? '/COPYALL' : o.sec ? '/SEC' : '', o.backup ? (o.restartable ? '/ZB' : '/B') : ''].filter(Boolean);
  if (elevated.length) warnings.push(`${elevated.join(' and ')} ${elevated.length > 1 ? 'need' : 'needs'} an elevated prompt (Run as administrator).`);
  if (o.tee && !log) warnings.push('/TEE has no effect without a log file.');
  if (o.listOnly) warnings.push('This is a test run. Remove /L to copy for real.');

  const command = ['robocopy', cmdQuote(o.source || 'SOURCE'), cmdQuote(o.destination || 'DESTINATION'), ...files.map(cmdQuote), ...args].join(' ');
  return { command, parts, warnings, errors };
}

export interface ExitCodeFlag {
  bit: number;
  label: string;
  meaning: string;
}

/** Robocopy exit codes are bit flags that add up. */
export const ROBOCOPY_EXIT_FLAGS: ExitCodeFlag[] = [
  { bit: 1, label: 'Files copied', meaning: 'One or more files were copied.' },
  { bit: 2, label: 'Extra files', meaning: 'Extra files or directories exist at the destination that are not in the source. Nothing is wrong with the copy.' },
  { bit: 4, label: 'Mismatches', meaning: 'Mismatched files or directories were found, such as a file where the source has a directory. Worth a look at the log.' },
  { bit: 8, label: 'Copy failures', meaning: 'Some files or directories could not be copied, the retry limit was reached. Check the log.' },
  { bit: 16, label: 'Fatal error', meaning: 'Robocopy copied nothing: a usage error, or no access to the source or destination.' },
];

export interface DecodedExitCode {
  code: number;
  valid: boolean;
  flags: ExitCodeFlag[];
  summary: string;
  failure: boolean;
}

export function decodeRobocopyExitCode(code: number): DecodedExitCode {
  if (!Number.isInteger(code) || code < 0 || code > 31) {
    return { code, valid: false, flags: [], summary: 'Robocopy exit codes are whole numbers from 0 to 31.', failure: false };
  }
  const flags = ROBOCOPY_EXIT_FLAGS.filter(flag => (code & flag.bit) !== 0);
  const failure = code >= 8;
  if (code === 0) {
    return { code, valid: true, flags, summary: 'Success: nothing needed copying. Source and destination are already in sync.', failure };
  }
  const list = flags.map(flag => flag.label.toLowerCase()).join(', ');
  return { code, valid: true, flags, summary: `${failure ? 'Failure' : 'Success'}: ${list}.`, failure };
}

/** Lines to put after the robocopy command in a script. Schedulers treat exit code 1 as a failure, so codes below 8 are turned into 0. */
export const ROBOCOPY_BATCH_SNIPPET = 'if %ERRORLEVEL% GEQ 8 exit /b %ERRORLEVEL%\nexit /b 0';
export const ROBOCOPY_POWERSHELL_SNIPPET = 'if ($LASTEXITCODE -ge 8) { exit $LASTEXITCODE } else { exit 0 }';

/** The command followed by the exit code handling for a batch file or a PowerShell script. */
export function robocopyScript(command: string, shell: 'batch' | 'powershell'): string {
  return `${command}\n${shell === 'batch' ? ROBOCOPY_BATCH_SNIPPET : ROBOCOPY_POWERSHELL_SNIPPET}`;
}
