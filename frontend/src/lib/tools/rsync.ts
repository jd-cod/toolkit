import { shQuote } from './shell.ts';

export interface RsyncOptions {
  source: string;
  destination: string;
  archive: boolean;
  verbose: boolean;
  compress: boolean;
  humanReadable: boolean;
  progress: boolean;
  dryRun: boolean;
  delete: boolean;
  deleteExcluded: boolean;
  partial: boolean;
  checksum: boolean;
  update: boolean;
  hardLinks: boolean;
  acls: boolean;
  xattrs: boolean;
  numericIds: boolean;
  oneFileSystem: boolean;
  removeSourceFiles: boolean;
  sudoRemote: boolean;
  sshPort: string;
  sshKey: string;
  bwLimit: string;
  excludes: string[];
  logFile: string;
}

export const RSYNC_DEFAULTS: RsyncOptions = {
  source: '/var/www/',
  destination: 'backup@backup.example.com:/srv/backups/www/',
  archive: true,
  verbose: true,
  compress: true,
  humanReadable: true,
  progress: false,
  dryRun: true,
  delete: false,
  deleteExcluded: false,
  partial: false,
  checksum: false,
  update: false,
  hardLinks: false,
  acls: false,
  xattrs: false,
  numericIds: false,
  oneFileSystem: false,
  removeSourceFiles: false,
  sudoRemote: false,
  sshPort: '',
  sshKey: '',
  bwLimit: '',
  excludes: [],
  logFile: '',
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

function isRemote(path: string): boolean {
  // host:path or user@host:path, but not a Windows drive (C:\) or a local path containing a colon after a slash.
  return /^[^/\s:]+:/.test(path) && !/^[A-Za-z]:[\\/]/.test(path);
}

export function buildRsyncCommand(input: RsyncOptions): BuiltCommand {
  const o = { ...input, source: input.source.trim(), destination: input.destination.trim() };
  const args: string[] = [];
  const parts: CommandPart[] = [];
  const warnings: string[] = [];
  const errors: string[] = [];
  const add = (flag: string, meaning: string) => { args.push(flag); parts.push({ flag, meaning }); };

  if (!o.source) errors.push('Enter a source path.');
  if (!o.destination) errors.push('Enter a destination path.');

  const sourceRemote = isRemote(o.source);
  const destRemote = isRemote(o.destination);
  const remote = sourceRemote || destRemote;
  if (sourceRemote && destRemote) errors.push('rsync cannot copy between two remote hosts. Run it on one of them.');

  if (o.archive) add('-a', 'Archive mode: recurse and keep permissions, times, owner, group and symlinks.');
  else add('-r', 'Recurse into directories. Without archive mode, permissions, times and owners are not kept.');
  if (o.verbose) add('-v', 'List each file as it is transferred.');
  if (o.compress) add('-z', 'Compress data in transit. Helps on slow links, costs CPU on fast ones.');
  if (o.humanReadable) add('-h', 'Show sizes in K, M and G.');
  if (o.hardLinks) add('-H', 'Keep hard links. Slower and uses more memory on large trees.');
  if (o.acls) add('-A', 'Keep ACLs.');
  if (o.xattrs) add('-X', 'Keep extended attributes, including SELinux labels.');
  if (o.checksum) add('-c', 'Compare files by checksum instead of size and time. Much slower.');
  if (o.update) add('-u', 'Skip files that are newer on the destination.');
  if (o.oneFileSystem) add('-x', 'Do not cross into other mounted filesystems.');
  if (o.numericIds) add('--numeric-ids', 'Keep numeric user and group IDs instead of mapping by name.');
  if (o.progress) add('--info=progress2', 'Show overall progress for the whole transfer.');
  if (o.partial) add('--partial', 'Keep partly transferred files so an interrupted copy can resume.');
  if (o.dryRun) add('--dry-run', 'Show what would be done without changing anything.');
  if (o.delete) add('--delete', 'Delete destination files that do not exist in the source.');
  if (o.deleteExcluded) add('--delete-excluded', 'Also delete excluded files from the destination.');
  if (o.removeSourceFiles) add('--remove-source-files', 'Delete each source file after it is transferred (a move).');

  const bw = o.bwLimit.trim();
  if (bw) {
    if (/^\d+$/.test(bw) && Number(bw) > 0) add(`--bwlimit=${bw}`, `Limit transfer speed to ${bw} KiB per second.`);
    else errors.push('Bandwidth limit must be a whole number of KiB per second.');
  }

  for (const pattern of o.excludes.map(item => item.trim()).filter(Boolean)) {
    add(`--exclude=${shQuote(pattern)}`, `Skip paths matching ${pattern}.`);
  }

  const log = o.logFile.trim();
  if (log) add(`--log-file=${shQuote(log)}`, `Write a log of the transfer to ${log}.`);

  const port = o.sshPort.trim();
  const key = o.sshKey.trim();
  if (port && !(/^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535)) {
    errors.push('SSH port must be between 1 and 65535.');
  } else if (port || key) {
    const ssh = ['ssh', ...(port ? ['-p', port] : []), ...(key ? ['-i', shQuote(key)] : [])].join(' ');
    add(`-e ${shQuote(ssh)}`, `Connect with ${ssh}.`);
    if (!remote) warnings.push('SSH options are set but neither path is remote (user@host:/path).');
  }

  if (o.sudoRemote) {
    add(`--rsync-path=${shQuote('sudo rsync')}`, 'Run rsync with sudo on the remote host. Needs passwordless sudo for rsync there.');
    if (!remote) warnings.push('Remote sudo is set but neither path is remote.');
  }

  if (o.delete && !o.dryRun) warnings.push('--delete removes files from the destination. Run once with --dry-run first.');
  if (o.deleteExcluded && !o.delete) warnings.push('--delete-excluded has no effect without --delete.');
  if (o.removeSourceFiles && !o.dryRun) warnings.push('--remove-source-files deletes the source files after copying.');
  if (o.source && !o.source.endsWith('/')) {
    warnings.push('The source has no trailing slash, so the directory itself is created inside the destination. Add / to copy only its contents.');
  }
  if (o.dryRun) warnings.push('This is a dry run. Remove --dry-run to copy for real.');

  const command = ['rsync', ...args, shQuote(o.source || 'SOURCE'), shQuote(o.destination || 'DESTINATION')].join(' ');
  return { command, parts, warnings, errors };
}
