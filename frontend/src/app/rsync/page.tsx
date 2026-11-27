'use client';

import { useState } from 'react';
import ToolPage from '@/components/ToolPage';
import { CodeBlock, DataTable, Field, FindingList, Panel, TextArea, TextInput, Toggle, type Finding } from '@/components/ToolUi';
import { buildRsyncCommand, RSYNC_DEFAULTS, type RsyncOptions } from '@/lib/tools/rsync';

type FlagKey = {
  [K in keyof RsyncOptions]: RsyncOptions[K] extends boolean ? K : never;
}[keyof RsyncOptions];

const FLAGS: Array<{ key: FlagKey; label: string; hint: string; danger?: boolean }> = [
  { key: 'archive', label: 'Archive (-a)', hint: 'Keep permissions, times, owners and symlinks' },
  { key: 'verbose', label: 'Verbose (-v)', hint: 'List transferred files' },
  { key: 'compress', label: 'Compress (-z)', hint: 'Compress data in transit' },
  { key: 'humanReadable', label: 'Readable sizes (-h)', hint: 'Show K, M and G' },
  { key: 'progress', label: 'Progress', hint: 'Overall transfer progress' },
  { key: 'dryRun', label: 'Dry run (--dry-run)', hint: 'Change nothing, only report' },
  { key: 'partial', label: 'Keep partial files', hint: 'Resume interrupted transfers' },
  { key: 'update', label: 'Skip newer (-u)', hint: 'Keep files that are newer on the destination' },
  { key: 'checksum', label: 'Checksum (-c)', hint: 'Compare by content, slower' },
  { key: 'hardLinks', label: 'Hard links (-H)', hint: 'Keep hard links' },
  { key: 'acls', label: 'ACLs (-A)', hint: 'Keep access control lists' },
  { key: 'xattrs', label: 'Extended attributes (-X)', hint: 'Keep xattrs and SELinux labels' },
  { key: 'numericIds', label: 'Numeric IDs', hint: 'Do not map users by name' },
  { key: 'oneFileSystem', label: 'One filesystem (-x)', hint: 'Do not cross mount points' },
  { key: 'sudoRemote', label: 'Remote sudo', hint: 'Run rsync with sudo on the remote host' },
  { key: 'delete', label: 'Delete extra files', hint: 'Remove destination files missing from the source', danger: true },
  { key: 'deleteExcluded', label: 'Delete excluded', hint: 'Also remove excluded files from the destination', danger: true },
  { key: 'removeSourceFiles', label: 'Remove source files', hint: 'Delete source files after copying', danger: true },
];

export default function RsyncPage() {
  const [options, setOptions] = useState<RsyncOptions>(RSYNC_DEFAULTS);
  const [excludeText, setExcludeText] = useState('');
  const set = <K extends keyof RsyncOptions>(key: K, value: RsyncOptions[K]) => setOptions(current => ({ ...current, [key]: value }));

  const built = buildRsyncCommand({ ...options, excludes: excludeText.split('\n') });
  const findings: Finding[] = [
    ...built.errors.map(title => ({ severity: 'critical' as const, title })),
    ...built.warnings.map(title => ({ severity: 'warning' as const, title })),
  ];

  return (
    <ToolPage tool="rsync" title="rsync Command Builder" icon="bi-arrow-repeat" lead="Pick the options you need and copy a command with every flag explained.">
      <Panel title="Paths" icon="bi-folder2-open">
        <div className="tk-form-grid">
          <Field label="Source" hint="A trailing slash copies the contents, not the directory.">
            <TextInput mono value={options.source} onChange={event => set('source', event.target.value)} placeholder="/var/www/" />
          </Field>
          <Field label="Destination" hint="Use user@host:/path for a remote server.">
            <TextInput mono value={options.destination} onChange={event => set('destination', event.target.value)} placeholder="user@host:/srv/backup/" />
          </Field>
          <Field label="SSH port" hint="Leave empty for port 22.">
            <TextInput mono inputMode="numeric" value={options.sshPort} onChange={event => set('sshPort', event.target.value)} placeholder="22" />
          </Field>
          <Field label="SSH key file">
            <TextInput mono value={options.sshKey} onChange={event => set('sshKey', event.target.value)} placeholder="~/.ssh/id_ed25519" />
          </Field>
          <Field label="Bandwidth limit (KiB/s)">
            <TextInput mono inputMode="numeric" value={options.bwLimit} onChange={event => set('bwLimit', event.target.value)} placeholder="No limit" />
          </Field>
          <Field label="Log file">
            <TextInput mono value={options.logFile} onChange={event => set('logFile', event.target.value)} placeholder="/var/log/rsync-backup.log" />
          </Field>
        </div>
      </Panel>

      <Panel title="Options" icon="bi-sliders">
        <div className="tk-toggle-grid">
          {FLAGS.map(flag => (
            <Toggle key={flag.key} label={flag.label} hint={flag.hint} danger={flag.danger} checked={options[flag.key]} onChange={next => set(flag.key, next)} />
          ))}
        </div>
      </Panel>

      <Panel title="Exclude patterns" icon="bi-funnel">
        <Field label="One pattern per line">
          <TextArea value={excludeText} onChange={event => setExcludeText(event.target.value)} placeholder={'node_modules/\n*.log\n.cache/'} style={{ minHeight: 96 }} />
        </Field>
      </Panel>

      <Panel title="Command" icon="bi-terminal">
        <FindingList findings={findings} />
        <div style={{ marginTop: findings.length ? '1rem' : 0 }}>
          <CodeBlock label="rsync" code={built.command} />
        </div>
      </Panel>

      <Panel title="What each flag does" icon="bi-list-check" flush>
        <DataTable head={['Flag', 'Meaning']} rows={built.parts.map(part => [<code key="flag" className="tk-mono">{part.flag}</code>, part.meaning])} />
      </Panel>
    </ToolPage>
  );
}
