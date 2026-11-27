'use client';

import { useState } from 'react';
import ToolPage from '@/components/ToolPage';
import { Badge, CodeBlock, DataTable, Field, FindingList, Panel, Select, TextInput, Toggle, type Finding } from '@/components/ToolUi';
import { useHydrated } from '@/hooks/useHydrated';
import { buildUnits, cronToOnCalendar, nextRuns, UNIT_DEFAULTS, type TimerScope, type UnitOptions } from '@/lib/tools/systemd-timer';

const PRESETS = [
  { label: 'Every 15 minutes', expr: '*/15 * * * *' },
  { label: 'Hourly', expr: '@hourly' },
  { label: 'Daily at 03:00', expr: '0 3 * * *' },
  { label: 'Weekdays at 09:00', expr: '0 9 * * 1-5' },
  { label: 'Sundays at 02:30', expr: '30 2 * * 0' },
  { label: '1st and 15th', expr: '30 2 1,15 * *' },
  { label: 'First of the month', expr: '@monthly' },
  { label: 'At boot', expr: '@reboot' },
];

const CRON_DIFFERENCES: Finding[] = [
  { severity: 'info', title: 'No MAILTO', detail: 'Output is not mailed. It goes to the journal: read it with journalctl -u and the service name.' },
  { severity: 'info', title: 'Missed runs', detail: 'With Persistent=true a job missed while the machine was off runs after the next boot. cron skips it.' },
  { severity: 'info', title: 'No shell, no crontab environment', detail: 'ExecStart is not run by a shell and does not get the PATH or variables set in a crontab. Use absolute paths.' },
  { severity: 'info', title: 'No overlap', detail: 'A timer does not start the service again while the previous run is still going.' },
];

const RUN_FORMAT: Intl.DateTimeFormatOptions = { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };

function timeUntil(run: Date, now: Date): string {
  const minutes = Math.max(1, Math.round((run.getTime() - now.getTime()) / 60000));
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} h ${minutes % 60} min`;
  return `${Math.floor(hours / 24)} days`;
}

type UnitForm = Omit<UnitOptions, 'onCalendar' | 'onBootSec'>;

export default function SystemdTimerPage() {
  const hydrated = useHydrated();
  const [cron, setCron] = useState('0 3 * * *');
  const [bootDelay, setBootDelay] = useState('1min');
  const [form, setForm] = useState<UnitForm>(UNIT_DEFAULTS);
  // The preview is relative to the last edit of the schedule, not to every render.
  const [now, setNow] = useState(() => new Date());
  const set = <K extends keyof UnitForm>(key: K, value: UnitForm[K]) => setForm(current => ({ ...current, [key]: value }));
  const changeCron = (value: string) => {
    setCron(value);
    setNow(new Date());
  };

  const conversion = cronToOnCalendar(cron, bootDelay);
  const atBoot = cron.trim().toLowerCase() === '@reboot';
  const runs = hydrated && conversion.valid && !atBoot ? nextRuns(cron, 5, now) : [];
  const built = buildUnits({ ...form, onCalendar: conversion.onCalendar, onBootSec: conversion.onBootSec });

  const scheduleLines = conversion.onBootSec ? [`OnBootSec=${conversion.onBootSec}`] : conversion.onCalendar.map(line => `OnCalendar=${line}`);
  const unitFindings: Finding[] = [
    ...built.errors.map(title => ({ severity: 'critical' as const, title })),
    ...built.warnings.map(title => ({ severity: 'warning' as const, title })),
    ...built.notes.map(title => ({ severity: 'info' as const, title })),
  ];

  let runsEmpty = 'Working out the next runs.';
  if (!conversion.valid) runsEmpty = 'Enter a valid cron expression to see the next runs.';
  else if (atBoot) runsEmpty = 'The job runs once after each boot, so there are no calendar times to show.';
  else if (hydrated) runsEmpty = 'No run in the next 8 years. This schedule never matches a real date.';

  return (
    <ToolPage tool="systemd-timer" title="systemd Timer Generator" icon="bi-stopwatch" lead="Turn a cron schedule into an OnCalendar expression and ready-to-install timer and service units.">
      <Panel
        title="Schedule"
        icon="bi-calendar-week"
        actions={<span role="status"><Badge tone={conversion.valid ? 'ok' : 'bad'}>{conversion.valid ? 'Valid' : 'Invalid'}</Badge></span>}
      >
        <div className="tk-form">
          <Field label="Cron expression" hint="Five fields: minute, hour, day of month, month, day of week. Macros such as @daily and @reboot also work." grow>
            <TextInput mono value={cron} onChange={event => changeCron(event.target.value)} placeholder="0 3 * * *" aria-invalid={!conversion.valid} />
          </Field>
          {atBoot && (
            <Field label="Delay after boot" hint="A time span such as 30s, 1min or 5min.">
              <TextInput mono value={bootDelay} onChange={event => setBootDelay(event.target.value)} placeholder="1min" />
            </Field>
          )}
        </div>
        <div className="tk-chip-row" role="group" aria-label="Schedule presets" style={{ margin: '1rem 0' }}>
          {PRESETS.map(preset => (
            <button key={preset.expr} type="button" className="tk-chip" aria-pressed={cron.trim() === preset.expr} onClick={() => changeCron(preset.expr)}>
              {preset.label}
            </button>
          ))}
        </div>
        <FindingList findings={[
          ...conversion.errors.map(title => ({ severity: 'critical' as const, title })),
          ...conversion.notes.map(title => ({ severity: 'info' as const, title })),
        ]} />
        {conversion.valid && (
          <div style={{ marginTop: conversion.notes.length ? '1rem' : 0 }}>
            <CodeBlock label="Timer schedule" code={scheduleLines.join('\n')} />
          </div>
        )}
      </Panel>

      <Panel title="Next 5 runs" icon="bi-clock-history" flush>
        <DataTable
          head={['Run', 'Date and time (browser time zone)', 'Starts in']}
          rows={runs.map((run, index) => [index + 1, <span key="when" className="tk-mono">{run.toLocaleString(undefined, RUN_FORMAT)}</span>, timeUntil(run, now)])}
          empty={runsEmpty}
        />
      </Panel>

      <Panel title="Job" icon="bi-gear">
        <div style={{ marginBottom: 14 }}>
          <Field label="Command" hint="Use the full path of the program. Pipes, redirects and && are wrapped in /bin/sh -c for you.">
            <TextInput mono value={form.command} onChange={event => set('command', event.target.value)} placeholder="/usr/local/bin/backup.sh" />
          </Field>
        </div>
        <div className="tk-form-grid">
          <Field label="Unit name" hint="Without .timer or .service.">
            <TextInput mono value={form.name} onChange={event => set('name', event.target.value)} placeholder="nightly-backup" />
          </Field>
          <Field label="Description">
            <TextInput value={form.description} onChange={event => set('description', event.target.value)} placeholder="Nightly backup" />
          </Field>
          <Field label="Scope" hint="A user timer needs no root and runs as you.">
            <Select value={form.scope} onChange={event => set('scope', event.target.value as TimerScope)}>
              <option value="system">System (root installs it)</option>
              <option value="user">User (systemctl --user)</option>
            </Select>
          </Field>
          <Field label="Run as user" hint="System scope only. Empty runs as root.">
            <TextInput mono value={form.user} onChange={event => set('user', event.target.value)} placeholder="root" />
          </Field>
          <Field label="Working directory">
            <TextInput mono value={form.workingDirectory} onChange={event => set('workingDirectory', event.target.value)} placeholder="/srv/app" />
          </Field>
          <Field label="Random delay" hint="RandomizedDelaySec: spreads the start, for example 5min.">
            <TextInput mono value={form.randomizedDelaySec} onChange={event => set('randomizedDelaySec', event.target.value)} placeholder="None" />
          </Field>
          <Field label="Accuracy" hint="AccuracySec: systemd may start up to 1min late unless you lower this.">
            <TextInput mono value={form.accuracySec} onChange={event => set('accuracySec', event.target.value)} placeholder="1min" />
          </Field>
        </div>
        <div className="tk-toggle-grid" style={{ marginTop: 14 }}>
          <Toggle label="Catch up missed runs (Persistent=true)" hint="Run the job after boot if the machine was off at the scheduled time." checked={form.persistent} onChange={next => set('persistent', next)} />
        </div>
      </Panel>

      <Panel title="Unit files" icon="bi-file-earmark-code">
        <FindingList findings={unitFindings} />
        <div style={{ marginTop: unitFindings.length ? '1rem' : 0 }}>
          <p className="tk-note">Save the timer as <code className="tk-mono">{built.timerPath}</code> and the service as <code className="tk-mono">{built.servicePath}</code>, or let the install commands write both.</p>
          <CodeBlock label="Timer unit (.timer)" code={built.timerUnit} />
          <CodeBlock label="Service unit (.service)" code={built.serviceUnit} />
          <CodeBlock label="Install and check" code={built.installCommands.join('\n')} />
        </div>
      </Panel>

      <Panel title="What changes from cron" icon="bi-arrow-left-right">
        <FindingList findings={CRON_DIFFERENCES} />
      </Panel>
    </ToolPage>
  );
}
