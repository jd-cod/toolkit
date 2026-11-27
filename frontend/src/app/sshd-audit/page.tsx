'use client';

import { useState } from 'react';
import ToolPage from '@/components/ToolPage';
import { Badge, CodeBlock, DataTable, ErrorBanner, Field, FindingList, Panel, Stat, StatGrid, TextArea, type Finding } from '@/components/ToolUi';
import { auditSshdConfig, SSHD_SAMPLE, type Severity, type SshdAudit } from '@/lib/tools/sshd-audit';

const GROUPS: Array<{ severity: Severity; title: string; icon: string }> = [
  { severity: 'critical', title: 'Critical', icon: 'bi-x-octagon' },
  { severity: 'warning', title: 'Warnings', icon: 'bi-exclamation-triangle' },
  { severity: 'info', title: 'Info', icon: 'bi-info-circle' },
  { severity: 'ok', title: 'Passed', icon: 'bi-check-circle' },
];

const MAX_MATCH_ROWS = 100;

function toFindings(audit: SshdAudit, severity: Severity): Finding[] {
  return audit.findings.filter(finding => finding.severity === severity).map(finding => ({ severity, title: finding.title, detail: finding.detail }));
}

export default function SshdAuditPage() {
  const [text, setText] = useState('');
  const [audit, setAudit] = useState<SshdAudit | null>(null);
  const [empty, setEmpty] = useState(false);

  const run = (input: string) => {
    const blank = input.trim() === '';
    setEmpty(blank);
    setAudit(blank ? null : auditSshdConfig(input));
  };
  const loadSample = () => {
    setText(SSHD_SAMPLE);
    run(SSHD_SAMPLE);
  };
  const clear = () => {
    setText('');
    setAudit(null);
    setEmpty(false);
  };

  return (
    <ToolPage tool="sshd-audit" title="SSH Config Auditor" icon="bi-terminal" lead="Paste an sshd_config or the output of sshd -T to find risky settings and get a hardened snippet.">
      <Panel title="Config" icon="bi-file-earmark-code">
        <Field label="sshd_config or sshd -T output" hint="The config is analyzed in your browser and is not uploaded. Run sudo sshd -T to get the settings in effect, including included files.">
          <TextArea
            value={text}
            onChange={event => setText(event.target.value)}
            placeholder={'PermitRootLogin prohibit-password\nPasswordAuthentication no\nX11Forwarding no\n...'}
            style={{ minHeight: 260 }}
          />
        </Field>
        <div className="tk-actions" style={{ marginTop: '1rem' }}>
          <button type="button" className="btn-primary" onClick={() => run(text)}>Audit</button>
          <button type="button" className="btn-secondary" onClick={loadSample}>Load sample</button>
          <button type="button" className="btn-secondary" onClick={clear}>Clear</button>
        </div>
      </Panel>

      {empty && <ErrorBanner>Nothing to audit. Paste an sshd_config or the output of sshd -T, or load the sample.</ErrorBanner>}

      {audit && (
        <div role="region" aria-label="Audit results">
          <StatGrid>
            <Stat label="Critical" value={audit.counts.critical} tone="bad" />
            <Stat label="Warnings" value={audit.counts.warning} tone="warn" />
            <Stat label="Info" value={audit.counts.info} tone="info" />
            <Stat label="Passed" value={audit.counts.ok} tone="ok" />
          </StatGrid>

          {GROUPS.filter(group => audit.counts[group.severity] > 0).map(group => (
            <Panel key={group.severity} title={`${group.title} (${audit.counts[group.severity]})`} icon={group.icon}>
              {group.severity === 'info' && <p className="tk-note">Settings that are not set are judged by the OpenSSH default.</p>}
              <div style={{ overflowWrap: 'anywhere' }}><FindingList findings={toFindings(audit, group.severity)} /></div>
            </Panel>
          ))}

          {audit.matchBlocks.length > 0 && (
            <Panel title={`Match blocks (${audit.matchBlocks.length})`} icon="bi-diagram-3">
              <p className="tk-note">Settings in a Match block apply only to connections that meet its conditions, and override the global section for them.</p>
              {audit.matchBlocks.slice(0, 20).map(block => (
                <div key={block.line} style={{ marginBottom: '1rem' }}>
                  <p className="tk-note tk-mono" style={{ marginBottom: '0.5rem', color: 'var(--text-primary)' }}>Match {block.criteria || '(no conditions)'}</p>
                  <DataTable
                    head={['Line', 'Directive', 'Value', 'Note']}
                    empty="No settings in this block."
                    rows={block.directives.slice(0, MAX_MATCH_ROWS).map(item => [
                      item.line,
                      <span key="directive" className="tk-mono" style={{ whiteSpace: 'nowrap' }}>{item.directive}</span>,
                      <span key="value" className="tk-mono" style={{ display: 'inline-block', minWidth: 120, overflowWrap: 'anywhere' }}>{item.value || '—'}</span>,
                      item.flagged ? <Badge key="note" tone="warn">Risky override</Badge> : '—',
                    ])}
                  />
                  {block.directives.length > MAX_MATCH_ROWS && <p className="tk-note">Showing the first {MAX_MATCH_ROWS} of {block.directives.length} settings.</p>}
                </div>
              ))}
              {audit.matchBlocks.length > 20 && <p className="tk-note">Showing the first 20 blocks.</p>}
            </Panel>
          )}

          <Panel title="Hardened snippet" icon="bi-shield-lock">
            {audit.hardenedSnippet ? (
              <>
                <p className="tk-note">
                  Only the settings that should change. Replace the existing lines with these: sshd uses the first value it reads, so adding them at the end of the file has no effect on settings that are already set. Make sure key login works before you turn off passwords.
                </p>
                <CodeBlock label="sshd_config" code={audit.hardenedSnippet} />
              </>
            ) : (
              <p className="tk-note" style={{ marginBottom: 0 }}>No changes to suggest for this config.</p>
            )}
          </Panel>

          <Panel title="Apply safely" icon="bi-arrow-repeat">
            <p className="tk-note">
              Keep a second SSH session open while you change the config. Test the syntax, reload, then log in from a new terminal before you close the old session. A reload does not drop existing sessions.
            </p>
            <CodeBlock label="RHEL, Fedora, SUSE, Arch" code="sudo sshd -t && sudo systemctl reload sshd" />
            <CodeBlock label="Debian, Ubuntu" code="sudo sshd -t && sudo systemctl reload ssh" />
          </Panel>
        </div>
      )}
    </ToolPage>
  );
}
