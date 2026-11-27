'use client';

import { useState } from 'react';
import ToolPage from '@/components/ToolPage';
import { CodeBlock, Field, FindingList, Panel, Select, TextInput, type Finding } from '@/components/ToolUi';
import { buildFirewallRules, FIREWALL_DEFAULTS, type FirewallAction, type FirewallDirection, type FirewallProtocol, type FirewallRule } from '@/lib/tools/firewall-rules';

const PRESETS: Array<{ label: string; rule: FirewallRule }> = [
  { label: 'SSH from an office IP', rule: { action: 'allow', direction: 'in', protocol: 'tcp', ports: '22', source: '203.0.113.10', iface: '', comment: 'Office SSH' } },
  { label: 'Web server', rule: { action: 'allow', direction: 'in', protocol: 'tcp', ports: '80,443', source: '', iface: '', comment: 'Web server' } },
  { label: 'MySQL from an app server', rule: { action: 'allow', direction: 'in', protocol: 'tcp', ports: '3306', source: '10.0.0.5', iface: '', comment: 'MySQL from app server' } },
  { label: 'Block an IP', rule: { action: 'deny', direction: 'in', protocol: 'any', ports: '', source: '198.51.100.23', iface: '', comment: 'Blocked address' } },
  { label: 'RDP from a subnet', rule: { action: 'allow', direction: 'in', protocol: 'tcp', ports: '3389', source: '192.168.10.0/24', iface: '', comment: 'RDP from LAN' } },
];

const sameRule = (a: FirewallRule, b: FirewallRule) => (Object.keys(a) as Array<keyof FirewallRule>).every(key => a[key] === b[key]);

export default function FirewallRulesPage() {
  const [rule, setRule] = useState<FirewallRule>(FIREWALL_DEFAULTS);
  const set = <K extends keyof FirewallRule>(key: K, value: FirewallRule[K]) => setRule(current => ({ ...current, [key]: value }));

  const result = buildFirewallRules(rule);
  const inbound = rule.direction === 'in';
  const findings: Finding[] = [
    ...result.errors.map(title => ({ severity: 'critical' as const, title })),
    ...result.warnings.map(title => ({ severity: 'warning' as const, title })),
  ];
  if (findings.length === 0) findings.push({ severity: 'ok', title: 'The rule is valid and raises no warnings.' });

  return (
    <ToolPage tool="firewall-rules" title="Firewall Rule Generator" icon="bi-bricks" lead="Describe one rule and get it for ufw, firewalld, nftables, iptables and Windows Firewall.">
      <Panel title="Rule" icon="bi-sliders">
        <p className="tk-note">Allow your own access before adding deny rules. A wrong rule on a remote server can lock you out.</p>
        <div className="tk-chip-row" role="group" aria-label="Rule presets" style={{ marginBottom: '1rem' }}>
          {PRESETS.map(preset => (
            <button key={preset.label} type="button" className="tk-chip" aria-pressed={sameRule(rule, preset.rule)} onClick={() => setRule(preset.rule)}>
              {preset.label}
            </button>
          ))}
        </div>
        <div className="tk-form-grid">
          <Field label="Action">
            <Select value={rule.action} onChange={event => set('action', event.target.value as FirewallAction)}>
              <option value="allow">Allow</option>
              <option value="deny">Deny (drop silently)</option>
              <option value="reject">Reject (answer with an error)</option>
            </Select>
          </Field>
          <Field label="Direction">
            <Select value={rule.direction} onChange={event => set('direction', event.target.value as FirewallDirection)}>
              <option value="in">Inbound</option>
              <option value="out">Outbound</option>
            </Select>
          </Field>
          <Field label="Protocol">
            <Select value={rule.protocol} onChange={event => set('protocol', event.target.value as FirewallProtocol)}>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="both">TCP and UDP</option>
              <option value="any">Any protocol (no ports)</option>
            </Select>
          </Field>
          <Field label="Ports" hint="One port, a list (80,443) or a range (8000-8100). Empty means all ports.">
            <TextInput mono value={rule.ports} onChange={event => set('ports', event.target.value)} placeholder="All ports" />
          </Field>
          <Field label={inbound ? 'Source address' : 'Destination address'} hint="IPv4, IPv6 or a CIDR range. Empty means any address.">
            <TextInput mono value={rule.source} onChange={event => set('source', event.target.value)} placeholder="Any" />
          </Field>
          <Field label="Interface" hint="Optional Linux interface name, such as eth0.">
            <TextInput mono value={rule.iface} onChange={event => set('iface', event.target.value)} placeholder="All interfaces" />
          </Field>
          <Field label="Comment" hint="Stored with the rule. Used as the rule name on Windows.">
            <TextInput value={rule.comment} onChange={event => set('comment', event.target.value)} placeholder="None" />
          </Field>
        </div>
      </Panel>

      <Panel title="Checks" icon="bi-clipboard-check">
        <FindingList findings={findings} />
      </Panel>

      <Panel title="Rules" icon="bi-terminal">
        {result.outputs.length === 0 && <p className="tk-note" style={{ marginBottom: 0 }}>Fix the errors above to see the rules.</p>}
        {result.outputs.map((output, index) => (
          <section key={output.key} aria-label={output.label} style={{ marginTop: index === 0 ? 0 : '1.5rem' }}>
            {output.commands.length > 0
              ? <CodeBlock label={output.label} code={output.commands.join('\n')} />
              : <FindingList findings={[{ severity: 'info', title: `${output.label}: no command for this rule` }]} />}
            <ul className="tk-note" style={{ margin: '0.75rem 0 0', paddingLeft: '1.1rem' }}>
              {output.commands.length > 0 && <li>{output.persistence}</li>}
              {output.notes.map(note => <li key={note}>{note}</li>)}
            </ul>
          </section>
        ))}
      </Panel>
    </ToolPage>
  );
}
