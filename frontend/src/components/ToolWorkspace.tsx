import type { ReactNode } from 'react';

const GUIDES = {
  ssl: { title: 'Read the certificate', icon: 'shield-check', steps: [['Trust & identity', 'Check hostname matching and the issuer chain before relying on the grade.'], ['Expiry window', 'Review the remaining days and every name covered by the certificate.'], ['Connection details', 'Inspect TLS protocol, key size, DNS resolution, and HSTS together.']] },
  whois: { title: 'Domain registration', icon: 'person-vcard', steps: [['Registration timeline', 'Compare creation, update, and expiration dates.'], ['Ownership signals', 'Review registrar, domain status, and available contacts. Some registries redact personal details.'], ['Keep a snapshot', 'Export or share the returned registration record for later comparison.']] },
  asn: { title: 'Network intelligence', icon: 'diagram-3', steps: [['Find a network', 'Use an ASN number or one of the network shortcuts.'], ['Explore announcements', 'Filter IPv4 and IPv6 prefixes, inspect BGP details, or test an IP against the network.'], ['Use the results', 'Export prefixes or build firewall rules in your preferred format.']] },
  abuse: { title: 'Investigate an address', icon: 'shield-exclamation', steps: [['Batch input', 'Enter one IP per line, optionally followed by a request count.'], ['Read the evidence', 'Compare reverse DNS, network ownership, and reported abuse. An absent report is not proof of safety.'], ['Inspect a result', 'Expand a row to see risk reasons and report details.']] },
  myip: { title: 'Your connection', icon: 'globe2', steps: [['Public address', 'The address observed by this server may belong to a VPN, proxy, or shared gateway.'], ['Network & location', 'GeoIP is an approximation of the network location, not a street address.'], ['Browser diagnostics', 'Connection and browser details depend on what your browser exposes.']] },
  cron: { title: 'Schedule reference', icon: 'clock', steps: [['Five fields', 'Minute · hour · day of month · month · day of week.'], ['Common operators', '* matches every value, / adds a step, - defines a range, and commas join values.'], ['Execution preview', 'Upcoming runs use your browser’s local time. Check the target server’s timezone before deployment.']] },
  subnet: { title: 'Plan your network', icon: 'hdd-network', steps: [['CIDR or netmask', 'Enter an IPv4 CIDR block, or an address followed by its dotted subnet mask.'], ['Address boundaries', 'Review network, broadcast, wildcard mask, and the usable host range.'], ['AWS capacity', 'AWS mode deducts five reserved addresses from subnet capacity.']] },
  chmod: { title: 'Permission reference', icon: 'key', steps: [['Read · write · execute', 'Read = 4, write = 2, execute = 1. Add the enabled bits for each role.'], ['Three roles', 'Owner, group, and others each have independent permissions.'], ['Special bits', 'Setuid, setgid, and sticky bits add a leading octal digit. Review the explanation before copying the command.']] },
  password: { title: 'Generation settings', icon: 'shield-lock', steps: [['Choose a mode', 'Use a random password, word-based passphrase, or numeric PIN.'], ['Match your policy', 'Adjust length and character sets; strength reflects the selected generation pool.'], ['Generate a batch', 'Use bulk generation for multiple values, then copy or export the batch.']] },
} as const;

export default function ToolWorkspace({ tool, children, wide = false }: { tool: keyof typeof GUIDES; children: ReactNode; wide?: boolean }) {
  const guide = GUIDES[tool];
  return <div className={`signal-tool-workspace signal-tool-${tool}${wide ? ' signal-tool-workspace-wide' : ''}`}>
    <div className="signal-tool-primary">{children}</div>
    <aside className="signal-tool-context" aria-label={guide.title}>
      <i className={`bi bi-${guide.icon}`} aria-hidden="true" />
      <h2>{guide.title}</h2>
      <dl>{guide.steps.map(([title, detail]) => <div key={title}><dt>{title}</dt><dd>{detail}</dd></div>)}</dl>
    </aside>
  </div>;
}

export function ToolEmptyState({ title, children }: { title: string; children: ReactNode }) {
  return <section className="signal-tool-empty"><i className="bi bi-search" aria-hidden="true" /><h2>{title}</h2><p>{children}</p></section>;
}
