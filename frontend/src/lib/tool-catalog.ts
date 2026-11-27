import type { Tool } from './api';

export type ToolCategory = 'Observability' | 'Network' | 'Email' | 'Security' | 'Utilities' | 'Windows';
export const TOOL_CATEGORIES: ToolCategory[] = ['Observability', 'Network', 'Email', 'Security', 'Utilities', 'Windows'];

const catalog: Record<string, { route: string; category: ToolCategory; processing: string; icon: string }> = {
  nginx: { route: '/nginx', category: 'Observability', processing: 'Local log analysis', icon: 'bi-bar-chart-line' },
  dns: { route: '/dns', category: 'Network', processing: 'DNS-over-HTTPS', icon: 'bi-globe2' },
  ssl: { route: '/ssl', category: 'Security', processing: 'Remote lookup', icon: 'bi-lock' },
  whois: { route: '/whois', category: 'Network', processing: 'Remote lookup', icon: 'bi-search' },
  abuse: { route: '/abuse', category: 'Security', processing: 'Remote lookup', icon: 'bi-shield-check' },
  asn: { route: '/asn', category: 'Network', processing: 'Remote lookup', icon: 'bi-diagram-3' },
  myip: { route: '/myip', category: 'Network', processing: 'Connection lookup', icon: 'bi-geo-alt' },
  cron: { route: '/cron', category: 'Utilities', processing: 'Local processing', icon: 'bi-clock' },
  password: { route: '/password-generator', category: 'Security', processing: 'Local processing', icon: 'bi-key' },
  subnet: { route: '/subnet', category: 'Utilities', processing: 'Local processing', icon: 'bi-hdd-network' },
  chmod: { route: '/chmod', category: 'Utilities', processing: 'Local processing', icon: 'bi-sliders' },
  'email-auth': { route: '/email-auth', category: 'Email', processing: 'DNS lookup', icon: 'bi-envelope-check' },
  blacklist: { route: '/blacklist', category: 'Email', processing: 'DNSBL lookup', icon: 'bi-slash-circle' },
  'email-headers': { route: '/email-headers', category: 'Email', processing: 'Local processing', icon: 'bi-envelope-open' },
  'smtp-test': { route: '/smtp-test', category: 'Email', processing: 'Remote connection', icon: 'bi-send-check' },
  'http-headers': { route: '/http-headers', category: 'Network', processing: 'Remote request', icon: 'bi-arrow-left-right' },
  'port-check': { route: '/port-check', category: 'Network', processing: 'Remote connection', icon: 'bi-door-open' },
  'cert-decoder': { route: '/cert-decoder', category: 'Security', processing: 'Local processing', icon: 'bi-file-earmark-lock' },
  'sshd-audit': { route: '/sshd-audit', category: 'Security', processing: 'Local processing', icon: 'bi-terminal' },
  'systemd-timer': { route: '/systemd-timer', category: 'Utilities', processing: 'Local processing', icon: 'bi-stopwatch' },
  'firewall-rules': { route: '/firewall-rules', category: 'Utilities', processing: 'Local processing', icon: 'bi-bricks' },
  rsync: { route: '/rsync', category: 'Utilities', processing: 'Local processing', icon: 'bi-arrow-repeat' },
  'auth-log': { route: '/auth-log', category: 'Observability', processing: 'Local log analysis', icon: 'bi-person-lock' },
  'mail-log': { route: '/mail-log', category: 'Observability', processing: 'Local log analysis', icon: 'bi-mailbox' },
  'windows-events': { route: '/windows-events', category: 'Windows', processing: 'Local reference', icon: 'bi-journal-text' },
  'windows-errors': { route: '/windows-errors', category: 'Windows', processing: 'Local reference', icon: 'bi-bug' },
  robocopy: { route: '/robocopy', category: 'Windows', processing: 'Local processing', icon: 'bi-copy' },
};

export function toolMetadata(tool: Pick<Tool, 'tool_key'>) {
  return catalog[tool.tool_key] ?? {
    route: `/${encodeURIComponent(tool.tool_key)}`,
    category: 'Utilities' as const,
    processing: 'Utility',
    icon: 'bi-tools',
  };
}

export function enabledTools(tools: Tool[]) {
  return tools.filter(tool => Boolean(Number(tool.is_enabled)))
    .toSorted((a, b) => a.sort_order - b.sort_order || a.id - b.id);
}

export function matchesTool(tool: Tool, query: string) {
  const searchable = [tool.label, tool.description, tool.tags, tool.tool_key, toolMetadata(tool).category].join(' ').toLowerCase();
  return query.trim().toLowerCase().split(/\s+/).every(word => searchable.includes(word));
}
