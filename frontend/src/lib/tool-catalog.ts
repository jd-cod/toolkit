import type { Tool } from './api';

export type ToolCategory = 'Observability' | 'Network' | 'Security' | 'Utilities';
export const TOOL_CATEGORIES: ToolCategory[] = ['Observability', 'Network', 'Security', 'Utilities'];

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
