/**
 * Expected state of the workspace shell (home page directory, sidebar, top
 * bar, command palette, footer), computed from a site configuration.
 *
 * The configuration is the input: `GET /api/site/config` for the real site,
 * or a payload the test builds and serves in its place. Nothing here imports
 * application code. The rules are written down as definitions:
 *
 * DEFINITIONS
 *  1. A tool is ENABLED when `is_enabled` is the number 1 (MySQL returns it as
 *     a number; a numeric string counts the same). Disabled tools appear
 *     nowhere: not in the directory, the counts, the sidebar or the palette.
 *  2. ORDER everywhere is ascending `sort_order`; tools with the same
 *     `sort_order` are ordered by ascending `id`.
 *  3. Each tool key has a fixed ROUTE, CATEGORY, PROCESSING note and SIDEBAR
 *     ICON: the table `CATALOGUE` below. A new tool must be added to it. A key
 *     that is not in the table opens `/<key>` (URL-encoded), belongs to
 *     "Utilities", is described as "Utility" and uses the `bi-tools` icon.
 *  4. A directory CARD shows the configured label, description and colour, the
 *     configured icon (the catalogue icon when none is configured), the
 *     category and the processing note. Tags are not displayed; they are only
 *     searchable.
 *  5. SEARCH (directory search box and command palette): the query is split on
 *     whitespace into words; case is ignored; a tool matches when EVERY word
 *     occurs somewhere in its label, description, tags, key or category. An
 *     empty query matches every tool. Words are plain text, never patterns.
 *  6. The SIDEBAR lists "Overview", then three groups in this order:
 *     "Observability" (category Observability), "Network & security"
 *     (categories Network and Security together, in tool order), "Utilities".
 *     A group without tools is not shown.
 *  7. The FOOTER line is the configured `footer_text`, unless that is empty or
 *     one of the two retired default sentences; then it is a sentence that
 *     depends on where the open tool does its work (see `defaultFooterLine`).
 *  8. THEME: the choice is stored in localStorage under `theme` (`dark` or
 *     `light`). Without a stored choice the visitor's system preference
 *     (`prefers-color-scheme`) decides. (Source: the request this suite was
 *     written for. See theme.spec.ts.)
 */

export type Category = 'Observability' | 'Network' | 'Security' | 'Utilities';

export const CATEGORY_ORDER: readonly Category[] = ['Observability', 'Network', 'Security', 'Utilities'];

export interface CatalogueEntry {
  route: string;
  category: Category;
  /** Second line of a card's footer: where the tool does its work. */
  processing: string;
  /** Bootstrap icon used in the sidebar and the command palette. */
  navIcon: string;
}

/** Definition 3. This is the list a new tool has to be added to. */
export const CATALOGUE: Readonly<Record<string, CatalogueEntry>> = {
  nginx:    { route: '/nginx',              category: 'Observability', processing: 'Local log analysis', navIcon: 'bi-bar-chart-line' },
  dns:      { route: '/dns',                category: 'Network',       processing: 'DNS-over-HTTPS',     navIcon: 'bi-globe2' },
  whois:    { route: '/whois',              category: 'Network',       processing: 'Remote lookup',      navIcon: 'bi-search' },
  asn:      { route: '/asn',                category: 'Network',       processing: 'Remote lookup',      navIcon: 'bi-diagram-3' },
  myip:     { route: '/myip',               category: 'Network',       processing: 'Connection lookup',  navIcon: 'bi-geo-alt' },
  ssl:      { route: '/ssl',                category: 'Security',      processing: 'Remote lookup',      navIcon: 'bi-lock' },
  abuse:    { route: '/abuse',              category: 'Security',      processing: 'Remote lookup',      navIcon: 'bi-shield-check' },
  password: { route: '/password-generator', category: 'Security',      processing: 'Local processing',   navIcon: 'bi-key' },
  cron:     { route: '/cron',               category: 'Utilities',     processing: 'Local processing',   navIcon: 'bi-clock' },
  subnet:   { route: '/subnet',             category: 'Utilities',     processing: 'Local processing',   navIcon: 'bi-hdd-network' },
  chmod:    { route: '/chmod',              category: 'Utilities',     processing: 'Local processing',   navIcon: 'bi-sliders' },
};

export const SIDEBAR_GROUPS: readonly { caption: string; categories: readonly Category[] }[] = [
  { caption: 'Observability', categories: ['Observability'] },
  { caption: 'Network & security', categories: ['Network', 'Security'] },
  { caption: 'Utilities', categories: ['Utilities'] },
];

export const ALL_TOOLS = 'All tools';

// ─── Shape of GET /api/site/config (backend/src/routes/public.js) ───

export interface ToolRow {
  id: number;
  tool_key: string;
  label: string;
  description: string;
  icon: string;
  color: string;
  tags: string;
  is_enabled: number | string;
  sort_order: number;
  meta_title?: string;
  meta_description?: string;
  seo_noindex?: number;
  updated_at?: string;
}

export interface MenuRow {
  id: number;
  location: string;
  label: string;
  url: string;
  icon: string;
  sort_order: number;
  is_visible: number;
  open_in_new_tab: number;
}

export interface PageRow {
  id: number;
  slug: string;
  title: string;
  sort_order: number;
  seo_noindex?: number;
}

export interface SiteConfig {
  settings: Record<string, string>;
  tools: ToolRow[];
  menus: { header: MenuRow[]; footer: MenuRow[] };
  footer: Record<string, string>;
  pages: PageRow[];
}

// ─── Tools ───

export function catalogueEntry(key: string): CatalogueEntry {
  if (Object.prototype.hasOwnProperty.call(CATALOGUE, key)) return CATALOGUE[key];
  return { route: `/${encodeURIComponent(key)}`, category: 'Utilities', processing: 'Utility', navIcon: 'bi-tools' };
}

export function isEnabled(tool: ToolRow): boolean {
  return String(tool.is_enabled).trim() === '1';
}

/** Definitions 1 and 2. */
export function enabledTools(config: SiteConfig): ToolRow[] {
  const kept: ToolRow[] = [];
  for (const tool of config.tools) if (isEnabled(tool)) kept.push(tool);
  // Two stable passes: by id, then by sort_order. Equal sort_order keeps id order.
  kept.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  kept.sort((a, b) => (a.sort_order < b.sort_order ? -1 : a.sort_order > b.sort_order ? 1 : 0));
  return kept;
}

export function toolsInCategory(tools: ToolRow[], category: string): ToolRow[] {
  return category === ALL_TOOLS ? tools.slice() : tools.filter(tool => catalogueEntry(tool.tool_key).category === category);
}

/** The five filter buttons, in display order, with the number each one shows. */
export function expectedCategoryButtons(config: SiteConfig, pressed: string = ALL_TOOLS): CategoryButtonView[] {
  const tools = enabledTools(config);
  return [ALL_TOOLS, ...CATEGORY_ORDER].map(name => ({
    name,
    count: toolsInCategory(tools, name).length,
    pressed: name === pressed,
  }));
}

// ─── Search (definition 5) ───

export function queryWords(query: string): string[] {
  const words: string[] = [];
  let current = '';
  for (const ch of query) {
    if (/\s/.test(ch)) {
      if (current) words.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  if (current) words.push(current);
  return words.map(word => word.toLowerCase());
}

export function searchFields(tool: ToolRow): string[] {
  return [tool.label, tool.description, tool.tags, tool.tool_key, catalogueEntry(tool.tool_key).category]
    .map(text => String(text ?? '').toLowerCase());
}

export function matchesQuery(tool: ToolRow, query: string): boolean {
  const fields = searchFields(tool);
  for (const word of queryWords(query)) {
    let found = false;
    for (const field of fields) {
      if (field.indexOf(word) !== -1) { found = true; break; }
    }
    if (!found) return false;
  }
  return true;
}

/** Tools the directory shows for a category button and a search text. */
export function visibleTools(config: SiteConfig, category: string, query: string): ToolRow[] {
  return toolsInCategory(enabledTools(config), category).filter(tool => matchesQuery(tool, query));
}

// ─── What each widget shows ───

export interface CardView {
  key: string;
  href: string;
  label: string;
  description: string;
  category: string;
  processing: string;
  /** Class list of the card's icon element. */
  icon: string;
  /** Value of the card's accent colour. */
  color: string;
}

export function expectedCard(tool: ToolRow): CardView {
  const entry = catalogueEntry(tool.tool_key);
  return {
    key: tool.tool_key,
    href: entry.route,
    label: tool.label,
    description: tool.description,
    category: entry.category,
    processing: entry.processing,
    icon: `bi ${tool.icon ? tool.icon : entry.navIcon}`,
    color: tool.color ? tool.color : 'var(--accent-primary)',
  };
}

export interface CategoryButtonView { name: string; count: number; pressed: boolean }

export interface NavLinkView { href: string; label: string; icon: string; current: boolean }

export interface NavView {
  overview: { href: string; current: boolean };
  groups: { caption: string; links: NavLinkView[] }[];
  pages: { href: string; label: string }[];
  version: string;
  brandName: string;
  brandTagline: string;
}

/** Definition 6, for the page at `pathname`. The drawer shows the same. */
export function expectedNav(config: SiteConfig, pathname: string): NavView {
  const tools = enabledTools(config);
  const groups: NavView['groups'] = [];
  for (const group of SIDEBAR_GROUPS) {
    const links: NavLinkView[] = [];
    for (const tool of tools) {
      const entry = catalogueEntry(tool.tool_key);
      if (!group.categories.includes(entry.category)) continue;
      links.push({ href: entry.route, label: tool.label, icon: `bi ${entry.navIcon}`, current: entry.route === pathname });
    }
    if (links.length > 0) groups.push({ caption: group.caption, links });
  }
  const s = config.settings;
  return {
    overview: { href: '/', current: pathname === '/' },
    groups,
    pages: config.pages.map(page => ({ href: `/page/${page.slug}`, label: page.title })),
    version: s.version_badge ?? 'v3.0',
    brandName: s.site_title || 'SysAdmin Toolkit',
    brandTagline: s.site_tagline || 'NETWORK & SECURITY',
  };
}

export interface PaletteResultView { href: string; label: string; category: string; icon: string }

export function expectedPaletteResults(config: SiteConfig, query: string): PaletteResultView[] {
  return visibleTools(config, ALL_TOOLS, query).map(tool => {
    const entry = catalogueEntry(tool.tool_key);
    return { href: entry.route, label: tool.label, category: entry.category, icon: `bi ${entry.navIcon}` };
  });
}

/** The brand mark is the built-in shield unless a different icon is configured. */
export type BrandMark = { kind: 'shield' } | { kind: 'icon'; name: string } | { kind: 'text'; text: string };

export function expectedBrandMark(settings: Record<string, string>): BrandMark {
  const configured = settings.favicon_emoji || settings.brand_icon || '';
  const builtIn = ['🛡️', 'bi-shield-lock-fill', 'bi bi-shield-lock-fill'];
  if (!configured || builtIn.includes(configured)) return { kind: 'shield' };
  if (configured.startsWith('bi-') || configured.startsWith('bi ')) return { kind: 'icon', name: configured.split(' ').pop() as string };
  return { kind: 'text', text: configured };
}

export interface HeroView { title: string; subtitle: string; countText: string; tagline: string }

export function expectedHero(config: SiteConfig): HeroView {
  const s = config.settings;
  return {
    title: s.home_hero_title || s.site_title || 'Free SysAdmin & Network Tools',
    subtitle: s.home_hero_subtitle || s.site_description || 'Essential network diagnostics, log analysis, and system administration tools.',
    countText: `${enabledTools(config).length} purpose-built tools`,
    tagline: s.site_tagline || 'Network & security suite',
  };
}

export const DEFAULT_MAINTENANCE_MESSAGE = 'We are currently performing scheduled maintenance. Please check back soon.';

export function expectedAnnouncement(settings: Record<string, string>): { text: string; warning: boolean } | null {
  if (settings.announcement_enabled !== '1' || !settings.announcement_text) return null;
  return { text: settings.announcement_text, warning: settings.announcement_type === 'warning' };
}

export interface MenuLinkView { label: string; href: string; target: string | null; rel: string | null }

/** Menu entries a visitor sees: the visible ones, new-tab entries marked as such. */
export function expectedMenu(items: MenuRow[] | undefined): MenuLinkView[] {
  return (items ?? []).filter(item => item.is_visible !== 0).map(item => ({
    label: item.label,
    href: item.url,
    target: item.open_in_new_tab ? '_blank' : null,
    rel: item.open_in_new_tab ? 'noopener noreferrer' : null,
  }));
}

/** Label after "Workspace /" in the top bar. */
export function expectedBreadcrumb(config: SiteConfig, pathname: string): string {
  if (pathname === '/') return 'Overview';
  for (const tool of enabledTools(config)) {
    if (catalogueEntry(tool.tool_key).route === pathname) return tool.label;
  }
  for (const page of config.pages) {
    if (`/page/${page.slug}` === pathname) return page.title;
  }
  return pathname.startsWith('/s/') ? 'Shared snapshot' : 'Tools';
}

// ─── Footer (definition 7) ───

const RETIRED_FOOTER_DEFAULTS = [
  'SysAdmin Toolkit · GeoIP by MaxMind · All processing runs in your browser',
  'SysAdmin Toolkit · GeoIP by MaxMind · Local log analysis. Remote network lookups.',
];

/**
 * The default line must agree with what the tool's card promises: a tool
 * described as "Local processing" says it runs in the browser, the log
 * analyzer names its local analysis, and every tool that asks a server says so.
 */
export function defaultFooterLine(pathname: string): string {
  const entry = Object.values(CATALOGUE).find(item => item.route === pathname);
  if (!entry) return 'SysAdmin Toolkit · Network, security & browser-based tools · GeoIP by MaxMind';
  if (entry.processing === 'Local processing') return 'SysAdmin Toolkit · This tool runs in your browser.';
  if (entry.processing === 'Local log analysis') {
    return 'SysAdmin Toolkit · GeoIP by MaxMind · Local log analysis. Remote sources and sharing use server services.';
  }
  return 'SysAdmin Toolkit · GeoIP by MaxMind · Network lookups use remote services.';
}

export interface FooterView { lines: string[]; links: MenuLinkView[] }

export function expectedFooter(config: SiteConfig, pathname: string): FooterView {
  const text = config.footer.footer_text;
  const lines = [text && !RETIRED_FOOTER_DEFAULTS.includes(text) ? text : defaultFooterLine(pathname)];
  if (config.footer.copyright_text) lines.push(config.footer.copyright_text);
  return { lines, links: expectedMenu(config.menus.footer) };
}

// ─── Sitemap ───

/** Paths a crawler must find: home, every enabled indexable tool, every indexable page. */
export function expectedSitemapPaths(config: SiteConfig): string[] {
  const paths = ['/'];
  for (const tool of config.tools) {
    if (isEnabled(tool) && !tool.seo_noindex) paths.push(catalogueEntry(tool.tool_key).route);
  }
  for (const page of config.pages) {
    if (!page.seo_noindex) paths.push(`/page/${encodeURIComponent(page.slug)}`);
  }
  return paths.sort();
}

// ─── Palette colours (appearance settings) ───

/**
 * A palette setting takes effect only when it is a 3- or 6-digit hex colour;
 * the 3-digit form is the usual CSS shorthand (each digit doubled).
 * Returns the colour as `rgb(r, g, b)`, or null when the setting is ignored.
 */
export function paletteColorAsRgb(value: string | undefined): string | null {
  const text = (value ?? '').trim();
  if (text[0] !== '#') return null;
  const digits = text.slice(1);
  if (digits.length !== 3 && digits.length !== 6) return null;
  for (const ch of digits) if (!'0123456789abcdefABCDEF'.includes(ch)) return null;
  const pairs = digits.length === 3 ? digits.split('').map(d => d + d) : [digits.slice(0, 2), digits.slice(2, 4), digits.slice(4, 6)];
  return `rgb(${pairs.map(pair => Number.parseInt(pair, 16)).join(', ')})`;
}
