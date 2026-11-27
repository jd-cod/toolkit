import type { Rng } from '../_support/rng';
import {
  CATALOGUE, CATEGORY_ORDER, catalogueEntry, enabledTools, matchesQuery,
  type MenuRow, type PageRow, type SiteConfig, type ToolRow,
} from './oracle';

/**
 * Random inputs for the workspace suite: search queries built from the words
 * the configured tools really contain, and site configurations to serve in
 * place of the real one.
 */

export function cloneConfig(config: SiteConfig): SiteConfig {
  return JSON.parse(JSON.stringify(config)) as SiteConfig;
}

// ─── Search queries ───

export interface GeneratedQuery {
  query: string;
  /** How the query was built, for the failure message. */
  kind: string;
}

interface Vocabulary {
  /** Letters-and-digits words per tool (at least two characters). */
  wordsByTool: string[][];
  /** Whitespace-separated chunks per tool, punctuation kept (`(PTR),`, `100%`, `Traffic,GeoIP`). */
  chunksByTool: string[][];
}

function vocabulary(tools: ToolRow[]): Vocabulary {
  const wordsByTool: string[][] = [];
  const chunksByTool: string[][] = [];
  for (const tool of tools) {
    const text = [tool.label, tool.description, tool.tags, tool.tool_key, catalogueEntry(tool.tool_key).category].join(' ');
    const words = text.split(/[^A-Za-z0-9]+/).filter(word => word.length >= 2);
    const chunks = text.split(/\s+/).filter(chunk => chunk.length >= 1);
    wordsByTool.push([...new Set(words)]);
    chunksByTool.push([...new Set(chunks)]);
  }
  return { wordsByTool, chunksByTool };
}

function randomCase(rng: Rng, text: string): string {
  let out = '';
  for (const ch of text) out += rng.bool() ? ch.toUpperCase() : ch.toLowerCase();
  return out;
}

function randomSlice(rng: Rng, word: string): string {
  if (word.length <= 2) return word;
  const length = rng.int(2, word.length);
  const start = rng.int(0, word.length - length);
  return word.slice(start, start + length);
}

function padding(rng: Rng): string {
  return ' '.repeat(rng.int(1, 3));
}

/** Text that is not a pattern for the search, however much it looks like one. */
const LITERAL_QUERIES = ['.*', '[a-z]+', '(', ')', '\\', '?', 'a|b', '^dns', 'dns$', '<img', '<b>', '%', '&', '/', '100%', '"', "'", '-', '—', '.', ','];

/**
 * `count` queries of every kind a visitor types. Each kind appears at least
 * once when `count` is at least the number of kinds.
 */
export function randomQueries(rng: Rng, tools: ToolRow[], count: number): GeneratedQuery[] {
  if (tools.length === 0) throw new Error('randomQueries: no tools to build queries from');
  const vocab = vocabulary(tools);
  const toolIndex = () => rng.int(0, tools.length - 1);
  const word = (index = toolIndex()) => rng.pick(vocab.wordsByTool[index]);
  const chunk = (index = toolIndex()) => rng.pick(vocab.chunksByTool[index]);

  const kinds: Record<string, () => string> = {
    'one word': () => word(),
    'one word, lower case': () => word().toLowerCase(),
    'two words of the same tool, any order': () => { const i = toolIndex(); return rng.shuffle([word(i), word(i)]).join(' '); },
    'two words of any tools': () => `${word()} ${word()}`,
    'three words of the same tool': () => { const i = toolIndex(); return rng.shuffle([word(i), word(i), word(i)]).join(' '); },
    'mixed case': () => randomCase(rng, word()),
    'two words in mixed case': () => { const i = toolIndex(); return randomCase(rng, `${word(i)} ${word(i)}`); },
    'part of a word': () => randomSlice(rng, word()),
    'parts of two words of the same tool': () => { const i = toolIndex(); return `${randomSlice(rng, word(i))} ${randomSlice(rng, word(i))}`; },
    'spaces before and after': () => `${padding(rng)}${word()}${padding(rng)}`,
    'several spaces between two words': () => { const i = toolIndex(); return `${word(i)}${padding(rng)} ${word(i)}`; },
    'only spaces': () => padding(rng),
    'chunk with punctuation': () => chunk(),
    'chunk with punctuation plus a word': () => { const i = toolIndex(); return `${chunk(i)} ${word(i)}`; },
    'tool key': () => rng.pick(tools).tool_key,
    'category name': () => randomCase(rng, rng.pick(CATEGORY_ORDER)),
    'category name plus a word': () => `${rng.pick(CATEGORY_ORDER).toLowerCase()} ${word()}`,
    'characters that are special in patterns or markup': () => rng.pick(LITERAL_QUERIES),
    'a word plus one that occurs nowhere': () => `${word()} ${noMatchQuery(rng, tools)}`,
    'matches nothing': () => noMatchQuery(rng, tools),
  };

  const names = Object.keys(kinds);
  const order = [...rng.shuffle(names)];
  while (order.length < count) order.push(rng.pick(names));
  return order.slice(0, count).map(kind => ({ kind, query: kinds[kind]() }));
}

/** A word that no tool contains (checked, not assumed). */
export function noMatchQuery(rng: Rng, tools: ToolRow[]): string {
  for (let attempt = 0; attempt < 200; attempt++) {
    const candidate = rng.string(rng.int(4, 9), 'qxzjkvw');
    if (!tools.some(tool => matchesQuery(tool, candidate))) return candidate;
  }
  throw new Error('noMatchQuery: could not build a query that matches no tool');
}

// ─── Site configurations ───

/**
 * Every served configuration carries a unique version badge. The sidebar shows
 * it, so a test can wait for it to know the page is showing the served
 * configuration and not the one the server rendered with.
 */
export function stamp(rng: Rng, config: SiteConfig): SiteConfig {
  const copy = cloneConfig(config);
  copy.settings.version_badge = `e2e-${rng.string(6)}`;
  return copy;
}

function nextId(config: SiteConfig): number {
  return config.tools.reduce((max, tool) => Math.max(max, tool.id), 0) + 1;
}

/** A tool whose key the catalogue does not know. */
export function unknownTool(rng: Rng, config: SiteConfig, overrides: Partial<ToolRow> = {}): ToolRow {
  let key = '';
  do { key = `x${rng.string(rng.int(4, 8), 'abcdefghijklmnopqrstuvwxyz')}`; }
  while (key in CATALOGUE || config.tools.some(tool => tool.tool_key === key));
  const noun = rng.pick(['Probe', 'Tailer', 'Inspector', 'Decoder', 'Watcher']);
  return {
    id: nextId(config),
    tool_key: key,
    label: `${noun} ${rng.string(4).toUpperCase()}`,
    description: `Experimental ${noun.toLowerCase()} number ${rng.int(100, 999)} for ${rng.pick(['syslog', 'journald', 'BGP', 'SNMP'])} data.`,
    icon: rng.bool() ? '' : rng.pick(['bi-wrench', 'bi-cpu', 'bi-terminal']),
    color: rng.bool() ? '' : `#${rng.string(6, '0123456789abcdef')}`,
    tags: `${rng.string(5)},${rng.string(6)}`,
    is_enabled: 1,
    sort_order: rng.int(0, 12),
    ...overrides,
  };
}

function menuItem(rng: Rng, id: number, location: string, overrides: Partial<MenuRow> = {}): MenuRow {
  return {
    id,
    location,
    label: `${rng.pick(['Docs', 'Status', 'Blog', 'Support', 'Changelog'])} ${rng.string(3)}`,
    url: rng.bool() ? `/page/${rng.string(6)}` : `https://example.com/${rng.string(6)}`,
    icon: '',
    sort_order: id,
    is_visible: 1,
    open_in_new_tab: rng.bool() ? 1 : 0,
    ...overrides,
  };
}

export function randomPages(rng: Rng, count: number): PageRow[] {
  return Array.from({ length: count }, (_, i) => ({
    id: 500 + i,
    slug: `${rng.pick(['about', 'privacy', 'terms', 'contact'])}-${rng.string(4)}`,
    title: `${rng.pick(['About', 'Privacy', 'Terms', 'Contact'])} ${rng.string(4)}`,
    sort_order: i + 1,
    seo_noindex: 0,
  }));
}

export function randomMenus(rng: Rng): SiteConfig['menus'] {
  const header = Array.from({ length: rng.int(1, 4) }, (_, i) => menuItem(rng, 700 + i, 'header'));
  // Always one entry of each kind the top bar must handle.
  header.push(menuItem(rng, 710, 'header', { label: `Hidden ${rng.string(4)}`, is_visible: 0 }));
  header.push(menuItem(rng, 711, 'header', { label: `External ${rng.string(4)}`, url: `https://example.org/${rng.string(5)}`, open_in_new_tab: 1 }));
  header.push(menuItem(rng, 712, 'header', { label: `Internal ${rng.string(4)}`, url: '/subnet', open_in_new_tab: 0 }));
  const footer = [
    menuItem(rng, 720, 'footer', { open_in_new_tab: 0 }),
    menuItem(rng, 721, 'footer', { label: `Hidden ${rng.string(4)}`, is_visible: 0 }),
    menuItem(rng, 722, 'footer', { url: `https://example.net/${rng.string(5)}`, open_in_new_tab: 1 }),
  ];
  return { header: rng.shuffle(header), footer };
}

/**
 * A configuration that differs from the real one in every way the shell reads:
 * which tools are enabled, their order (with ties), their texts, unknown tool
 * keys, site texts with their fall-backs, menus, pages and footer.
 */
export function randomConfig(rng: Rng, real: SiteConfig): SiteConfig {
  const config = stamp(rng, real);

  for (const tool of config.tools) {
    tool.is_enabled = rng.bool(0.7) ? 1 : 0;
    tool.sort_order = rng.int(-2, 6); // few values, many tools: ties are certain
    if (rng.bool(0.5)) tool.label = `${tool.label} ${rng.string(3).toUpperCase()}`;
    if (rng.bool(0.3)) tool.description = `${rng.pick(['Quickly', 'Safely', 'Reliably'])} ${tool.description}`;
    if (rng.bool(0.2)) tool.icon = '';
    if (rng.bool(0.2)) tool.color = '';
  }
  for (let i = rng.int(0, 2); i > 0; i--) config.tools.push(unknownTool(rng, config, { sort_order: rng.int(-2, 6) }));
  if (!config.tools.some(tool => tool.is_enabled === 1)) rng.pick(config.tools).is_enabled = 1;
  config.tools = rng.shuffle(config.tools);

  const s = config.settings;
  const maybe = (value: string) => rng.weighted([value, ''], [3, 1]);
  s.site_title = maybe(`Ops Desk ${rng.string(4)}`);
  s.site_description = maybe(`Described ${rng.string(8)}.`);
  s.site_tagline = maybe(`Tagline ${rng.string(5)}`);
  s.home_hero_title = maybe(`Hero ${rng.string(6)}`);
  s.home_hero_subtitle = maybe(`Subtitle ${rng.string(10)}.`);
  s.brand_icon = rng.pick(['bi-shield-lock-fill', 'bi-hdd-rack', 'bi bi-router', '']);
  s.favicon_emoji = rng.pick(['🛡️', '', '', '🧰']);
  s.announcement_enabled = rng.pick(['0', '1']);
  s.announcement_text = rng.pick(['', `Notice ${rng.string(8)}`]);
  s.announcement_type = rng.pick(['info', 'warning']);
  s.maintenance_mode = '0';

  config.menus = randomMenus(rng);
  config.pages = randomPages(rng, rng.int(0, 3));
  config.footer.footer_text = rng.pick([
    '',
    'SysAdmin Toolkit · GeoIP by MaxMind · All processing runs in your browser',
    'SysAdmin Toolkit · GeoIP by MaxMind · Local log analysis. Remote network lookups.',
    `Footer ${rng.string(8)}`,
  ]);
  config.footer.copyright_text = rng.pick(['', `© ${rng.int(2020, 2030)} ${rng.string(5)}`]);
  return config;
}

/** How many tools `randomConfig` left enabled, for a readable evidence file. */
export function describeConfig(config: SiteConfig): string {
  const tools = enabledTools(config).map(tool => `${tool.tool_key}(order ${tool.sort_order}, id ${tool.id})`);
  return `${tools.length} enabled: ${tools.join(', ')}`;
}
