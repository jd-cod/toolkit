import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TOOL_SEO_DEFAULTS } from '../../frontend/src/lib/seo.ts';
import { toolMetadata, TOOL_CATEGORIES } from '../../frontend/src/lib/tool-catalog.ts';

/**
 * A tool is registered in several files (see docs/TOOLS_ROADMAP.md, "How a
 * tool is wired"). Missing one of them fails quietly: a card that links to a
 * 404, a page with no title, or a tool that never reaches the database. This
 * test fails loudly instead.
 */

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = path => readFileSync(join(root, path), 'utf8');

const seeds = [...read('backend/src/routes/public.js').matchAll(/^\s*\['([a-z0-9-]+)',\s*(?:'[^']*'|"[^"]*"),[\s\S]*?,\s*1,\s*(\d+)\],?$/gm)]
  .map(match => ({ key: match[1], order: Number(match[2]) }));
const seedKeys = seeds.map(seed => seed.key);
const migrations = readdirSync(join(root, 'backend/migrations')).map(name => read(`backend/migrations/${name}`)).join('\n');
const guides = read('frontend/src/components/ToolWorkspace.tsx');
const NEW_TOOLS = [
  'email-auth', 'blacklist', 'email-headers', 'smtp-test', 'http-headers', 'port-check', 'cert-decoder', 'sshd-audit',
  'systemd-timer', 'firewall-rules', 'rsync', 'auth-log', 'mail-log', 'windows-events', 'windows-errors', 'robocopy',
];

test('the seed list in public.js is readable and contains the tools pack', () => {
  assert.ok(seedKeys.length >= 26, `only ${seedKeys.length} seed rows were recognised`);
  for (const key of NEW_TOOLS) assert.ok(seedKeys.includes(key), `${key} is missing from DEFAULT_TOOLS in public.js`);
});

test('every seeded tool has a route, SEO defaults, a page and a registry row', () => {
  for (const key of seedKeys) {
    const meta = toolMetadata({ tool_key: key });
    assert.notEqual(meta.processing, 'Utility', `${key} is missing from tool-catalog.ts`);
    assert.ok(TOOL_CATEGORIES.includes(meta.category), `${key} has an unknown category`);

    const seo = TOOL_SEO_DEFAULTS[key];
    assert.ok(seo, `${key} is missing from TOOL_SEO_DEFAULTS`);
    assert.equal(seo.path, meta.route, `${key}: SEO path and catalog route differ`);
    if (NEW_TOOLS.includes(key)) assert.ok(seo.description.length <= 170, `${key}: meta description is ${seo.description.length} characters, keep it under 170`);

    assert.ok(existsSync(join(root, 'frontend/src/app', meta.route.slice(1), 'page.tsx')), `${key} has no page at app${meta.route}/page.tsx`);
    assert.ok(migrations.includes(`'${key}'`) || key === 'myip', `${key} is not registered by any migration`);
  }
});

test('every tool in the pack has side-guide text and a two-line layout', () => {
  for (const key of NEW_TOOLS) {
    assert.match(guides, new RegExp(`^\\s*'?${key}'?: \\{ title:`, 'm'), `${key} is missing from GUIDES in ToolWorkspace.tsx`);
    const layout = read(`frontend/src/app/${key}/layout.tsx`);
    assert.ok(layout.includes(`createToolLayout('${key}')`), `${key}/layout.tsx does not use createToolLayout('${key}')`);
  }
});

test('sort_order is unique across seeded tools', () => {
  const orders = [...seeds.map(seed => seed.order), 10]; // 10 is `myip`, registered by migration 002 only
  assert.deepEqual(orders.filter((order, index) => orders.indexOf(order) !== index), []);
});
