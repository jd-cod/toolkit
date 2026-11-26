'use client';

import Link from 'next/link';
import { useState } from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ToolCard from '@/components/ToolCard';
import { useSiteConfig } from '@/components/WorkspaceShell';
import { enabledTools, matchesTool, toolMetadata, TOOL_CATEGORIES, type ToolCategory } from '@/lib/tool-catalog';
import { buildStructuredData } from '@/lib/seo';

function SamplePreview() {
  return (
    <div className="signal-preview" aria-label="Illustrative sample analysis preview">
      <div className="signal-preview-heading"><span><i className="bi bi-three-dots" aria-hidden="true" /> access.log</span><span>Sample analysis</span></div>
      <div className="signal-preview-metrics"><div><small>Requests</small><strong>128.9k</strong></div><div><small>Unique IPs</small><strong>3,218</strong></div><div><small>Human traffic</small><strong>73.2<small>%</small></strong></div></div>
      <svg viewBox="0 0 480 110" role="img" aria-label="Illustrative request volume over a day">
        <defs><linearGradient id="signal-preview-fill" x1="0" y1="0" x2="0" y2="1"><stop stopColor="currentColor" stopOpacity=".2" /><stop offset="1" stopColor="currentColor" stopOpacity="0" /></linearGradient></defs>
        <path d="M0 25H480M0 55H480M0 85H480" stroke="var(--border-color)" strokeDasharray="3 7" fill="none" />
        <path d="M0 90 14 85 27 89 40 79 54 84 66 78 78 82 92 67 104 75 117 63 128 72 143 65 156 75 168 61 181 69 194 48 207 53 220 41 233 49 246 37 259 45 272 61 285 55 298 65 311 49 324 54 337 38 350 46 363 39 376 45 389 31 402 41 415 37 428 49 441 38 454 42 467 31 480 35V110H0Z" fill="url(#signal-preview-fill)" />
        <path d="M0 90 14 85 27 89 40 79 54 84 66 78 78 82 92 67 104 75 117 63 128 72 143 65 156 75 168 61 181 69 194 48 207 53 220 41 233 49 246 37 259 45 272 61 285 55 298 65 311 49 324 54 337 38 350 46 363 39 376 45 389 31 402 41 415 37 428 49 441 38 454 42 467 31 480 35" stroke="currentColor" strokeWidth="1.8" fill="none" />
      </svg>
      <div className="signal-preview-axis"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:59</span></div>
      <p><i className="bi bi-lock" aria-hidden="true" /> Illustrative data · local-file analysis stays in your browser.</p>
    </div>
  );
}

export default function HomePage() {
  const { config, loading, error, retry } = useSiteConfig();
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState<ToolCategory | 'All tools'>('All tools');
  const settings = config?.settings || {};
  const tools = enabledTools(config?.tools || []);
  const visibleTools = tools.filter(tool => (category === 'All tools' || toolMetadata(tool).category === category) && matchesTool(tool, query));
  const hasNginx = tools.some(tool => tool.tool_key === 'nginx');
  const websiteSchema = buildStructuredData({ type: 'website', siteSettings: settings });

  if (settings.maintenance_mode === '1') {
    return <><Navbar /><main className="main-content signal-empty"><i className="bi bi-tools" aria-hidden="true" /><h1>Under Maintenance</h1><p>{settings.maintenance_message || 'We are currently performing scheduled maintenance. Please check back soon.'}</p></main></>;
  }

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(websiteSchema) }}
      />
      <Navbar />
      {settings.announcement_enabled === '1' && settings.announcement_text && <div className={`announcement-bar ${settings.announcement_type === 'warning' ? 'warning' : ''}`}>{settings.announcement_text}</div>}
      <main className="main-content signal-home">
        <header className="signal-page-heading" id="hero-section">
          <div><h1>{settings.home_hero_title || settings.site_title || 'Free SysAdmin & Network Tools'}</h1><p>{settings.home_hero_subtitle || settings.site_description || 'Essential network diagnostics, log analysis, and system administration tools.'}</p></div>
          {!loading && !error && <span className="signal-tool-count"><i className="bi bi-grid" aria-hidden="true" /> {tools.length} purpose-built tools</span>}
        </header>

        {hasNginx && <>
          <section className="signal-feature" aria-labelledby="signal-feature-title">
            <div className="signal-feature-copy"><p className="signal-eyebrow">Observability, without the overhead</p><h2 id="signal-feature-title">Your logs.<br /><span>A clearer picture.</span></h2><p>Turn raw web access logs into traffic insights, bot intelligence, and the signals that matter.</p><div className="signal-feature-actions"><Link className="signal-button signal-primary" href="/nginx" prefetch={false}><i className="bi bi-arrow-right" aria-hidden="true" /> Analyze your logs</Link><Link className="signal-button" href="/nginx?sample=ecommerce-normal.log" prefetch={false}>Explore a sample</Link></div></div>
            <SamplePreview />
          </section>
          <div className="signal-trust-strip"><span><i className="bi bi-shield-check" aria-hidden="true" /> Privacy-conscious by design</span><span><i className="bi bi-lightning-charge" aria-hidden="true" /> No setup required</span><span><i className="bi bi-terminal" aria-hidden="true" /> Made for real sysadmin work</span></div>
        </>}

        <section className="signal-directory" aria-labelledby="signal-directory-title">
          <div className="signal-section-heading"><div><h2 id="signal-directory-title">The right tool, one click away.</h2><p>Inspect, troubleshoot, and get back to work.</p></div><span className="signal-eyebrow">{settings.site_tagline || 'Network & security suite'}</span></div>
          <div className="signal-directory-controls">
            <div className="signal-category-filters" role="group" aria-label="Filter tools by category">{(['All tools', ...TOOL_CATEGORIES] as const).map(item => <button key={item} type="button" aria-pressed={category === item} onClick={() => setCategory(item)}>{item}<span>{item === 'All tools' ? tools.length : tools.filter(tool => toolMetadata(tool).category === item).length}</span></button>)}</div>
            <label className="signal-directory-search"><i className="bi bi-search" aria-hidden="true" /><span className="signal-sr-only">Search tools</span><input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search tools, tasks, or keywords…" /></label>
          </div>
          {loading && <div className="tool-grid" aria-label="Loading tools" aria-busy="true">{Array.from({ length: 6 }, (_, index) => <div className="signal-card-skeleton" key={index}><div className="skeleton" /><div className="skeleton" /><div className="skeleton" /></div>)}</div>}
          {error && !loading && <div className="signal-empty" role="alert"><i className="bi bi-cloud-slash" aria-hidden="true" /><h3>Tool directory unavailable</h3><p>{error}</p><button type="button" className="signal-button" onClick={retry}>Try again</button></div>}
          {!loading && !error && <>
            <p className="signal-sr-only" role="status">{visibleTools.length} tools found</p>
            <div className="tool-grid" id="tool-grid">{visibleTools.map(tool => <ToolCard key={tool.id} tool={tool} />)}</div>
            {visibleTools.length === 0 && <div className="signal-empty"><i className="bi bi-search" aria-hidden="true" /><h3>{tools.length ? 'No tools found' : 'No tools enabled yet'}</h3><p>{tools.length ? 'Try a different keyword or browse all tools.' : 'Check back soon for available tools.'}</p>{tools.length > 0 && <button type="button" className="signal-button" onClick={() => { setQuery(''); setCategory('All tools'); }}>Clear filters</button>}</div>}
          </>}
        </section>
        {hasNginx && <div className="signal-terminal-strip"><i className="bi bi-terminal" aria-hidden="true" /><div><strong>From a terminal to an answer.</strong><p>Upload a local log file, paste a snippet, or use a remote source.</p></div><Link href="/nginx" prefetch={false} className="signal-button">Try the traffic log analyzer <i className="bi bi-arrow-right" aria-hidden="true" /></Link></div>}
      </main>
      <Footer />
    </>
  );
}
