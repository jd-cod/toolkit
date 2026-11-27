'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';
import { useTheme } from './ThemeProvider';
import { useSiteConfig } from './WorkspaceShell';
import { enabledTools, matchesTool, toolMetadata } from '@/lib/tool-catalog';
import type { MenuItem } from '@/lib/api';

interface NavbarProps {
  siteTitle?: string;
  brandIcon?: string;
  versionBadge?: string;
  menuItems?: MenuItem[];
}

export function SignalMark() {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M12 3 4.5 6v5c0 4.9 3 8.2 7.5 10 4.5-1.8 7.5-5.1 7.5-10V6Z" /><path d="m8.5 11.5 2.3 2.3 4.8-4.8" /></svg>;
}

export default function Navbar(props: NavbarProps) {
  const { theme, toggleTheme } = useTheme();
  const { config, loading, error, retry } = useSiteConfig();
  const pathname = usePathname();
  const commandDialog = useRef<HTMLDialogElement>(null);
  const drawer = useRef<HTMLDialogElement>(null);
  const search = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState('');
  const [isNavigating, setIsNavigating] = useState(false);
  const tools = enabledTools(config?.tools || []);
  const settings = config?.settings || {};
  const title = props.siteTitle || settings.site_title || 'SysAdmin Toolkit';
  const brandIcon = props.brandIcon || settings.favicon_emoji || settings.brand_icon;
  const version = props.versionBadge ?? settings.version_badge ?? 'v3.0';
  const menus = props.menuItems ?? config?.menus?.header ?? [];
  const currentTool = tools.find(tool => toolMetadata(tool).route === pathname);
  const currentPage = config?.pages.find(page => `/page/${page.slug}` === pathname);
  const currentLabel = pathname === '/' ? 'Overview' : currentTool?.label || currentPage?.title || (pathname.startsWith('/s/') ? 'Shared snapshot' : 'Tools');
  const visibleTools = tools.filter(tool => matchesTool(tool, query));

  useEffect(() => {
    setIsNavigating(false);
  }, [pathname]);

  const handleNavClick = (route: string) => {
    if (route === pathname) {
      if (route === '/nginx') {
        const backBtn = document.getElementById('dash-back-btn');
        if (backBtn && backBtn.offsetParent !== null) {
          backBtn.click();
        }
      }
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else {
      setIsNavigating(true);
    }
    if (drawer.current?.open) {
      setTimeout(() => {
        drawer.current?.close();
      }, 50);
    }
  };

  function openSearch() {
    drawer.current?.close();
    commandDialog.current?.showModal();
    search.current?.focus();
  }

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        drawer.current?.close();
        commandDialog.current?.showModal();
        search.current?.focus();
      }
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, []);

  const brand = (
    <Link href="/" prefetch={false} className="signal-brand" onClick={() => handleNavClick('/')}>
      <span className="signal-brand-mark">
        {brandIcon && !['🛡️', 'bi-shield-lock-fill', 'bi bi-shield-lock-fill'].includes(brandIcon)
          ? (/^bi[ -]/.test(brandIcon) ? <i className={`bi ${brandIcon}`} aria-hidden="true" /> : brandIcon)
          : <SignalMark />}
      </span>
      <span className="signal-brand-name">{title}<small>{settings.site_tagline || 'NETWORK & SECURITY'}</small></span>
    </Link>
  );

  function navigation() {
    return (
      <>
        <button type="button" className="signal-find-tool" onClick={openSearch}><i className="bi bi-search" aria-hidden="true" />Find a tool<kbd>⌘ K</kbd></button>
        <nav aria-label="Tool navigation">
          <Link href="/" prefetch={false} className={`signal-nav-link ${pathname === '/' ? 'is-active' : ''}`} aria-current={pathname === '/' ? 'page' : undefined} onClick={() => handleNavClick('/')}><i className="bi bi-grid" aria-hidden="true" />Overview</Link>
          {[
            { label: 'Observability', categories: ['Observability'] },
            { label: 'Network & security', categories: ['Network', 'Security'] },
            { label: 'Email', categories: ['Email'] },
            { label: 'Utilities', categories: ['Utilities'] },
            { label: 'Windows', categories: ['Windows'] },
          ].map(group => {
            const members = tools.filter(tool => group.categories.includes(toolMetadata(tool).category));
            return members.length > 0 && (
              <div key={group.label} className="signal-nav-group">
                <p className="signal-nav-caption">{group.label}</p>
                {members.map(tool => {
                  const meta = toolMetadata(tool);
                  return <Link key={tool.id} href={meta.route} prefetch={false} className={`signal-nav-link ${pathname === meta.route ? 'is-active' : ''}`} aria-current={pathname === meta.route ? 'page' : undefined} onClick={() => handleNavClick(meta.route)}><i className={`bi ${meta.icon}`} aria-hidden="true" /><span>{tool.label}</span></Link>;
                })}
              </div>
            );
          })}
          {loading && <p className="signal-nav-status" role="status">Loading tools…</p>}
          {error && <div className="signal-nav-status"><p>Tool navigation is temporarily unavailable.</p><button type="button" className="signal-button" onClick={retry}>Retry</button></div>}
        </nav>
        <div className="signal-sidebar-bottom">
          {config?.pages.length ? <nav aria-label="Site pages">{config.pages.map(page => <Link className="signal-nav-link" href={`/page/${page.slug}`} prefetch={false} key={page.id} onClick={() => handleNavClick(`/page/${page.slug}`)}><i className="bi bi-journal-text" aria-hidden="true" />{page.title}</Link>)}</nav> : null}
          <div className="signal-local-note"><strong><i className="bi bi-shield-check" aria-hidden="true" />Built for your workflow</strong><p>Network, security, and everyday utilities in one workspace.</p></div>
          <div className="signal-sidebar-version"><span>SysAdmin Toolkit</span><span>{version}</span></div>
        </div>
      </>
    );
  }

  return (
    <>
      {isNavigating && <div className="signal-nav-loading-bar" aria-hidden="true" />}
      <button className="signal-skip" type="button" onClick={() => { const main = document.querySelector('main'); main?.setAttribute('tabindex', '-1'); main?.focus(); }}>Skip to content</button>
      <aside className="signal-sidebar" aria-label="Workspace sidebar">{brand}{navigation()}</aside>
      <header className="signal-topbar" id="main-navbar">
        <div className="signal-mobile-brand">{brand}</div>
        <div className="signal-breadcrumb"><i className="bi bi-grid" aria-hidden="true" /><Link href="/" prefetch={false}>Workspace</Link><span>/</span><span aria-current="page">{currentLabel}</span></div>
        <div className="signal-top-actions">
          <nav className="signal-custom-menu" aria-label="Site navigation">{menus.filter(item => item.is_visible !== 0).map(item => <Link key={item.id} href={item.url} prefetch={false} target={item.open_in_new_tab ? '_blank' : undefined} rel={item.open_in_new_tab ? 'noopener noreferrer' : undefined}>{item.label}</Link>)}</nav>
          <button type="button" className="signal-icon-button" onClick={toggleTheme} aria-label="Toggle theme" id="theme-toggle-btn" title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}><i className={`bi ${theme === 'dark' ? 'bi-sun' : 'bi-moon'}`} aria-hidden="true" /></button>
          <button type="button" className="signal-icon-button signal-mobile-menu" aria-label="Open tool navigation" onClick={() => drawer.current?.showModal()}><i className="bi bi-list" aria-hidden="true" /></button>
        </div>
      </header>
      <dialog className="signal-drawer" ref={drawer} aria-label="Tool navigation menu" onClick={event => { if (event.target === event.currentTarget) drawer.current?.close(); }}>
        <div className="signal-drawer-inner"><div className="signal-drawer-heading">{brand}<button type="button" className="signal-icon-button" aria-label="Close navigation" onClick={() => drawer.current?.close()}><i className="bi bi-x-lg" aria-hidden="true" /></button></div>{navigation()}{menus.length > 0 && <nav className="signal-mobile-site-links" aria-label="Site links">{menus.filter(item => item.is_visible !== 0).map(item => <Link key={item.id} href={item.url} prefetch={false} target={item.open_in_new_tab ? '_blank' : undefined} rel={item.open_in_new_tab ? 'noopener noreferrer' : undefined}>{item.label}</Link>)}</nav>}</div>
      </dialog>
      <dialog className="signal-command" ref={commandDialog} aria-labelledby="signal-command-title" onClick={event => { if (event.target === event.currentTarget) commandDialog.current?.close(); }}>
        <div className="signal-command-inner">
          <div className="signal-command-heading"><h2 id="signal-command-title">Find a tool</h2><button className="signal-icon-button" type="button" aria-label="Close tool search" onClick={() => commandDialog.current?.close()}><i className="bi bi-x-lg" aria-hidden="true" /></button></div>
          <label className="signal-sr-only" htmlFor="signal-command-search">Search all tools</label>
          <input ref={search} id="signal-command-search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search tools, tasks, or keywords…" autoComplete="off" />
          <div className="signal-command-results">{visibleTools.map(tool => <Link href={toolMetadata(tool).route} prefetch={false} key={tool.id} onClick={() => { setIsNavigating(true); commandDialog.current?.close(); }}><i className={`bi ${toolMetadata(tool).icon}`} aria-hidden="true" /><span><strong>{tool.label}</strong><small>{toolMetadata(tool).category}</small></span><i className="bi bi-arrow-right" aria-hidden="true" /></Link>)}{!loading && visibleTools.length === 0 && <p role="status">No tools match “{query}”. Try a different search.</p>}</div>
          <p className="signal-command-hint">Tab to a result, Enter to open · Esc to close</p>
        </div>
      </dialog>
    </>
  );
}
