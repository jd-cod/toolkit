'use client';

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { usePathname } from 'next/navigation';
import { api, type SiteConfig } from '@/lib/api';
import StyleInjector from './StyleInjector';

interface SiteConfigState {
  config: SiteConfig | null;
  loading: boolean;
  error: string;
  retry: () => void;
}
const SiteConfigContext = createContext<SiteConfigState>({ config: null, loading: true, error: '', retry: () => {} });

export function useSiteConfig() {
  return useContext(SiteConfigContext);
}

function PublicWorkspace({
  children,
  pathname,
  initialConfig,
}: {
  children: ReactNode;
  pathname: string;
  initialConfig?: SiteConfig | null;
}) {
  const [config, setConfig] = useState<SiteConfig | null>(initialConfig ?? null);
  const [loading, setLoading] = useState(initialConfig ? false : true);
  const [error, setError] = useState('');
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let active = true;
    api.getSiteConfig()
      .then(data => { if (active) { setConfig(data); setError(''); } })
      .catch((err: unknown) => {
        if (active) setError(err instanceof Error ? err.message : 'Unable to load tool configuration.');
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [attempt]);

  const retry = () => {
    setLoading(true);
    setError('');
    setAttempt(current => current + 1);
  };

  return (
    <SiteConfigContext.Provider value={{ config, loading, error, retry }}>
      <div className="signal-workspace" data-signal-route={pathname.split('/')[1] || 'home'}>
        <StyleInjector settings={config?.settings || {}} />
        {children}
      </div>
    </SiteConfigContext.Provider>
  );
}

export default function WorkspaceShell({
  children,
  initialConfig,
}: {
  children: ReactNode;
  initialConfig?: SiteConfig | null;
}) {
  const pathname = usePathname();
  // Keep the existing admin/login layout and theme isolated from the public redesign.
  if (pathname === '/admin' || pathname.startsWith('/admin/') || pathname === '/login') return children;
  return <PublicWorkspace pathname={pathname} initialConfig={initialConfig}>{children}</PublicWorkspace>;
}
