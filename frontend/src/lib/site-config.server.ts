import { cache } from 'react';
import type { SiteConfig } from './api';

const internalApiBase = (
  process.env.BACKEND_INTERNAL_URL ||
  process.env.BACKEND_API_URL ||
  'http://127.0.0.1:4000/api'
).replace(/\/+$/, '');

/**
 * Server-only cached loader for public site configuration.
 * Uses React cache() for request-scoped deduplication and cache: 'no-store'
 * so administrative changes (tool ordering, SEO overrides, toggles) are
 * reflected immediately without waiting for stale cache or manual invalidation.
 */
export const getSiteConfigServer = cache(async (): Promise<SiteConfig | null> => {
  try {
    const res = await fetch(`${internalApiBase}/site/config`, {
      cache: 'no-store',
      headers: {
        Accept: 'application/json',
      },
    });
    if (!res.ok) {
      console.warn(`[site-config.server] Upstream config returned HTTP ${res.status}`);
      return null;
    }
    return (await res.json()) as SiteConfig;
  } catch (err: unknown) {
    if (typeof err === 'object' && err !== null && 'digest' in err) {
      throw err;
    }
    console.warn(
      `[site-config.server] Unable to connect to backend: ${err instanceof Error ? err.message : String(err)}`
    );
    return null;
  }
});
