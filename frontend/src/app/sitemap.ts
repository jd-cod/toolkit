import type { MetadataRoute } from 'next';
import { getSiteConfigServer } from '@/lib/site-config.server';
import { getSitemapEntries, SITE_URL, TOOL_SEO_DEFAULTS } from '@/lib/seo';

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const config = await getSiteConfigServer();

  if (!config) {
    // Fallback to core enabled static landing routes if backend is temporarily offline
    return [
      { url: `${SITE_URL}/`, changeFrequency: 'daily', priority: 1.0 },
      ...Object.values(TOOL_SEO_DEFAULTS).map(tool => ({
        url: `${SITE_URL}${tool.path}`,
        changeFrequency: 'weekly' as const,
        priority: 0.9,
      })),
    ];
  }

  return getSitemapEntries(config);
}
