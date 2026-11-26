import type { MetadataRoute } from 'next';
import { getSiteConfigServer } from '@/lib/site-config.server';
import { getSitemapEntries, SITE_URL } from '@/lib/seo';

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const config = await getSiteConfigServer();

  if (!config) {
    // Fallback to core enabled static landing routes if backend is temporarily offline
    return [
      { url: `${SITE_URL}/`, changeFrequency: 'daily', priority: 1.0 },
      { url: `${SITE_URL}/nginx`, changeFrequency: 'weekly', priority: 0.9 },
      { url: `${SITE_URL}/dns`, changeFrequency: 'weekly', priority: 0.9 },
      { url: `${SITE_URL}/ssl`, changeFrequency: 'weekly', priority: 0.9 },
      { url: `${SITE_URL}/whois`, changeFrequency: 'weekly', priority: 0.9 },
      { url: `${SITE_URL}/asn`, changeFrequency: 'weekly', priority: 0.9 },
      { url: `${SITE_URL}/abuse`, changeFrequency: 'weekly', priority: 0.9 },
      { url: `${SITE_URL}/myip`, changeFrequency: 'weekly', priority: 0.9 },
      { url: `${SITE_URL}/subnet`, changeFrequency: 'weekly', priority: 0.9 },
      { url: `${SITE_URL}/chmod`, changeFrequency: 'weekly', priority: 0.9 },
      { url: `${SITE_URL}/cron`, changeFrequency: 'weekly', priority: 0.9 },
      { url: `${SITE_URL}/password-generator`, changeFrequency: 'weekly', priority: 0.9 },
    ];
  }

  return getSitemapEntries(config);
}
