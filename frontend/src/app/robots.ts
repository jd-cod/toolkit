import type { MetadataRoute } from 'next';
import { SITE_URL } from '@/lib/seo';

export default function robots(): MetadataRoute.Robots {
  // Allow indexing on production; internal /api/ and /ingest endpoints
  // are disallowed. /admin, /login, and /s/ are NOT disallowed in robots.txt
  // so search crawlers can fetch the pages and read their explicit `noindex` tags.
  return {
    rules: {
      userAgent: '*',
      allow: '/',
      disallow: ['/api/', '/ingest'],
    },
    sitemap: `${SITE_URL}/sitemap.xml`,
  };
}
