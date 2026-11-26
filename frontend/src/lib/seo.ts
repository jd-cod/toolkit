import type { Metadata } from 'next';
import type { SiteConfig, Tool } from './api';

export const SITE_URL = (
  process.env.NEXT_PUBLIC_SITE_URL ||
  process.env.SITE_URL ||
  'http://localhost:3000'
).replace(/\/+$/, '');

export const BRAND_NAME = 'SysAdmin Toolkit';

export const DEFAULT_TITLE = 'Free Sysadmin & Network Tools | SysAdmin Toolkit';

export const DEFAULT_DESCRIPTION =
  'Free online tools for sysadmins: analyze traffic logs, check DNS and SSL, look up ASN and WHOIS data, and calculate subnets, permissions and cron schedules.';

export interface ToolSeoDefault {
  title: string;
  description: string;
  path: string;
  category: 'NetworkingApplication' | 'SecurityApplication' | 'UtilitiesApplication';
}

export const TOOL_SEO_DEFAULTS: Record<string, ToolSeoDefault> = {
  nginx: {
    title: 'Traffic Log Analyzer',
    description:
      'Analyze web traffic and access logs to explore traffic patterns, status codes, bots and IP activity. Open local files in your browser or choose an available import method.',
    path: '/nginx',
    category: 'UtilitiesApplication',
  },
  dns: {
    title: 'DNS Lookup & Record Checker',
    description:
      'Look up DNS records including A, AAAA, MX, TXT and CNAME. Choose a resolver, inspect answers and TTLs, and troubleshoot domain configuration.',
    path: '/dns',
    category: 'NetworkingApplication',
  },
  ssl: {
    title: 'SSL Certificate Checker',
    description:
      'Check a domain’s SSL certificate, expiry date, issuer, hostname match and chain details. Understand certificate warnings before they affect visitors.',
    path: '/ssl',
    category: 'SecurityApplication',
  },
  whois: {
    title: 'WHOIS & Domain Registration Lookup',
    description:
      'Look up domain registration details through RDAP and WHOIS. Inspect registrar information, dates, statuses, nameservers and available DNSSEC data.',
    path: '/whois',
    category: 'NetworkingApplication',
  },
  asn: {
    title: 'ASN Lookup & IP Prefix Finder',
    description:
      'Find IP prefixes announced by an ASN. Explore IPv4 and IPv6 networks, filter results, check address containment and export supported firewall rules.',
    path: '/asn',
    category: 'NetworkingApplication',
  },
  abuse: {
    title: 'IP Reputation & Abuse Lookup',
    description:
      'Investigate IP addresses with network details, reverse DNS and available abuse reports. Compare reputation signals for single addresses or batches.',
    path: '/abuse',
    category: 'SecurityApplication',
  },
  myip: {
    title: 'What Is My IP? Public IP Lookup',
    description:
      'See your public IP address and available IPv4, IPv6, network and approximate location details. Understand what VPNs and proxies change.',
    path: '/myip',
    category: 'NetworkingApplication',
  },
  subnet: {
    title: 'IPv4 Subnet & CIDR Calculator',
    description:
      'Calculate IPv4 subnets from CIDR notation or a subnet mask. View network and broadcast addresses, usable host ranges and wildcard masks.',
    path: '/subnet',
    category: 'NetworkingApplication',
  },
  chmod: {
    title: 'Chmod Calculator for Linux Permissions',
    description:
      'Convert Linux file permissions between octal and symbolic notation. Set owner, group and other permissions, review special bits and copy a command.',
    path: '/chmod',
    category: 'UtilitiesApplication',
  },
  cron: {
    title: 'Crontab Builder & Cron Expression Generator',
    description:
      'Build five-field cron expressions with presets and execution previews. Understand scheduling fields and check the target server’s timezone.',
    path: '/cron',
    category: 'UtilitiesApplication',
  },
  password: {
    title: 'Password & Passphrase Generator',
    description:
      'Generate random passwords, passphrases and PINs in your browser. Choose length and generation settings, inspect strength and manage local history.',
    path: '/password-generator',
    category: 'SecurityApplication',
  },
};

export function formatTitle(title: string): string {
  const clean = title.trim();
  if (!clean) return DEFAULT_TITLE;
  if (clean.includes(BRAND_NAME)) return clean;
  return `${clean} | ${BRAND_NAME}`;
}

export function isRouteIndexable(
  path: string,
  options: { isSensitive?: boolean; seoNoindex?: boolean; isEnabled?: boolean } = {}
): boolean {
  if (options.isSensitive) return false;
  if (options.seoNoindex) return false;
  if (options.isEnabled === false) return false;
  if (path === '/admin' || path.startsWith('/admin/')) return false;
  if (path === '/login') return false;
  if (path === '/s' || path.startsWith('/s/')) return false;
  return true;
}

export function buildPageMetadata(options: {
  path: string;
  title?: string;
  description?: string;
  isSensitiveQuery?: boolean;
  noindex?: boolean;
  siteSettings?: Record<string, string>;
}): Metadata {
  const { path, title, description, isSensitiveQuery, noindex, siteSettings } = options;

  const resolvedTitle = formatTitle(title || siteSettings?.site_title || DEFAULT_TITLE);
  const resolvedDesc = (
    description ||
    siteSettings?.meta_description ||
    siteSettings?.site_description ||
    DEFAULT_DESCRIPTION
  ).trim();

  const canonicalUrl = `${SITE_URL}${path === '/' ? '' : path.split('?')[0]}`;
  const socialImage = siteSettings?.seo_social_image || '/og-image.png';
  const fullSocialImage = socialImage.startsWith('http') ? socialImage : `${SITE_URL}${socialImage}`;

  const indexable = isRouteIndexable(path, {
    isSensitive: isSensitiveQuery,
    seoNoindex: noindex,
  });

  const isStrictPrivate =
    path === '/admin' ||
    path.startsWith('/admin/') ||
    path === '/login' ||
    path === '/s' ||
    path.startsWith('/s/') ||
    Boolean(isSensitiveQuery);

  const robots = indexable
    ? { index: true, follow: true }
    : isStrictPrivate
      ? { index: false, follow: false }
      : { index: false, follow: true };

  const verification: Metadata['verification'] = {};
  if (siteSettings?.seo_google_verification) {
    verification.google = siteSettings.seo_google_verification;
  }
  if (siteSettings?.seo_bing_verification) {
    verification.other = {
      'msvalidate.01': siteSettings.seo_bing_verification,
    };
  }

  return {
    title: resolvedTitle,
    description: resolvedDesc,
    alternates: {
      canonical: canonicalUrl,
    },
    robots,
    openGraph: {
      title: resolvedTitle,
      description: resolvedDesc,
      url: canonicalUrl,
      siteName: BRAND_NAME,
      type: 'website',
      images: [
        {
          url: fullSocialImage,
          width: 1200,
          height: 630,
          alt: resolvedTitle,
        },
      ],
    },
    twitter: {
      card: 'summary_large_image',
      title: resolvedTitle,
      description: resolvedDesc,
      images: [fullSocialImage],
    },
    ...(Object.keys(verification).length > 0 ? { verification } : {}),
  };
}

export function buildToolMetadata(
  toolKey: string,
  toolOverride?: Partial<Tool>,
  siteSettings?: Record<string, string>
): Metadata {
  const toolDefaults = TOOL_SEO_DEFAULTS[toolKey];
  const title = toolOverride?.meta_title || toolDefaults?.title || toolOverride?.label || toolKey;
  const description =
    toolOverride?.meta_description ||
    toolDefaults?.description ||
    toolOverride?.description ||
    DEFAULT_DESCRIPTION;

  const path = toolDefaults?.path || `/${encodeURIComponent(toolKey)}`;

  const isEnabled = toolOverride?.is_enabled !== undefined ? Boolean(Number(toolOverride.is_enabled)) : true;
  const seoNoindex = Boolean(toolOverride?.seo_noindex);

  return buildPageMetadata({
    path,
    title,
    description,
    noindex: !isEnabled || seoNoindex,
    siteSettings,
  });
}

export function buildStructuredData(
  options:
    | { type: 'website'; siteSettings?: Record<string, string> }
    | { type: 'tool'; toolKey: string; toolOverride?: Partial<Tool> }
) {
  if (options.type === 'website') {
    return {
      '@context': 'https://schema.org',
      '@type': 'WebSite',
      name: BRAND_NAME,
      url: SITE_URL,
      description: options.siteSettings?.meta_description || DEFAULT_DESCRIPTION,
    };
  }

  const { toolKey, toolOverride } = options;
  const toolDefaults = TOOL_SEO_DEFAULTS[toolKey];
  const name = toolOverride?.label || toolDefaults?.title || toolKey;
  const description = toolOverride?.description || toolDefaults?.description || DEFAULT_DESCRIPTION;
  const path = toolDefaults?.path || `/${encodeURIComponent(toolKey)}`;

  return {
    '@context': 'https://schema.org',
    '@type': 'WebApplication',
    name,
    url: `${SITE_URL}${path}`,
    description,
    applicationCategory: toolDefaults?.category || 'UtilitiesApplication',
    operatingSystem: 'Any',
    offers: {
      '@type': 'Offer',
      price: '0',
      priceCurrency: 'USD',
    },
  };
}

export function getSitemapEntries(config: SiteConfig): Array<{
  url: string;
  lastModified?: Date;
  changeFrequency?: 'always' | 'hourly' | 'daily' | 'weekly' | 'monthly' | 'yearly' | 'never';
  priority?: number;
}> {
  const entries: Array<{
    url: string;
    lastModified?: Date;
    changeFrequency?: 'always' | 'hourly' | 'daily' | 'weekly' | 'monthly' | 'yearly' | 'never';
    priority?: number;
  }> = [];

  // 1. Homepage
  entries.push({
    url: `${SITE_URL}/`,
    changeFrequency: 'daily',
    priority: 1.0,
  });

  // 2. Enabled Tools (excluding those marked seo_noindex)
  for (const tool of config.tools || []) {
    if (!Number(tool.is_enabled)) continue;
    if (tool.seo_noindex) continue;
    const defaults = TOOL_SEO_DEFAULTS[tool.tool_key];
    const path = defaults?.path || `/${encodeURIComponent(tool.tool_key)}`;
    entries.push({
      url: `${SITE_URL}${path}`,
      changeFrequency: 'weekly',
      priority: 0.9,
    });
  }

  // 3. Published CMS Pages (excluding those marked seo_noindex)
  for (const page of config.pages || []) {
    if (page.seo_noindex) continue;
    entries.push({
      url: `${SITE_URL}/page/${encodeURIComponent(page.slug)}`,
      changeFrequency: 'monthly',
      priority: 0.7,
    });
  }

  return entries;
}
