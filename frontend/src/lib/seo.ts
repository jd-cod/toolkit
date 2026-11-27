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
    title: 'IPv4 & IPv6 Subnet Calculator',
    description:
      'Calculate IPv4 and IPv6 subnets from CIDR notation or a subnet mask. View network ranges, usable hosts, wildcard masks and /64 counts.',
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
  'email-auth': {
    title: 'SPF, DKIM & DMARC Checker',
    description:
      'Check a domain’s email authentication: MX records, SPF syntax and lookup count, DKIM selectors, DMARC policy, MTA-STS, TLS-RPT and BIMI, with clear findings.',
    path: '/email-auth',
    category: 'NetworkingApplication',
  },
  blacklist: {
    title: 'Email Blacklist (DNSBL) Check',
    description:
      'Check whether an IP address or mail server is listed on common DNS blacklists such as Spamhaus, SpamCop and Barracuda, and see which lists could not be queried.',
    path: '/blacklist',
    category: 'SecurityApplication',
  },
  'email-headers': {
    title: 'Email Header Analyzer',
    description:
      'Paste raw email headers to trace every relay hop and delay, and read SPF, DKIM and DMARC results. Headers are parsed in your browser and never uploaded.',
    path: '/email-headers',
    category: 'UtilitiesApplication',
  },
  'smtp-test': {
    title: 'SMTP Server Test',
    description:
      'Connect to a mail server and review its banner, EHLO extensions, STARTTLS support, certificate and response times. No message is sent.',
    path: '/smtp-test',
    category: 'NetworkingApplication',
  },
  'http-headers': {
    title: 'HTTP Headers & Redirect Checker',
    description:
      'Inspect HTTP response headers, follow the full redirect chain and audit security headers such as HSTS, CSP and cookie flags for any public URL.',
    path: '/http-headers',
    category: 'NetworkingApplication',
  },
  'port-check': {
    title: 'Open Port Checker',
    description:
      'Test whether TCP ports are reachable from the internet on your server or public IP. Check common service ports or a custom list.',
    path: '/port-check',
    category: 'NetworkingApplication',
  },
  'cert-decoder': {
    title: 'Certificate & CSR Decoder',
    description:
      'Decode PEM certificates and CSRs, and check that a private key matches a certificate. Everything is processed in your browser; keys are never uploaded.',
    path: '/cert-decoder',
    category: 'SecurityApplication',
  },
  'sshd-audit': {
    title: 'SSH Server Config Auditor',
    description:
      'Paste an sshd_config to find risky settings such as root login, password authentication and weak algorithms, with a hardened snippet to copy.',
    path: '/sshd-audit',
    category: 'SecurityApplication',
  },
  'systemd-timer': {
    title: 'systemd Timer Generator',
    description:
      'Convert a cron schedule to a systemd OnCalendar expression and generate matching .timer and .service unit files with install commands.',
    path: '/systemd-timer',
    category: 'UtilitiesApplication',
  },
  'firewall-rules': {
    title: 'Firewall Rule Generator',
    description:
      'Generate matching firewall rules for ufw, firewalld, nftables, iptables and Windows Firewall from one form: action, protocol, ports and source.',
    path: '/firewall-rules',
    category: 'SecurityApplication',
  },
  rsync: {
    title: 'rsync Command Builder',
    description:
      'Build an rsync command from options with every flag explained: archive mode, deletes, excludes, SSH port and key, bandwidth limits and dry runs.',
    path: '/rsync',
    category: 'UtilitiesApplication',
  },
  'auth-log': {
    title: 'SSH Auth Log Analyzer',
    description:
      'Analyze auth.log or secure logs in your browser: failed SSH logins, attacking IPs, targeted usernames, successful logins and a block list to copy.',
    path: '/auth-log',
    category: 'SecurityApplication',
  },
  'mail-log': {
    title: 'Postfix Mail Log Analyzer',
    description:
      'Analyze Postfix mail logs in your browser: delivered, deferred and bounced mail, reject reasons, top senders and failed SASL logins.',
    path: '/mail-log',
    category: 'UtilitiesApplication',
  },
  'windows-events': {
    title: 'Windows Event ID Lookup',
    description:
      'Look up common Windows Event IDs for logons, account changes, services and system events, with logon types and failure codes explained.',
    path: '/windows-events',
    category: 'UtilitiesApplication',
  },
  'windows-errors': {
    title: 'Windows Error Code Lookup',
    description:
      'Decode Windows error codes: Win32, HRESULT, NTSTATUS, Windows Update and stop codes, with the HRESULT fields broken down.',
    path: '/windows-errors',
    category: 'UtilitiesApplication',
  },
  robocopy: {
    title: 'Robocopy Command Builder',
    description:
      'Build a robocopy command from options with every switch explained, warnings for destructive switches and the exit codes decoded.',
    path: '/robocopy',
    category: 'UtilitiesApplication',
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
