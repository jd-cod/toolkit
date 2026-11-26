/**
 * API Client — Central fetch wrapper for the Fastify backend.
 * All API calls go through here.
 */

const API_BASE = (process.env.NEXT_PUBLIC_API_URL || '/api').replace(/\/$/, '');
import type { AbuseResult, GlobalDnsRegion, IPInfoEntry, SSLResult } from './tool-results';
import type { ShareOptions, SnapshotTool } from './share';

interface RequestOptions extends Omit<RequestInit, 'body'> {
  body?: unknown;
}

async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { body, headers: customHeaders, ...rest } = options;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(customHeaders as Record<string, string>),
  };

  const config: RequestInit = {
    ...rest,
    headers,
    credentials: 'include', // Send cookies for admin auth
  };

  if (body) {
    config.body = JSON.stringify(body);
  }

  const response = await fetch(`${API_BASE}${endpoint}`, config);

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
    throw new Error(error.error || `Request failed: ${response.status}`);
  }

  return response.json();
}

// ─── Public API ───

export interface SiteConfig {
  settings: Record<string, string>;
  tools: Tool[];
  menus: { header: MenuItem[]; footer: MenuItem[] };
  footer: Record<string, string>;
  pages: { id: number; slug: string; title: string; sort_order: number; seo_noindex?: number }[];
}

export interface Tool {
  id: number;
  tool_key: string;
  label: string;
  description: string;
  icon: string;
  color: string;
  tags: string;
  is_enabled: number;
  sort_order: number;
  meta_title?: string;
  meta_description?: string;
  seo_noindex?: number;
}

export interface MenuItem {
  id: number;
  location: string;
  label: string;
  url: string;
  icon: string;
  sort_order: number;
  is_visible: number;
  open_in_new_tab: number;
}

export interface WhoisContact {
  name: string;
  email: string;
  phone: string;
}

export interface WhoisSnapshot {
  domain: string;
  query_domain: string;
  data_source: 'rdap' | 'whois';
  registered: boolean;
  status_labels: string[];
  status_codes: string[];
  registrar: string;
  registrar_iana_id: string;
  abuse_email: string;
  abuse_phone: string;
  creation_date: string;
  updated_date: string;
  expiry_date: string;
  days_until_expiry: number | null;
  nameservers: string[];
  dns_nameservers: string[];
  nameserver_match: boolean | null;
  nameserver_only_in_whois: string[];
  nameserver_only_in_dns: string[];
  dnssec: 'signed' | 'unsigned' | 'unknown';
  privacy_detected: boolean;
  privacy_provider: string;
  contacts: {
    registrant: WhoisContact;
    admin: WhoisContact;
    tech: WhoisContact;
  };
  risk_signals: string[];
  raw_response: string;
  raw_whois: string;
  rdap_metadata?: {
    base_url?: string;
    handle?: string;
  } | null;
  checked_at_utc: string;
}

export interface CreatedShareResponse {
  success: boolean;
  code: string;
  url: string;
  expires_at: string | null;
  has_password: boolean;
}

function createSnapshotShare(data: {
  tool: SnapshotTool;
  subject: string;
  title: string;
  expiry?: string;
  password?: string;
  checked_at_utc?: string;
  snapshot: unknown;
}) {
  return request<CreatedShareResponse>('/share/snapshot', { method: 'POST', body: data });
}

/** Builds the `create` callback the share dialog needs for a tool that shares a snapshot of its result. */
export function snapshotShare(tool: SnapshotTool, subject: string, getSnapshot: () => unknown, checkedAt?: string) {
  return (options: ShareOptions) =>
    createSnapshotShare({ tool, subject, checked_at_utc: checkedAt, snapshot: getSnapshot(), ...options });
}

export const api = {
  // Site config (public)
  getSiteConfig: () => request<SiteConfig>('/site/config'),

  // Health
  getHealth: () => request<{ status: string; database: string }>('/health'),

  // Admin auth
  login: (username: string, password: string) =>
    request<{ success: boolean; username: string }>('/admin/login', {
      method: 'POST',
      body: { username, password },
    }),

  logout: () => request('/admin/logout', { method: 'POST' }),

  getMe: () => request<{ username: string; id: number }>('/admin/me'),

  // Tool-specific endpoints
  checkAbuse: (ips: { ip: string; hits: number }[], max?: number) =>
    request<AbuseResult>('/abuse', { method: 'POST', body: { ips, max } }),

  lookupASN: (asn: string) =>
    request<Record<string, unknown>>('/asn', { method: 'POST', body: { asn } }),

  lookupDNS: (domain: string, type: string, resolver: string) =>
    request<Record<string, unknown>>('/dns', { method: 'POST', body: { domain, type, resolver } }),

  lookupGlobalDNS: (domain: string, type: string) =>
    request<{ domain: string; type: string; results: GlobalDnsRegion[]; error?: string }>('/dns/global', { method: 'POST', body: { domain, type } }),
  getGlobalDnsCapability: () => request<{ available: boolean }>('/dns/global-capability'),

  lookupWhois: (domain: string) =>
    request<WhoisSnapshot>('/whois', { method: 'POST', body: { domain } }),

  checkSSL: (domain: string, port?: number) =>
    request<SSLResult>('/ssl', { method: 'POST', body: { domain, port } }),

  checkIPs: (ips: string[]) =>
    request<{ results: IPInfoEntry[]; error?: string }>('/ipinfo', { method: 'POST', body: { ips } }),

  // R2 object storage. These were previously named fetchGist/createGist, which
  // described a backend that no longer exists — the routes they call are the R2
  // storage API. Both were unreferenced; if you need them, use the R2 names.

  // Shares
  createShare: (data: { title: string; shareCode: string; source_url?: string; expiry?: string; password?: string }) =>
    request<CreatedShareResponse>('/share', { method: 'POST', body: data }),

  createSnapshotShare,

  createDnsShare: (data: { title: string; domain: string; expiry?: string; password?: string; checked_at_utc: string; snapshot: unknown }) =>
    createSnapshotShare({ tool: 'dns', subject: data.domain, ...data }),

  createWhoisShare: (data: { title: string; domain: string; expiry?: string; password?: string; checked_at_utc: string; snapshot: WhoisSnapshot }) =>
    createSnapshotShare({ tool: 'whois', subject: data.domain, ...data }),

  getShare: (code: string) => request<Record<string, unknown>>(`/share/${code}`),

  verifyShare: (code: string, password?: string) =>
    request<Record<string, unknown>>(`/share/${code}/verify`, { method: 'POST', body: { password } }),

  // What Is My IP
  getMyIP: (ip?: string | null) =>
    request<MyIPResult>(ip ? `/myip?ip=${encodeURIComponent(ip)}` : '/myip'),

  createMyIPShare: (data: { title: string; ip: string; expiry?: string; password?: string; checked_at_utc: string; snapshot: unknown }) =>
    createSnapshotShare({ tool: 'myip', subject: data.ip, ...data }),

  createAsnShare: (data: { title: string; asn: string; expiry?: string; password?: string; checked_at_utc: string; snapshot: unknown }) =>
    createSnapshotShare({ tool: 'asn', subject: data.asn, ...data }),

  searchASN: (query: string) =>
    request<{ results: { asn: string; name: string; holder: string; country: string; description: string }[] }>('/asn/search', {
      method: 'POST',
      body: { query },
    }),

  matchAsnIp: (asn: string, ip: string, prefixes: unknown[]) =>
    request<Record<string, unknown>>('/asn/match-ip', { method: 'POST', body: { asn, ip, prefixes } }),

  generateAsnRules: (data: {
    format: string;
    action: string;
    asn: string;
    orgName?: string;
    prefixes: unknown[];
  }) =>
    request<{ rules: string; total_prefixes: number; format: string; action: string }>('/asn/generate-rules', {
      method: 'POST',
      body: data,
    }),
};

export interface MyIPResult {
  ip: string;
  ip_version: string;
  city: string | null;
  region: string | null;
  region_code: string | null;
  country: string | null;
  country_code: string | null;
  registered_country: string | null;
  registered_country_code: string | null;
  represented_country: string | null;
  represented_country_code: string | null;
  represented_country_type: string | null;
  continent: string | null;
  continent_code: string | null;
  postal_code: string | null;
  accuracy_radius: number | null;
  latitude: number | null;
  longitude: number | null;
  metro_code: number | null;
  timezone: string | null;
  utc_offset: string | null;
  isp: string | null;
  org: string | null;
  asn: number | null;
  asn_name: string | null;
  domain: string | null;
  usage_type: string | null;
  proxy_type: string | null;
  proxy_detected: boolean;
  reverse_dns: string | null;
  network_type: string;
  ip2location_attribution_required?: boolean;
  data_sources: Record<string, string>;
  headers: {
    user_agent: string;
    accept_language: string;
    accept_encoding: string;
    referer: string;
    dnt: string;
  };
  checked_at_utc: string;
}
