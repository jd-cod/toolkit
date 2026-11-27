/** Response shapes of the server-backed tools in the 2026-11 tools pack. */

export interface ApiFinding {
  severity: 'critical' | 'warning' | 'info' | 'ok';
  title: string;
  detail?: string;
}

export type SectionStatus = 'pass' | 'warn' | 'fail' | 'missing' | 'error';

interface Section {
  status: SectionStatus;
  findings: ApiFinding[];
}

export interface SpfInclude {
  type: 'include' | 'redirect';
  domain: string;
  record: string;
  lookups: number;
  children: SpfInclude[];
  error: string;
}

export interface EmailAuthResult {
  domain: string;
  checked_at_utc: string;
  mx: Section & { records: Array<{ exchange: string; priority: number; addresses: string[] }>; provider: string; null_mx: boolean };
  spf: Section & { record: string; records: string[]; lookups: number; lookup_limit: number; all: string; includes: SpfInclude[] };
  dkim: Section & { selectors_checked: number; found: Array<{ selector: string; key_type: string; key_bits: number; revoked: boolean; invalid: boolean; testing: boolean; record: string }> };
  dmarc: Section & { record: string; source_domain: string; inherited: boolean; tags: Record<string, string>; policy: string };
  mta_sts: Section & { record: string; policy: { version: string; mode: string; mx: string[]; max_age: number | null } | null };
  tls_rpt: Section & { record: string };
  bimi: Section & { record: string };
  summary: { critical: number; warning: number; info: number; ok: number };
}

export interface BlacklistEntry {
  zone: string;
  name: string;
  url: string;
  status: 'listed' | 'policy' | 'clean' | 'unavailable';
  detail: string;
  reason?: string;
  codes: string[];
}

export interface BlacklistSummary { listed: number; policy: number; clean: number; unavailable: number; total: number }

export interface BlacklistResult {
  target: string;
  kind: 'ip' | 'domain';
  checked_at_utc: string;
  addresses: Array<{ ip: string; role: string; host: string; results: BlacklistEntry[]; summary: BlacklistSummary }>;
  domain: { target: string; results: BlacklistEntry[]; summary: BlacklistSummary } | null;
  summary: BlacklistSummary;
  note: string;
}

export interface SmtpExtensions {
  extensions: string[];
  starttls: boolean;
  auth_mechanisms: string[];
  size_limit: number | null;
}

export interface SmtpServerResult {
  host: string;
  priority: number | null;
  port: number;
  address: string;
  connected: boolean;
  implicit_tls: boolean;
  banner: string;
  banner_host: string;
  ehlo: SmtpExtensions | null;
  post_tls_ehlo: SmtpExtensions | null;
  starttls: { offered: boolean; upgraded: boolean; error: string };
  tls: {
    protocol: string;
    cipher: string;
    trusted: boolean;
    trust_error: string;
    certificate: { subject: string; issuer: string; valid_from: string; valid_to: string; days_remaining: number | null; names: string[]; hostname_match: boolean } | null;
  } | null;
  timings: { connect_ms: number | null; banner_ms: number | null; total_ms: number };
  transcript: Array<{ from: 'client' | 'server'; line: string }>;
  ptr: string[];
  error: string;
  findings: ApiFinding[];
}

export interface SmtpTestResult {
  target: string;
  port: number;
  mode: 'mx' | 'host';
  checked_at_utc: string;
  servers: SmtpServerResult[];
}

export interface HttpHop {
  url: string;
  status: number;
  status_text: string;
  http_version: string;
  address: string;
  elapsed_ms: number;
  headers: Array<[string, string]>;
  tls: { protocol: string; trusted: boolean; trust_error: string; subject: string; issuer: string; valid_to: string } | null;
  redirect_to?: string;
  error?: string;
}

export interface HttpCheckResult {
  requested_url: string;
  checked_at_utc: string;
  chain: HttpHop[];
  final_url: string;
  error: string;
  redirects: number;
  total_ms: number;
  http_upgrade: { status: number; location: string; upgrades: boolean } | null;
  delivery: Record<string, string>;
  findings: ApiFinding[];
  grade: string;
  score: number;
  total?: number;
  checks: Array<{ name: string; present: boolean; detail: string }>;
}

export interface PortCheckResult {
  host: string;
  address: string;
  checked_at_utc: string;
  results: Array<{ port: number; state: 'open' | 'closed' | 'filtered'; latency_ms: number | null; service: string; warning: string }>;
  summary: { open: number; closed: number; filtered: number };
}
