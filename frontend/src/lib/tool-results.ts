export interface GlobalDnsRecordObject {
  data?: string; value?: string; nsname?: string; hostmaster?: string; serial?: number;
  refresh?: number; retry?: number; expire?: number; exchange?: string;
  priority?: number; weight?: number; port?: number; name?: string;
}
export type GlobalDnsRecord = string | string[] | GlobalDnsRecordObject;
export interface GlobalDnsRegion {
  region: string;
  status: string;
  data?: { records?: GlobalDnsRecord[]; duration_ms?: number };
  error?: string;
}
export function formatGlobalDnsRecord(record: GlobalDnsRecord): string {
  if (typeof record === 'string') return record;
  if (Array.isArray(record)) return record.join(' ');
  if (record.nsname && record.hostmaster) return `ns: ${record.nsname} | admin: ${record.hostmaster} | serial: ${record.serial ?? ''} | refresh: ${record.refresh ?? ''} | retry: ${record.retry ?? ''} | expire: ${record.expire ?? ''}`;
  if (record.exchange !== undefined) return `priority: ${record.priority ?? 0} | exchange: ${record.exchange}`;
  if (record.port !== undefined && record.name !== undefined) return `priority: ${record.priority ?? 0} | weight: ${record.weight ?? 0} | port: ${record.port} | target: ${record.name}`;
  return record.data || record.value || JSON.stringify(record);
}

export interface Certificate {
  subject: string; subject_org: string; issuer: string; issuer_org: string;
  not_before: string; not_after: string; key_type: string; key_size: number;
}
export interface SSLResult extends Certificate {
  domain: string; error?: string; dns?: { ip: string }; server_type?: { server: string };
  is_trusted: boolean; is_self_signed: boolean; is_expired: boolean; hostname_match: boolean;
  days_remaining: number; grade: string; protocol: string; serial_number: string;
  fingerprint_sha256: string; response_time_ms: number; san_names: string[]; chain: Certificate[];
  security_headers?: { hsts?: string };
}
export interface IPInfoEntry {
  ip: string; is_private?: boolean; ip_version?: string; reverse_dns?: string;
  country?: string; country_code?: string; asn?: number | string; asn_org?: string; isp?: string;
  risk_level?: 'safe' | 'low' | 'medium' | 'high' | 'unknown'; risk_reasons?: string[];
}
export interface AbuseEntry {
  ip?: string; ipAddress?: string; domain?: string; isp?: string;
  country?: string; countryName?: string; country_code?: string; countryCode?: string;
  usage_type?: string; usageType?: string; abuse_score?: number; abuseConfidenceScore?: number;
  total_reports?: number; totalReports?: number; num_distinct_users?: number;
  last_reported_at?: string; is_tor?: boolean; is_whitelisted?: boolean;
}
export interface AbuseResult { api_available?: boolean; abusive?: AbuseEntry[]; non_abusive?: AbuseEntry[]; results?: AbuseEntry[]; error?: string }
