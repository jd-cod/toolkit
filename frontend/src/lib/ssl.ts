import { buildReportHtml } from './report-html';
import type { Certificate, SSLResult } from './tool-results';

/** An SSL check result as it is shared: the API result plus when and on which port it was taken. */
export interface SslSnapshot extends SSLResult {
  port: number;
  checked_at_utc: string;
}

const text = (value: unknown) => (typeof value === 'string' ? value : '');

function normalizeCertificate(raw: unknown): Certificate {
  const c = (raw ?? {}) as Partial<Certificate>;
  return {
    subject: text(c.subject),
    subject_org: text(c.subject_org),
    issuer: text(c.issuer),
    issuer_org: text(c.issuer_org),
    not_before: text(c.not_before),
    not_after: text(c.not_after),
    key_type: text(c.key_type),
    key_size: Number(c.key_size) || 0,
  };
}

/** Rebuilds a snapshot from stored JSON so a damaged or older share still renders. */
export function normalizeSslSnapshot(raw: unknown): SslSnapshot {
  const d = (raw ?? {}) as Partial<SslSnapshot>;
  return {
    ...normalizeCertificate(d),
    domain: text(d.domain),
    dns: d.dns && typeof d.dns === 'object' ? { ip: text(d.dns.ip) } : undefined,
    server_type: d.server_type && typeof d.server_type === 'object' ? { server: text(d.server_type.server) } : undefined,
    is_trusted: Boolean(d.is_trusted),
    is_self_signed: Boolean(d.is_self_signed),
    is_expired: Boolean(d.is_expired),
    hostname_match: Boolean(d.hostname_match),
    days_remaining: Number(d.days_remaining) || 0,
    grade: text(d.grade),
    protocol: text(d.protocol),
    serial_number: text(d.serial_number),
    fingerprint_sha256: text(d.fingerprint_sha256),
    response_time_ms: Number(d.response_time_ms) || 0,
    san_names: Array.isArray(d.san_names) ? d.san_names.filter((name): name is string => typeof name === 'string') : [],
    chain: Array.isArray(d.chain) ? d.chain.map(normalizeCertificate) : [],
    security_headers: d.security_headers && typeof d.security_headers === 'object' ? { hsts: text(d.security_headers.hsts) || undefined } : undefined,
    port: Number(d.port) || 443,
    checked_at_utc: text(d.checked_at_utc) || new Date().toISOString(),
  };
}

export function buildSslRerunHref(snapshot: Pick<SslSnapshot, 'domain' | 'port'>) {
  const params = new URLSearchParams({ domain: snapshot.domain });
  if (snapshot.port && snapshot.port !== 443) params.set('port', String(snapshot.port));
  return `/ssl?${params.toString()}`;
}

export function buildSslSummary(result: SSLResult) {
  return [
    `Domain: ${result.domain}`,
    `Issuer: ${result.issuer || 'N/A'}`,
    `Valid Until: ${result.not_after || 'N/A'}`,
    `Grade: ${result.grade || 'N/A'}`,
    `Protocol: ${result.protocol || 'N/A'}`,
  ].join('\n');
}

function trustText(result: SSLResult) {
  if (result.is_trusted) return 'Trusted';
  return result.is_self_signed ? 'Self-signed certificate' : 'Missing intermediate certificates';
}

export function buildSslReportHtml(result: SslSnapshot) {
  const chainRole = (index: number) => (index === 0 ? 'Server' : index === result.chain.length - 1 ? 'Root' : 'Intermediate');

  return buildReportHtml({
    title: 'SSL Certificate Report',
    subject: result.port && result.port !== 443 ? `${result.domain}:${result.port}` : result.domain,
    checkedAt: result.checked_at_utc,
    cards: [
      { label: 'Days Until Expiry', value: result.days_remaining },
      { label: 'Security Grade', value: result.grade },
      { label: 'Protocol', value: result.protocol, mono: true },
      { label: 'Key Type', value: `${result.key_type} ${result.key_size || ''}`.trim(), mono: true },
    ],
    sections: [
      {
        title: 'Validation Checks',
        rows: [
          ['DNS Resolution', result.dns?.ip ? `${result.domain} resolves to ${result.dns.ip}` : 'Not resolved'],
          ['Server', result.server_type?.server || 'Unknown'],
          ['Trust', trustText(result)],
          ['Expiry', result.is_expired ? 'Certificate EXPIRED' : `Expires in ${result.days_remaining} days`],
          ['Hostname', result.hostname_match ? 'Matches certificate' : 'Does NOT match certificate'],
          ['HSTS', result.security_headers?.hsts ? 'Enabled' : 'Not enabled'],
        ],
      },
      {
        title: 'Certificate Details',
        meta: `${result.response_time_ms}ms`,
        rows: [
          ['Subject', result.subject],
          ['Organization', result.subject_org],
          ['Issuer', result.issuer],
          ['Issuer Org', result.issuer_org],
          ['Serial Number', result.serial_number],
          ['Valid From', result.not_before],
          ['Valid Until', result.not_after],
          ['Fingerprint (SHA-256)', result.fingerprint_sha256],
        ],
      },
      { title: 'Subject Alternative Names', meta: `${result.san_names.length}`, pills: result.san_names, empty: 'No alternative names.' },
      {
        title: 'Certificate Chain',
        meta: `${result.chain.length}`,
        empty: 'No chain returned.',
        table: {
          columns: ['Role', 'Subject', 'Issuer', 'Valid From', 'Valid Until', 'Key'],
          rows: result.chain.map((cert, index) => [
            chainRole(index),
            cert.subject,
            cert.issuer,
            cert.not_before,
            cert.not_after,
            `${cert.key_type} ${cert.key_size || ''}`.trim(),
          ]),
        },
      },
    ],
  });
}
