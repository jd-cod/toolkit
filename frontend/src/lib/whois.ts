'use client';

import { WhoisSnapshot } from './api';

function emptyContact() {
  return { name: '', email: '', phone: '' };
}

export function normalizeDomainInput(input: string) {
  return input
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .replace(/:.*$/, '')
    .toLowerCase();
}

export function normalizeWhoisSnapshot(snapshot: unknown): WhoisSnapshot {
  const input = (snapshot ?? {}) as Partial<WhoisSnapshot>;
  return {
    domain: typeof input.domain === 'string' ? input.domain : '',
    query_domain: typeof input.query_domain === 'string' ? input.query_domain : (typeof input.domain === 'string' ? input.domain : ''),
    data_source: input.data_source === 'rdap' ? 'rdap' : 'whois',
    registered: Boolean(input.registered),
    status_labels: Array.isArray(input.status_labels) ? input.status_labels.filter((value): value is string => typeof value === 'string') : [],
    status_codes: Array.isArray(input.status_codes) ? input.status_codes.filter((value): value is string => typeof value === 'string') : [],
    registrar: typeof input.registrar === 'string' ? input.registrar : '',
    registrar_iana_id: typeof input.registrar_iana_id === 'string' ? input.registrar_iana_id : '',
    abuse_email: typeof input.abuse_email === 'string' ? input.abuse_email : '',
    abuse_phone: typeof input.abuse_phone === 'string' ? input.abuse_phone : '',
    creation_date: typeof input.creation_date === 'string' ? input.creation_date : '',
    updated_date: typeof input.updated_date === 'string' ? input.updated_date : '',
    expiry_date: typeof input.expiry_date === 'string' ? input.expiry_date : '',
    days_until_expiry: typeof input.days_until_expiry === 'number' ? input.days_until_expiry : null,
    nameservers: Array.isArray(input.nameservers) ? input.nameservers.filter((value): value is string => typeof value === 'string') : [],
    dns_nameservers: Array.isArray(input.dns_nameservers) ? input.dns_nameservers.filter((value): value is string => typeof value === 'string') : [],
    nameserver_match: typeof input.nameserver_match === 'boolean' ? input.nameserver_match : null,
    nameserver_only_in_whois: Array.isArray(input.nameserver_only_in_whois) ? input.nameserver_only_in_whois.filter((value): value is string => typeof value === 'string') : [],
    nameserver_only_in_dns: Array.isArray(input.nameserver_only_in_dns) ? input.nameserver_only_in_dns.filter((value): value is string => typeof value === 'string') : [],
    dnssec: input.dnssec === 'signed' || input.dnssec === 'unsigned' ? input.dnssec : 'unknown',
    privacy_detected: Boolean(input.privacy_detected),
    privacy_provider: typeof input.privacy_provider === 'string' ? input.privacy_provider : '',
    contacts: {
      registrant: typeof input.contacts?.registrant === 'object' && input.contacts?.registrant ? {
        name: typeof input.contacts.registrant.name === 'string' ? input.contacts.registrant.name : '',
        email: typeof input.contacts.registrant.email === 'string' ? input.contacts.registrant.email : '',
        phone: typeof input.contacts.registrant.phone === 'string' ? input.contacts.registrant.phone : '',
      } : emptyContact(),
      admin: typeof input.contacts?.admin === 'object' && input.contacts?.admin ? {
        name: typeof input.contacts.admin.name === 'string' ? input.contacts.admin.name : '',
        email: typeof input.contacts.admin.email === 'string' ? input.contacts.admin.email : '',
        phone: typeof input.contacts.admin.phone === 'string' ? input.contacts.admin.phone : '',
      } : emptyContact(),
      tech: typeof input.contacts?.tech === 'object' && input.contacts?.tech ? {
        name: typeof input.contacts.tech.name === 'string' ? input.contacts.tech.name : '',
        email: typeof input.contacts.tech.email === 'string' ? input.contacts.tech.email : '',
        phone: typeof input.contacts.tech.phone === 'string' ? input.contacts.tech.phone : '',
      } : emptyContact(),
    },
    risk_signals: Array.isArray(input.risk_signals) ? input.risk_signals.filter((value): value is string => typeof value === 'string') : [],
    raw_response: typeof input.raw_response === 'string'
      ? input.raw_response
      : (typeof input.raw_whois === 'string' ? input.raw_whois : ''),
    raw_whois: typeof input.raw_whois === 'string' ? input.raw_whois : '',
    rdap_metadata: typeof input.rdap_metadata === 'object' && input.rdap_metadata
      ? {
        base_url: typeof input.rdap_metadata.base_url === 'string' ? input.rdap_metadata.base_url : '',
        handle: typeof input.rdap_metadata.handle === 'string' ? input.rdap_metadata.handle : '',
      }
      : null,
    checked_at_utc: typeof input.checked_at_utc === 'string' ? input.checked_at_utc : new Date().toISOString(),
  };
}

export function formatWhoisDate(value: string) {
  if (!value) return 'Unknown';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('en-GB', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'UTC',
    hour12: false,
  }).format(date).replace(',', '') + ' UTC';
}

export function buildWhoisPlainText(snapshot: WhoisSnapshot) {
  const sourceLabel = snapshot.data_source === 'rdap' ? 'RDAP' : 'WHOIS';
  return [
    `Domain: ${snapshot.domain}`,
    `Data Source: ${sourceLabel}`,
    `Registered: ${snapshot.registered ? 'Yes' : 'No / Unknown'}`,
    `Registrar: ${snapshot.registrar || 'Unknown'}`,
    `Registrar IANA ID: ${snapshot.registrar_iana_id || 'Unknown'}`,
    `Creation Date: ${formatWhoisDate(snapshot.creation_date)}`,
    `Updated Date: ${formatWhoisDate(snapshot.updated_date)}`,
    `Expiry Date: ${formatWhoisDate(snapshot.expiry_date)}`,
    `Days Until Expiry: ${snapshot.days_until_expiry ?? 'Unknown'}`,
    `DNSSEC: ${snapshot.dnssec}`,
    `Privacy Detected: ${snapshot.privacy_detected ? (snapshot.privacy_provider || 'Yes') : 'No'}`,
    `Statuses: ${snapshot.status_labels.join(', ') || 'None'}`,
    `${sourceLabel} Nameservers: ${snapshot.nameservers.join(', ') || 'None'}`,
    `Live DNS Nameservers: ${snapshot.dns_nameservers.join(', ') || 'None'}`,
    `Risk Signals: ${snapshot.risk_signals.join(' | ') || 'None'}`,
  ].join('\n');
}

export function buildWhoisRerunHref(snapshot: WhoisSnapshot) {
  return `/whois?domain=${encodeURIComponent(snapshot.domain)}`;
}

export function buildWhoisSnapshotHtml(snapshot: WhoisSnapshot) {
  const sourceLabel = snapshot.data_source === 'rdap' ? 'RDAP' : 'WHOIS';
  const statusHtml = snapshot.status_labels.length > 0
    ? snapshot.status_labels.map((label) => `<span class="pill">${escapeHtml(label)}</span>`).join('')
    : '<span class="muted">No explicit statuses parsed</span>';
  const riskHtml = snapshot.risk_signals.length > 0
    ? `<ul>${snapshot.risk_signals.map((signal) => `<li>${escapeHtml(signal)}</li>`).join('')}</ul>`
    : '<p class="muted">No additional risk signals.</p>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(sourceLabel)} Snapshot - ${escapeHtml(snapshot.domain)}</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0b14; color: #e8ecf4; padding: 40px 20px; margin: 0; }
    .container { max-width: 1100px; margin: 0 auto; }
    h1 { font-size: 2rem; margin-bottom: 8px; }
    .subtitle { color: #94a3b8; margin-bottom: 24px; }
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 20px; }
    .card, .section { background: #12141f; border: 1px solid #1e2235; border-radius: 14px; }
    .card { padding: 18px; }
    .card-value { font-size: 1.35rem; font-weight: 800; line-height: 1.2; }
    .card-label { color: #94a3b8; font-size: 0.75rem; letter-spacing: 0.08em; text-transform: uppercase; margin-top: 6px; }
    .section { margin-bottom: 16px; overflow: hidden; }
    .section h2 { margin: 0; padding: 14px 18px; border-bottom: 1px solid #1e2235; font-size: 1rem; }
    .section-body { padding: 18px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }
    .label { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; color: #94a3b8; margin-bottom: 4px; }
    .value { font-size: 0.95rem; word-break: break-word; }
    .pill { display: inline-block; padding: 6px 10px; border-radius: 999px; border: 1px solid #334155; margin: 0 8px 8px 0; font-size: 0.82rem; }
    .muted { color: #94a3b8; }
    pre { white-space: pre-wrap; word-break: break-word; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.8rem; line-height: 1.6; }
    ul { margin: 0; padding-left: 18px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>${escapeHtml(sourceLabel)} Snapshot</h1>
    <p class="subtitle">${escapeHtml(snapshot.domain)} - Checked ${escapeHtml(formatWhoisDate(snapshot.checked_at_utc))}</p>
    <div class="cards">
      <div class="card"><div class="card-value">${escapeHtml(snapshot.domain)}</div><div class="card-label">Domain</div></div>
      <div class="card"><div class="card-value">${snapshot.registered ? 'Registered' : 'Unknown / Not Found'}</div><div class="card-label">Registration</div></div>
      <div class="card"><div class="card-value">${escapeHtml(snapshot.registrar || 'Unknown')}</div><div class="card-label">Registrar</div></div>
      <div class="card"><div class="card-value">${escapeHtml(snapshot.days_until_expiry == null ? 'Unknown' : String(snapshot.days_until_expiry))}</div><div class="card-label">Days Until Expiry</div></div>
      <div class="card"><div class="card-value">${escapeHtml(snapshot.dnssec)}</div><div class="card-label">DNSSEC</div></div>
    </div>
    <div class="section"><h2>Status</h2><div class="section-body">${statusHtml}</div></div>
    <div class="section"><h2>Details</h2><div class="section-body"><div class="grid">
      ${detailItem('Creation Date', formatWhoisDate(snapshot.creation_date))}
      ${detailItem('Updated Date', formatWhoisDate(snapshot.updated_date))}
      ${detailItem('Expiry Date', formatWhoisDate(snapshot.expiry_date))}
      ${detailItem('Registrar IANA ID', snapshot.registrar_iana_id || 'Unknown')}
      ${detailItem('Abuse Email', snapshot.abuse_email || 'Unknown')}
      ${detailItem('Abuse Phone', snapshot.abuse_phone || 'Unknown')}
      ${detailItem('Privacy', snapshot.privacy_detected ? (snapshot.privacy_provider || 'Detected') : 'Not detected')}
      ${detailItem('Source', sourceLabel)}
    </div></div></div>
    <div class="section"><h2>Nameservers</h2><div class="section-body"><div class="grid">
      ${detailItem(`${sourceLabel} Nameservers`, snapshot.nameservers.join(', ') || 'None')}
      ${detailItem('Live DNS Nameservers', snapshot.dns_nameservers.join(', ') || 'None')}
      ${detailItem('Nameserver Match', snapshot.nameserver_match == null ? 'Unknown' : (snapshot.nameserver_match ? 'Yes' : 'No'))}
    </div></div></div>
    <div class="section"><h2>Risk Signals</h2><div class="section-body">${riskHtml}</div></div>
    <div class="section"><h2>Raw ${escapeHtml(sourceLabel)}</h2><div class="section-body"><pre>${escapeHtml(snapshot.raw_response || snapshot.raw_whois || `No raw ${sourceLabel} data available.`)}</pre></div></div>
  </div>
</body>
</html>`;
}

function detailItem(label: string, value: string) {
  return `<div><div class="label">${escapeHtml(label)}</div><div class="value">${escapeHtml(value)}</div></div>`;
}

function escapeHtml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
