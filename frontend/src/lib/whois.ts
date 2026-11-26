'use client';

import type { WhoisSnapshot } from './api';
import { buildReportHtml } from './report-html';

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

  return buildReportHtml({
    title: `${sourceLabel} Snapshot`,
    subject: snapshot.domain,
    checkedAt: snapshot.checked_at_utc,
    cards: [
      { label: 'Domain', value: snapshot.domain, mono: true },
      { label: 'Registration', value: snapshot.registered ? 'Registered' : 'Unknown / Not Found' },
      { label: 'Registrar', value: snapshot.registrar || 'Unknown' },
      { label: 'Days Until Expiry', value: snapshot.days_until_expiry == null ? 'Unknown' : snapshot.days_until_expiry },
      { label: 'DNSSEC', value: snapshot.dnssec },
    ],
    sections: [
      { title: 'Status', pills: snapshot.status_labels, empty: 'No explicit statuses parsed.' },
      {
        title: 'Details',
        rows: [
          ['Creation Date', formatWhoisDate(snapshot.creation_date)],
          ['Updated Date', formatWhoisDate(snapshot.updated_date)],
          ['Expiry Date', formatWhoisDate(snapshot.expiry_date)],
          ['Registrar IANA ID', snapshot.registrar_iana_id || 'Unknown'],
          ['Abuse Email', snapshot.abuse_email || 'Unknown'],
          ['Abuse Phone', snapshot.abuse_phone || 'Unknown'],
          ['Privacy', snapshot.privacy_detected ? (snapshot.privacy_provider || 'Detected') : 'Not detected'],
          ['Source', sourceLabel],
        ],
      },
      {
        title: 'Nameservers',
        rows: [
          [`${sourceLabel} Nameservers`, snapshot.nameservers.join(', ') || 'None'],
          ['Live DNS Nameservers', snapshot.dns_nameservers.join(', ') || 'None'],
          ['Nameserver Match', snapshot.nameserver_match == null ? 'Unknown' : (snapshot.nameserver_match ? 'Yes' : 'No')],
        ],
      },
      { title: 'Risk Signals', list: snapshot.risk_signals, empty: 'No additional risk signals.' },
      { title: `Raw ${sourceLabel}`, text: snapshot.raw_response || snapshot.raw_whois || `No raw ${sourceLabel} data available.` },
    ],
  });
}
