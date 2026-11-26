'use client';

/**
 * Shared admin API helper + utility functions used across all admin sections.
 */

interface AdminApiOptions {
  method?: string;
  body?: BodyInit | Record<string, unknown> | null;
  headers?: Record<string, string>;
  [key: string]: unknown;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Unknown error';
}

export interface ContentPage {
  id: number; title: string; slug: string; content: string; is_published: number;
  meta_title: string; meta_description: string; seo_noindex?: number; updated_at: string;
}

export interface AdminShare {
  code: string; title: string; share_type: string; domain?: string; r2_key?: string; source_url?: string;
  expires_at?: string; created_at: string; is_expired: boolean; has_password: boolean;
}
export interface ShareList { items: AdminShare[]; total: number; counts: Record<string, number> }
export interface ActivityItem { action: string; details: string; created_at: string; admin_username: string }

export async function adminApi<T = unknown>(path: string, options: AdminApiOptions = {}): Promise<T> {
  const { body, headers: customHeaders, ...rest } = options;
  const headers: Record<string, string> = {
    ...(body !== undefined && body !== null ? { 'Content-Type': 'application/json' } : {}),
    ...customHeaders,
  };
  const opts: RequestInit = {
    headers,
    credentials: 'include',
    ...rest,
  };
  if (body && typeof body === 'object' && !(body instanceof FormData) && !(body instanceof URLSearchParams) && !(body instanceof Blob) && !(body instanceof ArrayBuffer)) {
    opts.body = JSON.stringify(body);
  } else if (body) {
    opts.body = body as BodyInit;
  }
  const resp = await fetch(`/api/admin${path}`, opts);
  const text = await resp.text();
  let data: unknown;
  try { data = JSON.parse(text); } catch { data = { error: text }; }
  if (!resp.ok) {
    const detail = data && typeof data === 'object' && 'error' in data ? ('message' in data ? data.message : data.error) : '';
    throw new Error(typeof detail === 'string' && detail ? detail : `HTTP ${resp.status}`);
  }
  return data as T;
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return '';
  try {
    const normalized = typeof iso === 'string' && iso.includes(' ') && !iso.includes('T') ? iso.replace(' ', 'T') : iso;
    const d = new Date(normalized);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  } catch { return iso || ''; }
}

export function formatDateInputValue(iso: string | null | undefined): string {
  if (!iso) return '';
  const normalized = typeof iso === 'string' && iso.includes(' ') && !iso.includes('T') ? iso.replace(' ', 'T') : iso;
  const d = new Date(normalized);
  if (isNaN(d.getTime())) return '';
  const local = new Date(d.getTime() - d.getTimezoneOffset() * 60000);
  return local.toISOString().slice(0, 16);
}

export function esc(str: string | null | undefined): string {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
