/**
 * Invite-only gate for the custom server (server.js).
 *
 * When an admin enables invite-only mode, page requests from visitors who are
 * neither on the IP whitelist nor signed in as admin get the gate page instead
 * of the site. The decision is made by the backend (GET /site/access-check),
 * which knows the settings, the trusted client IP and the admin session.
 *
 * What is never gated, matching the rules shown in the admin panel:
 * /api/* and /ingest, /admin and /login, and static assets.
 *
 * It runs in the custom server, before Next.js sees the request, and only
 * for page requests: API calls, uploads and assets never reach this code.
 */

const STATIC_EXTENSION = /\.(?:js|mjs|css|map|json|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|otf|eot|txt|xml|webmanifest|mmdb|log|gz|py)$/i;
const UNGATED_PREFIXES = ['/api', '/_next', '/admin', '/login', '/ingest'];

const FALLBACK_GATE_HTML = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Invite Only</title></head>'
  + '<body style="font-family:sans-serif;background:#07080f;color:#f8fafc;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">'
  + '<div style="text-align:center"><h1>Invite Only</h1><p>This site is currently invite-only.</p></div></body></html>';

function isGatedRequest(method, url) {
  if (method !== 'GET' && method !== 'HEAD') return false;
  let pathname;
  try {
    pathname = new URL(url, 'http://localhost').pathname;
  } catch {
    return true;
  }
  for (const prefix of UNGATED_PREFIXES) {
    if (pathname === prefix || pathname.startsWith(`${prefix}/`)) return false;
  }
  return !STATIC_EXTENSION.test(pathname);
}

function createAccessGate({
  apiBase,
  fetchImpl = fetch,
  now = Date.now,
  openTtlMs = 5000,
  timeoutMs = 3000,
  log = console,
} = {}) {
  const endpoint = `${String(apiBase).replace(/\/+$/, '')}/site/access-check?gate=1`;
  let openUntil = 0;       // invite-only is known to be off until this time
  let lastKnownEnabled = false;

  /**
   * @returns {Promise<null | {status: number, html: string}>} null to serve
   *   the request normally, or the gate response to send instead.
   */
  async function check(req) {
    if (!isGatedRequest(req.method, req.url)) return null;
    if (now() < openUntil) return null;

    let data;
    try {
      const headers = {};
      if (req.headers['x-forwarded-for']) headers['x-forwarded-for'] = req.headers['x-forwarded-for'];
      if (req.headers.cookie) headers.cookie = req.headers.cookie;
      const res = await fetchImpl(endpoint, { headers, signal: AbortSignal.timeout(timeoutMs) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      data = await res.json();
    } catch (err) {
      // Backend unreachable. If the site was last known to be public it stays
      // reachable; if invite-only was on, the gate stays closed.
      log.error?.(`Access check failed: ${err.message}`);
      return lastKnownEnabled ? { status: 503, html: FALLBACK_GATE_HTML } : null;
    }

    if (!data || data.invite_only !== true) {
      lastKnownEnabled = false;
      openUntil = now() + openTtlMs;
      return null;
    }
    lastKnownEnabled = true;
    if (data.allowed === true) return null;
    return { status: 403, html: typeof data.gate_html === 'string' && data.gate_html ? data.gate_html : FALLBACK_GATE_HTML };
  }

  return { check };
}

module.exports = { createAccessGate, isGatedRequest };
