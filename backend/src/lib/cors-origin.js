/**
 * Resolves the `origin` option for @fastify/cors.
 *
 * Outside production every origin is allowed, as before. In production:
 *   - CORS_ORIGIN (comma-separated list) wins when set;
 *   - otherwise the origin of APP_URL is used when it is set;
 *   - otherwise every origin is still allowed, so an existing deployment that
 *     calls the API cross-origin keeps working. server.js logs a warning.
 */
export function resolveCorsOrigin(env = process.env) {
  if (env.NODE_ENV !== 'production') return true;

  const configured = String(env.CORS_ORIGIN || '').split(',').map((s) => s.trim().replace(/\/+$/, '')).filter(Boolean);
  if (configured.includes('*')) return true;
  if (configured.length === 1) return configured[0];
  if (configured.length > 1) return configured;

  if (env.APP_URL) {
    try {
      return new URL(env.APP_URL).origin;
    } catch {
      /* fall through */
    }
  }
  return true;
}
