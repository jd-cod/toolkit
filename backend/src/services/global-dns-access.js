import { defaultProvider } from '@aws-sdk/credential-provider-node';

/** Bounded, single-flight discovery. Public callers receive capability, never credentials. */
export function createGlobalDnsAccess({ resolveCredentials = defaultProvider({ timeout: 1500, maxRetries: 0 }), timeoutMs = 2500, now = Date.now } = {}) {
  let cached = null;
  let expiresAt = 0;
  let pending = null;

  async function credentials() {
    if (now() < expiresAt) return cached;
    if (pending) return pending;
    pending = (async () => {
      let timer;
      try {
        const result = await Promise.race([
          Promise.resolve().then(resolveCredentials),
          new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Credential discovery timed out')), timeoutMs); }),
        ]);
        if (!result?.accessKeyId || !result?.secretAccessKey || (result.expiration && new Date(result.expiration).getTime() <= now())) throw new Error('Credentials unavailable');
        cached = result;
        expiresAt = Math.min(now() + 60000, result.expiration ? new Date(result.expiration).getTime() - 5000 : Infinity);
      } catch {
        cached = null;
        expiresAt = now() + 15000;
      } finally {
        clearTimeout(timer);
      }
      return cached;
    })();
    try { return await pending; } finally { pending = null; }
  }

  return {
    credentials,
    async capability() {
      return { available: Boolean(await credentials()) };
    },
  };
}
