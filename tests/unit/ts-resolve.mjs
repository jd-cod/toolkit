/**
 * Lets `node --test` import the frontend's TypeScript modules directly.
 *
 * Node strips types on its own but resolves imports literally, while the
 * frontend source uses extensionless relative imports and the `@/` alias.
 * This hook maps `@/x` to frontend/src/x and retries a failed relative import
 * with `.ts` appended.
 *
 * Usage: node --import ./tests/unit/ts-resolve.mjs --test tests/unit/
 */
import { registerHooks } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const FRONTEND_SRC = pathToFileURL(`${path.resolve(import.meta.dirname, '../../frontend/src')}/`).href;

registerHooks({
  resolve(specifier, context, nextResolve) {
    const target = specifier.startsWith('@/') ? new URL(specifier.slice(2), FRONTEND_SRC).href : specifier;
    try {
      return nextResolve(target, context);
    } catch (error) {
      if (error?.code !== 'ERR_MODULE_NOT_FOUND' || !/^(\.|file:)/.test(target)) throw error;
      return nextResolve(`${target}.ts`, context);
    }
  },
});
