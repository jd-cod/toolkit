/**
 * Health check.
 *
 * GET /health — database connectivity and whether every SQL migration has
 * been applied. Pending migrations answer 200 with status "degraded": the API
 * is deliberately kept serving on a partly migrated database, so this is where
 * that state is made visible.
 */

import { getPendingMigrations } from '../lib/migrations.js';

export default async function healthRoutes(fastify, opts = {}) {
  const migrationsDir = opts.migrationsDir;
  // Applied migrations stay applied, so the ledger is not read again once
  // nothing is pending.
  let allApplied = false;

  async function migrationState() {
    if (allApplied) return { migrations: 'applied' };
    let pending;
    try {
      pending = await getPendingMigrations(fastify.mysql, { dir: migrationsDir });
    } catch (err) {
      fastify.log.warn(`Migration status check failed: ${err.message}`);
      return { migrations: 'unknown' };
    }
    if (pending === null) return { migrations: 'unknown' };
    if (pending.length === 0) {
      allApplied = true;
      return { migrations: 'applied' };
    }
    return { migrations: 'pending', pending };
  }

  fastify.addHook('onReady', async () => {
    const state = await migrationState();
    if (state.migrations === 'pending') {
      fastify.log.error(
        `❌ ${state.pending.length} database migration(s) not applied: ${state.pending.join(', ')}. ` +
          'Run `npm run migrate` in backend/ and check its output.',
      );
    }
  });

  fastify.get('/health', async (request, reply) => {
    try {
      await fastify.mysql.execute('SELECT 1 as ok');
    } catch (err) {
      return reply.code(500).send({ status: 'error', database: 'disconnected', error: err.message });
    }

    const state = await migrationState();
    const timestamp = new Date().toISOString();
    if (state.migrations === 'pending') {
      // File names stay in the server log; this endpoint is public.
      return {
        status: 'degraded',
        database: 'connected',
        migrations: 'pending',
        pending_migrations: state.pending.length,
        timestamp,
      };
    }
    return { status: 'ok', database: 'connected', migrations: state.migrations, timestamp };
  });
}
