/**
 * Database Migration Runner
 *
 * Reads SQL files from the migrations/ directory and applies any that the
 * schema_migrations ledger has not recorded yet.
 *
 * Usage: node src/migrate.js [--status]
 *
 *   --status  list every migration and whether it has been applied, then exit
 *             without touching the schema. Useful for checking a production
 *             database without deploying to it.
 *
 * The runner stops at the first file that fails and exits with a non-zero
 * status. The failed file and everything after it stay pending, are retried on
 * the next run, and are reported by GET /api/health until they are applied.
 *
 * The ledger is an optimisation and a safety net, never a hard dependency: if
 * the table cannot be created or read, the runner falls back to replaying
 * every file, which is the behaviour that predates it.
 */

import 'dotenv/config';
import mysql from 'mysql2/promise';
import { applyMigrations, getMigrationStatus } from './lib/migrations.js';

async function migrate() {
  const statusOnly = process.argv.includes('--status');

  const connection = await mysql.createConnection({
    host: process.env.DB_HOST || '127.0.0.1',
    port: parseInt(process.env.DB_PORT || '3306', 10),
    user: process.env.DB_USER || 'sysadmin_app',
    password: process.env.DB_PASSWORD || '',
    multipleStatements: true,
    charset: 'utf8mb4',
  });

  console.log('✅ Connected to MySQL');

  try {
    if (statusOnly) {
      const status = await getMigrationStatus(connection);
      for (const { file, appliedAt } of status) {
        console.log(appliedAt ? `   ✅ ${file}  (${appliedAt})` : `   ⬜ ${file}  (pending)`);
      }
      const pending = status.filter((s) => !s.appliedAt).length;
      console.log(`\n${status.length} migration(s), ${pending} pending`);
      return;
    }

    await applyMigrations(connection);
    console.log('\n🎉 All migrations completed');
  } finally {
    await connection.end();
  }
}

migrate().catch((err) => {
  console.error(`❌ ${err.message}`);
  if (err.notAttempted?.length) {
    console.error(`   Not attempted: ${err.notAttempted.join(', ')}`);
  }
  process.exit(1);
});
