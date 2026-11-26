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
 * The ledger is an optimisation and a safety net, never a hard dependency: if
 * the table cannot be created or read, the runner falls back to replaying
 * every file, which is the behaviour that predates it.
 */

import 'dotenv/config';
import mysql from 'mysql2/promise';
import { readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(__dirname, '..', 'migrations');

// Quoted because the name comes from the environment and is interpolated into
// SQL. Matches the fallback in src/plugins/mysql.js.
const DB_NAME = process.env.DB_NAME || 'sysadmin_toolkit';

/**
 * Creates and reads the ledger, returning the set of applied filenames.
 *
 * Returns null when the ledger is unavailable. The app user is granted
 * privileges on this one database rather than globally, so the table is
 * addressed by its fully qualified name: the connection itself selects no
 * default schema, because that selection lives in the `USE` statements inside
 * the individual migration files.
 */
async function readLedger(connection) {
  try {
    await connection.query(
      `CREATE TABLE IF NOT EXISTS \`${DB_NAME}\`.schema_migrations (
         filename VARCHAR(255) NOT NULL PRIMARY KEY,
         applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
       ) ENGINE=InnoDB`,
    );
    const [rows] = await connection.query(
      `SELECT filename FROM \`${DB_NAME}\`.schema_migrations`,
    );
    return new Set(rows.map((r) => r.filename));
  } catch (err) {
    console.warn(
      `⚠️  schema_migrations unavailable (${err.message}); replaying every file`,
    );
    return null;
  }
}

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

  const files = readdirSync(migrationsDir)
    .filter(f => f.endsWith('.sql'))
    .sort();

  const applied = statusOnly ? null : await readLedger(connection);

  if (statusOnly) {
    let rows = [];
    try {
      [rows] = await connection.query(
        `SELECT filename, applied_at FROM \`${DB_NAME}\`.schema_migrations ORDER BY filename`,
      );
    } catch {
      /* ledger not created yet */
    }
    const appliedAt = new Map(rows.map((r) => [r.filename, r.applied_at]));
    for (const file of files) {
      const at = appliedAt.get(file);
      console.log(at ? `   ✅ ${file}  (${at})` : `   ⬜ ${file}  (pending)`);
    }
    const pending = files.filter(f => !appliedAt.has(f)).length;
    console.log(
      `\n${files.length} migration(s), ${pending} pending`,
    );
    await connection.end();
    return;
  }

  for (const file of files) {
    if (applied?.has(file)) {
      console.log(`⏭️  ${file} (already applied)`);
      continue;
    }

    console.log(`📄 Running migration: ${file}`);
    const sql = readFileSync(join(migrationsDir, file), 'utf8');
    try {
      await connection.query(sql);
      // Recorded only on success, so a file that fails is retried on the next
      // boot rather than being silently marked done.
      if (applied) {
        await connection.query(
          `INSERT IGNORE INTO \`${DB_NAME}\`.schema_migrations (filename) VALUES (?)`,
          [file],
        );
      }
      console.log(`   ✅ ${file} completed`);
    } catch (err) {
      console.error(`   ❌ ${file} failed: ${err.message}`);
      // Continue with other migrations but log the error
    }
  }

  await connection.end();
  console.log('\n🎉 All migrations completed');
}

migrate().catch(err => {
  console.error('Migration failed:', err);
  process.exit(1);
});
