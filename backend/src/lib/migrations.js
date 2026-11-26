/**
 * SQL migration helpers shared by the runner (src/migrate.js) and the health
 * check (src/routes/health.js).
 *
 * The schema_migrations ledger records which files have been applied. It is
 * addressed by its fully qualified name because the app user is granted
 * privileges on this one database rather than globally.
 */

import { readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

export const MIGRATIONS_DIR = join(__dirname, '..', '..', 'migrations');

const ER_BAD_DB_ERROR = 1049;
const ER_NO_SUCH_TABLE = 1146;

// Matches the fallback in src/plugins/mysql.js. Read on each call so it sees
// values loaded by dotenv after this module was imported.
function databaseName() {
  return process.env.DB_NAME || 'sysadmin_toolkit';
}

// Backticks are doubled because the name comes from the environment and is
// interpolated into SQL.
function quotedDatabase() {
  return `\`${databaseName().replaceAll('`', '``')}\``;
}

function ledgerTable() {
  return `${quotedDatabase()}.schema_migrations`;
}

export function listMigrationFiles(dir = MIGRATIONS_DIR) {
  return readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .sort();
}

/**
 * Creates the ledger if needed and returns the set of applied filenames, or
 * null when the ledger is unavailable (for example the database does not
 * exist yet on a brand-new server). `onUnavailable` receives the reason.
 */
export async function readLedger(connection, onUnavailable) {
  try {
    await connection.query(
      `CREATE TABLE IF NOT EXISTS ${ledgerTable()} (
         filename VARCHAR(255) NOT NULL PRIMARY KEY,
         applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
       ) ENGINE=InnoDB`,
    );
    const [rows] = await connection.query(`SELECT filename FROM ${ledgerTable()}`);
    return new Set(rows.map((r) => r.filename));
  } catch (err) {
    onUnavailable?.(err);
    return null;
  }
}

/**
 * Makes the application database the default schema, so a migration file does
 * not depend on an earlier file's `USE` having run on the same connection.
 * A database that does not exist yet is not an error: the first migration
 * creates it.
 */
async function selectDatabase(connection) {
  try {
    await connection.query(`USE ${quotedDatabase()}`);
  } catch (err) {
    if (err.errno !== ER_BAD_DB_ERROR) throw err;
  }
}

/**
 * Applies every migration the ledger has not recorded, in filename order, and
 * stops at the first file that fails: later files may depend on it, and a
 * schema that is only partly migrated must not be reported as up to date.
 *
 * A file is recorded only after it succeeds, so a failed file is retried on
 * the next run. Returns the files that were applied and those skipped.
 * Throws an Error carrying `file` and `notAttempted` when a file fails.
 */
export async function applyMigrations(connection, { dir = MIGRATIONS_DIR, log = console } = {}) {
  const files = listMigrationFiles(dir);
  let ledger = await readLedger(connection, (err) => {
    log.warn(`⚠️  schema_migrations unavailable (${err.message}); replaying every file`);
  });

  const applied = [];
  const skipped = [];
  // Applied while the ledger was unavailable, to be recorded once it exists.
  const unrecorded = [];

  for (const [index, file] of files.entries()) {
    if (ledger?.has(file)) {
      log.log(`⏭️  ${file} (already applied)`);
      skipped.push(file);
      continue;
    }

    log.log(`📄 Running migration: ${file}`);
    try {
      await selectDatabase(connection);
      await connection.query(readFileSync(join(dir, file), 'utf8'));

      unrecorded.push(file);
      ledger ??= await readLedger(connection);
      if (ledger) {
        for (const done of unrecorded.splice(0)) {
          await connection.query(
            `INSERT IGNORE INTO ${ledgerTable()} (filename) VALUES (?)`,
            [done],
          );
          ledger.add(done);
        }
      }
    } catch (cause) {
      const notAttempted = files.slice(index + 1).filter((f) => !ledger?.has(f));
      const err = new Error(
        `Migration ${file} failed: ${cause.message}` +
          (notAttempted.length ? ` (${notAttempted.length} later migration(s) not attempted)` : ''),
        { cause },
      );
      err.file = file;
      err.notAttempted = notAttempted;
      throw err;
    }

    applied.push(file);
    log.log(`   ✅ ${file} completed`);
  }

  return { applied, skipped };
}

/**
 * Read-only: lists the migration files the ledger has not recorded.
 *
 * Returns null when there is no ledger, which means the runner has never
 * completed against this database and nothing can be said either way.
 */
export async function getPendingMigrations(db, { dir = MIGRATIONS_DIR } = {}) {
  let rows;
  try {
    [rows] = await db.query(`SELECT filename FROM ${ledgerTable()}`);
  } catch (err) {
    if (err.errno === ER_NO_SUCH_TABLE) return null;
    throw err;
  }
  const done = new Set(rows.map((r) => r.filename));
  return listMigrationFiles(dir).filter((f) => !done.has(f));
}

/** Read-only: every migration file with the time it was applied, or null. */
export async function getMigrationStatus(db, { dir = MIGRATIONS_DIR } = {}) {
  let rows = [];
  try {
    [rows] = await db.query(`SELECT filename, applied_at FROM ${ledgerTable()}`);
  } catch (err) {
    if (err.errno !== ER_NO_SUCH_TABLE && err.errno !== ER_BAD_DB_ERROR) throw err;
  }
  const appliedAt = new Map(rows.map((r) => [r.filename, r.applied_at]));
  return listMigrationFiles(dir).map((file) => ({ file, appliedAt: appliedAt.get(file) ?? null }));
}
