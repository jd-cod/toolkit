import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Fastify from 'fastify';
import { applyMigrations, getPendingMigrations, getMigrationStatus } from '../src/lib/migrations.js';
import healthRoutes from '../src/routes/health.js';

const DB = 'sysadmin_toolkit';
const silent = { log() {}, warn() {}, error() {} };

function mysqlError(errno, message) {
  return Object.assign(new Error(message), { errno });
}

/**
 * Stand-in for a MySQL connection that behaves like the server in the ways
 * the runner depends on: a default schema per connection, a ledger table that
 * only exists once its database does, and statements that can fail.
 *
 * Migration bodies are tiny scripts: `CREATE DATABASE`, `USE`, `FAIL`, or
 * anything else, which needs a default schema to have been selected.
 */
function createFakeDb({ databaseExists = true, ledger = null } = {}) {
  const state = {
    databaseExists,
    selected: false,
    ledger: ledger ? new Map(ledger.map((f) => [f, new Date('2026-01-01T00:00:00Z')])) : null,
    executed: [],
  };

  async function query(sql, values = []) {
    if (sql.includes('schema_migrations')) {
      if (sql.startsWith('CREATE TABLE')) {
        if (!state.databaseExists) throw mysqlError(1049, `Unknown database '${DB}'`);
        state.ledger ??= new Map();
        return [{}];
      }
      if (!state.ledger) throw mysqlError(1146, `Table '${DB}.schema_migrations' doesn't exist`);
      if (sql.startsWith('INSERT')) {
        if (!state.ledger.has(values[0])) state.ledger.set(values[0], new Date());
        return [{ affectedRows: 1 }];
      }
      return [[...state.ledger].map(([filename, applied_at]) => ({ filename, applied_at }))];
    }
    if (sql.startsWith('SELECT 1')) return [[{ ok: 1 }]];
    if (sql.startsWith('USE ')) {
      if (!state.databaseExists) throw mysqlError(1049, `Unknown database '${DB}'`);
      state.selected = true;
      return [{}];
    }

    for (const line of sql.split('\n').map((l) => l.trim()).filter(Boolean)) {
      if (line === 'CREATE DATABASE') state.databaseExists = true;
      else if (line === 'USE') state.selected = true;
      else if (line === 'FAIL') throw mysqlError(1064, 'You have an error in your SQL syntax');
      else if (!state.selected) throw mysqlError(1046, 'No database selected');
    }
    state.executed.push(sql.trim());
    return [{}];
  }

  return { state, query, execute: query };
}

function migrationsDir(t, files) {
  const dir = mkdtempSync(join(tmpdir(), 'toolkit-migrations-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}

test('applies pending migrations in order and records each one', async (t) => {
  const dir = migrationsDir(t, { '002_b.sql': 'b', '001_a.sql': 'a', 'notes.txt': 'ignored' });
  const db = createFakeDb();

  const result = await applyMigrations(db, { dir, log: silent });

  assert.deepEqual(result, { applied: ['001_a.sql', '002_b.sql'], skipped: [] });
  assert.deepEqual(db.state.executed, ['a', 'b']);
  assert.deepEqual([...db.state.ledger.keys()], ['001_a.sql', '002_b.sql']);
});

test('stops at the first failing migration and leaves it and later files pending', async (t) => {
  const dir = migrationsDir(t, { '001_a.sql': 'a', '002_b.sql': 'FAIL', '003_c.sql': 'c', '004_d.sql': 'd' });
  const db = createFakeDb();

  await assert.rejects(applyMigrations(db, { dir, log: silent }), (err) => {
    assert.match(err.message, /^Migration 002_b\.sql failed: You have an error in your SQL syntax \(2 later migration\(s\) not attempted\)$/);
    assert.equal(err.file, '002_b.sql');
    assert.deepEqual(err.notAttempted, ['003_c.sql', '004_d.sql']);
    return true;
  });

  assert.deepEqual(db.state.executed, ['a']);
  assert.deepEqual([...db.state.ledger.keys()], ['001_a.sql']);
  assert.deepEqual(await getPendingMigrations(db, { dir }), ['002_b.sql', '003_c.sql', '004_d.sql']);
});

test('a failed migration is retried on the next run, and applied ones are not replayed', async (t) => {
  const dir = migrationsDir(t, { '001_a.sql': 'a', '002_b.sql': 'FAIL', '003_c.sql': 'c' });
  const db = createFakeDb();
  await assert.rejects(applyMigrations(db, { dir, log: silent }));

  writeFileSync(join(dir, '002_b.sql'), 'b fixed');
  const result = await applyMigrations(db, { dir, log: silent });

  assert.deepEqual(result, { applied: ['002_b.sql', '003_c.sql'], skipped: ['001_a.sql'] });
  assert.deepEqual(db.state.executed, ['a', 'b fixed', 'c']);
  assert.deepEqual(await getPendingMigrations(db, { dir }), []);
});

test('a migration without its own USE runs even when every earlier file is skipped', async (t) => {
  const dir = migrationsDir(t, { '001_initial.sql': 'CREATE DATABASE\nUSE\na', '002_no_use.sql': 'b' });
  const db = createFakeDb({ ledger: ['001_initial.sql'] });

  const result = await applyMigrations(db, { dir, log: silent });

  assert.deepEqual(result, { applied: ['002_no_use.sql'], skipped: ['001_initial.sql'] });
  assert.deepEqual(db.state.executed, ['b']);
});

test('on a brand-new server the first migration creates the database and the ledger still records everything', async (t) => {
  const dir = migrationsDir(t, { '001_initial.sql': 'CREATE DATABASE\nUSE\na', '002_b.sql': 'b' });
  const db = createFakeDb({ databaseExists: false });
  const warnings = [];

  const result = await applyMigrations(db, { dir, log: { ...silent, warn: (m) => warnings.push(m) } });

  assert.deepEqual(result.applied, ['001_initial.sql', '002_b.sql']);
  assert.deepEqual([...db.state.ledger.keys()], ['001_initial.sql', '002_b.sql']);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /schema_migrations unavailable \(Unknown database/);
});

test('an error selecting the database other than "unknown database" fails the migration', async (t) => {
  const dir = migrationsDir(t, { '001_a.sql': 'a' });
  const db = createFakeDb();
  const query = db.query;
  db.query = async (sql, values) => {
    if (sql.startsWith('USE ')) throw mysqlError(1044, "Access denied for user 'app' to database");
    return query(sql, values);
  };

  await assert.rejects(applyMigrations(db, { dir, log: silent }), /Migration 001_a\.sql failed: Access denied/);
  assert.deepEqual(db.state.executed, []);
});

test('pending and status are read-only and report an absent ledger as unknown', async (t) => {
  const dir = migrationsDir(t, { '001_a.sql': 'a', '002_b.sql': 'b' });

  const fresh = createFakeDb();
  assert.equal(await getPendingMigrations(fresh, { dir }), null);
  assert.deepEqual(await getMigrationStatus(fresh, { dir }), [
    { file: '001_a.sql', appliedAt: null },
    { file: '002_b.sql', appliedAt: null },
  ]);
  assert.equal(fresh.state.ledger, null);

  const partial = createFakeDb({ ledger: ['001_a.sql'] });
  assert.deepEqual(await getPendingMigrations(partial, { dir }), ['002_b.sql']);
  const status = await getMigrationStatus(partial, { dir });
  assert.ok(status[0].appliedAt instanceof Date);
  assert.equal(status[1].appliedAt, null);
});

async function healthApp(t, db, dir) {
  const app = Fastify();
  app.decorate('mysql', db);
  await app.register(healthRoutes, { prefix: '/api', migrationsDir: dir });
  t.after(() => app.close());
  return app;
}

test('health is ok when every migration is applied and stops reading the ledger after that', async (t) => {
  const dir = migrationsDir(t, { '001_a.sql': 'a' });
  const db = createFakeDb({ ledger: ['001_a.sql'] });
  let ledgerReads = 0;
  const query = db.query;
  db.query = async (sql, values) => {
    if (sql.includes('schema_migrations')) ledgerReads++;
    return query(sql, values);
  };
  const app = await healthApp(t, db, dir);

  const first = await app.inject('/api/health');
  const second = await app.inject('/api/health');

  assert.equal(first.statusCode, 200);
  const body = first.json();
  assert.equal(body.status, 'ok');
  assert.equal(body.database, 'connected');
  assert.equal(body.migrations, 'applied');
  assert.equal('pending_migrations' in body, false);
  assert.equal(second.json().migrations, 'applied');
  assert.equal(ledgerReads, 1);
});

test('health reports pending migrations as degraded without naming the files, then recovers', async (t) => {
  const dir = migrationsDir(t, { '001_a.sql': 'a', '002_b.sql': 'FAIL', '003_c.sql': 'c' });
  const db = createFakeDb();
  await assert.rejects(applyMigrations(db, { dir, log: silent }));
  const app = await healthApp(t, db, dir);

  const res = await app.inject('/api/health');

  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.equal(body.status, 'degraded');
  assert.equal(body.database, 'connected');
  assert.equal(body.migrations, 'pending');
  assert.equal(body.pending_migrations, 2);
  assert.doesNotMatch(res.body, /002_b|003_c/);

  writeFileSync(join(dir, '002_b.sql'), 'b');
  await applyMigrations(db, { dir, log: silent });
  assert.equal((await app.inject('/api/health')).json().status, 'ok');
});

test('health stays ok with migrations unknown when there is no ledger', async (t) => {
  const dir = migrationsDir(t, { '001_a.sql': 'a' });
  const app = await healthApp(t, createFakeDb(), dir);

  const body = (await app.inject('/api/health')).json();

  assert.equal(body.status, 'ok');
  assert.equal(body.migrations, 'unknown');
});

test('health answers 500 when the database is unreachable', async (t) => {
  const dir = migrationsDir(t, { '001_a.sql': 'a' });
  const db = createFakeDb({ ledger: ['001_a.sql'] });
  db.execute = async () => { throw new Error('connect ECONNREFUSED'); };
  const app = await healthApp(t, db, dir);

  const res = await app.inject('/api/health');

  assert.equal(res.statusCode, 500);
  assert.deepEqual(res.json(), { status: 'error', database: 'disconnected', error: 'connect ECONNREFUSED' });
});
