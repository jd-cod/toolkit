/**
 * Cleanup Scheduler
 *
 * Runs hourly to:
 *  - Delete expired snapshot shares from MySQL
 *  - Delete expired Traffic Analyzer shares past 7-day grace period from R2 and MySQL
 *  - Cleanup orphaned ephemeral sessions older than 10 minutes
 *
 * The R2 steps are skipped when R2 is not configured; snapshot shares live in
 * MySQL only, so they are cleaned up either way.
 */

import r2Storage from './r2-storage.js';

const GRACE_PERIOD_DAYS = 7;
const EPHEMERAL_TTL_MINUTES = 10;
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000; // 1 hour

let mysqlPool = null;

/**
 * Initialize the cleanup scheduler
 * @param {Object} mysql - MySQL connection pool from Fastify
 */
export function initCleanupScheduler(mysql) {
  mysqlPool = mysql;

  // Run cleanup immediately on startup
  runCleanup().catch(err => {
    console.error('Initial cleanup failed:', err);
  });

  // Schedule hourly cleanup
  const intervalId = setInterval(() => {
    runCleanup().catch(err => {
      console.error('Scheduled cleanup failed:', err);
    });
  }, CLEANUP_INTERVAL_MS);

  // Don't block Node.js event loop from exiting
  intervalId.unref();

  console.log('✅ Cleanup scheduler started (runs every hour)');
}

/**
 * Run cleanup process
 */
export async function runCleanup() {
  if (!mysqlPool) {
    return;
  }

  const startTime = Date.now();
  console.log('🧹 Starting cleanup process...');

  try {
    await cleanupExpiredSnapshotShares(mysqlPool);

    if (r2Storage.isEnabled()) {
      // Expired Traffic Analyzer shares (past grace period)
      await cleanupExpiredShares();

      // Ephemeral sessions older than 10 minutes
      await cleanupEphemeralSessions();
    }

    const duration = Date.now() - startTime;
    console.log(`✅ Cleanup completed in ${duration}ms`);
  } catch (err) {
    console.error('Cleanup process error:', err);
  }
}

/**
 * Delete snapshot shares as soon as they expire. An expired link already
 * answers 410, so there is nothing to keep the stored result for.
 */
export async function cleanupExpiredSnapshotShares(pool, now = new Date()) {
  try {
    const [result] = await pool.execute(
      'DELETE FROM tool_shares WHERE expires_at IS NOT NULL AND expires_at < ?',
      [now]
    );
    if (result.affectedRows > 0) {
      console.log(`   Deleted ${result.affectedRows} expired snapshot shares from MySQL`);
    }
    return result.affectedRows || 0;
  } catch (err) {
    console.error('Error cleaning up expired snapshot shares:', err);
    return 0;
  }
}

/**
 * Cleanup expired shares past the grace period
 */
async function cleanupExpiredShares() {
  try {
    // Calculate cutoff date (expires_at + 7 days grace period)
    const gracePeriodMs = GRACE_PERIOD_DAYS * 24 * 60 * 60 * 1000;
    const cutoffDate = new Date(Date.now() - gracePeriodMs);

    // Find expired shares past grace period
    const [expiredShares] = await mysqlPool.execute(
      'SELECT code, r2_key FROM shares WHERE expires_at IS NOT NULL AND expires_at < ?',
      [cutoffDate]
    );

    if (expiredShares.length === 0) {
      console.log('   No expired shares to clean up');
      return;
    }

    console.log(`   Found ${expiredShares.length} expired shares past grace period`);

    // Extract R2 keys
    const r2Keys = expiredShares
      .filter(share => share.r2_key)
      .map(share => share.r2_key);

    // Delete from R2
    if (r2Keys.length > 0) {
      await r2Storage.cleanupExpiredShares(r2Keys);
    }

    // Delete from MySQL
    const [result] = await mysqlPool.execute(
      'DELETE FROM shares WHERE expires_at IS NOT NULL AND expires_at < ?',
      [cutoffDate]
    );

    console.log(`   Deleted ${result.affectedRows} expired share records from MySQL`);
  } catch (err) {
    console.error('Error cleaning up expired shares:', err);
  }
}

/**
 * Cleanup ephemeral sessions older than TTL
 */
async function cleanupEphemeralSessions() {
  try {
    const ttlMs = EPHEMERAL_TTL_MINUTES * 60 * 1000;
    const cutoffDate = new Date(Date.now() - ttlMs);

    const deletedCount = await r2Storage.cleanupEphemeral(cutoffDate);

    if (deletedCount === 0) {
      console.log('   No expired ephemeral sessions to clean up');
    }
  } catch (err) {
    console.error('Error cleaning up ephemeral sessions:', err);
  }
}
