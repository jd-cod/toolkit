/**
 * Cleanup Scheduler for R2 Storage
 *
 * Runs hourly to:
 *  - Delete expired shares past 7-day grace period from R2 and MySQL
 *  - Cleanup orphaned ephemeral sessions older than 10 minutes
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
  if (!r2Storage.isEnabled()) {
    console.log('⚠️  R2 storage disabled, cleanup scheduler will not start');
    return;
  }

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
  if (!r2Storage.isEnabled() || !mysqlPool) {
    return;
  }

  const startTime = Date.now();
  console.log('🧹 Starting cleanup process...');

  try {
    // Cleanup 1: Expired shares (past grace period)
    await cleanupExpiredShares();

    // Cleanup 2: Ephemeral sessions older than 10 minutes
    await cleanupEphemeralSessions();

    const duration = Date.now() - startTime;
    console.log(`✅ Cleanup completed in ${duration}ms`);
  } catch (err) {
    console.error('Cleanup process error:', err);
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
