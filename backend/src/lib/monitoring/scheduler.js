/**
 * Runs due monitors on a timer.
 *
 * One tick: claim the monitors that are due, run their checks a few at a
 * time, store the results, record state changes and send alerts. Heartbeat
 * monitors are not probed; each tick only asks whether their last ping is
 * overdue.
 *
 * Claiming is an UPDATE that moves `next_check_at` forward and only succeeds
 * for one caller, so two backend processes pointed at one database do not run
 * the same check twice.
 *
 * Set MONITORING_ENABLED=false to keep the timer from starting.
 */

import { mapLimit } from '../dns-client.js';
import { applyCheckResult, evaluateHeartbeat } from './state.js';

const TICK_MS = 30000;
const BATCH = 20;
const CONCURRENCY = 5;

export function parseConfig(row) {
  let config = {};
  try {
    config = row.config_json ? JSON.parse(row.config_json) : {};
  } catch {
    config = {};
  }
  return { ...row, config };
}

export function createMonitorScheduler({ pool, runCheck, notify, log = console }) {
  let timer = null;
  let running = false;

  async function recordChange(monitor, status, previousStatus, message, shouldNotify) {
    await pool.execute('INSERT INTO monitor_events (monitor_id, status, previous_status, message) VALUES (?, ?, ?, ?)', [monitor.id, status, previousStatus, message.slice(0, 1000)]);
    if (shouldNotify) {
      try {
        await notify(monitor, { status, previousStatus, message });
      } catch (err) {
        log.warn?.(`[monitoring] notify failed: ${err.message}`);
      }
    }
  }

  /** Runs one monitor now and stores the outcome. Returns the check result. */
  async function runMonitor(row) {
    const monitor = parseConfig(row);
    const result = await runCheck(monitor);
    const next = applyCheckResult(monitor, result);

    // A DNS monitor with no expected value adopts its first answer as the baseline.
    let configJson = row.config_json;
    if (monitor.type === 'dns_record' && result.details?.baseline && !Array.isArray(monitor.config.baseline)) {
      configJson = JSON.stringify({ ...monitor.config, baseline: result.details.baseline });
    }

    await pool.execute(
      `UPDATE monitors SET status = ?, status_message = ?, consecutive_failures = ?, last_checked_at = NOW(),
         next_check_at = DATE_ADD(NOW(), INTERVAL ? MINUTE), last_result_json = ?, config_json = ?,
         status_since = IF(? = 1, NOW(), status_since)
       WHERE id = ?`,
      [next.status, next.message.slice(0, 1000), next.consecutiveFailures, next.nextCheckMinutes, JSON.stringify({ ...result, checked_at: new Date().toISOString() }).slice(0, 60000), configJson, next.changed ? 1 : 0, monitor.id],
    );
    if (next.changed) await recordChange(monitor, next.status, monitor.status || 'pending', next.message, next.notify);
    return { result, state: next };
  }

  /** Applies an overdue or recovered heartbeat. Returns true when the status changed. */
  async function applyHeartbeat(row) {
    const monitor = parseConfig(row);
    const change = evaluateHeartbeat(monitor, Date.now());
    if (!change) return false;
    await pool.execute('UPDATE monitors SET status = ?, status_message = ?, status_since = NOW(), last_checked_at = NOW() WHERE id = ?', [change.status, change.message, monitor.id]);
    // The first ping of a new monitor (pending to ok) is not worth an alert.
    await recordChange(monitor, change.status, monitor.status || 'pending', change.message, !(monitor.status === 'pending' && change.status === 'ok'));
    return true;
  }

  async function checkHeartbeats() {
    const [rows] = await pool.execute("SELECT * FROM monitors WHERE is_enabled = 1 AND type = 'heartbeat' AND last_ping_at IS NOT NULL");
    for (const row of rows) await applyHeartbeat(row);
  }

  async function tick() {
    if (running) return;
    running = true;
    try {
      const [due] = await pool.execute(
        `SELECT * FROM monitors WHERE is_enabled = 1 AND type <> 'heartbeat' AND (next_check_at IS NULL OR next_check_at <= NOW())
         ORDER BY next_check_at IS NULL DESC, next_check_at ASC LIMIT ${BATCH}`,
      );
      await mapLimit(due, CONCURRENCY, async row => {
        const [claim] = await pool.execute(
          'UPDATE monitors SET next_check_at = DATE_ADD(NOW(), INTERVAL interval_minutes MINUTE) WHERE id = ? AND is_enabled = 1 AND (next_check_at IS NULL OR next_check_at <= NOW())',
          [row.id],
        );
        if (claim.affectedRows !== 1) return;
        try {
          await runMonitor(row);
        } catch (err) {
          log.error?.(`[monitoring] monitor ${row.id} failed: ${err.message}`);
        }
      });
      await checkHeartbeats();
    } catch (err) {
      log.error?.(`[monitoring] tick failed: ${err.message}`);
    } finally {
      running = false;
    }
  }

  return {
    tick,
    runMonitor,
    applyHeartbeat,
    start() {
      if (timer || String(process.env.MONITORING_ENABLED || '').toLowerCase() === 'false') return false;
      timer = setInterval(() => { void tick(); }, TICK_MS);
      timer.unref?.();
      void tick();
      return true;
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = null;
    },
  };
}
