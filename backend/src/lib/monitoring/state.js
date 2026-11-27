/**
 * State transitions for monitors, kept free of I/O so they can be tested
 * exhaustively. The scheduler applies what these functions return.
 */

import { MONITOR_TYPES } from './types.js';

// A failure is rechecked after this long before it is believed.
export const RECHECK_MINUTES = 1;

const PROBLEM = new Set(['warn', 'down']);

/**
 * Decides what a finished check means for the monitor.
 *
 * A single failed probe is often a blip (a dropped packet, a restart), so the
 * network checks need `confirmAfter` failures in a row before the monitor
 * turns to down. Until then it keeps its status and is rechecked in a minute.
 * Recovery and warnings take effect at once.
 *
 * @returns {{ status: string, message: string, consecutiveFailures: number, changed: boolean, notify: boolean, nextCheckMinutes: number }}
 */
export function applyCheckResult(monitor, result) {
  const confirmAfter = MONITOR_TYPES[monitor.type]?.confirmAfter ?? 1;
  const previous = monitor.status || 'pending';
  const interval = monitor.interval_minutes;

  if (result.status === 'down') {
    const failures = (monitor.consecutive_failures || 0) + 1;
    if (failures < confirmAfter && previous !== 'down') {
      return { status: previous, message: monitor.status_message || '', consecutiveFailures: failures, changed: false, notify: false, nextCheckMinutes: Math.min(RECHECK_MINUTES, interval) };
    }
    const changed = previous !== 'down';
    return { status: 'down', message: result.message, consecutiveFailures: failures, changed, notify: changed, nextCheckMinutes: interval };
  }

  const changed = previous !== result.status;
  // The first result of a new monitor is only worth an alert when something is wrong.
  const notify = changed && (PROBLEM.has(result.status) || PROBLEM.has(previous));
  return { status: result.status, message: result.message, consecutiveFailures: 0, changed, notify, nextCheckMinutes: interval };
}

/**
 * A heartbeat monitor is down when its job has not pinged within the expected
 * interval plus the grace period. Before the first ping it stays pending: a
 * monitor that was just created is not a failure.
 *
 * @returns {{ status: string, message: string } | null} null when nothing changes
 */
export function evaluateHeartbeat(monitor, nowMs) {
  if (!monitor.last_ping_at) return null;
  const grace = monitor.config?.grace_minutes ?? 5;
  const allowedMs = (monitor.interval_minutes + grace) * 60000;
  const silentMs = nowMs - new Date(monitor.last_ping_at).getTime();

  if (silentMs > allowedMs) {
    if (monitor.status === 'down') return null;
    const minutes = Math.floor(silentMs / 60000);
    const unit = count => `${count} minute${count === 1 ? '' : 's'}`;
    return { status: 'down', message: `No ping for ${unit(minutes)}. Expected every ${unit(monitor.interval_minutes)}${grace ? `, plus ${unit(grace)} grace` : ''}.` };
  }
  if (monitor.status !== 'ok') return { status: 'ok', message: 'Ping received on time.' };
  return null;
}

export function describeTransition(monitor, status, message) {
  const label = MONITOR_TYPES[monitor.type]?.label || monitor.type;
  const state = { ok: 'recovered', warn: 'needs attention', down: 'is down', pending: 'is pending' }[status] || status;
  const target = monitor.target ? ` (${monitor.target})` : '';
  return { title: `${monitor.name} ${state}`, text: `[${status.toUpperCase()}] ${monitor.name}${target}: ${message}`, label };
}
