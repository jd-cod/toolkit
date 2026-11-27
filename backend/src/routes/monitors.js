/**
 * Monitoring — Fastify
 *
 * Admin (cookie auth), all under /api/admin:
 *   GET    /monitors                    list with current state
 *   POST   /monitors                    create
 *   PUT    /monitors/:id                update
 *   DELETE /monitors/:id
 *   POST   /monitors/:id/run            run the check now
 *   POST   /monitors/:id/accept         dns_record: accept the current value as the new baseline
 *   GET    /monitors/:id/events         last 50 state changes
 *   GET    /alert-channels              list (also reports whether email is configured)
 *   POST   /alert-channels              create
 *   PUT    /alert-channels/:id          update
 *   DELETE /alert-channels/:id
 *   POST   /alert-channels/:id/test     send a test alert
 *
 * Public:
 *   GET|POST /api/ping/:token           heartbeat for a cron job
 *
 * See docs/TOOLS_ROADMAP.md, "Monitoring".
 */

import { randomBytes } from 'node:crypto';
import { MONITOR_TYPES, normalizeChannelInput, normalizeMonitorInput } from '../lib/monitoring/types.js';
import { parseConfig } from '../lib/monitoring/scheduler.js';
import { buildAlert, deliver, smtpConfigured } from '../lib/monitoring/alerts.js';

const MAX_MONITORS = 500;
const MAX_CHANNELS = 20;

function safeParse(text) {
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    return null;
  }
}

function serializeMonitor(row) {
  const monitor = parseConfig(row);
  return {
    id: monitor.id,
    name: monitor.name,
    type: monitor.type,
    type_label: MONITOR_TYPES[monitor.type]?.label || monitor.type,
    target: monitor.target,
    config: monitor.config,
    interval_minutes: monitor.interval_minutes,
    is_enabled: monitor.is_enabled,
    status: monitor.status,
    status_message: monitor.status_message,
    status_since: monitor.status_since,
    last_checked_at: monitor.last_checked_at,
    next_check_at: monitor.next_check_at,
    consecutive_failures: monitor.consecutive_failures,
    heartbeat_token: monitor.type === 'heartbeat' ? monitor.heartbeat_token : null,
    last_ping_at: monitor.last_ping_at,
    last_result: safeParse(monitor.last_result_json),
  };
}

export default async function monitorRoutes(fastify, opts) {
  const pool = fastify.mysql;
  const guard = { preHandler: [fastify.auth.authMiddleware] };
  const { scheduler } = opts;
  const deliverAlert = opts.deliver || deliver;

  // Routes registered as plugins do not inherit the error handler in
  // server.js, so validation errors are answered here in the { error } shape.
  const handled = handler => async (request, reply) => {
    try {
      return await handler(request, reply);
    } catch (err) {
      if (err?.statusCode === 400) return reply.code(400).send({ error: err.message });
      request.log.error(err);
      return reply.code(500).send({ error: 'The request failed.' });
    }
  };

  async function logActivity(action, details, username) {
    try {
      await pool.execute('INSERT INTO admin_activity_log (action, details, admin_username) VALUES (?, ?, ?)', [action, details, username || 'system']);
    } catch (err) {
      fastify.log.warn(`activity log failed: ${err.message}`);
    }
  }

  async function findMonitor(id) {
    if (!/^\d+$/.test(String(id))) return null;
    const [rows] = await pool.execute('SELECT * FROM monitors WHERE id = ?', [Number(id)]);
    return rows[0] || null;
  }

  // ─── Monitors ───

  fastify.get('/admin/monitors', guard, handled(async () => {
    const [rows] = await pool.execute('SELECT * FROM monitors ORDER BY FIELD(status, \'down\', \'warn\', \'pending\', \'ok\'), name ASC');
    const monitors = rows.map(serializeMonitor);
    const counts = { down: 0, warn: 0, ok: 0, pending: 0, paused: 0 };
    for (const monitor of monitors) counts[monitor.is_enabled ? monitor.status : 'paused'] = (counts[monitor.is_enabled ? monitor.status : 'paused'] || 0) + 1;
    return { monitors, counts, types: MONITOR_TYPES };
  }));

  fastify.post('/admin/monitors', guard, handled(async (request, reply) => {
    const input = normalizeMonitorInput(request.body || {});
    const [[{ total }]] = await pool.execute('SELECT COUNT(*) AS total FROM monitors');
    if (total >= MAX_MONITORS) return reply.code(400).send({ error: `At most ${MAX_MONITORS} monitors can be created.` });

    const token = input.type === 'heartbeat' ? randomBytes(18).toString('base64url') : null;
    const [result] = await pool.execute(
      'INSERT INTO monitors (name, type, target, config_json, interval_minutes, is_enabled, heartbeat_token, status_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [input.name, input.type, input.target, JSON.stringify(input.config), input.interval_minutes, input.is_enabled, token, input.type === 'heartbeat' ? 'Waiting for the first ping.' : 'Waiting for the first check.'],
    );
    await logActivity('monitor.create', `Created monitor "${input.name}" (${input.type})`, request.admin?.username);
    return { success: true, monitor: serializeMonitor(await findMonitor(result.insertId)) };
  }));

  fastify.put('/admin/monitors/:id', guard, handled(async (request, reply) => {
    const existing = await findMonitor(request.params.id);
    if (!existing) return reply.code(404).send({ error: 'Monitor not found.' });
    const body = request.body || {};

    // A bare { is_enabled } pauses or resumes without re-validating the rest.
    if (Object.keys(body).length === 1 && body.is_enabled !== undefined) {
      await pool.execute('UPDATE monitors SET is_enabled = ?, next_check_at = NULL WHERE id = ?', [body.is_enabled ? 1 : 0, existing.id]);
      await logActivity('monitor.update', `${body.is_enabled ? 'Resumed' : 'Paused'} monitor "${existing.name}"`, request.admin?.username);
      return { success: true, monitor: serializeMonitor(await findMonitor(existing.id)) };
    }

    const current = parseConfig(existing);
    // The type cannot change: its state and history would no longer mean anything.
    const input = normalizeMonitorInput({ ...body, type: existing.type, config: { ...(body.config || {}), baseline: current.config.baseline } });
    const targetChanged = input.target !== existing.target || JSON.stringify({ ...input.config, baseline: null }) !== JSON.stringify({ ...current.config, baseline: null });
    if (targetChanged && input.type === 'dns_record') input.config.baseline = null;

    await pool.execute(
      `UPDATE monitors SET name = ?, target = ?, config_json = ?, interval_minutes = ?, is_enabled = ?, next_check_at = NULL,
         status = IF(? = 1, 'pending', status), status_message = IF(? = 1, 'Waiting for the next check.', status_message), consecutive_failures = IF(? = 1, 0, consecutive_failures)
       WHERE id = ?`,
      [input.name, input.target, JSON.stringify(input.config), input.interval_minutes, input.is_enabled, targetChanged ? 1 : 0, targetChanged ? 1 : 0, targetChanged ? 1 : 0, existing.id],
    );
    await logActivity('monitor.update', `Updated monitor "${input.name}"`, request.admin?.username);
    return { success: true, monitor: serializeMonitor(await findMonitor(existing.id)) };
  }));

  fastify.delete('/admin/monitors/:id', guard, handled(async (request, reply) => {
    const existing = await findMonitor(request.params.id);
    if (!existing) return reply.code(404).send({ error: 'Monitor not found.' });
    await pool.execute('DELETE FROM monitors WHERE id = ?', [existing.id]);
    await logActivity('monitor.delete', `Deleted monitor "${existing.name}"`, request.admin?.username);
    return { success: true };
  }));

  fastify.post('/admin/monitors/:id/run', guard, handled(async (request, reply) => {
    const existing = await findMonitor(request.params.id);
    if (!existing) return reply.code(404).send({ error: 'Monitor not found.' });
    if (existing.type === 'heartbeat') return reply.code(400).send({ error: 'Heartbeat monitors wait for a ping; there is nothing to run.' });
    await scheduler.runMonitor(existing);
    return { success: true, monitor: serializeMonitor(await findMonitor(existing.id)) };
  }));

  fastify.post('/admin/monitors/:id/accept', guard, handled(async (request, reply) => {
    const existing = await findMonitor(request.params.id);
    if (!existing) return reply.code(404).send({ error: 'Monitor not found.' });
    if (existing.type !== 'dns_record') return reply.code(400).send({ error: 'Only DNS record monitors have a baseline.' });
    const current = parseConfig(existing);
    const observed = safeParse(existing.last_result_json)?.details?.current;
    if (!Array.isArray(observed)) return reply.code(400).send({ error: 'Run the check first.' });
    await pool.execute('UPDATE monitors SET config_json = ?, consecutive_failures = 0 WHERE id = ?', [JSON.stringify({ ...current.config, expected: [], baseline: observed }), existing.id]);
    await logActivity('monitor.update', `Accepted new DNS baseline for "${existing.name}"`, request.admin?.username);
    await scheduler.runMonitor(await findMonitor(existing.id));
    return { success: true, monitor: serializeMonitor(await findMonitor(existing.id)) };
  }));

  fastify.get('/admin/monitors/:id/events', guard, handled(async (request, reply) => {
    const existing = await findMonitor(request.params.id);
    if (!existing) return reply.code(404).send({ error: 'Monitor not found.' });
    const [events] = await pool.execute('SELECT id, status, previous_status, message, created_at FROM monitor_events WHERE monitor_id = ? ORDER BY id DESC LIMIT 50', [existing.id]);
    return { events };
  }));

  // ─── Alert channels ───

  fastify.get('/admin/alert-channels', guard, handled(async () => {
    const [channels] = await pool.execute('SELECT * FROM alert_channels ORDER BY name ASC');
    return { channels, email_configured: smtpConfigured() };
  }));

  fastify.post('/admin/alert-channels', guard, handled(async (request, reply) => {
    const input = normalizeChannelInput(request.body || {});
    const [[{ total }]] = await pool.execute('SELECT COUNT(*) AS total FROM alert_channels');
    if (total >= MAX_CHANNELS) return reply.code(400).send({ error: `At most ${MAX_CHANNELS} alert channels can be created.` });
    const [result] = await pool.execute('INSERT INTO alert_channels (name, type, target, is_enabled) VALUES (?, ?, ?, ?)', [input.name, input.type, input.target, input.is_enabled]);
    await logActivity('alert_channel.create', `Created alert channel "${input.name}" (${input.type})`, request.admin?.username);
    return { success: true, id: result.insertId };
  }));

  fastify.put('/admin/alert-channels/:id', guard, handled(async (request, reply) => {
    if (!/^\d+$/.test(String(request.params.id))) return reply.code(404).send({ error: 'Channel not found.' });
    const [rows] = await pool.execute('SELECT * FROM alert_channels WHERE id = ?', [Number(request.params.id)]);
    if (!rows[0]) return reply.code(404).send({ error: 'Channel not found.' });
    const input = normalizeChannelInput({ ...rows[0], ...(request.body || {}) });
    await pool.execute('UPDATE alert_channels SET name = ?, type = ?, target = ?, is_enabled = ? WHERE id = ?', [input.name, input.type, input.target, input.is_enabled, rows[0].id]);
    return { success: true };
  }));

  fastify.delete('/admin/alert-channels/:id', guard, handled(async (request, reply) => {
    if (!/^\d+$/.test(String(request.params.id))) return reply.code(404).send({ error: 'Channel not found.' });
    const [result] = await pool.execute('DELETE FROM alert_channels WHERE id = ?', [Number(request.params.id)]);
    if (result.affectedRows === 0) return reply.code(404).send({ error: 'Channel not found.' });
    await logActivity('alert_channel.delete', `Deleted alert channel #${request.params.id}`, request.admin?.username);
    return { success: true };
  }));

  fastify.post('/admin/alert-channels/:id/test', guard, handled(async (request, reply) => {
    if (!/^\d+$/.test(String(request.params.id))) return reply.code(404).send({ error: 'Channel not found.' });
    const [rows] = await pool.execute('SELECT * FROM alert_channels WHERE id = ?', [Number(request.params.id)]);
    const channel = rows[0];
    if (!channel) return reply.code(404).send({ error: 'Channel not found.' });

    const alert = buildAlert({ id: 0, name: 'Test alert', type: 'http', target: 'https://example.com' }, { status: 'down', previousStatus: 'ok', message: 'This is a test alert from SysAdmin Toolkit. No monitor is down.' });
    let error = '';
    try {
      await deliverAlert(channel, alert);
    } catch (err) {
      error = String(err?.message || 'Delivery failed').slice(0, 500);
    }
    await pool.execute('UPDATE alert_channels SET last_status = ?, last_error = ?, last_sent_at = NOW() WHERE id = ?', [error ? 'error' : 'ok', error, channel.id]);
    return error ? reply.code(400).send({ error: `Delivery failed: ${error}` }) : { success: true };
  }));

  // ─── Heartbeat ping (public; the token is the credential) ───

  const ping = async (request, reply) => {
    const token = String(request.params.token || '');
    if (!/^[A-Za-z0-9_-]{16,64}$/.test(token)) return reply.code(404).send({ error: 'Unknown monitor.' });
    const [result] = await pool.execute('UPDATE monitors SET last_ping_at = NOW() WHERE heartbeat_token = ? AND type = \'heartbeat\' AND is_enabled = 1', [token]);
    if (result.affectedRows === 0) return reply.code(404).send({ error: 'Unknown monitor.' });
    const [rows] = await pool.execute('SELECT * FROM monitors WHERE heartbeat_token = ?', [token]);
    if (rows[0]) await scheduler.applyHeartbeat(rows[0]);
    return { ok: true };
  };
  const pingLimit = { config: { rateLimit: { max: 120, timeWindow: '1 minute' } } };
  fastify.get('/ping/:token', pingLimit, ping);
  fastify.post('/ping/:token', pingLimit, ping);
}
