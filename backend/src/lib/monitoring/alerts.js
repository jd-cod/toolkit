/**
 * Alert delivery: generic webhook, Slack-style webhook, email.
 *
 * Channel targets are entered by the admin and are trusted the same way
 * monitor targets are, so they may point at internal chat servers.
 *
 * Email needs ALERT_SMTP_HOST (and usually ALERT_SMTP_USER / ALERT_SMTP_PASS,
 * ALERT_SMTP_PORT, ALERT_SMTP_FROM). Without it email channels report
 * "not configured" and nothing is sent.
 */

import nodemailer from 'nodemailer';
import { describeTransition } from './state.js';

const TIMEOUT_MS = 10000;
let transport = null;

export function smtpConfigured() {
  return Boolean(process.env.ALERT_SMTP_HOST);
}

function mailer() {
  if (!transport) {
    const port = Number(process.env.ALERT_SMTP_PORT || 587);
    transport = nodemailer.createTransport({
      host: process.env.ALERT_SMTP_HOST,
      port,
      secure: port === 465,
      auth: process.env.ALERT_SMTP_USER ? { user: process.env.ALERT_SMTP_USER, pass: process.env.ALERT_SMTP_PASS || '' } : undefined,
      connectionTimeout: TIMEOUT_MS,
      socketTimeout: TIMEOUT_MS,
    });
  }
  return transport;
}

export function buildAlert(monitor, { status, previousStatus, message, at = new Date() }) {
  const { title, text, label } = describeTransition(monitor, status, message);
  return {
    title,
    text,
    payload: {
      event: 'monitor.status_changed',
      monitor: { id: monitor.id, name: monitor.name, type: monitor.type, type_label: label, target: monitor.target },
      status,
      previous_status: previousStatus,
      message,
      at: at.toISOString(),
    },
  };
}

async function postJson(url, body, fetchImpl) {
  const response = await fetchImpl(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': 'SysAdminToolkit-Monitor/1.0' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  await response.body?.cancel().catch(() => {});
  if (!response.ok) throw new Error(`The endpoint answered HTTP ${response.status}`);
}

/** Sends one alert to one channel. Throws with a short reason when delivery fails. */
export async function deliver(channel, alert, { fetchImpl = fetch, sendMail } = {}) {
  if (channel.type === 'webhook') return postJson(channel.target, alert.payload, fetchImpl);
  if (channel.type === 'slack') return postJson(channel.target, { text: alert.text }, fetchImpl);
  if (channel.type === 'email') {
    if (!sendMail && !smtpConfigured()) throw new Error('Email is not configured on this server (ALERT_SMTP_HOST is not set)');
    const mail = {
      from: process.env.ALERT_SMTP_FROM || process.env.ALERT_SMTP_USER || 'sysadmin-toolkit@localhost',
      to: channel.target,
      subject: `[Monitor] ${alert.title}`,
      text: `${alert.text}\n\nTime: ${alert.payload.at}\nMonitor type: ${alert.payload.monitor.type_label}\n`,
    };
    await (sendMail ? sendMail(mail) : mailer().sendMail(mail));
    return undefined;
  }
  throw new Error(`Unknown channel type "${channel.type}"`);
}

/**
 * Sends an alert to every enabled channel and records the outcome on each.
 * One failing channel never stops the others.
 */
export function createNotifier({ pool, log = console, deliverImpl = deliver } = {}) {
  return async function notify(monitor, change) {
    const [channels] = await pool.execute('SELECT * FROM alert_channels WHERE is_enabled = 1');
    const alert = buildAlert(monitor, change);
    await Promise.all(channels.map(async channel => {
      let error = '';
      try {
        await deliverImpl(channel, alert);
      } catch (err) {
        error = String(err?.message || 'Delivery failed').slice(0, 500);
        log.warn?.(`[monitoring] alert to "${channel.name}" failed: ${error}`);
      }
      await pool.execute('UPDATE alert_channels SET last_status = ?, last_error = ?, last_sent_at = NOW() WHERE id = ?', [error ? 'error' : 'ok', error, channel.id]);
    }));
    return channels.length;
  };
}
