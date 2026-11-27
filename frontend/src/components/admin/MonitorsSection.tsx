'use client';

import { useCallback, useEffect, useState } from 'react';
import { adminApi, errorMessage, formatTime } from './adminUtils';
import { useToast } from './AdminToast';
import AdminModal from './AdminModal';

/**
 * Monitors and alert channels. Monitors belong to the admin until customer
 * accounts exist (docs/TOOLS_ROADMAP.md, "Monitoring").
 */

type MonitorType = 'ssl_expiry' | 'domain_expiry' | 'blacklist' | 'dns_record' | 'http' | 'tcp' | 'heartbeat';
type Status = 'pending' | 'ok' | 'warn' | 'down';

interface Monitor {
  id: number;
  name: string;
  type: MonitorType;
  type_label: string;
  target: string;
  config: Record<string, unknown>;
  interval_minutes: number;
  is_enabled: number;
  status: Status;
  status_message: string;
  status_since: string | null;
  last_checked_at: string | null;
  heartbeat_token: string | null;
  last_ping_at: string | null;
}

interface MonitorEvent { id: number; status: Status; previous_status: string; message: string; created_at: string }
interface Channel { id: number; name: string; type: 'webhook' | 'slack' | 'email'; target: string; is_enabled: number; last_status: string; last_error: string; last_sent_at: string | null }
interface TypeSpec { label: string; minInterval: number; defaultInterval: number }

const TYPE_HELP: Record<MonitorType, { target: string; placeholder: string; about: string }> = {
  ssl_expiry: { target: 'Host (optionally host:port)', placeholder: 'www.example.com', about: 'Warns before a certificate expires, and when it stops matching the host name.' },
  domain_expiry: { target: 'Domain', placeholder: 'example.com', about: 'Warns before a domain registration runs out.' },
  blacklist: { target: 'IP address or host name', placeholder: '203.0.113.25', about: 'Alerts when a sending address appears on a spam blacklist.' },
  dns_record: { target: 'DNS name', placeholder: 'www.example.com', about: 'Alerts when a record no longer has the expected value.' },
  http: { target: 'URL', placeholder: 'https://example.com/health', about: 'Alerts when a URL stops answering, returns an error or loses a keyword.' },
  tcp: { target: 'Host and port', placeholder: 'db.example.com:5432', about: 'Alerts when a port stops accepting connections.' },
  heartbeat: { target: '', placeholder: '', about: 'Alerts when a scheduled job stops calling its ping URL.' },
};

const STATUS_BADGE: Record<Status, { label: string; className: string }> = {
  ok: { label: 'OK', className: 'badge-success' },
  warn: { label: 'Warning', className: 'badge-warning' },
  down: { label: 'Down', className: 'badge-danger' },
  pending: { label: 'Pending', className: 'badge-info' },
};

const EMPTY_FORM = {
  type: 'http' as MonitorType, name: '', target: '', interval_minutes: '', warn_days: '', record_type: 'A', expected: '',
  expected_status: '', keyword: '', timeout_seconds: '', grace_minutes: '',
};

function intervalText(minutes: number) {
  if (minutes % 1440 === 0) return `${minutes / 1440} d`;
  if (minutes % 60 === 0) return `${minutes / 60} h`;
  return `${minutes} min`;
}

export default function MonitorsSection() {
  const { toast } = useToast();
  const [monitors, setMonitors] = useState<Monitor[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [types, setTypes] = useState<Record<string, TypeSpec>>({});
  const [channels, setChannels] = useState<Channel[]>([]);
  const [emailConfigured, setEmailConfigured] = useState(true);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<number | null>(null);

  const [modalOpen, setModalOpen] = useState(false);
  const [editItem, setEditItem] = useState<Monitor | null>(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState<Monitor | null>(null);
  const [history, setHistory] = useState<{ monitor: Monitor; events: MonitorEvent[] } | null>(null);
  const [pingFor, setPingFor] = useState<Monitor | null>(null);

  const [channelModal, setChannelModal] = useState(false);
  const [channelForm, setChannelForm] = useState({ name: '', type: 'webhook' as Channel['type'], target: '' });

  const load = useCallback(async () => {
    try {
      const [monitorData, channelData] = await Promise.all([
        adminApi<{ monitors: Monitor[]; counts: Record<string, number>; types: Record<string, TypeSpec> }>('/monitors'),
        adminApi<{ channels: Channel[]; email_configured: boolean }>('/alert-channels'),
      ]);
      setMonitors(monitorData.monitors);
      setCounts(monitorData.counts);
      setTypes(monitorData.types);
      setChannels(channelData.channels);
      setEmailConfigured(channelData.email_configured);
    } catch (e) {
      toast('Failed to load monitors: ' + errorMessage(e), 'error');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
    // States change on the server while this page is open.
    const timer = window.setInterval(() => { void load(); }, 30000);
    return () => window.clearInterval(timer);
  }, [load]);

  const setField = <K extends keyof typeof EMPTY_FORM>(key: K, value: (typeof EMPTY_FORM)[K]) => setForm(prev => ({ ...prev, [key]: value }));
  const pingUrl = (monitor: Monitor) => `${window.location.origin}/api/ping/${monitor.heartbeat_token}`;

  function openCreate() {
    setEditItem(null);
    setForm(EMPTY_FORM);
    setModalOpen(true);
  }

  function openEdit(monitor: Monitor) {
    const config = monitor.config || {};
    const text = (value: unknown) => (value === undefined || value === null || value === 0 ? '' : String(value));
    setEditItem(monitor);
    setForm({
      type: monitor.type, name: monitor.name, target: monitor.target, interval_minutes: String(monitor.interval_minutes),
      warn_days: text(config.warn_days), record_type: text(config.record_type) || 'A',
      expected: Array.isArray(config.expected) ? config.expected.join(', ') : '',
      expected_status: text(config.expected_status), keyword: text(config.keyword), timeout_seconds: text(config.timeout_seconds),
      grace_minutes: config.grace_minutes === undefined ? '' : String(config.grace_minutes),
    });
    setModalOpen(true);
  }

  async function save() {
    setSaving(true);
    const body = {
      type: form.type, name: form.name, target: form.target, interval_minutes: form.interval_minutes,
      config: {
        warn_days: form.warn_days, record_type: form.record_type, expected: form.expected,
        expected_status: form.expected_status, keyword: form.keyword, timeout_seconds: form.timeout_seconds, grace_minutes: form.grace_minutes,
      },
    };
    try {
      if (editItem) {
        await adminApi(`/monitors/${editItem.id}`, { method: 'PUT', body });
        toast('Monitor updated');
      } else {
        const created = await adminApi<{ monitor: Monitor }>('/monitors', { method: 'POST', body });
        toast('Monitor created. The first check runs within a minute.');
        if (created.monitor.type === 'heartbeat') setPingFor(created.monitor);
      }
      setModalOpen(false);
      await load();
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setSaving(false);
    }
  }

  async function act(monitor: Monitor, action: () => Promise<unknown>, done: string) {
    setBusyId(monitor.id);
    try {
      await action();
      if (done) toast(done);
      await load();
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setBusyId(null);
    }
  }

  async function showHistory(monitor: Monitor) {
    try {
      const data = await adminApi<{ events: MonitorEvent[] }>(`/monitors/${monitor.id}/events`);
      setHistory({ monitor, events: data.events });
    } catch (e) {
      toast(errorMessage(e), 'error');
    }
  }

  async function saveChannel() {
    try {
      await adminApi('/alert-channels', { method: 'POST', body: channelForm });
      toast('Alert channel added');
      setChannelModal(false);
      setChannelForm({ name: '', type: 'webhook', target: '' });
      await load();
    } catch (e) {
      toast(errorMessage(e), 'error');
    }
  }

  async function channelAction(action: () => Promise<unknown>, done: string) {
    try {
      await action();
      toast(done);
    } catch (e) {
      toast(errorMessage(e), 'error');
    }
    await load();
  }

  const help = TYPE_HELP[form.type];
  const spec = types[form.type];

  return (
    <>
      <div className="admin-card mb-4">
        <div className="admin-card-header">
          <div>
            <h3 className="admin-card-title"><i className="bi bi-activity" style={{ marginRight: 8 }} />Monitors</h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: 6 }}>
              Checks that run on a schedule and alert when something changes: certificates, domains, blacklists, DNS, uptime and cron jobs.
            </p>
          </div>
          <button className="btn btn-sm btn-admin-primary" onClick={openCreate}><i className="bi bi-plus-lg" /> Add monitor</button>
        </div>
        <div className="admin-card-body">
          <div className="d-flex gap-2" style={{ flexWrap: 'wrap' }}>
            <span className="badge-admin badge-danger">{counts.down || 0} down</span>
            <span className="badge-admin badge-warning">{counts.warn || 0} warning</span>
            <span className="badge-admin badge-success">{counts.ok || 0} OK</span>
            <span className="badge-admin badge-info">{counts.pending || 0} pending</span>
            {(counts.paused || 0) > 0 && <span className="badge-admin">{counts.paused} paused</span>}
          </div>
        </div>
      </div>

      <div className="admin-card mb-4">
        <div className="admin-card-body" style={{ padding: 0 }}>
          {loading ? (
            <div style={{ padding: 16 }}><div className="skeleton" style={{ height: 36 }} /></div>
          ) : monitors.length === 0 ? (
            <div className="empty-state" style={{ padding: 24 }}>
              <i className="bi bi-activity" />
              <h4>No monitors yet</h4>
              <p>Add one to be told when a certificate is about to expire, a site goes down or a cron job stops running.</p>
            </div>
          ) : (
            <div className="table-responsive" style={{ overflowX: 'auto' }}>
              <table className="admin-table">
                <thead>
                  <tr><th>Monitor</th><th>Status</th><th>Last result</th><th>Checked</th><th>Every</th><th style={{ textAlign: 'right' }}>Actions</th></tr>
                </thead>
                <tbody>
                  {monitors.map(monitor => {
                    const badge = monitor.is_enabled ? STATUS_BADGE[monitor.status] : { label: 'Paused', className: '' };
                    const busy = busyId === monitor.id;
                    return (
                      <tr key={monitor.id}>
                        <td>
                          <div style={{ fontWeight: 600 }}>{monitor.name}</div>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{monitor.type_label}{monitor.target ? ` · ${monitor.target}` : ''}</div>
                        </td>
                        <td><span className={`badge-admin ${badge.className}`}>{badge.label}</span></td>
                        <td style={{ fontSize: '0.82rem', maxWidth: 360 }}>{monitor.status_message || '—'}</td>
                        <td style={{ fontSize: '0.78rem', whiteSpace: 'nowrap' }}>{formatTime(monitor.type === 'heartbeat' ? monitor.last_ping_at : monitor.last_checked_at) || 'Never'}</td>
                        <td style={{ fontSize: '0.78rem', whiteSpace: 'nowrap' }}>{intervalText(monitor.interval_minutes)}</td>
                        <td>
                          <div className="d-flex gap-1" style={{ justifyContent: 'flex-end' }}>
                            {monitor.type === 'heartbeat'
                              ? <button className="btn btn-icon btn-admin-outline" title="Show ping URL" aria-label="Show ping URL" onClick={() => setPingFor(monitor)}><i className="bi bi-link-45deg" /></button>
                              : <button className="btn btn-icon btn-admin-outline" title="Run now" aria-label="Run now" disabled={busy} onClick={() => void act(monitor, () => adminApi(`/monitors/${monitor.id}/run`, { method: 'POST' }), 'Check finished')}><i className={`bi ${busy ? 'bi-hourglass-split' : 'bi-play-fill'}`} /></button>}
                            {monitor.type === 'dns_record' && monitor.status === 'down' && (
                              <button className="btn btn-icon btn-admin-outline" title="Accept the current value" aria-label="Accept the current value" disabled={busy} onClick={() => void act(monitor, () => adminApi(`/monitors/${monitor.id}/accept`, { method: 'POST' }), 'Current value accepted as the baseline')}><i className="bi bi-check2-circle" /></button>
                            )}
                            <button className="btn btn-icon btn-admin-outline" title="History" aria-label="History" onClick={() => void showHistory(monitor)}><i className="bi bi-clock-history" /></button>
                            <button className="btn btn-icon btn-admin-outline" title={monitor.is_enabled ? 'Pause' : 'Resume'} aria-label={monitor.is_enabled ? 'Pause' : 'Resume'} onClick={() => void act(monitor, () => adminApi(`/monitors/${monitor.id}`, { method: 'PUT', body: { is_enabled: !monitor.is_enabled } }), monitor.is_enabled ? 'Monitor paused' : 'Monitor resumed')}><i className={`bi ${monitor.is_enabled ? 'bi-pause-fill' : 'bi-play-circle'}`} /></button>
                            <button className="btn btn-icon btn-admin-outline" title="Edit" aria-label="Edit" onClick={() => openEdit(monitor)}><i className="bi bi-pencil" /></button>
                            <button className="btn btn-icon btn-admin-outline" title="Delete" aria-label="Delete" onClick={() => setDeleting(monitor)}><i className="bi bi-trash" /></button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      <div className="admin-card">
        <div className="admin-card-header">
          <div>
            <h3 className="admin-card-title"><i className="bi bi-bell" style={{ marginRight: 8 }} />Alert channels</h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: 6 }}>Every status change is sent to all enabled channels.</p>
          </div>
          <button className="btn btn-sm btn-admin-primary" onClick={() => setChannelModal(true)}><i className="bi bi-plus-lg" /> Add channel</button>
        </div>
        <div className="admin-card-body" style={{ padding: 0 }}>
          {channels.length === 0 ? (
            <div className="empty-state" style={{ padding: 24 }}><i className="bi bi-bell-slash" /><h4>No alert channels</h4><p>Without a channel, status changes are only visible on this page.</p></div>
          ) : (
            <div className="table-responsive" style={{ overflowX: 'auto' }}>
              <table className="admin-table">
                <thead><tr><th>Channel</th><th>Type</th><th>Last delivery</th><th style={{ textAlign: 'right' }}>Actions</th></tr></thead>
                <tbody>
                  {channels.map(channel => (
                    <tr key={channel.id}>
                      <td><div style={{ fontWeight: 600 }}>{channel.name}</div><div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>{channel.target}</div></td>
                      <td>{channel.type === 'slack' ? 'Slack-style webhook' : channel.type === 'email' ? 'Email' : 'Webhook (JSON)'}</td>
                      <td style={{ fontSize: '0.82rem' }}>
                        {channel.last_status === 'ok' && <span className="badge-admin badge-success">Delivered</span>}
                        {channel.last_status === 'error' && <><span className="badge-admin badge-danger">Failed</span> {channel.last_error}</>}
                        {!channel.last_status && 'Not used yet'}
                        {channel.last_sent_at && <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{formatTime(channel.last_sent_at)}</div>}
                      </td>
                      <td>
                        <div className="d-flex gap-1" style={{ justifyContent: 'flex-end' }}>
                          <button className="btn btn-sm btn-admin-outline" onClick={() => void channelAction(() => adminApi(`/alert-channels/${channel.id}/test`, { method: 'POST' }), 'Test alert sent')}>Send test</button>
                          <button className="btn btn-icon btn-admin-outline" title={channel.is_enabled ? 'Disable' : 'Enable'} aria-label={channel.is_enabled ? 'Disable' : 'Enable'} onClick={() => void channelAction(() => adminApi(`/alert-channels/${channel.id}`, { method: 'PUT', body: { is_enabled: !channel.is_enabled } }), channel.is_enabled ? 'Channel disabled' : 'Channel enabled')}><i className={`bi ${channel.is_enabled ? 'bi-bell-fill' : 'bi-bell-slash'}`} /></button>
                          <button className="btn btn-icon btn-admin-outline" title="Delete" aria-label="Delete" onClick={() => void channelAction(() => adminApi(`/alert-channels/${channel.id}`, { method: 'DELETE' }), 'Channel deleted')}><i className="bi bi-trash" /></button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Add / edit monitor */}
      <AdminModal
        visible={modalOpen}
        title={editItem ? 'Edit monitor' : 'Add monitor'}
        onClose={() => setModalOpen(false)}
        footer={<div className="d-flex gap-2"><button className="btn btn-sm btn-admin-outline" onClick={() => setModalOpen(false)}>Cancel</button><button className="btn btn-sm btn-admin-primary" onClick={() => void save()} disabled={saving}>{saving ? 'Saving…' : editItem ? 'Save changes' : 'Add monitor'}</button></div>}
      >
        <div className="form-group">
          <label className="form-label" htmlFor="monitor-type">What to watch</label>
          <select id="monitor-type" className="form-select" value={form.type} disabled={Boolean(editItem)} onChange={e => setForm({ ...EMPTY_FORM, name: form.name, type: e.target.value as MonitorType })}>
            {Object.entries(types).map(([key, value]) => <option key={key} value={key}>{value.label}</option>)}
          </select>
          <p className="form-hint">{help.about}</p>
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="monitor-name">Name</label>
          <input id="monitor-name" className="form-input" value={form.name} onChange={e => setField('name', e.target.value)} placeholder="Shown in alerts" />
        </div>
        {form.type !== 'heartbeat' && (
          <div className="form-group">
            <label className="form-label" htmlFor="monitor-target">{help.target}</label>
            <input id="monitor-target" className="form-input" style={{ fontFamily: 'var(--font-mono)' }} value={form.target} onChange={e => setField('target', e.target.value)} placeholder={help.placeholder} />
          </div>
        )}
        <div className="form-row">
          <div className="form-group">
            <label className="form-label" htmlFor="monitor-interval">{form.type === 'heartbeat' ? 'Job runs every (minutes)' : 'Check every (minutes)'}</label>
            <input id="monitor-interval" className="form-input" inputMode="numeric" value={form.interval_minutes} onChange={e => setField('interval_minutes', e.target.value)} placeholder={spec ? String(spec.defaultInterval) : ''} />
            {spec && <p className="form-hint">Minimum {spec.minInterval}.</p>}
          </div>
          {(form.type === 'ssl_expiry' || form.type === 'domain_expiry') && (
            <div className="form-group">
              <label className="form-label" htmlFor="monitor-warn">Warn this many days before expiry</label>
              <input id="monitor-warn" className="form-input" inputMode="numeric" value={form.warn_days} onChange={e => setField('warn_days', e.target.value)} placeholder={form.type === 'ssl_expiry' ? '14' : '30'} />
            </div>
          )}
          {form.type === 'heartbeat' && (
            <div className="form-group">
              <label className="form-label" htmlFor="monitor-grace">Grace period (minutes)</label>
              <input id="monitor-grace" className="form-input" inputMode="numeric" value={form.grace_minutes} onChange={e => setField('grace_minutes', e.target.value)} placeholder="5" />
              <p className="form-hint">How late a ping may be before the alert.</p>
            </div>
          )}
          {(form.type === 'http' || form.type === 'tcp') && (
            <div className="form-group">
              <label className="form-label" htmlFor="monitor-timeout">Timeout (seconds)</label>
              <input id="monitor-timeout" className="form-input" inputMode="numeric" value={form.timeout_seconds} onChange={e => setField('timeout_seconds', e.target.value)} placeholder={form.type === 'http' ? '10' : '5'} />
            </div>
          )}
        </div>
        {form.type === 'dns_record' && (
          <div className="form-row">
            <div className="form-group">
              <label className="form-label" htmlFor="monitor-record-type">Record type</label>
              <select id="monitor-record-type" className="form-select" value={form.record_type} onChange={e => setField('record_type', e.target.value)}>
                {['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'].map(type => <option key={type} value={type}>{type}</option>)}
              </select>
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="monitor-expected">Expected value (optional)</label>
              <input id="monitor-expected" className="form-input" value={form.expected} onChange={e => setField('expected', e.target.value)} placeholder="Leave empty to use the current value" />
              <p className="form-hint">Separate several values with commas.</p>
            </div>
          </div>
        )}
        {form.type === 'http' && (
          <div className="form-row">
            <div className="form-group">
              <label className="form-label" htmlFor="monitor-status">Expected status (optional)</label>
              <input id="monitor-status" className="form-input" inputMode="numeric" value={form.expected_status} onChange={e => setField('expected_status', e.target.value)} placeholder="Any 2xx or 3xx" />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="monitor-keyword">Page must contain (optional)</label>
              <input id="monitor-keyword" className="form-input" value={form.keyword} onChange={e => setField('keyword', e.target.value)} placeholder="A word from the page" />
            </div>
          </div>
        )}
      </AdminModal>

      {/* Heartbeat ping URL */}
      <AdminModal visible={Boolean(pingFor)} title="Ping URL" onClose={() => setPingFor(null)} footer={<button className="btn btn-sm btn-admin-primary" onClick={() => setPingFor(null)}>Done</button>}>
        {pingFor && (
          <>
            <p style={{ fontSize: '0.88rem', marginBottom: 12 }}>Call this URL at the end of the job. If no call arrives in time, &quot;{pingFor.name}&quot; goes down and an alert is sent.</p>
            <div className="form-group">
              <label className="form-label" htmlFor="ping-url">URL</label>
              <input id="ping-url" className="form-input" readOnly style={{ fontFamily: 'var(--font-mono)' }} value={pingUrl(pingFor)} onFocus={e => e.target.select()} />
            </div>
            <div className="form-group">
              <label className="form-label" htmlFor="ping-cron">Crontab example</label>
              <textarea id="ping-cron" className="form-textarea" readOnly rows={3} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }} value={`0 3 * * * /usr/local/bin/backup.sh && curl -fsS -m 10 --retry 3 ${pingUrl(pingFor)} > /dev/null`} onFocus={e => e.target.select()} />
              <p className="form-hint">The ping is sent only when the job exits successfully. Treat the URL as a secret.</p>
            </div>
          </>
        )}
      </AdminModal>

      {/* History */}
      <AdminModal visible={Boolean(history)} title={history ? `History: ${history.monitor.name}` : 'History'} onClose={() => setHistory(null)} footer={<button className="btn btn-sm btn-admin-primary" onClick={() => setHistory(null)}>Close</button>}>
        {history && (history.events.length === 0
          ? <p style={{ fontSize: '0.88rem' }}>No status changes recorded yet.</p>
          : <table className="admin-table"><thead><tr><th>When</th><th>Status</th><th>Message</th></tr></thead><tbody>
              {history.events.map(event => (
                <tr key={event.id}>
                  <td style={{ fontSize: '0.78rem', whiteSpace: 'nowrap' }}>{formatTime(event.created_at)}</td>
                  <td><span className={`badge-admin ${STATUS_BADGE[event.status]?.className || ''}`}>{STATUS_BADGE[event.status]?.label || event.status}</span></td>
                  <td style={{ fontSize: '0.82rem' }}>{event.message}</td>
                </tr>
              ))}
            </tbody></table>)}
      </AdminModal>

      {/* Delete */}
      <AdminModal
        visible={Boolean(deleting)}
        title="Delete monitor"
        onClose={() => setDeleting(null)}
        footer={<div className="d-flex gap-2"><button className="btn btn-sm btn-admin-outline" onClick={() => setDeleting(null)}>Cancel</button><button className="btn btn-sm btn-admin-danger" onClick={() => { const target = deleting; setDeleting(null); if (target) void act(target, () => adminApi(`/monitors/${target.id}`, { method: 'DELETE' }), 'Monitor deleted'); }}>Delete</button></div>}
      >
        <p style={{ fontSize: '0.88rem' }}>Delete &quot;{deleting?.name}&quot; and its history? This cannot be undone.</p>
      </AdminModal>

      {/* Add channel */}
      <AdminModal
        visible={channelModal}
        title="Add alert channel"
        onClose={() => setChannelModal(false)}
        footer={<div className="d-flex gap-2"><button className="btn btn-sm btn-admin-outline" onClick={() => setChannelModal(false)}>Cancel</button><button className="btn btn-sm btn-admin-primary" onClick={() => void saveChannel()}>Add channel</button></div>}
      >
        <div className="form-group">
          <label className="form-label" htmlFor="channel-type">Type</label>
          <select id="channel-type" className="form-select" value={channelForm.type} onChange={e => setChannelForm(prev => ({ ...prev, type: e.target.value as Channel['type'], target: '' }))}>
            <option value="webhook">Webhook (JSON POST)</option>
            <option value="slack">Slack-style webhook (Slack, Mattermost, Rocket.Chat)</option>
            <option value="email">Email</option>
          </select>
          {channelForm.type === 'email' && !emailConfigured && <p className="form-error">Email is not configured on this server. Set ALERT_SMTP_HOST in the backend environment first.</p>}
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="channel-name">Name</label>
          <input id="channel-name" className="form-input" value={channelForm.name} onChange={e => setChannelForm(prev => ({ ...prev, name: e.target.value }))} placeholder="Ops channel" />
        </div>
        <div className="form-group">
          <label className="form-label" htmlFor="channel-target">{channelForm.type === 'email' ? 'Email address' : 'Webhook URL'}</label>
          <input id="channel-target" className="form-input" value={channelForm.target} onChange={e => setChannelForm(prev => ({ ...prev, target: e.target.value }))} placeholder={channelForm.type === 'email' ? 'ops@example.com' : 'https://hooks.example.com/…'} />
        </div>
      </AdminModal>
    </>
  );
}
