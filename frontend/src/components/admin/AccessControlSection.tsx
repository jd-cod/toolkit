'use client';
import { useState, useEffect } from 'react';
import { adminApi, errorMessage } from './adminUtils';
import { useToast } from './AdminToast';

export default function AccessControlSection() {
  const { toast } = useToast();
  const [settings, setSettings] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    adminApi<Record<string, string>>('/settings').then(setSettings).catch((e: unknown) => toast('Failed to load: ' + errorMessage(e), 'error'));
  }, [toast]);

  const update = (k: string, v: string) => setSettings(p => ({ ...p, [k]: v }));
  const enabled = settings.invite_only_enabled === '1';

  async function save() {
    setSaving(true);
    try {
      await adminApi('/settings', { method: 'PUT', body: {
        invite_only_enabled: settings.invite_only_enabled || '0',
        invite_only_title: settings.invite_only_title || '',
        invite_only_message: settings.invite_only_message || '',
        invite_only_whitelist_ips: settings.invite_only_whitelist_ips || '',
      }});
      toast('Access control settings saved!');
    } catch (e) { toast('Failed: ' + errorMessage(e), 'error'); }
    setSaving(false);
  }

  return (
    <div className="admin-card">
      <div className="admin-card-header">
        <h3 className="admin-card-title"><i className="bi bi-shield-lock-fill" style={{ marginRight: 8, opacity: 0.6 }} />Invite-Only Access</h3>
        <button className="btn btn-sm btn-admin-primary" onClick={save} disabled={saving}>
          <i className={`bi ${saving ? 'bi-hourglass-split' : 'bi-check-lg'}`} /> {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
      <div className="admin-card-body">
        <div style={{ padding: '14px 18px', borderRadius: 10, marginBottom: 24, display: 'flex', alignItems: 'center', gap: 12, background: enabled ? 'rgba(239,68,68,0.08)' : 'rgba(16,185,129,0.08)', border: `1px solid ${enabled ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)'}` }}>
          <i className={`bi ${enabled ? 'bi-shield-lock-fill' : 'bi-globe2'}`} style={{ fontSize: '1.3rem', color: enabled ? 'var(--accent-red)' : 'var(--accent-green)' }} />
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.9rem', color: enabled ? 'var(--accent-red)' : 'var(--accent-green)' }}>{enabled ? 'Invite-Only Mode Active' : 'Site is Public'}</div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{enabled ? 'Only whitelisted IPs and admins can access.' : 'All visitors can access the site freely.'}</div>
          </div>
        </div>

        <div className="d-flex align-center justify-between mb-3">
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>Enable Invite-Only Mode</div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>When enabled, visitors see an animated gate page.</div>
          </div>
          <label className="toggle-switch">
            <input type="checkbox" checked={enabled} onChange={e => update('invite_only_enabled', e.target.checked ? '1' : '0')} />
            <span className="toggle-slider" />
          </label>
        </div>

        <hr className="form-divider" />
        <h4 style={{ marginBottom: 16, fontSize: '0.95rem', fontWeight: 600 }}>Gate Page Customization</h4>
        <div className="form-group">
          <label className="form-label">Gate Page Title</label>
          <input className="form-input" value={settings.invite_only_title || ''} onChange={e => update('invite_only_title', e.target.value)} placeholder="e.g. Invite Only" />
        </div>
        <div className="form-group">
          <label className="form-label">Gate Page Message</label>
          <textarea className="form-textarea" value={settings.invite_only_message || ''} onChange={e => update('invite_only_message', e.target.value)} rows={3} placeholder="e.g. This site is currently invite-only..." />
        </div>

        <hr className="form-divider" />
        <h4 style={{ marginBottom: 16, fontSize: '0.95rem', fontWeight: 600 }}><i className="bi bi-hdd-network" style={{ marginRight: 6, opacity: 0.6 }} />IP Whitelist</h4>
        <div className="form-group">
          <label className="form-label">Whitelisted IPs / CIDRs</label>
          <textarea className="form-textarea" value={settings.invite_only_whitelist_ips || ''} onChange={e => update('invite_only_whitelist_ips', e.target.value)} rows={5} placeholder={"One IP or CIDR per line, e.g.\n203.0.113.50\n10.0.0.0/8\n192.168.1.0/24"} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }} />
          <p className="form-hint">IPs listed here bypass the invite-only gate. Supports exact IPs and CIDR notation. Admins always bypass.</p>
        </div>

        <hr className="form-divider" />
        <h4 style={{ marginBottom: 16, fontSize: '0.95rem', fontWeight: 600 }}>Bypass Rules</h4>
        <div className="bypass-rules">
          {['Admin users — Logged-in admins always bypass the gate', 'Whitelisted IPs — IPs and CIDRs listed above bypass the gate', 'API routes — All /api/* endpoints remain accessible', 'Admin panel — /admin is always accessible', 'Static assets — CSS, JS, fonts, and images are never blocked'].map((rule, i) => (
            <div key={i} className="bypass-rule"><i className="bi bi-check-circle-fill" /><span>{rule}</span></div>
          ))}
        </div>
      </div>
    </div>
  );
}
