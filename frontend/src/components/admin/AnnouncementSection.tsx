'use client';
import { useState, useEffect } from 'react';
import { adminApi, errorMessage } from './adminUtils';
import { useToast } from './AdminToast';

export default function AnnouncementSection() {
  const { toast } = useToast();
  const [settings, setSettings] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    adminApi<Record<string, string>>('/settings').then(setSettings).catch(e => toast('Failed to load: ' + errorMessage(e), 'error'));
  }, [toast]);

  const update = (k: string, v: string) => setSettings(p => ({ ...p, [k]: v }));

  async function save() {
    setSaving(true);
    try {
      await adminApi('/settings', { method: 'PUT', body: {
        announcement_enabled: settings.announcement_enabled || '0',
        announcement_text: settings.announcement_text || '',
        announcement_type: settings.announcement_type || 'info',
        announcement_dismissible: settings.announcement_dismissible || '1',
      }});
      toast('Announcement settings saved!');
    } catch (e) { toast('Failed: ' + errorMessage(e), 'error'); }
    setSaving(false);
  }

  const previewClass = `ann-preview ann-preview-${settings.announcement_type || 'info'}`;

  return (
    <div className="admin-card">
      <div className="admin-card-header">
        <h3 className="admin-card-title">Announcement Bar</h3>
        <button className="btn btn-sm btn-admin-primary" onClick={save} disabled={saving}>
          <i className={`bi ${saving ? 'bi-hourglass-split' : 'bi-check-lg'}`} /> {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
      <div className="admin-card-body">
        <div className="d-flex align-center justify-between mb-3">
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>Enable Announcement Bar</div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Shows a banner at the top of the site</div>
          </div>
          <label className="toggle-switch">
            <input type="checkbox" checked={settings.announcement_enabled === '1'} onChange={e => update('announcement_enabled', e.target.checked ? '1' : '0')} />
            <span className="toggle-slider" />
          </label>
        </div>
        <div className="form-group">
          <label className="form-label">Announcement Text</label>
          <input className="form-input" value={settings.announcement_text || ''} onChange={e => update('announcement_text', e.target.value)} placeholder="e.g. 🎉 New IP Intelligence tool launched!" />
        </div>
        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Type / Color</label>
            <select className="form-select" value={settings.announcement_type || 'info'} onChange={e => update('announcement_type', e.target.value)}>
              <option value="info">Info (Purple)</option>
              <option value="success">Success (Green)</option>
              <option value="warning">Warning (Amber)</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Dismissible</label>
            <select className="form-select" value={settings.announcement_dismissible || '1'} onChange={e => update('announcement_dismissible', e.target.value)}>
              <option value="1">Yes — users can close it</option>
              <option value="0">No — always visible</option>
            </select>
          </div>
        </div>
        {settings.announcement_text && (
          <>
            <label className="form-label" style={{ marginTop: 8 }}>Preview</label>
            <div className={previewClass}>{settings.announcement_text}</div>
          </>
        )}
      </div>
    </div>
  );
}
