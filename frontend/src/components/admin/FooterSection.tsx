'use client';
import { useState, useEffect } from 'react';
import { adminApi, errorMessage } from './adminUtils';
import { useToast } from './AdminToast';

export default function FooterSection() {
  const { toast } = useToast();
  const [footer, setFooter] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    adminApi<Record<string, string>>('/footer').then(setFooter).catch(e => toast('Failed to load footer: ' + errorMessage(e), 'error'));
  }, [toast]);

  const update = (k: string, v: string) => setFooter(p => ({ ...p, [k]: v }));

  async function save() {
    setSaving(true);
    try {
      await adminApi('/footer', { method: 'PUT', body: footer });
      toast('Footer settings saved!');
    } catch (e) { toast('Failed: ' + errorMessage(e), 'error'); }
    setSaving(false);
  }

  return (
    <div className="admin-card">
      <div className="admin-card-header">
        <h3 className="admin-card-title">Footer Settings</h3>
        <button className="btn btn-sm btn-admin-primary" onClick={save} disabled={saving}>
          <i className={`bi ${saving ? 'bi-hourglass-split' : 'bi-check-lg'}`} /> {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
      <div className="admin-card-body">
        <div className="form-group">
          <label className="form-label">Footer Text</label>
          <textarea className="form-textarea" value={footer.footer_text || ''} onChange={e => update('footer_text', e.target.value)} rows={2} placeholder="Main footer text" />
        </div>
        <div className="form-group">
          <label className="form-label">Copyright Text</label>
          <input className="form-input" value={footer.copyright_text || ''} onChange={e => update('copyright_text', e.target.value)} placeholder="e.g. © 2025 My Company. All rights reserved." />
        </div>
        <hr className="form-divider" />
        <h4 style={{ marginBottom: 16, fontSize: '0.95rem', fontWeight: 600 }}>Social Links</h4>
        <div className="form-row">
          <div className="form-group">
            <label className="form-label"><i className="bi bi-github" /> GitHub URL</label>
            <input className="form-input" value={footer.social_github || ''} onChange={e => update('social_github', e.target.value)} placeholder="https://github.com/..." />
          </div>
          <div className="form-group">
            <label className="form-label"><i className="bi bi-twitter-x" /> Twitter/X URL</label>
            <input className="form-input" value={footer.social_twitter || ''} onChange={e => update('social_twitter', e.target.value)} placeholder="https://x.com/..." />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label"><i className="bi bi-linkedin" /> LinkedIn URL</label>
          <input className="form-input" value={footer.social_linkedin || ''} onChange={e => update('social_linkedin', e.target.value)} placeholder="https://linkedin.com/in/..." />
        </div>
        <hr className="form-divider" />
        <div className="d-flex align-center justify-between">
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>Show Footer Links</div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Display page links in the footer</div>
          </div>
          <label className="toggle-switch">
            <input type="checkbox" checked={footer.footer_links_enabled !== '0'} onChange={e => update('footer_links_enabled', e.target.checked ? '1' : '0')} />
            <span className="toggle-slider" />
          </label>
        </div>
      </div>
    </div>
  );
}
