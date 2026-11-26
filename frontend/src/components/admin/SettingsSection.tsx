'use client';
import { useState, useEffect } from 'react';
import { adminApi, errorMessage } from './adminUtils';
import { useToast } from './AdminToast';
import AppearanceFields from './AppearanceFields';
import { PALETTE_FIELDS, normalizeHex } from '@/lib/appearance';

export default function SettingsSection() {
  const { toast } = useToast();
  const [settings, setSettings] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    adminApi<Record<string, string>>('/settings').then(setSettings).catch(e => toast('Failed to load settings: ' + errorMessage(e), 'error'));
  }, [toast]);

  const update = (key: string, value: string) => setSettings(prev => ({ ...prev, [key]: value }));

  async function save() {
    const invalid = PALETTE_FIELDS.some(field => ['', '_light'].some(suffix => settings[field.key + suffix] && !normalizeHex(settings[field.key + suffix])));
    if (invalid) { toast('Correct the invalid appearance colors before saving.', 'error'); return; }
    setSaving(true);
    try {
      await adminApi('/settings', { method: 'PUT', body: settings });
      toast('Settings saved successfully!');
    } catch (e) {
      toast('Failed to save: ' + errorMessage(e), 'error');
    }
    setSaving(false);
  }

  return (
    <div className="admin-card">
      <div className="admin-card-header">
        <h3 className="admin-card-title">General Settings</h3>
        <button className="btn btn-sm btn-admin-primary" onClick={save} disabled={saving}>
          <i className={`bi ${saving ? 'bi-hourglass-split' : 'bi-check-lg'}`} /> {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
      <div className="admin-card-body">
        <div className="form-group">
          <label className="form-label">Site Title</label>
          <input className="form-input" value={settings.site_title || ''} onChange={e => update('site_title', e.target.value)} placeholder="My Awesome Site" />
        </div>
        <div className="form-group">
          <label className="form-label">Site Description</label>
          <textarea className="form-textarea" value={settings.site_description || ''} onChange={e => update('site_description', e.target.value)} rows={2} placeholder="Short description" />
        </div>
        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Site Tagline (Badge)</label>
            <input className="form-input" value={settings.site_tagline || ''} onChange={e => update('site_tagline', e.target.value)} placeholder="e.g. Network & Security Suite" />
          </div>
          <div className="form-group">
            <label className="form-label">Version Badge Text</label>
            <input className="form-input" value={settings.version_badge || ''} onChange={e => update('version_badge', e.target.value)} placeholder="e.g. Self-Hosted" />
          </div>
        </div>

        <hr className="form-divider" />

        <div className="form-group">
          <label className="form-label">Hero Title (Home Page)</label>
          <input className="form-input" value={settings.home_hero_title || ''} onChange={e => update('home_hero_title', e.target.value)} placeholder="Main heading on home page" />
        </div>
        <div className="form-group">
          <label className="form-label">Hero Subtitle (Home Page)</label>
          <textarea className="form-textarea" value={settings.home_hero_subtitle || ''} onChange={e => update('home_hero_subtitle', e.target.value)} rows={2} placeholder="Subtext on home page" />
        </div>

        <hr className="form-divider" />

        <div className="form-group">
          <label className="form-label">Meta Description (SEO)</label>
          <textarea className="form-textarea" value={settings.meta_description || ''} onChange={e => update('meta_description', e.target.value)} rows={2} placeholder="Default fallback SEO meta description for homepage and unconfigured pages" />
          <p className="form-hint">Used for the homepage meta description if not overridden, and as a fallback description.</p>
        </div>
        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Google Search Console Verification Code</label>
            <input className="form-input" value={settings.seo_google_verification || ''} onChange={e => update('seo_google_verification', e.target.value)} placeholder="e.g. google-site-verification token or code" />
            <p className="form-hint">Optional meta tag verification token for Google Search Console.</p>
          </div>
          <div className="form-group">
            <label className="form-label">Bing Webmaster Verification Code</label>
            <input className="form-input" value={settings.seo_bing_verification || ''} onChange={e => update('seo_bing_verification', e.target.value)} placeholder="e.g. msvalidate.01 token" />
            <p className="form-hint">Optional meta tag verification token for Bing Webmaster Tools.</p>
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Default Social Preview Image Path (OG / Twitter)</label>
          <input className="form-input" value={settings.seo_social_image || ''} onChange={e => update('seo_social_image', e.target.value)} placeholder="/og-image.png" />
          <p className="form-hint">Relative path to a 1200x630 social preview image (defaults to /og-image.png).</p>
        </div>
        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Brand Icon (Bootstrap Icons class)</label>
            <input className="form-input" value={settings.brand_icon || ''} onChange={e => update('brand_icon', e.target.value)} placeholder="e.g. bi-shield-lock-fill" />
            <p className="form-hint">Browse icons at <a href="https://icons.getbootstrap.com" target="_blank" rel="noopener">icons.getbootstrap.com</a></p>
          </div>
          <div className="form-group">
            <label className="form-label">Favicon Emoji</label>
            <input className="form-input" value={settings.favicon_emoji || ''} onChange={e => update('favicon_emoji', e.target.value)} placeholder="e.g. 🛡️" style={{ fontSize: '1.2rem' }} />
          </div>
        </div>

        <hr className="form-divider" />
        <h4 style={{ marginBottom: 16, fontSize: '0.95rem', fontWeight: 600 }}>Maintenance Mode</h4>

        <div className="d-flex align-center justify-between mb-3">
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>Enable Maintenance Mode</div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Shows a maintenance banner to all visitors</div>
          </div>
          <label className="toggle-switch">
            <input type="checkbox" checked={settings.maintenance_mode === '1'} onChange={e => update('maintenance_mode', e.target.checked ? '1' : '0')} />
            <span className="toggle-slider" />
          </label>
        </div>
        <div className="form-group">
          <label className="form-label">Maintenance Message</label>
          <textarea className="form-textarea" value={settings.maintenance_message || ''} onChange={e => update('maintenance_message', e.target.value)} rows={2} placeholder="We are currently under maintenance..." />
        </div>

        <hr className="form-divider" />
        <h4 style={{ marginBottom: 16, fontSize: '0.95rem', fontWeight: 600 }}>Advanced</h4>
        <AppearanceFields settings={settings} update={update} />
        <hr className="form-divider" />
        <div className="form-group">
          <label className="form-label">Custom CSS</label>
          <textarea className="form-textarea" value={settings.custom_css || ''} onChange={e => update('custom_css', e.target.value)} rows={5} placeholder="/* Your custom CSS rules */" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }} />
          <p className="form-hint">Add custom CSS styles that will be injected into the public site.</p>
        </div>
        <div className="form-group">
          <label className="form-label">Analytics / Tracking Script</label>
          <textarea className="form-textarea" value={settings.analytics_script || ''} onChange={e => update('analytics_script', e.target.value)} rows={3} placeholder="<script>...</script>" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }} />
          <p className="form-hint">Paste your Google Analytics, Plausible, or other tracking script here.</p>
        </div>
      </div>
    </div>
  );
}
