'use client';

import { PALETTE_FIELDS, actionTextColor, normalizeHex } from '@/lib/appearance';

export default function AppearanceFields({ settings, update }: { settings: Record<string, string>; update: (key: string, value: string) => void }) {
  return <section aria-labelledby="appearance-heading">
    <h4 id="appearance-heading">Public site appearance</h4>
    <p className="form-hint">Customize each theme independently. Leave a value empty to use the Signal default.</p>
    <div className="appearance-theme-grid">
      {(['dark', 'light'] as const).map(theme => {
        const value = (key: string) => normalizeHex(settings[key + (theme === 'light' ? '_light' : '')]) || PALETTE_FIELDS.find(field => field.key === key)![theme];
        return <fieldset key={theme} className="appearance-theme-fields"><legend>{theme === 'dark' ? 'Dark theme' : 'Light theme'}</legend>
          {PALETTE_FIELDS.map(field => {
            const key = field.key + (theme === 'light' ? '_light' : '');
            const invalid = Boolean(settings[key] && !normalizeHex(settings[key]));
            return <div className="form-group" key={key}><label className="form-label" htmlFor={key}>{field.label}</label><div className="appearance-color-row"><input type="color" aria-label={`${theme} ${field.label} color picker`} value={normalizeHex(settings[key]) || field[theme]} onChange={event => update(key, event.target.value)} /><input id={key} className="form-input" aria-label={`${theme} ${field.label}`} value={settings[key] || ''} placeholder={field[theme]} onChange={event => update(key, event.target.value)} aria-invalid={invalid} /></div>{invalid && <p className="form-hint" role="alert">Enter a 3- or 6-digit hex color, such as #65e2ba.</p>}</div>;
          })}
          <div className="appearance-preview" style={{ background: value('palette_bg_primary'), color: value('palette_text_primary') }}><div style={{ background: value('palette_bg_card') }}><strong>Workspace preview</strong><p>Your tools, in your colors.</p><span style={{ background: value('palette_primary'), color: actionTextColor(value('palette_primary')) }}>Primary action</span></div></div>
          <button type="button" className="btn btn-sm btn-admin-outline" onClick={() => PALETTE_FIELDS.forEach(field => update(field.key + (theme === 'light' ? '_light' : ''), ''))}>Reset {theme} colors</button>
        </fieldset>;
      })}
    </div>
  </section>;
}
