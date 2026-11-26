export const PALETTE_FIELDS = [
  { key: 'palette_primary', token: '--accent-primary', label: 'Primary action', dark: '#65e2ba', light: '#087759' },
  { key: 'palette_secondary', token: '--accent-purple', label: 'Secondary accent', dark: '#b0a0f2', light: '#7350ac' },
  { key: 'palette_bg_primary', token: '--bg-primary', label: 'Page background', dark: '#0b1017', light: '#f5f7fa' },
  { key: 'palette_bg_card', token: '--bg-card', label: 'Panel background', dark: '#111a24', light: '#ffffff' },
  { key: 'palette_text_primary', token: '--text-primary', label: 'Primary text', dark: '#eef3f7', light: '#172c3c' },
  { key: 'palette_accent_green', token: '--accent-green', label: 'Success', dark: '#65e2ba', light: '#087759' },
  { key: 'palette_accent_red', token: '--accent-red', label: 'Risk / error', dark: '#f3898b', light: '#b43848' },
] as const;

export function normalizeHex(value: string | undefined): string | null {
  if (!value || !/^#(?:[\da-f]{3}|[\da-f]{6})$/i.test(value.trim())) return null;
  const hex = value.trim().toLowerCase();
  return hex.length === 4 ? '#' + [...hex.slice(1)].map(char => char + char).join('') : hex;
}

export function actionTextColor(color: string): string {
  const hex = normalizeHex(color) || '#65e2ba';
  const values = [1, 3, 5].map(index => parseInt(hex.slice(index, index + 2), 16) / 255).map(value => value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4);
  const luminance = .2126 * values[0] + .7152 * values[1] + .0722 * values[2];
  return luminance > .179 ? '#000000' : '#ffffff';
}

export function paletteCss(settings: Record<string, string>): string {
  return (['dark', 'light'] as const).map(theme => {
    const declarations = PALETTE_FIELDS.flatMap(field => {
      const value = normalizeHex(settings[field.key + (theme === 'light' ? '_light' : '')]);
      if (!value) return [];
      const rules = [`${field.token}:${value}`];
      if (field.key === 'palette_primary') {
        rules.push(
          `--accent-cyan:${value}`,
          `--signal-on-primary:${actionTextColor(value)}`,
          `--signal-tint:color-mix(in srgb,${value} 12%,transparent)`,
          `--gradient-primary:linear-gradient(${value},${value})`
        );
      }
      if (field.key === 'palette_bg_primary') rules.push(`--bg-secondary:color-mix(in srgb,${value} 92%,var(--text-primary))`, `--bg-input:color-mix(in srgb,${value} 96%,var(--text-primary))`);
      if (field.key === 'palette_bg_card') rules.push(`--bg-card-hover:color-mix(in srgb,${value} 92%,var(--text-primary))`);
      if (field.key === 'palette_text_primary') rules.push(`--text-secondary:color-mix(in srgb,${value} 75%,var(--bg-primary))`, `--text-muted:color-mix(in srgb,${value} 65%,var(--bg-primary))`);
      return rules;
    });
    return `:root[data-theme="${theme}"]:has(.signal-workspace), :root[data-theme="${theme}"] .signal-workspace{${declarations.join(';')}}`;
  }).join('\n');
}
