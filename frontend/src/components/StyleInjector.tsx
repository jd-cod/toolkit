import { paletteCss } from '@/lib/appearance';

export default function StyleInjector({ settings }: { settings: Record<string, string> }) {
  return <style id="signal-site-appearance">{paletteCss(settings) + '\n' + (settings.custom_css || '')}</style>;
}
