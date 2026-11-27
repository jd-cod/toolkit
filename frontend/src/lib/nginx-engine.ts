'use client';

import { loadGeoIP } from './geoip';

declare global {
  interface Window {
    initNginxPage?: () => (() => void) | undefined;
  }
}

// Classic scripts declare global consts. Removing their tags does not unload them:
// load each dependency once per document, then bind fresh input DOM on each visit.
const scriptLoads = new Map<string, Promise<void>>();
function loadScript(src: string) {
  const existing = scriptLoads.get(src);
  if (existing) return existing;
  const promise = new Promise<void>((resolve, reject) => {
    const script = document.createElement('script');
    script.src = src;
    script.onload = () => resolve();
    script.onerror = () => {
      script.remove();
      scriptLoads.delete(src);
      reject(new Error(`Failed to load: ${src}`));
    };
    document.body.appendChild(script);
  });
  scriptLoads.set(src, promise);
  return promise;
}

export async function loadNginxEngine() {
  await loadScript('https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js');
  if (!await loadGeoIP()) throw new Error('The GeoIP engine could not load.');
  for (const src of [
    '/js/stream-line-splitter.js?v=6.55',
    '/js/columnar-storage.js?v=6.55',
    '/js/log-parser.js?v=6.55',
    '/js/request-paths.js?v=6.55',
    '/js/bot-detector.js?v=6.55',
    '/js/traffic-classifier.js?v=6.55',
    '/js/analyzer.js?v=6.55',
    '/js/dashboard.js?v=6.55',
    '/js/share.js?v=6.55',
    '/js/report.js?v=6.55',
  ]) await loadScript(src);
}

export async function loadNginxInput() {
  await loadNginxEngine();
  await loadScript('/js/nginx-init.js?v=6.55');
}

export function disposeNginxDashboard() {
  const runtime = window as Window & { Dashboard?: { dispose?: () => void } };
  runtime.Dashboard?.dispose?.();
}
