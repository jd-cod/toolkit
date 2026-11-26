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
function loadScript(src: string, integrity?: string) {
  const existing = scriptLoads.get(src);
  if (existing) return existing;
  const promise = new Promise<void>((resolve, reject) => {
    const script = document.createElement('script');
    script.src = src;
    if (integrity) {
      // Third-party CDN file: the browser refuses it if the content changed.
      script.integrity = integrity;
      script.crossOrigin = 'anonymous';
    }
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
  await loadScript(
    'https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js',
    'sha384-vsrfeLOOY6KuIYKDlmVH5UiBmgIdB1oEf7p01YgWHuqmOHfZr374+odEv96n9tNC',
  );
  if (!await loadGeoIP()) throw new Error('The GeoIP engine could not load.');
  for (const src of [
    '/js/stream-line-splitter.js?v=6.52',
    '/js/columnar-storage.js?v=6.52',
    '/js/log-parser.js?v=6.52',
    '/js/bot-detector.js?v=6.52',
    '/js/analyzer.js?v=6.52',
    '/js/dashboard.js?v=6.52',
    '/js/share.js?v=6.52',
    '/js/report.js?v=6.53',
  ]) await loadScript(src);
}

export async function loadNginxInput() {
  await loadNginxEngine();
  await loadScript('/js/nginx-init.js?v=6.52');
}

export function disposeNginxDashboard() {
  const runtime = window as Window & { Dashboard?: { dispose?: () => void } };
  runtime.Dashboard?.dispose?.();
}
