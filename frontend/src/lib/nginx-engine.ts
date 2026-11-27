'use client';

import { loadGeoIP } from './geoip';
import { publishAssetVersion, versioned } from './asset-version';

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
  publishAssetVersion();
  for (const name of [
    'stream-line-splitter',
    'columnar-storage',
    'log-parser',
    'request-paths',
    'bot-detector',
    'traffic-classifier',
    'analyzer',
    'dashboard',
    'share',
    'report',
  ]) await loadScript(versioned(`/js/${name}.js`));
}

export async function loadNginxInput() {
  await loadNginxEngine();
  await loadScript(versioned('/js/nginx-init.js'));
}

export function disposeNginxDashboard() {
  const runtime = window as Window & { Dashboard?: { dispose?: () => void } };
  runtime.Dashboard?.dispose?.();
}
