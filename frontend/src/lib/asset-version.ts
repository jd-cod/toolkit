// Version of the classic scripts under public/js, set at build time in
// next.config.ts. Use `versioned()` for every URL to one of them.
export const ASSET_VERSION = process.env.NEXT_PUBLIC_ASSET_VERSION || '0';

export function versioned(src: string) {
  return `${src}?v=${ASSET_VERSION}`;
}

declare global {
  interface Window {
    __ASSET_VERSION__?: string;
  }
}

// The classic scripts start workers and need the same version for them.
export function publishAssetVersion() {
  if (typeof window !== 'undefined') window.__ASSET_VERSION__ = ASSET_VERSION;
}
