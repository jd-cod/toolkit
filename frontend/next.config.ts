import type { NextConfig } from "next";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

// The scripts under public/js are cached for 30 days, so every URL to one
// carries `?v=` and this value. It is a hash of their contents: it changes
// when, and only when, one of them changes.
function publicScriptVersion() {
  const dir = path.join(process.cwd(), "public", "js");
  const hash = createHash("sha256");
  try {
    for (const name of readdirSync(dir).filter((file) => file.endsWith(".js")).sort()) {
      hash.update(name).update("\0").update(readFileSync(path.join(dir, name))).update("\0");
    }
  } catch {
    return "0";
  }
  return hash.digest("hex").slice(0, 12);
}

const apiBase = (
  process.env.BACKEND_API_URL ??
  process.env.NEXT_PUBLIC_API_URL ??
  "http://localhost:4000/api"
).replace(/\/+$/, "");

const nextConfig: NextConfig = {
  env: {
    NEXT_PUBLIC_ASSET_VERSION: process.env.NEXT_PUBLIC_ASSET_VERSION || publicScriptVersion(),
  },
  allowedDevOrigins: [
    "192.168.0.12",
    ...(process.env.ALLOWED_DEV_ORIGINS
      ? process.env.ALLOWED_DEV_ORIGINS.split(",")
      : []),
  ],
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${apiBase}/:path*`,
      },
      {
        source: "/ingest",
        destination: `${apiBase}/ingest`,
      },
    ];
  },
  async redirects() {
    return [
      {
        source: "/password",
        destination: "/password-generator",
        permanent: true,
      },
    ];
  },
  async headers() {
    return [
      {
        source: "/data/:path*",
        headers: [
          {
            key: "Cache-Control",
            value: "public, max-age=604800, s-maxage=604800, stale-while-revalidate=86400",
          },
        ],
      },
      {
        source: "/data/geoip-meta.json",
        headers: [
          {
            key: "Cache-Control",
            value: "public, max-age=0, must-revalidate",
          },
        ],
      },
      {
        source: "/js/:path*",
        headers: [
          {
            key: "Cache-Control",
            value: "public, max-age=2592000, s-maxage=2592000, stale-while-revalidate=86400",
          },
        ],
      },
      {
        source: "/samples/:path*",
        headers: [
          {
            key: "Cache-Control",
            value: "public, max-age=2592000, s-maxage=2592000, immutable",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
