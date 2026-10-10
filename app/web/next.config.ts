import type { NextConfig } from "next";

// Static export so `npm run build` emits a fully static bundle into
// src/security_lakehouse/web/dist/ — Python wheel ships it, no Node in prod.
// basePath '/console' matches the Python server route.
//
// Next.js requires output inside the web workspace. The build script copies
// the completed static export into the Python package after Next succeeds.
// Keep development chunks in .next so their runtime imports resolve locally.
const isDev = process.env.NODE_ENV === "development";

const config: NextConfig = {
  output: "export",
  basePath: "/console",
  assetPrefix: "/console",
  trailingSlash: true,
  distDir: isDev ? ".next" : "out",
  cleanDistDir: true,
  images: { unoptimized: true },
  reactStrictMode: true,
  typescript: { ignoreBuildErrors: false },
};

export default config;
