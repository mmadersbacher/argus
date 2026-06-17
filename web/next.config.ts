import type { NextConfig } from "next";

// Dev-only: allow opening the console via 127.0.0.1 (and an optional LAN host
// set via ARGUS_DEV_ORIGIN), not just localhost. Without this, Next 16 blocks
// cross-origin dev resources (HMR and chunks), which can render the page blank
// when it is not opened via localhost. No hardcoded personal IP.
const devOrigins = ["127.0.0.1", "localhost"];
if (process.env.ARGUS_DEV_ORIGIN) {
  devOrigins.push(process.env.ARGUS_DEV_ORIGIN);
}

const nextConfig: NextConfig = {
  allowedDevOrigins: devOrigins,
};

export default nextConfig;
