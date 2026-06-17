import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Dev-only: allow opening the console via 127.0.0.1 and the LAN IP, not just
  // localhost. Without this, Next 16 blocks cross-origin dev resources (HMR and
  // chunks), which can render the page blank when it is not opened via localhost.
  allowedDevOrigins: ["127.0.0.1", "10.3.0.164"],
};

export default nextConfig;
