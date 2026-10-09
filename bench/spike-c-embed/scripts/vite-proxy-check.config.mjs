// Minimal Vite config used only to check that Vite's dev proxy streams SSE from the Rust
// server. It has no imports, so it can live outside ui/ and be run with ui's Vite:
//
//   node ../../ui/node_modules/vite/bin/vite.js --config scripts/vite-proxy-check.config.mjs
//
// Root and cache live under results/raw (git-ignored), so nothing under ui/ is touched.
// The real setup is the `server.proxy` block shown in README.md, merged into ui/vite.config.ts.
import { fileURLToPath } from "node:url";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));

export default {
  root: here("../results/raw/vite-root"),
  cacheDir: here("../results/raw/vite-cache"),
  logLevel: "warn",
  server: {
    host: "127.0.0.1",
    port: 5199,
    strictPort: true,
    proxy: {
      "/api": { target: "http://127.0.0.1:18640" },
    },
  },
};
