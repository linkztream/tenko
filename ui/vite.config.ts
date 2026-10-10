import { createReadStream } from "node:fs";
import { fileURLToPath } from "node:url";
import { defineConfig, loadEnv, type Plugin } from "vite";
import solid from "vite-plugin-solid";
import { i18n } from "./scripts/vite-plugin-i18n.mjs";

// The contents of dist/ are embedded into the server binary (ADR 0008).
//
// Modes:
//   npm run dev        proxies /api to the Rust server (TENKO_API_URL, default
//                      http://127.0.0.1:8080), including the SSE stream.
//   npm run dev:mock   answers /api in the browser with the msw handlers of
//                      src/api/mock (mode "mock", or VITE_TENKO_MOCK=1 in the
//                      environment); nothing is proxied.
/**
 * Message packs: the keys of lazily loaded areas, by key prefix. They stay out of the core
 * message table of the first page load; a route loads its packs with its chunk through
 * `withPacks` (src/i18n). A key belongs to the first pack whose prefix it starts with.
 */
const MESSAGE_PACKS: Record<string, readonly string[]> = {
  grid: ["grid."],
  // The texts of a move job come from the server as keys under ipam.move.; they belong to the
  // jobs pack, which is listed first because a key belongs to the first pack that matches. Only
  // the three prefixes the job uses: ipam.move.dragging and the rest are texts of the IPAM views.
  // The titles of connector and cluster jobs come from the server as keys too (WP2.9).
  // The title, manual task and step texts of the VLAN provision job come as keys too (WP2.7).
  // The guardrail refusals of network-controller writes show on the steps of those jobs and in
  // the move preview (WP2.8), so they come with the jobs pack rather than the connectors pack.
  jobs: [
    "jobs.",
    "ipam.move.task.",
    "ipam.move.step.",
    "ipam.move.title",
    "connect.job.",
    "cluster.job.",
    "ipam.vlan.job.",
    "ipam.vlan.task.",
    "ipam.vlan.step.",
    "errors.connect.guardrail.",
  ],
  // The adoption policy of a prefix is part of the prefix pane, with its error texts.
  ipam: ["ipam.", "hosts.", "move.", "errors.ipam.adoption."],
  audit: ["audit."],
  dashboard: ["dashboard."],
  import: ["import."],
  // The areas of WP1.9 that only their own lazy routes show.
  setup: ["setup."],
  settings: ["settings."],
  account: ["account."],
  // The updates page, the release notes dialog and the page of a module that is switched off
  // (OPS-24, OPS-25), and the error texts of the update endpoints.
  updates: ["updates.", "errors.update.", "errors.upgrade."],
  // Operator secrets: the secrets page, the reveal dialog (also on the host page) and the
  // error texts of the vault and remote hand-off endpoints (WP2.1).
  secrets: ["secrets.", "errors.vault.", "errors.remote."],
  // Discovery: the proposal inbox and the observations (also on the host page), with the error
  // texts of the proposal and reconciler endpoints (WP2.9).
  discovery: ["discovery.", "errors.ipam.proposal.", "errors.ipam.reconciler."],
  // Connector plugins and instances, with the error texts of the connector endpoints (WP2.9).
  connectors: ["connectors.", "errors.connect."],
  // Cluster nodes and enrolment tokens, with the error texts of the node endpoints (WP2.9).
  nodes: ["nodes.", "errors.cluster."],
  // The topology map (WP2.7).
  topology: ["topology."],
  // The areas of Slice 3, each with the fragment ui/i18n/<language>.d/<area>.xlf of its package:
  // the cluster page, the scans of discovery and the settings sub-pages for access, audit export,
  // the vault keys, backup and language packs. `cluster.job.` is a key of the jobs pack, which
  // is listed above and so wins.
  cluster: ["cluster."],
  scans: ["scans."],
  access: ["access."],
  audit_export: ["audit_export."],
  vault: ["vault."],
  backup: ["backup."],
  languages: ["languages."],
};

export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const mock = mode === "mock" || env.VITE_TENKO_MOCK === "1";
  const testing = process.env.VITEST !== undefined;

  return {
    define: {
      // The switch index.tsx reads; replaced at build time, so production never has it.
      "import.meta.env.VITE_TENKO_MOCK": JSON.stringify(mock && command === "serve" ? "1" : ""),
    },
    plugins: [
      // No hot-reload wrappers under test: vitest cannot resolve their runtime.
      solid({ hot: !testing }),
      // Tests keep every message in the core table, so a view renders without its packs.
      i18n({ packs: testing ? {} : MESSAGE_PACKS }),
      ...(testing ? [nodeConditionsForTests()] : []),
      ...(command === "serve" && mock ? [mockServiceWorker()] : []),
    ],
    resolve: {
      // Messages are compiled to ICU syntax trees at build time, so the browser bundle
      // does not need the message parser. Tests keep it for the compiler's own tests.
      alias: testing
        ? []
        : [
            {
              find: /^@formatjs\/icu-messageformat-parser$/,
              replacement: "@formatjs/icu-messageformat-parser/no-parser.js",
            },
          ],
    },
    server: {
      // Deep links contain FQDNs and IP addresses; Vite's HTML fallback serves
      // index.html for them because it does not treat a dot as a file marker.
      proxy: mock
        ? undefined
        : {
            "/api": {
              target: env.TENKO_API_URL || "http://127.0.0.1:8080",
              // Keep the browser's Host so the server's same-origin check sees the
              // origin the browser sends.
              changeOrigin: false,
              secure: false,
            },
          },
    },
    build: {
      outDir: "dist",
      assetsDir: "assets",
      emptyOutDir: true,
      target: "es2022",
      sourcemap: false,
      reportCompressedSize: false,
    },
    test: {
      environment: "jsdom",
      include: ["src/**/*.test.{ts,tsx}", "scripts/**/*.test.mjs"],
      setupFiles: ["src/app/testing/setup.ts"],
      restoreMocks: true,
      // Solid and its libraries go through Vite (with the browser condition, the DOM build);
      // everything else loads in Node with Node's own conditions.
      server: { deps: { inline: [/solid-js/, /@solidjs\//] } },
      testTimeout: 15000,
    },
  };
});

/**
 * vite-plugin-solid adds the `browser` condition to every environment under test, so the
 * DOM build of Solid runs in jsdom. Vitest hands the server environment's conditions to
 * Node for the dependencies it does not transform, and with `browser` Node cannot load
 * msw/node (its interceptors export nothing for browsers). Node keeps its own conditions.
 */
function nodeConditionsForTests(): Plugin {
  return {
    name: "tenko-node-conditions-for-tests",
    enforce: "post",
    configEnvironment(name, config) {
      if (name !== "ssr" || !config.resolve?.conditions) return;
      config.resolve.conditions = config.resolve.conditions.filter((c) => c !== "browser");
    },
  };
}

/** Serves msw's worker script in development with mocks on; never part of a build. */
function mockServiceWorker(): Plugin {
  const script = fileURLToPath(import.meta.resolve("msw/mockServiceWorker.js"));
  return {
    name: "tenko-mock-service-worker",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url?.split("?")[0] !== "/mockServiceWorker.js") return next();
        res.writeHead(200, {
          "content-type": "application/javascript; charset=utf-8",
          "cache-control": "no-cache",
          "service-worker-allowed": "/",
        });
        createReadStream(script).pipe(res);
      });
    },
  };
}
