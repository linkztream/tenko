// End-to-end tests of the embedded UI against the real server (WP1.11). Every test starts
// its own `tenko serve` from the debug build (see e2e/support/server.ts), so the build must
// embed the real UI: `npm run build`, then `cargo build -p tenko` without TENKO_UI_STUB.
// The binary is found through TENKO_BIN, CARGO_TARGET_DIR or ../target. Run: `npm run e2e`.

import { defineConfig, devices } from "@playwright/test";

const ci = !!process.env.CI;

export default defineConfig({
  testDir: "e2e",
  testMatch: "**/*.spec.ts",
  outputDir: "e2e/.artifacts/test-results",
  globalSetup: "./e2e/global-setup.ts",
  fullyParallel: true,
  forbidOnly: ci,
  retries: ci ? 1 : 0,
  workers: ci ? 2 : 4,
  timeout: 120_000,
  // The whole run must fit this budget, well inside the CI job's thirty minutes; past it the run
  // fails. With two workers on the runner the suite (252 scenarios) needs a little over ten minutes.
  globalTimeout: 20 * 60_000,
  expect: { timeout: 15_000 },
  reporter: [["list"], ["html", { outputFolder: "e2e/.artifacts/report", open: "never" }]],
  use: {
    ...devices["Desktop Chrome"],
    locale: "en-US",
    timezoneId: "UTC",
    // The internal CA is not in the browser's trust store; the tests compare its root with
    // the one in the data directory instead.
    ignoreHTTPSErrors: true,
    testIdAttribute: "data-testid",
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium" }],
});
