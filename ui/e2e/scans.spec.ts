// Scenario WP3.11a: the scans pages and the scan configuration of a probe end to end (SCAN-05,
// SCAN-09; docs/scanning.md, sections 7 and 12). The controller runs with the internal CA and a
// cluster port of its own (`serverOptions: { cluster: true }`) but without the probe role; the
// probe is a second `tenko` process (support/probe.ts) enrolled with a token from the API. It
// has no `[scan]` prefixes and the tests never give it any, so nothing is ever scanned.
//
// - The scans page of a fresh installation has no scans and lists the enrolled probe with its
//   state as the server reports it (in sync or not, the switch, a scope without prefixes). "Stop all scans"
//   with a reason turns on the kill switch of every probe (the page and `GET /scans/probes`
//   show the reason), "Resume all" turns it off again.
// - "Scan now" on the page of a documentation prefix that no probe covers is refused with
//   `scan.job.no_probe`, which the dialog shows; no scan is created.
// - The node panel links to the scan configuration of the probe. The page shows what the
//   server holds (the defaults the probe offered when it first connected), a save with a changed
//   `concurrency` (with `enabled` off and no prefixes) stores it, the revision follows and the
//   API answers the new value; a second save moves the revision again.
// - One probe is stopped with a reason and resumed from its configuration page; a viewer reads
//   the page and the form disabled; the scans page and the configuration page render in Swedish.
//
// Safety: no scenario saves a configuration with prefixes or with the scanner enabled, creates
// a scan a probe could run, or starts a probe with a `[scan]` section, so no packet leaves the
// loopback. Documentation values only: probe address 192.0.2.20, prefix 192.0.2.0/24.
//
// What stays manual: the progress and the result of a running scan (the scan page of one run,
// covered by the component tests and the Rust suites, since a run needs a probe that scans),
// a probe that was offline when the kill switch changed (`confirmed` stays false until it
// connects), the SNMP device table with its vault secrets, and a probe in another VRF.

import { signInAsViewer } from "./support/accounts";
import { ADMIN, type Api, type Schemas } from "./support/api";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { ProbeNode } from "./support/probe";
import type { TenkoServer } from "./support/server";

type Created = Schemas["CreatedEnrolment"];
type ProbeList = Schemas["ProbeList"];
type ProbeConfigView = Schemas["ProbeConfigView"];

test.use({ transport: "internal_ca", serverOptions: { cluster: true } });

/** The id the first node of a controller gets (docs/cluster.md, section 1.3). */
const NODE = 1001;
const NODE_NAME = "probe-dmz";
const NODE_ADDRESS = "192.0.2.20";

/** The probe node of a test: enrolled, started and connected to `server`. */
async function startProbe(server: TenkoServer, api: Api): Promise<ProbeNode> {
  const created = await api.post<Created>("/nodes/enrolments", { roles: ["probe"], name: NODE_NAME }, { idempotencyKey: null });
  const probe = await ProbeNode.create();
  try {
    const enrolled = await probe.enrol(server, created.token, { name: NODE_NAME, address: NODE_ADDRESS });
    expect(enrolled.code, enrolled.stderr).toBe(0);
    await probe.serve();
    await expect
      .poll(async () => (await api.get<Schemas["NodeView"]>(`/nodes/${NODE}`)).connected, { message: "the probe to be connected", timeout: 30_000 })
      .toBe(true);
  } catch (error) {
    await probe.stop();
    throw error;
  }
  return probe;
}

/** The probes as `GET /scans/probes` lists them. */
async function probes(api: Api): Promise<ProbeList["items"]> {
  return (await api.get<ProbeList>("/scans/probes")).items;
}

/** The scan configuration of the probe as the API shows it. */
function scanConfig(api: Api): Promise<ProbeConfigView> {
  return api.get<ProbeConfigView>(`/nodes/${NODE}/scan-config`);
}

test("the scans page has no scans and lists the probe; Stop all scans sets every kill switch with its reason and Resume all clears it", async ({
  page,
  api,
  server,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const probe = await startProbe(server, api);
  try {
    await test.step("no scans, and the probe as the server reports it", async () => {
      await page.goto("/scans");
      await expect(page.getByTestId("page-scans")).toBeVisible();
      await expect(page.getByTestId("scans-empty")).toBeVisible();
      await expect(page.getByTestId("scans-list")).toHaveCount(0);
      expect((await api.get<Schemas["Page_ScanView"]>("/scans")).items).toHaveLength(0);

      const listed = await probes(api);
      expect(listed).toHaveLength(1);
      expect(listed[0]).toMatchObject({ node: NODE, name: NODE_NAME, in_process: false });
      const row = page.getByTestId(`probe-row-${NODE}`);
      await expect(row).toBeVisible();
      await expect(row.getByTestId("probe-sync")).toHaveAttribute("data-state", listed[0]!.in_sync ? "in_sync" : "out_of_sync");
      await expect(row.getByTestId("probe-in-process")).toHaveCount(0);
      // It scans nothing: the scope it reports has no prefixes.
      expect(listed[0]!.applied?.prefixes).toEqual([]);
      await expect(row.getByTestId("probe-scope")).toBeVisible();
      await expect(row.getByTestId("probe-switch")).toHaveAttribute("data-state", "active");
      await expect(page.getByTestId("scans-resume-all")).toHaveCount(0);
      await expect(page.getByTestId("scans-stop-all")).toBeEnabled();
    });

    await test.step("Stop all scans with a reason turns the switch on, in the page and in the API", async () => {
      await page.getByTestId("scans-stop-all").click();
      const dialog = page.getByTestId("dialog-stop-scans");
      await expect(dialog).toBeVisible();
      await dialog.getByTestId("field-reason").fill("maintenance window of the lab");
      await dialog.getByTestId("confirm-ok").click();
      await expect(dialog).toHaveCount(0);

      const row = page.getByTestId(`probe-row-${NODE}`);
      await expect(row.getByTestId("probe-switch")).toHaveAttribute("data-state", "stopped");
      await expect(row).toContainText("maintenance window of the lab");
      await expect(page.getByTestId("scans-stop-all")).toBeDisabled();
      await expect(page.getByTestId("scans-resume-all")).toBeVisible();
      const stopped = (await probes(api))[0]!;
      expect(stopped.kill_switch).toMatchObject({ stopped: true, reason: "maintenance window of the lab" });
    });

    await test.step("Resume all turns it off again", async () => {
      await page.getByTestId("scans-resume-all").click();
      const row = page.getByTestId(`probe-row-${NODE}`);
      await expect(row.getByTestId("probe-switch")).toHaveAttribute("data-state", "active");
      await expect(page.getByTestId("scans-resume-all")).toHaveCount(0);
      await expect(page.getByTestId("scans-stop-all")).toBeEnabled();
      const resumed = (await probes(api))[0]!;
      expect(resumed.kill_switch.stopped).toBe(false);
    });
  } finally {
    await probe.stop();
  }
});

test("Scan now on a documentation prefix that no probe covers is refused with scan.job.no_probe and creates no scan", async ({
  page,
  api,
  server,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const probe = await startProbe(server, api);
  try {
    await api.post("/prefixes", { cidr: "192.0.2.0/24" });
    await page.goto("/ipam/prefixes/192.0.2.0/24");
    await expect(page.getByTestId("page-ipam")).toBeVisible();
    await page.getByTestId("scan-now").click();
    const dialog = page.getByTestId("dialog-scan-now");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByTestId("scan-now-kind-passive_refresh")).toBeChecked();
    await dialog.getByTestId("scan-now-start").click();

    const refusal = dialog.getByTestId("error-notice");
    await expect(refusal).toBeVisible();
    await expect(refusal).toHaveAttribute("data-code", "scan.job.no_probe");
    await expect(dialog.getByTestId("scan-now-started")).toHaveCount(0);
    await dialog.getByTestId("scan-now-cancel").click();
    await expect(dialog).toHaveCount(0);

    expect((await api.get<Schemas["Page_ScanView"]>("/scans")).items).toHaveLength(0);
    await page.goto("/scans");
    await expect(page.getByTestId("scans-empty")).toBeVisible();
  } finally {
    await probe.stop();
  }
});

test("the node panel links to the scan configuration; a save with a changed concurrency (scanner off, no prefixes) stores it and the revision follows", async ({
  page,
  api,
  server,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const probe = await startProbe(server, api);
  try {
    await test.step("the link in the node panel opens the page of that probe", async () => {
      await page.goto(`/nodes/${NODE}`);
      await expect(page.getByTestId("node-panel")).toBeVisible();
      await page.getByTestId("node-scan-config").click();
      await expect(page).toHaveURL(new RegExp(`/nodes/${NODE}/scan$`));
      await expect(page.getByTestId("page-scan-config")).toHaveAttribute("data-node", String(NODE));
    });

    // A probe without a `[scan]` section offers its defaults when it first connects: the
    // controllers store them as an offer, and they list no prefixes.
    const initial = await scanConfig(api);
    expect(initial.stored).toBe(true);
    expect(initial.origin).toBe("offer");
    expect(initial.config.prefixes ?? []).toEqual([]);

    await test.step("the page shows what the server holds", async () => {
      const sync = page.getByTestId("scan-config-sync");
      await expect(sync).toHaveAttribute("data-stored", "true");
      await expect(sync).toHaveAttribute("data-sync", String(initial.in_sync));
      await expect(page.getByTestId("scan-sync-origin")).toHaveAttribute("data-origin", "offer");
      await expect(page.getByTestId("scan-sync-revision")).toHaveText(String(initial.revision));
      await expect(page.getByTestId("scan-kill-switch")).toHaveAttribute("data-state", "running");
      await expect(page.getByTestId("field-concurrency")).toHaveValue(String(initial.config.concurrency));
      await expect(page.getByTestId("field-prefixes")).toHaveValue("");
      await expect(page.getByTestId("scan-config-save")).toBeDisabled();
      await expect(page.getByTestId("scan-config-readonly")).toHaveCount(0);
    });

    let first = 0;
    await test.step("switching the scanner off and changing the concurrency stores the configuration", async () => {
      const concurrency = initial.config.concurrency === 7 ? 9 : 7;
      // The scanner goes off first: nothing in this test lets a probe run.
      await page.getByTestId("field-enabled").uncheck();
      await page.getByTestId("field-concurrency").fill(String(concurrency));
      await expect(page.getByTestId("scan-config-form")).toHaveAttribute("data-dirty", "true");
      await page.getByTestId("scan-config-save").click();

      await expect(page.getByTestId("scan-config-form")).toHaveAttribute("data-dirty", "false");
      const stored = await scanConfig(api);
      expect(stored.origin).toBe("api");
      expect(stored.revision!).toBeGreaterThan(initial.revision!);
      expect(stored.config).toMatchObject({ enabled: false, concurrency });
      expect(stored.config.prefixes ?? []).toEqual([]);
      first = stored.revision!;
      await expect(page.getByTestId("scan-sync-revision")).toHaveText(String(first));
      await expect(page.getByTestId("scan-sync-origin")).toHaveAttribute("data-origin", stored.origin ?? "");
      await expect(page.getByTestId("field-concurrency")).toHaveValue(String(concurrency));
    });

    await test.step("a second save moves the revision again, and a reload shows the stored value", async () => {
      await page.getByTestId("field-concurrency").fill("11");
      await page.getByTestId("scan-config-save").click();
      await expect(page.getByTestId("scan-sync-revision")).not.toHaveText(String(first));
      const stored = await scanConfig(api);
      expect(stored.revision!).toBeGreaterThan(first);
      expect(stored.config).toMatchObject({ enabled: false, concurrency: 11 });
      expect(stored.config.prefixes ?? []).toEqual([]);
      await expect(page.getByTestId("scan-sync-revision")).toHaveText(String(stored.revision));

      await page.reload();
      await expect(page.getByTestId("page-scan-config")).toBeVisible();
      await expect(page.getByTestId("field-concurrency")).toHaveValue("11");
      await expect(page.getByTestId("field-enabled")).not.toBeChecked();
    });

    await test.step("the probe still has no prefixes to scan", async () => {
      await page.goto("/scans");
      await expect(page.getByTestId(`probe-row-${NODE}`)).toBeVisible();
      expect((await probes(api))[0]!.revision).toBe((await scanConfig(api)).revision);
      expect((await scanConfig(api)).config.prefixes ?? []).toEqual([]);
    });
  } finally {
    await probe.stop();
  }
});

test("one probe is stopped with a reason from its configuration page and resumed", async ({ page, api, server, signedIn }) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const probe = await startProbe(server, api);
  try {
    await page.goto(`/nodes/${NODE}/scan`);
    const card = page.getByTestId("scan-kill-switch");
    await expect(card).toHaveAttribute("data-state", "running");
    await expect(page.getByTestId("scan-resume")).toHaveCount(0);

    await page.getByTestId("scan-stop").click();
    const dialog = page.getByTestId("dialog-stop-probe");
    await expect(dialog).toBeVisible();
    await dialog.getByTestId("field-reason").fill("cabling work in the lab");
    await dialog.getByTestId("form-submit").click();
    await expect(dialog).toHaveCount(0);

    await expect(card).toHaveAttribute("data-state", "stopped");
    await expect(page.getByTestId("scan-ks-reason")).toHaveText("cabling work in the lab");
    await expect(page.getByTestId("scan-stop")).toHaveCount(0);
    expect((await scanConfig(api)).kill_switch).toMatchObject({ stopped: true, reason: "cabling work in the lab" });
    // The scans page shows the same switch.
    await page.goto("/scans");
    await expect(page.getByTestId(`probe-row-${NODE}`).getByTestId("probe-switch")).toHaveAttribute("data-state", "stopped");

    await page.goto(`/nodes/${NODE}/scan`);
    await page.getByTestId("scan-resume").click();
    await expect(page.getByTestId("scan-kill-switch")).toHaveAttribute("data-state", "running");
    expect((await scanConfig(api)).kill_switch.stopped).toBe(false);
  } finally {
    await probe.stop();
  }
});

test("a viewer reads the scans page and the scan configuration with the form disabled", async ({ page, api, server, signedIn }) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const probe = await startProbe(server, api);
  try {
    await signInAsViewer(api);

    await page.goto("/scans");
    await expect(page.getByTestId(`probe-row-${NODE}`)).toBeVisible();
    await expect(page.getByTestId("scans-stop-all")).toHaveCount(0);
    await expect(page.getByTestId("scans-resume-all")).toHaveCount(0);

    await page.goto(`/nodes/${NODE}/scan`);
    await expect(page.getByTestId("page-scan-config")).toBeVisible();
    await expect(page.getByTestId("scan-config-readonly")).toBeVisible();
    await expect(page.getByTestId("field-concurrency")).toBeDisabled();
    await expect(page.getByTestId("field-enabled")).toBeDisabled();
    await expect(page.getByTestId("field-prefixes")).toBeDisabled();
    await expect(page.getByTestId("scan-config-save")).toHaveCount(0);
    await expect(page.getByTestId("scan-stop")).toHaveCount(0);
    await expect(page.getByTestId("scan-resume")).toHaveCount(0);
  } finally {
    await probe.stop();
  }
});

test.describe("a Swedish browser", () => {
  test.use({ locale: "sv-SE" });

  test("shows the scans page, its stop dialog and the scan configuration in Swedish", async ({ page, api, server, signedIn }, testInfo) => {
    expect(signedIn.session.user.name).toBe(ADMIN.name);
    const probe = await startProbe(server, api);
    try {
      await page.goto("/scans");
      const root = page.getByTestId("page-scans");
      await expect(page.getByTestId(`probe-row-${NODE}`)).toBeVisible();
      await expect(page.getByTestId("scans-empty")).toBeVisible();
      await expectRendered(page, root, "sv", testInfo, "scans");

      await page.getByTestId("scans-stop-all").click();
      const dialog = page.getByTestId("dialog-stop-scans");
      await expect(dialog).toBeVisible();
      await expectRendered(page, dialog, "sv");
      await page.keyboard.press("Escape");
      await expect(dialog).toHaveCount(0);

      await page.goto(`/nodes/${NODE}/scan`);
      await expect(page.getByTestId("scan-config-form")).toBeVisible();
      await expectRendered(page, page.getByTestId("page-scan-config"), "sv", testInfo, "scan-config");
      await page.getByTestId("scan-stop").click();
      const stop = page.getByTestId("dialog-stop-probe");
      await expect(stop).toBeVisible();
      await expectRendered(page, stop, "sv");
    } finally {
      await probe.stop();
    }
  });
});
