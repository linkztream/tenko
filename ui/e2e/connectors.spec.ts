// WP2.11: the connectors area end to end (CONN-19, CONN-20, CONN-02, TGL-20; docs/plugins.md).
// The only plugin that works is the bundled sample (an inventory source that reports
// documentation data and contacts nothing); every instance in these scenarios is an instance
// of it.
//
// - Plugins and creation: `/connectors` lists the bundled plugin with what its manifest says,
//   and an installed plugin with a broken manifest as unusable with its problems; the list
//   agrees with `tenko plugin list` run from outside. An instance is created through the form
//   that the UI generates from the settings schema: the defaults of the schema show, an
//   invalid value is refused before anything is sent, and the valid form opens the instance
//   page, stores the settings with the defaults filled in and starts the plugin process.
// - Run and check: "Run now" starts the run job, the toast leads to the job page, the
//   instance shows the last run with its observations, and the observations arrive (the API
//   lists them, the observations view lists them for the source). "Check now" reports the
//   remote system healthy.
// - Lifecycle and dashboard: an instance is edited (the next run reads the new setting),
//   disabled (the process stops, the instance is not counted by the dashboard tile), enabled
//   again and deleted; the audit log keeps the lifecycle. A second page holds the dashboard
//   open to see the tile follow.
// - Swedish: the list, an instance page and the form with its generated fields.
// - A secret reference reaches the plugin: the vault secret is referenced for the purpose
//   `api_key`, the sample tags every host with `credential:present`, the injection is
//   audited, and the value shows nowhere.
// - Process and health follow without a reload: the page of a new instance, the list and the
//   dashboard tile show the plugin process going from starting to running. The plugin host
//   announces every change of a process or of its health as a `connectors` event (no store
//   write carries them), and the views read the instance again.
//
// Arrangement: instances are created through the API unless the scenario is about the form;
// documentation values only (192.0.2.0/24, 2001:db8::/32, MAC 00:00:5e:00:53:xx, names under
// example.test); the secret value is invented.
//
// What stays manual: an installed plugin that starts (it needs a plugin directory with a
// working executable or script), a plugin that crashes or hangs (supervision, backoff and the
// circuit breaker are covered by the Rust suites of the plugin host), and writes through a
// network-controller connector (the guardrail toggle is disabled for an inventory-only
// plugin; it needs the UniFi plugin of a later work package).

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Locator, Page } from "@playwright/test";
import { ADMIN, ApiError, type Api, type Schemas } from "./support/api";
import {
  createSampleConnector,
  observations,
  runConnector,
  sampleHost,
  waitForConnectorProcess,
  type ConnectorView,
  type ObservedFact,
} from "./support/discovery";
import { expect, test } from "./support/fixtures";
import { expectRendered } from "./support/i18n";
import { runTenko } from "./support/process";
import { cell, gridRow, withId, withIndex, withKey } from "./support/ui";

type JobSummary = Schemas["JobSummary"];

/** The settings schema of the sample, as far as these tests read it. */
interface SampleSchema {
  properties: Record<string, { default: unknown; title: string }>;
}

const OFFICE = "Office inventory";

/** Every instance, by name. */
async function connectors(api: Api): Promise<ConnectorView[]> {
  return (await api.get<Schemas["Page_ConnectorView"]>("/connectors", { limit: 1000 })).items;
}

/** The instance `id` as the API has it now. */
async function connectorOf(api: Api, id: string): Promise<ConnectorView> {
  return api.get<ConnectorView>(`/connectors/${id}`);
}

/** The jobs that name the instance as their target (edits and runs), newest first. */
async function jobsOf(api: Api, id: string): Promise<JobSummary[]> {
  return (await api.get<Schemas["Page_JobSummary"]>("/jobs", { target: `connector/${id}`, limit: 100 })).items;
}

/** The identifier at the end of the URL of an instance page. */
function idOfUrl(page: Page): string {
  return new URL(page.url()).pathname.split("/").pop()!;
}

/** The supervised process on an instance page (`data-state` of the state in the process card). */
function processOf(page: Page): Locator {
  return page.getByTestId("connector-process").locator("[data-state]");
}

/** The current host facts of a source once there are `count` of them (they follow the run). */
async function hostFacts(api: Api, id: string, count: number): Promise<ObservedFact[]> {
  let facts: ObservedFact[] = [];
  await expect
    .poll(
      async () => {
        facts = await observations(api, { source: id, type: "host", current: "true" });
        return facts.length;
      },
      { message: `${count} current host facts of connector ${id}` },
    )
    .toBe(count);
  return facts;
}

/** The hexadecimal digits of a MAC address, whatever its separators and case. */
function macDigits(text: string): string {
  return text.replace(/[^0-9a-f]/gi, "").toLowerCase();
}

/** The instance is gone: the API answers 404 `connect.instance.not_found`. */
async function expectGone(api: Api, id: string): Promise<void> {
  const error = await connectorOf(api, id).then(
    () => undefined,
    (reason: unknown) => reason,
  );
  expect(error).toBeInstanceOf(ApiError);
  expect((error as ApiError).status).toBe(404);
  expect((error as ApiError).code).toBe("connect.instance.not_found");
}

// U3: the Connectors block of the start page belongs to the Standard set; the e2e server runs the
// Lab profile, so the dashboards of these scenarios open with "Show all metrics" switched on for the
// session, which draws every block whatever the profile.
test.beforeEach(async ({ page }) => {
  await page.context().addInitScript(() => {
    try {
      sessionStorage.setItem("tenko.dashboard.show-all", "1");
    } catch {
      // A document without session storage (about:blank) has nothing to switch.
    }
  });
});

/**
 * The connectors block of the dashboard's health row (U3) shows `healthy/enabled`, with `healthy`
 * as its value, and its hint counts `enabled` instances of which `enabled - healthy` need a look
 * (the words are translated; the block and the hint carry the numbers as attributes).
 */
async function expectTile(tile: Locator, healthy: number, enabled: number): Promise<void> {
  await expect(tile).toHaveAttribute("data-value", String(healthy));
  const hint = tile.getByTestId("dashboard-connectors-hint");
  await expect(hint).toHaveAttribute("data-total", String(enabled));
  await expect(hint).toHaveAttribute("data-failing", String(enabled - healthy));
}

test("the plugin list agrees with the CLI, and the form generated from the settings schema creates and starts an instance", async ({
  page,
  api,
  server,
  signedIn,
}, testInfo) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  // An installed plugin whose manifest is not one (it lacks most members): the registry reads
  // the plugin directory on every listing and reports what is wrong instead of hiding it.
  const installed = join(server.dataDir, "plugins");
  await mkdir(join(installed, "broken-sample"), { recursive: true });
  await writeFile(join(installed, "broken-sample", "plugin.json"), JSON.stringify({ manifest_version: 1, name: "broken-sample" }));
  const plugins = (await api.get<Schemas["PluginList"]>("/connectors/plugins")).items;
  // The bundled plugins come first (the sample and the reference plugins; more join in later
  // work packages), then the installed ones.
  const names = plugins.map((p) => p.name);
  expect(names[0]).toBe("sample");
  expect(names).toEqual(expect.arrayContaining(["sample", "proxmox", "hass", "broken-sample"]));
  const sample = plugins.find((p) => p.name === "sample")!;
  expect(sample.source).toBe("bundled");
  const manifest = sample.manifest!;
  const schema = manifest.settings as unknown as SampleSchema;
  const broken = plugins.find((p) => p.name === "broken-sample")!;
  expect(broken).toMatchObject({ source: "installed", usable: false });
  expect(broken.problems?.length).toBeGreaterThan(0);
  const refused = await api.post("/connectors", { plugin: "broken-sample", name: "Never created", settings: {} }).then(
    () => undefined,
    (reason: unknown) => reason,
  );
  expect(refused).toBeInstanceOf(ApiError);
  expect([(refused as ApiError).status, (refused as ApiError).code]).toEqual([422, "connect.plugin.unusable"]);

  // The page lists every plugin, the broken one marked unusable with its problems, and no instance yet.
  await page.goto("/connectors");
  await expect(page.getByTestId("page-connectors")).toBeVisible();
  await expect(page.getByTestId("connectors-empty")).toBeVisible();
  const section = page.getByTestId("connectors-plugins");
  await expect(section.getByTestId("plugin")).toHaveCount(plugins.length);
  const unusable = withKey(section, "plugin", "broken-sample");
  await expect(unusable).toHaveAttribute("data-usable", "false");
  await expect(unusable.getByTestId("plugin-unusable")).toBeVisible();
  await expect(unusable).toContainText(broken.problems![0]!.message);
  const plugin = withKey(section, "plugin", "sample");
  await expect(plugin).toHaveAttribute("data-usable", "true");
  await expect(plugin.getByTestId("plugin-unusable")).toHaveCount(0);
  await expect(plugin).toContainText(manifest.version);
  await expect(plugin).toContainText(manifest.description);
  await expect(plugin).toContainText(manifest.platforms.join(", "));
  await expect(plugin).toContainText(manifest.secrets![0]!.purpose);
  await expect(plugin).toContainText(manifest.license!);

  // The CLI run from outside lists the same plugin as bundled, with the same version.
  const empty = testInfo.outputPath("plugins");
  await mkdir(empty, { recursive: true });
  const listed = await runTenko(["plugin", "list", "--plugins-dir", empty], { cwd: testInfo.outputDir });
  expect(listed.code, listed.stderr).toBe(0);
  const line = listed.stdout.split("\n").find((l) => l.startsWith("sample"));
  expect(line, listed.stdout).toBeDefined();
  expect(line).toContain("bundled");
  expect(line!.split(/\s+/)).toContain(manifest.version);
  expect(listed.stdout).not.toContain("broken-sample");
  // Pointed at the plugin directory of the server, it lists the broken plugin as not usable.
  const both = await runTenko(["plugin", "list", "--plugins-dir", installed], { cwd: testInfo.outputDir });
  expect(both.code, both.stderr).toBe(0);
  const brokenLine = both.stdout.split("\n").find((l) => l.startsWith("broken-sample"));
  expect(brokenLine, both.stdout).toBeDefined();
  expect(brokenLine).toContain("installed");
  expect(brokenLine).toContain("not usable");

  // The form: the plugin, and the settings with the defaults of the schema.
  const posts: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST" && new URL(request.url()).pathname === "/api/v1/connectors") posts.push(request.url());
  });
  await page.getByTestId("connectors-create").click();
  const form = page.getByTestId("dialog-connector-form");
  await expect(form).toBeVisible();
  await expect(form.getByTestId("field-plugin")).toHaveValue("sample");
  // Only a plugin that can run is offered.
  const offered = await form.getByTestId("field-plugin").evaluate((select: HTMLSelectElement) => [...select.options].map((o) => o.value));
  expect(offered).toEqual(plugins.filter((p) => p.usable).map((p) => p.name));
  const settings = form.getByTestId("connector-settings");
  await expect(settings.getByTestId("settings-form")).toBeVisible();
  for (const name of ["site", "hosts", "page_size", "endpoint"]) {
    await expect(settings.getByTestId(`field-settings-${name}`), name).toHaveValue(String(schema.properties[name]!.default));
  }
  // The secret purpose of the manifest is offered; the instance starts enabled and, as the
  // plugin only reads, without the option to allow writes.
  await expect(form.getByTestId("connector-secrets").getByTestId("field-secret-api_key")).toBeVisible();
  await expect(form.getByTestId("field-enabled")).toBeChecked();
  await expect(form.getByTestId("field-writes_enabled")).toBeDisabled();
  await expect(form.getByTestId("field-writes_enabled")).not.toBeChecked();

  // A form with no name, a number above the maximum and an address that is not a URI is
  // refused where it stands: each field says so, nothing is sent, nothing exists.
  await settings.getByTestId("field-settings-hosts").fill("201");
  await settings.getByTestId("field-settings-endpoint").fill("not-a-uri");
  await form.getByTestId("form-submit").click();
  await expect(form.getByTestId("field-name")).toHaveAttribute("aria-invalid", "true");
  await expect(settings.getByTestId("field-settings-hosts")).toHaveAttribute("aria-invalid", "true");
  await expect(settings.getByTestId("field-settings-endpoint")).toHaveAttribute("aria-invalid", "true");
  await expect(settings.getByTestId("field-settings-site")).not.toHaveAttribute("aria-invalid", "true");
  await expect(form).toBeVisible();
  expect(posts).toEqual([]);
  expect(await connectors(api)).toEqual([]);

  // Correcting the fields clears their errors; then the form is accepted.
  await form.getByTestId("field-name").fill(OFFICE);
  await settings.getByTestId("field-settings-site").fill("office");
  await settings.getByTestId("field-settings-hosts").fill("4");
  await settings.getByTestId("field-settings-endpoint").fill(String(schema.properties.endpoint!.default));
  await expect(form.getByTestId("field-name")).not.toHaveAttribute("aria-invalid", "true");
  await expect(settings.getByTestId("field-settings-hosts")).not.toHaveAttribute("aria-invalid", "true");
  await expect(settings.getByTestId("field-settings-endpoint")).not.toHaveAttribute("aria-invalid", "true");
  await form.getByTestId("form-submit").click();

  // The instance page opens; the API holds the settings with the defaults filled in.
  await expect(page.getByTestId("page-connector")).toBeVisible();
  await expect(page).toHaveURL(/\/connectors\/[0-9a-f-]{36}$/);
  const id = idOfUrl(page);
  await expect(page.getByTestId("page-connector")).toHaveAttribute("data-id", id);
  expect(posts).toHaveLength(1);
  const created = await connectorOf(api, id);
  expect(created.name).toBe(OFFICE);
  expect(created.plugin).toBe("sample");
  expect(created.enabled).toBe(true);
  expect(created.writes_enabled ?? false).toBe(false);
  expect(created.settings).toEqual({
    site: "office",
    hosts: 4,
    page_size: schema.properties.page_size!.default,
    endpoint: schema.properties.endpoint!.default,
  });
  expect((await connectors(api)).map((c) => c.id)).toEqual([id]);

  // The plugin process starts, and the page follows it from starting to running.
  await waitForConnectorProcess(api, id, "running");
  await expect(processOf(page)).toHaveAttribute("data-state", "running");
  await expect(page.getByTestId("connector-health")).toHaveAttribute("data-health", "healthy");
  const shown = page.getByTestId("connector-settings-view");
  await expect(shown.locator('[data-setting="site"]')).toHaveText("office");
  await expect(shown.locator('[data-setting="hosts"]')).toHaveText("4");
  await expect(shown.locator('[data-setting="page_size"]')).toHaveText(String(schema.properties.page_size!.default));

  // The list shows it too, with the same health and process.
  await page.goto("/connectors");
  const row = gridRow(page, "connectors", OFFICE);
  await expect(row).toHaveAttribute("data-id", id);
  await expect(cell(row, "health").getByTestId("connector-health")).toHaveAttribute("data-health", "healthy");
  await expect(cell(row, "process").locator("[data-state]")).toHaveAttribute("data-state", "running");
  await expect(cell(row, "plugin")).toContainText("sample");
});

// The health of an instance is the state of its supervised plugin process and the outcome of
// its last remote check, both kept in memory on the node. The page of a new instance opens
// while the process is still starting (the form opens it right after the create answer); the
// change to running reaches the page, the list and the dashboard tile as a `connectors` event
// of the plugin host, without a reload (found by WP2.11, fixed by WP2.12).
test("the page of a new instance, the list and the dashboard tile follow the plugin process from starting to running", async ({
  page,
  api,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  // The list and the dashboard stay open on two more pages of the same session.
  const list = await page.context().newPage();
  await list.goto("/connectors");
  await expect(list.getByTestId("connectors-empty")).toBeVisible();
  const dashboard = await page.context().newPage();
  await dashboard.goto("/");
  const tile = dashboard.getByTestId("dashboard-connectors");
  await expectTile(tile, 0, 0);

  await page.goto("/connectors");
  await page.getByTestId("connectors-create").click();
  const form = page.getByTestId("dialog-connector-form");
  await form.getByTestId("field-name").fill(OFFICE);
  await form.getByTestId("form-submit").click();
  await expect(page.getByTestId("page-connector")).toBeVisible();
  const id = idOfUrl(page);
  await waitForConnectorProcess(api, id, "running");
  await expect(processOf(page)).toHaveAttribute("data-state", "running");
  await expect(page.getByTestId("connector-health")).toHaveAttribute("data-health", "healthy");

  const row = gridRow(list, "connectors", OFFICE);
  await expect(row).toHaveAttribute("data-id", id);
  await expect(cell(row, "process").locator("[data-state]")).toHaveAttribute("data-state", "running");
  await expect(cell(row, "health").getByTestId("connector-health")).toHaveAttribute("data-health", "healthy");
  await expectTile(tile, 1, 1);

  // The first scheduled run follows a few seconds after the start. Its outcome reaches the open
  // page as well: the run is recorded in `connect.runs`, whose event names the instance (the
  // page reads only events about its instance; found on the Linux runner, fixed by WP2.12).
  await expect
    .poll(async () => (await connectorOf(api, id)).last_run?.outcome, { message: "the first scheduled run", timeout: 30_000 })
    .toBe("succeeded");
  await expect(page.getByTestId("connector-last-run").locator('[data-outcome="succeeded"]')).toBeVisible();
  await expect(cell(row, "last_run").locator('[data-outcome="succeeded"]')).toBeVisible();
});

test("a run follows its job, hands the observations on and a check reports the remote system healthy", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  const instance = await createSampleConnector(api, OFFICE, { site: "office", hosts: 4 });
  const id = instance.id;
  const before = new Set((await jobsOf(api, id)).map((job) => job.id));

  await page.goto(`/connectors/${id}`);
  await expect(page.getByTestId("page-connector")).toHaveAttribute("data-id", id);
  await expect(page.getByTestId("connector-health")).toHaveAttribute("data-health", "healthy");

  // Run now: the toast leads to the job page, where the run job succeeds.
  await page.getByTestId("connector-run").click();
  await withIndex(page, "toast-action", 0).click();
  await expect(page.getByTestId("page-job")).toBeVisible();
  await expect(page).toHaveURL(/\/jobs\/[0-9a-f-]{36}$/);
  const jobId = idOfUrl(page);
  expect(before.has(jobId)).toBe(false);
  await expect(page.getByTestId("page-job").getByTestId("job-state")).toHaveAttribute("data-state", "succeeded");
  const job = await api.waitForJob(jobId);
  expect(job.job.state).toBe("succeeded");
  expect(job.job.spec.kind).toBe("connect.run");
  expect(job.job.error ?? null).toBeNull();
  expect(job.job.spec.targets).toContainEqual({ kind: "connector", id });
  await expect(page.getByTestId("job-targets")).toContainText(id.slice(0, 8));
  const steps = page.getByTestId("job-steps");
  await expect(steps.getByTestId("job-step")).toHaveCount(job.job.steps.length);
  await expect(withIndex(steps, "job-step", 0)).toHaveAttribute("data-state", "done");
  await page.goBack();
  await expect(page.getByTestId("page-connector")).toHaveAttribute("data-id", id);

  // The instance records the run: four observations, handed on by this job.
  await expect.poll(async () => (await connectorOf(api, id)).last_run?.job).toBe(jobId);
  const ran = await connectorOf(api, id);
  expect(ran.last_run).toMatchObject({ outcome: "succeeded", observations: 4, trigger: "manual" });
  const lastRun = page.getByTestId("connector-last-run");
  await expect(lastRun.locator('[data-outcome="succeeded"]')).toBeVisible();
  await expect(lastRun.locator('[data-outcome="succeeded"]')).toContainText(/\b4\b/);
  const runJob = withId(page.getByTestId("connector-runs"), "connector-run-job", jobId);
  await expect(runJob).toBeVisible();
  await expect(runJob.getByTestId("job-state")).toHaveAttribute("data-state", "succeeded");

  // The observations arrived: four current host facts of this source, tagged with the site.
  const facts = await hostFacts(api, id, 4);
  for (const fact of facts) {
    const data = fact.observed.data as Schemas["ObservedHost"];
    expect(data.tags).toEqual(["office"]);
    expect(fact.source).toMatchObject({ type: "inventory", connector: id });
  }
  const byName = new Map(facts.map((fact) => [(fact.observed.data as Schemas["ObservedHost"]).name, fact]));
  for (let n = 0; n < 4; n += 1) {
    const sample = sampleHost(n);
    const data = byName.get(sample.name)?.observed.data as Schemas["ObservedHost"] | undefined;
    expect(data, sample.name).toBeDefined();
    expect(data!.macs?.map(macDigits)).toEqual([macDigits(sample.mac)]);
    expect(data!.ips).toEqual(expect.arrayContaining([sample.ipv4, sample.ipv6]));
  }

  // Check now: the remote system is healthy, on the page and through the API.
  await page.getByTestId("connector-check").click();
  await expect(page.getByTestId("connector-remote").locator('[data-health="healthy"]')).toBeVisible();
  await expect(page.getByTestId("connector-health")).toHaveAttribute("data-health", "healthy");
  const checked = await connectorOf(api, id);
  expect(checked.health.remote?.health).toBe("healthy");
  expect(checked.health.remote_error ?? null).toBeNull();

  // The link on the instance page leads to the observations of the source, and the view lists
  // every current fact the API has for it.
  await page.getByTestId("connector-observations").click();
  await expect(page.getByTestId("page-discovery-observations")).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`/discovery/observations\\?source=${id}`));
  await expect(page.getByTestId("filter-source")).toBeVisible();
  const all = await observations(api, { source: id, current: "true" });
  expect(all.map((fact) => fact.observed.type)).toEqual(["host", "host", "host", "host"]);
  const grid = page.getByTestId("grid-observations");
  await expect(grid.getByTestId("row")).toHaveCount(all.length);
  for (const fact of facts) {
    const row = withId(grid, "row", `${fact.source_key}|${fact.subject_key}`);
    await expect(row).toBeVisible();
    await expect(cell(row, "observed")).toContainText((fact.observed.data as Schemas["ObservedHost"]).name!);
  }
});

test("an instance is edited, disabled, enabled and deleted, and the dashboard tile counts the enabled and healthy ones", async ({
  page,
  api,
  signedIn,
}) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  // The dashboard stays open on a second page of the same session and follows along: no
  // instance, no healthy one.
  const dashboard = await page.context().newPage();
  await dashboard.goto("/");
  const tile = dashboard.getByTestId("dashboard-connectors");
  await expect(tile).toBeVisible();
  await expectTile(tile, 0, 0);

  // Two instances that run are two healthy ones; the tile follows their processes.
  const office = await createSampleConnector(api, OFFICE, { site: "office", hosts: 4 });
  const lab = await createSampleConnector(api, "Lab sample", { hosts: 2 });
  await expectTile(tile, 2, 2);

  // The list shows both; the instance opens from its row.
  await page.goto("/connectors");
  await expect(gridRow(page, "connectors", "Lab sample")).toBeVisible();
  const row = gridRow(page, "connectors", OFFICE);
  await expect(cell(row, "health").getByTestId("connector-health")).toHaveAttribute("data-health", "healthy");
  await cell(row, "name").click();
  await expect(page.getByTestId("page-connector")).toHaveAttribute("data-id", office.id);

  // Edit: the dialog shows the stored values and the fixed plugin; two changes are saved.
  await page.getByTestId("connector-edit").click();
  const form = page.getByTestId("dialog-connector-form");
  await expect(form).toBeVisible();
  await expect(form.getByTestId("connector-form-plugin")).toBeVisible();
  await expect(form.getByTestId("field-plugin")).toHaveCount(0);
  await expect(form.getByTestId("field-name")).toHaveValue(OFFICE);
  await expect(form.getByTestId("field-settings-site")).toHaveValue("office");
  await expect(form.getByTestId("field-settings-hosts")).toHaveValue("4");
  await form.getByTestId("field-settings-hosts").fill("6");
  await form.getByTestId("field-poll_interval").fill("120");
  await form.getByTestId("form-submit").click();
  await expect(form).toHaveCount(0);
  await expect(page.getByTestId("connector-settings-view").locator('[data-setting="hosts"]')).toHaveText("6");
  const edited = await connectorOf(api, office.id);
  expect(edited.settings).toMatchObject({ site: "office", hosts: 6 });
  expect(edited.poll_interval_secs).toBe(120);
  await expect(page.getByTestId("connector-config")).toContainText("120");
  expect(edited.revision).toBeGreaterThan(office.revision);
  expect(edited.name).toBe(OFFICE);

  // The next run reads the new setting: six hosts, without a restart of the plugin.
  await page.getByTestId("connector-run").click();
  await expect.poll(async () => (await connectorOf(api, office.id)).last_run?.observations).toBe(6);
  await expect(page.getByTestId("connector-last-run").locator('[data-outcome="succeeded"]')).toContainText(/\b6\b/);
  await hostFacts(api, office.id, 6);
  expect((await connectorOf(api, office.id)).health.process.restarts).toBe(0);

  // Disable: the process stops, the page says so, run and check are off, the tile drops it.
  await page.getByTestId("connector-toggle").click();
  await expect(page.getByTestId("connector-disabled")).toBeVisible();
  await expect.poll(async () => (await connectorOf(api, office.id)).enabled).toBe(false);
  await waitForConnectorProcess(api, office.id, "stopped");
  await expect(processOf(page)).toHaveAttribute("data-state", "stopped");
  await expect(page.getByTestId("connector-health")).toHaveAttribute("data-health", "off");
  await expect(page.getByTestId("connector-run")).toBeDisabled();
  await expect(page.getByTestId("connector-check")).toBeDisabled();
  await expectTile(tile, 1, 1);
  await page.goto("/connectors");
  await expect(cell(gridRow(page, "connectors", OFFICE), "health").getByTestId("connector-health")).toHaveAttribute("data-health", "off");
  await expect(cell(gridRow(page, "connectors", "Lab sample"), "health").getByTestId("connector-health")).toHaveAttribute(
    "data-health",
    "healthy",
  );

  // Enable again: the process runs, the tile counts the instance.
  await cell(gridRow(page, "connectors", OFFICE), "name").click();
  await expect(page.getByTestId("page-connector")).toHaveAttribute("data-id", office.id);
  await page.getByTestId("connector-toggle").click();
  await expect(page.getByTestId("connector-disabled")).toHaveCount(0);
  await waitForConnectorProcess(api, office.id, "running");
  expect((await connectorOf(api, office.id)).enabled).toBe(true);
  // The page and the tile follow the process from starting to running.
  await expect(processOf(page)).toHaveAttribute("data-state", "running");
  await expect(page.getByTestId("connector-health")).toHaveAttribute("data-health", "healthy");
  await expectTile(tile, 2, 2);

  // Delete: after the confirmation the instance is gone from the list and the API.
  await page.getByTestId("connector-delete").click();
  await expect(page.getByTestId("dialog-confirm")).toBeVisible();
  expect((await connectorOf(api, office.id)).id).toBe(office.id);
  await page.getByTestId("confirm-ok").click();
  await expect(page.getByTestId("page-connectors")).toBeVisible();
  await expect(gridRow(page, "connectors", "Lab sample")).toBeVisible();
  await expect(gridRow(page, "connectors", OFFICE)).toHaveCount(0);
  await expectGone(api, office.id);
  expect((await connectors(api)).map((c) => c.id)).toEqual([lab.id]);
  await expectTile(tile, 1, 1);

  // The audit log keeps the lifecycle of the deleted instance.
  const log = (await api.get<Schemas["Page_AuditRecord"]>("/audit", { action: "connect.instance.", order: "asc", limit: 1000 })).items;
  const actions = log.filter((r) => r.draft.objects?.some((o) => o.id === office.id)).map((r) => r.draft.action);
  expect(actions).toEqual([
    "connect.instance.create",
    "connect.instance.update",
    "connect.instance.disable",
    "connect.instance.enable",
    "connect.instance.delete",
  ]);
});

test.describe("a Swedish browser", () => {
  test.use({ locale: "sv-SE" });

  test("shows the connectors, an instance with its last run and the generated form in Swedish", async ({ page, api, signedIn }, testInfo) => {
    expect(signedIn.session.user.name).toBe(ADMIN.name);
    const instance = await createSampleConnector(api, OFFICE, { site: "office", hosts: 3 });
    await runConnector(api, instance.id);
    await expect.poll(async () => (await connectorOf(api, instance.id)).last_run?.observations).toBe(3);

    // The list with the instance and the plugin card.
    await page.goto("/connectors");
    await expect(gridRow(page, "connectors", OFFICE)).toBeVisible();
    await expect(withKey(page.getByTestId("connectors-plugins"), "plugin", "sample")).toBeVisible();
    await expect(cell(gridRow(page, "connectors", OFFICE), "last_run").locator('[data-outcome="succeeded"]')).toBeVisible();
    await expectRendered(page, page.getByTestId("page-connectors"), "sv", testInfo, "connectors");

    // The instance page: process, check, last run, recent runs, settings and configuration.
    await cell(gridRow(page, "connectors", OFFICE), "name").click();
    await expect(page.getByTestId("page-connector")).toHaveAttribute("data-id", instance.id);
    await expect(page.getByTestId("connector-last-run").locator('[data-outcome="succeeded"]')).toBeVisible();
    await expect(page.getByTestId("connector-settings-view").locator('[data-setting="hosts"]')).toHaveText("3");
    await expect(page.getByTestId("connector-run-job").first()).toBeVisible();
    await expectRendered(page, page.getByTestId("page-connector"), "sv", testInfo, "connector");

    // The form with its generated fields; the titles come from the plugin and stay English.
    await page.getByTestId("connector-edit").click();
    const form = page.getByTestId("dialog-connector-form");
    await expect(form.getByTestId("settings-form")).toBeVisible();
    await expect(form.getByTestId("field-settings-hosts")).toHaveValue("3");
    await expectRendered(page, form, "sv", testInfo, "connector-form");
  });
});

test("a secret reference reaches the plugin, which reports it by a tag and never the value", async ({ page, api, signedIn }) => {
  expect(signedIn.session.user.name).toBe(ADMIN.name);
  // Operator secrets need a session of password strength or more (IAM-07): the PIN of the
  // test administrator is raised with an authenticator app first.
  const { authenticator } = await api.enrolTotp();
  await api.logout();
  const raised = await api.signIn(authenticator);
  expect(raised.strength).toBe("password_totp");

  const value = "example-api-key-0f3a9c71-not-real";
  const secret = await api.post<Schemas["OperatorSecretView"]>("/secrets", {
    kind: "api_key",
    name: "Inventory API key",
    tags: ["api_key"],
    value,
  });

  // The form offers the secret for the purpose; the instance keeps the reference.
  await page.goto("/connectors");
  await page.getByTestId("connectors-create").click();
  const form = page.getByTestId("dialog-connector-form");
  await expect(form).toBeVisible();
  await form.getByTestId("field-name").fill(OFFICE);
  await form.getByTestId("field-settings-site").fill("office");
  await form.getByTestId("field-settings-hosts").fill("3");
  const choice = form.getByTestId("connector-secrets").getByTestId("field-secret-api_key");
  await choice.selectOption({ value: secret.id });
  await expect(choice).toHaveValue(secret.id);
  await form.getByTestId("form-submit").click();
  await expect(page.getByTestId("page-connector")).toBeVisible();
  const id = idOfUrl(page);
  const created = await connectorOf(api, id);
  expect(created.secrets).toEqual({ api_key: { secret: secret.id } });
  await expect(withKey(page.getByTestId("connector-config"), "connector-secret", "api_key")).toContainText("Inventory API key");
  await waitForConnectorProcess(api, id, "running");

  // The run injects the secret: every host carries the tag, and the value is nowhere.
  await page.getByTestId("connector-run").click();
  await expect.poll(async () => (await connectorOf(api, id)).last_run?.observations).toBe(3);
  const facts = await hostFacts(api, id, 3);
  for (const fact of facts) {
    expect((fact.observed.data as Schemas["ObservedHost"]).tags).toEqual(expect.arrayContaining(["office", "credential:present"]));
  }
  expect(JSON.stringify(facts)).not.toContain(value);
  expect(JSON.stringify(await connectorOf(api, id))).not.toContain(value);
  await expect(page.getByTestId("page-connector")).not.toContainText(value);

  // The injection is audited with the plugin and the purpose, and the record has no value.
  const log = (await api.get<Schemas["Page_AuditRecord"]>("/audit", { action: "connect.secret.inject", limit: 100 })).items;
  expect(log.length).toBeGreaterThan(0);
  expect(log.map((record) => record.draft.details?.context?.call)).toContain("poll");
  for (const record of log) {
    expect(record.principal).toMatchObject({ kind: "system", component: "connector" });
    expect(record.draft.objects).toEqual(expect.arrayContaining([{ kind: "connector", id }, { kind: "secret", id: secret.id }]));
    expect(record.draft.details?.context).toMatchObject({ plugin: "sample", purposes: "api_key" });
  }
  expect(JSON.stringify(log)).not.toContain(value);
});

// The form is taller than a laptop window: the panel ends inside a 700 px window and scrolls,
// and its submit button is in view at every scroll position (pinned, with the title), where
// before the panel reached past the bottom of the window and the buttons with it.
test("the connector form keeps its submit button in view in a 700 px window and scrolls the fields", async ({ page, signedIn }) => {
  void signedIn;
  await page.setViewportSize({ width: 1280, height: 700 });
  await page.goto("/connectors");
  await page.getByTestId("connectors-create").click();
  const form = page.getByTestId("dialog-connector-form");
  await expect(form).toBeVisible();
  const panel = form.locator("xpath=..");
  const submit = form.getByTestId("form-submit");
  const top = form.getByTestId("field-plugin");
  const box = await panel.boundingBox();
  expect(box, "the panel is laid out").not.toBeNull();
  expect((box?.y ?? 0) + (box?.height ?? 0), "the panel ends inside the window").toBeLessThanOrEqual(700);
  await expect(top).toBeInViewport();
  await expect(submit).toBeInViewport();
  // The panel scrolls (the form is taller than what fits); the button stays while the fields go.
  const overflow = await panel.evaluate((el) => el.scrollHeight - el.clientHeight);
  expect(overflow, "the panel scrolls").toBeGreaterThan(0);
  await panel.evaluate((el) => {
    el.scrollTop = el.scrollHeight;
  });
  await expect(top).not.toBeInViewport();
  await expect(submit).toBeInViewport();
  await panel.evaluate((el) => {
    el.scrollTop = 0;
  });
  await expect(top).toBeInViewport();
  await expect(submit).toBeInViewport();
});
