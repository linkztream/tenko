import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api } from "../api/client";
import {
  CONNECTOR_IDS,
  PLUGIN_NAMES,
  connectorsState,
  runningProcess,
  seedPlugin,
  setProcessState,
  type PluginInfo,
} from "../api/mock/connectors-store";
import { server } from "../api/mock/node";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { bridgeMockEvents } from "../audit/testkit";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import ConnectorsView from "./ConnectorsView";

const INVENTORY = CONNECTOR_IDS.inventory;
const HOME = CONNECTOR_IDS.controller;

let stopBridge: (() => void) | undefined;

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  stopBridge?.();
  stopBridge = undefined;
  setSessionForTest(null);
});

async function signInWithRole(role: "operator" | "viewer") {
  await signInAlex({
    prepare: (user) => {
      user.roles = [role];
    },
  });
}

function openConnectors() {
  return renderRoute(ConnectorsView, { url: "/connectors", path: "/connectors" });
}

/** The page with both instances and both plugins listed. */
async function openLoaded() {
  const view = openConnectors();
  await listed(2);
  await screen.findAllByTestId("plugin");
  return view;
}

const rows = () => screen.queryAllByTestId("row");
const names = () => rows().map((r) => r.dataset.key);
const cards = () => screen.queryAllByTestId("plugin");

async function listed(count: number) {
  await waitFor(() => expect(rows()).toHaveLength(count));
}

function rowOf(name: string): HTMLElement {
  const row = rows().find((r) => r.dataset.key === name);
  if (!row) throw new Error(`no row for ${name}`);
  return row;
}

function cellOf(row: HTMLElement, column: string): HTMLElement {
  const cell = row.querySelector<HTMLElement>(`[data-col="${column}"]`);
  if (!cell) throw new Error(`no ${column} cell`);
  return cell;
}

function cardOf(name: string): HTMLElement {
  const card = cards().find((c) => c.dataset.key === name);
  if (!card) throw new Error(`no plugin card for ${name}`);
  return card;
}

/** Opens the row menu of an instance. */
async function openMenu(name: string): Promise<HTMLElement> {
  fireEvent.click(within(rowOf(name)).getByRole("button", { name: `Actions for ${name}` }));
  return screen.findByTestId("row-menu");
}

async function chooseAction(name: string, label: string) {
  const menu = await openMenu(name);
  fireEvent.click(within(menu).getByRole("menuitem", { name: label }));
}

const toasts = () => screen.queryAllByTestId("toast");
const toastTitles = () => toasts().map((t) => t.querySelector(".t")?.textContent);

function fill(testid: string, value: string) {
  fireEvent.input(screen.getByTestId(testid), { target: { value } });
}

async function callApi(method: string, path: string, json?: unknown): Promise<Response> {
  return fetch(path, {
    method,
    headers: json === undefined ? {} : { "content-type": "application/json" },
    body: json === undefined ? null : JSON.stringify(json),
  });
}

const instance = (id: string) => {
  const view = connectorsState().instances.get(id);
  if (!view) throw new Error(`the mock has no instance ${id}`);
  return view;
};

/** A plugin whose manifest is fine but that cannot run on this node. */
function unusablePlugin(): PluginInfo {
  const sample = connectorsState().plugins.get(PLUGIN_NAMES.sample);
  return {
    name: "legacy-hub",
    source: "installed",
    usable: false,
    problems: [
      { path: "/protocol", message: "the plugin speaks protocol 3 only; this host speaks 1" },
      { path: "", message: "the manifest cannot be used" },
    ],
    manifest: { ...(sample?.manifest as NonNullable<PluginInfo["manifest"]>), name: "legacy-hub", version: "3.0.0", description: "A hub plugin for a newer host." },
  };
}

describe("the instances", () => {
  it("lists both instances with plugin, health, process, last run, interval and writes", async () => {
    openConnectors();
    await listed(2);
    expect(screen.getByTestId("page-connectors")).toBeTruthy();
    expect(screen.getByTestId("grid-connectors")).toBeTruthy();
    expect(names()).toEqual(["Home network", "Lab inventory"]);

    const lab = rowOf("Lab inventory");
    expect(lab.dataset.id).toBe(INVENTORY);
    expect(within(cellOf(lab, "name")).getByRole("link").getAttribute("href")).toBe(`/connectors/${INVENTORY}`);
    expect(cellOf(lab, "plugin").textContent).toContain("sample");
    await waitFor(() => expect(cellOf(lab, "plugin").textContent).toBe("sample 0.1.0-dev"));
    const labHealth = within(cellOf(lab, "health")).getByTestId("connector-health");
    expect(labHealth.dataset.health).toBe("healthy");
    expect(labHealth.textContent).toBe("Healthy");
    expect(within(cellOf(lab, "process")).getByText("Running")).toBeTruthy();
    expect(cellOf(lab, "process").querySelector<HTMLElement>("[data-state]")?.dataset.state).toBe("running");
    const labRun = cellOf(lab, "last_run").querySelector<HTMLElement>("[data-outcome]");
    expect(labRun?.dataset.outcome).toBe("succeeded");
    expect(labRun?.textContent).toContain("8 observations");
    expect(cellOf(lab, "poll").textContent).toBe("300 s (default)");
    expect(cellOf(lab, "writes").textContent).toBe("Read only");

    const home = rowOf("Home network");
    expect(home.dataset.id).toBe(HOME);
    await waitFor(() => expect(cellOf(home, "plugin").textContent).toBe("lab-controller 1.4.2"));
    const homeHealth = within(cellOf(home, "health")).getByTestId("connector-health");
    expect(homeHealth.dataset.health).toBe("failing");
    expect(homeHealth.textContent).toBe("Not running");
    const process = cellOf(home, "process");
    expect(process.querySelector<HTMLElement>("[data-state]")?.dataset.state).toBe("backoff");
    expect(process.textContent).toContain("Restarting after a failure");
    expect(process.textContent).toMatch(/until /);
    const homeRun = cellOf(home, "last_run").querySelector<HTMLElement>("[data-outcome]");
    expect(homeRun?.dataset.outcome).toBe("failed");
    expect(homeRun?.textContent).toContain("Failed");
    expect(cellOf(home, "poll").textContent).toBe("120 s");
    expect(home.classList.contains("health-failing")).toBe(true);
    expect(lab.classList.contains("health-healthy")).toBe(true);
    expect(screen.getByTestId("grid-foot").textContent).toContain("2");
  });

  it("shows an instance that was never run, and a disabled one", async () => {
    const created = await callApi("POST", "/api/v1/connectors", { name: "Spare", plugin: "sample", enabled: false });
    expect(created.status).toBe(201);
    openConnectors();
    await listed(3);
    const spare = rowOf("Spare");
    expect(cellOf(spare, "last_run").textContent).toBe("Not run yet");
    expect(within(cellOf(spare, "health")).getByTestId("connector-health").dataset.health).toBe("off");
    expect(cellOf(spare, "health").textContent).toBe("Disabled");
    expect(cellOf(spare, "process").textContent).toContain("Stopped");
  });

  it("shows a write-enabled instance with the guardrail marked", async () => {
    const view = instance(HOME);
    view.writes_enabled = true;
    openConnectors();
    await listed(2);
    const writes = cellOf(rowOf("Home network"), "writes");
    expect(writes.textContent).toBe("Allowed");
    expect(writes.querySelector("svg")).toBeTruthy();
  });

  it("says so when there is no instance", async () => {
    connectorsState().instances.clear();
    openConnectors();
    const empty = await screen.findByTestId("connectors-empty");
    expect(empty.textContent).toContain("No connector yet");
    expect(empty.textContent).toContain("Create one from a plugin below.");
  });

  it("opens an instance with a click on its row, with Enter and with the menu", async () => {
    const view = await openLoaded();
    fireEvent.click(cellOf(rowOf("Lab inventory"), "process"));
    await waitFor(() => expect(view.location()).toBe(`/connectors/${INVENTORY}`));

    view.history.set({ value: "/connectors" });
    await listed(2);
    const grid = screen.getByRole("grid", { name: "Instances" });
    fireEvent.focus(grid);
    // The focus starts on the first row, Home network.
    fireEvent.keyDown(grid, { key: "Enter" });
    await waitFor(() => expect(view.location()).toBe(`/connectors/${HOME}`));

    view.history.set({ value: "/connectors" });
    await listed(2);
    await chooseAction("Lab inventory", "Open");
    await waitFor(() => expect(view.location()).toBe(`/connectors/${INVENTORY}`));
  });

  it("has no accessibility violations", async () => {
    const view = await openLoaded();
    expect(await axeViolations(view.container)).toEqual([]);
  });
});

describe("the plugins", () => {
  it("shows both plugins from their manifests, the bundled one first", async () => {
    openConnectors();
    await screen.findAllByTestId("plugin");
    expect(cards().map((c) => c.dataset.key)).toEqual(["sample", "lab-controller"]);
    expect(screen.getByTestId("connectors-plugins")).toBeTruthy();

    const sample = cardOf("sample");
    expect(sample.dataset.usable).toBe("true");
    expect(sample.querySelector("h3")?.textContent).toBe("sample 0.1.0-dev");
    expect(sample.textContent).toContain("Bundled");
    expect(sample.textContent).toContain("Sample inventory source that reports documentation data");
    const sampleFacts = sample.querySelector("dl")?.textContent ?? "";
    expect(sampleFacts).toContain("Capabilitiesinventory");
    expect(sampleFacts).toContain("Platformsany");
    expect(sampleFacts).toContain("Secretsapi_key");
    expect(sampleFacts).toContain("LicenceLicenseRef-Proprietary");
    expect(within(sample).queryByTestId("plugin-unusable")).toBeNull();
    expect(within(sample).queryByRole("link")).toBeNull();

    const controller = cardOf("lab-controller");
    expect(controller.dataset.usable).toBe("true");
    expect(controller.querySelector("h3")?.textContent).toBe("lab-controller 1.4.2");
    expect(controller.textContent).toContain("Installed");
    const facts = controller.querySelector("dl")?.textContent ?? "";
    expect(facts).toContain("Capabilitiesnetwork controller");
    expect(facts).toContain("Platformsany");
    expect(facts).toContain("Secretsapi_key, password");
    expect(facts).toContain("LicenceApache-2.0");
    const home = within(controller).getByRole("link", { name: "https://example.org/tenko-lab-controller" });
    expect(home.getAttribute("href")).toBe("https://example.org/tenko-lab-controller");
    expect(home.getAttribute("target")).toBe("_blank");
    expect(home.getAttribute("rel")).toContain("noopener");
  });

  it("marks a plugin that cannot run here and lists what is wrong with it", async () => {
    seedPlugin(unusablePlugin());
    openConnectors();
    await waitFor(() => expect(cards()).toHaveLength(3));
    const card = cardOf("legacy-hub");
    expect(card.dataset.usable).toBe("false");
    const mark = within(card).getByTestId("plugin-unusable");
    expect(mark.textContent).toBe("Cannot run here");
    expect(mark.classList.contains("discrepancy")).toBe(true);
    const problems = Array.from(card.querySelectorAll(".plugin-problems li")).map((li) => li.textContent);
    expect(problems).toEqual(["/protocol the plugin speaks protocol 3 only; this host speaks 1", "/ the manifest cannot be used"]);
    expect(within(cardOf("sample")).queryByTestId("plugin-unusable")).toBeNull();
    expect(screen.getAllByTestId("plugin-unusable")).toHaveLength(1);
  });

  it("shows a plugin without a manifest by its name", async () => {
    seedPlugin({ name: "broken-plugin", source: "installed", usable: false, problems: [{ path: "", message: "the manifest is not valid JSON" }], manifest: null });
    openConnectors();
    await waitFor(() => expect(cards()).toHaveLength(3));
    const card = cardOf("broken-plugin");
    expect(card.querySelector("h3")?.textContent?.trim()).toBe("broken-plugin");
    expect(within(card).getByTestId("plugin-unusable")).toBeTruthy();
    expect(card.querySelector("dl")).toBeNull();
    expect(card.textContent).toContain("the manifest is not valid JSON");
  });

  it("reads the plugins again on request", async () => {
    openConnectors();
    await waitFor(() => expect(cards()).toHaveLength(2));
    seedPlugin(unusablePlugin());
    fireEvent.click(screen.getByRole("button", { name: "Read again" }));
    await waitFor(() => expect(cards()).toHaveLength(3));
  });

  it("says so when no plugin is installed", async () => {
    connectorsState().plugins.clear();
    openConnectors();
    await waitFor(() => expect(screen.getByTestId("connectors-plugins").textContent).toContain("No plugin is installed."));
    expect(cards()).toHaveLength(0);
  });

  it("shows the error when the plugins cannot be read, and keeps the instances", async () => {
    server.use(
      http.get("/api/v1/connectors/plugins", () =>
        HttpResponse.json({ code: "sys.unavailable", status: 503, title: "Service Unavailable", detail: "the host is busy", params: {} }, { status: 503, headers: { "content-type": "application/problem+json" } }),
      ),
    );
    openConnectors();
    await listed(2);
    const section = screen.getByTestId("connectors-plugins");
    await waitFor(() => expect(section.querySelector("[role='alert']")).toBeTruthy());
    expect(cards()).toHaveLength(0);
    // Nothing can be created without a plugin list.
    expect((screen.getByTestId("connectors-create") as HTMLButtonElement).disabled).toBe(true);
  });
});

describe("creating an instance", () => {
  it("creates an instance of the sample plugin and opens it", async () => {
    const view = openConnectors();
    await listed(2);
    const button = screen.getByTestId("connectors-create") as HTMLButtonElement;
    await waitFor(() => expect(button.disabled).toBe(false));
    fireEvent.click(button);
    const form = await screen.findByTestId("dialog-connector-form");
    expect((screen.getByTestId("field-plugin") as HTMLSelectElement).value).toBe("sample");
    fill("field-name", "Branch inventory");
    fill("field-settings-hosts", "12");
    fireEvent.click(within(form).getByTestId("form-submit"));

    await waitFor(() => expect(view.location()).toMatch(/^\/connectors\/[0-9a-f-]{36}$/));
    const stored = [...connectorsState().instances.values()].find((c) => c.name === "Branch inventory");
    expect(stored?.plugin).toBe("sample");
    expect(stored?.enabled).toBe(true);
    expect(stored?.writes_enabled).toBe(false);
    expect(stored?.settings).toEqual({ site: "lab", hosts: 12, page_size: 50, endpoint: "https://inventory.example.net" });
    expect(stored?.secrets).toEqual({});
    expect(view.location()).toBe(`/connectors/${stored?.id}`);
    expect(screen.queryByTestId("dialog-connector-form")).toBeNull();
  });

  it("does not offer a plugin that cannot run here", async () => {
    seedPlugin(unusablePlugin());
    openConnectors();
    await waitFor(() => expect(cards()).toHaveLength(3));
    fireEvent.click(screen.getByTestId("connectors-create"));
    const select = (await screen.findByTestId("field-plugin")) as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.value)).toEqual(["sample", "lab-controller"]);
    expect(select.textContent).not.toContain("legacy-hub");
  });

  it("lets an operator create an instance that needs no secret", async () => {
    await signInWithRole("operator");
    const view = openConnectors();
    await listed(2);
    const button = screen.getByTestId("connectors-create") as HTMLButtonElement;
    await waitFor(() => expect(button.disabled).toBe(false));
    fireEvent.click(button);
    const form = await screen.findByTestId("dialog-connector-form");
    fill("field-name", "Operator inventory");
    fireEvent.click(within(form).getByTestId("form-submit"));
    await waitFor(() => expect(view.location()).toMatch(/^\/connectors\/[0-9a-f-]{36}$/));
    expect([...connectorsState().instances.values()].some((c) => c.name === "Operator inventory")).toBe(true);
  });

  it("shows no create button to a viewer, and offers only to open an instance", async () => {
    await signInWithRole("viewer");
    openConnectors();
    await listed(2);
    expect(screen.queryByTestId("connectors-create")).toBeNull();
    const menu = await openMenu("Lab inventory");
    const items = within(menu).getAllByRole("menuitem");
    expect(items.map((i) => i.textContent)).toEqual(["Open", "Run now", "Check now", "Enable or disable", "Change", "Delete"]);
    expect(items.map((i) => i.getAttribute("aria-disabled"))).toEqual([null, "true", "true", "true", "true", "true"]);
    // A click on a disabled action does nothing.
    fireEvent.click(within(menu).getByRole("menuitem", { name: "Delete" }));
    expect(screen.queryByTestId("dialog-confirm")).toBeNull();
    expect(instance(INVENTORY).enabled).toBe(true);
  });
});

describe("the actions on an instance", () => {
  it("runs a connector now, says so and offers the job", async () => {
    const view = await openLoaded();
    await chooseAction("Lab inventory", "Run now");
    await waitFor(() => expect(toastTitles()).toEqual(["Started a run of Lab inventory"]));
    expect(toasts()[0]?.dataset.key).toBe("ok");
    expect(instance(INVENTORY).last_run?.trigger).toBe("manual");
    const job = instance(INVENTORY).last_run?.job;
    expect(job).toBeTruthy();
    fireEvent.click(within(toasts()[0] as HTMLElement).getByTestId("toast-action"));
    await waitFor(() => expect(view.location()).toBe(`/jobs/${job}`));
  });

  it("reports a run that cannot start because the plugin is not running", async () => {
    await openLoaded();
    await chooseAction("Home network", "Run now");
    await waitFor(() => expect(toastTitles()).toEqual(["Home network did not run"]));
    expect(toasts()[0]?.dataset.key).toBe("bad");
    expect(toasts()[0]?.textContent).toContain("The plugin is not running at the moment.");
    expect(instance(HOME).last_run?.trigger).toBe("schedule");
  });

  it("checks a connector now and reports the health of the remote system", async () => {
    await openLoaded();
    await chooseAction("Lab inventory", "Check now");
    await waitFor(() => expect(toastTitles()).toEqual(["Lab inventory: Healthy"]));
    expect(toasts()[0]?.dataset.key).toBe("ok");
  });

  it("reports a degraded remote system as a problem, with the detail", async () => {
    setProcessState(HOME, runningProcess("1.4.2"));
    await openLoaded();
    await chooseAction("Home network", "Check now");
    await waitFor(() => expect(toastTitles()).toEqual(["Home network: Degraded"]));
    expect(toasts()[0]?.dataset.key).toBe("bad");
    expect(toasts()[0]?.textContent).toContain("The controller answered without the site default.");
  });

  it("reports a check of a plugin that is not running", async () => {
    await openLoaded();
    await chooseAction("Home network", "Check now");
    await waitFor(() => expect(toastTitles()).toEqual(["The check of Home network failed"]));
    expect(toasts()[0]?.dataset.key).toBe("bad");
    expect(toasts()[0]?.textContent).toContain("The plugin is not running at the moment.");
  });

  it("disables and enables a connector", async () => {
    await openLoaded();
    await chooseAction("Lab inventory", "Enable or disable");
    await waitFor(() => expect(toastTitles()).toEqual(["Disabled Lab inventory"]));
    expect(instance(INVENTORY).enabled).toBe(false);
    await waitFor(() => expect(within(cellOf(rowOf("Lab inventory"), "health")).getByTestId("connector-health").dataset.health).toBe("off"));
    expect(cellOf(rowOf("Lab inventory"), "process").textContent).toContain("Stopped");

    // A disabled connector is neither run nor checked.
    const menu = await openMenu("Lab inventory");
    const state = (label: string) => within(menu).getByRole("menuitem", { name: label }).getAttribute("aria-disabled");
    expect(state("Run now")).toBe("true");
    expect(state("Check now")).toBe("true");
    expect(state("Enable or disable")).toBeNull();
    fireEvent.click(within(menu).getByRole("menuitem", { name: "Enable or disable" }));

    await waitFor(() => expect(toastTitles()).toEqual(["Disabled Lab inventory", "Enabled Lab inventory"]));
    expect(instance(INVENTORY).enabled).toBe(true);
    await waitFor(() => expect(within(cellOf(rowOf("Lab inventory"), "health")).getByTestId("connector-health").dataset.health).toBe("healthy"));
  });

  it("restarts the plugin of a connector in backoff when it is disabled and enabled again", async () => {
    await openLoaded();
    await chooseAction("Home network", "Enable or disable");
    // The connector is enabled, so the action disables it; enabling it again starts the plugin anew.
    await waitFor(() => expect(toastTitles()).toEqual(["Disabled Home network"]));
    await waitFor(() => expect(within(cellOf(rowOf("Home network"), "health")).getByTestId("connector-health").dataset.health).toBe("off"));
    await chooseAction("Home network", "Enable or disable");
    await waitFor(() => expect(toastTitles()).toEqual(["Disabled Home network", "Enabled Home network"]));
    await waitFor(() => expect(within(cellOf(rowOf("Home network"), "health")).getByTestId("connector-health").dataset.health).not.toBe("off"));
    expect(instance(HOME).health.process.state).toBe("running");
  });

  it("deletes a connector after asking, and says so", async () => {
    await openLoaded();
    await chooseAction("Lab inventory", "Delete");
    const dialog = await screen.findByTestId("dialog-confirm");
    expect(dialog.getAttribute("aria-label")).toBe("Delete Lab inventory?");
    expect(dialog.textContent).toContain("nothing in IPAM changes");
    expect(within(dialog).getByTestId("confirm-ok").textContent).toBe("Delete connector");
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    await waitFor(() => expect(names()).toEqual(["Home network"]));
    expect(toastTitles()).toEqual(["Deleted Lab inventory"]);
    expect(connectorsState().instances.has(INVENTORY)).toBe(false);
  });

  it("keeps the connector when the question is declined", async () => {
    await openLoaded();
    await chooseAction("Home network", "Delete");
    fireEvent.click(await screen.findByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-confirm")).toBeNull());
    expect(names()).toEqual(["Home network", "Lab inventory"]);
    expect(connectorsState().instances.has(HOME)).toBe(true);
    expect(toasts()).toHaveLength(0);
  });

  it("reports a connector that is gone already", async () => {
    await openLoaded();
    await chooseAction("Lab inventory", "Delete");
    const confirm = await screen.findByTestId("confirm-ok");
    expect((await callApi("DELETE", `/api/v1/connectors/${INVENTORY}`)).status).toBe(204);
    fireEvent.click(confirm);
    await waitFor(() => expect(toastTitles()).toEqual(["Lab inventory was not deleted"]));
    expect(toasts()[0]?.dataset.key).toBe("bad");
    expect(toasts()[0]?.textContent).toContain("The connector does not exist.");
  });

  it("opens the form to change an instance from the menu", async () => {
    openConnectors();
    await listed(2);
    await waitFor(() => expect(cellOf(rowOf("Lab inventory"), "plugin").textContent).toBe("sample 0.1.0-dev"));
    await chooseAction("Lab inventory", "Change");
    const form = await screen.findByTestId("dialog-connector-form");
    expect(form.closest("[role='dialog']")?.getAttribute("aria-label")).toBe("Change Lab inventory");
    expect((screen.getByTestId("field-name") as HTMLInputElement).value).toBe("Lab inventory");
    expect(screen.queryByTestId("field-plugin")).toBeNull();
    fireEvent.click(within(form).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByTestId("dialog-connector-form")).toBeNull());
  });

  it("changes an instance from the menu and shows the change in the list", async () => {
    openConnectors();
    await listed(2);
    await waitFor(() => expect(cellOf(rowOf("Lab inventory"), "plugin").textContent).toBe("sample 0.1.0-dev"));
    await chooseAction("Lab inventory", "Change");
    const form = await screen.findByTestId("dialog-connector-form");
    fill("field-name", "Lab inventory (main)");
    fill("field-poll_interval", "600");
    fireEvent.click(within(form).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-connector-form")).toBeNull());
    await waitFor(() => expect(names()).toEqual(["Home network", "Lab inventory (main)"]));
    expect(cellOf(rowOf("Lab inventory (main)"), "poll").textContent).toBe("600 s");
  });
});

describe("live updates", () => {
  it("follows a connector that is disabled through the API", async () => {
    stopBridge = bridgeMockEvents();
    await openLoaded();
    expect(within(cellOf(rowOf("Lab inventory"), "health")).getByTestId("connector-health").dataset.health).toBe("healthy");
    expect((await callApi("POST", `/api/v1/connectors/${INVENTORY}/disable`)).status).toBe(200);
    await waitFor(() => expect(within(cellOf(rowOf("Lab inventory"), "health")).getByTestId("connector-health").dataset.health).toBe("off"), { timeout: 3000 });
  });

  it("lists a connector that is created through the API and drops one that is deleted", async () => {
    stopBridge = bridgeMockEvents();
    await openLoaded();
    expect((await callApi("POST", "/api/v1/connectors", { name: "Annex inventory", plugin: "sample" })).status).toBe(201);
    await waitFor(() => expect(names()).toEqual(["Annex inventory", "Home network", "Lab inventory"]), { timeout: 3000 });
    expect((await callApi("DELETE", `/api/v1/connectors/${HOME}`)).status).toBe(204);
    await waitFor(() => expect(names()).toEqual(["Annex inventory", "Lab inventory"]), { timeout: 3000 });
  });

  it("shows the result of a run that is started elsewhere", async () => {
    stopBridge = bridgeMockEvents();
    await openLoaded();
    const before = cellOf(rowOf("Lab inventory"), "last_run").textContent;
    await api.post("/api/v1/connectors/{id}/run", { path: { id: INVENTORY } });
    await waitFor(() => expect(instance(INVENTORY).last_run?.trigger).toBe("manual"));
    await waitFor(() => expect(cellOf(rowOf("Lab inventory"), "last_run").textContent).not.toBe(before), { timeout: 3000 });
  });
});
