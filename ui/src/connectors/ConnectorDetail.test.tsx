import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CONNECTOR_IDS, connectorsState, setProcessState, runningProcess } from "../api/mock/connectors-store";
import { server } from "../api/mock/node";
import { SEED_SECRET_IDS } from "../api/mock/secrets-store";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { bridgeMockEvents } from "../audit/testkit";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import ConnectorDetail from "./ConnectorDetail";

const INVENTORY = CONNECTOR_IDS.inventory;
const HOME = CONNECTOR_IDS.controller;
const UNIFI = SEED_SECRET_IDS.unifiApi;
const UNKNOWN = "0190d1c2-0000-7000-8000-00000c0000ff";
const CONTROLLER_URL = "https://controller.example.net:8443";

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

function openDetail(id: string) {
  return renderRoute(ConnectorDetail, { url: `/connectors/${id}`, path: "/connectors/:id" });
}

/** The page for an instance, once the instance and its plugin are loaded. */
async function openLoaded(id: string) {
  const view = openDetail(id);
  const page = await screen.findByTestId("page-connector");
  await within(page).findByTestId("connector-process");
  // The plugin's manifest gives the settings their titles; wait for it.
  await waitFor(() => expect(screen.getByTestId("connector-settings-view").querySelector("dt")).toBeTruthy());
  return { view, page };
}

/** The text of the `dd` that follows the `dt` with the given label. */
function fact(root: HTMLElement, label: string): string | undefined {
  const dt = Array.from(root.querySelectorAll("dt")).find((d) => d.textContent === label);
  return dt?.nextElementSibling?.textContent?.trim();
}

/** The title of the page (the head also holds the plugin and the health in the heading). */
const titleOf = (page: HTMLElement) => page.querySelector("h1")?.firstChild?.textContent;

const toasts = () => screen.queryAllByTestId("toast");
const toastTitles = () => toasts().map((t) => t.querySelector(".t")?.textContent);

const stored = (id: string) => {
  const view = connectorsState().instances.get(id);
  if (!view) throw new Error(`the mock has no instance ${id}`);
  return view;
};

async function callApi(method: string, path: string, json?: unknown): Promise<Response> {
  return fetch(path, {
    method,
    headers: json === undefined ? {} : { "content-type": "application/json" },
    body: json === undefined ? null : JSON.stringify(json),
  });
}

describe("the healthy inventory connector", () => {
  it("shows its title, plugin and health in the head", async () => {
    const { page } = await openLoaded(INVENTORY);
    expect(page.dataset.id).toBe(INVENTORY);
    expect(titleOf(page)).toBe("Lab inventory");
    const head = page.querySelector(".page-head") as HTMLElement;
    await waitFor(() => expect(head.querySelector("h1 .sub")?.textContent).toContain("sample 0.1.0-dev"));
    expect(within(head).getByTestId("connector-health").dataset.health).toBe("healthy");
    expect(within(page).getByRole("link", { name: "Connectors" }).getAttribute("href")).toBe("/connectors");
  });

  it("shows the process: running, its version, the restarts and the last error with its code", async () => {
    const { page } = await openLoaded(INVENTORY);
    const card = within(page).getByTestId("connector-process");
    expect(fact(card, "State")).toContain("Running");
    expect(card.querySelector<HTMLElement>("[data-state]")?.dataset.state).toBe("running");
    expect(fact(card, "Version")).toBe("0.1.0-dev");
    expect(within(card).getByTestId("connector-restarts").textContent).toBe("2");
    expect(within(card).getByTestId("connector-failures").textContent).toBe("0");
    const error = within(card).getByTestId("connector-last-error");
    expect(error.dataset.code).toBe("connect.plugin.exited");
    expect(error.textContent).toContain("The plugin exited during its start.");
    expect(error.textContent).toContain("connect.plugin.exited");
  });

  it("shows the last check of the remote system", async () => {
    const { page } = await openLoaded(INVENTORY);
    const card = within(page).getByTestId("connector-remote");
    const health = Array.from(card.querySelectorAll<HTMLElement>("[data-health]")).find((e) => e.tagName === "DD");
    expect(health?.dataset.health).toBe("healthy");
    expect(health?.textContent).toBe("Healthy");
    expect(fact(card, "Round trip")).toBe("42 ms");
    expect(fact(card, "Remote version")).toBe("0.1.0-dev");
    expect(fact(card, "Detail")).toBeUndefined();
    expect(within(card).queryByTestId("connector-remote-error")).toBeNull();
  });

  it("shows the last run, what it handed on and the link to what the connector reports", async () => {
    const { page } = await openLoaded(INVENTORY);
    const card = within(page).getByTestId("connector-last-run");
    expect(fact(card, "Outcome")).toContain("8 observations");
    expect(card.querySelector<HTMLElement>("[data-outcome]")?.dataset.outcome).toBe("succeeded");
    expect(fact(card, "Started by")).toBe("Schedule");
    expect(fact(card, "Handed on")).toBe("8 observations from 1 page");
    expect(fact(card, "Last success")).toBeTruthy();
    expect(fact(card, "Failed runs in a row")).toBeUndefined();
    expect(fact(card, "Error")).toBeUndefined();
    expect(fact(card, "Job")).toBeUndefined();
    const link = within(card).getByTestId("connector-observations");
    expect(link.getAttribute("href")).toBe(`/discovery/observations?source=${INVENTORY}`);
    expect(link.textContent).toBe("What this connector reports");
  });

  it("shows the settings with the titles of the schema and their values", async () => {
    const { page } = await openLoaded(INVENTORY);
    const card = within(page).getByTestId("connector-settings-view");
    expect(card.querySelector("h2")?.textContent).toBe("Settings");
    const rows = Array.from(card.querySelectorAll("dt")).map((dt) => [dt.textContent, dt.nextElementSibling?.textContent]);
    expect(rows).toEqual([
      ["Site tag", "lab"],
      ["Number of hosts", "8"],
      ["Hosts per page", "50"],
      ["Source address", "https://inventory.example.net"],
    ]);
    expect(card.querySelector("[data-setting='hosts']")?.textContent).toBe("8");
  });

  it("shows the configuration: schedule, guardrail, capabilities, no secret, and what it contacts", async () => {
    const { page } = await openLoaded(INVENTORY);
    const card = within(page).getByTestId("connector-config");
    expect(fact(card, "Poll interval (seconds)")).toBe("300 s (default)");
    expect(fact(card, "Call timeout (seconds)")).toBe("30 s (default)");
    expect(within(card).getByTestId("connector-writes").textContent).toBe("Read only");
    expect(fact(card, "Capabilities")).toBe("inventory");
    expect(within(card).queryByTestId("connector-secret")).toBeNull();
    expect(fact(card, "Created")).toBeTruthy();
    expect(fact(card, "Changed")).toBeTruthy();
    expect(card.querySelector(".plain-list")?.textContent).toContain("https://inventory.example.net");
    expect(card.querySelector(".plain-list")?.textContent).toContain("The inventory source (the sample contacts nothing).");
  });

  it("has no accessibility violations", async () => {
    const { page } = await openLoaded(INVENTORY);
    expect(await axeViolations(page)).toEqual([]);
  });
});

describe("the connector in backoff", () => {
  it("shows a plugin that does not run, with the restarts and when the next start happens", async () => {
    const { page } = await openLoaded(HOME);
    expect(titleOf(page)).toBe("Home network");
    expect(within(page).getAllByTestId("connector-health")[0]?.dataset.health).toBe("failing");
    expect(within(page).getAllByTestId("connector-health")[0]?.textContent).toBe("Not running");
    const card = within(page).getByTestId("connector-process");
    expect(fact(card, "State")).toContain("Restarting after a failure");
    expect(fact(card, "State")).toMatch(/until /);
    expect(card.querySelector<HTMLElement>("[data-state]")?.dataset.state).toBe("backoff");
    expect(fact(card, "Version")).toBeUndefined();
    expect(within(card).getByTestId("connector-restarts").textContent).toBe("5");
    expect(within(card).getByTestId("connector-failures").textContent).toBe("2");
    const error = within(card).getByTestId("connector-last-error");
    expect(error.dataset.code).toBe("connect.plugin.exited");
    expect(error.textContent).toContain("connect.plugin.exited");
  });

  it("shows the degraded remote system with its detail", async () => {
    const { page } = await openLoaded(HOME);
    const card = within(page).getByTestId("connector-remote");
    const health = Array.from(card.querySelectorAll<HTMLElement>("dd[data-health]"))[0];
    expect(health?.dataset.health).toBe("degraded");
    expect(health?.textContent).toBe("Degraded");
    expect(fact(card, "Round trip")).toBe("180 ms");
    expect(fact(card, "Remote version")).toBe("8.1.113");
    expect(fact(card, "Detail")).toBe("The controller answered without the site default.");
  });

  it("shows the failed last run with its error code and the failures in a row", async () => {
    const { page } = await openLoaded(HOME);
    const card = within(page).getByTestId("connector-last-run");
    expect(card.querySelector<HTMLElement>("[data-outcome]")?.dataset.outcome).toBe("failed");
    expect(fact(card, "Outcome")).toContain("Failed");
    expect(fact(card, "Failed runs in a row")).toBe("2");
    expect(fact(card, "Last success")).toBeTruthy();
    expect(fact(card, "Handed on")).toBe("0 observations from 0 pages");
    const error = Array.from(card.querySelectorAll<HTMLElement>("dd[data-code]"))[0];
    expect(error?.dataset.code).toBe("connect.plugin.unavailable");
    expect(error?.textContent).toBe("The plugin is not running at the moment.");
    expect(within(card).getByTestId("connector-observations").getAttribute("href")).toBe(`/discovery/observations?source=${HOME}`);
  });

  it("shows the settings of the controller with titles, yes and no, lists and dashes for what is not set", async () => {
    const { page } = await openLoaded(HOME);
    const card = within(page).getByTestId("connector-settings-view");
    const rows = Object.fromEntries(Array.from(card.querySelectorAll("dt")).map((dt) => [dt.textContent, dt.nextElementSibling?.textContent]));
    expect(rows).toEqual({
      "Controller address": CONTROLLER_URL,
      Site: "default",
      "Verify the TLS certificate": "Yes",
      Mode: "read_only",
      "Clients per page": "100",
      "Timeout factor": "1.5",
      "Management address": "–",
      "DNS name": "–",
      VLANs: "10, 30",
      "Wireless networks": "iot, guest",
    });
  });

  it("shows the secret reference by name with a link to the secret, and never a value", async () => {
    const { page } = await openLoaded(HOME);
    const card = within(page).getByTestId("connector-config");
    await waitFor(() => expect(within(card).getByTestId("connector-secret").textContent).toBe("unifi api"));
    const secret = within(card).getByTestId("connector-secret");
    expect(secret.dataset.key).toBe("api_key");
    expect(within(secret).getByRole("link").getAttribute("href")).toBe(`/secrets/${UNIFI}`);
    expect(secret.previousElementSibling?.textContent).toBe("Secret api_key");
    expect(document.body.textContent).not.toContain("example-api-key");
    expect(fact(card, "Poll interval (seconds)")).toBe("120 s");
    expect(fact(card, "Call timeout (seconds)")).toBe("20 s (default)");
    expect(fact(card, "Capabilities")).toBe("network controller");
    expect(card.querySelector(".plain-list")?.textContent).toContain(`${CONTROLLER_URL} (8443)`);
    expect(card.querySelector(".plain-list")?.textContent).toContain("The controller API.");
  });

  it("shows a secret that this account cannot list as one that it cannot list", async () => {
    await signInWithRole("viewer");
    const { page } = await openLoaded(HOME);
    const secret = await within(page).findByTestId("connector-secret");
    await waitFor(() => expect(secret.textContent).toBe("A secret you cannot list"));
    expect(within(secret).getByRole("link").getAttribute("href")).toBe(`/secrets/${UNIFI}`);
  });
});

describe("run now and check now", () => {
  it("runs the connector, says so with a link to the job, and lists the run", async () => {
    const { view, page } = await openLoaded(INVENTORY);
    expect(page.querySelector("[data-testid='connector-runs']")?.textContent).toContain("No run by hand yet");
    expect(within(page).queryAllByTestId("connector-run-job")).toHaveLength(0);

    fireEvent.click(within(page).getByTestId("connector-run"));
    await waitFor(() => expect(toastTitles()).toEqual(["Started a run of Lab inventory"]));
    expect(toasts()[0]?.dataset.key).toBe("ok");
    const job = stored(INVENTORY).last_run?.job as string;
    expect(job).toBeTruthy();

    // The run is listed with its state, and the last run shows that it was started by hand.
    await waitFor(() => expect(within(page).getAllByTestId("connector-run-job")).toHaveLength(1));
    const item = within(page).getByTestId("connector-run-job");
    expect(item.dataset.id).toBe(job);
    expect(item.textContent).toContain("Run a connector");
    expect(within(item).getByRole("link").getAttribute("href")).toBe(`/jobs/${job}`);
    const card = within(page).getByTestId("connector-last-run");
    await waitFor(() => expect(fact(card, "Started by")).toBe("By hand"));
    const jobLink = within(card).getByRole("link", { name: "Open job" });
    expect(jobLink.getAttribute("href")).toBe(`/jobs/${job}`);

    fireEvent.click(within(toasts()[0] as HTMLElement).getByTestId("toast-action"));
    await waitFor(() => expect(view.location()).toBe(`/jobs/${job}`));
  });

  it("reports a run that cannot start because the plugin does not run", async () => {
    const { page } = await openLoaded(HOME);
    fireEvent.click(within(page).getByTestId("connector-run"));
    await waitFor(() => expect(toastTitles()).toEqual(["Home network did not run"]));
    expect(toasts()[0]?.dataset.key).toBe("bad");
    expect(toasts()[0]?.textContent).toContain("The plugin is not running at the moment.");
    expect(within(page).queryAllByTestId("connector-run-job")).toHaveLength(0);
  });

  it("checks the remote system and reports it", async () => {
    const { page } = await openLoaded(INVENTORY);
    fireEvent.click(within(page).getByTestId("connector-check"));
    await waitFor(() => expect(toastTitles()).toEqual(["Lab inventory: Healthy"]));
    expect(toasts()[0]?.dataset.key).toBe("ok");
  });

  it("reports a check that finds the remote system degraded", async () => {
    setProcessState(HOME, runningProcess("1.4.2"));
    const { page } = await openLoaded(HOME);
    fireEvent.click(within(page).getByTestId("connector-check"));
    await waitFor(() => expect(toastTitles()).toEqual(["Home network: Degraded"]));
    expect(toasts()[0]?.dataset.key).toBe("bad");
    expect(toasts()[0]?.textContent).toContain("The controller answered without the site default.");
  });

  it("answers 503 for the check of a plugin in backoff and shows the failed check on the page", async () => {
    const { page } = await openLoaded(HOME);
    expect(within(page).queryByTestId("connector-remote-error")).toBeNull();
    fireEvent.click(within(page).getByTestId("connector-check"));
    await waitFor(() => expect(toastTitles()).toEqual(["The check of Home network failed"]));
    expect(toasts()[0]?.dataset.key).toBe("bad");
    expect(toasts()[0]?.textContent).toContain("The plugin is not running at the moment.");
    const notice = await within(page).findByTestId("connector-remote-error");
    expect(notice.textContent).toBe("The last check failed: The plugin is not running at the moment.");
  });
});

describe("enabling and disabling", () => {
  it("disables the connector, tells that it does not run, and enables it again", async () => {
    const { page } = await openLoaded(INVENTORY);
    const toggle = within(page).getByTestId("connector-toggle");
    expect(toggle.textContent).toBe("Disable");
    expect(toggle.getAttribute("aria-pressed")).toBe("true");
    expect(within(page).queryByTestId("connector-disabled")).toBeNull();

    fireEvent.click(toggle);
    await waitFor(() => expect(toastTitles()).toEqual(["Disabled Lab inventory"]));
    const notice = await within(page).findByTestId("connector-disabled");
    expect(notice.textContent).toBe("This connector is disabled: it does not run and is not polled.");
    expect(stored(INVENTORY).enabled).toBe(false);
    await waitFor(() => expect(within(page).getAllByTestId("connector-health")[0]?.dataset.health).toBe("off"));
    expect(within(page).getAllByTestId("connector-health")[0]?.textContent).toBe("Disabled");
    expect(fact(within(page).getByTestId("connector-process"), "State")).toBe("Stopped");
    expect(toggle.textContent).toBe("Enable");
    expect(toggle.getAttribute("aria-pressed")).toBe("false");
    // A disabled connector is neither run nor checked.
    expect((within(page).getByTestId("connector-run") as HTMLButtonElement).disabled).toBe(true);
    expect((within(page).getByTestId("connector-check") as HTMLButtonElement).disabled).toBe(true);
    expect(await axeViolations(page)).toEqual([]);

    fireEvent.click(toggle);
    await waitFor(() => expect(toastTitles()).toEqual(["Disabled Lab inventory", "Enabled Lab inventory"]));
    await waitFor(() => expect(within(page).queryByTestId("connector-disabled")).toBeNull());
    expect(stored(INVENTORY).enabled).toBe(true);
    expect((within(page).getByTestId("connector-run") as HTMLButtonElement).disabled).toBe(false);
    expect(toggle.textContent).toBe("Disable");
  });
});

describe("changing", () => {
  it("opens the form with the instance, saves a change and shows it", async () => {
    const { page } = await openLoaded(INVENTORY);
    fireEvent.click(within(page).getByTestId("connector-edit"));
    const form = await screen.findByTestId("dialog-connector-form");
    expect(form.closest("[role='dialog']")?.getAttribute("aria-label")).toBe("Change Lab inventory");
    fireEvent.input(screen.getByTestId("field-name"), { target: { value: "Lab inventory (main)" } });
    fireEvent.input(screen.getByTestId("field-settings-hosts"), { target: { value: "12" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-connector-form")).toBeNull());
    await waitFor(() => expect(titleOf(page)).toBe("Lab inventory (main)"));
    await waitFor(() => expect(within(page).getByTestId("connector-settings-view").querySelector("[data-setting='hosts']")?.textContent).toBe("12"));
    expect(stored(INVENTORY).name).toBe("Lab inventory (main)");
  });

  it("closes the form without a change", async () => {
    const { page } = await openLoaded(INVENTORY);
    fireEvent.click(within(page).getByTestId("connector-edit"));
    const form = await screen.findByTestId("dialog-connector-form");
    fireEvent.click(within(form).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByTestId("dialog-connector-form")).toBeNull());
    expect(titleOf(page)).toBe("Lab inventory");
  });
});

describe("deleting", () => {
  it("asks first, deletes the connector and returns to the list", async () => {
    const { view, page } = await openLoaded(INVENTORY);
    fireEvent.click(within(page).getByTestId("connector-delete"));
    const dialog = await screen.findByTestId("dialog-confirm");
    expect(dialog.getAttribute("aria-label")).toBe("Delete Lab inventory?");
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    await waitFor(() => expect(view.location()).toBe("/connectors"));
    expect(toastTitles()).toEqual(["Deleted Lab inventory"]);
    expect(connectorsState().instances.has(INVENTORY)).toBe(false);
  });

  it("deletes the connector with the live stream on, and goes straight back to the list", async () => {
    stopBridge = bridgeMockEvents();
    const { view, page } = await openLoaded(INVENTORY);
    fireEvent.click(within(page).getByTestId("connector-delete"));
    fireEvent.click(await screen.findByTestId("confirm-ok"));
    await waitFor(() => expect(view.location()).toBe("/connectors"));
    expect(toastTitles()).toEqual(["Deleted Lab inventory"]);
    await new Promise((resolve) => setTimeout(resolve, 400));
    expect(screen.queryByText("The connector does not exist.")).toBeNull();
  });

  it("keeps the connector and the page when the question is declined", async () => {
    const { view, page } = await openLoaded(INVENTORY);
    fireEvent.click(within(page).getByTestId("connector-delete"));
    fireEvent.click(await screen.findByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-confirm")).toBeNull());
    expect(view.location()).toBe(`/connectors/${INVENTORY}`);
    expect(connectorsState().instances.has(INVENTORY)).toBe(true);
    expect(toasts()).toHaveLength(0);
  });

  it("stays on the page and says so when the connector cannot be deleted", async () => {
    const { view, page } = await openLoaded(INVENTORY);
    server.use(
      http.delete("/api/v1/connectors/:id", () =>
        HttpResponse.json({ code: "auth.forbidden", status: 403, title: "Forbidden", detail: "no", params: {} }, { status: 403, headers: { "content-type": "application/problem+json" } }),
      ),
    );
    fireEvent.click(within(page).getByTestId("connector-delete"));
    fireEvent.click(await screen.findByTestId("confirm-ok"));
    await waitFor(() => expect(toastTitles()).toEqual(["Lab inventory was not deleted"]));
    expect(toasts()[0]?.dataset.key).toBe("bad");
    expect(view.location()).toBe(`/connectors/${INVENTORY}`);
    expect(connectorsState().instances.has(INVENTORY)).toBe(true);
  });
});

describe("who may act", () => {
  it("gives an operator every action", async () => {
    await signInWithRole("operator");
    const { page } = await openLoaded(INVENTORY);
    for (const id of ["connector-run", "connector-check", "connector-toggle", "connector-edit", "connector-delete"]) {
      expect((within(page).getByTestId(id) as HTMLButtonElement).disabled, id).toBe(false);
    }
  });

  it("gives a viewer the facts and no action", async () => {
    await signInWithRole("viewer");
    const { page } = await openLoaded(HOME);
    for (const id of ["connector-run", "connector-check", "connector-toggle", "connector-edit", "connector-delete"]) {
      expect(within(page).queryByTestId(id), id).toBeNull();
    }
    expect(within(page).getByTestId("connector-process")).toBeTruthy();
    expect(within(page).getByTestId("connector-settings-view")).toBeTruthy();
    expect(within(page).getByTestId("connector-last-run")).toBeTruthy();
    expect(await axeViolations(page)).toEqual([]);
  });
});

describe("a connector that cannot be shown", () => {
  it("says that the connector does not exist and links back to the list", async () => {
    openDetail(UNKNOWN);
    const page = await screen.findByTestId("page-connector");
    await waitFor(() => expect(page.textContent).toContain("The connector does not exist."));
    expect(within(page).getByRole("alert").textContent).toBe("The connector does not exist.");
    expect(within(page).getByRole("link", { name: "Back to the connectors" }).getAttribute("href")).toBe("/connectors");
    expect(within(page).queryByTestId("connector-process")).toBeNull();
    expect(await axeViolations(page)).toEqual([]);
  });

  it("says what is wrong with an identifier that is no connector's", async () => {
    openDetail("not-an-identifier");
    const page = await screen.findByTestId("page-connector");
    await waitFor(() => expect(within(page).getByRole("alert")).toBeTruthy());
    expect(within(page).getByRole("link", { name: "Back to the connectors" })).toBeTruthy();
  });

  it("shows the page without the recent runs when they cannot be read", async () => {
    server.use(
      http.get("/api/v1/jobs", () =>
        HttpResponse.json({ code: "sys.unavailable", status: 503, title: "Service Unavailable", detail: "busy", params: {} }, { status: 503, headers: { "content-type": "application/problem+json" } }),
      ),
    );
    const { page } = await openLoaded(INVENTORY);
    expect(within(page).getByTestId("connector-runs").textContent).toContain("No run by hand yet");
    expect(within(page).getByTestId("connector-process")).toBeTruthy();
  });

  it("shows the page without the titles of the settings when the plugins cannot be read", async () => {
    server.use(
      http.get("/api/v1/connectors/plugins", () =>
        HttpResponse.json({ code: "sys.unavailable", status: 503, title: "Service Unavailable", detail: "busy", params: {} }, { status: 503, headers: { "content-type": "application/problem+json" } }),
      ),
    );
    const page = await (async () => {
      openDetail(INVENTORY);
      const p = await screen.findByTestId("page-connector");
      await within(p).findByTestId("connector-process");
      return p;
    })();
    await waitFor(() => expect(within(page).getByTestId("connector-settings-view").textContent).toContain("This plugin has no settings."));
    // Without a plugin list the form cannot be offered.
    expect((within(page).getByTestId("connector-edit") as HTMLButtonElement).disabled).toBe(true);
  });
});

describe("live updates", () => {
  it("follows a change made elsewhere", async () => {
    stopBridge = bridgeMockEvents();
    const { page } = await openLoaded(INVENTORY);
    expect((await callApi("PATCH", `/api/v1/connectors/${INVENTORY}`, { name: "Lab inventory (renamed)" })).status).toBe(200);
    await waitFor(() => expect(titleOf(page)).toBe("Lab inventory (renamed)"), { timeout: 3000 });
  });

  it("shows that the connector is disabled when it is disabled elsewhere", async () => {
    stopBridge = bridgeMockEvents();
    const { page } = await openLoaded(INVENTORY);
    expect((await callApi("POST", `/api/v1/connectors/${INVENTORY}/disable`)).status).toBe(200);
    await within(page).findByTestId("connector-disabled", undefined, { timeout: 3000 });
    expect(within(page).getAllByTestId("connector-health")[0]?.dataset.health).toBe("off");
  });

  it("shows the result of a run started elsewhere", async () => {
    stopBridge = bridgeMockEvents();
    const { page } = await openLoaded(INVENTORY);
    expect((await callApi("POST", `/api/v1/connectors/${INVENTORY}/run`)).status).toBe(202);
    const card = within(page).getByTestId("connector-last-run");
    await waitFor(() => expect(fact(card, "Started by")).toBe("By hand"), { timeout: 3000 });
    await waitFor(() => expect(within(page).getAllByTestId("connector-run-job")).toHaveLength(1), { timeout: 3000 });
  });

  it("shows that the connector is gone when it is deleted elsewhere", async () => {
    stopBridge = bridgeMockEvents();
    const { page } = await openLoaded(INVENTORY);
    expect((await callApi("DELETE", `/api/v1/connectors/${INVENTORY}`)).status).toBe(204);
    await waitFor(() => expect(page.textContent).toContain("The connector does not exist."), { timeout: 3000 });
    expect(within(page).getByRole("link", { name: "Back to the connectors" })).toBeTruthy();
  });
});
