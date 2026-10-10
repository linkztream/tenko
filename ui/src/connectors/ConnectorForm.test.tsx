import { cleanup, fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CONNECTOR_IDS, connectorsState, type PluginInfo } from "../api/mock/connectors-store";
import { server } from "../api/mock/node";
import { SEED_SECRET_IDS, dropSecret, seedSecret } from "../api/mock/secrets-store";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { getConnector, listPlugins, updateConnector, type ConnectorView } from "./api";
import { ConnectorForm } from "./ConnectorForm";

const INVENTORY = CONNECTOR_IDS.inventory;
const HOME = CONNECTOR_IDS.controller;
const UNIFI = SEED_SECRET_IDS.unifiApi;
const NAS = SEED_SECRET_IDS.nasAdmin;
const CONTROLLER_URL = "https://controller.example.net:8443";

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  setSessionForTest(null);
});

async function signInWithRole(role: "operator" | "viewer") {
  await signInAlex({
    prepare: (user) => {
      user.roles = [role];
    },
  });
}

interface Mounted {
  form: HTMLElement;
  onDone: ReturnType<typeof vi.fn<(view: ConnectorView) => void>>;
  onClose: ReturnType<typeof vi.fn<() => void>>;
}

/** The form over the plugins of the mock, creating an instance or changing `connector`. */
async function mountForm(options: { connector?: ConnectorView; plugins?: PluginInfo[] } = {}): Promise<Mounted> {
  const plugins = options.plugins ?? (await listPlugins());
  const onDone = vi.fn<(view: ConnectorView) => void>();
  const onClose = vi.fn<() => void>();
  renderRoute(() => <ConnectorForm plugins={plugins} connector={options.connector} onDone={onDone} onClose={onClose} />, { url: "/" });
  const form = await screen.findByTestId("dialog-connector-form");
  return { form, onDone, onClose };
}

/** The form for changing an instance of the mock; an earlier form of the test is closed first. */
async function mountEdit(id: string): Promise<Mounted & { connector: ConnectorView }> {
  cleanup();
  const connector = await getConnector(id);
  const mounted = await mountForm({ connector });
  return { ...mounted, connector };
}

const input = (testid: string) => screen.getByTestId(testid) as HTMLInputElement;
const select = (testid: string) => screen.getByTestId(testid) as HTMLSelectElement;
const optionLabels = (el: HTMLSelectElement) => Array.from(el.options).map((o) => o.textContent);

function fill(testid: string, value: string) {
  fireEvent.input(screen.getByTestId(testid), { target: { value } });
}

function pick(testid: string, value: string) {
  fireEvent.change(screen.getByTestId(testid), { target: { value } });
}

function submit(form: HTMLElement) {
  fireEvent.click(within(form).getByTestId("form-submit"));
}

/** The error line under a control (the `field-error` with the error glyph), or undefined. */
function noteOf(testid: string): string | undefined {
  const field = screen.getByTestId(testid).closest(".field");
  return field?.querySelector<HTMLElement>("[data-testid='field-error']")?.textContent?.trim();
}

/** The `data-field` of the error line under a control, or undefined. */
function noteFieldOf(testid: string): string | undefined {
  const field = screen.getByTestId(testid).closest(".field");
  return field?.querySelector<HTMLElement>("[data-testid='field-error']")?.getAttribute("data-field") ?? undefined;
}

const alerts = (form: HTMLElement) => within(form).queryAllByRole("alert").map((a) => a.textContent?.trim());

/** The secret choices are read when the form opens; waits until the select lists them. */
async function secretsListed(testid = "field-secret-api_key") {
  await waitFor(() => expect(select(testid).options.length).toBeGreaterThan(1));
}

interface Seen {
  method: string;
  body: Record<string, unknown> | null;
}

/** The writes the form sends to the connector endpoints; the mock still answers. */
function recordWrites(): Seen[] {
  const seen: Seen[] = [];
  const record = (method: string) => async ({ request }: { request: Request }) => {
    seen.push({ method, body: (await request.clone().json().catch(() => null)) as Record<string, unknown> | null });
    return undefined;
  };
  server.use(http.post("/api/v1/connectors", record("POST")), http.patch("/api/v1/connectors/:id", record("PATCH")));
  return seen;
}

const stored = (id: string) => {
  const view = connectorsState().instances.get(id);
  if (!view) throw new Error(`the mock has no instance ${id}`);
  return view;
};

const storedNamed = (name: string) => [...connectorsState().instances.values()].find((c) => c.name === name);

/** Chooses the lab-controller plugin and fills what it needs to be valid (as an administrator). */
function fillController(name: string) {
  pick("field-plugin", "lab-controller");
  fill("field-name", name);
  fill("field-settings-url", CONTROLLER_URL);
  pick("field-secret-api_key", UNIFI);
}

describe("creating: the first look", () => {
  it("opens on the first usable plugin with its defaults, its secrets and its guardrails", async () => {
    const { form } = await mountForm();
    expect(form.closest("[role='dialog']")?.getAttribute("aria-label")).toBe("New connector");
    expect(form.querySelector("h2")?.textContent).toBe("New connector");
    expect(select("field-plugin").value).toBe("sample");
    expect(optionLabels(select("field-plugin"))).toEqual(["sample 0.1.0-dev", "lab-controller 1.4.2"]);
    expect(form.querySelector(".connector-form-about")?.textContent).toContain("Sample inventory source that reports documentation data");
    expect(form.querySelector(".connector-form-about .caps")?.textContent).toBe("inventory");

    expect(input("field-name").value).toBe("");
    expect(input("field-settings-site").value).toBe("lab");
    expect(input("field-settings-hosts").value).toBe("8");
    expect(input("field-settings-page_size").value).toBe("50");
    expect(input("field-settings-endpoint").value).toBe("https://inventory.example.net");

    expect(input("field-poll_interval").value).toBe("");
    expect(input("field-poll_interval").placeholder).toBe("300");
    expect(input("field-call_timeout").placeholder).toBe("30");
    expect(screen.getByTestId("field-poll_interval").closest(".field")?.textContent).toContain("Empty: the plugin default, 300 s.");

    expect(select("field-secret-api_key")).toBeTruthy();
    expect(screen.getByLabelText("Secret api_key")).toBe(select("field-secret-api_key"));
    expect(input("field-enabled").checked).toBe(true);
    expect(within(form).getByTestId("form-submit").textContent).toBe("Create connector");
    expect(within(form).getByTestId("connector-settings")).toBeTruthy();
    // The network target comes from the setting that names it.
    expect(form.querySelector(".connector-targets")?.textContent).toContain("https://inventory.example.net");
    expect(await axeViolations(form)).toEqual([]);
  });

  it("opens with the defaults of the schema for a plugin that has them in the manifest", async () => {
    const { form } = await mountForm();
    pick("field-plugin", "lab-controller");
    expect(input("field-poll_interval").placeholder).toBe("120");
    expect(input("field-call_timeout").placeholder).toBe("20");
    expect(screen.getByTestId("field-poll_interval").closest(".field")?.textContent).toContain("Empty: the plugin default, 120 s.");
    expect(form.querySelector(".connector-targets")?.textContent).toContain("(8443)");
  });

  it("says so, and cannot submit, when no plugin can run here", async () => {
    const { form } = await mountForm({ plugins: [] });
    expect(form.textContent).toContain("No plugin can run on this node.");
    expect(screen.queryByTestId("field-plugin")).toBeNull();
    expect((within(form).getByTestId("form-submit") as HTMLButtonElement).disabled).toBe(true);
  });
});

describe("creating: the choice of the plugin", () => {
  it("resets the settings to the defaults of the new schema, and back again", async () => {
    await mountForm();
    fill("field-settings-site", "annex");
    fill("field-settings-hosts", "99");
    pick("field-plugin", "lab-controller");
    expect(select("field-plugin").value).toBe("lab-controller");

    expect(screen.queryByTestId("field-settings-hosts")).toBeNull();
    expect(input("field-settings-url").value).toBe("");
    expect(input("field-settings-site").value).toBe("default");
    expect(input("field-settings-verify_tls").checked).toBe(true);
    expect(select("field-settings-mode").value).toBe("read_only");
    expect(input("field-settings-page_size").value).toBe("100");
    expect(input("field-settings-timeout_factor").value).toBe("1.5");

    fill("field-settings-site", "annex");
    pick("field-plugin", "sample");
    expect(input("field-settings-site").value).toBe("lab");
    expect(input("field-settings-hosts").value).toBe("8");
    expect(screen.queryByTestId("field-settings-url")).toBeNull();
  });

  it("shows the secrets the new plugin declares and forgets the choices made for the old one", async () => {
    await mountForm();
    await secretsListed();
    pick("field-secret-api_key", UNIFI);
    expect(select("field-secret-api_key").value).toBe(UNIFI);
    expect(screen.queryByTestId("field-secret-password")).toBeNull();

    pick("field-plugin", "lab-controller");
    await secretsListed("field-secret-password");
    expect(select("field-secret-api_key").value).toBe("");
    expect(select("field-secret-password")).toBeTruthy();
    expect(screen.getByTestId("field-secret-api_key").closest(".field")?.querySelector("label")?.classList.contains("required")).toBe(true);
    expect(screen.getByTestId("field-secret-password").closest(".field")?.querySelector("label")?.classList.contains("required")).toBe(false);
  });

  it("forgets the refusal of the server for the old plugin", async () => {
    await mountForm();
    server.use(
      http.post("/api/v1/connectors", () =>
        HttpResponse.json(
          { code: "connect.plugin.unusable", status: 422, title: "Unprocessable Content", detail: "plugin `sample` cannot run here", params: { field: "plugin" } },
          { status: 422, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    fill("field-name", "Branch inventory");
    submit(screen.getByTestId("dialog-connector-form"));
    await waitFor(() => expect(noteOf("field-plugin")).toBe("The plugin cannot run on this node."));
    pick("field-plugin", "lab-controller");
    expect(noteOf("field-plugin")).toBeUndefined();
  });

  it("turns the writes guardrail off when another plugin is chosen", async () => {
    const seen = recordWrites();
    const { form } = await mountForm();
    await secretsListed();
    pick("field-plugin", "lab-controller");
    fireEvent.click(screen.getByTestId("field-writes_enabled"));
    expect(input("field-writes_enabled").checked).toBe(true);
    pick("field-plugin", "sample");
    expect(input("field-writes_enabled").disabled).toBe(true);
    expect(input("field-writes_enabled").checked).toBe(false);
    expect(screen.queryByTestId("connector-writes-warning")).toBeNull();
    fill("field-name", "Branch inventory");
    submit(form);
    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]?.body?.writes_enabled).toBe(false);
    expect(storedNamed("Branch inventory")?.writes_enabled).toBe(false);
  });
});

describe("creating: the checks before anything is sent", () => {
  it("asks for a name", async () => {
    const seen = recordWrites();
    const { form, onDone } = await mountForm();
    submit(form);
    await waitFor(() => expect(noteOf("field-name")).toBe("Enter a name."));
    expect(noteFieldOf("field-name")).toBe("name");
    expect(input("field-name").getAttribute("aria-invalid")).toBe("true");
    expect(seen).toEqual([]);
    expect(onDone).not.toHaveBeenCalled();
    expect(await axeViolations(form)).toEqual([]);
    fill("field-name", "   ");
    expect(noteOf("field-name")).toBe("Enter a name.");
    fill("field-name", "Branch inventory");
    expect(noteOf("field-name")).toBeUndefined();
  });

  it("refuses a name of more than 100 characters, and accepts 100", async () => {
    const seen = recordWrites();
    const { form } = await mountForm();
    fill("field-name", "n".repeat(101));
    submit(form);
    await waitFor(() => expect(noteOf("field-name")).toBe("At most 100 characters."));
    expect(seen).toEqual([]);
    fill("field-name", "n".repeat(100));
    expect(noteOf("field-name")).toBeUndefined();
  });

  it("shows nothing before the first try, then the problems of the settings at their fields", async () => {
    const seen = recordWrites();
    const { form } = await mountForm();
    await secretsListed();
    pick("field-plugin", "lab-controller");
    fill("field-name", "Home annex");
    fill("field-settings-site", "Bad Site!");
    fill("field-settings-page_size", "0");
    fill("field-settings-management_ip", "192.0.2.300");
    // Nothing is said while the person is still filling in the form.
    expect(noteOf("field-settings-url")).toBeUndefined();
    expect(noteOf("field-settings-site")).toBeUndefined();

    submit(form);
    await waitFor(() => expect(noteOf("field-settings-url")).toBe("Required."));
    expect(noteOf("field-settings-site")).toBe("Does not match the form the plugin expects (^[a-z0-9-]+$).");
    expect(noteOf("field-settings-page_size")).toBe("A value from 1 to 500.");
    expect(noteOf("field-settings-management_ip")).toBe("Not a valid IPv4 address.");
    // A setting names its error by its field path (as the API does), the fields of the form kit by the request field (`name` above).
    expect(noteFieldOf("field-settings-url")).toBe("settings.url");
    expect(noteFieldOf("field-settings-management_ip")).toBe("settings.management_ip");
    expect(screen.getByTestId("field-settings-url").getAttribute("aria-invalid")).toBe("true");
    expect(noteOf("field-secret-api_key")).toBe("The plugin needs this secret.");
    expect(seen).toEqual([]);
    expect(await axeViolations(form)).toEqual([]);

    // The messages follow the values as they are corrected.
    fill("field-settings-url", CONTROLLER_URL);
    expect(noteOf("field-settings-url")).toBeUndefined();
    fill("field-settings-site", "annex");
    expect(noteOf("field-settings-site")).toBeUndefined();
    fill("field-settings-page_size", "500");
    expect(noteOf("field-settings-page_size")).toBeUndefined();
  });

  it("checks the settings of the sample plugin: a page size of 0 and an address that is no URL", async () => {
    const seen = recordWrites();
    const { form } = await mountForm();
    fill("field-name", "Branch inventory");
    fill("field-settings-page_size", "0");
    fill("field-settings-endpoint", "not a url");
    submit(form);
    await waitFor(() => expect(noteOf("field-settings-page_size")).toBe("A value from 1 to 100."));
    expect(noteOf("field-settings-endpoint")).toBe("Not a valid URL.");
    expect(seen).toEqual([]);
    expect(storedNamed("Branch inventory")).toBeUndefined();
  });

  it("checks the entries of a list at the entry", async () => {
    const seen = recordWrites();
    const { form } = await mountForm();
    await secretsListed();
    fillController("Home annex");
    const add = screen.getAllByTestId("settings-item-add").find((b) => b.getAttribute("data-field") === "ssids") as HTMLElement;
    fireEvent.click(add);
    fireEvent.click(add);
    const items = () => screen.getAllByTestId("settings-item").filter((el) => el.getAttribute("data-field") === "ssids") as HTMLInputElement[];
    fireEvent.input(items()[0] as HTMLElement, { target: { value: "iot" } });
    fireEvent.input(items()[1] as HTMLElement, { target: { value: "x".repeat(33) } });
    submit(form);
    await waitFor(() => expect(noteOf("field-settings-ssids")).toBeUndefined());
    await waitFor(() => expect(form.textContent).toContain("1 to 32 characters."));
    expect(seen).toEqual([]);
    fireEvent.input(items()[1] as HTMLElement, { target: { value: "guest" } });
    submit(form);
    await waitFor(() => expect(seen).toHaveLength(1));
    expect((seen[0]?.body?.settings as Record<string, unknown>).ssids).toEqual(["iot", "guest"]);
  });

  it("holds the poll interval to 60 to 86400 seconds and the call timeout to 1 to 600", async () => {
    const seen = recordWrites();
    const { form } = await mountForm();
    fill("field-name", "Branch inventory");
    for (const bad of ["59", "0", "86401", "-5", "90.5"]) {
      fill("field-poll_interval", bad);
      submit(form);
      await waitFor(() => expect(noteOf("field-poll_interval"), bad).toBe("A whole number from 60 to 86400."));
    }
    fill("field-poll_interval", "");
    for (const bad of ["0", "601", "-1"]) {
      fill("field-call_timeout", bad);
      submit(form);
      await waitFor(() => expect(noteOf("field-call_timeout"), bad).toBe("A whole number from 1 to 600."));
    }
    expect(seen).toEqual([]);
    expect(noteOf("field-poll_interval")).toBeUndefined();

    fill("field-poll_interval", "60");
    fill("field-call_timeout", "600");
    expect(noteOf("field-poll_interval")).toBeUndefined();
    expect(noteOf("field-call_timeout")).toBeUndefined();
    submit(form);
    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]?.body).toMatchObject({ poll_interval_secs: 60, call_timeout_secs: 600 });
  });

  it("accepts the limits of the intervals", async () => {
    const { form, onDone } = await mountForm();
    fill("field-name", "Fast inventory");
    fill("field-poll_interval", "86400");
    fill("field-call_timeout", "1");
    submit(form);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(storedNamed("Fast inventory")).toMatchObject({ poll_interval_secs: 86400, call_timeout_secs: 1 });
  });
});

describe("creating: the secrets", () => {
  it("offers the secrets tagged with the purpose first, then the others, and never a value", async () => {
    seedSecret({ name: "backup api", kind: "api_key", tags: ["api_key"], value: "example-backup-key" });
    await mountForm();
    pick("field-plugin", "lab-controller");
    await secretsListed();
    const api = select("field-secret-api_key");
    const groups = Array.from(api.querySelectorAll("optgroup")).map((g) => ({
      label: g.label,
      options: Array.from(g.querySelectorAll("option")).map((o) => o.textContent),
    }));
    expect(optionLabels(api)[0]).toBe("None");
    expect(groups).toEqual([
      { label: "Tagged api_key", options: ["backup api", "unifi api"] },
      { label: "Other secrets", options: ["nas admin"] },
    ]);
    expect(api.value).toBe("");
    // No tag of the purpose password: one group only.
    const password = select("field-secret-password");
    expect(Array.from(password.querySelectorAll("optgroup")).map((g) => g.label)).toEqual(["Other secrets"]);
    expect(document.body.textContent).not.toContain("example-api-key");
    expect(document.body.textContent).not.toContain("example-backup-key");
  });

  it("requires the secret that the plugin needs and says so at the choice", async () => {
    const seen = recordWrites();
    const { form } = await mountForm();
    await secretsListed();
    pick("field-plugin", "lab-controller");
    fill("field-name", "Home annex");
    fill("field-settings-url", CONTROLLER_URL);
    submit(form);
    await waitFor(() => expect(noteOf("field-secret-api_key")).toBe("The plugin needs this secret."));
    expect(noteOf("field-secret-password")).toBeUndefined();
    expect(select("field-secret-api_key").getAttribute("aria-invalid")).toBe("true");
    expect(seen).toEqual([]);

    pick("field-secret-api_key", UNIFI);
    expect(noteOf("field-secret-api_key")).toBeUndefined();
    submit(form);
    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]?.body?.secrets).toEqual({ api_key: { secret: UNIFI } });
    expect(storedNamed("Home annex")?.secrets).toEqual({ api_key: { secret: UNIFI } });
  });

  it("sends a reference per chosen purpose and none for a purpose left on None", async () => {
    const seen = recordWrites();
    const { form } = await mountForm();
    await secretsListed();
    fillController("Home annex");
    pick("field-secret-password", NAS);
    submit(form);
    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]?.body?.secrets).toEqual({ api_key: { secret: UNIFI }, password: { secret: NAS } });
  });

  it("sends no reference for a purpose that was chosen and then put back to None", async () => {
    const seen = recordWrites();
    const { form } = await mountForm();
    await secretsListed();
    fillController("Home annex");
    pick("field-secret-password", NAS);
    pick("field-secret-password", "");
    submit(form);
    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]?.body?.secrets).toEqual({ api_key: { secret: UNIFI } });
  });

  it("shows the secrets as unavailable to an operator, who may create what needs none", async () => {
    await signInWithRole("operator");
    const seen = recordWrites();
    const { form, onDone } = await mountForm();
    expect(form.textContent).toContain("Choosing secrets needs an administrator.");
    await secretsListed();
    expect(select("field-secret-api_key").disabled).toBe(true);
    fill("field-name", "Operator inventory");
    submit(form);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(seen[0]?.body?.secrets).toEqual({});
    expect(storedNamed("Operator inventory")?.secrets).toEqual({});
    expect(await axeViolations(form)).toEqual([]);
  });

  it("does not let an operator create a plugin that needs a secret", async () => {
    await signInWithRole("operator");
    const seen = recordWrites();
    const { form } = await mountForm();
    pick("field-plugin", "lab-controller");
    expect(select("field-secret-api_key").disabled).toBe(true);
    expect(select("field-secret-password").disabled).toBe(true);
    fill("field-name", "Home annex");
    fill("field-settings-url", CONTROLLER_URL);
    submit(form);
    await waitFor(() => expect(noteOf("field-secret-api_key")).toBe("The plugin needs this secret."));
    expect(seen).toEqual([]);
  });

  it("puts the refusal of the server at the secret that it names", async () => {
    const gone = seedSecret({ name: "temporary api", kind: "api_key", tags: ["api_key"] });
    const { form } = await mountForm();
    pick("field-plugin", "lab-controller");
    await waitFor(() => expect(optionLabels(select("field-secret-api_key"))).toContain("temporary api"));
    fillController("Home annex");
    pick("field-secret-api_key", gone.id);
    // Another administrator deletes the secret while the form is open.
    dropSecret(gone.id);
    submit(form);
    await waitFor(() => expect(noteOf("field-secret-api_key")).toBe("The secret for api_key does not exist."));
    expect(alerts(form)).toEqual(["The secret for api_key does not exist."]);
    expect(storedNamed("Home annex")).toBeUndefined();
    expect((within(form).getByTestId("form-submit") as HTMLButtonElement).disabled).toBe(false);
  });
});

describe("creating: the writes guardrail and the start", () => {
  it("is off and disabled for a plugin that only reads", async () => {
    await mountForm();
    const box = input("field-writes_enabled");
    expect(box.checked).toBe(false);
    expect(box.disabled).toBe(true);
    expect(screen.getByTestId("connector-guardrails").textContent).toContain("This plugin only reads.");
    expect(screen.queryByTestId("connector-writes-warning")).toBeNull();
  });

  it("can be turned on for a plugin that writes, with a warning, and off again", async () => {
    await mountForm();
    pick("field-plugin", "lab-controller");
    const box = input("field-writes_enabled");
    expect(box.disabled).toBe(false);
    expect(box.checked).toBe(false);
    expect(screen.getByTestId("connector-guardrails").textContent).toContain("Off: the connector only reads.");
    expect(screen.queryByTestId("connector-writes-warning")).toBeNull();

    fireEvent.click(box);
    const warning = screen.getByTestId("connector-writes-warning");
    expect(warning.textContent).toContain("Writes change a system Tenko does not own.");
    fireEvent.click(box);
    expect(screen.queryByTestId("connector-writes-warning")).toBeNull();
  });

  it("creates an instance with writes allowed when asked to", async () => {
    const { form, onDone } = await mountForm();
    await secretsListed();
    fillController("Home annex");
    fireEvent.click(screen.getByTestId("field-writes_enabled"));
    submit(form);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(storedNamed("Home annex")?.writes_enabled).toBe(true);
  });

  it("starts the instance unless told not to", async () => {
    const { form, onDone } = await mountForm();
    fill("field-name", "Dormant inventory");
    fireEvent.click(screen.getByTestId("field-enabled"));
    expect(input("field-enabled").checked).toBe(false);
    submit(form);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    const view = storedNamed("Dormant inventory");
    expect(view?.enabled).toBe(false);
    expect(view?.health.process.state).toBe("stopped");
    expect(onDone.mock.calls[0]?.[0].id).toBe(view?.id);
  });

  it("sends what the form shows for the settings, and leaves out what is empty", async () => {
    const seen = recordWrites();
    const { form } = await mountForm();
    fill("field-name", "  Branch inventory  ");
    fill("field-settings-site", "");
    fill("field-settings-hosts", "12");
    submit(form);
    await waitFor(() => expect(seen).toHaveLength(1));
    expect(seen[0]?.method).toBe("POST");
    expect(seen[0]?.body).toEqual({
      name: "Branch inventory",
      plugin: "sample",
      settings: { hosts: 12, page_size: 50, endpoint: "https://inventory.example.net" },
      secrets: {},
      poll_interval_secs: null,
      call_timeout_secs: null,
      writes_enabled: false,
      enabled: true,
    });
    // The host fills in the default of the setting that was left empty.
    expect(storedNamed("Branch inventory")?.settings).toEqual({ site: "lab", hosts: 12, page_size: 50, endpoint: "https://inventory.example.net" });
  });
});

describe("creating: what the server refuses", () => {
  it("puts a name that is taken at the name and keeps the form for another try", async () => {
    const { form, onDone } = await mountForm();
    fill("field-name", "lab INVENTORY");
    submit(form);
    await waitFor(() => expect(noteOf("field-name")).toBe("Another connector has this name."));
    // The note is at the field, not once more above the buttons.
    expect(alerts(form)).toEqual(["Another connector has this name."]);
    expect(onDone).not.toHaveBeenCalled();
    expect((within(form).getByTestId("form-submit") as HTMLButtonElement).disabled).toBe(false);
    expect(input("field-name").value).toBe("lab INVENTORY");
    expect(await axeViolations(form)).toEqual([]);

    fill("field-name", "Lab inventory 2");
    submit(form);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(storedNamed("Lab inventory 2")).toBeTruthy();
  });

  it("puts the field errors of the settings at their fields, and an entry of a list at the entry", async () => {
    // The host sends the detail only; formatting a message without its numbers warns in development.
    vi.spyOn(console, "warn").mockImplementation(() => {});
    server.use(
      http.post("/api/v1/connectors", () =>
        HttpResponse.json(
          {
            code: "connect.settings.invalid",
            status: 422,
            title: "Invalid connector settings",
            detail: "invalid settings: /url: must be a URI",
            params: {},
            errors: [
              { field: "settings.url", code: "connect.settings.format", params: { detail: "must be a URI such as `https://host/path`" } },
              { field: "settings.ssids[1]", code: "connect.settings.length", params: { detail: "must have at least 1 character" } },
              { field: "settings.mode", code: "connect.settings.required", params: { detail: "a value is required" } },
            ],
          },
          { status: 422, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    const { form } = await mountForm();
    await secretsListed();
    fillController("Home annex");
    const add = screen.getAllByTestId("settings-item-add").find((b) => b.getAttribute("data-field") === "ssids") as HTMLElement;
    fireEvent.click(add);
    fireEvent.click(add);
    const items = screen.getAllByTestId("settings-item").filter((el) => el.getAttribute("data-field") === "ssids");
    fireEvent.input(items[0] as HTMLElement, { target: { value: "iot" } });
    fireEvent.input(items[1] as HTMLElement, { target: { value: "guest" } });
    submit(form);

    await waitFor(() => expect(noteOf("field-settings-url")).toBe("must be a URI such as `https://host/path`"));
    expect(noteOf("field-settings-mode")).toBe("Required.");
    // The entry carries its message (the list is described by the same words).
    const describedBy = items[1]?.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    expect(document.getElementById(describedBy as string)?.textContent).toContain("must have at least 1 character");
    expect(items[1]?.getAttribute("aria-invalid")).toBe("true");
    // Every error has its place: there is no general alert as well.
    expect(within(form).queryAllByRole("alert").every((a) => a.classList.contains("help"))).toBe(true);
    expect(alerts(form)).not.toContain("Some settings are not valid; see the fields.");
    expect((within(form).getByTestId("form-submit") as HTMLButtonElement).disabled).toBe(false);
  });

  it("shows a refusal that belongs to no field above the buttons", async () => {
    server.use(
      http.post("/api/v1/connectors", () =>
        HttpResponse.json(
          { code: "auth.forbidden", status: 403, title: "Forbidden", detail: "this needs the admin or operator role", params: {} },
          { status: 403, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    const { form } = await mountForm();
    fill("field-name", "Branch inventory");
    submit(form);
    await waitFor(() => expect(alerts(form)).toHaveLength(1));
    expect(alerts(form)[0]).not.toBe("");
    expect(form.querySelector(".dialog-actions")?.previousElementSibling?.getAttribute("role")).toBe("alert");
    expect((within(form).getByTestId("form-submit") as HTMLButtonElement).disabled).toBe(false);
  });

  it("closes with Cancel and with Escape, and sends nothing", async () => {
    const seen = recordWrites();
    const { form, onClose } = await mountForm();
    fireEvent.click(within(form).getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalledTimes(1);
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(2);
    expect(seen).toEqual([]);
  });
});

describe("changing an instance", () => {
  it("shows the instance as it is: the plugin is fixed, the name and settings are filled in", async () => {
    const { form } = await mountEdit(INVENTORY);
    expect(form.closest("[role='dialog']")?.getAttribute("aria-label")).toBe("Change Lab inventory");
    expect(screen.getByTestId("connector-form-plugin").textContent).toBe("Plugin sample 0.1.0-dev");
    expect(screen.queryByTestId("field-plugin")).toBeNull();
    expect(screen.queryByTestId("field-enabled")).toBeNull();
    expect(input("field-name").value).toBe("Lab inventory");
    expect(input("field-settings-site").value).toBe("lab");
    expect(input("field-settings-hosts").value).toBe("8");
    expect(input("field-poll_interval").value).toBe("");
    expect(within(form).getByTestId("form-submit").textContent).toBe("Save changes");
    expect(await axeViolations(form)).toEqual([]);
  });

  it("shows the secret references and the intervals of an instance that has them", async () => {
    await mountEdit(HOME);
    await waitFor(() => expect(optionLabels(select("field-secret-api_key"))).toContain("unifi api"));
    expect(select("field-secret-api_key").value).toBe(UNIFI);
    expect(select("field-secret-api_key").selectedOptions[0]?.textContent).toBe("unifi api");
    // The reference is never shown as one that cannot be listed while the list is read.
    expect(optionLabels(select("field-secret-api_key"))).not.toContain("A secret you cannot list");
    expect(select("field-secret-password").value).toBe("");
    expect(input("field-poll_interval").value).toBe("120");
    expect(input("field-call_timeout").value).toBe("");
    expect(input("field-settings-url").value).toBe(CONTROLLER_URL);
    const ssids = screen.getAllByTestId("settings-item").filter((el) => el.getAttribute("data-field") === "ssids") as HTMLInputElement[];
    expect(ssids.map((i) => i.value)).toEqual(["iot", "guest"]);
  });

  it("sends nothing for a form that was not changed, and leaves the revision as it was", async () => {
    const seen = recordWrites();
    const before = stored(INVENTORY).revision;
    const { form, onDone, connector } = await mountEdit(INVENTORY);
    submit(form);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(seen).toEqual([]);
    expect(onDone.mock.calls[0]?.[0]).toBe(connector);
    expect(stored(INVENTORY).revision).toBe(before);

    // A name with spaces round it is the same name.
    const second = await mountEdit(INVENTORY);
    fill("field-name", "  Lab inventory ");
    submit(second.form);
    await waitFor(() => expect(second.onDone).toHaveBeenCalledTimes(1));
    expect(seen).toEqual([]);
    expect(stored(INVENTORY).revision).toBe(before);
  });

  it("sends only the name when only the name changed", async () => {
    const seen = recordWrites();
    const before = stored(INVENTORY).revision;
    const { form, onDone } = await mountEdit(INVENTORY);
    fill("field-name", "Lab inventory (main)");
    submit(form);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(seen).toEqual([{ method: "PATCH", body: { name: "Lab inventory (main)" } }]);
    expect(stored(INVENTORY).name).toBe("Lab inventory (main)");
    expect(stored(INVENTORY).revision).toBeGreaterThan(before);
    expect(onDone.mock.calls[0]?.[0].revision).toBe(stored(INVENTORY).revision);
    expect(stored(INVENTORY).settings).toEqual({ site: "lab", hosts: 8, page_size: 50, endpoint: "https://inventory.example.net" });
  });

  it("sends the settings, and only the settings, when a setting changed", async () => {
    const seen = recordWrites();
    const { form, onDone } = await mountEdit(INVENTORY);
    fill("field-settings-hosts", "9");
    submit(form);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(seen).toEqual([{ method: "PATCH", body: { settings: { site: "lab", hosts: 9, page_size: 50, endpoint: "https://inventory.example.net" } } }]);
    expect(stored(INVENTORY).settings).toMatchObject({ hosts: 9 });
    expect(stored(INVENTORY).name).toBe("Lab inventory");
  });

  it("sends the new interval, and zero when the interval is cleared to return to the default", async () => {
    const seen = recordWrites();
    const first = await mountEdit(HOME);
    await secretsListed();
    fill("field-poll_interval", "600");
    fill("field-call_timeout", "45");
    submit(first.form);
    await waitFor(() => expect(first.onDone).toHaveBeenCalledTimes(1));
    expect(seen[0]?.body).toEqual({ poll_interval_secs: 600, call_timeout_secs: 45 });
    expect(stored(HOME)).toMatchObject({ poll_interval_secs: 600, call_timeout_secs: 45 });

    const second = await mountEdit(HOME);
    fill("field-poll_interval", "");
    fill("field-call_timeout", "");
    submit(second.form);
    await waitFor(() => expect(second.onDone).toHaveBeenCalledTimes(1));
    expect(seen[1]?.body).toEqual({ poll_interval_secs: 0, call_timeout_secs: 0 });
    expect(stored(HOME).poll_interval_secs ?? null).toBeNull();
    expect(stored(HOME).call_timeout_secs ?? null).toBeNull();
  });

  it("sends the references when another secret is chosen, and not when they stayed", async () => {
    const seen = recordWrites();
    const { form, onDone } = await mountEdit(HOME);
    await secretsListed();
    fill("field-name", "Home network (main)");
    submit(form);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(seen[0]?.body).toEqual({ name: "Home network (main)" });

    const second = await mountEdit(HOME);
    await secretsListed();
    pick("field-secret-api_key", NAS);
    pick("field-secret-password", UNIFI);
    submit(second.form);
    await waitFor(() => expect(second.onDone).toHaveBeenCalledTimes(1));
    expect(seen[1]?.body).toEqual({ secrets: { api_key: { secret: NAS }, password: { secret: UNIFI } } });
    expect(stored(HOME).secrets).toEqual({ api_key: { secret: NAS }, password: { secret: UNIFI } });
  });

  it("sends the guardrail only when it changed", async () => {
    const seen = recordWrites();
    const { form, onDone } = await mountEdit(HOME);
    await secretsListed();
    fireEvent.click(screen.getByTestId("field-writes_enabled"));
    expect(screen.getByTestId("connector-writes-warning")).toBeTruthy();
    submit(form);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(seen[0]?.body).toEqual({ writes_enabled: true });
    expect(stored(HOME).writes_enabled).toBe(true);

    // An instance with writes on shows the warning from the start.
    const again = await mountEdit(HOME);
    expect(input("field-writes_enabled").checked).toBe(true);
    expect(screen.getByTestId("connector-writes-warning")).toBeTruthy();
    expect(again.form).toBeTruthy();
  });

  it("checks the changed values before anything is sent", async () => {
    const seen = recordWrites();
    const { form, onDone } = await mountEdit(INVENTORY);
    fill("field-name", "");
    fill("field-settings-hosts", "201");
    fill("field-poll_interval", "30");
    submit(form);
    await waitFor(() => expect(noteOf("field-name")).toBe("Enter a name."));
    expect(noteOf("field-settings-hosts")).toBe("A value from 0 to 200.");
    expect(noteOf("field-poll_interval")).toBe("A whole number from 60 to 86400.");
    expect(seen).toEqual([]);
    expect(onDone).not.toHaveBeenCalled();
  });

  it("lets an operator change the schedule of an instance that holds a secret reference", async () => {
    await signInWithRole("operator");
    const seen = recordWrites();
    const { form, onDone } = await mountEdit(HOME);
    expect(form.textContent).toContain("Choosing secrets needs an administrator.");
    await secretsListed();
    // The reference stays selected while the select is disabled.
    expect(select("field-secret-api_key").value).toBe(UNIFI);
    expect(select("field-secret-api_key").disabled).toBe(true);
    fill("field-poll_interval", "300");
    submit(form);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(seen[0]?.body).toEqual({ poll_interval_secs: 300 });
  });

  it("shows the refusal when an operator changes the settings of an instance that holds a reference", async () => {
    await signInWithRole("operator");
    const { form, onDone } = await mountEdit(HOME);
    await secretsListed();
    fill("field-settings-site", "annex");
    submit(form);
    await waitFor(() => expect(alerts(form)).toHaveLength(1));
    expect(onDone).not.toHaveBeenCalled();
    expect(stored(HOME).settings).toMatchObject({ site: "default" });
  });

  it("says that the instance changed meanwhile, and keeps the form", async () => {
    const { form, onDone, connector } = await mountEdit(INVENTORY);
    await updateConnector(INVENTORY, { name: "Lab inventory (renamed elsewhere)" }, connector.revision);
    fill("field-settings-hosts", "9");
    submit(form);
    const note = await within(form).findByText("Someone changed this connector meanwhile. Close the form and open it again.");
    expect(note.closest(".note")?.classList.contains("warn")).toBe(true);
    // The stale note is the only note: there is no second error above the buttons.
    expect(within(form).queryAllByRole("alert")).toEqual([]);
    expect(onDone).not.toHaveBeenCalled();
    expect(stored(INVENTORY).name).toBe("Lab inventory (renamed elsewhere)");
    expect(stored(INVENTORY).settings).toMatchObject({ hosts: 8 });
    expect((within(form).getByTestId("form-submit") as HTMLButtonElement).disabled).toBe(false);
  });

  it("puts a name that another connector has at the name", async () => {
    const { form, onDone } = await mountEdit(INVENTORY);
    fill("field-name", "Home network");
    submit(form);
    await waitFor(() => expect(noteOf("field-name")).toBe("Another connector has this name."));
    expect(onDone).not.toHaveBeenCalled();
    expect(stored(INVENTORY).name).toBe("Lab inventory");
  });
});
