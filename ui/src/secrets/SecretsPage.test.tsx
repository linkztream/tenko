import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CONNECTOR_IDS } from "../api/mock/connectors-store";
import type { MockUser } from "../api/mock/db";
import { server } from "../api/mock/node";
import { SEED_HOST_ID, SEED_SECRET_IDS, bindSecret, mockSecrets, secretList, secretValue, seedSecret } from "../api/mock/secrets-store";
import { mockUpdates } from "../api/mock/routes-updates";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { setSessionForTest } from "../auth/session";
import { Shell } from "../shell/Shell";
import { signInAdmin } from "../updates/testkit";
import { forgetWhatsNew } from "../updates/WhatsNew";
import { updateSecret } from "./api";
import { clearNow } from "./clipboard";
import SecretsPage from "./SecretsPage";

const NAS = SEED_SECRET_IDS.nasAdmin;
const UNIFI = SEED_SECRET_IDS.unifiApi;
const VALUE = "example-new-secret-value";
const CONNECTOR = "0190d1c2-0000-7000-8000-00000000c001";
const GONE_HOST = "0190d1c2-0000-7000-8000-00000000c002";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  await clearNow();
  Reflect.deleteProperty(navigator, "clipboard");
  setSessionForTest(null);
});

/** The seed has a connector instance that references "unifi api"; delete it, as a person would. */
async function releaseUnifi() {
  const answer = await fetch(`/api/v1/connectors/${CONNECTOR_IDS.controller}`, { method: "DELETE" });
  expect(answer.status).toBe(204);
}

async function openPage(url = "/settings/secrets") {
  const view = renderRoute(SecretsPage, { url, path: "/settings/secrets/:id?" });
  await screen.findAllByTestId("secret");
  return view;
}

function rowOf(name: string): HTMLElement {
  const row = screen.getAllByTestId("secret").find((r) => r.dataset.key === name);
  if (!row) throw new Error(`no row for ${name}`);
  return row;
}

const names = () => screen.queryAllByTestId("secret").map((r) => r.dataset.key);

function fill(testid: string, value: string) {
  fireEvent.input(screen.getByTestId(testid), { target: { value } });
}

/** The message under the field `testid` (the line with the error glyph). */
function fieldError(testid: string): string | undefined {
  const field = screen.getByTestId(testid).closest(".field");
  return field?.querySelector<HTMLElement>("[data-testid='field-error']")?.textContent?.trim();
}

/** Records the bodies the page sends to the secrets endpoints; the mock still answers. */
function recordWrites() {
  const seen: { method: string; body: Record<string, unknown> }[] = [];
  const record = (method: string) => async ({ request }: { request: Request }) => {
    seen.push({ method, body: (await request.clone().json()) as Record<string, unknown> });
    return undefined;
  };
  server.use(http.post("/api/v1/secrets", record("POST")), http.patch("/api/v1/secrets/:id", record("PATCH")));
  return seen;
}

function fakeClipboard() {
  const state = { text: "" };
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: {
      writeText: vi.fn((text: string) => {
        state.text = text;
        return Promise.resolve();
      }),
      readText: vi.fn(() => Promise.resolve(state.text)),
    },
  });
  return state;
}

describe("the list", () => {
  it("shows the two seeded secrets with their metadata and never a value", async () => {
    await openPage();
    expect(screen.getByTestId("page-secrets")).toBeTruthy();
    expect(names()).toEqual(["nas admin", "unifi api"]);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("2 secrets");

    const nas = rowOf("nas admin");
    expect(nas.dataset.id).toBe(NAS);
    expect(within(nas).getByRole("link", { name: "nas admin" }).getAttribute("href")).toBe(`/settings/secrets/${NAS}`);
    expect(nas.textContent).toContain("Password");
    expect(nas.textContent).toContain("admin");
    expect(nas.textContent).toContain("ssh");
    expect(nas.textContent).toContain("Never");
    const cells = within(nas).getAllByRole("cell");
    expect(cells[4]?.textContent).toBe("1");

    const unifi = rowOf("unifi api");
    expect(unifi.textContent).toContain("API key");
    expect(unifi.textContent).toContain("unifi");
    expect(within(unifi).getAllByRole("cell")[4]?.textContent).toBe("0");
    expect(document.body.textContent).not.toContain("example-nas-pass");
    expect(document.body.textContent).not.toContain("example-api-key");
  });

  it("narrows by name, user name and tag, and by kind", async () => {
    await openPage();
    const input = screen.getByTestId("filter-input");
    expect(screen.getByTestId("filterbar")).toBeTruthy();

    fireEvent.input(input, { target: { value: "UNIFI" } });
    expect(names()).toEqual(["unifi api"]);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("1 of 2 secrets");

    fireEvent.input(input, { target: { value: "admin" } });
    expect(names()).toEqual(["nas admin"]);

    fireEvent.input(input, { target: { value: "ssh" } });
    expect(names()).toEqual(["nas admin"]);

    fireEvent.input(input, { target: { value: "nothing like this" } });
    expect(screen.getByTestId("secrets-empty").textContent).toBe("No secret matches the filter.");

    fireEvent.keyDown(input, { key: "Escape" });
    expect(names()).toEqual(["nas admin", "unifi api"]);

    fireEvent.change(screen.getByTestId("field-kind-filter"), { target: { value: "api_key" } });
    expect(names()).toEqual(["unifi api"]);
    fireEvent.change(screen.getByTestId("field-kind-filter"), { target: { value: "ssh_key" } });
    expect(screen.getByTestId("secrets-empty")).toBeTruthy();
    fireEvent.change(screen.getByTestId("field-kind-filter"), { target: { value: "" } });
    expect(names()).toEqual(["nas admin", "unifi api"]);
  });

  it("follows a change made elsewhere without a reload", async () => {
    const { bridgeMockEvents } = await import("../audit/testkit");
    const stop = bridgeMockEvents();
    try {
      await openPage();
      await updateSecret(UNIFI, { name: "unifi controller" });
      await waitFor(() => expect(names()).toEqual(["nas admin", "unifi controller"]));
    } finally {
      stop();
    }
  });

  it("has no accessibility violations", async () => {
    const view = await openPage();
    expect(await axeViolations(view.container)).toEqual([]);
  });
});

describe("create", () => {
  it("takes an SSH key with its line breaks in a text area", async () => {
    await openPage();
    fireEvent.click(screen.getByTestId("secrets-create"));
    const dialog = await screen.findByTestId("dialog-secret-form");
    fireEvent.change(screen.getByTestId("field-kind"), { target: { value: "ssh_key" } });
    expect(screen.getByTestId("field-value").tagName).toBe("TEXTAREA");
    const key = ["-----BEGIN EXAMPLE KEY-----", "example-key-line", "-----END EXAMPLE KEY-----", ""].join(String.fromCharCode(10));
    fill("field-name", "deploy key");
    fill("field-value", key);
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-secret-form")).toBeNull());
    const created = secretList().find((s) => s.name === "deploy key");
    if (!created) throw new Error("the secret was not created");
    expect(secretValue(created.id)).toBe(key);
  });

  it("creates a secret, opens it, says so and keeps the value out of the page", async () => {
    const writes = recordWrites();
    const view = await openPage();
    fireEvent.click(screen.getByTestId("secrets-create"));
    const dialog = await screen.findByTestId("dialog-secret-form");
    expect(dialog.getAttribute("aria-label")).toBe("New secret");
    const value = screen.getByTestId("field-value") as HTMLInputElement;
    expect(value.type).toBe("password");
    expect(value.autocomplete).toBe("new-password");

    fill("field-name", "  router admin ");
    fireEvent.change(screen.getByTestId("field-kind"), { target: { value: "ssh_key" } });
    fill("field-username", "root");
    fill("field-tags", "Lab, core,, lab");
    fill("field-notes", "Rack 2, left side");
    fill("field-value", VALUE);
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    await waitFor(() => expect(screen.queryByTestId("dialog-secret-form")).toBeNull());
    const created = secretList().find((s) => s.name === "router admin");
    if (!created) throw new Error("the secret was not created");
    expect(created).toMatchObject({ kind: "ssh_key", username: "root", tags: ["core", "lab"], notes: "Rack 2, left side" });
    expect(secretValue(created.id)).toBe(VALUE);
    expect(writes[0]?.method).toBe("POST");
    expect(writes[0]?.body).toEqual({
      name: "router admin",
      kind: "ssh_key",
      tags: ["core", "lab"],
      username: "root",
      notes: "Rack 2, left side",
      value: VALUE,
    });

    await waitFor(() => expect(view.location()).toBe(`/settings/secrets/${created.id}`));
    const detail = await screen.findByTestId("secret-detail");
    expect(detail.dataset.id).toBe(created.id);
    expect(await screen.findByText("Created router admin")).toBeTruthy();
    expect(names()).toContain("router admin");
    expect(document.body.textContent).not.toContain(VALUE);
  });

  it("asks for a name and a value before it sends anything", async () => {
    const writes = recordWrites();
    await openPage();
    fireEvent.click(screen.getByTestId("secrets-create"));
    const dialog = await screen.findByTestId("dialog-secret-form");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(fieldError("field-name")).toBe("Enter a name.");
    expect(fieldError("field-value")).toBe("Enter a value.");
    expect(writes).toEqual([]);
    expect(secretList()).toHaveLength(2);
  });

  it("shows a 422 next to the field it names and empties the value field", async () => {
    await openPage();
    fireEvent.click(screen.getByTestId("secrets-create"));
    const dialog = await screen.findByTestId("dialog-secret-form");
    fill("field-name", "router admin");
    fill("field-tags", "not a tag!");
    fill("field-value", VALUE);
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    await waitFor(() => expect(fieldError("field-tags")).toBe("A value is not valid: tags."));
    expect(fieldError("field-name")).toBeUndefined();
    expect(screen.getByTestId("field-tags").getAttribute("aria-invalid")).toBe("true");
    // The dialog stays open with the other fields, but the value is gone.
    expect((screen.getByTestId("field-name") as HTMLInputElement).value).toBe("router admin");
    expect((screen.getByTestId("field-value") as HTMLInputElement).value).toBe("");
    expect(within(dialog).getByText(/The value was cleared after the request/)).toBeTruthy();
    expect(secretList()).toHaveLength(2);
    expect(document.body.textContent).not.toContain(VALUE);

    // Fix the tag, type the value again and it goes through.
    fill("field-tags", "lab");
    fill("field-value", VALUE);
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-secret-form")).toBeNull());
    expect(secretList().map((s) => s.name)).toContain("router admin");
  });

  it("shows a value that is too large next to the value field", async () => {
    await openPage();
    fireEvent.click(screen.getByTestId("secrets-create"));
    const dialog = await screen.findByTestId("dialog-secret-form");
    fill("field-name", "big one");
    fill("field-value", "x".repeat(64 * 1024 + 1));
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError("field-value")).toBe("The value is larger than 64 KiB."));
    expect((screen.getByTestId("field-value") as HTMLInputElement).value).toBe("");
    expect(secretList()).toHaveLength(2);
  });

  it("explains the PIN coupling in a notice that names the accounts", async () => {
    mockSecrets.pinOnlyAccounts = ["sam"];
    await openPage();
    fireEvent.click(screen.getByTestId("secrets-create"));
    const dialog = await screen.findByTestId("dialog-secret-form");
    fill("field-name", "router admin");
    fill("field-value", VALUE);
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    const notice = await screen.findByTestId("secret-pin-coupling");
    expect(notice.getAttribute("role")).toBe("alert");
    expect(notice.textContent).toContain("Accounts with a PIN alone: sam.");
    expect(screen.getByTestId("dialog-secret-form")).toBeTruthy();
    expect((screen.getByTestId("field-value") as HTMLInputElement).value).toBe("");
    expect(secretList()).toHaveLength(2);
  });

  it("closes without creating anything on Cancel", async () => {
    await openPage();
    fireEvent.click(screen.getByTestId("secrets-create"));
    const dialog = await screen.findByTestId("dialog-secret-form");
    fill("field-name", "never saved");
    fireEvent.click(within(dialog).getByTestId("form-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-secret-form")).toBeNull());
    expect(secretList()).toHaveLength(2);
  });

  it("has no accessibility violations", async () => {
    await openPage();
    fireEvent.click(screen.getByTestId("secrets-create"));
    const dialog = await screen.findByTestId("dialog-secret-form");
    expect(await axeViolations(dialog)).toEqual([]);
    fill("field-name", "router admin");
    fill("field-tags", "not a tag!");
    fill("field-value", VALUE);
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError("field-tags")).toBeTruthy());
    expect(await axeViolations(dialog)).toEqual([]);
  });
});

describe("edit", () => {
  it("sends only what changed and clears the user name and the notes with null", async () => {
    const router = seedSecret({
      name: "router",
      kind: "token",
      username: "root",
      notes: "first note",
      tags: ["lab"],
      value: "example-router-pass",
    });
    const writes = recordWrites();
    await openPage();
    fireEvent.click(within(rowOf("router")).getByTestId("secret-edit"));
    const dialog = await screen.findByTestId("dialog-secret-form");
    expect(dialog.getAttribute("aria-label")).toBe("Edit router");
    expect(screen.queryByTestId("field-value")).toBeNull();
    expect((screen.getByTestId("field-name") as HTMLInputElement).value).toBe("router");
    expect((screen.getByTestId("field-username") as HTMLInputElement).value).toBe("root");
    expect((screen.getByTestId("field-tags") as HTMLInputElement).value).toBe("lab");
    expect((screen.getByTestId("field-notes") as HTMLTextAreaElement).value).toBe("first note");
    // Nothing changed yet: nothing to save.
    expect((within(dialog).getByTestId("form-submit") as HTMLButtonElement).disabled).toBe(true);

    fill("field-name", "core router");
    fill("field-username", "");
    fill("field-notes", "  ");
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    await waitFor(() => expect(screen.queryByTestId("dialog-secret-form")).toBeNull());
    expect(writes).toHaveLength(1);
    expect(writes[0]?.body).toEqual({ name: "core router", username: null, notes: null });
    const stored = secretList().find((s) => s.id === router.id);
    expect(stored).toMatchObject({ name: "core router", kind: "token", username: null, notes: null, tags: ["lab"] });
    expect(secretValue(router.id)).toBe("example-router-pass");
    expect(await screen.findByText("Saved core router")).toBeTruthy();
    await waitFor(() => expect(names()).toContain("core router"));
  });

  it("changes the tags and the kind", async () => {
    const writes = recordWrites();
    await openPage();
    fireEvent.click(within(rowOf("unifi api")).getByTestId("secret-edit"));
    await screen.findByTestId("dialog-secret-form");
    fireEvent.change(screen.getByTestId("field-kind"), { target: { value: "token" } });
    fill("field-tags", "unifi, api_key, lab");
    fireEvent.click(screen.getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-secret-form")).toBeNull());
    expect(writes[0]?.body).toEqual({ kind: "token", tags: ["api_key", "lab", "unifi"] });
  });

  it("shows a refused field next to it", async () => {
    await openPage();
    fireEvent.click(within(rowOf("unifi api")).getByTestId("secret-edit"));
    await screen.findByTestId("dialog-secret-form");
    fill("field-tags", "bad tag!");
    fireEvent.click(screen.getByTestId("form-submit"));
    await waitFor(() => expect(fieldError("field-tags")).toBe("A value is not valid: tags."));
  });

  it("says that someone else changed the secret and loads the latest version on request", async () => {
    await openPage();
    // Another administrator changes the secret after this page read it.
    await updateSecret(NAS, { notes: "changed elsewhere", name: "nas root" });

    fireEvent.click(within(rowOf("nas admin")).getByTestId("secret-edit"));
    const dialog = await screen.findByTestId("dialog-secret-form");
    fill("field-username", "operator");
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    const conflict = await screen.findByTestId("secret-conflict");
    expect(conflict.textContent).toContain("The secret was changed by someone else. Reload and try again.");
    expect(secretList().find((s) => s.id === NAS)?.username).toBe("admin");

    fireEvent.click(within(conflict).getByTestId("secret-reload"));
    await screen.findByTestId("secret-reloaded");
    expect(screen.queryByTestId("secret-conflict")).toBeNull();
    expect((screen.getByTestId("field-name") as HTMLInputElement).value).toBe("nas root");
    expect((screen.getByTestId("field-notes") as HTMLTextAreaElement).value).toBe("changed elsewhere");
    // The list behind the dialog has the latest version too.
    await waitFor(() => expect(names()).toEqual(["nas root", "unifi api"]));

    fill("field-username", "operator");
    fireEvent.click(screen.getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-secret-form")).toBeNull());
    expect(secretList().find((s) => s.id === NAS)).toMatchObject({
      name: "nas root",
      username: "operator",
      notes: "changed elsewhere",
    });
  });

  it("has no accessibility violations", async () => {
    await openPage();
    fireEvent.click(within(rowOf("nas admin")).getByTestId("secret-edit"));
    expect(await axeViolations(await screen.findByTestId("dialog-secret-form"))).toEqual([]);
  });
});

describe("replace the value", () => {
  it("sends the new value alone, then forgets it", async () => {
    const writes = recordWrites();
    await openPage();
    fireEvent.click(within(rowOf("unifi api")).getByTestId("secret-replace"));
    const dialog = await screen.findByTestId("dialog-secret-value");
    const field = screen.getByTestId("field-value") as HTMLInputElement;
    expect(field.type).toBe("password");
    expect(field.autocomplete).toBe("new-password");
    fill("field-value", VALUE);
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    await waitFor(() => expect(screen.queryByTestId("dialog-secret-value")).toBeNull());
    expect(writes[0]?.body).toEqual({ value: VALUE });
    expect(secretValue(UNIFI)).toBe(VALUE);
    expect(await screen.findByText("Replaced the value of unifi api")).toBeTruthy();
    expect(document.body.textContent).not.toContain(VALUE);
    expect(field.value).toBe("");
  });

  it("asks for a value", async () => {
    const writes = recordWrites();
    await openPage();
    fireEvent.click(within(rowOf("unifi api")).getByTestId("secret-replace"));
    const dialog = await screen.findByTestId("dialog-secret-value");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(fieldError("field-value")).toBe("Enter a value.");
    expect(writes).toEqual([]);
  });

  it("shows a value that is too large next to the field and empties it", async () => {
    await openPage();
    fireEvent.click(within(rowOf("unifi api")).getByTestId("secret-replace"));
    const dialog = await screen.findByTestId("dialog-secret-value");
    fill("field-value", "x".repeat(64 * 1024 + 1));
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError("field-value")).toBe("The value is larger than 64 KiB."));
    expect((screen.getByTestId("field-value") as HTMLInputElement).value).toBe("");
    expect(secretValue(UNIFI)).toBe("example-api-key");
  });

  it("offers to reload when the secret changed meanwhile", async () => {
    await openPage();
    await updateSecret(UNIFI, { notes: "changed elsewhere" });
    fireEvent.click(within(rowOf("unifi api")).getByTestId("secret-replace"));
    const dialog = await screen.findByTestId("dialog-secret-value");
    fill("field-value", VALUE);
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    const conflict = await screen.findByTestId("secret-conflict");
    expect(secretValue(UNIFI)).toBe("example-api-key");

    fireEvent.click(within(conflict).getByTestId("secret-reload"));
    await screen.findByTestId("secret-reloaded");
    fill("field-value", VALUE);
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-secret-value")).toBeNull());
    expect(secretValue(UNIFI)).toBe(VALUE);
  });

  it("has no accessibility violations", async () => {
    await openPage();
    fireEvent.click(within(rowOf("nas admin")).getByTestId("secret-replace"));
    expect(await axeViolations(await screen.findByTestId("dialog-secret-value"))).toEqual([]);
  });
});

describe("delete", () => {
  it("refuses a secret that a host uses, lists the host and offers no delete button", async () => {
    await openPage();
    fireEvent.click(within(rowOf("nas admin")).getByTestId("secret-delete"));
    const dialog = await screen.findByTestId("dialog-secret-delete");
    expect(dialog.getAttribute("aria-label")).toBe("nas admin is in use");
    const host = within(dialog).getByTestId("secret-host");
    expect(host.dataset.key).toBe("nas");
    expect(host.dataset.id).toBe(SEED_HOST_ID);
    expect(within(host).getByRole("link", { name: "nas" }).getAttribute("href")).toBe("/ipam/hosts/nas");
    expect(host.textContent).toContain("Role: Administration");
    expect(within(dialog).getByText(/Unbind it from the following first/)).toBeTruthy();
    expect(screen.queryByTestId("confirm-ok")).toBeNull();
    expect(within(dialog).queryByRole("button", { name: /Delete/ })).toBeNull();
    expect(await axeViolations(dialog)).toEqual([]);

    fireEvent.click(within(dialog).getByTestId("secret-delete-close"));
    await waitFor(() => expect(screen.queryByTestId("dialog-secret-delete")).toBeNull());
    expect(secretList().map((s) => s.id)).toContain(NAS);
  });

  it("lists a connector instance too", async () => {
    server.use(
      http.get("/api/v1/secrets/:id/references", ({ params }) =>
        HttpResponse.json({
          id: params.id,
          hosts: [],
          connectors: [{ connector: CONNECTOR, name: "UniFi lab", plugin: "unifi", purpose: "api_key" }],
        }),
      ),
    );
    await openPage();
    fireEvent.click(within(rowOf("unifi api")).getByTestId("secret-delete"));
    const dialog = await screen.findByTestId("dialog-secret-delete");
    const connector = within(dialog).getByTestId("secret-connector");
    expect(connector.dataset.key).toBe("UniFi lab");
    expect(connector.textContent).toContain("unifi, purpose api_key");
    expect(screen.queryByTestId("confirm-ok")).toBeNull();
  });

  it("deletes an unused secret after a confirmation that names it", async () => {
    await releaseUnifi();
    await openPage();
    fireEvent.click(within(rowOf("unifi api")).getByTestId("secret-delete"));
    const dialog = await screen.findByTestId("dialog-confirm");
    expect(dialog.getAttribute("aria-label")).toBe("Delete unifi api");
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));

    await waitFor(() => expect(screen.queryByTestId("dialog-confirm")).toBeNull());
    expect(secretList().map((s) => s.id)).toEqual([NAS]);
    expect(await screen.findByText("Deleted unifi api")).toBeTruthy();
    await waitFor(() => expect(names()).toEqual(["nas admin"]));
  });

  it("keeps the secret when the confirmation is cancelled", async () => {
    await releaseUnifi();
    await openPage();
    fireEvent.click(within(rowOf("unifi api")).getByTestId("secret-delete"));
    const dialog = await screen.findByTestId("dialog-confirm");
    fireEvent.click(within(dialog).getByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-confirm")).toBeNull());
    expect(secretList()).toHaveLength(2);
  });

  it("turns the confirmation into the list when a host binds the secret meanwhile", async () => {
    await releaseUnifi();
    await openPage();
    fireEvent.click(within(rowOf("unifi api")).getByTestId("secret-delete"));
    const dialog = await screen.findByTestId("dialog-confirm");
    bindSecret(SEED_HOST_ID, UNIFI, "web");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));

    const inUse = await screen.findByTestId("dialog-secret-delete");
    // The refusal shows at once; the list follows when the references have been read again.
    const host = await within(inUse).findByTestId("secret-host");
    expect(host.dataset.key).toBe("nas");
    expect(host.textContent).toContain("Web interface");
    expect(within(inUse).queryByRole("alert")).toBeNull();
    expect(secretList().map((s) => s.id)).toContain(UNIFI);
  });

  it("offers to reload when the secret changed since the page read it", async () => {
    await releaseUnifi();
    await openPage();
    await updateSecret(UNIFI, { notes: "changed elsewhere" });
    fireEvent.click(within(rowOf("unifi api")).getByTestId("secret-delete"));
    const dialog = await screen.findByTestId("dialog-confirm");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    const conflict = await screen.findByTestId("secret-conflict");
    expect(secretList().map((s) => s.id)).toContain(UNIFI);

    fireEvent.click(within(conflict).getByTestId("secret-reload"));
    await waitFor(() => expect(screen.queryByTestId("secret-conflict")).toBeNull());
    fireEvent.click(within(screen.getByTestId("dialog-confirm")).getByTestId("confirm-ok"));
    await waitFor(() => expect(screen.queryByTestId("dialog-confirm")).toBeNull());
    expect(secretList().map((s) => s.id)).toEqual([NAS]);
  });

  it("leaves the detail of a deleted secret", async () => {
    await releaseUnifi();
    const view = await openPage(`/settings/secrets/${UNIFI}`);
    const detail = await screen.findByTestId("secret-detail");
    fireEvent.click(within(detail).getByTestId("secret-delete"));
    fireEvent.click(await screen.findByTestId("confirm-ok"));
    await waitFor(() => expect(view.location()).toBe("/settings/secrets"));
    await waitFor(() => expect(screen.queryByTestId("secret-detail")).toBeNull());
  });
});

describe("reveal", () => {
  it("opens the reveal dialog for the secret without a host and stamps the row", async () => {
    const clipboard = fakeClipboard();
    await openPage();
    fireEvent.click(within(rowOf("nas admin")).getByTestId("secret-reveal"));
    const dialog = await screen.findByTestId("dialog-reveal");
    expect(dialog.getAttribute("aria-label")).toBe("Reveal nas admin");
    await waitFor(() => expect(screen.getByTestId("reveal-status").dataset.state).toBe("copied"));
    expect(clipboard.text).toBe("example-nas-pass");
    expect(document.body.textContent).not.toContain("example-nas-pass");

    fireEvent.click(screen.getByTestId("reveal-close"));
    await waitFor(() => expect(screen.queryByTestId("dialog-reveal")).toBeNull());
    await waitFor(() => expect(within(rowOf("nas admin")).getByTestId("secret-last-reveal").textContent).toMatch(/^alex, /));
  });
});

describe("the detail", () => {
  it("shows the facts and the host that binds the secret", async () => {
    await openPage(`/settings/secrets/${NAS}`);
    const detail = await screen.findByTestId("secret-detail");
    expect(detail.dataset.id).toBe(NAS);
    expect(within(detail).getByRole("heading", { level: 2, name: "nas admin" })).toBeTruthy();
    expect(within(detail).getByTestId("secret-kind").textContent).toBe("Password");
    expect(within(detail).getByTestId("secret-username").textContent).toBe("admin");
    expect(detail.textContent).toContain("ssh");
    expect(within(detail).getByTestId("secret-notes").textContent).toBe("None");
    expect(detail.textContent).toContain("Entered by hand");
    expect(detail.textContent).toContain("Never");
    expect(rowOf("nas admin").getAttribute("aria-current")).toBe("true");

    const host = await within(detail).findByTestId("secret-host");
    expect(host.dataset.key).toBe("nas");
    expect(within(host).getByRole("link", { name: "nas" }).getAttribute("href")).toBe("/ipam/hosts/nas");
    expect(host.textContent).toContain("Administration");
    expect(document.body.textContent).not.toContain("example-nas-pass");
    // The detail has the same actions as the row.
    for (const action of ["secret-reveal", "secret-edit", "secret-replace", "secret-delete"]) {
      expect(within(detail).getByTestId(action)).toBeTruthy();
    }
  });

  it("opens from the list and closes again", async () => {
    await releaseUnifi();
    const view = await openPage();
    expect(screen.queryByTestId("secret-detail")).toBeNull();
    fireEvent.click(within(rowOf("unifi api")).getByRole("link", { name: "unifi api" }));
    await waitFor(() => expect(view.location()).toBe(`/settings/secrets/${UNIFI}`));
    const detail = await screen.findByTestId("secret-detail");
    expect(await within(detail).findByTestId("secret-unused")).toBeTruthy();
    fireEvent.click(within(detail).getByTestId("secret-detail-close"));
    await waitFor(() => expect(view.location()).toBe("/settings/secrets"));
    await waitFor(() => expect(screen.queryByTestId("secret-detail")).toBeNull());
  });

  it("opens a row that is clicked outside its link", async () => {
    const view = await openPage();
    fireEvent.click(within(rowOf("unifi api")).getByText("API key"));
    await waitFor(() => expect(view.location()).toBe(`/settings/secrets/${UNIFI}`));
  });

  it("lists hosts, a deleted host and connector instances", async () => {
    server.use(
      http.get("/api/v1/secrets/:id/references", ({ params }) =>
        HttpResponse.json({
          id: params.id,
          hosts: [
            { host: SEED_HOST_ID, name: "nas", role: "admin" },
            { host: GONE_HOST, name: "old-box", role: "ssh", deleted: true },
          ],
          connectors: [{ connector: CONNECTOR, name: "UniFi lab", plugin: "unifi", purpose: "api_key" }],
        }),
      ),
    );
    await openPage(`/settings/secrets/${NAS}`);
    const detail = await screen.findByTestId("secret-detail");
    await within(detail).findAllByTestId("secret-host");
    const hosts = within(detail).getAllByTestId("secret-host");
    expect(hosts.map((h) => h.dataset.key)).toEqual(["nas", "old-box"]);
    expect(within(hosts[0] as HTMLElement).getByRole("link", { name: "nas" })).toBeTruthy();
    // A deleted host is marked in words and has no link.
    expect(within(hosts[1] as HTMLElement).queryByRole("link")).toBeNull();
    expect(hosts[1]?.textContent).toContain("Deleted");
    expect(hosts[1]?.textContent).toContain("SSH");
    const connector = within(detail).getByTestId("secret-connector");
    expect(connector.dataset.key).toBe("UniFi lab");
    expect(connector.textContent).toContain("unifi, purpose api_key");
    expect(await axeViolations(detail)).toEqual([]);
  });

  it("says so when the secret does not exist", async () => {
    renderRoute(SecretsPage, { url: "/settings/secrets/0190d1c2-0000-7000-8000-0000000dffff", path: "/settings/secrets/:id?" });
    await screen.findAllByTestId("secret");
    const missing = await screen.findByTestId("secret-missing");
    expect(missing.textContent).toContain("The secret does not exist (any more).");
    expect(screen.queryByTestId("secret-detail")).toBeNull();
  });

  it("has no accessibility violations", async () => {
    const view = await openPage(`/settings/secrets/${NAS}`);
    await screen.findByTestId("secret-host");
    expect(await axeViolations(view.container)).toEqual([]);
  });
});

describe("roles", () => {
  it("shows an administrator the settings navigation with the secrets page as the current tab", async () => {
    await openPage();
    const nav = screen.getByRole("navigation", { name: "Settings sections" });
    expect(within(nav).getAllByRole("link").map((a) => a.textContent)).toEqual(["Security", "Users", "Updates", "Secrets"]);
    const current = within(nav).getByRole("link", { name: "Secrets" });
    expect(current.getAttribute("href")).toBe("/settings/secrets");
    expect(current.getAttribute("aria-current")).toBe("page");
    expect(within(nav).getByRole("link", { name: "Security" }).getAttribute("href")).toBe("/settings/security");
    expect(await axeViolations(nav)).toEqual([]);
  });

  it("lets an operator reveal but not create, change or delete", async () => {
    await signInAlex({
      prepare: (user) => {
        user.roles = ["operator"];
      },
    });
    const clipboard = fakeClipboard();
    await openPage(`/settings/secrets/${NAS}`);
    // The settings pages are for administrators, so the operator is not offered their navigation.
    expect(screen.queryByTestId("settings-nav")).toBeNull();
    expect(screen.queryByTestId("secrets-create")).toBeNull();
    for (const root of [rowOf("nas admin"), await screen.findByTestId("secret-detail")]) {
      expect(within(root).getByTestId("secret-reveal")).toBeTruthy();
      for (const action of ["secret-edit", "secret-replace", "secret-delete"]) {
        expect(within(root).queryByTestId(action), action).toBeNull();
      }
    }
    fireEvent.click(within(rowOf("nas admin")).getByTestId("secret-reveal"));
    await screen.findByTestId("dialog-reveal");
    await waitFor(() => expect(clipboard.text).toBe("example-nas-pass"));
  });

  it("shows a viewer only a note and asks the server for nothing", async () => {
    await signInAlex({
      prepare: (user) => {
        user.roles = ["viewer"];
      },
    });
    let reads = 0;
    server.use(
      http.get("/api/v1/secrets", () => {
        reads += 1;
        return undefined;
      }),
    );
    const view = renderRoute(SecretsPage, { url: "/settings/secrets", path: "/settings/secrets/:id?" });
    const notice = await screen.findByTestId("secrets-no-access");
    expect(notice.textContent).toContain("Your role shows no secrets.");
    expect(screen.queryByTestId("secret")).toBeNull();
    expect(screen.queryByTestId("filterbar")).toBeNull();
    expect(screen.queryByTestId("secrets-create")).toBeNull();
    expect(screen.queryByTestId("settings-nav")).toBeNull();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Secrets");
    expect(await axeViolations(view.container)).toEqual([]);
    expect(reads).toBe(0);
  });

  it("tells an administrator how to store the first secret", async () => {
    server.use(http.get("/api/v1/secrets", () => HttpResponse.json({ items: [], next_cursor: null, revision: 1 })));
    renderRoute(SecretsPage, { url: "/settings/secrets", path: "/settings/secrets/:id?" });
    const empty = await screen.findByTestId("secrets-empty");
    expect(empty.textContent).toBe("There are no secrets yet. Use New secret to store the first one.");
  });
});

describe("the command palette", () => {
  async function openPalette(prepare?: (user: MockUser) => void) {
    await signInAdmin(prepare);
    mockUpdates.lastSeen = mockUpdates.running;
    forgetWhatsNew();
    renderRoute(() => <Shell><div /></Shell>, { url: "/jobs", path: "/jobs/*rest" });
    await screen.findByRole("navigation", { name: "Main" });
    fireEvent.keyDown(document, { key: "k", ctrlKey: true });
    await screen.findByRole("combobox");
    return screen.queryAllByRole("option").map((o) => (o.textContent ?? "").trim());
  }

  it("offers the secrets page to an administrator", async () => {
    expect((await openPalette()).some((title) => title.startsWith("Secrets"))).toBe(true);
  });

  it("offers it to an operator", async () => {
    const titles = await openPalette((user) => {
      user.roles = ["operator"];
    });
    expect(titles.some((title) => title.startsWith("Secrets"))).toBe(true);
  });

  it("does not offer it to a viewer", async () => {
    const titles = await openPalette((user) => {
      user.roles = ["viewer"];
    });
    expect(titles.some((title) => title.startsWith("Secrets"))).toBe(false);
  });
});
