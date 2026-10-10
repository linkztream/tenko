// The credentials section of the host page (IAM-16, API-11): what is bound to the host, the
// reveal with the host in view, and binding and unbinding for administrators. The section is
// rendered on its own for a host of the IPAM mock; the host page holding it is in
// HostView.test.tsx. The mock API is src/api/mock/routes-secrets.ts: "nas admin" (user name
// admin) is bound to the host nas, "unifi api" to none.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HOST_IDS, ipamState } from "../api/mock/ipam/api";
import { server } from "../api/mock/node";
import {
  SEED_HOST_ID,
  SEED_SECRET_IDS,
  SEED_SECRET_VALUES,
  bindSecret,
  credentialVersion,
  revealsOf,
  secretValue,
} from "../api/mock/secrets-store";
import type { Host } from "../api/types";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { hostCredentials, listSecrets } from "../secrets/api";
import { clearNow } from "../secrets/clipboard";
import { secretsPath } from "../secrets/paths";
import { HostCredentialsSection } from "./credentials";

const NAS = SEED_SECRET_IDS.nasAdmin;
const UNIFI = SEED_SECRET_IDS.unifiApi;
const CREDENTIALS_PATH = /^\/api\/v1\/hosts\/[^/]+\/credentials$/;
const REVEAL_PATH = /^\/api\/v1\/secrets\/[^/]+\/reveal$/;

/** Renders the section for a host of the IPAM mock (nas by default). */
function renderSection(name = "nas") {
  const host = ipamState().data.host.get(HOST_IDS[name] as string) as Host;
  return renderRoute(() => <HostCredentialsSection host={host} />, { url: "/credentials-under-test" });
}

const rows = () => screen.queryAllByTestId("credential");
const section = () => screen.getByTestId("host-credentials");

/** Renders the section for nas and waits until the seeded credential is listed. */
async function openNas(): Promise<void> {
  renderSection("nas");
  await screen.findByTestId("credential");
}

/** The dialog that binds a credential, with its secrets loaded. */
async function openBindDialog(): Promise<HTMLElement> {
  fireEvent.click(screen.getByTestId("credential-bind"));
  const dialog = await screen.findByTestId("dialog-credential-bind");
  await within(dialog).findByTestId("field-secret");
  return dialog;
}

interface Sent {
  method: string;
  path: string;
  ifMatch: string | null;
  body: Promise<unknown>;
}

/** Records the requests that `match` accepts, with their bodies, as the server saw them. */
function recordRequests(match: (method: string, path: string) => boolean): Sent[] {
  const sent: Sent[] = [];
  server.events.on("request:start", ({ request }) => {
    const path = new URL(request.url).pathname;
    if (!match(request.method, path)) return;
    sent.push({
      method: request.method,
      path,
      ifMatch: request.headers.get("if-match"),
      body: request
        .clone()
        .text()
        .then((text) => (text ? (JSON.parse(text) as unknown) : undefined)),
    });
  });
  return sent;
}

const writes = () => recordRequests((method, path) => method === "PUT" && CREDENTIALS_PATH.test(path));

/** A clipboard that keeps what was written to it. */
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

/** Signs in as alex with other roles than the administrator's. */
async function signInWithRoles(...roles: ("operator" | "viewer")[]): Promise<void> {
  await signInAlex({
    prepare: (user) => {
      user.roles = roles;
    },
  });
}

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  server.events.removeAllListeners();
  await clearNow();
  Reflect.deleteProperty(navigator, "clipboard");
});

describe("the list", () => {
  it("shows the credential bound to nas with its role, user name and link to the secret", async () => {
    await openNas();
    expect(screen.getByRole("heading", { name: /Credentials/ })).toBeTruthy();
    expect(screen.queryByTestId("credentials-empty")).toBeNull();

    const [row, ...rest] = rows() as [HTMLElement];
    expect(rest).toEqual([]);
    expect(row.dataset.id).toBe(NAS);
    expect(row.dataset.key).toBe("nas admin");
    expect(row.dataset.role).toBe("admin");
    const [name, role, user, revealed] = [...row.querySelectorAll("td")];
    expect(within(name as HTMLElement).getByRole("link", { name: "nas admin" }).getAttribute("href")).toBe(secretsPath(NAS));
    expect(role?.textContent).toBe("Administration");
    expect(user?.textContent).toBe("admin");
    expect(revealed?.textContent).toBe("Never");
    expect(within(row).getByTestId("credential-copy").dataset.id).toBe(NAS);
    // Say what a reveal leaves behind.
    expect(section().textContent).toContain("Reveals are audited");
    // The list never shows a password.
    expect(document.body.textContent).not.toContain(SEED_SECRET_VALUES.nasAdmin);
  });

  it("lists the credentials by role, with a dash for a secret without a user name", async () => {
    bindSecret(SEED_HOST_ID, UNIFI, "rdp");
    renderSection("nas");
    await waitFor(() => expect(rows()).toHaveLength(2));
    expect(rows().map((row) => [row.dataset.key, row.dataset.role])).toEqual([
      ["nas admin", "admin"],
      ["unifi api", "rdp"],
    ]);
    const unifi = rows()[1] as HTMLElement;
    const cells = [...unifi.querySelectorAll("td")].map((td) => td.textContent);
    expect(cells.slice(0, 3)).toEqual(["unifi api", "Remote desktop", "–"]);
  });

  it("says that no credentials are bound to a host without any", async () => {
    renderSection("pve1");
    const empty = await screen.findByTestId("credentials-empty");
    expect(empty.textContent).toBe("No credentials are bound to this host.");
    expect(rows()).toEqual([]);
    expect(within(section()).queryByRole("table")).toBeNull();
    // An administrator can bind one.
    expect(screen.getByTestId("credential-bind")).toBeTruthy();
  });

  it("shows the error when the credentials cannot be loaded", async () => {
    server.use(
      http.get("/api/v1/hosts/:id/credentials", () =>
        HttpResponse.json(
          { type: "about:blank", title: "", status: 500, code: "vault.no_translation", detail: "", params: {} },
          { status: 500, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    renderSection("nas");
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("could not complete the request");
    expect(rows()).toEqual([]);
    expect(screen.queryByTestId("credentials-empty")).toBeNull();
  });
});

describe("Copy password", () => {
  it("opens the reveal dialog, reveals with the host in view and copies the password", async () => {
    const clipboard = fakeClipboard();
    const sent = recordRequests((method, path) => method === "POST" && REVEAL_PATH.test(path));
    await openNas();
    expect(screen.queryByTestId("dialog-reveal")).toBeNull();
    fireEvent.click(screen.getByTestId("credential-copy"));

    const dialog = await screen.findByTestId("dialog-reveal");
    expect(within(dialog).getByRole("heading", { name: "Reveal nas admin" })).toBeTruthy();
    await waitFor(() => expect(within(dialog).getByTestId("reveal-status").dataset.state).toBe("copied"));
    expect(clipboard.text).toBe(SEED_SECRET_VALUES.nasAdmin);
    expect(clipboard.text).toBe(secretValue(NAS));

    expect(sent).toHaveLength(1);
    expect(sent[0]?.path).toBe(`/api/v1/secrets/${NAS}/reveal`);
    expect(await sent[0]?.body).toEqual({ host: SEED_HOST_ID });
    expect(within(dialog).getByTestId("reveal-username").textContent).toBe("admin");
    // The value is not on the page unless the person asks for it.
    expect(document.body.textContent).not.toContain(SEED_SECRET_VALUES.nasAdmin);

    // The reveal is audited with the host.
    const [record, ...rest] = revealsOf(NAS);
    expect(rest).toEqual([]);
    expect(record?.draft.outcome).toEqual({ kind: "success" });
    expect(record?.draft.objects).toEqual([
      { kind: "secret", id: NAS },
      { kind: "host", id: SEED_HOST_ID },
    ]);

    fireEvent.click(within(dialog).getByTestId("reveal-close"));
    await waitFor(() => expect(screen.queryByTestId("dialog-reveal")).toBeNull());
    // The list is still there.
    expect(rows()).toHaveLength(1);
  });

  it("says why when the server refuses the reveal", async () => {
    fakeClipboard();
    server.use(
      http.post("/api/v1/secrets/:id/reveal", () =>
        HttpResponse.json(
          { type: "about:blank", title: "Not bound", status: 409, code: "vault.reveal.not_bound", detail: "", params: {} },
          { status: 409, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    await openNas();
    fireEvent.click(screen.getByTestId("credential-copy"));
    const dialog = await screen.findByTestId("dialog-reveal");
    await waitFor(() => expect(within(dialog).getByTestId("reveal-status").dataset.state).toBe("failed"));
    expect(within(dialog).getByRole("alert").textContent).toBe("The secret is not bound to this host.");
    expect(navigator.clipboard.writeText).not.toHaveBeenCalled();
  });
});

describe("binding a credential", () => {
  it("binds unifi api as rdp: the dialog offers the free secrets, and the list shows the new row", async () => {
    const sent = writes();
    await openNas();
    const version = credentialVersion(SEED_HOST_ID);
    const dialog = await openBindDialog();

    // Only a secret that is not bound to the host is offered; nas admin is bound already.
    const secret = within(dialog).getByTestId("field-secret") as HTMLSelectElement;
    expect([...secret.options].map((o) => [o.value, o.textContent])).toEqual([[UNIFI, "unifi api"]]);
    expect(secret.value).toBe(UNIFI);
    const role = within(dialog).getByTestId("field-role") as HTMLSelectElement;
    expect([...role.options].map((o) => o.value)).toEqual(["admin", "rdp", "ssh", "web", "other"]);
    expect(role.value).toBe("admin");

    fireEvent.change(role, { target: { value: "rdp" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    await waitFor(() => expect(screen.queryByTestId("dialog-credential-bind")).toBeNull());
    await waitFor(() => expect(rows()).toHaveLength(2));
    expect(rows().map((row) => [row.dataset.id, row.dataset.key, row.dataset.role])).toEqual([
      [NAS, "nas admin", "admin"],
      [UNIFI, "unifi api", "rdp"],
    ]);
    expect(await screen.findByText("Credential bound")).toBeTruthy();

    // The whole set goes in, guarded by the version read with the list.
    expect(sent).toHaveLength(1);
    expect(sent[0]?.path).toBe(`/api/v1/hosts/${SEED_HOST_ID}/credentials`);
    expect(sent[0]?.ifMatch).toBe(`"${version}"`);
    expect(await sent[0]?.body).toEqual({
      credentials: [
        { secret: NAS, role: "admin" },
        { secret: UNIFI, role: "rdp" },
      ],
    });
    const stored = await hostCredentials(SEED_HOST_ID);
    expect(stored.items.map((item) => [item.secret.id, item.role])).toEqual([
      [NAS, "admin"],
      [UNIFI, "rdp"],
    ]);
  });

  it("uses the role of the field and the secret as chosen", async () => {
    const sent = writes();
    renderSection("pve1");
    await screen.findByTestId("credentials-empty");
    const dialog = await openBindDialog();
    const secret = within(dialog).getByTestId("field-secret") as HTMLSelectElement;
    expect([...secret.options].map((o) => o.value).sort()).toEqual([NAS, UNIFI].sort());
    fireEvent.change(secret, { target: { value: NAS } });
    fireEvent.change(within(dialog).getByTestId("field-role"), { target: { value: "ssh" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    await waitFor(() => expect(rows()).toHaveLength(1));
    expect(rows()[0]?.dataset.role).toBe("ssh");
    expect(rows()[0]?.dataset.key).toBe("nas admin");
    expect(screen.queryByTestId("credentials-empty")).toBeNull();
    expect(await sent[0]?.body).toEqual({ credentials: [{ secret: NAS, role: "ssh" }] });
  });

  it("closes with Cancel and changes nothing", async () => {
    const sent = writes();
    await openNas();
    const dialog = await openBindDialog();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByTestId("dialog-credential-bind")).toBeNull());
    expect(sent).toEqual([]);
    expect(rows()).toHaveLength(1);
  });

  it("offers nothing when every secret is bound already, and a link to the secrets", async () => {
    bindSecret(SEED_HOST_ID, UNIFI, "rdp");
    renderSection("nas");
    await waitFor(() => expect(rows()).toHaveLength(2));
    fireEvent.click(screen.getByTestId("credential-bind"));
    const dialog = await screen.findByTestId("dialog-credential-bind");
    expect(await within(dialog).findByText(/Every operator secret is bound to this host already/)).toBeTruthy();
    expect(within(dialog).queryByTestId("field-secret")).toBeNull();
    expect(within(dialog).getByRole("link", { name: "Manage secrets" }).getAttribute("href")).toBe(secretsPath());
    expect((within(dialog).getByTestId("form-submit") as HTMLButtonElement).disabled).toBe(true);
  });

  it("keeps the dialog open and says so when the credentials of the host changed meanwhile", async () => {
    await openNas();
    const dialog = await openBindDialog();
    // Somebody else binds the secret after the list was read: its version moves on.
    bindSecret(SEED_HOST_ID, UNIFI, "ssh");
    fireEvent.click(within(dialog).getByTestId("form-submit"));

    const alert = await within(dialog).findByRole("alert");
    expect(alert.textContent).toBe("The credentials of the host were changed by someone else. Reload and try again.");
    expect(screen.getByTestId("dialog-credential-bind")).toBeTruthy();
    expect(rows()).toHaveLength(1);
  });

  it("has no accessibility violations in the dialog", async () => {
    await openNas();
    const dialog = await openBindDialog();
    expect(await axeViolations(dialog)).toEqual([]);
  });
});

describe("unbinding a credential", () => {
  it("asks first, then removes the row and tells that the secret stays in the vault", async () => {
    const sent = writes();
    await openNas();
    const version = credentialVersion(SEED_HOST_ID);
    const unbind = screen.getByTestId("credential-unbind");
    expect(unbind.dataset.id).toBe(NAS);
    expect(unbind.getAttribute("aria-label")).toBe("Unbind nas admin");
    fireEvent.click(unbind);

    const dialog = await screen.findByTestId("dialog-confirm");
    expect(within(dialog).getByRole("heading", { name: "Unbind nas admin?" })).toBeTruthy();
    expect(dialog.textContent).toContain("The secret nas admin stays in the vault; only its binding to nas goes.");
    // Nothing happened yet.
    expect(sent).toEqual([]);
    expect(rows()).toHaveLength(1);

    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    await waitFor(() => expect(screen.queryByTestId("dialog-confirm")).toBeNull());
    await screen.findByTestId("credentials-empty");
    expect(rows()).toEqual([]);
    expect(await screen.findByText("nas admin is no longer bound to this host")).toBeTruthy();

    expect(sent).toHaveLength(1);
    expect(sent[0]?.ifMatch).toBe(`"${version}"`);
    expect(await sent[0]?.body).toEqual({ credentials: [] });
    expect((await hostCredentials(SEED_HOST_ID)).items).toEqual([]);
    // The secret itself is still in the vault, with its value.
    expect((await listSecrets()).map((s) => s.id)).toContain(NAS);
    expect(secretValue(NAS)).toBe(SEED_SECRET_VALUES.nasAdmin);
  });

  it("keeps the other credentials when one is unbound", async () => {
    bindSecret(SEED_HOST_ID, UNIFI, "rdp");
    const sent = writes();
    renderSection("nas");
    await waitFor(() => expect(rows()).toHaveLength(2));
    const unbind = within(rows()[1] as HTMLElement).getByTestId("credential-unbind");
    expect(unbind.getAttribute("aria-label")).toBe("Unbind unifi api");
    fireEvent.click(unbind);
    fireEvent.click(within(await screen.findByTestId("dialog-confirm")).getByTestId("confirm-ok"));

    await waitFor(() => expect(rows()).toHaveLength(1));
    expect(rows()[0]?.dataset.key).toBe("nas admin");
    expect(await sent[0]?.body).toEqual({ credentials: [{ secret: NAS, role: "admin" }] });
  });

  it("keeps the credential when the question is cancelled", async () => {
    const sent = writes();
    await openNas();
    fireEvent.click(screen.getByTestId("credential-unbind"));
    const dialog = await screen.findByTestId("dialog-confirm");
    fireEvent.click(within(dialog).getByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-confirm")).toBeNull());
    expect(sent).toEqual([]);
    expect(rows()).toHaveLength(1);
    expect((await hostCredentials(SEED_HOST_ID)).items).toHaveLength(1);
  });

  it("keeps the question open with a toast when the credentials changed meanwhile", async () => {
    await openNas();
    bindSecret(SEED_HOST_ID, UNIFI, "ssh");
    fireEvent.click(screen.getByTestId("credential-unbind"));
    const dialog = await screen.findByTestId("dialog-confirm");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));

    const title = await screen.findByText("The credential could not be unbound");
    const toast = title.closest(".toast") as HTMLElement;
    expect(toast.dataset.key).toBe("bad");
    expect(within(toast).getByText("The credentials of the host were changed by someone else. Reload and try again.")).toBeTruthy();
    expect(screen.getByTestId("dialog-confirm")).toBeTruthy();
    expect(rows()).toHaveLength(1);
    // Nothing was unbound on the server.
    expect((await hostCredentials(SEED_HOST_ID)).items.map((item) => item.secret.id)).toContain(NAS);
  });
});

describe("who sees what", () => {
  it("shows an administrator the bind button and an unbind button for each row", async () => {
    bindSecret(SEED_HOST_ID, UNIFI, "rdp");
    renderSection("nas");
    await waitFor(() => expect(rows()).toHaveLength(2));
    expect(screen.getAllByTestId("credential-bind")).toHaveLength(1);
    expect(screen.getAllByTestId("credential-copy")).toHaveLength(2);
    expect(screen.getAllByTestId("credential-unbind").map((b) => b.dataset.id)).toEqual([NAS, UNIFI]);
  });

  it("shows an operator Copy password but no bind or unbind, and the operator can reveal", async () => {
    await signInWithRoles("operator");
    const clipboard = fakeClipboard();
    await openNas();
    expect(screen.getAllByTestId("credential-copy")).toHaveLength(1);
    expect(screen.queryByTestId("credential-bind")).toBeNull();
    expect(screen.queryByTestId("credential-unbind")).toBeNull();
    expect(screen.queryByRole("button", { name: /Bind credential/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Unbind/ })).toBeNull();

    fireEvent.click(screen.getByTestId("credential-copy"));
    const dialog = await screen.findByTestId("dialog-reveal");
    await waitFor(() => expect(within(dialog).getByTestId("reveal-status").dataset.state).toBe("copied"));
    expect(clipboard.text).toBe(SEED_SECRET_VALUES.nasAdmin);
  });

  it("shows an operator the empty state without a bind button", async () => {
    await signInWithRoles("operator");
    renderSection("pve1");
    await screen.findByTestId("credentials-empty");
    expect(screen.queryByTestId("credential-bind")).toBeNull();
  });

  it("shows a viewer no credentials section at all, because the server refuses the list", async () => {
    await signInWithRoles("viewer");
    // The premise: the list is refused with 403.
    await expect(hostCredentials(SEED_HOST_ID)).rejects.toMatchObject({ status: 403 });
    renderSection("nas");
    await waitFor(() => expect(screen.queryByTestId("host-credentials")).toBeNull());
    // Give a late answer the time to show something it should not.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.queryByTestId("host-credentials")).toBeNull();
    expect(screen.queryByRole("heading", { name: /Credentials/ })).toBeNull();
    expect(screen.queryByTestId("credentials-empty")).toBeNull();
    expect(screen.queryByTestId("credential")).toBeNull();
    expect(screen.queryByTestId("credential-bind")).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(document.body.textContent).not.toContain("nas admin");
  });
});

describe("accessibility", () => {
  it("has no violations in the list of an administrator", async () => {
    bindSecret(SEED_HOST_ID, UNIFI, "rdp");
    renderSection("nas");
    await waitFor(() => expect(rows()).toHaveLength(2));
    expect(await axeViolations(section())).toEqual([]);
  });

  it("has no violations in the list of an operator", async () => {
    await signInWithRoles("operator");
    await openNas();
    expect(await axeViolations(section())).toEqual([]);
  });

  it("has no violations in the empty state", async () => {
    renderSection("pve1");
    await screen.findByTestId("credentials-empty");
    expect(await axeViolations(section())).toEqual([]);
  });

  it("has no violations in the question before an unbind", async () => {
    await openNas();
    fireEvent.click(screen.getByTestId("credential-unbind"));
    const dialog = await screen.findByTestId("dialog-confirm");
    expect(await axeViolations(dialog)).toEqual([]);
  });
});
