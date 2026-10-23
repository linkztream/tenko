// The trust anchors of the recursion page (WP10.4): the root's card with its shipped keys and the
// key that waits for its hold-down, the operator's anchor, the refresh, adding a key as a DS or a
// DNSKEY record (local checks, the refusals of the server, the root's protection), removing an
// anchor after a confirmation, the root that only the Lab profile lets go, what a viewer and an
// operator see, Swedish, and no accessibility violations.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../../api/mock/db";
import { server } from "../../api/mock/node";
import { dnsAnchorsState } from "../../api/mock/routes-dns";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { resetToasts, signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { session, setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { recordWrites } from "../testkit";
import RecursionPage from "./RecursionPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  resetToasts();
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(RecursionPage, { url: "/dns/recursion", path: "/dns/recursion" });

const cards = () => screen.queryAllByTestId("dns-anchor");
const zones = () => cards().map((card) => card.dataset.key);

function card(zone: string): HTMLElement {
  const found = cards().find((c) => c.dataset.key === zone);
  if (!found) throw new Error(`no anchor card ${zone}: ${zones().join(", ")}`);
  return found;
}

const keyRows = (zone: string) => within(card(zone)).getAllByTestId("dns-anchor-key");

async function loaded() {
  await waitFor(() => expect(zones()).toEqual([".", "corp.example.test"]));
}

/** The Lab profile, in the session the page reads and in the mock the requests reach. */
function labProfile() {
  const current = session();
  if (!current) throw new Error("no session");
  db.settings.profile = "lab";
  setSessionForTest({ ...current, profile: "lab" });
}

function paths(calls: { method: string; url: string }[]): string[] {
  return calls.map((call) => `${call.method} ${new URL(call.url, "http://x").pathname}`);
}

async function openAdd(): Promise<HTMLElement> {
  fireEvent.click(await screen.findByTestId("dns-anchor-add"));
  return screen.findByTestId("dialog-anchor-add");
}

function fieldError(dialog: HTMLElement, field: string): string | undefined {
  return dialog.querySelector(`[data-testid="field-error"][data-field="${field}"]`)?.textContent ?? undefined;
}

const DS = "12345 8 2 ABCDEF0123456789ABCDEF0123456789";
const PROBLEM = { type: "about:blank", params: {} };

describe("the trust anchors", () => {
  it("shows the root first, with its shipped keys, the key that waits and its times", async () => {
    const view = open();
    await loaded();
    const root = card(".");
    expect(root.dataset.valid).toBe("2");
    expect(root.dataset.pending).toBe("1");
    expect(within(root).getByRole("heading", { level: 3 }).textContent).toContain("(the root)");
    const keys = keyRows(".");
    expect(keys.map((k) => [k.dataset.key, k.dataset.state])).toEqual([
      ["20326", "valid"],
      ["38696", "valid"],
      ["47000", "add_pend"],
    ]);
    const cells = (row: HTMLElement) => within(row).getAllByRole("cell").map((c) => c.textContent ?? "");
    expect(cells(keys[0]!).slice(0, 3)).toEqual(["20326", "8", "DS, digest type 2"]);
    expect(cells(keys[0]!)[3]).toContain("Valid");
    expect(cells(keys[0]!)[4]).toBe("Shipped in 0.0.4");
    expect(cells(keys[2]!)[3]).toContain("Add pending");
    expect(cells(keys[2]!)[4]).toBe("Learned by RFC 5011");
    expect(within(keys[0]!).getByTestId("dns-anchor-state").getAttribute("title")).toContain("In this state since");
    expect(within(root).getByTestId("dns-anchor-pending").textContent).toBe("1 new key waits for its hold-down before it is trusted.");
    expect(within(root).getByTestId("dns-anchor-last").textContent).not.toBe("Not yet");
    expect(within(root).getByTestId("dns-anchor-next").textContent).not.toBe("Not yet");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("shows the anchor an operator added for a private zone without a pending note", async () => {
    open();
    await loaded();
    const corp = card("corp.example.test");
    expect(corp.dataset.valid).toBe("1");
    expect(corp.dataset.pending).toBe("0");
    expect(within(corp).queryByTestId("dns-anchor-pending")).toBeNull();
    expect(within(corp).queryByText("(the root)")).toBeNull();
    const [key] = keyRows("corp.example.test");
    expect(key?.dataset.key).toBe("3613");
    expect(within(key!).getAllByRole("cell").map((c) => c.textContent)).toContain("Added by an operator");
    expect(within(key!).getAllByRole("cell")[2]?.textContent).toBe("DS, digest type 2");
  });

  it("shows a key that was never seen in the zone and a DNSKEY without a digest type", async () => {
    const corp = dnsAnchorsState().anchors.find((a) => a.zone === "corp.example.test");
    if (!corp) throw new Error("no operator anchor");
    corp.keys = [
      { key_tag: 4242, algorithm: 15, data: { kind: "dnskey", rdata: "257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=" }, state: "valid", state_since: "2026-10-01T00:00:00Z", source: { kind: "operator" }, added_at: "2026-10-01T00:00:00Z", last_seen: null },
    ];
    open();
    await loaded();
    const cells = within(keyRows("corp.example.test")[0]!).getAllByRole("cell").map((c) => c.textContent);
    expect(cells[2]).toBe("DNSKEY");
    expect(cells[5]).toBe("Not yet");
  });

  it("refreshes a zone now, tells so, and reads the times again", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    const before = within(card("corp.example.test")).getByTestId("dns-anchor-next").textContent;
    fireEvent.click(within(card("corp.example.test")).getByTestId("dns-anchor-refresh"));
    expect((await screen.findByTestId("toast")).textContent).toContain("The trust anchor of corp.example.test is refreshed now");
    expect(paths(writes())).toEqual(["POST /api/v1/dns/trust-anchors/corp.example.test/refresh"]);
    await waitFor(() => expect(within(card("corp.example.test")).getByTestId("dns-anchor-next").textContent).not.toBe(before));
  });

  it("refreshes the root through the path segment root", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    fireEvent.click(within(card(".")).getByTestId("dns-anchor-refresh"));
    await screen.findByTestId("toast");
    expect(paths(writes())).toEqual(["POST /api/v1/dns/trust-anchors/root/refresh"]);
  });

  it("says when the refresh could not be started", async () => {
    server.use(
      http.post("/api/v1/dns/trust-anchors/:zone/refresh", () =>
        HttpResponse.json(
          { ...PROBLEM, status: 500, code: "sys.internal", title: "Internal Server Error", detail: "the store failed" },
          { status: 500, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    await loaded();
    fireEvent.click(within(card(".")).getByTestId("dns-anchor-refresh"));
    expect((await screen.findByTestId("toast")).textContent).toContain("The refresh could not be started");
    expect((within(card(".")).getByTestId("dns-anchor-refresh") as HTMLButtonElement).disabled).toBe(false);
  });
});

describe("adding a trust anchor", () => {
  it("opens a form for a zone and a DS record, with the DNSKEY form one click away", async () => {
    open();
    await loaded();
    const dialog = await openAdd();
    expect(within(dialog).getByRole("heading", { level: 2 }).textContent).toBe("Add a trust anchor");
    expect((within(dialog).getByTestId("field-anchor-kind-ds") as HTMLInputElement).checked).toBe(true);
    expect((within(dialog).getByTestId("field-anchor-kind-dnskey") as HTMLInputElement).checked).toBe(false);
    // A blank zone is the root, whose protection the form says at once.
    expect(within(dialog).getByTestId("dns-anchor-root-note")).toBeTruthy();
    fireEvent.input(within(dialog).getByTestId("field-anchor-zone"), { target: { value: "lab.example.test" } });
    expect(within(dialog).queryByTestId("dns-anchor-root-note")).toBeNull();
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.click(within(dialog).getByTestId("field-anchor-kind-dnskey"));
    expect(within(dialog).getByText("DNSKEY record")).toBeTruthy();
    expect(within(dialog).getByTestId("field-anchor-kind-dnskey")).toBeTruthy();
    fireEvent.click(within(dialog).getByTestId("form-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-anchor-add")).toBeNull());
  });

  it("checks the zone and the DS record before it sends anything", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    const dialog = await openAdd();
    fireEvent.input(within(dialog).getByTestId("field-anchor-zone"), { target: { value: "*.example.test" } });
    fireEvent.input(within(dialog).getByTestId("field-anchor-key"), { target: { value: "12345 8 2" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["anchor-zone", "anchor-key"]));
    expect(fieldError(dialog, "anchor-zone")).toBe("Enter a zone name, or `.` for the root.");
    expect(fieldError(dialog, "anchor-key")).toBe("A DS record is four fields: key tag, algorithm, digest type and a hexadecimal digest.");
    expect(within(dialog).getByTestId("field-anchor-key").getAttribute("aria-invalid")).toBe("true");
    expect(writes()).toHaveLength(0);
    expect(await axeViolations(dialog)).toEqual([]);
  });

  it("checks the DNSKEY record by its own shape", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    const dialog = await openAdd();
    fireEvent.click(within(dialog).getByTestId("field-anchor-kind-dnskey"));
    fireEvent.input(within(dialog).getByTestId("field-anchor-zone"), { target: { value: "lab.example.test" } });
    fireEvent.input(within(dialog).getByTestId("field-anchor-key"), { target: { value: "257 3 15" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "anchor-key")).toBe("A DNSKEY record is four fields: flags, protocol, algorithm and a Base64 key."));
    expect(fieldError(dialog, "anchor-zone")).toBeUndefined();
    expect(writes()).toHaveLength(0);
  });

  it("adds a DS record as the anchor of a new zone and lists it in its place", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    const dialog = await openAdd();
    fireEvent.input(within(dialog).getByTestId("field-anchor-zone"), { target: { value: " Lab.Example.Test. " } });
    fireEvent.input(within(dialog).getByTestId("field-anchor-key"), { target: { value: `  ${DS}  ` } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-anchor-add")).toBeNull());
    expect((await screen.findByTestId("toast")).textContent).toContain("The trust anchor of lab.example.test was saved");
    const posts = writes();
    expect(paths(posts)).toEqual(["POST /api/v1/dns/trust-anchors"]);
    expect(posts[0]?.body).toEqual({ zone: "lab.example.test", ds: DS });
    await waitFor(() => expect(zones()).toEqual([".", "corp.example.test", "lab.example.test"]));
    const [key] = keyRows("lab.example.test");
    expect(key?.dataset.key).toBe("12345");
    expect(key?.dataset.state).toBe("valid");
    expect(card("lab.example.test").dataset.valid).toBe("1");
  });

  it("adds a DNSKEY record to the anchor of a zone that has one", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    const dialog = await openAdd();
    fireEvent.click(within(dialog).getByTestId("field-anchor-kind-dnskey"));
    fireEvent.input(within(dialog).getByTestId("field-anchor-zone"), { target: { value: "corp.example.test" } });
    fireEvent.input(within(dialog).getByTestId("field-anchor-key"), { target: { value: "257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-anchor-add")).toBeNull());
    expect(writes()[0]?.body).toEqual({ zone: "corp.example.test", dnskey: "257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=" });
    await waitFor(() => expect(keyRows("corp.example.test")).toHaveLength(2));
    expect(card("corp.example.test").dataset.valid).toBe("2");
    expect(keyRows("corp.example.test").map((k) => within(k).getAllByRole("cell")[2]?.textContent)).toEqual(["DS, digest type 2", "DNSKEY"]);
  });

  it("shows the refusal of the server for a key under the key and keeps the form", async () => {
    open();
    await loaded();
    const dialog = await openAdd();
    fireEvent.input(within(dialog).getByTestId("field-anchor-zone"), { target: { value: "lab.example.test" } });
    fireEvent.click(within(dialog).getByTestId("field-anchor-kind-dnskey"));
    // The shape is right; the protocol of a DNSKEY is 3.
    fireEvent.input(within(dialog).getByTestId("field-anchor-key"), { target: { value: "257 4 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "anchor-key")).toBe("The key is not a DS or DNSKEY record the resolver can use."));
    expect(within(dialog).queryByTestId("error-notice")).toBeNull();
    expect(screen.getByTestId("dialog-anchor-add")).toBeTruthy();
    expect(zones()).toEqual([".", "corp.example.test"]);
  });

  it("shows another failure of the add as an error in the form", async () => {
    server.use(
      http.post("/api/v1/dns/trust-anchors", () =>
        HttpResponse.json(
          { ...PROBLEM, status: 500, code: "sys.internal", title: "Internal Server Error", detail: "the store failed" },
          { status: 500, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    await loaded();
    const dialog = await openAdd();
    fireEvent.input(within(dialog).getByTestId("field-anchor-zone"), { target: { value: "lab.example.test" } });
    fireEvent.input(within(dialog).getByTestId("field-anchor-key"), { target: { value: DS } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByRole("alert")).toBeTruthy();
    expect((within(dialog).getByTestId("form-submit") as HTMLButtonElement).disabled).toBe(false);
  });

  it("tells the root is protected under the default profile and sends the refusal on", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    const dialog = await openAdd();
    // A blank zone is the root.
    fireEvent.input(within(dialog).getByTestId("field-anchor-key"), { target: { value: DS } });
    expect(within(dialog).getByTestId("dns-anchor-root-note").textContent).toBe("The root's trust anchor can be replaced or removed under the Lab profile only.");
    expect(within(dialog).queryByTestId("field-anchor-replace-root")).toBeNull();
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect(await within(dialog).findByRole("alert")).toBeTruthy();
    expect(writes()[0]?.body).toEqual({ zone: ".", ds: DS });
    expect(card(".").dataset.valid).toBe("2");
    expect(dnsAnchorsState().anchors[0]?.keys).toHaveLength(3);
    // A zone that is not the root takes the note away.
    fireEvent.input(within(dialog).getByTestId("field-anchor-zone"), { target: { value: "lab.example.test" } });
    expect(within(dialog).queryByTestId("dns-anchor-root-note")).toBeNull();
  });

  it("replaces the root's keys under the Lab profile when asked to", async () => {
    labProfile();
    const writes = recordWrites();
    open();
    await loaded();
    const dialog = await openAdd();
    fireEvent.input(within(dialog).getByTestId("field-anchor-zone"), { target: { value: "." } });
    fireEvent.input(within(dialog).getByTestId("field-anchor-key"), { target: { value: DS } });
    expect(within(dialog).queryByTestId("dns-anchor-root-note")).toBeNull();
    const replace = within(dialog).getByTestId("field-anchor-replace-root") as HTMLInputElement;
    expect(replace.checked).toBe(false);
    fireEvent.click(replace);
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-anchor-add")).toBeNull());
    expect(writes()[0]?.body).toEqual({ zone: ".", ds: DS, replace_root: true });
    await waitFor(() => expect(keyRows(".")).toHaveLength(1));
    expect(keyRows(".")[0]?.dataset.key).toBe("12345");
  });
});

describe("removing a trust anchor", () => {
  it("removes the anchor of a private zone after a confirmation", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    fireEvent.click(within(card("corp.example.test")).getByTestId("dns-anchor-remove"));
    const dialog = await screen.findByTestId("dialog-anchor-remove");
    expect(dialog.textContent).toContain("Remove the trust anchor of corp.example.test?");
    expect(dialog.textContent).toContain("Answers under corp.example.test are no longer validated with these keys");
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.click(within(dialog).getByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-anchor-remove")).toBeNull());
    expect(writes()).toHaveLength(0);
    fireEvent.click(within(card("corp.example.test")).getByTestId("dns-anchor-remove"));
    fireEvent.click(within(await screen.findByTestId("dialog-anchor-remove")).getByTestId("confirm-ok"));
    await waitFor(() => expect(zones()).toEqual(["."]));
    expect(paths(writes())).toEqual(["DELETE /api/v1/dns/trust-anchors/corp.example.test"]);
    expect((await screen.findByTestId("toast")).textContent).toContain("The trust anchor of corp.example.test was removed");
    expect(dnsAnchorsState().anchors.map((a) => a.zone)).toEqual(["."]);
  });

  it("shows a refusal of the removal in the dialog", async () => {
    server.use(
      http.delete("/api/v1/dns/trust-anchors/:zone", () =>
        HttpResponse.json(
          { ...PROBLEM, status: 404, code: "dns.trust_anchor.not_found", title: "Not found", detail: "no trust anchor", params: { zone: "corp.example.test" } },
          { status: 404, headers: { "content-type": "application/problem+json" } },
        ),
      ),
    );
    open();
    await loaded();
    fireEvent.click(within(card("corp.example.test")).getByTestId("dns-anchor-remove"));
    const dialog = await screen.findByTestId("dialog-anchor-remove");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    expect(await within(dialog).findByRole("alert")).toBeTruthy();
    expect(zones()).toEqual([".", "corp.example.test"]);
  });

  it("keeps the root's anchor under the default profile and says why", async () => {
    open();
    await loaded();
    const root = card(".");
    const remove = within(root).getByTestId("dns-anchor-remove") as HTMLButtonElement;
    expect(remove.disabled).toBe(true);
    const why = within(root).getByTestId("dns-anchor-root-protected");
    expect(why.textContent).toBe("The root's trust anchor can be replaced or removed under the Lab profile only.");
    expect(remove.getAttribute("aria-describedby")).toBe(why.id);
    fireEvent.click(remove);
    expect(screen.queryByTestId("dialog-anchor-remove")).toBeNull();
    // The operator's anchor has no such note and its button works.
    expect(within(card("corp.example.test")).queryByTestId("dns-anchor-root-protected")).toBeNull();
    expect((within(card("corp.example.test")).getByTestId("dns-anchor-remove") as HTMLButtonElement).disabled).toBe(false);
  });

  it("removes the root's anchor under the Lab profile with the warning that nothing validates then", async () => {
    labProfile();
    const writes = recordWrites();
    open();
    await loaded();
    const root = card(".");
    expect((within(root).getByTestId("dns-anchor-remove") as HTMLButtonElement).disabled).toBe(false);
    expect(within(root).queryByTestId("dns-anchor-root-protected")).toBeNull();
    fireEvent.click(within(root).getByTestId("dns-anchor-remove"));
    const dialog = await screen.findByTestId("dialog-anchor-remove");
    expect(dialog.textContent).toContain("Without a root anchor nothing can be validated");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    await waitFor(() => expect(zones()).toEqual(["corp.example.test"]));
    expect(paths(writes())).toEqual(["DELETE /api/v1/dns/trust-anchors/root"]);
  });
});

describe("who may change the trust anchors", () => {
  it("shows a viewer the anchors and offers no button", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await loaded();
    expect(screen.queryByTestId("dns-anchor-add")).toBeNull();
    expect(screen.queryAllByTestId("dns-anchor-refresh")).toHaveLength(0);
    expect(screen.queryAllByTestId("dns-anchor-remove")).toHaveLength(0);
    // Nothing to explain either: the root is not offered for removal at all.
    expect(screen.queryByTestId("dns-anchor-root-protected")).toBeNull();
    expect(keyRows(".")).toHaveLength(3);
  });

  it("holds the keys back from an operator, who may write zones but not keys", async () => {
    await signInWithRoles(["operator"]);
    open();
    await loaded();
    expect(screen.queryByTestId("dns-anchor-add")).toBeNull();
    expect(screen.queryAllByTestId("dns-anchor-refresh")).toHaveLength(0);
    expect(screen.queryAllByTestId("dns-anchor-remove")).toHaveLength(0);
  });
});

describe("the language", () => {
  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    await loaded();
    expect(screen.getByRole("heading", { level: 2, name: "Förtroendeankare" })).toBeTruthy();
    expect(within(card(".")).getByRole("heading", { level: 3 }).textContent).toContain("(roten)");
    expect(within(card(".")).getByTestId("dns-anchor-pending").textContent).toBe("1 ny nyckel väntar på sin hold-down-tid innan den betros.");
    expect(within(keyRows(".")[0]!).getAllByRole("cell")[4]?.textContent).toBe("Medföljde 0.0.4");
    expect(within(card(".")).getByTestId("dns-anchor-root-protected").textContent).toBe("Rotens förtroendeankare kan bara ersättas eller tas bort under profilen Lab.");
    expect(within(card(".")).getByTestId("dns-anchor-refresh").textContent).toBe("Uppdatera nu");
    expect(screen.getByTestId("dns-anchor-add").textContent).toBe("Lägg till ett förtroendeankare");
    fireEvent.click(screen.getByTestId("dns-anchor-add"));
    const dialog = await screen.findByTestId("dialog-anchor-add");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "anchor-key")).toContain("En DS-post har fyra fält"));
  });
});
