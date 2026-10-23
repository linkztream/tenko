// The views page: the views in order with their rules in words, their zone scopes with the
// share of each weight and their recursion list; create with a rule of every test, the scope
// map and a recursion list; the local checks and the refusals of the server; edit with the
// revision; reorder with the buttons, the row menu and a drag; delete, refused while a
// forwarding rule names the view; the in-use rules of zones and lists; what a viewer sees;
// the states of the service; Swedish.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DNS_IDS } from "../../api/mock/dns-model";
import { VIEW_IDS } from "../../api/mock/dns-views-model";
import { dnsResolverState, dnsState, dnsViewsState } from "../../api/mock/routes-dns";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { dnsNotBuilt, dnsSwitchedOff, recordWrites, row, rowAction, rowActions, rows } from "../testkit";
import ViewsPage from "./ViewsPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(ViewsPage, { url: "/dns/views", path: "/dns/views" });

/** The names of the views listed, in order. */
const names = () => rows("dns-views").map((r) => r.dataset.key);

const loaded = () => waitFor(() => expect(names()).toEqual(["office", "encrypted clients"]));

async function openCreate(): Promise<HTMLElement> {
  fireEvent.click(screen.getByTestId("dns-view-create"));
  return screen.findByTestId("dialog-view-form");
}

function fieldError(dialog: HTMLElement, field: string): string | undefined {
  return dialog.querySelector(`[data-testid="field-error"][data-field="${field}"]`)?.textContent ?? undefined;
}

/** Adds a rule of `kind` in the dialog and returns its editor. */
function addRule(dialog: HTMLElement, kind: string): HTMLElement {
  fireEvent.change(within(dialog).getByTestId("field-rule-kind"), { target: { value: kind } });
  fireEvent.click(within(dialog).getByTestId("view-rule-add"));
  const editors = within(dialog).getAllByTestId("view-rule-editor");
  const editor = editors[editors.length - 1];
  if (!editor) throw new Error("no rule editor");
  expect(editor.dataset.kind).toBe(kind);
  return editor;
}

/** The `If-Match` header of the writes sent, in order. */
function ifMatchOfWrites(): (string | undefined)[] {
  return vi
    .mocked(globalThis.fetch)
    .mock.calls.filter(([, init]) => String(init?.method ?? "GET") !== "GET")
    .map(([, init]) => (init?.headers as Record<string, string> | undefined)?.["If-Match"]);
}

describe("the views", () => {
  it("lists the views in order with their rules, scopes, shares and recursion", async () => {
    const view = open();
    await loaded();
    const office = row("dns-views", "office");
    expect(within(office).getByTestId("view-order").dataset.key).toBe("1");
    expect(within(office).getAllByTestId("view-rule").map((r) => r.textContent)).toEqual(["Client in 192.0.2.0/24, 2001:db8:0:10::/64"]);
    expect(within(office).getByTestId("view-scope").dataset.key).toBe("example.test:internal");
    expect(within(office).getByTestId("view-recursion").dataset.state).toBe("default");
    const tls = row("dns-views", "encrypted clients");
    expect(within(tls).getByTestId("view-rule").textContent).toBe("Over DNS over TLS, DNS over HTTPS");
    expect(within(tls).getAllByTestId("view-scope").map((s) => s.textContent)).toEqual([
      "example.test: internal, weight 700 (70 %)",
      "example.test: external, weight 300 (30 %)",
    ]);
    expect(screen.getByTestId("view-default").textContent).toContain("sees the default scope of every zone");
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("shows a view without rules as matching every query and a missing list as such", async () => {
    dnsViewsState().views.push({ id: "0190d1c2-0000-7000-8000-00000000def0", name: "rest", order: 3, rules: [], scope_map: [], recursion: "0190d1c2-0000-7000-8000-0000000000aa", profile_resolution: "recurse", revision: 1 });
    open();
    await waitFor(() => expect(names()).toEqual(["office", "encrypted clients", "rest"]));
    const rest = row("dns-views", "rest");
    expect(within(rest).getByTestId("view-every")).toBeTruthy();
    expect(within(rest).getByTestId("view-recursion").dataset.state).toBe("missing");
  });
});

describe("creating a view", () => {
  it("sends a rule of every test, the scope map, the recursion list and the position", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "lab" } });
    fireEvent.change(within(dialog).getByTestId("field-order"), { target: { value: "1" } });
    fireEvent.input(within(addRule(dialog, "client_subnet")).getByTestId("field-rule-values"), { target: { value: "198.51.100.0/24\n2001:db8:1::/48" } });
    const transport = addRule(dialog, "transport");
    fireEvent.click(within(transport).getByTestId("field-rule-transport-udp"));
    fireEvent.click(within(transport).getByTestId("field-rule-transport-doh"));
    fireEvent.input(within(addRule(dialog, "interface")).getByTestId("field-rule-values"), { target: { value: "192.0.2.53" } });
    fireEvent.input(within(addRule(dialog, "qtype")).getByTestId("field-rule-values"), { target: { value: "a, aaaa" } });
    fireEvent.input(within(addRule(dialog, "qname")).getByTestId("field-rule-values"), { target: { value: "Example.Test." } });
    const time = addRule(dialog, "time_of_day");
    fireEvent.input(within(time).getByTestId("field-rule-from"), { target: { value: "22:00" } });
    fireEvent.input(within(time).getByTestId("field-rule-to"), { target: { value: "06:00" } });
    // Two scopes of example.test: 700 and 300, shown as 70 and 30 per cent.
    fireEvent.click(within(dialog).getByTestId("view-scope-add"));
    fireEvent.click(within(dialog).getByTestId("view-scope-add"));
    const [first, second] = within(dialog).getAllByTestId("view-scope-editor");
    if (!first || !second) throw new Error("no scope editors");
    fireEvent.change(within(first).getByTestId("field-scope-zone"), { target: { value: DNS_IDS.zone.example } });
    fireEvent.change(within(first).getByTestId("field-scope-scope"), { target: { value: "internal" } });
    fireEvent.input(within(first).getByTestId("field-scope-weight"), { target: { value: "700" } });
    fireEvent.change(within(second).getByTestId("field-scope-zone"), { target: { value: DNS_IDS.zone.example } });
    fireEvent.change(within(second).getByTestId("field-scope-scope"), { target: { value: "external" } });
    fireEvent.input(within(second).getByTestId("field-scope-weight"), { target: { value: "300" } });
    expect(within(dialog).getAllByTestId("view-share").map((s) => s.dataset.key)).toEqual(["70", "30"]);
    fireEvent.change(within(dialog).getByTestId("field-recursion"), { target: { value: DNS_IDS.acl.internal } });
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-view-form")).toBeNull());
    const posts = writes().filter((w) => w.method === "POST");
    expect(posts).toHaveLength(1);
    expect(posts[0]?.url).toContain("/api/v1/dns/views");
    expect(posts[0]?.body).toEqual({
      name: "lab",
      order: 1,
      rules: [
        { test: "client_subnet", prefixes: ["198.51.100.0/24", "2001:db8:1::/48"] },
        { test: "transport", transports: ["udp", "dot"] },
        { test: "interface", addresses: ["192.0.2.53"] },
        { test: "qtype", types: ["A", "AAAA"] },
        { test: "qname", suffixes: ["example.test"] },
        { test: "time_of_day", from_minute: 1320, to_minute: 360 },
      ],
      scope_map: [
        { zone: DNS_IDS.zone.example, scope: "internal", weight: 700 },
        { zone: DNS_IDS.zone.example, scope: "external", weight: 300 },
      ],
      recursion: DNS_IDS.acl.internal,
      description: null,
    });
    // First in order now; the others moved down.
    await waitFor(() => expect(names()).toEqual(["lab", "office", "encrypted clients"]));
    expect(within(row("dns-views", "lab")).getByTestId("view-recursion").dataset.key).toBe("internal");
    expect(within(row("dns-views", "lab")).getAllByTestId("view-rule")).toHaveLength(6);
    expect(dnsViewsState().views.map((v) => [v.name, v.order]).sort()).toEqual([
      ["encrypted clients", 3],
      ["lab", 1],
      ["office", 2],
    ]);
  });

  it("puts a new view last by default", async () => {
    open();
    await loaded();
    const dialog = await openCreate();
    expect((within(dialog).getByTestId("field-order") as HTMLSelectElement).value).toBe("3");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "everyone" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(names()).toEqual(["office", "encrypted clients", "everyone"]));
    expect(within(row("dns-views", "everyone")).getByTestId("view-every")).toBeTruthy();
  });

  it("checks the view before it is sent", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    const dialog = await openCreate();
    fireEvent.input(within(addRule(dialog, "client_subnet")).getByTestId("field-rule-values"), { target: { value: "192.0.2.0/33" } });
    fireEvent.click(within(dialog).getByTestId("view-scope-add"));
    fireEvent.input(within(dialog).getByTestId("field-scope-weight"), { target: { value: "0" } });
    expect(within(dialog).getByTestId("view-share").dataset.key).toBe("0");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "name")).toBe("Give the view a name."));
    expect(fieldError(dialog, "rules")).toBe("Rule 1: 192.0.2.0/33 is not a prefix.");
    expect(fieldError(dialog, "scope_map")).toBe("Zone scope 1: the weight is a whole number from 1 to 1000.");
    expect(writes()).toHaveLength(0);
    // A rule without values, then a removed one.
    const empty = addRule(dialog, "qname");
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "x" } });
    fireEvent.click(within(within(dialog).getAllByTestId("view-rule-editor")[0] as HTMLElement).getByTestId("view-rule-remove"));
    fireEvent.input(within(dialog).getByTestId("field-scope-weight"), { target: { value: "5" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "rules")).toBe("Rule 1 lists no value."));
    expect(empty.dataset.index).toBe("1");
    expect(writes()).toHaveLength(0);
  });

  it("shows the refusals of the server under their fields", async () => {
    open();
    await loaded();
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "Office" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "name")).toBe("A view of this name exists already."));
    // A scope the zone lacks: lab.example.test has only the default scope; the mock drops one meanwhile.
    fireEvent.input(within(dialog).getByTestId("field-name"), { target: { value: "new" } });
    fireEvent.click(within(dialog).getByTestId("view-scope-add"));
    fireEvent.change(within(dialog).getByTestId("field-scope-scope"), { target: { value: "default" } });
    const zone = dnsState().zones.find((z) => z.id === (within(dialog).getByTestId("field-scope-zone") as HTMLSelectElement).value);
    if (!zone) throw new Error("no zone");
    zone.scopes = [{ name: "other", description: null }];
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "scope_map")).toBe(`The zone ${zone.name} has no scope default.`));
  });
});

describe("changing a view", () => {
  it("sends the change with the revision, and the profile default for recursion", async () => {
    const view = dnsViewsState().views.find((v) => v.id === VIEW_IDS.office);
    if (!view) throw new Error("no view");
    view.recursion = DNS_IDS.acl.internal;
    const writes = recordWrites();
    open();
    await loaded();
    fireEvent.dblClick(row("dns-views", "office"));
    const dialog = await screen.findByTestId("dialog-view-form");
    expect(within(dialog).queryByTestId("field-order")).toBeNull();
    expect((within(dialog).getByTestId("field-recursion") as HTMLSelectElement).value).toBe(DNS_IDS.acl.internal);
    expect((within(dialog).getByTestId("field-rule-values") as HTMLTextAreaElement).value).toBe("192.0.2.0/24\n2001:db8:0:10::/64");
    fireEvent.change(within(dialog).getByTestId("field-recursion"), { target: { value: "" } });
    fireEvent.input(within(dialog).getByTestId("field-description"), { target: { value: "" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-view-form")).toBeNull());
    const patch = writes().find((w) => w.method === "PATCH");
    expect(patch?.body).toEqual({
      name: "office",
      rules: [{ test: "client_subnet", prefixes: ["192.0.2.0/24", "2001:db8:0:10::/64"] }],
      scope_map: [{ zone: DNS_IDS.zone.example, scope: "internal", weight: 1 }],
      description: "",
      default_recursion: true,
    });
    expect(ifMatchOfWrites()[0]).toMatch(/^"\d+"$/);
    await waitFor(() => expect(within(row("dns-views", "office")).getByTestId("view-recursion").dataset.state).toBe("default"));
  });
});

describe("the order", () => {
  it("moves a view with the buttons and the row menu, with the revision", async () => {
    const writes = recordWrites();
    open();
    await loaded();
    expect((within(row("dns-views", "office")).getByTestId("view-move-up") as HTMLButtonElement).disabled).toBe(true);
    expect((within(row("dns-views", "encrypted clients")).getByTestId("view-move-down") as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(row("dns-views", "office")).getByTestId("view-move-down"));
    await waitFor(() => expect(names()).toEqual(["encrypted clients", "office"]));
    expect(writes().find((w) => w.method === "PATCH")?.body).toEqual({ order: 2 });
    expect(ifMatchOfWrites()[0]).toMatch(/^"\d+"$/);
    await rowAction(row("dns-views", "office"), "up");
    await waitFor(() => expect(names()).toEqual(["office", "encrypted clients"]));
  });

  it("moves a view dropped onto another to its place", async () => {
    open();
    await loaded();
    const handle = within(row("dns-views", "encrypted clients")).getByTestId("view-drag");
    fireEvent.dragStart(handle, { dataTransfer: { setData: () => undefined, effectAllowed: "all" } });
    const target = within(row("dns-views", "office")).getByTestId("view-order");
    expect(target.classList.contains("drop-target")).toBe(true);
    fireEvent.dragOver(target);
    fireEvent.drop(target);
    await waitFor(() => expect(names()).toEqual(["encrypted clients", "office"]));
    expect(dnsViewsState().views.find((v) => v.id === VIEW_IDS.tls)?.order).toBe(1);
  });

  it("says so when the view changed meanwhile", async () => {
    open();
    await loaded();
    const office = dnsViewsState().views.find((v) => v.id === VIEW_IDS.office);
    if (!office) throw new Error("no view");
    office.revision += 100;
    fireEvent.click(within(row("dns-views", "office")).getByTestId("view-move-down"));
    expect((await screen.findByTestId("error-notice")).dataset.code).toBe("sys.store.precondition_failed");
  });
});

describe("deleting a view", () => {
  it("is refused while a forwarding rule names the view, with the names", async () => {
    dnsResolverState().forwarders.push({
      id: "0190d1c2-0000-7000-8000-00000000dcff",
      suffix: "office.example.net",
      transport: "plain",
      upstreams: [{ address: "192.0.2.10" }],
      tls_name: null,
      view: VIEW_IDS.office,
      description: null,
      revision: 1,
    });
    open();
    await loaded();
    await rowAction(row("dns-views", "office"), "delete");
    const dialog = await screen.findByTestId("dialog-view-delete");
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    const refused = await within(dialog).findByTestId("view-in-use");
    expect(within(refused).getAllByTestId("view-in-use-by").map((b) => b.dataset.key)).toEqual(["forwarder:office.example.net"]);
    expect(dnsViewsState().views).toHaveLength(2);
  });

  it("deletes a view and the others close up", async () => {
    open();
    await loaded();
    await rowAction(row("dns-views", "office"), "delete");
    fireEvent.click(within(await screen.findByTestId("dialog-view-delete")).getByTestId("confirm-ok"));
    await waitFor(() => expect(names()).toEqual(["encrypted clients"]));
    expect(within(row("dns-views", "encrypted clients")).getByTestId("view-order").dataset.key).toBe("1");
  });
});

describe("the in-use rules of the mock", () => {
  it("keeps a scope, a zone and an access list a view names", async () => {
    const view = dnsViewsState().views.find((v) => v.id === VIEW_IDS.office);
    if (!view) throw new Error("no view");
    view.recursion = DNS_IDS.acl.internal;
    const zone = `/api/v1/dns/zones/${DNS_IDS.zone.example}`;
    const patch = await fetch(zone, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ scopes: [{ name: "default" }] }) });
    expect(patch.status).toBe(409);
    expect(((await patch.json()) as { code: string; params: { by: string } }).params.by).toBe("view:encrypted clients,view:office");
    const removed = await fetch(zone, { method: "DELETE" });
    expect(((await removed.json()) as { code: string }).code).toBe("dns.view.in_use");
    const acl = await fetch(`/api/v1/dns/acls/${DNS_IDS.acl.internal}`, { method: "DELETE" });
    expect(acl.status).toBe(409);
    expect(((await acl.json()) as { code: string }).code).toBe("dns.acl.in_use");
  });
});

describe("who sees what", () => {
  it("offers a viewer no create, no moves and no row actions", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await loaded();
    expect(screen.queryByTestId("dns-view-create")).toBeNull();
    const office = row("dns-views", "office");
    expect(within(office).queryByTestId("view-move-down")).toBeNull();
    expect(within(office).queryByTestId("view-drag")).toBeNull();
    expect(await rowActions(office)).toEqual([]);
    fireEvent.dblClick(office);
    expect(screen.queryByTestId("dialog-view-form")).toBeNull();
  });

  it("offers an operator every row action", async () => {
    await signInWithRoles(["operator"]);
    open();
    await loaded();
    expect(await rowActions(row("dns-views", "encrypted clients"))).toEqual(["edit", "up", "down", "delete"]);
  });
});

describe("the states of the service", () => {
  it("says the DNS service is not built yet when the server answers 501", async () => {
    dnsNotBuilt();
    open();
    expect(await screen.findByTestId("dns-not-built")).toBeTruthy();
    expect(screen.queryByTestId("dns-view-create")).toBeNull();
    expect(screen.queryByTestId("grid-dns-views")).toBeNull();
  });

  it("says the module is switched off when the routes do not exist", async () => {
    dnsSwitchedOff();
    open();
    expect(await screen.findByTestId("dns-off")).toBeTruthy();
  });

  it("shows the empty state without views", async () => {
    dnsViewsState().views = [];
    open();
    expect(await screen.findByTestId("dns-views-empty")).toBeTruthy();
    expect(screen.getByTestId("view-default")).toBeTruthy();
  });
});

describe("the language", () => {
  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    expect((await screen.findByRole("heading", { level: 1 })).textContent).toContain("Vyer");
    await loaded();
    expect(within(row("dns-views", "office")).getByTestId("view-rule").textContent).toBe("Klient i 192.0.2.0/24, 2001:db8:0:10::/64");
    const dialog = await openCreate();
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(fieldError(dialog, "name")).toBe("Ge vyn ett namn."));
  });
});
