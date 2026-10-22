// The forwarders page: the rules by suffix, the notice while no default forwarder exists, create
// (with the offer of DNS over TLS for a well-known resolver), the local checks and the refusals
// of the server, edit with the revision, delete, what a viewer sees, and the states of the
// service (not built, switched off, problems the node reports).
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { dnsResolverState } from "../../api/mock/routes-dns";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { session, setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { dnsNotBuilt, dnsSwitchedOff, recordWrites, row, rowAction, rowActions, rows } from "../testkit";
import ForwardersPage from "./ForwardersPage";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  setSessionForTest(null);
  await setLocale("en");
});

const open = () => renderRoute(ForwardersPage, { url: "/dns/forwarders", path: "/dns/forwarders" });

/** The keys of the rules listed. */
const keys = () => rows("dns-forwarders").map((r) => r.dataset.key);

/** Opens the create dialog and waits for it. */
async function openCreate(): Promise<HTMLElement> {
  fireEvent.click(screen.getByTestId("dns-forwarder-create"));
  return screen.findByTestId("dialog-forwarder-form");
}

/** The text of the error line under field `field` of a dialog. */
function fieldError(dialog: HTMLElement, field: string): string | undefined {
  return dialog.querySelector(`[data-testid="field-error"][data-field="${field}"]`)?.textContent ?? undefined;
}

/** The `If-Match` header of the writes sent, in order. */
function ifMatchOfWrites(): (string | undefined)[] {
  return vi
    .mocked(globalThis.fetch)
    .mock.calls.filter(([, init]) => String(init?.method ?? "GET") !== "GET")
    .map(([, init]) => (init?.headers as Record<string, string> | undefined)?.["If-Match"]);
}

describe("the forwarding rules", () => {
  it("lists the rule of the seed with its upstreams and transport", async () => {
    const view = open();
    await waitFor(() => expect(keys()).toEqual(["corp.example.test"]));
    const corp = row("dns-forwarders", "corp.example.test");
    expect(within(corp).getAllByTestId("fwd-upstream").map((u) => u.textContent)).toEqual(["192.0.2.10:53", "192.0.2.11:53"]);
    expect(within(corp).getByTestId("fwd-transport").dataset.kind).toBe("plain");
    expect(within(corp).queryByTestId("fwd-default")).toBeNull();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  // dns-visibility: the upstreams' figures on the node that answers.
  it("shows each upstream's state and time on the node, the chosen one marked", async () => {
    open();
    await waitFor(() => expect(keys()).toEqual(["corp.example.test"]));
    const corp = row("dns-forwarders", "corp.example.test");
    const figures = within(corp).getAllByTestId("upstream-figures");
    expect(figures.map((f) => f.dataset.state)).toEqual(["up", "up"]);
    expect(figures.map((f) => within(f).getByTestId("upstream-rtt").textContent)).toEqual(["12 ms", "28 ms"]);
    expect(figures[0]?.dataset.chosen).toBe("true");
    expect(figures[1]?.dataset.chosen).toBeUndefined();
    expect(within(corp).getAllByTestId("upstream-chosen")).toHaveLength(1);
    expect(figures[0]?.getAttribute("title")).toContain("99th percentile 31 ms");
    expect(figures[0]?.textContent).toContain("Answering");
  });

  it("says where the other names go while no default forwarder exists, and stops when one is created", async () => {
    open();
    const note = await screen.findByTestId("fwd-no-default");
    expect(note.textContent).toContain("No default forwarder in the store.");
    expect(within(note).getByTestId("fwd-settings-link").getAttribute("href")).toBe("/settings/dns");
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-upstreams"), { target: { value: "192.0.2.53" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(keys()).toEqual([".", "corp.example.test"]));
    expect(screen.queryByTestId("fwd-no-default")).toBeNull();
    expect(within(row("dns-forwarders", ".")).getByTestId("fwd-default").textContent).toBe("Default forwarder");
  });

  it("creates the default forwarder with a DNS over TLS upstream", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toEqual(["corp.example.test"]));
    const dialog = await openCreate();
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.input(within(dialog).getByTestId("field-suffix"), { target: { value: "." } });
    fireEvent.click(within(dialog).getByTestId("field-transport-dot"));
    fireEvent.input(within(dialog).getByTestId("field-upstreams"), { target: { value: "192.0.2.53\n[2001:db8::53]:8853" } });
    fireEvent.input(await within(dialog).findByTestId("field-tls_name"), { target: { value: "DNS.Example.Test" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-forwarder-form")).toBeNull());
    const posts = writes().filter((w) => w.method === "POST");
    expect(posts).toHaveLength(1);
    expect(posts[0]?.url).toContain("/api/v1/dns/forwarders");
    expect(posts[0]?.body).toEqual({
      suffix: ".",
      transport: "dot",
      upstreams: [{ address: "192.0.2.53" }, { address: "2001:db8::53", port: 8853 }],
      tls_name: "dns.example.test",
      description: null,
    });
    await waitFor(() => expect(keys()).toEqual([".", "corp.example.test"]));
    const root = row("dns-forwarders", ".");
    expect(within(root).getByTestId("fwd-default")).toBeTruthy();
    expect(within(root).getByTestId("fwd-transport").dataset.kind).toBe("dot");
    expect(within(root).getAllByTestId("fwd-upstream").map((u) => u.textContent)).toEqual(["192.0.2.53:853", "[2001:db8::53]:8853"]);
    expect(dnsResolverState().forwarders.find((r) => r.suffix === ".")?.tls_name).toBe("dns.example.test");
  });

  it("offers DNS over TLS for the addresses of a well-known resolver", async () => {
    open();
    await waitFor(() => expect(keys()).toHaveLength(1));
    const dialog = await openCreate();
    expect(within(dialog).queryByTestId("fwd-known")).toBeNull();
    expect(within(dialog).queryByTestId("field-tls_name")).toBeNull();
    fireEvent.input(within(dialog).getByTestId("field-upstreams"), { target: { value: "9.9.9.9" } });
    const offer = await within(dialog).findByTestId("fwd-known");
    expect(offer.dataset.key).toBe("dns.quad9.net");
    expect(offer.textContent).toContain("Quad9");
    expect(within(dialog).getByTestId("fwd-use-dot")).toBeTruthy();
    // Only for a plain rule: with DNS over TLS chosen the offer is gone.
    fireEvent.click(within(dialog).getByTestId("field-transport-dot"));
    await waitFor(() => expect(within(dialog).queryByTestId("fwd-known")).toBeNull());
  });

  it("switches to DNS over TLS with the TLS name of the resolver (fwd-use-dot)", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toHaveLength(1));
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-suffix"), { target: { value: "." } });
    fireEvent.input(within(dialog).getByTestId("field-upstreams"), { target: { value: "9.9.9.9\n149.112.112.112" } });
    fireEvent.click(await within(dialog).findByTestId("fwd-use-dot"));
    await waitFor(() => expect((within(dialog).getByTestId("field-tls_name") as HTMLInputElement).value).toBe("dns.quad9.net"));
    expect((within(dialog).getByTestId("field-transport-dot") as HTMLInputElement).checked).toBe(true);
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(keys()).toEqual([".", "corp.example.test"]));
    expect(writes().find((w) => w.method === "POST")?.body).toMatchObject({ transport: "dot", tls_name: "dns.quad9.net" });
  });

  it("does not offer DNS over TLS for a mix of resolvers or an unknown address", async () => {
    open();
    await waitFor(() => expect(keys()).toHaveLength(1));
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-upstreams"), { target: { value: "9.9.9.9\n1.1.1.1" } });
    expect(within(dialog).queryByTestId("fwd-known")).toBeNull();
    fireEvent.input(within(dialog).getByTestId("field-upstreams"), { target: { value: "192.0.2.53" } });
    expect(within(dialog).queryByTestId("fwd-known")).toBeNull();
  });

  it("checks the form before it sends anything", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toHaveLength(1));
    const dialog = await openCreate();
    fireEvent.click(within(dialog).getByTestId("field-transport-dot"));
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(within(dialog).getAllByTestId("field-error").map((e) => e.dataset.field)).toEqual(["upstreams", "tls_name"]));
    expect(fieldError(dialog, "upstreams")).toBe("Give at least one upstream.");
    expect(fieldError(dialog, "tls_name")).toBe(
      "DNS over TLS and DNS over HTTPS need the TLS name of the upstreams.",
    );
    fireEvent.input(within(dialog).getByTestId("field-upstreams"), { target: { value: "192.0.2.53\n192.0.2.54:0" } });
    fireEvent.input(within(dialog).getByTestId("field-tls_name"), { target: { value: "not a name" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() =>
      expect(fieldError(dialog, "upstreams")).toBe("192.0.2.54:0: the port is 1 to 65535."),
    );
    expect(fieldError(dialog, "tls_name")).toBe("Give a DNS name or an IP address.");
    expect(within(dialog).getByTestId("field-upstreams").getAttribute("aria-invalid")).toBe("true");
    expect(writes()).toHaveLength(0);
    expect(await axeViolations(dialog)).toEqual([]);
  });

  it("shows a bad suffix under the suffix field", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toHaveLength(1));
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-suffix"), { target: { value: "*.example.test" } });
    fireEvent.input(within(dialog).getByTestId("field-upstreams"), { target: { value: "192.0.2.53" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    const error = await within(dialog).findByTestId("field-error");
    expect(error.dataset.field).toBe("suffix");
    expect(error.textContent).toBe("Not a DNS name.");
    expect(writes()).toHaveLength(0);
  });

  it("shows the refusal of the server for a suffix that has a rule under the suffix field", async () => {
    open();
    await waitFor(() => expect(keys()).toEqual(["corp.example.test"]));
    const dialog = await openCreate();
    fireEvent.input(within(dialog).getByTestId("field-suffix"), { target: { value: "corp.example.test" } });
    fireEvent.input(within(dialog).getByTestId("field-upstreams"), { target: { value: "192.0.2.53" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    const error = await within(dialog).findByTestId("field-error");
    expect(error.dataset.field).toBe("suffix");
    expect(error.textContent).toBe("A rule for this suffix exists in this view.");
    expect(within(dialog).queryByTestId("error-notice")).toBeNull();
    expect(dnsResolverState().forwarders).toHaveLength(1);
    // Another suffix goes through from the same dialog.
    fireEvent.input(within(dialog).getByTestId("field-suffix"), { target: { value: "lab.example.test" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(keys()).toEqual(["corp.example.test", "lab.example.test"]));
  });

  it("edits a rule and sends its revision", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toEqual(["corp.example.test"]));
    const revision = dnsResolverState().forwarders[0]?.revision;
    await rowAction(row("dns-forwarders", "corp.example.test"), "edit");
    const dialog = await screen.findByTestId("dialog-forwarder-form");
    expect((within(dialog).getByTestId("field-suffix") as HTMLInputElement).value).toBe("corp.example.test");
    expect((within(dialog).getByTestId("field-upstreams") as HTMLTextAreaElement).value).toBe("192.0.2.10\n192.0.2.11");
    fireEvent.input(within(dialog).getByTestId("field-upstreams"), { target: { value: "192.0.2.10:5353" } });
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    await waitFor(() => expect(screen.queryByTestId("dialog-forwarder-form")).toBeNull());
    const patches = writes().filter((w) => w.method === "PATCH");
    expect(patches).toHaveLength(1);
    expect(patches[0]?.url).toContain("/api/v1/dns/forwarders/");
    expect(patches[0]?.body).toMatchObject({ suffix: "corp.example.test", transport: "plain", upstreams: [{ address: "192.0.2.10", port: 5353 }], tls_name: "" });
    expect(ifMatchOfWrites()).toEqual([`"${revision}"`]);
    await waitFor(() =>
      expect(within(row("dns-forwarders", "corp.example.test")).getAllByTestId("fwd-upstream").map((u) => u.textContent)).toEqual(["192.0.2.10:5353"]),
    );
  });

  it("opens the edit dialog from the row", async () => {
    open();
    await waitFor(() => expect(keys()).toEqual(["corp.example.test"]));
    fireEvent.dblClick(row("dns-forwarders", "corp.example.test"));
    const dialog = await screen.findByTestId("dialog-forwarder-form");
    expect(within(dialog).getByRole("heading", { level: 2 }).textContent).toBe("Forwarding rule corp.example.test");
  });

  it("deletes a rule after the confirmation, with its revision", async () => {
    const writes = recordWrites();
    open();
    await waitFor(() => expect(keys()).toEqual(["corp.example.test"]));
    const revision = dnsResolverState().forwarders[0]?.revision;
    await rowAction(row("dns-forwarders", "corp.example.test"), "delete");
    const dialog = await screen.findByTestId("dialog-forwarder-delete");
    expect(dialog.textContent).toContain("Delete the rule for corp.example.test?");
    expect(dialog.textContent).not.toContain("This is the default forwarder.");
    expect(await axeViolations(dialog)).toEqual([]);
    fireEvent.click(within(dialog).getByTestId("confirm-ok"));
    await waitFor(() => expect(screen.getByTestId("dns-forwarders-empty")).toBeTruthy());
    expect(writes().map((w) => w.method)).toEqual(["DELETE"]);
    expect(ifMatchOfWrites()).toEqual([`"${revision}"`]);
    expect(dnsResolverState().forwarders).toHaveLength(0);
    expect(screen.getByTestId("fwd-no-default")).toBeTruthy();
  });

  it("warns when the rule to delete is the default forwarder", async () => {
    dnsResolverState().forwarders.push({
      id: "0190d1c2-0000-7000-8000-00000000dc02",
      suffix: ".",
      transport: "plain",
      upstreams: [{ address: "192.0.2.53" }],
      tls_name: null,
      view: null,
      description: null,
      revision: 1,
    });
    open();
    await waitFor(() => expect(keys()).toEqual([".", "corp.example.test"]));
    expect(screen.queryByTestId("fwd-no-default")).toBeNull();
    await rowAction(row("dns-forwarders", "."), "delete");
    const dialog = await screen.findByTestId("dialog-forwarder-delete");
    expect(dialog.textContent).toContain("This is the default forwarder.");
    fireEvent.click(within(dialog).getByTestId("confirm-cancel"));
    await waitFor(() => expect(screen.queryByTestId("dialog-forwarder-delete")).toBeNull());
    expect(dnsResolverState().forwarders).toHaveLength(2);
  });
});

describe("who may change the rules", () => {
  it("offers a viewer no create button and no row actions", async () => {
    await signInWithRoles(["viewer"]);
    open();
    await waitFor(() => expect(keys()).toEqual(["corp.example.test"]));
    expect(screen.queryByTestId("dns-forwarder-create")).toBeNull();
    const corp = row("dns-forwarders", "corp.example.test");
    expect(await rowActions(corp)).toEqual([]);
    fireEvent.dblClick(corp);
    expect(screen.queryByTestId("dialog-forwarder-form")).toBeNull();
  });

  it("offers an operator the create button and both row actions", async () => {
    await signInWithRoles(["operator"]);
    open();
    await waitFor(() => expect(keys()).toEqual(["corp.example.test"]));
    expect(screen.getByTestId("dns-forwarder-create")).toBeTruthy();
    expect(await rowActions(row("dns-forwarders", "corp.example.test"))).toEqual(["edit", "delete"]);
  });
});

describe("the states of the service", () => {
  it("says the DNS service is not built yet when the server answers 501", async () => {
    dnsNotBuilt();
    open();
    expect(await screen.findByTestId("dns-not-built")).toBeTruthy();
    expect(screen.queryByTestId("dns-forwarder-create")).toBeNull();
    expect(screen.queryByTestId("grid-dns-forwarders")).toBeNull();
    expect(screen.queryByTestId("dns-recursion")).toBeNull();
  });

  it("says the module is switched off when the routes do not exist", async () => {
    dnsSwitchedOff();
    open();
    expect(await screen.findByTestId("dns-off")).toBeTruthy();
    expect(screen.queryByTestId("dns-forwarder-create")).toBeNull();
  });

  it("lists the problems the node reports for the resolver side", async () => {
    dnsResolverState().problems.push("stub zone lab.example.test: no primary answers", "recursion list internal: not found");
    open();
    const notice = await screen.findByTestId("fwd-problems");
    expect(within(notice).getAllByTestId("fwd-problem").map((p) => p.textContent)).toEqual([
      "stub zone lab.example.test: no primary answers",
      "recursion list internal: not found",
    ]);
  });

  it("shows no problems notice when the node reports none", async () => {
    open();
    await waitFor(() => expect(keys()).toHaveLength(1));
    expect(screen.queryByTestId("fwd-problems")).toBeNull();
  });
});

describe("who may recurse", () => {
  it("follows the profile in force", async () => {
    open();
    const section = await screen.findByTestId("dns-recursion");
    expect(section.dataset.key).toBe(session()?.profile);
    expect(section.textContent).toContain("the prefixes IPAM knows and loopback may recurse");
  });

  it("names the Home profile", async () => {
    const current = session();
    if (!current) throw new Error("no session");
    setSessionForTest({ ...current, profile: "home" });
    open();
    const section = await screen.findByTestId("dns-recursion");
    expect(section.dataset.key).toBe("home");
    expect(section.textContent).toContain("follows the profile Home");
    expect(section.textContent).toContain("the prefixes IPAM knows and loopback may recurse");
  });

  it("says no client may recurse in the hardened profile and every client in the lab profile", async () => {
    open();
    const section = await screen.findByTestId("dns-recursion");
    const current = session();
    if (!current) throw new Error("no session");
    setSessionForTest({ ...current, profile: "hardened" });
    await waitFor(() => expect(section.dataset.key).toBe("hardened"));
    expect(section.textContent).toContain("no client may recurse until a view names an access list");
    setSessionForTest({ ...current, profile: "lab" });
    await waitFor(() => expect(section.dataset.key).toBe("lab"));
    expect(section.textContent).toContain("an open resolver");
  });
});

describe("the language", () => {
  it("speaks Swedish", async () => {
    await setLocale("sv");
    open();
    expect((await screen.findByRole("heading", { level: 1 })).textContent).toContain("Vidarebefordrare");
    await waitFor(() => expect(keys()).toEqual(["corp.example.test"]));
    expect(screen.getByTestId("fwd-no-default").textContent).toContain("Ingen standardvidarebefordrare");
    fireEvent.click(screen.getByTestId("dns-forwarder-create"));
    const dialog = await screen.findByTestId("dialog-forwarder-form");
    fireEvent.click(within(dialog).getByTestId("form-submit"));
    expect((await within(dialog).findAllByTestId("field-error")).length).toBeGreaterThan(0);
  });
});
