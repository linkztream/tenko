// The lifecycle of hosts in the hosts list: the lifecycle filter, the columns of a decommissioned
// host (when, by whom, why), and Decommission, Reinstate and Delete on a row and on the selection.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { applyCommands, HOST_IDS, ipamState } from "../api/mock/ipam/api";
import type { IpamCommand } from "../api/types";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { applied, confirmPlan, recordWrites } from "../ipam/testkit";
import HostsView from "./HostsView";

beforeEach(async () => {
  await signInAlex();
});

function renderList(url = paths.hosts()) {
  return renderRoute(HostsView, { url, path: "/ipam/hosts", routes: { "/ipam/hosts/:fqdn": () => <div data-testid="host-route" /> } });
}

const rows = (): HTMLElement[] => screen.queryAllByTestId("row");
const names = (): (string | undefined)[] => rows().map((r) => r.dataset.key);

function rowOf(name: string): HTMLElement {
  const row = rows().find((r) => r.dataset.key === name);
  if (!row) throw new Error(`no row for host ${name}`);
  return row;
}

const listed = () => waitFor(() => expect(rows().length).toBeGreaterThan(0));
const stored = (name: string) => ipamState().data.host.get(HOST_IDS[name] as string);
const cell = (name: string, column: string): string => rowOf(name).querySelector(`[data-col='${column}']`)?.textContent ?? "";

function select(...hosts: string[]): void {
  for (const name of hosts) fireEvent.click(within(rowOf(name)).getByRole("checkbox"));
}

/** Retires hosts through the mock, as a person did earlier. */
function decommission(name: string, reason: string | null = null, keepDns = false): void {
  applyCommands([{ op: "decommission_host", args: { host: HOST_IDS[name], reason, keep_dns: keepDns } }] as unknown as IpamCommand[]);
}

function chooseLifecycle(value: "active" | "decommissioned" | "all"): void {
  fireEvent.change(screen.getByTestId("filter-lifecycle"), { target: { value } });
}

async function rowAction(name: string, item: string): Promise<void> {
  fireEvent.click(rowOf(name).querySelector(".row-menu") as HTMLElement);
  const menu = await screen.findByTestId("row-menu");
  const entry = menu.querySelector<HTMLElement>(`[data-item='${item}']`);
  if (!entry) throw new Error(`no row action ${item}`);
  fireEvent.click(entry);
}

/** The GET requests for the list of hosts so far. */
function hostListRequests(): () => string[] {
  const spy = vi.spyOn(globalThis, "fetch");
  return () =>
    spy.mock.calls
      .map(([url, init]) => ({ url: String(url), method: String(init?.method ?? "GET") }))
      .filter((c) => c.method === "GET" && /\/api\/v1\/hosts\?/.test(c.url))
      .map((c) => c.url);
}

const gone = (testid: string) => waitFor(() => expect(screen.queryByTestId(testid)).toBeNull());

describe("the lifecycle filter", () => {
  it("hides decommissioned hosts by default and sends no lifecycle", async () => {
    decommission("laptop-ak", "Moved to the lab");
    const requests = hostListRequests();
    const view = renderList();
    await listed();
    expect(names()).not.toContain("laptop-ak");
    expect(names()).toContain("gw");
    expect(requests().every((url) => !url.includes("lifecycle"))).toBe(true);
    expect((screen.getByTestId("filter-lifecycle") as HTMLSelectElement).value).toBe("active");
    expect(view.location()).not.toContain("lifecycle");
    // The columns of the lifecycle come with the views that list retired hosts.
    const headers = within(screen.getByRole("grid", { name: "Hosts" }))
      .getAllByRole("columnheader")
      .map((h) => h.textContent);
    expect(headers).not.toContain("Decommissioned");
  });

  it("shows when, by whom and why in the Decommissioned view, and keeps the filter in the address", async () => {
    decommission("laptop-ak", "Moved to the lab");
    decommission("tv-living");
    const requests = hostListRequests();
    const view = renderList();
    await listed();
    chooseLifecycle("decommissioned");
    await waitFor(() => expect(names()).toEqual(["laptop-ak", "tv-living"]));
    expect(view.location()).toContain("lifecycle=decommissioned");
    expect(requests().some((url) => url.includes("lifecycle=decommissioned"))).toBe(true);

    const headers = within(screen.getByRole("grid", { name: "Hosts" }))
      .getAllByRole("columnheader")
      .map((h) => h.textContent);
    expect(headers).toEqual(expect.arrayContaining(["Decommissioned", "Reason"]));
    // The badge, the time, the person and the reason.
    expect(within(rowOf("laptop-ak")).getByTestId("decommissioned-tag").textContent).toBe("Decommissioned");
    expect(cell("laptop-ak", "decommissioned")).toMatch(/by .*alex/i);
    expect(cell("laptop-ak", "decommission_reason")).toBe("Moved to the lab");
    expect(cell("tv-living", "decommission_reason")).toBe("");
    expect(rowOf("laptop-ak").classList.contains("decommissioned")).toBe(true);

    chooseLifecycle("all");
    await waitFor(() => expect(names()).toContain("gw"));
    expect(names()).toEqual(expect.arrayContaining(["laptop-ak", "gw"]));
    expect(within(rowOf("gw")).queryByTestId("decommissioned-tag")).toBeNull();
    expect(within(rowOf("laptop-ak")).getByTestId("decommissioned-tag")).toBeTruthy();
    expect(view.location()).toContain("lifecycle=all");

    chooseLifecycle("active");
    await waitFor(() => expect(names()).not.toContain("laptop-ak"));
    expect(view.location()).not.toContain("lifecycle");
  });

  it("starts in the view the address names and says so when nothing is decommissioned", async () => {
    renderList(`${paths.hosts()}?lifecycle=decommissioned`);
    expect(await screen.findByText("No decommissioned hosts.")).toBeTruthy();
    expect((screen.getByTestId("filter-lifecycle") as HTMLSelectElement).value).toBe("decommissioned");
  });
});

describe("decommissioning from the list", () => {
  it("asks for a reason and the DNS choice, previews, then applies at the revision of the host", async () => {
    const writes = recordWrites();
    renderList();
    await listed();
    const before = stored("laptop-ak");
    await rowAction("laptop-ak", "decommission");

    const form = await screen.findByTestId("dialog-decommission");
    expect(within(form).getByRole("heading", { name: "Decommission laptop-ak" })).toBeTruthy();
    // By default the DNS names go; the person may keep them.
    const keep = within(form).getByTestId("decommission-keep-dns") as HTMLInputElement;
    expect(keep.checked).toBe(false);
    expect(within(form).getByText(/DNS records of the released addresses are removed/)).toBeTruthy();
    fireEvent.input(within(form).getByTestId("decommission-reason"), { target: { value: "  Replaced by a new laptop  " } });
    fireEvent.click(keep);
    expect(applied(writes())).toHaveLength(0);
    expect(writes()).toHaveLength(0);
    fireEvent.click(within(form).getByTestId("form-submit"));

    // The preview is a dry run and writes nothing.
    const plan = await screen.findByTestId("dialog-decommission-plan");
    await within(plan).findByTestId("plan-preview");
    expect(within(plan).getByText("The DNS names of the released addresses are kept.")).toBeTruthy();
    expect(within(plan).getByTestId("plan-summary").textContent).toMatch(/Host: 1 updated/);
    const preview = writes().find((w) => w.url.includes("/decommission"));
    expect(preview?.url).toContain(`/hosts/${HOST_IDS["laptop-ak"]}/decommission`);
    expect(preview?.url).toContain("dry_run=true");
    expect(preview?.body).toEqual({ reason: "Replaced by a new laptop", keep_dns: true });
    expect(preview?.headers["If-Match"]).toBe(`"${before?.meta.revision}"`);
    expect(stored("laptop-ak")?.decommissioned).toBeUndefined();

    await confirmPlan({ dialog: "dialog-decommission-plan" });
    await gone("dialog-decommission-plan");
    const sent = applied(writes()).filter((w) => w.url.includes("/decommission"));
    expect(sent).toHaveLength(1);
    expect(sent[0]?.body).toEqual({ reason: "Replaced by a new laptop", keep_dns: true });
    expect(stored("laptop-ak")?.decommissioned).toMatchObject({ reason: "Replaced by a new laptop", kept_dns: true });
    // The host left the default list, and the toast says what happened.
    await waitFor(() => expect(names()).not.toContain("laptop-ak"));
    expect(await screen.findByText("Decommission laptop-ak")).toBeTruthy();
  });

  it("has no accessibility violations in the decommission dialog", async () => {
    renderList();
    await listed();
    await rowAction("gw", "decommission");
    const form = await screen.findByTestId("dialog-decommission");
    expect(await axeViolations(form)).toEqual([]);
  });

  it("sends no reason and removes the DNS names when nothing is chosen", async () => {
    const writes = recordWrites();
    renderList();
    await listed();
    await rowAction("pve1", "decommission");
    fireEvent.click(within(await screen.findByTestId("dialog-decommission")).getByTestId("form-submit"));
    await confirmPlan({ dialog: "dialog-decommission-plan" });
    await gone("dialog-decommission-plan");
    const sent = applied(writes()).filter((w) => w.url.includes("/decommission"));
    expect(sent[0]?.body).toEqual({ reason: null, keep_dns: false });
    expect(stored("pve1")?.decommissioned?.kept_dns).toBe(false);
  });

  it("refuses a reason over 1,024 bytes and leaves the host alone when cancelled", async () => {
    const writes = recordWrites();
    renderList();
    await listed();
    await rowAction("gw", "decommission");
    const form = await screen.findByTestId("dialog-decommission");
    const submit = within(form).getByTestId("form-submit") as HTMLButtonElement;
    fireEvent.input(within(form).getByTestId("decommission-reason"), { target: { value: "é".repeat(600) } });
    expect(submit.disabled).toBe(true);
    expect(within(form).getByText(/longer than 1,024 bytes/)).toBeTruthy();
    fireEvent.input(within(form).getByTestId("decommission-reason"), { target: { value: "é".repeat(500) } });
    expect(submit.disabled).toBe(false);
    fireEvent.click(within(form).getByRole("button", { name: "Cancel" }));
    await gone("dialog-decommission");
    expect(writes()).toHaveLength(0);
    expect(stored("gw")?.decommissioned).toBeUndefined();
  });

  it("decommissions the selection in one bulk request", async () => {
    const writes = recordWrites();
    renderList();
    await listed();
    select("ap-hall", "ap-garage");
    fireEvent.click(screen.getByTestId("action-decommission"));
    const form = await screen.findByTestId("dialog-decommission");
    expect(within(form).getByRole("heading", { name: "Decommission 2 hosts" })).toBeTruthy();
    fireEvent.input(within(form).getByTestId("decommission-reason"), { target: { value: "Garage rebuild" } });
    fireEvent.click(within(form).getByTestId("form-submit"));
    const plan = await screen.findByTestId("dialog-decommission-plan");
    await within(plan).findByTestId("plan-preview");
    const preview = writes().find((w) => w.url.includes("/hosts/bulk"));
    expect(preview?.url).toContain("dry_run=true");
    expect(preview?.body).toEqual({
      operations: [
        { op: "decommission_host", args: { host: HOST_IDS["ap-garage"], reason: "Garage rebuild", keep_dns: false, expected: stored("ap-garage")?.meta.revision } },
        { op: "decommission_host", args: { host: HOST_IDS["ap-hall"], reason: "Garage rebuild", keep_dns: false, expected: stored("ap-hall")?.meta.revision } },
      ],
    });
    await confirmPlan({ dialog: "dialog-decommission-plan" });
    await gone("dialog-decommission-plan");
    expect(applied(writes()).filter((w) => w.url.includes("/hosts/bulk"))).toHaveLength(1);
    expect(stored("ap-hall")?.decommissioned?.reason).toBe("Garage rebuild");
    expect(stored("ap-garage")?.decommissioned?.reason).toBe("Garage rebuild");
    await waitFor(() => expect(names()).not.toContain("ap-hall"));
    expect(screen.queryByTestId("actionbar")).toBeNull();
  });

  it("offers Decommission only when every selected host is active", async () => {
    decommission("laptop-ak");
    renderList(`${paths.hosts()}?lifecycle=all`);
    await listed();
    select("gw");
    expect(screen.getByTestId("action-decommission")).toBeTruthy();
    expect(screen.queryByTestId("action-reinstate")).toBeNull();
    select("laptop-ak");
    expect(screen.queryByTestId("action-decommission")).toBeNull();
    expect(screen.queryByTestId("action-reinstate")).toBeNull();
    expect(screen.getByTestId("action-delete")).toBeTruthy();
  });
});

describe("reinstating from the list", () => {
  it("reinstates one host with its row action", async () => {
    decommission("laptop-ak", "Away");
    const writes = recordWrites();
    renderList(`${paths.hosts()}?lifecycle=decommissioned`);
    await waitFor(() => expect(names()).toEqual(["laptop-ak"]));
    // A decommissioned host offers Reinstate and no Decommission.
    fireEvent.click(rowOf("laptop-ak").querySelector(".row-menu") as HTMLElement);
    const menu = await screen.findByTestId("row-menu");
    const ids = [...menu.querySelectorAll<HTMLElement>("[data-item]")].map((el) => el.dataset.item);
    expect(ids).toContain("reinstate");
    expect(ids).not.toContain("decommission");
    fireEvent.click(menu.querySelector("[data-item='reinstate']") as HTMLElement);

    const dialog = await screen.findByTestId("dialog-reinstate");
    expect(within(dialog).getByRole("heading", { name: "Reinstate laptop-ak" })).toBeTruthy();
    await confirmPlan({ dialog: "dialog-reinstate" });
    await gone("dialog-reinstate");
    const sent = applied(writes()).filter((w) => w.url.includes("/reinstate"));
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).toContain(`/hosts/${HOST_IDS["laptop-ak"]}/reinstate`);
    expect(stored("laptop-ak")?.decommissioned).toBeUndefined();
    // It left the Decommissioned view.
    await waitFor(() => expect(names()).toEqual([]));
  });

  it("reinstates the selection in one bulk request and tells which addresses were not bound again", async () => {
    decommission("laptop-ak");
    decommission("tv-living");
    // Another host takes the address of the laptop meanwhile.
    const other = [...ipamState().data.interface.values()].find((i) => i.host === HOST_IDS["gw"]);
    const laptopAddress = stored("laptop-ak")?.decommissioned?.released?.[0]?.address as string;
    applyCommands([{ op: "update_address", args: { id: laptopAddress, patch: { interface: other?.id } } }] as unknown as IpamCommand[]);

    const writes = recordWrites();
    renderList(`${paths.hosts()}?lifecycle=decommissioned`);
    await waitFor(() => expect(names()).toEqual(["laptop-ak", "tv-living"]));
    select("laptop-ak", "tv-living");
    fireEvent.click(screen.getByTestId("action-reinstate"));
    const dialog = await screen.findByTestId("dialog-reinstate");
    expect(within(dialog).getByRole("heading", { name: "Reinstate 2 hosts" })).toBeTruthy();
    await within(dialog).findByTestId("plan-preview");
    // The preview already warns about the address that is taken.
    expect(within(dialog).getByTestId("plan-warnings").textContent).toContain("192.0.2.20 was not bound to the host again: the address is assigned to another host.");
    const preview = writes().find((w) => w.url.includes("/hosts/bulk"));
    expect(preview?.body).toEqual({
      operations: [
        { op: "reinstate_host", args: { host: HOST_IDS["laptop-ak"], expected: stored("laptop-ak")?.meta.revision } },
        { op: "reinstate_host", args: { host: HOST_IDS["tv-living"], expected: stored("tv-living")?.meta.revision } },
      ],
    });
    await confirmPlan({ dialog: "dialog-reinstate" });
    await gone("dialog-reinstate");
    expect(stored("laptop-ak")?.decommissioned).toBeUndefined();
    expect(stored("tv-living")?.decommissioned).toBeUndefined();
    await waitFor(() => expect(names()).toEqual([]));
    expect(await screen.findByText("1 address was not bound again")).toBeTruthy();
  });
});

describe("deleting decommissioned hosts", () => {
  it("deletes one host with its row action", async () => {
    decommission("laptop-ak");
    const writes = recordWrites();
    renderList(`${paths.hosts()}?lifecycle=decommissioned`);
    await waitFor(() => expect(names()).toEqual(["laptop-ak"]));
    await rowAction("laptop-ak", "delete");
    await confirmPlan({ dialog: "dialog-delete" });
    await gone("dialog-delete");
    expect(applied(writes()).filter((w) => w.method === "DELETE")).toHaveLength(1);
    expect(stored("laptop-ak")?.meta.deleted).toBeTruthy();
    await waitFor(() => expect(names()).toEqual([]));
  });

  it("deletes the selection in one bulk request, with the choice to take what the hosts contain", async () => {
    decommission("laptop-ak");
    decommission("tv-living");
    const writes = recordWrites();
    renderList(`${paths.hosts()}?lifecycle=decommissioned`);
    await waitFor(() => expect(names()).toEqual(["laptop-ak", "tv-living"]));
    select("laptop-ak", "tv-living");
    fireEvent.click(screen.getByTestId("action-delete"));
    const dialog = await screen.findByTestId("dialog-hosts-delete");
    expect(within(dialog).getByRole("heading", { name: "Delete 2 hosts" })).toBeTruthy();
    await within(dialog).findByTestId("plan-preview");
    const first = writes().find((w) => w.url.includes("/hosts/bulk"));
    expect(first?.body).toEqual({
      operations: [
        { op: "delete", args: { object: { kind: "host", id: HOST_IDS["laptop-ak"] }, expected: stored("laptop-ak")?.meta.revision, cascade: false } },
        { op: "delete", args: { object: { kind: "host", id: HOST_IDS["tv-living"] }, expected: stored("tv-living")?.meta.revision, cascade: false } },
      ],
    });
    fireEvent.click(within(dialog).getByTestId("delete-cascade"));
    await waitFor(() => expect(writes().filter((w) => w.url.includes("/hosts/bulk")).length).toBeGreaterThan(1));
    await confirmPlan({ dialog: "dialog-hosts-delete" });
    await gone("dialog-hosts-delete");
    const sent = applied(writes()).filter((w) => w.url.includes("/hosts/bulk"));
    expect(sent).toHaveLength(1);
    expect((sent[0]?.body as { operations: { args: { cascade: boolean } }[] }).operations.map((o) => o.args.cascade)).toEqual([true, true]);
    expect(stored("laptop-ak")?.meta.deleted).toBeTruthy();
    expect(stored("tv-living")?.meta.deleted).toBeTruthy();
    await waitFor(() => expect(names()).toEqual([]));
  });
});
