// Display gating of the hosts views (IAM-01): a scoped operator sees no write action outside its
// scope, a viewer none at all, an administrator all. The mock does not filter reads by scope, so
// casey sees every host and the views must hide the actions on those outside 203.0.113.0/24.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { describe, expect, it } from "vitest";
import { applyCommands, HOST_IDS } from "../api/mock/ipam/api";
import type { IpamCommand } from "../api/types";
import { paths } from "../app/paths";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { signInScopedOperator, signInWithRoles } from "../auth/scope-testkit";
import HostsView from "./HostsView";
import HostView from "./HostView";

const INSIDE = "cam-01"; // 203.0.113.193, inside casey's operator grant
const OUTSIDE = "gw"; // 192.0.2.1 and 2001:db8:0:10::1, no grant at all
const VIEWER_ONLY = "gw-iot"; // 198.51.100.1, casey is only a viewer there

function renderList() {
  return renderRoute(HostsView, { url: paths.hosts(), path: "/ipam/hosts", routes: { "/ipam/hosts/:fqdn": () => <div /> } });
}

const rows = () => screen.queryAllByTestId("row");
const rowOf = (name: string): HTMLElement => {
  const row = rows().find((r) => r.dataset.key === name);
  if (!row) throw new Error(`no row for host ${name}`);
  return row;
};
const listed = () => waitFor(() => expect(rows().length).toBeGreaterThan(20));
const select = (...names: string[]) => {
  for (const name of names) fireEvent.click(within(rowOf(name)).getByRole("checkbox"));
};
const BAR = ["action-move", "action-mode", "action-lock", "action-decommission", "action-delete"];
const barActions = () => BAR.filter((id) => screen.queryByTestId(id));

/** The ids of the items of the row menu of a host. */
async function menuOf(name: string): Promise<string[]> {
  fireEvent.click(rowOf(name).querySelector(".row-menu") as HTMLElement);
  const menu = await screen.findByTestId("row-menu");
  const ids = [...menu.querySelectorAll<HTMLElement>("[data-item]")].map((el) => el.dataset.item ?? "");
  fireEvent.keyDown(menu, { key: "Escape" });
  return ids;
}

describe("gating of the hosts list", () => {
  it("shows an administrator every action", async () => {
    await signInAlex();
    renderList();
    await listed();
    expect(screen.getByTestId("hosts-create")).toBeTruthy();
    select(INSIDE, OUTSIDE);
    expect(barActions()).toEqual(BAR);
    expect(await menuOf(OUTSIDE)).toEqual(["open", "move", "lock", "history", "restore", "decommission", "delete"]);
  });

  it("shows a scoped operator the actions on the hosts of its grant only", async () => {
    await signInScopedOperator();
    renderList();
    await listed();
    // A prefix rule can cover a host, so new hosts are not hidden.
    expect(screen.queryByTestId("hosts-create")).toBeNull();
    select(INSIDE);
    expect(barActions()).toEqual(BAR);
    expect(await menuOf(INSIDE)).toEqual(["open", "move", "lock", "history", "restore", "decommission", "delete"]);
    // A host outside the scope in the selection hides the bulk write actions.
    select(OUTSIDE);
    expect(barActions()).toEqual([]);
    expect(screen.getByTestId("action-export")).toBeTruthy();
  });

  it.each([OUTSIDE, VIEWER_ONLY])("hides every row action of a scoped operator on %s", async (name) => {
    await signInScopedOperator();
    renderList();
    await listed();
    select(name);
    expect(barActions()).toEqual([]);
    expect(screen.getByTestId("action-export")).toBeTruthy();
    expect(await menuOf(name)).toEqual(["open", "history"]);
    expect(rowOf(name).getAttribute("draggable")).not.toBe("true");
  });

  it("hides every write action from a viewer", async () => {
    await signInWithRoles(["viewer"]);
    renderList();
    await listed();
    expect(screen.queryByTestId("hosts-create")).toBeNull();
    select(INSIDE);
    expect(barActions()).toEqual([]);
    expect(await menuOf(INSIDE)).toEqual(["open", "history"]);
  });
});

describe("gating of the host view", () => {
  const ACTIONS = ["host-edit", "host-mode", "host-lock", "host-move", "host-decommission", "host-delete", "interface-add"];

  async function shown(name: string) {
    renderRoute(HostView, { url: paths.host(name), path: "/ipam/hosts/:fqdn" });
    const page = await screen.findByTestId("page-host");
    await screen.findByTestId("host-modes");
    await waitFor(() => expect(within(screen.getByTestId("grid-host-interfaces")).queryAllByTestId("row")).toHaveLength(1));
    await waitFor(() => expect(within(page).queryByTestId("history-panel")).toBeTruthy());
    return page;
  }
  const present = (page: HTMLElement) => ACTIONS.filter((id) => within(page).queryByTestId(id));

  async function interfaceMenu(): Promise<string[]> {
    const grid = screen.getByTestId("grid-host-interfaces");
    const button = grid.querySelector(".row-menu") as HTMLElement | null;
    if (!button) return [];
    fireEvent.click(button);
    const menu = await screen.findByTestId("row-menu");
    const ids = [...menu.querySelectorAll<HTMLElement>("[data-item]")].map((el) => el.dataset.item ?? "");
    fireEvent.keyDown(menu, { key: "Escape" });
    return ids;
  }

  it("shows an administrator every action", async () => {
    await signInAlex();
    const page = await shown(OUTSIDE);
    expect(present(page)).toEqual(ACTIONS);
    expect(await interfaceMenu()).toEqual(["edit", "delete"]);
  });

  it("shows a scoped operator the actions on a host of its grant", async () => {
    await signInScopedOperator();
    const page = await shown(INSIDE);
    expect(present(page)).toEqual(ACTIONS);
    expect(await interfaceMenu()).toEqual(["edit", "delete"]);
  });

  it.each([OUTSIDE, VIEWER_ONLY])("hides them from a scoped operator on %s", async (name) => {
    await signInScopedOperator();
    const page = await shown(name);
    expect(present(page)).toEqual([]);
    expect(await interfaceMenu()).toEqual([]);
    // The keys do nothing either.
    fireEvent.keyDown(document, { key: "m" });
    expect(screen.queryByTestId("dialog-move-target")).toBeNull();
  });

  it("hides them from a viewer", async () => {
    await signInWithRoles(["viewer"]);
    const page = await shown(INSIDE);
    expect(present(page)).toEqual([]);
    expect(await interfaceMenu()).toEqual([]);
  });
});

describe("gating of the host lifecycle", () => {
  const decommission = (name: string) =>
    applyCommands([{ op: "decommission_host", args: { host: HOST_IDS[name], keep_dns: false } }] as unknown as IpamCommand[]);
  const LIFECYCLE_BAR = ["action-decommission", "action-reinstate", "action-delete"];
  const lifecycleBar = () => LIFECYCLE_BAR.filter((id) => screen.queryByTestId(id));

  function renderWith(lifecycle: string) {
    return renderRoute(HostsView, { url: `${paths.hosts()}?lifecycle=${lifecycle}`, path: "/ipam/hosts", routes: { "/ipam/hosts/:fqdn": () => <div /> } });
  }

  it("offers a scoped operator Reinstate and Delete on the decommissioned hosts of its grant only", async () => {
    await signInScopedOperator();
    decommission(INSIDE);
    decommission(OUTSIDE);
    renderWith("decommissioned");
    await waitFor(() => expect(rows()).toHaveLength(2));
    expect(await menuOf(INSIDE)).toEqual(["open", "move", "lock", "history", "restore", "reinstate", "delete"]);
    expect(await menuOf(OUTSIDE)).toEqual(["open", "history"]);
    select(INSIDE);
    expect(lifecycleBar()).toEqual(["action-reinstate", "action-delete"]);
    select(OUTSIDE);
    expect(lifecycleBar()).toEqual([]);
  });

  it("shows an administrator Reinstate for decommissioned hosts and Decommission for active ones", async () => {
    await signInAlex();
    decommission(OUTSIDE);
    renderWith("all");
    await listed();
    expect(await menuOf(OUTSIDE)).toEqual(["open", "move", "lock", "history", "restore", "reinstate", "delete"]);
    expect(await menuOf(INSIDE)).toEqual(["open", "move", "lock", "history", "restore", "decommission", "delete"]);
    select(OUTSIDE);
    expect(lifecycleBar()).toEqual(["action-reinstate", "action-delete"]);
    select(INSIDE);
    // A mix of active and decommissioned hosts can be deleted, nothing else of the lifecycle.
    expect(lifecycleBar()).toEqual(["action-delete"]);
  });

  async function banner(name: string) {
    renderRoute(HostView, { url: paths.host(name), path: "/ipam/hosts/:fqdn" });
    await screen.findByTestId("host-modes");
    return await screen.findByTestId("host-decommissioned");
  }

  it("offers Reinstate on the banner to whoever may delete the host", async () => {
    await signInScopedOperator();
    decommission(INSIDE);
    const shown = await banner(INSIDE);
    expect(within(shown).getByTestId("host-reinstate")).toBeTruthy();
  });

  it.each([OUTSIDE, VIEWER_ONLY])("shows a scoped operator the banner of %s without Reinstate", async (name) => {
    await signInScopedOperator();
    decommission(name);
    const shown = await banner(name);
    expect(within(shown).queryByTestId("host-reinstate")).toBeNull();
    expect(screen.queryByTestId("host-decommission")).toBeNull();
  });

  it("shows a viewer the banner without Reinstate", async () => {
    await signInWithRoles(["viewer"]);
    decommission(INSIDE);
    const shown = await banner(INSIDE);
    expect(within(shown).queryByTestId("host-reinstate")).toBeNull();
  });
});
