import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it } from "vitest";
import { HOST_IDS, ipamState } from "../api/mock/ipam/api";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { applied, confirmPlan, recordWrites } from "../ipam/testkit";
import HostsView from "./HostsView";

beforeEach(async () => {
  await signInAlex();
});

const BULK_DIALOG = "dialog-hosts-bulk";
/** The filter bar applies what is typed after a short pause. */
const DEBOUNCED = { timeout: 3000 };

function renderList(url = paths.hosts()) {
  return renderRoute(HostsView, { url, path: "/ipam/hosts", routes: { "/ipam/hosts/:fqdn": () => <div data-testid="host-route" /> } });
}

function rows(): HTMLElement[] {
  return screen.queryAllByTestId("row");
}

function names(): (string | undefined)[] {
  return rows().map((r) => r.dataset.key);
}

function rowOf(name: string): HTMLElement {
  const row = rows().find((r) => r.dataset.key === name);
  if (!row) throw new Error(`no row for host ${name}`);
  return row;
}

/** The mode word of a row, as a person reads it. */
function modeOf(name: string): string | undefined {
  return rowOf(name).querySelector(".mode")?.textContent ?? undefined;
}

function isLocked(name: string): boolean {
  return rowOf(name).querySelector(".flag.locked") !== null;
}

async function listed() {
  await waitFor(() => expect(rows().length).toBeGreaterThan(0));
}

function select(...hosts: string[]): void {
  for (const name of hosts) fireEvent.click(within(rowOf(name)).getByRole("checkbox"));
}

function typeFilter(text: string): void {
  fireEvent.input(screen.getByTestId("filter-input"), { target: { value: text } });
}

/** The host as the mock API stores it. */
function stored(name: string) {
  return ipamState().data.host.get(HOST_IDS[name] as string);
}

/** Opens the "Set mode" menu of the action bar and chooses a mode. */
async function chooseMode(mode: string): Promise<void> {
  fireEvent.click(screen.getByTestId("action-mode"));
  const menu = await screen.findByTestId("mode-menu");
  const item = menu.querySelector<HTMLElement>(`[data-item='${mode}']`);
  if (!item) throw new Error(`no menu item for the mode ${mode}`);
  fireEvent.click(item);
}

/** Waits for the plan dialog of a bulk action and returns it, preview done. */
async function bulkDialog(): Promise<HTMLElement> {
  const dialog = await screen.findByTestId(BULK_DIALOG);
  await within(dialog).findByTestId("plan-preview");
  return dialog;
}

async function dialogGone(): Promise<void> {
  await waitFor(() => expect(screen.queryByTestId(BULK_DIALOG)).toBeNull());
}

describe("the hosts list", () => {
  it("lists the seeded hosts with name, mode and lock", async () => {
    renderList();
    await listed();
    const grid = screen.getByRole("grid", { name: "Hosts" });
    const headers = within(grid)
      .getAllByRole("columnheader")
      .map((h) => h.textContent);
    expect(headers).toEqual(expect.arrayContaining(["Name", "Mode"]));
    // Sorted by name, ascending, as the request asks.
    expect(names()).toEqual([...names()].sort());
    // Every live host is in the list (the grid draws a window of them); the deleted one is not.
    const live = [...ipamState().data.host.values()].filter((h) => !h.meta.deleted);
    expect(grid.getAttribute("aria-rowcount")).toBe(String(live.length + 1));
    expect(names()).toEqual(expect.arrayContaining(["gw", "ha", "nas", "laptop-ak", "legacy-ups"]));
    expect(names()).not.toContain("old-printer");
    // The mode is a word, the lock a flag with a word.
    expect(modeOf("gw")).toBe("static");
    expect(modeOf("ap-hall")).toBe("reserved");
    expect(modeOf("laptop-ak")).toBe("dynamic");
    expect(modeOf("legacy-ups")).toBe("unmanaged");
    expect(isLocked("nas")).toBe(true);
    expect(within(rowOf("nas")).getByText("Locked")).toBeTruthy();
    expect(isLocked("gw")).toBe(false);
    expect(rows().filter((r) => r.querySelector(".flag.locked")).map((r) => r.dataset.key)).toEqual(["nas"]);
  });

  it("counts hosts in its footer and says why the number is not the number of addresses", async () => {
    renderList();
    await listed();
    const grid = screen.getByRole("grid", { name: "Hosts" });
    const shown = Number(grid.getAttribute("aria-rowcount")) - 1;
    const count = screen.getByTestId("grid-count");
    expect(count.textContent).toBe(`${shown} hosts`);
    expect(count.getAttribute("title")).toContain("Hosts, not addresses: a host can have several addresses");
  });

  it("narrows the list when a name is typed and brings it back when the filter is cleared", async () => {
    const view = renderList();
    await listed();
    expect(rows().length).toBeGreaterThan(10);
    typeFilter("printer");
    await waitFor(() => expect(names()).toEqual(["printer-1"]), DEBOUNCED);
    // The filter is part of the address of the page, so a link keeps it.
    expect(view.location()).toContain("q=printer");
    typeFilter("");
    await waitFor(() => expect(rows().length).toBeGreaterThan(10), DEBOUNCED);
    expect(view.location()).not.toContain("q=");
  });

  it("narrows the list with a mode term, alone and next to a name", async () => {
    renderList();
    await listed();
    typeFilter("mode:dynamic");
    await waitFor(() => expect(names()).toEqual(["host-192-0-2-16", "laptop-ak", "tv-living"]), DEBOUNCED);
    typeFilter("mode:static sw");
    await waitFor(() => expect(names()).toEqual(["sw-core", "sw-desk"]), DEBOUNCED);
    typeFilter("mode:unmanaged");
    await waitFor(() => expect(names()).toEqual(["legacy-ups"]), DEBOUNCED);
  });

  it("points out a mode that does not exist and keeps the list", async () => {
    renderList();
    await listed();
    typeFilter("mode:bogus");
    expect((await screen.findByText("bogus is not a value of mode", {}, DEBOUNCED)).closest("[role='status']")).toBeTruthy();
    expect(rows().length).toBeGreaterThan(10);
  });

  it("shows only locked hosts with the Locked chip", async () => {
    renderList();
    await listed();
    const chip = screen.getByTestId("filter-locked");
    expect(chip.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(chip);
    await waitFor(() => expect(names()).toEqual(["nas"]));
    expect(chip.getAttribute("aria-pressed")).toBe("true");
  });

  it("opens the host with Enter on the focused row", async () => {
    const view = renderList();
    await listed();
    const table = screen.getByRole("grid", { name: "Hosts" });
    table.focus();
    // The grid keeps the cell focus apart from the DOM focus: move it to the second row, then Enter.
    fireEvent.keyDown(table, { key: "ArrowDown" });
    const focused = document.getElementById(table.getAttribute("aria-activedescendant") ?? "")?.closest("tr");
    const name = focused?.dataset.key;
    expect(name).toBe(names()[1]);
    fireEvent.keyDown(table, { key: "Enter" });
    await waitFor(() => expect(view.location()).toBe(paths.host(name as string)));
    expect(await screen.findByTestId("host-route")).toBeTruthy();
  });

  it("has no accessibility violations once loaded", async () => {
    renderList();
    await listed();
    expect(await axeViolations(screen.getByTestId("page-hosts"))).toEqual([]);
  });
});

describe("bulk actions on the selection", () => {
  it("shows the action bar with the count while rows are selected", async () => {
    renderList();
    await listed();
    expect(screen.queryByTestId("actionbar")).toBeNull();
    select("ap-hall", "ap-garage");
    const bar = await screen.findByTestId("actionbar");
    expect(within(bar).getByText("2")).toBeTruthy();
    for (const id of ["action-move", "action-mode", "action-lock", "action-export"]) expect(within(bar).getByTestId(id)).toBeTruthy();
  });

  it("previews setting the mode as a dry run, applies it on confirm and shows the new mode", async () => {
    const writes = recordWrites();
    renderList();
    await listed();
    select("ap-hall", "ap-garage");
    await chooseMode("static");

    // The dialog names the action and the hosts; the preview wrote nothing.
    const dialog = await bulkDialog();
    expect(within(dialog).getByRole("heading", { name: "Set 2 hosts to static" })).toBeTruthy();
    expect([...dialog.querySelectorAll("ul.plain-list li")].map((li) => li.textContent)).toEqual(["ap-garage", "ap-hall"]);
    expect(within(dialog).getByTestId("plan-summary").textContent).toMatch(/Hosts: 2 updated/);
    expect(stored("ap-hall")?.mode).toBe("reserved");
    expect(stored("ap-garage")?.mode).toBe("reserved");
    expect(applied(writes())).toHaveLength(0);
    const preview = writes().find((w) => w.url.includes("/hosts/bulk"));
    expect(preview?.url).toContain("dry_run=true");
    expect(preview?.body).toEqual({
      operations: [
        { op: "set_mode", args: { host: HOST_IDS["ap-garage"], mode: "static", expected: stored("ap-garage")?.meta.revision } },
        { op: "set_mode", args: { host: HOST_IDS["ap-hall"], mode: "static", expected: stored("ap-hall")?.meta.revision } },
      ],
    });

    await confirmPlan({ dialog: BULK_DIALOG });
    await dialogGone();
    // One write applied, and the list read the hosts again.
    expect(applied(writes()).filter((w) => w.url.includes("/hosts/bulk"))).toHaveLength(1);
    expect(stored("ap-hall")?.mode).toBe("static");
    expect(stored("ap-garage")?.mode).toBe("static");
    await waitFor(() => expect(modeOf("ap-hall")).toBe("static"));
    expect(modeOf("ap-garage")).toBe("static");
    // The others are as they were, the selection is gone and the toast says what happened.
    expect(modeOf("ha")).toBe("reserved");
    expect(screen.queryByTestId("actionbar")).toBeNull();
    expect(await screen.findByText("Set 2 hosts to static")).toBeTruthy();
  });

  it("leaves the hosts alone when the dialog is cancelled", async () => {
    const writes = recordWrites();
    renderList();
    await listed();
    select("ap-hall");
    await chooseMode("dynamic");
    const dialog = await bulkDialog();
    expect(within(dialog).getByRole("heading", { name: "Set 1 host to dynamic" })).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await dialogGone();
    expect(applied(writes())).toHaveLength(0);
    expect(stored("ap-hall")?.mode).toBe("reserved");
    expect(modeOf("ap-hall")).toBe("reserved");
    // The selection stays, so the person can choose another action.
    expect(screen.getByTestId("actionbar")).toBeTruthy();
  });

  it("locks the selection from the action bar", async () => {
    renderList();
    await listed();
    select("gw", "ha");
    fireEvent.click(screen.getByTestId("action-lock"));
    const dialog = await bulkDialog();
    expect(within(dialog).getByRole("heading", { name: "Lock 2 hosts" })).toBeTruthy();
    expect(stored("gw")?.lock).toBe(false);
    await confirmPlan({ dialog: BULK_DIALOG });
    await dialogGone();
    expect(stored("gw")?.lock).toBe(true);
    expect(stored("ha")?.lock).toBe(true);
    await waitFor(() => expect(isLocked("gw")).toBe(true));
    expect(isLocked("ha")).toBe(true);
    expect(isLocked("pve1")).toBe(false);
    expect(screen.queryByTestId("actionbar")).toBeNull();
  });

  it("unlocks locked hosts with the L key", async () => {
    renderList();
    await listed();
    expect(isLocked("nas")).toBe(true);
    select("nas");
    fireEvent.keyDown(document.body, { key: "l" });
    const dialog = await bulkDialog();
    // Every selected host is locked, so the key unlocks.
    expect(within(dialog).getByRole("heading", { name: "Unlock 1 host" })).toBeTruthy();
    await confirmPlan({ dialog: BULK_DIALOG });
    await dialogGone();
    expect(stored("nas")?.lock).toBe(false);
    await waitFor(() => expect(isLocked("nas")).toBe(false));
  });

  it("locks all of a mixed selection with the L key", async () => {
    renderList();
    await listed();
    select("nas", "gw");
    fireEvent.keyDown(document.body, { key: "L", shiftKey: true });
    const dialog = await bulkDialog();
    expect(within(dialog).getByRole("heading", { name: "Lock 2 hosts" })).toBeTruthy();
    await confirmPlan({ dialog: BULK_DIALOG });
    await dialogGone();
    expect(stored("nas")?.lock).toBe(true);
    expect(stored("gw")?.lock).toBe(true);
    await waitFor(() => expect(isLocked("gw")).toBe(true));
  });

  it("ignores the L key while nothing is selected and while typing in the filter", async () => {
    renderList();
    await listed();
    fireEvent.keyDown(document.body, { key: "l" });
    expect(screen.queryByTestId(BULK_DIALOG)).toBeNull();
    select("gw");
    fireEvent.keyDown(screen.getByTestId("filter-input"), { key: "l" });
    expect(screen.queryByTestId(BULK_DIALOG)).toBeNull();
  });
});
