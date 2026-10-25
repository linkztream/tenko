import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ADDRESS_IDS, IPAM_IDS, ipamState } from "../../api/mock/ipam/api";
import type { AddressRow } from "../../api/types";
import { paths } from "../../app/paths";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { chooseVrf } from "../scope";
import { confirmPlan } from "../testkit";
import AddressesView from "./AddressesView";
import { ADDRESS_COLUMNS, addressesCsv, csvField, protectCell, toCsv } from "./csv";

// ---------------------------------------------------------------------------------
// Helpers

const BOM = String.fromCharCode(0xfeff);

beforeEach(async () => {
  // The VRF in view is remembered per browser; every test starts from the default.
  chooseVrf(null);
  await signInAlex();
});

afterEach(() => {
  chooseVrf(null);
});

function renderList(url = paths.addresses()) {
  return renderRoute(AddressesView, {
    url,
    path: "/ipam/addresses",
    routes: {
      "/ipam/addresses/:ip": () => <div data-testid="address-route" />,
      "/ipam/move": () => <div data-testid="move-route" />,
    },
  });
}

function rows(): HTMLElement[] {
  return screen.queryAllByTestId("row");
}

function keys(): (string | undefined)[] {
  return rows().map((r) => r.dataset.key);
}

function rowOf(ip: string): HTMLElement {
  const row = rows().find((r) => r.dataset.key === ip);
  if (!row) throw new Error(`no row for ${ip}`);
  return row;
}

/** The text of one cell of a row, by column id. */
function cell(ip: string, column: string): string {
  const td = rowOf(ip).querySelector(`td[data-col="${column}"]`);
  if (!td) throw new Error(`no ${column} cell in the row of ${ip}`);
  return td.textContent?.trim() ?? "";
}

async function listed() {
  await waitFor(() => expect(rows().length).toBeGreaterThan(0));
}

function filterBy(text: string) {
  fireEvent.input(within(screen.getByTestId("filterbar")).getByTestId("filter-input"), { target: { value: text } });
}

function select(...ips: string[]) {
  for (const ip of ips) fireEvent.click(within(rowOf(ip)).getByRole("checkbox"));
}

/** The requests that went to the API, as paths with their queries. */
function spyOnRequests(): () => URL[] {
  const spy = vi.spyOn(globalThis, "fetch");
  return () =>
    spy.mock.calls.map(([input]) => new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, "http://localhost"));
}

/** Replaces the object URL functions jsdom lacks and records what `saveTextFile` hands to the browser. */
function captureDownloads() {
  const blobs: Blob[] = [];
  const saved: { createObjectURL?: PropertyDescriptor | undefined; revokeObjectURL?: PropertyDescriptor | undefined } = {};
  const define = (name: "createObjectURL" | "revokeObjectURL", value: unknown) => {
    saved[name] = Object.getOwnPropertyDescriptor(URL, name);
    Object.defineProperty(URL, name, { value, configurable: true, writable: true });
  };
  define("createObjectURL", (blob: Blob) => {
    blobs.push(blob);
    return `blob:https://tenko.example.test/${blobs.length}`;
  });
  define("revokeObjectURL", () => undefined);
  const downloads: string[] = [];
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
    downloads.push(this.download);
  });
  const restore = () => {
    for (const name of ["createObjectURL", "revokeObjectURL"] as const) {
      const original = saved[name];
      if (original) Object.defineProperty(URL, name, original);
      else Reflect.deleteProperty(URL, name);
    }
  };
  return { blobs, downloads, restore };
}

/** The bytes of a blob, read the way a browser saves them. */
function bytesOf(blob: Blob): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(blob);
  });
}

const stored = (ip: string) => ipamState().data.address.get(ADDRESS_IDS[ip] as string)!;

// ---------------------------------------------------------------------------------
// The list

describe("the global address list", () => {
  it("lists the addresses of the VRF in view in address order", async () => {
    renderList();
    await listed();
    const grid = screen.getByRole("grid", { name: "Addresses" });
    expect(within(grid).getAllByRole("columnheader").map((h) => h.textContent?.trim())).toEqual([
      "",
      "Address",
      "Prefix",
      "DNS name",
      "Host",
      "Mode",
      "MAC",
      "Status",
      "Actions",
    ]);
    // The first rows, in address order; the soft-deleted 192.0.2.35 and the VRF isolated are not in the list.
    expect(keys().slice(0, 6)).toEqual(["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.10"]);
    expect(keys()).not.toContain("192.0.2.35");
    const live = [...ipamState().data.address.values()].filter((a) => a.vrf === IPAM_IDS.vrf.default && !a.meta.deleted);
    expect(grid.getAttribute("aria-rowcount")).toBe(String(live.length + 1));
    expect(screen.getByTestId("grid-foot").textContent).toContain(`${live.length} rows`);
    // The prefix column names the network of the address.
    expect(cell("192.0.2.41", "prefix")).toBe("192.0.2.0/24");
    expect(cell("198.51.100.1", "prefix")).toBe("198.51.100.0/24");
    expect(cell("203.0.113.193", "prefix")).toBe("203.0.113.192/28");
  });

  it("shows the host, mode and MAC of a bound address from the expanded list", async () => {
    renderList();
    await listed();
    expect(cell("192.0.2.41", "dns_name")).toBe("thermostat-1.example.test");
    expect(cell("192.0.2.41", "host")).toBe("thermostat-1");
    const link = within(rowOf("192.0.2.41")).getByRole("link", { name: "thermostat-1" });
    expect(link.getAttribute("href")).toBe(paths.host("thermostat-1"));
    expect(cell("192.0.2.41", "mode")).toBe("reserved");
    expect(cell("192.0.2.41", "mac")).toBe("00:00:5e:00:53:29");
    expect(cell("192.0.2.41", "status")).toBe("Active");
    // Other modes, and the lock flag of a locked host.
    expect(cell("192.0.2.30", "mode")).toBe("static");
    expect(cell("192.0.2.20", "mode")).toBe("dynamic");
    expect(cell("192.0.2.250", "mode")).toBe("unmanaged");
    expect(cell("192.0.2.11", "mode")).toContain("Locked");
    expect(cell("192.0.2.30", "mode")).not.toContain("Locked");
  });

  it("leaves the MAC empty for an interface without one", async () => {
    renderList();
    await listed();
    expect(cell("192.0.2.60", "host")).toBe("doorbell");
    expect(cell("192.0.2.60", "mode")).toBe("reserved");
    expect(cell("192.0.2.60", "mac")).toBe("");
  });

  it("leaves host, mode and MAC empty for an address that no interface holds", async () => {
    // A free-standing address: the VRF default has none in the seed, so release one.
    const address = stored("192.0.2.42");
    address.interface = null;
    renderList();
    await listed();
    expect(cell("192.0.2.42", "dns_name")).toBe("plug-kitchen.example.test");
    expect(cell("192.0.2.42", "host")).toBe("");
    expect(cell("192.0.2.42", "mode")).toBe("");
    expect(cell("192.0.2.42", "mac")).toBe("");
  });

  it("reads the host, mode and MAC with the list itself and makes no request per row", async () => {
    const requests = spyOnRequests();
    renderList();
    await listed();
    await waitFor(() => expect(cell("192.0.2.41", "mac")).toBe("00:00:5e:00:53:29"));
    const all = requests();
    const lists = all.filter((u) => u.pathname === "/api/v1/addresses");
    expect(lists.length).toBeGreaterThanOrEqual(1);
    for (const url of lists) expect(url.searchParams.get("expand"), url.href).toBe("host");
    // Not one read of a host, an interface or a single address.
    const perRow = all.filter((u) => /^\/api\/v1\/(hosts|interfaces|addresses)\/[^/]+/.test(u.pathname));
    expect(perRow.map((u) => u.pathname)).toEqual([]);
    expect(all.filter((u) => u.pathname.startsWith("/api/v1/hosts"))).toEqual([]);
    expect(all.filter((u) => u.pathname.startsWith("/api/v1/interfaces"))).toEqual([]);
  });

  it("asks the server for the VRF in view and the sort", async () => {
    const requests = spyOnRequests();
    renderList();
    await listed();
    const list = requests().find((u) => u.pathname === "/api/v1/addresses");
    expect(list?.searchParams.get("vrf")).toBe(IPAM_IDS.vrf.default);
    expect(list?.searchParams.get("sort")).toBe("ip");
    expect(list?.searchParams.has("deleted")).toBe(false);
  });

  it("shows the addresses of another VRF after switching with the scope switcher", async () => {
    renderList();
    await listed();
    const scope = screen.getByTestId("ipam-scope") as HTMLSelectElement;
    expect([...scope.options].map((o) => o.textContent)).toEqual(["default / default", "Workshop / isolated"]);
    fireEvent.change(scope, { target: { value: IPAM_IDS.vrf.isolated } });
    await waitFor(() => expect(keys()).toEqual(["192.0.2.10", "192.0.2.20"]));
    expect(cell("192.0.2.10", "dns_name")).toBe("bench-1.example.test");
    expect(cell("192.0.2.10", "host")).toBe("");
    expect(cell("192.0.2.10", "prefix")).toBe("192.0.2.0/24");
  });

  it("opens an address with a double click, naming its VRF in the link", async () => {
    const view = renderList();
    await listed();
    fireEvent.dblClick(within(rowOf("192.0.2.41")).getByText("41"));
    await screen.findByTestId("address-route");
    expect(view.location()).toBe(paths.address("192.0.2.41", IPAM_IDS.vrf.default));
  });

  it("opens an address from its row menu", async () => {
    const view = renderList();
    await listed();
    fireEvent.click(within(rowOf("198.51.100.44")).getByRole("button", { name: "Actions for 198.51.100.44" }));
    const menu = await screen.findByTestId("row-menu");
    fireEvent.click(within(menu).getByRole("menuitem", { name: "Open" }));
    await screen.findByTestId("address-route");
    expect(view.location()).toBe(paths.address("198.51.100.44", IPAM_IDS.vrf.default));
  });

  it("says so when the VRF has no addresses", async () => {
    for (const id of [...ipamState().data.address.keys()]) {
      if (ipamState().data.address.get(id)?.vrf === IPAM_IDS.vrf.isolated) ipamState().data.address.delete(id);
    }
    chooseVrf(IPAM_IDS.vrf.isolated);
    renderList();
    const empty = await screen.findByTestId("grid-empty");
    expect(empty.textContent).toContain("No addresses in this VRF yet.");
  });
});

// ---------------------------------------------------------------------------------
// Filtering

describe("filtering the address list", () => {
  it("narrows the list by text and writes the text into the link", async () => {
    const view = renderList();
    await listed();
    filterBy("thermostat");
    await waitFor(() => expect(keys()).toEqual(["192.0.2.41"]));
    expect(view.location()).toBe("/ipam/addresses?q=thermostat");
    // The text also matches the address itself.
    filterBy("198.51.100");
    await waitFor(() => expect(keys()).toEqual(["198.51.100.1", "198.51.100.44"]));
    // Clearing the field brings the list back and drops the parameter.
    filterBy("");
    await waitFor(() => expect(rows().length).toBeGreaterThan(20));
    expect(view.location()).toBe("/ipam/addresses");
  });

  it("narrows the list by a field term", async () => {
    renderList();
    await listed();
    filterBy("within:203.0.113.192/28");
    await waitFor(() => expect(rows().length).toBe(13));
    expect(keys().every((k) => k?.startsWith("203.0.113.19") || k?.startsWith("203.0.113.20"))).toBe(true);
    expect(cell("203.0.113.193", "host")).toBe("cam-01");
    // A status term, together with the within term.
    filterBy("within:203.0.113.192/28 status:planned");
    expect(await screen.findByText("No rows match the filter.")).toBeTruthy();
    expect(rows()).toEqual([]);
  });

  it("combines free text with a field term", async () => {
    renderList();
    await listed();
    filterBy("within:203.0.113.192/28 cam-05");
    await waitFor(() => expect(keys()).toEqual(["203.0.113.197"]));
  });

  it("starts from the q of the link", async () => {
    renderList("/ipam/addresses?q=within:198.51.100.0/24");
    await waitFor(() => expect(keys()).toEqual(["198.51.100.1", "198.51.100.44"]));
    expect((screen.getByTestId("filter-input") as HTMLInputElement).value).toBe("within:198.51.100.0/24");
  });

  it("points out a status the filter does not know and does not send it", async () => {
    const requests = spyOnRequests();
    renderList();
    await listed();
    filterBy("status:bogus");
    const note = await screen.findByText("bogus is not a value of status");
    expect(note).toBeTruthy();
    await waitFor(() => expect(rows().length).toBeGreaterThan(20));
    expect(requests().some((u) => u.searchParams.get("status") === "bogus")).toBe(false);
  });

  it("shows deleted addresses, marked as deleted, with the deleted filter", async () => {
    renderList();
    await listed();
    expect(keys()).not.toContain("192.0.2.35");
    const filter = screen.getByRole("group", { name: "Deleted objects" });
    expect((within(filter).getByRole("button", { name: "Current" }) as HTMLButtonElement).getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(within(filter).getByRole("button", { name: "With deleted" }));
    await waitFor(() => expect(keys()).toContain("192.0.2.35"));
    const gone = rowOf("192.0.2.35");
    expect(gone.classList.contains("deleted")).toBe(true);
    expect(within(gone).getByText("Deleted")).toBeTruthy();
    // A deleted address cannot be selected; a live one can.
    expect(within(gone).queryByRole("checkbox")).toBeNull();
    expect(within(rowOf("192.0.2.41")).getByRole("checkbox")).toBeTruthy();
    expect(rowOf("192.0.2.41").classList.contains("deleted")).toBe(false);
    expect(within(rowOf("192.0.2.41")).queryByText("Deleted")).toBeNull();
  });

  it("shows only the deleted addresses and keeps the choice in the link", async () => {
    const view = renderList();
    await listed();
    const filter = screen.getByRole("group", { name: "Deleted objects" });
    fireEvent.click(within(filter).getByRole("button", { name: "Deleted only" }));
    await waitFor(() => expect(keys()).toEqual(["192.0.2.35"]));
    expect(view.location()).toBe("/ipam/addresses?deleted=only");
    expect(cell("192.0.2.35", "status")).toContain("Deleted");
    // Back to the current addresses.
    fireEvent.click(within(filter).getByRole("button", { name: "Current" }));
    await waitFor(() => expect(keys()).not.toContain("192.0.2.35"));
    expect(view.location()).toBe("/ipam/addresses");
  });

  it("starts with the deleted addresses when the link asks for them", async () => {
    renderList("/ipam/addresses?deleted=only");
    await waitFor(() => expect(keys()).toEqual(["192.0.2.35"]));
    const filter = screen.getByRole("group", { name: "Deleted objects" });
    expect(within(filter).getByRole("button", { name: "Deleted only" }).getAttribute("aria-pressed")).toBe("true");
  });

  it("offers restore for a deleted address and delete for a live one", async () => {
    renderList("/ipam/addresses?deleted=include");
    await waitFor(() => expect(keys()).toContain("192.0.2.35"));
    /** Which items of the row menu are switched off, by item id. */
    const switchedOff = async (ip: string) => {
      fireEvent.click(within(rowOf(ip)).getByRole("button", { name: `Actions for ${ip}` }));
      const menu = await screen.findByTestId("row-menu");
      const state: Record<string, boolean> = {};
      for (const item of within(menu).getAllByRole("menuitem")) state[item.dataset.item ?? ""] = item.getAttribute("aria-disabled") === "true";
      fireEvent.keyDown(menu, { key: "Escape" });
      await waitFor(() => expect(screen.queryByTestId("row-menu")).toBeNull());
      return state;
    };
    expect(await switchedOff("192.0.2.35")).toEqual({ open: false, move: true, history: false, restore: false, delete: true });
    // "Reserve in DHCP" depends on the DHCP scopes, which are read in a request of their own.
    await waitFor(async () =>
      expect(await switchedOff("192.0.2.41")).toEqual({ open: false, move: false, history: false, reserve: false, restore: true, delete: false }),
    );
  });

  it("deletes an address from its row menu and restores it from the deleted ones", async () => {
    renderList();
    await listed();
    const menuItem = async (ip: string, name: string) => {
      fireEvent.click(within(rowOf(ip)).getByRole("button", { name: `Actions for ${ip}` }));
      fireEvent.click(await within(await screen.findByTestId("row-menu")).findByRole("menuitem", { name }));
    };
    await menuItem("192.0.2.42", "Delete");
    await confirmPlan({ dialog: "dialog-delete" });
    await waitFor(() => expect(stored("192.0.2.42").meta.deleted).toBeTruthy());
    await waitFor(() => expect(keys()).not.toContain("192.0.2.42"));

    fireEvent.click(within(screen.getByRole("group", { name: "Deleted objects" })).getByRole("button", { name: "Deleted only" }));
    await waitFor(() => expect(keys()).toEqual(["192.0.2.35", "192.0.2.42"]));
    await menuItem("192.0.2.42", "Restore");
    await confirmPlan({ dialog: "dialog-restore" });
    await waitFor(() => expect(stored("192.0.2.42").meta.deleted).toBeNull());
    await waitFor(() => expect(keys()).toEqual(["192.0.2.35"]));
  });

  it("shows the history of an address from its row menu", async () => {
    renderList();
    await listed();
    fireEvent.click(within(rowOf("192.0.2.41")).getByRole("button", { name: "Actions for 192.0.2.41" }));
    fireEvent.click(await within(await screen.findByTestId("row-menu")).findByRole("menuitem", { name: "History" }));
    const dialog = await screen.findByTestId("dialog-history");
    expect(within(dialog).getByRole("heading", { name: "History of 192.0.2.41" })).toBeTruthy();
    const entries = await within(dialog).findAllByTestId("history-entry");
    expect(entries.length).toBeGreaterThan(0);
    expect(entries[entries.length - 1]?.dataset.action).toBe("create");
  });
});

// ---------------------------------------------------------------------------------
// Selection and its actions

describe("acting on selected addresses", () => {
  it("shows the action bar with the count while addresses are selected", async () => {
    renderList();
    await listed();
    expect(screen.queryByTestId("action-export")).toBeNull();
    select("192.0.2.41", "192.0.2.42");
    const bar = await screen.findByRole("toolbar", { name: "Selection actions" });
    expect(bar.textContent).toContain("2");
    expect(within(bar).getByTestId("action-move")).toBeTruthy();
    expect(within(bar).getByTestId("action-export")).toBeTruthy();
    fireEvent.click(within(bar).getByRole("button", { name: "Clear selection (Esc)" }));
    await waitFor(() => expect(screen.queryByRole("toolbar", { name: "Selection actions" })).toBeNull());
  });

  it("opens the move target dialog for the selection", async () => {
    renderList();
    await listed();
    select("192.0.2.41", "192.0.2.42");
    fireEvent.click(await screen.findByTestId("action-move"));
    const dialog = await screen.findByTestId("dialog-move-target");
    expect(within(dialog).getByRole("heading", { name: "Move 2 objects to a network" })).toBeTruthy();
    await waitFor(() => expect(within(dialog).getAllByRole("option").length).toBeGreaterThan(0));
  });

  it("goes to the move preview with the selected addresses when a target is chosen", async () => {
    const view = renderList();
    await listed();
    select("192.0.2.41", "192.0.2.42");
    fireEvent.click(await screen.findByTestId("action-move"));
    const dialog = await screen.findByTestId("dialog-move-target");
    await waitFor(() => expect(within(dialog).getAllByRole("option").length).toBeGreaterThan(0));
    fireEvent.click(within(dialog).getAllByRole("option").find((o) => (o as HTMLElement).dataset.key === "198.51.100.0/24") as HTMLElement);
    await screen.findByTestId("move-route");
    expect(view.location()).toBe(
      paths.move(IPAM_IDS.prefix.iot, [
        { kind: "address", id: ADDRESS_IDS["192.0.2.41"] as string },
        { kind: "address", id: ADDRESS_IDS["192.0.2.42"] as string },
      ]),
    );
  });

  it("opens the move target dialog with the M key", async () => {
    renderList();
    await listed();
    // Nothing is selected, so M does nothing.
    fireEvent.keyDown(document.body, { key: "m" });
    expect(screen.queryByTestId("dialog-move-target")).toBeNull();
    select("192.0.2.43");
    fireEvent.keyDown(document.body, { key: "m" });
    const dialog = await screen.findByTestId("dialog-move-target");
    expect(within(dialog).getByRole("heading", { name: "Move 1 object to a network" })).toBeTruthy();
  });

  describe("exporting the selection as CSV", () => {
    let capture: ReturnType<typeof captureDownloads>;

    beforeEach(() => {
      capture = captureDownloads();
    });

    afterEach(() => {
      capture.restore();
    });

    it("saves the selected rows with a byte order mark, quoted cells and protected formulas", async () => {
      // Cells a spreadsheet would misread: a formula with commas and quotes, tags with a space.
      const thermostat = stored("192.0.2.41");
      thermostat.meta.description = '=HYPERLINK("https://example.org/a","x")';
      thermostat.meta.tags = ["iot", "front door"];
      const printer = stored("192.0.2.30");
      printer.meta.description = "Floor 2, room 4";
      renderList();
      await listed();
      select("192.0.2.60", "192.0.2.41", "192.0.2.30");
      fireEvent.click(await screen.findByTestId("action-export"));

      expect(capture.downloads).toEqual(["addresses.csv"]);
      expect(capture.blobs).toHaveLength(1);
      const blob = capture.blobs[0] as Blob;
      expect(blob.type).toBe("text/csv;charset=utf-8");
      const bytes = await bytesOf(blob);
      // The byte order mark: EF BB BF.
      expect([...bytes.slice(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
      const text = new TextDecoder().decode(bytes.slice(3));
      const lines = text.split("\r\n");
      // The rows come in grid order; the file ends with a line break.
      expect(lines.pop()).toBe("");
      expect(lines).toEqual([
        "address,vrf,status,dns_name,host,interface,mac,duid,description,tags",
        "192.0.2.30,default,active,printer-1.example.test,printer-1,eth0,00:00:5e:00:53:1e,,\"Floor 2, room 4\",",
        "192.0.2.41,default,active,thermostat-1.example.test,thermostat-1,eth0,00:00:5e:00:53:29,,\"'=HYPERLINK(\"\"https://example.org/a\"\",\"\"x\"\")\",iot; front door",
        // The doorbell has no MAC address: its cell is empty.
        "192.0.2.60,default,active,doorbell.example.test,doorbell,eth0,,,,",
      ]);
    });

    it("names the VRF of the rows in the file", async () => {
      chooseVrf(IPAM_IDS.vrf.isolated);
      renderList();
      await waitFor(() => expect(keys()).toEqual(["192.0.2.10", "192.0.2.20"]));
      select("192.0.2.20");
      fireEvent.click(await screen.findByTestId("action-export"));
      const bytes = await bytesOf(capture.blobs[0] as Blob);
      const lines = new TextDecoder().decode(bytes.slice(3)).split("\r\n");
      expect(lines[1]).toBe("192.0.2.20,isolated,active,bench-2.example.test,,,,,,");
    });
  });

  it("passes axe", async () => {
    renderList();
    await listed();
    select("192.0.2.41");
    await screen.findByTestId("action-export");
    expect(await axeViolations(screen.getByTestId("page-ipam-addresses"))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------
// csv.ts

describe("the CSV functions", () => {
  describe("protectCell", () => {
    it("puts a quote before a cell a spreadsheet would read as a formula", () => {
      for (const cell of ["=1+1", "+1", "-1+1", "@SUM(A1)", "\tcmd", "\rcmd", "=cmd|' /C calc'!A0", "-x", "-1.5", "- 3"]) {
        expect(protectCell(cell), JSON.stringify(cell)).toBe(`'${cell}`);
      }
    });

    it("quotes again a cell that already starts with quotes before a formula character", () => {
      expect(protectCell("'=1+1")).toBe("''=1+1");
    });

    it("keeps a negative whole number a number", () => {
      expect(protectCell("-5")).toBe("-5");
      expect(protectCell("-0")).toBe("-0");
    });

    it("leaves ordinary cells alone", () => {
      for (const cell of ["", "plain", "192.0.2.41", "00:00:5e:00:53:29", "a=b", "x-y", "2001:db8::1", "name@example.org", "'quoted", " =space"]) {
        expect(protectCell(cell), JSON.stringify(cell)).toBe(cell);
      }
    });
  });

  describe("csvField", () => {
    it("quotes a cell with a comma, a quote or a line break", () => {
      expect(csvField("a,b")).toBe('"a,b"');
      expect(csvField('say "hi"')).toBe('"say ""hi"""');
      expect(csvField("two\nlines")).toBe('"two\nlines"');
      expect(csvField("two\r\nlines")).toBe('"two\r\nlines"');
      expect(csvField("one\rtwo")).toBe('"one\rtwo"');
    });

    it("leaves a plain cell unquoted", () => {
      expect(csvField("plain")).toBe("plain");
      expect(csvField("")).toBe("");
      expect(csvField("with space")).toBe("with space");
      expect(csvField("semi; colon")).toBe("semi; colon");
    });

    it("protects a formula before it quotes", () => {
      expect(csvField("=A1")).toBe("'=A1");
      expect(csvField("=A1,B1")).toBe(`"'=A1,B1"`);
      expect(csvField('@"x"')).toBe(`"'@""x"""`);
    });
  });

  describe("toCsv", () => {
    it("writes a byte order mark, CRLF line ends and a closing line break", () => {
      const text = toCsv(["a", "b"], [["1", "2"], ["3", "4"]]);
      expect(text.startsWith(BOM)).toBe(true);
      expect(text.charCodeAt(0)).toBe(0xfeff);
      expect(text.slice(1)).toBe("a,b\r\n1,2\r\n3,4\r\n");
      expect(text.slice(1).includes("\n\n")).toBe(false);
    });

    it("writes only the header for no rows", () => {
      expect(toCsv(["a", "b"], [])).toBe(`${BOM}a,b\r\n`);
    });

    it("applies the cell rules to the header and the rows", () => {
      expect(toCsv(["=h", "x,y"], [["-1", "-a", '"q"']])).toBe(`${BOM}'=h,"x,y"\r\n-1,'-a,"""q"""\r\n`);
    });

    it("keeps non-ASCII text as it is", () => {
      expect(toCsv(["name"], [["café"]])).toBe(`${BOM}name\r\ncafé\r\n`);
    });
  });

  describe("addressesCsv", () => {
    const base = (): AddressRow => structuredClone(stored("192.0.2.41")) as AddressRow;

    it("uses the import vocabulary as its header", () => {
      expect(ADDRESS_COLUMNS).toEqual(["address", "vrf", "status", "dns_name", "host", "interface", "mac", "duid", "description", "tags"]);
      expect(addressesCsv([], (id) => id)).toBe(`${BOM}${ADDRESS_COLUMNS.join(",")}\r\n`);
    });

    it("writes an address with its host and interface", () => {
      const row: AddressRow = {
        ...base(),
        host: { id: "h", name: "thermostat-1", mode: "reserved", lock: false },
        interface_detail: { id: "i", name: "eth0", mac: "00:00:5e:00:53:29", duid: null },
      };
      row.meta.tags = ["iot", "camera"];
      row.meta.description = "Hall";
      const lines = addressesCsv([row], (id) => (id === IPAM_IDS.vrf.default ? "default" : id)).split("\r\n");
      expect(lines[1]).toBe("192.0.2.41,default,active,thermostat-1.example.test,thermostat-1,eth0,00:00:5e:00:53:29,,Hall,iot; camera");
    });

    it("writes empty cells for what an address does not have", () => {
      const row: AddressRow = { ...base(), dns_name: null, interface: null };
      row.meta.description = null;
      row.meta.tags = [];
      const lines = addressesCsv([row], () => "default").split("\r\n");
      expect(lines[1]).toBe("192.0.2.41,default,active,,,,,,,");
    });

    it("writes the DUID of an IPv6 interface", () => {
      const row: AddressRow = {
        ...base(),
        ip: "2001:db8:0:10::1",
        dns_name: "gw.example.test",
        host: { id: "h", name: "gw", mode: "static", lock: false },
        interface_detail: { id: "i", name: "eth0", mac: null, duid: "00:01:00:01:23:45:67:89:00:00:5e:00:53:01" },
      };
      const lines = addressesCsv([row], () => "default").split("\r\n");
      expect(lines[1]).toBe("2001:db8:0:10::1,default,active,gw.example.test,gw,eth0,,00:01:00:01:23:45:67:89:00:00:5e:00:53:01,,");
    });

    it("looks the VRF up by its id for every row", () => {
      const names: Record<string, string> = { a: "default", b: "isolated" };
      const one = { ...base(), vrf: "a" };
      const two = { ...base(), vrf: "b", ip: "192.0.2.42" };
      const lines = addressesCsv([one, two], (id) => names[id] ?? id).split("\r\n");
      expect(lines[1]?.split(",")[1]).toBe("default");
      expect(lines[2]?.split(",")[1]).toBe("isolated");
    });

    it("protects the free-text cells a person typed", () => {
      const row = base();
      row.dns_name = "=evil.example.test";
      row.meta.description = "+SUM(A1)";
      row.meta.tags = ["-t", "ok"];
      const lines = addressesCsv([row], () => "default").split("\r\n");
      expect(lines[1]).toBe("192.0.2.41,default,active,'=evil.example.test,,,,,'+SUM(A1),'-t; ok");
    });
  });
});
