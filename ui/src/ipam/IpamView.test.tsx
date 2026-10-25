import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ADDRESS_IDS, IPAM_IDS, ipamState } from "../api/mock/ipam/api";
import type { Vrf } from "../api/types";
import { paths } from "../app/paths";
import { axeViolations } from "../app/testing/axe";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import IpamView from "./IpamView";
import { chooseVrf } from "./scope";
import { recordWrites } from "./testkit";

// ---------------------------------------------------------------------------------
// Helpers

/** The prefixes of the VRF default, in the order of the tree. */
const DEFAULT_TREE = [
  "192.0.2.0/24",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "203.0.113.0/25",
  "203.0.113.128/26",
  "203.0.113.192/28",
  "2001:db8::/32",
  "2001:db8:0:10::/64",
  "2001:db8:0:30::/64",
];

beforeEach(async () => {
  // The VRF in view is remembered per browser; every test starts from the default.
  chooseVrf(null);
  await signInAlex();
});

afterEach(() => {
  chooseVrf(null);
});

function renderIpam(url = paths.ipam()) {
  return renderRoute(IpamView, {
    url,
    path: "/ipam",
    routes: {
      "/ipam/prefixes/:network/:length": IpamView,
      "/ipam/addresses/:ip": () => <div data-testid="address-route" />,
      "/ipam/move": () => <div data-testid="move-route" />,
    },
  });
}

function treeNodes(): HTMLElement[] {
  return screen.queryAllByTestId("tree-node");
}

function treeKeys(): (string | undefined)[] {
  return treeNodes().map((n) => n.dataset.key);
}

function treeNode(cidr: string): HTMLElement {
  const node = treeNodes().find((n) => n.dataset.key === cidr);
  if (!node) throw new Error(`no tree node ${cidr}`);
  return node;
}

/** The tree with every prefix of the VRF default. */
async function treeLoaded(count = DEFAULT_TREE.length) {
  await waitFor(() => expect(treeNodes()).toHaveLength(count));
}

/** The prefix pane of a prefix, once it shows that prefix. */
async function paneOf(cidr: string): Promise<HTMLElement> {
  const pane = await screen.findByTestId("prefix-pane");
  await waitFor(() => expect(screen.getByTestId("prefix-pane").dataset.key).toBe(cidr));
  return pane;
}

/** The pane of a network with its address grid loaded. */
async function openNetwork(cidr = "192.0.2.0/24") {
  const view = renderIpam(paths.prefix(cidr));
  const pane = await paneOf(cidr);
  await waitFor(() => expect(addressRows().length).toBeGreaterThan(0));
  return { ...view, pane };
}

function addressGrid(): HTMLElement {
  return screen.getByTestId("grid-prefix-addresses");
}

/** The rows of the address grid: addresses and free gaps. */
function gridRows(): HTMLElement[] {
  return within(addressGrid()).queryAllByTestId("row");
}

/** The address rows of the address grid (the free gaps left out). */
function addressRows(): HTMLElement[] {
  return gridRows().filter((r) => !r.classList.contains("free"));
}

function freeRows(): HTMLElement[] {
  return gridRows().filter((r) => r.classList.contains("free"));
}

function rowOf(ip: string): HTMLElement {
  const row = gridRows().find((r) => r.dataset.key === ip);
  if (!row) throw new Error(`no row for ${ip}`);
  return row;
}

function selectRows(...ips: string[]) {
  for (const ip of ips) fireEvent.click(within(rowOf(ip)).getByRole("checkbox"));
}

function tab(name: string): HTMLElement {
  return screen.getByRole("tab", { name });
}

const stored = (ip: string) => ipamState().data.address.get(ADDRESS_IDS[ip] as string)!;

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

function bytesOf(blob: Blob): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(blob);
  });
}

// ---------------------------------------------------------------------------------
// The tree and the overview

describe("the networks page", () => {
  it("shows the prefixes of the VRF in the tree with their utilization", async () => {
    renderIpam();
    await screen.findByTestId("page-ipam");
    await treeLoaded();
    expect(treeKeys()).toEqual(DEFAULT_TREE);
    // The soft-deleted 2001:db8:0:99::/64 and the VRF isolated are not in the tree.
    expect(treeKeys()).not.toContain("2001:db8:0:99::/64");
    const value = (cidr: string) => treeNode(cidr).querySelector(".meter .val")?.textContent;
    expect(value("192.0.2.0/24")).toBe("50.4%");
    expect(value("198.51.100.0/24")).toBe("40.2%");
    expect(value("203.0.113.0/25")).toBe("0%");
    expect(treeNode("192.0.2.0/24").querySelector(".meter")?.getAttribute("title")).toBe("20 of 254 addresses in use");
    // The depth follows the nesting; a critical network is flagged with a word.
    expect(treeNode("203.0.113.0/25").getAttribute("aria-level")).toBe("2");
    const cameras = treeNode("203.0.113.192/28");
    expect(cameras.querySelector(".meter.crit")).toBeTruthy();
    expect(within(cameras).getAllByText("Critical").length).toBeGreaterThan(0);
    // The description and, once the VLANs have loaded, the VLAN chip.
    expect(treeNode("192.0.2.0/24").textContent).toContain("LAN");
    await waitFor(() => expect(treeNode("192.0.2.0/24").querySelector(".vlan")?.textContent).toBe("10"));
    expect(treeNode("198.51.100.0/24").querySelector(".vlan")?.textContent).toBe("30");
    expect(treeNode("203.0.113.0/24").querySelector(".vlan")).toBeNull();
  });

  it("shows the overview of the VRF until a prefix is chosen", async () => {
    renderIpam();
    const overview = await screen.findByTestId("vrf-overview");
    await waitFor(() => expect(within(overview).getByRole("heading", { level: 1 }).textContent).toBe("defaultdefault, 9 prefixes, 1 alarm"));
    const grid = within(overview).getByTestId("grid-vrf-prefixes");
    await waitFor(() => expect(within(grid).getAllByTestId("row").map((r) => r.dataset.key)).toEqual(DEFAULT_TREE));
    const lan = within(grid).getAllByTestId("row").find((r) => r.dataset.key === "192.0.2.0/24") as HTMLElement;
    expect(lan.textContent).toContain("LAN");
    expect(lan.textContent).toContain("Network");
    expect(lan.textContent).toContain("50.4%");
    const cameras = within(grid).getAllByTestId("row").find((r) => r.dataset.key === "203.0.113.192/28") as HTMLElement;
    expect(within(cameras).getAllByText("Critical").length).toBeGreaterThan(0);
    expect(screen.queryByTestId("prefix-pane")).toBeNull();
  });

  it("opens a prefix from the overview", async () => {
    const view = renderIpam();
    const grid = await screen.findByTestId("grid-vrf-prefixes");
    await waitFor(() => expect(within(grid).getAllByTestId("row")).toHaveLength(DEFAULT_TREE.length));
    const row = within(grid).getAllByTestId("row").find((r) => r.dataset.key === "198.51.100.0/24") as HTMLElement;
    fireEvent.dblClick(within(row).getByText("IoT"));
    await paneOf("198.51.100.0/24");
    expect(view.location()).toBe(paths.prefix("198.51.100.0/24"));
  });

  it("selects a prefix by clicking it in the tree", async () => {
    const view = renderIpam();
    await treeLoaded();
    fireEvent.click(treeNode("198.51.100.0/24").querySelector(".tnode") as HTMLElement);
    await paneOf("198.51.100.0/24");
    expect(view.location()).toBe(paths.prefix("198.51.100.0/24"));
    await waitFor(() => expect(treeNode("198.51.100.0/24").getAttribute("aria-selected")).toBe("true"));
    expect(treeNode("192.0.2.0/24").getAttribute("aria-selected")).toBe("false");
    expect(screen.queryByTestId("vrf-overview")).toBeNull();
  });

  it("narrows the tree with its filter and keeps the parents of a match", async () => {
    renderIpam();
    await treeLoaded();
    fireEvent.input(screen.getByTestId("tree-filter"), { target: { value: "cameras" } });
    await waitFor(() => expect(treeKeys()).toEqual(["203.0.113.0/24", "203.0.113.192/28"]));
  });

  it("moves the focus to the tree with [ and to the grid with ]", async () => {
    await openNetwork();
    fireEvent.keyDown(document.body, { key: "[" });
    expect(document.activeElement).toBe(screen.getByRole("tree", { name: "Networks" }));
    fireEvent.keyDown(document.body, { key: "]" });
    expect(document.activeElement).toBe(within(addressGrid()).getByRole("grid"));
    // Typing in a field is not a command.
    fireEvent.keyDown(screen.getByTestId("tree-filter"), { key: "[" });
    expect(document.activeElement).toBe(within(addressGrid()).getByRole("grid"));
  });
});

// ---------------------------------------------------------------------------------
// Switching VRF and prefixes of other VRFs

describe("the VRF in view", () => {
  it("changes the tree when another VRF is chosen with the scope switcher", async () => {
    const view = renderIpam();
    const scope = (await screen.findByTestId("ipam-scope")) as HTMLSelectElement;
    await treeLoaded();
    expect([...scope.options].map((o) => o.textContent)).toEqual(["default / default", "Workshop / isolated"]);
    expect(scope.value).toBe(IPAM_IDS.vrf.default);
    fireEvent.change(scope, { target: { value: IPAM_IDS.vrf.isolated } });
    await waitFor(() => expect(treeKeys()).toEqual(["192.0.2.0/24"]));
    expect(treeNode("192.0.2.0/24").textContent).toContain("Workshop LAN");
    expect(view.location()).toBe(paths.ipam());
    // The overview names the VRF and its tenant.
    const overview = await screen.findByTestId("vrf-overview");
    await waitFor(() => expect(within(overview).getByRole("heading", { level: 1 }).textContent).toBe("isolatedWorkshop, 1 prefix, no alarms"));
    // And back.
    fireEvent.change(screen.getByTestId("ipam-scope"), { target: { value: IPAM_IDS.vrf.default } });
    await treeLoaded();
  });

  it("shows the prefix of the VRF the link names", async () => {
    renderIpam(paths.prefix("192.0.2.0/24", IPAM_IDS.vrf.isolated));
    await waitFor(() => expect(screen.getByTestId("prefix-pane").dataset.id).toBe(IPAM_IDS.prefix.workshop));
    const pane = screen.getByTestId("prefix-pane");
    expect(within(pane).getByRole("heading", { level: 1 }).textContent).toContain("Workshop LAN");
    await waitFor(() => expect((screen.getByTestId("ipam-scope") as HTMLSelectElement).value).toBe(IPAM_IDS.vrf.isolated));
  });

  // A link with `?vrf=` changes the VRF twice in one tick (none to the default, the default to
  // the VRF of the link); the tree must follow the second change.
  it("shows the tree of the VRF the link names", async () => {
    renderIpam(paths.prefix("192.0.2.0/24", IPAM_IDS.vrf.isolated));
    await waitFor(() => expect((screen.getByTestId("ipam-scope") as HTMLSelectElement).value).toBe(IPAM_IDS.vrf.isolated));
    await waitFor(() => expect(treeKeys()).toEqual(["192.0.2.0/24"]));
    expect(treeNode("192.0.2.0/24").textContent).toContain("Workshop LAN");
  });

  it("shows the prefix of the VRF in view when several VRFs have it", async () => {
    renderIpam(paths.prefix("192.0.2.0/24"));
    const pane = await paneOf("192.0.2.0/24");
    expect(pane.dataset.id).toBe(IPAM_IDS.prefix.lan);
  });

  it("switches to the other VRF when only that one has the prefix", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    chooseVrf(IPAM_IDS.vrf.isolated);
    renderIpam(paths.prefix("198.51.100.0/24"));
    const pane = await paneOf("198.51.100.0/24");
    expect(pane.dataset.id).toBe(IPAM_IDS.prefix.iot);
    await waitFor(() => expect((screen.getByTestId("ipam-scope") as HTMLSelectElement).value).toBe(IPAM_IDS.vrf.default));
    // The last tree the page asked for is the tree of the VRF it switched to.
    await waitFor(() => {
      const trees = spy.mock.calls.map(([input]) => new URL(String(input), "http://localhost")).filter((u) => u.pathname === "/api/v1/prefixes/tree");
      expect(trees.at(-1)?.searchParams.get("vrf")).toBe(IPAM_IDS.vrf.default);
    });
    await treeLoaded();
  });

  it("asks which VRF when several have the prefix and none is in view", async () => {
    // A third VRF without prefixes is the one in view.
    const spare: Vrf = {
      ...structuredClone(ipamState().data.vrf.get(IPAM_IDS.vrf.isolated) as Vrf),
      id: "0190d1c2-0000-7000-8000-0000000200a3",
      name: "spare",
    };
    ipamState().data.vrf.set(spare.id, spare);
    chooseVrf(spare.id);
    const view = renderIpam(paths.prefix("192.0.2.0/24"));
    expect(await screen.findByText("192.0.2.0/24 exists in several VRFs. Choose one:")).toBeTruthy();
    expect(screen.queryByTestId("prefix-pane")).toBeNull();
    const choices = () => within(screen.getByRole("list")).getAllByRole("button");
    await waitFor(() => expect(choices().map((b) => b.textContent)).toEqual(["default / default", "Workshop / isolated"]));
    fireEvent.click(choices()[1] as HTMLElement);
    const pane = await paneOf("192.0.2.0/24");
    expect(pane.dataset.id).toBe(IPAM_IDS.prefix.workshop);
    expect(view.location()).toContain(`vrf=${IPAM_IDS.vrf.isolated}`);
  });

  it("says so when no VRF has the prefix", async () => {
    renderIpam(paths.prefix("192.0.2.128/25"));
    expect(await screen.findByText("No prefix 192.0.2.128/25 in this VRF.")).toBeTruthy();
    expect(screen.queryByTestId("prefix-pane")).toBeNull();
    expect(screen.queryByTestId("vrf-overview")).toBeNull();
  });
});

// ---------------------------------------------------------------------------------
// The prefix pane

describe("the prefix pane", () => {
  it("shows the summary of a network", async () => {
    const { pane } = await openNetwork("192.0.2.0/24");
    const head = within(pane).getByRole("heading", { level: 1 });
    expect(head.textContent).toBe("192.0.2.0/24LAN, Network");
    const crumbs = within(pane).getByRole("navigation", { name: "Where this prefix lies" });
    expect(crumbs.textContent).toBe("default");
    const summary = within(pane).getByTestId("prefix-summary");
    expect(summary.querySelector(".pct")?.textContent).toBe("50.4%");
    expect(summary.querySelector(".of")?.textContent).toBe("20 of 254 addresses in use");
    expect(summary.querySelector(".meter")?.getAttribute("data-level")).toBe("normal");
    expect([...summary.querySelectorAll(".legend > span")].map((s) => s.textContent)).toEqual(["DHCP pool 100", "Infrastructure 19"]);
    const facts = [...summary.querySelectorAll("dt")].map((dt) => dt.textContent);
    expect(facts).toEqual(["Status", "VLAN", "Allocation", "Alarm at"]);
    const values = [...summary.querySelectorAll("dd")].map((dd) => dd.textContent);
    expect(values).toEqual(["Active", "10LAN", "From the lowest address", "warning 80%, critical 95%"]);
    expect([...summary.querySelectorAll(".tags .tag")].map((t) => t.textContent)).toEqual(["home"]);
  });

  it("flags a critical network in the summary", async () => {
    const { pane } = await openNetwork("203.0.113.192/28");
    const summary = within(pane).getByTestId("prefix-summary");
    await waitFor(() => expect(summary.querySelector(".meter")?.getAttribute("data-level")).toBe("critical"));
    expect(within(summary).getAllByText("Critical").length).toBeGreaterThan(0);
    expect(summary.querySelector(".pct")?.textContent).toBe("92.9%");
  });

  it("shows the address tab first for a network and the prefixes tab first for a supernet", async () => {
    await openNetwork("192.0.2.0/24");
    expect(screen.getAllByRole("tab").map((t) => t.textContent)).toEqual(["Addresses", "Ranges", "Adoption", "History"]);
    expect(tab("Addresses").getAttribute("aria-selected")).toBe("true");
  });

  it("lists the addresses of a network with their host, mode and MAC", async () => {
    await openNetwork("192.0.2.0/24");
    const grid = within(addressGrid()).getByRole("grid", { name: "Addresses in 192.0.2.0/24" });
    expect(within(grid).getAllByRole("columnheader").map((h) => h.textContent?.trim())).toEqual([
      "",
      "Address",
      "DNS name",
      "Host",
      "Mode",
      "MAC",
      "Status",
      "Actions",
    ]);
    const row = rowOf("192.0.2.41");
    const text = (column: string) => row.querySelector(`td[data-col="${column}"]`)?.textContent?.trim();
    expect(text("dns_name")).toBe("thermostat-1.example.test");
    expect(text("host")).toBe("thermostat-1");
    expect(text("mode")).toBe("reserved");
    expect(text("mac")).toBe("00:00:5e:00:53:29");
    expect(text("status")).toBe("Active");
    expect(addressRows()).toHaveLength(20);
  });

  it("shows the free gaps between the addresses and hides them with the toggle", async () => {
    await openNetwork("192.0.2.0/24");
    const toggle = screen.getByTestId("toggle-free");
    expect(toggle.getAttribute("aria-pressed")).toBe("true");
    expect(freeRows().map((r) => r.dataset.key)).toEqual([
      "192.0.2.6",
      "192.0.2.16",
      "192.0.2.21",
      "192.0.2.31",
      "192.0.2.45",
      "192.0.2.58",
      "192.0.2.61",
      "192.0.2.251",
    ]);
    expect(rowOf("192.0.2.6").textContent).toContain("192.0.2.6 – 192.0.2.9");
    expect(rowOf("192.0.2.6").textContent).toContain("4 free");
    expect(rowOf("192.0.2.6").textContent).toContain("Claim 192.0.2.6");
    // The gap after the last address ends at the last usable address of the network.
    expect(rowOf("192.0.2.251").textContent).toContain("192.0.2.251 – 192.0.2.254");
    // Gaps sit between the addresses in address order.
    const order = gridRows().map((r) => r.dataset.key);
    expect(order.indexOf("192.0.2.5")).toBeLessThan(order.indexOf("192.0.2.6"));
    expect(order.indexOf("192.0.2.6")).toBeLessThan(order.indexOf("192.0.2.10"));

    fireEvent.click(toggle);
    await waitFor(() => expect(freeRows()).toEqual([]));
    expect(toggle.getAttribute("aria-pressed")).toBe("false");
    expect(addressRows()).toHaveLength(20);
    fireEvent.click(toggle);
    await waitFor(() => expect(freeRows()).toHaveLength(8));
  });

  it("asks the server for the free gaps and the hosts only while the toggle is on", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    await openNetwork("192.0.2.0/24");
    const lists = () =>
      spy.mock.calls
        .map(([input]) => new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, "http://localhost"))
        .filter((u) => u.pathname === `/api/v1/prefixes/${IPAM_IDS.prefix.lan}/addresses`);
    expect(lists().at(-1)?.searchParams.get("include_free")).toBe("true");
    expect(lists().at(-1)?.searchParams.get("expand")).toBe("host");
    fireEvent.click(screen.getByTestId("toggle-free"));
    await waitFor(() => expect(freeRows()).toEqual([]));
    expect(lists().at(-1)?.searchParams.has("include_free")).toBe(false);
    expect(lists().at(-1)?.searchParams.get("expand")).toBe("host");
    // No read of a host for any row.
    const perHost = spy.mock.calls.filter(([input]) => String(input).includes("/api/v1/hosts"));
    expect(perHost).toEqual([]);
  });

  it("claims a free gap with its button", async () => {
    await openNetwork("192.0.2.0/24");
    expect(
      [...ipamState().data.address.values()].some((a) => a.ip === "192.0.2.6" && a.vrf === IPAM_IDS.vrf.default),
    ).toBe(false);
    fireEvent.click(within(rowOf("192.0.2.6")).getByTestId("claim-gap"));
    expect(await screen.findByText("Claimed 192.0.2.6")).toBeTruthy();
    expect(
      [...ipamState().data.address.values()].some((a) => a.ip === "192.0.2.6" && a.vrf === IPAM_IDS.vrf.default),
    ).toBe(true);
    // The row is an address now, and the gap that remains starts after it.
    await waitFor(() => expect(addressRows().map((r) => r.dataset.key)).toContain("192.0.2.6"));
    expect(freeRows().map((r) => r.dataset.key)).toContain("192.0.2.7");
    expect(freeRows().map((r) => r.dataset.key)).not.toContain("192.0.2.6");
  });

  it("narrows the addresses with the filter and leaves the gaps out while filtering", async () => {
    await openNetwork("192.0.2.0/24");
    const filter = within(screen.getByTestId("filterbar-prefix-addresses")).getByTestId("filter-input");
    fireEvent.input(filter, { target: { value: "thermostat" } });
    await waitFor(() => expect(gridRows().map((r) => r.dataset.key)).toEqual(["192.0.2.41"]));
    fireEvent.input(filter, { target: { value: "192.0.2.4" } });
    await waitFor(() => expect(gridRows().map((r) => r.dataset.key)).toEqual(["192.0.2.4", "192.0.2.41", "192.0.2.42", "192.0.2.43", "192.0.2.44"]));
    fireEvent.input(filter, { target: { value: "no such host" } });
    expect(await screen.findByText("No rows match the filter.")).toBeTruthy();
    fireEvent.input(filter, { target: { value: "" } });
    await waitFor(() => expect(gridRows()).toHaveLength(28));
  });

  it("opens an address with a double click", async () => {
    const { location } = await openNetwork("192.0.2.0/24");
    fireEvent.dblClick(within(rowOf("192.0.2.41")).getByText("41"));
    await screen.findByTestId("address-route");
    expect(location()).toBe(paths.address("192.0.2.41"));
  });

  it("shows the ranges of a network", async () => {
    await openNetwork("192.0.2.0/24");
    fireEvent.click(tab("Ranges"));
    const grid = await screen.findByTestId("grid-prefix-ranges");
    await waitFor(() => expect(within(grid).getAllByTestId("row").map((r) => r.dataset.key)).toEqual(["192.0.2.1-192.0.2.19", "192.0.2.100-192.0.2.199"]));
    const [infrastructure, pool] = within(grid).getAllByTestId("row");
    expect(infrastructure?.querySelector('td[data-col="role"]')?.textContent).toBe("Infrastructure");
    expect(infrastructure?.querySelector('td[data-col="lease"]')?.textContent).toBe("");
    expect(pool?.querySelector('td[data-col="role"]')?.textContent).toBe("DHCP pool");
    expect(pool?.querySelector('td[data-col="lease"]')?.textContent).toBe("1 day");
    expect(tab("Ranges").getAttribute("aria-selected")).toBe("true");
    expect(screen.queryByTestId("grid-prefix-addresses")).toBeNull();
  });

  it("opens the form for a new range", async () => {
    await openNetwork("192.0.2.0/24");
    fireEvent.click(tab("Ranges"));
    fireEvent.click(await screen.findByTestId("range-add"));
    const form = await screen.findByTestId("dialog-range-form");
    expect(within(form).getByTestId("field-first")).toBeTruthy();
  });

  it("shows the prefixes inside a supernet", async () => {
    renderIpam(paths.prefix("203.0.113.0/24"));
    const pane = await paneOf("203.0.113.0/24");
    expect(screen.getAllByRole("tab").map((t) => t.textContent)).toEqual(["Prefixes", "Addresses", "Adoption", "History"]);
    expect(tab("Prefixes").getAttribute("aria-selected")).toBe("true");
    const grid = await screen.findByTestId("grid-prefix-children");
    await waitFor(() =>
      expect(within(grid).getAllByTestId("row").map((r) => r.dataset.key)).toEqual(["203.0.113.0/25", "203.0.113.128/26", "203.0.113.192/28"]),
    );
    const cameras = within(grid).getAllByTestId("row")[2] as HTMLElement;
    expect(cameras.textContent).toContain("Cameras");
    expect(cameras.textContent).toContain("92.9%");
    expect(within(pane).getByRole("heading", { level: 1 }).textContent).toBe("203.0.113.0/24Documentation supernet, Supernet");
    // The addresses of the supernet are those of its networks.
    fireEvent.click(tab("Addresses"));
    await waitFor(() => expect(addressRows()).toHaveLength(13));
    expect(addressRows()[0]?.dataset.key).toBe("203.0.113.193");
    expect(addressRows().at(-1)?.dataset.key).toBe("203.0.113.205");
    expect(rowOf("203.0.113.193").querySelector('td[data-col="host"]')?.textContent).toBe("cam-01");
  });

  it("opens a child prefix from the prefixes tab and shows the parent in the crumbs", async () => {
    const view = renderIpam(paths.prefix("203.0.113.0/24"));
    const grid = await screen.findByTestId("grid-prefix-children");
    await waitFor(() => expect(within(grid).getAllByTestId("row")).toHaveLength(3));
    fireEvent.dblClick((within(grid).getAllByTestId("row")[1] as HTMLElement).querySelector('td[data-col="cidr"]') as HTMLElement);
    const pane = await paneOf("203.0.113.128/26");
    expect(view.location()).toBe(paths.prefix("203.0.113.128/26"));
    const crumbs = within(pane).getByRole("navigation", { name: "Where this prefix lies" });
    await waitFor(() => expect(within(crumbs).getByRole("link", { name: "203.0.113.0/24" })).toBeTruthy());
    fireEvent.click(within(crumbs).getByRole("link", { name: "203.0.113.0/24" }));
    await paneOf("203.0.113.0/24");
    expect(view.location()).toBe(paths.prefix("203.0.113.0/24"));
  });

  it("shows only the direct children of a supernet in the prefixes tab", async () => {
    renderIpam(paths.prefix("2001:db8::/32"));
    await paneOf("2001:db8::/32");
    const grid = await screen.findByTestId("grid-prefix-children");
    await waitFor(() => expect(within(grid).getAllByTestId("row")).toHaveLength(2));
    expect(within(grid).getAllByTestId("row").map((r) => r.dataset.key)).toEqual(["2001:db8:0:10::/64", "2001:db8:0:30::/64"]);
  });

  it("shows the history of a prefix, the newest change first", async () => {
    await openNetwork("192.0.2.0/24");
    fireEvent.click(tab("History"));
    const panel = await screen.findByTestId("history-panel");
    await waitFor(() => expect(within(panel).getAllByTestId("history-entry")).toHaveLength(2));
    const entries = within(panel).getAllByTestId("history-entry");
    expect(entries.map((e) => e.dataset.action)).toEqual(["update", "create"]);
    expect(entries[0]?.querySelector("li[data-field='meta.description']")?.textContent).toBe("meta.description: Home LAN → LAN");
    expect(screen.queryByTestId("grid-prefix-addresses")).toBeNull();
  });

  it("goes back to the addresses from another tab", async () => {
    await openNetwork("192.0.2.0/24");
    fireEvent.click(tab("History"));
    await screen.findByTestId("history-panel");
    fireEvent.click(tab("Addresses"));
    await waitFor(() => expect(addressRows()).toHaveLength(20));
  });
});

// ---------------------------------------------------------------------------------
// Actions that open a dialog

describe("the actions of the prefix pane", () => {
  it("opens the next free address dialog with the button", async () => {
    await openNetwork("192.0.2.0/24");
    fireEvent.click(screen.getByTestId("prefix-next-free-address"));
    const dialog = await screen.findByTestId("dialog-next-free-address");
    expect(within(dialog).getByRole("heading", { name: "Next free address in 192.0.2.0/24" })).toBeTruthy();
    // The ranges of the network are offered to allocate from.
    await waitFor(() => expect([...(within(dialog).getByTestId("field-range") as HTMLSelectElement).options]).toHaveLength(3));
  });

  it("opens the next free address dialog with the N key", async () => {
    await openNetwork("198.51.100.0/24");
    fireEvent.keyDown(document.body, { key: "n" });
    const dialog = await screen.findByTestId("dialog-next-free-address");
    expect(within(dialog).getByRole("heading", { name: "Next free address in 198.51.100.0/24" })).toBeTruthy();
  });

  it("does not open the dialog with N while typing in a field", async () => {
    await openNetwork("192.0.2.0/24");
    fireEvent.keyDown(screen.getByTestId("tree-filter"), { key: "n" });
    fireEvent.keyDown(within(screen.getByTestId("filterbar-prefix-addresses")).getByTestId("filter-input"), { key: "n" });
    expect(screen.queryByTestId("dialog-next-free-address")).toBeNull();
  });

  it("offers the next free prefix, not the next free address, for a supernet", async () => {
    renderIpam(paths.prefix("203.0.113.0/24"));
    await paneOf("203.0.113.0/24");
    expect(screen.queryByTestId("prefix-next-free-address")).toBeNull();
    // N claims an address, so it does nothing on a supernet.
    fireEvent.keyDown(document.body, { key: "n" });
    expect(screen.queryByTestId("dialog-next-free-address")).toBeNull();
    fireEvent.click(screen.getByTestId("prefix-next-free-prefix"));
    const dialog = await screen.findByTestId("dialog-next-free-prefix");
    expect(within(dialog).getByRole("heading", { name: "Next free prefix in 203.0.113.0/24" })).toBeTruthy();
  });

  it("opens the prefix form with the supernet's network typed in when a prefix is added to a supernet", async () => {
    renderIpam(paths.prefix("203.0.113.0/24"));
    await paneOf("203.0.113.0/24");
    fireEvent.click(screen.getByTestId("ipam-add-prefix"));
    const form = await screen.findByTestId("dialog-prefix-form");
    expect((within(form).getByTestId("field-cidr") as HTMLInputElement).value).toBe("203.0.113.");
  });

  it("opens the prefix form empty when a prefix is added next to a network", async () => {
    await openNetwork("192.0.2.0/24");
    fireEvent.click(screen.getByTestId("ipam-add-prefix"));
    const form = await screen.findByTestId("dialog-prefix-form");
    expect((within(form).getByTestId("field-cidr") as HTMLInputElement).value).toBe("");
  });

  it("opens the prefix form from the overview too", async () => {
    renderIpam();
    await treeLoaded();
    // The button waits for the VRF in view.
    await waitFor(() => expect((screen.getByTestId("ipam-add-prefix") as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByTestId("ipam-add-prefix"));
    expect(await screen.findByTestId("dialog-prefix-form")).toBeTruthy();
  });

  it("opens the prefix form with the prefix to edit", async () => {
    const { pane } = await openNetwork("192.0.2.0/24");
    fireEvent.click(within(pane).getByTestId("prefix-edit"));
    const form = await screen.findByTestId("dialog-prefix-form");
    expect(within(form).getByRole("heading").textContent).toContain("192.0.2.0/24");
    expect((within(form).getByTestId("field-cidr") as HTMLInputElement).value).toBe("192.0.2.0/24");
    expect((within(form).getByTestId("field-description") as HTMLInputElement).value).toBe("LAN");
  });

  it("opens the delete dialog for the prefix", async () => {
    const { pane } = await openNetwork("192.0.2.0/24");
    fireEvent.click(within(pane).getByTestId("prefix-delete"));
    const dialog = await screen.findByTestId("dialog-delete");
    expect(within(dialog).getByRole("heading", { name: "Delete prefix 192.0.2.0/24" })).toBeTruthy();
    expect(within(dialog).getByTestId("delete-cascade")).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------------
// Editing in the grid

describe("editing an address in the grid", () => {
  const dnsCell = (ip: string) => rowOf(ip).querySelector('td[data-col="dns_name"]') as HTMLElement;

  it("saves a new DNS name through the API when Enter is pressed", async () => {
    const writes = recordWrites();
    await openNetwork("192.0.2.0/24");
    fireEvent.dblClick(dnsCell("192.0.2.41"));
    const editor = (await within(dnsCell("192.0.2.41")).findByTestId("cell-editor")) as HTMLInputElement;
    expect(editor.value).toBe("thermostat-1.example.test");
    fireEvent.input(editor, { target: { value: "hall-thermostat.example.test" } });
    fireEvent.keyDown(editor, { key: "Enter" });
    await waitFor(() => expect(stored("192.0.2.41").dns_name).toBe("hall-thermostat.example.test"));
    // One write: a PATCH of the address with the revision the row had.
    const sent = writes().filter((w) => w.method === "PATCH");
    expect(sent).toHaveLength(1);
    expect(sent[0]?.url).toBe(`/api/v1/addresses/${ADDRESS_IDS["192.0.2.41"]}`);
    expect(sent[0]?.body).toEqual({ dns_name: "hall-thermostat.example.test" });
    expect(await screen.findByText("192.0.2.41 is now hall-thermostat.example.test")).toBeTruthy();
    // The editor closes and the grid shows the new name.
    await waitFor(() => expect(within(dnsCell("192.0.2.41")).queryByTestId("cell-editor")).toBeNull());
    await waitFor(() => expect(dnsCell("192.0.2.41").textContent).toBe("hall-thermostat.example.test"));
  });

  it("clears the DNS name when the field is emptied", async () => {
    await openNetwork("192.0.2.0/24");
    fireEvent.dblClick(dnsCell("192.0.2.42"));
    const editor = (await within(dnsCell("192.0.2.42")).findByTestId("cell-editor")) as HTMLInputElement;
    fireEvent.input(editor, { target: { value: "" } });
    fireEvent.keyDown(editor, { key: "Enter" });
    await waitFor(() => expect(stored("192.0.2.42").dns_name ?? null).toBeNull());
    expect(await screen.findByText("192.0.2.42 is now –")).toBeTruthy();
  });

  it("writes nothing when the edit is cancelled with Escape", async () => {
    const writes = recordWrites();
    await openNetwork("192.0.2.0/24");
    fireEvent.dblClick(dnsCell("192.0.2.43"));
    const editor = (await within(dnsCell("192.0.2.43")).findByTestId("cell-editor")) as HTMLInputElement;
    fireEvent.input(editor, { target: { value: "other.example.test" } });
    fireEvent.keyDown(editor, { key: "Escape" });
    await waitFor(() => expect(within(dnsCell("192.0.2.43")).queryByTestId("cell-editor")).toBeNull());
    expect(stored("192.0.2.43").dns_name).toBe("cam-door.example.test");
    expect(writes()).toEqual([]);
  });

  it("writes nothing when the name is not changed", async () => {
    const writes = recordWrites();
    await openNetwork("192.0.2.0/24");
    fireEvent.dblClick(dnsCell("192.0.2.44"));
    const editor = (await within(dnsCell("192.0.2.44")).findByTestId("cell-editor")) as HTMLInputElement;
    fireEvent.keyDown(editor, { key: "Enter" });
    await waitFor(() => expect(within(dnsCell("192.0.2.44")).queryByTestId("cell-editor")).toBeNull());
    expect(writes()).toEqual([]);
  });

  it("keeps the editor open and shows the message when the server refuses the name", async () => {
    await openNetwork("192.0.2.0/24");
    fireEvent.dblClick(dnsCell("192.0.2.41"));
    const editor = (await within(dnsCell("192.0.2.41")).findByTestId("cell-editor")) as HTMLInputElement;
    fireEvent.input(editor, { target: { value: "not a name" } });
    fireEvent.keyDown(editor, { key: "Enter" });
    const alert = await within(dnsCell("192.0.2.41")).findByRole("alert");
    expect(alert.textContent).not.toBe("");
    expect(within(dnsCell("192.0.2.41")).getByTestId("cell-editor")).toBeTruthy();
    expect(stored("192.0.2.41").dns_name).toBe("thermostat-1.example.test");
  });

  it("does not edit a free gap", async () => {
    await openNetwork("192.0.2.0/24");
    fireEvent.dblClick(rowOf("192.0.2.6"));
    expect(screen.queryByTestId("cell-editor")).toBeNull();
  });
});

// ---------------------------------------------------------------------------------
// Selecting addresses

describe("acting on selected addresses of the prefix", () => {
  it("shows the action bar with the number of selected addresses and not for free gaps", async () => {
    await openNetwork("192.0.2.0/24");
    expect(within(rowOf("192.0.2.6")).queryByRole("checkbox")).toBeNull();
    expect(screen.queryByTestId("action-move")).toBeNull();
    selectRows("192.0.2.41", "192.0.2.42", "192.0.2.43");
    const bar = await screen.findByRole("toolbar", { name: "Selection actions" });
    expect(bar.textContent).toContain("3");
    expect(rowOf("192.0.2.41").getAttribute("aria-selected")).toBe("true");
    expect(rowOf("192.0.2.44").getAttribute("aria-selected")).toBe("false");
  });

  it("opens the move target dialog for the selected addresses", async () => {
    await openNetwork("192.0.2.0/24");
    selectRows("192.0.2.41", "192.0.2.42");
    fireEvent.click(await screen.findByTestId("action-move"));
    const dialog = await screen.findByTestId("dialog-move-target");
    expect(within(dialog).getByRole("heading", { name: "Move 2 objects to a network" })).toBeTruthy();
    // Only networks are targets, and the dialog filters them.
    await waitFor(() => expect(within(dialog).getAllByRole("option").map((o) => (o as HTMLElement).dataset.key)).toEqual([
      "192.0.2.0/24",
      "198.51.100.0/24",
      "203.0.113.0/25",
      "203.0.113.128/26",
      "203.0.113.192/28",
      "2001:db8:0:10::/64",
      "2001:db8:0:30::/64",
    ]));
  });

  // Choosing a target closes the dialog, which drops the selection it was opened with.
  it("goes to the move preview with the addresses when a target is chosen", async () => {
    const { location } = await openNetwork("192.0.2.0/24");
    selectRows("192.0.2.41", "192.0.2.42");
    fireEvent.click(await screen.findByTestId("action-move"));
    const dialog = await screen.findByTestId("dialog-move-target");
    await waitFor(() => expect(within(dialog).getAllByRole("option").length).toBeGreaterThan(0));
    fireEvent.click(within(dialog).getAllByRole("option").find((o) => (o as HTMLElement).dataset.key === "198.51.100.0/24") as HTMLElement);
    await screen.findByTestId("move-route");
    expect(location()).toBe(
      paths.move(IPAM_IDS.prefix.iot, [
        { kind: "address", id: ADDRESS_IDS["192.0.2.41"] as string },
        { kind: "address", id: ADDRESS_IDS["192.0.2.42"] as string },
      ]),
    );
  });

  it("opens the move target dialog with the M key, and not without a selection", async () => {
    await openNetwork("192.0.2.0/24");
    fireEvent.keyDown(document.body, { key: "m" });
    expect(screen.queryByTestId("dialog-move-target")).toBeNull();
    selectRows("192.0.2.43");
    fireEvent.keyDown(document.body, { key: "m" });
    const dialog = await screen.findByTestId("dialog-move-target");
    expect(within(dialog).getByRole("heading", { name: "Move 1 object to a network" })).toBeTruthy();
  });

  it("opens the move target dialog for one address from its row menu", async () => {
    await openNetwork("192.0.2.0/24");
    fireEvent.click(within(rowOf("192.0.2.30")).getByRole("button", { name: "Actions for 192.0.2.30" }));
    fireEvent.click(await within(await screen.findByTestId("row-menu")).findByRole("menuitem", { name: "Move to network" }));
    const dialog = await screen.findByTestId("dialog-move-target");
    expect(within(dialog).getByRole("heading", { name: "Move 1 object to a network" })).toBeTruthy();
  });

  it("offers open, move, reserve in DHCP and delete for an address, and none of them for a free gap", async () => {
    await openNetwork("192.0.2.0/24");
    expect(within(rowOf("192.0.2.30")).getByRole("button", { name: "Actions for 192.0.2.30" })).toBeTruthy();
    expect(within(rowOf("192.0.2.6")).queryByRole("button", { name: /^Actions for/ })).toBeNull();
    fireEvent.click(within(rowOf("192.0.2.30")).getByRole("button", { name: "Actions for 192.0.2.30" }));
    const menu = await screen.findByTestId("row-menu");
    expect(within(menu).getAllByRole("menuitem").map((m) => m.dataset.item)).toEqual(["open", "move", "reserve", "delete"]);
    fireEvent.click(within(menu).getByRole("menuitem", { name: "Delete" }));
    const dialog = await screen.findByTestId("dialog-delete");
    expect(within(dialog).getByRole("heading", { name: "Delete address 192.0.2.30" })).toBeTruthy();
  });

  describe("exporting the selection as CSV", () => {
    let capture: ReturnType<typeof captureDownloads>;

    beforeEach(() => {
      capture = captureDownloads();
    });

    afterEach(() => {
      capture.restore();
    });

    it("saves the selected addresses in a file named after the prefix", async () => {
      await openNetwork("192.0.2.0/24");
      selectRows("192.0.2.41", "192.0.2.1");
      fireEvent.click(await screen.findByTestId("action-export"));
      expect(capture.downloads).toEqual(["addresses-192.0.2.0_24.csv"]);
      const blob = capture.blobs[0] as Blob;
      expect(blob.type).toBe("text/csv;charset=utf-8");
      const bytes = await bytesOf(blob);
      expect([...bytes.slice(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
      expect(new TextDecoder().decode(bytes.slice(3)).split("\r\n")).toEqual([
        "address,vrf,status,dns_name,host,interface,mac,duid,description,tags",
        "192.0.2.1,default,active,gw.example.test,gw,eth0,00:00:5e:00:53:01,,,",
        "192.0.2.41,default,active,thermostat-1.example.test,thermostat-1,eth0,00:00:5e:00:53:29,,,",
        "",
      ]);
    });

    it("names an IPv6 prefix without colons and slashes in the file name", async () => {
      await openNetwork("2001:db8:0:10::/64");
      await waitFor(() => expect(addressRows().map((r) => r.dataset.key)).toEqual(["2001:db8:0:10::1"]));
      selectRows("2001:db8:0:10::1");
      fireEvent.click(await screen.findByTestId("action-export"));
      expect(capture.downloads).toEqual(["addresses-2001_db8_0_10___64.csv"]);
    });
  });
});

// ---------------------------------------------------------------------------------
// Accessibility

describe("accessibility of the networks page", () => {
  it("passes axe with a network selected", async () => {
    const { pane } = await openNetwork("192.0.2.0/24");
    await treeLoaded();
    await waitFor(() => expect(within(pane).getByTestId("prefix-summary").querySelector(".meter")).toBeTruthy());
    expect(await axeViolations(screen.getByTestId("page-ipam"))).toEqual([]);
  });

  it("passes axe with rows selected", async () => {
    await openNetwork("192.0.2.0/24");
    await treeLoaded();
    selectRows("192.0.2.41");
    await screen.findByTestId("action-move");
    expect(await axeViolations(screen.getByTestId("page-ipam"))).toEqual([]);
  });

  it("passes axe with a supernet selected", async () => {
    renderIpam(paths.prefix("203.0.113.0/24"));
    await paneOf("203.0.113.0/24");
    await treeLoaded();
    const grid = await screen.findByTestId("grid-prefix-children");
    await waitFor(() => expect(within(grid).getAllByTestId("row")).toHaveLength(3));
    expect(await axeViolations(screen.getByTestId("page-ipam"))).toEqual([]);
  });

  it("passes axe on the overview", async () => {
    renderIpam();
    await treeLoaded();
    const grid = await screen.findByTestId("grid-vrf-prefixes");
    await waitFor(() => expect(within(grid).getAllByTestId("row")).toHaveLength(DEFAULT_TREE.length));
    expect(await axeViolations(screen.getByTestId("page-ipam"))).toEqual([]);
  });
});
