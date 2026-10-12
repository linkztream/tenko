// Display gating of the IPAM views (IAM-01): a scoped operator sees no write action outside its
// scope, a viewer none at all, an administrator all. The mock does not filter reads by scope, so
// the scoped operator sees every prefix and the views must hide the actions on those outside.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ADDRESS_IDS, IPAM_IDS } from "../api/mock/ipam/api";
import { paths } from "../app/paths";
import { renderRoute } from "../app/testing/render";
import { signInAlex } from "../auth/account/testkit";
import { signInScopedOperator, signInWithRoles } from "../auth/scope-testkit";
import { endDrag, startDrag } from "../grid/dnd";
import AddressesView from "./address/AddressesView";
import AddressView from "./address/AddressView";
import IpamView from "./IpamView";
import MovePreview from "./move/MovePreview";
import { chooseVrf } from "./scope";

const LAB = "203.0.113.0/25"; // inside casey's operator grant
const CAMERAS = "203.0.113.192/28"; // inside it too, with addresses
const IOT = "198.51.100.0/24"; // casey is only a viewer here
const LAN = "192.0.2.0/24"; // no grant at all

beforeEach(() => {
  chooseVrf(null);
});

afterEach(() => {
  chooseVrf(null);
  endDrag();
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

async function paneOf(cidr: string): Promise<HTMLElement> {
  await screen.findByTestId("prefix-pane");
  await waitFor(() => expect(screen.getByTestId("prefix-pane").dataset.key).toBe(cidr));
  return screen.getByTestId("prefix-pane");
}

/** Opens a network and waits for the tree and, when it has addresses, the grid. */
async function openPane(cidr: string, withRows = true): Promise<HTMLElement> {
  renderIpam(paths.prefix(cidr));
  const pane = await paneOf(cidr);
  await waitFor(() => expect(screen.queryAllByTestId("tree-node").length).toBeGreaterThan(3));
  if (withRows) await waitFor(() => expect(within(pane).queryAllByTestId("row").length).toBeGreaterThan(0));
  return pane;
}

const treeNode = (cidr: string) => {
  const node = screen.queryAllByTestId("tree-node").find((n) => n.dataset.key === cidr);
  if (!node) throw new Error(`no tree node ${cidr}`);
  return node.querySelector(".tnode") as HTMLElement;
};

const HEAD_ACTIONS = ["prefix-edit", "prefix-delete", "prefix-next-free-address"];

function headActions(pane: HTMLElement): string[] {
  return HEAD_ACTIONS.filter((id) => within(pane).queryByTestId(id));
}

function rowOf(ip: string): HTMLElement {
  const row = screen.queryAllByTestId("row").find((r) => r.dataset.key === ip);
  if (!row) throw new Error(`no row for ${ip}`);
  return row;
}

function select(...ips: string[]) {
  for (const ip of ips) fireEvent.click(within(rowOf(ip)).getByRole("checkbox"));
}

/** Waits until the adoption tab has read the policy. */
const adoptionLoaded = (pane: HTMLElement) =>
  waitFor(() => expect(within(pane).getByTestId("adoption-effective")).toBeTruthy(), { timeout: 5000 });

/** Opens the inline editor of the DNS name of a row; true when an input appeared. */
function editsInline(ip: string): boolean {
  const cell = rowOf(ip).querySelector('td[data-col="dns_name"]') as HTMLElement;
  fireEvent.dblClick(cell);
  return within(cell).queryByRole("textbox") !== null;
}

describe("gating of the prefix tree and the prefix pane", () => {
  it("shows an administrator every action", async () => {
    await signInAlex();
    const pane = await openPane(LAN);
    expect(screen.getByTestId("ipam-add-prefix")).toBeTruthy();
    expect(headActions(pane)).toEqual(HEAD_ACTIONS);
    startDrag([{ kind: "address", id: "x", label: "x", ip: "192.0.2.41" }]);
    fireEvent.dragOver(treeNode(IOT));
    expect(treeNode(IOT).classList.contains("drop")).toBe(true);
  });

  it("shows a scoped operator the actions on prefixes of its grant only", async () => {
    await signInScopedOperator();
    // Inside the grant: a network with no address yet.
    const lab = await openPane(LAB, false);
    expect(screen.getByTestId("ipam-add-prefix")).toBeTruthy();
    expect(headActions(lab)).toEqual(HEAD_ACTIONS);
    fireEvent.click(within(lab).getByTestId("prefix-tab-ranges"));
    expect(within(lab).getByTestId("range-add")).toBeTruthy();
    fireEvent.click(within(lab).getByTestId("prefix-tab-adoption"));
    await adoptionLoaded(lab);
    expect(within(lab).getByTestId("adoption-edit")).toBeTruthy();
    // A network of the grant takes a drop, one outside it does not.
    startDrag([{ kind: "address", id: "x", label: "x", ip: "192.0.2.41" }]);
    fireEvent.dragOver(treeNode(LAB));
    expect(treeNode(LAB).classList.contains("drop")).toBe(true);
    for (const outside of [IOT, LAN]) {
      fireEvent.dragOver(treeNode(outside));
      expect(treeNode(outside).classList.contains("drop")).toBe(false);
      expect(treeNode(outside).classList.contains("dim")).toBe(true);
    }
  });

  it.each([IOT, LAN])("hides every action of a scoped operator on %s", async (cidr) => {
    await signInScopedOperator();
    const pane = await openPane(cidr);
    expect(headActions(pane)).toEqual([]);
    expect(within(pane).queryByTestId("claim-gap")).toBeNull();
    select(cidr === IOT ? "198.51.100.1" : "192.0.2.1");
    expect(screen.getByTestId("actionbar")).toBeTruthy();
    expect(screen.queryByTestId("action-move")).toBeNull();
    expect(screen.getByTestId("action-export")).toBeTruthy();
    fireEvent.click(within(pane).getByTestId("prefix-tab-ranges"));
    expect(within(pane).queryByTestId("range-add")).toBeNull();
    fireEvent.click(within(pane).getByTestId("prefix-tab-adoption"));
    await adoptionLoaded(pane);
    expect(within(pane).queryByTestId("adoption-edit")).toBeNull();
    // Last, as a double-click on a cell that does not edit opens the address.
    fireEvent.click(within(pane).getByTestId("prefix-tab-addresses"));
    await waitFor(() => expect(within(pane).queryAllByTestId("row").length).toBeGreaterThan(0));
    expect(editsInline(cidr === IOT ? "198.51.100.1" : "192.0.2.1")).toBe(false);
  });

  it("offers a scoped operator the grid actions on the addresses of its grant", async () => {
    await signInScopedOperator();
    const pane = await openPane(CAMERAS);
    expect(headActions(pane)).toEqual(HEAD_ACTIONS);
    select("203.0.113.193");
    expect(screen.getByTestId("action-move")).toBeTruthy();
    expect(editsInline("203.0.113.193")).toBe(true);
  });

  it("hides every action from a viewer", async () => {
    await signInWithRoles(["viewer"]);
    const pane = await openPane(LAN);
    expect(screen.queryByTestId("ipam-add-prefix")).toBeNull();
    expect(headActions(pane)).toEqual([]);
    select("192.0.2.1");
    expect(screen.queryByTestId("action-move")).toBeNull();
    expect(editsInline("192.0.2.1")).toBe(false);
    startDrag([{ kind: "address", id: "x", label: "x", ip: "192.0.2.41" }]);
    fireEvent.dragOver(treeNode(IOT));
    expect(treeNode(IOT).classList.contains("drop")).toBe(false);
  });

  it("offers a scoped operator no new prefix beside a supernet it may not write", async () => {
    await signInScopedOperator();
    renderIpam(paths.prefix("2001:db8::/32"));
    await paneOf("2001:db8::/32");
    expect(screen.queryByTestId("ipam-add-prefix")).toBeNull();
    expect(screen.queryByTestId("prefix-next-free-prefix")).toBeNull();
  });
});

describe("gating of the address grid", () => {
  function renderList() {
    return renderRoute(AddressesView, {
      url: paths.addresses(),
      path: "/ipam/addresses",
      routes: { "/ipam/addresses/:ip": () => <div />, "/ipam/move": () => <div /> },
    });
  }
  const listed = () => waitFor(() => expect(screen.queryAllByTestId("row").length).toBeGreaterThan(20));

  it("shows an administrator the bar actions", async () => {
    await signInAlex();
    renderList();
    await listed();
    select("192.0.2.1", "203.0.113.193");
    expect(screen.getByTestId("action-move")).toBeTruthy();
  });

  it("hides the write actions of the bar when the selection has a row outside the scope", async () => {
    await signInScopedOperator();
    renderList();
    await listed();
    select("203.0.113.193");
    expect(screen.getByTestId("action-move")).toBeTruthy();
    select("192.0.2.1");
    expect(screen.queryByTestId("action-move")).toBeNull();
    expect(screen.getByTestId("action-export")).toBeTruthy();
  });

  it("hides the write actions of the bar from a viewer", async () => {
    await signInWithRoles(["viewer"]);
    renderList();
    await listed();
    select("203.0.113.193");
    expect(screen.queryByTestId("action-move")).toBeNull();
    expect(screen.getByTestId("action-export")).toBeTruthy();
  });
});

describe("gating of the address view", () => {
  function renderAddress(ip: string) {
    return renderRoute(AddressView, {
      url: paths.address(ip),
      path: "/ipam/addresses/:ip",
      routes: { "/ipam/prefixes/:network/:length": () => <div />, "/ipam/hosts/:fqdn": () => <div />, "/ipam/move": () => <div /> },
    });
  }
  const ACTIONS = ["address-edit", "address-move", "address-delete"];
  const shown = async (ip: string) => {
    const page = await screen.findByTestId("page-ipam-address");
    await waitFor(() => expect(within(page).getByRole("heading", { level: 1 }).textContent).toContain(ip));
    await waitFor(() => expect(within(page).queryByTestId("history-panel")).toBeTruthy());
    return page;
  };
  const present = (page: HTMLElement) => ACTIONS.filter((id) => within(page).queryByTestId(id));

  it("shows an administrator edit, move and delete", async () => {
    await signInAlex();
    renderAddress("192.0.2.41");
    expect(present(await shown("192.0.2.41"))).toEqual(ACTIONS);
  });

  it("shows a scoped operator the actions on an address of its grant only", async () => {
    await signInScopedOperator();
    renderAddress("203.0.113.193");
    expect(present(await shown("203.0.113.193"))).toEqual(ACTIONS);
  });

  it.each(["198.51.100.1", "192.0.2.41"])("hides them from a scoped operator on %s", async (ip) => {
    await signInScopedOperator();
    renderAddress(ip);
    expect(present(await shown(ip))).toEqual([]);
  });

  it("hides them from a viewer", async () => {
    await signInWithRoles(["viewer"]);
    renderAddress("192.0.2.41");
    expect(present(await shown("192.0.2.41"))).toEqual([]);
  });
});


describe("gating of the move preview", () => {
  async function preview(target: string, ...ips: string[]) {
    const objects = ips.map((ip) => ({ kind: "address", id: ADDRESS_IDS[ip] as string }));
    renderRoute(MovePreview, { url: paths.move(target, objects), path: "/ipam/move", routes: {} });
    const table = await screen.findByTestId("move-devices");
    await waitFor(() => expect(within(table).getAllByTestId("move-item")).toHaveLength(ips.length));
    await waitFor(() => expect(table.getAttribute("aria-busy")).toBeNull());
    // The cancel button is there whatever the principal may do: the page has rendered its foot.
    expect(screen.getByTestId("move-cancel")).toBeTruthy();
    return table;
  }

  it("shows an administrator the apply button", async () => {
    await signInAlex();
    await preview(IPAM_IDS.prefix.iot, "192.0.2.41");
    expect(screen.getByTestId("move-start")).toBeTruthy();
  });

  it("shows a scoped operator the apply button when every object and the target are in its scope", async () => {
    await signInScopedOperator();
    await preview(IPAM_IDS.prefix.lab, "203.0.113.193");
    expect(screen.getByTestId("move-start")).toBeTruthy();
  });

  it.each([
    ["an object outside the scope", IPAM_IDS.prefix.lab, ["203.0.113.193", "192.0.2.41"]],
    ["a target outside the scope", IPAM_IDS.prefix.iot, ["203.0.113.193"]],
  ] as const)("hides the apply button of a scoped operator for %s, the preview stays", async (_name, target, ips) => {
    await signInScopedOperator();
    const table = await preview(target, ...ips);
    expect(screen.queryByTestId("move-start")).toBeNull();
    expect(within(table).getAllByTestId("move-item").length).toBe(ips.length);
  });

  it("hides the apply button from a viewer", async () => {
    await signInWithRoles(["viewer"]);
    const table = await preview(IPAM_IDS.prefix.iot, "192.0.2.41");
    expect(screen.queryByTestId("move-start")).toBeNull();
    expect(within(table).getAllByTestId("move-item").length).toBe(1);
  });
});
