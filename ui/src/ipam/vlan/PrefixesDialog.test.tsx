import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { applyCommands, IPAM_IDS, ipamState } from "../../api/mock/ipam/api";
import type { Vlan } from "../../api/types";
import { paths } from "../../app/paths";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import VlansView from "../tenancy/VlansView";
import { PrefixesDialog } from "./PrefixesDialog";

beforeEach(async () => {
  await signInAlex();
});

const vlanOf = (id: string): Vlan => {
  const found = ipamState().data.vlan.get(id);
  if (!found) throw new Error(`no VLAN ${id} in the mock`);
  return found;
};

function open(vlan: Vlan) {
  const close = vi.fn();
  const view = renderRoute(() => <PrefixesDialog vlan={vlan} onClose={close} />, {
    routes: { "/ipam/prefixes/:network/:length": () => <div data-testid="prefix-page" /> },
  });
  return { close, view };
}

const dialog = () => screen.findByTestId("dialog-vlan-prefixes");
const itemsOf = (root: HTMLElement) => within(root).queryAllByTestId("vlan-prefix");

describe("the prefixes of a VLAN", () => {
  it("lists the linked prefixes with a link to each prefix page and its status", async () => {
    open(vlanOf(IPAM_IDS.vlan.v10));
    const dlg = await dialog();
    expect(within(dlg).getByRole("heading", { name: "Prefixes of VLAN 10 (LAN)" })).toBeTruthy();
    await waitFor(() => expect(itemsOf(dlg)).toHaveLength(2));
    const items = itemsOf(dlg);
    expect(items.map((i) => i.dataset.key)).toEqual(["192.0.2.0/24", "2001:db8:0:10::/64"]);
    const links = items.map((i) => within(i).getByRole("link"));
    expect(links.map((a) => a.getAttribute("href"))).toEqual([
      paths.prefix("192.0.2.0/24", IPAM_IDS.vrf.default),
      paths.prefix("2001:db8:0:10::/64", IPAM_IDS.vrf.default),
    ]);
    expect(links.map((a) => a.textContent)).toEqual(["192.0.2.0/24", "2001:db8:0:10::/64"]);
    expect(within(items[0] as HTMLElement).getByTestId("status-badge").dataset.status).toBe("active");
    expect(items[0]?.textContent).toContain("Network");
    // The note on how a prefix is linked.
    expect(within(dlg).getByText("A prefix is linked to a VLAN by editing the prefix.")).toBeTruthy();
    expect(within(dlg).queryByTestId("vlan-prefixes-empty")).toBeNull();
    expect(await axeViolations(dlg)).toEqual([]);
  });

  it("says so when no prefix is linked", async () => {
    open(vlanOf(IPAM_IDS.vlan.v50));
    const dlg = await dialog();
    const empty = await within(dlg).findByTestId("vlan-prefixes-empty");
    expect(empty.textContent).toBe("No prefix is linked to this VLAN.");
    expect(itemsOf(dlg)).toHaveLength(0);
    expect(within(dlg).getByText("A prefix is linked to a VLAN by editing the prefix.")).toBeTruthy();
    expect(await axeViolations(dlg)).toEqual([]);
  });

  it("names the VRF of a prefix and keeps the VRF in its link", async () => {
    applyCommands([{ op: "update_prefix", args: { id: IPAM_IDS.prefix.workshop, expected: null, patch: { vlan: IPAM_IDS.vlan.v10 } } }] as never);
    open(vlanOf(IPAM_IDS.vlan.v10));
    const dlg = await dialog();
    await waitFor(() => expect(itemsOf(dlg)).toHaveLength(3));
    // The network of the workshop has the address of the LAN in another VRF: tell them by the link.
    const cidr = ipamState().data.prefix.get(IPAM_IDS.prefix.workshop)?.cidr ?? "";
    const href = paths.prefix(cidr, IPAM_IDS.vrf.isolated);
    const isolated = () => itemsOf(dlg).find((i) => within(i).getByRole("link").getAttribute("href") === href);
    expect(isolated()).toBeTruthy();
    await waitFor(() => expect(isolated()?.textContent).toContain("VRF isolated"));
    expect(itemsOf(dlg).filter((i) => i.textContent?.includes("VRF default"))).toHaveLength(2);
  });

  it("opens the prefix page from the link", async () => {
    const { view } = open(vlanOf(IPAM_IDS.vlan.v20));
    const dlg = await dialog();
    const item = (await within(dlg).findAllByTestId("vlan-prefix"))[0] as HTMLElement;
    fireEvent.click(within(item).getByRole("link"));
    await waitFor(() => expect(view.location()).toBe(paths.prefix(item.dataset.key ?? "", IPAM_IDS.vrf.default)));
  });

  it("shows the error of a VLAN that does not exist", async () => {
    open({ ...vlanOf(IPAM_IDS.vlan.v10), id: "0190d1c2-0000-7000-8000-0000000400ff" });
    const dlg = await dialog();
    expect(await within(dlg).findByRole("alert")).toBeTruthy();
    expect(within(dlg).queryByTestId("vlan-prefixes-empty")).toBeNull();
    expect(itemsOf(dlg)).toHaveLength(0);
  });

  it("closes with the button", async () => {
    const { close } = open(vlanOf(IPAM_IDS.vlan.v10));
    const dlg = await dialog();
    fireEvent.click(within(dlg).getByTestId("vlan-prefixes-close"));
    expect(close).toHaveBeenCalledTimes(1);
  });
});

describe("the prefixes action of the VLAN page", () => {
  it("opens the list for the row and closes it again", async () => {
    renderRoute(VlansView, { url: "/ipam/vlans" });
    const grid = await screen.findByTestId("grid-vlans");
    await waitFor(() => expect(within(grid).queryAllByTestId("row")).toHaveLength(6));
    const row = within(grid).getAllByTestId("row").find((r) => r.dataset.key === "30 IoT") as HTMLElement;
    fireEvent.click(within(row).getByRole("button", { name: "Actions for 30 IoT" }));
    const menu = await screen.findByTestId("row-menu");
    fireEvent.click(within(menu).getAllByTestId("menu-item").find((i) => i.dataset.key === "prefixes") as HTMLElement);
    const dlg = await dialog();
    expect(within(dlg).getByRole("heading", { name: "Prefixes of VLAN 30 (IoT)" })).toBeTruthy();
    await waitFor(() => expect(itemsOf(dlg).map((i) => i.dataset.key)).toEqual(["198.51.100.0/24", "2001:db8:0:30::/64"]));
    fireEvent.click(within(dlg).getByTestId("vlan-prefixes-close"));
    await waitFor(() => expect(screen.queryByTestId("dialog-vlan-prefixes")).toBeNull());
  });
});
