import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ANY_REVISION } from "../../api/client";
import { ADDRESS_IDS, IPAM_IDS, ipamState } from "../../api/mock/ipam/api";
import type { Vrf } from "../../api/types";
import { paths } from "../../app/paths";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { chooseVrf } from "../scope";
import { confirmPlan } from "../testkit";
import AddressView from "./AddressView";

// ---------------------------------------------------------------------------------
// Helpers

beforeEach(async () => {
  // The VRF in view is remembered per browser; every test starts from the default.
  chooseVrf(null);
  await signInAlex();
});

afterEach(() => {
  chooseVrf(null);
});

function renderAddress(ip: string, vrf?: string) {
  return renderRoute(AddressView, {
    url: paths.address(ip, vrf),
    path: "/ipam/addresses/:ip",
    routes: {
      "/ipam/prefixes/:network/:length": () => <div data-testid="prefix-route" />,
      "/ipam/hosts/:fqdn": () => <div data-testid="host-route" />,
      "/ipam/move": () => <div data-testid="move-route" />,
    },
  });
}

/** Waits for the address to be shown (its heading carries the address). */
async function shown(ip: string) {
  const page = await screen.findByTestId("page-ipam-address");
  await waitFor(() => expect(within(page).getByRole("heading", { level: 1 }).textContent).toContain(ip));
  return page;
}

/** The text of the value that follows a label of the facts list. */
function fact(page: HTMLElement, label: string): HTMLElement {
  const dt = within(page)
    .getAllByText(label, { selector: "dt" })
    .at(0);
  const dd = dt?.nextElementSibling;
  if (!dd || dd.tagName !== "DD") throw new Error(`no fact ${label}`);
  return dd as HTMLElement;
}

const stored = (ip: string) => ipamState().data.address.get(ADDRESS_IDS[ip] as string)!;

// ---------------------------------------------------------------------------------
// A bound address

describe("the address page", () => {
  it("shows the address, its DNS name and where it lies", async () => {
    renderAddress("192.0.2.41");
    const page = await shown("192.0.2.41");
    const heading = within(page).getByRole("heading", { level: 1 });
    expect(heading.textContent).toBe("192.0.2.41thermostat-1.example.test");
    expect(within(page).getByRole("heading", { level: 2, name: "Address" })).toBeTruthy();
    // The crumbs: the VRF and the network, once the tree has loaded.
    const crumbs = within(page).getByRole("navigation", { name: "Where this prefix lies" });
    await waitFor(() => expect(within(crumbs).getByRole("link", { name: "192.0.2.0/24" })).toBeTruthy());
    expect(crumbs.textContent).toContain("default");
    expect(within(crumbs).getByRole("link", { name: "192.0.2.0/24" }).getAttribute("href")).toBe(paths.prefix("192.0.2.0/24", IPAM_IDS.vrf.default));
  });

  it("shows status, prefix, VRF, host, interface and MAC address", async () => {
    renderAddress("192.0.2.41");
    const page = await shown("192.0.2.41");
    expect(fact(page, "Status").textContent).toBe("Active");
    // The VRF is named once the VRFs have loaded.
    await waitFor(() => expect(fact(page, "VRF").textContent).toBe("default"));
    // The prefix link appears once the tree has loaded.
    await waitFor(() => expect(within(fact(page, "Prefix")).getByRole("link", { name: "192.0.2.0/24" })).toBeTruthy());
    expect(within(fact(page, "Prefix")).getByRole("link").getAttribute("href")).toBe(paths.prefix("192.0.2.0/24", IPAM_IDS.vrf.default));
    // The host, its mode with the sentence that explains it, and no lock flag.
    const host = fact(page, "Host");
    const hostLink = within(host).getByRole("link", { name: "thermostat-1" });
    expect(hostLink.getAttribute("href")).toBe(paths.host("thermostat-1"));
    expect(host.querySelector(".mode.reserved")?.textContent).toBe("reserved");
    expect(host.querySelector(".mode-hint")?.textContent).toBe("An address change moves the DHCP reservation and updates DNS.");
    expect(host.querySelector(".flag.locked")).toBeNull();
    // The interface and its MAC address.
    expect(fact(page, "Interface").textContent?.trim()).toBe("eth0 00:00:5e:00:53:29");
    expect(fact(page, "Description").textContent).toBe("–");
    expect(fact(page, "Changed").textContent).not.toBe("");
  });

  it("shows the lock flag of a locked host", async () => {
    renderAddress("192.0.2.11");
    const page = await shown("192.0.2.11");
    const host = fact(page, "Host");
    expect(within(host).getByRole("link", { name: "nas" })).toBeTruthy();
    expect(within(host).getByText("Locked")).toBeTruthy();
  });

  it("shows the description and the tags", async () => {
    const address = stored("192.0.2.41");
    address.meta.description = "Hall thermostat";
    address.meta.tags = ["iot", "front door"];
    renderAddress("192.0.2.41");
    const page = await shown("192.0.2.41");
    expect(fact(page, "Description").textContent).toBe("Hall thermostat");
    const tags = [...fact(page, "Tags").querySelectorAll(".tag")].map((t) => t.textContent);
    expect(tags).toEqual(["iot", "front door"]);
  });

  it("leaves the MAC address out for an interface without one", async () => {
    renderAddress("192.0.2.60");
    const page = await shown("192.0.2.60");
    expect(within(fact(page, "Host")).getByRole("link", { name: "doorbell" })).toBeTruthy();
    expect(fact(page, "Interface").textContent?.trim()).toBe("eth0");
    expect(fact(page, "Interface").querySelector(".mac")).toBeNull();
  });

  it("says so when no host holds the address", async () => {
    stored("192.0.2.42").interface = null;
    renderAddress("192.0.2.42");
    const page = await shown("192.0.2.42");
    expect(fact(page, "Host").textContent).toBe("Not assigned to a host");
    expect(fact(page, "Interface").textContent).toBe("–");
  });

  it("reads the address with its host in one request and none for the host", async () => {
    // A static host: the address of a reserved host also reads its host and interface for the
    // reservation block (see "the reservation in DHCP").
    const spy = vi.spyOn(globalThis, "fetch");
    renderAddress("192.0.2.30");
    await shown("192.0.2.30");
    await waitFor(() => expect(screen.getAllByTestId("history-entry").length).toBeGreaterThan(0));
    const urls = spy.mock.calls.map(([input]) => new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, "http://localhost"));
    const lists = urls.filter((u) => u.pathname === "/api/v1/addresses");
    expect(lists).toHaveLength(1);
    expect(lists[0]?.searchParams.get("expand")).toBe("host");
    expect(lists[0]?.searchParams.get("q")).toBe("192.0.2.30");
    expect(urls.filter((u) => u.pathname.startsWith("/api/v1/hosts") || u.pathname.startsWith("/api/v1/interfaces"))).toEqual([]);
  });

  it("follows the links to the prefix and the host", async () => {
    const view = renderAddress("192.0.2.41");
    const page = await shown("192.0.2.41");
    await waitFor(() => expect(within(fact(page, "Prefix")).getByRole("link")).toBeTruthy());
    fireEvent.click(within(fact(page, "Prefix")).getByRole("link"));
    await screen.findByTestId("prefix-route");
    expect(view.location()).toBe(paths.prefix("192.0.2.0/24", IPAM_IDS.vrf.default));
  });
});

// ---------------------------------------------------------------------------------
// History

describe("the history of an address", () => {
  it("lists the creation, and later changes with the fields that changed", async () => {
    const address = stored("192.0.2.41");
    await api.patch("/api/v1/addresses/{id}", {
      path: { id: address.id },
      body: { description: "Hall thermostat" },
      ifMatch: ANY_REVISION,
    });
    renderAddress("192.0.2.41");
    const page = await shown("192.0.2.41");
    const panel = within(page).getByRole("region", { name: "History of 192.0.2.41" });
    await waitFor(() => expect(within(panel).getAllByTestId("history-entry")).toHaveLength(2));
    const entries = within(panel).getAllByTestId("history-entry");
    // Newest first.
    expect(entries.map((e) => e.dataset.action)).toEqual(["update", "create"]);
    const change = entries[0]?.querySelector("li[data-field='meta.description']");
    expect(change?.textContent).toBe("meta.description: – → Hall thermostat");
    expect(within(page).getByRole("heading", { level: 2, name: "History" })).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------------
// Not found, several VRFs, deleted

describe("an address that is not there", () => {
  it("shows the not-found state for an address nobody has", async () => {
    renderAddress("192.0.2.99");
    const page = await screen.findByTestId("page-ipam-address");
    expect(await within(page).findByText("No address 192.0.2.99 here.")).toBeTruthy();
    expect(within(page).queryByRole("heading", { level: 1 })).toBeNull();
    expect(within(page).queryByTestId("address-edit")).toBeNull();
    expect(within(page).queryByTestId("history-panel")).toBeNull();
  });

  it("shows the not-found state for an unknown identifier in the place of an address", async () => {
    renderAddress("0190d1c2-0000-7000-8000-0000e5ffffff");
    const page = await screen.findByTestId("page-ipam-address");
    expect(await within(page).findByText("No address 0190d1c2-0000-7000-8000-0000e5ffffff here.")).toBeTruthy();
    expect(within(page).queryByRole("heading", { level: 1 })).toBeNull();
  });

  it("shows the not-found state when the address is in another VRF than the one asked for", async () => {
    // 192.0.2.41 exists in the VRF default only.
    renderAddress("192.0.2.41", IPAM_IDS.vrf.isolated);
    const page = await screen.findByTestId("page-ipam-address");
    expect(await within(page).findByText("No address 192.0.2.41 here.")).toBeTruthy();
  });

  it("passes axe in the not-found state", async () => {
    renderAddress("192.0.2.99");
    const page = await screen.findByTestId("page-ipam-address");
    await within(page).findByText("No address 192.0.2.99 here.");
    expect(await axeViolations(page)).toEqual([]);
  });
});

describe("an address that exists in several VRFs", () => {
  it("shows the one in the VRF in view", async () => {
    renderAddress("192.0.2.10");
    const page = await shown("192.0.2.10");
    await waitFor(() => expect(fact(page, "VRF").textContent).toBe("default"));
    expect(within(fact(page, "Host")).getByRole("link", { name: "pve1" })).toBeTruthy();
  });

  it("shows the one the link names", async () => {
    renderAddress("192.0.2.10", IPAM_IDS.vrf.isolated);
    const page = await shown("192.0.2.10");
    await waitFor(() => expect(fact(page, "VRF").textContent).toBe("isolated"));
    expect(fact(page, "Host").textContent).toBe("Not assigned to a host");
    expect(page.textContent).toContain("bench-1.example.test");
  });

  it("asks which one when none is in the VRF in view", async () => {
    // A third VRF that has neither address, chosen as the VRF in view.
    const third: Vrf = { ...structuredClone(ipamState().data.vrf.get(IPAM_IDS.vrf.isolated) as Vrf), id: "0190d1c2-0000-7000-8000-0000000200a3", name: "spare" };
    ipamState().data.vrf.set(third.id, third);
    chooseVrf(third.id);
    renderAddress("192.0.2.10");
    const page = await screen.findByTestId("page-ipam-address");
    expect(await within(page).findByText("192.0.2.10 exists in several VRFs. Choose one:")).toBeTruthy();
    // The VRFs are named once they have loaded.
    const choices = () => within(page.querySelector("ul.list") as HTMLElement).getAllByRole("link");
    await waitFor(() => expect(choices().map((l) => l.textContent)).toEqual(["default", "isolated"]));
    expect(choices().map((l) => [l.textContent, l.getAttribute("href")])).toEqual([
      ["default", paths.address("192.0.2.10", IPAM_IDS.vrf.default)],
      ["isolated", paths.address("192.0.2.10", IPAM_IDS.vrf.isolated)],
    ]);
    expect(within(page).queryByRole("heading", { level: 1 })).toBeNull();
  });
});

describe("a deleted address", () => {
  it("is marked as deleted and offers restore instead of edit, move and delete", async () => {
    renderAddress("192.0.2.35");
    const page = await shown("192.0.2.35");
    expect(within(page).getByRole("heading", { level: 1 }).textContent).toContain("Deleted");
    expect(within(page).getByTestId("address-restore")).toBeTruthy();
    expect(within(page).queryByTestId("address-edit")).toBeNull();
    expect(within(page).queryByTestId("address-move")).toBeNull();
    expect(within(page).queryByTestId("address-delete")).toBeNull();
    // Its interface is deleted too, so no host and no MAC are shown.
    expect(fact(page, "Host").textContent).toBe("Not assigned to a host");
    // The history ends with the delete.
    await waitFor(() => expect(within(page).getAllByTestId("history-entry").map((e) => e.dataset.action)).toEqual(["delete", "create"]));
  });

  it("shows an address deleted in this page and brings it back with restore", async () => {
    renderAddress("192.0.2.42");
    const page = await shown("192.0.2.42");
    fireEvent.click(within(page).getByTestId("address-delete"));
    await confirmPlan({ dialog: "dialog-delete" });
    await waitFor(() => expect(stored("192.0.2.42").meta.deleted).toBeTruthy());
    await waitFor(() => expect(within(page).getByTestId("address-restore")).toBeTruthy());
    expect(within(page).getByRole("heading", { level: 1 }).textContent).toContain("Deleted");
    fireEvent.click(within(page).getByTestId("address-restore"));
    await confirmPlan({ dialog: "dialog-restore" });
    await waitFor(() => expect(stored("192.0.2.42").meta.deleted).toBeNull());
    await waitFor(() => expect(within(page).getByTestId("address-edit")).toBeTruthy());
    expect(within(page).getByRole("heading", { level: 1 }).textContent).not.toContain("Deleted");
  });
});

// ---------------------------------------------------------------------------------
// Actions

describe("the actions of the address page", () => {
  it("opens the form to edit the address", async () => {
    renderAddress("192.0.2.41");
    const page = await shown("192.0.2.41");
    fireEvent.click(within(page).getByTestId("address-edit"));
    const form = await screen.findByTestId("dialog-address-form");
    expect((within(form).getByTestId("field-ip") as HTMLInputElement).value).toBe("192.0.2.41");
    expect((within(form).getByTestId("field-dns_name") as HTMLInputElement).value).toBe("thermostat-1.example.test");
  });

  it("opens the move target dialog for the address", async () => {
    renderAddress("192.0.2.41");
    const page = await shown("192.0.2.41");
    fireEvent.click(within(page).getByTestId("address-move"));
    const dialog = await screen.findByTestId("dialog-move-target");
    expect(within(dialog).getByRole("heading", { name: "Move 1 object to a network" })).toBeTruthy();
  });

  it("goes to the move preview of the address when a target is chosen", async () => {
    const view = renderAddress("192.0.2.41");
    const page = await shown("192.0.2.41");
    fireEvent.click(within(page).getByTestId("address-move"));
    const dialog = await screen.findByTestId("dialog-move-target");
    await waitFor(() => expect(within(dialog).getAllByRole("option").length).toBeGreaterThan(0));
    fireEvent.click(within(dialog).getAllByRole("option").find((o) => (o as HTMLElement).dataset.key === "198.51.100.0/24") as HTMLElement);
    await screen.findByTestId("move-route");
    expect(view.location()).toBe(paths.move(IPAM_IDS.prefix.iot, [{ kind: "address", id: ADDRESS_IDS["192.0.2.41"] as string }]));
  });

  it("opens the delete dialog for the address", async () => {
    renderAddress("192.0.2.41");
    const page = await shown("192.0.2.41");
    fireEvent.click(within(page).getByTestId("address-delete"));
    const dialog = await screen.findByTestId("dialog-delete");
    expect(within(dialog).getByRole("heading", { name: "Delete address 192.0.2.41" })).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------------
// Accessibility

describe("accessibility of the address page", () => {
  it("passes axe with an address, its host and its history", async () => {
    renderAddress("192.0.2.41");
    const page = await shown("192.0.2.41");
    await waitFor(() => expect(within(fact(page, "Prefix")).getByRole("link")).toBeTruthy());
    await waitFor(() => expect(within(page).getAllByTestId("history-entry").length).toBeGreaterThan(0));
    expect(await axeViolations(page)).toEqual([]);
  });

  it("passes axe with a deleted address", async () => {
    renderAddress("192.0.2.35");
    const page = await shown("192.0.2.35");
    await waitFor(() => expect(within(page).getAllByTestId("history-entry").length).toBeGreaterThan(0));
    expect(await axeViolations(page)).toEqual([]);
  });
});
