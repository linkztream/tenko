// Reserving an address in DHCP (DHCP-01, IPAM-18, IPAM-23): from the IPAM address page and the
// address list's row menu, and from the lease list; the prefill (host, interface, MAC address,
// client identifier, name), the sentences before the save, the save in one request with one audit
// record, the reservation shown afterwards, the address inside a pool, the lease that already is a
// reservation, and who is offered the action.
import { fireEvent, screen, waitFor, within } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../../api/client";
import { audit } from "../../api/mock/audit-store";
import { ADDRESS_IDS, HOST_IDS, INTERFACE_IDS, ipamState } from "../../api/mock/ipam/api";
import { grantMockLease } from "../../api/mock/routes-dhcp-leases";
import { paths } from "../../app/paths";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import AddressesView from "../../ipam/address/AddressesView";
import AddressView from "../../ipam/address/AddressView";
import { chooseVrf } from "../../ipam/scope";
import LeasesPage from "../leases/LeasesPage";
import { row, rowAction, rowActions, rows } from "../testkit";

beforeEach(async () => {
  chooseVrf(null);
  await signInAlex();
});

afterEach(async () => {
  vi.restoreAllMocks();
  chooseVrf(null);
  setSessionForTest(null);
  await setLocale("en");
});

const LEASES = "dhcp-leases";

function openAddress(ip: string) {
  return renderRoute(AddressView, {
    url: paths.address(ip),
    path: "/ipam/addresses/:ip",
    routes: { "/ipam/hosts/:fqdn": () => <div data-testid="host-route" />, "/dhcp/scopes/:prefix": () => <div data-testid="scope-route" /> },
  });
}

async function addressPage(ip: string) {
  const page = await screen.findByTestId("page-ipam-address");
  await waitFor(() => expect(within(page).getByRole("heading", { level: 1 }).textContent).toContain(ip));
  return page;
}

function openLeases() {
  return renderRoute(LeasesPage, { url: "/dhcp/leases", path: "/dhcp/leases", routes: { "/ipam/hosts/:fqdn": () => <div data-testid="host-route" /> } });
}

/** The dialog once it has read what it needs. */
async function dialog(): Promise<HTMLElement> {
  const found = await screen.findByTestId("dialog-reserve");
  await within(found).findByTestId("reserve-form");
  return found;
}

/** The message keys of the sentences of the preview. */
function sentences(d: HTMLElement): string[] {
  return within(d)
    .getAllByTestId("reserve-sentence")
    .map((s) => s.dataset.key ?? "");
}

function sentence(d: HTMLElement, key: string): string {
  const found = within(d)
    .getAllByTestId("reserve-sentence")
    .find((s) => s.dataset.key === key);
  if (!found) throw new Error(`no sentence ${key}: ${sentences(d).join(", ")}`);
  return found.textContent ?? "";
}

const field = (d: HTMLElement, id: string) => within(d).getByTestId(`field-${id}`) as HTMLInputElement & HTMLSelectElement;

describe("from the address page", () => {
  it("prefills the address's host, interface and MAC address and says what the save changes", async () => {
    openAddress("192.0.2.30");
    const page = await addressPage("192.0.2.30");
    fireEvent.click(await within(page).findByTestId("address-reserve"));
    const d = await dialog();
    expect(within(d).getByTestId("reserve-address").textContent).toBe("192.0.2.30");
    expect(within(d).getByTestId("reserve-scope").textContent).toContain("192.0.2.0/24");
    await waitFor(() => expect(field(d, "reserve-iface").value).toBe(INTERFACE_IDS["printer-1"]));
    expect(field(d, "reserve-host").value).toBe(HOST_IDS["printer-1"]);
    expect(field(d, "reserve-mac").value).toBe("00:00:5e:00:53:1e");
    expect(field(d, "reserve-client-id").value).toBe("");
    expect(sentence(d, "dhcp.reserve.will.host_mode")).toBe("Host printer-1 becomes reserved (it is static now).");
    expect(sentence(d, "dhcp.reserve.will.interface_mac_kept")).toBe("Interface eth0 keeps the MAC address 00:00:5e:00:53:1e.");
    expect(sentence(d, "dhcp.reserve.will.address_kept")).toBe("The address 192.0.2.30 stays active.");
    expect(sentence(d, "dhcp.reserve.will.keyed_mac")).toBe("The reservation is keyed by the MAC address 00:00:5e:00:53:1e.");
    // An active address does not go back to planned (IPAM-05).
    expect(within(field(d, "reserve-status")).getAllByRole("radio")).toHaveLength(1);
    expect(await axeViolations(d)).toEqual([]);
  });

  it("writes the rows in one request with one audit record and shows the reservation", async () => {
    const spy = vi.spyOn(globalThis, "fetch");
    openAddress("192.0.2.30");
    const page = await addressPage("192.0.2.30");
    fireEvent.click(await within(page).findByTestId("address-reserve"));
    const d = await dialog();
    await waitFor(() => expect(field(d, "reserve-iface").value).toBe(INTERFACE_IDS["printer-1"]));
    fireEvent.input(field(d, "reserve-client-id"), { target: { value: "01:00:00:5e:00:53:1e" } });
    expect(sentence(d, "dhcp.reserve.will.interface_client_id")).toBe("Interface eth0 gets the client identifier 01:00:00:5e:00:53:1e.");
    expect(sentence(d, "dhcp.reserve.will.keyed_client_id")).toContain("01:00:00:5e:00:53:1e");
    const before = audit.records.length;
    fireEvent.click(within(d).getByTestId("form-submit"));
    const done = await within(d).findByTestId("reserve-done");
    expect(within(done).getByTestId("reserve-saved").textContent).toBe("192.0.2.30 is reserved for printer-1.");
    // The reservation as the host page shows it, with the scope.
    const block = await within(done).findByTestId("host-reservations");
    await waitFor(() => expect(within(block).getAllByTestId("host-reservation")).toHaveLength(1));
    expect(within(block).getByTestId("host-reservation-identity").dataset.kind).toBe("client_id");
    expect(within(block).getByTestId("host-reservation-scope").textContent).toBe("192.0.2.0/24");
    expect(within(done).getByTestId("reserve-open-host").getAttribute("href")).toBe(paths.host("printer-1"));

    const writes = spy.mock.calls
      .map(([input, init]) => ({ url: new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, "http://localhost"), method: (init?.method ?? "GET").toUpperCase(), body: init?.body }))
      .filter((c) => c.method !== "GET");
    expect(writes.map((w) => `${w.method} ${w.url.pathname}`)).toEqual([`POST /api/v1/addresses/${ADDRESS_IDS["192.0.2.30"]}/reserve`]);
    expect(JSON.parse(String(writes[0]?.body))).toEqual({
      host: HOST_IDS["printer-1"],
      interface: INTERFACE_IDS["printer-1"],
      mac: "00:00:5e:00:53:1e",
      client_id: "0100005e00531e",
      status: "active",
    });
    const data = ipamState().data;
    expect(data.host.get(HOST_IDS["printer-1"] as string)?.mode).toBe("reserved");
    expect(data.interface.get(INTERFACE_IDS["printer-1"] as string)?.client_id).toBe("0100005e00531e");
    const added = audit.records.slice(before).map((r) => r.draft.action);
    expect(added).toEqual(["ipam.address.reserve"]);
  });

  it("offers a new host named after the address for an address without a host", async () => {
    await api.post("/api/v1/addresses", { body: { ip: "192.0.2.77", dns_name: "Scanner.example.test" } as never });
    openAddress("192.0.2.77");
    const page = await addressPage("192.0.2.77");
    fireEvent.click(await within(page).findByTestId("address-reserve"));
    const d = await dialog();
    expect(field(d, "reserve-host").value).toBe("new");
    expect(field(d, "reserve-new-host").value).toBe("scanner");
    expect(field(d, "reserve-new-iface").value).toBe("eth0");
    // No MAC address is known: the save needs one.
    fireEvent.click(within(d).getByTestId("form-submit"));
    expect((await within(d).findByTestId("field-error")).textContent).toBe("A reservation needs a MAC address or a client identifier.");
    fireEvent.input(field(d, "reserve-mac"), { target: { value: "02-00-5E-10-00-77" } });
    expect(sentence(d, "dhcp.reserve.will.host_new")).toBe("A new host scanner is created, of mode reserved.");
    expect(sentence(d, "dhcp.reserve.will.interface_new_mac")).toBe("A new interface eth0 is created with the MAC address 02:00:5e:10:00:77.");
    expect(sentence(d, "dhcp.reserve.will.address_bound")).toBe("The address 192.0.2.77 is bound to interface eth0.");
    fireEvent.click(within(d).getByTestId("form-submit"));
    await within(d).findByTestId("reserve-done");
    const host = [...ipamState().data.host.values()].find((h) => h.name === "scanner");
    expect(host?.mode).toBe("reserved");
  });

  it("shows the reservation of the address of a reserved host", async () => {
    openAddress("192.0.2.41");
    const page = await addressPage("192.0.2.41");
    const block = await within(page).findByTestId("host-reservations");
    await waitFor(() => expect(within(block).getAllByTestId("host-reservation")).toHaveLength(1));
    expect(within(block).getByTestId("host-reservation-identity").textContent).toContain("00:00:5e:00:53:29");
  });

  it("says why the save is refused and keeps the dialog open", async () => {
    // Another reserved host presents the same MAC address in the scope (IPAM-23).
    openAddress("192.0.2.30");
    const page = await addressPage("192.0.2.30");
    fireEvent.click(await within(page).findByTestId("address-reserve"));
    const d = await dialog();
    await waitFor(() => expect(field(d, "reserve-iface").value).toBe(INTERFACE_IDS["printer-1"]));
    fireEvent.input(field(d, "reserve-mac"), { target: { value: "00:00:5e:00:53:29" } });
    fireEvent.click(within(d).getByTestId("form-submit"));
    const refusal = await within(d).findByTestId("error-notice");
    expect(refusal.dataset.code).toBe("dhcp.reservation.conflict");
    expect(ipamState().data.host.get(HOST_IDS["printer-1"] as string)?.mode).toBe("static");
  });

  it("is offered only where the prefix has a scope and to those who may write IPAM and DHCP", async () => {
    // 198.51.100.0/24 has no scope.
    openAddress("198.51.100.44");
    const iot = await addressPage("198.51.100.44");
    await within(iot).findByTestId("address-edit");
    expect(within(iot).queryByTestId("address-reserve")).toBeNull();
  });

  it("is not offered to a viewer", async () => {
    await signInWithRoles(["viewer"]);
    openAddress("192.0.2.30");
    const page = await addressPage("192.0.2.30");
    await waitFor(() => expect(within(page).getByRole("heading", { level: 2, name: "Address" })).toBeTruthy());
    expect(within(page).queryByTestId("address-reserve")).toBeNull();
  });
});

describe("from the address list", () => {
  it("opens the dialog from the row menu", async () => {
    renderRoute(AddressesView, { url: "/ipam/addresses", path: "/ipam/addresses" });
    await waitFor(() => expect(rows("addresses").length).toBeGreaterThan(0));
    const target = rows("addresses").find((r) => r.dataset.key === "192.0.2.30") as HTMLElement;
    await waitFor(async () => expect(await rowActions(target)).toContain("reserve"));
    await rowAction(target, "reserve");
    const d = await dialog();
    expect(within(d).getByTestId("reserve-address").textContent).toBe("192.0.2.30");
  });

  it("offers no reservation for an address in a prefix without a scope", async () => {
    renderRoute(AddressesView, { url: "/ipam/addresses", path: "/ipam/addresses" });
    await waitFor(() => expect(rows("addresses").length).toBeGreaterThan(0));
    const lan = rows("addresses").find((r) => r.dataset.key === "192.0.2.30") as HTMLElement;
    await waitFor(async () => expect(await rowActions(lan)).toContain("reserve"));
    const iot = rows("addresses").find((r) => r.dataset.key === "198.51.100.44") as HTMLElement;
    expect(await rowActions(iot)).not.toContain("reserve");
  });
});

describe("from the lease list", () => {
  it("prefills the lease's client and offers the next free address outside the pool", async () => {
    openLeases();
    await waitFor(() => expect(rows(LEASES).length).toBeGreaterThan(0));
    // The lease of laptop-ak's MAC address: IPAM knows its host.
    await waitFor(async () => expect(await rowActions(row(LEASES, "192.0.2.104"))).toContain("reserve"));
    await rowAction(row(LEASES, "192.0.2.104"), "reserve");
    const d = await dialog();
    expect(field(d, "reserve-ip").value).toBe("192.0.2.104");
    expect(field(d, "reserve-host").value).toBe(HOST_IDS["laptop-ak"]);
    expect(field(d, "reserve-mac").value).toBe("00:00:5e:00:53:14");
    expect(field(d, "reserve-client-id").value).toBe("01:00:00:5e:00:53:14");
    // The address lies in the pool: the save waits for another address.
    expect(within(d).getByTestId("reserve-in-pool").textContent).toContain("192.0.2.100–192.0.2.199");
    expect((within(d).getByTestId("form-submit") as HTMLButtonElement).disabled).toBe(true);
    const use = await within(d).findByTestId("reserve-use-free");
    const next = /Use (\S+),/.exec(use.textContent ?? "")?.[1] ?? "";
    fireEvent.click(use);
    expect(field(d, "reserve-ip").value).toBe(next);
    await waitFor(() => expect(within(d).queryByTestId("reserve-in-pool")).toBeNull());
    expect(sentence(d, "dhcp.reserve.will.address_new")).toBe(`The address ${next} is created in IPAM on interface eth0, status active.`);
    expect(sentence(d, "dhcp.reserve.will.host_mode")).toBe("Host laptop-ak becomes reserved (it is dynamic now).");
    fireEvent.click(within(d).getByTestId("form-submit"));
    await within(d).findByTestId("reserve-done");
    const created = [...ipamState().data.address.values()].find((a) => a.ip === next && !a.meta.deleted);
    expect(created?.interface).toBe(INTERFACE_IDS["laptop-ak"]);
  });

  it("names a new host after the lease's host name", async () => {
    openLeases();
    await waitFor(() => expect(rows(LEASES).length).toBeGreaterThan(0));
    await waitFor(async () => expect(await rowActions(row(LEASES, "192.0.2.101"))).toContain("reserve"));
    await rowAction(row(LEASES, "192.0.2.101"), "reserve");
    const d = await dialog();
    expect(field(d, "reserve-host").value).toBe("new");
    expect(field(d, "reserve-new-host").value).toBe("host-2");
    expect(field(d, "reserve-mac").value).toBe("00:00:5e:00:53:11");
  });

  it("shows a lease that is its client's reservation as reserved, with its host", async () => {
    grantMockLease({ mac: "00:00:5e:00:53:29", hostname: "thermostat-1", addr: "192.0.2.41" });
    const view = openLeases();
    await waitFor(() => expect(rows(LEASES).length).toBeGreaterThan(0));
    const reserved = row(LEASES, "192.0.2.41");
    expect(within(reserved).getByTestId("lease-reserved")).toBeTruthy();
    const link = await within(reserved).findByTestId("lease-reserved-host");
    expect(link.getAttribute("href")).toBe(paths.host("thermostat-1"));
    const actions = await rowActions(reserved);
    expect(actions).toContain("open_host");
    expect(actions).not.toContain("reserve");
    await rowAction(reserved, "open_host");
    await screen.findByTestId("host-route");
    expect(view.location()).toBe(paths.host("thermostat-1"));
  });

  it("offers a viewer neither", async () => {
    await signInWithRoles(["viewer"]);
    openLeases();
    await waitFor(() => expect(rows(LEASES).length).toBeGreaterThan(0));
    expect(await rowActions(row(LEASES, "192.0.2.104"))).toEqual(["history"]);
  });
});
