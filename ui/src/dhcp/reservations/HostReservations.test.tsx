// The DHCP reservations block of a reserved host: a host with a MAC address in a served scope with
// an active lease, a lease held by another client, an address in no scope, an interface without
// identity, a disabled scope, a server where the dhcp role does not run, the block hiding itself
// where DHCP is off or not readable, and a lease that arrives while the page is open. DHCPv6 (WP9.4):
// a reservation keyed by the interface's DUID, one keyed by its MAC address, an address without
// either, and a lease held by another DUID or another MAC address.
import { screen, waitFor, within } from "@solidjs/testing-library";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { events, type ApiEvent } from "../../api/events";
import { db } from "../../api/mock/db";
import { DHCP_IDS } from "../../api/mock/dhcp-model";
import { IPAM_IDS } from "../../api/mock/ipam/api";
import { server } from "../../api/mock/node";
import { dhcpState } from "../../api/mock/routes-dhcp";
import { docMac, grantMockLease } from "../../api/mock/routes-dhcp-leases";
import type { Address, Host, Interface } from "../../api/types";
import { axeViolations } from "../../app/testing/axe";
import { renderRoute } from "../../app/testing/render";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { setLocale } from "../../i18n";
import { dhcpNoService, dhcpSwitchedOff } from "../testkit";
import HostReservations from "./HostReservations";

beforeEach(async () => {
  await signInAlex();
});

afterEach(async () => {
  setSessionForTest(null);
  await setLocale("en");
});

const VRF = IPAM_IDS.vrf.default;
const META = { revision: 1, tags: [], custom: {}, created: { at: "2025-01-01T00:00:00Z" }, updated: { at: "2025-01-01T00:00:00Z" } };
const MAC = "00:00:5e:00:53:29";
const OTHER_MAC = "00:00:5e:00:53:7f";

const host = { id: "host-1", name: "thermostat-1", mode: "reserved", lock: false, meta: META } as unknown as Host;
const eth0 = (extra: Partial<Interface> = {}) => ({ id: "if-1", host: "host-1", name: "eth0", mac: MAC, meta: META, ...extra }) as unknown as Interface;
const addr = (ip: string, extra: Partial<Address> = {}) => ({ id: `ad-${ip}`, ip, vrf: VRF, status: "active", interface: "if-1", prefix: "p", meta: META, ...extra }) as unknown as Address;

function show(interfaces: Interface[], addresses: Address[]) {
  return renderRoute(() => <HostReservations host={host} interfaces={interfaces} addresses={addresses} />, { url: "/ipam/hosts/thermostat-1", path: "/ipam/hosts/:fqdn" });
}
const rows = () => screen.queryAllByTestId("host-reservation");
const rowOf = (ip: string) => rows().find((r) => r.dataset.key === ip) as HTMLElement;
/** Waits until the block has its rows (it shows nothing before the DHCP data is there). */
const loaded = async (count = 1) => {
  await screen.findByTestId("host-reservations");
  await waitFor(() => expect(rows()).toHaveLength(count));
};
const settled = async (ip: string) => waitFor(() => expect(rowOf(ip).dataset.lease).not.toBe("loading"));

function problem(status: number, code: string): Response {
  return HttpResponse.json({ type: "about:blank", status, code, title: "Problem", detail: code, params: {} }, { status, headers: { "content-type": "application/problem+json" } });
}

describe("a reserved host with a MAC address in a served scope", () => {
  it("shows the identity, the scope, that it is served, and the active lease with its end", async () => {
    grantMockLease({ mac: MAC, addr: "192.0.2.41", hostname: "thermostat-1" });
    const view = show([eth0()], [addr("192.0.2.41")]);
    await loaded();
    await settled("192.0.2.41");
    const row = rowOf("192.0.2.41");
    expect(row.dataset.state).toBe("served");
    expect(row.dataset.lease).toBe("active");
    expect(row.dataset.mismatch).toBeUndefined();
    expect(within(row).getByTestId("host-reservation-identity").dataset.kind).toBe("mac");
    expect(within(row).getByTestId("host-reservation-identity").textContent).toBe(`MAC address ${MAC}`);
    const scope = within(row).getByTestId("host-reservation-scope");
    expect(scope.getAttribute("href")).toBe(`/dhcp/scopes/${DHCP_IDS.lan}`);
    expect(scope.textContent).toBe("192.0.2.0/24");
    expect(within(row).getByTestId("host-reservation-state-tag").textContent).toBe("Served");
    expect(within(row).getByTestId("host-reservation-lease-state").textContent).toBe("Active");
    expect(row.textContent).toMatch(/Ends in (59|60) minutes|Ends in 1 hour/);
    expect(within(row).getByTestId("host-reservation-history").getAttribute("href")).toBe("/dhcp/history?addr=192.0.2.41");
    expect(screen.getByTestId("host-reservations").dataset.count).toBe("1");
    expect(within(row).queryByTestId("host-reservation-mismatch")).toBeNull();
    expect(await axeViolations(view.container)).toEqual([]);
  });

  it("says there is no lease yet when the client has not asked", async () => {
    show([eth0()], [addr("192.0.2.41")]);
    await loaded();
    await settled("192.0.2.41");
    const row = rowOf("192.0.2.41");
    expect(row.dataset.state).toBe("served");
    expect(row.dataset.lease).toBe("none");
    expect(within(row).getByTestId("host-reservation-no-lease").textContent).toBe("No lease yet: the client has not asked since the reservation exists");
  });

  it("warns when the lease on the address is held by another client", async () => {
    grantMockLease({ mac: OTHER_MAC, addr: "192.0.2.41" });
    show([eth0()], [addr("192.0.2.41")]);
    await loaded();
    await settled("192.0.2.41");
    const row = rowOf("192.0.2.41");
    expect(row.dataset.mismatch).toBe("true");
    expect(row.dataset.lease).toBe("active");
    expect(within(row).getByTestId("host-reservation-mismatch").textContent).toBe(`Held by another client: ${OTHER_MAC}`);
  });

  it("compares the client identifier when the reservation is keyed by one", async () => {
    // The lease of the client with this identifier is the right one even from another hardware address.
    const lease = grantMockLease({ mac: OTHER_MAC, addr: "192.0.2.41" });
    lease.client!.client_id = "0100005e005329";
    show([eth0({ client_id: "01:00:00:5e:00:53:29" })], [addr("192.0.2.41")]);
    await loaded();
    await settled("192.0.2.41");
    const row = rowOf("192.0.2.41");
    expect(within(row).getByTestId("host-reservation-identity").dataset.kind).toBe("client_id");
    expect(within(row).getByTestId("host-reservation-identity").textContent).toBe("Client identifier 01:00:00:5e:00:53:29");
    expect(row.dataset.mismatch).toBeUndefined();
  });

  it("shows a lease that is not active by its state, without an end and without a warning", async () => {
    const lease = grantMockLease({ mac: OTHER_MAC, addr: "192.0.2.41" });
    lease.state = "expired";
    show([eth0()], [addr("192.0.2.41")]);
    await loaded();
    await settled("192.0.2.41");
    const row = rowOf("192.0.2.41");
    expect(row.dataset.lease).toBe("expired");
    expect(row.dataset.mismatch).toBeUndefined();
    expect(within(row).getByTestId("host-reservation-lease-state").textContent).toBe("Expired");
    expect(row.textContent).not.toMatch(/Ends/);
  });

  it("follows a lease that is granted while the page is open", async () => {
    const subscribe = vi.spyOn(events, "subscribe");
    show([eth0()], [addr("192.0.2.41")]);
    await loaded();
    await settled("192.0.2.41");
    expect(rowOf("192.0.2.41").dataset.lease).toBe("none");
    grantMockLease({ mac: MAC, addr: "192.0.2.41" });
    // The server announces the change on the dhcp topic; the block reads the lease again.
    const handler = subscribe.mock.calls.find(([topic]) => topic === "dhcp")?.[1];
    if (!handler) throw new Error("the block did not subscribe to the dhcp topic");
    const revision = db.revision + 100_000;
    const event: ApiEvent = { topic: "dhcp", type: "dhcp", objects: [], deleted: [], revision, data: { tables: ["dhcp.leases"], revision } };
    handler(event);
    await waitFor(() => expect(rowOf("192.0.2.41").dataset.lease).toBe("active"));
  });

  it("lists the IPv4 address before the IPv6 one, each with its family, and no longer says IPv6 gets no reservation", async () => {
    show([eth0()], [addr("2001:db8:0:10::41"), addr("192.0.2.41")]);
    await loaded(2);
    expect(rows().map((r) => r.dataset.key)).toEqual(["192.0.2.41", "2001:db8:0:10::41"]);
    expect(within(rowOf("192.0.2.41")).getByTestId("host-reservation-family").textContent).toBe("DHCPv4");
    expect(within(rowOf("2001:db8:0:10::41")).getByTestId("host-reservation-family").dataset.key).toBe("v6");
    expect(screen.queryByTestId("host-reservations-ipv6")).toBeNull();
  });

  it("links the address to its page", async () => {
    show([eth0()], [addr("192.0.2.41")]);
    await loaded();
    const link = within(rowOf("192.0.2.41")).getAllByRole("link")[0] as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe(`/ipam/addresses/192.0.2.41?vrf=${VRF}`);
  });
});

const DUID_LL = "00:03:00:01:00:00:5e:00:53:10";
const DUID_EN = "00:02:00:00:00:09:0c:0c:0c:0c:01";

describe("a DHCPv6 reservation", () => {
  it("is keyed by the DUID of the interface, with the scope, that it is served and the lease on the address", async () => {
    show([eth0({ duid: DUID_LL, mac: null })], [addr("2001:db8:0:10::100")]);
    await loaded();
    await settled("2001:db8:0:10::100");
    const row = rowOf("2001:db8:0:10::100");
    expect(row.dataset.state).toBe("served");
    expect(row.dataset.lease).toBe("active");
    expect(row.dataset.mismatch).toBeUndefined();
    expect(within(row).getByTestId("host-reservation-identity").dataset.kind).toBe("duid");
    expect(within(row).getByTestId("host-reservation-identity").textContent).toBe(`DUID ${DUID_LL}`);
    const scope = within(row).getByTestId("host-reservation-scope");
    expect(scope.textContent).toBe("2001:db8:0:10::/64");
    expect(scope.getAttribute("href")).toBe(`/dhcp/scopes/${DHCP_IDS.lanV6}`);
    expect(within(row).getByTestId("host-reservation-state-tag").textContent).toBe("Served");
    expect(within(row).getByTestId("host-reservation-lease-state").textContent).toBe("Active");
    expect(within(row).getByTestId("host-reservation-history").getAttribute("href")).toBe("/dhcp/history?addr=2001%3Adb8%3A0%3A10%3A%3A100");
  });

  it("prefers the DUID to the MAC address when the interface has both", async () => {
    show([eth0({ duid: DUID_LL, mac: OTHER_MAC })], [addr("2001:db8:0:10::100")]);
    await loaded();
    await settled("2001:db8:0:10::100");
    const row = rowOf("2001:db8:0:10::100");
    expect(within(row).getByTestId("host-reservation-identity").dataset.kind).toBe("duid");
    expect(row.dataset.mismatch).toBeUndefined();
  });

  it("is keyed by the MAC address when the interface has no DUID, and compares it with the link-layer address of the lease", async () => {
    show([eth0({ mac: docMac(0x12) })], [addr("2001:db8:0:10::102")]);
    await loaded();
    await settled("2001:db8:0:10::102");
    const row = rowOf("2001:db8:0:10::102");
    expect(row.dataset.state).toBe("served");
    expect(within(row).getByTestId("host-reservation-identity").dataset.kind).toBe("mac");
    expect(within(row).getByTestId("host-reservation-identity").textContent).toBe("MAC address 00:00:5e:00:53:12");
    expect(row.dataset.lease).toBe("active");
    expect(row.dataset.mismatch).toBeUndefined();
  });

  it("says an address on an interface with neither a DUID nor a MAC address has no reservation", async () => {
    show([eth0({ mac: null, duid: null })], [addr("2001:db8:0:10::100")]);
    await loaded();
    const row = rowOf("2001:db8:0:10::100");
    expect(row.dataset.state).toBe("no_identity");
    expect(row.dataset.lease).toBe("none");
    expect(within(row).getByTestId("host-reservation-identity").dataset.kind).toBe("none");
    expect(within(row).getByTestId("host-reservation-identity").textContent).toBe("No DUID or MAC address: no reservation");
  });

  it("warns when the lease is held by another DUID, and names it", async () => {
    // The lease at ::100 belongs to the client with the DUID-LL; the interface has another DUID.
    show([eth0({ duid: DUID_EN })], [addr("2001:db8:0:10::100")]);
    await loaded();
    await settled("2001:db8:0:10::100");
    const row = rowOf("2001:db8:0:10::100");
    expect(row.dataset.mismatch).toBe("true");
    expect(row.dataset.lease).toBe("active");
    expect(within(row).getByTestId("host-reservation-mismatch").textContent).toBe(`Held by another client: ${DUID_LL}`);
  });

  it("warns when a MAC-keyed reservation sits on a lease of another MAC address", async () => {
    show([eth0({ mac: OTHER_MAC })], [addr("2001:db8:0:10::100")]);
    await loaded();
    await settled("2001:db8:0:10::100");
    const row = rowOf("2001:db8:0:10::100");
    expect(row.dataset.mismatch).toBe("true");
    expect(within(row).getByTestId("host-reservation-mismatch").textContent).toBe("Held by another client: 00:00:5e:00:53:10");
  });

  it("does not warn about a lease whose client has no MAC address when the reservation is keyed by one", async () => {
    // The lease at ::101 has a DUID-EN: there is no link-layer address to compare.
    show([eth0({ mac: OTHER_MAC })], [addr("2001:db8:0:10::101")]);
    await loaded();
    await settled("2001:db8:0:10::101");
    expect(rowOf("2001:db8:0:10::101").dataset.lease).toBe("active");
    expect(rowOf("2001:db8:0:10::101").dataset.mismatch).toBeUndefined();
  });

  it("shows a lease that is not active by its state, without a warning", async () => {
    show([eth0({ duid: DUID_LL })], [addr("2001:db8:0:10::103")]);
    await loaded();
    await settled("2001:db8:0:10::103");
    const row = rowOf("2001:db8:0:10::103");
    expect(row.dataset.lease).toBe("expired");
    expect(row.dataset.mismatch).toBeUndefined();
  });

  it("says there is no lease yet at an address nobody holds", async () => {
    show([eth0({ duid: DUID_LL })], [addr("2001:db8:0:10::150")]);
    await loaded();
    await settled("2001:db8:0:10::150");
    expect(rowOf("2001:db8:0:10::150").dataset.lease).toBe("none");
  });

  it("says an IPv6 address outside every scope has none", async () => {
    show([eth0({ duid: DUID_LL })], [addr("2001:db8:0:99::5")]);
    await loaded();
    expect(rowOf("2001:db8:0:99::5").dataset.state).toBe("no_scope");
  });
});

describe("a reservation that is not served", () => {
  it("says an address in no scope has none, and offers the scopes to a writer", async () => {
    show([eth0()], [addr("198.51.100.7")]);
    await loaded();
    const row = rowOf("198.51.100.7");
    expect(row.dataset.state).toBe("no_scope");
    expect(row.dataset.lease).toBe("none");
    expect(row.textContent).toContain("No DHCP scope serves this network");
    expect(within(row).queryByTestId("host-reservation-scope")).toBeNull();
    expect(within(row).getByTestId("host-reservation-scopes").getAttribute("href")).toBe("/dhcp");
    expect(within(row).queryByTestId("host-reservation-history")).toBeNull();
  });

  it("offers a viewer no way to set up a scope", async () => {
    await signInWithRoles(["viewer"]);
    show([eth0()], [addr("198.51.100.7")]);
    await loaded();
    expect(rowOf("198.51.100.7").dataset.state).toBe("no_scope");
    expect(screen.queryByTestId("host-reservation-scopes")).toBeNull();
  });

  it("says an interface without MAC address or client identifier gets no reservation", async () => {
    show([eth0({ mac: null })], [addr("192.0.2.41")]);
    await loaded();
    const row = rowOf("192.0.2.41");
    expect(row.dataset.state).toBe("no_identity");
    expect(row.dataset.lease).toBe("none");
    expect(within(row).getByTestId("host-reservation-identity").textContent).toBe("No MAC address or client identifier: no reservation");
    expect(within(row).queryByTestId("host-reservation-scope")).not.toBeNull();
  });

  it("says a disabled scope does not serve the reservation, and still shows its lease", async () => {
    grantMockLease({ mac: MAC, addr: "192.0.2.41" });
    const scope = dhcpState().scopes.find((s) => s.prefix === DHCP_IDS.lan);
    if (scope) scope.enabled = false;
    show([eth0()], [addr("192.0.2.41")]);
    await loaded();
    await settled("192.0.2.41");
    const row = rowOf("192.0.2.41");
    expect(row.dataset.state).toBe("scope_disabled");
    expect(within(row).getByTestId("host-reservation-state-tag").textContent).toBe("The scope is disabled");
    expect(row.dataset.lease).toBe("active");
  });

  it("says so when the dhcp role does not run on this server", async () => {
    server.use(http.get("/api/v1/nodes/:id/dhcp", () => problem(409, "dhcp.node.not_dhcp")));
    show([eth0()], [addr("192.0.2.41")]);
    await loaded();
    await settled("192.0.2.41");
    const row = rowOf("192.0.2.41");
    expect(row.dataset.state).toBe("not_serving");
    expect(within(row).getByTestId("host-reservation-state-tag").textContent).toBe("The dhcp role does not run on this server");
  });

  it("counts a role that does not serve like one that does not run", async () => {
    server.use(http.get("/api/v1/nodes/:id/dhcp", () => HttpResponse.json({ accepting: true, leases: [], listeners: [], node: 1, probe: false, revision: 1, scopes: 0, serving: false })));
    show([eth0()], [addr("192.0.2.41")]);
    await loaded();
    expect(rowOf("192.0.2.41").dataset.state).toBe("not_serving");
  });

  it("keeps the lease out of sight of a row that has no reservation", async () => {
    // The address has a lease, but without an identity there is no reservation to compare it with.
    grantMockLease({ mac: docMac(1), addr: "192.0.2.41" });
    show([eth0({ mac: null })], [addr("192.0.2.41")]);
    await loaded();
    expect(rowOf("192.0.2.41").dataset.lease).toBe("none");
  });

  it("says a host without addresses has nothing to reserve", async () => {
    show([eth0()], []);
    await screen.findByTestId("host-reservations");
    expect(await screen.findByTestId("host-reservations-empty")).toBeTruthy();
    expect(screen.getByTestId("host-reservations").dataset.count).toBe("0");
  });
});

describe("where DHCP is not there", () => {
  it("hides itself when the module is switched off", async () => {
    dhcpSwitchedOff();
    show([eth0()], [addr("192.0.2.41")]);
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(screen.queryByTestId("host-reservations")).toBeNull();
  });

  it("hides itself when the server runs no configuration service", async () => {
    dhcpNoService();
    show([eth0()], [addr("192.0.2.41")]);
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(screen.queryByTestId("host-reservations")).toBeNull();
  });

  it("shows nothing to a principal who may not read DHCP", async () => {
    server.use(http.get("/api/v1/dhcp/*", () => problem(403, "auth.forbidden")), http.get("/api/v1/nodes/:id/dhcp", () => problem(403, "auth.forbidden")));
    show([eth0()], [addr("192.0.2.41")]);
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(screen.queryByTestId("host-reservations")).toBeNull();
  });

  it("hides itself when a lease read is refused", async () => {
    server.use(http.get("/api/v1/dhcp/leases/:addr", () => problem(403, "auth.forbidden")));
    show([eth0()], [addr("192.0.2.41")]);
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(screen.queryByTestId("host-reservations")).toBeNull();
  });

  it("says a lease that cannot be read, row by row, and keeps the block", async () => {
    server.use(http.get("/api/v1/dhcp/leases/:addr", () => problem(500, "sys.internal")));
    show([eth0()], [addr("192.0.2.41")]);
    await loaded();
    await settled("192.0.2.41");
    expect(rowOf("192.0.2.41").dataset.lease).toBe("unknown");
    expect(screen.getByTestId("host-reservation-lease-failed").textContent).toBe("The lease could not be read.");
  });
});

describe("the words", () => {
  it("speaks Swedish", async () => {
    await setLocale("sv");
    show([eth0()], [addr("192.0.2.41")]);
    await loaded();
    await settled("192.0.2.41");
    expect(screen.getByRole("heading", { name: "DHCP-reservationer" })).toBeTruthy();
    expect(within(rowOf("192.0.2.41")).getByTestId("host-reservation-state-tag").textContent).toBe("Betjänas");
    expect(within(rowOf("192.0.2.41")).getByTestId("host-reservation-no-lease").textContent).toBe("Inget lån ännu: klienten har inte frågat sedan reservationen fanns");
  });
});
