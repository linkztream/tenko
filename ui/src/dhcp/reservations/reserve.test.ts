// The pure part of the reserve dialog: the prefill, the checks, the request and the sentences.
import { describe, expect, it } from "vitest";
import {
  draftProblems,
  identity,
  macPrefill,
  namePrefill,
  poolOf,
  preview,
  reserveRequest,
  statusChoices,
  statusPrefill,
  type ReserveContext,
  type ReserveDraft,
} from "./reserve";

const ctx = (extra: Partial<ReserveContext> = {}): ReserveContext => ({
  address: { id: "a1", ip: "192.0.2.30", vrf: "v1", status: "active", interface: "i1" },
  vrf: "v1",
  hosts: [{ id: "h1", name: "printer-1", mode: "static" }],
  interfaces: [{ id: "i1", name: "eth0", mac: "02:00:5e:10:00:01", client_id: null }],
  scope: { cidr: "192.0.2.0/24", enabled: true },
  serving: true,
  ...extra,
});

const draft = (extra: Partial<ReserveDraft> = {}): ReserveDraft => ({
  ip: "192.0.2.30",
  host: "h1",
  newHost: "",
  iface: "i1",
  newInterface: "eth0",
  mac: "02:00:5e:10:00:01",
  clientId: "",
  status: "active",
  ...extra,
});

const keys = (d: ReserveDraft, c: ReserveContext) => preview(d, c).map((s) => s.key);

describe("the prefill", () => {
  it("takes the MAC address of the interface, else of the lease, else the observed one", () => {
    expect(macPrefill({ interfaceMac: "02:00:5E:10:00:01", leaseMac: "02:00:5e:10:00:02" })).toBe("02:00:5e:10:00:01");
    expect(macPrefill({ interfaceMac: null, leaseMac: "02-00-5e-10-00-02", observedMac: "02:00:5e:10:00:03" })).toBe("02:00:5e:10:00:02");
    expect(macPrefill({ observedMac: "02:00:5e:10:00:03" })).toBe("02:00:5e:10:00:03");
    expect(macPrefill({})).toBe("");
  });

  it("names a new host after the first label of the DNS name, else the lease's host name, else the observed name", () => {
    expect(namePrefill({ dnsName: "Scanner.example.test", leaseHostname: "other" })).toBe("scanner");
    expect(namePrefill({ leaseHostname: "Living Room TV" })).toBe("living-room-tv");
    expect(namePrefill({ observedName: "cam_door.example.test" })).toBe("cam-door");
    expect(namePrefill({})).toBe("");
  });

  it("keeps an active or planned status and offers planned only where IPAM allows it", () => {
    expect(statusPrefill("planned")).toBe("planned");
    expect(statusPrefill("reserved")).toBe("active");
    expect(statusPrefill(undefined)).toBe("active");
    expect(statusChoices("active")).toEqual(["active"]);
    expect(statusChoices("planned")).toEqual(["active", "planned"]);
    expect(statusChoices(undefined)).toEqual(["active", "planned"]);
  });

  it("finds the pool an address lies in", () => {
    const pools = [{ first: "192.0.2.100", last: "192.0.2.199" }];
    expect(poolOf("192.0.2.150", pools)).toEqual(pools[0]);
    expect(poolOf("192.0.2.99", pools)).toBeUndefined();
    expect(poolOf("2001:db8::1", pools)).toBeUndefined();
  });
});

describe("the checks", () => {
  it("needs a MAC address or a client identifier", () => {
    const c = ctx({ interfaces: [{ id: "i1", name: "eth0", mac: null, client_id: null }] });
    expect(draftProblems(draft({ mac: "" }), c)).toEqual({ identity: "dhcp.reserve.check.identity" });
    expect(draftProblems(draft({ mac: "", clientId: "01:02" }), c)).toEqual({});
  });

  it("refuses a malformed MAC address, client identifier, host name and address", () => {
    expect(draftProblems(draft({ mac: "02:00" }), ctx()).mac).toBe("dhcp.reserve.check.mac");
    expect(draftProblems(draft({ clientId: "xyz" }), ctx()).client_id).toBe("dhcp.reserve.check.client_id");
    expect(draftProblems(draft({ host: "new", newHost: "living room" }), ctx()).host_name).toBe("dhcp.reserve.check.host_name");
    expect(draftProblems(draft({ ip: "nope" }), ctx({ address: undefined })).ip).toBe("dhcp.reserve.check.ip");
  });

  it("keys the reservation by the client identifier when there is one", () => {
    expect(identity(draft(), ctx())).toEqual({ kind: "mac", value: "02:00:5e:10:00:01" });
    expect(identity(draft({ clientId: "0102005e100001" }), ctx())).toEqual({ kind: "client_id", value: "01:02:00:5e:10:00:01" });
  });
});

describe("the request", () => {
  it("names the existing host and interface of an IPAM address", () => {
    expect(reserveRequest(draft(), ctx())).toEqual({
      address: "a1",
      body: { host: "h1", interface: "i1", mac: "02:00:5e:10:00:01", status: "active" },
    });
  });

  it("names the address by value when IPAM does not hold it, with a new host and interface", () => {
    const d = draft({ ip: "192.0.2.21", host: "new", newHost: "laptop", iface: "new", newInterface: "wlan0", clientId: "01:02" });
    expect(reserveRequest(d, ctx({ address: undefined, interfaces: [] }))).toEqual({
      body: { ip: "192.0.2.21", vrf: "v1", new_host: "laptop", new_interface: "wlan0", mac: "02:00:5e:10:00:01", client_id: "0102", status: "active" },
    });
  });

  it("clears the interface's client identifier when the field is emptied", () => {
    const c = ctx({ interfaces: [{ id: "i1", name: "eth0", mac: "02:00:5e:10:00:01", client_id: "0102" }] });
    expect(reserveRequest(draft(), c).body.client_id).toBeNull();
  });
});

describe("the sentences", () => {
  it("say that a static host becomes reserved and what stays", () => {
    expect(keys(draft(), ctx())).toEqual([
      "dhcp.reserve.will.host_mode",
      "dhcp.reserve.will.interface_mac_kept",
      "dhcp.reserve.will.address_kept",
      "dhcp.reserve.will.keyed_mac",
      "dhcp.reserve.will.scope_served",
    ]);
  });

  it("say that nothing changes when the reservation is in place", () => {
    const c = ctx({ hosts: [{ id: "h1", name: "printer-1", mode: "reserved" }] });
    expect(keys(draft(), c)[0]).toBe("dhcp.reserve.will.nothing");
  });

  it("say that a MAC address is replaced, the address moves and the scope is disabled", () => {
    const c = ctx({ address: { id: "a1", ip: "192.0.2.30", vrf: "v1", status: "planned", interface: null }, scope: { cidr: "192.0.2.0/24", enabled: false } });
    const sentences = preview(draft({ mac: "02:00:5e:10:00:09", status: "active" }), c);
    expect(sentences.map((s) => s.key)).toEqual([
      "dhcp.reserve.will.host_mode",
      "dhcp.reserve.will.interface_mac_replaced",
      "dhcp.reserve.will.address_bound",
      "dhcp.reserve.will.address_status",
      "dhcp.reserve.will.keyed_mac",
      "dhcp.reserve.will.scope_disabled",
    ]);
    expect(sentences[1]?.args).toEqual({ name: "eth0", mac: "02:00:5e:10:00:09", old: "02:00:5e:10:00:01" });
  });

  it("warn when another client holds the lease on the address", () => {
    expect(keys(draft(), ctx({ leaseMac: "02:00:5e:10:00:77" }))).toContain("dhcp.reserve.will.lease_other");
    expect(keys(draft(), ctx({ leaseMac: "02:00:5e:10:00:01", serving: false }))).toEqual(expect.arrayContaining(["dhcp.reserve.will.not_serving"]));
  });
});
