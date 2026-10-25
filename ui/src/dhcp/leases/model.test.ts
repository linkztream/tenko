// The readers and filters of the lease and history views, for both address families (WP9.4): the
// MAC address of a lease without a client key, DUIDs as text, the kind and the shown address of a
// lease, the link to the peer, the filters in the URL and in the query.
import { describe, expect, it } from "vitest";
import {
  anyFilter,
  clientIdOf,
  clientMac,
  colons,
  displayAddr,
  duidProblem,
  familyName,
  historyQuery,
  holderOf,
  kindOf,
  leaseQuery,
  macOf,
  nameOf,
  peerHref,
  readHistoryFilters,
  readLeaseFilters,
  shortDuid,
} from "./model";

describe("the client of a lease", () => {
  const client = { htype: 1, chaddr: "00005e005310", client_id: "0100005e005310" };

  it("takes the MAC address the server names, else the hardware address of a DHCPv4 client", () => {
    expect(clientMac({ mac: "00:00:5E:00:53:10" })).toBe("00:00:5e:00:53:10");
    expect(clientMac({ client })).toBe("00:00:5e:00:53:10");
    expect(clientMac({ mac: "00:00:5e:00:53:11", client })).toBe("00:00:5e:00:53:11");
    expect(clientMac({})).toBe("");
    expect(clientMac({ mac: null, client: null })).toBe("");
  });

  it("reads a client key that is not there as nothing", () => {
    expect(macOf(client)).toBe("00:00:5e:00:53:10");
    expect(macOf(undefined)).toBe("");
    expect(macOf(null)).toBe("");
    expect(clientIdOf(client)).toBe("01:00:00:5e:00:53:10");
    expect(clientIdOf(undefined)).toBeUndefined();
    expect(clientIdOf({ htype: 1, chaddr: "00005e005310" })).toBeUndefined();
  });

  it("names the holder by the MAC address, else the DUID", () => {
    expect(holderOf({ mac: "00:00:5e:00:53:10", duid: "0003000100005e005310" })).toBe("00:00:5e:00:53:10");
    expect(holderOf({ duid: "0002000000090c0c0c0c01" })).toBe("00:02:00:00:00:09:0c:0c:0c:0c:01");
    expect(holderOf({ client })).toBe("00:00:5e:00:53:10");
    expect(holderOf({})).toBe("");
  });
});

describe("DUIDs as text", () => {
  it("writes the octets with colons", () => {
    expect(colons("0003000100005E005310")).toBe("00:03:00:01:00:00:5e:00:53:10");
  });

  it("shows up to twelve octets in full and cuts a longer one in the middle", () => {
    expect(shortDuid("0003000100005e005310")).toBe("00:03:00:01:00:00:5e:00:53:10");
    expect(shortDuid("000100012d9c8a4f00005e005312")).toBe("00:01:00:01:2d:9c…5e:00:53:12");
    expect(shortDuid("000400112233445566778899")).toBe("00:04:00:11:22:33:44:55:66:77:88:99");
    expect(shortDuid("")).toBe("");
  });

  it("says a text is no DUID unless it is hexadecimal digits in pairs with separators between", () => {
    for (const ok of ["", "  ", "00:03:00:01", "0003-0001", "00 03 00 01", "0003000100005E005310", "00.03.00.01"]) expect(duidProblem(ok)).toBe(false);
    for (const bad of ["xyz", "000", "00:03:0", "00:03:zz", "00_03"]) expect(duidProblem(bad)).toBe(true);
  });
});

describe("what a lease holds", () => {
  it("is an address for DHCPv4 and for na, a prefix for pd", () => {
    expect(kindOf({})).toBe("address");
    expect(kindOf({ kind: null })).toBe("address");
    expect(kindOf({ kind: "na" })).toBe("address");
    expect(kindOf({ kind: "pd" })).toBe("prefix");
  });

  it("shows a delegated prefix with its length", () => {
    expect(displayAddr({ addr: "192.0.2.100" })).toBe("192.0.2.100");
    expect(displayAddr({ addr: "2001:db8::100", kind: "na", prefix_len: 128 })).toBe("2001:db8::100");
    expect(displayAddr({ addr: "2001:db8:1::", kind: "pd", prefix_len: 56 })).toBe("2001:db8:1::/56");
    expect(displayAddr({ addr: "2001:db8:1::", kind: "pd" })).toBe("2001:db8:1::");
  });

  it("names a DHCPv6 lease by its FQDN", () => {
    expect(nameOf({ fqdn: "pc-1.example.net" })).toEqual({ name: "pc-1.example.net", extra: "" });
    expect(nameOf({ fqdn: "host-1.example.test", hostname: "host-1" })).toEqual({ name: "host-1.example.test", extra: "host-1" });
    expect(nameOf({})).toEqual({ name: "", extra: "" });
  });

  it("names the families as the protocols are written", () => {
    expect(familyName("v4")).toBe("DHCPv4");
    expect(familyName("v6")).toBe("DHCPv6");
  });
});

describe("the link to the lease of the other family", () => {
  it("narrows the list to the address of the peer", () => {
    const url = new URL(peerHref({ addr: "2001:db8:0:10::100" }), "http://localhost");
    expect(url.pathname).toBe("/dhcp/leases");
    expect(url.searchParams.get("addr")).toBe("2001:db8:0:10::100");
    expect([...url.searchParams.keys()]).toEqual(["addr"]);
    expect(new URL(peerHref({ addr: "192.0.2.100" }), "http://localhost").searchParams.get("addr")).toBe("192.0.2.100");
  });
});

describe("the filters of the lease list", () => {
  it("reads the family and the DUID from the URL, and a family that is none as both", () => {
    expect(readLeaseFilters({ family: "v6", duid: "0003" })).toMatchObject({ family: "v6", duid: "0003" });
    expect(readLeaseFilters({ family: "v4" }).family).toBe("v4");
    expect(readLeaseFilters({ family: "v5" }).family).toBe("");
    expect(readLeaseFilters({ family: ["v6", "v4"] }).family).toBe("v6");
    expect(readLeaseFilters({}).family).toBe("");
    expect(anyFilter(readLeaseFilters({ family: "v6" }))).toBe(true);
    expect(anyFilter(readLeaseFilters({ family: "v5" }))).toBe(false);
  });

  it("sends only the filters that are set", () => {
    expect(leaseQuery(readLeaseFilters({}))).toEqual({
      scope: undefined,
      addr: undefined,
      mac: undefined,
      duid: undefined,
      name: undefined,
      state: undefined,
      family: undefined,
    });
    const query = leaseQuery(readLeaseFilters({ family: "v6", duid: " 00:03:00:01 ", mac: "00-00-5E-00-53-10", addr: "2001:db8:" }));
    expect(query).toMatchObject({ family: "v6", duid: "00:03:00:01", mac: "00:00:5e:00:53:10", addr: "2001:db8:" });
  });
});

describe("the filters of the history", () => {
  it("reads and sends the family and the DUID too", () => {
    const filters = readHistoryFilters({ family: "v6", duid: "0003000100005e005310", addr: "2001:db8:0:10::100" });
    expect(filters).toMatchObject({ family: "v6", duid: "0003000100005e005310", addr: "2001:db8:0:10::100" });
    expect(historyQuery(filters)).toMatchObject({ family: "v6", duid: "0003000100005e005310", addr: "2001:db8:0:10::100" });
    expect(historyQuery(readHistoryFilters({})).family).toBeUndefined();
    expect(readHistoryFilters({ family: "both" }).family).toBe("");
  });
});
