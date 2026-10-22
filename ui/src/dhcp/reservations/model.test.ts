import { describe, expect, it } from "vitest";
import type { Address, Interface } from "../../api/types";
import type { Scope } from "../types";
import { hasLeaseToRead, hexDigits, identityOf, reservationRows, sameClient, scopeFor, stateOf } from "./model";

const VRF = "0190d1c2-0000-7000-8000-000000000001";
const OTHER_VRF = "0190d1c2-0000-7000-8000-000000000002";
const META = { revision: 1, tags: [], custom: {} };

const iface = (id: string, extra: Partial<Interface> = {}, deleted = false): Interface =>
  ({ id, host: "h", name: id, meta: { ...META, ...(deleted ? { deleted: { at: "2025-01-01T00:00:00Z" } } : {}) }, ...extra }) as unknown as Interface;
const address = (ip: string, interfaceId: string | null, extra: Partial<Address> = {}, deleted = false): Address =>
  ({ id: `a-${ip}`, ip, vrf: VRF, status: "active", interface: interfaceId, prefix: "p", meta: { ...META, ...(deleted ? { deleted: { at: "2025-01-01T00:00:00Z" } } : {}) }, ...extra }) as unknown as Address;
const scope = (prefix: string, cidr: string, extra: Partial<Scope> = {}): Scope => ({ prefix, cidr, vrf: VRF, enabled: true, ...extra }) as unknown as Scope;

const LAN = scope("lan", "192.0.2.0/24");
const MAC = "00:00:5e:00:53:29";

describe("the identity of an interface", () => {
  it("prefers the client identifier to the MAC address", () => {
    expect(identityOf({ client_id: "01:00:00:5e:00:53:29", mac: MAC })).toEqual({ kind: "client_id", value: "01:00:00:5e:00:53:29" });
    expect(identityOf({ mac: MAC })).toEqual({ kind: "mac", value: MAC });
    expect(identityOf({ client_id: null, mac: MAC })).toEqual({ kind: "mac", value: MAC });
    expect(identityOf({ client_id: "", mac: "" })).toBeUndefined();
    expect(identityOf({})).toBeUndefined();
  });

  it("reads hexadecimal with or without separators", () => {
    expect(hexDigits("00:00:5E:00:53:29")).toBe("00005e005329");
    expect(hexDigits("00005e005329")).toBe("00005e005329");
  });
});

describe("the scope of an address", () => {
  it("takes the most specific network of the same VRF that contains the address", () => {
    const wide = scope("wide", "192.0.0.0/16");
    expect(scopeFor({ ip: "192.0.2.41", vrf: VRF }, [wide, LAN])?.prefix).toBe("lan");
    expect(scopeFor({ ip: "192.0.9.1", vrf: VRF }, [wide, LAN])?.prefix).toBe("wide");
    expect(scopeFor({ ip: "198.51.100.5", vrf: VRF }, [wide, LAN])).toBeUndefined();
    expect(scopeFor({ ip: "192.0.2.41", vrf: OTHER_VRF }, [LAN])).toBeUndefined();
    expect(scopeFor({ ip: "not an address", vrf: VRF }, [LAN])).toBeUndefined();
  });
});

describe("the state of a reservation", () => {
  const identity = { kind: "mac", value: MAC } as const;
  it("asks for the identity first, then the scope, then the scope's switch, then the role", () => {
    expect(stateOf(undefined, undefined, false)).toBe("no_identity");
    expect(stateOf(undefined, LAN, true)).toBe("no_identity");
    expect(stateOf(identity, undefined, true)).toBe("no_scope");
    expect(stateOf(identity, scope("lan", "192.0.2.0/24", { enabled: false }), true)).toBe("scope_disabled");
    expect(stateOf(identity, LAN, false)).toBe("not_serving");
    expect(stateOf(identity, LAN, true)).toBe("served");
  });

  it("reads leases only where a reservation is made", () => {
    expect(["served", "scope_disabled", "not_serving"].every((s) => hasLeaseToRead(s as never))).toBe(true);
    expect(hasLeaseToRead("no_scope")).toBe(false);
    expect(hasLeaseToRead("no_identity")).toBe(false);
  });
});

describe("the rows of a host", () => {
  const eth0 = iface("eth0", { mac: MAC });
  it("has one row per live IPv4 address of status active or planned on a live interface, by address", () => {
    const { rows, ipv6 } = reservationRows(
      [eth0, iface("eth1", { mac: "00:00:5e:00:53:2a" }, true), iface("eth2")],
      [
        address("192.0.2.50", "eth0", { status: "planned" }),
        address("192.0.2.41", "eth0"),
        address("192.0.2.42", "eth0", { status: "deprecated" }),
        address("192.0.2.43", "eth0", { status: "reserved" }),
        address("192.0.2.44", "eth0", {}, true),
        address("192.0.2.45", "eth1"),
        address("192.0.2.46", null),
        address("192.0.2.47", "eth2"),
        address("2001:db8:0:10::41", "eth0"),
        address("2001:db8:0:10::42", "eth0"),
      ],
      [LAN],
      true,
    );
    expect(rows.map((r) => [r.address.ip, r.state])).toEqual([
      ["192.0.2.41", "served"],
      ["192.0.2.47", "no_identity"],
      ["192.0.2.50", "served"],
    ]);
    expect(ipv6).toBe(2);
  });

  it("keys the reservation by the client identifier when the interface has one", () => {
    const { rows } = reservationRows([iface("eth0", { mac: MAC, client_id: "010203" })], [address("192.0.2.41", "eth0")], [LAN], true);
    expect(rows[0]?.identity).toEqual({ kind: "client_id", value: "010203" });
  });

  it("marks an address outside every scope and a disabled scope", () => {
    const off = scope("off", "198.51.100.0/24", { enabled: false });
    const { rows } = reservationRows([eth0], [address("192.0.2.41", "eth0"), address("198.51.100.7", "eth0"), address("203.0.113.9", "eth0")], [LAN, off], false);
    expect(rows.map((r) => [r.address.ip, r.state])).toEqual([
      ["192.0.2.41", "not_serving"],
      ["198.51.100.7", "scope_disabled"],
      ["203.0.113.9", "no_scope"],
    ]);
  });
});

describe("whether the lease is held by the client of the reservation", () => {
  const client = (chaddr: string, client_id?: string) => ({ htype: 1, chaddr, ...(client_id ? { client_id } : {}) });
  it("compares the MAC address of a reservation with the hardware address of the lease", () => {
    const identity = { kind: "mac", value: MAC } as const;
    expect(sameClient(identity, { mac: MAC }, client("00005e005329"))).toBe(true);
    expect(sameClient(identity, { mac: MAC }, client("00005e00532b"))).toBe(false);
  });

  it("compares the client identifier when both sides have one", () => {
    const identity = { kind: "client_id", value: "01:00:00:5e:00:53:29" } as const;
    expect(sameClient(identity, { mac: MAC, client_id: identity.value }, client("00005e00532b", "0100005e005329"))).toBe(true);
    expect(sameClient(identity, { mac: MAC, client_id: identity.value }, client("00005e005329", "0100005e00532b"))).toBe(false);
    // A lease without a client identifier is compared by the interface's MAC address.
    expect(sameClient(identity, { mac: MAC, client_id: identity.value }, client("00005e005329"))).toBe(true);
    expect(sameClient(identity, { mac: MAC, client_id: identity.value }, client("00005e00532b"))).toBe(false);
  });

  it("does not warn when there is nothing to compare", () => {
    expect(sameClient({ kind: "client_id", value: "0102" }, {}, client("00005e00532b"))).toBe(true);
  });
});
