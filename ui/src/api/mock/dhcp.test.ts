// The mock DHCP service: the pure model without msw (seed, settings, scopes with pools and
// utilization, exclusions, shared networks, the option catalog, definitions and option sets with
// the wire encoding and the effective merge, classes, policies, MAC filters) and the routes over
// it (ETag and If-Match, the module switch, the scope of the caller, the audit records).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api } from "../client";
import { ApiError } from "../problem";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { audit } from "./audit-store";
import {
  DHCP_IDS,
  DhcpFailure,
  catalog,
  createClass,
  createExclusion,
  createFilter,
  createOptionDef,
  createPolicy,
  createScope,
  createSharedNetwork,
  decodeData,
  deleteClass,
  deleteOptionDef,
  deleteScope,
  deleteSharedNetwork,
  effectiveOptions,
  encodeData,
  getOptionSet,
  listExclusions,
  listPools,
  listScopes,
  putOptionSet,
  putSettings,
  seedDhcp,
  setPool,
  updateFilter,
  updateOptionDef,
  updatePolicy,
  updateScope,
  utilization,
  type DhcpContext,
  type DhcpState,
} from "./dhcp-model";
import { dhcpState } from "./routes-dhcp";
import { mockUpdates } from "./routes-updates";
import type { Term } from "../../dhcp/types";

const NOW = Date.UTC(2026, 9, 17, 12);
const IOT_V6 = "0190d1c2-0000-7000-8000-0000000a0009";
const POOL = DHCP_IDS.lanPool;
const SUPERNET = "0190d1c2-0000-7000-8000-0000000a00f1";
const WIFI = "0190d1c2-0000-7000-8000-0000000a00f2";
const V6_POOL = DHCP_IDS.lanV6Pool;

let rev = 0;
let ids = 0;
let state: DhcpState;
let ctx: DhcpContext;

/** A small IPAM: the LAN with a pool, the IoT network, a supernet and a Wi-Fi network. */
const NETWORKS: Record<string, { cidr: string; role: "network" | "supernet" }> = {
  [DHCP_IDS.lan]: { cidr: "192.0.2.0/24", role: "network" },
  [DHCP_IDS.iot]: { cidr: "198.51.100.0/24", role: "network" },
  [SUPERNET]: { cidr: "203.0.113.0/24", role: "supernet" },
  [WIFI]: { cidr: "203.0.113.0/25", role: "network" },
  [DHCP_IDS.lanV6]: { cidr: "2001:db8:0:10::/64", role: "network" },
  [IOT_V6]: { cidr: "2001:db8:0:30::/64", role: "network" },
};

beforeEach(() => {
  rev = 0;
  ids = 0;
  ctx = {
    now: () => NOW,
    nextRevision: () => ++rev,
    principal: () => ({ kind: "system", component: "api" }) as ReturnType<DhcpContext["principal"]>,
    newId: () => `0190d1c2-0000-7000-8000-${String(++ids).padStart(12, "0")}`,
    ipam: {
      prefix: (id) => (NETWORKS[id] ? { id, vrf: "vrf", ...(NETWORKS[id] as { cidr: string; role: "network" | "supernet" }) } : undefined),
      pools: (prefix) =>
        prefix === DHCP_IDS.lan
          ? [{ id: POOL, first: "192.0.2.100", last: "192.0.2.199", lease_secs: 86_400 }]
          : prefix === DHCP_IDS.lanV6
            ? [{ id: V6_POOL, first: "2001:db8:0:10::100", last: "2001:db8:0:10::1ff" }]
            : prefix === IOT_V6
              ? [{ id: "range-wide", first: "2001:db8:0:30::", last: "2001:db8:0:30:ffff:ffff:ffff:ffff" }]
              : [],
      range: (id) => (id === POOL ? { id, prefix: DHCP_IDS.lan, role: "dhcp_pool" } : id === "range-reserved" ? { id, prefix: DHCP_IDS.lan, role: "reserved" } : undefined),
      reservation: (mac) => (mac === "00:00:5e:00:53:04" ? "0190d1c2-0000-7000-8000-000000000999" : undefined),
    },
  };
  state = seedDhcp(ctx);
});

/** Runs `fn`, expects it to fail with a DhcpFailure and returns the failure. */
function failure(fn: () => unknown): DhcpFailure {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(DhcpFailure);
    return error as DhcpFailure;
  }
  throw new Error("expected a DhcpFailure");
}

const LEASE = { default_secs: 7200, min_secs: 600, max_secs: 86_400 };

describe("seedDhcp", () => {
  it("makes one scope on the LAN with a pool, an exclusion, options, a class, a policy and a filter", () => {
    expect(listScopes(state, ctx).map((s) => [s.cidr, s.family, s.pools, s.leases])).toEqual([
      ["192.0.2.0/24", "v4", 1, 12],
      ["2001:db8:0:10::/64", "v6", 1, 3],
    ]);
    // WP9.4: the DHCPv6 scope has rapid commit set and the DNS servers and the search list as dhcp6 options.
    expect(listScopes(state, ctx)[1]).toMatchObject({ v6: { rapid_commit: true }, description: "House LAN, IPv6" });
    expect(getOptionSet(state, ctx, `scope:${DHCP_IDS.lanV6}`).values.map((v) => [v.space, v.code, v.name, v.typed])).toEqual([
      ["dhcp6", 23, "dns-servers", { ipv6: { values: ["2001:db8:0:10::53"] } }],
      ["dhcp6", 24, "domain-search", { names: ["example.net"] }],
    ]);
    expect(listExclusions(state, DHCP_IDS.lan).map((e) => [e.first, e.last])).toEqual([["192.0.2.150", "192.0.2.159"]]);
    expect(getOptionSet(state, ctx, "server").values.map((v) => [v.code, v.name])).toEqual([
      [6, "domain-name-servers"],
      [15, "domain-name"],
    ]);
    expect(state.classes.map((c) => c.name)).toEqual(["pxe-clients"]);
    expect(state.policies.map((p) => p.name)).toEqual(["pxe-boot"]);
    expect(state.filters.map((f) => f.mac)).toEqual(["00:00:5e:00:53:*"]);
  });
});

describe("settings", () => {
  it("is saved with the revision read and shows the value in force for the unset ones", () => {
    const before = state.settings.revision;
    const saved = putSettings(state, ctx, { lease: LEASE, authoritative: false, history_days: 14 }, before);
    expect(saved.lease).toEqual(LEASE);
    expect(saved.authoritative).toBe(false);
    expect([saved.history_days, saved.effective_history_days]).toEqual([14, 14]);
    expect([saved.conflict_detection, saved.effective_conflict_detection]).toEqual([undefined, true]);
    expect(failure(() => putSettings(state, ctx, { lease: LEASE }, before)).status).toBe(412);
  });

  it("refuses lease times out of order and a history of 0 days", () => {
    const wrong = failure(() => putSettings(state, ctx, { lease: { default_secs: 100, min_secs: 600, max_secs: 700 } }, "*"));
    expect([wrong.code, wrong.params.field]).toEqual(["dhcp.lease_times.invalid", "lease.default_secs"]);
    expect(failure(() => putSettings(state, ctx, { lease: LEASE, history_days: 0 }, "*")).code).toBe("dhcp.settings.invalid");
    expect(failure(() => putSettings(state, ctx, { lease: { ...LEASE, max_secs: 40_000_000 } }, "*")).params.field).toBe("lease.max_secs");
  });
});

describe("scopes", () => {
  it("creates a scope for a network, with the server's settings for what is left out", () => {
    const scope = createScope(state, ctx, { prefix: DHCP_IDS.iot, description: "IoT" });
    expect([scope.cidr, scope.enabled, scope.lease, scope.restricted, scope.pools]).toEqual(["198.51.100.0/24", true, undefined, false, 0]);
  });

  it("refuses a supernet, a network that has a scope and a prefix that does not exist", () => {
    expect(failure(() => createScope(state, ctx, { prefix: SUPERNET })).code).toBe("dhcp.scope.not_network");
    expect(failure(() => createScope(state, ctx, { prefix: DHCP_IDS.lan })).code).toBe("dhcp.scope.exists");
    expect(failure(() => createScope(state, ctx, { prefix: "0190d1c2-0000-7000-8000-0000000a00ff" })).status).toBe(404);
  });

  it("changes what the patch names, takes back the lease times and leaves the shared network with the nil id", () => {
    const scope = listScopes(state, ctx)[0]!;
    const patched = updateScope(state, ctx, scope.prefix, { enabled: false, lease: LEASE, shared_network: DHCP_IDS.sharedNetwork, description: "Changed" }, scope.revision);
    expect([patched.enabled, patched.lease, patched.shared_network, patched.description]).toEqual([false, LEASE, DHCP_IDS.sharedNetwork, "Changed"]);
    expect(failure(() => updateScope(state, ctx, scope.prefix, { enabled: true }, scope.revision)).status).toBe(412);
    const back = updateScope(state, ctx, scope.prefix, { clear_lease: true, shared_network: "00000000-0000-0000-0000-000000000000", description: "" }, patched.revision);
    expect([back.lease, back.shared_network, back.description]).toEqual([undefined, undefined, undefined]);
  });

  it("checks the server identifier and the classes", () => {
    expect(failure(() => updateScope(state, ctx, DHCP_IDS.lan, { server_id: "not an address" }, "*")).code).toBe("dhcp.scope.invalid");
    expect(failure(() => updateScope(state, ctx, DHCP_IDS.lan, { classes: ["0190d1c2-0000-7000-8000-0000000000ff"] }, "*")).code).toBe("dhcp.class.not_found");
  });

  it("deletes the scope with its exclusions, pool settings, policies and options", () => {
    setPool(state, ctx, POOL, { classes: [DHCP_IDS.class] }, 0);
    putOptionSet(state, ctx, `pool:${POOL}`, { values: [{ code: 3, typed: { ipv4: { values: ["192.0.2.1"] } } }] }, 0);
    deleteScope(state, ctx, DHCP_IDS.lan, "*");
    // The DHCPv6 scope of the seed and its options stay.
    expect([state.scopes, state.exclusions, state.pools, state.policies].map((x) => x.length)).toEqual([1, 0, 0, 0]);
    expect([...state.optionSets.keys()].sort()).toEqual([`scope:${DHCP_IDS.lanV6}`, "server"]);
    expect(state.classes).toHaveLength(1);
  });

  it("counts the pool without the exclusions in the utilization", () => {
    const u = utilization(state, ctx, DHCP_IDS.lan);
    // 100 addresses, the exclusion 192.0.2.150 to 159 is not inside the pool 100 to 199 as a whole: it takes 10.
    expect([u.pool_size, u.leased, u.free, u.reserved, u.abandoned]).toEqual([90, 12, 78, 0, 0]);
    expect(u.utilization).toBeCloseTo(12 / 90);
  });
});

describe("exclusions", () => {
  it("adds a range inside the network and refuses one that is unordered or outside", () => {
    const added = createExclusion(state, ctx, DHCP_IDS.lan, { first: "192.0.2.10", last: "192.0.2.19", description: "Servers" });
    expect(listExclusions(state, DHCP_IDS.lan).map((e) => e.first)).toEqual(["192.0.2.10", "192.0.2.150"]);
    expect(added.description).toBe("Servers");
    expect(failure(() => createExclusion(state, ctx, DHCP_IDS.lan, { first: "192.0.2.20", last: "192.0.2.10" })).code).toBe("dhcp.exclusion.invalid");
    expect(failure(() => createExclusion(state, ctx, DHCP_IDS.lan, { first: "198.51.100.1", last: "198.51.100.9" })).code).toBe("dhcp.exclusion.invalid");
  });
});

describe("shared networks", () => {
  it("is not deleted while a scope belongs to it and its name follows the rule", () => {
    const network = createSharedNetwork(state, ctx, { name: "links" });
    updateScope(state, ctx, DHCP_IDS.lan, { shared_network: network.id }, "*");
    const busy = failure(() => deleteSharedNetwork(state, ctx, network.id, "*"));
    expect([busy.code, busy.params.count]).toEqual(["dhcp.shared_network.in_use", "1"]);
    expect(failure(() => createSharedNetwork(state, ctx, { name: "Bad Name" })).code).toBe("dhcp.shared_network.invalid");
    expect(failure(() => createSharedNetwork(state, ctx, { name: "links" })).params.field).toBe("name");
    updateScope(state, ctx, DHCP_IDS.lan, { shared_network: "00000000-0000-0000-0000-000000000000" }, "*");
    deleteSharedNetwork(state, ctx, network.id, "*");
    expect(state.sharedNetworks.map((n) => n.name)).toEqual(["home-links"]);
  });
});

describe("pools", () => {
  it("sets the classes and the lease times, and refuses a range that is no pool", () => {
    const pool = setPool(state, ctx, POOL, { classes: [DHCP_IDS.class], lease: LEASE }, 0);
    expect([pool.settings?.classes, pool.settings?.lease, pool.size, pool.revision > 0]).toEqual([[DHCP_IDS.class], LEASE, 90, true]);
    expect(failure(() => setPool(state, ctx, POOL, { classes: [] }, 0)).status).toBe(412);
    expect(failure(() => setPool(state, ctx, "range-reserved", {}, 0)).code).toBe("dhcp.pool.not_pool");
    expect(listPools(state, ctx, DHCP_IDS.lan)).toHaveLength(1);
  });
});

describe("the catalog and the definitions", () => {
  it("marks the codes the server sets itself", () => {
    const entries = catalog();
    expect(entries.find((c) => c.code === 54)?.server_managed).toBe(true);
    expect(entries.find((c) => c.code === 6)).toMatchObject({ name: "domain-name-servers", kind: "ipv4_address", array: true, server_managed: false });
  });

  it("defines a code, refuses a catalog code and a second definition, and keeps a used one", () => {
    const def = createOptionDef(state, ctx, { code: 240, name: "site-name", kind: "string" });
    expect([def.space, def.used_by]).toEqual(["dhcp4", 0]);
    expect(failure(() => createOptionDef(state, ctx, { code: 6, name: "other", kind: "string" })).code).toBe("dhcp.option.code_reserved");
    expect(failure(() => createOptionDef(state, ctx, { code: 54, name: "other", kind: "string" })).code).toBe("dhcp.option.code_reserved");
    expect(failure(() => createOptionDef(state, ctx, { code: 240, name: "again", kind: "string" })).code).toBe("dhcp.option_def.exists");
    putOptionSet(state, ctx, "server", { values: [{ code: 240, typed: { text: "lab" } }] }, state.optionSets.get("server")?.revision ?? 0);
    const used = failure(() => deleteOptionDef(state, ctx, def.id, "*"));
    expect([used.code, used.params.by]).toEqual(["dhcp.option_def.in_use", "server"]);
    expect(failure(() => updateOptionDef(state, ctx, def.id, { kind: "u8" }, "*")).code).toBe("dhcp.option_def.in_use");
    expect(updateOptionDef(state, ctx, def.id, { description: "Changed" }, "*").description).toBe("Changed");
  });
});

describe("option data in wire form", () => {
  it("encodes and decodes every type", () => {
    const cases: [Parameters<typeof encodeData>[0], boolean, Parameters<typeof encodeData>[2], string][] = [
      ["ipv4_address", true, { ipv4: { values: ["192.0.2.53", "192.0.2.54"] } }, "c0000235c0000236"],
      ["ipv6_address", true, { ipv6: { values: ["2001:db8::53"] } }, "20010db8000000000000000000000053"],
      ["ipv6_prefix", true, { ipv6_prefix: { values: ["2001:db8::/32"] } }, "2020010db8000000000000000000000000"],
      ["u8", false, { unsigned: [7] }, "07"],
      ["u16", false, { unsigned: [1500] }, "05dc"],
      ["u32", false, { unsigned: [86_400] }, "00015180"],
      ["i32", false, { signed: -3600 }, "fffff1f0"],
      ["bool", false, { bool: [true] }, "01"],
      ["string", false, { text: "example.test" }, "6578616d706c652e74657374"],
      ["fqdn", true, { names: ["example.test"] }, "076578616d706c65" + "04" + "74657374" + "00"],
      ["classless_routes", false, { routes: [{ destination: "203.0.113.0/24", router: "192.0.2.1" }] }, "18cb0071c0000201"],
      ["binary", false, { binary: "c0ff" }, "c0ff"],
      ["empty", false, "empty", ""],
    ];
    for (const [kind, array, data, hex] of cases) {
      expect(encodeData(kind, array, data), kind).toEqual({ hex });
      expect(decodeData(kind, array, hex), kind).toEqual({ data });
    }
  });

  it("refuses data that does not fit the type", () => {
    expect(encodeData("u8", false, { unsigned: [300] })).toHaveProperty("reason");
    expect(encodeData("ipv4_address", false, { ipv4: { values: ["192.0.2.1", "192.0.2.2"] } })).toHaveProperty("reason");
    expect(encodeData("string", false, { unsigned: [1] })).toHaveProperty("reason");
    expect(decodeData("u16", false, "010203")).toHaveProperty("reason");
  });
});

describe("option sets", () => {
  it("replaces the whole set from typed or raw values and reads it back typed", () => {
    const set = putOptionSet(
      state,
      ctx,
      `scope:${DHCP_IDS.lan}`,
      { values: [{ code: 3, typed: { ipv4: { values: ["192.0.2.1"] } } }, { code: 26, data: "05dc" }, { code: 230, typed: { unsigned: [4] } }] },
      state.optionSets.get(`scope:${DHCP_IDS.lan}`)?.revision ?? 0,
    );
    expect(set.values.map((v) => [v.code, v.name, v.data])).toEqual([
      [3, "routers", "c0000201"],
      [26, "interface-mtu", "05dc"],
      [230, "site-code", "0004"],
    ]);
    expect(set.values[1]?.typed).toEqual({ unsigned: [1500] });
    expect(getOptionSet(state, ctx, `pool:${POOL}`).values).toEqual([]);
  });

  it("names the code a refusal is about", () => {
    const rev0 = (path: string) => state.optionSets.get(path)?.revision ?? 0;
    const reserved = failure(() => putOptionSet(state, ctx, "server", { values: [{ code: 51, typed: { unsigned: [1] } }] }, rev0("server")));
    expect([reserved.code, reserved.status, reserved.params.code]).toEqual(["dhcp.option.code_reserved", 409, "51"]);
    const unknown = failure(() => putOptionSet(state, ctx, "server", { values: [{ code: 200, data: "00" }] }, rev0("server")));
    expect([unknown.code, unknown.params.code]).toEqual(["dhcp.option.unknown", "200"]);
    const bad = failure(() => putOptionSet(state, ctx, "server", { values: [{ code: 26, typed: { unsigned: [70_000] } }] }, rev0("server")));
    expect([bad.code, bad.params.code]).toEqual(["dhcp.option.invalid", "26"]);
    const twice = failure(() => putOptionSet(state, ctx, "server", { values: [{ code: 15, typed: { text: "a" } }, { code: 15, typed: { text: "b" } }] }, rev0("server")));
    expect(twice.code).toBe("dhcp.option.invalid");
    expect(failure(() => putOptionSet(state, ctx, "server", { values: [] }, 1)).status).toBe(412);
  });

  it("clears the set with an empty list and reads an owner without options as revision 0", () => {
    putOptionSet(state, ctx, "server", { values: [] }, state.optionSets.get("server")?.revision ?? 0);
    expect(getOptionSet(state, ctx, "server")).toMatchObject({ values: [], revision: 0, level: "server" });
    expect(failure(() => getOptionSet(state, ctx, `scope:${SUPERNET}`)).code).toBe("dhcp.scope.not_found");
  });
});

describe("the effective options of a client", () => {
  it("merges the levels, the more specific one winning per code, each with its level", () => {
    putOptionSet(state, ctx, `scope:${DHCP_IDS.lan}`, { values: [{ code: 6, typed: { ipv4: { values: ["192.0.2.54"] } } }, { code: 3, typed: { ipv4: { values: ["192.0.2.1"] } } }] }, state.optionSets.get(`scope:${DHCP_IDS.lan}`)?.revision ?? 0);
    const result = effectiveOptions(state, ctx, DHCP_IDS.lan, { mac: "00:00:5e:00:53:01" });
    expect(result.options.map((o) => [o.value.code, o.level, o.typed])).toEqual([
      [6, "scope", { ipv4: { values: ["192.0.2.54"] } }],
      [15, "server", { text: "example.test" }],
      [3, "scope", { ipv4: { values: ["192.0.2.1"] } }],
    ]);
    expect(result.reservation).toBeUndefined();
  });

  it("adds the options of the reservation of a client as the last level", () => {
    putOptionSet(state, ctx, "host:0190d1c2-0000-7000-8000-000000000999", { values: [{ code: 15, typed: { text: "ap.example.test" } }] }, 0);
    const result = effectiveOptions(state, ctx, DHCP_IDS.lan, { mac: "00:00:5e:00:53:04" });
    expect(result.reservation).toBe("0190d1c2-0000-7000-8000-000000000999");
    expect(result.options.find((o) => o.value.code === 15)).toMatchObject({ level: "host", typed: { text: "ap.example.test" } });
  });
});

// WP8.6: the matcher behind the effective options (docs/dhcp.md section 16.1).
describe("the matcher of the effective options", () => {
  const MAC = "00:00:5e:00:53:01";
  const OTHER = "02:00:00:00:00:01";
  type Facts = Parameters<typeof effectiveOptions>[3];
  const client = (q: Facts) => effectiveOptions(state, ctx, DHCP_IDS.lan, q);
  const className = (id: string) => state.classes.find((c) => c.id === id)?.name;
  const policyName = (id: string) => state.policies.find((p) => p.id === id)?.name;
  const classesOf = (q: Facts) => (client(q).classes ?? []).map(className).sort();
  const policiesOf = (q: Facts) => (client(q).policies ?? []).map(policyName);
  const PXE: Term = { match: { vendor_class: { value: "PXEClient", prefix: true } } };

  /** A policy that sets the domain name (15) and the boot file (67). */
  const bootPolicy = (name: string, terms: Term[], text: string, extra: { scope?: string | null; order?: number; enabled?: boolean } = {}) => {
    const body: Record<string, unknown> = { name, condition: { join: "and", terms }, enabled: extra.enabled ?? true };
    if (extra.scope !== null) body.scope = extra.scope ?? DHCP_IDS.lan;
    if (extra.order !== undefined) body.order = extra.order;
    const policy = createPolicy(state, ctx, body);
    putOptionSet(state, ctx, `policy:${policy.id}`, { values: [{ code: 15, typed: { text } }, { code: 67, typed: { text: `${name}.efi` } }] }, 0);
    return policy;
  };

  it("finds a client in a class by what it sends: vendor class exact or prefix, user class, MAC pattern, client id, architecture, host name", () => {
    createClass(state, ctx, { name: "uefi", matches: [{ architecture: { code: 7 } }, { architecture: { code: 9 } }] });
    createClass(state, ctx, { name: "lab-gear", matches: [{ mac: { pattern: "00:00:5e:00:53:*" } }, { client_id: { value: "01aabb" } }] });
    createClass(state, ctx, { name: "named", matches: [{ host_name: { value: "Printer", prefix: true } }, { user_class: { value: "lab" } }] });
    createClass(state, ctx, { name: "exact", matches: [{ vendor_class: { value: "MSFT 5.0" } }] });
    // The seeded class takes a vendor class that starts with PXEClient.
    expect(classesOf({ mac: OTHER, vendor_class: "PXEClient:Arch:00007" })).toEqual(["pxe-clients"]);
    expect(classesOf({ mac: OTHER, vendor_class: "PXE" })).toEqual([]);
    expect(classesOf({ mac: MAC, architecture: 9 })).toEqual(["lab-gear", "uefi"]);
    expect(classesOf({ mac: OTHER, architecture: 0 })).toEqual([]);
    expect(classesOf({ mac: OTHER, client_id: "01AABB" })).toEqual(["lab-gear"]);
    expect(classesOf({ mac: OTHER, host_name: "PRINTER-7" })).toEqual(["named"]);
    expect(classesOf({ mac: OTHER, host_name: "my-printer" })).toEqual([]);
    expect(classesOf({ mac: OTHER, user_class: "lab" })).toEqual(["named"]);
    expect(classesOf({ mac: OTHER, vendor_class: "MSFT 5.0" })).toEqual(["exact"]);
    expect(classesOf({ mac: OTHER, vendor_class: "MSFT 5.0 plus" })).toEqual([]);
  });

  it("never matches circuit-id and remote-id, and a fact that is absent matches nothing", () => {
    createClass(state, ctx, { name: "relayed", matches: [{ circuit_id: { value: "0001" } }, { remote_id: { value: "0a0b" } }] });
    createClass(state, ctx, { name: "arch-zero", matches: [{ architecture: { code: 0 } }] });
    expect(client({ mac: MAC, client_id: "0001" }).classes).toEqual([]);
    expect(client({ mac: MAC }).classes).toEqual([]);
    expect(classesOf({ mac: MAC, architecture: 0 })).toEqual(["arch-zero"]);
  });

  it("joins the terms of a policy with and or or, with negations, and a deleted class is false", () => {
    createPolicy(state, ctx, { name: "both", scope: DHCP_IDS.lan, order: 5, condition: { join: "and", terms: [{ class: DHCP_IDS.class }, { match: { host_name: { value: "pxe", prefix: true } } }] } });
    createPolicy(state, ctx, { name: "either", scope: DHCP_IDS.lan, order: 6, condition: { join: "or", terms: [{ match: { architecture: { code: 7 } } }, { match: { host_name: { value: "nothing" } } }] } });
    createPolicy(state, ctx, { name: "not-pxe", scope: DHCP_IDS.lan, order: 7, condition: { join: "and", terms: [{ not_class: DHCP_IDS.class }, { not_match: { architecture: { code: 7 } } }] } });
    expect(policiesOf({ mac: MAC, vendor_class: "PXEClient", host_name: "pxe-1" })).toEqual(["pxe-boot", "both"]);
    expect(policiesOf({ mac: MAC, vendor_class: "PXEClient" })).toEqual(["pxe-boot"]);
    expect(policiesOf({ mac: MAC, architecture: 7 })).toEqual(["either"]);
    expect(policiesOf({ mac: MAC })).toEqual(["not-pxe"]);
    expect(policiesOf({ mac: MAC, architecture: 0 })).toEqual(["not-pxe"]);
    // A class that is gone: a term that names it is false and its negation true.
    state.classes = state.classes.filter((k) => k.id !== DHCP_IDS.class);
    expect(policiesOf({ mac: MAC, vendor_class: "PXEClient", host_name: "pxe-1" })).toEqual(["not-pxe"]);
  });

  it("leaves out a policy that is disabled and puts the policies of the scope by order before those of the server", () => {
    bootPolicy("everywhere", [PXE], "server.example.test", { scope: null, order: 1 });
    bootPolicy("second", [PXE], "second.example.test", { order: 9 });
    bootPolicy("off", [PXE], "off.example.test", { order: 0, enabled: false });
    expect(policiesOf({ mac: MAC, vendor_class: "PXEClient:Arch:00007" })).toEqual(["pxe-boot", "second", "everywhere"]);
  });

  it("gives each option to the first matching policy that sets it, at the policy level between the scope and the reservation", () => {
    const first = bootPolicy("first", [{ match: { architecture: { code: 7 } } }], "first.example.test", { order: 2 });
    const second = bootPolicy("second", [{ match: { architecture: { code: 7 } } }], "second.example.test", { order: 3 });
    // The second policy sets an option the first does not.
    const set = state.optionSets.get(`policy:${second.id}`);
    putOptionSet(state, ctx, `policy:${second.id}`, { values: [{ code: 15, typed: { text: "second.example.test" } }, { code: 67, typed: { text: "second.efi" } }, { code: 66, typed: { text: "tftp.example.test" } }] }, set?.revision ?? 0);
    const result = client({ mac: MAC, architecture: 7 });
    const by = Object.fromEntries(result.options.map((o) => [o.value.code, o]));
    expect([by[15]?.level, by[15]?.owner, by[15]?.typed]).toEqual(["policy", { policy: first.id }, { text: "first.example.test" }]);
    expect([by[67]?.owner, by[67]?.typed]).toEqual([{ policy: first.id }, { text: "first.efi" }]);
    expect([by[66]?.level, by[66]?.owner]).toEqual(["policy", { policy: second.id }]);
    // The codes of the lower levels stay where they first appeared; the codes a policy adds follow.
    expect(result.options.map((o) => o.value.code)).toEqual([6, 15, 3, 67, 66]);
    expect([by[6]?.level, by[3]?.level]).toEqual(["server", "scope"]);
    // The reservation is the last level and wins over a policy.
    putOptionSet(state, ctx, "host:0190d1c2-0000-7000-8000-000000000999", { values: [{ code: 15, typed: { text: "ap.example.test" } }] }, 0);
    const reserved = effectiveOptions(state, ctx, DHCP_IDS.lan, { mac: "00:00:5e:00:53:04", architecture: 7 });
    expect(reserved.options.find((o) => o.value.code === 15)).toMatchObject({ level: "host", typed: { text: "ap.example.test" } });
    expect(reserved.options.find((o) => o.value.code === 67)).toMatchObject({ level: "policy" });
  });

  it("returns every class that matches, and none for a client that sends nothing", () => {
    createClass(state, ctx, { name: "any-mac", matches: [{ mac: { pattern: "*:*:*:*:*:*" } }] });
    expect(classesOf({ mac: MAC, vendor_class: "PXEClient" })).toEqual(["any-mac", "pxe-clients"]);
    expect(client({}).classes).toEqual([]);
    expect(client({}).policies).toEqual([]);
  });
});

describe("classes", () => {
  it("is created with its matches in canonical form and not deleted while it is named", () => {
    const item = createClass(state, ctx, { name: "lab-macs", matches: [{ mac: { pattern: "00:00:5E:*" } }, { client_id: { value: "01:AA:bb" } }, { architecture: { code: 7 } }] });
    expect(item.matches).toEqual([{ mac: { pattern: "00:00:5e:*:*:*" } }, { client_id: { value: "01aabb" } }, { architecture: { code: 7 } }]);
    const busy = failure(() => deleteClass(state, ctx, DHCP_IDS.class, "*"));
    expect([busy.code, busy.params.by]).toEqual(["dhcp.class.in_use", `policy:${DHCP_IDS.policy}`]);
    deleteClass(state, ctx, item.id, "*");
    expect(state.classes).toHaveLength(1);
  });

  it("refuses a name that breaks the rule, no matches and a bad match, naming the field", () => {
    expect(failure(() => createClass(state, ctx, { name: "Bad", matches: [{ vendor_class: { value: "x" } }] })).params.field).toBe("name");
    expect(failure(() => createClass(state, ctx, { name: "ok", matches: [] })).params.field).toBe("matches");
    expect(failure(() => createClass(state, ctx, { name: "ok", matches: [{ mac: { pattern: "zz" } }] })).params.field).toBe("matches[0]");
    expect(failure(() => createClass(state, ctx, { name: "pxe-clients", matches: [{ vendor_class: { value: "x" } }] })).code).toBe("dhcp.class.invalid");
  });
});

describe("policies", () => {
  it("goes after the last policy of its scope and is checked", () => {
    const policy = createPolicy(state, ctx, {
      name: "labs",
      scope: DHCP_IDS.lan,
      condition: { join: "or", terms: [{ class: DHCP_IDS.class }, { not_match: { host_name: { value: "pr", prefix: true } } }] },
      action: { range: { first: "192.0.2.100", last: "192.0.2.119" } },
    });
    expect([policy.order, policy.enabled]).toEqual([2, true]);
    expect(failure(() => createPolicy(state, ctx, { name: "pxe-boot", scope: DHCP_IDS.lan, condition: { join: "and", terms: [{ class: DHCP_IDS.class }] } })).params.field).toBe("name");
    expect(failure(() => createPolicy(state, ctx, { name: "empty", condition: { join: "and", terms: [] } })).params.field).toBe("condition.terms");
    expect(failure(() => createPolicy(state, ctx, { name: "range", condition: { join: "and", terms: [{ class: DHCP_IDS.class }] }, action: { range: { first: "192.0.2.9", last: "192.0.2.1" } } })).params.field).toBe("action.range");
    expect(updatePolicy(state, ctx, policy.id, { enabled: false, order: 9, description: "Off" }, policy.revision)).toMatchObject({ enabled: false, order: 9, description: "Off" });
  });
});

describe("MAC filters", () => {
  it("keeps the pattern in its stored form, one entry per pattern", () => {
    const filter = createFilter(state, ctx, { mac: "00-00-5E-01-*", kind: "deny", note: "Guests" });
    expect(filter.mac).toBe("00:00:5e:01:*:*");
    expect(failure(() => createFilter(state, ctx, { mac: "00:00:5e:01:*", kind: "allow" })).code).toBe("dhcp.filter.exists");
    expect(failure(() => createFilter(state, ctx, { mac: "xx", kind: "allow" })).code).toBe("dhcp.filter.invalid");
    const allowed = updateFilter(state, ctx, filter.id, { kind: "allow", note: "" }, filter.revision);
    expect(allowed.kind).toBe("allow");
    expect(allowed.note).toBeUndefined();
  });
});

describe("DHCPv6 (WP9.4)", () => {
  it("creates a scope on an IPv6 network with its DHCPv6 settings and says the family of every scope", () => {
    const scope = createScope(state, ctx, { prefix: IOT_V6, v6: { preferred_secs: 3600, rapid_commit: false, interface_id: "eth1" } });
    expect([scope.family, scope.cidr, scope.v6]).toEqual(["v6", "2001:db8:0:30::/64", { preferred_secs: 3600, rapid_commit: false, interface_id: "eth1" }]);
    expect(createScope(state, ctx, { prefix: DHCP_IDS.iot }).family).toBe("v4");
    expect(createScope(state, ctx, { prefix: WIFI }).v6).toBeUndefined();
  });

  it("refuses the DHCPv6 settings on an IPv4 prefix, a preferred lifetime above the valid lifetime and a long Interface-Id", () => {
    const v4 = failure(() => createScope(state, ctx, { prefix: DHCP_IDS.iot, v6: { rapid_commit: true } }));
    expect([v4.status, v4.code, v4.params.field]).toEqual([400, "dhcp.scope.invalid", "v6"]);
    expect(failure(() => updateScope(state, ctx, DHCP_IDS.lan, { v6: { rapid_commit: true } }, "*")).params.field).toBe("v6");
    // The valid lifetime is the default lease time in force: the server's 24 hours, then the scope's 2 hours.
    expect(failure(() => updateScope(state, ctx, DHCP_IDS.lanV6, { v6: { preferred_secs: 86_401 } }, "*")).params.field).toBe("v6.preferred_secs");
    expect(updateScope(state, ctx, DHCP_IDS.lanV6, { v6: { preferred_secs: 86_400 } }, "*").v6).toEqual({ preferred_secs: 86_400 });
    updateScope(state, ctx, DHCP_IDS.lanV6, { lease: LEASE }, "*");
    expect(failure(() => updateScope(state, ctx, DHCP_IDS.lanV6, { v6: { preferred_secs: 7201 } }, "*")).code).toBe("dhcp.scope.invalid");
    for (const secs of [0, -1, 1.5, "3600"]) {
      expect(failure(() => updateScope(state, ctx, DHCP_IDS.lanV6, { v6: { preferred_secs: secs } }, "*")).params.field, String(secs)).toBe("v6.preferred_secs");
    }
    expect(failure(() => updateScope(state, ctx, DHCP_IDS.lanV6, { v6: { interface_id: "x".repeat(65) } }, "*")).params.field).toBe("v6.interface_id");
    expect(updateScope(state, ctx, DHCP_IDS.lanV6, { v6: { interface_id: "x".repeat(64) } }, "*").v6?.interface_id).toHaveLength(64);
  });

  it("replaces the DHCPv6 settings whole on a change and drops them with clear_v6", () => {
    updateScope(state, ctx, DHCP_IDS.lanV6, { v6: { preferred_secs: 3600, interface_id: "eth1" } }, "*");
    expect(updateScope(state, ctx, DHCP_IDS.lanV6, { v6: { rapid_commit: false } }, "*").v6).toEqual({ rapid_commit: false });
    expect(updateScope(state, ctx, DHCP_IDS.lanV6, { description: "Other" }, "*").v6).toEqual({ rapid_commit: false });
    const cleared = updateScope(state, ctx, DHCP_IDS.lanV6, { clear_v6: true }, "*");
    expect([cleared.v6, cleared.description]).toEqual([undefined, "Other"]);
  });

  it("counts the pools of a DHCPv6 scope with 128-bit sizes and says the size of a large one as a power of two", () => {
    const small = utilization(state, ctx, DHCP_IDS.lanV6);
    expect([small.family, small.pool_size, small.leased, small.free, small.pool_bits]).toEqual(["v6", 256, 3, 253, undefined]);
    expect(utilization(state, ctx, DHCP_IDS.lan)).toMatchObject({ family: "v4" });
    createScope(state, ctx, { prefix: IOT_V6 });
    // A /64 pool: 2^64 addresses, which the count stops at 2^64 - 1 (it reads as 2^64 in a double).
    const wide = utilization(state, ctx, IOT_V6);
    expect([wide.family, wide.pool_bits, wide.pool_size, wide.leased, wide.free]).toEqual(["v6", 64, Number((1n << 64n) - 1n), 0, Number((1n << 64n) - 1n)]);
    // An exclusion of half the pool leaves 2^63 addresses: the size rounded down is 63.
    createExclusion(state, ctx, IOT_V6, { first: "2001:db8:0:30:8000::", last: "2001:db8:0:30:ffff:ffff:ffff:ffff" });
    expect(utilization(state, ctx, IOT_V6).pool_bits).toBe(63);
  });

  it("has the built-in DHCPv6 catalog, with the codes the server sets itself", () => {
    const six = catalog("dhcp6");
    expect(six.every((c) => c.space === "dhcp6")).toBe(true);
    expect(six.filter((c) => c.server_managed).map((c) => c.code)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 18, 19, 20, 25, 26, 37, 39, 79]);
    expect(six.filter((c) => !c.server_managed).map((c) => c.code)).toEqual([21, 22, 23, 24, 27, 28, 29, 30, 31, 32, 41, 42, 56, 59, 60, 64, 82, 83]);
    expect(six.find((c) => c.code === 23)).toMatchObject({ name: "dns-servers", kind: "ipv6_address", array: true });
    expect(six.find((c) => c.code === 24)).toMatchObject({ name: "domain-search", kind: "fqdn", array: true });
    expect(catalog("dhcp4").every((c) => c.space === "dhcp4")).toBe(true);
    const both = catalog();
    expect(both.slice(0, catalog("dhcp4").length).every((c) => c.space === "dhcp4")).toBe(true);
    expect(both).toHaveLength(catalog("dhcp4").length + six.length);
  });

  it("saves dhcp6 option values typed, refuses a server-managed code, a type that does not fit and a code without a definition", () => {
    const path = `scope:${DHCP_IDS.lanV6}`;
    const revision = state.optionSets.get(path)?.revision ?? 0;
    const saved = putOptionSet(
      state,
      ctx,
      path,
      { values: [{ space: "dhcp6", code: 23, typed: { ipv6: { values: ["2001:db8:0:10::53", "2001:db8:0:10::54"] } } }, { space: "dhcp6", code: 32, typed: { unsigned: [86_400] } }] },
      revision,
    );
    expect(saved.values.map((v) => [v.space, v.code, v.name, v.data])).toEqual([
      ["dhcp6", 23, "dns-servers", "20010db8000000100000000000000053" + "20010db8000000100000000000000054"],
      ["dhcp6", 32, "information-refresh-time", "00015180"],
    ]);
    const reserved = failure(() => putOptionSet(state, ctx, path, { values: [{ space: "dhcp6", code: 3, data: "" }] }, "*"));
    expect([reserved.status, reserved.code]).toEqual([409, "dhcp.option.code_reserved"]);
    expect(failure(() => putOptionSet(state, ctx, path, { values: [{ space: "dhcp6", code: 23, typed: { ipv4: { values: ["192.0.2.1"] } } }] }, "*")).code).toBe("dhcp.option.invalid");
    expect(failure(() => putOptionSet(state, ctx, path, { values: [{ space: "dhcp6", code: 23, typed: { ipv6: { values: [] } } }] }, "*")).code).toBe("dhcp.option.invalid");
    expect(failure(() => putOptionSet(state, ctx, path, { values: [{ space: "dhcp6", code: 99, data: "00" }] }, "*")).code).toBe("dhcp.option.unknown");
    // The same code number in the other space is another option: dhcp4 option 3 is the routers.
    expect(putOptionSet(state, ctx, path, { values: [{ code: 3, typed: { ipv4: { values: ["192.0.2.1"] } } }] }, "*").values.map((v) => [v.space, v.code])).toEqual([["dhcp4", 3]]);
  });

  it("refuses a custom definition of a dhcp6 catalog code", () => {
    expect(failure(() => createOptionDef(state, ctx, { space: "dhcp6", code: 23, name: "mine", kind: "string" })).code).toBe("dhcp.option.code_reserved");
    expect(createOptionDef(state, ctx, { space: "dhcp6", code: 200, name: "site-six", kind: "string" })).toMatchObject({ space: "dhcp6", code: 200 });
  });
});

describe("the routes", () => {
  beforeEach(async () => {
    await signInAlex();
  });
  afterEach(() => {
    setSessionForTest(null);
    mockUpdates.modules.running = ["ipam", "dns", "dhcp", "discovery"];
  });

  it("answers the scope with its ETag and refuses a stale If-Match with 412", async () => {
    const scope = await api.get("/api/v1/dhcp/scopes/{prefix}", { path: { prefix: DHCP_IDS.lan } });
    expect(scope.cidr).toBe("192.0.2.0/24");
    const changed = await api.patch("/api/v1/dhcp/scopes/{prefix}", { path: { prefix: DHCP_IDS.lan }, body: { description: "Changed" }, ifMatch: scope.revision });
    expect(changed.revision).toBeGreaterThan(scope.revision);
    await expect(api.patch("/api/v1/dhcp/scopes/{prefix}", { path: { prefix: DHCP_IDS.lan }, body: { description: "Again" }, ifMatch: scope.revision })).rejects.toMatchObject({ status: 412, code: "sys.store.precondition_failed" });
    expect(dhcpState().scopes[0]?.description).toBe("Changed");
  });

  it("lists a page and audits a write", async () => {
    const page = await api.get("/api/v1/dhcp/scopes");
    expect(page.items.map((s) => s.cidr)).toEqual(["192.0.2.0/24", "2001:db8:0:10::/64"]);
    const before = audit.records.length;
    await api.post("/api/v1/dhcp/filters", { body: { mac: "02:00:00:00:00:*", kind: "deny" } });
    expect(audit.records.slice(before).map((r) => r.draft.action)).toEqual(["dhcp.filter.create"]);
  });

  it("answers the option catalog by space, both with dhcp4 first, and refuses another space", async () => {
    const six = await api.get("/api/v1/dhcp/option-catalog", { query: { space: "dhcp6" } });
    expect(six.every((c) => c.space === "dhcp6")).toBe(true);
    expect(six.some((c) => c.code === 23)).toBe(true);
    const four = await api.get("/api/v1/dhcp/option-catalog", { query: { space: "dhcp4" } });
    expect(four.every((c) => c.space === "dhcp4")).toBe(true);
    const both = await api.get("/api/v1/dhcp/option-catalog");
    expect(both).toHaveLength(four.length + six.length);
    expect(both[0]?.space).toBe("dhcp4");
    expect(both[both.length - 1]?.space).toBe("dhcp6");
    await expect(api.get("/api/v1/dhcp/option-catalog", { query: { space: "dhcp5" } })).rejects.toMatchObject({ status: 400, code: "sys.invalid_query" });
  });

  it("changes the DHCPv6 settings of a scope with the revision, drops them, and refuses them on an IPv4 scope", async () => {
    const scope = await api.get("/api/v1/dhcp/scopes/{prefix}", { path: { prefix: DHCP_IDS.lanV6 } });
    expect([scope.family, scope.v6]).toEqual(["v6", { rapid_commit: true }]);
    const changed = await api.patch("/api/v1/dhcp/scopes/{prefix}", {
      path: { prefix: DHCP_IDS.lanV6 },
      body: { v6: { preferred_secs: 3600, rapid_commit: false, interface_id: "eth1" } },
      ifMatch: scope.revision,
    });
    expect(changed.v6).toEqual({ preferred_secs: 3600, rapid_commit: false, interface_id: "eth1" });
    const cleared = await api.patch("/api/v1/dhcp/scopes/{prefix}", { path: { prefix: DHCP_IDS.lanV6 }, body: { clear_v6: true }, ifMatch: changed.revision });
    expect(cleared.v6).toBeUndefined();
    const err = await api.patch("/api/v1/dhcp/scopes/{prefix}", { path: { prefix: DHCP_IDS.lan }, body: { v6: { rapid_commit: true } }, ifMatch: "*" as never }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect([(err as ApiError).status, (err as ApiError).code, (err as ApiError).params.field]).toEqual([400, "dhcp.scope.invalid", "v6"]);
  });

  it("answers the utilization of a DHCPv6 scope with its family", async () => {
    const u = await api.get("/api/v1/dhcp/scopes/{prefix}/utilization", { path: { prefix: DHCP_IDS.lanV6 } });
    expect([u.family, u.pool_size, u.leased]).toEqual(["v6", 256, 3]);
  });

  it("puts and reads the dhcp6 options of a DHCPv6 scope", async () => {
    const owner = `scope:${DHCP_IDS.lanV6}`;
    const set = await api.get("/api/v1/dhcp/option-sets/{owner}", { path: { owner } });
    const saved = await api.put("/api/v1/dhcp/option-sets/{owner}", {
      path: { owner },
      body: { values: [{ space: "dhcp6", code: 23, typed: { ipv6: { values: ["2001:db8::53"] } } }] },
      ifMatch: set.revision,
    });
    expect(saved.values.map((v) => [v.space, v.code, v.typed])).toEqual([["dhcp6", 23, { ipv6: { values: ["2001:db8::53"] } }]]);
    await expect(
      api.put("/api/v1/dhcp/option-sets/{owner}", { path: { owner }, body: { values: [{ space: "dhcp6", code: 1, data: "00" }] }, ifMatch: saved.revision }),
    ).rejects.toMatchObject({ status: 409, code: "dhcp.option.code_reserved" });
  });

  it("answers a refusal as a problem with the field under errors", async () => {
    const err = await api.post("/api/v1/dhcp/classes", { body: { name: "Bad Name", matches: [{ vendor_class: { value: "x" } }] } }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe("dhcp.class.invalid");
    expect((err as ApiError).fieldErrors.map((f) => f.field)).toEqual(["name"]);
  });

  it("answers the effective options of a client with the classes and policies the facts of the query match", async () => {
    const base = { path: { prefix: DHCP_IDS.lan } };
    const plain = await api.get("/api/v1/dhcp/scopes/{prefix}/effective-options", { ...base, query: { mac: "00:00:5e:00:53:01" } });
    expect([plain.classes, plain.policies]).toEqual([[], []]);
    const pxe = await api.get("/api/v1/dhcp/scopes/{prefix}/effective-options", {
      ...base,
      query: { mac: "00-00-5E-00-53-01", client_id: "01:AA", vendor_class: "PXEClient:Arch:00007", user_class: "lab", architecture: 7, host_name: "Boot-1" },
    });
    expect([pxe.classes, pxe.policies]).toEqual([[DHCP_IDS.class], [DHCP_IDS.policy]]);
  });

  it("refuses an architecture that is not a number from 0 to 65535, and a client identifier that is not hexadecimal", async () => {
    for (const architecture of ["x", "-1", "65536", "1.5"]) {
      await expect(api.get("/api/v1/dhcp/scopes/{prefix}/effective-options", { path: { prefix: DHCP_IDS.lan }, query: { mac: "00:00:5e:00:53:01", architecture: architecture as never } })).rejects.toMatchObject({ status: 400, code: "sys.invalid_query" });
    }
    await expect(api.get("/api/v1/dhcp/scopes/{prefix}/effective-options", { path: { prefix: DHCP_IDS.lan }, query: { mac: "00:00:5e:00:53:01", client_id: "zz" } })).rejects.toMatchObject({ status: 400, code: "sys.invalid_query" });
    const ok = await api.get("/api/v1/dhcp/scopes/{prefix}/effective-options", { path: { prefix: DHCP_IDS.lan }, query: { architecture: 0 as never } });
    expect(ok.prefix).toBe(DHCP_IDS.lan);
  });

  it("answers 404 sys.route_not_found while the DHCP module is switched off", async () => {
    mockUpdates.modules.running = ["ipam", "dns"];
    await expect(api.get("/api/v1/dhcp/scopes")).rejects.toMatchObject({ status: 404, code: "sys.route_not_found" });
  });

  it("lets a viewer read and refuses the write", async () => {
    await signInWithRoles(["viewer"]);
    expect((await api.get("/api/v1/dhcp/classes")).items).toHaveLength(1);
    await expect(api.post("/api/v1/dhcp/filters", { body: { mac: "02:00:00:00:00:*", kind: "deny" } })).rejects.toMatchObject({ status: 403 });
  });

  // WP7.5 answers the lease, history and node routes (routes-dhcp-leases.ts); the reservations stay stubs.
  it("leaves the reservation routes to the 501 stubs", async () => {
    await expect(api.get("/api/v1/dhcp/reservations")).rejects.toMatchObject({ status: 501 });
  });
});
