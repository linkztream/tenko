import { describe, expect, it } from "vitest";
import type { AuditRecord, Principal, TreeNode } from "../api/types";
import { mockMetricsSnapshot } from "../api/mock/metrics-model";
import type { MetricsHost, MetricsSample } from "./metrics";
import { dashboardSet, familyUse, groupChanges, hiddenKeys, isSystem, isV6, profileOf, type DashboardSet } from "./model";

describe("profileOf", () => {
  it("gives home for an unknown name, an empty name and no name", () => {
    expect(profileOf("enterprise")).toBe("home");
    expect(profileOf("")).toBe("home");
    expect(profileOf(null)).toBe("home");
    expect(profileOf(undefined)).toBe("home");
  });

  it("gives each of the four profiles back as it is", () => {
    for (const name of ["lab", "home", "standard", "hardened"] as const) expect(profileOf(name)).toBe(name);
  });
});

describe("dashboardSet", () => {
  it("draws the operations blocks only under standard and hardened, or with show all", () => {
    for (const profile of ["lab", "home"] as const) {
      expect(dashboardSet(profile, false, false).operations).toBe(false);
      expect(dashboardSet(profile, true, false).operations).toBe(false);
      expect(dashboardSet(profile, false, true).operations).toBe(true);
    }
    for (const profile of ["standard", "hardened"] as const) {
      expect(dashboardSet(profile, false, false).operations).toBe(true);
      expect(dashboardSet(profile, true, true).operations).toBe(true);
    }
  });

  it("draws the controller metrics under lab, with more than one node, or with show all", () => {
    expect(dashboardSet("lab", false, false).controller).toBe(true);
    for (const profile of ["home", "standard", "hardened"] as const) {
      expect(dashboardSet(profile, false, false).controller).toBe(false);
      expect(dashboardSet(profile, true, false).controller).toBe(true);
      expect(dashboardSet(profile, false, true).controller).toBe(true);
    }
  });

  it("draws the cluster block only with more than one node or with show all, whatever the profile", () => {
    for (const profile of ["lab", "home", "standard", "hardened"] as const) {
      expect(dashboardSet(profile, false, false).cluster).toBe(false);
      expect(dashboardSet(profile, true, false).cluster).toBe(true);
      expect(dashboardSet(profile, false, true).cluster).toBe(true);
    }
  });

  it("draws the security panel only under hardened, and show all does not add it to the other profiles", () => {
    expect(dashboardSet("hardened", false, false).security).toBe(true);
    for (const profile of ["lab", "home", "standard"] as const) {
      expect(dashboardSet(profile, false, false).security).toBe(false);
      expect(dashboardSet(profile, true, true).security).toBe(false);
    }
  });

  it("starts with system activity on under lab and home and off under standard and hardened", () => {
    expect(dashboardSet("lab", false, false).systemActivity).toBe(true);
    expect(dashboardSet("home", true, true).systemActivity).toBe(true);
    expect(dashboardSet("standard", false, false).systemActivity).toBe(false);
    expect(dashboardSet("hardened", true, true).systemActivity).toBe(false);
  });
});

describe("hiddenKeys", () => {
  const everything: DashboardSet = { operations: true, controller: true, cluster: true, security: false, systemActivity: true };
  const full = (): MetricsSample => mockMetricsSnapshot(1, { dns: true, dhcp: true, host: true }).cluster;
  const withHost = (host: MetricsHost | null | undefined): MetricsSample => {
    const sample = full();
    if (host === undefined) delete sample.host;
    else sample.host = host;
    return sample;
  };
  const GIB = 1024 ** 3;

  it("names nothing for an administrator whose sample has everything and whose set draws everything", () => {
    expect(hiddenKeys({ set: everything, admin: true, sample: full() })).toEqual([]);
  });

  it("names the host when the sample has no host part", () => {
    expect(hiddenKeys({ set: everything, admin: true, sample: withHost(undefined) })).toEqual(["host"]);
    expect(hiddenKeys({ set: everything, admin: true, sample: withHost(null) })).toEqual(["host"]);
  });

  it("names the host when neither the CPU nor the memory was read", () => {
    expect(hiddenKeys({ set: everything, admin: true, sample: withHost({ disk_total: 100 * GIB, disk_available: 50 * GIB }) })).toEqual(["host"]);
  });

  it("names the memory when the CPU was read and the memory was not", () => {
    expect(hiddenKeys({ set: everything, admin: true, sample: withHost({ cpu_percent: 12.5 }) })).toEqual(["host-memory"]);
  });

  it("names the CPU when the memory was read and the CPU was not", () => {
    const host: MetricsHost = { cpu_percent: null, memory_total: 16 * GIB, memory_available: 4 * GIB };
    expect(hiddenKeys({ set: everything, admin: true, sample: withHost(host) })).toEqual(["host-cpu"]);
  });

  it("names neither the CPU nor the memory when both were read", () => {
    const host: MetricsHost = { cpu_percent: 12.5, memory_total: 16 * GIB, memory_available: 4 * GIB };
    expect(hiddenKeys({ set: everything, admin: true, sample: withHost(host) })).toEqual([]);
  });

  it("names the controller block when the set does not draw it, for an administrator only", () => {
    const set = { ...everything, controller: false };
    expect(hiddenKeys({ set, admin: true, sample: full() })).toEqual(["controller"]);
    expect(hiddenKeys({ set, admin: false, sample: null })).not.toContain("controller");
  });

  it("names the operations blocks when the set does not draw them, for an administrator and a viewer", () => {
    const set = { ...everything, operations: false };
    expect(hiddenKeys({ set, admin: true, sample: full() })).toEqual(["operations"]);
    expect(hiddenKeys({ set, admin: false, sample: null })).toContain("operations");
  });

  it("names the DNS and DHCP panels when the sample has no such part", () => {
    const noDns = full();
    noDns.dns = null;
    expect(hiddenKeys({ set: everything, admin: true, sample: noDns })).toEqual(["dns"]);
    const noDhcp = full();
    delete noDhcp.dhcp;
    expect(hiddenKeys({ set: everything, admin: true, sample: noDhcp })).toEqual(["dhcp"]);
    const neither = mockMetricsSnapshot(1, { dns: false, dhcp: false, host: true }).cluster;
    expect(hiddenKeys({ set: everything, admin: true, sample: neither })).toEqual(["dns", "dhcp"]);
  });

  it("lists the keys in the order of the line", () => {
    const sample = mockMetricsSnapshot(1, { dns: false, dhcp: false, host: false }).cluster;
    const set = { ...everything, controller: false, operations: false };
    expect(hiddenKeys({ set, admin: true, sample })).toEqual(["host", "controller", "operations", "dns", "dhcp"]);
  });

  it("names the account for a viewer and never the host, DNS, DHCP or controller", () => {
    const set = { ...everything, controller: false };
    expect(hiddenKeys({ set, admin: false, sample: full() })).toEqual(["admin"]);
    const bare = mockMetricsSnapshot(1, { dns: false, dhcp: false, host: false }).cluster;
    expect(hiddenKeys({ set, admin: false, sample: bare })).toEqual(["admin"]);
  });

  it("names no host, DNS or DHCP before the first sample", () => {
    expect(hiddenKeys({ set: everything, admin: true, sample: null })).toEqual([]);
    expect(hiddenKeys({ set: everything, admin: true, sample: undefined })).toEqual([]);
    expect(hiddenKeys({ set: { ...everything, controller: false, operations: false }, admin: true, sample: null })).toEqual(["controller", "operations"]);
  });
});

function tree(cidr: string, depth: number, role: "network" | "supernet", inUse: string): TreeNode {
  return {
    cidr,
    depth,
    role,
    id: `prefix-${cidr}`,
    children: 0,
    level: "ok",
    status: "active",
    utilization: { in_use: inUse },
  } as unknown as TreeNode;
}

describe("isV6", () => {
  it("tells an IPv6 prefix by its colon", () => {
    expect(isV6({ cidr: "2001:db8::/32" })).toBe(true);
    expect(isV6({ cidr: "192.0.2.0/24" })).toBe(false);
  });
});

describe("familyUse", () => {
  it("is zero for an empty tree", () => {
    expect(familyUse([])).toEqual({ v4: { used: 0n, networks: 0 }, v6: { used: 0n, networks: 0 } });
  });

  it("counts the addresses in use of the top-level prefixes only, per family", () => {
    const nodes = [
      tree("192.0.2.0/24", 0, "network", "100"),
      tree("198.51.100.0/24", 0, "network", "28"),
      tree("203.0.113.0/25", 1, "network", "60"),
      tree("2001:db8::/48", 0, "network", "4000000000000000000000"),
      tree("2001:db8:0:1::/64", 1, "network", "5"),
    ];
    const use = familyUse(nodes);
    expect(use.v4.used).toBe(128n);
    expect(use.v6.used).toBe(4_000_000_000_000_000_000_000n);
  });

  it("counts the prefixes with the role network at any depth and leaves supernets out of the networks", () => {
    const nodes = [
      tree("10.0.0.0/8", 0, "supernet", "10"),
      tree("10.1.0.0/16", 1, "supernet", "10"),
      tree("10.1.1.0/24", 2, "network", "10"),
      tree("10.1.2.0/24", 2, "network", "0"),
      tree("2001:db8::/32", 0, "supernet", "7"),
      tree("2001:db8:1::/48", 1, "network", "7"),
    ];
    const use = familyUse(nodes);
    expect(use.v4.networks).toBe(2);
    expect(use.v6.networks).toBe(1);
    // A supernet at the top counts its tree's addresses once, and its children below add nothing.
    expect(use.v4.used).toBe(10n);
    expect(use.v6.used).toBe(7n);
  });

  it("counts a number that is not an integer as zero", () => {
    expect(familyUse([tree("192.0.2.0/24", 0, "network", "n/a")]).v4.used).toBe(0n);
  });
});

const user = (id: string): Principal => ({ kind: "user", id, session: "session-1", strength: "password" }) as unknown as Principal;
const token = (id: string): Principal => ({ kind: "token", id, owner: "user-1" }) as unknown as Principal;
const system = (component: string, onBehalfOf?: string | null): Principal =>
  ({ kind: "system", component, ...(onBehalfOf === undefined ? {} : { on_behalf_of: onBehalfOf }) }) as unknown as Principal;
const node = (id: number): Principal => ({ kind: "node", id }) as unknown as Principal;

function record(seq: number, action: string, principal: Principal): AuditRecord {
  return { seq, principal, draft: { action, outcome: "success" } } as unknown as AuditRecord;
}

describe("isSystem", () => {
  it("is true for a component acting on its own", () => {
    expect(isSystem(system("reconciler"))).toBe(true);
    expect(isSystem(system("reconciler", null))).toBe(true);
  });

  it("is false for a component acting on behalf of a person", () => {
    expect(isSystem(system("jobs", "user-1"))).toBe(false);
  });

  it("is true for a node", () => {
    expect(isSystem(node(1001))).toBe(true);
  });

  it("is false for a user and a token", () => {
    expect(isSystem(user("user-1"))).toBe(false);
    expect(isSystem(token("token-1"))).toBe(false);
  });
});

describe("groupChanges", () => {
  const all = { system: true, limit: 10 };
  const seqs = (groups: ReturnType<typeof groupChanges>) => groups.map((g) => [g.record.seq, g.count]);

  it("is empty without records", () => {
    expect(groupChanges([], all)).toEqual([]);
  });

  it("groups records next to each other with the same action by the same principal, the newest as the entry", () => {
    const records = [
      record(5, "address.create", user("user-1")),
      record(4, "address.create", user("user-1")),
      record(3, "address.create", user("user-1")),
      record(2, "prefix.update", user("user-1")),
    ];
    expect(seqs(groupChanges(records, all))).toEqual([
      [5, 3],
      [2, 1],
    ]);
  });

  it("keeps two actions by the same principal apart", () => {
    const records = [record(3, "address.create", user("user-1")), record(2, "address.delete", user("user-1")), record(1, "address.create", user("user-1"))];
    expect(seqs(groupChanges(records, all))).toEqual([
      [3, 1],
      [2, 1],
      [1, 1],
    ]);
  });

  it("breaks a run when another principal comes in between", () => {
    const records = [record(3, "address.create", user("user-1")), record(2, "address.create", user("user-2")), record(1, "address.create", user("user-1"))];
    expect(seqs(groupChanges(records, all))).toEqual([
      [3, 1],
      [2, 1],
      [1, 1],
    ]);
  });

  it("tells principals of different kinds, components and nodes apart even with the same id", () => {
    const records = [
      record(6, "x.run", user("7")),
      record(5, "x.run", token("7")),
      record(4, "x.run", system("jobs")),
      record(3, "x.run", system("reconciler")),
      record(2, "x.run", node(7)),
      record(1, "x.run", node(8)),
    ];
    expect(groupChanges(records, all)).toHaveLength(6);
    expect(groupChanges([record(2, "x.run", system("jobs")), record(1, "x.run", system("jobs"))], all)).toHaveLength(1);
    expect(groupChanges([record(2, "x.run", node(7)), record(1, "x.run", node(7))], all)).toHaveLength(1);
  });

  it("leaves Tenko's own changes out without the system switch, and then groups across the removed ones", () => {
    const records = [
      record(4, "address.create", user("user-1")),
      record(3, "address.create", system("reconciler")),
      record(2, "address.create", node(1001)),
      record(1, "address.create", user("user-1")),
    ];
    expect(seqs(groupChanges(records, { system: false, limit: 10 }))).toEqual([[4, 2]]);
    expect(seqs(groupChanges(records, all))).toEqual([
      [4, 1],
      [3, 1],
      [2, 1],
      [1, 1],
    ]);
  });

  it("keeps a change made by a component on behalf of a person when the system switch is off", () => {
    const records = [record(2, "job.run", system("jobs", "user-1")), record(1, "job.run", system("jobs"))];
    expect(seqs(groupChanges(records, { system: false, limit: 10 }))).toEqual([[2, 1]]);
  });

  it("caps the entries at the limit", () => {
    const records = [record(4, "a.one", user("user-1")), record(3, "a.two", user("user-1")), record(2, "a.three", user("user-1")), record(1, "a.four", user("user-1"))];
    expect(seqs(groupChanges(records, { system: true, limit: 2 }))).toEqual([
      [4, 1],
      [3, 1],
    ]);
  });

  it("counts a record that continues the last entry even after the limit is reached", () => {
    const records = [
      record(5, "a.one", user("user-1")),
      record(4, "a.two", user("user-1")),
      record(3, "a.two", user("user-1")),
      record(2, "a.three", user("user-1")),
    ];
    expect(seqs(groupChanges(records, { system: true, limit: 2 }))).toEqual([
      [5, 1],
      [4, 2],
    ]);
  });
});
