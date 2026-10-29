import { beforeEach, describe, expect, it } from "vitest";
import { setLocale } from "../i18n";
import type { NodeKind, TopologyNode, VlanInView } from "./api";
import {
  bandWord,
  EDGE_KINDS,
  edgeBucket,
  edgeClass,
  edgeWord,
  EMPTY_FILTER,
  filterKey,
  filterParams,
  filterSearch,
  groupBucket,
  groupParent,
  isFiltered,
  isGroupId,
  isHashedName,
  kindIcon,
  kindWord,
  mapReadOnly,
  NODE_KINDS,
  nodeAriaLabel,
  nodeSecondLine,
  parseFilter,
  portStateWord,
  portTitle,
  selectedVid,
  SHAPES,
  shortLabel,
  sourceWord,
  toggleKind,
  topologyPath,
  unplacedDevices,
  VLAN_COLOR_LIMIT,
  vlanColorIds,
  vidOf,
  viewOf,
} from "./model";

beforeEach(async () => {
  await setLocale("en");
});

const VLAN_OBJECT = "7a8d4b1e-3c2f-4e59-9a61-0b1c2d3e4f50";

/** `count` VLANs in view, VLAN ids 1 to count, in a scrambled order. */
function manyVlans(count: number): VlanInView[] {
  const vlans: VlanInView[] = [];
  for (let vid = 1; vid <= count; vid += 1) vlans.push({ vid, nodes: 1 });
  return vlans.sort((a, b) => ((a.vid * 7919) % 101) - ((b.vid * 7919) % 101));
}

describe("the words of kinds and edges", () => {
  it("has a word, an icon and a distinct shape for every node kind", () => {
    expect(NODE_KINDS).toHaveLength(8);
    const words = NODE_KINDS.map(kindWord);
    expect(words).toEqual(["Router", "Switch", "Access point", "Hypervisor", "Virtual machine", "Container", "Host", "Other device"]);
    expect(new Set(words).size).toBe(NODE_KINDS.length);
    expect(new Set(NODE_KINDS.map(kindIcon)).size).toBe(NODE_KINDS.length);
    const shapes = [...NODE_KINDS, "group" as const].map((k) => SHAPES[k]);
    expect(new Set(shapes).size).toBe(shapes.length);
    for (const shape of shapes) expect(shape).toMatch(/^M-?\d/);
  });

  it("has a word and a line class for every edge kind", () => {
    expect(EDGE_KINDS).toEqual(["uplink", "wired", "wireless", "lldp", "vm_host"]);
    expect(EDGE_KINDS.map(edgeWord)).toEqual(["Uplink", "Wired", "Wireless", "LLDP link", "Hosted on hypervisor"]);
    for (const kind of EDGE_KINDS) expect(edgeClass(kind)).toBe(`topology-edge edge-${kind}`);
  });

  it("names a device by its label and kind", () => {
    expect(nodeAriaLabel({ label: "sw-core", kind: "switch" })).toBe("sw-core, Switch");
    expect(nodeAriaLabel({ label: "ap-hall", kind: "access_point" })).toBe("ap-hall, Access point");
  });

  it("says the source of a fact in words and keeps what it does not know", () => {
    expect(sourceWord("intent")).toBe("Intent");
    expect(sourceWord("network_controller:5b0a5e4c-0001")).toBe("Network controller");
    expect(sourceWord("probe:1:snmp")).toBe("Probe");
    expect(sourceWord("inventory:abc")).toBe("Inventory");
    expect(sourceWord("custom:thing")).toBe("custom:thing");
  });

  it("says the link state and the name of a port", () => {
    expect(portStateWord(true)).toBe("Link up");
    expect(portStateWord(false)).toBe("Link down");
    expect(portStateWord(null)).toBe("Link state unknown");
    expect(portStateWord(undefined)).toBe("Link state unknown");
    expect(portTitle({ port: "3", name: "Port 3" })).toBe("3 (Port 3)");
    expect(portTitle({ port: "eth0", name: "eth0" })).toBe("eth0");
    expect(portTitle({ port: "7" })).toBe("7");
  });

  it("cuts a long label and keeps a short one", () => {
    expect(shortLabel("sw-core")).toBe("sw-core");
    expect(shortLabel("a".repeat(20))).toBe("a".repeat(20));
    expect(shortLabel("b".repeat(30))).toBe(`${"b".repeat(19)}…`);
    expect(shortLabel("abcdef", 4)).toBe("abc…");
  });

  it("tells a group from a device and finds its parent", () => {
    expect(isGroupId("group:h-1")).toBe(true);
    expect(isGroupId("h-1")).toBe(false);
    expect(groupParent("group:h-1")).toBe("h-1");
    expect(groupParent("h-1")).toBe("h-1");
  });

  it("reads the port or SSID of a group id and leaves a group of a whole parent without one", () => {
    expect(groupParent("group:h-1#iot.example.test")).toBe("h-1");
    expect(groupBucket("group:h-1#iot.example.test")).toBe("iot.example.test");
    expect(groupBucket("group:h-1#7")).toBe("7");
    expect(groupBucket("group:h-1")).toBeUndefined();
    expect(groupBucket("h-1")).toBeUndefined();
    // Only the first separator counts: a bucket may hold one itself.
    expect(groupParent("group:h-1#guest#2")).toBe("h-1");
    expect(groupBucket("group:h-1#guest#2")).toBe("guest#2");
    expect(isGroupId("group:h-1#7")).toBe(true);
  });
});

describe("the filter in the URL", () => {
  it("reads an empty query as no filter", () => {
    expect(parseFilter({})).toEqual(EMPTY_FILTER);
    expect(isFiltered(parseFilter({}))).toBe(false);
    expect(filterSearch(EMPTY_FILTER)).toBe("");
  });

  it("reads the site, the VLAN id, the kinds and the text", () => {
    const filter = parseFilter({ site: "5e0c1a2b", vlan: "30", kind: "switch,router", q: "  hall  " });
    expect(filter).toEqual({ site: "5e0c1a2b", vlan: "30", kinds: ["router", "switch"], q: "hall" });
    expect(isFiltered(filter)).toBe(true);
  });

  it("reads the identifier of a VLAN object too", () => {
    expect(parseFilter({ vlan: VLAN_OBJECT }).vlan).toBe(VLAN_OBJECT);
    expect(parseFilter({ vlan: VLAN_OBJECT.toUpperCase() }).vlan).toBe(VLAN_OBJECT.toUpperCase());
  });

  it("ignores what it does not know", () => {
    expect(parseFilter({ vlan: "0" }).vlan).toBeUndefined();
    expect(parseFilter({ vlan: "4095" }).vlan).toBeUndefined();
    expect(parseFilter({ vlan: "abc" }).vlan).toBeUndefined();
    expect(parseFilter({ vlan: "30,40" }).vlan).toBeUndefined();
    expect(parseFilter({ kind: "toaster,host,,HOST" }).kinds).toEqual(["host"]);
    expect(parseFilter({ kind: "" }).kinds).toEqual([]);
    // A repeated parameter counts as absent.
    expect(parseFilter({ site: ["a", "b"], q: ["x", "y"], vlan: ["10", "20"], kind: ["host", "vm"] })).toEqual(EMPTY_FILTER);
    expect(parseFilter({ q: "   " }).q).toBe("");
  });

  it("lists kinds once each, in the order of the filter bar", () => {
    expect(parseFilter({ kind: "device,vm,router,vm" }).kinds).toEqual(["router", "vm", "device"]);
  });

  it("writes the filter back in a stable order", () => {
    const filter = parseFilter({ q: "hall", kind: "switch,router", vlan: "30", site: "5e0c1a2b" });
    expect(filterParams(filter)).toEqual({ site: "5e0c1a2b", vlan: "30", kind: "router,switch", q: "hall" });
    expect(filterSearch(filter)).toBe("?site=5e0c1a2b&vlan=30&kind=router%2Cswitch&q=hall");
    // What is not set leaves the URL: the values are undefined.
    expect(filterParams(EMPTY_FILTER)).toEqual({ site: undefined, vlan: undefined, kind: undefined, q: undefined });
    expect(filterSearch({ ...EMPTY_FILTER, vlan: "30" })).toBe("?vlan=30");
  });

  it("round-trips through the URL", () => {
    const filter = { site: "5e0c1a2b", vlan: VLAN_OBJECT, kinds: ["access_point", "host"] satisfies NodeKind[], q: "iot" };
    const search = new URLSearchParams(filterSearch(filter));
    const back = parseFilter(Object.fromEntries(search));
    expect(back).toEqual(filter);
    expect(filterKey(back)).toBe(filterKey(filter));
  });

  it("gives equal filters one key and different filters different keys", () => {
    const a = parseFilter({ kind: "vm,host" });
    const b = parseFilter({ kind: "host,vm" });
    expect(filterKey(a)).toBe(filterKey(b));
    expect(filterKey(a)).not.toBe(filterKey(parseFilter({ kind: "host" })));
    expect(filterKey(EMPTY_FILTER)).toBe("");
  });

  it("switches a kind on and off", () => {
    expect(toggleKind([], "switch")).toEqual(["switch"]);
    expect(toggleKind(["switch"], "router")).toEqual(["router", "switch"]);
    expect(toggleKind(["router", "switch"], "router")).toEqual(["switch"]);
    expect(toggleKind(["switch"], "switch")).toEqual([]);
  });

  it("reads a VLAN id", () => {
    expect(vidOf("1")).toBe(1);
    expect(vidOf("4094")).toBe(4094);
    expect(vidOf("4095")).toBeUndefined();
    expect(vidOf("0")).toBeUndefined();
    expect(vidOf("01x")).toBeUndefined();
    expect(vidOf(undefined)).toBeUndefined();
  });
});

describe("which VLANs get a color", () => {
  it("colors every VLAN in view below the limit, ascending, once each", () => {
    const vlans: VlanInView[] = [
      { vid: 30, nodes: 2 },
      { vid: 10, nodes: 5 },
      { vid: 30, nodes: 1 },
      { vid: 20, nodes: 3 },
    ];
    expect(vlanColorIds(vlans, undefined)).toEqual([10, 20, 30]);
    // The filter does not matter while there are few VLANs.
    expect(vlanColorIds(vlans, "20")).toEqual([10, 20, 30]);
  });

  it("colors every VLAN at 149 and none but the chosen one at 150", () => {
    expect(VLAN_COLOR_LIMIT).toBe(150);
    expect(vlanColorIds(manyVlans(149), undefined)).toHaveLength(149);
    expect(vlanColorIds(manyVlans(149), "7")).toHaveLength(149);
    expect(vlanColorIds(manyVlans(150), undefined)).toEqual([]);
    expect(vlanColorIds(manyVlans(150), "42")).toEqual([42]);
    expect(vlanColorIds(manyVlans(300), "42")).toEqual([42]);
  });

  it("finds the chosen VLAN when the filter holds a VLAN object", () => {
    const vlans = manyVlans(200).map((v) => (v.vid === 77 ? { ...v, vlan: VLAN_OBJECT } : v));
    expect(selectedVid(VLAN_OBJECT, vlans)).toBe(77);
    expect(vlanColorIds(vlans, VLAN_OBJECT)).toEqual([77]);
    // A VLAN object that is not in view colors nothing.
    expect(vlanColorIds(manyVlans(200), VLAN_OBJECT)).toEqual([]);
    expect(selectedVid(undefined, vlans)).toBeUndefined();
    expect(selectedVid("12", vlans)).toBe(12);
  });

  it("has nothing to color without VLANs", () => {
    expect(vlanColorIds([], undefined)).toEqual([]);
    expect(vlanColorIds([], "10")).toEqual([]);
  });
});

describe("the link of a selected device", () => {
  it("is the topology path with the device and keeps the query string", () => {
    expect(topologyPath()).toBe("/topology");
    expect(topologyPath(undefined, "?vlan=30")).toBe("/topology?vlan=30");
    expect(topologyPath("h-0a1b", "")).toBe("/topology/h-0a1b");
    expect(topologyPath("m-00005e0053d2", "?kind=host")).toBe("/topology/m-00005e0053d2?kind=host");
    expect(topologyPath("group:h-1")).toBe("/topology/group:h-1");
    expect(topologyPath("a b/c")).toBe("/topology/a%20b%2Fc");
  });
});

// ---------------------------------------------------------------------------------
// U7

type Plain = Pick<TopologyNode, "label" | "vendor" | "ips">;

describe("hashed names", () => {
  it("knows the name Tenko makes up from twelve hexadecimal digits", () => {
    expect(isHashedName("host-00005e005301")).toBe(true);
    expect(isHashedName("host-00005E00ABCD")).toBe(true);
    expect(isHashedName("host-00005e005301-2")).toBe(true);
    expect(isHashedName("  host-00005e005301  ")).toBe(true);
  });

  it("refuses a name that says something", () => {
    expect(isHashedName("host-1")).toBe(false);
    expect(isHashedName("host-00005e00530")).toBe(false);
    expect(isHashedName("host-00005e0053011")).toBe(false);
    expect(isHashedName("host-00005e00530g")).toBe(false);
    expect(isHashedName("my-host-00005e005301")).toBe(false);
    expect(isHashedName("nas")).toBe(false);
    expect(isHashedName("")).toBe(false);
  });

  it("gives a hashed name a second line of vendor and first address", () => {
    const node = (extra: Partial<Plain>): Plain => ({ label: "host-00005e005301", ...extra });
    expect(nodeSecondLine(node({ vendor: "Example Devices", ips: ["192.0.2.7", "192.0.2.8"] }))).toBe("Example Devices · 192.0.2.7");
    expect(nodeSecondLine(node({ vendor: "Example Devices" }))).toBe("Example Devices");
    expect(nodeSecondLine(node({ ips: ["2001:db8::7"] }))).toBe("2001:db8::7");
    expect(nodeSecondLine(node({ vendor: "Example Devices", ips: [] }))).toBe("Example Devices");
    // Blank parts are left out, and no part leaves no line.
    expect(nodeSecondLine(node({ vendor: "  ", ips: ["192.0.2.7"] }))).toBe("192.0.2.7");
    expect(nodeSecondLine(node({ vendor: null, ips: [] }))).toBeUndefined();
    expect(nodeSecondLine(node({}))).toBeUndefined();
  });

  it("gives a name that says something no second line", () => {
    expect(nodeSecondLine({ label: "nas", vendor: "Example Devices", ips: ["192.0.2.7"] })).toBeUndefined();
    expect(nodeSecondLine({ label: "Example Devices 00:53:d2", vendor: "Example Devices", ips: [] })).toBeUndefined();
  });
});

describe("the bucket of a client link", () => {
  it("is the SSID of a wireless link and the port of a wired one", () => {
    expect(edgeBucket({ kind: "wireless", ssid: "iot.example.test", a_port: "3" })).toBe("iot.example.test");
    expect(edgeBucket({ kind: "wired", ssid: "iot.example.test", a_port: "3" })).toBe("3");
    expect(edgeBucket({ kind: "wireless", ssid: null, a_port: "3" })).toBeUndefined();
    expect(edgeBucket({ kind: "wired", a_port: null })).toBeUndefined();
    expect(edgeBucket({ kind: "wired" })).toBeUndefined();
  });

  it("is none for a link between network devices or a virtual placement", () => {
    for (const kind of ["uplink", "lldp", "vm_host"] as const) {
      expect(edgeBucket({ kind, ssid: "iot.example.test", a_port: "3" })).toBeUndefined();
    }
  });
});

describe("devices that are not placed", () => {
  const node = (id: string, label: string, ips?: string[]): TopologyNode => ({
    id,
    kind: "host",
    label,
    sources: ["network_controller:test"],
    ...(ips ? { ips } : {}),
  });

  it("lists each unplaced device, in the order given, with no duplicates for a unique one", () => {
    const nodes = [node("a", "alpha", ["192.0.2.1"]), node("b", "beta", ["192.0.2.2"]), node("c", "gamma")];
    expect(unplacedDevices(["b", "a"], nodes)).toEqual([
      { id: "b", duplicates: [] },
      { id: "a", duplicates: [] },
    ]);
    expect(unplacedDevices([], nodes)).toEqual([]);
  });

  it("finds duplicates by label, ignoring case and blanks, and by a shared address", () => {
    const nodes = [
      node("a", "Printer", ["192.0.2.9"]),
      node("b", " printer ", ["192.0.2.10"]),
      node("c", "scanner", ["192.0.2.9", "192.0.2.20"]),
      node("d", "other", ["198.51.100.1"]),
    ];
    expect(unplacedDevices(["a"], nodes)).toEqual([{ id: "a", duplicates: ["b", "c"] }]);
    expect(unplacedDevices(["d"], nodes)).toEqual([{ id: "d", duplicates: [] }]);
    // A device is no duplicate of itself, and the duplicates are in id order.
    expect(unplacedDevices(["c", "b"], nodes)).toEqual([
      { id: "c", duplicates: ["a"] },
      { id: "b", duplicates: ["a"] },
    ]);
  });

  it("leaves out an id the graph does not have", () => {
    expect(unplacedDevices(["gone", "a"], [node("a", "alpha")])).toEqual([{ id: "a", duplicates: [] }]);
  });
});

describe("a read-only map", () => {
  const off = [{ writes_enabled: false }];
  const on = [{ writes_enabled: true }];

  it("is read-only under Hardened while no controller allows writes", () => {
    expect(mapReadOnly("hardened", [])).toBe(true);
    expect(mapReadOnly("hardened", off)).toBe(true);
    expect(mapReadOnly("hardened", [{}])).toBe(true);
    expect(mapReadOnly("hardened", [...off, ...off])).toBe(true);
  });

  it("is writable once one controller allows writes", () => {
    expect(mapReadOnly("hardened", on)).toBe(false);
    expect(mapReadOnly("hardened", [...off, ...on])).toBe(false);
  });

  it("is writable under every other profile, with or without a controller", () => {
    for (const profile of ["standard", "home", "lab", undefined, null, ""]) {
      expect(mapReadOnly(profile, off)).toBe(false);
      expect(mapReadOnly(profile, [])).toBe(false);
    }
  });
});

describe("radio bands and views", () => {
  it("writes a band in words", () => {
    expect(bandWord("2g")).toBe("2.4 GHz");
    expect(bandWord("5g")).toBe("5 GHz");
    expect(bandWord("6g")).toBe("6 GHz");
    expect(bandWord(null)).toBe("");
    expect(bandWord(undefined)).toBe("");
  });

  it("writes a band in Swedish", async () => {
    await setLocale("sv");
    try {
      expect(bandWord("2g")).toBe("2,4 GHz");
    } finally {
      await setLocale("en");
    }
  });

  it("shows the SSID view only when the URL asks for it", () => {
    expect(viewOf("ssids")).toBe("ssids");
    expect(viewOf(undefined)).toBe("map");
    expect(viewOf("map")).toBe("map");
    expect(viewOf("")).toBe("map");
    expect(viewOf("SSIDS")).toBe("map");
    expect(viewOf(["ssids", "map"])).toBe("map");
  });
});
