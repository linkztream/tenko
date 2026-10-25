// The IPAM data a scenario starts with: a home network in the documentation ranges (RFC 5737
// and RFC 3849 addresses, RFC 7042 MAC addresses, names under example.test), the history of
// every object and the alarm levels. Times are offsets from "now". Seeding writes the state
// and the history directly; it records no audit entry and no job.
import type {
  Address,
  AssignmentMode,
  CustomFieldDef,
  CustomValue,
  HistoryEntry,
  Host,
  Interface,
  IpamObject,
  Meta,
  Prefix,
  Principal,
  Range,
  Site,
  Stamp,
  Tenant,
  Vlan,
  Vrf,
} from "../../types";
import { db } from "../db";
import { MOCK_USER_IDS } from "../fixtures";
import { DAY_MS, iso } from "../util";
import { emptyData, objectOf, type IpamData, type IpamStore, type Kind, type KindTypes } from "./state";
import { allLevels } from "./tree";
import { diffObjects } from "./workspace";

// ---------------------------------------------------------------------------------
// Identifiers

const BASE = "0190d1c2-0000-7000-8000-0000000";

/**
 * A fixed identifier: seven zeros, a group digit and four hex digits of the number. The
 * groups: 1 tenants, 2 VRFs, 3 sites, 4 VLANs, 5 ranges, 6 interfaces, 7 addresses, 8 custom
 * fields, 9 requests of the history, a prefixes, b hosts. The prefixes of the audit seed
 * (a0001 to a0003), its hosts (b0001 to b0004) and its address 192.0.2.35 (a0135) keep the
 * identifiers audit-store.ts and job-store.ts use for them.
 */
function uid(group: string, n: number): string {
  return `${BASE}${group}${n.toString(16).padStart(4, "0")}`;
}

/** The fixed identifiers of the seed, so tests can refer to them. */
export const IPAM_IDS = {
  tenant: { default: uid("1", 1), workshop: uid("1", 2) },
  vrf: { default: uid("2", 1), isolated: uid("2", 2) },
  site: { home: uid("3", 1), garage: uid("3", 2), lab: uid("3", 3) },
  vlan: { v10: uid("4", 10), v20: uid("4", 20), v30: uid("4", 30), v40: uid("4", 40), v50: uid("4", 50), v99: uid("4", 99) },
  prefix: {
    /** 192.0.2.0/24, the LAN. */
    lan: uid("a", 1),
    /** 198.51.100.0/24, IoT. */
    iot: uid("a", 2),
    /** 203.0.113.0/24, the supernet of the next three. */
    documentation: uid("a", 4),
    /** 203.0.113.0/25. */
    lab: uid("a", 3),
    /** 203.0.113.128/26. */
    dmz: uid("a", 5),
    /** 203.0.113.192/28, critical. */
    cameras: uid("a", 6),
    /** 2001:db8::/32, the IPv6 supernet. */
    v6: uid("a", 7),
    /** 2001:db8:0:10::/64. */
    lanV6: uid("a", 8),
    /** 2001:db8:0:30::/64. */
    iotV6: uid("a", 9),
    /** 2001:db8:0:99::/64, deleted two days ago. */
    managementV6: uid("a", 10),
    /** 192.0.2.0/24 in the VRF isolated. */
    workshop: uid("a", 11),
  },
  range: {
    infrastructure: uid("5", 1),
    pool: uid("5", 2),
    iotPool: uid("5", 3),
    /** 2001:db8:0:10::100 to 2001:db8:0:10::1ff, the pool of the DHCPv6 scope on the v6 LAN (WP9.4). */
    lanV6Pool: uid("5", 4),
  },
  field: { assetTag: uid("8", 1), rack: uid("8", 2), warrantyUntil: uid("8", 3) },
} as const;

/** Host identifiers by host name (live hosts and the deleted `old-printer`). */
export const HOST_IDS: Record<string, string> = {};
/** The identifier of the interface `eth0` of each host, by host name. */
export const INTERFACE_IDS: Record<string, string> = {};
/** Address identifiers by address; the VRF isolated ones are keyed `isolated:<address>`. */
export const ADDRESS_IDS: Record<string, string> = {};

// ---------------------------------------------------------------------------------
// Builders

const ALEX: Principal = {
  kind: "user",
  id: MOCK_USER_IDS.alex,
  session: "0190d1c2-0000-7000-8000-0000000e0001",
  strength: "passkey",
};

const text = (value: string): CustomValue => ({ type: "text", value });

interface MetaOptions {
  /** Days since creation (default 30). */
  created?: number;
  /** Days since the last update (default: the creation). */
  updated?: number;
  /** Days since the soft delete. */
  deleted?: number;
  tags?: string[];
  description?: string;
  custom?: Record<string, CustomValue>;
}

function makeMeta(now: number, options: MetaOptions = {}): Meta {
  const created = options.created ?? 30;
  const stamp = (days: number): Stamp => ({ at: iso(now - days * DAY_MS), by: ALEX });
  return {
    revision: db.revision,
    created: stamp(created),
    updated: stamp(options.updated ?? options.deleted ?? created),
    deleted: options.deleted === undefined ? null : stamp(options.deleted),
    tags: options.tags ?? [],
    custom: options.custom ?? {},
    description: options.description ?? null,
  };
}

interface SeedHost {
  name: string;
  /** The IPv4 address in the VRF default. */
  ip: string;
  mode: AssignmentMode;
  /** The last MAC octet in hex; null for an interface without a MAC. */
  mac: string | null;
  lock?: boolean;
  site?: string;
  tags?: string[];
  custom?: Record<string, CustomValue>;
  description?: string;
}

/** The hosts the seed jobs and audit records name (job-store.ts MOCK_HOST_IDS). */
const HOST_FIXED: Readonly<Record<string, string>> = {
  "thermostat-1": uid("b", 1),
  "plug-kitchen": uid("b", 2),
  "cam-door": uid("b", 3),
  nas: uid("b", 4),
};

const LAN_HOSTS: SeedHost[] = [
  { name: "gw", ip: "192.0.2.1", mode: "static", mac: "01", description: "Internet gateway" },
  { name: "sw-core", ip: "192.0.2.2", mode: "static", mac: "02" },
  { name: "sw-desk", ip: "192.0.2.3", mode: "static", mac: "03" },
  { name: "ap-hall", ip: "192.0.2.4", mode: "reserved", mac: "04" },
  { name: "ap-garage", ip: "192.0.2.5", mode: "reserved", mac: "05", site: IPAM_IDS.site.garage },
  { name: "pve1", ip: "192.0.2.10", mode: "static", mac: "0a" },
  {
    name: "nas",
    ip: "192.0.2.11",
    mode: "reserved",
    mac: "0b",
    lock: true,
    tags: ["infra"],
    custom: { asset_tag: text("A-0042") },
    description: "Storage server",
  },
  { name: "ha", ip: "192.0.2.12", mode: "reserved", mac: "0c" },
  { name: "tenko1", ip: "192.0.2.13", mode: "static", mac: "0d" },
  { name: "tenko2", ip: "192.0.2.14", mode: "static", mac: "0e" },
  { name: "tenko3", ip: "192.0.2.15", mode: "static", mac: "0f" },
  { name: "laptop-ak", ip: "192.0.2.20", mode: "dynamic", mac: "14" },
  { name: "printer-1", ip: "192.0.2.30", mode: "static", mac: "1e", tags: ["printer"] },
  { name: "thermostat-1", ip: "192.0.2.41", mode: "reserved", mac: "29", tags: ["iot"] },
  { name: "plug-kitchen", ip: "192.0.2.42", mode: "reserved", mac: "2a", tags: ["iot"] },
  { name: "cam-door", ip: "192.0.2.43", mode: "reserved", mac: "2b", tags: ["camera", "iot"] },
  { name: "speaker-den", ip: "192.0.2.44", mode: "reserved", mac: "2c", tags: ["iot"] },
  { name: "tv-living", ip: "192.0.2.57", mode: "dynamic", mac: "39" },
  { name: "doorbell", ip: "192.0.2.60", mode: "reserved", mac: null, tags: ["iot"], description: "No MAC known yet" },
  { name: "legacy-ups", ip: "192.0.2.250", mode: "unmanaged", mac: "fa" },
];

const IOT_HOSTS: SeedHost[] = [
  { name: "gw-iot", ip: "198.51.100.1", mode: "static", mac: "a1" },
  { name: "sensor-garage", ip: "198.51.100.44", mode: "reserved", mac: "a2" },
];

const CAMERA_HOSTS: SeedHost[] = Array.from({ length: 13 }, (_, index) => ({
  name: `cam-${String(index + 1).padStart(2, "0")}`,
  ip: `203.0.113.${193 + index}`,
  mode: "reserved" as const,
  mac: (193 + index).toString(16),
}));

// ---------------------------------------------------------------------------------
// The seed

/** How an object looked when it was created, for the first history entry. */
type Override = (copy: IpamObject) => void;

function description(copy: IpamObject, value: string): void {
  (copy.data as { meta: Meta }).meta.description = value;
}

/** Builds the seeded state, history and alarm levels at `now`. */
export function buildSeed(now: number): IpamStore {
  const data: IpamData = emptyData();
  const history = new Map<string, HistoryEntry[]>();
  const overrides = new Map<string, Override>();
  const later: { id: string; days: number }[] = [];
  let requests = 0;

  const add = <K extends Kind>(kind: K, value: KindTypes[K]): void => {
    (data[kind] as Map<string, KindTypes[K]>).set((value as { id: string }).id, value);
  };
  const entry = (object: IpamObject, action: HistoryEntry["action"], daysAgo: number, before: IpamObject | null): HistoryEntry => {
    const id = (object.data as { id: string }).id;
    requests += 1;
    const changes = diffObjects(before, object);
    return {
      object: { kind: object.kind, id },
      action,
      at: iso(now - daysAgo * DAY_MS),
      by: ALEX,
      request: uid("9", requests),
      ...(before ? { before: structuredClone(before) } : {}),
      after: structuredClone(object),
      ...(changes.length > 0 ? { changes } : {}),
      job_kind: "ipam.apply",
      revision: db.revision,
    };
  };

  // Tenants, VRFs and sites.
  const tenants: Tenant[] = [
    { id: IPAM_IDS.tenant.default, name: "default", meta: makeMeta(now) },
    { id: IPAM_IDS.tenant.workshop, name: "Workshop", meta: makeMeta(now, { description: "Hobby workshop network" }) },
  ];
  tenants.forEach((t) => add("tenant", t));
  const vrfs: Vrf[] = [
    { id: IPAM_IDS.vrf.default, tenant: IPAM_IDS.tenant.default, name: "default", rd: null, meta: makeMeta(now) },
    { id: IPAM_IDS.vrf.isolated, tenant: IPAM_IDS.tenant.workshop, name: "isolated", rd: null, meta: makeMeta(now) },
  ];
  vrfs.forEach((v) => add("vrf", v));
  const sites: Site[] = [
    { id: IPAM_IDS.site.home, name: "Home", parent: null, ad_site: "Default-First-Site-Name", meta: makeMeta(now) },
    { id: IPAM_IDS.site.garage, name: "Garage", parent: IPAM_IDS.site.home, ad_site: null, meta: makeMeta(now) },
    { id: IPAM_IDS.site.lab, name: "Lab", parent: null, ad_site: null, meta: makeMeta(now) },
  ];
  sites.forEach((s) => add("site", s));

  // VLANs.
  const vlan = (key: keyof typeof IPAM_IDS.vlan, vid: number, name: string, site: string, status: Vlan["status"] = "active"): Vlan => ({
    id: IPAM_IDS.vlan[key],
    vid,
    vni: null,
    name,
    site,
    status,
    meta: makeMeta(now),
  });
  [
    vlan("v10", 10, "LAN", IPAM_IDS.site.home),
    vlan("v20", 20, "Lab", IPAM_IDS.site.lab),
    vlan("v30", 30, "IoT", IPAM_IDS.site.home),
    vlan("v40", 40, "DMZ", IPAM_IDS.site.home),
    vlan("v99", 99, "Management", IPAM_IDS.site.home),
    vlan("v50", 50, "Guest", IPAM_IDS.site.home, "planned"),
  ].forEach((v) => add("vlan", v));

  // Custom field definitions.
  const fields: CustomFieldDef[] = [
    { id: IPAM_IDS.field.assetTag, key: "asset_tag", kind: { type: "text" }, applies_to: ["host"], required: false },
    {
      id: IPAM_IDS.field.rack,
      key: "rack",
      kind: { type: "select", options: ["A1", "A2", "B1"] },
      applies_to: ["host", "prefix"],
      required: false,
    },
    { id: IPAM_IDS.field.warrantyUntil, key: "warranty_until", kind: { type: "date" }, applies_to: ["host"], required: false },
  ];
  fields.forEach((f) => {
    add("custom_field", f);
    data.fieldRevisions.set(f.id, db.revision);
  });

  // Prefixes.
  const prefix = (
    id: string,
    cidr: string,
    role: Prefix["role"],
    options: {
      vrf?: string;
      vlan?: string;
      site?: string;
      alarm?: { warn_pct: number; crit_pct: number };
      meta?: MetaOptions;
    },
  ): Prefix => ({
    id,
    vrf: options.vrf ?? IPAM_IDS.vrf.default,
    cidr,
    role,
    status: "active",
    vlan: options.vlan ?? null,
    site: options.site ?? null,
    alarm: options.alarm ?? null,
    alloc: "lowest",
    meta: makeMeta(now, options.meta),
  });
  const P = IPAM_IDS.prefix;
  const lan = prefix(P.lan, "192.0.2.0/24", "network", {
    vlan: IPAM_IDS.vlan.v10,
    site: IPAM_IDS.site.home,
    alarm: { warn_pct: 80, crit_pct: 95 },
    meta: { description: "LAN", tags: ["home"], updated: 5 },
  });
  overrides.set(P.lan, (copy) => description(copy, "Home LAN"));
  later.push({ id: P.lan, days: 5 });
  [
    lan,
    prefix(P.iot, "198.51.100.0/24", "network", {
      vlan: IPAM_IDS.vlan.v30,
      site: IPAM_IDS.site.home,
      meta: { description: "IoT" },
    }),
    prefix(P.documentation, "203.0.113.0/24", "supernet", { meta: { description: "Documentation supernet" } }),
    prefix(P.lab, "203.0.113.0/25", "network", {
      vlan: IPAM_IDS.vlan.v20,
      site: IPAM_IDS.site.lab,
      meta: { description: "Lab" },
    }),
    prefix(P.dmz, "203.0.113.128/26", "network", {
      vlan: IPAM_IDS.vlan.v40,
      site: IPAM_IDS.site.home,
      meta: { description: "DMZ" },
    }),
    prefix(P.cameras, "203.0.113.192/28", "network", {
      alarm: { warn_pct: 70, crit_pct: 90 },
      meta: { description: "Cameras" },
    }),
    prefix(P.v6, "2001:db8::/32", "supernet", { meta: { description: "IPv6 supernet" } }),
    prefix(P.lanV6, "2001:db8:0:10::/64", "network", {
      vlan: IPAM_IDS.vlan.v10,
      site: IPAM_IDS.site.home,
      meta: { description: "LAN v6" },
    }),
    prefix(P.iotV6, "2001:db8:0:30::/64", "network", {
      vlan: IPAM_IDS.vlan.v30,
      site: IPAM_IDS.site.home,
      meta: { description: "IoT v6" },
    }),
    prefix(P.managementV6, "2001:db8:0:99::/64", "network", {
      vlan: IPAM_IDS.vlan.v99,
      meta: { description: "Management v6", deleted: 2 },
    }),
    prefix(P.workshop, "192.0.2.0/24", "network", {
      vrf: IPAM_IDS.vrf.isolated,
      meta: { description: "Workshop LAN" },
    }),
  ].forEach((p) => add("prefix", p));

  // Ranges.
  const range = (id: string, prefixId: string, first: string, last: string, role: Range["role"], lease?: number): Range => ({
    id,
    prefix: prefixId,
    first,
    last,
    role,
    ...(lease === undefined ? {} : { lease_secs: lease }),
    status: "active",
    meta: makeMeta(now),
  });
  [
    range(IPAM_IDS.range.infrastructure, P.lan, "192.0.2.1", "192.0.2.19", "infrastructure"),
    range(IPAM_IDS.range.pool, P.lan, "192.0.2.100", "192.0.2.199", "dhcp_pool", 86_400),
    range(IPAM_IDS.range.iotPool, P.iot, "198.51.100.100", "198.51.100.199", "dhcp_pool", 3_600),
    // WP9.4: the pool of the seeded DHCPv6 scope.
    range(IPAM_IDS.range.lanV6Pool, P.lanV6, "2001:db8:0:10::100", "2001:db8:0:10::1ff", "dhcp_pool"),
  ].forEach((r) => add("range", r));

  // Hosts, interfaces and addresses.
  let index = 0;
  const addHost = (item: SeedHost, vrf: string, prefixId: string, deleted?: number): void => {
    index += 1;
    const hostId = HOST_FIXED[item.name] ?? uid("b", 0x10 + index);
    const interfaceId = uid("6", index);
    const addressId = item.ip === "192.0.2.35" ? uid("a", 0x135) : uid("7", index);
    HOST_IDS[item.name] = hostId;
    INTERFACE_IDS[item.name] = interfaceId;
    ADDRESS_IDS[item.ip] = addressId;
    const meta = (extra: MetaOptions = {}): Meta => makeMeta(now, { ...(deleted === undefined ? {} : { deleted }), ...extra });
    const host: Host = {
      id: hostId,
      tenant: IPAM_IDS.tenant.default,
      name: item.name,
      mode: item.mode,
      lock: item.lock ?? false,
      site: item.site ?? null,
      meta: meta({
        ...(item.tags ? { tags: item.tags } : {}),
        ...(item.custom ? { custom: item.custom } : {}),
        ...(item.description ? { description: item.description } : {}),
      }),
    };
    const iface: Interface = {
      id: interfaceId,
      host: hostId,
      name: "eth0",
      mac: item.mac === null ? null : `00:00:5e:00:53:${item.mac}`,
      duid: null,
      client_id: null,
      meta: meta(),
    };
    const address: Address = {
      id: addressId,
      vrf,
      ip: item.ip,
      prefix: prefixId,
      status: "active",
      interface: interfaceId,
      dns_name: `${item.name}.example.test`,
      meta: meta(),
    };
    add("host", host);
    add("interface", iface);
    add("address", address);
  };
  LAN_HOSTS.forEach((h) => addHost(h, IPAM_IDS.vrf.default, P.lan));
  IOT_HOSTS.forEach((h) => addHost(h, IPAM_IDS.vrf.default, P.iot));
  CAMERA_HOSTS.forEach((h) => addHost(h, IPAM_IDS.vrf.default, P.cameras));

  // gw also has an IPv6 address on the same interface.
  const gwV6: Address = {
    id: uid("7", 900),
    vrf: IPAM_IDS.vrf.default,
    ip: "2001:db8:0:10::1",
    prefix: P.lanV6,
    status: "active",
    interface: INTERFACE_IDS.gw ?? null,
    dns_name: "gw.example.test",
    meta: makeMeta(now),
  };
  ADDRESS_IDS["2001:db8:0:10::1"] = gwV6.id;
  add("address", gwV6);

  // The deleted host with its interface and address, deleted together two days ago.
  addHost({ name: "old-printer", ip: "192.0.2.35", mode: "static", mac: "23" }, IPAM_IDS.vrf.default, P.lan, 2);

  // The VRF isolated: two addresses that exist in the VRF default as well.
  const bench = (n: number, ip: string): Address => ({
    id: uid("7", 910 + n),
    vrf: IPAM_IDS.vrf.isolated,
    ip,
    prefix: P.workshop,
    status: "active",
    interface: null,
    dns_name: `bench-${n}.example.test`,
    meta: makeMeta(now),
  });
  [bench(1, "192.0.2.10"), bench(2, "192.0.2.20")].forEach((a) => {
    ADDRESS_IDS[`isolated:${a.ip}`] = a.id;
    add("address", a);
  });

  // nas was a static host until three days ago.
  const nas = data.host.get(HOST_IDS.nas ?? "");
  if (nas) {
    nas.meta.updated = { at: iso(now - 3 * DAY_MS), by: ALEX };
    overrides.set(nas.id, (copy) => {
      (copy.data as Host).mode = "static";
    });
    later.push({ id: nas.id, days: 3 });
  }

  // History: a create entry for every object, then the later changes.
  const kinds: Kind[] = ["tenant", "vrf", "site", "vlan", "prefix", "range", "address", "host", "interface", "custom_field"];
  for (const kind of kinds) {
    for (const value of (data[kind] as Map<string, KindTypes[Kind]>).values()) {
      const final = objectOf(kind, value as never);
      const id = (value as { id: string }).id;
      const created = structuredClone(final);
      const meta = kind === "custom_field" ? null : (created.data as { meta: Meta }).meta;
      if (meta) {
        meta.updated = meta.created;
        meta.deleted = null;
      }
      overrides.get(id)?.(created);
      const list: HistoryEntry[] = [entry(created, "create", 30, null)];
      const update = later.find((l) => l.id === id);
      if (update) list.push(entry(final, "update", update.days, created));
      const deletedAt = meta === null ? null : (final.data as { meta: Meta }).meta.deleted;
      if (deletedAt) {
        const days = Math.round((now - Date.parse(deletedAt.at)) / DAY_MS);
        list.push(entry(final, "delete", days, list[list.length - 1]?.after ?? created));
      }
      history.set(id, list);
    }
  }

  return { data, history, levels: new Map([...allLevels(data)].map(([id, value]) => [id, value.level])) };
}
