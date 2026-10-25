// The observation layer and the proposals of the mock (docs/reconciliation.md): a few facts
// of an inventory connector, a network controller and a probe, the proposals the reconciler
// would derive from them, and adoption policies on some prefixes. Everything uses the
// documentation ranges and the IPAM seed (ipam/seed.ts). The state is built when it is first
// read and again after every reset, so it always matches the IPAM seed of the scenario.
import type { components } from "../generated/schema";
import { db, onMockReset } from "./db";
import { ADDRESS_IDS, HOST_IDS, INTERFACE_IDS, IPAM_IDS } from "./ipam/api";
import { MOCK_USER_IDS } from "./fixtures";
import { DAY_MS, HOUR_MS, MINUTE, iso } from "./util";

type S = components["schemas"];
export type ObservedFact = S["ObservedFact"];
export type IntentProposal = S["IntentProposal"];
export type AdoptionPolicy = S["AdoptionPolicy"];
export type Stamp = S["Stamp"];

/** A prefix's own adoption policy, with the revision of its last change. */
export interface StoredPolicy {
  policy: AdoptionPolicy;
  revision: number;
  updated: Stamp;
}

export interface ReconcileState {
  facts: ObservedFact[];
  proposals: Map<string, IntentProposal>;
  policies: Map<string, StoredPolicy>;
}

/** The connectors and the probe node that report the seeded facts. */
export const RECONCILE_IDS = {
  inventory: "0190d1c2-0000-7000-8000-00000c000001",
  controller: "0190d1c2-0000-7000-8000-00000c000002",
  probeNode: 1,
  proposal: {
    mediaPc: "0190d1c2-0000-7000-8000-00000d000001",
    hallSwitchClient: "0190d1c2-0000-7000-8000-00000d000002",
    iotAddress: "0190d1c2-0000-7000-8000-00000d000003",
    thermostat: "0190d1c2-0000-7000-8000-00000d000004",
    outside: "0190d1c2-0000-7000-8000-00000d000005",
    printerTaken: "0190d1c2-0000-7000-8000-00000d000006",
    guestPhone: "0190d1c2-0000-7000-8000-00000d000007",
    speaker: "0190d1c2-0000-7000-8000-00000d000008",
    oldTest: "0190d1c2-0000-7000-8000-00000d000009",
  },
  /** Identifiers the commands of the open proposals give the objects they create. */
  created: {
    mediaPcHost: "0190d1c2-0000-7000-8000-00000d100001",
    mediaPcInterface: "0190d1c2-0000-7000-8000-00000d100002",
    hallClientHost: "0190d1c2-0000-7000-8000-00000d100003",
    hallClientInterface: "0190d1c2-0000-7000-8000-00000d100004",
    iotHost: "0190d1c2-0000-7000-8000-00000d100005",
    iotInterface: "0190d1c2-0000-7000-8000-00000d100006",
  },
} as const;

const REASON_GONE = "the observation behind it no longer holds";

let state: ReconcileState | null = null;

onMockReset(() => {
  state = null;
});

/** The state, built from the seed on first use after a reset. */
export function reconcileState(): ReconcileState {
  if (!state) {
    const empty = db.scenario === "setup" || db.scenario === "setup-slow-disk";
    state = empty ? { facts: [], proposals: new Map(), policies: new Map() } : buildSeed(Date.now(), db.revision);
  }
  return state;
}

/** A stable 64-digit hexadecimal digest of a text (not cryptographic; the mock only compares it). */
export function digestOf(text: string): string {
  let out = "";
  let h = 0x811c9dc5;
  for (let round = 0; round < 8; round++) {
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i) + round;
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    out += h.toString(16).padStart(8, "0");
  }
  return out;
}

/** The system principal of the reconciler. */
export const RECONCILER: S["Principal"] = { kind: "system", component: "reconciler" } as S["Principal"];

function buildSeed(now: number, revision: number): ReconcileState {
  const vrf = IPAM_IDS.vrf.default;
  const ago = (ms: number) => iso(now - ms);
  const later = (ms: number) => iso(now + ms);
  const inventory: S["ObservationSource"] = { type: "inventory", connector: RECONCILE_IDS.inventory };
  const controller: S["ObservationSource"] = { type: "network_controller", connector: RECONCILE_IDS.controller };
  const probe = (method: S["ProbeMethod"]): S["ObservationSource"] => ({ type: "probe", node: RECONCILE_IDS.probeNode, method });
  const sourceKey = (source: S["ObservationSource"]): string => {
    switch (source.type) {
      case "inventory":
        return `inventory:${source.connector}`;
      case "network_controller":
        return `network_controller:${source.connector}`;
      case "probe":
        return `probe:${source.node}:${source.method}`;
      case "dns_record":
        return `dns:${source.zone}`;
      case "dhcp_lease":
        return `dhcp:${source.node}`;
    }
  };
  let observationNo = 0;
  const fact = (
    source: S["ObservationSource"],
    subject: S["FactSubject"],
    subjectKey: string,
    observed: S["Observed"],
    seen: { first: number; last: number; sightings: number; expires?: number | null },
  ): ObservedFact => {
    observationNo += 1;
    return {
      source,
      source_key: sourceKey(source),
      subject,
      subject_key: subjectKey,
      observed,
      observation: `0190d1c2-0000-7000-8000-00000e${observationNo.toString(16).padStart(6, "0")}`,
      first_seen: ago(seen.first),
      last_seen: ago(seen.last),
      received_at: ago(seen.last),
      expires_at: seen.expires === null ? null : seen.expires !== undefined ? iso(now + seen.expires) : later(45 * MINUTE),
      sightings: seen.sightings,
      counted_at: ago(seen.last),
      revision,
    };
  };
  const addressFact = (method: S["ProbeMethod"], ip: string, mac: string | null, seen: { first: number; last: number; sightings: number }) =>
    fact(probe(method), { type: "address", data: { ip, vrf } }, `address:${vrf}/${ip}`, { type: "address", data: { ip, vrf, mac } }, seen);

  const mediaPc = fact(
    inventory,
    { type: "host", data: { external_id: "vm-104" } },
    "host:vm-104",
    {
      type: "host",
      data: {
        external_id: "vm-104",
        name: "media-pc",
        macs: ["00:00:5e:00:53:d1"],
        ips: ["192.0.2.150"],
        os: "Debian 12",
        platform: "qemu",
        parent: "pve1",
        tags: ["media"],
      },
    },
    { first: 3 * DAY_MS, last: 10 * MINUTE, sightings: 9 },
  );
  const mediaServices = fact(
    probe("tcp_syn"),
    { type: "services", data: { ip: "192.0.2.150" } },
    "services:192.0.2.150",
    { type: "services", data: { ip: "192.0.2.150", open_tcp: [22, 8096] } },
    { first: 2 * DAY_MS, last: 40 * MINUTE, sightings: 4 },
  );
  const mediaOs = fact(
    probe("os_fingerprint"),
    { type: "os", data: { ip: "192.0.2.150" } },
    "os:192.0.2.150",
    { type: "os", data: { ip: "192.0.2.150", guess: "Linux 6.x", confidence: 90 } },
    { first: 2 * DAY_MS, last: 40 * MINUTE, sightings: 4 },
  );
  const hallClient = fact(
    controller,
    { type: "attachment", data: { mac: "00:00:5e:00:53:d2" } },
    "attachment:00:00:5e:00:53:d2",
    { type: "attachment", data: { mac: "00:00:5e:00:53:d2", device: "switch-hall", port: "7", vlan: 10 } },
    { first: 2 * DAY_MS, last: 5 * MINUTE, sightings: 12 },
  );
  const iotAddress = addressFact("icmp", "198.51.100.77", null, { first: DAY_MS, last: 15 * MINUTE, sightings: 5 });
  const thermostatSeen = addressFact("arp", "192.0.2.49", "00:00:5e:00:53:29", { first: 6 * HOUR_MS, last: 8 * MINUTE, sightings: 3 });
  const thermostatAttached = fact(
    controller,
    { type: "attachment", data: { mac: "00:00:5e:00:53:29" } },
    "attachment:00:00:5e:00:53:29",
    { type: "attachment", data: { mac: "00:00:5e:00:53:29", device: "ap-garage", ssid: "iot", vlan: 30 } },
    { first: 9 * DAY_MS, last: 5 * MINUTE, sightings: 40 },
  );
  const outside = addressFact("arp", "203.0.113.230", "00:00:5e:00:53:d5", { first: 4 * HOUR_MS, last: 20 * MINUTE, sightings: 2 });
  const printerTaken = addressFact("arp", "192.0.2.30", "00:00:5e:00:53:b0", { first: 2 * HOUR_MS, last: 12 * MINUTE, sightings: 2 });
  const oldTest = fact(
    inventory,
    { type: "host", data: { external_id: "vm-200" } },
    "host:vm-200",
    { type: "host", data: { external_id: "vm-200", name: "old-test", macs: ["00:00:5e:00:53:c4"], ips: [], platform: "lxc" } },
    { first: 12 * DAY_MS, last: 2 * DAY_MS, sightings: 30, expires: -DAY_MS },
  );
  const guestPhone = fact(
    controller,
    { type: "attachment", data: { mac: "00:00:5e:00:53:c3" } },
    "attachment:00:00:5e:00:53:c3",
    { type: "attachment", data: { mac: "00:00:5e:00:53:c3", device: "ap-hall", ssid: "guest", vlan: 50 } },
    { first: 4 * DAY_MS, last: 30 * MINUTE, sightings: 6 },
  );
  // What probes find besides sightings: a name for an address (reverse DNS) and the vendor of a
  // MAC address (its OUI, read where ARP shows the MAC address). Neither is a sighting.
  const speakerName = fact(
    probe("reverse_dns"),
    { type: "name", data: { ip: "192.0.2.44" } },
    "name:192.0.2.44",
    { type: "name", data: { ip: "192.0.2.44", name: "speaker-den.example.test" } },
    { first: 6 * DAY_MS, last: 25 * MINUTE, sightings: 8, expires: 3 * HOUR_MS },
  );
  const outsideVendor = fact(
    probe("arp"),
    { type: "vendor", data: { mac: "00:00:5e:00:53:d5" } },
    "vendor:00:00:5e:00:53:d5",
    { type: "vendor", data: { mac: "00:00:5e:00:53:d5", vendor: "ICANN, IANA Department" } },
    { first: 4 * HOUR_MS, last: 18 * MINUTE, sightings: 2 },
  );
  const facts = [
    mediaPc,
    mediaServices,
    mediaOs,
    hallClient,
    iotAddress,
    thermostatSeen,
    thermostatAttached,
    outside,
    printerTaken,
    oldTest,
    guestPhone,
    speakerName,
    outsideVendor,
  ];

  const evidence = (f: ObservedFact, pair: { mac?: string | null; ip?: string | null; name?: string | null }): S["ProposalEvidence"] => ({
    source: f.source,
    source_key: f.source_key,
    subject_key: f.subject_key,
    observation: f.observation,
    mac: pair.mac ?? null,
    ip: pair.ip ?? null,
    name: pair.name ?? null,
    first_seen: f.first_seen,
    last_seen: f.last_seen,
    sightings: f.sightings ?? 1,
  });
  const ids = RECONCILE_IDS.proposal;
  const made = RECONCILE_IDS.created;
  const alex: S["Principal"] = {
    kind: "user",
    id: MOCK_USER_IDS.alex,
    session: "0190d1c2-0000-7000-8000-0000000e0001",
    strength: "passkey",
  } as S["Principal"];
  const proposal = (p: Omit<IntentProposal, "fingerprint" | "revision">): IntentProposal => ({
    ...p,
    fingerprint: digestOf(`${p.kind}|${p.key}|${JSON.stringify(p.commands ?? [])}|${p.evidence.map((e) => `${e.source_key}/${e.subject_key}`).join(",")}`),
    revision,
  });

  const list: IntentProposal[] = [
    proposal({
      id: ids.mediaPc,
      kind: "discovered_host",
      rule: "ipam.reconcile.discovered_mac",
      key: "discovered_host/mac:00:00:5e:00:53:d1",
      severity: "info",
      state: "open",
      subject: { mac: "00:00:5e:00:53:d1", ip: "192.0.2.150", name: "media-pc", prefix: IPAM_IDS.prefix.lan, vrf, objects: [] },
      summary: "Unknown device 00:00:5e:00:53:d1 (media-pc) seen at 192.0.2.150 by 1 source; adopt it as host media-pc",
      params: { mac: "00:00:5e:00:53:d1", name: "media-pc", sources: "1", ips: "192.0.2.150" },
      evidence: [evidence(mediaPc, { mac: "00:00:5e:00:53:d1", ip: "192.0.2.150", name: "media-pc" })],
      commands: [
        {
          op: "create_host",
          args: {
            id: made.mediaPcHost,
            name: "media-pc",
            mode: "dynamic",
            tags: ["discovered"],
            interfaces: [{ id: made.mediaPcInterface, name: "eth0", mac: "00:00:5e:00:53:d1" }],
          },
        },
        { op: "create_address", args: { ip: "192.0.2.150", vrf, interface: made.mediaPcInterface } },
      ],
      created: ago(3 * DAY_MS),
      updated: ago(10 * MINUTE),
    }),
    proposal({
      id: ids.hallSwitchClient,
      kind: "discovered_host",
      rule: "ipam.reconcile.discovered_mac",
      key: "discovered_host/mac:00:00:5e:00:53:d2",
      severity: "info",
      state: "open",
      subject: { mac: "00:00:5e:00:53:d2", objects: [] },
      summary: "Unknown device 00:00:5e:00:53:d2 (host-00005e0053d2) seen by 1 source; adopt it as host host-00005e0053d2",
      params: { mac: "00:00:5e:00:53:d2", name: "host-00005e0053d2", sources: "1" },
      evidence: [evidence(hallClient, { mac: "00:00:5e:00:53:d2" })],
      commands: [
        {
          op: "create_host",
          args: {
            id: made.hallClientHost,
            name: "host-00005e0053d2",
            mode: "dynamic",
            tags: ["discovered"],
            interfaces: [{ id: made.hallClientInterface, name: "eth0", mac: "00:00:5e:00:53:d2" }],
          },
        },
      ],
      created: ago(2 * DAY_MS),
      updated: ago(5 * MINUTE),
    }),
    proposal({
      id: ids.iotAddress,
      kind: "discovered_host",
      rule: "ipam.reconcile.discovered_address",
      key: `discovered_host/ip:${vrf}/198.51.100.77`,
      severity: "info",
      state: "open",
      subject: { ip: "198.51.100.77", prefix: IPAM_IDS.prefix.iot, vrf, objects: [] },
      summary: "Unknown device (host-198-51-100-77) seen at 198.51.100.77 by 1 source; adopt it as host host-198-51-100-77",
      params: { name: "host-198-51-100-77", sources: "1", ips: "198.51.100.77" },
      evidence: [evidence(iotAddress, { ip: "198.51.100.77" })],
      commands: [
        {
          op: "create_host",
          args: {
            id: made.iotHost,
            name: "host-198-51-100-77",
            mode: "dynamic",
            tags: ["discovered"],
            interfaces: [{ id: made.iotInterface, name: "eth0" }],
          },
        },
        { op: "create_address", args: { ip: "198.51.100.77", vrf, interface: made.iotInterface } },
      ],
      created: ago(DAY_MS),
      updated: ago(15 * MINUTE),
    }),
    proposal({
      id: ids.thermostat,
      kind: "address_mismatch",
      rule: "ipam.reconcile.address_mismatch",
      key: `address_mismatch/interface:${INTERFACE_IDS["thermostat-1"]}/${vrf}/v4`,
      severity: "warning",
      state: "open",
      subject: {
        mac: "00:00:5e:00:53:29",
        ip: "192.0.2.49",
        name: "thermostat-1",
        prefix: IPAM_IDS.prefix.lan,
        vrf,
        objects: [
          { kind: "host", id: HOST_IDS["thermostat-1"]! },
          { kind: "interface", id: INTERFACE_IDS["thermostat-1"]! },
          { kind: "address", id: ADDRESS_IDS["192.0.2.41"]! },
        ],
      },
      summary: "thermostat-1 eth0 is seen at 192.0.2.49, not at its intended 192.0.2.41",
      params: { host: "thermostat-1", ip: "192.0.2.49", intended: "192.0.2.41" },
      evidence: [evidence(thermostatSeen, { mac: "00:00:5e:00:53:29", ip: "192.0.2.49" })],
      commands: [{ op: "update_address", args: { id: ADDRESS_IDS["192.0.2.41"]!, patch: { ip: "192.0.2.49" } } }],
      created: ago(6 * HOUR_MS),
      updated: ago(8 * MINUTE),
    }),
    proposal({
      id: ids.outside,
      kind: "outside_prefixes",
      rule: "ipam.reconcile.outside_prefixes",
      key: `outside_prefixes/${vrf}/203.0.113.224/27`,
      severity: "warning",
      state: "open",
      subject: { cidr: "203.0.113.224/27", ip: "203.0.113.230", vrf, objects: [{ kind: "prefix", id: IPAM_IDS.prefix.documentation }] },
      summary: "1 address seen outside every known network; create the network 203.0.113.224/27",
      params: { cidr: "203.0.113.224/27", count: "1", ips: "203.0.113.230" },
      evidence: [evidence(outside, { mac: "00:00:5e:00:53:d5", ip: "203.0.113.230" })],
      commands: [{ op: "create_prefix", args: { cidr: "203.0.113.224/27", vrf, role: "network", tags: ["discovered"] } }],
      created: ago(4 * HOUR_MS),
      updated: ago(20 * MINUTE),
    }),
    proposal({
      id: ids.printerTaken,
      kind: "conflict",
      rule: "ipam.reconcile.conflict_address_taken",
      key: `conflict/taken:${ADDRESS_IDS["192.0.2.30"]}`,
      severity: "warning",
      state: "open",
      subject: {
        ip: "192.0.2.30",
        mac: "00:00:5e:00:53:b0",
        prefix: IPAM_IDS.prefix.lan,
        vrf,
        objects: [
          { kind: "address", id: ADDRESS_IDS["192.0.2.30"]! },
          { kind: "host", id: HOST_IDS["printer-1"]! },
        ],
      },
      summary: "192.0.2.30 is intended for printer-1 (00:00:5e:00:53:1e) but used by 00:00:5e:00:53:b0",
      params: { ip: "192.0.2.30", host: "printer-1", intended_mac: "00:00:5e:00:53:1e", macs: "00:00:5e:00:53:b0", hosts: HOST_IDS["printer-1"]!, dormant_hosts: "" },
      evidence: [evidence(printerTaken, { mac: "00:00:5e:00:53:b0", ip: "192.0.2.30" })],
      commands: [],
      created: ago(2 * HOUR_MS),
      updated: ago(12 * MINUTE),
    }),
    proposal({
      id: ids.guestPhone,
      kind: "discovered_host",
      rule: "ipam.reconcile.discovered_mac",
      key: "discovered_host/mac:00:00:5e:00:53:c3",
      severity: "info",
      state: "rejected",
      subject: { mac: "00:00:5e:00:53:c3", objects: [] },
      summary: "Unknown device 00:00:5e:00:53:c3 (host-00005e0053c3) seen by 1 source; adopt it as host host-00005e0053c3",
      params: { mac: "00:00:5e:00:53:c3", name: "host-00005e0053c3", sources: "1" },
      evidence: [evidence(guestPhone, { mac: "00:00:5e:00:53:c3" })],
      commands: [
        {
          op: "create_host",
          args: { name: "host-00005e0053c3", mode: "dynamic", tags: ["discovered"], interfaces: [{ name: "eth0", mac: "00:00:5e:00:53:c3" }] },
        },
      ],
      reason: "A guest phone on the guest network",
      decided: { at: ago(3 * DAY_MS), by: alex },
      created: ago(4 * DAY_MS),
      updated: ago(3 * DAY_MS),
    }),
    proposal({
      id: ids.speaker,
      kind: "discovered_host",
      rule: "ipam.reconcile.discovered_mac",
      key: "discovered_host/mac:00:00:5e:00:53:2c",
      severity: "info",
      state: "accepted",
      subject: { mac: "00:00:5e:00:53:2c", ip: "192.0.2.44", name: "speaker-den", prefix: IPAM_IDS.prefix.lan, vrf, objects: [] },
      summary: "Unknown device 00:00:5e:00:53:2c (speaker-den) seen at 192.0.2.44 by 1 source; adopt it as host speaker-den",
      params: { mac: "00:00:5e:00:53:2c", name: "speaker-den", sources: "1", ips: "192.0.2.44" },
      evidence: [],
      commands: [],
      results: [{ kind: "host", id: HOST_IDS["speaker-den"]! }],
      adopted_by: IPAM_IDS.prefix.lan,
      decided: { at: ago(20 * DAY_MS), by: RECONCILER },
      created: ago(21 * DAY_MS),
      updated: ago(20 * DAY_MS),
    }),
    proposal({
      id: ids.oldTest,
      kind: "discovered_host",
      rule: "ipam.reconcile.discovered_mac",
      key: "discovered_host/mac:00:00:5e:00:53:c4",
      severity: "info",
      state: "expired",
      subject: { mac: "00:00:5e:00:53:c4", name: "old-test", objects: [] },
      summary: "Unknown device 00:00:5e:00:53:c4 (old-test) seen by 1 source; adopt it as host old-test",
      params: { mac: "00:00:5e:00:53:c4", name: "old-test", sources: "1" },
      evidence: [evidence(oldTest, { mac: "00:00:5e:00:53:c4", name: "old-test" })],
      commands: [],
      reason: REASON_GONE,
      decided: { at: ago(DAY_MS), by: RECONCILER },
      created: ago(12 * DAY_MS),
      updated: ago(DAY_MS),
    }),
  ];

  const policies = new Map<string, StoredPolicy>([
    [
      IPAM_IDS.prefix.iot,
      {
        policy: { mode: "adopt_hosts", only_dhcp_pools: true, vendors: ["00:00:5e"], min_sightings: 2, host_mode: "dynamic" },
        revision,
        updated: { at: ago(10 * DAY_MS), by: alex },
      },
    ],
    [
      IPAM_IDS.prefix.documentation,
      {
        policy: { mode: "adopt_all", only_dhcp_pools: false, vendors: [], min_sightings: 3, host_mode: "dynamic" },
        revision,
        updated: { at: ago(8 * DAY_MS), by: alex },
      },
    ],
    [
      IPAM_IDS.prefix.lab,
      {
        policy: { mode: "manual", only_dhcp_pools: false, vendors: [], min_sightings: 1, host_mode: "dynamic" },
        revision,
        updated: { at: ago(8 * DAY_MS), by: alex },
      },
    ],
  ]);

  return { facts, proposals: new Map(list.map((p) => [p.id, p])), policies };
}

export { REASON_GONE };

export interface ServicesOptions {
  /** The open ports that answered a TLS handshake. */
  tls?: number[];
  /** The probe method that reported them (default `tcp_connect`). */
  method?: S["ProbeMethod"];
  /** How long ago the last scan was, in milliseconds (default 20 minutes). */
  ago?: number;
  /** Whether the fact has expired already. */
  expired?: boolean;
}

let servicesNo = 0;

/**
 * Sets what the probe saw open at an address (the `services` fact of docs/scanning.md): the
 * fact of that address from the same method is replaced by a new one. For the tests of the
 * host page's Connect panel.
 */
export function putServices(ip: string, openTcp: number[], options: ServicesOptions = {}): ObservedFact {
  const method = options.method ?? "tcp_connect";
  const now = Date.now();
  const seen = iso(now - (options.ago ?? 20 * MINUTE));
  const source: S["ObservationSource"] = { type: "probe", node: RECONCILE_IDS.probeNode, method };
  const key = `probe:${RECONCILE_IDS.probeNode}:${method}`;
  const facts = reconcileState().facts;
  for (let i = facts.length - 1; i >= 0; i--) {
    const f = facts[i] as ObservedFact;
    if (f.source_key === key && f.observed.type === "services" && f.observed.data.ip === ip) facts.splice(i, 1);
  }
  servicesNo += 1;
  const added: ObservedFact = {
    source,
    source_key: key,
    subject: { type: "services", data: { ip } },
    subject_key: `services:${ip}`,
    observed: { type: "services", data: { ip, open_tcp: openTcp, ...(options.tls ? { tls_tcp: options.tls } : {}) } },
    observation: `0190d1c2-0000-7000-8000-00000f${servicesNo.toString(16).padStart(6, "0")}`,
    first_seen: seen,
    last_seen: seen,
    received_at: seen,
    expires_at: options.expired ? iso(now - MINUTE) : iso(now + 6 * HOUR_MS),
    sightings: 1,
    counted_at: seen,
    revision: db.revision,
  };
  facts.push(added);
  return added;
}

export interface GuestOptions {
  /** The power state the source reports (default `stopped`). */
  power?: "running" | "stopped";
  /** Whether the fact has expired already. */
  expired?: boolean;
}

let guestNo = 0;

/**
 * Adds the fact an inventory connector reports for a guest with the address `ip`; by default
 * the guest is stopped, so its address is a dormant claim. For the tests of the lifecycle of
 * a host and of the address conflicts.
 */
export function putGuest(ip: string, name: string, options: GuestOptions = {}): ObservedFact {
  const now = Date.now();
  guestNo += 1;
  const externalId = `vm-9${guestNo}`;
  const seen = iso(now - 5 * MINUTE);
  const added: ObservedFact = {
    source: { type: "inventory", connector: RECONCILE_IDS.inventory },
    source_key: `inventory:${RECONCILE_IDS.inventory}`,
    subject: { type: "host", data: { external_id: externalId } },
    subject_key: `host:${externalId}`,
    observed: { type: "host", data: { external_id: externalId, name, ips: [ip], platform: "qemu", power: options.power ?? "stopped" } },
    observation: `0190d1c2-0000-7000-8000-0000a0${guestNo.toString(16).padStart(6, "0")}`,
    first_seen: iso(now - DAY_MS),
    last_seen: seen,
    received_at: seen,
    expires_at: options.expired ? iso(now - MINUTE) : iso(now + 6 * HOUR_MS),
    sightings: 3,
    counted_at: seen,
    revision: db.revision,
  };
  reconcileState().facts.push(added);
  return added;
}

export interface AddressConflictOptions {
  rule: "ipam.reconcile.conflict_shared_address" | "ipam.reconcile.conflict_address_taken";
  ip: string;
  /** The ids of the hosts in the conflict (for a taken address the intended host first). */
  hosts: string[];
  /** The ids of the hosts whose claim comes only from a stopped guest. */
  dormant?: string[];
}

let conflictNo = 0;

/** Adds an open address conflict about the hosts, as the reconciler opens one for two claims on one address. */
export function putAddressConflict(options: AddressConflictOptions): IntentProposal {
  conflictNo += 1;
  const now = Date.now();
  const id = `0190d1c2-0000-7000-8000-0000d2${conflictNo.toString(16).padStart(6, "0")}`;
  const taken = options.rule === "ipam.reconcile.conflict_address_taken";
  const params: Record<string, string> = {
    ip: options.ip,
    hosts: options.hosts.join(", "),
    macs: "00:00:5e:00:53:b0, 00:00:5e:00:53:b1",
    count: String(options.hosts.length),
  };
  if (taken) {
    params.host = "intended";
    params.intended_mac = "00:00:5e:00:53:1e";
    params.dormant_hosts = (options.dormant ?? []).join(", ");
  }
  const proposal: IntentProposal = {
    id,
    kind: "conflict",
    rule: options.rule,
    key: `conflict/${taken ? "taken" : "shared"}:${options.ip}`,
    severity: "warning",
    state: "open",
    subject: { ip: options.ip, objects: [] },
    summary: `${options.ip} is claimed by ${options.hosts.length} hosts`,
    params,
    evidence: [],
    commands: [],
    fingerprint: digestOf(`${id}|${options.ip}`),
    revision: db.revision,
    created: iso(now - HOUR_MS),
    updated: iso(now - 5 * MINUTE),
  };
  reconcileState().proposals.set(id, proposal);
  return proposal;
}
