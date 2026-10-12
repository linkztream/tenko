// The scan control of the mock (docs/scanning.md, sections 7.5 to 7.7): the probes with their
// stored scan configuration, the scope each applies and its kill switch, and the scan runs.
// The controller's own probe is node 1 (`ctl-1.example.test`); the enrolled probes are the nodes
// of nodes-store.ts with the role `probe`, so enrolling or revoking one shows here as well.
//
// Simplifications: the commands to the probes are not modelled, a probe confirms a command at
// once; a scan runs on a clock of reads: it goes from `queued` to `running` on the first read
// and gains 20 percent on every later read of it or of the list, until it is `done`; the diff
// of a run that was started here is one new address, one new name and one changed vendor.
// The state is built from the seed on first use and again after every reset; the setup
// scenarios have no probes and no scans.
import type { components } from "../generated/schema";
import { CONFIG_METHODS, type ScanConfig } from "../../scans/model";
import { containsCidr, containsIp, formatCidr, overlaps, parseCidr, parseIp, type Cidr } from "../../ipam/ip";
import { db, onMockReset } from "./db";
import { MOCK_USER_IDS } from "./fixtures";
import { IPAM_IDS } from "./ipam/api";
import { cidrOf, hostBounds, ipText } from "./ipam/net";
import { ipamState } from "./ipam/state";
import { nodesState } from "./nodes-store";
import { HOUR_MS, MINUTE, iso, randomId } from "./util";

type S = components["schemas"];
export type ScanView = S["ScanView"];
export type ProbeProgress = S["ProbeProgress"];
export type ScanDiff = S["ScanDiff"];
export type DiffItem = S["DiffItem"];
export type KillSwitchView = S["KillSwitchView"];
export type ProbeScope = S["ProbeScope"];
export type ProbeConfigView = S["ProbeConfigView"];
export type ProbeSummary = S["ProbeSummary"];

/** The node id of the controller's own probe role. */
export const CONTROLLER_PROBE = 1;

/** The fixed ids of the seeded scans. */
export const SCAN_IDS = {
  done: "0190d1c2-0000-7000-8000-0000000c5001",
  running: "0190d1c2-0000-7000-8000-0000000c5002",
} as const;

/** The reason a stop gets when the request names none. */
export const DEFAULT_STOP_REASON = "stopped from the controllers";

/** Percent a running scan gains on every read. */
export const PROGRESS_STEP = 20;

/** A probe as the mock keeps it. */
export interface StoredProbe {
  node: number;
  name: string;
  inProcess: boolean;
  config: ScanConfig;
  /** Whether the controllers hold the configuration (false: defaults, the probe runs on its own file). */
  stored: boolean;
  revision: number | null;
  origin: S["ProbeConfigOrigin"] | null;
  updatedAt: string | null;
  updatedBy: string | null;
  applied: ProbeScope | null;
  inSync: boolean;
  killSwitch: KillSwitchView;
}

/** A run: the view, and the diff it shows once it ended. */
export interface StoredScan {
  view: ScanView;
}

export interface ScansState {
  probes: Map<number, StoredProbe>;
  /** Newest first. */
  scans: StoredScan[];
}

let state: ScansState | null = null;

onMockReset(() => {
  state = null;
});

/** The state, built from the seed on first use after a reset, with the probes synchronised with the nodes. */
export function scansState(): ScansState {
  if (!state) {
    const empty = db.scenario === "setup" || db.scenario === "setup-slow-disk";
    state = empty ? { probes: new Map(), scans: [] } : buildSeed(Date.now());
  }
  syncProbes(state);
  return state;
}

/** The configuration a probe has while the controllers hold none: the defaults of the document. */
export function defaultScanConfig(prefixes: string[] = []): ScanConfig {
  return {
    active: true,
    arp: { enabled: true, interval_secs: 300, ttl_secs: null },
    arp_sweep: { enabled: false, interval_secs: 3600, ttl_secs: null },
    blackout: [],
    concurrency: 32,
    enabled: true,
    exclude: [],
    icmp: { enabled: true, interval_secs: 1800, timeout_ms: 1000, ttl_secs: null },
    lldp: { enabled: false, interval_secs: 3600, ttl_secs: null },
    llmnr: { enabled: true, interval_secs: 3600, port: 5355, timeout_ms: 1000, ttl_secs: null },
    max_hosts_per_prefix: 4096,
    mdns: {
      enabled: true,
      group: "224.0.0.251:5353",
      interval_secs: 900,
      listen_secs: 4,
      passive: true,
      ttl_secs: null,
      unicast_port: 5353,
    },
    nd: { enabled: true, interval_secs: 300, ttl_secs: null },
    os_fingerprint: { enabled: false, interval_secs: 3600, ttl_secs: null },
    packets_per_second: null,
    per_host_interval_ms: 100,
    prefixes,
    rate: "normal",
    reverse_dns: { enabled: true, interval_secs: 3600, servers: [], timeout_ms: 2000, ttl_secs: null },
    snmp: {
      attach_on_lldp_ports: false,
      devices: [],
      enabled: true,
      interval_secs: 900,
      retries: 2,
      timeout_ms: 2000,
      ttl_secs: null,
    },
    tcp_connect: {
      enabled: true,
      interval_secs: 21600,
      ports: [22, 53, 80, 443, 445, 3389, 8080],
      targets: "known",
      timeout_ms: 1500,
      tls_hint: true,
      ttl_secs: null,
    },
    tcp_syn: { enabled: false, interval_secs: 3600, ttl_secs: null },
    timezone: null,
    vrf: null,
  } as ScanConfig;
}

/** The methods that run on schedule under a configuration, by name. */
export function scheduledMethods(config: ScanConfig): string[] {
  if (!config.enabled) return [];
  return CONFIG_METHODS.filter(({ key, raw }) => {
    if (raw || !config[key].enabled) return false;
    if (!config.active && (key === "icmp" || key === "tcp_connect")) return false;
    return key !== "snmp" || config.snmp.devices.length > 0;
  }).map(({ key }) => key);
}

/** The scope a probe reports after it applied `probe.config` at `revision`. */
export function scopeOf(probe: StoredProbe, revision: number, at = Date.now()): ProbeScope {
  return {
    node: probe.node,
    prefixes: [...probe.config.prefixes],
    exclude: [...probe.config.exclude],
    methods: scheduledMethods(probe.config),
    active: probe.config.active,
    stopped: probe.killSwitch.stopped,
    stop_reason: probe.killSwitch.stopped ? (probe.killSwitch.reason ?? null) : null,
    origin: "synced",
    revision,
    error: null,
    applied_at: iso(at),
    reported_at: iso(at),
    vrf: null,
  };
}

function idleSwitch(): KillSwitchView {
  return { stopped: false, confirmed: true, reason: null, at: null, by: null };
}

function newProbe(node: number, name: string, inProcess: boolean): StoredProbe {
  return {
    node,
    name,
    inProcess,
    config: defaultScanConfig(),
    stored: false,
    revision: null,
    origin: null,
    updatedAt: null,
    updatedBy: null,
    applied: null,
    inSync: true,
    killSwitch: idleSwitch(),
  };
}

/** Adds the enrolled nodes with the role `probe` that have no record yet and drops the revoked ones. */
function syncProbes(st: ScansState): void {
  const nodes = nodesState().nodes;
  for (const node of nodes.values()) {
    if (node.roles.includes("probe") && !st.probes.has(node.id)) st.probes.set(node.id, newProbe(node.id, node.name, false));
  }
  for (const probe of [...st.probes.values()]) {
    if (!probe.inProcess && !nodes.get(probe.node)?.roles.includes("probe")) st.probes.delete(probe.node);
  }
}

/** The probes, this controller's own first, then by id. */
export function probeList(): StoredProbe[] {
  return [...scansState().probes.values()].sort((a, b) => Number(b.inProcess) - Number(a.inProcess) || a.node - b.node);
}

/** What the API shows of a probe in the lists. */
export function probeSummary(probe: StoredProbe): ProbeSummary {
  return {
    node: probe.node,
    name: probe.name,
    in_process: probe.inProcess,
    stored: probe.stored,
    revision: probe.revision,
    applied: probe.applied,
    in_sync: probe.inSync,
    kill_switch: probe.killSwitch,
  };
}

/** What the API shows of a probe's configuration. */
export function probeConfigView(probe: StoredProbe): ProbeConfigView {
  return {
    node: probe.node,
    config: probe.config,
    stored: probe.stored,
    origin: probe.origin,
    revision: probe.revision,
    updated_at: probe.updatedAt,
    updated_by: probe.updatedBy,
    applied: probe.applied,
    in_sync: probe.inSync,
    lacking_secrets: [],
    kill_switch: probe.killSwitch,
  };
}

/** Sets a probe's kill switch (confirmed at once) and cancels the runs it is part of on a stop. */
export function setKillSwitch(probe: StoredProbe, stopped: boolean, reason: string | null, by: string): void {
  const at = Date.now();
  probe.killSwitch = { stopped, confirmed: true, reason: stopped ? reason : null, at: iso(at), by };
  if (probe.applied) probe.applied = { ...probe.applied, stopped, stop_reason: stopped ? reason : null, reported_at: iso(at) };
  if (stopped) for (const scan of scansState().scans) cancelPart(scan.view, probe.node);
}

// ---------------------------------------------------------------------------------
// Scans

const ACTIVE_PART = new Set(["pending", "accepted", "running"]);

function isOver(view: ScanView): boolean {
  return ["done", "partial", "failed", "cancelled"].includes(view.state);
}

/** The probe's part of a run is withdrawn; the run ends when no part is left to wait for. */
function cancelPart(view: ScanView, node: number): void {
  if (isOver(view)) return;
  const part = view.probes.find((p) => p.node === node);
  if (!part || !ACTIVE_PART.has(part.state)) return;
  part.state = "cancelled";
  part.detail = "stopped by the kill switch";
  if (view.probes.some((p) => ACTIVE_PART.has(p.state))) return;
  if (view.probes.some((p) => p.state === "done")) finish(view);
  else {
    view.state = "cancelled";
    view.error = "stopped by the kill switch";
    view.finished_at = iso(Date.now());
  }
}

/** Ends a run whose parts are over: `done` when every part finished, else `partial`. */
function finish(view: ScanView): void {
  for (const part of view.probes) {
    if (ACTIVE_PART.has(part.state)) {
      part.state = "done";
      part.progress = 100;
      part.ingested = part.batches ?? 1;
    }
  }
  view.state = view.probes.every((p) => p.state === "done") ? "done" : "partial";
  view.progress = 100;
  view.finished_at = iso(Date.now());
  view.diff = diffOf(view.networks);
}

/** One read of the clock: queued runs start, running ones gain `PROGRESS_STEP`; true when a run ended. */
export function advanceScans(): boolean {
  let ended = false;
  for (const { view } of scansState().scans) {
    if (view.state === "queued") {
      view.state = "running";
      for (const part of view.probes) if (part.state === "pending") part.state = "running";
      continue;
    }
    if (view.state !== "running") continue;
    view.progress = Math.min(100, view.progress + PROGRESS_STEP);
    for (const part of view.probes) if (ACTIVE_PART.has(part.state)) part.progress = view.progress;
    if (view.progress >= 100) {
      finish(view);
      ended = true;
    }
  }
  return ended;
}

/** A run as `GET /scans` lists it: the counts of its diff, without the items. */
export function listedScan(view: ScanView): ScanView {
  return view.diff ? { ...view, diff: { ...view.diff, items: [] } } : view;
}

/** The small diff of a run started here: the first host address of the first network is new. */
function diffOf(networks: string[]): ScanDiff {
  const cidr = parseCidr(networks[0] ?? "", { strict: false });
  const first = cidr ? hostBounds(cidr).first : 0n;
  const ip = cidr ? ipText(cidr.version, first + 2n) : "192.0.2.2";
  const mac = "00:00:5e:00:53:7f";
  const source = `probe:${CONTROLLER_PROBE}:arp`;
  const vrf = IPAM_IDS.vrf.default;
  return {
    counts: {
      address: { new: 1, changed: 0, unchanged: 0, gone: 0 },
      name: { new: 1, changed: 0, unchanged: 0, gone: 0 },
      vendor: { new: 0, changed: 1, unchanged: 0, gone: 0 },
    },
    items: [
      { change: "new", fact_type: "address", subject: ip, source, after: { type: "address", data: { ip, mac, vrf } } },
      {
        change: "new",
        fact_type: "name",
        subject: ip,
        source: `probe:${CONTROLLER_PROBE}:reverse_dns`,
        after: { type: "name", data: { ip, name: "scanned.example.test" } },
      },
      {
        change: "changed",
        fact_type: "vendor",
        subject: mac,
        source,
        before: { type: "vendor", data: { mac, vendor: "Example Devices" } },
        after: { type: "vendor", data: { mac, vendor: "Example Devices Ltd" } },
      },
    ],
    truncated: false,
  };
}

// ---------------------------------------------------------------------------------
// Targets

/** A target resolved to networks; `failure` names the problem of `scan.job.target` otherwise. */
export type Resolved =
  | { networks: Cidr[]; vrf: string | null }
  | { failure: "not_found" | "unscannable"; detail: string };

/** The networks a target stands for: a prefix, the addresses of a host, an address or a network. */
export function resolveTarget(kind: string, value: string): Resolved {
  const data = ipamState().data;
  switch (kind) {
    case "prefix": {
      const prefix = data.prefix.get(value);
      if (!prefix || prefix.meta.deleted) return { failure: "not_found", detail: `no prefix has the id ${value}` };
      return { networks: [cidrOf(prefix.cidr)], vrf: prefix.vrf };
    }
    case "host": {
      const host = data.host.get(value);
      if (!host || host.meta.deleted) return { failure: "not_found", detail: `no host has the id ${value}` };
      const interfaces = new Set([...data.interface.values()].filter((i) => i.host === value).map((i) => i.id));
      const addresses = [...data.address.values()].filter((a) => !a.meta.deleted && !!a.interface && interfaces.has(a.interface));
      if (addresses.length === 0) return { failure: "unscannable", detail: `the host ${host.name} has no address to scan` };
      return { networks: addresses.map((a) => cidrOf(a.ip)), vrf: addresses[0]?.vrf ?? null };
    }
    case "address": {
      const ip = parseIp(value.trim());
      if (!ip) return { failure: "unscannable", detail: `${value} is not an IP address` };
      return { networks: [{ version: ip.version, network: ip.value, length: ip.version === 4 ? 32 : 128 }], vrf: null };
    }
    default: {
      const cidr = parseCidr(value, { strict: false });
      if (!cidr) return { failure: "unscannable", detail: `${value} is not a network` };
      return { networks: [cidr], vrf: null };
    }
  }
}

/** The scope of a probe: its prefixes minus the exclusions are not subtracted, a covered target is cut by them in `partOf`. */
function scopeNetworks(probe: StoredProbe): Cidr[] {
  if (!probe.config.enabled) return [];
  return probe.config.prefixes.flatMap((p) => parseCidr(p, { strict: false }) ?? []);
}

/** The part of `networks` inside the probe's scope, as network texts; empty when it covers none. */
export function partOf(probe: StoredProbe, networks: readonly Cidr[]): string[] {
  const scope = scopeNetworks(probe);
  const excluded = probe.config.exclude.flatMap((p) => parseCidr(p, { strict: false }) ?? []);
  const parts: string[] = [];
  for (const network of networks) {
    for (const covered of scope) {
      if (!overlaps(network, covered)) continue;
      const inner = containsCidr(covered, network) ? network : covered;
      if (excluded.some((x) => containsCidr(x, inner))) continue;
      if (inner.length === (inner.version === 4 ? 32 : 128) && excluded.some((x) => containsIp(x, { version: inner.version, value: inner.network }))) continue;
      parts.push(formatCidr(inner));
    }
  }
  return [...new Set(parts)];
}

/** Starts a run on the probes that cover `networks`; null when none does. */
export function startScan(
  target: S["ScanTarget"],
  networks: readonly Cidr[],
  vrf: string | null,
  kinds: S["ScanKind"][],
  deadlineSecs: number,
  by: string,
): ScanView | null {
  const st = scansState();
  const probes: ProbeProgress[] = [];
  for (const probe of probeList()) {
    const part = partOf(probe, networks);
    if (part.length === 0) continue;
    const stopped = probe.killSwitch.stopped;
    probes.push({
      node: probe.node,
      command: randomId(),
      target: part.join(", "),
      state: stopped ? "rejected" : "pending",
      progress: 0,
      detail: stopped ? "scan.stopped" : kinds.join(", "),
      batches: stopped ? 0 : 1,
      ingested: 0,
    });
  }
  if (probes.length === 0) return null;
  const now = Date.now();
  const view: ScanView = {
    id: randomId(),
    job_id: randomId(),
    target,
    networks: networks.map(formatCidr),
    vrf,
    kinds,
    requested_by: by,
    created_at: iso(now),
    deadline: iso(now + deadlineSecs * 1000),
    finished_at: null,
    error: null,
    state: "queued",
    progress: 0,
    probes,
    diff: null,
  };
  if (probes.every((p) => p.state === "rejected")) {
    view.state = "failed";
    view.error = "scan.stopped";
    view.finished_at = iso(now);
  }
  st.scans.unshift({ view });
  return view;
}

// ---------------------------------------------------------------------------------
// Seed

function buildSeed(now: number): ScansState {
  const probes = new Map<number, StoredProbe>();
  const nodes = nodesState().nodes;
  const rows: { node: number; name: string; inProcess: boolean; prefixes: string[]; exclude: string[]; revision: number }[] = [
    { node: CONTROLLER_PROBE, name: "ctl-1.example.test", inProcess: true, prefixes: ["192.0.2.0/24", "2001:db8:0:10::/64"], exclude: ["192.0.2.1"], revision: 3 },
    ...[...nodes.values()]
      .filter((n) => n.roles.includes("probe"))
      .sort((a, b) => a.id - b.id)
      .map((n, i) => ({
        node: n.id,
        name: n.name,
        inProcess: false,
        prefixes: i === 0 ? ["203.0.113.128/26", "203.0.113.192/28"] : ["203.0.113.0/25", "198.51.100.0/24"],
        exclude: i === 0 ? ["203.0.113.200"] : [],
        revision: 2 - Math.min(i, 1),
      })),
  ];
  for (const row of rows) {
    const probe = newProbe(row.node, row.name, row.inProcess);
    probe.config = { ...defaultScanConfig(row.prefixes), exclude: row.exclude };
    probe.stored = true;
    probe.revision = row.revision;
    probe.origin = "api";
    probe.updatedAt = iso(now - 3 * 24 * HOUR_MS);
    probe.updatedBy = MOCK_USER_IDS.alex;
    probe.applied = scopeOf(probe, row.revision, now - 10 * MINUTE);
    probes.set(row.node, probe);
  }
  const dmz = rows.find((r) => !r.inProcess)?.node ?? CONTROLLER_PROBE;
  const done = doneScan(now);
  const running = runningScan(now, dmz);
  return { probes, scans: [{ view: running }, { view: done }] };
}

function doneScan(now: number): ScanView {
  const vrf = IPAM_IDS.vrf.default;
  const at = now - 2 * HOUR_MS;
  const arp = `probe:${CONTROLLER_PROBE}:arp`;
  const mac = (n: number) => `00:00:5e:00:53:${n.toString(16).padStart(2, "0")}`;
  const items: DiffItem[] = [
    { change: "new", fact_type: "address", subject: "192.0.2.41", source: arp, after: { type: "address", data: { ip: "192.0.2.41", mac: mac(0x41), vrf } } },
    { change: "new", fact_type: "name", subject: "192.0.2.41", source: `probe:${CONTROLLER_PROBE}:reverse_dns`, after: { type: "name", data: { ip: "192.0.2.41", name: "printer-2.example.test" } } },
    { change: "new", fact_type: "vendor", subject: mac(0x41), source: arp, after: { type: "vendor", data: { mac: mac(0x41), vendor: "Example Devices" } } },
    {
      change: "changed",
      fact_type: "address",
      subject: "192.0.2.12",
      source: arp,
      before: { type: "address", data: { ip: "192.0.2.12", mac: mac(0x12), vrf } },
      after: { type: "address", data: { ip: "192.0.2.12", mac: mac(0x92), vrf } },
    },
    {
      change: "changed",
      fact_type: "services",
      subject: "192.0.2.10",
      source: `probe:${CONTROLLER_PROBE}:tcp_connect`,
      before: { type: "services", data: { ip: "192.0.2.10", open_tcp: [22, 80] } },
      after: { type: "services", data: { ip: "192.0.2.10", open_tcp: [22, 80, 443], tls_tcp: [443] } },
    },
    { change: "gone", fact_type: "address", subject: "192.0.2.77", source: arp, before: { type: "address", data: { ip: "192.0.2.77", mac: mac(0x77), vrf } } },
    { change: "gone", fact_type: "name", subject: "192.0.2.77", source: `probe:${CONTROLLER_PROBE}:reverse_dns`, before: { type: "name", data: { ip: "192.0.2.77", name: "old-camera.example.test" } } },
  ];
  return {
    id: SCAN_IDS.done,
    job_id: "0190d1c2-0000-7000-8000-0000000c6001",
    target: { kind: "prefix", value: IPAM_IDS.prefix.lan },
    networks: ["192.0.2.0/24"],
    vrf,
    kinds: ["passive_refresh", "port_scan"],
    requested_by: MOCK_USER_IDS.alex,
    created_at: iso(at),
    deadline: iso(at + 600_000),
    finished_at: iso(at + 3 * MINUTE),
    error: null,
    state: "done",
    progress: 100,
    probes: [
      {
        node: CONTROLLER_PROBE,
        command: "0190d1c2-0000-7000-8000-0000000c7001",
        target: "192.0.2.0/24",
        state: "done",
        progress: 100,
        detail: "passive_refresh, port_scan",
        batches: 4,
        ingested: 4,
      },
    ],
    diff: {
      counts: {
        address: { new: 1, changed: 1, unchanged: 22, gone: 1 },
        name: { new: 1, changed: 0, unchanged: 19, gone: 1 },
        vendor: { new: 1, changed: 0, unchanged: 21, gone: 0 },
        services: { new: 0, changed: 1, unchanged: 8, gone: 0 },
      },
      items,
      truncated: false,
    },
  };
}

function runningScan(now: number, node: number): ScanView {
  const at = now - 4 * MINUTE;
  return {
    id: SCAN_IDS.running,
    job_id: "0190d1c2-0000-7000-8000-0000000c6002",
    target: { kind: "prefix", value: IPAM_IDS.prefix.dmz },
    networks: ["203.0.113.128/26"],
    vrf: IPAM_IDS.vrf.default,
    kinds: ["passive_refresh"],
    requested_by: MOCK_USER_IDS.sam,
    created_at: iso(at),
    deadline: iso(at + 600_000),
    finished_at: null,
    error: null,
    state: "running",
    progress: 40,
    probes: [
      {
        node,
        command: "0190d1c2-0000-7000-8000-0000000c7002",
        target: "203.0.113.128/26",
        state: "running",
        progress: 40,
        detail: "arp",
        batches: 2,
        ingested: 1,
      },
    ],
    diff: null,
  };
}
