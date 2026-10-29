// The root of the topology map, the SSID view and the two WLAN rules of the mock, with the
// decisions a person stores on them (crates/tenko-ipam/src/topology/{root,wlan,stored}.rs,
// crates/tenko-api/src/routes/topology/decisions.rs).
//
// The root: two sources name it, ranked. The first is the router a network controller reports
// (the gateway of the graph), the second the next hop of the default route kept in the topology
// state (`TopologyState.nextHops`; by default the gateway's own address, so the sources
// agree). When they name different nodes the finding `topology_root` is open until a person
// chooses; the choice remembers the keys of the candidates then on offer.
//
// The SSID view reads the wireless clients of the controller (the topology state) against the
// live IPAM mock. The rules raise findings to review: an IoT-classed host (the tag
// `class:iot`) on a WLAN whose VLAN has no IoT role (the tag `role:iot` on the VLAN or one of
// its networks), and a host whose address is outside every network of its SSID's VLAN (same
// address family only). Skipped: ignored SSIDs, kept pairs, unmanaged and decommissioned hosts
// and clients that are no host.
//
// The IPAM mock's tag list is fixed by its own tests, so the seed has no `class:iot` tag. The
// mock classes tv-living as IoT itself (`mockTopologyDecisions.iotHosts`), which makes the
// default data raise exactly one `wlan_class` finding; a test adds hosts to the set or tags
// them through IPAM.
import { containsIp, parseCidr, parseIp, type Cidr } from "../../ipam/ip";
import type { components } from "../generated/schema";
import { appendAudit, principalNow, testDigest } from "./audit-store";
import { commit, db, onMockReset } from "./db";
import { HOST_IDS, ipamState } from "./ipam/api";
import { notFound, revisionMismatch } from "./ipam/problems";
import { Problem } from "./reply";
import { mockVlanController, topologyState } from "./topology-store";

type S = components["schemas"];
export type RootDecision = S["RootDecision"];
export type RootCandidate = S["RootCandidate"];
export type RootChoice = S["RootChoice"];
export type RootSource = S["RootSource"];
export type SsidView = S["SsidView"];
export type SsidEntry = S["SsidEntry"];
export type SsidVlan = S["SsidVlan"];
export type SsidClient = S["SsidClient"];
export type WlanPolicy = S["WlanPolicy"];
export type StoredWlanPolicy = S["StoredWlanPolicy"];
export type WlanException = S["WlanException"];
type Finding = S["Finding"];
type FieldChange = S["FieldChange"];
type ObjectRef = S["ObjectRef"];
type IntentHost = S["Host"];
type IntentVlan = S["Vlan"];
type IntentPrefix = S["Prefix"];

/** The tag that classes a host as an IoT device, and the one that gives a network the IoT role. */
export const HOST_CLASS_IOT = "class:iot";
export const NETWORK_ROLE_IOT = "role:iot";

/** The codes of the findings of the topology. */
export const ROOT_CODE = "ipam.topology.root_disagree";
export const RULE = { class: "ipam.topology.wlan_class", prefix: "ipam.topology.wlan_prefix" } as const;

const MAX_SSID_BYTES = 32;
const MAX_REASON_BYTES = 1_024;
const NIL = "00000000-0000-0000-0000-000000000000";

// ---------------------------------------------------------------------------------
// The stored decisions

/** What a person decided; one object for the life of the module, a reset restores the seed. */
export interface MockTopologyDecisions {
  /** The chosen root. */
  root: RootChoice | null;
  /** The policy of an SSID, by SSID. */
  policies: Map<string, StoredWlanPolicy>;
  /** "Keep on this WLAN", by host and SSID (`<host>|<ssid>`). */
  exceptions: Map<string, WlanException>;
  /** Hosts classed as IoT besides those that carry the tag `class:iot`. */
  iotHosts: Set<string>;
}

function freshDecisions(): MockTopologyDecisions {
  return {
    root: null,
    policies: new Map(),
    exceptions: new Map(),
    iotHosts: new Set(HOST_IDS["tv-living"] ? [HOST_IDS["tv-living"]] : []),
  };
}

export const mockTopologyDecisions: MockTopologyDecisions = freshDecisions();

onMockReset(() => {
  Object.assign(mockTopologyDecisions, freshDecisions());
});

const exceptionKey = (host: string, ssid: string): string => `${host}|${ssid}`;

/** The policy of an SSID and whether a person set it (else the default: ignore a guest SSID). */
function policyOf(ssid: string, guest: boolean): [WlanPolicy, boolean] {
  const stored = mockTopologyDecisions.policies.get(ssid);
  if (stored) return [stored.policy, true];
  return [guest ? "ignore" : "track", false];
}

// ---------------------------------------------------------------------------------
// Small helpers

const plainCompare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

function byteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

/** The stable part of the identifier of a topology finding: 32 hexadecimal digits. */
function digest(text: string): string {
  return testDigest(text).slice(0, 32);
}

const tagged = (tags: readonly string[] | undefined, tag: string): boolean =>
  (tags ?? []).some((t) => t.trim().toLowerCase() === tag);

const startedAt = (): string => new Date(db.startedAt).toISOString();

const sameKeys = (a: readonly string[], b: readonly string[]): boolean => a.length === b.length && a.every((v, i) => v === b[i]);

// ---------------------------------------------------------------------------------
// The root

const CONTROLLER_PREFIX = "network_controller:";

function listed(): boolean {
  return mockVlanController.present && mockVlanController.enabled;
}

/** The router a network controller reports: the first by label and identifier. */
function controllerCandidate(): RootCandidate | null {
  if (!listed()) return null;
  const gateways = topologyState()
    .nodes.filter((node) => node.kind === "router" && node.sources.some((s) => s.startsWith(CONTROLLER_PREFIX)))
    .sort((a, b) => plainCompare(a.label, b.label) || plainCompare(a.id, b.id));
  const node = gateways[0];
  if (!node) return null;
  return { source: "controller", node: node.id, label: node.label, ...(node.ips?.[0] ? { ip: node.ips[0] } : {}) };
}

/** The next hop of the default route: the first hop a node (never an access point) holds, else the first hop. */
function routeCandidate(): RootCandidate | null {
  const state = topologyState();
  const hops = state.nextHops;
  for (const hop of hops) {
    const holder = state.nodes
      .filter((node) => node.kind !== "access_point" && (node.ips ?? []).includes(hop))
      .sort((a, b) => plainCompare(a.label, b.label) || plainCompare(a.id, b.id))[0];
    if (holder) return { source: "default_route", node: holder.id, label: holder.label, ip: hop };
  }
  const first = hops[0];
  return first === undefined ? null : { source: "default_route", label: first, ip: first };
}

/** The key a choice remembers: `controller:<node>` or `route:<address>`. */
export function candidateKey(candidate: RootCandidate): string {
  return candidate.source === "controller"
    ? `controller:${candidate.node ?? candidate.label}`
    : `route:${candidate.ip ?? candidate.label}`;
}

/** Decides the root from the two sources and the stored choice. */
export function rootDecision(): RootDecision {
  const candidates = [controllerCandidate(), routeCandidate()].filter((c): c is RootCandidate => c !== null);
  const [first, second] = candidates;
  const disagree = candidates.length === 2 && (first?.node ?? null) !== (second?.node ?? null);
  const keys = candidates.map(candidateKey).sort();
  const choice = mockTopologyDecisions.root;
  const chosen = choice ? candidates.find((c) => c.source === choice.source) : undefined;
  const named = chosen ?? first;
  const decision: RootDecision = {
    candidates,
    disagree,
    open: disagree && (!choice || !sameKeys(choice.offered ?? [], keys)),
    revision: db.revision,
  };
  if (named) decision.root = { source: named.source, chosen: chosen !== undefined, ...(named.node ? { node: named.node } : {}) };
  if (choice) decision.choice = structuredClone(choice);
  return decision;
}

/** The finding of an open disagreement, to review, with "Use this" per candidate. */
function rootFinding(decision: RootDecision): Finding | null {
  if (!decision.open) return null;
  const keys = decision.candidates.map(candidateKey).sort();
  const params: Record<string, string> = {};
  for (const candidate of decision.candidates) {
    params[`${candidate.source}_label`] = candidate.label;
    if (candidate.node) params[`${candidate.source}_node`] = candidate.node;
    if (candidate.ip) params[`${candidate.source}_ip`] = candidate.ip;
  }
  const label = decision.candidates.map((c) => c.label).join(" / ");
  return {
    id: `topology:root:${digest(keys.join("|"))}`,
    kind: "topology_root",
    severity: "review",
    area: "topology",
    subject: { kind: "node", label },
    summary: `Topology root: the sources disagree (${label}); choose the one the map is drawn from`,
    code: ROOT_CODE,
    params,
    evidence: { id: "root", path: "/topology/root" },
    action: "use_root",
    since: startedAt(),
    source: "topology",
  };
}

// ---------------------------------------------------------------------------------
// The WLAN view and rules

interface Book {
  hosts: Map<string, IntentHost>;
  hostOfMac: Map<string, string>;
  vlans: IntentVlan[];
  networks: { prefix: IntentPrefix; cidr: Cidr }[];
}

function bookOfIntent(): Book {
  const data = ipamState().data;
  const hosts = new Map<string, IntentHost>();
  for (const host of data.host.values()) if (!host.meta.deleted) hosts.set(host.id, host);
  const hostOfMac = new Map<string, string>();
  for (const iface of data.interface.values()) {
    if (!iface.meta.deleted && iface.mac && hosts.has(iface.host)) hostOfMac.set(iface.mac.toLowerCase(), iface.host);
  }
  const networks: Book["networks"] = [];
  for (const prefix of data.prefix.values()) {
    if (prefix.meta.deleted || prefix.role !== "network") continue;
    const cidr = parseCidr(prefix.cidr);
    if (cidr) networks.push({ prefix, cidr });
  }
  networks.sort((a, b) => b.cidr.length - a.cidr.length || plainCompare(a.prefix.id, b.prefix.id));
  return { hosts, hostOfMac, vlans: [...data.vlan.values()].filter((v) => !v.meta.deleted), networks };
}

/** The VLAN object of `vid` for a host at `site`: the site's, else the global one, else the only one. */
function vlanOf(book: Book, vid: number, site: string | null | undefined): IntentVlan | undefined {
  const all = book.vlans.filter((v) => v.vid === vid);
  return (
    (site ? all.find((v) => v.site === site) : undefined) ?? all.find((v) => !v.site) ?? (all.length === 1 ? all[0] : undefined)
  );
}

const prefixesOf = (book: Book, vlan: IntentVlan): Book["networks"] => book.networks.filter((n) => n.prefix.vlan === vlan.id);

function iotRole(book: Book, vlan: IntentVlan): boolean {
  return tagged(vlan.meta.tags, NETWORK_ROLE_IOT) || prefixesOf(book, vlan).some((n) => tagged(n.prefix.meta.tags, NETWORK_ROLE_IOT));
}

const isIotHost = (host: IntentHost): boolean => tagged(host.meta.tags, HOST_CLASS_IOT) || mockTopologyDecisions.iotHosts.has(host.id);

/** The most specific network of intent that holds `ip`. */
function networkOf(book: Book, ip: string): Book["networks"][number] | undefined {
  const parsed = parseIp(ip);
  return parsed ? book.networks.find((n) => containsIp(n.cidr, parsed)) : undefined;
}

interface Judged {
  host: IntentHost;
  ssid: string;
  vid: number | null;
  vlan: IntentVlan | undefined;
  iotVlan: boolean;
  prefixes: Book["networks"];
  ip: string | undefined;
  mac: string;
  accessPoint: string;
  band: string;
}

/** The kinds of the findings the two rules raise for one client. */
function judge(judged: Judged): ("wlan_class" | "wlan_prefix")[] {
  const kinds: ("wlan_class" | "wlan_prefix")[] = [];
  if (isIotHost(judged.host) && !judged.iotVlan) kinds.push("wlan_class");
  const ip = judged.ip ? parseIp(judged.ip) : null;
  if (ip) {
    const sameFamily = judged.prefixes.filter((n) => n.cidr.version === ip.version);
    if (sameFamily.length > 0 && !sameFamily.some((n) => containsIp(n.cidr, ip))) kinds.push("wlan_prefix");
  }
  return kinds;
}

function ruleFinding(book: Book, judged: Judged, kind: "wlan_class" | "wlan_prefix"): Finding {
  const { host } = judged;
  const code = kind === "wlan_class" ? RULE.class : RULE.prefix;
  const cidrs = judged.prefixes.map((n) => n.prefix.cidr).join(", ");
  const vlanText = judged.vid === null ? "untagged" : `VLAN ${judged.vid}`;
  const summary =
    kind === "wlan_class"
      ? `${host.name} is classed as IoT and is on the WLAN ${judged.ssid} (${vlanText}), which is not an IoT network`
      : `${host.name} has the address ${judged.ip ?? ""} on the WLAN ${judged.ssid}, outside ${cidrs} of ${vlanText}`;
  const params: Record<string, string> = {
    host: host.name,
    ssid: judged.ssid,
    mac: judged.mac,
    class: "iot",
    role: judged.iotVlan ? "iot" : "other",
    access_point: judged.accessPoint,
  };
  if (kind === "wlan_prefix" && !isIotHost(host)) delete params.class;
  if (judged.vid !== null) params.vlan = String(judged.vid);
  if (judged.vlan) params.vlan_name = judged.vlan.name;
  if (cidrs !== "") params.prefix = cidrs;
  if (judged.ip) params.ip = judged.ip;
  if (judged.band) params.band = judged.band;
  const network = judged.ip ? networkOf(book, judged.ip) : undefined;
  const objects: ObjectRef[] = [{ kind: "host", id: host.id }];
  return {
    id: `topology:wlan:${digest(`${code}|${host.id}|${judged.ssid}`)}`,
    kind,
    severity: "review",
    area: "topology",
    subject: {
      kind: "host",
      label: host.name,
      host: host.id,
      mac: judged.mac,
      ip: judged.ip ?? null,
      prefix: network?.prefix.id ?? null,
      vrf: network?.prefix.vrf ?? null,
      objects,
    },
    summary,
    code,
    params,
    evidence: { id: `${host.id}/${judged.ssid}`, path: "/topology/ssids" },
    action: "move_host",
    since: startedAt(),
    source: "topology",
  };
}

interface Evaluation {
  ssids: SsidEntry[];
  findings: Finding[];
}

interface SsidAcc {
  vid: number | null;
  guest: boolean;
  enabled: boolean;
  accessPoints: Set<string>;
  clients: Map<number | null, SsidClient[]>;
}

function vlanEntry(book: Book, vid: number | null, clients: SsidClient[]): SsidVlan {
  clients.sort((a, b) => plainCompare(a.label, b.label) || plainCompare(a.mac, b.mac));
  const vlan = vid === null ? undefined : vlanOf(book, vid, null);
  const entry: SsidVlan = {
    iot: vlan ? iotRole(book, vlan) : false,
    prefixes: vlan ? prefixesOf(book, vlan).map((n) => ({ id: n.prefix.id, cidr: n.prefix.cidr })) : [],
    clients,
  };
  if (vid !== null) entry.vid = vid;
  if (vlan) {
    entry.vlan = vlan.id;
    entry.name = vlan.name;
  }
  return entry;
}

/** The view and the findings of the two rules, over the controller's tables, intent and the stored decisions. */
function evaluate(): Evaluation {
  const state = topologyState();
  if (!listed() || state.nodes.length === 0) return { ssids: [], findings: [] };
  const book = bookOfIntent();
  const nodes = new Map(state.nodes.map((n) => [n.id, n] as const));
  const ssids = new Map<string, SsidAcc>();
  const accOf = (ssid: string): SsidAcc => {
    let acc = ssids.get(ssid);
    if (!acc) {
      acc = { vid: null, guest: false, enabled: false, accessPoints: new Set(), clients: new Map() };
      ssids.set(ssid, acc);
    }
    return acc;
  };
  for (const wlan of state.wlans) {
    const acc = accOf(wlan.ssid);
    acc.vid = acc.vid ?? wlan.vid;
    acc.guest ||= wlan.guest;
    acc.enabled ||= wlan.enabled;
    for (const node of state.nodes) {
      if (node.kind === "access_point" && (node.ssids ?? []).includes(wlan.ssid)) acc.accessPoints.add(node.label);
    }
  }
  const findings: Finding[] = [];
  for (const client of state.wireless) {
    const node = nodes.get(client.node);
    const ap = nodes.get(client.accessPoint);
    if (!node) continue;
    const vid: number | null = client.vid || null;
    const hostId = book.hostOfMac.get(client.mac.toLowerCase());
    const host = hostId ? book.hosts.get(hostId) : undefined;
    const acc = accOf(client.ssid);
    const [policy] = policyOf(client.ssid, acc.guest);
    const kept = host !== undefined && mockTopologyDecisions.exceptions.has(exceptionKey(host.id, client.ssid));
    const row: SsidClient = {
      mac: client.mac,
      label: host?.name ?? node.label,
      access_point: ap?.label ?? client.accessPoint,
      iot: host !== undefined && isIotHost(host),
      kept,
      findings: [],
      node: node.id,
      band: client.band,
    };
    if (client.ip) row.ip = client.ip;
    if (host) row.host = host.id;
    if (node.vendor) row.vendor = node.vendor;
    if (ap) row.access_point_node = ap.id;
    if (host && host.mode !== "unmanaged" && !host.decommissioned && policy === "track" && !kept) {
      const vlan = vid === null ? undefined : vlanOf(book, vid, host.site);
      const judged: Judged = {
        host,
        ssid: client.ssid,
        vid,
        vlan,
        iotVlan: vlan ? iotRole(book, vlan) : false,
        prefixes: vlan ? prefixesOf(book, vlan) : [],
        ip: client.ip,
        mac: client.mac,
        accessPoint: row.access_point,
        band: client.band,
      };
      const raised = judge(judged).map((kind) => ruleFinding(book, judged, kind));
      row.findings = raised.map((f) => f.kind);
      findings.push(...raised);
    }
    const list = acc.clients.get(vid);
    if (list) list.push(row);
    else acc.clients.set(vid, [row]);
  }
  findings.sort((a, b) => plainCompare(a.id, b.id));
  const entries = [...ssids]
    .sort(([a], [b]) => plainCompare(a, b))
    .map(([ssid, acc]): SsidEntry => {
      const [policy, policySet] = policyOf(ssid, acc.guest);
      const vlans = [...acc.clients].map(([vid, clients]) => vlanEntry(book, vid, clients));
      // The SSID's own VLAN first, then by VLAN id.
      vlans.sort((a, b) => Number((a.vid ?? null) !== acc.vid) - Number((b.vid ?? null) !== acc.vid) || (a.vid ?? -1) - (b.vid ?? -1));
      if (vlans.length === 0) vlans.push(vlanEntry(book, acc.vid, []));
      const rows = vlans.flatMap((v) => v.clients);
      const entry: SsidEntry = {
        ssid,
        connectors: [mockVlanController.id],
        guest: acc.guest,
        enabled: acc.enabled,
        access_points: [...acc.accessPoints].sort(plainCompare),
        policy,
        policy_set: policySet,
        clients: rows.length,
        findings: rows.reduce((sum, row) => sum + (row.findings?.length ?? 0), 0),
        vlans,
      };
      if (acc.vid !== null) entry.vid = acc.vid;
      return entry;
    });
  return { ssids: entries, findings };
}

/** `GET /topology/ssids`. */
export function ssidView(): SsidView {
  return { ssids: evaluate().ssids, revision: db.revision };
}

/** The findings of the topology: the root when the sources disagree and the two WLAN rules. */
export function topologyFindings(): Finding[] {
  const root = rootFinding(rootDecision());
  const wlan = evaluate().findings;
  return root ? [root, ...wlan] : wlan;
}

// ---------------------------------------------------------------------------------
// Writing the decisions

function notStored(kind: string): Problem {
  return new Problem("ipam.topology.not_stored", { status: 404, detail: `no ${kind} is stored`, params: { kind } });
}

function invalidTopology(field: string, detail: string): Problem {
  return new Problem("ipam.topology.invalid", {
    status: 422,
    detail,
    params: { field },
    errors: [{ field, code: "ipam.topology.invalid" }],
  });
}

/** An SSID as a request gives it: 1 to 32 octets, no control characters (422 `ipam.topology.invalid`). */
export function validSsid(ssid: string): string {
  const bytes = byteLength(ssid);
  if (bytes === 0 || bytes > MAX_SSID_BYTES) throw invalidTopology("ssid", "an SSID has 1 to 32 octets");
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(ssid)) throw invalidTopology("ssid", "an SSID has no control characters");
  return ssid;
}

/** 412 when `ifMatch` is a revision and not the stored row's. */
function checkIfMatch(kind: string, id: string, ifMatch: number | "*" | null, current: number | undefined): void {
  if (typeof ifMatch === "number" && ifMatch !== current) throw revisionMismatch(kind, id, ifMatch, current ?? 0);
}

const SYSTEM: ObjectRef = { kind: "system", id: NIL };

function stamp(): S["Stamp"] {
  return { at: new Date().toISOString(), by: principalNow() };
}

function change(field: string, old: string | null, next: string | null): FieldChange {
  return { field, old, new: next };
}

/** Commits the write (revision, event on `ipam` that reaches `findings`) and audits it; returns the new revision. */
function recordWrite(action: string, objects: ObjectRef[], changes: FieldChange[], table: string): number {
  commit("ipam", { objects, tables: [table] });
  const revision = db.revision;
  appendAudit({ action, objects, changes });
  return revision;
}

/** "Use this": the map follows the candidate of `source` from now on. */
export function chooseRoot(source: RootSource, ifMatch: number | "*" | null): RootDecision {
  checkIfMatch("topology_root", "root", ifMatch, mockTopologyDecisions.root?.revision);
  const decision = rootDecision();
  const candidate = decision.candidates.find((c) => c.source === source);
  if (!candidate) {
    throw new Problem("ipam.topology.no_candidate", {
      status: 409,
      detail: `the source ${source} names no root now`,
      params: { source },
    });
  }
  const old = mockTopologyDecisions.root;
  const row: RootChoice = {
    source,
    offered: decision.candidates.map(candidateKey).sort(),
    decided: stamp(),
    revision: 0,
  };
  row.revision = recordWrite(
    "ipam.topology_root.choose",
    [SYSTEM],
    [change("source", old?.source ?? null, source), change("root", null, candidate.label)],
    "ipam.topology_root",
  );
  mockTopologyDecisions.root = row;
  return rootDecision();
}

/** Forgets the chosen root; the ranked sources decide again. */
export function clearRoot(ifMatch: number | "*" | null): void {
  const old = mockTopologyDecisions.root;
  if (!old) throw notStored("root choice");
  checkIfMatch("topology_root", "root", ifMatch, old.revision);
  mockTopologyDecisions.root = null;
  recordWrite("ipam.topology_root.clear", [SYSTEM], [change("source", old.source, null)], "ipam.topology_root");
}

/** Sets whether the WLAN rules read an SSID. */
export function setPolicy(ssid: string, policy: WlanPolicy, ifMatch: number | "*" | null): StoredWlanPolicy {
  validSsid(ssid);
  const old = mockTopologyDecisions.policies.get(ssid);
  checkIfMatch("wlan_policy", ssid, ifMatch, old?.revision);
  const row: StoredWlanPolicy = { ssid, policy, updated: stamp(), revision: 0 };
  row.revision = recordWrite(
    "ipam.wlan_policy.set",
    [SYSTEM],
    [change("ssid", null, ssid), change("policy", old?.policy ?? null, policy)],
    "ipam.wlan_policies",
  );
  mockTopologyDecisions.policies.set(ssid, row);
  return structuredClone(row);
}

/** Removes the policy of an SSID, so its default applies again. */
export function clearPolicy(ssid: string, ifMatch: number | "*" | null): void {
  validSsid(ssid);
  const old = mockTopologyDecisions.policies.get(ssid);
  if (!old) throw notStored("WLAN policy");
  checkIfMatch("wlan_policy", ssid, ifMatch, old.revision);
  mockTopologyDecisions.policies.delete(ssid);
  recordWrite("ipam.wlan_policy.clear", [SYSTEM], [change("ssid", ssid, null), change("policy", old.policy, null)], "ipam.wlan_policies");
}

/** "Keep on this WLAN": the rules skip the host on the SSID from now on. */
export function keepOnWlan(hostId: string, ssid: string, reason: string | null, ifMatch: number | "*" | null): WlanException {
  validSsid(ssid);
  const text = reason?.trim() ?? "";
  // eslint-disable-next-line no-control-regex
  if (text !== "" && (byteLength(text) > MAX_REASON_BYTES || /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/.test(text))) {
    throw invalidTopology("reason", "a reason has at most 1,024 bytes and no control characters");
  }
  const host = ipamState().data.host.get(hostId);
  if (!host || host.meta.deleted) throw notFound("host", hostId);
  const key = exceptionKey(hostId, ssid);
  const old = mockTopologyDecisions.exceptions.get(key);
  checkIfMatch("wlan_exception", hostId, ifMatch, old?.revision);
  const wanted = text === "" ? null : text;
  // Keeping a pair that is kept with the same reason changes nothing.
  if (old && (old.reason ?? null) === wanted) return structuredClone(old);
  const row: WlanException = { host: hostId, ssid, ...(wanted ? { reason: wanted } : {}), decided: stamp(), revision: 0 };
  const changes = [change("ssid", null, ssid), ...(wanted ? [change("reason", null, wanted)] : [])];
  row.revision = recordWrite("ipam.wlan_exception.keep", [{ kind: "host", id: hostId }], changes, "ipam.wlan_exceptions");
  mockTopologyDecisions.exceptions.set(key, row);
  return structuredClone(row);
}

/** Removes the exception: the rules read the host on the SSID again. */
export function forgetException(hostId: string, ssid: string, ifMatch: number | "*" | null): void {
  validSsid(ssid);
  const key = exceptionKey(hostId, ssid);
  const old = mockTopologyDecisions.exceptions.get(key);
  if (!old) throw notStored("WLAN exception");
  checkIfMatch("wlan_exception", hostId, ifMatch, old.revision);
  mockTopologyDecisions.exceptions.delete(key);
  recordWrite("ipam.wlan_exception.clear", [{ kind: "host", id: hostId }], [change("ssid", ssid, null)], "ipam.wlan_exceptions");
}
